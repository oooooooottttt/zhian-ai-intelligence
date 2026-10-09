"""Pure, bounded upstream POC/exploit-reference metadata projection.

The POC entry point reads only explicit POC reference ``tags``; titles, URL paths, GitHub
hosts, CVSS exploitability and arbitrary payload fields never establish a POC.
An NVD ``Exploit`` tag can identify an advisory or technical description rather
than runnable code, so its class differs from an explicit ``POC`` tag. Every
result remains an unverified candidate; no reference is resolved or fetched.
``extract_poc_references`` excludes Exploit-only tags. The separate
``extract_tagged_reference_leads`` preserves both classes for metadata review;
its Exploit-only results must not be put into metadata.poc_references.

NVD API reference shape (official schema, inspected 2026-10-04):
https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
``reference`` defines ``url``, optional ``source``, and string-array ``tags``.
The schema does not enumerate tags or license third-party linked material.
NVD attribution/terms belong to the enclosing observation, not to the linked
publisher. An explicitly supplied license is an upstream label, not a checked
license grant. Never infer it from NVD, the hostname, or a repository's name.

Limits: at most 128 input references, 32 tags per reference, and 64 output leads
for the existing enrichment consumer. Invalid containers and excess input raise
a sanitized ValueError. Invalid entries are omitted. Beyond 64 distinct leads,
new leads are omitted in input order; later duplicates can still contribute
tags to an already retained lead. The caller must describe this bounded scope
and must not interpret an empty result as evidence that a POC does not exist.

URL checks cover syntax, credentials, local hostnames and non-public IP literals
without DNS or network calls. They cannot establish the current DNS resolution,
reachability, redirect destination, authenticity or code availability of a name.
Any future fetch would require the separate allowlisted HTTP/DNS boundary.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

MAX_INPUT_REFERENCES = 128
MAX_POC_REFERENCES = 64
MAX_TAGS = 32
MAX_URL_LENGTH = 2048
_SECRET_KEY = re.compile(
    r"token|password|passwd|secret|api.?key|authorization|credential|"
    r"signature|session|bearer|jwt|^auth$|^key$", re.I,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?:\b(?:api[_-]?key|access[_-]?token|password|passwd|authorization|"
    r"secret|bearer|jwt|auth|credential|session|signature)\s*[:=]|"
    r"\bbearer\s+\S+|\bsk-[A-Za-z0-9_-]{12,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", re.I,
)
_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_LOCAL_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa",
    ".onion", ".test", ".invalid", ".example",
)
_POC_TAGS = frozenset({"poc", "proof of concept", "proof of concept (poc)", "proof of concept/poc"})


def _decoded(value: str) -> str | None:
    """Inspect bounded percent decoding without interpreting a nested payload."""
    for _ in range(3):
        next_value = unquote(value, errors="strict")
        if next_value == value:
            return value
        value = next_value
    return value if unquote(value, errors="strict") == value else None


def _public_url(value: Any) -> str:
    if (type(value) is not str or not value or len(value) > MAX_URL_LENGTH
            or any(ord(c) <= 32 or ord(c) == 127 or unicodedata.category(c).startswith("C") for c in value)
            or any(c in value for c in "\\<>\"")):
        return ""
    try:
        decoded = _decoded(value)
        if (decoded is None or any(ord(c) <= 32 or ord(c) == 127 or unicodedata.category(c).startswith("C") for c in decoded)
                or "\\" in decoded or _EMAIL.search(decoded) or _SECRET_ASSIGNMENT.search(decoded)):
            return ""
        parts = urlsplit(value)
        host = (parts.hostname or "").lower().rstrip(".")
        if (parts.scheme not in {"http", "https"} or not host or len(host) > 253
                or parts.username is not None or parts.password is not None
                or parts.port not in {None, 80, 443} or "%" in host
                or host in {"localhost", "localhost.localdomain"} or host.endswith(_LOCAL_SUFFIXES)):
            return ""
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                # Literal parsing only: inet_aton does not perform a DNS query.
                address = ipaddress.ip_address(socket.inet_aton(host))
            except OSError:
                address = None
            if address is None and ("." not in host or re.fullmatch(r"[0-9.]+", host)
                                    or any(not _HOST_LABEL.fullmatch(label) for label in host.split("."))):
                return ""
        if address is not None and (not address.is_global or address.is_multicast):
            return ""
        decoded_parts = urlsplit(decoded)
        for section in (decoded_parts.query, decoded_parts.fragment):
            for key, _ in parse_qsl(section, keep_blank_values=True):
                if _SECRET_KEY.search(key.rsplit("/", 1)[-1].lstrip("?!#")):
                    return ""
        netloc = f"[{host}]" if ":" in host else host
        if parts.port is not None and parts.port != (443 if parts.scheme == "https" else 80):
            netloc += f":{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, parts.fragment))
    except (ValueError, UnicodeError, OverflowError):
        return ""


def _label(value: Any, limit: int = 128) -> str:
    """Keep a small explicit public label; omit emails, commands and secrets."""
    if type(value) is not str or not value or len(value) > limit:
        return ""
    if any(not (c.isalnum() or c in " .,+_:/()&-") for c in value):
        return ""
    if _EMAIL.search(value) or _SECRET_ASSIGNMENT.search(value) or "http" in value.lower():
        return ""
    return value.strip()


def _tags(value: Any) -> list[str]:
    if type(value) not in {list, tuple} or not value or len(value) > MAX_TAGS:
        return []
    labels = [_label(tag, 64) for tag in value]
    # Do not turn malformed nested values or an injected tag into assertions.
    if any(not label for label in labels):
        return []
    return list(dict.fromkeys(labels))


def _classification(tags: list[str]) -> tuple[str, str] | None:
    normalized = {re.sub(r"[-_]+", " ", tag.casefold()) for tag in tags}
    if normalized & _POC_TAGS:
        return "explicit_poc_reference", "explicit_upstream_poc_tag"
    if "exploit" in normalized:
        return "exploit_reference", "explicit_upstream_exploit_tag"
    return None


def extract_tagged_reference_leads(references: Any) -> list[dict[str, Any]]:
    """Project explicit upstream-tagged leads, never verify code or access URLs.

    Deduplicate the same normalized URL with the same optional source/publisher/
    license labels. Different supplied labels retain separate provenance. Tags
    from duplicates are combined; an explicit POC tag takes precedence over an
    Exploit-only classification without claiming stronger verification.
    """
    if type(references) not in {list, tuple}:
        raise ValueError("POC reference input must be a list or tuple")
    if len(references) > MAX_INPUT_REFERENCES:
        raise ValueError("POC reference input exceeds 128 references")
    results: list[dict[str, Any]] = []
    retained: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for reference in references:
        if type(reference) is not dict:
            continue
        tags = _tags(reference.get("tags"))
        classification = _classification(tags)
        if classification is None:
            continue
        url = _public_url(reference.get("url"))
        if not url:
            continue
        source = _label(reference.get("source"))
        publisher = _label(reference.get("publisher"))
        license_label = _label(reference.get("license"))
        key = (url, source, publisher, license_label)
        if key in retained:
            lead = retained[key]
            merged_tags = list(dict.fromkeys((*lead["upstream_tags"], *tags)))
            projected_tags = merged_tags[:MAX_TAGS]
            # Retain the decisive raw upstream tag even when auxiliary tags fill
            # the projection. The stored class must have visible tag support.
            if classification[0] == "explicit_poc_reference" and not (
                    _classification(projected_tags) and _classification(projected_tags)[0] == "explicit_poc_reference"):
                decisive_tag = next(tag for tag in tags if _classification([tag]) and _classification([tag])[0] == "explicit_poc_reference")
                projected_tags[-1] = decisive_tag
            lead["upstream_tags"] = projected_tags
            if classification[0] == "explicit_poc_reference":
                lead["class"], lead["basis"] = classification
            continue
        if len(results) >= MAX_POC_REFERENCES:
            continue
        lead = {
            "url": url, "class": classification[0], "basis": classification[1],
            "upstream_tags": tags, "availability": "not_checked", "verification": "unverified",
            "downloaded": False, "executed": False,
        }
        for name, label in (("upstream_source", source), ("publisher", publisher), ("license", license_label)):
            if label:
                lead[name] = label
        retained[key] = lead
        results.append(lead)
    return results


def extract_poc_references(references: Any) -> list[dict[str, Any]]:
    """Return explicit upstream POC-tagged references only, never Exploit-only.

    No NVD free-text/URL heuristic upgrades an exploit reference to a POC. The
    independent explicit-POC cap applies after tag selection, so unrelated
    Exploit-only metadata cannot crowd out a later explicitly tagged POC.
    """
    if type(references) not in {list, tuple}:
        raise ValueError("POC reference input must be a list or tuple")
    if len(references) > MAX_INPUT_REFERENCES:
        raise ValueError("POC reference input exceeds 128 references")
    explicit = [reference for reference in references if type(reference) is dict
                and (classification := _classification(_tags(reference.get("tags"))))
                and classification[0] == "explicit_poc_reference"]
    return extract_tagged_reference_leads(explicit)
