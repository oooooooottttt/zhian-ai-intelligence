"""Passive, bounded CycloneDX/SPDX JSON projection into authorized inventory.

``parse_sbom(document, *, now=None)`` returns ``assets``, ``warnings``, ``format``
(CycloneDX or SPDX), and ``component_count``. ``observed_at`` is also accepted as
a compatible keyword. ``parse_sbom_assets`` provides an asset-list wrapper. The count is before
deduplication and includes CycloneDX metadata.component and nested components.
Only the existing inventory fields are returned; PURLs are parsed into package
identity, never fetched or retained. IDs use only the sanitized projection.

This is an identity projection, not full SBOM schema/attestation validation.
Supported envelopes: CycloneDX JSON 1.3--1.7 and SPDX JSON 2.2/2.3. SPDX 3's
different graph model is deliberately rejected. No CPE/product/server inference,
dependency graph, deployment assessment, license conclusion, or network access.
Unknown/malformed/conflicting PURLs remain unmapped rather than falling back to
name-based guesses about ecosystems. Exposure and authentication stay unknown.

Field definitions consulted 2026-10-04, without downloading PDFs:
https://cyclonedx.org/docs/1.7/json/
https://spdx.github.io/spdx-spec/v2.3/package-information/
https://github.com/package-url/purl-spec/tree/main/docs/types/definitions
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import unicodedata
from urllib.parse import unquote


MAX_COMPONENTS = 256
MAX_DOCUMENT_BYTES = 1_048_576
MAX_DEPTH = 20
MAX_NODES = 20_000
MAX_STRING_BYTES = 65_536
MAX_LIST_ITEMS = 4096
MAX_EXTERNAL_REFS = 64
_UNKNOWN = {"", "unknown", "noassertion", "none", "n/a", "unspecified", "not specified", "*", "latest"}
_SECRET = re.compile(
    r"(?i)(?:\bbearer\s+\S+|\b(?:password|passwd|api[_-]?key|access[_-]?token|secret|token|authorization|credential)\s*[:=]"
    r"|\bsk-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)
_URI = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://|\b(?:https?|ssh|file|data|javascript|mailto):)")
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SEGMENT = re.compile(r"[A-Za-z0-9._+~-]+", re.ASCII)
_TYPE = re.compile(r"[a-z][a-z0-9.+-]{0,79}", re.ASCII)
# Ecosystem labels deliberately match the existing GitHub/enrichment contract.
# An unregistered/custom type (including generic/docker/OS packages) stays unknown.
_ECOSYSTEMS = {"pypi": "pypi", "npm": "npm", "maven": "maven", "nuget": "nuget",
               "gem": "rubygems", "cargo": "rust", "golang": "go", "composer": "composer",
               "hex": "erlang", "pub": "pub", "swift": "swift"}
_NO_NAMESPACE = {"pypi", "nuget", "gem", "cargo", "hex", "pub"}


def _bounded_json(document: object) -> None:
    """Accept only actual JSON value types; reject cycles before serialization."""
    stack = [(document, 0, False)]
    ancestors: set[int] = set()
    nodes = size = 0
    while stack:
        item, depth, leaving = stack.pop()
        if leaving:
            ancestors.remove(id(item))
            continue
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("SBOM exceeds node/depth limits")
        kind = type(item)
        if kind in (dict, list):
            if id(item) in ancestors:
                raise ValueError("SBOM must be acyclic JSON")
            ancestors.add(id(item))
            stack.append((item, depth, True))
            if kind is dict:
                if len(item) > 128 or any(type(k) is not str or len(k) > 128 for k in item):
                    raise ValueError("SBOM object exceeds field limits")
                size += 2 + 2 * len(item)
                for key, value in item.items():
                    stack.append((key, depth + 1, False))
                    stack.append((value, depth + 1, False))
            else:
                if len(item) > MAX_LIST_ITEMS:
                    raise ValueError("SBOM array exceeds item limits")
                size += 2 + len(item)
                stack.extend((value, depth + 1, False) for value in item)
        elif kind is str:
            try:
                # JSON escaping counts too; neither the temporary text nor input
                # is stored or returned. This bounds even ignored metadata.
                encoded = json.dumps(item, ensure_ascii=False).encode("utf-8")
            except (UnicodeError, ValueError):
                raise ValueError("SBOM contains invalid Unicode") from None
            if len(encoded) > MAX_STRING_BYTES:
                raise ValueError("SBOM string exceeds size limit")
            size += len(encoded)
        elif item is None or kind is bool:
            size += 5
        elif kind is int:
            if item.bit_length() > 64:
                raise ValueError("SBOM integer exceeds size limit")
            size += 21
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError("SBOM numbers must be finite")
            size += 32
        else:
            raise ValueError("SBOM must contain only JSON values")
        if size > MAX_DOCUMENT_BYTES:
            raise ValueError("SBOM exceeds document size limit")


def _safe_text(value: object, maximum: int, *, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if type(value) is not str or len(value) > maximum:
        raise ValueError("SBOM identity field has invalid type/length")
    text = value.strip()
    if (required and not text) or any(unicodedata.category(c).startswith("C") for c in value):
        raise ValueError("SBOM identity field is empty or contains controls")
    # Check nested escaping for credential/URL disguise, without changing the
    # package name. Raw narrative metadata is never copied to inventory.
    decoded = text
    for _ in range(4):
        if (_SECRET.search(decoded) or _URI.search(decoded)
                or any(c in decoded for c in "<>\\\"';=`")
                or any(unicodedata.category(c).startswith("C") for c in decoded)):
            raise ValueError("SBOM identity field is unsafe")
        updated = unquote(decoded)
        if updated == decoded:
            break
        decoded = updated
    else:
        raise ValueError("SBOM identity field contains excessive escaping")
    return text


def _version(value: object) -> str:
    text = _safe_text(value, 128)
    return "unknown" if text.casefold() in _UNKNOWN else text


def _decode(value: str) -> str:
    if _BAD_ESCAPE.search(value):
        raise ValueError("Invalid PURL percent encoding")
    try:
        return unquote(value, encoding="utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("Invalid PURL Unicode") from None


@dataclass(frozen=True)
class _Purl:
    package_type: str
    namespace: str
    name: str
    component: str
    version: str
    qualifiers: bool
    subpath: bool


def _parse_purl(value: object) -> _Purl:
    if type(value) is not str or len(value) > 2048 or not value.startswith("pkg:"):
        raise ValueError("Invalid PURL")
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Invalid PURL whitespace")
    body = value[4:]
    if body.count("#") > 1 or body.count("?") > 1:
        raise ValueError("Invalid PURL separators")
    body, marker, subpath = body.partition("#")
    if marker:
        if not subpath or "?" in subpath:
            raise ValueError("Invalid PURL subpath")
        for part in subpath.split("/"):
            if not part or _decode(part) in {".", ".."} or "/" in _decode(part):
                raise ValueError("Invalid PURL subpath")
    body, query_marker, query = body.partition("?")
    if query_marker:
        if not query or len(query.split("&")) > 32:
            raise ValueError("Invalid PURL qualifiers")
        keys = set()
        for qualifier in query.split("&"):
            key, equals, raw = qualifier.partition("=")
            if not equals or not raw or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", key) or key in keys:
                raise ValueError("Invalid PURL qualifier")
            keys.add(key)
            decoded = _decode(raw)
            if any(unicodedata.category(c).startswith("C") for c in decoded):
                raise ValueError("Invalid PURL qualifier controls")
            # Qualifiers, including repository URLs/credentials, never enter
            # output, warnings, or asset hashes; no URL is visited.
    package_type, slash, path = body.partition("/")
    if not slash or not _TYPE.fullmatch(package_type) or not path or path.startswith("/"):
        raise ValueError("Invalid PURL package type/path")
    if "@" in path:
        path, _, raw_version = path.rpartition("@")
        if not raw_version or "@" in path:
            raise ValueError("Invalid PURL version separator")
        version = _version(_decode(raw_version))
    else:
        version = "unknown"
    parts = path.split("/")
    if any(not part for part in parts):
        raise ValueError("Invalid PURL path")
    name = _safe_text(_decode(parts[-1]), 256, required=True)
    namespace_parts = [_safe_text(_decode(part), 256, required=True) for part in parts[:-1]]
    if not _SEGMENT.fullmatch(name) or name in {".", ".."}:
        raise ValueError("Unsupported PURL name syntax")
    if any(part in {".", ".."} or not re.fullmatch(r"@?[A-Za-z0-9._+~-]+", part) for part in namespace_parts):
        raise ValueError("Unsupported PURL namespace syntax")
    namespace = "/".join(namespace_parts)
    if package_type in _NO_NAMESPACE and namespace:
        raise ValueError("PURL type prohibits namespace")
    if package_type == "npm" and namespace and (len(namespace_parts) != 1 or not re.fullmatch(r"@[A-Za-z0-9._-]+", namespace)):
        raise ValueError("Invalid npm scope")
    if package_type in {"maven", "composer"} and (len(namespace_parts) != 1 or namespace.startswith("@")):
        raise ValueError("PURL type requires namespace")
    if package_type == "pypi":
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
            raise ValueError("Invalid PyPI package name")
        name = re.sub(r"[-_.]+", "-", name).lower()
    component = (namespace + (":" if package_type == "maven" else "/") if namespace else "") + name
    _safe_text(component, 256, required=True)
    return _Purl(package_type, namespace, name, component, version, bool(query_marker), bool(marker))


def _timestamp(now: str | None) -> str:
    if now is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if type(now) is not str or len(now) > 64 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", now):
        raise ValueError("Invalid SBOM import timestamp")
    try:
        dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise ValueError("Invalid SBOM import timestamp") from None


def _components(document: dict) -> tuple[str, list[dict]]:
    if document.get("bomFormat") == "CycloneDX" and "spdxVersion" not in document:
        specification = document.get("specVersion")
        if type(specification) is not str or specification not in {"1.3", "1.4", "1.5", "1.6", "1.7"}:
            raise ValueError("Unsupported CycloneDX JSON version")
        root = document.get("components", [])
        if type(root) is not list:
            raise ValueError("CycloneDX components must be an array")
        metadata = document.get("metadata", {})
        if type(metadata) is not dict:
            raise ValueError("CycloneDX metadata must be an object")
        pending = list(reversed(root))
        if "component" in metadata:
            pending.append(metadata["component"])
        rows = []
        while pending:
            row = pending.pop()
            if type(row) is not dict:
                raise ValueError("SBOM component must be an object")
            rows.append(row)
            if len(rows) + len(pending) > MAX_COMPONENTS:
                raise ValueError("SBOM must contain 1 to 256 components")
            children = row.get("components", [])
            if type(children) is not list:
                raise ValueError("Nested CycloneDX components must be an array")
            pending.extend(reversed(children))
        return "CycloneDX", rows
    specification = document.get("spdxVersion")
    if type(specification) is str and specification in {"SPDX-2.2", "SPDX-2.3"} and "bomFormat" not in document:
        rows = document.get("packages")
        if type(rows) is not list or any(type(row) is not dict for row in rows):
            raise ValueError("SPDX packages must be an array of objects")
        return "SPDX", rows
    raise ValueError("Unsupported or ambiguous SBOM JSON format")


def parse_sbom_report(document: dict, *, observed_at: str | None = None) -> dict:
    """Project a user-authorized SBOM; errors are generic and never echo input.

    ``observed_at`` is a host-supplied import time, not a document creation time. Mapping
    does not prove a component is installed, running, reachable, or vulnerable.
    Exact projected duplicates merge, keeping raw component_count visible.
    """
    if type(document) is not dict:
        raise ValueError("SBOM document must be a JSON object")
    _bounded_json(document)
    timestamp = _timestamp(observed_at)
    format_name, rows = _components(document)
    if not 1 <= len(rows) <= MAX_COMPONENTS:
        raise ValueError("SBOM must contain 1 to 256 components")
    warnings = ["SBOM is passive component inventory; deployment, exposure, authentication and capabilities are not inferred.",
                "observed_at is import time, not SBOM creation time or proof of current installation."]
    assets, seen = [], set()
    for index, row in enumerate(rows, 1):
        label = f"component[{index}]"
        name = _safe_text(row.get("name"), 256, required=True)
        group = _safe_text(row.get("group"), 256) if format_name == "CycloneDX" else ""
        version = _version(row.get("version" if format_name == "CycloneDX" else "versionInfo"))
        fallback = _safe_text(f"{group}/{name}" if group else name, 256, required=True)
        raw_purls = []
        if format_name == "CycloneDX":
            if "purl" in row:
                raw_purls.append(row["purl"])
        else:
            refs = row.get("externalRefs", [])
            if type(refs) is not list or len(refs) > MAX_EXTERNAL_REFS or any(type(ref) is not dict for ref in refs):
                raise ValueError("SPDX external references exceed limits or have invalid structure")
            for ref in refs:
                if ref.get("referenceType") == "purl":
                    if ref.get("referenceCategory") == "PACKAGE-MANAGER":
                        raw_purls.append(ref.get("referenceLocator"))
                    else:
                        warnings.append(f"{label}: purl has an invalid category; not mapped.")
        purls = []
        malformed = False
        for raw_purl in raw_purls:
            try:
                purls.append(_parse_purl(raw_purl))
            except ValueError:
                malformed = True
        ecosystem, component = "unknown", fallback
        identities = {(p.package_type, p.namespace, p.name) for p in purls}
        if malformed or len(identities) > 1:
            warnings.append(f"{label}: malformed or conflicting purl identity; ecosystem is unknown.")
            version = "unknown" if len({p.version for p in purls} - {"unknown"}) > 1 else version
        elif purls:
            purl = purls[0]
            candidate_name = re.sub(r"[-_.]+", "-", name).lower() if purl.package_type == "pypi" else name
            conflict = candidate_name not in {purl.name, purl.component} or bool(group and group != purl.namespace)
            if conflict:
                warnings.append(f"{label}: name/group conflicts with purl; ecosystem is unknown.")
            else:
                component = purl.component
                ecosystem = _ECOSYSTEMS.get(purl.package_type, "unknown")
                if ecosystem == "unknown":
                    warnings.append(f"{label}: purl type has no supported package ecosystem mapping.")
                # Existing matching lowercases npm identities; preserve legacy
                # mixed-case packages as unmapped rather than conflate them.
                elif purl.package_type == "npm" and component != component.lower():
                    ecosystem = "unknown"
                    warnings.append(f"{label}: case-sensitive legacy npm identity is not mapped by the current matcher.")
            versions = {p.version for p in purls} - {"unknown"}
            if version != "unknown":
                versions.add(version)
            if len(versions) > 1:
                version = "unknown"
                warnings.append(f"{label}: version fields conflict; version is unknown.")
            elif versions:
                version = next(iter(versions))
            if any(p.qualifiers or p.subpath for p in purls):
                warnings.append(f"{label}: purl qualifiers/subpath are omitted; artifact/platform differences are not represented.")
        else:
            warnings.append(f"{label}: no usable purl; ecosystem and client/server identity are unknown.")
        if version == "unknown":
            warnings.append(f"{label}: installed version is unknown.")
        identity = (ecosystem, component, version)
        if identity in seen:
            warnings.append(f"{label}: duplicate projected package identity merged; occurrences are not deployment instances.")
            continue
        seen.add(identity)
        asset_id = "sbom-" + hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()[:24]
        assets.append({"asset_id": asset_id, "name": component, "ecosystem": ecosystem,
                       "component": component, "version": version, "exposed": None,
                       "authenticated": None, "observed_at": timestamp, "capabilities": {}})
    return {"assets": assets, "warnings": warnings, "format": format_name, "component_count": len(rows)}


def parse_sbom(document: dict, *, now: str | None = None, observed_at: str | None = None) -> dict:
    """Passive import entry point with bounded diagnostics for the local UI.

    ``now`` retains the original integration API. ``observed_at`` is an alias;
    supplying both is rejected to prevent ambiguous import-clock selection.
    """
    if now is not None and observed_at is not None:
        raise ValueError("Specify one SBOM import timestamp")
    return parse_sbom_report(document, observed_at=observed_at if observed_at is not None else now)


def parse_sbom_assets(document: dict, *, observed_at: str | None = None) -> list[dict]:
    """Compatibility wrapper returning only accepted asset fields."""
    return parse_sbom_report(document, observed_at=observed_at)["assets"]
