"""Bounded evidence enrichment. No network, database, model or target access.

The caller supplies authorized source revisions and inventory. Structured fields
are source assertions, not instructions. This module never extracts scores,
versions, exploitability or repair commands from narrative text.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import math
import re
import socket
from typing import Any, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from .contracts import Assessment, EnrichmentResult, Evidence, Fact
from .versioning import match_version

MAX_EVIDENCE = 128
MAX_RELATED = 128
MAX_ASSETS = 256
MAX_ITEMS = 64
# The current QA projection consumes at most 256 facts per event. Fail closed
# above that shared consumption budget rather than silently losing facts.
MAX_FACTS = 256
MAX_FACT_VALUE_BYTES = 8192
MAX_RESULT_BYTES = 1_000_000
INVENTORY_MAX_AGE = timedelta(hours=24)
_ALIAS = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[A-Za-z0-9]{4}(?:-[A-Za-z0-9]{4}){2}|OSV-[A-Za-z0-9._-]+)", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9@/._:+ -]{1,256}", re.ASCII)
_CAP = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
_SECRET = re.compile(r"token|password|passwd|secret|api.?key|authorization|credential|signature|session|bearer|jwt|^auth$|^key$", re.I)


def _text(value: Any, limit: int = 512) -> str:
    """Small source text projection, with common embedded credentials removed."""
    if not isinstance(value, str):
        return ""
    value = "".join(c for c in value[:limit] if c in "\n\t" or ord(c) >= 32)
    value = re.sub(r"(?i)\b(?:api[_-]?key|access[_-]?token|password|passwd|authorization|secret|bearer|jwt|auth)\s*[:=]\s*[^\s,;]+", "[credential omitted]", value)
    return re.sub(r"https?://[^\s<>\"']+", lambda m: m[0] if _public_url(m[0]) else "[URL omitted]", value)


def _public_url(value: Any) -> str:
    # This is a literal/hostname safety check only, never DNS or a fetch.
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        return ""
    try:
        p = urlsplit(value)
        host = (p.hostname or "").lower().rstrip(".")
        if p.scheme not in {"https", "http"} or not host or p.username is not None or p.password is not None or p.port not in {None, 80, 443} or "%" in host:
            return ""
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".lan", ".home", ".onion")):
            return ""
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                address = ipaddress.ip_address(socket.inet_aton(host))
            except OSError:
                address = None
            if address is None and (not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host or re.fullmatch(r"[0-9.]+", host)):
                return ""
        if address is not None and (not address.is_global or address.is_multicast):
            return ""
        if any(_SECRET.search(k.rsplit("/", 1)[-1].lstrip("?!#")) for text in (p.query, p.fragment) for k, _ in parse_qsl(text, keep_blank_values=True)):
            return ""
        if _SECRET.search(unquote(p.fragment).split("=", 1)[0].rsplit("/", 1)[-1].lstrip("?!#")) and "=" in unquote(p.fragment):
            return ""
        if re.search(r"\b[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", unquote(value)):
            return ""
        return urlunsplit(p)
    except (ValueError, UnicodeError):
        return ""


def _items(value: Any, label: str, warnings: list[str]) -> list:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > MAX_ITEMS:
        warnings.append(f"{label}: structured list invalid or exceeds {MAX_ITEMS}; not evaluated")
        return []
    return list(value)


def _dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _eco(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 80:
        return ""
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", value):
        return ""
    return {"pip": "pypi", "python": "pypi", "ollama": "product"}.get(value, value)


def _identity(ecosystem: Any, component: Any) -> tuple[str, str] | None:
    ecosystem = _eco(ecosystem)
    if not ecosystem or not isinstance(component, str) or not _NAME.fullmatch(component) or component.startswith("cpe:") or _text(component, 256) != component:
        return None
    name = component.strip()
    if ecosystem == "pypi":
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name, re.ASCII):
            return None
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem in {"product", "npm"}:
        name = name.lower()
    return (ecosystem, name) if name else None


def _ids(e: Evidence) -> set[str]:
    return {s.upper() for s in (*e.aliases, e.upstream_id) if isinstance(s, str) and len(s) <= 128 and _ALIAS.fullmatch(s)}


def _bounded_json(value: Any) -> None:
    """Bound supplied metadata without serializing or interpreting arbitrary objects."""
    stack = [(value, 0)]
    nodes, text_size = 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 4096 or depth > 10:
            raise ValueError("Evidence metadata exceeds node/depth budget")
        if isinstance(item, str):
            text_size += len(item)
            if len(item) > 16384 or text_size > 100000:
                raise ValueError("Evidence metadata exceeds text budget")
        elif isinstance(item, dict):
            if len(item) > 256 or any(not isinstance(k, str) or len(k) > 128 for k in item):
                raise ValueError("Evidence metadata object exceeds budget")
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, (list, tuple)):
            if len(item) > 256:
                raise ValueError("Evidence metadata array exceeds budget")
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, int):
            if item.bit_length() > 4096:
                raise ValueError("Evidence metadata number exceeds budget")
        elif item is not None and not isinstance(item, (float, bool)):
            raise ValueError("Evidence metadata must be JSON data")


def _current(primary: Sequence[Evidence], related: Sequence[Evidence], warnings: list[str]) -> tuple[list[Evidence], list[Evidence]]:
    """Latest supplied revision wins, including a latest withdrawal/permission denial."""
    groups: dict[int, list[Evidence]] = defaultdict(list)
    for e in (*primary, *related):
        if (not isinstance(e, Evidence) or not isinstance(e.observation_id, int) or isinstance(e.observation_id, bool)
                or e.observation_id <= 0 or not isinstance(e.revision_number, int) or isinstance(e.revision_number, bool)
                or e.revision_number <= 0 or e.id != f"obs:{e.observation_id}:r:{e.revision_number}"):
            raise ValueError("Evidence identity does not match its observation and revision")
        if not isinstance(e.metadata, dict) or len(e.metadata) > 128 or len(e.aliases) > MAX_ITEMS or len(e.components) > MAX_ITEMS or len(e.references) > MAX_ITEMS:
            raise ValueError("Evidence projection exceeds bounds")
        _bounded_json(e.metadata)
        for values, limit in ((e.aliases, 128), (e.components, 1024), (e.references, 4096)):
            if any(not isinstance(v, str) or len(v) > limit for v in values):
                raise ValueError("Evidence identifiers/components/references exceed bounds")
        if any(not isinstance(v, str) or len(v) > limit for v, limit in ((e.source_id, 128), (e.upstream_id, 256), (e.kind, 32), (e.title, 1024), (e.summary, 16384), (e.url, 4096))):
            raise ValueError("Evidence text exceeds bounds")
        groups[e.observation_id].append(e)
    active = {}
    for obs, revisions in groups.items():
        highest = max(e.revision_number for e in revisions)
        latest = [e for e in revisions if e.revision_number == highest]
        if any(e != latest[0] for e in latest[1:]) or len({e.source_id for e in revisions}) > 1:
            warnings.append(f"obs:{obs}: conflicting evidence identity excluded")
            continue
        e = latest[0]
        status = e.metadata.get("status")
        if e.withdrawn or e.metadata.get("withdrawn") is True or e.metadata.get("withdrawn_at") or isinstance(status, str) and status.lower() == "rejected":
            warnings.append(f"{e.id}: withdrawn evidence excluded from current support")
        elif e.metadata.get("authorized") is False or e.metadata.get("enrichment_allowed") is False:
            warnings.append(f"{e.id}: source permission denies enrichment")
        else:
            active[e.id] = e
    def select(seq):
        return sorted({e.id: active[e.id] for e in seq if e.id in active}.values(), key=lambda e: e.id)
    return select(primary), select(related)


@dataclass(frozen=True)
class _Condition:
    field: str
    expected: bool | None
    supported: bool = True
    locator: str = ""


def _conditions(value: Any, warnings: list[str], locator: str, evidence_id: str = "") -> tuple[_Condition, ...]:
    if value is None:
        return ()
    if isinstance(value, dict) and len(value) <= MAX_ITEMS:
        # A simple map is AND; do not interpret OR/negation or prose.
        raw = []
        for key, expected in value.items():
            if key == "capabilities" and isinstance(expected, dict) and len(expected) <= MAX_ITEMS:
                for k, v in expected.items():
                    valid_key = isinstance(k, str) and _CAP.fullmatch(k)
                    raw.append({"field": "capabilities." + k if valid_key else "source_conditions", "equals": v,
                                "_locator": locator + ".capabilities." + k if valid_key else locator + ".capabilities"})
            else:
                raw.append({"field": key if key in {"exposed", "authenticated"} else "source_conditions", "equals": expected,
                            "_locator": locator + "." + key if key in {"exposed", "authenticated"} else locator})
    elif isinstance(value, (list, tuple)) and len(value) <= MAX_ITEMS:
        raw = list(value)
    else:
        warnings.append(f"{evidence_id}:{locator}: unsupported conditions; applicability unknown")
        return (_Condition("source_conditions", None, False, locator),)
    if len(raw) > MAX_ITEMS:
        return (_Condition("source_conditions", None, False, locator),)
    out = []
    for i, item in enumerate(raw):
        field = item.get("field") if isinstance(item, dict) else None
        expected = item.get("equals", item.get("value")) if isinstance(item, dict) else None
        supported = (isinstance(field, str) and (field in {"exposed", "authenticated"} or field.startswith("capabilities.") and bool(_CAP.fullmatch(field[13:])))
                     and isinstance(expected, bool) and set(item) <= ({"field", "equals", "value", "_locator"} if isinstance(value, dict) else {"field", "equals", "value"})
                     and ("equals" not in item or "value" not in item or item["equals"] == item["value"]))
        if not supported:
            warnings.append(f"{evidence_id}:{locator}[{i}]: unsupported condition; applicability unknown")
        actual_locator = item.get("_locator", locator + f"[{i}]") if isinstance(value, dict) else locator + f"[{i}]"
        out.append(_Condition(field if supported else "source_conditions", expected if supported else None, supported, actual_locator))
    return tuple(out)


def _condition_result(conditions: tuple[_Condition, ...], asset: dict) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    missing, unmet = [], []
    caps = asset.get("capabilities") if isinstance(asset.get("capabilities"), dict) else {}
    for c in conditions:
        actual = caps.get(c.field[13:]) if c.field.startswith("capabilities.") else asset.get(c.field)
        if not c.supported or not isinstance(actual, bool):
            missing.append(c.field)
        elif actual != c.expected:
            unmet.append(c.field)
    assertions: dict[str, set[bool]] = defaultdict(set)
    for c in conditions:
        if c.supported:
            assertions[c.field].add(c.expected)
    contradictory = [field for field, values in assertions.items() if len(values) > 1]
    if contradictory:
        missing.extend("conflicting_condition:" + field for field in contradictory)
    unsupported = bool(contradictory) or any(not c.supported for c in conditions)
    return ("unknown" if unsupported else "unmet" if unmet else "unknown" if missing else "met", tuple(dict.fromkeys(missing)), tuple(dict.fromkeys(unmet)))


def _range_claims(package: dict) -> Any:
    """Both accepted structured range fields contribute OR branches."""
    fields = [key for key in ("vulnerable_version_range", "ranges") if key in package]
    if len(fields) < 2:
        return package.get(fields[0]) if fields else None
    combined = []
    for key in fields:
        value = package[key]
        if isinstance(value, (list, tuple)):
            combined.extend(value)
        elif value is not None:
            combined.append(value)
    return combined


_BASE = {
    "2.0": {"AV": "LAN", "AC": "HML", "Au": "MSN", "C": "NPC", "I": "NPC", "A": "NPC"},
    "3.0": {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"},
    "3.1": {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"},
    "4.0": {"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN"},
}


def _cvss(raw: Any) -> dict | None:
    if not isinstance(raw, dict):
        return None
    vector = _text(raw.get("vector"), 256)
    declared = raw.get("version")
    if not isinstance(declared, str) or len(declared) > 16:
        declared = ""
    inferred = vector.split("/")[0][5:] if vector.startswith("CVSS:") else "2.0" if vector.startswith("AV:") else ""
    version = inferred if declared in {"cvss", "cvss_v3", "cvss_v4", ""} else declared
    version_consistent = declared not in {"cvss_v3", "cvss_v4"} or inferred in ({"3.0", "3.1"} if declared == "cvss_v3" else {"4.0"})
    version_consistent = version_consistent and (not inferred or version == inferred)
    metrics = {}
    valid = bool(vector and version in _BASE and version_consistent)
    for segment in (vector.split("/")[1:] if vector.startswith("CVSS:") else vector.split("/")):
        pair = segment.split(":")
        if len(pair) != 2 or pair[0] in metrics:
            valid = False
            continue
        metrics[pair[0]] = pair[1]
    base = _BASE.get(version, {})
    valid = valid and set(metrics) == set(base) and all(v in base[k] and len(v) == 1 for k, v in metrics.items() if k in base)
    score = raw.get("score")
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10 or not math.isfinite(score):
        score = None
    if not vector and score is None:
        return None
    return {"version": version or "unknown", "vector": vector or None, "score": score,
            "validation": "base_vector_syntax" if valid else "unvalidated_vector", "score_recomputed": False,
            "version_consistent": version_consistent, "metrics": metrics if valid else {},
            "type": _text(raw.get("type"), 30)}


@dataclass(frozen=True)
class _Package:
    evidence: Evidence
    locator: str
    identity: tuple[str, str]
    ranges: Any
    exact: Any
    scheme: str | None
    conditions: tuple[_Condition, ...]
    range_locator: str


def _relation(material: Evidence, target: Evidence) -> tuple[str, str, str] | None:
    target_ids = _ids(target)
    if _ids(material) & target_ids:
        locator = "upstream_id" if material.upstream_id.upper() in target_ids else "aliases[" + str(next(i for i, s in enumerate(material.aliases) if s.upper() in target_ids)) + "]"
        return "direct", "exact_defect_identifier", locator
    for key in ("defect_ids", "defect_evidence_ids"):
        raw = material.metadata.get(key, [])
        if isinstance(raw, (list, tuple)) and len(raw) <= MAX_ITEMS:
            if key == "defect_ids" and any(isinstance(s, str) and s.upper() in target_ids for s in raw):
                index = next(i for i, s in enumerate(raw) if isinstance(s, str) and s.upper() in target_ids)
                return "direct", "explicit_defect_identifier", f"metadata.defect_ids[{index}]"
            if key == "defect_evidence_ids" and target.id in raw:
                return "direct", "explicit_evidence_revision", f"metadata.defect_evidence_ids[{raw.index(target.id)}]"
    common = {s.lower() for s in material.components if isinstance(s, str)} & {s.lower() for s in target.components if isinstance(s, str)}
    if common:
        index = next(i for i, s in enumerate(material.components) if s.lower() in common)
        return "background", "component_similarity_only", f"components[{index}]"
    return None


def enrich(evidence: Sequence[Evidence], assets: Sequence[dict], related: Sequence[Evidence] = (), *, now: str | None = None) -> EnrichmentResult:
    """Enrich a single event from bounded, authorized projections.

    Exceeding top-level budgets fails closed, rather than producing a partial
    negative assessment. Inventory age threshold is 24 hours. No ``resolved``
    status is inferred because this API has no prior remediation verification.
    """
    for seq, limit, label in ((evidence, MAX_EVIDENCE, "evidence"), (related, MAX_RELATED, "related"), (assets, MAX_ASSETS, "assets")):
        if not isinstance(seq, (list, tuple)) or len(seq) > limit:
            raise ValueError(f"{label} exceeds bounded sequence contract")
    instant = datetime.now(timezone.utc) if now is None else _dt(now)
    if instant is None:
        raise ValueError("now must be an aware ISO8601 timestamp")
    warnings: list[str] = []
    primary, materials = _current(evidence, related, warnings)
    targets = [e for e in primary if e.kind == "vulnerability"]
    materials = sorted({e.id: e for e in (*materials, *primary) if e.kind in {"paper", "article", "standard", "policy"}}.values(), key=lambda e: e.id)
    facts: list[Fact] = []
    packages: list[_Package] = []
    invalid_packages: set[str] = set()

    def add(predicate, value, eids, *, status="valid", locator=None):
        if len(facts) >= MAX_FACTS:
            raise ValueError("Enrichment fact budget exceeded (256); no partial result")
        if locator is not None:
            value = dict(value, locator=locator)
        if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_FACT_VALUE_BYTES:
            raise ValueError("Enrichment fact value exceeds QA byte budget (8192); no partial result")
        facts.append(Fact(predicate, value, tuple(dict.fromkeys(eids)), status))

    for e in targets:
        raw_packages = e.metadata.get("packages", [])
        if not raw_packages or not isinstance(raw_packages, (list, tuple)) or len(raw_packages) > MAX_ITEMS:
            invalid_packages.add(e.id)
        for i, raw in enumerate(_items(raw_packages, e.id + ".packages", warnings)):
            locator = f"metadata.packages[{i}]"
            identity = _identity(raw.get("ecosystem"), raw.get("name")) if isinstance(raw, dict) else None
            if identity is None:
                invalid_packages.add(e.id)
                warnings.append(f"{e.id}:{locator}: package identity invalid; applicability unknown")
                continue
            ecosystem, name = identity
            conds = _conditions(e.metadata.get("conditions"), warnings, "metadata.conditions", e.id) + _conditions(raw.get("conditions"), warnings, locator + ".conditions", e.id)
            range_key = "vulnerable_version_range" if "vulnerable_version_range" in raw else "ranges" if "ranges" in raw else "exact_versions" if "exact_versions" in raw else None
            range_locator = locator + "." + range_key if range_key else locator
            packages.append(_Package(e, locator, identity, _range_claims(raw), raw.get("exact_versions", ()), raw.get("version_scheme"), conds, range_locator))
            add("affected_component", {"ecosystem": ecosystem, "name": name, "identity_precision": "package"}, (e.id,), locator=locator)
            # Raw ranges are not safety conclusions; use the same parser to safely
            # project its bounded raw ranges and show unsupported rule reasons.
            capability = match_version(None, packages[-1].ranges, ecosystem=ecosystem, exact_versions=packages[-1].exact, version_scheme=packages[-1].scheme)
            add("affected_range", {"ecosystem": ecosystem, "name": name, "ranges": [_text(r) for r in capability.raw_ranges],
                                   "exact_versions": [_text(v, 128) for v in raw.get("exact_versions", [])] if isinstance(raw.get("exact_versions"), (list, tuple)) and len(raw["exact_versions"]) <= 256 else [],
                                   "scheme": capability.scheme, "rule_version": capability.rule_version,
                                   "locators": [locator + "." + key for key in ("vulnerable_version_range", "ranges", "exact_versions") if key in raw]}, (e.id,), locator=range_locator)
            for c in conds:
                add("condition", {"ecosystem": ecosystem, "name": name, "field": c.field, "equals": c.expected, "supported": c.supported}, (e.id,), status="valid" if c.supported else "candidate", locator=c.locator)
            patched = raw.get("patched_versions")
            if isinstance(patched, str) and patched.strip():
                add("fix", {"ecosystem": ecosystem, "name": name, "patched_versions": _text(patched), "kind": "source_reported_patch",
                            "verification": "not_tested", "conditions": [{"field": c.field, "equals": c.expected, "supported": c.supported, "locator": c.locator} for c in conds]}, (e.id,), status="valid" if all(c.supported for c in conds) else "candidate", locator=locator + ".patched_versions")
        if not raw_packages and e.components:
            for i, component in enumerate(e.components):
                add("affected_component", {"name": _text(component, 1024), "identity_precision": "cpe_unmapped" if isinstance(component, str) and component.startswith("cpe:") else "unmapped"}, (e.id,), status="candidate", locator=f"components[{i}]")
        for i, score in enumerate(_items(e.metadata.get("cvss", []), e.id + ".cvss", warnings)):
            value = _cvss(score)
            if value is not None:
                add("cvss", value, (e.id,), status="valid" if value["validation"] == "base_vector_syntax" else "candidate", locator=f"metadata.cvss[{i}]")
                if value["metrics"]:
                    add("impact", {"scope": "source_cvss_base_metrics", "version": value["version"], "metrics": value["metrics"], "confirmed_exploitation": False}, (e.id,), locator=f"metadata.cvss[{i}].vector")
        for i, cwe in enumerate(_items(e.metadata.get("cwes", []), e.id + ".cwes", warnings)):
            if isinstance(cwe, str) and re.fullmatch(r"CWE-\d{1,8}", cwe):
                add("weakness", {"cwe_id": cwe}, (e.id,), locator=f"metadata.cwes[{i}]")
        for i, fix in enumerate(_items(e.metadata.get("fixes", []), e.id + ".fixes", warnings)):
            if not isinstance(fix, dict) or not isinstance(fix.get("kind"), str) or fix["kind"] not in {"patch", "mitigation", "workaround"}:
                warnings.append(f"{e.id}:metadata.fixes[{i}]: unsupported repair card")
                continue
            value = {k: _text(fix.get(k)) for k in ("description", "ecosystem", "name", "patched_versions") if isinstance(fix.get(k), str)}
            if not value.get("description") and not value.get("patched_versions"):
                continue
            url = _public_url(fix.get("url"))
            if url:
                value["url"] = url
            conds = _conditions(fix.get("conditions"), warnings, f"metadata.fixes[{i}].conditions", e.id)
            value.update(kind=fix["kind"], verification="not_tested", conditions=[{"field": c.field, "equals": c.expected, "supported": c.supported} for c in conds])
            add("fix", value, (e.id,), status="valid" if all(c.supported for c in conds) else "candidate", locator=f"metadata.fixes[{i}]")

    # Keep each source score; disagreements are surfaced, never averaged.
    cvss_by_version: dict[str, list[Fact]] = defaultdict(list)
    for f in facts:
        if f.predicate == "cvss":
            cvss_by_version[f.value["version"]].append(f)
    for version, entries in cvss_by_version.items():
        if len({(f.value["score"], f.value["vector"]) for f in entries}) > 1:
            warnings.append(f"CVSS {version}: source assertions disagree; retained separately")
            for f in entries:
                f.value["conflict"] = True

    for material in materials:
        for target in targets:
            relation = _relation(material, target)
            if relation is not None:
                add("related_material", {"material_evidence_id": material.id, "target_evidence_id": material.id, "advisory_evidence_id": target.id, "relation": relation[0], "basis": relation[1],
                                         "kind": material.kind, "title": _text(material.title), "url": _public_url(material.url) or None,
                                         "scope": "provided_metadata_only", "locator_evidence_id": material.id}, (material.id, target.id), status="valid" if relation[0] == "direct" else "candidate", locator=relation[2])

    for e in (*targets, *materials):
        for i, poc in enumerate(_items(e.metadata.get("poc_references", []), e.id + ".poc_references", warnings)):
            if not isinstance(poc, dict):
                continue
            url = _public_url(poc.get("url"))
            if not url:
                warnings.append(f"{e.id}:metadata.poc_references[{i}]: unsafe URL omitted")
                continue
            target_ids = [t.id for t in targets if t.id == e.id or _relation(e, t) and _relation(e, t)[0] == "direct"]
            add("poc_reference", {"url": url, "publisher": _text(poc.get("publisher"), 128) or None, "license": _text(poc.get("license"), 128) or None,
                                  "reference_class": _text(poc.get("class",poc.get("reference_class")),128) or None,
                                  "basis": _text(poc.get("basis"),256) or None,
                                  "upstream_tags": [_text(t,128) for t in poc.get("upstream_tags",[])[:32] if isinstance(t,str)] if isinstance(poc.get("upstream_tags"),list) else [],
                                  "upstream_source": _text(poc.get("upstream_source"),256) or None,
                                  "availability": "not_checked", "verification": "unverified", "downloaded": False, "executed": False,
                                  "target_evidence_ids": target_ids, "relation": "direct" if target_ids else "unestablished"}, (e.id, *target_ids), status="candidate", locator=f"metadata.poc_references[{i}]")

    assessments: list[Assessment] = []
    seen_assets = set()
    for asset in assets:
        if not isinstance(asset, dict) or len(asset) > 32 or not isinstance(asset.get("asset_id"), str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", asset["asset_id"]) or asset["asset_id"] in seen_assets:
            raise ValueError("Inventory asset identity invalid or duplicated")
        seen_assets.add(asset["asset_id"])
        if not isinstance(asset.get("capabilities", {}), dict) or len(asset.get("capabilities", {})) > MAX_ITEMS:
            raise ValueError("Inventory capabilities exceed bounds")
        identity = _identity(asset.get("ecosystem"), asset.get("component"))
        relevant = [p for p in packages if identity is not None and p.identity == identity]
        observed = _dt(asset.get("observed_at"))
        stale = observed is None or observed > instant or instant - observed > INVENTORY_MAX_AGE
        reasons = ["仅评估已提供的授权资产清单，未扫描或确认利用。"]
        missing = []
        if stale:
            missing.append("inventory.observed_at")
            reasons.append("资产清单时间缺失、异常或超过24小时，当前状态需重新核实。")
        positive, unknown, per_source, support = [], [], defaultdict(set), []
        for p in relevant:
            match = match_version(asset.get("version"), p.ranges, ecosystem=p.identity[0], exact_versions=p.exact, version_scheme=p.scheme)
            condition = _condition_result(p.conditions, asset)
            per_source[p.evidence.id].add(match.status)
            support.append(p.evidence.id)
            if match.status == "affected":
                positive.append(condition)
            elif match.status == "unknown":
                unknown.append(match)
            missing.extend(condition[1] if match.status != "not_in_range" else ())
        if positive:
            version_match = "affected"
            reasons.append("至少一个明确受影响范围命中；版本命中不证明已被攻击。")
            if any(c[0] == "met" for c in positive):
                status = "potentially_affected"
            elif all(c[0] == "unmet" for c in positive) and not unknown:
                status = "not_affected_with_reason"
                reasons.append("当前清单中来源要求的适用条件不满足：" + ", ".join(sorted({x for c in positive for x in c[2]})))
            else:
                status = "under_investigation"
                reasons.append("配置前提缺失或其他版本范围无法判定。")
        elif relevant and not unknown and not invalid_packages:
            version_match, status = "not_in_range", "not_affected_with_reason"
            reasons.append("已支持的同一组件范围全部未命中，仅适用于该来源范围。")
        elif packages and not relevant and identity is not None and not invalid_packages:
            version_match, status = "not_in_range", "not_affected_with_reason"
            support.extend(p.evidence.id for p in packages)
            reasons.append("资产包名与生态未匹配公告中的组件；客户端与服务端身份分开。")
        else:
            version_match, status = "unknown", "under_investigation"
            missing.append("version_or_component_mapping")
            support.extend(e.id for e in targets)
            reasons.append("没有可确认的组件映射、版本或可支持的完整范围；CPE名称不证明安装身份。")
        if unknown:
            reasons.append("部分版本规则不受支持，保留unknown；明确命中的范围优先。")
        source_results = {eid: "affected" if "affected" in values else "unknown" if "unknown" in values else "not_in_range" for eid, values in per_source.items()}
        if "affected" in source_results.values() and "not_in_range" in source_results.values():
            reasons.append("不同来源的受影响范围对该版本存在分歧，需核实。")
            warnings.append(f"asset:{asset['asset_id']}: source range disagreement")
            status = "under_investigation"
        if invalid_packages:
            reasons.append("来源含未能完整处理的组件声明，不能据此排除影响。")
            support.extend(sorted(invalid_packages))
            if status == "not_affected_with_reason":
                version_match, status = "affected" if positive else "unknown", "under_investigation"
        if stale:
            status = "under_investigation"
        missing = list(dict.fromkeys(missing))
        if len(missing) > 32 or len(reasons) > 32 or any(len(reason) > 1024 for reason in reasons):
            raise ValueError("Enrichment assessment exceeds QA condition/reason budget; no partial result")
        assessments.append(Assessment(asset["asset_id"], version_match, status, tuple(reasons), tuple(dict.fromkeys(support)), tuple(missing)))

        # Generic AI modes are capability hypotheses independent of CVE matching.
        # Source IDs provide advisory context only, never capability proof.
        if asset.get("capabilities"):
            caps = asset.get("capabilities", {})
            patterns = (
                ("prompt_injection_tool_abuse", (("external_documents", "tools"), ("untrusted_inputs", "tool_execution"))),
                ("retrieval_content_poisoning", (("external_documents", "rag"), ("untrusted_inputs", "retrieval"))),
                ("tool_network_egress", (("tools", "network"),)),
                ("tool_write_abuse", (("tools", "write_access"),)),
                ("sensitive_data_exposure", (("untrusted_inputs", "sensitive_data"),)),
                ("untrusted_model_loading", (("loads_untrusted_models",),)),
            )
            for pattern, alternatives in patterns:
                required = next((required for required in alternatives if all(caps.get(k) is True for k in required)), None)
                if required is not None:
                    add("risk_pattern", {"asset_id": asset["asset_id"], "pattern": pattern, "basis": "asset_declared_capabilities",
                                         "capabilities": {k: True for k in required}, "asset_snapshot_id": asset.get("snapshot_id") if isinstance(asset.get("snapshot_id"), int) else None,
                                         "observed_at": observed.isoformat() if observed else None, "stale": stale, "confirmed_vulnerability": False,
                                         "evidence_role": "advisory_context_only" if support else "no_advisory_context"}, tuple(dict.fromkeys(support)), status="candidate", locator="inventory.capabilities")
    result = EnrichmentResult(tuple(facts), tuple(assessments), tuple(dict.fromkeys(warnings)))
    if len(json.dumps(result.to_dict(), ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_RESULT_BYTES:
        raise ValueError("Enrichment result exceeds publication byte budget; no partial result")
    return result
