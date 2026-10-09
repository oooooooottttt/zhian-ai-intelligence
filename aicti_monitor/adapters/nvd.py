"""Bounded NVD CVE API 2.0 monitoring with restartable windows.

``keywords`` is an OR list of independently paginated keyword searches. Previously
observed CVEs are also refreshed by ID: rejection can remove the original keyword.
The returned cursor must be committed atomically with its records by the runner.
"""
from __future__ import annotations

import copy
import ipaddress
import math
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit, urlunsplit

from aicti_monitor.models import FetchBudgetExceeded, FetchError, FetchResult, Record, SourceConfig

if TYPE_CHECKING:
    from aicti_monitor.http import HttpClient

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TERMS_URL = "https://nvd.nist.gov/developers/start-here"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)
_ALIAS = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[A-Za-z0-9]{4}(?:-[A-Za-z0-9]{4}){2}|OSV-[A-Za-z0-9._-]+)", re.ASCII)
_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SECRET_KEYS = re.compile(r"token|password|passwd|secret|api.?key|authorization|signature|credential|session|bearer|jwt|^auth$|^key$", re.I)


def _dt(value: Any, label: str = "date") -> datetime:
    if not isinstance(value, str):
        raise FetchError(f"Invalid {label}")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # NVD's documented JSON timestamps are UTC without a suffix.
        return (result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise FetchError(f"Invalid {label}") from exc


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FetchError("now must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _date(value: Any) -> str | None:
    return None if value is None else _utc(_dt(value))


def _public_url(value: Any) -> str:
    """Reject credentialed/unsafe reference URLs; actual fetch DNS checks are HTTP's job."""
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 33 for c in value):
        return ""
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme not in ("http", "https") or not host or parts.username is not None or parts.password is not None:
            return ""
        if parts.port not in (None, 80, 443) or "\\" in value or "%" in host or _EMAIL.search(unquote(value)):
            return ""
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal")) or "." not in host and ":" not in host:
            return ""
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global or address.is_multicast:
                return ""
        except ValueError:
            try:
                # inet_aton only parses literals; it does not perform a DNS query.
                address = ipaddress.ip_address(socket.inet_aton(host))
                if not address.is_global or address.is_multicast:
                    return ""
            except OSError:
                if not re.fullmatch(r"[a-z0-9.-]+", host) or re.fullmatch(r"[0-9.]+", host):
                    return ""
        if any(_SECRET_KEYS.search(key) for key in parse_qs(parts.query, keep_blank_values=True)):
            return ""
        if host == "api.github.com" and parts.path.startswith("/users/"):
            return ""
        if host == "github.com" and len([s for s in parts.path.split("/") if s]) < 2:
            return ""
        return urlunsplit(parts)
    except (ValueError, UnicodeError):
        return ""


def _text(value: Any, limit: int = 4000) -> str:
    if not isinstance(value, str):
        return ""
    value = _EMAIL.sub("[email omitted]", value)
    value = re.sub(r"https?://[^\s<>\"']+", lambda m: m.group(0) if _public_url(m.group(0)) else "[URL omitted]", value)
    value = re.sub(r"(?i)\b(?:api[_-]?key|access[_-]?token|password|authorization|secret)\s*[:=]\s*[^\s,;]+", "[credential omitted]", value)
    return "".join(c for c in value if c in "\n\t" or ord(c) >= 32)[:limit]


def _integer(value: Any, low: int, high: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise FetchError(f"Invalid {label}")
    return value


def _endpoint(source: SourceConfig, host: str, path_pattern: str) -> str:
    value = _public_url(source.endpoint)
    parts = urlsplit(value)
    if (not value or parts.scheme != "https" or parts.hostname != host or parts.port not in (None, 443)
            or host not in source.allowed_hosts or parts.query or parts.fragment or not re.fullmatch(path_pattern, parts.path)):
        raise FetchError("Adapter requires an allowlisted official API endpoint without query or credentials")
    if source.content_scope not in {"metadata_only", "public_advisory"}:
        raise FetchError("Unsupported vulnerability content scope")
    return value.rstrip("/")


def _json_response(http: HttpClient, url: str, headers: dict[str, str], now: datetime) -> tuple[Any, Any]:
    response = http.get(url, headers=headers)
    if response.status != 200:
        retry = None
        raw = response.headers.get("retry-after")
        try:
            if raw is not None:
                try:
                    retry = max(0.0, float(raw))
                except ValueError:
                    retry = max(0.0, (parsedate_to_datetime(raw) - now).total_seconds())
            elif response.headers.get("x-ratelimit-remaining") == "0":
                retry = max(0.0, float(response.headers["x-ratelimit-reset"]) - now.timestamp())
        except (ValueError, TypeError, KeyError, OverflowError):
            pass
        if response.status in (403, 429) and retry is None:
            retry = 60.0
        # Do not put upstream bodies, request URLs, or authorization in errors.
        raise FetchError(f"Official vulnerability API returned HTTP {response.status}", status=response.status, retry_after=retry)
    try:
        return response.json(), response
    except (ValueError, UnicodeError) as exc:
        raise FetchError("Malformed vulnerability API JSON") from exc


def _cooldown(cursor: dict[str, Any], state: dict[str, Any], now: datetime) -> None:
    if cursor.get("retry_not_before"):
        deadline = _dt(cursor["retry_not_before"], "rate-limit deadline")
        if deadline > now:
            raise FetchError("Official API rate-limit cooldown is still active", retry_after=(deadline - now).total_seconds())


def _defer_if_limited(response: Any, state: dict[str, Any], now: datetime) -> bool:
    """Commit a processed successful page, then stop before spending a zero quota."""
    if response.headers.get("x-ratelimit-remaining") != "0":
        return False
    try:
        reset = float(response.headers.get("x-ratelimit-reset", now.timestamp() + 60))
        if not math.isfinite(reset):
            raise ValueError()
        deadline = datetime.fromtimestamp(max(reset, now.timestamp() + 1), timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise FetchError("Invalid official API rate-limit reset") from exc
    state["retry_not_before"] = _utc(deadline)
    return True


def _strings(value: Any, label: str, limit: int = 1000) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or len(value) > limit or any(not isinstance(v, str) or not v.strip() or len(v) > 256 for v in value):
        raise FetchError(f"Invalid {label}")
    return list(dict.fromkeys(v.strip() for v in value))


def _tracked(cursor: dict[str, Any], pattern: re.Pattern[str]) -> list[str]:
    values = cursor.get("tracked_ids", [])
    if not isinstance(values, list) or any(not isinstance(v, str) or not pattern.fullmatch(v) for v in values):
        raise FetchError("Invalid tracked vulnerability IDs")
    return list(dict.fromkeys(values))


def _window(source: SourceConfig, cursor: dict[str, Any], now: datetime) -> tuple[str, str]:
    overlap = _integer(source.params.get("overlap_seconds", 300), 0, 86400, "overlap_seconds")
    days = _integer(source.params.get("window_days", 30), 2, 119, "window_days")
    if cursor.get("committed_end"):
        start = _dt(cursor["committed_end"], "committed_end") - timedelta(seconds=overlap)
    elif source.params.get("initial_start"):
        start = _dt(source.params["initial_start"], "initial_start")
    else:
        lookback = _integer(source.params.get("lookback_days", 1), 1, 36500, "lookback_days")
        start = now - timedelta(days=lookback)
    if start > now or (cursor.get("committed_end") and _dt(cursor["committed_end"]) > now):
        raise FetchError("Monitoring cursor starts after now")
    return _utc(start), _utc(min(now, start + timedelta(days=days)))


def _provenance(source: SourceConfig, collected_at: datetime | None, attribution: str, default_terms: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "attribution": attribution, "source_url": _public_url(source.endpoint),
        "terms_url": _public_url(source.terms_url) or default_terms,
        "content_scope": source.content_scope,
    }
    if collected_at is not None:
        metadata["collected_at"] = _utc(collected_at)
    return metadata


def parse(source: SourceConfig, payload: Any, collected_at: datetime | None = None) -> list[Record]:
    """Pure normalizer for an NVD API page; no URLs in references are fetched."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise FetchError("Malformed NVD vulnerability page")
    records: list[Record] = []
    for item in payload["vulnerabilities"]:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            raise FetchError("Malformed NVD CVE entry")
        cve = item["cve"]
        identifier = cve.get("id")
        if not isinstance(identifier, str) or not _CVE.fullmatch(identifier):
            raise FetchError("Invalid NVD CVE identifier")
        descriptions = cve.get("descriptions", [])
        if not isinstance(descriptions, list):
            raise FetchError("Invalid NVD descriptions")
        description = next((v.get("value", "") for v in descriptions if isinstance(v, dict) and v.get("lang") == "en"), "")
        if not description:
            description = next((v.get("value", "") for v in descriptions if isinstance(v, dict)), "")
        status = _text(cve.get("vulnStatus"), 100)
        metadata = _provenance(source, collected_at, "NIST National Vulnerability Database (NVD)", TERMS_URL)
        metadata.update({"upstream_revision": _date(cve.get("lastModified")), "status": status,
                         "withdrawn": status.lower() == "rejected",
                         "usage_conditions": "Preserve NVD attribution and disclaimer; upstream references retain their own rights.",
                         "disclaimer": "This product uses the NVD API but is not endorsed or certified by the NVD."})
        from .poc_metadata import extract_poc_references, extract_tagged_reference_leads
        try:
            upstream_references = cve.get("references", [])
            metadata["poc_references"] = extract_poc_references(upstream_references)
            metadata["tagged_reference_leads"] = extract_tagged_reference_leads(upstream_references)
            metadata["poc_scope"] = "explicit upstream POC tags only; max 128 references and 64 leads; unverified, not fetched"
        except ValueError as exc:
            raise FetchError("Invalid bounded upstream reference metadata") from exc
        metrics = []
        raw_metrics = cve.get("metrics", {})
        if isinstance(raw_metrics, dict):
            for name in ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"):
                for metric in raw_metrics.get(name, []) if isinstance(raw_metrics.get(name, []), list) else []:
                    if not isinstance(metric, dict) or not isinstance(metric.get("cvssData"), dict):
                        continue
                    data = metric["cvssData"]
                    normalized = {"version": _text(data.get("version"), 10), "vector": _text(data.get("vectorString"), 256), "type": _text(metric.get("type"), 30)}
                    score = data.get("baseScore")
                    if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
                        normalized["score"] = score
                    normalized["severity"] = _text(data.get("baseSeverity", metric.get("baseSeverity")), 30)
                    metrics.append(normalized)
        metadata["cvss"] = metrics
        weaknesses = cve.get("weaknesses", [])
        if not isinstance(weaknesses, list):
            raise FetchError("Invalid NVD weaknesses")
        cwes = set()
        for weakness in weaknesses:
            if not isinstance(weakness, dict) or not isinstance(weakness.get("description", []), list):
                raise FetchError("Invalid NVD weakness entry")
            for value in weakness.get("description", []):
                if isinstance(value, dict) and isinstance(value.get("value"), str) and re.fullmatch(r"CWE-\d+", value["value"]):
                    cwes.add(value["value"])
        metadata["cwes"] = sorted(cwes)
        components: list[str] = []
        stack = list(cve.get("configurations", [])) if isinstance(cve.get("configurations", []), list) else []
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for key in ("nodes", "children"):
                if isinstance(node.get(key), list):
                    stack.extend(node[key])
            for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch", []), list) else []:
                if isinstance(match, dict) and match.get("vulnerable") is True and isinstance(match.get("criteria"), str):
                    components.append(_text(match["criteria"], 1024))
        refs = cve.get("references", [])
        references = sorted({_public_url(v.get("url")) for v in refs if isinstance(v, dict)} - {""}) if isinstance(refs, list) else []
        summary = _text(description, 4000 if source.content_scope == "public_advisory" else 500)
        records.append(Record(source.id, identifier, "vulnerability", identifier, summary,
                              f"https://nvd.nist.gov/vuln/detail/{identifier}",
                              _date(cve.get("published")), _date(cve.get("lastModified")),
                              [identifier], sorted(set(components)), references, metadata))
    return records


def _restart_term(pending: dict[str, Any]) -> None:
    pending.update(start_index=0, term_total=None, term_first_id=None,
                   term_anchor=None, term_pages=0, verify=False)


def _finish_term(pending: dict[str, Any]) -> None:
    pending["term_index"] += 1
    _restart_term(pending)


def fetch(source: SourceConfig, cursor: dict[str, Any], http: HttpClient, now: datetime) -> FetchResult:
    endpoint = _endpoint(source, "services.nvd.nist.gov", r"/rest/json/cves/2\.0/?")
    now = _dt(_utc(now))
    state = copy.deepcopy(cursor or {})
    tracked = _tracked(state, _CVE)
    state = {"version": 1, "tracked_ids": tracked, **({"committed_end": _utc(_dt(state["committed_end"]))} if state.get("committed_end") else {})}
    _cooldown(cursor or {}, state, now)
    incoming = (cursor or {}).get("pending")
    if incoming:
        if not isinstance(incoming, dict):
            raise FetchError("Invalid NVD pending cursor")
        pending = copy.deepcopy(incoming)
        _dt(pending.get("window_start")); _dt(pending.get("window_end"))
        if _dt(pending["window_end"]) > now or _dt(pending["window_end"]) < _dt(pending["window_start"]) or _dt(pending["window_end"]) - _dt(pending["window_start"]) > timedelta(days=120):
            raise FetchError("Invalid NVD pending time window")
        pending["keywords"] = _strings(pending.get("keywords"), "pending keywords", 100)
        _integer(pending.get("term_index"), 0, len(pending["keywords"]), "term_index")
        _integer(pending.get("start_index"), 0, 2**63 - 1, "start_index")
        _integer(pending.get("page_size"), 1, 2000, "page_size")
        refresh_ids = _tracked({"tracked_ids": pending.get("refresh_ids", [])}, _CVE)
        _integer(pending.get("refresh_index"), 0, len(refresh_ids), "refresh_index")
        if not isinstance(pending.get("exact_match"), bool):
            raise FetchError("Invalid exact_match")
        pending = {k: pending[k] for k in ("window_start", "window_end", "keywords", "term_index", "start_index", "page_size", "exact_match", "refresh_index")}
        pending["refresh_ids"] = refresh_ids
        # A legacy offset-only cursor has no continuity proof; restart its term.
        for key, default in (("term_total", None), ("term_first_id", None), ("term_anchor", None),
                             ("term_pages", 0), ("verify", False), ("last_response_at", None)):
            pending[key] = incoming.get(key, default)
        if pending["term_total"] is not None:
            _integer(pending["term_total"], 0, 2**63 - 1, "pending total")
        for key in ("term_first_id", "term_anchor"):
            if pending[key] is not None and (not isinstance(pending[key], str) or not _CVE.fullmatch(pending[key])):
                raise FetchError("Invalid NVD pagination anchor")
        _integer(pending["term_pages"], 0, 2**63 - 1, "term_pages")
        if not isinstance(pending["verify"], bool):
            raise FetchError("Invalid NVD final verification flag")
        if pending["last_response_at"] is not None:
            pending["last_response_at"] = _date(pending["last_response_at"])
        if "term_total" not in incoming and pending["start_index"]:
            _restart_term(pending)
    else:
        keywords = source.params.get("keywords", source.params.get("keyword_search", source.params.get("keywordSearch", [])))
        keywords = _strings(keywords, "keywords", 100)
        if not keywords:
            raise FetchError("NVD monitoring requires configured keyword scope")
        start, end = _window(source, state, now)
        exact = source.params.get("keyword_exact_match", False)
        if not isinstance(exact, bool):
            raise FetchError("Invalid keyword_exact_match")
        pending = {"window_start": start, "window_end": end, "keywords": keywords, "term_index": 0,
                   "start_index": 0, "page_size": _integer(source.params.get("results_per_page", 2000), 1, 2000, "results_per_page"),
                   "exact_match": exact, "refresh_ids": tracked.copy(), "refresh_index": 0}
        _restart_term(pending)
        pending["last_response_at"] = None
    state["pending"] = pending
    headers = {"Accept": "application/json"}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    records: dict[str, Record] = {}
    while pending["term_index"] < len(pending["keywords"]) or pending["refresh_index"] < len(pending["refresh_ids"]):
        refreshing = pending["term_index"] == len(pending["keywords"])
        if len(records) + (1 if refreshing else pending["page_size"]) > 10000:
            return FetchResult(list(records.values()), state, complete=False)
        if refreshing:
            query: dict[str, Any] = {"cveId": pending["refresh_ids"][pending["refresh_index"]]}
        else:
            # Repeat the last row of the preceding page. If the offset shifted,
            # its ID no longer occupies this position and the term must restart.
            requested_size = 1 if pending["verify"] else max(2, pending["page_size"]) if pending["term_anchor"] else pending["page_size"]
            query = {"lastModStartDate": pending["window_start"], "lastModEndDate": pending["window_end"],
                     "resultsPerPage": requested_size, "startIndex": 0 if pending["verify"] else pending["start_index"],
                     "keywordSearch": pending["keywords"][pending["term_index"]]}
            if pending["exact_match"]:
                query["keywordExactMatch"] = ""
        try:
            payload, response = _json_response(http, endpoint + "?" + urlencode(query), headers, now)
        except FetchBudgetExceeded:
            return FetchResult(list(records.values()), state, complete=False)
        # Store records each run's collection time separately. Keep the semantic
        # record stable so polling an unchanged page does not create a revision.
        page = parse(source, payload)
        total = _integer(payload.get("totalResults"), 0, 2**63 - 1, "NVD totalResults")
        offset = _integer(payload.get("startIndex"), 0, 2**63 - 1, "NVD startIndex")
        size = _integer(payload.get("resultsPerPage"), 0, 2000, "NVD resultsPerPage")
        if len(page) > size or (page and offset + len(page) > total) or (not refreshing and (offset != query["startIndex"] or len(page) > requested_size)) or (not page and total > offset):
            raise FetchError("NVD pagination response does not make progress")
        if refreshing and (total > 1 or any(r.upstream_id != query["cveId"] for r in page)):
            raise FetchError("NVD ID lookup returned unrelated CVEs")
        if len({r.upstream_id for r in page}) != len(page):
            raise FetchError("NVD page contains duplicate CVE IDs")
        pending["last_response_at"] = _date(payload.get("timestamp"))
        drifted = False
        if not refreshing:
            drifted = pending["term_total"] is not None and total != pending["term_total"]
            if pending["verify"]:
                drifted = drifted or not page or page[0].upstream_id != pending["term_first_id"]
            elif pending["term_anchor"]:
                drifted = drifted or not page or page[0].upstream_id != pending["term_anchor"]
        for record in page:
            record.metadata["filter_explanation"] = "New CVEs use configured OR keyword searches; previously observed CVEs are refreshed by exact ID"
            record.metadata["keyword_scope"] = pending["keywords"].copy()
            previous = records.get(record.upstream_id)
            if previous is None or (record.updated_at or "") >= (previous.updated_at or ""):
                records[record.upstream_id] = record
            if record.upstream_id not in tracked:
                tracked.append(record.upstream_id)
        limited = _defer_if_limited(response, state, now)
        if refreshing:
            pending["refresh_index"] += 1
        elif drifted:
            # Previously parsed records remain valid observations. Re-run this
            # whole keyword before a window can be committed; never skip ahead.
            _restart_term(pending)
            return FetchResult(list(records.values()), state, complete=False)
        elif pending["verify"]:
            _finish_term(pending)
        else:
            if pending["term_total"] is None:
                pending["term_total"] = total
                pending["term_first_id"] = page[0].upstream_id if page else None
            pending["term_pages"] += 1
            if offset + len(page) >= total:
                if pending["term_pages"] > 1:
                    # NVD does not expose a snapshot token. Check the final
                    # total and the first-page anchor before finishing the term.
                    pending["verify"] = True
                    pending["start_index"] = 0
                else:
                    _finish_term(pending)
            else:
                if pending["term_anchor"] and len(page) < 2:
                    raise FetchError("NVD overlapping page does not make progress")
                pending["start_index"] = offset + len(page) - 1
                pending["term_anchor"] = page[-1].upstream_id
        if limited and (pending["term_index"] < len(pending["keywords"]) or pending["refresh_index"] < len(pending["refresh_ids"])):
            return FetchResult(list(records.values()), state, complete=False)
    state.pop("pending")
    state["committed_end"] = pending["window_end"]
    return FetchResult(list(records.values()), state, complete=_dt(pending["window_end"]) >= now)
