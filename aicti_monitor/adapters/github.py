"""Official public GitHub global and repository security advisory monitoring."""
from __future__ import annotations

import copy
import os
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlsplit

from aicti_monitor.models import FetchBudgetExceeded, FetchError, FetchResult, Record, SourceConfig
from aicti_monitor.adapters.nvd import (
    _ALIAS, _cooldown, _date, _defer_if_limited, _dt, _endpoint, _integer, _json_response, _provenance,
    _public_url, _strings, _text, _tracked, _utc, _window,
)

if TYPE_CHECKING:
    from aicti_monitor.http import HttpClient

API_VERSION = "2026-03-10"
TERMS_URL = "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service"
LICENSE_URL = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
_GHSA = re.compile(r"GHSA-[A-Za-z0-9]{4}(?:-[A-Za-z0-9]{4}){2}", re.ASCII)


def _modified_range(start: str, end: str) -> str:
    """GitHub rejects fractional seconds; broaden to inclusive whole seconds."""
    lower = _dt(start).replace(microsecond=0)
    upper = _dt(end)
    if upper.microsecond:
        upper = upper.replace(microsecond=0) + timedelta(seconds=1)
    return lower.strftime("%Y-%m-%dT%H:%M:%SZ") + ".." + upper.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(source: SourceConfig, payload: Any, collected_at: datetime | None = None) -> list[Record]:
    """Normalize an API list, keeping allowlisted security fields only."""
    if not isinstance(payload, list):
        raise FetchError("Malformed GitHub advisory page")
    records = []
    repository = source.adapter == "github_repository"
    for advisory in payload:
        if not isinstance(advisory, dict):
            raise FetchError("Malformed GitHub advisory entry")
        identifier = advisory.get("ghsa_id")
        if not isinstance(identifier, str) or not _GHSA.fullmatch(identifier):
            raise FetchError("Invalid GitHub advisory identifier")
        # Even a privileged fake/client response must not ingest drafts/closed submissions.
        if repository and (advisory.get("state") != "published" or not advisory.get("published_at")):
            continue
        metadata = _provenance(source, collected_at, "GitHub Security Advisories", TERMS_URL)
        metadata.update({"upstream_revision": _date(advisory.get("updated_at")),
                         "severity": _text(advisory.get("severity"), 30),
                         "withdrawn_at": _date(advisory.get("withdrawn_at")),
                         "withdrawn": bool(advisory.get("withdrawn_at")),
                         "state": "published" if repository else _text(advisory.get("type"), 30),
                         "usage_conditions": "Preserve attribution and source terms; linked third-party content retains its own rights."})
        if not repository:
            metadata["license"] = "CC-BY-4.0"
            metadata["license_url"] = LICENSE_URL
        else:
            metadata["usage_conditions"] = "Public repository advisory metadata/excerpt only; no inferred redistribution license. Preserve repository/source terms."
        aliases = {identifier}
        if isinstance(advisory.get("cve_id"), str) and _ALIAS.fullmatch(advisory["cve_id"]):
            aliases.add(advisory["cve_id"])
        for alias in advisory.get("identifiers", []) if isinstance(advisory.get("identifiers", []), list) else []:
            if isinstance(alias, dict) and isinstance(alias.get("value"), str) and _ALIAS.fullmatch(alias["value"]):
                aliases.add(alias["value"])
        packages = []
        for vulnerable in advisory.get("vulnerabilities", []) if isinstance(advisory.get("vulnerabilities", []), list) else []:
            if not isinstance(vulnerable, dict) or not isinstance(vulnerable.get("package"), dict):
                continue
            package = vulnerable["package"]
            entry = {"ecosystem": _text(package.get("ecosystem"), 80), "name": _text(package.get("name"), 256),
                     "vulnerable_version_range": _text(vulnerable.get("vulnerable_version_range"), 512),
                     "patched_versions": _text(vulnerable.get("patched_versions", vulnerable.get("first_patched_version")), 512)}
            if entry["name"]:
                packages.append(entry)
        metadata["packages"] = packages
        cwes = advisory.get("cwes", [])
        if not isinstance(cwes, list):
            raise FetchError("Invalid GitHub CWEs")
        metadata["cwes"] = sorted({v["cwe_id"] for v in cwes if isinstance(v, dict) and isinstance(v.get("cwe_id"), str) and re.fullmatch(r"CWE-\d+", v["cwe_id"])})
        cvss = []
        raw_scores = advisory.get("cvss_severities", {})
        if not isinstance(raw_scores, dict):
            raw_scores = {}
        raw_scores = dict(raw_scores)
        if isinstance(advisory.get("cvss"), dict):
            raw_scores.setdefault("cvss", advisory["cvss"])
        for version, score in raw_scores.items():
            if version not in {"cvss", "cvss_v3", "cvss_v4"} or not isinstance(score, dict):
                continue
            entry = {"version": version, "vector": _text(score.get("vector_string"), 256)}
            if isinstance(score.get("score"), (int, float)) and not isinstance(score["score"], bool) and 0 <= score["score"] <= 10:
                entry["score"] = score["score"]
            cvss.append(entry)
        metadata["cvss"] = cvss
        refs = advisory.get("references", [])
        references = sorted({_public_url(v.get("url") if isinstance(v, dict) else v) for v in refs} - {""}) if isinstance(refs, list) else []
        url = _public_url(advisory.get("html_url"))
        if not url or urlsplit(url).hostname != "github.com":
            url = "https://github.com/advisories/" + identifier
        summary = _text(advisory.get("summary"), 500)
        # Repository licenses vary: avoid retaining the full markdown description.
        detail_limit = 4000 if not repository and source.content_scope == "public_advisory" else 500
        detail = _text(advisory.get("description"), detail_limit)
        records.append(Record(source.id, identifier, "vulnerability", summary or identifier, detail or summary, url,
                              _date(advisory.get("published_at")), _date(advisory.get("updated_at")),
                              sorted(aliases), sorted({v["name"] for v in packages}), references, metadata))
    return records


def _next_after(link: str, endpoint: str, query: dict[str, str]) -> str | None:
    next_links = []
    for match in re.finditer(r'<([^<>]+)>\s*((?:;\s*[^,]+)*)', link):
        if re.search(r';\s*rel\s*=\s*["\']?next(?:["\']|\s|;|$)', match.group(2), re.I):
            next_links.append(match.group(1))
    if not next_links:
        if re.search(r'rel\s*=\s*["\']?next', link, re.I):
            raise FetchError("Malformed GitHub next-page Link")
        return None
    if len(next_links) != 1:
        raise FetchError("Ambiguous GitHub next-page Link")
    value = _public_url(next_links[0])
    parts = urlsplit(value)
    base = urlsplit(endpoint)
    path_matches = parts.path.rstrip("/") == base.path
    # GitHub's official repository Link uses /repositories/{numeric_id}; rebuild
    # the request on the configured owner/name endpoint and reuse only the cursor.
    # We never follow or persist the upstream canonical path itself.
    if re.fullmatch(r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security-advisories", base.path):
        path_matches = path_matches or bool(re.fullmatch(r"/repositories/[1-9][0-9]*/security-advisories/?", parts.path))
    if not value or parts.scheme != "https" or parts.netloc != base.netloc or not path_matches or parts.fragment:
        raise FetchError("GitHub next-page Link leaves the official endpoint")
    values = parse_qs(parts.query, keep_blank_values=True)
    if any(len(v) != 1 for v in values.values()):
        raise FetchError("Ambiguous GitHub pagination parameters")
    after = values.pop("after", [None])[0]
    if "before" in values:
        raise FetchError("GitHub next-page Link has conflicting boundary cursors")
    expected = {k: [v] for k, v in query.items() if k != "after"}
    if values != expected or not isinstance(after, str) or not after or len(after) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in after):
        raise FetchError("GitHub next-page Link changed filters or has no valid after cursor")
    if after == query.get("after"):
        raise FetchError("GitHub pagination cursor did not advance")
    return after


def fetch(source: SourceConfig, cursor: dict[str, Any], http: HttpClient, now: datetime) -> FetchResult:
    repository = source.adapter == "github_repository"
    if source.adapter not in {"github_advisories", "github_repository"}:
        raise FetchError("Unknown GitHub advisory adapter")
    endpoint = _endpoint(source, "api.github.com", r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security-advisories/?" if repository else r"/advisories/?")
    now = _dt(_utc(now))
    incoming = copy.deepcopy(cursor or {})
    tracked = _tracked(incoming, _GHSA)
    state: dict[str, Any] = {"version": 1, "tracked_ids": tracked}
    if incoming.get("committed_end"):
        state["committed_end"] = _utc(_dt(incoming["committed_end"]))
    _cooldown(incoming, state, now)
    if incoming.get("pending"):
        pending = incoming["pending"]
        if not isinstance(pending, dict) or pending.get("endpoint") != endpoint:
            raise FetchError("Invalid GitHub pending endpoint")
        start, end = _dt(pending.get("window_start")), _dt(pending.get("window_end"))
        if start > end or end > now:
            raise FetchError("Invalid GitHub pending window")
        query = pending.get("query")
        allowed = {"sort", "direction", "per_page", "state"} if repository else {"sort", "direction", "per_page", "type", "modified", "affects", "ecosystem"}
        if not isinstance(query, dict) or set(query) - allowed or any(not isinstance(v, str) for v in query.values()) or query.get("sort") != "updated" or query.get("direction") != ("desc" if repository else "asc"):
            raise FetchError("Invalid GitHub pending filters")
        if repository and query.get("state") != "published":
            raise FetchError("Repository monitoring only permits published advisories")
        if not repository and (query.get("type") not in {"reviewed", "unreviewed", "malware"} or query.get("modified") != _modified_range(pending["window_start"], pending["window_end"])):
            raise FetchError("Invalid GitHub pending date/type filters")
        try:
            _integer(int(query.get("per_page", "")), 1, 100, "per_page")
        except ValueError as exc:
            raise FetchError("Invalid GitHub page size") from exc
        after = pending.get("after")
        if after is not None and (not isinstance(after, str) or not after or len(after) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in after)):
            raise FetchError("Invalid GitHub pagination cursor")
        refresh_ids = _tracked({"tracked_ids": pending.get("refresh_ids", [])}, _GHSA)
        index = _integer(pending.get("refresh_index"), 0, len(refresh_ids), "refresh_index")
        if not isinstance(pending.get("listing_done"), bool):
            raise FetchError("Invalid GitHub listing progress")
        pending = {"endpoint": endpoint, "window_start": _utc(start), "window_end": _utc(end), "query": query,
                   "after": after, "listing_done": pending["listing_done"], "refresh_ids": refresh_ids, "refresh_index": index}
    else:
        start, end = _window(source, state, now)
        query = {"sort": "updated", "direction": "desc" if repository else "asc",
                 "per_page": str(_integer(source.params.get("per_page", 100), 1, 100, "per_page"))}
        if repository:
            query["state"] = "published"
        else:
            advisory_type = source.params.get("type", "reviewed")
            if advisory_type not in {"reviewed", "unreviewed", "malware"}:
                raise FetchError("Invalid GitHub advisory type")
            query.update({"type": advisory_type, "modified": _modified_range(start, end)})
            packages = source.params.get("packages", source.params.get("affects", []))
            packages = _strings(packages, "packages")
            if packages:
                query["affects"] = ",".join(packages)
            if source.params.get("ecosystem"):
                ecosystem = source.params["ecosystem"]
                if ecosystem not in {"rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust", "erlang", "actions", "pub", "other", "swift"}:
                    raise FetchError("Invalid GitHub ecosystem")
                query["ecosystem"] = ecosystem
        pending = {"endpoint": endpoint, "window_start": start, "window_end": end, "query": query,
                   "after": None, "listing_done": False, "refresh_ids": tracked.copy(), "refresh_index": 0}
    state["pending"] = pending
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION}
    # Repository requests are intentionally anonymous: an optional broad token must
    # not turn this public monitor into a collector of private repository advisories.
    token = os.environ.get("GITHUB_TOKEN") if not repository else None
    if token:
        headers["Authorization"] = "Bearer " + token
    records: dict[str, Record] = {}
    while not pending["listing_done"] or pending["refresh_index"] < len(pending["refresh_ids"]):
        refreshing = pending["listing_done"]
        if len(records) + (1 if refreshing else int(pending["query"]["per_page"])) > 10000:
            return FetchResult(list(records.values()), state, complete=False)
        request_query = dict(pending["query"])
        if pending["after"] is not None:
            request_query["after"] = pending["after"]
        url = endpoint + "/" + pending["refresh_ids"][pending["refresh_index"]] if refreshing else endpoint + "?" + urlencode(request_query)
        if len(url) > 8192:
            raise FetchError("GitHub package scope exceeds bounded request URL length")
        try:
            payload, response = _json_response(http, url, headers, now)
        except FetchBudgetExceeded:
            return FetchResult(list(records.values()), state, complete=False)
        if refreshing:
            if not isinstance(payload, dict) or payload.get("ghsa_id") != pending["refresh_ids"][pending["refresh_index"]]:
                raise FetchError("GitHub ID lookup returned an unrelated advisory")
            payload = [payload]
        elif not isinstance(payload, list) or len(payload) > int(pending["query"]["per_page"]):
            raise FetchError("GitHub response exceeds its requested page size or is not a list")
        # Collection timestamps belong to Store's observations/runs; poll time
        # must not alter an unchanged advisory's semantic revision fingerprint.
        page = parse(source, payload)
        older = False
        for record in page:
            dates = [value for value in (record.updated_at, record.published_at, record.metadata.get("withdrawn_at")) if value]
            if not dates:
                raise FetchError("GitHub advisory has no modified/published date")
            modified = max(_dt(value, "advisory modified date") for value in dates)
            if not refreshing:
                if modified < _dt(pending["window_start"]):
                    older = True
                    continue
                if modified > _dt(pending["window_end"]):
                    continue
            record.metadata["filter_explanation"] = "Official repository published advisories with a local update window; previously observed advisories refreshed by GHSA ID" if repository else "GitHub modified window and optional package scope; previously observed advisories refreshed by GHSA ID"
            if pending["query"].get("affects"):
                record.metadata["package_scope"] = pending["query"]["affects"]
            previous = records.get(record.upstream_id)
            if previous is None or (record.updated_at or "") >= (previous.updated_at or ""):
                records[record.upstream_id] = record
            if record.upstream_id not in tracked:
                tracked.append(record.upstream_id)
        if refreshing:
            pending["refresh_index"] += 1
            if _defer_if_limited(response, state, now) and pending["refresh_index"] < len(pending["refresh_ids"]):
                return FetchResult(list(records.values()), state, complete=False)
            continue
        after = _next_after(response.headers.get("link", ""), endpoint, request_query)
        if after is not None and not payload:
            raise FetchError("GitHub pagination returned an empty page with a next cursor")
        # Repository results are requested newest first; crossing the lower bound
        # ends the list scan. ID refresh still detects changes to tracked entries.
        pending["listing_done"] = after is None or (repository and older)
        pending["after"] = after
        if _defer_if_limited(response, state, now) and (not pending["listing_done"] or pending["refresh_index"] < len(pending["refresh_ids"])):
            return FetchResult(list(records.values()), state, complete=False)
    state.pop("pending")
    state["committed_end"] = pending["window_end"]
    return FetchResult(list(records.values()), state, complete=_dt(pending["window_end"]) >= now)
