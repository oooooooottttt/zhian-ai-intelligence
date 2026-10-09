"""arXiv legacy API metadata monitoring, sorted by revision time.

The documented API has no lastUpdatedDate range filter. Scan descending to a
local overlapping cutoff; retain an offset, result count and boundary anchor to
replay when offset positions change. Feed.updated is NOT a snapshot. No PDFs.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from aicti_monitor.models import FetchBudgetExceeded, FetchError, FetchResult, Record
from .rss import (ATOM, MAX_ENTRY_BYTES, _content, _deduplicate, _outbound, _text,
                  ensure_ok, parse_date, parse_xml, plain_text, safe_url, utc_iso)

OPENSEARCH = "http://a9.com/-/spec/opensearch/1.1/"
ARXIV = "http://arxiv.org/schemas/atom"
TERMS_URL = "https://info.arxiv.org/help/api/tou.html"
LICENSE_URL = "https://creativecommons.org/publicdomain/zero/1.0/"
_IDENTIFIER = re.compile(r"^(?P<id>(?:\d{4}\.\d{4,5}|[a-zA-Z][a-zA-Z0-9.-]*(?:\.[A-Z]{2})?/\d{7}))(?P<version>v[1-9]\d*)?$")


@dataclass
class ArxivPage:
    records: list[Record]
    total_results: int
    start_index: int
    feed_id: str
    updated_at: str


def _number(root, field):
    value = root.findtext(f"{{{OPENSEARCH}}}{field}")
    if value is None or not re.fullmatch(r"\d{1,12}", value.strip()):
        raise FetchError("arXiv pagination metadata is missing or invalid")
    return int(value)


def parse_atom(body: bytes, source, now: datetime) -> ArxivPage:
    root = parse_xml(body)
    if root.tag != f"{{{ATOM}}}feed":
        raise FetchError("arXiv response is not an Atom feed")
    entries = root.findall(f"{{{ATOM}}}entry")
    if len(entries) > 2000:
        raise FetchError("arXiv page exceeds entry limit")
    feed_updated = parse_date(_text(root, "updated"), required=True)
    feed_id = safe_url(_text(root, "id")) or safe_url(source.endpoint)
    records = []
    for entry in entries:
        if len(ET.tostring(entry, encoding="utf-8")) > MAX_ENTRY_BYTES:
            raise FetchError("arXiv entry exceeds size limit")
        raw_id = _text(entry, "id")
        url = safe_url(raw_id)
        if url is None or urlsplit(url).hostname != "arxiv.org" or not urlsplit(url).path.startswith("/abs/"):
            # API errors are themselves Atom entries, including HTTP-200 errors.
            raise FetchError("arXiv API returned an error or invalid article ID")
        identifier = urlsplit(url).path.removeprefix("/abs/")
        match = _IDENTIFIER.fullmatch(identifier)
        if not match:
            raise FetchError("arXiv article identifier is invalid")
        upstream_id = match.group("id")
        version = match.group("version")
        title = plain_text(_content(entry, "title"), 1024)
        if not title:
            raise FetchError("arXiv article title is missing")
        published = parse_date(_text(entry, "published"), required=True)
        updated = parse_date(_text(entry, "updated"), required=True)
        if _time(updated) < _time(published):
            raise FetchError("arXiv update timestamp precedes publication")
        authors = [plain_text(_text(author, "name"), 256) for author in entry.findall(f"{{{ATOM}}}author")]
        authors = [name for name in authors[:100] if name]
        categories = [plain_text(c.get("term", ""), 128) for c in entry.findall(f"{{{ATOM}}}category")][:30]
        comment = plain_text(entry.findtext(f"{{{ARXIV}}}comment") or "", 2048)
        # arXiv's API ToU explicitly includes abstracts in CC0 descriptive
        # metadata. This is metadata_only; the full paper is never requested.
        summary = plain_text(_content(entry, "summary"))
        metadata = {"source_name": plain_text(source.name, 256), "source_url": safe_url(source.endpoint),
                    "collected_at": utc_iso(now), "upstream_url": f"https://arxiv.org/abs/{identifier}",
                    "version": int(version[1:]) if version else None,
                    "authors": authors, "categories": categories, "comment": comment,
                    "feed_id": feed_id, "feed_updated_at": feed_updated,
                    "license": "CC0-1.0 (descriptive metadata only)", "license_url": LICENSE_URL,
                    "terms_url": TERMS_URL, "content_scope": "metadata_only", "fulltext_fetched": False}
        if source.params.get("demo") is True:
            metadata["demo"] = True
        if re.search(r"(?i)\b(?:has been|is|was|have been|we have)\s+(?:withdrawn|retracted)\b", comment):
            metadata.update(withdrawn=True, status="withdrawn", withdrawal_evidence="upstream_comment")
        primary = entry.find(f"{{{ARXIV}}}primary_category")
        if primary is not None:
            metadata["primary_category"] = plain_text(primary.get("term", ""), 128)
        doi = plain_text(entry.findtext(f"{{{ARXIV}}}doi") or "", 256)
        references = []
        if re.fullmatch(r"10\.\d{4,9}/[^\s<>]+", doi):
            doi_url = safe_url("https://doi.org/" + doi)
            if doi_url:
                metadata["doi"] = doi
                references.append(doi_url)
        records.append(Record(source.id, upstream_id, "paper", title, summary,
                              f"https://arxiv.org/abs/{upstream_id}", published_at=published,
                              updated_at=updated, references=references, metadata=metadata))
    # Keep the upstream row count/order for pagination; dedup at fetch boundary.
    return ArxivPage(records, _number(root, "totalResults"), _number(root, "startIndex"), feed_id, feed_updated)


def _time(value):
    normalized = parse_date(value, required=True)
    return datetime.fromisoformat(normalized.replace("Z", "+00:00"))


def _anchor(record):
    payload = [record.upstream_id, record.updated_at, record.metadata.get("version"), record.title, record.summary]
    return sha256(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _url(endpoint, query, offset, page_size):
    parts = urlsplit(endpoint)
    params = dict(parse_qsl(parts.query))
    params.update(search_query=query, start=str(offset), max_results=str(page_size),
                  sortBy="lastUpdatedDate", sortOrder="descending")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def fetch(source, cursor, http, now) -> FetchResult:
    endpoint = _outbound(source.endpoint, source)
    if urlsplit(endpoint).hostname != "export.arxiv.org" or urlsplit(endpoint).path != "/api/query":
        raise FetchError("arXiv must use its official API endpoint")
    if source.min_request_interval_seconds < 3:
        raise FetchError("arXiv requires at least three seconds between requests")
    state = deepcopy(cursor or {})
    query = source.params.get("search_query", source.params.get("query", "cat:cs.CR"))
    page_size = int(source.params.get("page_size", 100))
    overlap = int(source.params.get("overlap_seconds", 2 * 86400))
    lookback = int(source.params.get("initial_lookback_days", 7))
    if not isinstance(query, str) or not 1 <= len(query) <= 2048 or any(ord(c) < 32 for c in query) or not 1 <= page_size <= 1000 or not 0 <= overlap <= 30 * 86400 or not 1 <= lookback <= 3650:
        raise FetchError("Invalid arXiv query or window configuration")
    pending = state.get("pending")
    if pending and (pending.get("query") != query or pending.get("endpoint") != endpoint or pending.get("page_size") != page_size):
        raise FetchError("arXiv configuration changed during pending pagination")
    if not pending:
        high = _time(utc_iso(now))
        low = _time(state["watermark"]) - timedelta(seconds=overlap) if state.get("watermark") else high - timedelta(days=lookback)
        pending = {"endpoint": endpoint, "query": query, "page_size": page_size,
                   "low": utc_iso(low), "high": utc_iso(high), "offset": 0,
                   "total_results": None, "anchor": None, "restarts": 0}
        state["pending"] = pending
    if "snapshot" in pending:
        # Upgrade a pre-integration cursor that used [feed.updated, total].
        # Per-page feed timestamps are not a collection version and must not
        # trigger replays. Retain only the count and existing boundary anchor.
        legacy = pending.pop("snapshot")
        pending["total_results"] = legacy[1] if isinstance(legacy, list) and len(legacy) == 2 else None
    low, high = _time(pending["low"]), _time(pending["high"])
    if low > high:
        raise FetchError("arXiv cursor window is ahead of the collection clock")
    records = []
    while True:
        offset = pending["offset"]
        # One-row overlap validates the previously processed boundary while
        # allowing even a one-request cycle to make progress on stable results.
        start = max(0, offset - 1)
        requested = page_size + (1 if offset else 0)
        if start >= 30000:
            raise FetchError("arXiv API result ceiling reached; narrow the query or use OAI-PMH")
        try:
            response = http.get(_url(endpoint, query, start, requested), headers={"Accept": "application/atom+xml"})
        except FetchBudgetExceeded:
            return FetchResult(_deduplicate(records), state, complete=False)
        ensure_ok(response, now)
        _outbound(response.url, source)
        page = parse_atom(response.body, source, now)
        if page.start_index != start or len(page.records) > requested:
            raise FetchError("arXiv returned an unexpected page offset or size")
        changed = pending["total_results"] is not None and pending["total_results"] != page.total_results
        shifted = bool(offset and (not page.records or _anchor(page.records[0]) != pending["anchor"]))
        if offset and (changed or shifted):
            pending.update(offset=0, total_results=None, anchor=None, restarts=pending["restarts"] + 1)
            # Previously persisted rows can be replayed; the completed window
            # remains untouched until the entire frozen interval is observed.
            continue
        pending["total_results"] = page.total_results
        rows = page.records[1:] if offset else page.records
        if not rows and offset < page.total_results:
            raise FetchError("arXiv returned an empty page before the result set ended")
        previous_time = _time(page.records[0].updated_at) if offset and page.records else None
        cutoff = False
        for record in rows:
            updated = _time(record.updated_at)
            if previous_time is not None and updated > previous_time:
                raise FetchError("arXiv results are not sorted by descending update time")
            previous_time = updated
            if updated < low:
                cutoff = True
            elif updated <= high:
                records.append(record)
        next_offset = offset + len(rows)
        if cutoff or next_offset >= page.total_results:
            state["watermark"] = pending["high"]
            state["last_completed_at"] = utc_iso(now)
            state["last_restarts"] = pending["restarts"]
            state.pop("pending", None)
            return FetchResult(_deduplicate(records), state)
        if len(page.records) < requested:
            raise FetchError("arXiv returned a short page before the result set ended")
        pending["offset"] = next_offset
        pending["anchor"] = _anchor(rows[-1])


parse_arxiv = parse_atom
