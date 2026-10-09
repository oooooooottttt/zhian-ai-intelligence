"""Bounded RSS 2.0, RDF RSS 1.0 and Atom ingestion, without HTML fetching.

``parse_feed`` is pure. DNS and redirect checks are the HTTP client's job;
syntax/private-address checks also apply to every stored or followed URL here.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html.parser import HTMLParser
import ipaddress
import math
import re
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from aicti_monitor.models import FetchBudgetExceeded, FetchError, FetchResult, Record

ATOM = "http://www.w3.org/2005/Atom"
TOMBSTONE = "http://purl.org/atompub/tombstones/1.0"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024
MAX_ENTRIES = 1000
MAX_TEXT = 8192
_SECRET_QUERY = re.compile(r"(?i)(?:token|secret|password|passwd|credential|authorization|api[_-]?key|signature)")
_TRACKING = {"fbclid", "gclid", "mc_cid", "mc_eid"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class _PlainHTML(HTMLParser):
    _blocked = {"script", "style", "iframe", "object", "embed", "svg", "math", "template", "head"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.rsplit(":", 1)[-1].lower()
        if tag in self._blocked:
            self.hidden.append(tag)
        elif tag in {"p", "br", "div", "li", "h1", "h2", "h3"} and not self.hidden:
            self.parts.append(" ")

    def handle_startendtag(self, tag, attrs):
        if not self.hidden:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        tag = tag.rsplit(":", 1)[-1].lower()
        if tag in self.hidden:
            self.hidden = self.hidden[:self.hidden.index(tag)]
        elif not self.hidden:
            self.parts.append(" ")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def plain_text(value: str, limit: int = MAX_TEXT) -> str:
    parser = _PlainHTML()
    parser.feed(value[:MAX_ENTRY_BYTES])
    parser.close()
    text = "".join(parser.parts)
    text = "".join(c for c in text if c in "\t\n\r" or ord(c) >= 32)
    return " ".join(text.split())[:limit]


def safe_url(value: str, base_url: str = "") -> str | None:
    """Canonical public HTTP(S) URL, or None; this never resolves/fetches it."""
    if not isinstance(value, str) or len(value) > 4096:
        return None
    value = value.strip()
    if not value or "\\" in value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        return None
    try:
        parts = urlsplit(urljoin(base_url, value))
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme.lower() not in {"http", "https"} or not host or parts.username is not None or parts.password is not None:
            return None
        if "%" in host or parts.port not in {None, 80, 443}:
            return None
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global or address.is_multicast:
                return None
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if "." not in host or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
                return None
            if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host):
                return None
            if not re.search(r"[a-z]", host) or all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", label) for label in host.split(".")):
                return None
        query = []
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            if _SECRET_QUERY.search(unquote(key)):
                return None
            if key.lower().startswith("utm_") or key.lower() in _TRACKING:
                continue
            query.append((key, val))
        # Credentials/control characters can also be concealed by percent encoding.
        if any(ord(c) < 32 for c in unquote(parts.path + parts.query)):
            return None
        authority = f"[{host}]" if ":" in host else host
        if parts.port and parts.port != (443 if parts.scheme.lower() == "https" else 80):
            return None
        return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", urlencode(query), ""))
    except (ValueError, UnicodeError):
        return None


def _outbound(value: str, source, base_url: str = "") -> str:
    url = safe_url(value, base_url)
    if url is None or urlsplit(url).hostname not in source.allowed_hosts:
        raise FetchError("Feed request URL violates source host policy")
    return url


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FetchError("An aware collection time is required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_date(value: str | None, *, required: bool = False) -> str | None:
    result = None
    if value:
        try:
            result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            try:
                result = parsedate_to_datetime(value.strip())
            except (ValueError, TypeError, OverflowError):
                pass
    if result is not None and result.tzinfo is not None and result.utcoffset() is not None:
        return utc_iso(result)
    if required:
        raise FetchError("Feed entry has a missing or invalid timestamp")
    return None


def parse_xml(body: bytes) -> ET.Element:
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:
        raise FetchError("Feed XML exceeds body limit")
    try:
        text = body.decode("utf-8-sig")
    except UnicodeError as exc:
        raise FetchError("Feed XML must use UTF-8") from exc
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
        raise FetchError("XML DOCTYPE and ENTITY declarations are forbidden")
    declaration = re.match(r"\s*<\?xml[^>]*encoding\s*=\s*['\"]([^'\"]+)", text, re.I)
    if declaration and declaration.group(1).lower() not in {"utf-8", "utf8", "us-ascii", "ascii"}:
        raise FetchError("Unsupported feed XML encoding")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError) as exc:
        raise FetchError("Malformed feed XML") from exc
    count = 0
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 15000 or depth > 40:
            raise FetchError("Feed XML structure exceeds limits")
        stack.extend((child, depth + 1) for child in node)
    return root


def _child(node, name):
    return next((c for c in node if _local(c.tag) == name), None)


def _text(node, name) -> str:
    child = _child(node, name)
    return "" if child is None else "".join(child.itertext()).strip()


def _content(node, name) -> str:
    child = _child(node, name)
    if child is None:
        return ""
    return (child.text or "") + "".join(ET.tostring(c, encoding="unicode") for c in child)


def _xml_base(node, fallback: str) -> str:
    value = node.get("{http://www.w3.org/XML/1998/namespace}base")
    if value is None:
        return fallback
    base = safe_url(value, fallback)
    if base is None:
        raise FetchError("Unsafe XML base URL")
    return base


def _id(value: str, fallback: str) -> str:
    value = " ".join(value.split())
    if not value or len(value) > 1024 or any(ord(c) < 32 for c in value):
        return fallback
    if value.lower().startswith(("http:", "https:")):
        canonical = safe_url(value)
        if not canonical:
            return fallback
        # Atom IDs are identifiers, not navigation links: fragments and query
        # parameters distinguish entries and must not be discarded as tracking.
        original, clean = urlsplit(value), urlsplit(canonical)
        if _SECRET_QUERY.search(unquote(original.fragment)):
            return fallback
        return urlunsplit((clean.scheme, clean.netloc, clean.path, original.query, original.fragment))
    # Reject URI schemes that could conceal credentials or unsafe navigation.
    if re.match(r"(?i)(?:javascript|data|file|ftp):", value) or "@" in value:
        return fallback
    return value


def _validator(value: str | None) -> str | None:
    if value and len(value) <= 512 and all(32 <= ord(c) < 127 for c in value):
        return value
    return None


def ensure_ok(response, now):
    if response.status == 200:
        return
    retry = response.headers.get("retry-after")
    delay = None
    if retry:
        try:
            number = float(retry)
            delay = min(365 * 86400, max(0.0, number)) if math.isfinite(number) else None
        except ValueError:
            date = parse_date(retry)
            if date:
                delay = max(0.0, (datetime.fromisoformat(date.replace("Z", "+00:00")) - now).total_seconds())
    raise FetchError("Feed HTTP request failed", status=response.status, retry_after=delay)


def _deduplicate(records: list[Record]) -> list[Record]:
    # Source identity is part of the key: unrelated feeds must never collide.
    latest = {}
    for record in records:
        key = (record.source_id, record.upstream_id)
        current = latest.get(key)
        def timestamp(item):
            value = item.updated_at
            return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else datetime.min.replace(tzinfo=timezone.utc)
        if current is None or timestamp(record) >= timestamp(current):
            latest[key] = record
    return list(latest.values())


@dataclass
class FeedPage:
    records: list[Record]
    feed_id: str
    updated_at: str | None
    next_url: str | None = None
    dropped_entries: int = 0


def parse_feed(body: bytes, source, now: datetime, base_url: str | None = None) -> FeedPage:
    """Normalize feed data; never retain Atom content/content:encoded or HTML."""
    root = parse_xml(body)
    base = safe_url(base_url or source.endpoint)
    if not base:
        raise FetchError("Invalid feed base URL")
    root_base = _xml_base(root, base)
    atom = root.tag == f"{{{ATOM}}}feed"
    if atom:
        channel = root
        entries = [c for c in root if c.tag in {f"{{{ATOM}}}entry", f"{{{TOMBSTONE}}}deleted-entry"}]
    elif _local(root.tag) == "rss":
        channel = _child(root, "channel")
        if channel is None:
            raise FetchError("RSS channel is missing")
        entries = [c for c in channel if _local(c.tag) == "item"]
    elif root.tag == "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF":
        channel = _child(root, "channel")
        if channel is None:
            raise FetchError("RDF RSS channel is missing")
        entries = [c for c in root if _local(c.tag) == "item"]
    else:
        raise FetchError("Unsupported XML feed format")
    channel_base = root_base if channel is root else _xml_base(channel, root_base)
    if len(entries) > MAX_ENTRIES:
        raise FetchError("Feed entry count exceeds limit")
    feed_id = _id(_text(channel, "id"), base)
    updated = parse_date(_text(channel, "updated") or _text(channel, "lastBuildDate"))
    next_url = None
    for link in channel:
        if link.tag == f"{{{ATOM}}}link" and link.get("rel") == "next":
            if next_url is not None:
                raise FetchError("Feed has multiple next links")
            next_url = _outbound(link.get("href", ""), source, _xml_base(link, channel_base))
    terms_url = safe_url(source.terms_url) if source.terms_url else None
    authorized_excerpt = source.content_scope == "feed_excerpt" and source.params.get("excerpt_authorized") is True and terms_url is not None
    collected = utc_iso(now)
    records, dropped = [], 0
    kind = {"research_paper": "paper", "standard": "standard", "policy": "policy"}.get(source.category, "article")
    for entry in entries:
        if len(ET.tostring(entry, encoding="utf-8")) > MAX_ENTRY_BYTES:
            raise FetchError("Feed entry exceeds size limit")
        deleted = entry.tag == f"{{{TOMBSTONE}}}deleted-entry"
        entry_base = _xml_base(entry, channel_base if _local(root.tag) == "rss" else root_base)
        raw_id = entry.get("ref", "") if deleted else _text(entry, "id" if atom else "guid")
        url = None
        if atom and not deleted:
            for link in entry:
                if link.tag == f"{{{ATOM}}}link" and link.get("rel", "alternate") == "alternate" and link.get("type", "text/html") in {"text/html", "application/xhtml+xml"}:
                    url = safe_url(link.get("href", ""), _xml_base(link, entry_base))
                    if url:
                        break
        elif not deleted:
            link = _child(entry, "link")
            url = safe_url(_text(entry, "link"), _xml_base(link, entry_base) if link is not None else entry_base)
        if not url and raw_id.lower().startswith(("http:", "https:")):
            url = safe_url(raw_id, base)
        if deleted:
            # Opaque Atom IDs remain IDs; the feed URL is the evidence location.
            url = safe_url(raw_id) or base
        if not url:
            dropped += 1
            continue
        upstream_id = _id(raw_id, url)
        if deleted and (not raw_id or upstream_id != " ".join(raw_id.split()) and not safe_url(raw_id)):
            raise FetchError("Atom tombstone has an unsafe or missing reference")
        title = "Withdrawn feed entry" if deleted else plain_text(_content(entry, "title"), 1024)
        if not title:
            dropped += 1
            continue
        published = None if deleted else parse_date(_text(entry, "published" if atom else "pubDate") or _text(entry, "date"))
        changed = parse_date(entry.get("when"), required=True) if deleted else parse_date(_text(entry, "updated") or _text(entry, "modified")) or published
        # Metadata-only feeds deliberately omit even supplied excerpts. Atom
        # <content> and RSS content:encoded can be full articles and are unused.
        excerpt = plain_text(_content(entry, "summary" if atom else "description")) if authorized_excerpt and not deleted else ""
        metadata = {"source_name": plain_text(source.name, 256), "source_url": base,
                    "collected_at": collected, "feed_id": feed_id, "feed_updated_at": updated,
                    "content_scope": source.content_scope, "terms_url": terms_url,
                    "excerpt_retained": bool(excerpt), "fulltext_fetched": False,
                    "normalization": "HTML removed; title and excerpt length limited"}
        if source.params.get("demo") is True:
            metadata["demo"] = True
        rights = plain_text(_content(entry, "rights") or _content(channel, "rights") or _content(channel, "copyright"), 2048)
        if rights:
            metadata["rights_notice"] = rights
        if not deleted:
            # Public creator names needed for attribution; omit author email,
            # profile URL and contact fields. RSS dc:creator is often a name.
            author_nodes = [author for author in entry if author.tag == f"{{{ATOM}}}author"]
            if not author_nodes:
                author_nodes = [author for author in channel if author.tag == f"{{{ATOM}}}author"]
            creators = [plain_text(_text(author, "name"), 256) for author in author_nodes]
            creators.extend(plain_text("".join(c.itertext()), 256) for c in entry if _local(c.tag) == "creator")
            if not atom:
                byline = _text(entry, "author")
                if "@" in byline:
                    match = re.search(r"\(([^()]*)\)\s*$", byline)
                    byline = match.group(1) if match else ""
                if byline:
                    creators.append(plain_text(byline, 256))
            creators = [name for name in creators[:100] if name and "@" not in name]
            if creators:
                metadata["authors"] = creators
        entry_licenses = [url for link in entry if link.tag == f"{{{ATOM}}}link" and link.get("rel") == "license"
                          if (url := safe_url(link.get("href", ""), _xml_base(link, entry_base)))]
        if entry_licenses:
            metadata["upstream_license_urls"] = entry_licenses[:10]
        if source.params.get("license"):
            metadata["license"] = plain_text(str(source.params["license"]), 256)
        license_url = safe_url(str(source.params.get("license_url", "")))
        if license_url:
            metadata["license_url"] = license_url
        if deleted:
            metadata.update(withdrawn=True, status="withdrawn", withdrawal_evidence="atom_tombstone")
        records.append(Record(source.id, upstream_id, kind, title, excerpt, url,
                              published_at=published, updated_at=changed, metadata=metadata))
    return FeedPage(_deduplicate(records), feed_id, updated, next_url, dropped)


def fetch(source, cursor, http, now) -> FetchResult:
    endpoint = _outbound(source.endpoint, source)
    state = deepcopy(cursor or {})
    pending = state.get("pending")
    max_pages = int(source.params.get("max_pages", 100))
    if not 1 <= max_pages <= 1000:
        raise FetchError("RSS max_pages must be between 1 and 1000")
    if pending and pending.get("endpoint") != endpoint:
        raise FetchError("RSS endpoint changed during pending pagination")
    if not pending:
        pending = {"endpoint": endpoint, "next_url": endpoint, "window_end": utc_iso(now),
                   "visited": [], "validators": {}, "dropped_entries": 0}
        state["pending"] = pending
    records = []
    while True:
        url = _outbound(pending["next_url"], source)
        first = not pending["visited"]
        headers = {"Accept": "application/atom+xml, application/rss+xml, application/xml;q=0.9"}
        if first:
            for key, header in (("etag", "If-None-Match"), ("last_modified", "If-Modified-Since")):
                validator = _validator(state.get(key))
                if validator:
                    headers[header] = validator
        try:
            response = http.get(url, headers=headers)
        except FetchBudgetExceeded:
            return FetchResult(_deduplicate(records), state, complete=False)
        if response.status == 304:
            if not first or not (headers.get("If-None-Match") or headers.get("If-Modified-Since")):
                raise FetchError("Unexpected HTTP 304 during feed pagination")
            state.pop("pending", None)
            state["last_completed_at"] = utc_iso(now)
            return FetchResult([], state, not_modified=True)
        ensure_ok(response, now)
        actual = _outbound(response.url, source)
        page = parse_feed(response.body, source, now, actual)
        records.extend(page.records)
        pending["dropped_entries"] += page.dropped_entries
        if first:
            pending["validators"] = {key: value for key, header in (("etag", "etag"), ("last_modified", "last-modified"))
                                      if (value := _validator(response.headers.get(header)))}
            pending["feed_id"] = page.feed_id
        # Keep only URL hashes in the visited set (and bound the cursor size).
        digest = sha256(url.encode()).hexdigest()
        if digest in pending["visited"]:
            raise FetchError("Feed pagination loop detected")
        pending["visited"].append(digest)
        if not page.next_url:
            for key in ("etag", "last_modified"):
                state.pop(key, None)
            state.update(pending["validators"])
            state.update(last_completed_at=pending["window_end"], feed_id=pending.get("feed_id"),
                         dropped_entries=pending["dropped_entries"])
            state.pop("pending", None)
            return FetchResult(_deduplicate(records), state)
        if sha256(page.next_url.encode()).hexdigest() in pending["visited"]:
            raise FetchError("Feed pagination loop detected")
        if len(pending["visited"]) >= max_pages:
            raise FetchError("Feed pagination exceeds configured page limit")
        pending["next_url"] = page.next_url


# A convenient explicit parser name for callers that only support RSS sources.
parse_rss = parse_feed
