"""Official NIST publication-draft and Cybersecurity Insights metadata feeds.

This adapter consumes only the two feeds linked by NIST, never their HTML/PDF
targets. Feed disappearance is not withdrawal. Full snapshot re-observation and
conditional validators, rather than a claimed time-window API, provide updates.
Explicit Atom next/tombstone protocol elements are supported by the shared RSS
transport; neither was observed in the verified NIST snapshots.
"""
from __future__ import annotations

from datetime import datetime
import re
from urllib.parse import unquote, urlsplit

from aicti_monitor.models import FetchError, FetchResult, SourceConfig
from . import rss

PUBLICATIONS_ENDPOINT = "https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml"
BLOG_ENDPOINT = "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml"
LICENSE_URL = "https://www.nist.gov/open/license"
PUBLICATIONS_DOCS = "https://csrc.nist.gov/publications/drafts-open-for-comment"
BLOG_DOCS = "https://www.nist.gov/coo/nist-rss-feeds"
USAGE_CONDITIONS = (
    "NIST metadata; acknowledge NIST and source URL. Normalized title/link/date "
    "fields only; no excerpt, article or publication full text retained. NIST "
    "employee works have NIST's published reuse terms; third-party works can "
    "retain copyright and are not relicensed by this adapter. Provided AS IS, "
    "without NIST endorsement. See https://www.nist.gov/open/license."
)
_SECRET = re.compile(r"(?i)(?:bearer\s+\S+|(?:password|api[_-]?key|access[_-]?token|secret|authorization)\s*[:=]\s*[^\s,;]+|\bsk-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")
_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _text(value: str, maximum: int = 1024) -> str:
    return _EMAIL.sub("[email omitted]", _SECRET.sub("[credential omitted]", rss.plain_text(value, maximum)))


def _profile(source: SourceConfig) -> str:
    if source.endpoint == PUBLICATIONS_ENDPOINT and source.category == "standard":
        profile, host = "publications", "csrc.nist.gov"
    elif source.endpoint == BLOG_ENDPOINT and source.category == "security_blog":
        profile, host = "blog", "www.nist.gov"
    else:
        raise FetchError("NIST adapter requires a documented official feed and matching category")
    if host not in source.allowed_hosts or source.content_scope != "metadata_only":
        raise FetchError("NIST adapter requires allowlisted metadata-only access")
    if source.terms_url != LICENSE_URL:
        raise FetchError("NIST adapter requires the reviewed NIST usage conditions")
    return profile


def _request_url(value: str, source: SourceConfig) -> str:
    # A future next link must be explicitly published within the same feed URL.
    # Do not invent paging parameters or follow external/article links.
    clean = rss.safe_url(value)
    expected, actual = urlsplit(source.endpoint), urlsplit(clean or "")
    if (not clean or actual.scheme != "https" or actual.hostname != expected.hostname
            or actual.path != expected.path or actual.hostname not in source.allowed_hosts
            or len(actual.query) > 1024 or any(c in unquote(actual.path) for c in "\\\x00")):
        raise FetchError("NIST next request is outside the documented feed")
    return clean


class _FeedHTTP:
    def __init__(self, source, http):
        self.source, self.http = source, http

    def get(self, url, headers=None):
        _request_url(url, self.source)
        headers = dict(headers or {})
        # CSRC serves Atom as text/xml and returns 406 when that type is omitted.
        headers["Accept"] = "application/atom+xml, application/rss+xml, text/xml, application/xml;q=0.9"
        response = self.http.get(url, headers=headers)
        _request_url(response.url, self.source)
        return response


def _normalize(records, source: SourceConfig):
    profile = _profile(source)
    for record in records:
        withdrawn = record.metadata.get("withdrawn") is True
        locator = record.upstream_id if withdrawn else record.url
        url = rss.safe_url(locator)
        parts = urlsplit(url or "")
        metadata = {
            "source_name": "NIST CSRC" if profile == "publications" else "NIST Cybersecurity Insights",
            "source_url": source.endpoint, "collected_at": record.metadata["collected_at"],
            "feed_id": record.metadata.get("feed_id"),
            "feed_updated_at": record.metadata.get("feed_updated_at"),
            "upstream_revision": record.updated_at,
            "attribution": "National Institute of Standards and Technology (NIST)",
            "usage_conditions": USAGE_CONDITIONS,
            "terms_url": LICENSE_URL, "license_url": LICENSE_URL,
            "content_scope": "metadata_only", "excerpt_retained": False,
            "fulltext_fetched": False, "monitoring": "feed",
            "absence_is_withdrawal": False,
            "normalization": "Title and dates normalized; source excerpt/full text omitted",
        }
        if profile == "publications":
            match = re.fullmatch(r"/pubs/(fips|sp|ir|cswp|ai|tn)/[A-Za-z0-9/_-]+", parts.path)
            if parts.hostname != "csrc.nist.gov" or not match or parts.query:
                raise FetchError("NIST draft entry is not an official technical publication")
            if record.upstream_id != url:
                raise FetchError("NIST publication upstream identity is not its official metadata URL")
            series = match.group(1)
            # Special Publications are guidelines/specifications, not all formal
            # standards. The monitor Record enum has no guide; retain article
            # plus the accurate knowledge-kind discriminator for integration.
            record.kind = "standard" if series == "fips" else "paper" if series in {"ir", "ai", "tn"} else "article"
            knowledge_kind = "standard" if series == "fips" else "guide" if series in {"sp", "cswp"} else None
            suffix = parts.path.rsplit("/", 1)[-1]
            status = {"iwd": "initial_working_draft", "ipd": "initial_public_draft", "iprd": "initial_preliminary_draft",
                      "2pd": "second_public_draft", "3pd": "third_public_draft", "draft": "public_draft"}.get(suffix, "draft_status_unspecified")
            metadata.update(publication_series=series.upper(), knowledge_kind=knowledge_kind,
                            publication_status=status, feed_scope="drafts_open_for_comment",
                            feed_documentation=PUBLICATIONS_DOCS)
        else:
            if (parts.hostname != "www.nist.gov" or parts.query
                    or not re.fullmatch(r"/blogs/cybersecurity-insights/[A-Za-z0-9_-]+/?", parts.path)):
                raise FetchError("NIST blog entry is not an official Cybersecurity Insights article")
            ident = rss.safe_url(record.upstream_id)
            identity = urlsplit(ident or "")
            if (not ident or ident != record.upstream_id or identity.scheme != "https"
                    or identity.hostname != "www.nist.gov" or identity.query
                    or not (re.fullmatch(r"/node/[0-9]+", identity.path) or ident == url)):
                raise FetchError("NIST blog upstream identity is not an official metadata URL")
            record.kind = "article"
            metadata.update(document_type="security_blog_article", feed_scope="recent_blog_entries", feed_documentation=BLOG_DOCS)
        if withdrawn:
            metadata.update(withdrawn=True, status="withdrawn", withdrawal_evidence="atom_tombstone")
        record.title = _text(record.title)
        record.summary = ""
        record.aliases, record.components, record.references = [], [], []
        record.metadata = metadata
    return records


def parse_feed(body: bytes, source: SourceConfig, now: datetime, base_url: str | None = None) -> rss.FeedPage:
    """Pure bounded parser; every retained field comes from feed metadata."""
    _profile(source)
    _request_url(base_url or source.endpoint, source)
    page = rss.parse_feed(body, source, now, base_url)
    if page.dropped_entries:
        # Do not commit a completed observation that skipped malformed entries.
        raise FetchError("NIST feed contains incomplete or unsafe entries")
    if page.next_url:
        _request_url(page.next_url, source)
    page.records = _normalize(page.records, source)
    return page


def fetch(source, cursor, http, now) -> FetchResult:
    _profile(source)
    # Shared implementation preserves pending pages and only commits first-page
    # validators after all pages are consumed. Validation happens before any
    # result is returned to the runner's atomic evidence/cursor transaction.
    class ValidatedHTTP(_FeedHTTP):
        def get(self, url, headers=None):
            response = super().get(url, headers=headers)
            if response.status == 200:
                parse_feed(response.body, source, now, response.url)
            return response
    result = rss.fetch(source, cursor, ValidatedHTTP(source, http), now)
    result.records = _normalize(result.records, source)
    return result


def recommended_sources() -> list[dict]:
    """Detached config entries; main chat owns installation/registry changes."""
    return [{
        "id": ident, "name": name, "adapter": "nist_feeds", "category": category,
        "endpoint": endpoint, "allowed_hosts": [urlsplit(endpoint).hostname],
        "interval_seconds": 21600, "min_request_interval_seconds": 3.1,
        "enabled": True, "terms_url": LICENSE_URL, "content_scope": "metadata_only",
        "params": {"policy_status": "reviewed", "max_pages": 20,
                   "license": "NIST terms; third-party rights remain separate",
                   "license_url": LICENSE_URL},
    } for ident, name, category, endpoint in (
        ("nist-drafts", "NIST CSRC · 公开评论技术文件草案", "standard", PUBLICATIONS_ENDPOINT),
        ("nist-cybersecurity-blog", "NIST · Cybersecurity Insights 技术博客", "security_blog", BLOG_ENDPOINT),
    )]
