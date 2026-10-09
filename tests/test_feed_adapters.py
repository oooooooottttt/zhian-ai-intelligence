from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET

from aicti_monitor.adapters import arxiv, rss
from aicti_monitor.models import FetchBudgetExceeded, FetchError, HttpResponse, SourceConfig

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)


def fixture(name):
    return (FIXTURES / name).read_bytes()


def source(adapter="rss", **kwargs):
    values = dict(id="example-feed", name="Example security community", adapter=adapter,
                  category="security_community", endpoint="https://example.com/feed", allowed_hosts=("example.com",),
                  terms_url="https://example.com/terms", content_scope="metadata_only")
    if adapter == "arxiv":
        values.update(id="arxiv-security", name="arXiv", category="research_paper",
                      endpoint="https://export.arxiv.org/api/query", allowed_hosts=("export.arxiv.org",),
                      terms_url=arxiv.TERMS_URL, params={"page_size": 2})
    values.update(kwargs)
    return SourceConfig(**values)


def response(body=b"", *, status=200, headers=None, url="https://example.com/feed"):
    return HttpResponse(status, body, headers or {}, url)


class FakeHTTP:
    def __init__(self, responses, budget=99):
        self.responses = list(responses)
        self.budget = budget
        self.calls = []

    def get(self, url, headers=None):
        if len(self.calls) >= self.budget:
            raise FetchBudgetExceeded("Offline request budget exhausted")
        self.calls.append((url, dict(headers or {})))
        if not self.responses:
            raise AssertionError("Unexpected HTTP request")
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return replace(value, url=url)


def arxiv_response(name):
    return response(fixture(name), url="https://export.arxiv.org/api/query")


def changed_arxiv(name, *, updated=None, total=None, start=None):
    root = ET.fromstring(fixture(name))
    for field, value, namespace in (("updated", updated, rss.ATOM), ("totalResults", total, arxiv.OPENSEARCH), ("startIndex", start, arxiv.OPENSEARCH)):
        if value is not None:
            root.find(f"{{{namespace}}}{field}").text = str(value)
    return ET.tostring(root)


class RSSParserTests(unittest.TestCase):
    def test_metadata_only_excludes_excerpts_profiles_and_full_content(self):
        page = rss.parse_feed(fixture("rss.xml"), source(), NOW)
        self.assertEqual(2, len(page.records))
        self.assertEqual(2, page.dropped_entries)
        self.assertEqual("AI security update", page.records[0].title)
        self.assertEqual("https://example.com/article?id=1", page.records[0].url)
        self.assertEqual("2026-09-29T12:00:00Z", page.records[0].published_at)
        self.assertEqual("https://example.com/safe", page.records[1].upstream_id)
        data = json.dumps([record.to_dict() for record in page.records])
        self.assertNotIn("FULL ARTICLE", data)
        self.assertNotIn("private@example.com", data)
        self.assertNotIn("password", data)
        self.assertTrue(all(record.summary == "" for record in page.records))

    def test_only_explicitly_authorized_excerpt_retained_as_plain_text(self):
        config = source(content_scope="feed_excerpt", params={"excerpt_authorized": True, "license": "CC-BY-SA-4.0", "license_url": "https://creativecommons.org/licenses/by-sa/4.0/"})
        records = rss.parse_feed(fixture("rss.xml"), config, NOW).records
        self.assertEqual("A feed excerpt with plain text .", records[0].summary)
        self.assertEqual("Excerpt outside.", records[1].summary)
        self.assertEqual("CC-BY-SA-4.0", records[0].metadata["license"])
        self.assertNotIn("script", records[0].summary)
        self.assertNotIn("secret", records[0].summary)
        self.assertFalse(records[0].metadata["fulltext_fetched"])
        config = replace(config, params={})
        self.assertEqual("", rss.parse_feed(fixture("rss.xml"), config, NOW).records[0].summary)
        config = replace(config, params={"excerpt_authorized": True}, terms_url="")
        self.assertEqual("", rss.parse_feed(fixture("rss.xml"), config, NOW).records[0].summary)

    def test_atom_ids_xhtml_updates_and_tombstones(self):
        config = source(content_scope="feed_excerpt", params={"excerpt_authorized": True})
        first = rss.parse_feed(fixture("atom-page-1.xml"), config, NOW)
        self.assertEqual("tag:example.com,2026:feed", first.feed_id)
        self.assertEqual("tag:example.com,2026:notice-1", first.records[0].upstream_id)
        self.assertEqual("2026-09-29T12:00:00Z", first.records[0].updated_at)
        self.assertEqual("Allowed excerpt.", first.records[0].summary)
        self.assertEqual("https://example.com/feed?page=2", first.next_url)
        second = rss.parse_feed(fixture("atom-page-2.xml"), config, NOW)
        self.assertEqual(first.records[0].upstream_id, second.records[0].upstream_id)
        self.assertTrue(second.records[0].metadata["withdrawn"])
        self.assertEqual("2026-09-29T13:00:00Z", second.records[0].updated_at)

    def test_rdf_rss_and_missing_guid_fallback(self):
        body = b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>RSS1</title></channel><item><title>Standard update</title><link>https://example.com/spec</link><dc:date>2026-09-29T12:00:00+08:00</dc:date></item></rdf:RDF>'
        record = rss.parse_feed(body, source(category="standard"), NOW).records[0]
        self.assertEqual("standard", record.kind)
        self.assertEqual(record.url, record.upstream_id)
        self.assertEqual("2026-09-29T04:00:00Z", record.published_at)

    def test_xml_base_and_relative_link_normalization(self):
        body = b'<feed xmlns="http://www.w3.org/2005/Atom" xml:base="https://example.com/news/"><entry xml:base="updates/"><id>tag:example.com,2026:base</id><title>Update</title><link href="item?utm_source=rss"/></entry></feed>'
        record = rss.parse_feed(body, source(), NOW).records[0]
        self.assertEqual("https://example.com/news/updates/item", record.url)
        self.assertEqual("https://example.com/feed", record.metadata["source_url"])
        with self.assertRaises(FetchError):
            rss.parse_feed(body.replace(b"https://example.com/news/", b"http://127.0.0.1/"), source(), NOW)

    def test_duplicate_ids_keep_latest_but_different_sources_remain_distinct(self):
        body = b'<rss><channel><item><guid>notice</guid><title>Old</title><link>https://example.com/a</link><pubDate>2026-09-28T00:00:00Z</pubDate></item><item><guid>notice</guid><title>Corrected</title><link>https://example.com/a</link><pubDate>2026-09-29T00:00:00Z</pubDate></item></channel></rss>'
        a = rss.parse_feed(body, source(id="a"), NOW).records
        b = rss.parse_feed(body, source(id="b"), NOW).records
        self.assertEqual(["Corrected"], [r.title for r in a])
        self.assertEqual(2, len(rss._deduplicate(a + b)))
        self.assertEqual([], a[0].aliases)

    def test_atom_uri_id_fragments_are_preserved(self):
        body = b'<feed xmlns="http://www.w3.org/2005/Atom"><id>https://example.com/feed#identity</id><entry><id>https://example.com/article#one</id><title>One</title><link href="https://example.com/article#one"/></entry><entry><id>https://example.com/article#two</id><title>Two</title><link href="https://example.com/article#two"/></entry></feed>'
        page = rss.parse_feed(body, source(), NOW)
        self.assertEqual("https://example.com/feed#identity", page.feed_id)
        self.assertEqual(2, len(page.records))
        self.assertEqual(["https://example.com/article#one", "https://example.com/article#two"], [r.upstream_id for r in page.records])

    def test_authorized_excerpt_retains_credit_and_license_notice(self):
        body = b'<feed xmlns="http://www.w3.org/2005/Atom"><rights>CC BY-SA; Example Foundation</rights><entry><id>tag:example.com,2026:entry</id><title>Entry</title><link href="https://example.com/article"/><link rel="license" href="https://creativecommons.org/licenses/by-sa/4.0/"/><author><name>Example Author</name><email>contact@example.com</email></author><summary>Excerpt.</summary></entry></feed>'
        record = rss.parse_feed(body, source(content_scope="feed_excerpt", params={"excerpt_authorized": True}), NOW).records[0]
        self.assertEqual(["Example Author"], record.metadata["authors"])
        self.assertEqual("CC BY-SA; Example Foundation", record.metadata["rights_notice"])
        self.assertEqual(["https://creativecommons.org/licenses/by-sa/4.0/"], record.metadata["upstream_license_urls"])
        self.assertNotIn("contact@example.com", json.dumps(record.to_dict()))

    def test_fractional_update_timestamps_deduplicate_chronologically(self):
        body = b'<rss><channel><item><guid>n</guid><title>Fractional revision</title><link>https://example.com/a</link><pubDate>2026-09-29T00:00:00.1Z</pubDate></item><item><guid>n</guid><title>Old revision</title><link>https://example.com/a</link><pubDate>2026-09-29T00:00:00Z</pubDate></item></channel></rss>'
        self.assertEqual("Fractional revision", rss.parse_feed(body, source(), NOW).records[0].title)

    def test_feed_default_author_and_rss_byline_credit_without_email(self):
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><author><name>Foundation Author</name><email>private@example.com</email></author><entry><id>tag:example.com,2026:x</id><title>Title</title><link href="https://example.com/x"/><summary>Excerpt.</summary></entry></feed>'
        classic = b'<rss><channel><item><title>Title</title><link>https://example.com/x</link><author>private@example.com (Foundation Author)</author><description>Excerpt.</description></item></channel></rss>'
        for config in (source(), source(content_scope="feed_excerpt", params={"excerpt_authorized": True})):
            for body in (atom, classic):
                record = rss.parse_feed(body, config, NOW).records[0]
                self.assertEqual(["Foundation Author"], record.metadata["authors"])
                self.assertNotIn("private@example.com", json.dumps(record.to_dict()))

    def test_excerpt_and_title_length_bounds(self):
        body = ("<rss><channel><item><guid>x</guid><title>" + "T" * 2000 + "</title><link>https://example.com/a</link><description>" + "S" * 12000 + "</description></item></channel></rss>").encode()
        record = rss.parse_feed(body, source(content_scope="feed_excerpt", params={"excerpt_authorized": True}), NOW).records[0]
        self.assertEqual(1024, len(record.title))
        self.assertEqual(8192, len(record.summary))

    def test_unsafe_links_filtered(self):
        bad = ["javascript:alert(1)", "data:text/html,a", "file:///etc/passwd", "http://127.0.0.1/", "http://[::1]/", "http://10.1.2.3/", "http://169.254.169.254/", "http://224.0.0.1/", "http://[ff02::1]/", "http://2130706433/", "http://127.1/", "http://0x7f000001/", "http://localhost/", "https://user:pass@example.com/", "https://example.com/?api_key=x", "https://example.com/?%74oken=x", "https://foo.internal/", "https://example.com:8443/", "https://example.com/%0d%0aevil"]
        for url in bad:
            with self.subTest(url=url):
                self.assertIsNone(rss.safe_url(url))
        self.assertEqual("https://example.com/a?id=1", rss.safe_url("https://EXAMPLE.com:443/a?id=1&utm_campaign=x#fragment"))

    def test_doctype_entities_bad_encoding_and_malformed_xml_rejected(self):
        payloads = [b'<!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss/>', b'<!ENTITY x "bad"><rss/>', b'<rss>', '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE rss><rss/>'.encode("utf-16"), b'<?xml version="1.0" encoding="iso-8859-1"?><rss/>']
        for body in payloads:
            with self.subTest(body=body[:40]), self.assertRaises(FetchError):
                rss.parse_feed(body, source(), NOW)

    def test_payload_entry_structure_and_count_limits(self):
        payloads = [b" " * (rss.MAX_BODY_BYTES + 1), ("<rss><channel><item><title>" + "x" * rss.MAX_ENTRY_BYTES + "</title></item></channel></rss>").encode(), ("<rss><channel>" + "<item/>" * (rss.MAX_ENTRIES + 1) + "</channel></rss>").encode(), ("<rss><channel>" + "<x>" * 45 + "</x>" * 45 + "</channel></rss>").encode()]
        for body in payloads:
            with self.subTest(length=len(body)), self.assertRaises(FetchError):
                rss.parse_feed(body, source(), NOW)


class RSSFetchTests(unittest.TestCase):
    def test_conditional_get_and_304(self):
        cursor = {"etag": '"abc"', "last_modified": "Tue, 29 Sep 2026 12:00:00 GMT"}
        old = deepcopy(cursor)
        http = FakeHTTP([response(status=304)])
        result = rss.fetch(source(), cursor, http, NOW)
        self.assertEqual('"abc"', http.calls[0][1]["If-None-Match"])
        self.assertEqual(cursor["last_modified"], http.calls[0][1]["If-Modified-Since"])
        self.assertTrue(result.not_modified)
        self.assertTrue(result.complete)
        self.assertEqual([], result.records)
        self.assertEqual(old, cursor)
        with self.assertRaises(FetchError):
            rss.fetch(source(), {}, FakeHTTP([response(status=304)]), NOW)

    def test_atom_pagination_resumes_without_committing_etag_or_completion(self):
        cursor = {"etag": '"old"', "last_completed_at": "2026-09-28T00:00:00Z"}
        original = deepcopy(cursor)
        first = FakeHTTP([response(fixture("atom-page-1.xml"), headers={"etag": '"new"', "last-modified": "Tue, 29 Sep 2026 12:00:00 GMT"})], budget=1)
        partial = rss.fetch(source(), cursor, first, NOW)
        self.assertFalse(partial.complete)
        self.assertEqual('"old"', partial.cursor["etag"])
        self.assertEqual(cursor["last_completed_at"], partial.cursor["last_completed_at"])
        self.assertEqual("https://example.com/feed?page=2", partial.cursor["pending"]["next_url"])
        self.assertEqual(original, cursor)
        second = FakeHTTP([response(fixture("atom-page-2.xml"))], budget=1)
        done = rss.fetch(source(), partial.cursor, second, NOW + timedelta(hours=1))
        self.assertTrue(done.complete)
        self.assertNotIn("If-None-Match", second.calls[0][1])
        self.assertEqual('"new"', done.cursor["etag"])
        self.assertEqual("2026-09-30T00:00:00Z", done.cursor["last_completed_at"])
        self.assertNotIn("pending", done.cursor)
        self.assertTrue(done.records[0].metadata["withdrawn"])

    def test_changed_200_clears_stale_cache_and_empty_feed_completes(self):
        result = rss.fetch(source(), {"etag": '"stale"'}, FakeHTTP([response(b"<rss><channel/></rss>")]), NOW)
        self.assertTrue(result.complete)
        self.assertFalse(result.not_modified)
        self.assertEqual([], result.records)
        self.assertNotIn("etag", result.cursor)

    def test_failed_second_page_keeps_original_cursor_and_validators(self):
        cursor = {"etag": '"stale"'}
        saved = deepcopy(cursor)
        http = FakeHTTP([response(fixture("atom-page-1.xml"), headers={"etag": '"new"'}), FetchError("interrupted")])
        with self.assertRaises(FetchError):
            rss.fetch(source(), cursor, http, NOW)
        self.assertEqual(saved, cursor)

    def test_unsafe_next_link_loop_and_page_limit_fail_closed(self):
        body = fixture("atom-page-1.xml")
        for href in ("http://127.0.0.1/", "https://other.example.org/", "https://example.com/?token=SECRET", "/feed"):
            modified = body.replace(b'/feed?page=2', href.encode())
            http = FakeHTTP([response(modified)])
            with self.subTest(href=href), self.assertRaises(FetchError):
                rss.fetch(source(), {}, http, NOW)
            self.assertEqual(1, len(http.calls))
        with self.assertRaises(FetchError):
            rss.fetch(source(params={"max_pages": 1}), {}, FakeHTTP([response(body)]), NOW)

    def test_rate_limit_and_forbidden_do_not_retry_or_leak_body(self):
        for status in (429, 403):
            cursor = {"etag": '"old"'}
            http = FakeHTTP([response(b"secret upstream body", status=status, headers={"retry-after": "120"})])
            with self.subTest(status=status), self.assertRaises(FetchError) as error:
                rss.fetch(source(), cursor, http, NOW)
            self.assertEqual(status, error.exception.status)
            self.assertEqual(120, error.exception.retry_after)
            self.assertNotIn("secret", str(error.exception))
            self.assertEqual(1, len(http.calls))
            self.assertEqual({"etag": '"old"'}, cursor)

    def test_conditional_header_injection_not_sent(self):
        http = FakeHTTP([response(b"<rss><channel/></rss>", headers={"etag": "bad\r\nInjected: x"})])
        result = rss.fetch(source(), {"etag": "bad\r\nInjected: x"}, http, NOW)
        self.assertNotIn("If-None-Match", http.calls[0][1])
        self.assertNotIn("etag", result.cursor)
        with self.assertRaises(FetchError):
            rss.fetch(source(), {"etag": "bad\r\nInjected: x"}, FakeHTTP([response(status=304)]), NOW)

    def test_http_date_retry_after_and_nonfinite_rejected(self):
        for value, expected in (("Wed, 30 Sep 2026 00:02:00 GMT", 120), ("inf", None), ("nan", None)):
            with self.subTest(value=value), self.assertRaises(FetchError) as error:
                rss.fetch(source(), {}, FakeHTTP([response(status=429, headers={"retry-after": value})]), NOW)
            self.assertEqual(expected, error.exception.retry_after)


class ArxivTests(unittest.TestCase):
    def test_revision_normalization_cc0_abstract_and_attribution(self):
        page = arxiv.parse_atom(fixture("arxiv-page-0.xml"), source("arxiv"), NOW)
        record = page.records[0]
        self.assertEqual("2601.01001", record.upstream_id)
        self.assertEqual(2, record.metadata["version"])
        self.assertEqual("https://arxiv.org/abs/2601.01001", record.url)
        self.assertIn("CC0 descriptive metadata", record.summary)
        self.assertEqual(["Example Researcher"], record.metadata["authors"])
        self.assertEqual(["https://doi.org/10.1234/example"], record.references)
        self.assertNotIn("omit@example.com", json.dumps(record.to_dict()))
        self.assertNotIn("/pdf/", json.dumps(record.to_dict()))
        self.assertEqual([], record.aliases)

    def test_multi_cycle_offset_overlap_and_frozen_window(self):
        config = source("arxiv")
        first_http = FakeHTTP([arxiv_response("arxiv-page-0.xml")], budget=1)
        first = arxiv.fetch(config, {}, first_http, NOW)
        self.assertFalse(first.complete)
        self.assertEqual(2, first.cursor["pending"]["offset"])
        self.assertNotIn("watermark", first.cursor)
        query = parse_qs(urlsplit(first_http.calls[0][0]).query)
        self.assertEqual(["lastUpdatedDate"], query["sortBy"])
        self.assertEqual(["descending"], query["sortOrder"])
        self.assertNotIn("submittedDate", query["search_query"][0])
        second_http = FakeHTTP([arxiv_response("arxiv-page-1.xml")], budget=1)
        second = arxiv.fetch(config, first.cursor, second_http, NOW + timedelta(days=1))
        self.assertFalse(second.complete)
        self.assertEqual(["1"], parse_qs(urlsplit(second_http.calls[0][0]).query)["start"])
        self.assertEqual(4, second.cursor["pending"]["offset"])
        self.assertEqual(first.cursor["pending"]["high"], second.cursor["pending"]["high"])
        self.assertTrue(second.records[0].metadata["withdrawn"])
        third_http = FakeHTTP([arxiv_response("arxiv-page-3.xml")], budget=1)
        third = arxiv.fetch(config, second.cursor, third_http, NOW + timedelta(days=2))
        self.assertTrue(third.complete)
        self.assertEqual("2026-09-30T00:00:00Z", third.cursor["watermark"])
        self.assertNotIn("pending", third.cursor)
        all_records = first.records + second.records + third.records
        self.assertEqual(["2601.01001", "2609.01002", "2609.01003", "2609.01004"], [r.upstream_id for r in all_records])

    def test_updated_old_paper_not_missed_by_submission_filter(self):
        cursor = {"watermark": "2026-09-29T23:00:00Z"}
        http = FakeHTTP([arxiv_response("arxiv-page-0.xml"), arxiv_response("arxiv-page-1.xml"), arxiv_response("arxiv-page-3.xml")])
        result = arxiv.fetch(source("arxiv"), cursor, http, NOW)
        self.assertTrue(result.complete)
        self.assertEqual("2026-01-02T00:00:00Z", result.records[0].published_at)
        self.assertEqual("2601.01001", result.records[0].upstream_id)
        self.assertEqual({"watermark": "2026-09-29T23:00:00Z"}, cursor)

    def test_changed_result_count_restarts_without_advancing_watermark(self):
        old = {"watermark": "2026-09-29T00:00:00Z"}
        partial = arxiv.fetch(source("arxiv"), old, FakeHTTP([arxiv_response("arxiv-page-0.xml")], budget=1), NOW)
        changed = changed_arxiv("arxiv-page-1.xml", total=6)
        again = arxiv.fetch(source("arxiv"), partial.cursor, FakeHTTP([response(changed)], budget=1), NOW + timedelta(days=1))
        self.assertFalse(again.complete)
        self.assertEqual(0, again.cursor["pending"]["offset"])
        self.assertEqual(1, again.cursor["pending"]["restarts"])
        self.assertEqual(old["watermark"], again.cursor["watermark"])
        self.assertEqual(partial.cursor["pending"]["high"], again.cursor["pending"]["high"])

    def test_different_per_page_feed_updated_does_not_restart_or_stall(self):
        changed = changed_arxiv("arxiv-page-1.xml", updated="2026-10-01T03:04:05Z")
        first = arxiv.fetch(source("arxiv"), {}, FakeHTTP([arxiv_response("arxiv-page-0.xml")], budget=1), NOW)
        # Upgrade the exact legacy cursor shape observed in live integration.
        legacy = deepcopy(first.cursor)
        total = legacy["pending"].pop("total_results")
        legacy["pending"]["snapshot"] = ["2026-09-30T00:00:00Z", total]
        result = arxiv.fetch(source("arxiv"), legacy, FakeHTTP([response(changed)], budget=1), NOW + timedelta(days=1))
        self.assertFalse(result.complete)
        self.assertEqual(4, result.cursor["pending"]["offset"])
        self.assertEqual(0, result.cursor["pending"]["restarts"])
        self.assertEqual(5, result.cursor["pending"]["total_results"])
        self.assertNotIn("snapshot", result.cursor["pending"])
        final = arxiv.fetch(source("arxiv"), result.cursor, FakeHTTP([arxiv_response("arxiv-page-3.xml")]), NOW + timedelta(days=1))
        self.assertTrue(final.complete)
        self.assertEqual("2026-09-30T00:00:00Z", final.cursor["watermark"])

    def test_shifted_boundary_restarts_even_with_same_feed_timestamp(self):
        first = arxiv.fetch(source("arxiv"), {}, FakeHTTP([arxiv_response("arxiv-page-0.xml")], budget=1), NOW)
        shifted = fixture("arxiv-page-1.xml").replace(b"2609.01002v1", b"2609.02002v1")
        result = arxiv.fetch(source("arxiv"), first.cursor, FakeHTTP([response(shifted)], budget=1), NOW)
        self.assertFalse(result.complete)
        self.assertEqual(0, result.cursor["pending"]["offset"])

    def test_empty_result_and_invalid_partial_page(self):
        root = ET.fromstring(fixture("arxiv-page-0.xml"))
        for entry in root.findall(f"{{{rss.ATOM}}}entry"):
            root.remove(entry)
        root.find(f"{{{arxiv.OPENSEARCH}}}totalResults").text = "0"
        result = arxiv.fetch(source("arxiv"), {}, FakeHTTP([response(ET.tostring(root))]), NOW)
        self.assertTrue(result.complete)
        self.assertEqual([], result.records)
        root.find(f"{{{arxiv.OPENSEARCH}}}totalResults").text = "5"
        with self.assertRaises(FetchError):
            arxiv.fetch(source("arxiv"), {}, FakeHTTP([response(ET.tostring(root))]), NOW)

    def test_errors_bad_dates_unsorted_and_wrong_page_never_commit(self):
        invalid = [fixture("arxiv-page-0.xml").replace(b"http://arxiv.org/abs/2601.01001v2", b"http://arxiv.org/api/errors#bad"), fixture("arxiv-page-0.xml").replace(b"2026-09-29T22:00:00Z", b"bad date"), fixture("arxiv-page-0.xml").replace(b"2026-09-29T21:00:00Z", b"2026-09-29T23:00:00Z"), changed_arxiv("arxiv-page-0.xml", start=100)]
        for body in invalid:
            cursor = {"watermark": "2026-09-28T00:00:00Z"}
            saved = deepcopy(cursor)
            with self.subTest(body=body[:40]), self.assertRaises(FetchError):
                arxiv.fetch(source("arxiv"), cursor, FakeHTTP([response(body)]), NOW)
            self.assertEqual(saved, cursor)

    def test_network_failure_original_cursor_is_unchanged(self):
        cursor = {"watermark": "2026-09-28T00:00:00Z"}
        saved = deepcopy(cursor)
        http = FakeHTTP([arxiv_response("arxiv-page-0.xml"), FetchError("offline interruption")])
        with self.assertRaises(FetchError):
            arxiv.fetch(source("arxiv"), cursor, http, NOW)
        self.assertEqual(saved, cursor)

    def test_minimum_interval_and_official_endpoint_enforced(self):
        for config in (replace(source("arxiv"), min_request_interval_seconds=1), replace(source("arxiv"), endpoint="https://example.com/api/query", allowed_hosts=("example.com",))):
            http = FakeHTTP([])
            with self.subTest(config=config.id), self.assertRaises(FetchError):
                arxiv.fetch(config, {}, http, NOW)
            self.assertEqual([], http.calls)

    def test_rate_limit_does_not_advance_or_retry(self):
        cursor = {"watermark": "2026-09-28T00:00:00Z"}
        http = FakeHTTP([response(status=429, headers={"retry-after": "30"})])
        with self.assertRaises(FetchError) as error:
            arxiv.fetch(source("arxiv"), cursor, http, NOW)
        self.assertEqual(30, error.exception.retry_after)
        self.assertEqual(1, len(http.calls))
        self.assertNotIn("pending", cursor)


if __name__ == "__main__":
    unittest.main()
