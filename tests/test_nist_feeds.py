from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET

from aicti_monitor.adapters import nist_feeds as nist, rss
from aicti_monitor.models import FetchBudgetExceeded, FetchError, HttpResponse, SourceConfig
from aicti_monitor.storage import Store

NOW = datetime(2026, 10, 4, 10, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "nist"


def source(profile="publications", **kwargs):
    values = nist.recommended_sources()[0 if profile == "publications" else 1]
    values["allowed_hosts"] = tuple(values["allowed_hosts"])
    values.update(kwargs)
    return SourceConfig(**values)


def fixture(name="drafts-2026-10-04.xml"):
    return (FIXTURES / name).read_bytes()


def response(body=b"", status=200, headers=None, url=nist.PUBLICATIONS_ENDPOINT):
    return HttpResponse(status, body, headers or {}, url)


class FakeHTTP:
    def __init__(self, responses, budget=99):
        self.responses, self.budget, self.calls = list(responses), budget, []

    def get(self, url, headers=None):
        if len(self.calls) >= self.budget:
            raise FetchBudgetExceeded("Budget exhausted")
        self.calls.append((url, dict(headers or {})))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return replace(result, url=url)


def atom(title="AI guide draft", ident="https://csrc.nist.gov/pubs/sp/800/218/a/ipd", updated="2026-10-03T00:00:00Z", next_url=None, tombstone=False):
    root = ET.Element(f"{{{rss.ATOM}}}feed")
    ET.SubElement(root, f"{{{rss.ATOM}}}id").text = nist.PUBLICATIONS_ENDPOINT
    ET.SubElement(root, f"{{{rss.ATOM}}}updated").text = updated
    if next_url:
        ET.SubElement(root, f"{{{rss.ATOM}}}link", {"rel": "next", "href": next_url})
    if tombstone:
        ET.SubElement(root, f"{{{rss.TOMBSTONE}}}deleted-entry", {"ref": ident, "when": updated})
    else:
        entry = ET.SubElement(root, f"{{{rss.ATOM}}}entry")
        for name, value in (("id", ident), ("title", title), ("updated", updated)):
            ET.SubElement(entry, f"{{{rss.ATOM}}}{name}").text = value
        ET.SubElement(entry, f"{{{rss.ATOM}}}link", {"href": ident})
    return ET.tostring(root)


class NISTFeedTests(unittest.TestCase):
    def test_actual_official_draft_and_blog_snapshots(self):
        pub = nist.parse_feed(fixture(), source(), NOW).records[0]
        self.assertIn("Artificial Intelligence (AI)", pub.title)
        self.assertEqual("https://csrc.nist.gov/pubs/sp/1353/ipd", pub.upstream_id)
        self.assertEqual("2026-08-19T04:00:00Z", pub.updated_at)
        self.assertEqual("guide", pub.metadata["knowledge_kind"])
        self.assertEqual("initial_public_draft", pub.metadata["publication_status"])
        self.assertEqual("article", pub.kind)
        self.assertEqual("", pub.summary)
        self.assertFalse(pub.metadata["fulltext_fetched"])
        serialized = json.dumps(pub.to_dict())
        self.assertNotIn("csf@nist.gov", serialized)
        self.assertNotIn("Submit Your Comments", serialized)
        blog = nist.parse_feed(fixture("blog-2026-10-04.xml"), source("blog"), NOW).records[0]
        self.assertIn("Agentic AI", blog.title)
        self.assertEqual("article", blog.kind)
        self.assertEqual("security_blog_article", blog.metadata["document_type"])
        self.assertEqual("2026-08-27T12:00:00Z", blog.published_at)
        self.assertNotIn("knowledge_kind", blog.metadata)
        self.assertEqual("", blog.summary)

    def test_formal_standard_and_report_are_not_indiscriminately_classified(self):
        fips = nist.parse_feed(atom(ident="https://csrc.nist.gov/pubs/fips/203/ipd"), source(), NOW).records[0]
        report = nist.parse_feed(atom(ident="https://csrc.nist.gov/pubs/ir/8613/ipd"), source(), NOW).records[0]
        self.assertEqual(("standard", "standard"), (fips.kind, fips.metadata["knowledge_kind"]))
        self.assertEqual("paper", report.kind)
        self.assertIsNone(report.metadata["knowledge_kind"])

    def test_conditional_poll_and_no_hidden_fetches(self):
        http = FakeHTTP([response(fixture(), headers={"etag": '"snapshot-1"', "last-modified": "Sun, 04 Oct 2026 09:05:12 GMT"})])
        initial = nist.fetch(source(), {}, http, NOW)
        self.assertEqual(1, len(http.calls))
        self.assertIn("text/xml", http.calls[0][1]["Accept"])
        self.assertTrue(initial.complete)
        followup = FakeHTTP([response(status=304)])
        unchanged = nist.fetch(source(), initial.cursor, followup, NOW + timedelta(hours=6))
        self.assertTrue(unchanged.not_modified)
        self.assertEqual([], unchanged.records)
        self.assertEqual('"snapshot-1"', followup.calls[0][1]["If-None-Match"])
        self.assertNotIn("pending", unchanged.cursor)

    def test_explicit_next_link_protocol_resume_freezes_completion_time(self):
        # NIST snapshots currently have no pagination; this tests only the
        # generic Atom next-link protocol, not an invented upstream page API.
        next_url = nist.PUBLICATIONS_ENDPOINT + "?page=2"
        old = {"last_completed_at": "2026-10-01T00:00:00Z"}
        copy = deepcopy(old)
        first = nist.fetch(source(), old, FakeHTTP([response(atom(next_url=next_url))], budget=1), NOW)
        self.assertFalse(first.complete)
        self.assertEqual(copy, old)
        self.assertEqual(old["last_completed_at"], first.cursor["last_completed_at"])
        self.assertEqual(next_url, first.cursor["pending"]["next_url"])
        saved = json.loads(json.dumps(first.cursor))
        resumed_http = FakeHTTP([response(atom(ident="https://csrc.nist.gov/pubs/fips/203/ipd"))])
        second = nist.fetch(source(), saved, resumed_http, NOW + timedelta(hours=1))
        self.assertTrue(second.complete)
        self.assertEqual(next_url, resumed_http.calls[0][0])
        self.assertNotIn("If-None-Match", resumed_http.calls[0][1])
        self.assertEqual("2026-10-04T10:00:00Z", second.cursor["last_completed_at"])

    def test_page_failure_rate_limit_and_malformed_page_do_not_mutate_cursor(self):
        next_url = nist.PUBLICATIONS_ENDPOINT + "?page=2"
        first = nist.fetch(source(), {}, FakeHTTP([response(atom(next_url=next_url))], budget=1), NOW)
        old = deepcopy(first.cursor)
        for reply in (response(status=429, headers={"retry-after": "45"}), response(b"<broken"), FetchError("network failure")):
            with self.subTest(reply=type(reply).__name__):
                with self.assertRaises(FetchError) as caught:
                    nist.fetch(source(), first.cursor, FakeHTTP([reply]), NOW)
                self.assertEqual(old, first.cursor)
                if isinstance(reply, HttpResponse) and reply.status == 429:
                    self.assertEqual(45, caught.exception.retry_after)

    def test_absence_does_not_manufacture_withdrawal_but_tombstone_is_preserved(self):
        empty = b'<feed xmlns="http://www.w3.org/2005/Atom"><id>https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml</id></feed>'
        result = nist.fetch(source(), {}, FakeHTTP([response(empty)]), NOW)
        self.assertEqual([], result.records)
        self.assertTrue(result.complete)
        deleted = nist.parse_feed(atom(tombstone=True), source(), NOW).records[0]
        self.assertTrue(deleted.metadata["withdrawn"])
        self.assertEqual("atom_tombstone", deleted.metadata["withdrawal_evidence"])
        self.assertFalse(deleted.metadata["absence_is_withdrawal"])

    def test_reobserve_dedup_update_and_transaction_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.sqlite")
            def commit(records, cursor, when=NOW):
                at = rss.utc_iso(when)
                run = store.begin_run(source().id, at)
                return store.ingest_and_finish(run, source().id, records, cursor, at, at, True)
            first = nist.fetch(source(), {}, FakeHTTP([response(atom())]), NOW)
            self.assertEqual(1, commit(first.records, first.cursor)["new"])
            second = nist.fetch(source(), first.cursor, FakeHTTP([response(atom())]), NOW + timedelta(hours=1))
            self.assertEqual(1, commit(second.records, second.cursor, NOW + timedelta(hours=1))["unchanged"])
            revised = nist.fetch(source(), second.cursor, FakeHTTP([response(atom(title="Corrected AI guide draft", updated="2026-10-04T00:00:00Z"))]), NOW)
            self.assertEqual(1, commit(revised.records, revised.cursor)["updated"])
            before = store.get_cursor(source().id)
            bad = nist.parse_feed(atom(ident="https://csrc.nist.gov/pubs/fips/204/ipd"), source(), NOW).records
            original = store._append_revision
            def fail(*args, **kwargs):
                raise sqlite3.OperationalError("fixture transaction failure")
            store._append_revision = fail
            with self.assertRaises(sqlite3.OperationalError):
                commit(bad, {"last_completed_at": "2026-10-05T00:00:00Z"})
            store._append_revision = original
            self.assertEqual(before, store.get_cursor(source().id))
            self.assertEqual(1, store.stats()["total_observations"])
            self.assertEqual(2, store.stats()["total_revisions"])

    def test_feed_identity_scope_and_untrusted_input_boundaries(self):
        invalid_sources = [source(endpoint="https://csrc.nist.gov/news"), source(allowed_hosts=("www.nist.gov",)),
                           source(content_scope="feed_excerpt"), source(terms_url="https://example.com/terms")]
        for config in invalid_sources:
            with self.assertRaises(FetchError):
                nist.parse_feed(fixture(), config, NOW)
        for ident in ("https://csrc.nist.gov/news/standard", "https://example.com/pubs/sp/123/ipd",
                      "http://127.0.0.1/pubs/sp/123/ipd", "https://u:secret@csrc.nist.gov/pubs/sp/123/ipd"):
            with self.assertRaises(FetchError):
                nist.parse_feed(atom(ident=ident), source(), NOW)
        for next_url in ("https://csrc.nist.gov/pubs/sp/123/ipd", "https://csrc.nist.gov/CSRC/media/feeds/pubs/other.xml",
                         "https://127.0.0.1/", "https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml?token=secret"):
            with self.assertRaises(FetchError):
                nist.parse_feed(atom(next_url=next_url), source(), NOW)
        with self.assertRaises(FetchError):
            nist.parse_feed(b'<!DOCTYPE feed [<!ENTITY x "injected">]><feed/>', source(), NOW)
        opaque_identity = ET.fromstring(atom())
        opaque_identity.find(f"{{{rss.ATOM}}}entry/{{{rss.ATOM}}}id").text = "api_key=secret-fixture"
        with self.assertRaises(FetchError):
            nist.parse_feed(ET.tostring(opaque_identity), source(), NOW)
        sanitized = nist.parse_feed(atom(title="<script>unsafe</script>AI guide api_key=secret-fixture person@example.com"), source(), NOW).records[0]
        self.assertNotIn("secret-fixture", json.dumps(sanitized.to_dict()))
        self.assertNotIn("unsafe", sanitized.title)
        self.assertNotIn("person@example.com", sanitized.title)

    def test_newest_duplicate_id_is_retained(self):
        root = ET.fromstring(atom(title="Old"))
        newer = ET.fromstring(atom(title="New", updated="2026-10-04T00:00:00Z")).find(f"{{{rss.ATOM}}}entry")
        root.append(newer)
        records = nist.parse_feed(ET.tostring(root), source(), NOW).records
        self.assertEqual(["New"], [record.title for record in records])


if __name__ == "__main__":
    unittest.main()
