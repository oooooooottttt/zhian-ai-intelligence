from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aicti_monitor.models import Record
from aicti_monitor.storage import Store


NOW = "2026-09-30T10:00:00Z"
LATER = "2026-09-30T11:00:00Z"
NEXT = "2026-09-30T12:00:00Z"
CVE = "CVE-2026-12345"
GHSA = "GHSA-2345-CFGH-JMPQ"


def record(source: str = "nvd", upstream: str = "item-1", **kwargs) -> Record:
    fields = {"source_id": source, "upstream_id": upstream, "kind": "vulnerability",
              "title": "PyTorch arbitrary code execution", "summary": "Unsafe deserialization",
              "url": "https://example.com/advisory/" + upstream,
              "published_at": "2020-01-01T00:00:00Z", "updated_at": "2026-09-29T00:00:00Z"}
    fields.update(kwargs)
    return Record(**fields)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "monitor.sqlite3"
        self.store = Store(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def ingest(self, records, source="nvd", now=NOW, cursor=None, complete=True):
        run = self.store.begin_run(source, now)
        counts = self.store.ingest_and_finish(run, source, records, cursor or {}, now, NEXT, complete)
        return run, counts

    def test_empty_store_defaults_and_wal(self):
        self.assertEqual(self.store.get_cursor("unknown"), {})
        state = self.store.get_source_state("unknown")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertIsNone(state["last_success_at"])
        self.assertEqual(self.store.list_records(), [])
        self.assertIsNone(self.store.get_record(1))
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_repeated_import_is_observation_dedup_and_not_revision(self):
        first_run, counts = self.ingest([record(aliases=[CVE])], cursor={"finished": "old"})
        self.assertEqual(counts, {"fetched": 1, "new": 1, "updated": 0, "unchanged": 0, "ai_related": 1})
        _, counts = self.ingest([record(aliases=[CVE])], now=LATER, cursor={"finished": "new"})
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(counts["new"], 0)
        event = self.store.get_record(self.store.list_records()[0]["id"])
        self.assertEqual(event["revision_count"], 1)
        self.assertEqual(event["first_seen_at"], NOW)
        self.assertEqual(event["last_seen_at"], LATER)
        self.assertEqual(event["revisions"][0]["collected_at"], NOW)
        self.assertEqual(self.store.get_cursor("nvd"), {"finished": "new"})
        self.assertEqual(self.store.list_runs()[1]["id"], first_run)

    def test_duplicate_within_one_batch_has_explicit_counts(self):
        _, counts = self.ingest([record(), record()])
        self.assertEqual(counts, {"fetched": 2, "new": 1, "updated": 0, "unchanged": 1, "ai_related": 2})
        self.assertEqual(self.store.stats()["total_observations"], 1)

    def test_optional_timestamp_fractions_preserve_order_and_observation_bounds(self):
        fraction = "2026-09-30T10:00:00.000100Z"
        self.ingest([record(upstream="earlier")], now=NOW)
        self.ingest([record(upstream="later")], now=fraction)
        self.assertEqual(self.store.list_records()[0]["upstream_id"], "later")
        self.assertEqual(self.store.stats()["last_collected_at"], fraction)
        self.ingest([record(upstream="earlier")], now=fraction)
        event = self.store.get_record(1)
        self.assertEqual(event["first_seen_at"], NOW)
        self.assertEqual(event["last_seen_at"], fraction)
        self.assertEqual(event["observations"][0]["first_seen_at"], NOW)
        self.assertEqual(event["observations"][0]["last_seen_at"], fraction)

    def test_newly_collected_old_material_does_not_displace_new_intelligence(self):
        recent = record(upstream="recent", published_at="2026-09-28T00:00:00Z",
                        updated_at="2026-09-29T00:00:00Z")
        historical = record(upstream="historical", published_at="2020-01-01T00:00:00Z",
                            updated_at="2021-02-01T00:00:00Z")
        self.ingest([recent])
        self.ingest([historical], now=LATER)
        self.ingest([historical], now=NEXT)
        events = self.store.list_records()
        self.assertEqual([event["upstream_id"] for event in events], ["recent", "historical"])
        self.assertEqual(events[1]["latest_upstream_at"], historical.updated_at)
        self.assertEqual(events[1]["last_seen_at"], NEXT)
        self.assertEqual(self.store.get_record(events[1]["id"])["latest_upstream_at"], historical.updated_at)

    def test_upstream_order_is_global_before_pagination_and_publication_is_fallback(self):
        entries = [
            record(upstream="third", updated_at="2026-07-01T00:00:00Z"),
            record(upstream="newest", updated_at="2026-09-29T00:00:00Z"),
            record(upstream="oldest", updated_at="2023-01-01T00:00:00Z"),
            record(upstream="second", published_at="2026-08-01T00:00:00Z", updated_at=None),
            record(upstream="fourth", updated_at="2025-01-01T00:00:00Z"),
        ]
        self.ingest(entries)
        pages = [self.store.list_records(limit=2, offset=offset) for offset in (0, 2, 4)]
        ordered = [event for page in pages for event in page]
        self.assertEqual([event["upstream_id"] for event in ordered],
                         ["newest", "second", "third", "fourth", "oldest"])
        self.assertEqual(ordered[1]["latest_upstream_at"], entries[3].published_at)
        self.assertEqual(len({event["id"] for event in ordered}), len(entries))
        self.assertEqual(self.store.list_records(limit=2, offset=6), [])

    def test_event_latest_upstream_date_uses_all_current_sources_not_representative_or_history(self):
        self.ingest([record(upstream="linked", aliases=[CVE], updated_at="2021-01-01T00:00:00Z"),
                     record(upstream="middle", updated_at="2025-01-01T00:00:00Z")])
        other = record("other", "linked-source", aliases=[CVE], title="Generic advisory",
                       summary="No explicit AI evidence", updated_at="2026-09-29T00:00:00Z")
        self.ingest([other], source="other", now=LATER)
        event = self.store.list_records(source_id="nvd", limit=1)[0]
        self.assertEqual(event["upstream_id"], "linked")
        self.assertEqual(event["updated_at"], "2021-01-01T00:00:00Z")
        self.assertEqual(event["latest_upstream_at"], other.updated_at)
        # Historical source snapshots never determine the current event order.
        self.ingest([replace(other, updated_at="2022-01-01T00:00:00Z")], source="other", now=NEXT)
        self.assertEqual(self.store.list_records(limit=1)[0]["upstream_id"], "middle")
        detail = self.store.get_record(event["id"])
        self.assertEqual(detail["latest_upstream_at"], "2022-01-01T00:00:00Z")
        self.assertIn(other.updated_at, [item["updated_at"] for item in detail["revisions"]])

    def test_equal_or_missing_upstream_dates_use_first_seen_and_id_not_refresh_time(self):
        first = record(upstream="first")
        second = record(upstream="second")
        self.ingest([first], now=NOW)
        self.ingest([second], now=LATER)
        self.ingest([record(upstream="undated-a", published_at=None, updated_at=None),
                     record(upstream="undated-b", published_at=None, updated_at=None)], now=NEXT)
        self.ingest([first], now=NEXT)
        events = self.store.list_records()
        self.assertEqual([event["upstream_id"] for event in events],
                         ["second", "first", "undated-b", "undated-a"])
        self.assertIsNone(events[2]["latest_upstream_at"])
        self.assertEqual(self.store.list_records(limit=1, offset=1)[0]["upstream_id"], "first")

    def test_upstream_sort_preserves_fractional_seconds_and_normalizes_timezones(self):
        self.ingest([record(upstream="fraction", updated_at="2026-09-30T18:00:00.000100+08:00"),
                     record(upstream="whole-second", updated_at=NOW)])
        events = self.store.list_records()
        self.assertEqual(events[0]["upstream_id"], "fraction")
        self.assertEqual(events[0]["latest_upstream_at"], "2026-09-30T10:00:00.000100Z")

    def test_upstream_changes_append_snapshots_and_reversion(self):
        original = record(aliases=[CVE], metadata={"terms_url": "https://example.com/terms"})
        self.ingest([original])
        changed = replace(original, summary="Corrected: no remote exploitability", updated_at=LATER)
        _, counts = self.ingest([changed], now=LATER)
        self.assertEqual(counts["updated"], 1)
        _, counts = self.ingest([original], now=NEXT)
        self.assertEqual(counts["updated"], 1)
        event = self.store.get_record(1)
        self.assertEqual([item["summary"] for item in event["revisions"]],
                         [original.summary, changed.summary, original.summary])
        self.assertEqual([item["revision_number"] for item in event["revisions"]], [1, 2, 3])
        self.assertEqual(event["observations"][0]["revision_count"], 3)

    def test_collection_and_page_metadata_do_not_invent_content_revisions(self):
        metadata = {"collected_at": NOW, "upstream_response_at": NOW, "feed_updated_at": NOW,
                    "feed_id": "https://example.com/feed?page=1", "filter_explanation": "keyword window",
                    "source_name": "Original display name", "source_category": "vendor_advisory",
                    "version": 1, "upstream_revision": "v1", "demo": True}
        original = record(metadata=metadata)
        self.ingest([original])
        observed = replace(original, metadata={**metadata, "collected_at": LATER,
                           "upstream_response_at": LATER, "feed_updated_at": LATER,
                           "feed_id": "https://example.com/feed?page=2", "filter_explanation": "ID refresh",
                           "source_name": "Renamed source", "source_category": "vulnerability_database"})
        _, counts = self.ingest([observed], now=LATER)
        self.assertEqual(counts, {"fetched": 1, "new": 0, "updated": 0, "unchanged": 1, "ai_related": 1})
        event = self.store.get_record(1)
        self.assertEqual(event["revision_count"], 1)
        self.assertEqual(event["last_seen_at"], LATER)
        self.assertEqual(event["metadata"]["collected_at"], LATER)
        self.assertEqual(event["metadata"]["filter_explanation"], "ID refresh")
        self.assertEqual(event["metadata"]["source_name"], "Renamed source")
        self.assertEqual(event["revisions"][0]["metadata"]["collected_at"], NOW)
        self.assertEqual(event["revisions"][0]["collected_at"], NOW)
        # Entry-specific facts continue to produce content revisions.
        for changes in [{"title": "PyTorch corrected advisory"},
                        {"metadata": {**observed.metadata, "version": 2}},
                        {"metadata": {**observed.metadata, "upstream_revision": "v2"}},
                        {"metadata": {**observed.metadata, "withdrawn": True}}]:
            _, counts = self.ingest([replace(observed, **changes)], now=NEXT)
            self.assertEqual(counts["updated"], 1)
        self.assertEqual(self.store.get_record(1)["revision_count"], 5)

    def test_shared_cve_links_sources_without_overwriting_evidence(self):
        self.ingest([record(aliases=[CVE])])
        _, counts = self.ingest([record("github", "GHSA-evidence", title="LangChain denial of service",
                                          summary="A conflicting source description", aliases=[CVE, GHSA])], source="github", now=LATER)
        self.assertEqual(counts["new"], 1)  # A new source observation, not a new event.
        events = self.store.list_records()
        self.assertEqual(len(events), 1)
        event = self.store.get_record(events[0]["id"])
        self.assertEqual(event["canonical_aliases"], sorted([CVE, GHSA]))
        self.assertEqual(event["observation_count"], 2)
        self.assertEqual(event["revision_count"], 2)
        descriptions = {item["source_id"]: item["summary"] for item in event["observations"]}
        self.assertEqual(descriptions, {"nvd": "Unsafe deserialization", "github": "A conflicting source description"})

    def test_late_alias_bridge_merges_events_and_keeps_old_ids_resolvable(self):
        self.ingest([record(upstream="no-alias")])
        self.ingest([record("github", "ghsa", aliases=[GHSA])], source="github")
        self.ingest([record("other", "cve", aliases=[CVE])], source="other")
        ids = sorted(item["id"] for item in self.store.list_records())
        self.assertEqual(len(ids), 3)
        _, counts = self.ingest([record(upstream="no-alias", aliases=[CVE, GHSA])], now=LATER)
        self.assertEqual(counts["updated"], 1)
        self.assertEqual(len(self.store.list_records()), 1)
        winner = self.store.get_record(ids[0])
        self.assertEqual(winner["observation_count"], 3)
        self.assertEqual(winner["revision_count"], 4)
        for loser in ids[1:]:
            redirected = self.store.get_record(loser)
            self.assertEqual(redirected["id"], ids[0])
            self.assertEqual(redirected["merged_from_id"], loser)
            self.assertEqual(len(redirected["revisions"]), 4)

    def test_identical_titles_and_shared_upstream_ids_never_merge_sources(self):
        self.ingest([record(aliases=["OSV-2026-123", "CVE-2026-12", "GHSA-AAAA-BBBB-CCCC"])])
        self.ingest([record("other", aliases=["OSV-2026-123", "CVE-2026-12", "GHSA-AAAA-BBBB-CCCC"])], source="other")
        self.assertEqual(self.store.stats()["total_records"], 2)
        self.assertEqual(self.store.stats()["total_observations"], 2)
        self.assertEqual(self.store.get_record(1)["canonical_aliases"], [])

    def test_valid_alias_case_and_order_do_not_create_revision(self):
        self.ingest([record(aliases=[CVE.lower(), GHSA.lower()])])
        _, counts = self.ingest([record(aliases=[GHSA, CVE, CVE])], now=LATER)
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(self.store.get_record(1)["canonical_aliases"], sorted([CVE, GHSA]))

    def test_removed_alias_is_historical_link_and_current_evidence_is_retained(self):
        self.ingest([record(aliases=[CVE])])
        self.ingest([record(aliases=[])], now=LATER)
        event = self.store.get_record(1)
        self.assertEqual(event["aliases"], [])
        self.assertEqual(event["canonical_aliases"], [CVE])
        self.assertEqual(event["revisions"][0]["aliases"], [CVE])

    def test_withdrawal_is_a_revision_not_a_deletion(self):
        self.ingest([record(aliases=[CVE])])
        _, counts = self.ingest([record(aliases=[CVE], metadata={"withdrawn_at": LATER, "status": "withdrawn"})], now=LATER)
        self.assertEqual(counts["updated"], 1)
        event = self.store.get_record(1)
        self.assertTrue(event["withdrawn"])
        self.assertFalse(event["revisions"][0]["withdrawn"])
        self.assertTrue(event["revisions"][1]["withdrawn"])
        self.ingest([record("other", aliases=[CVE])], source="other", now=NEXT)
        self.assertFalse(self.store.get_record(1)["withdrawn"])
        self.assertTrue(any(item["withdrawn"] for item in self.store.get_record(1)["observations"]))

    def test_non_ai_retained_by_default_hidden_and_can_become_ai(self):
        item = record(title="Email database availability", summary="Ordinary database update")
        _, counts = self.ingest([item])
        self.assertEqual(counts["ai_related"], 0)
        self.assertEqual(self.store.list_records(), [])
        self.assertEqual(len(self.store.list_records(include_non_ai=True)), 1)
        self.assertIsNotNone(self.store.get_record(1))
        self.ingest([replace(item, components=["pytorch"])], now=LATER)
        self.assertEqual(len(self.store.list_records()), 1)
        self.ingest([item], now=NEXT)
        self.assertEqual(self.store.list_records(), [])
        history = self.store.get_record(1)["revisions"]
        self.assertEqual([item["is_ai_related"] for item in history], [False, True, False])

    def test_event_ai_relevance_uses_all_current_source_evidence(self):
        self.ingest([record(aliases=[CVE])])
        self.ingest([record("other", title="Unspecified vulnerability", summary="No AI evidence", aliases=[CVE])], source="other", now=LATER)
        event = self.store.list_records(source_id="other")[0]
        self.assertTrue(event["is_ai_related"])
        self.assertEqual(event["source_id"], "nvd")
        self.assertFalse(next(item for item in event["observations"] if item["source_id"] == "other")["is_ai_related"])

    def test_content_transaction_failure_rolls_back_every_write(self):
        self.ingest([record(aliases=[CVE])], cursor={"finished": "initial"})
        self.ingest([record("other", aliases=[GHSA])], source="other")
        baseline = self.store.stats()
        run = self.store.begin_run("nvd", LATER)
        with sqlite3.connect(self.path) as connection:
            connection.execute("""CREATE TRIGGER reject_revision BEFORE INSERT ON revisions
                WHEN NEW.revision_number=2 BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.ingest_and_finish(run, "nvd", [record(aliases=[CVE, GHSA], summary="New evidence")],
                                         {"finished": "must-not-commit"}, LATER, NEXT, True)
        after = self.store.stats()
        for key in ["total_records", "total_observations", "total_revisions", "last_collected_at"]:
            self.assertEqual(after[key], baseline[key])
        self.assertEqual(self.store.get_record(1)["canonical_aliases"], [CVE])
        self.assertEqual(self.store.get_record(2)["canonical_aliases"], [GHSA])
        self.assertEqual(self.store.get_cursor("nvd"), {"finished": "initial"})
        self.assertEqual(self.store.list_runs()[0]["status"], "running")
        self.store.fail_run(run, "nvd", "transaction aborted", LATER, NEXT)
        self.assertEqual(self.store.list_runs()[0]["status"], "failed")

    def test_invalid_late_record_rolls_back_earlier_record_in_batch(self):
        run = self.store.begin_run("nvd", NOW)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(run, "nvd", [record(), record(upstream="bad", url="http://127.0.0.1/admin")],
                                         {"pending": {"offset": 20}}, NOW, NEXT, False)
        self.assertEqual(self.store.stats()["total_records"], 0)
        self.assertEqual(self.store.stats()["total_revisions"], 0)
        self.assertEqual(self.store.get_cursor("nvd"), {})

    def test_partial_window_commits_resumable_cursor_then_failure_keeps_it(self):
        pending = {"finished_until": "2026-09-29T00:00:00Z", "pending": {"start": NOW, "offset": 2000}}
        self.ingest([record()], cursor=pending, complete=False)
        state = self.store.get_source_state("nvd")
        self.assertEqual(state["cursor"], pending)
        self.assertEqual(state["last_success_at"], NOW)
        self.assertIsNone(state["last_completed_at"])
        self.assertFalse(state["last_result"]["complete"])
        self.assertEqual(self.store.list_runs()[0]["status"], "partial")
        run = self.store.begin_run("nvd", LATER)
        self.store.fail_run(run, "nvd", "HTTP 429; Retry-After=3600", LATER, NEXT)
        state = self.store.get_source_state("nvd")
        self.assertEqual(state["cursor"], pending)
        self.assertEqual(state["next_run_at"], NEXT)
        self.assertEqual(state["consecutive_failures"], 1)
        self.assertEqual(state["last_success_at"], NOW)
        self.ingest([], now=NEXT, cursor={"finished_until": LATER}, complete=True)
        state = self.store.get_source_state("nvd")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertIsNone(state["last_error"])
        self.assertEqual(state["last_completed_at"], NEXT)

    def test_failure_counter_error_redaction_and_cursor_preservation(self):
        self.ingest([], cursor={"window_end": NOW})
        for timestamp in [LATER, NEXT]:
            run = self.store.begin_run("nvd", timestamp)
            self.store.fail_run(run, "nvd", "Authorization: Bearer TOPSECRET https://example.com/?api_key=KEYSECRET", timestamp, NEXT)
        state = self.store.get_source_state("nvd")
        self.assertEqual(state["consecutive_failures"], 2)
        self.assertEqual(state["cursor"], {"window_end": NOW})
        self.assertNotIn("TOPSECRET", state["last_error"])
        self.assertNotIn("KEYSECRET", json.dumps(self.store.list_runs()))

    def test_source_mismatch_and_finished_run_cannot_commit(self):
        run = self.store.begin_run("nvd", NOW)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(run, "nvd", [record("other")], {}, NOW, NEXT, True)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(run, "other", [], {}, NOW, NEXT, True)
        self.store.fail_run(run, "nvd", "failed", NOW, NEXT)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(run, "nvd", [], {"oops": 1}, NOW, NEXT, True)
        self.assertEqual(self.store.stats()["total_records"], 0)

    def test_older_overlapping_run_cannot_regress_committed_cursor(self):
        old = self.store.begin_run("nvd", NOW)
        new = self.store.begin_run("nvd", LATER)
        self.store.ingest_and_finish(new, "nvd", [], {"latest": 2}, LATER, NEXT, True)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(old, "nvd", [], {"older": 1}, NOW, NEXT, True)
        self.store.fail_run(old, "nvd", "late older failure", LATER, NEXT)
        state = self.store.get_source_state("nvd")
        self.assertEqual(state["cursor"], {"latest": 2})
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertIsNone(state["last_error"])

    def test_chinese_query_pagination_source_kind_and_sql_injection(self):
        self.ingest([record(upstream="a", title="PyTorch 中文安全漏洞 100%"),
                     record(upstream="b", title="LLM 中文研究", kind="paper"),
                     record(upstream="c", title="MLflow English security")])
        first = self.store.list_records(limit=1, query="中文")
        second = self.store.list_records(limit=1, offset=1, query="中文")
        self.assertEqual(first[0]["upstream_id"], "b")
        self.assertEqual(second[0]["upstream_id"], "a")
        self.assertEqual(self.store.list_records(limit=1, offset=2, query="中文"), [])
        self.assertEqual(len(self.store.list_records(kind="paper", source_id="nvd", query="中文")), 1)
        self.assertEqual(self.store.list_records(query="%' OR 1=1 --"), [])
        self.assertEqual(len(self.store.list_records(query="100%")), 1)
        self.assertEqual(self.store.list_records(query="_"), [])
        self.assertEqual(self.store.list_records(source_id="nvd' OR 1=1 --"), [])
        for kwargs in [{"limit": -1}, {"limit": 501}, {"offset": -1}, {"limit": True}, {"query": []}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.store.list_records(**kwargs)

    def test_metadata_demo_attribution_and_public_evidence_are_preserved(self):
        metadata = {"demo": True, "terms_url": "https://example.com/terms", "attribution": "Example upstream",
                    "usage_conditions": "Metadata only; source rights apply", "revision": "v2",
                    "Authorization": "SECRET1", "nested": {"api_key": "SECRET2", "status": "public"}}
        self.ingest([record(metadata=metadata)])
        event = self.store.get_record(1)
        self.assertTrue(event["metadata"]["demo"])
        self.assertEqual(event["metadata"]["attribution"], metadata["attribution"])
        self.assertEqual(event["metadata"]["usage_conditions"], metadata["usage_conditions"])
        self.assertEqual(event["metadata"]["nested"], {"status": "public"})
        self.assertNotIn("SECRET", json.dumps(event))
        self.assertEqual(metadata["Authorization"], "SECRET1")  # Caller evidence is not mutated.

    def test_credential_and_private_network_url_boundaries(self):
        unsafe_urls = ["https://user:pass@example.com/a", "https://example.com/?%74oken=SECRET",
                       "http://127.0.0.1/", "http://127.1/", "http://2130706433/",
                       "http://0x7f000001/", "http://10.0.0.1/", "http://169.254.169.254/latest/",
                       "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://localhost/",
                       "http://host.local/", "file:///etc/passwd", "javascript:alert(1)",
                       "https://example.com\\@localhost/", "https://example.com/\n"]
        for index, url in enumerate(unsafe_urls):
            with self.subTest(url=url):
                run = self.store.begin_run("nvd", NOW)
                with self.assertRaises(ValueError):
                    self.store.ingest_and_finish(run, "nvd", [record(upstream=str(index), url=url)], {}, NOW, NEXT, True)
                self.store.fail_run(run, "nvd", "invalid URL", NOW, NEXT)
        self.assertEqual(self.store.stats()["total_records"], 0)
        self.assertEqual(self.store.get_cursor("nvd"), {})

    def test_unsafe_reference_and_cursor_credentials_abort_the_transaction(self):
        run = self.store.begin_run("nvd", NOW)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(run, "nvd", [record(references=["https://user:secret@example.com/"])], {}, NOW, NEXT, True)
        with self.assertRaises(ValueError):
            self.store.ingest_and_finish(run, "nvd", [record()], {"access_token": "SECRET"}, NOW, NEXT, True)
        self.assertEqual(self.store.stats()["total_records"], 0)

    def test_statistics_separate_collection_publication_and_history(self):
        self.ingest([record(), record(upstream="non-ai", title="Email database", summary="Availability")])
        stats = self.store.stats()
        self.assertEqual(stats["total_records"], 2)
        self.assertEqual(stats["ai_related_records"], 1)
        self.assertEqual(stats["non_ai_records"], 1)
        self.assertEqual(stats["total_observations"], 2)
        self.assertEqual(stats["total_revisions"], 2)
        self.assertEqual(stats["by_source"], {"nvd": 2})
        self.assertEqual(stats["last_collected_at"], NOW)
        event = self.store.list_records()[0]
        self.assertEqual(event["published_at"], "2020-01-01T00:00:00Z")
        self.assertEqual(event["first_seen_at"], NOW)

    def test_threaded_writes_and_reads_use_independent_connections(self):
        def work(index):
            source = "source-" + str(index)
            run = self.store.begin_run(source, NOW)
            self.store.ingest_and_finish(run, source, [record(source, aliases=[CVE])], {"index": index}, NOW, NEXT, True)
            return self.store.get_cursor(source), self.store.list_records()
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(work, range(8)))
        self.assertEqual([cursor["index"] for cursor, _ in results], list(range(8)))
        event = self.store.get_record(1)
        self.assertEqual(event["observation_count"], 8)
        self.assertEqual(event["revision_count"], 8)
        self.assertEqual(self.store.stats()["total_records"], 1)
        Store(self.path)  # Schema initialization is restartable.
        self.assertEqual(self.store.stats()["total_revisions"], 8)

    def test_relevance_rule_change_does_not_rewrite_upstream_history(self):
        self.ingest([record()])
        changed = {"is_ai_related": False, "score": 0.0, "reasons": ["Rule changed"], "risk_categories": []}
        with patch("aicti_monitor.storage.classify", return_value=changed):
            _, counts = self.ingest([record()], now=LATER)
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(self.store.list_records(), [])
        event = self.store.get_record(1)
        self.assertEqual(event["revision_count"], 1)
        self.assertTrue(event["revisions"][0]["is_ai_related"])
        self.assertFalse(event["is_ai_related"])

    def test_naive_timestamps_and_non_json_metadata_fail_without_cursor_commit(self):
        with self.assertRaises(ValueError):
            self.store.begin_run("nvd", "2026-09-30T10:00:00")
        run = self.store.begin_run("nvd", NOW)
        for metadata in [{"value": float("nan")}, {"value": object()}]:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                self.store.ingest_and_finish(run, "nvd", [record(metadata=metadata)], {"done": True}, NOW, NEXT, True)
        self.assertEqual(self.store.get_cursor("nvd"), {})
        self.assertEqual(self.store.stats()["total_records"], 0)


if __name__ == "__main__":
    unittest.main()
