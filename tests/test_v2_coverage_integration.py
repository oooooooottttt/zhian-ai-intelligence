"""Production wiring of metadata sources into current, cited host facts."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aicti_monitor.config import load_sources
from aicti_monitor.adapters.nvd import parse
from aicti_core.catalog_ingest import seed_catalog
from aicti_core.service import Application
from aicti_core.store import CoreStore, utc_now


class CoverageIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CoreStore(Path(self.temp.name)/"coverage.sqlite3")
        self.sources = load_sources()
        self.app = Application(self.store,self.sources)

    def tearDown(self):
        self.app.stop()
        self.temp.cleanup()

    def test_two_official_feeds_are_registered_with_reviewed_metadata_scope(self):
        sources = {s.id:s for s in self.sources}
        for ident in ("nist-drafts","nist-cybersecurity-blog"):
            self.assertEqual(sources[ident].adapter,"nist_feeds")
            self.assertEqual(sources[ident].content_scope,"metadata_only")
            self.assertTrue(sources[ident].enabled)
            self.assertEqual(sources[ident].params["policy_status"],"reviewed")
        self.assertEqual(len(sources),7)
        self.assertEqual(len({s.category for s in sources.values()}),6)

    def test_explicit_poc_metadata_reaches_cited_fact_without_exploit_tag_promotion(self):
        source = next(s for s in self.sources if s.id=="nvd-ai")
        refs = [{"url":"https://github.com/example/research/poc","source":"NVD upstream label","tags":["POC"]},
                {"url":"https://github.com/example/research/discussion","tags":["Exploit"]},
                {"url":"https://github.com/example/research/untagged","tags":[]}]
        record = parse(source,{"vulnerabilities":[{"cve":{"id":"CVE-2026-12345",
            "descriptions":[{"lang":"en","value":"vllm security advisory"}],"references":refs}}]})[0]
        self.assertEqual(len(record.metadata["poc_references"]),1)
        self.assertEqual(len(record.metadata["tagged_reference_leads"]),2)
        at = utc_now()
        run = self.store.monitor_store.begin_run(source.id,at)
        self.store.monitor_store.ingest_and_finish(run,source.id,[record],{},at,at,True)
        self.app.process()
        facts = [f for e in self.store.snapshot()["events"] for f in e["facts"] if f["predicate"]=="poc_reference"]
        self.assertEqual(len(facts),1)
        value = facts[0]["value"]
        self.assertEqual(value["reference_class"],"explicit_poc_reference")
        self.assertEqual(value["upstream_tags"],["POC"])
        self.assertEqual(value["upstream_source"],"NVD upstream label")
        self.assertEqual(value["verification"],"unverified")
        self.assertFalse(value["downloaded"])
        self.assertFalse(value["executed"])
        self.assertTrue(facts[0]["evidence_ids"])

    def test_curated_metadata_is_queryable_with_calendar_dates_and_real_revisions(self):
        seed_catalog(self.store.monitor_store)
        self.app.process()
        snapshot = self.store.snapshot()
        facts = [f for e in snapshot["events"] for f in e["facts"] if f["predicate"]=="source_metadata"]
        self.assertEqual(len(facts),5)
        self.assertTrue(all(f["value"]["monitoring"]=="curated" for f in facts))
        self.assertTrue(all("UTC_instant_unknown" in f["value"]["date_precision"] for f in facts))
        self.app.configure_model({"provider":"mock"})
        result = self.app.ask("NIST FIPS 203 的资料内容、更新时间和来源是什么？")
        self.assertEqual(result["mode"],"mock_model")
        self.assertTrue(any(c["predicate"]=="source_metadata" for c in result["claims"]))
        self.assertTrue(result["citations"])
        self.assertTrue(all(self.store.evidence(c["evidence_id"])["current"] for c in result["citations"]))
        self.assertNotIn("虚构演示",result["answer"])

    def test_reimport_does_not_turn_collection_time_into_document_revision(self):
        seed_catalog(self.store.monitor_store)
        with self.store.connection() as db:
            before = [(r[0],r[1]) for r in db.execute("SELECT id,revision_count FROM observations ORDER BY id")]
        seed_catalog(self.store.monitor_store)
        with self.store.connection() as db:
            after = [(r[0],r[1]) for r in db.execute("SELECT id,revision_count FROM observations ORDER BY id")]
        self.assertEqual(before,after)


if __name__ == "__main__":
    unittest.main()
