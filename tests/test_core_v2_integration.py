"""Offline checks of the new user-visible orchestration boundaries."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aicti_core.demo import ALIAS,default_assets,seed_demo
from aicti_core.service import Application
from aicti_core.store import CoreStore
from aicti_core.grounding import compose_answer
from aicti_core.qa import answer as actual_answer


class V2IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CoreStore(Path(self.temp.name)/"system.sqlite3")
        seed_demo(self.store.monitor_store)
        self.app = Application(self.store,demo=True)
        self.app.import_assets(default_assets())
        self.app.process()

    def tearDown(self):
        self.app.stop()
        self.temp.cleanup()

    def test_explicit_mock_runs_same_planning_tool_and_analysis_path(self):
        status = self.app.configure_model({"provider":"mock"})["model"]
        self.assertEqual(status["provider"],"mock")
        self.assertTrue(status["enabled"])
        result = self.app.ask(ALIAS+"影响哪些资产，应该如何处置并说明依据？")
        self.assertEqual(result["mode"],"mock_model")
        self.assertEqual(result["retrieval"],"mock_plan")
        self.assertTrue(result["claims"])
        self.assertTrue(result["analysis_sections"])
        self.assertTrue(all(self.store.evidence(c["evidence_id"])["current"] for c in result["citations"]))
        self.assertTrue(any(t.get("event")=="tool" for t in result["trace"]))

    def test_deepseek_key_never_returned_or_saved_and_clear_disables(self):
        key = "test-private-credential-never-export"
        status = self.app.configure_model({"provider":"deepseek","api_key":key})
        self.assertTrue(status["model"]["credential_configured"])
        public = json.dumps({"settings":status,"system":self.app.system()})
        self.assertNotIn(key,public)
        with self.store.connection() as db:
            self.assertNotIn(key," ".join(db.iterdump()))
        self.app.configure_model({"provider":"deepseek","reasoning_effort":"low"})
        self.assertTrue(self.app.model_status()["credential_configured"])
        self.app.clear_model()
        self.assertFalse(self.app.model_status()["enabled"])
        self.assertFalse(self.app.model_status()["credential_configured"])
        self.assertIsNone(self.app.gateway)

    def test_model_reads_do_not_call_provider(self):
        self.app.configure_model({"provider":"mock"})
        with patch.object(type(self.app.gateway),"complete",side_effect=AssertionError("unexpected model call")):
            self.app.model_status()
            self.app.system()

    def test_mock_model_test_is_structured_and_never_cloud(self):
        self.app.configure_model({"provider":"mock"})
        check = self.app.test_model()
        self.assertTrue(check["ok"])
        self.assertEqual(check["model"]["provider"],"mock")
        self.assertIsNone(check["model"]["endpoint"])

    def test_settings_strict_provider_endpoint_and_key_boundaries(self):
        for settings in ({"provider":"deepseek","base_url":"http://127.0.0.1"},
                {"provider":"deepseek","model":"deepseek-other"},
                {"provider":"mock","api_key":"secret"},
                {"provider":[]},{"provider":"deepseek","api_key":"bad\nkey"}):
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    self.app.configure_model(settings)

    def test_clear_during_model_answer_stops_old_publication(self):
        self.app.configure_model({"provider":"mock"})
        def changing(question,snapshot,*,history=None,gateway=None):
            result = actual_answer(question,snapshot,history=history,gateway=None)
            if gateway is not None:
                self.app.clear_model()
            return result
        with patch("aicti_core.qa.answer",side_effect=changing):
            result = self.app.ask(ALIAS+"修复？")
        self.assertEqual(result["mode"],"pending")
        self.assertFalse(self.store.sessions())

    def test_supported_analysis_persisted_separately_from_verified_fact(self):
        self.app.configure_model({"provider":"mock"})
        def synthesized(question,snapshot,*,history=None,gateway=None):
            result = actual_answer(question,snapshot,history=history,gateway=None)
            if gateway is not None:
                card = result["claims"][0]
                result["analysis_sections"]=[{"kind":"recommendation","text":"建议先核对部署条件，再根据来源安排修复。",
                    "claim_ids":[card["id"]],"evidence_ids":card["evidence_ids"]}]
                result["answer"]=compose_answer(result["claims"],result["analysis_sections"])
                result["mode"]="mock_model"
            return result
        with patch("aicti_core.qa.answer",side_effect=synthesized):
            result = self.app.ask(ALIAS+"修复？")
        self.assertEqual(result["mode"],"mock_model")
        self.assertTrue(result["analysis_sections"])
        detail = self.store.session_detail(result["session_id"])
        self.assertEqual(detail["messages"][1]["payload"]["analysis_sections"],result["analysis_sections"])

    def test_metadata_fact_has_source_revision_not_fulltext_claim(self):
        snapshot = self.store.snapshot(demo=True)
        facts = [f for e in snapshot["events"] for f in e["facts"] if f["predicate"]=="source_metadata"]
        self.assertTrue(facts)
        self.assertTrue(all(f["evidence_ids"] for f in facts))
        self.assertTrue(all(f["value"]["monitoring"]=="feed" for f in facts))

    def test_sbom_passive_import_and_knowledge_api(self):
        result = self.app.import_sbom({"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"type":"library","name":"vllm","version":"99.1.0","purl":"pkg:pypi/vllm@99.1.0"}]})
        self.assertEqual(result["count"],1)
        self.assertTrue(result["warnings"])
        self.app.process()
        assets = self.store.snapshot(demo=True)["assets"]
        self.assertIsNone(assets[0]["exposed"])
        self.assertIsNone(assets[0]["authenticated"])
        catalog = self.app.knowledge()
        self.assertTrue(catalog["items"])
        self.assertTrue(all(item["monitoring"]=="curated" for item in catalog["items"]))
