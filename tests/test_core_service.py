from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aicti_core.demo import seed_demo,default_assets,ALIAS,replay_demo
from aicti_core.qa import answer as actual_answer
from aicti_core.qa import host_card_catalog
from aicti_core.service import Application
from aicti_core.store import CoreStore,detached

class FakeGateway:
    enabled = True
    embedding_enabled = False
    model = "test"

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CoreStore(Path(self.temp.name)/"system.sqlite3")
        seed_demo(self.store.monitor_store)
        self.app = Application(self.store,demo=True)
        self.app.import_assets(default_assets())
        self.assertEqual(self.app.process()["processed"],3)
    def tearDown(self):
        self.app.stop()
        self.temp.cleanup()

    def test_inventory_to_impact_fix_and_citation(self):
        result = self.app.ask(ALIAS+" 影响哪些资产，如何修复？")
        self.assertEqual(result["mode"],"facts")
        self.assertTrue(any(c["predicate"]=="asset_assessment" and c["value"]["status"]=="potentially_affected" for c in result["claims"]))
        self.assertTrue(any(c["predicate"]=="fix" for c in result["claims"]))
        self.assertTrue(all(self.store.evidence(c["evidence_id"])["current"] for c in result["citations"]))
    def test_withdrawal_corrects_current_answer_keeps_history(self):
        result = self.app.ask(ALIAS+" 如何修复？")
        self.assertTrue(result["claims"])
        epoch = result["knowledge_epoch"]
        self.app.withdraw_demo(); self.app.process()
        result = self.app.ask("它现在如何修复？",result["session_id"])
        self.assertGreater(result["knowledge_epoch"],epoch)
        self.assertFalse(any(c["predicate"]=="fix" for c in result["claims"]))
        self.assertFalse(self.store.evidence("obs:1:r:1")["current"])
        self.assertTrue(seed_demo(self.store.monitor_store) is False)
    def test_explicit_demo_replay_is_new_revision_and_retains_history(self):
        self.app.withdraw_demo(); self.app.process()
        self.assertTrue(self.store.evidence("obs:1:r:2")["withdrawn"])
        replay_demo(self.store.monitor_store); self.app.process()
        self.assertFalse(self.store.evidence("obs:1:r:3")["withdrawn"])
        self.assertTrue(self.store.evidence("obs:1:r:2")["withdrawn"])
        result = self.app.ask(ALIAS+" 如何修复？")
        self.assertTrue(any(c["evidence_id"]=="obs:1:r:3" for c in result["citations"]))
    def test_changed_inventory_is_reassessed(self):
        rows = default_assets()
        rows[0]["version"] = "99.2.0"
        self.app.import_assets(rows); self.app.process()
        result = self.app.ask(ALIAS+" 资产 demo-inference 影响如何？")
        matches = [c for c in result["claims"] if c["predicate"]=="asset_assessment"]
        self.assertTrue(matches)
        self.assertTrue(all(c["value"]["status"]=="not_affected_with_reason" for c in matches))
    def test_model_unavailable_keeps_supported_cards(self):
        self.app.gateway = FakeGateway()
        result = self.app.ask("反序列化服务有什么修复依据？")
        self.assertEqual(result["mode"],"degraded")
        self.assertTrue(result["claims"])
    def fake_answer(self,mutate):
        def injected(question,snapshot,*,history=None,gateway=None):
            result = actual_answer(question,snapshot,history=history,gateway=None)
            if gateway is not None:
                result = mutate(result,snapshot)
            return result
        return injected
    def test_free_prose_without_claims_is_rejected(self):
        self.app.gateway = FakeGateway()
        def mutate(result,_):
            return {**result,"answer":"所有资产完全安全","claims":[],"citations":[],"entities":[],"mode":"local_model"}
        with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
            result = self.app.ask(ALIAS+" 如何修复？")
        self.assertEqual(result["mode"],"degraded")
        self.assertNotIn("完全安全",result["answer"])
        self.assertTrue(result["claims"])
    def test_malformed_claims_or_citations_degrade(self):
        self.app.gateway = FakeGateway()
        for key in ("claims","citations"):
            with self.subTest(key=key):
                def mutate(result,_,key=key):
                    return {**result,key:[None]}
                with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
                    result = self.app.ask(ALIAS+" 如何修复？")
                self.assertEqual(result["mode"],"degraded")
                self.assertTrue(result["claims"])
    def test_missing_citations_or_entities_are_output_errors(self):
        self.app.gateway = FakeGateway()
        for key in ("citations","entities"):
            with self.subTest(key=key):
                def mutate(result,_,key=key):
                    return {**result,key:[]}
                with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
                    result = self.app.ask(ALIAS+" 如何修复？")
                self.assertEqual(result["mode"],"degraded")
                self.assertTrue(result["claims"])
                self.assertTrue(result["citations"])
    def test_unhashable_model_identifiers_degrade(self):
        self.app.gateway = FakeGateway()
        for key,field in (("claims","id"),("citations","evidence_id")):
            with self.subTest(key=key):
                def mutate(result,_,key=key,field=field):
                    result[key][0][field] = []
                    return result
                with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
                    result = self.app.ask(ALIAS+" 如何修复？")
                self.assertEqual(result["mode"],"degraded")
                self.assertTrue(result["claims"])
    def test_history_survives_reopening_database(self):
        first = self.app.ask(ALIAS+" 如何修复？")
        reopened = CoreStore(self.store.path)
        detail = reopened.session_detail(first["session_id"])
        self.assertEqual(len(detail["messages"]),2)
        self.assertEqual(detail["messages"][1]["payload"]["citations"],first["citations"])
        self.app.withdraw_demo(); self.app.process()
        self.assertTrue(reopened.session_detail(first["session_id"])["messages"][1]["stale"])
    def test_model_cannot_change_card_value_or_text(self):
        self.app.gateway = FakeGateway()
        def mutate(result,_):
            result["claims"][0]["text"] = "未经证实的入侵结论"
            result["answer"] = "\n".join(c["text"] for c in result["claims"])
            return result
        with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
            result = self.app.ask(ALIAS+" 如何修复？")
        self.assertEqual(result["mode"],"degraded")
        self.assertNotIn("未经证实",result["answer"])
    def test_model_cannot_mutate_authoritative_baseline(self):
        self.app.gateway = FakeGateway()
        before = detached(self.store.snapshot())
        def mutate(result,snapshot):
            snapshot["knowledge_epoch"] = 999999
            snapshot["events"][0]["facts"] = []
            return result
        with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
            result = self.app.ask(ALIAS+" 如何修复？")
        self.assertEqual(result["knowledge_epoch"],before["knowledge_epoch"])
        self.assertEqual(self.store.snapshot()["events"],before["events"])
    def test_semantic_recall_cards_outside_keyword_reference_are_host_verified(self):
        self.app.gateway = FakeGateway()
        def semantic(question,snapshot,*,history=None,gateway=None):
            if gateway is None:
                return actual_answer(question,snapshot,history=history)
            event = next(e for e in snapshot["events"] if ALIAS in e["aliases"])
            card = next(c for c in host_card_catalog(snapshot,[event["id"]]).values() if c["predicate"]=="fix")
            claim = {k:card[k] for k in ("id","text","evidence_ids","entity_id","predicate","value")}
            citations = [{"evidence_id":i} for i in claim["evidence_ids"]]
            return {"answer":claim["text"],"claims":[claim],"citations":citations,"entities":[event["id"]],
                "mode":"local_model","warnings":[],"trace":[],"knowledge_epoch":snapshot["knowledge_epoch"],
                "as_of":snapshot["as_of"],"retrieval":"hybrid_local"}
        with patch("aicti_core.qa.answer",side_effect=semantic):
            result = self.app.ask("这种示例该怎么办？")
        self.assertEqual(result["mode"],"local_model")
        self.assertEqual(result["claims"][0]["predicate"],"fix")
        self.assertEqual(result["citations"][0]["source_id"],"demo-advisory")
    def test_new_knowledge_during_answer_returns_pending_without_saved_claim(self):
        self.app.gateway = FakeGateway()
        def mutate(result,_):
            self.app.withdraw_demo()
            return result
        with patch("aicti_core.qa.answer",side_effect=self.fake_answer(mutate)):
            result = self.app.ask(ALIAS+" 如何修复？")
        self.assertEqual(result["mode"],"pending")
        self.assertEqual(result["claims"],[])
        self.assertIsInstance(result["session_id"],str)
        self.assertEqual(self.store.sessions(),[])
    def test_detail_concurrent_withdrawal_never_returns_current_old_facts(self):
        event = next(e for e in self.store.snapshot()["events"] if ALIAS in e["aliases"])
        original = self.store.evidence
        fired = []
        def inject(ident):
            if not fired:
                fired.append(True); self.app.withdraw_demo()
            return original(ident)
        with patch.object(self.store,"evidence",side_effect=inject):
            detail = self.app.event(event["id"])
        self.assertTrue(detail["stale"])
        self.assertEqual(detail["facts"],[])
    def test_live_collection_is_disabled_in_demo(self):
        self.assertFalse(self.app.collect_now()["queued"])
        self.assertTrue(self.app.system()["snapshot"]["demo"])
