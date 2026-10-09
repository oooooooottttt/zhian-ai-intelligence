from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aicti_monitor.models import Record
from aicti_core.contracts import EnrichmentResult,Fact,Assessment
from aicti_core.store import CoreStore,StaleResult,utc_now,validate_assets

CVE = "CVE-2099-99001"
OTHER = "CVE-2099-99002"

def rec(source="fixture",upstream="one",**kwargs):
    data = {"source_id":source,"upstream_id":upstream,"kind":"vulnerability",
        "title":"vLLM fixture advisory","summary":"AI inference fixture",
        "url":"https://example.com/advisory/"+upstream,"aliases":[CVE],
        "metadata":{"packages":[{"ecosystem":"pip","name":"vllm","vulnerable_version_range":"< 99.2.0","patched_versions":"99.2.0"}]}}
    data.update(kwargs)
    return Record(**data)

def asset(**kwargs):
    return {"asset_id":"one","ecosystem":"pip","component":"vllm","version":"99.1.0",**kwargs}

class CoreStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/"database.sqlite3"
        self.store = CoreStore(self.path)
    def tearDown(self):
        self.temp.cleanup()
    def ingest(self,*records):
        at = utc_now()
        run = self.store.monitor_store.begin_run(records[0].source_id,at)
        return self.store.monitor_store.ingest_and_finish(run,records[0].source_id,list(records),{},at,at,True)
    def result(self,task):
        refs = tuple(e["id"] for e in task["evidence"] if not e["withdrawn"])
        return EnrichmentResult(facts=(Fact("impact",{"text":"fixture impact"},refs),)) if refs else EnrichmentResult()
    def ready(self):
        self.ingest(rec())
        task = self.store.claim("worker")
        self.store.publish(task,self.result(task))
        return self.store.snapshot()
    def response(self,snapshot):
        event = snapshot["events"][0]
        ref = event["evidence_ids"][0]
        return {"answer":"fixture","claims":[{"text":"fixture","entity_id":event["id"],"predicate":"impact","evidence_ids":[ref]}],
            "citations":[{"evidence_id":ref,"source_id":"forged","url":"http://127.0.0.1/private"}],"entities":[event["id"]]}

    def test_idempotent_reconciliation_and_existing_monitor_schema(self):
        self.ingest(rec())
        self.store.sync(); self.store.sync()
        self.assertEqual(len(self.store.jobs()),1)
        with self.store.connection() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],1)
    def test_revision_atomically_invalidates_projection(self):
        before = self.ready()
        self.ingest(rec(summary="vLLM changed"))
        after = self.store.snapshot()
        self.assertGreater(after["knowledge_epoch"],before["knowledge_epoch"])
        self.assertEqual(after["events"][0]["status"],"dirty")
        self.assertEqual(after["events"][0]["facts"],[])
    def test_duplicate_fetch_does_not_invalidate(self):
        before = self.ready()
        self.ingest(rec())
        self.assertEqual(self.store.snapshot()["knowledge_epoch"],before["knowledge_epoch"])
        self.assertEqual(self.store.snapshot()["events"][0]["status"],"ready")
    def test_monitor_failure_rolls_back_trigger_and_evidence(self):
        before = self.ready()
        at = utc_now()
        run = self.store.monitor_store.begin_run("fixture",at)
        with self.assertRaises(ValueError):
            self.store.monitor_store.ingest_and_finish(run,"fixture",[rec(summary="vLLM changed"),rec(source="wrong")],{},at,at,True)
        self.assertEqual(self.store.snapshot()["knowledge_epoch"],before["knowledge_epoch"])
        self.assertEqual(self.store.snapshot()["events"][0]["status"],"ready")
    def test_lease_expired_without_reclaim_is_rejected(self):
        self.ingest(rec())
        task = self.store.claim("first",now=100,lease_seconds=2)
        with self.assertRaises(StaleResult):
            self.store.publish(task,self.result(task),now=103)
    def test_old_worker_cannot_publish_after_reclaim(self):
        self.ingest(rec())
        first = self.store.claim("first",now=100,lease_seconds=2)
        second = self.store.claim("second",now=103,lease_seconds=2)
        self.assertEqual(first["id"],second["id"])
        with self.assertRaises(StaleResult):
            self.store.publish(first,self.result(first),now=103)
        self.store.publish(second,self.result(second),now=104)
    def test_lease_sample_after_transaction_lock(self):
        import threading
        self.ingest(rec())
        task = self.store.claim("worker",lease_seconds=.1)
        outcome = []
        def publish():
            try:
                self.store.publish(task,self.result(task))
                outcome.append("published")
            except StaleResult:
                outcome.append("stale")
        with self.store.connection(write=True):
            worker = threading.Thread(target=publish)
            worker.start(); time.sleep(.2)
        worker.join(timeout=3)
        self.assertEqual(outcome,["stale"])
    def test_source_change_cancels_running_job(self):
        self.ingest(rec())
        task = self.store.claim("worker")
        self.ingest(rec(summary="vLLM corrected"))
        with self.assertRaises(StaleResult):
            self.store.publish(task,self.result(task))
    def test_asset_import_cancels_running_job(self):
        self.ingest(rec())
        task = self.store.claim("worker")
        self.store.import_assets([asset()])
        with self.assertRaises(StaleResult):
            self.store.publish(task,self.result(task))
    def test_policy_terms_change_invalidates(self):
        self.store.set_policy(["fixture"],source_conditions={"license":"one"})
        before = self.ready()
        self.store.set_policy(["fixture"],source_conditions={"license":"two"})
        after = self.store.snapshot()
        self.assertGreater(after["policy_generation"],before["policy_generation"])
        self.assertEqual(after["events"][0]["status"],"dirty")
    def test_cross_entity_evidence_not_accepted(self):
        self.ingest(rec(),rec(upstream="two",aliases=[OTHER]))
        task = self.store.claim("worker")
        alien = next(e["id"] for e in self.store.snapshot()["evidence"] if e["id"] not in [x["id"] for x in task["evidence"]])
        with self.assertRaises(ValueError):
            self.store.publish(task,EnrichmentResult(facts=(Fact("impact",{"text":"wrong"},(alien,)),)))
    def test_publish_transaction_failure_has_no_partial_ready(self):
        self.ingest(rec())
        task = self.store.claim("worker")
        with self.store.connection(write=True) as db:
            db.execute("CREATE TRIGGER fail_result BEFORE INSERT ON kb_results BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.publish(task,self.result(task))
        self.assertEqual(self.store.snapshot()["events"][0]["status"],"dirty")
        self.assertEqual(self.store.jobs()[0]["status"],"running")
    def test_withdrawal_invalidates_answer_and_keeps_history(self):
        before = self.ready()
        old = before["evidence"][0]["id"]
        self.ingest(rec(metadata={"withdrawn":True,"status":"withdrawn"}))
        with self.assertRaises(StaleResult):
            self.store.save_answer("query",self.response(before),before)
        self.assertFalse(self.store.evidence(old)["current"])
        self.assertTrue(self.store.snapshot()["evidence"][0]["withdrawn"])
    def test_citation_fields_are_owned_by_database(self):
        snapshot = self.ready()
        result = self.store.save_answer("query",self.response(snapshot),snapshot)
        self.assertEqual(result["citations"][0]["source_id"],"fixture")
        self.assertEqual(result["citations"][0]["url"],"https://example.com/advisory/one")
    def test_answer_cannot_omit_entity_dependency(self):
        snapshot = self.ready()
        response = self.response(snapshot); response["entities"] = []
        with self.assertRaises(StaleResult):
            self.store.save_answer("query",response,snapshot)
    def test_merge_and_removed_bridge_require_manual_review(self):
        self.ingest(rec(upstream="a"),rec(upstream="b",aliases=[OTHER]))
        self.store.sync()
        self.ingest(rec(upstream="bridge",aliases=[CVE,OTHER]))
        self.store.sync()
        self.ingest(rec(upstream="bridge",aliases=[CVE,OTHER],metadata={"withdrawn":True}))
        event = self.store.snapshot()["events"][0]
        self.assertEqual(event["status"],"quarantined")
        groups = [[e["observation_id"]] for e in self.store.snapshot()["evidence"]]
        with self.assertRaises(StaleResult):
            self.store.confirm_groups(event["id"],groups,"fixture",expected_generation=event["generation"]-1)
        self.store.confirm_groups(event["id"],groups,"fixture",expected_generation=event["generation"])
        self.assertEqual(len(self.store.snapshot()["events"]),3)
        self.ingest(rec(upstream="a",summary="vLLM revised"))
        event = next(e for e in self.store.snapshot()["events"] if e["status"]=="quarantined")
        self.store.confirm_groups(event["id"],groups,"fixture again",expected_generation=event["generation"])
        self.assertEqual(len(self.store.snapshot()["events"]),3)
        self.assertTrue(all(e["status"]=="dirty" for e in self.store.snapshot()["events"]))
    def test_inventory_security_and_unknowns(self):
        normalized = validate_assets([asset(version="unknown")])[0]
        self.assertIsNone(normalized["exposed"])
        for rows in ([asset(url="http://127.0.0.1")],[asset(component="https://user:password@example.com")],[asset(exposed="false")],[asset(),asset()]):
            with self.assertRaises(ValueError):
                validate_assets(rows)
    def test_source_authorization_hides_removed_source(self):
        self.ready()
        self.store.set_policy([])
        self.assertEqual(self.store.snapshot()["events"],[])
        self.assertIsNone(self.store.evidence("obs:1:r:1"))
    def test_new_permission_deny_blocks_historical_evidence(self):
        self.ready()
        self.ingest(rec(metadata={"authorized":False}))
        self.assertEqual(self.store.snapshot()["evidence"],[])
        self.assertIsNone(self.store.evidence("obs:1:r:1"))
    def test_permission_denied_relation_target_is_rejected(self):
        self.ingest(rec())
        self.ingest(rec(upstream="paper",kind="paper",metadata={"authorized":False},aliases=[]))
        task = self.store.claim("worker")
        self.assertEqual(task["related"],[])
        fact = Fact("related_material",{"target_evidence_id":"obs:2:r:1","relation":"direct"},("obs:1:r:1",))
        with self.assertRaises(ValueError):
            self.store.publish(task,EnrichmentResult(facts=(fact,)))
    def test_related_poc_stays_metadata_only(self):
        self.ingest(rec())
        self.ingest(rec(upstream="paper",kind="paper",metadata={"defect_ids":[CVE]},aliases=[]))
        task = self.store.claim("worker")
        value = {"url":"https://example.com/poc","target_evidence_ids":["obs:1:r:1"],
            "availability":"not_checked","verification":"unverified","downloaded":False,"executed":False}
        fact = Fact("poc_reference",value,("obs:2:r:1","obs:1:r:1"),status="candidate")
        self.store.publish(task,EnrichmentResult(facts=(fact,)))
        self.assertEqual(self.store.snapshot()["events"][-1]["facts"][0]["status"],"candidate")
    def test_asset_expiry_is_a_new_input_without_source_change(self):
        self.ready()
        self.store.import_assets([asset()])
        task = self.store.claim("worker")
        self.store.publish(task,self.result(task))
        before = self.store.snapshot()
        with patch("aicti_core.store.time.time",return_value=time.time()+86401):
            after = self.store.snapshot()
            same = self.store.snapshot()
        self.assertGreater(after["knowledge_epoch"],before["knowledge_epoch"])
        self.assertEqual(after["events"][0]["status"],"dirty")
        self.assertEqual(same["knowledge_epoch"],after["knowledge_epoch"])
    def test_expiry_after_sync_is_rechecked_and_committed_at_publish(self):
        self.ingest(rec())
        self.store.import_assets([asset()])
        task = self.store.claim("worker")
        base = time.time()
        clock = [base]
        original = self.store.sync
        def sync_then_elapsed():
            result = original()
            clock[0] = base+86401
            return result
        with patch("aicti_core.store.time.time",side_effect=lambda:clock[0]),patch.object(self.store,"sync",side_effect=sync_then_elapsed):
            with self.assertRaises(StaleResult):
                self.store.publish(task,self.result(task))
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT status FROM kb_tasks WHERE id=?",(task["id"],)).fetchone()[0],"cancelled")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM kb_results").fetchone()[0],0)
    def test_expiry_after_sync_rejects_answer_without_rolling_back_invalidation(self):
        self.ready()
        self.store.import_assets([asset()])
        task = self.store.claim("worker")
        self.store.publish(task,self.result(task))
        before = self.store.snapshot()
        base,clock = time.time(),[time.time()]
        original = self.store.sync
        def sync_then_elapsed():
            result = original()
            clock[0] = base+86401
            return result
        with patch("aicti_core.store.time.time",side_effect=lambda:clock[0]),patch.object(self.store,"sync",side_effect=sync_then_elapsed):
            with self.assertRaises(StaleResult):
                self.store.save_answer("query",self.response(before),before)
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT status FROM kb_entities WHERE id=?",(before["events"][0]["id"],)).fetchone()[0],"dirty")
            self.assertGreater(db.execute("SELECT knowledge_epoch FROM kb_meta").fetchone()[0],before["knowledge_epoch"])
        self.assertEqual(self.store.sessions(),[])
