"""Offline regressions for V2 degradation and curated permission races."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aicti_core.catalog_ingest import seed_catalog
from aicti_core.demo import default_assets, seed_demo
from aicti_core.mock_gateway import MockGateway
from aicti_core.qa import answer
from aicti_core.service import Application
from aicti_core.store import CoreStore, utc_now
from aicti_monitor.models import Record


class DegradedModelBoundaryRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CoreStore(Path(self.temp.name) / "system.sqlite3")
        seed_demo(self.store.monitor_store)
        self.app = Application(self.store, demo=True)
        self.app.import_assets(default_assets())
        self.app.process()

    def tearDown(self):
        self.temp.cleanup()

    def assert_degradation_preserved(self, scenario, reason):
        # This ordinary wording exercises model planning without an exact CVE.
        question = "这种示例该怎么办？"
        raw = answer(question, self.store.snapshot(demo=True),
                     gateway=MockGateway(scenario=scenario))
        self.assertEqual(raw["mode"], "degraded")
        self.assertTrue(any(reason in warning for warning in raw["warnings"]))
        self.app.gateway = MockGateway(scenario=scenario)
        submitted = self.app.ask(question)

        self.assertEqual(submitted["mode"], "degraded")
        self.assertTrue(any(reason in warning for warning in submitted["warnings"]),
                        "The application must retain the actual model failure reason")
        self.assertEqual(submitted.get("model_provider"), "mock")
        self.assertEqual(submitted.get("model"), "mock-deepseek-v4-pro")
        self.assertTrue(any("未调用真实 DeepSeek" in warning
                            for warning in submitted["warnings"]))
        self.assertEqual(submitted["retrieval"], raw["retrieval"])
        self.assertEqual(submitted["claims"], raw["claims"],
                         "Host-verified planned cards must survive synthesis failure")
        self.assertNotIn("回答文本未通过事实卡校验。", submitted["warnings"])
        saved = self.store.session_detail(submitted["session_id"])["messages"][1]["payload"]
        self.assertEqual(saved["retrieval"], raw["retrieval"])
        self.assertEqual(saved["model_provider"], "mock")
        self.assertTrue(any(reason in warning for warning in saved["warnings"]))

    def test_invalid_synthesis_keeps_mock_plan_facts_and_failure_reason(self):
        self.assert_degradation_preserved("invalid_json", "无效结构")

    def test_rate_limited_planning_keeps_specific_reason_and_mock_label(self):
        self.assert_degradation_preserved("rate_limited", "限流")


class CuratedPermissionRaceRegressions(unittest.TestCase):
    def assert_seed_preserves_concurrent_revocation(self, field, value):
        with tempfile.TemporaryDirectory() as temporary:
            store = CoreStore(Path(temporary) / "system.sqlite3")
            monitor = store.monitor_store
            seed_catalog(monitor)
            original_begin_run = monitor.begin_run
            committed = []

            def revoke_after_catalog_preparation(source_id, collected_at):
                # seed_catalog has already checked every previous record by
                # this seam. A second writer now commits a newer restriction.
                if source_id == "catalog-nist" and not committed:
                    with monitor._connection() as db:
                        row = db.execute(
                            "SELECT record_json FROM observations WHERE source_id=? "
                            "ORDER BY id LIMIT 1", (source_id,)).fetchone()
                    payload = json.loads(row[0])
                    payload["metadata"][field] = value
                    now = utc_now()
                    run = original_begin_run(source_id, now)
                    monitor.ingest_and_finish(run, source_id, [Record(**payload)],
                                              {"permission_revision": field}, now, now, True)
                    committed.append(payload["upstream_id"])
                return original_begin_run(source_id, collected_at)

            with patch.object(monitor, "begin_run", side_effect=revoke_after_catalog_preparation):
                seed_catalog(monitor)

            self.assertEqual(len(committed), 1, "The concurrent restriction must be committed")
            with monitor._connection() as db:
                row = db.execute(
                    "SELECT record_json FROM observations WHERE source_id=? AND upstream_id=?",
                    ("catalog-nist", committed[0])).fetchone()
            current = json.loads(row[0])
            self.assertIs(current["metadata"].get(field), value,
                          "Prepared curated metadata must not undo a newer restriction")

    def test_seed_does_not_restore_concurrently_revoked_authorization(self):
        self.assert_seed_preserves_concurrent_revocation("authorized", False)

    def test_seed_does_not_restore_concurrently_withdrawn_record(self):
        self.assert_seed_preserves_concurrent_revocation("withdrawn", True)

    def test_seed_does_not_restore_concurrently_disabled_enrichment(self):
        self.assert_seed_preserves_concurrent_revocation("enrichment_allowed", False)


if __name__ == "__main__":
    unittest.main()
