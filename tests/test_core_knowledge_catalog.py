"""Offline boundaries for official curated metadata and the frozen API schema."""
import datetime
import json
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from aicti_core.knowledge_catalog import catalog_items, catalog_records, get_catalog, knowledge_catalog


ITEM_KEYS = {
    "id", "title", "kind", "source", "url", "updated_at", "summary", "topics",
    "attribution", "usage_conditions", "monitoring",
}


class KnowledgeCatalogTests(unittest.TestCase):
    def test_curated_record_projection_preserves_metadata_and_separates_feed(self):
        records = catalog_records(collected_at="2026-10-04T18:00:00+08:00")
        self.assertEqual(5, len(records))
        self.assertEqual([x["id"] for x in catalog_items()], [r.upstream_id for r in records])
        for record in records:
            self.assertEqual("official-knowledge-curated", record.source_id)
            self.assertEqual("curated", record.metadata["monitoring"])
            self.assertNotIn("demo", record.metadata)
            self.assertFalse(record.metadata["fulltext_fetched"])
            self.assertEqual("2026-10-04T10:00:00Z", record.metadata["collected_at"])
            self.assertTrue(record.summary)
            self.assertTrue(record.metadata["usage_conditions"])
            self.assertIn("curated", record.metadata["summary_origin"])
            self.assertEqual([], record.aliases)
            self.assertEqual([], record.components)
            self.assertEqual([], record.references)
            self.assertIsNone(record.published_at)
            self.assertIsNone(record.updated_at)
            datetime.date.fromisoformat(record.metadata["source_publication_date"])
            datetime.date.fromisoformat(record.metadata["source_updated_date"])
            if record.metadata["knowledge_kind"] == "guide":
                self.assertEqual("article", record.kind)
            json.dumps(record.to_dict(), allow_nan=False)
        records[0].metadata["topics"].append("caller data")
        self.assertNotIn("caller data", catalog_records()[0].metadata["topics"])

    def test_curated_projection_rejects_ambiguous_host_clock_and_source_identity(self):
        for timestamp in ("2026-10-04", "2026-10-04T10:00:00", "bad", 5):
            with self.assertRaises(ValueError):
                catalog_records(collected_at=timestamp)
        for identity in ("bad\nsource", "Password=fixture", "curated/source", ""):
            with self.assertRaises(ValueError):
                catalog_records(source_id=identity)

    def test_frozen_list_entry_point(self):
        items = catalog_items()
        self.assertIsInstance(items, list)
        self.assertEqual(knowledge_catalog()["items"], items)
        items[0]["topics"].append("caller modification")
        self.assertNotEqual(items, catalog_items())

    def test_frozen_schema_and_official_metadata_links(self):
        result = knowledge_catalog()
        self.assertEqual({"items", "coverage"}, set(result))
        identifiers = set()
        for item in result["items"]:
            with self.subTest(id=item["id"]):
                self.assertEqual(ITEM_KEYS, set(item))
                self.assertNotIn(item["id"], identifiers)
                identifiers.add(item["id"])
                self.assertIn(item["kind"], {"standard", "policy", "guide"})
                self.assertIn(item["monitoring"], {"curated", "feed"})
                self.assertEqual("curated", item["monitoring"])
                for field in ITEM_KEYS - {"topics"}:
                    self.assertIsInstance(item[field], str)
                    self.assertTrue(item[field])
                self.assertTrue(item["topics"])
                self.assertTrue(all(isinstance(topic, str) and topic for topic in item["topics"]))
                parsed = urlsplit(item["url"])
                self.assertEqual("https", parsed.scheme)
                self.assertIn(parsed.hostname, {"www.nist.gov", "csrc.nist.gov", "eur-lex.europa.eu"})
                self.assertIsNone(parsed.username)
                self.assertIsNone(parsed.password)
                self.assertFalse(parsed.path.lower().endswith(".pdf"))
                datetime.date.fromisoformat(item["updated_at"])
        self.assertEqual(5, len(identifiers))
        self.assertEqual(result, json.loads(json.dumps(result, ensure_ascii=False)))

    def test_every_snapshot_is_deeply_detached(self):
        baseline = knowledge_catalog()
        altered = get_catalog()
        altered["items"][0]["title"] = "caller-controlled"
        altered["items"][0]["topics"].append("caller topic")
        altered["items"].clear()
        altered["coverage"]["verification"][0]["supporting_urls"].append("https://attacker.invalid/")
        altered["coverage"]["gaps"].clear()
        self.assertEqual(baseline, knowledge_catalog())
        self.assertEqual(baseline, get_catalog())

    def test_catalog_retrieval_has_no_live_network_or_verification_clock(self):
        with patch("socket.create_connection", side_effect=AssertionError("no network")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("no fetch")):
            first = knowledge_catalog()
            second = get_catalog()
        self.assertEqual(first, second)
        self.assertEqual("2026-10-04", first["coverage"]["verified_on"])
        self.assertFalse(first["coverage"]["continuous_monitoring"])
        self.assertFalse(first["coverage"]["pdf_downloaded"])
        self.assertEqual(0, first["coverage"]["feed_count"])
        self.assertEqual(len(first["items"]), first["coverage"]["curated_count"])

    def test_page_update_and_verification_are_not_document_revision(self):
        result = knowledge_catalog()
        by_id = {item["id"]: item for item in result["items"]}
        verification = {item["id"]: item for item in result["coverage"]["verification"]}
        self.assertEqual(set(by_id), set(verification))
        profile = by_id["nist-ai-600-1"]
        provenance = verification[profile["id"]]
        self.assertEqual("2024-07-26", provenance["publication_date"])
        self.assertEqual("2026-04-08", profile["updated_at"])
        self.assertEqual(profile["updated_at"], provenance["source_page_updated_at"])
        self.assertNotEqual(result["coverage"]["verified_on"], profile["updated_at"])
        self.assertEqual("source_page_updated_at", provenance["updated_at_basis"])
        self.assertIn("不能据此认定", profile["summary"])

    def test_guides_are_not_relabelled_as_mandatory_standards(self):
        result = knowledge_catalog()
        nist = [item for item in result["items"] if item["id"].startswith("nist-") and item["kind"] == "guide"]
        self.assertEqual(3, len(nist))
        self.assertTrue(all(item["kind"] == "guide" for item in nist))
        ssdf = next(item for item in nist if item["id"] == "nist-sp-800-218a")
        self.assertEqual("2024-07-26", ssdf["updated_at"])
        self.assertIn("SP 800-218", ssdf["summary"])
        self.assertTrue(any("强制技术标准" in gap for gap in result["coverage"]["gaps"]))

    def test_fips_standard_is_infrastructure_background_with_planning_note(self):
        result = knowledge_catalog()
        item = next(item for item in result["items"] if item["id"] == "nist-fips-203")
        self.assertEqual("standard", item["kind"])
        self.assertEqual("2024-08-13", item["updated_at"])
        self.assertEqual("https://csrc.nist.gov/pubs/fips/203/final", item["url"])
        self.assertIn("并非 AI 专属标准", item["summary"])
        self.assertIn("2025-11-17", item["summary"])
        self.assertIn("不代表问题已修复", item["summary"])
        record = next(r for r in catalog_records() if r.upstream_id == item["id"])
        self.assertEqual("standard", record.kind)

    def test_eu_original_edition_is_not_claimed_as_verified_current_consolidation(self):
        result = knowledge_catalog()
        item = next(item for item in result["items"] if item["kind"] == "policy")
        verification = next(entry for entry in result["coverage"]["verification"] if entry["id"] == item["id"])
        self.assertIn("原始", item["title"])
        self.assertEqual("2024-07-12", item["updated_at"])
        self.assertIn("现行", item["summary"])
        self.assertEqual("robot_verification_required_not_bypassed", verification["direct_document_fetch"])
        self.assertIn("未核验完整现行合并文本", verification["notes"])

    def test_usage_conditions_keep_material_specific_exceptions(self):
        result = knowledge_catalog()
        for item in result["items"]:
            with self.subTest(id=item["id"]):
                self.assertIn("第三方", item["usage_conditions"])
                self.assertIn("条件出处：https://", item["usage_conditions"])
        eu = next(item for item in result["items"] if item["kind"] == "policy")
        self.assertIn("CC0", eu["usage_conditions"])
        self.assertIn("CC BY 4.0", eu["usage_conditions"])
        self.assertIn("除另有说明", eu["usage_conditions"])


if __name__ == "__main__":
    unittest.main()
