"""Offline tests for passive upstream POC/exploit metadata only."""
from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from aicti_monitor.adapters.poc_metadata import (
    MAX_INPUT_REFERENCES, MAX_POC_REFERENCES,
    extract_tagged_reference_leads as extract_poc_references,
    extract_poc_references as extract_strict_poc_references,
)


def reference(url="https://github.com/example/fixture", tags=None, **extra):
    return {"url": url, "tags": ["Exploit"] if tags is None else tags, **extra}


class PocMetadataTests(unittest.TestCase):
    def test_production_poc_entry_point_requires_explicit_poc_tag(self):
        self.assertEqual([], extract_strict_poc_references([reference(tags=["Exploit"])]))
        self.assertEqual([], extract_strict_poc_references([reference(tags=["Vendor Advisory"])]))
        lead = extract_strict_poc_references([reference(tags=["Exploit", "Proof of Concept"])])[0]
        self.assertEqual("explicit_poc_reference", lead["class"])
        self.assertEqual("unverified", lead["verification"])
        self.assertEqual("not_checked", lead["availability"])

    def test_exploit_only_references_cannot_crowd_out_later_explicit_poc(self):
        refs = [reference(f"https://example.org/{i}") for i in range(127)]
        refs.append(reference("https://example.org/explicit", ["POC"]))
        leads = extract_strict_poc_references(refs)
        self.assertEqual(["https://example.org/explicit"], [lead["url"] for lead in leads])

    def test_strict_poc_entry_point_retains_input_bounds(self):
        for value in (None, "POC", {}):
            with self.assertRaises(ValueError):
                extract_strict_poc_references(value)
        with self.assertRaises(ValueError):
            extract_strict_poc_references([reference()] * 129)

    def test_nvd_shape_keeps_exploit_reference_distinct_and_unverified(self):
        # Official NVD API schema: url + optional source + string-array tags.
        # An Exploit-tagged vendor advisory is not proof of available POC code.
        leads = extract_poc_references([reference(
            "https://github.com/statamic/cms/security/advisories/GHSA-6r5g-cq4q-327g",
            ["Exploit", "Vendor Advisory"], source="GitHub, Inc.",
        )])
        self.assertEqual(len(leads), 1)
        lead = leads[0]
        self.assertEqual(lead["class"], "exploit_reference")
        self.assertEqual(lead["basis"], "explicit_upstream_exploit_tag")
        self.assertEqual(lead["upstream_tags"], ["Exploit", "Vendor Advisory"])
        self.assertEqual(lead["upstream_source"], "GitHub, Inc.")
        self.assertNotIn("publisher", lead)
        self.assertNotIn("license", lead)
        self.assertEqual(lead["availability"], "not_checked")
        self.assertEqual(lead["verification"], "unverified")
        self.assertIs(lead["downloaded"], False)
        self.assertIs(lead["executed"], False)

    def test_explicit_poc_tags_only(self):
        for tag in ("POC", "poc", "Proof of Concept", "Proof-of-Concept", "proof_of_concept", "Proof of Concept (POC)", "Proof of Concept/POC"):
            with self.subTest(tag=tag):
                lead = extract_poc_references([reference(tags=[tag])])[0]
                self.assertEqual(lead["class"], "explicit_poc_reference")
                self.assertEqual(lead["basis"], "explicit_upstream_poc_tag")
                self.assertEqual(lead["upstream_tags"], [tag])

    def test_url_host_title_or_free_text_never_establishes_a_poc(self):
        refs = [
            reference("https://github.com/example/poc", []),
            reference("https://www.exploit-db.com/exploits/123", ["Third Party Advisory"]),
            reference(tags=["Not a POC"]), reference(tags=["Exploitability"]),
            {"url": "https://example.org/report", "title": "Proof of Concept", "type": "POC"},
            reference(tags=["Vendor Advisory"], description="POC code", poc=True),
        ]
        self.assertEqual(extract_poc_references(refs), [])

    def test_explicit_safe_labels_only_and_no_arbitrary_payload(self):
        ref = reference(tags=["POC"], publisher="Example Security", license="MIT",
                        source="Example CNA", code="malicious shell", payload={"api_key": "sensitive-fixture"},
                        verification="verified", available=True, downloaded=True, executed=True)
        lead = extract_poc_references([ref])[0]
        self.assertEqual(lead["publisher"], "Example Security")
        self.assertEqual(lead["license"], "MIT")
        self.assertEqual(lead["upstream_source"], "Example CNA")
        self.assertEqual(lead["verification"], "unverified")
        self.assertEqual(lead["availability"], "not_checked")
        self.assertFalse(lead["downloaded"] or lead["executed"])
        serialized = json.dumps(lead)
        self.assertNotIn("malicious shell", serialized)
        self.assertNotIn("sensitive-fixture", serialized)
        self.assertNotIn("payload", lead)

    def test_email_or_secret_labels_are_omitted_without_affecting_the_lead(self):
        for field in ("source", "publisher", "license"):
            for value in ("researcher@example.org", "api_key=sensitive-fixture", "Bearer sensitive-fixture", "<script>alert(1)</script>", "line\nsecond", "x" * 129):
                with self.subTest(field=field, value=value):
                    lead = extract_poc_references([reference(**{field: value})])[0]
                    self.assertNotIn("upstream_source" if field == "source" else field, lead)
                    self.assertNotIn("sensitive-fixture", json.dumps(lead))

    def test_private_credentialed_and_malformed_urls_are_omitted(self):
        unsafe = [
            "https://user:password@example.org/x", "https://user@example.org/x",
            "http://127.0.0.1/x", "http://2130706433/x", "http://0x7f000001/x",
            "http://0x7f.0.0.1/x", "http://0177.0.0.1/x", "http://127.1/x",
            "https://10.1.2.3/x", "https://172.16.0.1/x", "https://192.168.1.1/x",
            "http://169.254.169.254/x", "http://0.0.0.0/x", "https://224.0.0.1/x",
            "http://[::1]/x", "http://[::ffff:127.0.0.1]/x", "http://[fe80::1]/x",
            "http://[fc00::1]/x", "http://localhost/x", "http://localhost.localdomain/x",
            "http://host.local/x", "https://host.internal/x", "https://host.home.arpa/x",
            "https://host.onion/x", "https://host.lan/x", "https://intranet/x",
            "https://example..org/x", "https://-example.org/x", "https://example.org:444/x",
            "https://example.org/?api_key=sensitive-fixture", "https://example.org/?auth=sensitive-fixture",
            "https://example.org/?jwt=sensitive-fixture", "https://example.org/#/token=sensitive-fixture",
            "https://example.org/#api%5Fkey=sensitive-fixture", "https://example.org/?x=1;secret=sensitive-fixture",
            "https://example.org/?api%255Fkey=sensitive-fixture", "https://example.org/password=sensitive-fixture",
            "https://example.org/researcher%40example.org", "https://example.org/\nx",
            "https://example.org/%0ax", "https://example.org/%00x", "https://example.org\u200bx",
            "https://example.org\\@127.0.0.1/x", "https://example.org/%5c@127.0.0.1",
            "https://%31%32%37.0.0.1/x", "file:///etc/passwd", "javascript:alert(1)",
            "data:text/plain,x", "https://example.org/" + "x" * 2048,
        ]
        for url in unsafe:
            with self.subTest(url=url):
                self.assertEqual(extract_poc_references([reference(url)]), [])

    def test_public_ip_urls_and_safe_line_fragment_are_retained(self):
        urls = ("https://8.8.8.8/x", "https://[2606:4700:4700::1111]/x",
                "http://example.org/report#L10", "https://example.org/report?version=1.0")
        self.assertEqual([r["url"] for r in extract_poc_references([reference(u) for u in urls])], list(urls))

    def test_bad_tags_fail_closed_and_bad_entries_are_skipped(self):
        refs = [None, "https://github.com/example/poc", [], {"tags": ["POC"]},
                reference(tags="POC"), reference(tags=["POC", {}]), reference(tags=["POC", "api_key=sensitive-fixture"]),
                reference(tags=["POC", "<script>"]), reference(tags=["POC"] * 33), reference(tags=["x" * 65]),
                reference(tags=["Proof of Concept, Vendor Advisory"])]
        self.assertEqual(extract_poc_references(refs), [])

    def test_duplicate_tags_merge_and_explicit_poc_has_precedence(self):
        refs = [reference("https://EXAMPLE.org:443/report", ["Exploit", "Vendor Advisory"]),
                reference("https://example.org/report", ["POC", "Exploit"]),
                reference("https://example.org/report", ["Exploit", "Vendor Advisory"])]
        result = extract_poc_references(refs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["class"], "explicit_poc_reference")
        self.assertEqual(result[0]["upstream_tags"], ["Exploit", "Vendor Advisory", "POC"])

    def test_different_explicit_source_or_license_keeps_provenance_separate(self):
        leads = extract_poc_references([reference(source="NIST"), reference(source="Example CNA"),
                                      reference(source="NIST", license="MIT")])
        self.assertEqual(len(leads), 3)
        self.assertEqual([v["upstream_source"] for v in leads], ["NIST", "Example CNA", "NIST"])

    def test_duplicate_projection_keeps_the_decisive_raw_poc_tag_at_tag_cap(self):
        tags = ["Exploit", *(f"Auxiliary {i}" for i in range(31))]
        lead = extract_poc_references([reference(tags=tags), reference(tags=["Proof of Concept"])])[0]
        self.assertEqual(len(lead["upstream_tags"]), 32)
        self.assertIn("Proof of Concept", lead["upstream_tags"])
        self.assertEqual(lead["class"], "explicit_poc_reference")

    def test_128_input_cap_and_64_output_cap(self):
        refs = [reference(f"https://example.org/report/{i}") for i in range(MAX_INPUT_REFERENCES)]
        leads = extract_poc_references(refs)
        self.assertEqual(len(leads), MAX_POC_REFERENCES)
        self.assertEqual(leads[-1]["url"], "https://example.org/report/63")
        # Later duplicates can enrich retained lead metadata at the output cap.
        refs[-1] = reference("https://example.org/report/0", ["POC"])
        self.assertEqual(extract_poc_references(refs)[0]["class"], "explicit_poc_reference")
        with self.assertRaisesRegex(ValueError, "exceeds 128"):
            extract_poc_references(refs + [reference()])

    def test_invalid_input_container_errors_are_sanitized(self):
        for value in (None, "sensitive-fixture", {"token": "sensitive-fixture"}, (reference() for _ in range(1))):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ValueError) as caught:
                    extract_poc_references(value)
                self.assertNotIn("sensitive-fixture", str(caught.exception))

    def test_pure_no_network_and_detached_json_serializable_result(self):
        refs = [reference(tags=["POC"], source="Example CNA", code="ignored")]
        before = copy.deepcopy(refs)
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
                patch("socket.create_connection", side_effect=AssertionError("network forbidden")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("HTTP forbidden")):
            result = extract_poc_references(refs)
        self.assertEqual(refs, before)
        json.dumps(result, allow_nan=False)
        result[0]["upstream_tags"].append("changed output")
        self.assertEqual(refs, before)

    def test_reparse_updated_tags_and_removed_reference_does_not_keep_old_lead(self):
        original = [reference(tags=["Exploit"])]
        self.assertEqual(len(extract_poc_references(original)), 1)
        updated = [reference(tags=["Vendor Advisory"])]
        self.assertEqual(extract_poc_references(updated), [])
        self.assertEqual(extract_poc_references([]), [])


if __name__ == "__main__":
    unittest.main()
