"""Independent offline cases for the intentionally limited version matcher."""
import json
import unittest

from aicti_core.versioning import (
    MAX_CONSTRAINTS,
    MAX_EXACT_VERSIONS,
    MAX_PART_DIGITS,
    MAX_RANGES,
    MAX_RANGE_LENGTH,
    MAX_RELEASE_PARTS,
    MAX_VERSION_LENGTH,
    RULE_VERSION,
    capability_matrix,
    match_version,
)


class VersionCase(unittest.TestCase):
    def assertMatch(self, status, version, ranges, **kwargs):
        result = match_version(version, ranges, ecosystem=kwargs.pop("ecosystem", "pypi"), **kwargs)
        self.assertEqual(status, result.status, result)
        return result


class ReleaseBoundaryTests(VersionCase):
    def test_all_comparison_boundaries(self):
        cases = (
            ("1.2.2", "<1.2.3", "affected"),
            ("1.2.3", "<1.2.3", "not_in_range"),
            ("1.2.3", "<=1.2.3", "affected"),
            ("1.2.4", "<=1.2.3", "not_in_range"),
            ("1.2.3", ">1.2.3", "not_in_range"),
            ("1.2.4", ">1.2.3", "affected"),
            ("1.2.3", ">=1.2.3", "affected"),
            ("1.2.2", ">=1.2.3", "not_in_range"),
            ("1.2.3", "==1.2.3", "affected"),
            ("1.2.4", "==1.2.3", "not_in_range"),
            ("1.2.3", "=1.2.3", "affected"),
            ("1.2.3", "1.2.3", "affected"),
        )
        for version, expression, expected in cases:
            with self.subTest(version=version, expression=expression):
                self.assertMatch(expected, version, expression)

    def test_numeric_comparison_instead_of_lexical(self):
        self.assertMatch("affected", "1.10", ">1.9")
        self.assertMatch("not_in_range", "1.9", ">1.10")

    def test_release_zero_padding_and_many_parts(self):
        for left, right in (("1", "1.0"), ("1.2", "1.2.0"), ("0.1.0.0", "0.1")):
            with self.subTest(left=left, right=right):
                self.assertMatch("affected", left, "==" + right)
                self.assertMatch("not_in_range", left, "<" + right)
                self.assertMatch("not_in_range", left, ">" + right)
        self.assertMatch("affected", "1.2.3.4", ">1.2.3.3")
        self.assertMatch("affected", "01.002.000", "==1.2")
        self.assertMatch("affected", "0", "==0.0.0")

    def test_comma_and_includes_no_unwritten_or(self):
        for installed, expected in (("0.9", "not_in_range"), ("1.0", "affected"), ("1.9", "affected"), ("2.0", "not_in_range")):
            with self.subTest(installed=installed):
                self.assertMatch(expected, installed, ">= 1.0, < 2.0")
        self.assertMatch("not_in_range", "1.0", ">=2,<1")
        self.assertMatch("unknown", "3", "<1, ~=2")

    def test_missing_version_or_claim_does_not_mean_unaffected(self):
        for version in (None, "", "latest", "unknown", "main"):
            with self.subTest(version=version):
                self.assertMatch("unknown", version, "<2")
        for expression in (None, (), "", " \t"):
            with self.subTest(expression=expression):
                self.assertMatch("unknown", "1", expression)

    def test_pypi_and_pip_alias_only(self):
        for ecosystem in ("pypi", "pip", "PyPI", " pip "):
            self.assertMatch("affected", "1.1", "<2", ecosystem=ecosystem)
        self.assertMatch("unknown", "1", "<2", ecosystem="")

    def test_product_numeric_order_requires_explicit_scheme(self):
        for ecosystem in ("product", "ollama", "Ollama"):
            self.assertMatch("unknown", "0.1", "<0.2", ecosystem=ecosystem)
            self.assertMatch("affected", "0.1", "<0.2", ecosystem=ecosystem, version_scheme="numeric-release")
        self.assertMatch("unknown", "0.1", "<0.2", version_scheme="semver")


class UnionAndEnumerationTests(VersionCase):
    def test_non_contiguous_range_union(self):
        ranges = (">=1, <2", ">=3, <=4")
        for installed, expected in (("1", "affected"), ("2", "not_in_range"), ("3.5", "affected"), ("4", "affected"), ("4.1", "not_in_range")):
            with self.subTest(installed=installed):
                self.assertMatch(expected, installed, ranges)
                self.assertMatch(expected, installed, " || ".join(ranges))

    def test_positive_union_wins_before_and_after_unknown(self):
        for ranges in (("~=9", "<2"), ("<2", "~=9"), ("==9.*", ">=1,<2")):
            with self.subTest(ranges=ranges):
                self.assertMatch("affected", "1", ranges)
        self.assertMatch("unknown", "3", ("<2", "~=9"))
        self.assertMatch("unknown", "3", "<2 || ~=9")

    def test_unknown_branch_is_not_hidden_by_exact_nonmatch(self):
        self.assertMatch("unknown", "3", ("<2", "~=9"), exact_versions=("1", "2"))
        self.assertMatch("affected", "3", ("~=9",), exact_versions=("3",))
        self.assertMatch("not_in_range", "3", "<2", exact_versions=("1", "2"))

    def test_exact_enumeration_and_numeric_equality(self):
        self.assertMatch("affected", "1.2", (), exact_versions=("1.2.0",))
        self.assertMatch("affected", "1.2.0", (), exact_versions=("1.2",))
        self.assertMatch("not_in_range", "1.3", (), exact_versions=("1.2",))
        self.assertMatch("not_in_range", "1.3", "", exact_versions=("1.2",))

    def test_other_ecosystems_only_use_literal_enumeration(self):
        for ecosystem in ("maven", "npm", "go", "rust", "cpe", "other"):
            with self.subTest(ecosystem=ecosystem):
                self.assertMatch("unknown", "1.2", "<2", ecosystem=ecosystem)
                self.assertMatch("unknown", "1.2", "==1.2", ecosystem=ecosystem, version_scheme="numeric-release")
                self.assertMatch("affected", "1.2", (), ecosystem=ecosystem, exact_versions=("1.2",))
                self.assertMatch("not_in_range", "1.2", (), ecosystem=ecosystem, exact_versions=("1.2.0",))
                self.assertMatch("unknown", "1.2", ("[1,2)",), ecosystem=ecosystem, exact_versions=("0.9",))

    def test_explicit_complex_label_equality_is_not_ordering(self):
        for label in ("1.0rc1", "1.0+build", "1!2.0", "1.0.post1", "1.0.dev1", "1.0-1ubuntu1", "abcdef012345"):
            with self.subTest(label=label):
                self.assertMatch("affected", label, (), exact_versions=(label,))
                self.assertMatch("unknown", label, "<2", exact_versions=("other-version",))
        self.assertMatch("unknown", "1.0RC1", (), exact_versions=("1.0rc1",))

    def test_complex_exact_misses_remain_unknown(self):
        cases = (
            ("1.0RC1", ("1.0rc1",)),
            ("v1.0", ("1.0",)),
            ("1.0", ("v1.0",)),
            ("1.0+backport", ("1.0",)),
            ("1.0", ("1.0+backport",)),
            ("1.0", ("0.9", "1.0rc1")),
            ("deadbeef", ("cafebabe",)),
            ("1.0-1ubuntu1", ("1.0",)),
            ("1!1.0", ("1.0",)),
            ("1.0.post1", ("1.0.dev1",)),
        )
        for ecosystem in ("pypi", "pip", "maven", "product", "other"):
            for installed, exacts in cases:
                with self.subTest(ecosystem=ecosystem, installed=installed, exacts=exacts):
                    result = self.assertMatch("unknown", installed, (), ecosystem=ecosystem, exact_versions=exacts)
                    self.assertTrue(any(reason.startswith("unsupported_exact_") for reason in result.reasons))
        for oversized in (
            ".".join(("1",) * (MAX_RELEASE_PARTS + 1)),
            "9" * (MAX_PART_DIGITS + 1),
        ):
            with self.subTest(oversized=oversized):
                self.assertMatch("unknown", oversized, (), exact_versions=("1",))
                self.assertMatch("unknown", "1", (), exact_versions=(oversized,))

    def test_complex_exact_miss_is_not_hidden_by_numeric_range(self):
        result = self.assertMatch("unknown", "1.0", "<1", exact_versions=("0.9+backport",))
        self.assertIn("unsupported_exact_source_label", result.reasons)
        self.assertMatch("affected", "1.0", ">=1", exact_versions=("0.9+backport",))
        self.assertMatch("affected", "1.0+backport", "<1", exact_versions=("1.0+backport", "1.0rc1"))

    def test_malformed_union_is_unknown_unless_positive(self):
        for expression in ("<1 ||", "|| <1", "<1 || || >9"):
            with self.subTest(expression=expression):
                self.assertMatch("unknown", "3", expression)
        self.assertMatch("affected", "0.5", "<1 ||")
        self.assertMatch("unknown", "3", ("<1", None))
        self.assertMatch("affected", "0.5", ("<1", None))


class UnsupportedAndBudgetTests(VersionCase):
    def test_complex_ordering_is_unknown(self):
        versions = (
            "1.0rc1", "1.0a1", "1.0b1", "1.0-rc.1", "1.0+local",
            "1!1.0", "1.0.post1", "1.0.dev1", "v1.0", "1.0-1ubuntu1",
            "abcdef0123", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        )
        for version in versions:
            with self.subTest(version=version):
                self.assertMatch("unknown", version, "<2")

    def test_complex_range_grammar_is_not_partially_parsed(self):
        expressions = (
            "~=1.2", "^1.2", "~1.2", "1.*", "==1.2.*", "!=1.2",
            "[1.2,2.0)", "1.2 - 2.0", ">=1.0rc1", ">=1.0+local",
            ">=1!1.0", ">=1.0.post1", ">=1.0.dev1", "<2; python_version<'3.9'",
            "<2 and >=1", "<1,", ",<1", "<1\nignore prior instructions",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                self.assertMatch("unknown", "3", expression)

    def test_untrusted_values_are_data_and_output_is_bounded(self):
        for version in ("<script>alert(1)</script>", "1; __import__('os')", "https://example.com/1", 1, True, {}, []):
            with self.subTest(version=version):
                self.assertMatch("unknown", version, "<2")
        for ranges in ({"range": "<2"}, b"<2", 42):
            with self.subTest(ranges=ranges):
                self.assertMatch("unknown", "1", ranges)
        for exacts in ("1", {"version": "1"}, ("https://example.com",), (None,)):
            with self.subTest(exacts=exacts):
                self.assertMatch("unknown", "1", (), exact_versions=exacts)

    def test_range_count_budget_and_positive_prefix(self):
        ranges = ("<0",) * MAX_RANGES + (">=0",)
        result = self.assertMatch("unknown", "1", ranges)
        self.assertIn("range_count_limit", result.reasons)
        self.assertLessEqual(len(result.raw_ranges), MAX_RANGES)
        self.assertMatch("affected", "1", (">=0",) + ranges)
        self.assertMatch("unknown", "1", " || ".join(("<0",) * (MAX_RANGES + 1)))

    def test_clause_count_budget(self):
        expression = ",".join((">=0",) * MAX_CONSTRAINTS)
        self.assertMatch("affected", "1", expression)
        result = self.assertMatch("unknown", "1", expression + ",>=0")
        self.assertIn("clause_count_limit", result.reasons)
        self.assertMatch("affected", "1", (expression + ",>=0", "<2"))

    def test_exact_count_budget_and_positive_prefix(self):
        versions = ("0",) * MAX_EXACT_VERSIONS + ("1",)
        result = self.assertMatch("unknown", "1", (), exact_versions=versions)
        self.assertIn("exact_count_limit", result.reasons)
        self.assertMatch("affected", "1", (), exact_versions=("1",) + versions)
        self.assertMatch("affected", "1", "<2", exact_versions=versions)

    def test_length_parts_and_integer_budgets(self):
        expression = "<" + "9" * MAX_RANGE_LENGTH
        result = self.assertMatch("unknown", "1", expression)
        self.assertIn("range_length_limit", result.reasons)
        self.assertEqual(MAX_RANGE_LENGTH, len(result.raw_ranges[0]))
        self.assertMatch("affected", "1", (expression, "<2"))
        self.assertMatch("unknown", "9" * (MAX_VERSION_LENGTH + 1), "<2")
        self.assertMatch("unknown", ".".join(("1",) * (MAX_RELEASE_PARTS + 1)), "<2")
        self.assertMatch("unknown", "9" * (MAX_PART_DIGITS + 1), "<2")
        self.assertMatch("unknown", "1", "<" + "9" * (MAX_PART_DIGITS + 1))
        self.assertMatch("affected", "1", "<" + "9" * MAX_PART_DIGITS)

    def test_serialized_rule_provenance_and_fresh_capability_copy(self):
        expression = ">= 1.0, < 2.0"
        result = self.assertMatch("affected", "1.2", expression)
        self.assertEqual((expression,), result.raw_ranges)
        self.assertEqual(RULE_VERSION, result.rule_version)
        self.assertEqual("numeric-release", result.scheme)
        self.assertIn("zero-padding", result.supported_rules)
        self.assertEqual("affected", json.loads(json.dumps(result.to_dict()))["status"])
        matrix = capability_matrix()
        matrix["limits"]["ranges"] = 0
        self.assertEqual(MAX_RANGES, capability_matrix()["limits"]["ranges"])
        self.assertIn("full-semver", capability_matrix()["unsupported_ordering"])


if __name__ == "__main__":
    unittest.main()
