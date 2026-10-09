"""Bounded version matching; this is deliberately not a general ecosystem parser.

Only PyPI/pip numeric releases, or product/ollama releases explicitly declared
``numeric-release``, have ordered comparisons.  Their supported subset consists
of 1--8 dotted non-negative integers, compared with trailing zero padding.
No pre-release, local, epoch, development, post-release, wildcard, compatible,
caret, tilde, Git-ancestry or distribution-backport ordering is inferred.

Source-declared exact enumerations use literal label equality in every ecosystem.
Within the numeric subset they also use its tested zero-padding equality.  Thus
an explicitly enumerated complex label can be matched without claiming to know
its ordering.  A literal miss cannot exclude that version: if the installed label
or any enumerated label is outside the bounded numeric-release subset, the
enumeration is unresolved.  For example, PyPI case and preceding-v normalization
can make different strings refer to the same version, and backport labels require
additional semantics.  No such normalization is inferred here.
Package/product identity is a separate enrichment responsibility.

Comma-separated clauses are AND; sequence entries and ``||`` branches are OR.
A positive union result wins.  Otherwise any unresolved branch or exhausted
budget keeps the result unknown, including when an exact enumeration misses.
All functions are pure and make no network, filesystem or database accesses.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
import re
from typing import Any


RULE_VERSION = "numeric-release-v2"
MAX_RANGES = 64
MAX_CONSTRAINTS = 16
MAX_EXACT_VERSIONS = 256
MAX_RANGE_LENGTH = 512
MAX_VERSION_LENGTH = 128
MAX_RELEASE_PARTS = 8
MAX_PART_DIGITS = 9

_PYPI = frozenset({"pypi", "pip"})
_PRODUCTS = frozenset({"product", "ollama"})
_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+)*", re.ASCII)
_CLAUSE = re.compile(r"\s*(<=|>=|==|=|<|>)?\s*([0-9]+(?:\.[0-9]+)*)\s*", re.ASCII)
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!\-]*", re.ASCII)
_PLACEHOLDERS = frozenset({"unknown", "latest", "main", "master", "head", "none", "null", "undefined"})


@dataclass(frozen=True)
class VersionMatch:
    """Serializable judgment with enough rule information for provenance.

    ``raw_ranges`` preserves provided expressions, bounded by the public limits;
    truncation is explicitly reported in ``reasons``.  Reasons are stable codes
    rather than strings incorporating untrusted input.  Supported rules describe
    the selected capability, not a claim that every supplied expression parsed.
    """

    status: str
    reasons: tuple[str, ...]
    scheme: str
    rule_version: str = RULE_VERSION
    raw_ranges: tuple[str, ...] = ()
    supported_rules: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def capability_matrix() -> dict[str, Any]:
    """Return a fresh, JSON-compatible capability declaration and hard limits."""
    return {
        "rule_version": RULE_VERSION,
        "exact_nonmatch_policy": "all labels within bounded numeric-release subset",
        "ecosystems": {
            "pypi": {
                "aliases": ["pypi", "pip"],
                "ordered_scheme": "numeric-release",
                "scheme_required": False,
            },
            "product": {
                "aliases": ["product", "ollama"],
                "ordered_scheme": "numeric-release",
                "scheme_required": True,
            },
            "other": {
                "ordered_scheme": None,
                "exact_enumeration_only": True,
                "examples": ["maven", "npm", "go", "rust", "cpe"],
            },
        },
        "supported": [
            "literal-exact-enumeration", "numeric-release-equality",
            "zero-padding", "operators:<,<=,>,>=,==,=", "bare-release-equality",
            "comma-and", "range-union", "positive-union-priority",
        ],
        "unsupported_ordering": [
            "pre-release", "build/local", "epoch", "post/dev", "git-ancestry",
            "backport", "wildcard", "compatible", "caret", "tilde",
            "full-pep440", "full-semver", "maven-interval",
        ],
        "limits": {
            "ranges": MAX_RANGES,
            "clauses_per_range": MAX_CONSTRAINTS,
            "exact_versions": MAX_EXACT_VERSIONS,
            "range_length": MAX_RANGE_LENGTH,
            "version_length": MAX_VERSION_LENGTH,
            "release_parts": MAX_RELEASE_PARTS,
            "digits_per_part": MAX_PART_DIGITS,
        },
    }


def _unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _label(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_VERSION_LENGTH:
        return None
    value = value.strip(" \t\r\n")
    if not _LABEL.fullmatch(value) or value.lower() in _PLACEHOLDERS:
        return None
    return value


def _release(value: str) -> tuple[int, ...] | None:
    if not _RELEASE.fullmatch(value):
        return None
    parts = value.split(".")
    if len(parts) > MAX_RELEASE_PARTS or any(len(part) > MAX_PART_DIGITS for part in parts):
        return None
    parsed = tuple(int(part) for part in parts)
    # Removing trailing zeroes implements zero-padding without extending tuples.
    while len(parsed) > 1 and parsed[-1] == 0:
        parsed = parsed[:-1]
    return parsed


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    size = max(len(left), len(right))
    left = left + (0,) * (size - len(left))
    right = right + (0,) * (size - len(right))
    return (left > right) - (left < right)


def _scheme(ecosystem: object, declared: object) -> tuple[str, str | None]:
    if not isinstance(ecosystem, str) or len(ecosystem) > 80:
        return "exact-label", "unsupported_ecosystem"
    ecosystem = ecosystem.strip().lower()
    if declared not in (None, "", "numeric-release"):
        return "exact-label", "unsupported_version_scheme"
    if ecosystem in _PYPI:
        return "numeric-release", None
    if ecosystem in _PRODUCTS:
        if declared == "numeric-release":
            return "numeric-release", None
        return "exact-label", "version_scheme_required"
    return "exact-label", "unsupported_ecosystem"


def _ranges(value: object) -> tuple[list[str], tuple[str, ...], list[str]]:
    """Read at most the bounded prefix, without interpreting truncated text."""
    issues: list[str] = []
    if value is None:
        items: Sequence[Any] = ()
    elif isinstance(value, str):
        items = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items = value
    else:
        return [], (), ["invalid_range_container"]

    if len(items) > MAX_RANGES:
        issues.append("range_count_limit")
    branches: list[str] = []
    originals: list[str] = []
    for index in range(min(len(items), MAX_RANGES)):
        item = items[index]
        if not isinstance(item, str):
            issues.append("range_not_text")
            continue
        if len(item) > MAX_RANGE_LENGTH:
            originals.append(item[:MAX_RANGE_LENGTH])
            issues.append("range_length_limit")
            continue
        if not item.strip():
            # Empty metadata fields express no additional affected range.
            continue
        originals.append(item)
        for branch in item.split("||"):
            if len(branches) >= MAX_RANGES:
                issues.append("range_count_limit")
                break
            if not branch.strip():
                issues.append("empty_union_branch")
                continue
            branches.append(branch)
    return branches, tuple(originals), issues


def _exacts(value: object) -> tuple[list[str], list[str]]:
    if value is None:
        return [], []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return [], ["invalid_exact_container"]
    issues = ["exact_count_limit"] if len(value) > MAX_EXACT_VERSIONS else []
    labels: list[str] = []
    for index in range(min(len(value), MAX_EXACT_VERSIONS)):
        label = _label(value[index])
        if label is None:
            issues.append("invalid_exact_label")
        else:
            labels.append(label)
    return labels, issues


def _in_range(version: tuple[int, ...], expression: str) -> bool | None:
    clauses = expression.split(",")
    if len(clauses) > MAX_CONSTRAINTS:
        return None
    parsed: list[tuple[str, tuple[int, ...]]] = []
    # Validate the whole branch before evaluating; do not hide an unknown clause
    # behind an earlier nonmatching clause.
    for clause in clauses:
        match = _CLAUSE.fullmatch(clause)
        if match is None:
            return None
        bound = _release(match.group(2))
        if bound is None:
            return None
        parsed.append((match.group(1) or "==", bound))
    for operator, bound in parsed:
        comparison = _compare(version, bound)
        if not {
            "<": comparison < 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
            "==": comparison == 0,
            "=": comparison == 0,
        }[operator]:
            return False
    return True


def match_version(
    version: str | None,
    ranges: str | Sequence[str] | None = (),
    *,
    ecosystem: str = "",
    exact_versions: Sequence[str] = (),
    version_scheme: str | None = None,
) -> VersionMatch:
    """Match an installed label against the union of structured source claims.

    An enumeration-only nonmatch is ``not_in_range`` when the installed label and
    all enumerated labels lie within the bounded numeric-release subset and all
    claims were read.  Other ecosystems use literal equality only even for those
    numeric labels.  The result describes that supplied enumeration, not all
    possible advisories.  Missing claims, unsupported semantics, malformed input,
    and bounds exhaustion return ``unknown`` unless a bounded branch matches.
    ``ranges`` is never inferred from prose and no patch version is guessed.
    """
    branches, raw_ranges, range_issues = _ranges(ranges)
    exacts, exact_issues = _exacts(exact_versions)
    scheme, scheme_issue = _scheme(ecosystem, version_scheme)
    rules = ("literal-exact-enumeration", "range-union", "positive-union-priority")
    if scheme == "numeric-release":
        rules += (
            "numeric-release-equality", "zero-padding", "comma-and",
            "operators:<,<=,>,>=,==,=", "bare-release-equality",
        )

    def result(status: str, reasons: list[str]) -> VersionMatch:
        return VersionMatch(status, _unique(reasons), scheme, RULE_VERSION, raw_ranges, rules)

    issues = range_issues + exact_issues
    installed = _label(version)
    if installed is None:
        reason = "version_missing" if version in (None, "") else "invalid_version_label"
        return result("unknown", [reason] + issues)
    installed_release = _release(installed)
    numeric = installed_release if scheme == "numeric-release" else None

    for exact in exacts:
        exact_numeric = _release(exact) if numeric is not None else None
        if installed == exact or (
            numeric is not None and exact_numeric is not None and _compare(numeric, exact_numeric) == 0
        ):
            return result("affected", ["exact_enumeration_hit"] + issues)

    # Exact string equality is sufficient for an explicit positive claim, but a
    # miss is not sufficient to rule out labels whose normalization/equivalence
    # we do not support.  Preserve these unknowns even if numeric ranges miss.
    if exacts:
        if installed_release is None:
            issues.append("unsupported_exact_installed_label")
        if any(_release(exact) is None for exact in exacts):
            issues.append("unsupported_exact_source_label")

    known_nonmatches = bool(exacts)
    unknown = bool(issues)
    if branches:
        if scheme_issue is not None:
            issues.append(scheme_issue)
            unknown = True
        elif numeric is None:
            issues.append("unsupported_version_ordering")
            unknown = True
        else:
            for branch in branches:
                matched = _in_range(numeric, branch)
                if matched is True:
                    return result("affected", ["range_union_hit"] + issues)
                if matched is None:
                    unknown = True
                    if len(branch.split(",")) > MAX_CONSTRAINTS:
                        issues.append("clause_count_limit")
                    else:
                        issues.append("unsupported_range")
                else:
                    known_nonmatches = True
    if unknown:
        return result("unknown", ["union_has_unresolved_claims"] + issues)
    if known_nonmatches:
        reasons = ["all_supplied_claims_nonmatching"]
        if exacts:
            reasons.append("exact_enumeration_nonmatch")
        return result("not_in_range", reasons)
    return result("unknown", ["affected_versions_missing"])
