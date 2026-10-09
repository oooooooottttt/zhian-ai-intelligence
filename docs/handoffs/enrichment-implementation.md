# Enrichment implementation handoff — 2026-10-03

Implementation is complete in the assigned files. **72 offline tests pass: 24
version tests and 48 enrichment tests.** Main chat owns persistence, publication,
QA and UI integration; no files assigned to those chats were changed.

## Integration items

1. **`poc_reference` legitimately uses task.related evidence IDs**, in addition to
   `related_material` and `risk_pattern`. A POC URL/publisher/license supplied by a
   controlled paper/article candidate belongs to that candidate's exact source
   revision; substituting the vulnerability revision would give incorrect
   attribution. Allow only IDs in this task's authorized related snapshot, and
   preserve candidate/unverified/not_checked labels.
2. `related_material.target_evidence_id` points to the **material** revision,
   matching the store's relation validation. `advisory_evidence_id` identifies the
   vulnerability revision; `material_evidence_id` also names the material. Both
   exact IDs occur in Fact.evidence_ids. `locator_evidence_id` specifies whose
   source field the locator addresses. The store should include these related
   revisions in the event's published evidence closure so QA can resolve them.
3. Root's proposed empty-evidence exception for a `candidate` `risk_pattern` with
   `basis=asset_declared_capabilities` is appropriate. These hypotheses exist even
   for paper-only/no-advisory inputs. Validate `asset_id`, `asset_snapshot_id`,
   observation time, the permitted pattern, and required declared capability
   values against the task's inventory snapshot. `value.capabilities` contains
   the **required subset**, not the entire capability map. Source IDs, if present,
   are advisory context only; they never prove inventory capabilities. Keep these
   candidates out of current confirmed QA claims, as root proposed. A future
   inventory-evidence domain type could give them independent citations without
   inventing source observation IDs.
4. Budgets align with current QA: 256 facts/event, 8192 UTF-8 bytes/fact value,
   at most 32 missing-condition/reason entries, reasons <=1024 characters, result
   <=1,000,000 bytes. Budget failures raise ValueError and return no partial
   assessments. Surface a bounded-input error rather than repeatedly retrying an
   identical oversized task. The UI inspected during development still takes
   only 100 event facts; show all 256 or visibly report the omitted count.
5. Current QA admits only `valid` facts. Background material, unsupported-vector
   CVSS, POC clues and capability modes are intentionally `candidate`; they must
   retain those labels if exposed in answers. They remain visible in the result
   for UI display and must never become confirmed vulnerability claims merely
   to pass a consumer filter.
6. The actual version rule is `numeric-release-v2`; affected_range values retain
   that rule version. Include it in root's method/input signature or invalidate
   older v1 projections when deploying this change. The shared METHOD_VERSION
   constant remains owned by root and was not edited by this module chat.

Resume verification on 2026-10-03: reread current service/store and reran the
assigned two test files; **all 72 tests passed again**. Service calls the frozen
enrich API with at most 128 related candidates and an omission warning. Store
already validates candidate capability risk asset/snapshot IDs and the supplied
capability subset against inventory; it correctly restricts empty-support
assessments to unknown/under_investigation. At this verification point its related
support allowlist still omitted `poc_reference`; root's announced controlled
candidate POC exception is the remaining publication integration item. No
store/service file was modified here.

## Files and frozen APIs

- `aicti_core/versioning.py`: `match_version(...) -> VersionMatch`,
  `capability_matrix()`, `RULE_VERSION='numeric-release-v2'`.
- `aicti_core/enrichment.py`: frozen
  `enrich(evidence, assets, related=(), *, now=None) -> EnrichmentResult`.
- `tests/test_core_versioning.py`, `tests/test_core_enrichment.py`.
- This handoff.

Shared contracts and monitoring adapters were only read. Original four-page
competition PDF was read for module requirements and remains unchanged. No
dependency installation, live server, model download, DB access, target scan,
paper PDF download, POC download or execution occurred.

## Version capability matrix

| Input | Supported behavior | Conservative limit |
|---|---|---|
| PyPI/pip | 1–8 dotted integer release parts, <=9 digits/part; trailing-zero padding; `< <= > >= = ==` and bare numeric equality | Not full PEP 440 |
| product/ollama | Same numeric release subset only with `version_scheme='numeric-release'` | No inferred ordering from a product name |
| Other ecosystems, including Maven/npm/Go/Rust | Source-declared exact enumeration | No ecosystem ordering or canonicalization |
| Ranges | Comma AND; list/tuple or `||` OR; exact enumeration participates in the union | 64 branches, 16 clauses/branch, 512 chars/range |
| Complex labels | Literal source-declared exact hit can establish a match without ordering | Any unsupported installed/enumerated label on a miss keeps unknown, even alongside a numeric range nonmatch |

Positive evaluated union branches win. Otherwise any unsupported, malformed or
overflow branch prevents a negative result. No claim of full SemVer/Maven/PEP440
support. Pre-release, epoch, local/build, post/dev, wildcard, compatible, caret,
tilde, Git ancestry and backport ordering remain unsupported. Version labels are
bounded to 128 characters; enumerations to 256 entries.

## Enrichment behavior and data shapes

The function has no network/DB/model dependencies and does not mutate supplied
evidence or inventory. Latest supplied revision per observation wins, including
latest withdrawal or explicit `authorized=False` / `enrichment_allowed=False`.
Inconsistent duplicate identities are excluded. It can only know the revisions
the caller supplies; root still performs current-policy/current-revision checks.

Structured `metadata.packages` provides ecosystem/name,
`vulnerable_version_range`, `patched_versions`. Optional `ranges` and
`exact_versions` are supported; if both range fields are present, both participate
in the OR union. Facts retain exact evidence revisions and actual field locators.
PyPI names are syntax-checked, then normalized across case and runs of `-_.`.
Package ecosystem remains part of identity: PyPI `ollama` is a client package,
distinct from product `Ollama`. No substring aliasing, import-name inference, CPE
version inference, or server installation claim. A source with unmapped component
declarations keeps otherwise-negative assessments unknown. A known positive
range remains affected even when another relevant branch is unsupported.

`metadata.conditions` and each package's optional `conditions` accept:

```
[{"field":"exposed","equals":true},
 {"field":"authenticated","equals":false},
 {"field":"capabilities.tools","equals":true}]
```

or an AND map:

```
{"exposed":true,"authenticated":false,"capabilities":{"tools":true}}
```

Supported values are bounded booleans. Missing inventory values, unsupported
condition structures or contradictory conditions produce investigation, not a
default match. An explicit supported unmet precondition can give
not_affected_with_reason for fresh inventory; reasons retain the precondition.
Different source range assertions yielding affected vs not_in_range are retained
and require investigation. No source score/range is averaged or chosen silently.

Every supplied asset receives an assessment. Inventory observed_at missing,
naive, malformed, future or older than 24 hours prevents a current definitive
status. Version match is retained while status becomes under_investigation.
`resolved` is never inferred because this API lacks remediation verification
history. Version match means potential applicability, never confirmed attack.

CVSS consumes normalized metadata.cvss lists from both actual adapters. It checks
numeric finite 0–10 scores, version/prefix consistency, duplicate metrics and
base-vector syntax for 2.0/3.0/3.1/4.0. Source score/vector conflicts are flagged
and preserved separately. **Scores are not recomputed**; this does not verify
score/vector arithmetic consistency. Vectors with optional/temporal/environmental
metrics are retained as candidates, not claimed fully validated. Source base
metrics generate an impact projection with confirmed_exploitation=false. CWEs
come only from structured metadata.cwes. Narrative scores/versions are ignored.

Repair cards come from source-reported package patched_versions and optional
`metadata.fixes` entries with kind patch/mitigation/workaround, description,
ecosystem/name, patched_versions, conditions and a safe optional URL. They preserve
source revisions/conditions and `verification=not_tested`; no commands execute,
no patch is derived from a summary, and repairs are not applied automatically.

Related material is direct only for exact CVE/GHSA/OSV IDs or explicit
`metadata.defect_ids` / `metadata.defect_evidence_ids`. Same component alone gives
background/candidate. A matching title or partial defect ID proves no relation.
Locators name the actual alias/upstream/metadata/component field; paper metadata
does not establish unavailable full-paper experimental findings.

Optional `metadata.poc_references` entries project URL/publisher/license only.
Availability is not_checked; verification is unverified; downloaded/executed are
false. General reference URLs are not guessed to be POC code. The current live
GitHub/NVD adapters do not supply this optional field; actual POC coverage requires
an authorized upstream metadata producer. No URLs are fetched. Pure link checks
block userinfo, private literals/obfuscated IPv4, localhost/private suffixes,
control characters and credential query/fragment keys. Public DNS resolution and
redirect checks remain the networking boundary's responsibility.

Capability modes support root inventory names external_documents/rag/tools/
network/write_access, with patterns for injection-to-tools, retrieval poisoning,
tool network egress and tool write abuse. Richer direct-call fixtures also support
untrusted_inputs/tool_execution/sensitive_data/retrieval/loads_untrusted_models;
root currently rejects those extra import keys, so they are not a claimed live
import capability. Every mode is candidate, based on asset declarations, with
confirmed_vulnerability=false and explicit inventory snapshot/time provenance.

## Bounds, test evidence and limitations

Top-level budgets: primary evidence 128, related 128, inventory 256. Used structured
lists generally cap at 64. Metadata is bounded by nodes/depth/text/array/object
limits before processing. Invalid identity or excessive projections fail closed.
There is no partial-safe assessment returned on a budget failure.

Executed successfully on 2026-10-03:

```
python3 -m unittest tests.test_core_versioning tests.test_core_enrichment -v
Ran 72 tests
OK
```

Tests include range boundaries/unions/unknown/complex exact-miss, withdrawn/latest
revision, independent source conflicts, Ollama client/server and invalid PyPI
identity, mixed CPE/package sources, conditions and staleness, true field locators,
POC credentials/private links, narrative injection, CVSS malformed/huge/NaN/inf
scores, bounded metadata and consumer size, pure input isolation and actual
GitHub/NVD parser fixture compatibility. Fake/fictional source and asset data are
used; tests make no public API calls. Independent read-only review supplied
counterexamples that were fixed and made regressions. No production-scale
accuracy/recall/latency benchmark has been performed or claimed.

## Primary specifications consulted

PyPI naming validation/normalization follows the
[PyPA name specification](https://packaging.python.org/en/latest/specifications/name-normalization/).
Conservative unknown for unsupported label equivalences is informed by
[PyPA version normalization](https://packaging.python.org/en/latest/specifications/version-specifiers/#normalization).
The base-vector syntax subset was checked against FIRST's
[CVSS v2 guide](https://www.first.org/cvss/v2/guide),
[CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
and [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document).
These are implementation references, not evidence that source scores or live
asset vulnerability assertions have been independently verified.
