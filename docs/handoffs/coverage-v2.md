# Coverage V2 handoff — 2026-10-04

## Implemented ownership

Only added/edited Coverage files:

- `aicti_monitor/adapters/nist_feeds.py`
- `aicti_monitor/adapters/poc_metadata.py`
- `aicti_core/knowledge_catalog.py`
- `aicti_core/sbom.py`
- `tests/test_nist_feeds.py`, `test_poc_metadata.py`, `test_core_knowledge_catalog.py`, `test_core_sbom.py`
- `tests/fixtures/nist/drafts-2026-10-04.xml`, `blog-2026-10-04.xml` (selected authentic feed entries)
- this handoff

Existing adapters, config, registry, service, store, UI, competition PDF and existing
databases were not edited. Live transport verification used the existing HTTP
client, whose normal per-host rate lock writes may update `.data/http-rate/`.
No dependencies were installed, credentials inspected, DeepSeek requests made,
paper PDFs fetched, linked articles fetched, or POC code downloaded/executed.

## Final integration APIs

The latest main-chat message selects the original detailed return formats.
These are the final functions currently in the shared files:

```python
from aicti_core.knowledge_catalog import knowledge_catalog, catalog_items, catalog_records
from aicti_core.sbom import parse_sbom, parse_sbom_report, parse_sbom_assets

knowledge_catalog()  # {"items": [...], "coverage": {...}}
catalog_items()      # detached list with exactly the V2 item schema
catalog_records(collected_at=None, source_id="official-knowledge-curated")
# -> list[Record], for explicit live-library ingestion; always curated

parse_sbom(document, now=None)  # {"assets": [...], "warnings": [...],
                                #  "format": "CycloneDX"|"SPDX", "component_count": N}
parse_sbom(document, observed_at=None)  # alias for the clock keyword; also dict
parse_sbom_report(document, observed_at=None)  # detailed dict; root's latest selected entry
parse_sbom_assets(document, observed_at=None)  # compatibility list wrapper
```

Passing both non-null SBOM clock keywords raises a generic ValueError. Import
time defaults to current UTC. An explicit clock is a host-supplied timezone-aware
ISO string; document creation times are never treated as current observations.

Root `GET /api/knowledge` can return `knowledge_catalog()`. For
`POST /api/assets/sbom`, after the existing local write/body/schema checks:

```python
result = parse_sbom_report(body["document"])
import_result = service.import_assets(result["assets"])
# Return the host import result plus result warnings/format/component_count.
# Existing authorized inventory import remains the only write boundary.
```

The parser does not itself import anything, call a target, or access the network.

## Official feed registration owned by root

`nist_feeds.recommended_sources()` returns two detached JSON-ready config entries.
Add `"nist_feeds"` to `aicti_monitor.config.ADAPTERS` and append these entries to
root-owned config. The current runner already dynamically imports an adapter
with the same name; no runner implementation change is necessary.

```python
from aicti_monitor.adapters.nist_feeds import recommended_sources
new_entries = recommended_sources()
```

Exact endpoint/category settings:

| ID | Endpoint | Category | Interval | Content |
|---|---|---|---|---|
| `nist-drafts` | `https://csrc.nist.gov/CSRC/media/feeds/pubs/drafts-open-for-comment.xml` | `standard` | 21600 s | metadata_only |
| `nist-cybersecurity-blog` | `https://www.nist.gov/blogs/cybersecurity-insights/rss.xml` | `security_blog` | 21600 s | metadata_only |

Both use `adapter="nist_feeds"`, exact respective allowed host, minimum request
interval 3.1 s, `terms_url="https://www.nist.gov/open/license"`,
`params={"policy_status":"reviewed","max_pages":20,
"license":"NIST terms; third-party rights remain separate",
"license_url":"https://www.nist.gov/open/license"}`, enabled true.

The new adapter overrides Accept to include `text/xml`; actual CSRC requests
without that type returned HTTP 406. The amended request succeeded. RSS
transport handles request budgets, validators, explicit Atom next links and
tombstones. The NIST wrapper additionally limits requests to the same official
feed path, checks response URLs, rejects incomplete/unsafe entries before a
result can commit, validates publication/blog identities, and strips excerpts,
full text, profiles and unnecessary fields.

The category `standard` identifies the technical-publication source, not every
document's class. Record classification is deliberately accurate:

- FIPS: `kind="standard"`, `metadata.knowledge_kind="standard"`.
- SP: `kind="article"`, `metadata.knowledge_kind="guide"` (Record has no guide enum).
- CSWP: `kind="article"`, `metadata.knowledge_kind="guide"`.
- IR/AI/TN reports: `kind="paper"`, no standard/guide classification.
- Blog: `kind="article"`, `metadata.document_type="security_blog_article"`.

No blog/news item is promoted to a standard. An actual source category count
must not count curated policy metadata as a continuously monitored policy feed.

### Feed capability limits

The verified publication feed is a **current open-comment draft snapshot**,
not an API of all current standards, historical publications, or final editions.
It provides Atom entry identifiers, title, published/updated timestamps and a
feed update timestamp. The blog is a recent-entry RSS snapshot. Polling reobserves
available metadata; canonical identity/content fingerprinting supplies dedup and
title/date revisions. Conditional validators are committed only on completion.
This is snapshot/conditional incremental polling, not a fabricated modified-date
server query. There is no completeness/backfill guarantee for missed entries.

No pagination or tombstone was present in either inspected NIST snapshot. Code
supports an explicitly published Atom next link only under the same feed path;
tests of that protocol are synthetic and do not establish that NIST currently
offers paging. An explicitly published tombstone is preserved; **disappearance
from an open-comment or recent-blog snapshot never manufactures withdrawal**.
These feeds do not establish finalized, superseded or withdrawn status. Draft
stage is extracted only from known official locator suffixes; otherwise unknown.

Fetch exceptions do not mutate the caller's committed cursor. A budget limit
returns a pending page cursor without advancing last completion. Record and
cursor persistence still relies on the existing runner/store atomic transaction.
There is no measured monitoring latency or source coverage score guarantee.

## Curated official knowledge and QA ingestion

Catalog items: NIST FIPS 203 (ML-KEM technical standard), NIST AI 100-1 / AI RMF
1.0, NIST SP 800-218A (AI SSDF profile), NIST AI 600-1 (generative AI profile),
and the **original 2024 publication** of Regulation (EU) 2024/1689. All five are
`monitoring="curated"`. FIPS 203 is a genuine general cryptographic infrastructure
standard, explicitly not AI-exclusive. Its official final-publication date is
2024-08-13; the official page's 2025-11-17 planning note reports an issue slated
for correction in a future revision. No correction or new edition is claimed and
neither its PDF nor errata spreadsheet was downloaded. The other NIST items are
guides, not relabeled mandatory standards. Coverage explicitly reports curated counts,
zero feed observations in this static catalog, source dates versus verification,
and the lack of automatic legal revision monitoring.

`catalog_records()` now provides the requested Record projection. Root can
explicitly ingest it in the **real database only**, using the existing
`begin_run`/`ingest_and_finish` transaction, then reconcile/process as usual.
Do not call it during demo setup; it intentionally has no `metadata.demo` flag.
Guides project as article with `metadata.knowledge_kind="guide"`; policy keeps
`kind="policy"`. Each row preserves actual attribution, item-specific terms URL,
usage conditions, independently written summary, official URL, topics,
`curated_verified_on`, `upstream_revision`, and `monitoring="curated"`.

Source publications report calendar dates rather than precise UTC instants, so
Record `published_at`/`updated_at` remain null and exact source dates are retained
in `metadata.source_publication_date` and `metadata.source_updated_date`.
Collection time remains a real UTC timestamp. Do not substitute import time for
document version dates or imply a webpage update is a new document edition.

**Coverage does not modify enrichment/QA fact construction. Root must add its
host-owned `source_metadata` fact/cards** to make summary/title/date/attribution
queryable with immutable observation revisions and citations. Use current
authorized evidence, distinguish curated summaries from feed observations, and
preserve the original-edition legal and revision qualifications. Merely exposing
the catalog API is not evidence-grounded question answering. No fake model or
score claims were added here.

## POC lead production wiring owned by root

```python
from aicti_monitor.adapters.poc_metadata import extract_poc_references

# In NVD parse(), before raw cve references are flattened to URL strings:
refs = cve.get("references", [])
if isinstance(refs, list):
    metadata["poc_references"] = extract_poc_references(refs)
    metadata["poc_scope"] = "explicit upstream tags only; at most 128 input references and 64 retained leads; links not checked"
```

The helper consumes NVD-shaped `{url,source,tags}` objects. Empty or ordinary
GitHub URL-only references are **not** POC evidence. Only explicit `POC` / `Proof
of Concept` tags produce `metadata.poc_references`, class
`explicit_poc_reference`. **Exploit-only tags produce no POC references.** The
separate `extract_tagged_reference_leads(refs)` helper can preserve both explicit
POC and Exploit classes for metadata review; its Exploit-only results must stay
outside `metadata.poc_references`. They can point to an advisory/description and
do not establish runnable POC code. `basis` and original `upstream_tags`
preserve provenance. An upstream source label is not automatically a
publisher. License is retained only as an explicit safe upstream label and is
not verified permission to download or redistribute code.

All leads have `verification="unverified"`, `availability="not_checked"`,
`downloaded=False`, `executed=False`; no DNS/network is performed. Syntax,
private-literal/hostname, credential/query/fragment, markup and control checks
protect stored URLs. These checks cannot establish DNS resolution, redirects or
code existence; a future fetch would require the independent network boundary.

Input cap 128 references, 32 tags each; invalid containers/excess input fail with
generic errors rather than silently advancing an unprocessed fetch. Output cap
64 matches existing enrichment `_items`; excess distinct leads are omitted and
must be described as bounded coverage, never "no POC exists". Updated tag removal
produces an empty new projection; no cache retains removed leads.

No newly verified public source here guarantees runnable POC availability or
explicit POC tags on current AI records. A normal NVD `Exploit` tag alone remains
insufficient under the latest main-chat rule; an empty POC list is a coverage
gap, not proof of nonexistence.

The current enrichment consumer already generates candidate `poc_reference`
facts from `metadata.poc_references`, but its fact value currently discards
`class`, `basis`, `upstream_tags`, and `upstream_source`. Root should preserve
these optional fields if UI/facts need the Exploit-versus-explicit-POC distinction;
it must continue to host-enforce the four unverified/nonexecution fields.
Historical normalized NVD evidence has already lost raw tag information and
cannot be retroactively tagged by guessing URLs. New official payload refreshes
are needed. Existing GitHub APIs without explicit tags yield no inferred leads.

## SBOM behavior and bounds

Accepts CycloneDX JSON envelopes 1.3–1.7 and SPDX JSON 2.2/2.3; this is a bounded
identity projection, not complete schema, dependency-graph or attestation
validation. SPDX 3's different model is rejected. CycloneDX includes nested
components and `metadata.component`; SPDX uses package-manager purl external
references. A single JSON object is required. Limits apply even to ignored fields:
1 MiB approximate serialized bound, 20 levels, 20,000 nodes, 4096 array elements,
128 object fields, 65,536 bytes per string; no cyclic/non-JSON/NaN values.

At most 256 components **before dedup**. Purls supply known ecosystem, complete
package name and version; npm scope and Maven group are preserved. PyPI name
normalization follows its package identity rules. Unsupported/generic/container
purls, missing purls, malformed/conflicting identities, name/group conflicts,
and legacy case-sensitive npm identities remain ecosystem `unknown` rather
than guessing server/product identity. Conflicting versions become `unknown`.
Absent/NOASSERTION/latest/wildcard versions remain unknown. Purl qualifiers and
subpaths are omitted with warnings; platform/artifact differences are not modeled.

PyPI `ollama` is a Python package and never inferred to be the Ollama server.
No CPE fallback, scan, installation proof or deployment-role inference is added.
Exact projected duplicate packages merge and warnings explain that component
occurrences are not deployment instances. Asset IDs hash only sanitized package
identity, unaffected by credential-bearing metadata, raw bom refs or ignored
descriptions. Purls themselves are not retained in assets because the inventory
schema does not allow that field and qualifiers may contain private URLs/secrets.

Output uses only current accepted inventory fields: asset_id,name,ecosystem,
component,version,exposed,authenticated,observed_at,capabilities. Exposure and
authentication are null, capabilities `{}`, import timestamp current UTC.
Unsafe retained identity fields fail with generic errors that do not echo input;
arbitrary descriptions/properties/source URLs/credentials never reach output.

## Actual online verification

Verified on 2026-10-04 using official documentation/pages and public feed GETs.
No access restriction was bypassed. The normal sandbox blocked DNS for direct
HTTP, so the same bounded official feed check was rerun with tool approval.
Final **existing HttpClient + new adapter** calls, one-request budget per source:

```
nist-drafts ok 10 True ['article', 'paper']
nist-cybersecurity-blog ok 40 True ['article']
```

These were parse/transport checks only; they did not ingest observations into a
production database. The current draft sample includes SP 1353 AI CSF guidance;
the current blog sample includes "Back to the Future: Why Agentic AI Needs a
Strong Identity Foundation". No FIPS record was present in the inspected draft
snapshot, and the snapshot is not represented as an exhaustive standards list.

Official documentation/usage sources:

- [CSRC documented Atom/JSON draft feeds](https://csrc.nist.gov/publications/drafts-open-for-comment)
- [NIST documented feeds and Cybersecurity Insights link](https://www.nist.gov/coo/nist-rss-feeds)
- [NIST data/technical-publication reuse conditions](https://www.nist.gov/open/license)
- [NIST website copyright and exclusions](https://www.nist.gov/copyrights-disclaimers)
- [NVD official 2.0 reference schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [NVD reference-tag explanation](https://nvd.nist.gov/general/FAQ-Sections/CVE-FAQs)
- [FIPS 203 final publication and planning note](https://csrc.nist.gov/pubs/fips/203/final)
- [AI RMF 1.0 publication metadata](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
- [SP 800-218A final metadata/history](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [AI 600-1 publication metadata](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [EU Commission AI Act overview](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [EU official Act Service Desk original-edition citation](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-108)
- [EUR-Lex metadata/content usage conditions](https://eur-lex.europa.eu/content/legal-notice/legal-notice.html)
- [CycloneDX JSON field definitions](https://cyclonedx.org/docs/1.7/json/)
- [SPDX 2.3 package/purl references](https://spdx.github.io/spdx-spec/v2.3/package-information/)
- [Official purl type definitions](https://github.com/package-url/purl-spec/tree/main/docs/types/definitions)

EUR-Lex direct original-document access displayed robot verification. It was not
bypassed; official indexed metadata, Commission pages and the official Service
Desk citation establish the cataloged original edition. Current consolidated
law and later amendments/timelines were not fully verified. EU metadata CC0,
editorial/consolidated text CC BY 4.0 and material-specific exceptions remain
distinct. No continuously monitored policy feed is claimed.

## Offline validation

Run only Coverage-owned tests:

```
python3 -m unittest tests.test_nist_feeds tests.test_core_sbom tests.test_core_knowledge_catalog tests.test_poc_metadata -q
```

**60 tests passed** (9 NIST, 22 SBOM, 11 catalog, 18 tagged-reference/strict-POC).
This includes authentic feed parsing, request Accept and
validators, synthetic explicit pagination/resumption, last-completion freezing,
rate limits/network/malformed failure with unchanged cursors, source updates and
dedup, absence versus explicit tombstone, evidence/cursor transaction rollback,
XML/URL/source-identity boundaries, detached curated schema/Record projection,
source date precision, legal edition and license qualifications, SBOM namespaces,
client/server counterexamples, conflict/unknown versions, input bounds/secret
absence/no network, and explicit POC-tag provenance/no generic GitHub heuristic.

Root owns registration, live/demo integration, fact/QA/UI wiring, full-suite and
browser checks. These tests do not establish performance, accuracy, recall,
competition score thresholds, current legal completeness or POC availability.
