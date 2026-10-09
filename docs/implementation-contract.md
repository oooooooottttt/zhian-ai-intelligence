# Implementation contract (2026-10-03)

The user authorized implementing the full system. The main chat owns integration.
All chats use the same local workspace; do not edit files assigned to others.
Use Python 3.11+ standard library, unittest, no installation or credential reads.
Preserve the competition PDF and existing live/demo database separation.

## Ownership

| Owner | Assigned files only |
|---|---|
| Main chat | contracts.py, store.py, service.py, web.py, cli.py, __main__.py, demo.py under aicti_core; integration/store/service/web tests; AGENTS.md, README.md, implementation docs |
| Enrichment chat | aicti_core/versioning.py, aicti_core/enrichment.py; tests/test_core_versioning.py, tests/test_core_enrichment.py; docs/handoffs/enrichment-implementation.md |
| Agent/QA chat | aicti_core/gateway.py, aicti_core/harness.py, aicti_core/qa.py; tests/test_core_gateway.py, tests/test_core_harness.py, tests/test_core_qa.py; docs/handoffs/qa-implementation.md |
| UI chat | aicti_core/ui.py; tests/test_core_ui.py; docs/handoffs/ui-implementation.md |

Do not edit existing monitoring files or shared contracts. Report needed changes
in the assigned handoff; main chat integrates. Do not create extra chats.

## Shared domain types

See aicti_core/contracts.py. Evidence IDs are `obs:<observation_id>:r:<revision_number>`.
Facts bind predicates and JSON values to exact evidence IDs. Withdrawn evidence
cannot support current facts. Facts statuses valid/candidate; assessments use
affected/not_in_range/unknown and potentially_affected/not_affected_with_reason/
under_investigation/resolved. Current results never imply confirmed exploitation.

Asset rows are dicts: asset_id, name, ecosystem, component, version,
exposed (bool or None), authenticated (bool or None), observed_at (UTC ISO8601),
capabilities (dict of bounded booleans). Optional snapshot_id is added by store.
No arbitrary URLs, credentials, script or executable fields in asset imports.

## Enrichment API (module 2)

`enrich(evidence: Sequence[Evidence], assets: Sequence[dict], related:
Sequence[Evidence] = (), *, now: str | None = None) -> EnrichmentResult`

Pure, bounded, no network/DB access. Read GitHub metadata.packages
(ecosystem, name, vulnerable_version_range, patched_versions), metadata.cvss,
metadata.cwes, metadata.conditions/fixes where explicitly structured. NVD CPE
names alone do not prove package range or installed product identity.
Preferred predicates: affected_component, affected_range, cvss, weakness,
condition, fix, impact, related_material, poc_reference, risk_pattern.
related_material value includes target_evidence_id and relation direct/background.
Only exact IDs or explicit defect evidence imply direct relation; topic/name
similarity is background. POC references are unverified metadata, never fetched.
Do not invent CVSS/fix data. Preserve conflicts and unsupported-version unknown.
Client ollama/PyPI differs from Ollama server/product. Union of ranges:
positive match wins; otherwise any unsupported relevant range -> unknown;
only fully evaluated nonmatches -> not_in_range. Inventory staleness visible.

## Model and bounded Agent API (module 3)

`gateway.ModelGateway(base_url=None, model=None, *, timeout=15.0)`
implements `complete(messages: list[dict], *, tools=None, max_tokens=800) -> dict`.
Result normalized to content:str, tool_calls:list[dict], model:str; failures raise
`ModelUnavailable` or `ModelError` without echoing secrets/untrusted responses.
Default model disabled unless explicitly configured. Support fixed local Ollama
HTTP API at localhost/127.0.0.1 (not arbitrary local URLs/paths or redirects).
Optional remote transport must have equivalent public network safety, allowlist,
request/response size and deadline controls; do not silently forward inventory
to cloud. No downloads/installations/model startup. Offline injected fakes.
Optional `embed(texts: list[str]) -> list[list[float]]` for local semantic recall,
bounded finite dimensions and count, with clear unavailable degradation.

`harness` implements typed registered read-only tools, host-assigned run identity,
immutable final results, deny that cannot be overridden, globally bounded calls/
steps/depth/time. Real model/tool feedback loop, not three fixed prompts with
Agent labels. Unknown tools, unsafe arguments, stale data and no-progress stop.

`qa.answer(question: str, snapshot: dict, *, history: list[dict] | None = None,
gateway=None) -> dict` is bounded, never accesses DB or arbitrary network itself;
may use gateway for local inference. Returns at least answer:str, claims:list,
citations:list, mode:str (facts/local_model/degraded), warnings:list, trace:list,
entities:list[int], knowledge_epoch:int, as_of:str. Each claim has text and
evidence_ids; each citation contains evidence_id, source_id, upstream_id, url,
title, revision_number and collected_at. No fabricated citations/versions.
Injected external text is data, not instructions. Exact CVE/asset facts fast path;
Chinese short terms, continuation and limited 2–3-hop evidence paths supported.
Semantic retrieval optional through local embeddings, isolated model profile;
keyword/facts fallback explicitly labeled, not reported as semantic capability.

Snapshot supplied by main service (JSON-compatible):
```
{
  knowledge_epoch: int, policy_generation: int, asset_snapshot_id: int,
  as_of: UTC str, demo: bool,
  assets: [asset dict], evidence: [Evidence.to_dict()],
  events: [{id:int, title:str, aliases:list[str], generation:int,
            status:'ready'|'dirty'|'quarantined', evidence_ids:list[str],
            facts:[Fact.to_dict()], assessments:[Assessment.to_dict()], warnings:list}]
}
```
Only ready, currently authorized events yield current facts. Withdrawn entries
may appear for historical trace but must be excluded from current support.
Store/service performs final current-snapshot revalidation; QA must return exact
dependency IDs/entities so it can reject concurrent changes. Do not persist
model history/semantic vectors in module files or introduce a second DB truth.

## UI contract

`ui.PAGE: str` is complete self-contained HTML/CSS/JS; placeholders __NONCE__,
__TOKEN__ replaced by server. CSP only nonce inline style/script, connect self;
no external fonts/scripts/resources. All external text via textContent, never
innerHTML. No model markdown interpreted as HTML. Links only validated public
http(s) without credentials/private literals/local hostnames. No target scans.

Endpoints, JSON responses:
- GET /api/system -> {snapshot:<above>, jobs:[job status], model:{enabled,model},
  monitoring:{stats,sources,collect,busy}, sessions:[id,title,updated_at]}
- GET /api/events/<id> -> event + evidence:[Evidence dict with history if needed]
- GET /api/evidence/<evidence_id> -> Evidence dict (history status labeled)
- GET /api/sessions/<32-hex-id> -> {id,title,updated_at,knowledge_epoch,messages:[
  {role,content,created_at,knowledge_epoch,stale,payload?:<saved answer>}]}
  Saved assistant payloads retain their original epoch; stale answers are history.
  Currently unauthorized source content is hidden from historical payloads.
- POST /api/assets -> {assets:[asset rows]} -> {snapshot_id,count,queued}
- POST /api/process -> {} -> {processed,remaining} (bounded manual wake)
- POST /api/ask -> {question,session_id?:str} -> above answer + session_id
- POST /api/collect -> {} -> {queued} (disabled in offline demo/no-collect)
- POST /api/demo/withdraw -> {} -> {updated,knowledge_epoch} (demo only)
- POST /api/entities/confirm -> {event_id,groups:[[observation IDs]],reason,expected_generation}
  -> {updated} (quarantined case only; optional advanced UI)

All POST fetches use Content-Type application/json and X-Monitor-Token __TOKEN__;
server additionally enforces localhost Host, Origin, body limit/JSON/schema.
Show sources+revisions, inventory age+unknowns, impacts+repair evidence, chat with
claim-level citations, task/degraded/dirty/quarantine state. Demo data permanently
labeled fictional, model-free supported. No manual giant JSON config in main
product flow; use a small form or import example. Prefer coherent Chinese UI.

Root limits inventory imports to 256 rows, with ASCII asset IDs (1–64 chars,
letters/digits/underscore/dot/hyphen) and five declared capabilities:
external_documents, rag, tools, network, write_access. Metadata permission denies
exclude evidence from current projections. related candidates are host-selected,
at most 128 per job. Candidate capability hypotheses without observation support
are inventory-derived UI notices, not confirmed QA claims. POC candidates retain
unverified/not_checked/downloaded=false/executed=false. Local generation and local
embedding profiles are separate opt-ins. Remote model transport is not implemented.

## Integration and persistence

Main installs SQLite triggers in the shared monitor DB to record revision changes
and invalidate core projections in the same collection transaction, without
changing monitor adapters. Historical data backfill bounded. First implementation
may conservatively invalidate all derived events; report this cost honestly.
Worker tasks have lease owner/attempt/expiry, signature of source revisions,
assets/mapping/policy/method versions; stale/cancelled/unauthorized publication
rejected in the same write transaction. Source changes and inventory changes
queue work; query revalidates raw latest revisions before current answers.
Wrong alias bridge removal quarantines merged bucket; human confirmation creates
derived entity groups without modifying original observation/revision IDs.

Meaningful offline tests include range unions/unknown, model failure/injection,
citations that do not support claims, crash/retry/withdrawal/old worker, mapping
quarantine, import security, HTTP origin/CSP and end-to-end normal+correction.
Do not claim 95% accuracy, semantic support, cloud permission, scale or <=5s
without corresponding real measurements. Independent module chats run only
their assigned test files until main integrates.
