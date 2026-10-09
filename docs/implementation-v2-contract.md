# V2 implementation contract — 2026-10-04

The user explicitly authorized DeepSeek V4 Pro API inference, a full frontend
redesign, completion of competition features, and new GPT-6.1 sol Ultra module
chats. All work is in the shared existing checkout. Main chat integrates.

Read AGENTS.md and the original four-page competition PDF. Preserve existing
evidence, databases and PDF. Python 3.11+ standard library, no installation or
unrelated credentials. No active scans, exploit/POC execution or downloads,
automatic target remediation, or paper PDF downloads.

## Ownership

| Owner | Files |
|---|---|
| Main chat | aicti_core/service.py, store.py, web.py, cli.py, demo.py, contracts.py, model_settings.py, catalog_ingest.py; shared config/monitor storage/registry and existing NVD/enrichment provenance integration; root integration tests; AGENTS.md and public docs |
| Cloud QA chat | aicti_core/cloud_gateway.py (new), mock_gateway.py (new), grounding.py (new), qa.py, harness.py, gateway.py if necessary; tests/test_core_cloud_gateway.py, test_core_mock_gateway.py, test_core_grounding.py and existing QA/Harness/gateway tests; docs/handoffs/cloud-qa-v2.md |
| Frontend chat | aicti_core/ui.py, tests/test_core_ui.py; docs/handoffs/ui-v2.md |
| Coverage chat | new aicti_monitor/adapters/ modules only, aicti_core/sbom.py and knowledge_catalog.py (new); corresponding new tests; docs/handoffs/coverage-v2.md. Do not edit existing adapters, config, registry, store or service; report exact integration changes to main |

Do not overwrite another owner's files or launch extra chats. Report needed
cross-module changes. Only run owned tests until root runs full suite.

## DeepSeek gateway

Official API verified 2026-10-04:
- https://api-docs.deepseek.com/quick_start/pricing/
- https://api-docs.deepseek.com/api/create-chat-completion/
- https://api-docs.deepseek.com/guides/tool_calls/
- https://api-docs.deepseek.com/guides/json_mode/

Model ID `deepseek-v4-pro`, HTTPS host `api.deepseek.com`, fixed
`/chat/completions`. No arbitrary endpoints/proxies/redirects. Standard-library
TLS, public DNS/IP validation and request/response/deadline limits. Dedicated
DEEPSEEK_API_KEY env or explicit local UI input only; secret must never enter
repr, errors, logs, database, browser responses, URL or answer payloads.

`DeepSeekGateway(api_key=None, *, model='deepseek-v4-pro', timeout=20.0,
reasoning_effort='none')` exposes provider='deepseek', enabled, configured,
model, complete(messages, *, tools=None, max_tokens=...), with_timeout().
Local gateway retains existing compatibility. Provider does not imply support
for embeddings: DeepSeek's chat API must not be used as a fake embedding API.
Normalize content/tool_calls into existing Harness protocol. If thinking is
enabled, correctly preserve bounded reasoning_content for tool follow-up in
memory, never expose or persist hidden reasoning. Default non-thinking for
latency; no timing guarantee. Typed sanitized errors for auth/rate limits etc.
Injected HTTP transport for offline tests. No paid or live key calls in tests.

## Real question answering

User steering: the API key is left unfilled for now; use an explicitly labeled
Mock model to complete and verify the same plan/tool/synthesis pipeline. Do not
make a real paid API request or inspect keys for validation this round.
`mock_gateway.MockGateway()` mirrors the normalized gateway protocol and emits
deterministic JSON-schema-conforming planning/tool/synthesis responses; it has
provider='mock', model='mock-deepseek-v4-pro', enabled=True and with_timeout().
Mock results use mode='mock_model', retrieval='mock_plan'; never label mock as
real semantic quality, connected DeepSeek or cloud inference. Publish reusable
JSON Schemas for plans, analysis sections, tool arguments and final answer plans,
and implement bounded strict host validation without installing dependencies.

Cloud-mode questions should actually invoke the model, including explicit CVE
queries. Add semantic query planning/ranking over a bounded host-owned catalog,
then registered read-only tools and evidence synthesis. Exact/facts fallback
remains. Use model understanding for ordinary Chinese/multi-turn/related-document
queries, not merely relabeling keyword output as semantic.

Verified `claims` remain unchanged canonical host cards (existing six fields).
Add optional `analysis_sections`: bounded list of objects with exactly
`kind` ('analysis'|'recommendation'|'uncertainty'), `text`, `claim_ids`,
`evidence_ids`. Each nonempty text section must link to current verified claims;
evidence IDs must exactly equal the union of their evidence references. Model
synthesis is visibly labeled inference/advice, never a verified source assertion.
Unsupported source-free prose, invented IDs/versions/scores, exploitation claims
and invented links must be rejected or removed. Missing evidence is explicit.
No model reasoning_content is shown as an explanation path.

`grounding.validate_analysis_sections(sections, claims) -> list[dict]` performs
strict bounded host validation and numeric/identity guards; document its actual
semantic limits honestly. `grounding.compose_answer(claims, sections, *,
empty_answer=None) -> str` deterministically builds the saved display text.
Main service independently revalidates claims against host_card_catalog plus
original facts answer and calls these functions on detached copies before save.
Canonical citations/current revision/authorization/store transaction gates stay.

Return mode='cloud_model' for successful cloud QA, model provider/model and
retrieval='llm_semantic' only if real planning/ranking completed. Optional
analysis_sections absent or empty is backwards compatible. Model failure returns
degraded facts with clear reason. Global generation/tool budget remains bounded;
plan + tools + synthesis share <=4 model calls, <=6 tool calls, deadline <=30s.

Cloud projection must omit raw inventory and actual internal asset labels/IDs,
pseudonymize necessary asset facts and substitute those aliases in model-bound
question/history. Do not send unrelated entities, full source history or raw
credential-like strings. Host restores names in verified facts, not in opaque
untrusted prose. Document outbound data scope. Keep prompt injection boundaries.

## Additive local APIs owned by main chat

GET /api/model -> public model status only.
POST /api/model -> settings object with provider ('facts'|'ollama'|'deepseek'|'mock'),
optional model, api_key, reasoning_effort ('none'|'low'|'high'|'max'). DeepSeek
endpoint/model fixed in this version. API key is memory only; never returned.
POST /api/model/test -> {}: one bounded, explicitly requested test call.
POST /api/model/clear -> {}: disable generation and clear in-memory key.
All writes retain same Origin/token/schema/body boundaries.

`/api/system.model` adds provider, configured, credential_configured,
semantic_mode, reasoning_effort, last_test (safe status only), endpoint.
Facts mode is not a connection error. No hidden live API calls on status reads.

Main will add GET /api/knowledge -> {items:[...], coverage:{...}}. Knowledge
items: id,title,kind ('standard'|'policy'|'guide'), source,url,updated_at,
summary,topics,attribution,usage_conditions,monitoring ('curated'|'feed').
No fake live updates. Catalog is explicitly official curated metadata and/or
documented permitted feed observations; no paper PDF downloads.

POST /api/assets remains {assets:[...]}; new POST /api/assets/sbom ->
{document:<CycloneDX/SPDX JSON object>} uses bounded passive SBOM parser,
then imports authorized component inventory. No network or target discovery.

## UI redesign

Build a polished security intelligence workbench from the existing code target:
navy/teal/neutral colors, deliberate hierarchy, useful density, responsive desktop
and mobile, clear empty/loading/error states; no emoji decoration, invented scores
or mock analytics in real mode. Question answering and evidence/asset context are
primary. Keep all current behavior including session replay, source history,
withdrawal invalidation and quarantine review. Render data as text, no innerHTML
or external assets/scripts/fonts. Root CSP/token placeholders remain.

Add visible model settings (password input, memory-only notice, clear/test/save),
public provider/connectivity state, distinctly labeled verified claims and model
analysis. Add knowledge view and SBOM import using the additive APIs above.
No secrets in localStorage/URLs/browser logs, no direct browser-to-DeepSeek calls.

## Coverage and acceptance

Find official documented permitted metadata APIs/feeds for technical standards,
policies and security blogs. Implement at least one genuinely validated new
adapter plus a curated official knowledge metadata catalog; do not substitute
curated entries for continuous monitoring. Root owns registration/config changes.
POC: explicit upstream POC references only, unverified metadata; do not classify
all GitHub links as POC, do not check code availability/download or execute.
SBOM parser handles CycloneDX/SPDX JSON/purl, unknown versions, bounded input,
ambiguous client/server identity; no scan or secret data transfer.

Tests cover actual protocol requests, malformed output/injection, secret absence,
semantic/multi-turn paths, citation grounding, withdrawal/permission concurrency,
source pagination/update/resumption and SBOM identity/bounds. Main tests full
system and browser, and a real API call only if the user provides an authorized
key locally. Missing key is reported, never pretend to have run real inference.
Do not claim score thresholds, accuracy/recall or <=5s without measured results.
