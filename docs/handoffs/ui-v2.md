# Frontend V2 handoff — 2026-10-04

## Owned files and verification

Implemented only `aicti_core/ui.py`, `tests/test_core_ui.py`, and this handoff.
Read AGENTS.md, the V2 frozen contract, system implementation notes, and all
four pages of the original competition PDF. No backend files, source evidence,
database or competition PDF were changed. No service was started, credentials
read, dependencies installed, or live model request made.

`python3 -m unittest tests.test_core_ui -q`: **58 tests passed**, including all
35 original tests. The actual nonce-bearing inline script runs in Node's
built-in VM, with offline fetch fakes and a rejecting HTML setter. A separate
HTML parser check confirmed balanced container nesting. Browser layout and
real HTTP integration are left to the main chat as assigned; these tests do
not establish browser accessibility conformance or real-model availability.

## Delivered workbench

- Rebuilt the shell, hierarchy and responsive layouts: deep navy navigation,
  restrained teal controls, light content surfaces, native SVG navigation,
  wide desktop question workspace, a live evidence/asset context rail, and
  stacked mobile views. No fonts, scripts or assets load from external hosts.
- Evidence question answering is the default view. Four useful starters cover
  impact, repair, prevention/investigation, and evidence paths. Existing session
  replay, multi-turn submission, source revision dialogs, withdrawal/history
  invalidation, task controls, CSV/TSV editing and quarantine partition review
  remain intact.
- Verified claims and model analysis/recommendations/unknowns render separately.
  Each analysis section has its own evidence buttons and buttons back to the
  supporting facts. Client validation bounds sections and verifies field shape,
  known claim IDs and exact citation unions. The page explicitly says structural
  checks do not prove semantic correctness. `cloud_model` and `llm_semantic`
  have distinct labels; `mock_model` and `mock_plan` are clearly marked offline
  demonstrations and never claim DeepSeek is connected.
- Model settings support facts, mock, Ollama and official DeepSeek V4 Pro. The
  DeepSeek endpoint/model are fixed and noneditable. Cloud activation requires
  a visible opt-in checkbox. The password field clears before the request waits
  and also after validation/failure; secrets never enter UI state, storage,
  status text or logs. Existing configured service credentials may be retained
  by leaving the field blank. Provider changes away from DeepSeek clear it.
  Only explicitly pressing the test button invokes the local test endpoint.
- Knowledge cards show actual kinds, attribution, source dates, topics, official
  links and usage conditions. Curated metadata and feed observations are
  separately labeled; counts come from the API items. Empty, loading, failed and
  cached-after-failure states are distinct. Demo banner explicitly exempts the
  real official knowledge directory from fictional demo records.
- Passive CycloneDX/SPDX JSON import reads at most 1 MB (1,000,000 bytes including request wrapper), checks basic format,
  and posts only to the local SBOM endpoint. Imported warnings are retained
  visibly. Success uses the existing epoch/snapshot write barrier and refresh;
  concurrent SBOM/inventory writes and repeated submits are blocked. Input is
  preserved on failure. File selection races retain the latest document; loading a new file blocks submission of the older text. The limit matches the current HTTP MAX_BODY of 1,000,000 bytes.
- `source_metadata` has a dedicated fact label and detail section, and distinguishes
  metadata/abstracts from full-paper or experimental conclusions. Curated update
  basis is labeled. Monitoring shows source count and distinct category count
  separately (e.g. 5 sources / 4 categories); no score or chart is fabricated.

## Additive integration expectations

All pre-existing API routes, payloads and nonce/token placeholders remain.
New routes follow the V2 contract:

| Route | UI expectation |
| --- | --- |
| GET/POST `/api/model` | `{model: public_status}`; direct status objects are also accepted. `provider` must be facts/mock/ollama/deepseek. |
| POST `/api/model/test` | `{ok, last_test, model}`. `last_test` is public metadata only; known status labels include ok/success/passed/failed/error/auth/rate_limit/timeout/unavailable/disabled. |
| POST `/api/model/clear` | `{model: public_status}` with facts mode and credentials cleared. |
| GET `/api/knowledge` | `{items: [...], coverage: {...}}`, up to 256 items. |
| POST `/api/assets/sbom` | `{document: <JSON object>}`; asset-import result fields `count`, `snapshot_id`, optional `knowledge_epoch`, and bounded `warnings`. |

Status rendering uses an allowlisted projection and will not echo unexpected
api_key, prompt or reasoning_content fields. Trace rendering shows bounded
business processing metadata and does not expose hidden reasoning. An in-flight
system read cannot restore the old provider after successful save/test/clear;
model sequencing is guarded independently from knowledge snapshot sequencing.

No additional backend API change is required by this UI. Recommended main-chat
acceptance: open the demo with provider mock; verify four question starters,
analysis references, restored history and withdrawal markers; configure facts
then mock without a Key; verify catalog types/counts/curated labels; import an
SBOM with unknown versions and inspect its warnings; inspect desktop and narrow
screen layouts. Test official DeepSeek only when the user later supplies a Key
locally. A catalog's curated update timestamp and SBOM import timestamp do not
prove continuous monitoring or newly verified deployment state.

## Browser acceptance wording follow-up — 2026-10-04

Main chat reported browser acceptance of QA, multi-turn continuation, citations,
model save/test, knowledge catalog and SBOM import. Its remaining wording
feedback was implemented only in the owned UI: known SBOM parser warnings now
use Chinese user-facing wording, and missing asset conditions show component
identity/version/applicability, inventory time/freshness, authentication and
Internet exposure questions rather than internal field names. Unknown messages
retain their original text; official document names and parser/data semantics
are unchanged. All **58 existing UI tests passed** again. No redundant wording
mirror tests were added.
