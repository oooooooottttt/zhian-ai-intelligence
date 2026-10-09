# SQLite storage and AI relevance handoff

Implemented only the assigned files: `aicti_monitor/storage.py`,
`aicti_monitor/relevance.py`, `tests/test_storage.py`, `tests/test_relevance.py`,
and this handoff. No public model or other module changes. Standard library only.

## Behavior and interface

- All contracted `Store` methods are implemented. Every public method opens and
  closes its own connection; SQLite WAL, foreign keys, busy timeout, explicit
  transactions, and FULL synchronous durability are enabled. Read methods use
  a consistent snapshot when they perform multiple queries.
- An observation is unique by `(source_id, upstream_id)`. `new` counts new source
  observations, including a second source describing an existing canonical
  event. `updated` counts changed observations; `unchanged` counts repeats;
  `fetched` counts all supplied records, and `ai_related` counts positive records
  in that batch. Duplicate rows in one batch count as one new plus repeats.
- Only structurally valid CVE (year >= 1999, at least four sequence digits) and
  GHSA (documented restricted alphabet) aliases link events. Case is normalized.
  OSV IDs and invalid aliases remain upstream evidence and do not link events.
  Titles, summaries, and IDs from different sources never merge by similarity.
- A newly received alias can bridge existing events. The smallest event ID
  survives; source observations, historical aliases, and every revision remain.
  `get_record(old_id)` resolves merged IDs and adds `merged_from_id`.
  Removed aliases remain historical links in `canonical_aliases`; a source's
  current and historical `aliases` retain the facts it actually supplied.
- Fingerprints compare normalized semantic record content. Metadata fields
  `collected_at`, `fetched_at`, `upstream_response_at`, `feed_updated_at`, `feed_id`,
  `filter_explanation`, `source_name`, `source_category`, and `trust` are observation
  or local display fields and do not create upstream content revisions. An
  unchanged observation still receives its latest full sanitized payload and
  `last_seen_at`. Real `upstream_revision`, `version`, title, summary, aliases,
  components, reference, rights, and withdrawal changes append snapshots.
- `ingest_and_finish` commits observations, revisions, alias merges/redirects,
  result counts, run completion, and opaque cursor together. Any exception rolls
  everything back and leaves the run `running`; the runner then calls `fail_run`.
  A failure preserves the cursor, previous successful result/time, and evidence.
  An older concurrent run cannot replace a newer finalized source state.
- Partial successful runs have `status="partial"`; complete runs have
  `status="success"`. `last_success_at` is the latest committed successful fetch,
  including a resumable partial fetch. The additive `last_completed_at` advances
  only on complete fetches. `last_result` includes counts plus `complete`.
  `next_run_at`, `last_error`, and `consecutive_failures` support scheduler backoff;
  timing and HTTP rate-limit enforcement remain the runner/client responsibility.

## UI and export data

`list_records` returns canonical events, defaulting to current AI-positive
events. `include_non_ai=True` exposes all collected events, and `get_record`
always permits inspection of non-AI evidence. Pagination limit is 0..500 with a
nonnegative offset. Chinese and literal `%`, `_`, backslash searches use bound
SQL parameters and query current title/summary/components/aliases/upstream ID.
Kind and source filters match the same source observation; AI visibility is
determined across all current observations of that event.

Default order is each event's `MAX(updated_at or published_at)` over all current
source observations, descending. Each observation prefers its update date and
falls back to its publication date. SQL computes this global order before
pagination using `json_extract` on the current normalized payloads; historical
revision dates and recent backfill/refresh collection times do not promote an
old entry. Equal upstream dates use `first_seen_at DESC, id DESC`; entries with
no upstream date sort after dated entries with the same stable fallback. Source
and kind filters select events but do not discard another source's current date
from that canonical event's aggregate. UTC normalization/fraction-safe keys keep
SQL ordering consistent with returned dates. No schema migration or dependency
is required; this uses SQLite's built-in JSON support.

Each event has the contracted Record fields from a deterministic representative
observation (AI-positive first, then latest collection, then earliest observation
ID), plus `id`, `record_id`, `first_seen_at`, `last_seen_at`, `latest_upstream_at`, `revision_count`,
`is_ai_related`, `relevance_score`, `relevance_reasons`, `risk_categories`,
`canonical_aliases`, `source_ids`, `observation_count`, `withdrawn`, and
`observations`. The representative is a display convenience; conflicting facts
remain under their independent observations. Event `revision_count` includes
each source's initial snapshot; event `withdrawn` is true only when every current
source observation is withdrawn. AI flags/reasons/risks aggregate current evidence.
`latest_upstream_at` is the actual latest update/publication timestamp across
current observations, or `None` when none is available, and is present in both
list and detail results. It may belong to a different source than the display
representative. `first_seen_at`/`last_seen_at` remain independent collection times.

Details additionally include per-observation `revisions` and a flat event
`revisions` list. Each revision includes Record fields, `id` (revision ID),
`observation_id`, `record_id`, `revision_number`, `collected_at`, `fingerprint`,
AI explanation/risk fields, and `withdrawn`. Initial snapshots are revision 1.
Changing classifier rules updates current presentation on the next observation
without inventing content revisions or rewriting historical relevance decisions.

`list_runs` returns `id`, `source_id`, `started_at`, `finished_at`, `status`,
`complete`, `error`, and count dictionaries under `counts` and `result`.
`stats` returns `total_records`, `ai_related_records`, `non_ai_records`,
`total_observations`, `total_revisions`, `total_runs`, `by_kind`, `by_source`,
`sources` (source-state dictionaries), and `last_collected_at`. Conflicting kinds
can make one event appear in multiple `by_kind` groups. Publication/updated times
remain upstream facts; collection times and backfill counts are not latency or
freshness measurements. `metadata.demo=true` and attribution/usage terms persist;
the caller remains responsible for selecting a separate demonstration DB.

## Security and limits

Stored primary/reference links must be public HTTP(S), without URL credentials,
known secret query parameters, localhost, or literal private/reserved IPs
(including legacy numeric IPv4). Secret-shaped metadata keys and credential
assignments are redacted. Cursor credentials/unsafe links are rejected rather
than silently changing an opaque resume token. Normalized records and cursors
have a 2 MB serialized limit; JSON depth is bounded and NaN/custom objects fail.
No links are fetched here; DNS/redirect restrictions are enforced by HTTP, and
HTML escaping belongs to the renderer. Adapters must continue minimizing data
and excluding authorization: heuristic redaction cannot identify arbitrary
unlabeled secrets. The database must be a file; `:memory:` is rejected because
the contract requires a new connection per operation. Schema version is 1.

AI classification uses known packages, bounded English terms, Chinese concepts,
and AI security behaviors, with explanations and risk categories. URL/alias and
arbitrary metadata text cannot force relevance. Generic `AI` substrings and bare
`ML`, `RAG`, or `Ray` are insufficient. This heuristic may miss unfamiliar
packages or euphemisms; it is neither an LLM nor an exploitability/severity score.

## Offline verification

Run `python3 -m unittest tests.test_storage tests.test_relevance -v`.
42 tests pass, including duplicate imports, true and false revisions, source
collisions, valid/invalid aliases, late three-event bridging and redirects,
withdrawal, non-AI retention, SQLite-trigger-induced rollback during a merge,
invalid late-batch rollback, partial/failure cursor safety, backoff state,
overlapping-run ordering, Chinese/literal search pagination, URL/credential
boundaries, provenance/demo retention, threaded reads/writes, rule changes, and
correct ordering/bounds for UTC timestamps with optional fractional seconds.
Additional regressions cover newly collected old material staying below recent
intelligence, correct global pagination, update/publication fallbacks, all-source
current date aggregation, historical revisions excluded from ordering, stable
ties/undated entries, and upstream fractional seconds/timezone normalization.
No network, credentials, paper downloads, POC execution, or dependencies used.
No required contract/model changes.
