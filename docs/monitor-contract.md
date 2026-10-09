# Monitoring module implementation contract

Python package: `aicti_monitor`. The main chat creates `models.py`, `http.py`,
`config.py`, `runner.py`, `cli.py`, and the web application. Assigned module
chats implement their own files. Import contracts below; do not edit models.

## SourceConfig (dataclass, models.py)

- id: str
- name: str
- adapter: str (`nvd`, `github_advisories`, `github_repository`, `arxiv`, `rss`)
- category: str (`vulnerability_database`, `vendor_advisory`, `research_paper`,
  `security_blog`, `security_community`, `standard`, `policy`)
- endpoint: str
- allowed_hosts: tuple[str, ...] (exact hostnames only)
- interval_seconds: int
- min_request_interval_seconds: float
- enabled: bool
- terms_url: str
- content_scope: str (`public_advisory` or `metadata_only` or `feed_excerpt`)
- params: dict[str, Any]

## Record (dataclass, models.py)

- source_id: str
- upstream_id: str
- kind: str (`vulnerability`, `paper`, `article`, `standard`, `policy`)
- title: str
- summary: str
- url: str
- published_at: str | None (UTC ISO8601)
- updated_at: str | None (UTC ISO8601)
- aliases: list[str] (CVE/GHSA/OSV IDs only, no generic article identifiers)
- components: list[str]
- references: list[str]
- metadata: dict[str, Any] (normalized public data, exclude personal/profile data
  not needed for security research; do not include HTTP authorization)

`record.to_dict()` returns a JSON-serializable dictionary.

## FetchResult (dataclass, models.py)

- records: list[Record]
- cursor: dict[str, Any]
- complete: bool = True
- not_modified: bool = False

Cursor is opaque to runner; adapters must support resuming pagination. A cursor
can contain a frozen pending window and page offset as well as the last finished
window, but must never discard the remainder of a window. Re-query a small time
overlap to catch changes. If bounded requests are exhausted, return a partial
result plus a resumable cursor; do not label partial results complete.

## HTTP boundary (http.py)

`HttpClient(source: SourceConfig, max_requests: int = 6, timeout: float = 15.0)`

`client.get(url: str, headers: dict[str,str] | None = None) -> HttpResponse`

HttpResponse fields: `status`, `body` (bytes), `headers` (lowercase keys), `url`.
Methods: `json() -> Any`, `text() -> str`.

The client raises `FetchError(message, status=None, retry_after=None)` on network,
policy, payload-size and HTTP errors; status 304 is returned normally. It raises
`FetchBudgetExceeded` when the per-cycle request budget is consumed. Never print
headers or tokens. HTTP DNS/redirect validation is enforced by the main chat.

## Adapter files

Each exports `fetch(source, cursor, http, now) -> FetchResult`, with `now` an aware
UTC datetime. Also export a pure parser for fixture tests. Modules:

- `aicti_monitor/adapters/nvd.py`
- `aicti_monitor/adapters/github.py` (handles github_advisories + github_repository)
- `aicti_monitor/adapters/arxiv.py`
- `aicti_monitor/adapters/rss.py`

AI relevance belongs to storage/runner filtering, not brittle API-only keyword
logic. NVD may use configurable narrowly scoped keyword terms to bound fetching;
GitHub can use configured package filters. Preserve filtering explanation.

## Storage interface (storage.py)

`Store(path: str | Path)` creates SQLite DB/migrations. Each public method opens
its own connection (safe across HTTP/worker threads).

- get_cursor(source_id) -> dict
- get_source_state(source_id) -> dict (last_started_at, last_success_at,
  last_error, next_run_at, consecutive_failures, cursor, last_result)
- begin_run(source_id, now: str) -> int
- ingest_and_finish(run_id, source_id, records: list[Record], cursor: dict,
  now: str, next_run_at: str, complete: bool) -> dict of counts
- fail_run(run_id, source_id, error: str, now: str, next_run_at: str) -> None
- list_records(limit=50, offset=0, kind=None, query=None,
  source_id=None, include_non_ai=False) -> list[dict]
- get_record(record_id: int) -> dict | None
- list_runs(limit=30) -> list[dict]
- stats() -> dict

`ingest_and_finish` atomically writes records, revision history, aliases, source
observations, run results and cursor. Failed transaction rolls back all of them.
Keep different source observations and conflicting facts; a shared CVE/GHSA alias
links a canonical event, never silently overwrites source-specific evidence.
Records from demo sources must retain `metadata.demo = true`; demos use a
separate database, not live data. Full upstream arbitrary payloads are not needed.

## Relevance (relevance.py)

`classify(record: Record) -> dict` returns `is_ai_related: bool`, `score: float`,
`reasons: list[str]`, `risk_categories: list[str]`. Explainable heuristic for
monitoring only, not an LLM-based security or exploitability determination. Include
known AI components and behavioral terms, avoid broad `AI` substring matching.

## Test expectations

Use `unittest`, fixture files, fake HTTP clients, and fixed timestamps. No public
network calls in unit tests. Cover pagination > one cycle, empty responses,
upstream revision/withdrawal, source collisions, rate limits, malformed XML/JSON,
and content policy. Produce a short handoff in docs/handoffs/ with files, tests,
limitations, and any interface changes needed. The main chat verifies integration.
