# Agent / QA implementation handoff

Implemented 2026-10-03 in the seven assigned files only:

- `aicti_core/gateway.py`, `aicti_core/harness.py`, `aicti_core/qa.py`
- `tests/test_core_gateway.py`, `tests/test_core_harness.py`, `tests/test_core_qa.py`
- this handoff

No shared contract change is required. No service was started, dependency
installed, credentials inspected, model or paper downloaded, POC fetched or
executed, target scanned, asset changed, database written or extra chat created.
Internal agents worked in separately assigned gateway/harness files; an
independent read-only reviewer challenged QA boundaries. The competition PDF's
four pages were extracted and visually inspected. Original SHA256 remains
`37f28bc38db91ec0407551b1254c8bc882432a8488ce896c681e1210814c6cf3`.

## Integration API

The frozen `ModelGateway(base_url=None, model=None, *, timeout=15.0)` and
`complete(messages, *, tools=None, max_tokens=800)` interfaces are unchanged.
Generation is disabled when model is absent. `enabled`, `model`, `base_url` and
`timeout` are readable properties. Tool calls normalize to
`{"name": name, "arguments": dict}`; assistant feedback may use this shape or
the Ollama function shape. Tool results use `role="tool", tool_name=name`.

Explicit embedding configuration is separate:

```python
gateway = ModelGateway(model="already-installed-chat-model")
gateway = gateway.with_embedding_model("already-installed-embedding-model")
# Or ModelGateway().with_embedding_model(...) for embedding-only retrieval.
```

`embedding_enabled` defaults to false. `embed(texts)` uses the independent
embedding model; it does not silently reuse the chat model. `with_timeout(s)`
returns a new gateway retaining both profiles and tightening the timeout to
`min(old_timeout, s)`. No environment variables or configuration credentials are
read. These methods neither install nor start a model.

Harness integration:

```python
registry = ToolRegistry()
registry.register(ToolSpec(name, description, parameters, handler))
run = Harness(gateway, registry, policy=HarnessPolicy(...), budget=RunBudget(...))
result = run.run(messages)
child = run.child(allowed_tools={"read_facts"})
```

`ToolSpec` accepts strict bounded JSON Schema parameters and a trusted read-only
handler. A one-argument handler named args/arguments/params receives the argument
dict; otherwise arguments are passed as keywords. `argument_mode` may explicitly
select mapping/kwargs. Optional freshness checks reject stale reads.
`HarnessResult` provides content, trace, status, run_id, generations and tool_calls;
trace is deeply frozen and `to_dict()` exports a detached JSON-compatible copy.
No prompt, arguments, results, untrusted exception body or hidden reasoning is
written to trace. Host-assigned identity, deny policy and the physical budget
state are shared by children; children can only narrow the parent's tool scope.

`qa.answer(question, snapshot, *, history=None, gateway=None)` returns the frozen
contract fields, plus:

- `evidence_ids`, `policy_generation`, `asset_snapshot_id`, `event_generations`
- `signature` containing those dependency fields and `knowledge_epoch`
- `retrieval` (`keywords` or `hybrid_local`) and `paths`
- each claim's `id`, `entity_id`, `predicate` and structured `value`

Main service must still revalidate the independent pre-answer snapshot and all
returned entities, evidence revisions, policy and asset signature before
publication. All `claims.entity_id` values occur in `entities`. Path, actual
tool-read, projected model-catalog and global asset-count dependencies are also
included even when a model omits their card.
Snapshot authorization is the host service's responsibility; explicit
`authorized=False` or `current=False` additionally fails closed here. A caller
cannot make untrusted documents authoritative merely by marking them ready.

`host_card_catalog(snapshot: dict, entity_ids: list[int]) -> dict[str, dict]` is
the pure, bounded approval helper requested for main-service semantic selection
validation. It uses the same current snapshot and deterministic cards as QA,
without model, network or persistent writes. It accepts at most 32 positive
integer entity IDs (booleans are rejected), deduplicates them and returns up to
64 fact cards and 64 asset-assessment cards separately for each ready entity.
Values and evidence support remain detached from the input snapshot. Counts
remain approved through the existing independent reference-answer calculation.
Use this catalog to supplement the existing reference-approved card collection.
The per-category caps mean a valid intent-selected repair card or exact asset
card beyond the catalog's first 64 may still be present in the reference answer;
catalog absence alone must not discard an independently approved reference card.
Other omitted cards should fail closed or degrade, without weakening support
validation or accepting model prose.

## Implemented behavior

**Transport:** only the exact localhost/127.0.0.1 HTTP endpoint on port 11434 is
accepted, and the connection is physically pinned to numeric 127.0.0.1. Only
`/api/show`, `/api/chat` and `/api/embed` are available. No DNS, environment proxy,
credentials in URLs, arbitrary path, redirect or remote transport is used.
Every inference first checks model-only `/api/show`; cloud names, remote fields
and unverified local formats are rejected before sending question/evidence.
Request limit is 256 KiB, response 2 MiB, HTTP framing/header lines 16 KiB, vectors
32 inputs / 4096 dimensions with finite nonzero values and bounded magnitude.
Show and inference share one deadline; a watchdog closes slow sockets. HTTP 429
is classified with bounded Retry-After rather than retried indefinitely.
Exceptions contain only fixed safe diagnostics.

**Harness:** a real model → validated tool → immutable feedback → model loop.
The full proposed tool batch is validated before any handler executes. Unknown
tools, scope expansion, immutable denies, unsafe arguments, stale data, payload
limits and repeated no-progress calls stop the run. Global generation maximum
is four, including repeat runs, children and any future repair call using the
same budget. QA additionally limits six executed tools, ten steps, depth one and
a twenty-second overall deadline, passing remaining time into actual gateway
clones. Normal tools are read_facts and, only for relationship intent, relations.
Actual relationship reads are recorded and merged into the result signature,
including when a per-event read reaches edges omitted by the initial global
32-path projection cap. No network, execution or write tool is registered in QA.

**Facts and recall:** only ready, valid facts with all support IDs in the host's
event dependency projection are published. Evidence identity must match its
observation/revision fields. Highest revisions supersede older entries; a new
withdrawn revision cannot revive an old fact. Conflicting duplicate evidence
identities fail closed. Exact CVE/GHSA (including identifiers directly adjacent
to Chinese), component and asset queries use current facts without generation.
An explicit inventory asset ID plus CVE returns only that asset's assessment even
without the word “资产”; exact asset cards take priority over other event facts
before the 64-card display cap. The facts fast path remains `mode="facts"` even
if an injected unavailable gateway was supplied, because no inference was tried.
For a relevant observation whose latest validated authorized/current revision
is withdrawn, QA explicitly warns that this source's evidence was withdrawn.
Old withdrawn revisions superseded by live revisions and unrelated withdrawals
do not produce this query warning; other current source facts remain usable.
Chinese bigrams and short intent terms support keyword recall. Unknown explicit
identifiers do not return a different vulnerability or asset. Continuations use
only history entity IDs, reload current facts and reject stale anchors; historical
answer prose is not evidence. Asset/name ASCII boundaries avoid asset-1/asset-10
and prod/product collisions. Private/credential/alternate numeric IP citation
links are omitted; QA never resolves or opens any citation.

**Optional semantic branch:** an explicitly configured local embedding profile
performs actual cosine candidate recall plus reciprocal rank fusion with lexical
ranking over at most 31 ready events per request. Vectors exist only in memory.
It is a bounded recall branch, not a persistent full-corpus semantic index. Model
or embedding failure shows keyword/fact degradation. A successful branch is not
a measured claim of semantic accuracy or Chinese understanding.

**Evidence answers:** returned nonempty answer text is exactly the newline join
of deterministic host-rendered claim cards. Models may select existing card IDs;
arbitrary answer/claims/prose, invented IDs or extra fields are rejected, even
when they contain existing citations. An empty selection is visibly an abstention.
There is no untested semantic-support judge declaring free assertions correct.
Version fields come from fact/inventory values. Asset counts are computed from
valid published assessments and deduplicated by asset_id, with unknown/staleness
and missing conditions visible. Global inventory counts include all current
validated events rather than silently counting only eight display events.

Fact cards now use deterministic Chinese rendering while preserving each
claim's original structured value and exact evidence support. The primary text
shows supplied component ecosystem/package names, original version boundaries,
literal exposure/authentication conditions, source-reported patches plus their
unverified effect, CVSS score/version/source and cautiously worded impact.
Internal locator, rule-version and identity-precision fields stay in structured
details. CVSS interpretation uses only supplied metrics and distinguishes
potential consequences of successful exploitation from actual exploitation of
an inventory asset. CVSS is owned by FIRST and used by permission; supplied
vectors remain in claim/evidence details with their score. Related-material
cards show the current title and direct/background scope, without upgrading
similarity to the same defect. Inventory-derived capability risks remain
hypotheses with inventory provenance. Asset reasons have duplicate sentence
punctuation removed without altering assessment values.

**Relations:** graph nodes are exact evidence revisions, not event buckets inferred
from shared dependencies. Declared valid related_material edges can be traversed
up to three hops. Background edges remain background throughout a path and are
never interpreted as the same defect or a usable attack chain. Every traversed
declaration's event and exact evidence are signature dependencies. Actual
enrichment's advisory_evidence_id → target_evidence_id (material) direction and
two-evidence support are tested.
Background relations and POC references marked candidate by enrichment do not
become current QA facts; the mock valid-background graph test verifies the
conservative graph behavior if the host later publishes a validated background
relation. It does not claim current enrichment publishes background candidates.

## Bounds and limitations

QA supports at most 1024 events, 4096 evidence records, 2048 assets and a 4,000,000
byte JSON snapshot; exceeding top-level bounds raises a fixed ValueError for the
main service to report. A question contains 1–4000 characters. Per-event facts are
processed up to 256 and assessments up to 2048, with explicit warnings rather
than dropping the entire event silently. At most eight events' cards and 64 cards
are displayed; truncation is labeled. Selected upstream event warnings are
preserved. Counting beyond display scope retains its full revalidation signature.

Only trusted host code registers handlers. A read_only declaration does not
prove an arbitrary Python function lacks side effects. Synchronous fake gateways
and host handlers cannot be safely killed if they never return; late results
are discarded and no further tool executes. The concrete network gateway's
socket watchdog and remaining-deadline cloning do enforce its bounded I/O.

The local daemon is a trusted administrator boundary. This client cannot attest
a malicious daemon, prevent that daemon from secretly forwarding data, or
eliminate the model inspection/use race. Operators should disable Ollama cloud
features. Remote providers are not implemented or implicitly enabled. No native
self-hosted Jev support is claimed: DecisionGateway is an unconfigured selection
adapter seam and cannot create facts or bypass publication checks.

No real model was run. No semantic quality, benchmark accuracy, full-corpus
recall, model latency, <=5s response guarantee or competition score was measured.
The fact-card restriction trades generative fluency for an auditable support
boundary. Source assertions can still be wrong; QA validates current provenance
and publication status, not objective truth or semantic correctness of enrichment.

## Validation

Ran only the three assigned test modules:

```text
python3 -m unittest tests.test_core_gateway tests.test_core_harness tests.test_core_qa -q
Ran 108 tests in 0.133s — OK
gateway: 24; harness: 28; QA: 56
```

Gateway tests use mocks and socketpair IPC, not a listening service. They cover
request/response schema and size limits, redirection, throttling, local/cloud
boundaries, malformed/nonfinite embeddings, real HTTP parser lifecycle and
slow-response deadline interruption. Harness covers feedback, whole-batch
validation, immutable results/policies, shared parent/child budgets, denied and
unknown tools, stale data, no progress and late responses. QA covers latest and
withdrawn revisions, candidate/dirty/quarantined/unauthorized data, mixed missing
support, invalid identities, exact and Chinese recall, stale multi-turn history,
unsupported model assertions with real citations, tool injection and feedback,
actual embedding/fallback branches, prefix/private-link boundaries, deduplicated
global counts over ten events, warning/truncation reporting, three-hop background
paths, shared-dependency non-edges, actual relation-tool dependencies beyond the
initial path cap and a real enrich → QA direct relation roundtrip.
Integration follow-up regressions also cover CVE + asset ID without a generic
asset word, multiple assets/events without scope leakage, exact assessment card
priority under display truncation, source-specific latest withdrawal warnings,
pending/history withdrawal status and preservation of other live sources.
Readability regressions preserve actual enrichment values and support, version
boundaries, AND conditions, source-reported unverified repair claims, distinct
conflicting CVSS sources, score zero, sparse/invalid impact metrics and CVSS
v2/v3/v4 semantics. They also cover relation titles/scope, inventory-origin risk
hypotheses and asset punctuation. Catalog regressions cover exact card parity,
semantic cards outside keyword recall, current/ready/authorized support,
independent 64-card category caps, 32-entity input bounds, count exclusion and
detached return values.

Official API references checked for implementation:

- [Ollama chat](https://docs.ollama.com/api/chat)
- [Ollama embed](https://docs.ollama.com/api/embed)
- [Ollama tool calling and feedback](https://docs.ollama.com/capabilities/tool-calling)
- [Official remote model fields](https://github.com/ollama/ollama/blob/main/api/types.go)
- [Ollama FAQ including cloud disablement](https://docs.ollama.com/faq)
- [FIRST CVSS v2 guide](https://www.first.org/cvss/v2/guide)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
- [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
