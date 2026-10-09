# Integration security review (2026-10-03)

Scope: read-only review of `AGENTS.md`, the implementation contract, shared
contracts, and existing monitoring persistence/UI. This is a pre-implementation
boundary review, not a claim that the forthcoming core implementation contains
these defects. No services, external fetches, credentials, or executable/PDF
downloads were used.

## Findings that must be addressed at integration

1. **Raw alias links are historical, not current identity truth.**
   `aicti_monitor/storage.py:358` resolves each new observation through `aliases`;
   line 370 adds/overwrites aliases, but removed aliases are never deleted.
   Withdrawal also does not split a raw event. Core must reconstruct relationships
   from latest, non-withdrawn revision payloads. A bridge disappearing from that
   graph must quarantine the previously merged bucket before any projection is
   published. A global invalidation must preserve quarantine. Future observations
   pulled into the old raw bucket by a stale alias must not silently inherit a
   confirmed core entity's authority or identity.

2. **Revision insertion alone does not capture every merge.**
   The raw merge path moves observations and aliases, inserts redirects, and
   deletes losing events (`storage.py:332`). This can happen before ingesting
   an unchanged observation. Capture observation membership changes or redirects
   transactionally as well as revision insertion. Avoid derived foreign keys to
   a raw event that make deletion fail, cascade away historical audit evidence,
   or leave an old job publishable under a recycled/redirected event identity.

3. **Lease expiry and signatures must be checked at commit.**
   A write transaction must re-read lease owner, attempt, status, expiry, current
   source revision fingerprints, inventory snapshot, mapping/policy generation,
   and method version. Expiry alone invalidates the old worker even when no newer
   worker has reclaimed the job. Require exactly one affected completion row and
   atomically write derived results plus success status. Stale/cancelled inputs
   must not report a completed successful task. An outbox consumer cannot advance
   its checkpoint ahead of failed invalidation/queue writes.

4. **Manual confirmation needs a current, complete partition.**
   Groups must be nonempty, disjoint, contain only observations in the current
   quarantined bucket, and exactly cover that bucket. Revalidate membership and
   revision/mapping generation in the same transaction as applying confirmation.
   A stale browser confirmation must not clear quarantine after a concurrent
   correction. Subsequent source changes cannot restore ready status merely
   because an earlier confirmation exists.

5. **Final answer checks must cover all current claims and host inputs.**
   Do not trust the model to report all dependencies: preserve the host's snapshot
   baseline and revalidate source/inventory/mapping/policy/method inputs after
   inference. Every current claim's support must exist at the exact latest
   revision, be non-withdrawn, and belong to a ready, authorized entity. Unknown
   entities, fabricated IDs, omitted or incompatible support, and extra model
   prose must fail closed or explicitly degrade. Historical evidence can remain
   visible, but must be labeled historical and excluded from current support.

6. **Frozen dataclasses are only shallowly immutable.**
   `Evidence.metadata` and `Fact.value` remain mutable dictionaries. Give workers
   and QA detached bounded values, preserve an independent host baseline, and
   validate returned facts/assessments rather than allowing a module or injected
   model/tool fake to mutate the object used for the final signature check.

7. **Do not inherit the legacy UI's incomplete URL/body boundary.**
   Legacy `web.py` only blocks a few private hostname/IP spellings in its JS link
   helper, and its POST collector does not read/validate JSON, body limits, or
   Content-Type. New routes need strict schema/body controls and one consistent
   public URL policy, including RFC1918, non-global IPv6, hostname suffixes,
   trailing-dot/legacy IP forms, credentials, and sensitive query keys. Continue
   rendering external content with `textContent` and retaining nonce CSP.

## Minimal adversarial integration checks

- Fail/interrupt raw ingest after a revision-triggered outbox entry: revision,
  checkpoint, epoch, projection invalidation and outbox must all roll back.
- Re-read unchanged evidence that induces a raw event merge: latest identity
  signature changes and the old task cannot publish.
- Remove/withdraw an alias bridge; process again; query the UI and QA; old merged
  facts never become ready until a valid current confirmation.
- Submit a duplicate/incomplete/cross-bucket or stale confirmation: reject it
  without clearing quarantine or incrementing a successful job state.
- Finish a lease after expiry, after reclaim, after cancel, after inventory edit,
  and after a source revision; none publishes or reports success.
- Withdraw evidence or change inventory while a model is answering; final output
  excludes stale current claims and labels the interrupted/degraded outcome.
- Have an injected fake mutate its snapshot and fabricate/omit claim evidence;
  final host validation uses the independent baseline and rejects publication.

## Implementation follow-up

The main integration chat has received the specific risks above. The first
`aicti_core/store.py` implementation was subsequently reviewed. The following
issues were reproduced with temporary, offline SQLite fixtures under
`/private/tmp`, without modifying implementation files or launching services.

### Confirmed issues in the first store implementation

1. **P1: Quarantined evidence can support a saved current answer.**
   In the initial `save_answer` implementation (lines 473–490), the ready check
   applies only to the model-supplied `entities` list; evidence validation checks
   global latest/authorized/non-withdrawn membership. With `entities=[]`, a claim
   citing an observation in a quarantined bucket is accepted and saved.
   Reproduction: merge two CVEs through a third bridge observation, withdraw the
   bridge, call `snapshot()` and observe the quarantined entity, then save a claim
   citing one remaining latest observation and no entities. The call succeeds.
   Derive each support's current ready entity from host state, require claimed
   entities to cover those owners, and verify supported current facts rather than
   trusting an empty dependency list from the model.

2. **P1: Citation metadata can be fabricated despite a valid ID.**
   The same saved claim used a correct evidence ID with `source_id='fabricated'`,
   `revision_number=999`, and `url='http://127.0.0.1/private'`; these fields were
   persisted unchanged. Rebuild citations from canonical DB evidence or require
   every provenance field to exactly match the canonical record. Evidence-ID
   membership alone does not validate the displayed attribution or URL.

3. **P1: Publication can import support from another quarantined entity.**
   Initial `publish` lines 364–370 accept any globally latest, authorized,
   non-withdrawn evidence. In a fixture, the claimed task contained only
   `obs:4:r:1`; a supplied `impact` fact cited quarantined `obs:1:r:1`. Publication
   succeeded and entity 4 became ready with that unrelated support. Default
   support must be constrained to the task's entity evidence. Explicit related
   material requires a separate bounded rule; unrelated/quarantined vulnerability
   evidence must not support an asset-impact conclusion for the task entity.

4. **P1: A worker can publish after its lease expires while waiting for a lock.**
   Initial `publish` samples `time.time()` before result serialization and
   `BEGIN IMMEDIATE` (lines 354–360). A competing writer held the database lock
   for 0.4 seconds while a task had a 0.15-second lease. The worker began publishing
   before expiry, waited for the lock, and succeeded after the lease had expired;
   the job status became `succeeded`. Production time must be sampled after the
   write transaction is acquired, and that time must drive the lease check.
   Retain explicit injected time only for deterministic offline tests. Claiming
   also samples before synchronization/lock acquisition and needs the same review.

5. **P2: Renewed manual confirmation can retire every visible entity.**
   First confirmation of a complete split partition creates group keys and works.
   After a source revision re-quarantines a group, confirming the same complete
   partition returns `updated=True` but `snapshot()['events']` is empty. The
   confirmation retires all entities in the bucket, then `sync()` reuses existing
   group keys and preserves their `retired` status (initial lines 284–287). Reactivate
   only the currently confirmed partition's entities into dirty state under the
   confirmation's fresh generation/signature; keep removed old groups retired.

All five reproduced issues were sent to the main chat promptly. Follow-up review
of the corrected store and new service/web paths remains pending.
