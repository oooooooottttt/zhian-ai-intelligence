"""One SQLite truth: immutable monitor evidence and fenced core projections."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import json
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from aicti_monitor.storage import Store as MonitorStore
from .contracts import Evidence, EnrichmentResult, METHOD_VERSION


class StaleResult(ValueError):
    """An input, authorization or execution lease is no longer current."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))


def detached(value: Any) -> Any:
    return json.loads(dumps(value))


def digest(value: Any) -> str:
    return hashlib.sha256(dumps(value).encode()).hexdigest()


def evidence_from_dict(value: dict) -> Evidence:
    data = detached({f.name: value[f.name] for f in fields(Evidence) if f.name in value})
    for name in ("aliases", "components", "references"):
        if name in data:
            data[name] = tuple(data[name])
    return Evidence(**data)


def _text(value, name, maximum=256, required=True):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError(f"Invalid {name}")
    value = value.strip()
    if required and not value:
        raise ValueError(f"Missing {name}")
    if re.search(r"(?i)(bearer\s+\S+|(?:password|api[_-]?key|secret|token)\s*[:=]|https?://\S+@)", value):
        raise ValueError("Credentials are not accepted")
    return value


def validate_assets(rows: list[dict]) -> list[dict]:
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise ValueError("Inventory must contain 1 to 256 rows")
    allowed = {"asset_id", "name", "ecosystem", "component", "version", "exposed",
               "authenticated", "observed_at", "capabilities"}
    normalized, ids = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - allowed:
            raise ValueError("Unknown inventory fields")
        asset_id = _text(row.get("asset_id"), "asset_id", 64)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", asset_id) or asset_id in ids:
            raise ValueError("Invalid or duplicate asset ID")
        ids.add(asset_id)
        entry = {"asset_id": asset_id, "name": _text(row.get("name", asset_id), "name"),
                 "ecosystem": _text(row.get("ecosystem"), "ecosystem", 80),
                 "component": _text(row.get("component"), "component"),
                 "version": _text(row.get("version", "unknown"), "version", 128)}
        for name in ("exposed", "authenticated"):
            value = row.get(name)
            if value is not None and not isinstance(value, bool):
                raise ValueError("Inventory conditions must be bool or null")
            entry[name] = value
        at = row.get("observed_at") or utc_now()
        if not isinstance(at, str) or len(at) > 64:
            raise ValueError("Invalid inventory timestamp")
        try:
            dt = datetime.fromisoformat(at.replace("Z", "+00:00"))
            if dt.tzinfo is None or dt.timestamp() > time.time() + 300:
                raise ValueError("Inventory timestamp needs a valid timezone")
        except (ValueError, OverflowError):
            raise ValueError("Invalid inventory timestamp") from None
        entry["observed_at"] = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        capabilities = row.get("capabilities", {})
        allowed_capabilities = {"external_documents", "rag", "tools", "network", "write_access"}
        if not isinstance(capabilities, dict) or set(capabilities) - allowed_capabilities:
            raise ValueError("Unknown capability")
        if any(v is not None and not isinstance(v, bool) for v in capabilities.values()):
            raise ValueError("Capabilities must be bool or null")
        entry["capabilities"] = capabilities.copy()
        normalized.append(entry)
    return normalized


class CoreStore:
    MAX_OBSERVATIONS = 5000

    def __init__(self, path: str | Path):
        self.monitor_store = MonitorStore(path)
        self.path = self.monitor_store.path
        with self.connection(write=True) as db:
            # executescript closes the preliminary transaction; begin the actual
            # schema transaction inside the script and let connection commit it.
            db.executescript("""BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS kb_meta (
                    id INTEGER PRIMARY KEY CHECK(id=1), knowledge_epoch INTEGER NOT NULL DEFAULT 1,
                    policy_generation INTEGER NOT NULL DEFAULT 1, asset_snapshot_id INTEGER NOT NULL DEFAULT 0,
                    mapping_version INTEGER NOT NULL DEFAULT 1, policy_json TEXT NOT NULL DEFAULT '{}');
                INSERT OR IGNORE INTO kb_meta(id) VALUES(1);
                CREATE TABLE IF NOT EXISTS kb_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, observation_id INTEGER NOT NULL,
                    revision_number INTEGER, reason TEXT NOT NULL, handled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS kb_entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, monitor_event_id INTEGER NOT NULL,
                    group_key TEXT NOT NULL UNIQUE, title TEXT NOT NULL, aliases_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'dirty', quarantine_reason TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS kb_source_cache (
                    observation_id INTEGER PRIMARY KEY, revision_number INTEGER NOT NULL,
                    aliases_json TEXT NOT NULL, monitor_event_id INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_overrides (
                    monitor_event_id INTEGER PRIMARY KEY, groups_json TEXT NOT NULL,
                    reason TEXT NOT NULL, confirmed_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_asset_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, assets_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER NOT NULL,
                    generation INTEGER NOT NULL, signature TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
                    attempt INTEGER NOT NULL DEFAULT 0, owner TEXT, lease_until REAL,
                    next_run REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL, finished_at TEXT,
                    error TEXT, UNIQUE(entity_id, generation, signature));
                CREATE TABLE IF NOT EXISTS kb_results (
                    entity_id INTEGER PRIMARY KEY, generation INTEGER NOT NULL,
                    result_json TEXT NOT NULL, signature TEXT NOT NULL, published_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_sessions (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS kb_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
                    role TEXT NOT NULL, content TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}',
                    knowledge_epoch INTEGER NOT NULL, created_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS kb_task_due ON kb_tasks(status,next_run,id);
                CREATE INDEX IF NOT EXISTS kb_messages_session ON kb_messages(session_id,id);
                CREATE TRIGGER IF NOT EXISTS kb_revision_changed AFTER INSERT ON revisions BEGIN
                    INSERT INTO kb_changes(observation_id,revision_number,reason)
                        VALUES(NEW.observation_id,NEW.revision_number,'revision');
                    UPDATE kb_meta SET knowledge_epoch=knowledge_epoch+1 WHERE id=1;
                    UPDATE kb_entities SET generation=generation+1,
                        status=CASE WHEN status IN ('quarantined','retired') THEN status ELSE 'dirty' END;
                    UPDATE kb_tasks SET status='cancelled' WHERE status IN ('queued','retry_wait','running');
                END;
                CREATE TRIGGER IF NOT EXISTS kb_mapping_changed AFTER UPDATE OF event_id ON observations
                    WHEN NEW.event_id != OLD.event_id BEGIN
                    INSERT INTO kb_changes(observation_id,reason) VALUES(NEW.id,'mapping');
                    UPDATE kb_meta SET knowledge_epoch=knowledge_epoch+1,mapping_version=mapping_version+1 WHERE id=1;
                    UPDATE kb_entities SET generation=generation+1,
                        status=CASE WHEN status IN ('quarantined','retired') THEN status ELSE 'dirty' END;
                    UPDATE kb_tasks SET status='cancelled' WHERE status IN ('queued','retry_wait','running');
                END;
            """)
            # A resumable source-of-truth reconciliation handles historical rows.
            if not db.execute("SELECT 1 FROM kb_source_cache LIMIT 1").fetchone():
                db.execute("INSERT INTO kb_changes(observation_id,reason) SELECT id,'backfill' FROM observations")
            columns = {r[1] for r in db.execute("PRAGMA table_info(kb_asset_snapshots)")}
            if "expired" not in columns:
                db.execute("ALTER TABLE kb_asset_snapshots ADD COLUMN expired INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def connection(self, write=False):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _meta(db):
        return dict(db.execute("SELECT * FROM kb_meta WHERE id=1").fetchone())

    def set_policy(self, source_ids: list[str] | None, *, method_version=METHOD_VERSION, source_conditions=None):
        policy = {"sources": sorted(source_ids) if source_ids is not None else None,
                  "method": method_version, "conditions": detached(source_conditions or {})}
        with self.connection(write=True) as db:
            if self._meta(db)["policy_json"] != dumps(policy):
                db.execute("UPDATE kb_meta SET policy_json=?,policy_generation=policy_generation+1,knowledge_epoch=knowledge_epoch+1 WHERE id=1", (dumps(policy),))
                self._invalidate(db)

    @staticmethod
    def _invalidate(db):
        db.execute("UPDATE kb_entities SET generation=generation+1,status=CASE WHEN status IN ('quarantined','retired') THEN status ELSE 'dirty' END")
        db.execute("UPDATE kb_tasks SET status='cancelled' WHERE status IN ('queued','retry_wait','running')")

    def _observations(self, db):
        rows = db.execute("""SELECT o.*,r.id AS revision_id,r.collected_at FROM observations o
            JOIN revisions r ON r.observation_id=o.id AND r.revision_number=o.revision_count
            ORDER BY o.id LIMIT ?""", (self.MAX_OBSERVATIONS + 1,)).fetchall()
        if len(rows) > self.MAX_OBSERVATIONS:
            raise ValueError("Core observation limit exceeded; no partial reconciliation committed")
        return rows

    @staticmethod
    def _evidence(row):
        value = json.loads(row["record_json"])
        metadata = value.get("metadata", {})
        withdrawn = bool(metadata.get("withdrawn") or metadata.get("withdrawn_at") or
                         str(metadata.get("status", "")).casefold() in {"withdrawn", "rejected", "reject"})
        return Evidence(id=f"obs:{row['id']}:r:{row['revision_count']}", observation_id=row["id"],
            revision_number=row["revision_count"], source_id=value["source_id"], upstream_id=value["upstream_id"],
            kind=value["kind"], title=value["title"], summary=value["summary"], url=value["url"],
            aliases=tuple(value.get("aliases", [])), components=tuple(value.get("components", [])),
            references=tuple(value.get("references", [])), metadata=metadata, withdrawn=withdrawn,
            collected_at=row["collected_at"], updated_at=value.get("updated_at"), published_at=value.get("published_at"))

    @staticmethod
    def _split_current(rows):
        active = []
        for row in rows:
            e = CoreStore._evidence(row)
            if e.kind == "vulnerability" and not e.withdrawn:
                aliases = {x.casefold() for x in (*e.aliases, e.upstream_id)
                           if re.fullmatch(r"(?i)(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", x)}
                active.append((e.observation_id, aliases))
        groups: list[tuple[set[int], set[str]]] = []
        for obs, aliases in active:
            linked = [g for g in groups if aliases & g[1]]
            if linked:
                ids, tags = {obs}, set(aliases)
                for g in linked:
                    ids.update(g[0]); tags.update(g[1]); groups.remove(g)
                groups.append((ids, tags))
            else:
                groups.append(({obs}, aliases))
        return len(groups) > 1

    @staticmethod
    def _authorized(e):
        return e.metadata.get("authorized") is not False and e.metadata.get("enrichment_allowed") is not False

    def _related_candidates(self, db, evidence, own_ids):
        quarantined = {i for r in db.execute("SELECT evidence_json FROM kb_entities WHERE status='quarantined'") for i in json.loads(r[0])}
        primary = [e for e in evidence if e.id in own_ids]
        aliases = {a.casefold() for e in primary for a in (*e.aliases,e.upstream_id)}
        materials = [e for e in evidence if e.kind in {"paper","article","standard","policy"} and
                     not e.withdrawn and self._authorized(e) and e.id not in quarantined]
        def score(e):
            explicit = {str(a).casefold() for a in (*e.aliases,e.upstream_id,*e.metadata.get("defect_ids",[]))}
            return (not bool(explicit & aliases),e.id)
        materials.sort(key=score)
        return materials[:128],len(materials)>128

    def _expire_inventory(self,db):
        current = self._meta(db)["asset_snapshot_id"]
        inventory = db.execute("SELECT assets_json,expired FROM kb_asset_snapshots WHERE id=?",(current,)).fetchone()
        if not inventory:
            return False
        rows = json.loads(inventory["assets_json"])
        expired = sorted(a["asset_id"] for a in rows if time.time()-datetime.fromisoformat(a["observed_at"].replace("Z","+00:00")).timestamp()>86400)
        prior = json.loads(inventory["expired"]) if isinstance(inventory["expired"],str) else []
        if expired != prior:
            db.execute("UPDATE kb_asset_snapshots SET expired=? WHERE id=?",(dumps(expired),current))
            db.execute("UPDATE kb_meta SET knowledge_epoch=knowledge_epoch+1 WHERE id=1")
            self._invalidate(db)
            return True
        return False

    def sync(self):
        """Reconcile latest observations; no historical alias table is trusted."""
        with self.connection(write=True) as db:
            self._expire_inventory(db)
            rows = self._observations(db)
            by_bucket = {}
            for row in rows:
                by_bucket.setdefault(row["event_id"], []).append(row)
            live_keys = set()
            for bucket, members in by_bucket.items():
                # Non-AI data stays in monitor; authorized papers remain related candidates.
                if not any(r["is_ai_related"] for r in members):
                    continue
                override = db.execute("SELECT * FROM kb_overrides WHERE monitor_event_id=?", (bucket,)).fetchone()
                groups = json.loads(override["groups_json"]) if override else [[r["id"] for r in members]]
                current_ids = {r["id"] for r in members}
                exact_override = override and {x for group in groups for x in group} == current_ids
                split = self._split_current(members)
                for group in groups:
                    chosen = [r for r in members if r["id"] in group]
                    if not chosen:
                        continue
                    key = f"m:{bucket}" if not override else f"m:{bucket}:{digest(sorted(group))[:16]}"
                    live_keys.add(key)
                    evidence = [self._evidence(r) for r in chosen]
                    aliases = sorted({a for e in evidence if not e.withdrawn for a in e.aliases})
                    existing = db.execute("SELECT * FROM kb_entities WHERE group_key=?", (key,)).fetchone()
                    # Changes after manual confirmation require renewed review if split persists.
                    changed = any((cached := db.execute("SELECT * FROM kb_source_cache WHERE observation_id=?", (r["id"],)).fetchone())
                                  and (cached["revision_number"] != r["revision_count"] or cached["monitor_event_id"] != bucket)
                                  for r in chosen)
                    quarantine = (split and not override) or bool(override and (not exact_override or (split and changed)))
                    old_quarantine = existing and existing["status"] == "quarantined"
                    status = "quarantined" if quarantine or old_quarantine else "dirty"
                    reason = "当前来源的别名关系已分离或变更，需确认实体映射" if quarantine or old_quarantine else ""
                    title = next((e.title for e in evidence if e.kind == "vulnerability" and not e.withdrawn), evidence[0].title)
                    ids_json = dumps([e.id for e in evidence])
                    if not existing:
                        db.execute("INSERT INTO kb_entities(monitor_event_id,group_key,title,aliases_json,evidence_json,status,quarantine_reason) VALUES(?,?,?,?,?,?,?)", (bucket,key,title,dumps(aliases),ids_json,status,reason))
                    else:
                        fresh_status = status if quarantine or old_quarantine or existing["status"] == "retired" else existing["status"]
                        if existing["evidence_json"] != ids_json:
                            fresh_status = "quarantined" if quarantine or old_quarantine else "dirty"
                        db.execute("UPDATE kb_entities SET title=?,aliases_json=?,evidence_json=?,status=?,quarantine_reason=? WHERE id=?", (title,dumps(aliases),ids_json,fresh_status,reason,existing["id"]))
                for r in members:
                    db.execute("INSERT INTO kb_source_cache VALUES(?,?,?,?) ON CONFLICT(observation_id) DO UPDATE SET revision_number=excluded.revision_number,aliases_json=excluded.aliases_json,monitor_event_id=excluded.monitor_event_id", (r["id"],r["revision_count"],dumps(self._evidence(r).aliases),bucket))
            for row in db.execute("SELECT id,group_key FROM kb_entities WHERE status!='retired'").fetchall():
                if row["group_key"] not in live_keys:
                    db.execute("UPDATE kb_entities SET status='retired',generation=generation+1 WHERE id=?", (row["id"],))
                    db.execute("UPDATE kb_tasks SET status='cancelled' WHERE entity_id=? AND status IN ('queued','running','retry_wait')", (row["id"],))
            db.execute("UPDATE kb_changes SET handled=1 WHERE handled=0")
            queued = 0
            for entity in db.execute("SELECT * FROM kb_entities WHERE status='dirty'").fetchall():
                signature = self._signature(db, entity)
                queued += db.execute("INSERT OR IGNORE INTO kb_tasks(entity_id,generation,signature,created_at) VALUES(?,?,?,?)", (entity["id"],entity["generation"],signature,utc_now())).rowcount
            return queued

    def _assets(self, db):
        ident = self._meta(db)["asset_snapshot_id"]
        row = db.execute("SELECT assets_json FROM kb_asset_snapshots WHERE id=?", (ident,)).fetchone()
        return [{**x, "snapshot_id": ident} for x in json.loads(row[0])] if row else []

    def import_assets(self, rows):
        rows = validate_assets(rows)
        with self.connection(write=True) as db:
            ident = db.execute("INSERT INTO kb_asset_snapshots(created_at,assets_json) VALUES(?,?)", (utc_now(),dumps(rows))).lastrowid
            db.execute("UPDATE kb_meta SET asset_snapshot_id=?,knowledge_epoch=knowledge_epoch+1 WHERE id=1", (ident,))
            self._invalidate(db)
        return {"snapshot_id": ident, "count": len(rows), "queued": self.sync()}

    def _signature(self, db, entity):
        meta = self._meta(db)
        evidence_ids = json.loads(entity["evidence_json"])
        revisions = [(r["id"],r["revision_count"],r["fingerprint"],r["event_id"]) for r in self._observations(db)]
        return digest({"entity":entity["id"],"generation":entity["generation"],"evidence_ids":evidence_ids,
                       "revisions":revisions,"assets":meta["asset_snapshot_id"],"mapping":meta["mapping_version"],
                       "policy":meta["policy_generation"],"policy_json":meta["policy_json"],"method":METHOD_VERSION})

    def claim(self, owner: str, *, now=None, lease_seconds=120):
        self.sync()
        with self.connection(write=True) as db:
            if self._expire_inventory(db):
                # Normal exit commits the invalidation; next polling cycle will
                # enqueue the current generation rather than claim a stale job.
                return None
            now = time.time() if now is None else now
            task = db.execute("""SELECT * FROM kb_tasks WHERE (status IN ('queued','retry_wait') AND next_run<=?)
                OR (status='running' AND lease_until<=?) ORDER BY id LIMIT 1""", (now,now)).fetchone()
            if not task:
                return None
            entity = db.execute("SELECT * FROM kb_entities WHERE id=?", (task["entity_id"],)).fetchone()
            if not entity or entity["status"] != "dirty" or task["signature"] != self._signature(db,entity):
                db.execute("UPDATE kb_tasks SET status='cancelled' WHERE id=?", (task["id"],))
                return None
            attempt = task["attempt"] + 1
            db.execute("UPDATE kb_tasks SET status='running',attempt=?,owner=?,lease_until=?,error=NULL WHERE id=?", (attempt,owner,now+lease_seconds,task["id"]))
            policy = json.loads(self._meta(db)["policy_json"])
            allowed = policy.get("sources")
            all_evidence = [self._evidence(r) for r in self._observations(db)
                            if allowed is None or json.loads(r["record_json"])["source_id"] in allowed]
            own_ids = set(json.loads(entity["evidence_json"]))
            related, omitted = self._related_candidates(db,all_evidence,own_ids)
            return {**dict(task),"attempt":attempt,"owner":owner,"lease_until":now+lease_seconds,
                    "evidence":[e.to_dict() for e in all_evidence if e.id in own_ids],
                    "related":[e.to_dict() for e in related],"related_omitted":omitted,
                    "assets":self._assets(db)}

    def _check_task(self, db, task, now):
        row = db.execute("SELECT * FROM kb_tasks WHERE id=?", (task["id"],)).fetchone()
        entity = db.execute("SELECT * FROM kb_entities WHERE id=?", (task["entity_id"],)).fetchone()
        if (not row or not entity or row["status"] != "running" or row["owner"] != task["owner"] or
            row["attempt"] != task["attempt"] or row["lease_until"] <= now or entity["status"] != "dirty" or
            row["generation"] != entity["generation"] or row["signature"] != self._signature(db,entity)):
            raise StaleResult("输入或任务资格已经变化")
        return row, entity

    def publish(self, task, result: EnrichmentResult, *, now=None):
        # Persist a time-triggered invalidation before entering the publish
        # transaction, so rejecting a stale result does not roll it back.
        self.sync()
        payload = detached(result.to_dict())
        if len(dumps(payload).encode()) > 1_000_000:
            raise ValueError("Enrichment result too large")
        with self.connection(write=True) as db:
            if self._expire_inventory(db):
                # Only invalidation writes have occurred. Preserve them even
                # though publication is rejected; connection rollback is then
                # harmless because this transaction has already committed.
                db.commit()
                raise StaleResult("Inventory expired while waiting to publish")
            now = time.time() if now is None else now
            row, entity = self._check_task(db,task,now)
            meta = self._meta(db)
            policy = json.loads(meta["policy_json"])
            allowed = policy.get("sources")
            latest = {e.id:e for r in self._observations(db) if not (e := self._evidence(r)).withdrawn
                      and self._authorized(e) and (allowed is None or e.source_id in allowed)}
            inventory = {x["asset_id"]:x for x in self._assets(db)}
            primary_ids = set(json.loads(entity["evidence_json"])) & set(latest)
            related_ids = {e.id for e in self._related_candidates(db,list(latest.values()),primary_ids)[0]}
            for item in (*payload["facts"], *payload["assessments"]):
                ids = item.get("evidence_ids", [])
                candidate = (item.get("predicate")=="risk_pattern" and item.get("status")=="candidate" and
                             item.get("value",{}).get("basis")=="asset_declared_capabilities")
                if candidate:
                    value = item["value"]
                    asset = inventory.get(value.get("asset_id"))
                    patterns = {"prompt_injection_tool_abuse":("external_documents","tools"),
                        "retrieval_content_poisoning":("external_documents","rag"),
                        "tool_network_egress":("tools","network"),"tool_write_abuse":("tools","write_access")}
                    required = patterns.get(value.get("pattern"))
                    if not asset or not required or value.get("asset_snapshot_id") != meta["asset_snapshot_id"] or not isinstance(value.get("capabilities"),dict) or set(value["capabilities"]) != set(required) or any(value["capabilities"].get(k) is not True or asset["capabilities"].get(k) is not True for k in required):
                        raise ValueError("Invalid capability hypothesis")
                if not isinstance(ids,list) or (item in payload["facts"] and not ids and not candidate) or any(i not in latest for i in ids):
                    raise ValueError("Result references invalid evidence")
                if item in payload["assessments"] and not ids and (item.get("status")!="under_investigation" or item.get("version_match")!="unknown"):
                    raise ValueError("Unreferenced assessment cannot conclude applicability")
                support = primary_ids | related_ids if item.get("predicate") in {"related_material","risk_pattern","poc_reference"} else primary_ids
                if any(i not in support for i in ids):
                    raise ValueError("Evidence does not support this entity")
                if any(latest[i].metadata.get("authorized") is False or latest[i].metadata.get("enrichment_allowed") is False for i in ids):
                    raise ValueError("Evidence permission denied")
                if item.get("predicate") == "related_material":
                    target = item.get("value",{}).get("target_evidence_id")
                    if target not in related_ids or item["value"].get("relation") not in {"direct","background"}:
                        raise ValueError("Invalid material relation")
                for key in ("target_evidence_id","material_evidence_id","advisory_evidence_id","locator_evidence_id"):
                    pointer = item.get("value",{}).get(key)
                    if pointer is not None and (pointer not in support or pointer not in ids):
                        raise ValueError("Invalid evidence pointer")
                if item.get("predicate") == "poc_reference":
                    value = item["value"]
                    targets = value.get("target_evidence_ids",[])
                    if item.get("status")!="candidate" or value.get("verification")!="unverified" or value.get("availability")!="not_checked" or value.get("downloaded") is not False or value.get("executed") is not False or not isinstance(targets,list) or any(i not in primary_ids or i not in ids for i in targets):
                        raise ValueError("POC metadata must remain unverified")
            asset_ids = {x["asset_id"] for x in self._assets(db)}
            if any(x["asset_id"] not in asset_ids for x in payload["assessments"]):
                raise ValueError("Unknown asset in result")
            at = utc_now()
            db.execute("INSERT INTO kb_results VALUES(?,?,?,?,?) ON CONFLICT(entity_id) DO UPDATE SET generation=excluded.generation,result_json=excluded.result_json,signature=excluded.signature,published_at=excluded.published_at", (entity["id"],entity["generation"],dumps(payload),row["signature"],at))
            db.execute("UPDATE kb_entities SET status='ready' WHERE id=? AND generation=?", (entity["id"],entity["generation"]))
            updated = db.execute("UPDATE kb_tasks SET status='succeeded',finished_at=?,lease_until=NULL WHERE id=? AND owner=? AND attempt=? AND status='running'", (at,row["id"],task["owner"],task["attempt"])).rowcount
            if updated != 1:
                raise StaleResult("Task completion lost ownership")
            # Publishing a new projection also changes the answerable snapshot.
            # It does not invalidate other tasks whose input signature is unchanged.
            db.execute("UPDATE kb_meta SET knowledge_epoch=knowledge_epoch+1 WHERE id=1")

    def fail(self, task, *, now=None, permanent=False):
        now = time.time() if now is None else now
        with self.connection(write=True) as db:
            row = db.execute("SELECT * FROM kb_tasks WHERE id=?", (task["id"],)).fetchone()
            if row and row["status"] == "running" and row["owner"] == task["owner"] and row["attempt"] == task["attempt"]:
                status = "failed" if permanent or row["attempt"] >= 3 else "retry_wait"
                error = "输入超界或结构不支持，保留证据，请检查任务输入" if permanent else "处理失败，保留证据并等待重试"
                db.execute("UPDATE kb_tasks SET status=?,next_run=?,error=?,lease_until=NULL WHERE id=?", (status,now+min(60,2**row["attempt"]),error,task["id"]))

    def pending_count(self):
        with self.connection() as db:
            return db.execute("SELECT COUNT(*) FROM kb_tasks WHERE status IN ('queued','running','retry_wait')").fetchone()[0]

    def jobs(self, limit=40):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT id,entity_id,generation,status,attempt,created_at,finished_at,error FROM kb_tasks ORDER BY id DESC LIMIT ?", (min(100,max(1,limit)),))]

    def snapshot(self, *, demo=False):
        self.sync()
        with self.connection() as db:
            meta = self._meta(db)
            policy = json.loads(meta["policy_json"])
            allowed = policy.get("sources")
            evidence = [e.to_dict() for r in self._observations(db) if self._authorized(e := self._evidence(r))
                        and (allowed is None or e.source_id in allowed)]
            permitted = {e["id"] for e in evidence}
            permitted_evidence = {e["id"]:e for e in evidence}
            events = []
            for row in db.execute("SELECT * FROM kb_entities WHERE status!='retired' ORDER BY id DESC"):
                own = [i for i in json.loads(row["evidence_json"]) if i in permitted]
                if not own:
                    continue
                result = db.execute("SELECT * FROM kb_results WHERE entity_id=? AND generation=?", (row["id"],row["generation"])).fetchone()
                payload = json.loads(result["result_json"]) if result and row["status"] == "ready" else {"facts":[],"assessments":[],"warnings":[]}
                support = {i for f in payload["facts"] for i in f["evidence_ids"]}
                support.update(f["value"]["target_evidence_id"] for f in payload["facts"] if f["predicate"] == "related_material")
                refs = sorted(set(own) | (support & permitted))
                projected = [permitted_evidence[i] for i in own]
                title = next((e["title"] for e in projected if not e["withdrawn"]), projected[0]["title"])
                aliases = sorted({a for e in projected if not e["withdrawn"] for a in e["aliases"]})
                events.append({"id":row["id"],"title":title,"aliases":aliases,
                    "generation":row["generation"],"status":row["status"],"evidence_ids":refs,
                    **payload,"quarantine_reason":row["quarantine_reason"]})
            return {"knowledge_epoch":meta["knowledge_epoch"],"policy_generation":meta["policy_generation"],
                    "asset_snapshot_id":meta["asset_snapshot_id"],"mapping_version":meta["mapping_version"],
                    "as_of":utc_now(),"demo":demo,"assets":self._assets(db),"evidence":evidence,"events":events}

    def evidence(self, ident):
        match = re.fullmatch(r"obs:(\d+):r:(\d+)", ident)
        if not match:
            return None
        with self.connection() as db:
            row = db.execute("""SELECT o.id,o.event_id,o.revision_count,o.record_json AS latest_record_json,r.record_json,r.collected_at,
                r.revision_number AS requested_revision FROM observations o JOIN revisions r ON o.id=r.observation_id
                WHERE o.id=? AND r.revision_number=?""", tuple(map(int,match.groups()))).fetchone()
            if not row:
                return None
            value = dict(row)
            current_revision = value["revision_count"]
            value["revision_count"] = value["requested_revision"]
            e = self._evidence(value)
            latest_metadata = json.loads(value["latest_record_json"]).get("metadata",{})
            policy = json.loads(self._meta(db)["policy_json"])
            if not self._authorized(e) or latest_metadata.get("authorized") is False or latest_metadata.get("enrichment_allowed") is False or policy.get("sources") is not None and e.source_id not in policy["sources"]:
                return None
            return {**e.to_dict(),"current":current_revision == e.revision_number,"current_revision_number":current_revision}

    def confirm_groups(self, entity_id, groups, reason, *, expected_generation):
        reason = _text(reason,"reason",1000)
        if not isinstance(groups,list) or not 1 <= len(groups) <= 50 or any(not isinstance(g,list) or not g for g in groups):
            raise ValueError("Invalid entity groups")
        flat = [x for g in groups for x in g]
        if any(type(x) is not int for x in flat) or len(set(flat)) != len(flat):
            raise ValueError("Entity groups must be a unique partition")
        with self.connection(write=True) as db:
            row = db.execute("SELECT * FROM kb_entities WHERE id=?", (entity_id,)).fetchone()
            if not row or row["status"] != "quarantined" or row["generation"] != expected_generation:
                raise StaleResult("Entity needs a fresh review")
            ids = {r[0] for r in db.execute("SELECT id FROM observations WHERE event_id=?", (row["monitor_event_id"],))}
            if set(flat) != ids:
                raise StaleResult("Groups no longer cover current observations")
            db.execute("INSERT INTO kb_overrides VALUES(?,?,?,?) ON CONFLICT(monitor_event_id) DO UPDATE SET groups_json=excluded.groups_json,reason=excluded.reason,confirmed_at=excluded.confirmed_at", (row["monitor_event_id"],dumps(groups),reason,utc_now()))
            db.execute("UPDATE kb_meta SET mapping_version=mapping_version+1,knowledge_epoch=knowledge_epoch+1 WHERE id=1")
            self._invalidate(db)
            db.execute("UPDATE kb_entities SET status='retired' WHERE monitor_event_id=?", (row["monitor_event_id"],))
        self.sync()
        return {"updated":True}

    def history(self, session_id):
        if not session_id:
            return []
        if not isinstance(session_id,str) or not re.fullmatch(r"[a-f0-9]{32}",session_id):
            raise ValueError("Invalid session ID")
        with self.connection() as db:
            rows = db.execute("SELECT * FROM kb_messages WHERE session_id=? ORDER BY id DESC LIMIT 8", (session_id,)).fetchall()
            current = self._meta(db)["knowledge_epoch"]
            return [{"role":r["role"],"content":r["content"],"entities":json.loads(r["payload_json"]).get("entities",[]),
                     "stale":r["knowledge_epoch"] != current} for r in reversed(rows)]

    def save_answer(self, question, answer, baseline, session_id=None):
        question = _text(question,"question",2000)
        answer = detached(answer)
        self.sync()
        with self.connection(write=True) as db:
            if self._expire_inventory(db):
                db.commit()
                raise StaleResult("Inventory expired while waiting to answer")
            meta = self._meta(db)
            if any(meta[k] != baseline[k] for k in ("knowledge_epoch","policy_generation","asset_snapshot_id","mapping_version")):
                raise StaleResult("Knowledge changed during answering")
            latest = {e.id:e for r in self._observations(db) if not (e := self._evidence(r)).withdrawn and self._authorized(e)}
            allowed = json.loads(meta["policy_json"]).get("sources")
            latest = {i:e for i,e in latest.items() if allowed is None or e.source_id in allowed}
            ready = {r["id"]:r for r in db.execute("SELECT * FROM kb_entities WHERE status='ready'")}
            requested = answer.get("entities",[])
            if not isinstance(requested,list) or any(type(i) is not int or i not in ready for i in requested):
                raise StaleResult("Answer depends on an unavailable entity")
            baseline_events = {e["id"]:e for e in baseline["events"] if e["status"] == "ready"}
            if any(i not in baseline_events or ready[i]["generation"] != baseline_events[i]["generation"] for i in requested):
                raise StaleResult("Answer entity generation changed")
            support_by_entity = {i:set(baseline_events[i]["evidence_ids"]) & set(latest) for i in requested}
            permitted_support = set().union(*support_by_entity.values()) if requested else set()
            ids = set()
            for claim in answer.get("claims",[]):
                if not isinstance(claim,dict) or not isinstance(claim.get("evidence_ids"),list) or not claim["evidence_ids"]:
                    raise ValueError("Every claim needs evidence")
                if claim.get("entity_id") not in support_by_entity:
                    raise StaleResult("Claim entity is unavailable")
                allowed_support = permitted_support if claim.get("predicate") == "asset_count" else support_by_entity[claim["entity_id"]]
                if any(i not in allowed_support for i in claim["evidence_ids"]):
                    raise StaleResult("Claim is outside its entity evidence")
                ids.update(claim["evidence_ids"])
            for citation in answer.get("citations",[]):
                ids.add(citation.get("evidence_id"))
            if any(i not in latest or i not in permitted_support for i in ids):
                raise StaleResult("Evidence withdrawn or revised")
            citation_ids = {x.get("evidence_id") for x in answer.get("citations",[])}
            if not ids.issubset(citation_ids):
                raise ValueError("Missing claim citation")
            # The database owns source identity and URLs, never model output.
            answer["citations"] = [{"evidence_id":i, **{k:getattr(latest[i],k) for k in
                ("source_id","upstream_id","url","title","revision_number","collected_at")}} for i in sorted(citation_ids)]
            session_id = session_id or uuid.uuid4().hex
            if not re.fullmatch(r"[a-f0-9]{32}",session_id):
                raise ValueError("Invalid session ID")
            answer["session_id"] = session_id
            answer["as_of"] = baseline["as_of"]
            answer["knowledge_epoch"] = meta["knowledge_epoch"]
            db.execute("INSERT INTO kb_sessions VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at", (session_id,question[:60],utc_now()))
            for role, content, payload in (("user",question,{}),("assistant",str(answer.get("answer","")),answer)):
                db.execute("INSERT INTO kb_messages(session_id,role,content,payload_json,knowledge_epoch,created_at) VALUES(?,?,?,?,?,?)", (session_id,role,content,dumps(payload),meta["knowledge_epoch"],utc_now()))
            return answer

    def sessions(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM kb_sessions ORDER BY updated_at DESC LIMIT 50")]

    def session_detail(self,session_id):
        if not isinstance(session_id,str) or not re.fullmatch(r"[a-f0-9]{32}",session_id):
            raise ValueError("Invalid session ID")
        with self.connection() as db:
            session = db.execute("SELECT * FROM kb_sessions WHERE id=?",(session_id,)).fetchone()
            if not session:
                return None
            meta = self._meta(db)
            allowed = json.loads(meta["policy_json"]).get("sources")
            permitted_observations = {e.observation_id for row in self._observations(db) if self._authorized(e := self._evidence(row)) and (allowed is None or e.source_id in allowed)}
            rows = db.execute("SELECT * FROM kb_messages WHERE session_id=? ORDER BY id DESC LIMIT 60",(session_id,)).fetchall()
            messages = []
            for row in reversed(rows):
                value = dict(row)
                payload = json.loads(value.pop("payload_json"))
                value["stale"] = value["knowledge_epoch"] != meta["knowledge_epoch"]
                if value["role"]=="assistant":
                    cites = payload.get("citations",[])
                    inaccessible = any(not re.fullmatch(r"obs:(\d+):r:(\d+)",str(c.get("evidence_id",""))) or
                        int(c["evidence_id"].split(":")[1]) not in permitted_observations for c in cites)
                    if inaccessible:
                        value["content"] = "该历史回答包含当前未获授权的来源，内容已隐藏。"
                        payload = {"answer":value["content"],"claims":[],"citations":[],"entities":[],
                            "mode":"history","knowledge_epoch":value["knowledge_epoch"],"as_of":value["created_at"],
                            "warnings":["来源权限已变化"],"trace":[],"session_id":session_id}
                        value["stale"] = True
                    value["payload"] = payload
                messages.append(value)
            return {**dict(session),"messages":messages,"knowledge_epoch":meta["knowledge_epoch"]}
