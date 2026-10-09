"""Transactional SQLite observations, revisions, and canonical alias links.

Collection times describe when this monitor saw evidence. Upstream publication
and revision times remain separate; importing historical data is not proof of
monitoring timeliness. All public operations use their own SQLite connection.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlsplit

from .models import Record
from .relevance import classify


_CVE = re.compile(r"CVE-(\d{4})-\d{4,}\Z", re.I)
_GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z", re.I)
_SECRET_KEYS = frozenset({
    "authorization", "proxyauthorization", "authentication", "apikey", "accesskey",
    "accesstoken", "refreshtoken", "idtoken", "token", "bearer", "clientsecret",
    "secret", "password", "passwd", "credential", "credentials", "cookie",
    "setcookie", "privatekey", "xapikey", "xamzcredential", "xamzsignature",
    "xgoogcredential", "xgoogsignature", "signature", "sig", "key",
})
_URL_TEXT = re.compile(r"https?://[^\s<>\"']+", re.I)
_SECRET_TEXT = re.compile(
    r"\b(authorization|proxy-authorization|api[_ -]?key|access[_ -]?token|"
    r"refresh[_ -]?token|client[_ -]?secret|password|passwd)\s*[:=]\s*"
    r"(?:(?:bearer|basic)\s+)?[^\s,;]+", re.I,
)
_OBSERVATION_METADATA = frozenset({
    "collected_at", "fetched_at", "upstream_response_at", "feed_updated_at",
    "feed_id", "filter_explanation", "source_name", "source_category", "trust",
})


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _time(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Timestamps must be aware ISO8601 strings")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Timestamps must be aware ISO8601 strings") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamps must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_key(value: str | None) -> str | None:
    # ISO strings with optional fractions otherwise compare incorrectly when
    # one timestamp is exactly on a second and another is within that second.
    if value is None:
        return None
    return value if "." in value else value[:-1] + ".000000Z"


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 1024 or "\x00" in value:
        raise ValueError(f"Invalid {label}")
    if _safe_text(value) != value:
        raise ValueError(f"Credentials are not permitted in {label}")
    return value


def _url(value: str) -> str:
    """Syntactic storage boundary; HTTP still validates DNS and redirects."""
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValueError("Invalid public URL")
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Invalid public URL")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            raise ValueError("Invalid public URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL credentials are not permitted")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid public URL port")
        host = host.rstrip(".").lower().encode("idna").decode("ascii")
        if "%" in host or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError("Private network URLs are not permitted")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # inet_aton catches legacy decimal, octal, and hex IPv4 spellings.
            try:
                address = ipaddress.ip_address(socket.inet_aton(host))
            except OSError:
                if "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
                    raise ValueError("Invalid public hostname")
                address = None
        if address is not None and not address.is_global:
            raise ValueError("Private network URLs are not permitted")
        if any(_key(key) in _SECRET_KEYS for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
            raise ValueError("URL credentials are not permitted")
    except (UnicodeError, TypeError) as exc:
        raise ValueError("Invalid public URL") from exc
    return value


def _safe_text(value: str) -> str:
    def replace_url(match: re.Match[str]) -> str:
        try:
            return _url(match.group())
        except ValueError:
            return "[redacted unsafe URL]"
    return _SECRET_TEXT.sub(lambda m: m.group(1) + "=[redacted]", _URL_TEXT.sub(replace_url, value))


def _clean(value: Any, depth: int = 0) -> Any:
    if depth > 30:
        raise ValueError("JSON nesting limit exceeded")
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            if _key(key) not in _SECRET_KEYS:
                result[_safe_text(key)] = _clean(child, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_clean(child, depth + 1) for child in value]
    if isinstance(value, str):
        return _safe_text(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    raise ValueError("Payload must contain only JSON values")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _fingerprint(payload: dict[str, Any]) -> str:
    # These adapter fields describe how a page was observed, not a revision of
    # its entry. Keep them in snapshots/current evidence, never in identity.
    semantic = {**payload, "metadata": {key: value for key, value in payload["metadata"].items()
                                         if key not in _OBSERVATION_METADATA}}
    return hashlib.sha256(_json(semantic).encode("utf-8")).hexdigest()


def _aliases(values: list[str]) -> list[str]:
    result = set()
    for value in values:
        candidate = value.strip().upper()
        cve = _CVE.fullmatch(candidate)
        if (cve and int(cve.group(1)) >= 1999) or _GHSA.fullmatch(candidate):
            result.add(candidate)
    return sorted(result)


def _normalize(record: Record, source_id: str) -> dict[str, Any]:
    if not isinstance(record, Record) or record.source_id != source_id:
        raise ValueError("Record source does not match the run")
    payload = record.to_dict()
    _identifier(payload["source_id"], "source_id")
    _identifier(payload["upstream_id"], "upstream_id")
    if payload["kind"] not in {"vulnerability", "paper", "article", "standard", "policy"}:
        raise ValueError("Unsupported record kind")
    for field in ("title", "summary"):
        if not isinstance(payload[field], str):
            raise ValueError(f"Invalid record {field}")
        payload[field] = _safe_text(payload[field])
    payload["url"] = _url(payload["url"])
    for field in ("published_at", "updated_at"):
        if payload[field] is not None:
            payload[field] = _time(payload[field])
    for field in ("aliases", "components", "references"):
        values = payload[field]
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError(f"Invalid record {field}")
        payload[field] = sorted(set(_url(item) if field == "references" else _safe_text(item) for item in values))
    # Normalized valid CVE/GHSA IDs coexist with upstream OSV identifiers, which
    # are preserved as evidence but do not drive cross-source event merges.
    valid = _aliases(payload["aliases"])
    other = [value for value in payload["aliases"] if not _aliases([value])]
    payload["aliases"] = sorted(set(valid + other))
    if not isinstance(payload["metadata"], dict):
        raise ValueError("Record metadata must be an object")
    payload["metadata"] = _clean(payload["metadata"])
    if len(_json(payload).encode("utf-8")) > 2_000_000:
        raise ValueError("Normalized record exceeds storage size limit")
    return payload


def _withdrawn(payload: dict[str, Any]) -> bool:
    metadata = payload["metadata"]
    return bool(metadata.get("withdrawn") or metadata.get("withdrawn_at") or
                str(metadata.get("status", "")).casefold() in {"withdrawn", "rejected", "reject"})


class Store:
    """An on-disk SQLite store with one fresh connection per public operation."""

    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise ValueError("Store requires an on-disk database for independent connections")
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            with self._transaction(connection):
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in {0, 1}:
                    raise ValueError("Unsupported monitor database schema version")
                statements = [
                    """CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL)""",
                    """CREATE TABLE IF NOT EXISTS observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id INTEGER NOT NULL REFERENCES events(id),
                        source_id TEXT NOT NULL, upstream_id TEXT NOT NULL,
                        first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
                        revision_count INTEGER NOT NULL, fingerprint TEXT NOT NULL,
                        record_json TEXT NOT NULL, kind TEXT NOT NULL, search_text TEXT NOT NULL,
                        is_ai_related INTEGER NOT NULL, relevance_json TEXT NOT NULL,
                        UNIQUE(source_id, upstream_id))""",
                    """CREATE TABLE IF NOT EXISTS revisions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        observation_id INTEGER NOT NULL REFERENCES observations(id),
                        revision_number INTEGER NOT NULL, collected_at TEXT NOT NULL,
                        fingerprint TEXT NOT NULL, record_json TEXT NOT NULL,
                        relevance_json TEXT NOT NULL,
                        UNIQUE(observation_id, revision_number))""",
                    """CREATE TABLE IF NOT EXISTS aliases (
                        alias TEXT PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id))""",
                    """CREATE TABLE IF NOT EXISTS event_redirects (
                        old_event_id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id))""",
                    """CREATE TABLE IF NOT EXISTS source_state (
                        source_id TEXT PRIMARY KEY, last_started_at TEXT, last_success_at TEXT,
                        last_completed_at TEXT, last_error TEXT, next_run_at TEXT,
                        consecutive_failures INTEGER NOT NULL DEFAULT 0,
                        cursor_json TEXT NOT NULL DEFAULT '{}', last_result_json TEXT NOT NULL DEFAULT '{}',
                        last_finalized_run_id INTEGER NOT NULL DEFAULT 0)""",
                    """CREATE TABLE IF NOT EXISTS runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL,
                        started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
                        complete INTEGER, result_json TEXT, error TEXT)""",
                    "CREATE INDEX IF NOT EXISTS observations_event ON observations(event_id)",
                    "CREATE INDEX IF NOT EXISTS observations_source ON observations(source_id, kind, is_ai_related)",
                    "CREATE INDEX IF NOT EXISTS revisions_observation ON revisions(observation_id, revision_number)",
                    "CREATE INDEX IF NOT EXISTS events_seen ON events(last_seen_at DESC, id DESC)",
                    "CREATE INDEX IF NOT EXISTS runs_source ON runs(source_id, id DESC)",
                ]
                for statement in statements:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version=1")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.create_function("utc_key", 1, _utc_key, deterministic=True)
        connection.create_function("utc_min", 2, lambda a, b: min((a, b), key=_utc_key), deterministic=True)
        connection.create_function("utc_max", 2, lambda a, b: max((a, b), key=_utc_key), deterministic=True)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    @staticmethod
    @contextmanager
    def _transaction(connection: sqlite3.Connection, write: bool = True) -> Iterator[None]:
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

    @staticmethod
    def _state(row: sqlite3.Row | None, source_id: str) -> dict[str, Any]:
        if row is None:
            return {"source_id": source_id, "last_started_at": None, "last_success_at": None,
                    "last_completed_at": None, "last_error": None, "next_run_at": None,
                    "consecutive_failures": 0, "cursor": {}, "last_result": {}}
        state = dict(row)
        state["cursor"] = json.loads(state.pop("cursor_json"))
        state["last_result"] = json.loads(state.pop("last_result_json"))
        state.pop("last_finalized_run_id")
        return state

    def get_cursor(self, source_id: str) -> dict[str, Any]:
        _identifier(source_id, "source_id")
        with self._connection() as connection:
            row = connection.execute("SELECT cursor_json FROM source_state WHERE source_id=?", (source_id,)).fetchone()
            return json.loads(row[0]) if row else {}

    def get_source_state(self, source_id: str) -> dict[str, Any]:
        _identifier(source_id, "source_id")
        with self._connection() as connection:
            return self._state(connection.execute("SELECT * FROM source_state WHERE source_id=?", (source_id,)).fetchone(), source_id)

    def begin_run(self, source_id: str, now: str) -> int:
        _identifier(source_id, "source_id")
        now = _time(now)
        with self._connection() as connection, self._transaction(connection):
            connection.execute("INSERT INTO source_state(source_id) VALUES(?) ON CONFLICT(source_id) DO NOTHING", (source_id,))
            run = connection.execute("INSERT INTO runs(source_id, started_at, status) VALUES(?, ?, 'running')", (source_id, now))
            connection.execute("UPDATE source_state SET last_started_at=? WHERE source_id=?", (now, source_id))
            return int(run.lastrowid)

    @staticmethod
    def _check_run(connection: sqlite3.Connection, run_id: int, source_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM runs WHERE id=? AND source_id=?", (run_id, source_id)).fetchone()
        if row is None or row["status"] != "running":
            raise ValueError("Run is missing, belongs to another source, or is already finished")
        return row

    @staticmethod
    def _merge_events(connection: sqlite3.Connection, event_ids: set[int]) -> int:
        survivor = min(event_ids)
        for loser in sorted(event_ids - {survivor}):
            times = connection.execute("SELECT first_seen_at, last_seen_at FROM events WHERE id IN (?, ?)", (survivor, loser)).fetchall()
            connection.execute("UPDATE events SET first_seen_at=?, last_seen_at=? WHERE id=?", (min((row[0] for row in times), key=_utc_key), max((row[1] for row in times), key=_utc_key), survivor))
            connection.execute("UPDATE observations SET event_id=? WHERE event_id=?", (survivor, loser))
            connection.execute("UPDATE aliases SET event_id=? WHERE event_id=?", (survivor, loser))
            connection.execute("UPDATE event_redirects SET event_id=? WHERE event_id=?", (survivor, loser))
            connection.execute("INSERT INTO event_redirects(old_event_id, event_id) VALUES(?, ?)", (loser, survivor))
            connection.execute("DELETE FROM events WHERE id=?", (loser,))
        return survivor

    @staticmethod
    def _append_revision(connection: sqlite3.Connection, observation_id: int,
                         revision_number: int, now: str, fingerprint: str,
                         record_json: str, relevance_json: str) -> None:
        connection.execute("""INSERT INTO revisions(observation_id, revision_number,
            collected_at, fingerprint, record_json, relevance_json) VALUES(?, ?, ?, ?, ?, ?)""",
            (observation_id, revision_number, now, fingerprint, record_json, relevance_json))

    def _ingest_record(self, connection: sqlite3.Connection, payload: dict[str, Any], now: str) -> tuple[str, bool]:
        record_json = _json(payload)
        fingerprint = _fingerprint(payload)
        relevance = classify(Record(**payload))
        relevance_json = _json(relevance)
        observation = connection.execute("SELECT * FROM observations WHERE source_id=? AND upstream_id=?", (payload["source_id"], payload["upstream_id"])).fetchone()
        valid_aliases = _aliases(payload["aliases"])
        event_ids = {observation["event_id"]} if observation else set()
        for alias in valid_aliases:
            row = connection.execute("SELECT event_id FROM aliases WHERE alias=?", (alias,)).fetchone()
            if row:
                event_ids.add(row[0])
        if event_ids:
            event_id = self._merge_events(connection, event_ids)
        else:
            event_id = int(connection.execute("INSERT INTO events(first_seen_at, last_seen_at) VALUES(?, ?)", (now, now)).lastrowid)
        connection.execute("UPDATE events SET first_seen_at=utc_min(first_seen_at, ?), last_seen_at=utc_max(last_seen_at, ?) WHERE id=?", (now, now, event_id))
        for alias in valid_aliases:
            connection.execute("INSERT INTO aliases(alias, event_id) VALUES(?, ?) ON CONFLICT(alias) DO UPDATE SET event_id=excluded.event_id", (alias, event_id))
        search_text = "\n".join([payload["title"], payload["summary"], payload["upstream_id"], *payload["components"], *payload["aliases"]])
        if observation is None:
            result = connection.execute("""INSERT INTO observations(event_id, source_id, upstream_id,
                first_seen_at, last_seen_at, revision_count, fingerprint, record_json,
                kind, search_text, is_ai_related, relevance_json) VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
                (event_id, payload["source_id"], payload["upstream_id"], now, now, fingerprint, record_json,
                 payload["kind"], search_text, int(relevance["is_ai_related"]), relevance_json))
            self._append_revision(connection, int(result.lastrowid), 1, now, fingerprint, record_json, relevance_json)
            status = "new"
        elif _fingerprint(json.loads(observation["record_json"])) != fingerprint:
            revision_number = observation["revision_count"] + 1
            connection.execute("""UPDATE observations SET event_id=?, first_seen_at=utc_min(first_seen_at, ?),
                last_seen_at=utc_max(last_seen_at, ?), revision_count=?, fingerprint=?, record_json=?,
                kind=?, search_text=?, is_ai_related=?, relevance_json=? WHERE id=?""",
                (event_id, now, now, revision_number, fingerprint, record_json, payload["kind"],
                 search_text, int(relevance["is_ai_related"]), relevance_json, observation["id"]))
            self._append_revision(connection, observation["id"], revision_number, now, fingerprint, record_json, relevance_json)
            status = "updated"
        else:
            # Reclassify current evidence if rule code changed, without inventing
            # an upstream content revision or modifying historical decisions.
            connection.execute("""UPDATE observations SET event_id=?, first_seen_at=utc_min(first_seen_at, ?),
                last_seen_at=utc_max(last_seen_at, ?), fingerprint=?, record_json=?,
                is_ai_related=?, relevance_json=? WHERE id=?""",
                (event_id, now, now, fingerprint, record_json,
                 int(relevance["is_ai_related"]), relevance_json, observation["id"]))
            status = "unchanged"
        return status, relevance["is_ai_related"]

    def ingest_and_finish(self, run_id: int, source_id: str, records: list[Record],
                          cursor: dict[str, Any], now: str, next_run_at: str,
                          complete: bool, *, preserve_restrictions: bool = False) -> dict[str, int]:
        _identifier(source_id, "source_id")
        now, next_run_at = _time(now), _time(next_run_at)
        if not isinstance(cursor, dict) or not isinstance(complete, bool) or type(preserve_restrictions) is not bool:
            raise ValueError("Cursor must be an object and complete must be a boolean")
        cleaned_cursor = _clean(cursor)
        if _json(cleaned_cursor) != _json(cursor):
            raise ValueError("Cursor contains disallowed credentials or unsafe URLs")
        cursor_json = _json(cursor)
        if len(cursor_json.encode("utf-8")) > 2_000_000:
            raise ValueError("Cursor exceeds storage size limit")
        counts = {"fetched": len(records), "new": 0, "updated": 0, "unchanged": 0, "ai_related": 0}
        with self._connection() as connection, self._transaction(connection):
            self._check_run(connection, run_id, source_id)
            state = connection.execute("SELECT last_finalized_run_id FROM source_state WHERE source_id=?", (source_id,)).fetchone()
            if run_id <= state[0]:
                raise ValueError("A newer run already finalized this source")
            for record in records:
                payload = _normalize(record, source_id)
                # Curated seeds may refresh descriptions but cannot restore
                # withdrawn or disallowed evidence. Check inside the same
                # write transaction, after acquiring SQLite's writer lock.
                if preserve_restrictions:
                    previous = connection.execute(
                        "SELECT record_json FROM observations WHERE source_id=? AND upstream_id=?",
                        (source_id,payload["upstream_id"])).fetchone()
                    if previous:
                        current = json.loads(previous[0])
                        metadata = current["metadata"]
                        if (_withdrawn(current) or metadata.get("authorized") is False
                                or metadata.get("enrichment_allowed") is False):
                            counts["unchanged"] += 1
                            continue
                status, related = self._ingest_record(connection, payload, now)
                counts[status] += 1
                counts["ai_related"] += int(related)
            last_result = {**counts, "complete": complete}
            connection.execute("""UPDATE runs SET finished_at=?, status=?, complete=?, result_json=?
                WHERE id=?""", (now, "success" if complete else "partial", int(complete), _json(counts), run_id))
            connection.execute("""UPDATE source_state SET cursor_json=?, last_success_at=?,
                last_completed_at=CASE WHEN ? THEN ? ELSE last_completed_at END,
                last_error=NULL, next_run_at=?, consecutive_failures=0, last_result_json=?,
                last_finalized_run_id=? WHERE source_id=?""",
                (cursor_json, now, int(complete), now, next_run_at, _json(last_result), run_id, source_id))
        return counts

    def fail_run(self, run_id: int, source_id: str, error: str, now: str, next_run_at: str) -> None:
        _identifier(source_id, "source_id")
        now, next_run_at = _time(now), _time(next_run_at)
        error = _safe_text(str(error))[:2000]
        with self._connection() as connection, self._transaction(connection):
            self._check_run(connection, run_id, source_id)
            connection.execute("UPDATE runs SET finished_at=?, status='failed', complete=0, error=? WHERE id=?", (now, error, run_id))
            # An older concurrent failure may be recorded, but cannot replace a
            # newer source's cursor, scheduling state, or successful result.
            connection.execute("""UPDATE source_state SET last_error=?, next_run_at=?,
                consecutive_failures=consecutive_failures+1, last_finalized_run_id=?
                WHERE source_id=? AND last_finalized_run_id<?""", (error, next_run_at, run_id, source_id, run_id))

    @staticmethod
    def _page(limit: int, offset: int = 0) -> None:
        if type(limit) is not int or not 0 <= limit <= 500 or type(offset) is not int or offset < 0:
            raise ValueError("Pagination requires limit 0..500 and a nonnegative offset")

    @staticmethod
    def _observation(row: sqlite3.Row) -> dict[str, Any]:
        payload = json.loads(row["record_json"])
        relevance = json.loads(row["relevance_json"])
        return {**payload, "id": row["id"], "record_id": row["event_id"],
                "first_seen_at": row["first_seen_at"], "last_seen_at": row["last_seen_at"],
                "revision_count": row["revision_count"], "is_ai_related": relevance["is_ai_related"],
                "relevance_score": relevance["score"], "relevance_reasons": relevance["reasons"],
                "risk_categories": relevance["risk_categories"], "withdrawn": _withdrawn(payload)}

    def _event(self, connection: sqlite3.Connection, row: sqlite3.Row, detail: bool = False) -> dict[str, Any]:
        observations = [self._observation(item) for item in connection.execute(
            "SELECT * FROM observations WHERE event_id=? ORDER BY is_ai_related DESC, utc_key(last_seen_at) DESC, id ASC", (row["id"],))]
        representative = observations[0]
        aliases = [item[0] for item in connection.execute("SELECT alias FROM aliases WHERE event_id=? ORDER BY alias", (row["id"],))]
        reasons = sorted({reason for item in observations if item["is_ai_related"] for reason in item["relevance_reasons"]})
        risks = sorted({risk for item in observations for risk in item["risk_categories"]})
        upstream_dates = [item["updated_at"] or item["published_at"] for item in observations
                          if item["updated_at"] or item["published_at"]]
        event = {**representative, "id": row["id"], "record_id": row["id"],
                 "first_seen_at": row["first_seen_at"], "last_seen_at": row["last_seen_at"],
                 "latest_upstream_at": max(upstream_dates, key=_utc_key, default=None),
                 "revision_count": sum(item["revision_count"] for item in observations),
                 "is_ai_related": any(item["is_ai_related"] for item in observations),
                 "relevance_score": max(item["relevance_score"] for item in observations),
                 "relevance_reasons": reasons or representative["relevance_reasons"],
                 "risk_categories": risks, "canonical_aliases": aliases,
                 "source_ids": sorted({item["source_id"] for item in observations}),
                 "observation_count": len(observations), "observations": observations,
                 "withdrawn": all(item["withdrawn"] for item in observations)}
        if detail:
            revisions = []
            for observation in observations:
                history = []
                for revision in connection.execute("SELECT * FROM revisions WHERE observation_id=? ORDER BY revision_number", (observation["id"],)):
                    payload = json.loads(revision["record_json"])
                    relevance = json.loads(revision["relevance_json"])
                    item = {**payload, "id": revision["id"], "observation_id": observation["id"],
                            "record_id": row["id"], "revision_number": revision["revision_number"],
                            "collected_at": revision["collected_at"], "fingerprint": revision["fingerprint"],
                            "is_ai_related": relevance["is_ai_related"], "relevance_score": relevance["score"],
                            "relevance_reasons": relevance["reasons"], "risk_categories": relevance["risk_categories"],
                            "withdrawn": _withdrawn(payload)}
                    history.append(item)
                    revisions.append(item)
                observation["revisions"] = history
            event["revisions"] = sorted(revisions, key=lambda item: (_utc_key(item["collected_at"]), item["id"]))
        return event

    def list_records(self, limit: int = 50, offset: int = 0, kind: str | None = None,
                     query: str | None = None, source_id: str | None = None,
                     include_non_ai: bool = False) -> list[dict[str, Any]]:
        self._page(limit, offset)
        clauses, values = [], []
        if not include_non_ai:
            clauses.append("EXISTS(SELECT 1 FROM observations ai WHERE ai.event_id=e.id AND ai.is_ai_related=1)")
        observation_clauses = ["o.event_id=e.id"]
        if kind is not None:
            observation_clauses.append("o.kind=?")
            values.append(kind)
        if source_id is not None:
            observation_clauses.append("o.source_id=?")
            values.append(source_id)
        if query is not None and (not isinstance(query, str) or len(query) > 2000):
            raise ValueError("Invalid search query")
        if query:
            observation_clauses.append("o.search_text LIKE ? ESCAPE '\\'")
            values.append("%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        clauses.append("EXISTS(SELECT 1 FROM observations o WHERE " + " AND ".join(observation_clauses) + ")")
        # Compute each canonical event's most recent *current upstream* date
        # across all source observations before applying LIMIT/OFFSET. Sorting a
        # page in Python would hide newer events on subsequent pages, while
        # last_seen_at would promote freshly backfilled historical material.
        sql = """SELECT e.*, (
            SELECT MAX(utc_key(COALESCE(json_extract(current.record_json, '$.updated_at'),
                                        json_extract(current.record_json, '$.published_at'))))
            FROM observations current WHERE current.event_id=e.id
        ) AS latest_upstream_sort FROM events e WHERE """ + " AND ".join(clauses) + """
            ORDER BY latest_upstream_sort DESC, utc_key(e.first_seen_at) DESC, e.id DESC
            LIMIT ? OFFSET ?"""
        with self._connection() as connection, self._transaction(connection, write=False):
            return [self._event(connection, row) for row in connection.execute(sql, (*values, limit, offset)).fetchall()]

    def get_record(self, record_id: int) -> dict[str, Any] | None:
        if type(record_id) is not int or record_id < 1:
            return None
        with self._connection() as connection, self._transaction(connection, write=False):
            row = connection.execute("SELECT * FROM events WHERE id=?", (record_id,)).fetchone()
            if row is None:
                redirect = connection.execute("SELECT event_id FROM event_redirects WHERE old_event_id=?", (record_id,)).fetchone()
                if redirect is None:
                    return None
                row = connection.execute("SELECT * FROM events WHERE id=?", (redirect[0],)).fetchone()
            event = self._event(connection, row, detail=True)
            if event["id"] != record_id:
                event["merged_from_id"] = record_id
            return event

    def list_runs(self, limit: int = 30) -> list[dict[str, Any]]:
        self._page(limit)
        with self._connection() as connection:
            runs = []
            for row in connection.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)):
                run = dict(row)
                run["counts"] = json.loads(run.pop("result_json")) if row["result_json"] else {}
                run["result"] = dict(run["counts"])
                run["complete"] = bool(run["complete"]) if run["complete"] is not None else None
                runs.append(run)
            return runs

    def stats(self) -> dict[str, Any]:
        with self._connection() as connection, self._transaction(connection, write=False):
            total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            related = connection.execute("SELECT COUNT(*) FROM events e WHERE EXISTS(SELECT 1 FROM observations o WHERE o.event_id=e.id AND o.is_ai_related=1)").fetchone()[0]
            by_kind = {row[0]: row[1] for row in connection.execute("SELECT kind, COUNT(DISTINCT event_id) FROM observations GROUP BY kind ORDER BY kind")}
            by_source = {row[0]: row[1] for row in connection.execute("SELECT source_id, COUNT(*) FROM observations GROUP BY source_id ORDER BY source_id")}
            sources = [self._state(row, row["source_id"]) for row in connection.execute("SELECT * FROM source_state ORDER BY source_id")]
            latest = connection.execute("SELECT last_seen_at FROM events ORDER BY utc_key(last_seen_at) DESC LIMIT 1").fetchone()
            return {"total_records": total, "ai_related_records": related,
                    "non_ai_records": total - related,
                    "total_observations": connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
                    "total_revisions": connection.execute("SELECT COUNT(*) FROM revisions").fetchone()[0],
                    "total_runs": connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
                    "by_kind": by_kind, "by_source": by_source, "sources": sources,
                    "last_collected_at": latest[0] if latest else None}
