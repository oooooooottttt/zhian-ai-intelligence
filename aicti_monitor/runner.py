from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib
import json
import logging
from pathlib import Path
import threading
from typing import Callable

from .http import HttpClient, bounded_retry
from .models import FetchError, Record, SourceConfig

LOG = logging.getLogger("aicti_monitor")


def utcnow():
    return datetime.now(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_error(exc: Exception) -> str:
    # Upstream exceptions can contain URLs or credentials. Persist fixed categories.
    if isinstance(exc, FetchError):
        if exc.status is not None:
            return f"HTTP {exc.status}：来源访问失败；未推进采集游标"
        return "访问策略、网络或响应校验失败；未推进采集游标"
    if isinstance(exc, (ValueError, KeyError, TypeError, json.JSONDecodeError)):
        return "数据源格式或解析失败；未推进采集游标"
    return "采集流程异常；未推进采集游标"


def validate_records(records, source):
    if len(records) > 10000:
        raise ValueError("单批条目数过大")
    for r in records:
        if not isinstance(r, Record) or r.source_id != source.id or not r.upstream_id:
            raise ValueError("来源或记录标识不匹配")
        if r.kind not in {"vulnerability", "paper", "article", "standard", "policy"}:
            raise ValueError("内容类型无效")
        if len(r.title) > 2000 or len(r.summary) > 200000:
            raise ValueError("条目文本过大")
        # Reject control characters used to smuggle fake log entries.
        r.title = " ".join(r.title.split())
        r.metadata["source_name"] = source.name
        r.metadata["source_category"] = source.category
        r.metadata["terms_url"] = source.terms_url
        r.metadata["content_scope"] = source.content_scope
        r.metadata["license"] = source.params.get("license", "source-specific")
        if source.params.get("license_url"):
            r.metadata["license_url"] = source.params["license_url"]
        r.metadata["local_processing"] = "本项目规范化字段、校验链接，并按来源范围限制文本长度。"
        r.metadata["trust"] = "untrusted_external_data"
        json.dumps(r.to_dict(), ensure_ascii=False, allow_nan=False)


class Monitor:
    def __init__(self, store, sources: list[SourceConfig], http_factory: Callable = HttpClient):
        self.store = store
        self.sources = sources
        self.http_factory = http_factory
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.busy = False
        self.worker = None

    def run_once(self, source_ids: set[str] | None = None, force=False, now=None):
        import fcntl
        at = now or utcnow()
        results = []
        if not self.lock.acquire(blocking=False):
            return [{"status": "busy"}]
        lock_file = None
        try:
            lock_path = Path(self.store.path).with_suffix(".collector.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_file = lock_path.open("a+")
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return [{"status": "busy"}]
            self.busy = True
            # Exclusive ownership means prior 'running' runs lost their process.
            # Mark them failed without changing any committed resume position.
            for run in self.store.list_runs(limit=500):
                if run["status"] == "running":
                    self.store.fail_run(run["id"], run["source_id"],
                                        "上次采集进程中断；保留已提交位置并接续处理", iso(at), iso(at))
            for source in self.sources:
                if self.stop_event.is_set():
                    break
                if not source.enabled or source_ids and source.id not in source_ids:
                    continue
                state = self.store.get_source_state(source.id) or {}
                next_at = state.get("next_run_at")
                if not force and next_at:
                    due = datetime.fromisoformat(next_at.replace("Z", "+00:00"))
                    if due > at:
                        continue
                # Manual collection never bypasses an upstream rate-limit backoff.
                if force and state.get("consecutive_failures", 0) and next_at:
                    due = datetime.fromisoformat(next_at.replace("Z", "+00:00"))
                    if due > at:
                        results.append({"source_id": source.id, "status": "backoff", "next_run_at": next_at})
                        continue
                run_id = self.store.begin_run(source.id, iso(at))
                try:
                    module = {"github_advisories": "github", "github_repository": "github"}.get(source.adapter, source.adapter)
                    fetch = importlib.import_module(f"aicti_monitor.adapters.{module}").fetch
                    client = self.http_factory(source)
                    result = fetch(source, self.store.get_cursor(source.id), client, at)
                    validate_records(result.records, source)
                    finished = now or utcnow()
                    delay = source.interval_seconds if result.complete else 60
                    next_run = iso(finished + timedelta(seconds=delay))
                    counts = self.store.ingest_and_finish(run_id, source.id, result.records,
                        result.cursor, iso(finished), next_run, result.complete)
                    results.append({"source_id": source.id, "status": "ok" if result.complete else "partial",
                                    "counts": counts, "not_modified": result.not_modified})
                    LOG.info("采集 %s：%s", source.id, counts)
                except Exception as exc:
                    finished = now or utcnow()
                    failures = state.get("consecutive_failures", 0) + 1
                    wait = min(86400, 60 * 2 ** min(failures, 10))
                    if isinstance(exc, FetchError):
                        retry = bounded_retry(exc.retry_after)
                        if retry is not None:
                            wait = max(wait, retry)
                    next_run = iso(finished + timedelta(seconds=wait))
                    error = safe_error(exc)
                    self.store.fail_run(run_id, source.id, error, iso(finished), next_run)
                    results.append({"source_id": source.id, "status": "failed", "error": error})
                    LOG.warning("采集 %s：%s", source.id, error)
            return results
        finally:
            self.busy = False
            if lock_file is not None:
                lock_file.close()
            self.lock.release()

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        def work():
            while not self.stop_event.is_set():
                try:
                    self.run_once()
                except Exception:
                    LOG.error("调度运行失败，请检查本地数据库状态")
                self.wake_event.wait(15)
                self.wake_event.clear()
        self.worker = threading.Thread(target=work, daemon=True, name="monitor-worker")
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()

    def trigger(self):
        if self.busy:
            return False
        # The scheduled worker preserves due times and upstream backoff.
        self.wake_event.set()
        return True
