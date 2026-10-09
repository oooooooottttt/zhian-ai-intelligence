"""Application boundary: the model receives copies; only the host writes truth."""
from __future__ import annotations

from dataclasses import replace
import threading
import time
import uuid

from .contracts import EnrichmentResult, Fact
from .store import CoreStore, StaleResult, detached, digest, dumps, evidence_from_dict, _text


class Application:
    def __init__(self, store: CoreStore, sources=(), monitor=None, *, gateway=None, demo=False, collect=False):
        self.store, self.sources, self.monitor = store, list(sources), monitor
        self.gateway, self.demo, self.collect = gateway, demo, collect and not demo
        self.stop_event, self.wake_event = threading.Event(), threading.Event()
        self.worker = None
        self.last_error = None
        self.process_lock, self.ask_lock = threading.Lock(), threading.Lock()
        self.owner = uuid.uuid4().hex
        self._model_lock = threading.RLock()
        self._model_test_lock = threading.Lock()
        self._model_generation = 0
        self._last_model_test = None
        if demo:
            from .demo import SOURCE_IDS
            allowed, conditions = SOURCE_IDS, {"mode":"fictional_demo"}
        else:
            allowed = [s.id for s in sources if s.enabled]
            conditions = {s.id:{"terms_url":s.terms_url,"content_scope":s.content_scope} for s in sources if s.enabled}
            from .catalog_ingest import CATALOG_SOURCES
            allowed.extend(CATALOG_SOURCES)
            conditions["curated_catalog"] = {"monitoring":"curated","content_scope":"metadata_only"}
        from .contracts import METHOD_VERSION
        from .versioning import RULE_VERSION
        store.set_policy(allowed, source_conditions=conditions,method_version=METHOD_VERSION+"/"+RULE_VERSION)

    def process(self, limit=50):
        from .enrichment import enrich
        if not self.process_lock.acquire(blocking=False):
            return {"processed":0,"remaining":self.store.pending_count(),"busy":True}
        processed = 0
        try:
            for _ in range(min(50, max(1, limit))):
                task = self.store.claim(self.owner)
                if not task:
                    break
                try:
                    primary = [evidence_from_dict(e) for e in detached(task["evidence"])]
                    related = [evidence_from_dict(e) for e in detached(task["related"])]
                    aliases = {a.casefold() for e in primary for a in (*e.aliases,e.upstream_id)}
                    # Direct identifiers first; bounded background exploration next.
                    related.sort(key=lambda e:(not any(a in (e.title+' '+e.summary).casefold() for a in aliases),e.id))
                    omitted = task.get("related_omitted",False) or len(related)>128
                    result = enrich(primary, detached(task["assets"]), related[:128])
                    # Metadata is a separately identified source assertion;
                    # an abstract is never promoted to a full-text conclusion.
                    metadata_facts = tuple(Fact("source_metadata",{
                        "kind":e.kind,"title":e.title[:500],"summary":e.summary[:1000],
                        "url":e.url,"updated_at":e.updated_at or e.metadata.get("source_updated_date"),
                        "date_precision":e.metadata.get("timestamp_precision","upstream_timestamp"),
                        "monitoring":"curated" if e.metadata.get("curated") is True else "feed",
                    },(e.id,)) for e in primary if e.kind in {"paper","article","standard","policy"})
                    if metadata_facts:
                        if len(result.facts)+len(metadata_facts)>256:
                            raise ValueError("Metadata fact budget exceeded")
                        result = replace(result,facts=(*result.facts,*metadata_facts))
                    if omitted:
                        result = replace(result,warnings=(*result.warnings,"本次关联候选限制为 128 条，未评估其余资料；不据此认定无关联。"))
                    self.store.publish(task,result)
                    processed += 1
                except StaleResult:
                    # A replacement job is created from the current authoritative input.
                    continue
                except ValueError:
                    self.store.fail(task,permanent=True)
                except Exception:
                    self.store.fail(task)
            self.last_error = None
            return {"processed":processed,"remaining":self.store.pending_count()}
        finally:
            self.process_lock.release()

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        self.stop_event.clear()
        def work():
            while not self.stop_event.is_set():
                try:
                    self.process()
                except Exception:
                    # Unknown exception strings can contain source content/secrets.
                    self.last_error = "自动处理暂不可用，请检查数据库容量和任务状态。"
                self.wake_event.wait(2)
                self.wake_event.clear()
        self.worker = threading.Thread(target=work,daemon=True,name="knowledge-worker")
        self.worker.start()
        if self.collect and self.monitor:
            self.monitor.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
        if self.monitor:
            self.monitor.stop()
        if self.worker:
            self.worker.join(timeout=3)

    def system(self):
        return {"snapshot":self.store.snapshot(demo=self.demo),"jobs":self.store.jobs(),
            "model":self.model_status(),
            "monitoring":{"stats":self.store.monitor_store.stats(),"collect":self.collect,
                "busy":bool(self.monitor and self.monitor.busy),
                "sources":[{"id":s.id,"name":s.name,"enabled":s.enabled,"category":s.category,
                            "terms_url":s.terms_url,"content_scope":s.content_scope,
                            **self.store.monitor_store.get_source_state(s.id)} for s in self.sources]},
            "sessions":self.store.sessions(),"processing":{"alive":bool(self.worker and self.worker.is_alive()),"last_error":self.last_error}}

    def event(self, ident):
        snapshot = self.store.snapshot(demo=self.demo)
        event = next((e for e in snapshot["events"] if e["id"] == ident),None)
        if not event:
            return None
        records = [self.store.evidence(i) for i in event["evidence_ids"]]
        for record in records:
            if record:
                with self.store.connection() as db:
                    numbers = [r[0] for r in db.execute("SELECT revision_number FROM revisions WHERE observation_id=? ORDER BY revision_number DESC LIMIT 30",(record["observation_id"],))]
                record["history"] = [self.store.evidence(f"obs:{record['observation_id']}:r:{n}") for n in numbers]
        fresh = self.store.snapshot(demo=self.demo)
        if any(fresh[k] != snapshot[k] for k in ("knowledge_epoch","policy_generation","mapping_version","asset_snapshot_id")):
            latest = next((e for e in fresh["events"] if e["id"]==ident),None)
            if not latest:
                return None
            refs = set(latest["evidence_ids"])
            return {**latest,"status":"dirty","facts":[],"assessments":[],"stale":True,
                "evidence":[e for e in fresh["evidence"] if e["id"] in refs],"knowledge_epoch":fresh["knowledge_epoch"],
                "warnings":["详情读取期间证据发生变化，请刷新查看当前结论。"]}
        return {**event,"evidence":[e for e in records if e],"knowledge_epoch":snapshot["knowledge_epoch"],"as_of":snapshot["as_of"]}

    def import_assets(self, rows):
        result = self.store.import_assets(rows)
        self.wake_event.set()
        return result

    def import_sbom(self, document):
        from .sbom import parse_sbom_report
        report = parse_sbom_report(document)
        result = self.import_assets(report["assets"])
        return {**result,"format":report["format"],"component_count":report["component_count"],
                "warnings":report["warnings"]}

    def knowledge(self):
        from .knowledge_catalog import knowledge_catalog
        return knowledge_catalog()

    def model_status(self):
        from .model_settings import public_model
        with self._model_lock:
            return public_model(self.gateway,generation=self._model_generation,last_test=self._last_model_test)

    def configure_model(self, settings):
        if type(settings) is not dict or set(settings)-{"provider","model","api_key","reasoning_effort"} or "provider" not in settings:
            raise ValueError("Invalid model settings")
        from .model_settings import make_gateway
        with self._model_lock:
            gateway = make_gateway(**settings,existing=self.gateway)
            self.gateway = gateway
            self._model_generation += 1
            self._last_model_test = None
            return {"model":self.model_status()}

    def clear_model(self):
        return self.configure_model({"provider":"facts"})

    def test_model(self):
        from .store import utc_now
        if not self._model_test_lock.acquire(blocking=False):
            raise ValueError("A model test is already running")
        try:
            with self._model_lock:
                gateway, generation = self.gateway, self._model_generation
            started = time.monotonic()
            status = "disabled"
            if gateway and getattr(gateway,"enabled",False):
                try:
                    import json
                    bounded = gateway.with_timeout(12)
                    response = bounded.complete([
                        {"role":"system","content":"Only return the JSON object {\"ok\":true}. Do not call tools."},
                        {"role":"user","content":"JSON connection test: {\"ok\":true}"}],max_tokens=32)
                    value = json.loads(response.get("content",""))
                    status = "ok" if type(value) is dict and set(value)=={"ok"} and value["ok"] is True and not response.get("tool_calls") else "failed"
                except Exception as exc:
                    code = getattr(exc,"code",None)
                    status = {"authentication":"authentication","authentication_error":"authentication",
                        "rate_limited":"rate_limited","timeout":"timeout","unavailable":"unavailable"}.get(code,"failed")
            check = {"status":status,"at":utc_now(),"latency_ms":round((time.monotonic()-started)*1000)}
            with self._model_lock:
                if generation!=self._model_generation:
                    check = {"status":"failed","at":utc_now(),"reason":"configuration_changed"}
                else:
                    self._last_model_test = check
                return {"ok":check["status"]=="ok","last_test":check,"model":self.model_status()}
        finally:
            self._model_test_lock.release()

    def ask(self, question, session_id=None):
        from .qa import answer,host_card_catalog
        question = _text(question,"question",2000)
        session_id = session_id or uuid.uuid4().hex
        if not self.ask_lock.acquire(blocking=False):
            raise ValueError("Another question is being processed")
        try:
            started = time.monotonic()
            with self._model_lock:
                gateway, model_generation = self.gateway, self._model_generation
            baseline = detached(self.store.snapshot(demo=self.demo))
            history = detached(self.store.history(session_id))
            # Previous conclusions are context for entity selection only. Their
            # old content cannot re-enter a prompt as current factual support.
            for item in history:
                if item.get("stale") and item["role"] == "assistant":
                    item["content"] = "此前回答已失效，请重新读取当前事实。"
            reference = answer(question,detached(baseline),history=detached(history),gateway=None)
            try:
                result = answer(question,detached(baseline),history=detached(history),gateway=gateway) if gateway and (gateway.enabled or getattr(gateway,"embedding_enabled",False)) else reference
                result = detached(result)
                if not isinstance(result,dict) or len(dumps(result).encode())>1_000_000 or result.get("mode") not in {"facts","local_model","cloud_model","mock_model","degraded"}:
                    raise ValueError("Malformed answer")
                for key,maximum in (("claims",64),("citations",256),("entities",32),("warnings",128),("trace",128)):
                    if not isinstance(result.get(key),list) or len(result[key])>maximum:
                        raise ValueError("Malformed answer list")
                if any(not isinstance(w,str) or len(w)>4096 for w in result["warnings"]):
                    raise ValueError("Malformed warning")
                if any(not isinstance(c,dict) for c in result["claims"]+result["citations"]):
                    raise ValueError("Malformed claim or citation")
                if any(not isinstance(c.get("id"),str) or not isinstance(c.get("text"),str) or type(c.get("entity_id")) is not int or not isinstance(c.get("evidence_ids"),list) or any(not isinstance(i,str) for i in c["evidence_ids"]) for c in result["claims"]):
                    raise ValueError("Malformed claim identity")
                if any(not isinstance(c.get("evidence_id"),str) for c in result["citations"]):
                    raise ValueError("Malformed citation identity")
            except Exception:
                result = detached(reference)
                result["mode"] = "degraded"
                result["warnings"].append("模型结果不可用，已使用当前事实。")
            # A model may select supported cards, never introduce new prose or
            # change their meaning. Compare against host-generated facts first.
            approved = {c["id"]:digest(c) for c in reference["claims"]}
            reported = result.get("entities",[])
            permitted = [e["id"] for e in baseline["events"] if e["status"]=="ready" and e["id"] in reported]
            try:
                catalog = host_card_catalog(detached(baseline),permitted)
                fields = ("id","text","evidence_ids","entity_id","predicate","value")
                approved.update({ident:digest({k:card[k] for k in fields}) for ident,card in catalog.items()})
            except (ValueError,TypeError):
                result = detached(reference)
                result["mode"] = "degraded"
                result["warnings"].append("事实目录超出本次核验范围，已使用当前事实。")
            cards = result.get("claims",[])
            if any(c.get("id") not in approved or digest(c) != approved[c["id"]] for c in cards):
                result = reference
                result["mode"] = "degraded"
                result["warnings"].append("模型断言未通过事实卡校验，已使用当前事实。")
            if "analysis_sections" in result:
                from .grounding import validate_analysis_sections,compose_answer
                sections = validate_analysis_sections(detached(result["analysis_sections"]),detached(result["claims"]))
                if sections!=result["analysis_sections"]:
                    result["warnings"].append("部分模型分析未通过结构、引用或数值检查，已移除。")
                result["analysis_sections"] = sections
                expected_text = compose_answer(detached(result["claims"]),sections,empty_answer=reference["answer"])
            else:
                expected_text = "\n".join(c["text"] for c in result["claims"]) if result["claims"] else reference["answer"]
            if (not result["claims"] and reference["claims"]) or result.get("answer") != expected_text:
                result = reference
                result["mode"] = "degraded"
                result["warnings"].append("回答文本未通过事实卡校验。")
            # Malformed dependency declarations are a model-output failure,
            # distinct from authoritative knowledge actually changing later.
            baseline_events = {e["id"]:e for e in baseline["events"] if e["status"]=="ready"}
            entities = result.get("entities",[])
            valid_dependencies = all(type(i) is int and i in baseline_events for i in entities)
            supported = set().union(*(set(baseline_events[i]["evidence_ids"]) for i in entities)) if valid_dependencies and entities else set()
            claim_ids = {i for c in result["claims"] for i in c.get("evidence_ids",[])}
            citation_ids = {c.get("evidence_id") for c in result["citations"]}
            if not valid_dependencies or any(c.get("entity_id") not in entities for c in result["claims"]) or not claim_ids.issubset(citation_ids) or not citation_ids.issubset(supported):
                result = detached(reference)
                result["mode"] = "degraded"
                result["warnings"].append("模型引用或依赖声明不完整，已使用当前事实。")
            result["latency_ms"] = round((time.monotonic()-started)*1000)
            try:
                with self._model_lock:
                    if model_generation!=self._model_generation:
                        raise StaleResult("Model configuration changed during answering")
                    return self.store.save_answer(question,result,baseline,session_id)
            except StaleResult:
                current = self.store.snapshot(demo=self.demo)
                return {"answer":"回答期间情报、清单或模型设置发生变化，旧结论未发布。请待处理完成后重问。",
                    "claims":[],"citations":[],"entities":[],"mode":"pending","warnings":["当前证据已变化"],"trace":[],
                    "knowledge_epoch":current["knowledge_epoch"],"as_of":current["as_of"],"session_id":session_id,
                    "latency_ms":round((time.monotonic()-started)*1000)}
            except (ValueError,TypeError):
                safe = detached(reference)
                safe["mode"] = "degraded"
                safe["warnings"].append("模型结果未通过提交检查，已使用当前事实。")
                safe["latency_ms"] = round((time.monotonic()-started)*1000)
                # This call still applies the same current-snapshot transaction
                # gate; a concurrent change must never bypass it through fallback.
                with self._model_lock:
                    if model_generation!=self._model_generation:
                        raise StaleResult("Model configuration changed during fallback")
                    return self.store.save_answer(question,safe,baseline,session_id)
        finally:
            self.ask_lock.release()

    def collect_now(self):
        if not self.collect or not self.monitor:
            return {"queued":False}
        return {"queued":self.monitor.trigger()}

    def withdraw_demo(self):
        if not self.demo:
            raise ValueError("Demo mutation is unavailable")
        from .demo import withdraw_demo
        updated = withdraw_demo(self.store.monitor_store)
        self.wake_event.set()
        return {"updated":updated,"knowledge_epoch":self.store.snapshot(demo=True)["knowledge_epoch"]}
