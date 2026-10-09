"""Clearly fictional, offline, idempotent demo; never a real vulnerability claim."""
from dataclasses import replace
from aicti_monitor.models import Record
from .store import utc_now

SOURCE_IDS = ["demo-advisory","demo-research","demo-policy"]
ALIAS = "CVE-2099-99001"

def advisory(*, withdrawn=False):
    return Record(source_id="demo-advisory",upstream_id=ALIAS,kind="vulnerability",
        title="【虚构演示】vLLM 示例服务的反序列化风险",summary="仅用于演示情报更新和清单匹配；版本、编号和漏洞均为虚构。",
        url="https://example.com/demo/advisory",aliases=[ALIAS],components=["vllm"],
        metadata={"demo":True,"status":"withdrawn" if withdrawn else "published","withdrawn":withdrawn,
            "packages":[{"ecosystem":"pip","name":"vllm","vulnerable_version_range":">= 99.0.0, < 99.2.0","patched_versions":"99.2.0"}],
            "cvss":[{"version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":9.8}],
            "cwes":[{"cwe_id":"CWE-502","name":"Deserialization of Untrusted Data"}],
            "conditions":{"exposed":True,"authenticated":False},
            "impact":"虚构演示：处理不可信输入存在执行风险；没有证明任一资产已入侵。",
            "usage_conditions":{"scope":"fictional metadata only","attribution":"AICTI demo"}})

def seed_demo(store):
    # A withdrawn demo remains withdrawn on restart; restarting cannot resurrect it.
    with store._connection() as db:
        exists = db.execute("SELECT 1 FROM observations WHERE source_id='demo-advisory'").fetchone()
    if exists:
        return False
    records = [advisory(),
        Record("demo-research","demo-paper-1","paper","【虚构演示】大模型服务的反序列化防御研究",
               f"讨论 {ALIAS} 的演示案例；不是已发表论文。", "https://example.com/demo/research",
               components=["vllm"],metadata={"demo":True,"defect_ids":[ALIAS],"usage_conditions":{"scope":"fictional metadata only"}}),
        Record("demo-policy","demo-guide-1","article","【虚构演示】RAG 提示注入防护指南",
               "外部文档提示注入的示例防护流程，不属于任何已发布标准。","https://example.com/demo/guide",
               components=["rag"],metadata={"demo":True,"risk_patterns":[{"type":"prompt_injection","capabilities":["external_documents","rag"],"prevention":"将文档作为数据；工具最小权限；引用核验。","correction":"撤销受污染内容，重建索引并重新评估。"}],"usage_conditions":{"scope":"fictional metadata only"}})]
    for record in records:
        at = utc_now()
        run = store.begin_run(record.source_id,at)
        store.ingest_and_finish(run,record.source_id,[record],{"demo_seed":1},at,at,True)
    return True

def default_assets():
    return [{"asset_id":"demo-inference","name":"演示推理服务","ecosystem":"pip","component":"vllm","version":"99.1.0",
             "exposed":True,"authenticated":False,"observed_at":utc_now(),
             "capabilities":{"external_documents":True,"rag":True,"tools":False,"network":False,"write_access":False}},
            {"asset_id":"demo-patched","name":"演示修补服务","ecosystem":"pip","component":"vllm","version":"99.2.0",
             "exposed":False,"authenticated":True,"observed_at":utc_now(),"capabilities":{}}]

def withdraw_demo(store):
    at = utc_now()
    current = advisory(withdrawn=True)
    current.updated_at = at
    run = store.begin_run(current.source_id,at)
    counts = store.ingest_and_finish(run,current.source_id,[current],{"demo_seed":1,"withdrawn":True},at,at,True)
    return bool(counts["updated"])

def replay_demo(store):
    """Explicit replay adds a new fictional source revision, preserving history."""
    at = utc_now()
    record = advisory()
    record.updated_at = at
    run = store.begin_run(record.source_id,at)
    return store.ingest_and_finish(run,record.source_id,[record],{"demo_seed":1,"replayed_at":at},at,at,True)
