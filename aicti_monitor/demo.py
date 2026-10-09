"""Explicitly fictional, offline examples in a separate database."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .models import Record
from .runner import iso


def seed_demo(store):
    if store.stats()["total_records"]:
        return False
    at = datetime(2026, 9, 30, 0, 0, tzinfo=timezone.utc)
    shared = {"demo": True, "trust": "untrusted_external_data", "attribution": "虚构演示数据",
              "license": "Local fictional demonstration", "content_scope": "metadata_only"}
    records = [
        Record("demo-vendor", "example-vllm-1", "vulnerability", "[演示] vLLM 服务公告：访问权限配置问题",
               "虚构示例，用于展示公告被更新及证据修订。不能用于判断任何真实版本是否有漏洞。",
               "https://github.com/vllm-project/vllm/security", iso(at), iso(at),
               components=["vllm"], metadata={**shared, "source_name": "演示厂商公告", "upstream_revision": "example-1"}),
        Record("demo-paper", "example-paper-1", "paper", "[演示] LLM agent prompt injection 防御研究",
               "虚构论文条目，用于展示论文元数据、来源链接及采集时间。", "https://arxiv.org/",
               iso(at), iso(at), metadata={**shared, "source_name": "演示学术订阅"}),
        Record("demo-community", "example-guide-1", "article", "[演示] 模型供应链安全监测指南",
               "虚构订阅条目：来源明确授权后，按许可范围采集摘要。", "https://genai.owasp.org/",
               iso(at), iso(at), metadata={**shared, "source_name": "演示社区订阅"}),
    ]
    for record in records:
        run = store.begin_run(record.source_id, iso(at))
        store.ingest_and_finish(run, record.source_id, [record], {"example": 1}, iso(at), iso(at + timedelta(hours=1)), True)
    updated = replace(records[0], summary="[虚构更新] 厂商发布了配置修正建议。原始版本保留在修订历史中。",
                      updated_at=iso(at + timedelta(hours=1)),
                      metadata={**records[0].metadata, "upstream_revision": "example-2"})
    run = store.begin_run(updated.source_id, iso(at + timedelta(hours=1)))
    store.ingest_and_finish(run, updated.source_id, [updated], {"example": 2}, iso(at + timedelta(hours=1)),
                            iso(at + timedelta(hours=2)), True)
    return True
