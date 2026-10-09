"""Official, manually verified knowledge metadata; retrieval never uses the network.

The public item keys match ``docs/implementation-v2-contract.md``. This catalog
does not supply monitor observations, current legal advice, full-text documents,
or an automatic change/withdrawal detector. ``updated_at`` records an explicitly
reported source-page update date where available, otherwise the edition's
publication date. Verification dates and the exact date basis are in coverage.

Metadata/abstract pages and source usage notices were checked on 2026-10-04.
No linked PDFs were downloaded. Summaries below are independently written.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re
from typing import Any

from aicti_monitor.models import Record


_NIST_USAGE = (
    "仅收录出版元数据、独立撰写的简述与官方链接。NIST 说明：除标记为受版权保护的材料外，"
    "站点信息可复制或分发，并请求保留适当署名；单项材料可能另有条件，第三方材料不能据此"
    "视为获准再分发。条件出处：https://www.nist.gov/copyrights-disclaimers"
)
_EU_USAGE = (
    "仅收录原始法规的元数据、独立撰写的简述与官方链接。EUR-Lex 元数据使用 CC0；"
    "法律文书除另有说明外可用于商业或非商业目的。编辑内容、法规摘要与合并文本适用"
    "CC BY 4.0，须署名并说明修改；第三方内容及标识等有例外。"
    "条件出处：https://eur-lex.europa.eu/content/legal-notice/legal-notice.html"
)

_ITEMS: tuple[dict[str, Any], ...] = (
    {
        "id": "nist-fips-203",
        "title": "NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard",
        "kind": "standard",
        "source": "NIST Computer Security Resource Center (CSRC)",
        "url": "https://csrc.nist.gov/pubs/fips/203/final",
        "updated_at": "2024-08-13",
        "summary": (
            "2024-08-13 发布的联邦信息处理标准，规定 ML-KEM 密钥封装机制。它属于通用"
            "密码基础设施标准，可作为 AI 基础设施通信安全的背景知识，并非 AI 专属标准。"
            "官方页面 2025-11-17 规划说明指出存在将在未来更新或修订中纠正的问题；本目录"
            "未读取勘误表，updated_at 表示此公布版本的日期，不代表问题已修复或新版已发布。"
        ),
        "topics": ["技术标准", "密码基础设施", "后量子密码", "ML-KEM", "AI 基础设施背景"],
        "attribution": "NIST (2024), FIPS 203, DOI: 10.6028/NIST.FIPS.203.",
        "usage_conditions": _NIST_USAGE,
        "monitoring": "curated",
    },
    {
        "id": "nist-ai-100-1",
        "title": "NIST AI 100-1 — Artificial Intelligence Risk Management Framework (AI RMF 1.0)",
        "kind": "guide",
        "source": "National Institute of Standards and Technology (NIST)",
        "url": "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10",
        "updated_at": "2023-01-26",
        "summary": (
            "AI RMF 1.0 是面向 AI 设计、开发、部署和使用的自愿风险管理框架，适用于不同"
            "行业与用途。此条目收录 2023 年版本的出版元数据；NIST 已说明正在修订该框架，"
            "本目录不自动追踪修订，也不表示认证或合规证明。"
        ),
        "topics": ["人工智能", "风险管理", "可信 AI", "治理"],
        "attribution": "Elham Tabassi; NIST (2023), NIST AI 100-1, DOI: 10.6028/NIST.AI.100-1.",
        "usage_conditions": _NIST_USAGE,
        "monitoring": "curated",
    },
    {
        "id": "nist-sp-800-218a",
        "title": "NIST SP 800-218A — Secure Software Development Practices for Generative AI and Dual-Use Foundation Models: An SSDF Community Profile",
        "kind": "guide",
        "source": "NIST Computer Security Resource Center (CSRC)",
        "url": "https://csrc.nist.gov/pubs/sp/800/218/a/final",
        "updated_at": "2024-07-26",
        "summary": (
            "面向生成式 AI 与两用基础模型的安全软件开发指南，为 SSDF 1.1 补充 AI 模型"
            "开发生命周期相关实践。该社区配置文件应与 SP 800-218 配合使用；条目对应"
            "2024-07-26 发布的最终版本，不表示组织已满足安全要求。"
        ),
        "topics": ["生成式 AI", "安全软件开发", "SSDF", "供应链", "基础模型"],
        "attribution": (
            "Harold Booth, Murugiah Souppaya, Apostol Vassilev, Michael Ogata, Martin Stanley, "
            "Karen Scarfone; NIST (2024), SP 800-218A, DOI: 10.6028/NIST.SP.800-218A."
        ),
        "usage_conditions": _NIST_USAGE,
        "monitoring": "curated",
    },
    {
        "id": "nist-ai-600-1",
        "title": "NIST AI 600-1 — Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile",
        "kind": "guide",
        "source": "National Institute of Standards and Technology (NIST)",
        "url": "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence",
        "updated_at": "2026-04-08",
        "summary": (
            "AI RMF 1.0 的跨行业生成式 AI 配套风险管理指南，出版于 2024-07-26。"
            "updated_at 取官方出版介绍页标示的 2026-04-08 页面更新日期，不能据此认定"
            "文档已发布新版；本目录只维护元数据。"
        ),
        "topics": ["生成式 AI", "风险管理", "AI 生命周期", "可信 AI"],
        "attribution": (
            "Chloe Autio, Reva Schwartz, Jesse Dunietz, Shomik Jain, Martin Stanley, Elham Tabassi, "
            "Patrick Hall, Kamie Roberts; NIST (2024), AI 600-1, DOI: 10.6028/NIST.AI.600-1."
        ),
        "usage_conditions": _NIST_USAGE,
        "monitoring": "curated",
    },
    {
        "id": "eu-reg-2024-1689-original",
        "title": "Regulation (EU) 2024/1689 — Artificial Intelligence Act（2024 年原始公布版本）",
        "kind": "policy",
        "source": "European Parliament and Council of the European Union / EUR-Lex",
        "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng",
        "updated_at": "2024-07-12",
        "summary": (
            "欧洲议会与理事会于 2024-06-13 通过、2024-07-12 在官方公报公布的 AI 法规，"
            "采用基于风险的监管框架。此处明确收录原始公布版本；后续修订、勘误、合并文本"
            "及当前适用时间表未由本目录自动监测，不能直接用作现行合规判断。"
        ),
        "topics": ["人工智能", "欧盟", "法规", "风险治理", "通用 AI"],
        "attribution": "European Union (2024), Regulation (EU) 2024/1689, OJ L, 12 July 2024; CELEX: 32024R1689.",
        "usage_conditions": _EU_USAGE,
        "monitoring": "curated",
    },
)

_COVERAGE: dict[str, Any] = {
    "mode": "curated_official_metadata",
    "verified_on": "2026-10-04",
    "curated_count": len(_ITEMS),
    "feed_count": 0,
    "continuous_monitoring": False,
    "pdf_downloaded": False,
    "scope": "官方指南与原始法规版本的人工核验元数据；不包含全文或实时修订监测。",
    "updated_at_semantics": (
        "优先采用来源明确报告的介绍页更新日期，否则采用所列文档版本的公开发布日期；"
        "与 verified_on 核验日期分别记录。页面更新不等于文档版本更新。"
    ),
    "gaps": [
        "本目录没有持续 feed 观察，不承诺最新修订或撤回已被发现。",
        "NIST AI RMF、AI 600-1 与 SP 800-218A 归类为指南，不计为强制技术标准。",
        "FIPS 203 是通用密码基础设施标准，不是 AI 专属标准；其规划说明和未来修订仍需核实。",
        "欧盟条目为 2024 年原始法规元数据，不是现行合并文本或个案法律意见。",
    ],
    "verification": [
        {
            "id": "nist-fips-203",
            "method": "official_metadata_page",
            "publication_date": "2024-08-13",
            "source_planning_note_date": "2025-11-17",
            "updated_at_basis": "final_publication_history_date",
            "supporting_urls": ["https://csrc.nist.gov/pubs/fips/203/final"],
            "notes": "官方页及 Document History 确认最终公布日期；规划说明报告未来拟纠正问题，未下载标准 PDF 或勘误表。",
        },
        {
            "id": "nist-ai-100-1",
            "method": "official_metadata_page",
            "publication_date": "2023-01-26",
            "updated_at_basis": "publication_date",
            "supporting_urls": [
                "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10",
                "https://www.nist.gov/itl/ai-risk-management-framework",
            ],
            "notes": "官方页面列出版日期、作者及编号；AI RMF 项目页说明 1.0 正在修订。",
        },
        {
            "id": "nist-sp-800-218a",
            "method": "official_metadata_page",
            "publication_date": "2024-07-26",
            "updated_at_basis": "final_publication_history_date",
            "supporting_urls": ["https://csrc.nist.gov/pubs/sp/800/218/a/final"],
            "notes": "页首出版日期为 July 2024，Document History 明列 07/26/24 Final。",
        },
        {
            "id": "nist-ai-600-1",
            "method": "official_metadata_page",
            "publication_date": "2024-07-26",
            "source_page_updated_at": "2026-04-08",
            "updated_at_basis": "source_page_updated_at",
            "supporting_urls": [
                "https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence"
            ],
            "notes": "介绍页分别列 Published July 26, 2024 与 Updated April 8, 2026。",
        },
        {
            "id": "eu-reg-2024-1689-original",
            "method": "official_indexed_metadata_and_commission_page",
            "publication_date": "2024-07-12",
            "adoption_date": "2024-06-13",
            "updated_at_basis": "original_official_journal_publication_date",
            "direct_document_fetch": "robot_verification_required_not_bypassed",
            "supporting_urls": [
                "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689",
                "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
                "https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-108",
            ],
            "notes": (
                "官方 EUR-Lex 索引元数据与欧盟委员会 AI Act 页面核验身份；"
                "官方 AI Act Service Desk 第 108 条脚注明列通过日期与公报日期。"
                "直接访问原文出现机器人验证，未绕过，也未核验完整现行合并文本。"
            ),
        },
    ],
    "usage_notice_urls": [
        "https://www.nist.gov/copyrights-disclaimers",
        "https://eur-lex.europa.eu/content/legal-notice/legal-notice.html",
    ],
}


def knowledge_catalog() -> dict[str, Any]:
    """Return a detached JSON-compatible metadata snapshot for GET /api/knowledge.

    Reading this catalog performs no outbound fetch and never promotes curated
    entries to feed observations. Caller mutation cannot alter future snapshots.
    """
    return {"items": deepcopy(list(_ITEMS)), "coverage": deepcopy(_COVERAGE)}


def get_catalog() -> dict[str, Any]:
    """Compatibility spelling for the same detached catalog snapshot."""
    return knowledge_catalog()


def catalog_items() -> list[dict[str, Any]]:
    """Frozen integration entry point: detached official curated item list."""
    return deepcopy(list(_ITEMS))


def catalog_records(*, collected_at: str | None = None,
                    source_id: str = "official-knowledge-curated") -> list[Record]:
    """Project curated metadata for explicit host-owned live-library ingestion.

    These are clearly curated observations, never automatic feed results. The
    host must keep them out of demo databases and generate source-metadata fact
    cards separately. A guide maps to Record.kind=article because the monitor
    enum has no guide; metadata.knowledge_kind preserves the accurate class.
    """
    if not isinstance(source_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", source_id):
        raise ValueError("Invalid curated catalog source identity")
    if collected_at is None:
        collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if not isinstance(collected_at, str) or len(collected_at) > 64:
        raise ValueError("Invalid curated catalog collection time")
    try:
        instant = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        if instant.tzinfo is None:
            raise ValueError()
        collected_at = instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise ValueError("Invalid curated catalog collection time") from None
    return [Record(
        source_id=source_id, upstream_id=item["id"],
        kind="article" if item["kind"] == "guide" else item["kind"],
        title=item["title"], summary=item["summary"], url=item["url"],
        # The source supplies calendar dates, not UTC instants. Keep those
        # dates in metadata rather than inventing midnight publication times.
        published_at=None, updated_at=None,
        metadata={
            "source_name": item["source"], "knowledge_kind": item["kind"],
            "monitoring": "curated", "collected_at": collected_at,
            "curated_verified_on": _COVERAGE["verified_on"],
            "attribution": item["attribution"], "usage_conditions": item["usage_conditions"],
            "terms_url": "https://eur-lex.europa.eu/content/legal-notice/legal-notice.html" if item["kind"] == "policy" else "https://www.nist.gov/copyrights-disclaimers",
            "content_scope": "metadata_only", "fulltext_fetched": False,
            "summary_origin": "independently_written_curated_metadata_summary",
            "upstream_revision": item["updated_at"],
            "source_publication_date": next(v["publication_date"] for v in _COVERAGE["verification"] if v["id"] == item["id"]),
            "source_updated_date": item["updated_at"],
            "timestamp_precision": "source_dates_only; UTC_instant_unknown",
            "topics": deepcopy(item["topics"]),
        },
    ) for item in catalog_items()]


__all__ = ["catalog_items", "catalog_records", "knowledge_catalog", "get_catalog"]
