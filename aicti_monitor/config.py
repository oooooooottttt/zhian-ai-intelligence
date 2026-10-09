from __future__ import annotations

import json
import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .models import SourceConfig

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "sources.json"
ADAPTERS = {"nvd", "github_advisories", "github_repository", "arxiv", "rss", "nist_feeds"}
CATEGORIES = {"vulnerability_database", "vendor_advisory", "research_paper",
              "security_blog", "security_community", "standard", "policy"}


def _safe_config_url(value):
    if not isinstance(value, str) or any(ord(c) < 33 for c in value) or "\\" in value:
        raise ValueError("配置链接无效")
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.port not in (None, 443) or parts.fragment):
        raise ValueError("配置链接必须是无凭据的 HTTPS URL")
    host = parts.hostname
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("配置链接不能指向私网")
    try:
        if not ipaddress.ip_address(host).is_global:
            raise ValueError("配置链接不能指向私网")
    except ValueError as exc:
        if re.fullmatch(r"[0-9.:]+", host):
            raise ValueError("配置链接不能指向私网") from exc
    if any(re.search(r"token|password|passwd|secret|api.?key|authorization|credential", key, re.I)
           for key, _ in parse_qsl(parts.query, keep_blank_values=True)):
        raise ValueError("配置链接不能携带凭据")
    return parts


def _no_credentials(value):
    if isinstance(value, dict):
        for k, v in value.items():
            if re.search(r"token|password|passwd|secret|api.?key|authorization|credential", k, re.I):
                raise ValueError("凭据只能通过环境变量提供")
            _no_credentials(v)
    elif isinstance(value, list):
        for v in value:
            _no_credentials(v)


def load_sources(path: str | Path = DEFAULT_CONFIG) -> list[SourceConfig]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("sources"), list):
        raise ValueError("配置必须包含 sources 数组")
    sources = []
    seen = set()
    for item in raw["sources"]:
        if not isinstance(item, dict):
            raise ValueError("数据源配置必须是对象")
        values = dict(item)
        hosts = values.get("allowed_hosts")
        if not isinstance(hosts, list) or not hosts or any(not isinstance(h, str) or not re.fullmatch(r"[a-z0-9.-]+", h) for h in hosts):
            raise ValueError("allowed_hosts 必须是明确的域名列表")
        values["allowed_hosts"] = tuple(hosts)
        source = SourceConfig(**values)
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", source.id) or source.id in seen:
            raise ValueError("数据源 ID 无效或重复")
        seen.add(source.id)
        if source.adapter not in ADAPTERS or source.category not in CATEGORIES:
            raise ValueError(f"{source.id}: 适配器或来源类型无效")
        if source.content_scope not in {"metadata_only", "public_advisory", "feed_excerpt"}:
            raise ValueError(f"{source.id}: 内容使用范围无效")
        if type(source.enabled) is not bool or not isinstance(source.params, dict):
            raise ValueError(f"{source.id}: enabled / params 类型无效")
        if type(source.interval_seconds) is not int or not 60 <= source.interval_seconds <= 604800:
            raise ValueError(f"{source.id}: 轮询间隔应在一分钟至七天之间")
        if type(source.min_request_interval_seconds) not in (int, float) or not math.isfinite(source.min_request_interval_seconds) or not 0 <= source.min_request_interval_seconds <= 60:
            raise ValueError(f"{source.id}: 请求间隔无效")
        parts = _safe_config_url(source.endpoint)
        if (parts.scheme != "https" or parts.username or parts.password
                or parts.port not in (None, 443)
                or parts.hostname not in source.allowed_hosts):
            raise ValueError(f"{source.id}: 必须使用白名单 HTTPS 接口")
        if not source.terms_url:
            raise ValueError(f"{source.id}: 缺少来源使用条件链接")
        _safe_config_url(source.terms_url)
        _no_credentials(source.params)
        if {"initial_days", "overlap_minutes"} & source.params.keys():
            raise ValueError(f"{source.id}: 使用适配器约定的回溯和重叠参数")
        if source.enabled and source.params.get("policy_status") != "reviewed":
            raise ValueError(f"{source.id}: 未复核的来源不能启用")
        sources.append(source)
    return sources
