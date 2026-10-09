"""Credential-free deterministic model simulator for the actual QA protocol.

No network, environment, database or source access occurs here. The mock consumes
the same bounded anonymous question/catalog/tool transcript as DeepSeek. It
demonstrates orchestration and schema/grounding behavior, not semantic quality.
The normal flow must read host tool feedback before emitting referenced advice.
Fault scenarios let offline tests exercise the actual safety/fallback path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import threading

from .gateway import ModelError, ModelUnavailable, _encode, _json_shape, _tools
from .cloud_gateway import _messages as _protocol_messages

_SCENARIOS = frozenset({"normal", "invalid_json", "schema_violation", "unsafe_tool",
                        "invalid_arguments", "invented_analysis", "no_progress", "rate_limited", "timeout"})


@dataclass
class _MockState:
    lock: object = field(default_factory=threading.RLock)
    calls: int = 0


class MockGateway:
    provider = "mock"
    model = "mock-deepseek-v4-pro"
    enabled = True
    configured = True
    credential_configured = False
    embedding_enabled = False
    embedding_model = None
    supports_json_output = True
    reasoning_effort = "none"
    endpoint = "offline://mock"
    base_url = "offline://mock"
    __slots__ = ("_timeout", "_scenario", "_state")

    def __init__(self, *, timeout=20.0, scenario="normal"):
        if type(timeout) not in (float, int) or not math.isfinite(timeout) or not 0 < timeout <= 30 or type(scenario) is not str or scenario not in _SCENARIOS:
            raise ModelError("invalid_configuration")
        self._timeout, self._scenario, self._state = float(timeout), scenario, _MockState()

    def __repr__(self):
        return f"MockGateway(provider='mock', model='mock-deepseek-v4-pro', scenario={self._scenario!r})"

    @property
    def timeout(self):
        return self._timeout

    @property
    def calls(self):
        with self._state.lock:
            return self._state.calls

    def with_timeout(self, timeout):
        clone = MockGateway(timeout=min(timeout, self.timeout) if type(timeout) in (int, float) else timeout,
                            scenario=self._scenario)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ModelError("invalid_configuration")
        clone._state = self._state
        return clone

    def _reply(self, data=None, *, content=None, calls=None):
        return {"content": content if content is not None else json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                "tool_calls": calls or [], "provider": self.provider, "model": self.model}

    def complete(self, messages, *, tools=None, max_tokens=800, response_format=None):
        _json_shape(messages, code="invalid_input")
        if type(messages) is not list or not 1 <= len(messages) <= 64 or type(max_tokens) is not int or not 1 <= max_tokens <= 2048:
            raise ModelError("invalid_input")
        for message in messages:
            if type(message) is not dict or message.get("role") not in {"system", "user", "assistant", "tool"} or type(message.get("content")) is not str:
                raise ModelError("invalid_input")
        _protocol_messages(messages, thinking=False)
        if response_format is not None and (type(response_format) is not dict or response_format != {"type": "json_object"}):
            raise ModelError("invalid_input")
        tool_list = _tools(tools) or []
        _encode({"messages": messages, "tools": tool_list})
        with self._state.lock:
            self._state.calls += 1
        if self._scenario == "rate_limited":
            raise ModelUnavailable("rate_limited", retry_after=5)
        if self._scenario == "timeout":
            raise ModelUnavailable("timeout")
        user = next((row["content"] for row in reversed(messages) if row["role"] == "user"), "")
        try:
            payload = json.loads(user)
        except (ValueError, TypeError):
            payload = None
        if payload == {"ok": True} or ("ok" in user and "true" in user and not (type(payload) is dict and ("current_catalog" in payload or "card_catalog" in payload))):
            return self._reply({"ok": True})
        if type(payload) is not dict or not ("current_catalog" in payload or "card_catalog" in payload):
            return self._reply(content="离线模拟连接检查通过；未调用外部模型。")
        if "current_catalog" in payload:
            return self._plan(payload)
        return self._synthesize(payload, messages, tool_list)

    def _plan(self, payload):
        catalog = payload.get("current_catalog", [])
        if type(catalog) is not list or len(catalog) > 32 or any(type(row) is not dict or type(row.get("event_id")) is not str for row in catalog):
            raise ModelError("invalid_input")
        question = str(payload.get("question_data", "")).casefold()
        # Deliberately fixed demonstration rules; QA labels this mock_plan.
        related = any(term in question for term in ("关联", "关系", "论文", "文章", "攻击链", "跨文档"))
        comparison = related or any(term in question for term in ("比较", "共同", "差异", "分别"))
        intents = []
        if any(term in question for term in ("修复", "升级", "补丁", "处置", "处理", "应对", "怎么办", "收紧", "稳妥")):
            intents = ["fix", "condition", "affected_range"]
        if related:
            intents.append("related_material")
        if any(term in question for term in ("rmf", "标准", "政策", "论文", "指南", "是什么", "讲什么", "摘要")):
            intents.append("source_metadata")
        asset_intent = any(term in question for term in ("资产", "清单", "部署", "服务器", "a000", "a001"))
        count = any(term in question for term in ("多少", "数量", "几台", "几个"))
        events = [row["event_id"] for row in catalog[:2 if comparison else 1]]
        return self._reply({"event_ids": events, "intents": intents, "asset_intent": asset_intent,
                            "relation_depth": 3 if related else 0, "count_assets": count})

    def _synthesize(self, payload, messages, tools):
        events, catalog = payload.get("event_ids"), payload.get("card_catalog")
        if type(events) is not list or type(catalog) is not list or not events or not catalog:
            return self._reply({"claim_ids": [], "analysis_sections": []})
        names = {row["function"]["name"] for row in tools}
        feedback = [row for row in messages if row["role"] == "tool"]
        if not feedback:
            name = "execute" if self._scenario == "unsafe_tool" else "read_facts"
            args = {"event_id": "E99999"} if self._scenario == "invalid_arguments" else {"event_id": events[0]}
            if name not in names and name != "execute":
                raise ModelError("invalid_input")
            calls = [{"id": "mock_facts_1", "name": name, "arguments": args}]
            if self._scenario == "normal":
                calls.extend({"id": f"mock_facts_{n}", "name": "read_facts", "arguments": {"event_id": event_id}}
                             for n, event_id in enumerate(events[1:2], 2))
            if "relations" in names and self._scenario == "normal":
                calls.append({"id": "mock_relations_1", "name": "relations", "arguments": {"event_id": events[0], "depth": 1}})
            return self._reply(content="", calls=calls)
        if self._scenario == "invalid_json":
            return self._reply(content="{invalid simulated output")
        if self._scenario == "schema_violation":
            return self._reply({"claim_ids": [catalog[0]["id"]], "analysis_sections": [], "answer": "extra unsupported prose"})
        if self._scenario == "no_progress":
            return self._reply(content="", calls=[{"id": f"mock_repeat_{len(feedback)}", "name": "read_facts", "arguments": {"event_id": events[0]}}])
        readable = {}
        for row in feedback:
            try:
                output = json.loads(row["content"])
                if output.get("ok") is True and type(output.get("data")) is dict:
                    for card in output["data"].get("cards", []):
                        readable[card["id"]] = card
            except (ValueError, TypeError, KeyError):
                raise ModelError("invalid_input") from None
        # The output demonstrably depends on actual host read_facts feedback.
        available = [row for row in catalog if row.get("id") in readable]
        question = str(payload.get("question_data", "")).casefold()
        asset_question = any(term in question for term in ("资产", "清单", "服务器", "部署", "a000", "a001"))
        priorities = (["asset_assessment", "fix", "condition", "affected_range", "affected_component"] if asset_question
                      else ["source_metadata", "fix", "affected_component", "related_material", "condition", "affected_range"])
        available.sort(key=lambda row: priorities.index(row["predicate"]) if row["predicate"] in priorities else len(priorities))
        chosen = []
        for event_id in events[:2]:
            chosen.extend([row for row in available if row.get("event_id") == event_id][:4 if len(events) == 1 else 2])
        if not chosen:
            return self._reply({"claim_ids": [], "analysis_sections": []})
        ids = [row["id"] for row in chosen]
        refs = sorted({ref for row in chosen for ref in row["evidence_ids"]})
        kind = "recommendation" if any(row["predicate"] == "fix" for row in chosen) else "analysis"
        text = ("建议先核对相关组件和部署条件，再依据当前修复卡安排人工处置，并验证处置效果。" if kind == "recommendation"
                else "这些记录可以作为核对相关组件和适用条件的依据；具体处置仍需结合部署情况判断。")
        if self._scenario == "invented_analysis":
            text = "已确认成功利用，建议升级到9.9.9且评分为10.0。"
        sections = [{"kind": kind, "text": text, "claim_ids": ids, "evidence_ids": refs},
                    {"kind": "uncertainty", "text": "当前证据不能确认已被入侵，也不能证明已被利用。",
                     "claim_ids": ids, "evidence_ids": refs}]
        return self._reply({"claim_ids": ids, "analysis_sections": sections})
