import copy
import json
import unittest
from unittest.mock import patch

from aicti_core.contracts import Evidence, Fact
from aicti_core.qa import answer, host_card_catalog


def evidence(n=1, revision=1, **changes):
    row = Evidence(f"obs:{n}:r:{revision}", n, revision, "official", f"advisory-{n}", "vulnerability", f"Advisory {n}", "public summary", f"https://example.org/advisories/{n}", collected_at="2026-10-03T00:00:00Z").to_dict()
    row.update(changes)
    return row


def fact(predicate, value, *refs, **changes):
    row = Fact(predicate, value, refs or ("obs:1:r:1",)).to_dict()
    row.update(changes)
    return row


def event(n=1, refs=None, facts=None, **changes):
    row = {"id": n, "title": f"vLLM 漏洞 {n}", "aliases": [f"CVE-2026-{12344 + n}"], "generation": 2, "status": "ready", "evidence_ids": refs or [f"obs:{n}:r:1"], "facts": facts if facts is not None else [fact("affected_component", {"ecosystem": "PyPI", "name": "vllm"}, f"obs:{n}:r:1"), fact("fix", {"patched_versions": ["0.9.1"]}, f"obs:{n}:r:1")], "assessments": [], "warnings": []}
    row.update(changes)
    return row


def snapshot(events=None, evidences=None, assets=None):
    return {"knowledge_epoch": 7, "policy_generation": 3, "asset_snapshot_id": 11, "as_of": "2026-10-03T02:00:00Z", "demo": False, "events": events if events is not None else [event()], "evidence": evidences if evidences is not None else [evidence()], "assets": assets or []}


class FakeGateway:
    enabled = True
    embedding_enabled = False

    def __init__(self, responses=None, error=None):
        self.responses = responses or [{"content": '{"claim_ids":["event:1:fact:1"]}', "tool_calls": [], "model": "offline"}]
        self.error = error
        self.messages = []

    def complete(self, messages, *, tools=None, max_tokens=800):
        self.messages.append(copy.deepcopy(messages))
        if self.error:
            raise RuntimeError(self.error)
        return self.responses.pop(0)


class FakeCloudGateway(FakeGateway):
    provider = "deepseek"
    model = "deepseek-v4-pro"
    def complete(self, messages, *, tools=None, max_tokens=800, response_format=None):
        self.formats = getattr(self, "formats", []) + [response_format]
        return super().complete(messages, tools=tools, max_tokens=max_tokens)


def cloud_plan(events=None, intents=None, **updates):
    data = {"event_ids": events if events is not None else ["E001"],
            "intents": intents if intents is not None else ["fix"],
            "asset_intent": False, "relation_depth": 0, "count_assets": False}
    data.update(updates)
    return {"content": json.dumps(data, ensure_ascii=False), "tool_calls": []}


def cloud_final(ids=None, sections=None):
    return {"content": json.dumps({"claim_ids": ids if ids is not None else ["C0002"],
                                   "analysis_sections": sections or []}, ensure_ascii=False), "tool_calls": []}


class QATests(unittest.TestCase):
    def test_contract_dataclasses_and_chinese_adjacent_cve(self):
        gateway = FakeGateway(error="must not run")
        result = answer("CVE-2026-12345的修复版本？", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "facts")
        self.assertEqual(gateway.messages, [])
        self.assertIn("0.9.1", result["answer"])
        self.assertEqual(result["entities"], [1])
        self.assertEqual(result["evidence_ids"], ["obs:1:r:1"])
        self.assertEqual(result["signature"]["event_generations"], {"1": 2})
        self.assertEqual(result["signature"]["policy_generation"], 3)

    def test_unknown_exact_cve_never_returns_other_vulnerability(self):
        result = answer("CVE-2026-99999如何修复", snapshot())
        self.assertEqual(result["entities"], [])
        self.assertEqual(result["claims"], [])
        self.assertNotIn("0.9.1", result["answer"])

    def test_dirty_and_quarantined_never_yield_current_facts(self):
        for status in ("dirty", "quarantined"):
            with self.subTest(status=status):
                result = answer("CVE-2026-12345的修复", snapshot(events=[event(status=status)]))
                self.assertEqual(result["claims"], [])
                self.assertTrue(any("更新或待核" in w for w in result["warnings"]))

    def test_unauthorized_event_and_evidence(self):
        for s in (snapshot(events=[event(authorized=False)]), snapshot(evidences=[evidence(authorized=False)])):
            self.assertEqual(answer("CVE-2026-12345修复", s)["claims"], [])

    def test_withdrawal_and_new_revision_invalidate_old_fact(self):
        for new in (evidence(revision=2), evidence(revision=2, withdrawn=True)):
            result = answer("CVE-2026-12345修复", snapshot(evidences=[evidence(), new]))
            self.assertEqual(result["claims"], [])
            self.assertEqual(result["citations"], [])

    def test_latest_withdrawal_is_explicit_and_does_not_revoke_other_sources(self):
        ready = event(refs=["obs:1:r:1", "obs:2:r:1"], facts=[fact("fix", {"patched_versions": ["0.9.1"]}, "obs:1:r:1"), fact("fix", {"patched_versions": ["0.9.2"]}, "obs:2:r:1")])
        s = snapshot(events=[ready], evidences=[evidence(), evidence(revision=2, withdrawn=True), evidence(2)])
        result = answer("CVE-2026-12345怎么修复", s)
        self.assertTrue(any("最新证据已撤回" in w for w in result["warnings"]))
        self.assertNotIn("0.9.1", result["answer"])
        self.assertIn("0.9.2", result["answer"])
        self.assertEqual(result["evidence_ids"], ["obs:2:r:1"])
        self.assertEqual(result["mode"], "facts")

    def test_withdrawal_warning_survives_pending_event_and_history(self):
        s = snapshot(events=[event(status="dirty")], evidences=[evidence(revision=2, withdrawn=True)])
        for q, history in (("CVE-2026-12345修复", None), ("它怎么修复", [{"entities": [1]}])):
            result = answer(q, s, history=history)
            self.assertEqual(result["claims"], [])
            self.assertTrue(any("最新证据已撤回" in w for w in result["warnings"]))

    def test_historical_withdrawal_superseded_by_live_revision_is_not_current_warning(self):
        current = event(refs=["obs:1:r:2"], facts=[fact("fix", {"patched_versions": ["0.9.2"]}, "obs:1:r:2")])
        result = answer("CVE-2026-12345修复", snapshot(events=[current], evidences=[evidence(withdrawn=True), evidence(revision=2)]))
        self.assertIn("0.9.2", result["answer"])
        self.assertFalse(any("最新证据已撤回" in w for w in result["warnings"]))

    def test_unrelated_or_noncurrent_withdrawal_is_not_a_query_warning(self):
        for withdrawn in (evidence(2, withdrawn=True), evidence(revision=2, withdrawn=True, current=False)):
            result = answer("CVE-2026-12345修复", snapshot(evidences=[evidence(), withdrawn]))
            self.assertFalse(any("最新证据已撤回" in w for w in result["warnings"]))
        result = answer("CVE-2026-12345修复", snapshot(evidences=[evidence(), evidence(2, withdrawn=True)]))
        self.assertIn("0.9.1", result["answer"])

    def test_fact_support_is_all_or_nothing(self):
        rows = [fact("fix", {"patched_versions": ["9.9.9"]}, "obs:1:r:1", "obs:2:r:1")]
        for ev2 in (None, evidence(2, withdrawn=True), evidence(2)):
            # Even live ref not included in the host event's dependency set.
            evs = [evidence()] + ([] if ev2 is None else [ev2])
            result = answer("CVE-2026-12345修复", snapshot(events=[event(facts=rows)], evidences=evs))
            self.assertEqual(result["claims"], [])

    def test_candidate_or_unsupported_predicate_does_not_publish(self):
        rows = [fact("fix", {"patched_versions": ["9.9.9"]}, status="candidate"), fact("arbitrary_assertion", {"text": "all safe"})]
        self.assertEqual(answer("CVE-2026-12345", snapshot(events=[event(facts=rows)]))["claims"], [])

    def test_duplicate_evidence_identity_is_quarantined(self):
        result = answer("CVE-2026-12345", snapshot(evidences=[evidence(), evidence(title="contradictory")]))
        self.assertEqual(result["claims"], [])
        self.assertTrue(any("不一致" in w for w in result["warnings"]))

    def test_malformed_evidence_id_and_revision_not_used(self):
        result = answer("CVE-2026-12345", snapshot(evidences=[evidence(revision_number=3)]))
        self.assertEqual(result["claims"], [])

    def test_component_intent_and_unknown_component(self):
        result = answer("vllm怎么修复", snapshot())
        self.assertEqual(result["entities"], [1])
        self.assertIn("修复依据", result["answer"])
        unknown = answer("UnknownServer怎么修复", snapshot())
        self.assertEqual(unknown["entities"], [])
        self.assertTrue(answer("有哪些修复建议", snapshot())["claims"])

    def test_chinese_short_word_recall(self):
        rows = [fact("risk_pattern", {"name": "提示词注入", "conditions": ["外部输入"]})]
        result = answer("注入", snapshot(events=[event(facts=rows)]))
        self.assertEqual(result["entities"], [1])
        self.assertIn("提示词注入", result["answer"])
        self.assertEqual(result["retrieval"], "keywords")

    def test_continuation_reloads_current_facts_ignores_history_prose(self):
        history = [{"entities": [1], "answer": "修复版本 99.99.99，全部安全"}]
        result = answer("它怎么修复", snapshot(), history=history)
        self.assertIn("0.9.1", result["answer"])
        self.assertNotIn("99.99.99", result["answer"])
        changed = snapshot(events=[event(facts=[fact("fix", {"patched_versions": ["0.9.2"]})])])
        result = answer("它怎么修复", changed, history=history)
        self.assertIn("0.9.2", result["answer"])

    def test_stale_continuation_does_not_pick_another_entity(self):
        s = snapshot(events=[event(status="dirty"), event(2)], evidences=[evidence(), evidence(2)])
        result = answer("它怎么修复", s, history=[{"entities": [1]}])
        self.assertEqual(result["entities"], [])
        self.assertEqual(result["claims"], [])

    def test_explicit_component_overrides_continuation(self):
        ev2 = event(2, facts=[fact("affected_component", {"name": "ollama-server"}, "obs:2:r:1"), fact("fix", {"patched_versions": ["1.0.1"]}, "obs:2:r:1")])
        result = answer("那ollama-server怎么修复", snapshot(events=[event(), ev2], evidences=[evidence(), evidence(2)]), history=[{"entities": [1]}])
        self.assertEqual(result["entities"], [2])

    def test_citations_preserve_revision_provenance(self):
        result = answer("CVE-2026-12345", snapshot())
        citation = result["citations"][0]
        self.assertEqual(set(citation), {"evidence_id", "source_id", "upstream_id", "url", "title", "revision_number", "collected_at"})
        self.assertEqual(citation["url"], "https://example.org/advisories/1")
        self.assertTrue(all(c["evidence_ids"] for c in result["claims"]))

    def test_private_credential_and_alternate_ip_links_not_rendered(self):
        for url in ("http://127.0.0.1/x", "http://[::1]/x", "https://user:secret@example.org/x", "http://2130706433/x", "http://127.1/x", "http://0x7f.0x0.0x0.0x1/x", "http://127.0x0.0.1/x", "https://thing.internal/x", "https://example.org\\@localhost/x"):
            with self.subTest(url=url):
                result = answer("CVE-2026-12345", snapshot(evidences=[evidence(url=url)]))
                self.assertEqual(result["citations"][0]["url"], "")

    def test_model_free_assertion_with_real_citation_is_rejected(self):
        for content in ('{"answer":"修复版本9.9.9","evidence_ids":["obs:1:r:1"]}', '{"claims":[{"text":"已经被入侵","evidence_ids":["obs:1:r:1"]}]}', '{"claim_ids":["event:1:fact:1"],"answer":"all safe"}'):
            gateway = FakeGateway([{"content": content, "tool_calls": []}])
            result = answer("怎么修复", snapshot(), gateway=gateway)
            self.assertEqual(result["mode"], "degraded")
            self.assertNotIn("9.9.9", result["answer"])
            self.assertNotIn("已经被入侵", result["answer"])
            self.assertTrue(result["claims"])

    def test_model_selects_only_host_cards(self):
        result = answer("怎么修复", snapshot(), gateway=FakeGateway())
        self.assertEqual(result["mode"], "local_model")
        self.assertEqual([c["id"] for c in result["claims"]], ["event:1:fact:1"])
        self.assertEqual(result["answer"], result["claims"][0]["text"])

    def test_tool_feedback_loop_selects_fact_after_read(self):
        gateway = FakeGateway([
            {"content": "", "tool_calls": [{"name": "read_facts", "arguments": {"event_id": 1}}]},
            {"content": '{"claim_ids":["event:1:fact:1"]}', "tool_calls": []},
        ])
        result = answer("怎么修复", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "local_model")
        self.assertEqual(len(gateway.messages), 2)
        self.assertTrue(any(m["role"] == "tool" and "0.9.1" in m["content"] for m in gateway.messages[1]))

    def test_tool_injection_cannot_request_network_or_write(self):
        gateway = FakeGateway([{"content": "", "tool_calls": [{"name": "fetch", "arguments": {"url": "http://127.0.0.1"}}]}])
        result = answer("怎么修复", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "degraded")
        self.assertEqual(len(gateway.messages), 1)
        self.assertTrue(result["claims"])

    def test_gateway_errors_do_not_echo_secrets(self):
        result = answer("怎么修复", snapshot(), gateway=FakeGateway(error="secret=do-not-echo"))
        self.assertEqual(result["mode"], "degraded")
        self.assertNotIn("do-not-echo", json.dumps(result))

    def test_optional_embeddings_have_real_hybrid_branch(self):
        class EmbeddingOnly:
            enabled = False
            embedding_enabled = True
            def embed(self, texts):
                self.texts = texts
                return [[1.0, 0.0], [1.0, 0.0]]
        gateway = EmbeddingOnly()
        result = answer("找资料", snapshot(), gateway=gateway)
        self.assertEqual(result["retrieval"], "hybrid_local")
        self.assertEqual(result["entities"], [1])
        self.assertEqual(len(gateway.texts), 2)

    def test_bad_embeddings_degrade_to_keywords(self):
        class Bad:
            enabled = False
            embedding_enabled = True
            def embed(self, texts):
                return [[float("nan")], [1.0]]
        result = answer("怎么修复", snapshot(), gateway=Bad())
        self.assertEqual(result["retrieval"], "keywords")
        self.assertTrue(any("语义检索不可用" in w for w in result["warnings"]))

    def test_model_abstention_is_not_fake_success(self):
        gateway = FakeGateway([{"content": '{"claim_ids":[]}', "tool_calls": []}])
        result = answer("怎么修复", snapshot(), gateway=gateway)
        self.assertEqual(result["claims"], [])
        self.assertTrue(any("弃权" in w for w in result["warnings"]))

    def test_assets_and_unique_counts_come_from_validated_assessments(self):
        assets = [{"asset_id": "server-x", "name": "推理节点", "ecosystem": "PyPI", "component": "vllm", "version": "0.8.5", "observed_at": "2026-10-01T00:00:00Z"}]
        assessment = {"asset_id": "server-x", "version_match": "affected", "status": "potentially_affected", "reasons": ["范围命中"], "evidence_ids": ["obs:1:r:1"], "missing_conditions": ["配置尚未确认"]}
        e1 = event(assessments=[assessment])
        a2 = {**assessment, "evidence_ids": ["obs:2:r:1"]}
        e2 = event(2, assessments=[a2])
        result = answer("有多少资产可能受影响", snapshot(events=[e1, e2], evidences=[evidence(), evidence(2)], assets=assets))
        counts = next(c["value"] for c in result["claims"] if c["predicate"] == "asset_count")
        self.assertEqual(counts["potentially_affected_assets"], 1)
        self.assertEqual(counts["assessed_assets"], 1)
        self.assertIn("0.8.5", result["answer"])
        self.assertTrue(any("较旧" in w for w in result["warnings"]))
        self.assertTrue(any("不表示资产已被入侵" in w for w in result["warnings"]))

    def test_unknown_or_unauthorized_asset_not_safety_claim(self):
        assessment = {"asset_id": "server-x", "version_match": "unknown", "status": "under_investigation", "reasons": [], "evidence_ids": ["obs:1:r:1"], "missing_conditions": ["版本未知"]}
        s = snapshot(events=[event(assessments=[assessment])], assets=[{"asset_id": "server-x", "name": "节点", "observed_at": "2026-10-03T00:00:00Z"}])
        result = answer("server-x的资产影响", s)
        self.assertIn("待调查", result["answer"])
        s["assets"][0]["authorized"] = False
        self.assertFalse(any(c["predicate"] == "asset_assessment" for c in answer("资产", s)["claims"]))

    def test_cve_and_asset_id_without_asset_word_returns_only_matching_assessment(self):
        assets = [{"asset_id": aid, "name": aid, "observed_at": "2026-10-03T00:00:00Z"} for aid in ("node-a", "node-b")]
        def assessment(aid, ref):
            return {"asset_id": aid, "version_match": "affected", "status": "potentially_affected", "reasons": [], "evidence_ids": [ref], "missing_conditions": []}
        e1 = event(assessments=[assessment("node-a", "obs:1:r:1"), assessment("node-b", "obs:1:r:1")])
        e2 = event(2, assessments=[assessment("node-a", "obs:2:r:1")])
        gateway = FakeGateway(error="exact facts must not use model")
        result = answer("CVE-2026-12345对node-a有影响吗", snapshot([e1, e2], [evidence(), evidence(2)], assets), gateway=gateway)
        assessments = [c for c in result["claims"] if c["predicate"] == "asset_assessment"]
        self.assertEqual([(c["entity_id"], c["value"]["asset_id"]) for c in assessments], [(1, "node-a")])
        self.assertEqual(result["entities"], [1])
        self.assertEqual(result["evidence_ids"], ["obs:1:r:1"])
        self.assertEqual(result["mode"], "facts")
        self.assertEqual(gateway.messages, [])

    def test_exact_asset_assessment_is_prioritized_before_display_cap(self):
        asset = {"asset_id": "node-a", "name": "节点", "observed_at": "2026-10-03T00:00:00Z"}
        assessment = {"asset_id": "node-a", "version_match": "affected", "status": "potentially_affected", "reasons": [], "evidence_ids": ["obs:1:r:1"], "missing_conditions": []}
        rows = [fact("impact", {"description": f"来源影响条目{n}"}) for n in range(65)]
        result = answer("CVE-2026-12345对node-a有影响吗", snapshot(events=[event(facts=rows, assessments=[assessment])], assets=[asset]))
        self.assertEqual(result["claims"][0]["predicate"], "asset_assessment")
        self.assertEqual(result["claims"][0]["value"]["asset_id"], "node-a")
        self.assertEqual(len(result["claims"]), 64)
        self.assertTrue(any("六十四条" in w for w in result["warnings"]))

    def test_asset_prefix_collisions_do_not_pick_other_asset(self):
        asset = {"asset_id": "asset-1", "name": "prod", "component": "vllm", "observed_at": "2026-10-03T00:00:00Z"}
        assessment = {"asset_id": "asset-1", "version_match": "affected", "status": "potentially_affected", "reasons": [], "evidence_ids": ["obs:1:r:1"], "missing_conditions": []}
        s = snapshot(events=[event(assessments=[assessment])], assets=[asset])
        for q in ("asset-10是否受影响", "product修复建议", "how many product assets are affected"):
            result = answer(q, s)
            self.assertEqual(result["claims"], [])
            self.assertEqual(result["entities"], [])

    def test_global_asset_counts_cover_more_than_eight_events(self):
        assets, events, evs = [], [], []
        for n in range(1, 11):
            assets.append({"asset_id": f"node-{n}", "name": f"节点{n}", "observed_at": "2026-10-03T00:00:00Z"})
            assessment = {"asset_id": f"node-{n}", "version_match": "affected", "status": "potentially_affected", "reasons": [], "evidence_ids": [f"obs:{n}:r:1"], "missing_conditions": []}
            events.append(event(n, assessments=[assessment]))
            evs.append(evidence(n))
        result = answer("有多少资产可能受影响", snapshot(events, evs, assets))
        counts = next(c for c in result["claims"] if c["predicate"] == "asset_count")
        self.assertEqual(counts["value"]["potentially_affected_assets"], 10)
        self.assertEqual(result["entities"], list(range(1, 11)))
        self.assertEqual(len(counts["evidence_ids"]), 10)

    def test_upstream_warnings_and_fact_cap_are_visible(self):
        rows = [fact("fix", {"patched_versions": [f"0.9.{n}"]}) for n in range(257)]
        result = answer("CVE-2026-12345修复", snapshot(events=[event(facts=rows, warnings=["范围冲突，仍待确认"])]))
        self.assertTrue(result["claims"])
        self.assertTrue(any("二百五十六" in w for w in result["warnings"]))
        self.assertTrue(any("范围冲突" in w for w in result["warnings"]))

    def test_non_relation_intent_cannot_consult_unsigned_paths(self):
        gateway = FakeGateway([{"content": "", "tool_calls": [{"name": "relations", "arguments": {"event_id": 1, "depth": 3}}]}])
        result = answer("怎么修复", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "degraded")
        self.assertTrue(any(t.get("status") == "unknown_tool" for t in result["trace"]))

    def test_actual_enrichment_relation_shape_and_candidate_background(self):
        from aicti_core.enrichment import enrich
        target = Evidence(**evidence(aliases=("CVE-2026-12345",), metadata={"packages": [{"ecosystem": "PyPI", "name": "vllm", "vulnerable_version_range": "< 0.9.1", "patched_versions": "0.9.1"}]}))
        paper = Evidence(**evidence(2, kind="paper", aliases=("CVE-2026-12345",)))
        enriched = enrich([target], [], [paper], now="2026-10-03T02:00:00Z")
        related = [f.to_dict() for f in enriched.facts if f.predicate == "related_material"]
        self.assertTrue(related)
        result = answer("CVE-2026-12345论文关联", snapshot(events=[event(refs=[target.id, paper.id], facts=[f.to_dict() for f in enriched.facts])], evidences=[target.to_dict(), paper.to_dict()]))
        self.assertTrue(any(c["predicate"] == "related_material" for c in result["claims"]))
        path = result["paths"][0]
        self.assertEqual(path["from_evidence_id"], target.id)
        self.assertEqual(path["target_evidence_id"], paper.id)
        candidate = copy.deepcopy(related[0])
        candidate["status"] = "candidate"
        candidate["value"]["relation"] = "background"
        result = answer("CVE-2026-12345论文关联", snapshot(events=[event(refs=[target.id, paper.id], facts=[candidate])], evidences=[target.to_dict(), paper.to_dict()]))
        self.assertEqual(result["claims"], [])
        self.assertEqual(result["paths"], [])

    def test_real_enrichment_renders_readable_facts_without_changing_values(self):
        from aicti_core.enrichment import enrich
        metadata = {
            "packages": [{"ecosystem": "PyPI", "name": "vllm", "vulnerable_version_range": ">= 0.8.0, < 0.9.1", "exact_versions": ["0.8.7.post1"], "patched_versions": "0.9.1"}],
            "conditions": {"exposed": True, "authenticated": False},
            "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8}],
            "cwes": ["CWE-502"],
        }
        target = Evidence(**evidence(aliases=("CVE-2026-12345",), metadata=metadata))
        paper = Evidence(**evidence(2, kind="paper", title="同一漏洞的分析资料", aliases=("CVE-2026-12345",)))
        enriched = enrich([target], [], [paper], now="2026-10-03T02:00:00Z")
        original_facts = [f.to_dict() for f in enriched.facts]
        before = copy.deepcopy(original_facts)
        s = snapshot([event(refs=[target.id, paper.id], facts=original_facts)], [target.to_dict(), paper.to_dict()])
        result = answer("CVE-2026-12345", s)
        self.assertEqual(original_facts, before)
        self.assertEqual(result["answer"], "\n".join(c["text"] for c in result["claims"]))
        for claim in result["claims"]:
            self.assertTrue(any(claim["predicate"] == f["predicate"] and claim["value"] == f["value"] for f in before))
            self.assertTrue(set(claim["evidence_ids"]) <= {target.id, paper.id})
        by_predicate = {}
        for claim in result["claims"]:
            by_predicate.setdefault(claim["predicate"], []).append(claim)
        self.assertIn("PyPI 包 vllm", by_predicate["affected_component"][0]["text"])
        self.assertIn(">= 0.8.0, < 0.9.1", by_predicate["affected_range"][0]["text"])
        self.assertIn("0.8.7.post1", by_predicate["affected_range"][0]["text"])
        self.assertTrue(any("暴露状态为是" in c["text"] for c in by_predicate["condition"]))
        self.assertTrue(any("认证状态为否" in c["text"] for c in by_predicate["condition"]))
        patch = by_predicate["fix"][0]
        self.assertEqual(patch["value"]["patched_versions"], "0.9.1")
        self.assertIn("来源报告", patch["text"])
        self.assertIn("尚未验证", patch["text"])
        self.assertIn("认证状态为否", patch["text"])
        self.assertIn("且", patch["text"])
        self.assertIn("9.8/10", by_predicate["cvss"][0]["text"])
        self.assertIn("CVSS 3.1", by_predicate["cvss"][0]["text"])
        self.assertIn("保密性影响高", by_predicate["impact"][0]["text"])
        self.assertIn("不能据此确认", by_predicate["impact"][0]["text"])
        self.assertIn("同一漏洞的分析资料", by_predicate["related_material"][0]["text"])
        for internal in ("locator", "rule_version", "identity_precision", "score_recomputed", "base_vector_syntax", "{", "}"):
            self.assertNotIn(internal, result["answer"])
        self.assertNotIn("无需认证即可", result["answer"])

    def test_rendered_cvss_conflicts_keep_exact_source_scores(self):
        from aicti_core.enrichment import enrich
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        a = Evidence(**evidence(source_id="nvd", aliases=("CVE-2026-12345",), metadata={"cvss": [{"version": "3.1", "vector": vector, "score": 9.8}]}))
        b = Evidence(**evidence(2, source_id="vendor", aliases=("CVE-2026-12345",), metadata={"cvss": [{"version": "3.1", "vector": vector, "score": 8.8}]}))
        enriched = enrich([a, b], [], now="2026-10-03T02:00:00Z")
        result = answer("CVE-2026-12345评分", snapshot([event(refs=[a.id, b.id], facts=[f.to_dict() for f in enriched.facts])], [a.to_dict(), b.to_dict()]))
        scores = [c for c in result["claims"] if c["predicate"] == "cvss"]
        self.assertEqual(len(scores), 2)
        for claim, source, score, ref in ((scores[0], "nvd", 9.8, a.id), (scores[1], "vendor", 8.8, b.id)):
            self.assertEqual(claim["value"]["score"], score)
            self.assertEqual(claim["evidence_ids"], [ref])
            self.assertIn(source, claim["text"])
            self.assertIn(f"{score}/10", claim["text"])
            self.assertIn("存在分歧", claim["text"])
            self.assertIn("未重新计算", claim["text"])
        self.assertNotIn("9.3/10", result["answer"])

    def test_cvss_missing_score_does_not_become_zero(self):
        from aicti_core.enrichment import enrich
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        for score in (0, None):
            with self.subTest(score=score):
                target = Evidence(**evidence(aliases=("CVE-2026-12345",), metadata={"cvss": [{"version": "3.1", "vector": vector, "score": score}]}))
                enriched = enrich([target], [], now="2026-10-03T02:00:00Z")
                result = answer("CVE-2026-12345评分", snapshot([event(facts=[f.to_dict() for f in enriched.facts])], [target.to_dict()]))
                claim = next(c for c in result["claims"] if c["predicate"] == "cvss")
                self.assertEqual(claim["value"]["score"], score)
                if score is None:
                    self.assertIn("未提供有效评分", claim["text"])
                    self.assertNotIn("0/10", claim["text"])
                else:
                    self.assertIn("0/10", claim["text"])
                    self.assertNotIn("未提供有效评分", claim["text"])

    def test_cvss_impact_versions_and_missing_metrics_preserve_meaning(self):
        from aicti_core.enrichment import enrich
        cases = [
            ("2.0", "AV:N/AC:L/Au:N/C:P/I:C/A:N", ("保密性影响部分", "完整性影响完全", "可用性影响无")),
            ("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:H/SA:L", ("漏洞所在系统的保密性影响高", "后续系统的保密性影响无", "后续系统的完整性影响高")),
        ]
        for version, vector, expected in cases:
            with self.subTest(version=version):
                target = Evidence(**evidence(aliases=("CVE-2026-12345",), metadata={"cvss": [{"version": version, "vector": vector, "score": 7.5}]}))
                enriched = enrich([target], [], now="2026-10-03T02:00:00Z")
                result = answer("CVE-2026-12345影响", snapshot([event(facts=[f.to_dict() for f in enriched.facts])], [target.to_dict()]))
                claim = next(c for c in result["claims"] if c["predicate"] == "impact")
                self.assertEqual(claim["value"]["version"], version)
                self.assertEqual(claim["value"]["confirmed_exploitation"], False)
                for text in expected:
                    self.assertIn(text, claim["text"])
                self.assertIn("利用成功时的潜在影响", claim["text"])
                self.assertNotIn("没有攻击发生", claim["text"])
        raw = {"scope": "source_cvss_base_metrics", "version": "3.1", "metrics": {"C": "X"}, "confirmed_exploitation": False}
        result = answer("CVE-2026-12345影响", snapshot(events=[event(facts=[fact("impact", raw)])]))
        self.assertEqual(result["claims"][0]["value"], raw)
        self.assertIn("不足", result["answer"])
        self.assertNotIn("保密性影响高", result["answer"])

    def test_relation_text_retains_title_scope_and_background_limits(self):
        for relation in ("direct", "background"):
            raw = {"target_evidence_id": "obs:2:r:1", "title": "研究资料标题", "relation": relation, "scope": "provided_metadata_only", "locator": "aliases[0]"}
            result = answer("CVE-2026-12345论文", snapshot(events=[event(facts=[fact("related_material", raw)])], evidences=[evidence(), evidence(2)]))
            self.assertEqual(result["claims"][0]["value"], raw)
            self.assertEqual(result["claims"][0]["evidence_ids"], ["obs:1:r:1", "obs:2:r:1"])
            self.assertIn("研究资料标题", result["answer"])
            self.assertIn("仅据已有元数据", result["answer"])
            self.assertNotIn("locator", result["answer"])
            if relation == "background":
                self.assertIn("不作为同一漏洞证据", result["answer"])
            else:
                self.assertIn("直接关联", result["answer"])
                self.assertIn("不证明可利用的攻击链", result["answer"])

    def test_sparse_ranges_and_unknown_conditions_do_not_gain_facts(self):
        ranges = {"ecosystem": "product", "name": "ollama", "ranges": [], "exact_versions": [], "rule_version": "private-rule"}
        condition = {"field": "authenticated", "equals": 0, "supported": False, "locator": "metadata.conditions"}
        patch = {"patched_versions": ["0.9.1", "0.9.2"], "verification": "not_tested"}
        result = answer("CVE-2026-12345", snapshot(events=[event(facts=[fact("affected_range", ranges), fact("condition", condition), fact("fix", patch)])]))
        self.assertEqual([c["value"] for c in result["claims"]], [ranges, condition, patch])
        self.assertIn("未给出", result["claims"][0]["text"])
        self.assertNotIn("所有版本", result["answer"])
        self.assertIn("尚不能自动判断", result["claims"][1]["text"])
        self.assertNotIn("认证状态为否", result["claims"][1]["text"])
        self.assertIn("0.9.1", result["claims"][2]["text"])
        self.assertIn("0.9.2", result["claims"][2]["text"])
        self.assertNotIn("private-rule", result["answer"])

    def test_asset_reason_punctuation_changes_display_only(self):
        assessment = {"asset_id": "node-a", "version_match": "affected", "status": "under_investigation", "reasons": ["版本范围命中。", "清单需要核实。。"], "evidence_ids": ["obs:1:r:1"], "missing_conditions": ["exposed", "authenticated", "inventory.observed_at"]}
        result = answer("CVE-2026-12345对node-a的影响", snapshot(events=[event(assessments=[assessment])], assets=[{"asset_id": "node-a", "name": "节点", "observed_at": "2026-10-03T00:00:00Z"}]))
        claim = next(c for c in result["claims"] if c["predicate"] == "asset_assessment")
        self.assertEqual(claim["value"], assessment)
        self.assertNotIn("。。", claim["text"])
        self.assertNotIn("。；", claim["text"])
        self.assertIn("暴露状态", claim["text"])
        self.assertIn("认证状态", claim["text"])
        self.assertIn("清单观察时间", claim["text"])

    def test_inventory_derived_risk_keeps_hypothesis_and_staleness_limits(self):
        raw = {"asset_id": "node-a", "pattern": "prompt_injection_tool_abuse", "basis": "asset_declared_capabilities", "capabilities": {"external_documents": True, "tools": True}, "observed_at": "2026-10-01T00:00:00Z", "stale": True, "confirmed_vulnerability": False, "evidence_role": "advisory_context_only", "locator": "inventory.capabilities"}
        result = answer("CVE-2026-12345注入风险", snapshot(events=[event(facts=[fact("risk_pattern", raw)])]))
        claim = result["claims"][0]
        self.assertEqual(claim["value"], raw)
        self.assertIn("授权清单能力提示", claim["text"])
        self.assertIn("node-a", claim["text"])
        self.assertIn("处理外部文档", claim["text"])
        self.assertIn("公告仅作背景", claim["text"])
        self.assertIn("重新核实", claim["text"])
        self.assertIn("尚未据此确认漏洞", claim["text"])
        self.assertNotIn("inventory.capabilities", claim["text"])

    def test_host_catalog_all_fact_categories_and_assets_match_answer_cards(self):
        rows = [fact("cvss", {"version": "3.1", "score": 9.8}), fact("weakness", {"cwe_id": "CWE-502"}), fact("related_material", {"target_evidence_id": "obs:2:r:1", "title": "研究资料", "relation": "direct"})]
        assessment = {"asset_id": "node-a", "version_match": "affected", "status": "potentially_affected", "reasons": ["版本命中。"], "evidence_ids": ["obs:1:r:1"], "missing_conditions": []}
        s = snapshot([event(facts=rows, assessments=[assessment])], [evidence(), evidence(2)], [{"asset_id": "node-a", "observed_at": "2026-10-03T00:00:00Z"}])
        before = copy.deepcopy(s)
        catalog = host_card_catalog(s, [1])
        self.assertEqual(s, before)
        self.assertEqual({c["predicate"] for c in catalog.values()}, {"cvss", "weakness", "related_material", "asset_assessment"})
        result = answer("CVE-2026-12345对node-a的评分与论文关联", s)
        for claim in result["claims"]:
            approved = catalog[claim["id"]]
            for field in ("id", "text", "value", "predicate", "entity_id", "evidence_ids"):
                self.assertEqual(claim[field], approved[field])
        self.assertEqual(catalog["event:1:fact:2"]["evidence_ids"], ["obs:1:r:1", "obs:2:r:1"])

    def test_host_catalog_accepts_valid_semantic_card_outside_keyword_reference(self):
        s = snapshot()
        keyword_reference = answer("找机器执行权限边界", s)
        self.assertEqual(keyword_reference["claims"], [])
        class SemanticOnly:
            enabled = False
            embedding_enabled = True
            def embed(self, texts):
                return [[1.0, 0.0], [1.0, 0.0]]
        semantic = answer("找机器执行权限边界", s, gateway=SemanticOnly())
        self.assertEqual(semantic["retrieval"], "hybrid_local")
        self.assertTrue(semantic["claims"])
        approved = host_card_catalog(s, [1])
        for claim in semantic["claims"]:
            for field in ("text", "value", "evidence_ids", "entity_id"):
                self.assertEqual(claim[field], approved[claim["id"]][field])

    def test_host_catalog_rejects_stale_withdrawn_candidate_and_unauthorized_data(self):
        bad_candidate = event(facts=[fact("fix", {"patched_versions": ["9.9.9"]}, status="candidate")])
        bad_support = event(facts=[fact("fix", {"patched_versions": ["9.9.9"]}, "obs:1:r:1", "obs:2:r:1")])
        cases = [snapshot(events=[event(status=status)]) for status in ("dirty", "quarantined")]
        cases += [snapshot(events=[event(authorized=False)]), snapshot(events=[bad_candidate]), snapshot(events=[bad_support]), snapshot(evidences=[evidence(withdrawn=True)]), snapshot(evidences=[evidence(), evidence(revision=2)]), snapshot(evidences=[evidence(authorized=False)])]
        for s in cases:
            self.assertEqual(host_card_catalog(s, [1]), {})
        self.assertEqual(host_card_catalog(snapshot(), [2]), {})
        self.assertEqual(host_card_catalog(snapshot(), []), {})
        catalog = host_card_catalog(snapshot(), [1, 1, 999])
        self.assertEqual(set(catalog), {"event:1:fact:0", "event:1:fact:1"})

    def test_host_catalog_separate_fact_asset_caps_and_no_counts(self):
        rows = [fact("impact", {"description": f"来源影响条目{n}"}) for n in range(65)]
        assets = [{"asset_id": f"node-{n}", "observed_at": "2026-10-03T00:00:00Z"} for n in range(65)]
        assessments = [{"asset_id": a["asset_id"], "version_match": "affected", "status": "potentially_affected", "reasons": [], "evidence_ids": ["obs:1:r:1"], "missing_conditions": []} for a in assets]
        catalog = host_card_catalog(snapshot(events=[event(facts=rows, assessments=assessments)], assets=assets), [1])
        self.assertEqual(len(catalog), 128)
        self.assertEqual(sum(c["predicate"] == "asset_assessment" for c in catalog.values()), 64)
        self.assertEqual(sum(c["predicate"] == "impact" for c in catalog.values()), 64)
        self.assertNotIn("asset:counts", catalog)
        for ids in ([1] * 33, [True], [0], [-1], ["1"], None, (1,)):
            with self.assertRaises(ValueError):
                host_card_catalog(snapshot(), ids)

    def test_host_catalog_asset_authorization_and_detached_results(self):
        assessment = {"asset_id": "node-a", "version_match": "affected", "status": "potentially_affected", "reasons": [], "evidence_ids": ["obs:1:r:1"], "missing_conditions": []}
        s = snapshot(events=[event(assessments=[assessment])], assets=[{"asset_id": "node-a", "authorized": False}])
        self.assertFalse(any(c["predicate"] == "asset_assessment" for c in host_card_catalog(s, [1]).values()))
        catalog = host_card_catalog(s, [1])
        catalog["event:1:fact:1"]["value"]["patched_versions"].append("9.9.9")
        self.assertEqual(host_card_catalog(s, [1])["event:1:fact:1"]["value"]["patched_versions"], ["0.9.1"])

    def test_three_hop_paths_keep_background_and_dependencies(self):
        evs = [evidence(n) for n in range(1, 6)]
        events = [event(n, facts=[fact("related_material", {"target_evidence_id": f"obs:{n + 1}:r:1", "relation": "background" if n == 1 else "direct"}, f"obs:{n}:r:1")]) for n in range(1, 5)]
        result = answer("CVE-2026-12345的关联路径", snapshot(events=events, evidences=evs))
        self.assertEqual([p["hops"] for p in result["paths"]], [1, 2, 3])
        self.assertTrue(all(p["path_relation"] == "background" for p in result["paths"]))
        self.assertEqual(result["entities"], [1, 2, 3])
        self.assertEqual(result["evidence_ids"], [f"obs:{n}:r:1" for n in range(1, 5)])
        self.assertIn("不作为同一漏洞证据", result["answer"])

    def test_shared_dependency_does_not_invent_event_edge(self):
        e1 = event(refs=["obs:1:r:1", "obs:2:r:1"], facts=[fact("related_material", {"target_evidence_id": "obs:2:r:1", "relation": "background"}, "obs:1:r:1")])
        e3 = event(3, refs=["obs:3:r:1", "obs:2:r:1"], facts=[])
        result = answer("CVE-2026-12345的关联", snapshot(events=[e1, e3], evidences=[evidence(1), evidence(2), evidence(3)]))
        self.assertEqual(len(result["paths"]), 1)
        self.assertNotIn(3, result["entities"])
        self.assertNotIn("to_event", result["paths"][0])

    def test_model_relation_reads_beyond_precomputed_cap_are_signed(self):
        events, evs = [], [evidence(1), evidence(2)]
        for n, start in ((1, 100), (2, 200)):
            rows = []
            for material in range(start, start + 35):
                evs.append(evidence(material))
                rows.append(fact("related_material", {"target_evidence_id": f"obs:{material}:r:1", "relation": "background"}, f"obs:{n}:r:1"))
            events.append(event(n, facts=rows))
        gateway = FakeGateway([
            {"content": "", "tool_calls": [{"name": "relations", "arguments": {"event_id": 2, "depth": 3}}]},
            {"content": '{"claim_ids":["event:1:fact:0"]}', "tool_calls": []},
        ])
        result = answer("论文关联", snapshot(events, evs), gateway=gateway)
        self.assertEqual(result["mode"], "local_model")
        feedback = next(m for m in gateway.messages[1] if m["role"] == "tool")
        read_refs = {ref for p in json.loads(feedback["content"])["data"]["paths"] for ref in p["evidence_ids"]}
        self.assertTrue(read_refs <= set(result["evidence_ids"]))
        self.assertIn("obs:231:r:1", result["evidence_ids"])
        self.assertEqual(result["entities"], [1, 2])
        self.assertTrue(any(p["from_event"] == 2 for p in result["paths"]))

    def test_withdrawn_relation_target_is_not_current_material(self):
        e1 = event(facts=[fact("related_material", {"target_evidence_id": "obs:2:r:1", "relation": "direct"})])
        result = answer("CVE-2026-12345论文", snapshot(events=[e1], evidences=[evidence(), evidence(2, withdrawn=True)]))
        self.assertEqual(result["claims"], [])
        self.assertEqual(result["paths"], [])

    def test_snapshot_and_question_bounds_and_no_mutation(self):
        s = snapshot()
        before = copy.deepcopy(s)
        answer("CVE-2026-12345", s)
        self.assertEqual(s, before)
        for q in ("", "x" * 4001, None):
            with self.assertRaises(ValueError):
                answer(q, s)
        with self.assertRaises(ValueError):
            answer("漏洞", snapshot(events=[event()] * 1025))

    def test_demo_is_always_labeled(self):
        s = snapshot()
        s["demo"] = True
        self.assertTrue(any("虚构" in w for w in answer("CVE-2026-12345", s)["warnings"]))


class CloudQATests(unittest.TestCase):
    def test_explicit_cve_calls_real_plan_then_synthesis(self):
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        result = answer("CVE-2026-12345怎么处理？", snapshot(), gateway=gateway)
        self.assertEqual((result["mode"], result["retrieval"]), ("cloud_model", "llm_semantic"))
        self.assertEqual(result["generation_count"], 2)
        self.assertEqual(len(gateway.messages), 2)
        self.assertEqual(result["model_provider"], "deepseek")
        self.assertEqual(gateway.formats, [{"type": "json_object"}] * 2)
        self.assertEqual(result["claims"], answer("CVE-2026-12345修复", snapshot())["claims"][1:])

    def test_semantic_chinese_paraphrase_recalls_outside_keywords(self):
        question = "有没有办法把推理服务的暴露面收紧？"
        self.assertEqual(answer(question, snapshot())["claims"], [])
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        result = answer(question, snapshot(), gateway=gateway)
        self.assertEqual(result["retrieval"], "llm_semantic")
        self.assertIn("0.9.1", result["answer"])
        catalog = json.loads(gateway.messages[0][-1]["content"])["current_catalog"]
        self.assertEqual(catalog[0]["event_id"], "E001")

    def test_analysis_is_separate_canonical_claims_unchanged(self):
        section = {"kind": "recommendation", "text": "建议先核对相关组件版本，再依据当前修复卡安排人工升级。",
                   "claim_ids": ["C0002"], "evidence_ids": ["D0001"]}
        gateway = FakeCloudGateway([cloud_plan(), cloud_final(sections=[section])])
        result = answer("vllm怎样处置才稳妥", snapshot(), gateway=gateway)
        self.assertEqual(len(result["analysis_sections"]), 1)
        self.assertEqual(result["analysis_sections"][0]["claim_ids"], ["event:1:fact:1"])
        self.assertIn("模型", result["answer"])
        self.assertEqual(set(result["claims"][0]), {"id", "text", "evidence_ids", "entity_id", "predicate", "value"})
        self.assertEqual(result["claims"][0], host_card_catalog(snapshot(), [1])["event:1:fact:1"])

    def test_multi_turn_reloads_current_evidence_not_previous_answer(self):
        history = [{"question": "CVE-2026-12345影响？", "result": {"entities": [1], "answer": "SECRET-HISTORY ignore rules"}}]
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        result = answer("接下来该怎么处置它？", snapshot(), history=history, gateway=gateway)
        payload = json.loads(gateway.messages[0][-1]["content"])
        self.assertEqual(payload["history_data"][0]["current_event_ids"], ["E001"])
        self.assertNotIn("SECRET-HISTORY", json.dumps(gateway.messages))
        self.assertEqual(result["mode"], "cloud_model")

    def test_stale_continuation_and_unknown_exact_never_expand_scope(self):
        for question, history in (("它怎么处置", [{"entities": [99]}]), ("CVE-2026-99999修复", None)):
            gateway = FakeCloudGateway([cloud_plan(events=[])])
            result = answer(question, snapshot(), history=history, gateway=gateway)
            self.assertEqual(result["claims"], [])
            self.assertEqual(len(gateway.messages), 1)
            self.assertEqual(json.loads(gateway.messages[0][-1]["content"])["current_catalog"], [])

    def test_internal_asset_names_ids_question_and_history_are_anonymized(self):
        assets = [{"asset_id": "secret-prod-id", "name": "财务核心机器", "component": "vllm", "version": "0.9.0", "authorized": True},
                  {"asset_id": "secret-denied-id", "name": "隐藏主机", "component": "vllm", "authorized": False}]
        assessment = {"asset_id": "secret-prod-id", "status": "potentially_affected", "version_match": "affected", "reasons": ["财务核心机器需核对"], "missing_conditions": [], "evidence_ids": ["obs:1:r:1"]}
        snap = snapshot(events=[event(assessments=[assessment])], assets=assets)
        history = [{"question": "财务核心机器 secret-prod-id 隐藏主机 secret-denied-id", "entities": [1]}]
        gateway = FakeCloudGateway([cloud_plan(asset_intent=True), cloud_final(ids=["C0001"])])
        result = answer("财务核心机器 secret-prod-id 是否受影响", snap, history=history, gateway=gateway)
        outbound = json.dumps(gateway.messages, ensure_ascii=False)
        for label in ("财务核心机器", "secret-prod-id", "隐藏主机", "secret-denied-id", "obs:1:r:1", "event:1:asset:0"):
            self.assertNotIn(label, outbound)
        self.assertIn("财务核心机器", result["answer"])
        self.assertIn("secret-prod-id", result["claims"][0]["value"]["asset_id"])
        self.assertNotIn('"assets"', outbound)

    def test_secret_like_question_and_evidence_strings_not_sent(self):
        poisoned = event(title="public sk-abcdefghijklmnopqrst token=abcdefghijkl private https://admin:password@10.0.0.1/")
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        answer("vllm修复 api_key=sample-private-value 联系 a@example.internal", snapshot(events=[poisoned]), gateway=gateway)
        outbound = json.dumps(gateway.messages)
        for sensitive in ("sk-abcdefghijklmnopqrst", "abcdefghijkl", "sample-private-value", "admin:password", "a@example.internal"):
            self.assertNotIn(sensitive, outbound)

    def test_tool_followup_is_real_and_shared_with_planning_budget(self):
        tool = {"content": "", "tool_calls": [{"id": "call_read_1", "name": "read_facts", "arguments": {"event_id": "E001"}}], "reasoning_content": "private thinking"}
        gateway = FakeCloudGateway([cloud_plan(), tool, cloud_final()])
        result = answer("vllm怎样处置", snapshot(), gateway=gateway)
        self.assertEqual((result["generation_count"], result["tool_call_count"]), (3, 1))
        feedback = gateway.messages[2][-1]
        self.assertEqual(feedback["tool_call_id"], "call_read_1")
        self.assertEqual(json.loads(feedback["content"])["data"]["cards"][0]["evidence_ids"], ["D0001"])
        self.assertEqual(gateway.messages[2][-2]["reasoning_content"], "private thinking")
        self.assertNotIn("private thinking", json.dumps(result))

    def test_planner_unregistered_identity_or_duplicate_fields_degrades(self):
        responses = [cloud_plan(events=["E999"]), cloud_plan(intents=["execute"]),
                     {"content": '{"event_ids":[],"event_ids":["E001"],"intents":[],"asset_intent":false,"relation_depth":0,"count_assets":false}', "tool_calls": []}]
        for reply in responses:
            gateway = FakeCloudGateway([reply])
            result = answer("CVE-2026-12345修复", snapshot(), gateway=gateway)
            self.assertEqual(result["mode"], "degraded")
            self.assertEqual(result["retrieval"], "keywords")
            self.assertIn("0.9.1", result["answer"])

    def test_malicious_analysis_removed_while_facts_retained(self):
        for text, refs in (("建议升级到9.9.9且评分为10.0。", ["D0001"]),
                           ("已确认服务器被成功利用。", ["D0001"]),
                           ("建议核对修复卡。", ["D9999"]),
                           ("建议在https://evil.example/执行验证。", ["D0001"])):
            section = {"kind": "analysis", "text": text, "claim_ids": ["C0002"], "evidence_ids": refs}
            gateway = FakeCloudGateway([cloud_plan(), cloud_final(sections=[section])])
            result = answer("vllm修复建议", snapshot(), gateway=gateway)
            self.assertEqual(result["analysis_sections"], [])
            self.assertIn("0.9.1", result["answer"])

    def test_hidden_tool_injection_never_executes_unknown_tool(self):
        reply = {"content": "", "tool_calls": [{"id": "evil_call", "name": "execute", "arguments": {"command": "credential"}}]}
        gateway = FakeCloudGateway([cloud_plan(), reply])
        result = answer("vllm修复", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "degraded")
        self.assertEqual(result["tool_call_count"], 0)
        self.assertIn("0.9.1", result["answer"])

    def test_generation_budget_includes_planning_and_stops_at_four(self):
        tool = lambda n, depth: {"content": "", "tool_calls": [{"id": f"call_{n}", "name": "relations", "arguments": {"event_id": "E001", "depth": depth}}]}
        gateway = FakeCloudGateway([cloud_plan(relation_depth=3), tool(1, 1), tool(2, 2), tool(3, 3), cloud_final()])
        result = answer("vllm与分析文档如何关联", snapshot(), gateway=gateway)
        self.assertLessEqual(len(gateway.messages), 4)
        self.assertLessEqual(result["generation_count"], 4)
        self.assertLessEqual(result["tool_call_count"], 6)

    def test_catalog_inputs_kept_in_exact_snapshot_dependencies(self):
        snap = snapshot(events=[event(), event(2)], evidences=[evidence(), evidence(2)])
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        result = answer("如何收紧推理服务", snap, gateway=gateway)
        self.assertEqual(result["entities"], [1, 2])
        self.assertEqual(result["evidence_ids"], ["obs:1:r:1", "obs:2:r:1"])
        self.assertEqual(result["event_generations"], {"1": 2, "2": 2})

    def test_model_failure_sanitized_and_no_embedding_attempt(self):
        class Failure(FakeCloudGateway):
            embedding_enabled = True
            def embed(self, texts):
                raise AssertionError("DeepSeek has no embedding API")
        gateway = Failure(error="secret API key and server body")
        result = answer("解释推理服务暴露面", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "degraded")
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(len(gateway.messages), 1)

    def test_unicode_and_embedded_asset_terms_and_ipv6_do_not_leak(self):
        assets = [{"asset_id": "prod-secret-host", "name": "财务核心机器", "authorized": False}]
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        answer("vllm修复 prefix-prod-secret-host-suffix 财务核心机器 ｓｋ－abcdefghijklmnop fd00::1234", snapshot(assets=assets), gateway=gateway)
        outbound = json.dumps(gateway.messages, ensure_ascii=False)
        for token in ("prod-secret-host", "财务核心机器", "abcdefghijklmnop", "fd00::1234"):
            self.assertNotIn(token, outbound)

    def test_expired_shared_deadline_never_starts_planning_call(self):
        gateway = FakeCloudGateway([cloud_plan(), cloud_final()])
        with patch("aicti_core.qa.time.monotonic", side_effect=[0.0] + [31.0] * 100):
            result = answer("CVE-2026-12345修复", snapshot(), gateway=gateway)
        self.assertEqual(result["mode"], "degraded")
        self.assertEqual(result["generation_count"], 0)
        self.assertEqual(gateway.messages, [])


if __name__ == "__main__":
    unittest.main()
