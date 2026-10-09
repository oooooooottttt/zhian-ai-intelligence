"""Offline security and orchestration tests for the bounded host tool loop."""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import json
import threading
import time
import unittest

from aicti_core.harness import (
    Harness, HarnessError, HarnessPolicy, RunBudget, StaleData,
    ToolRegistry, ToolResult, ToolSpec,
)


def tool_call(name="read_fact", **arguments):
    return {"content": "", "tool_calls": [{"function": {"name": name, "arguments": arguments}}], "model": "fake"}


def final(content="Fact from evidence."):
    return {"content": content, "tool_calls": [], "model": "fake"}


class FakeGateway:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, messages, *, tools=None, max_tokens=800, timeout=None):
        self.calls.append({"messages": copy.deepcopy(messages), "tools": copy.deepcopy(tools),
                           "max_tokens": max_tokens, "timeout": timeout})
        if not self.responses:
            raise AssertionError("Unexpected extra model generation")
        response = self.responses.pop(0)
        if callable(response):
            return response()
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)


SCHEMA = {"type": "object", "properties": {"event_id": {"type": "integer", "minimum": 1, "maximum": 10}},
          "required": ["event_id"], "additionalProperties": False}


class HarnessTests(unittest.TestCase):
    def make(self, responses, *, handler=None, policy=None, budget=None):
        self.tool_args = []

        def read_fact(event_id):
            self.tool_args.append(event_id)
            return {"event_id": event_id, "evidence_ids": ["obs:1:r:2"], "fact": "vulnerable range < 2.0"}

        self.gateway = FakeGateway(responses)
        self.registry = ToolRegistry([ToolSpec("read_fact", "Read authorized facts", SCHEMA, handler or read_fact)])
        self.harness = Harness(self.gateway, self.registry, policy=policy, budget=budget)
        return self.harness

    def run_harness(self, harness):
        return harness.run([{"role": "user", "content": "Which version is affected?"}])

    def test_actual_tool_result_feedback_and_host_identity(self):
        harness = self.make([tool_call(event_id=1), final()])
        result = self.run_harness(harness)
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.content, "Fact from evidence.")
        self.assertEqual((result.generations, result.tool_calls), (2, 1))
        self.assertEqual(self.tool_args, [1])
        feedback = self.gateway.calls[1]["messages"][-1]
        self.assertEqual(feedback["role"], "tool")
        self.assertEqual(feedback["tool_name"], "read_fact")
        self.assertEqual(json.loads(feedback["content"])["data"]["evidence_ids"], ["obs:1:r:2"])
        self.assertEqual(self.gateway.calls[0]["tools"][0]["function"]["name"], "read_fact")
        self.assertEqual(result.run_id, harness.budget.run_id)
        self.assertEqual(result.trace[0]["run_id"], result.run_id)
        self.assertEqual(len(result.run_id), 32)
        self.assertGreater(self.gateway.calls[0]["timeout"], 0)

    def test_cloud_thinking_and_exact_tool_ids_only_exist_in_transient_followup(self):
        reply = tool_call(event_id=1)
        reply["tool_calls"][0]["id"] = "call.exact:ID-1"
        reply["reasoning_content"] = "private thinking never logged"
        harness = self.make([reply, final()])
        self.gateway.provider = "deepseek"
        result = self.run_harness(harness)
        self.assertEqual(result.status, "complete")
        prompt = self.gateway.calls[1]["messages"]
        self.assertEqual(prompt[-1]["tool_call_id"], "call.exact:ID-1")
        self.assertEqual(prompt[-2]["reasoning_content"], "private thinking never logged")
        self.assertNotIn("private thinking", json.dumps(result.to_dict()))

    def test_cloud_missing_duplicate_or_malformed_call_ids_never_execute_handlers(self):
        for ids in ((None,), ("same", "same"), ("secret id with spaces",)):
            reply = tool_call(event_id=1)
            reply["tool_calls"] = [copy.deepcopy(reply["tool_calls"][0]) for _ in ids]
            for call, identity in zip(reply["tool_calls"], ids):
                if identity is not None:
                    call["id"] = identity
            harness = self.make([reply])
            self.gateway.provider = "deepseek"
            result = self.run_harness(harness)
            self.assertEqual(result.status, "unsafe_arguments")
            self.assertEqual(self.tool_args, [])

    def test_qa_mapping_handler_and_timeout_alias_are_supported(self):
        seen = []
        spec = ToolSpec("read_fact", "Facts", SCHEMA, lambda args: seen.append(args) or {"id": args["event_id"]})
        gateway = FakeGateway([tool_call(event_id=2), final()])
        budget = RunBudget(timeout=2.0)
        result = self.run_harness(Harness(gateway, ToolRegistry([spec]), budget=budget))
        self.assertEqual(result.status, "complete")
        self.assertEqual(seen, [{"event_id": 2}])
        self.assertEqual(budget.timeout_seconds, 2.0)
        with self.assertRaises(HarnessError):
            RunBudget(timeout=1.0, timeout_seconds=2.0)

    def test_model_cannot_supply_run_identity_or_override_deny(self):
        reply = tool_call("execute", run_id="forged", command="echo secret")
        reply["run_id"] = "forged"
        harness = self.make([reply], policy=HarnessPolicy(denied_tools=frozenset()))
        result = self.run_harness(harness)
        self.assertEqual(result.status, "denied_tool")
        self.assertNotEqual(result.run_id, "forged")
        self.assertEqual(result.tool_calls, 0)
        with self.assertRaises(HarnessError):
            ToolSpec("execute", "No", {"type": "object"}, lambda: None)
        with self.assertRaises(HarnessError):
            ToolSpec("scan_assets", "No", {"type": "object"}, lambda: None)

    def test_unknown_tool_stops_without_handlers(self):
        harness = self.make([tool_call("invented", event_id=1)])
        result = self.run_harness(harness)
        self.assertEqual(result.status, "unknown_tool")
        self.assertEqual(result.tool_calls, 0)
        self.assertEqual(self.tool_args, [])

    def test_extra_policy_deny_cannot_be_overridden_by_scope(self):
        harness = self.make([tool_call(event_id=1)], policy=HarnessPolicy(denied_tools={"read_fact"}))
        self.assertEqual(self.run_harness(harness).status, "denied_tool")
        self.assertEqual(self.gateway.calls[0]["tools"], [])
        with self.assertRaises(HarnessError):
            harness.run([{"role": "user", "content": "x"}], allowed_tools={"read_fact"})
        with self.assertRaises(HarnessError):
            HarnessPolicy(denied_tools=None)
        with self.assertRaises(HarnessError):
            Harness(self.gateway, self.registry, policy=False)
        with self.assertRaises(HarnessError):
            Harness(self.gateway, self.registry, budget=False)

    def test_strict_argument_types_required_fields_and_bounds(self):
        bad_values = [True, 0, 11, "1", None, 1.5]
        for value in bad_values:
            with self.subTest(value=value):
                result = self.run_harness(self.make([tool_call(event_id=value)]))
                self.assertEqual(result.status, "unsafe_arguments")
                self.assertEqual(result.tool_calls, 0)
        for arguments in ({}, {"event_id": 1, "command": "injected"}):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_harness(self.make([tool_call(**arguments)])).status, "unsafe_arguments")

    def test_complete_batch_validated_before_first_handler(self):
        reply = tool_call(event_id=1)
        reply["tool_calls"].append(tool_call(event_id="unsafe")["tool_calls"][0])
        harness = self.make([reply])
        self.assertEqual(self.run_harness(harness).status, "unsafe_arguments")
        self.assertEqual(self.tool_args, [])

    def test_ollama_requires_object_arguments(self):
        reply = tool_call(event_id=1)
        reply["tool_calls"][0]["function"]["arguments"] = '{"event_id":1}'
        result = self.run_harness(self.make([reply]))
        self.assertEqual(result.status, "unsafe_arguments")

    def test_read_only_registry_schema_and_snapshot_cannot_be_replaced(self):
        harness = self.make([tool_call("read_other", event_id=1)])
        spec = self.registry.snapshot()["read_fact"]
        with self.assertRaises(TypeError):
            spec.parameters["properties"]["event_id"]["maximum"] = 999
        with self.assertRaises(HarnessError):
            self.registry.register(spec)
        with self.assertRaises(HarnessError):
            ToolSpec("read_mutable", "No", {"type": "object"}, lambda: None, read_only=False)
        with self.assertRaises(HarnessError):
            ToolSpec("read_url", "No", {"type": "object", "properties": {"url": {"type": "string"}}}, lambda url: None)
        self.registry.register(ToolSpec("read_other", "Read other facts", SCHEMA, lambda event_id: {}))
        self.assertEqual(self.run_harness(harness).status, "unknown_tool")

    def test_result_is_deeply_immutable_and_to_dict_is_independent(self):
        result = self.run_harness(self.make([final("safe")]))
        with self.assertRaises(FrozenInstanceError):
            result.content = "changed"
        with self.assertRaises(TypeError):
            result.trace[0]["event"] = "changed"
        with self.assertRaises(TypeError):
            result.trace[0]["tools"][0] = "changed"
        exported = result.to_dict()
        exported["trace"][0]["event"] = "changed"
        self.assertEqual(result.trace[0]["event"], "start")
        self.assertIsInstance(result.trace, tuple)

    def test_children_and_correction_runs_share_physical_generation_budget(self):
        gateway = FakeGateway([tool_call("narrow_task"), final("child fact"), final("root fact"), final("correction")])
        holder = {}
        children = []

        def narrow_task():
            child = holder["harness"].child(allowed_tools=())
            children.append(child)
            result = child.run([{"role": "user", "content": "Narrow evidence task"}])
            return {"status": result.status, "content": result.content, "run_id": result.run_id}

        registry = ToolRegistry([ToolSpec("narrow_task", "A narrow host task", {"type": "object"}, narrow_task)])
        harness = Harness(gateway, registry)
        holder["harness"] = harness
        first = self.run_harness(harness)
        self.assertEqual(first.status, "complete")
        self.assertEqual(first.generations, 3)
        self.assertIs(children[0].budget, harness.budget)
        self.assertEqual(children[0].budget.run_id, first.run_id)
        self.assertEqual(self.run_harness(harness).content, "correction")
        self.assertEqual(self.run_harness(harness).status, "budget_exhausted")
        self.assertEqual(len(gateway.calls), 4)
        self.assertEqual(harness.budget.generations, 4)

    def test_nested_child_cannot_expand_scope_depth_or_generations(self):
        harness = self.make([final()], budget=RunBudget(max_depth=1))
        child = harness.child(allowed_tools=())
        with self.assertRaises(HarnessError):
            child.child(allowed_tools={"read_fact"})
        with self.assertRaises(HarnessError):
            child.child(allowed_tools=())
        with self.assertRaises(HarnessError):
            child.run([{"role": "user", "content": "x"}], allowed_tools={"read_fact"})
        with self.assertRaises(HarnessError):
            RunBudget(max_generations=5)

    def test_concurrent_children_reserve_the_same_generation_budget_atomically(self):
        calls = []
        lock = threading.Lock()
        gate = threading.Barrier(12)

        class ConcurrentGateway:
            def complete(self, messages, *, tools=None, max_tokens=800):
                with lock:
                    calls.append(1)
                return final()

        harness = self.make([])
        root = Harness(ConcurrentGateway(), self.registry)
        children = [root.child(allowed_tools=()) for _ in range(12)]

        def execute(child):
            gate.wait(timeout=2)
            return self.run_harness(child)

        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(execute, children))
        self.assertEqual(len(calls), 4)
        self.assertEqual(root.budget.generations, 4)
        self.assertEqual(sum(result.status == "complete" for result in results), 4)
        self.assertEqual(sum(result.status == "budget_exhausted" for result in results), 8)
        self.assertEqual({result.run_id for result in results}, {root.budget.run_id})

    def test_global_tool_budget_shared_with_children(self):
        gateway = FakeGateway([tool_call("narrow_task"), tool_call(event_id=1), final("cannot claim child success")])
        holder = {}
        child_results = []

        def narrow_task():
            result = holder["harness"].child(allowed_tools={"read_fact"}).run([{"role": "user", "content": "child"}])
            child_results.append(result)
            return {"status": result.status}

        handlers = []
        registry = ToolRegistry([
            ToolSpec("narrow_task", "Narrow task", {"type": "object"}, narrow_task),
            ToolSpec("read_fact", "Fact", SCHEMA, lambda event_id: handlers.append(event_id)),
        ])
        harness = Harness(gateway, registry, budget=RunBudget(max_tool_calls=1))
        holder["harness"] = harness
        result = self.run_harness(harness)
        self.assertEqual(child_results[0].status, "budget_exhausted")
        self.assertEqual(result.tool_calls, 1)
        self.assertEqual(handlers, [])

    def test_step_budget_counts_models_and_actual_tools(self):
        harness = self.make([tool_call(event_id=1), final()], budget=RunBudget(max_steps=1))
        result = self.run_harness(harness)
        self.assertEqual(result.status, "budget_exhausted")
        self.assertEqual((result.generations, result.tool_calls), (1, 0))
        self.assertEqual(self.tool_args, [])

    def test_repeated_tool_calls_use_cache_and_stop_without_reexecuting(self):
        harness = self.make([tool_call(event_id=1), tool_call(event_id=1), tool_call(event_id=1), final()])
        result = self.run_harness(harness)
        self.assertEqual(result.status, "no_progress")
        self.assertEqual(result.generations, 3)
        self.assertEqual(result.tool_calls, 1)
        self.assertEqual(self.tool_args, [1])
        self.assertEqual(self.gateway.calls[2]["messages"][-1]["role"], "tool")

    def test_different_queries_with_identical_tool_output_stop(self):
        harness = self.make([tool_call(event_id=1), tool_call(event_id=2), tool_call(event_id=3)], handler=lambda event_id: {"facts": []})
        result = self.run_harness(harness)
        self.assertEqual(result.status, "no_progress")
        self.assertEqual(result.tool_calls, 3)

    def test_snapshot_stale_before_or_after_generation_discards_tools(self):
        harness = self.make([tool_call(event_id=1)], policy=HarnessPolicy(is_current=lambda: False))
        self.assertEqual(self.run_harness(harness).status, "stale")
        self.assertEqual(self.gateway.calls, [])
        current = [True]

        def become_stale():
            current[0] = False
            return tool_call(event_id=1)

        harness = self.make([become_stale], policy=HarnessPolicy(is_current=lambda: current[0]))
        result = self.run_harness(harness)
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.content, "")
        self.assertEqual(self.tool_args, [])

    def test_stale_handler_protocol_and_freshness_check(self):
        for handler in (lambda event_id: ToolResult({"secret": "ignored"}, stale=True),
                        lambda event_id: (_ for _ in ()).throw(StaleData("sensitive"))):
            result = self.run_harness(self.make([tool_call(event_id=1)], handler=handler))
            self.assertEqual(result.status, "stale")
            self.assertNotIn("sensitive", json.dumps(result.to_dict()))
        gateway = FakeGateway([tool_call(event_id=1)])
        registry = ToolRegistry([ToolSpec("read_fact", "Facts", SCHEMA, lambda event_id: self.fail("must not run"),
                                          freshness_check=lambda: False)])
        result = self.run_harness(Harness(gateway, registry))
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.tool_calls, 0)

    def test_late_model_result_is_discarded_and_no_tool_starts(self):
        def slow():
            time.sleep(0.025)
            return tool_call(event_id=1)

        harness = self.make([slow], budget=RunBudget(timeout_seconds=0.01))
        result = self.run_harness(harness)
        self.assertEqual(result.status, "time_exhausted")
        self.assertEqual(result.content, "")
        self.assertEqual(self.tool_args, [])
        self.assertEqual(len(self.gateway.calls), 1)

    def test_late_tool_result_is_discarded_without_lingering_execution(self):
        calls = []

        def slow(event_id):
            time.sleep(0.025)
            calls.append(event_id)
            return {"content": "late"}

        harness = self.make([tool_call(event_id=1), final()], handler=slow,
                            budget=RunBudget(timeout_seconds=0.01))
        result = self.run_harness(harness)
        self.assertEqual(result.status, "time_exhausted")
        self.assertEqual(result.content, "")
        self.assertEqual(calls, [1])
        self.assertEqual(len(self.gateway.calls), 1)

    def test_gateway_without_timeout_kwarg_is_supported(self):
        class StrictGateway:
            def complete(self, messages, *, tools=None, max_tokens=800):
                return final()

        harness = self.make([])
        result = self.run_harness(Harness(StrictGateway(), self.registry))
        self.assertEqual(result.status, "complete")

    def test_gateway_timeout_clone_is_preferred_without_changing_shared_gateway(self):
        limits = []
        calls = []

        class OriginalGateway:
            def complete(self, messages, *, tools=None, max_tokens=800):
                raise AssertionError("Original unrestricted gateway must not be called")

            def with_timeout(self, seconds):
                limits.append(seconds)
                return TightGateway()

        class TightGateway:
            def complete(self, messages, *, tools=None, max_tokens=800):
                calls.append(messages)
                return final()

        harness = self.make([])
        original = OriginalGateway()
        instance = Harness(original, self.registry, budget=RunBudget(timeout=2.0))
        result = self.run_harness(instance)
        self.assertEqual(result.status, "complete")
        self.assertIs(instance.gateway, original)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(limits), 1)
        self.assertTrue(0 < limits[0] <= 2.0)

    def test_expired_timeout_clone_never_starts_model_generation(self):
        calls = []

        class SlowCloneGateway:
            def complete(self, messages, *, tools=None, max_tokens=800):
                calls.append(1)
                return final()

            def with_timeout(self, seconds):
                time.sleep(0.025)
                return self

        harness = self.make([])
        result = self.run_harness(Harness(SlowCloneGateway(), self.registry, budget=RunBudget(timeout=0.01)))
        self.assertEqual(result.status, "time_exhausted")
        self.assertEqual(calls, [])

    def test_error_logs_do_not_echo_prompts_model_arguments_or_tool_payloads(self):
        sensitive = "super-secret credential: not logged"
        harness = self.make([RuntimeError(sensitive)])
        result = harness.run([{"role": "user", "content": sensitive}])
        self.assertEqual(result.status, "model_error")
        self.assertNotIn(sensitive, json.dumps(result.to_dict()))
        harness = self.make([tool_call(event_id=1)], handler=lambda event_id: (_ for _ in ()).throw(RuntimeError(sensitive)))
        result = self.run_harness(harness)
        self.assertEqual(result.status, "tool_error")
        self.assertNotIn(sensitive, json.dumps(result.to_dict()))

    def test_bounded_tool_payload_and_model_tool_batch(self):
        harness = self.make([tool_call(event_id=1)], handler=lambda event_id: {"large": "x" * 1000},
                            budget=RunBudget(max_tool_result_bytes=256))
        self.assertEqual(self.run_harness(harness).status, "payload_limit")
        reply = tool_call(event_id=1)
        reply["tool_calls"] *= 2
        harness = self.make([reply], budget=RunBudget(max_tool_calls=1))
        self.assertEqual(self.run_harness(harness).status, "budget_exhausted")
        self.assertEqual(self.tool_args, [])

    def test_nested_schema_array_enum_nullable_and_nonfinite_values(self):
        schema = {"type": "object", "properties": {
            "queries": {"type": "array", "maxItems": 2, "items": {"type": "object", "properties": {
                "term": {"type": "string", "enum": ["修复", "影响"], "maxLength": 2},
                "confirmed": {"type": ["boolean", "null"]}}, "required": ["term"], "additionalProperties": False}}},
            "required": ["queries"], "additionalProperties": False}
        seen = []
        registry = ToolRegistry([ToolSpec("read_queries", "Queries", schema, lambda queries: seen.append(queries) or {})])
        gateway = FakeGateway([tool_call("read_queries", queries=[{"term": "修复", "confirmed": None}]), final()])
        self.assertEqual(self.run_harness(Harness(gateway, registry)).status, "complete")
        self.assertEqual(seen, [[{"term": "修复", "confirmed": None}]])
        for arguments in ([{"term": "任意"}], [{"term": "影响", "confirmed": 1}], [{"term": "修复"}] * 3):
            gateway = FakeGateway([tool_call("read_queries", queries=arguments)])
            self.assertEqual(self.run_harness(Harness(gateway, registry)).status, "unsafe_arguments")
        self.assertEqual(self.run_harness(self.make([tool_call(event_id=float("inf"))])).status, "unsafe_arguments")

    def test_input_messages_are_copied_and_invalid_messages_fail_before_model(self):
        harness = self.make([final()])
        messages = [{"role": "user", "content": "original"}]
        original = copy.deepcopy(messages)
        harness.run(messages)
        self.assertEqual(messages, original)
        for invalid in ([], [{"role": "tool", "content": "pretend host result"}],
                        [{"role": "user", "content": "x", "tools": []}]):
            with self.assertRaises(HarnessError):
                harness.run(invalid)


if __name__ == "__main__":
    unittest.main()
