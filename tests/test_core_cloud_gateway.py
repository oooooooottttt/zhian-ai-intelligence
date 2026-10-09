"""Offline DeepSeek tests: fake credentials, DNS, TLS and HTTP only."""
import copy
import io
import json
import math
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import Mock, patch

from aicti_core import cloud_gateway as cloud
from aicti_core.cloud_gateway import (
    DeepSeekAuthenticationError, DeepSeekError, DeepSeekGateway,
    DeepSeekUnavailable,
)
from aicti_core.gateway import ModelError, ModelUnavailable


KEY = "offline-fake-dedicated-key"
MESSAGES = [{"role": "user", "content": "请解释当前证据"}]
TOOL = {"type": "function", "function": {
    "name": "get_event", "description": "Read current anonymous facts",
    "parameters": {"type": "object", "properties": {"event_id": {"type": "string"}},
                   "required": ["event_id"], "additionalProperties": False},
}}
PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]


def reply(content="事实答案", *, calls=None, reasoning=None, finish=None):
    message = {"role": "assistant", "content": content}
    if calls is not None:
        message["tool_calls"] = calls
    if reasoning is not None:
        message["reasoning_content"] = reasoning
    return {"id": "chat-offline", "object": "chat.completion", "model": cloud.OFFICIAL_MODEL,
            "choices": [{"index": 0, "finish_reason": finish or ("tool_calls" if calls else "stop"),
                         "message": message}]}


def tool_call(*, identity="call_00_exact:ID-1", arguments='{"event_id":"event_1"}', name="get_event"):
    return {"id": identity, "type": "function", "function": {"name": name, "arguments": arguments}}


class FakeResponse:
    def __init__(self, body=b"", *, status=200, headers=None, chunk_size=8192):
        if type(body) is dict:
            body = json.dumps(body, ensure_ascii=False).encode()
        self.body = io.BytesIO(body)
        self.status = status
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.chunk_size = chunk_size
        self.closed = False
        self.reads = 0

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def read1(self, limit):
        self.reads += 1
        return self.body.read(min(limit, self.chunk_size))

    def isclosed(self):
        return self.closed

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, response):
        self.sock = Mock()
        self.response = response
        self.request = Mock()
        self.closed = False
        self.connect = Mock()
        self.abort = Mock()
        self.getresponse = Mock(return_value=response)

    def close(self):
        self.closed = True


class DeepSeekGatewayTests(unittest.TestCase):
    def client(self, response=None, **kwargs):
        transport = Mock(return_value=reply() if response is None else response)
        return DeepSeekGateway(KEY, transport=transport, **kwargs), transport

    def transport(self, response, *, payload=None, connection=None):
        connection = FakeConnection(response) if connection is None else connection
        with patch.object(cloud, "_resolve_public", return_value=((socket.AF_INET, ("8.8.8.8", 443)),)) as resolve:
            with patch.object(cloud, "_PinnedHTTPSConnection", return_value=connection) as factory:
                result = cloud._post(payload or {"model": cloud.OFFICIAL_MODEL}, api_key=KEY, deadline=time.monotonic() + 5)
        return result, connection, factory, resolve

    def test_absent_key_constructs_disabled_without_network(self):
        with patch.object(cloud.os.environ, "get", return_value="") as env, patch.object(cloud, "_post") as post:
            client = DeepSeekGateway()
            self.assertFalse(client.enabled)
            self.assertFalse(client.configured)
            self.assertFalse(client.credential_configured)
            self.assertFalse(client.embedding_enabled)
            self.assertIsNone(client.embedding_model)
            self.assertFalse(hasattr(client, "embed"))
            with self.assertRaises(DeepSeekUnavailable) as failed:
                client.complete(MESSAGES)
            self.assertIsInstance(failed.exception, ModelUnavailable)
            self.assertEqual(failed.exception.code, "disabled")
            self.assertIsNone(failed.exception.__context__)
            env.assert_called_once_with("DEEPSEEK_API_KEY", "")
            post.assert_not_called()

    def test_only_dedicated_env_variable_read_and_explicit_empty_disables(self):
        with patch.object(cloud.os.environ, "get", return_value=KEY) as env:
            client = DeepSeekGateway()
            self.assertTrue(client.enabled)
            self.assertEqual(client.provider, "deepseek")
            env.assert_called_once_with("DEEPSEEK_API_KEY", "")
        with patch.object(cloud.os.environ, "get", side_effect=AssertionError("No env access")):
            self.assertFalse(DeepSeekGateway("").enabled)
            self.assertTrue(DeepSeekGateway(KEY).enabled)

    def test_public_properties_and_repr_never_include_key(self):
        client, _ = self.client()
        self.assertEqual(client.model, "deepseek-v4-pro")
        self.assertEqual(client.base_url, "https://api.deepseek.com")
        self.assertEqual(client.endpoint, "https://api.deepseek.com/chat/completions")
        self.assertEqual(client.reasoning_effort, "none")
        self.assertTrue(client.supports_json_output)
        self.assertNotIn(KEY, repr(client))
        self.assertNotIn(KEY, str(client))
        self.assertFalse(hasattr(client, "api_key"))
        self.assertFalse(hasattr(client, "__dict__"))

    def test_bad_configuration_is_sanitized_and_never_reads_credentials(self):
        options = [
            {"model": "deepseek-chat"}, {"model": "https://secret.test/model"},
            {"model": None}, {"reasoning_effort": "ultra"}, {"reasoning_effort": []},
            {"transport": "secret"},
        ]
        options += [{"timeout": value} for value in (0, -1, True, 31, 1 << 10_000, math.inf, math.nan, "secret", None)]
        with patch.object(cloud.os.environ, "get", side_effect=AssertionError("No env access")):
            for kwargs in options:
                with self.subTest(kwargs=kwargs), self.assertRaises(DeepSeekError) as failed:
                    DeepSeekGateway(KEY, **kwargs)
                self.assertEqual(failed.exception.code, "invalid_configuration")
                self.assertNotIn("secret", str(failed.exception))
            for key in (1, b"secret", "secret\r\nAuthorization:x", " secret", "secret\x00", "密钥", "x" * 513):
                with self.subTest(key=type(key)), self.assertRaises(DeepSeekError) as failed:
                    DeepSeekGateway(key)
                self.assertNotIn("secret", str(failed.exception))

    def test_timeout_cloning_tightens_and_preserves_memory_configuration(self):
        client, transport = self.client(reasoning_effort="high", timeout=20)
        with patch.object(cloud.os.environ, "get", side_effect=AssertionError("No env access")):
            bounded = client.with_timeout(0.25)
            self.assertEqual(bounded.timeout, 0.25)
            self.assertEqual(client.timeout, 20)
            self.assertEqual(client.with_timeout(30).timeout, 20)
            self.assertEqual(bounded.reasoning_effort, "high")
            self.assertTrue(bounded.enabled)
            bounded.complete(MESSAGES)
            self.assertEqual(transport.call_count, 1)
        for timeout in (0, -1, True, math.inf, math.nan, 31, 1 << 10_000, None):
            with self.assertRaises(DeepSeekError):
                client.with_timeout(timeout)
        self.assertFalse(DeepSeekGateway("").with_timeout(1).configured)

    def test_non_streaming_request_disables_thinking_and_bounds_tokens(self):
        client, transport = self.client()
        result = client.complete(MESSAGES, max_tokens=300)
        self.assertEqual(result, {"content": "事实答案", "tool_calls": [], "model": cloud.OFFICIAL_MODEL, "provider": "deepseek"})
        payload = transport.call_args.args[0]
        self.assertEqual(payload, {"model": cloud.OFFICIAL_MODEL, "messages": MESSAGES, "stream": False,
                                   "max_tokens": 300, "thinking": {"type": "disabled"}, "reasoning_effort": "none"})
        self.assertEqual(transport.call_args.kwargs["api_key"], KEY)
        self.assertGreater(transport.call_args.kwargs["deadline"], time.monotonic())
        self.assertNotIn(KEY, json.dumps(payload))

    def test_all_thinking_efforts_explicit_and_reasoning_ephemeral(self):
        for effort in ("low", "high", "max"):
            with self.subTest(effort=effort):
                client, transport = self.client(reply(reasoning="bounded private protocol state"), reasoning_effort=effort)
                result = client.complete(MESSAGES, tools=[TOOL])
                self.assertEqual(result["reasoning_content"], "bounded private protocol state")
                self.assertEqual(transport.call_args.args[0]["thinking"], {"type": "enabled"})
                self.assertEqual(transport.call_args.args[0]["reasoning_effort"], effort)
                self.assertNotIn("bounded private protocol state", repr(client))
        client, _ = self.client(reply(reasoning="provider unexpected reasoning"))
        self.assertNotIn("reasoning_content", client.complete(MESSAGES))

    def test_json_output_is_explicit_with_json_instruction(self):
        client, transport = self.client(reply('{"ok":true}'))
        messages = [{"role": "system", "content": 'Return JSON such as {"ok":true}.'}, *MESSAGES]
        client.complete(messages, response_format={"type": "json_object"})
        self.assertEqual(transport.call_args.args[0]["response_format"], {"type": "json_object"})
        transport.reset_mock()
        for format_ in ({"type": "json_schema"}, {"type": "json_object", "secret": "x"}, "json", None):
            if format_ is None:
                client.complete(MESSAGES)
                self.assertNotIn("response_format", transport.call_args.args[0])
            else:
                with self.assertRaises(DeepSeekError):
                    client.complete(messages, response_format=format_)
        with self.assertRaises(DeepSeekError):
            client.complete(MESSAGES, response_format={"type": "json_object"})
        client.complete(MESSAGES, response_format={"type": "text"})

    def test_tool_wire_normalization_preserves_call_id_and_copies_inputs(self):
        original = copy.deepcopy(TOOL)
        response = reply(None, calls=[tool_call()])
        client, transport = self.client(response)
        result = client.complete(MESSAGES, tools=[TOOL])
        self.assertEqual(result["content"], "")
        self.assertEqual(result["tool_calls"], [{"id": "call_00_exact:ID-1", "name": "get_event", "arguments": {"event_id": "event_1"}}])
        messages = [*MESSAGES,
                    {"role": "assistant", "content": "", "tool_calls": result["tool_calls"]},
                    {"role": "tool", "tool_name": "get_event", "tool_call_id": "call_00_exact:ID-1", "content": '{"ok":true}'}]
        saved = copy.deepcopy(messages)
        transport.return_value = reply()
        client.complete(messages, tools=[TOOL])
        wire = transport.call_args.args[0]
        self.assertEqual(wire["messages"][1]["tool_calls"], [tool_call()])
        self.assertEqual(wire["messages"][2], {"role": "tool", "tool_call_id": "call_00_exact:ID-1", "content": '{"ok":true}'})
        wire["tools"][0]["function"]["name"] = "mutated"
        wire["messages"][1]["tool_calls"][0]["function"]["arguments"] = "{}"
        self.assertEqual(TOOL, original)
        self.assertEqual(messages, saved)
        self.assertEqual(response["choices"][0]["message"]["tool_calls"], [tool_call()])

    def test_thinking_followup_retains_full_prior_reasoning_and_exact_ids(self):
        client, transport = self.client(reasoning_effort="high")
        messages = [
            {"role": "user", "content": "请读取"},
            {"role": "assistant", "content": "", "reasoning_content": "private reasoning 中间状态", "tool_calls": [
                {"id": "original_call-id", "function": {"name": "get_event", "arguments": {"event_id": "event_2"}}},
            ]},
            {"role": "tool", "tool_call_id": "original_call-id", "content": "{}"},
            {"role": "assistant", "content": "第一问的公开回答", "reasoning_content": "prior final internal state"},
            {"role": "user", "content": "然后呢"},
        ]
        client.complete(messages, tools=[TOOL])
        wire = transport.call_args.args[0]["messages"]
        self.assertEqual(wire[1]["reasoning_content"], messages[1]["reasoning_content"])
        self.assertEqual(wire[3]["reasoning_content"], messages[3]["reasoning_content"])
        self.assertEqual(wire[2]["tool_call_id"], "original_call-id")
        self.assertEqual(wire[1]["tool_calls"][0]["function"]["arguments"], '{"event_id":"event_2"}')
        self.assertNotIn("prior final internal state", repr(client))

    def test_missing_or_oversized_thinking_state_rejected_without_truncation(self):
        client, transport = self.client(reasoning_effort="high")
        messages = [
            {"role": "assistant", "content": "", "tool_calls": [{"id": "call_one", "name": "get_event", "arguments": {}}]},
            {"role": "tool", "tool_call_id": "call_one", "content": "{}"},
        ]
        with self.assertRaises(DeepSeekError):
            client.complete(messages)
        messages[0]["reasoning_content"] = "私" * (cloud.MAX_REASONING_BYTES // 3 + 1)
        with self.assertRaises(DeepSeekError):
            client.complete(messages)
        transport.assert_not_called()
        transport.return_value = reply(reasoning="x" * (cloud.MAX_REASONING_BYTES + 1))
        with self.assertRaises(DeepSeekError) as failed:
            client.complete(MESSAGES)
        self.assertEqual(failed.exception.code, "invalid_response")

    def test_empty_thinking_state_is_explicit_on_tool_and_final_replies(self):
        client, transport = self.client(reply(None, calls=[tool_call()]), reasoning_effort="low")
        result = client.complete(MESSAGES)
        self.assertEqual(result["reasoning_content"], "")
        transport.return_value = reply()
        self.assertEqual(client.complete(MESSAGES)["reasoning_content"], "")

    def test_invalid_tool_correlations_rejected_before_transport(self):
        assistant = {"role": "assistant", "content": "", "tool_calls": [{"id": "call_one", "name": "get_event", "arguments": {}}]}
        tool = {"role": "tool", "tool_call_id": "call_one", "content": "{}"}
        invalid = [
            [tool], [assistant], [assistant, {**tool, "tool_call_id": "other"}],
            [assistant, {**tool, "name": "other_tool"}], [assistant, tool, tool],
            [assistant, *MESSAGES, tool],
            [assistant, tool, assistant, tool],
            [{**assistant, "tool_calls": [{"name": "get_event", "arguments": {}}]}, tool],
            [assistant, {"role": "tool", "content": "{}"}],
            [assistant, {**tool, "tool_call_id": "call_one\nsecret"}],
        ]
        client, transport = self.client()
        for messages in invalid:
            with self.subTest(messages=messages), self.assertRaises(DeepSeekError):
                client.complete(messages, tools=[TOOL])
        transport.assert_not_called()

    def test_input_schema_and_byte_limits_before_transport(self):
        cyclic = {"role": "user", "content": "hello"}
        cyclic["tool_calls"] = [cyclic]
        invalid = [
            [], "secret", [{"role": "developer", "content": "secret"}],
            [{"role": "user", "content": 1}], [{"role": "user", "content": "x", "images": []}],
            [{"role": "user", "content": "x", "reasoning_content": "hidden"}],
            [{"role": "assistant", "content": "x", "tool_call_id": "call_one"}],
            [{"role": "user", "content": "x", "tool_calls": []}],
            [{"role": "user", "content": "\ud800"}], [cyclic],
            [{"role": "user", "content": "x" * (cloud.MAX_TEXT_BYTES + 1)}],
            MESSAGES * (cloud.MAX_MESSAGES + 1),
            [{"role": "user", "content": "界" * 20_000}] * 5,
        ]
        client, transport = self.client()
        for messages in invalid:
            with self.subTest(messages=type(messages)), self.assertRaises(DeepSeekError) as failed:
                client.complete(messages)
            self.assertEqual(failed.exception.code, "invalid_input")
        for max_tokens in (0, -1, True, 2049, "secret"):
            with self.assertRaises(DeepSeekError):
                client.complete(MESSAGES, max_tokens=max_tokens)
        transport.assert_not_called()

    def test_bad_tools_and_nonfinite_tool_arguments_are_rejected(self):
        client, transport = self.client()
        for tools in ({}, [TOOL, TOOL], [TOOL] * 17, [lambda: None],
                      [{"type": "function", "function": {"name": "unsafe-url", "parameters": {"type": "object"}}}],
                      [{"type": "function", "function": {**TOOL["function"], "strict": True}}]):
            with self.assertRaises(DeepSeekError):
                client.complete(MESSAGES, tools=tools)
        for args in ({"score": math.inf}, {"score": math.nan}, {"number": 1 << 300}, {"secret": "x" * 8193}):
            with self.assertRaises(DeepSeekError):
                client.complete([
                    {"role": "assistant", "content": "", "tool_calls": [{"id": "call_one", "name": "get_event", "arguments": args}]},
                    {"role": "tool", "tool_call_id": "call_one", "content": "{}"},
                ])
        transport.assert_not_called()

    def test_malformed_tool_reply_json_and_duplicates_are_rejected(self):
        bad_calls = [
            [tool_call(arguments="secret")], [tool_call(arguments="[]")], [tool_call(arguments='{"x":1,"x":2}')],
            [tool_call(arguments='{"x":NaN}')], [tool_call(arguments='{"x":Infinity}')],
            [tool_call(arguments={})], [tool_call(arguments='{"x":"' + "x" * 8192 + '"}')],
            [tool_call(name="unsafe(url)")], [tool_call(identity="secret\n")],
            [tool_call(), tool_call()], [tool_call()] * 9,
            [{"type": "other", "id": "one", "function": {"name": "get_event", "arguments": "{}"}}],
            [{"function": {"name": "get_event", "arguments": "{}"}}],
        ]
        for calls in bad_calls:
            client, _ = self.client(reply(None, calls=calls))
            with self.subTest(calls=calls), self.assertRaises(DeepSeekError) as failed:
                client.complete(MESSAGES)
            self.assertEqual(failed.exception.code, "invalid_response")
            self.assertNotIn("secret", str(failed.exception))

    def test_response_root_model_role_choice_and_content_are_checked(self):
        invalid = [
            [], {**reply(), "model": "deepseek-flash"}, {**reply(), "object": "chat.completion.chunk"},
            {**reply(), "choices": []}, {**reply(), "choices": [reply()["choices"][0]] * 2},
            {**reply(), "choices": [{**reply()["choices"][0], "index": True}]},
            {**reply(), "choices": [{**reply()["choices"][0], "message": {"role": "user", "content": "secret"}}]},
            reply(7), reply(None), reply("\ud800"), reply("x" * (cloud.MAX_CONTENT_BYTES + 1)),
            reply("x", calls=[tool_call()], finish="stop"), reply("x", calls=[], finish="tool_calls"),
            reply("x", calls="secret", finish="tool_calls"), reply("x", finish="unknown"),
            {"model": cloud.OFFICIAL_MODEL, "error": {"message": "secret"}},
        ]
        for response in invalid:
            client, _ = self.client(response)
            with self.subTest(response=type(response)), self.assertRaises(DeepSeekError) as failed:
                client.complete(MESSAGES)
            self.assertNotIn("secret", str(failed.exception))

    def test_finish_reasons_cannot_publish_partial_or_filtered_output(self):
        codes = {"length": "output_truncated", "content_filter": "content_filtered",
                 "insufficient_system_resource": "unavailable", "aborted": "unavailable"}
        for finish, code in codes.items():
            client, transport = self.client(reply('partial secret output', finish=finish))
            with self.subTest(finish=finish), self.assertRaises(DeepSeekError) as failed:
                client.complete(MESSAGES)
            self.assertEqual(failed.exception.code, code)
            self.assertNotIn("secret", str(failed.exception))
            self.assertEqual(transport.call_count, 1)

    def test_current_key_is_never_sent_in_body_or_returned_from_provider(self):
        client, transport = self.client()
        for messages in ([{"role": "user", "content": "Key: " + KEY}],
                         [{"role": "assistant", "content": "prior " + KEY}]):
            with self.assertRaises(DeepSeekError) as failed:
                client.complete(messages)
            self.assertEqual(failed.exception.code, "secret_in_payload")
            self.assertNotIn(KEY, str(failed.exception))
        transport.assert_not_called()
        for response in (reply("echo " + KEY), reply(reasoning=KEY),
                         reply(None, calls=[tool_call(arguments=json.dumps({"event_id": KEY}))]),
                         {**reply(), "provider_debug": KEY}):
            transport.return_value = response
            with self.assertRaises(DeepSeekError) as failed:
                client.complete(MESSAGES)
            self.assertEqual(failed.exception.code, "secret_in_payload")
            self.assertNotIn(KEY, str(failed.exception))
            self.assertIsNone(failed.exception.__context__)

    def test_injected_transport_failures_and_contexts_are_sanitized(self):
        for raw in (RuntimeError("server body " + KEY), OSError("URL secret"), ValueError(KEY), TimeoutError(KEY)):
            transport = Mock(side_effect=raw)
            client = DeepSeekGateway(KEY, transport=transport)
            with self.assertRaises(DeepSeekError) as failed:
                client.complete(MESSAGES)
            self.assertEqual(failed.exception.code, "timeout" if isinstance(raw, TimeoutError) else "unavailable")
            self.assertIsNone(failed.exception.__context__)
            self.assertIsNone(failed.exception.__cause__)
            self.assertNotIn(KEY, str(failed.exception))
            self.assertEqual(transport.call_count, 1)

    def test_deadline_applies_before_and_after_injected_transport(self):
        client, transport = self.client(timeout=1)
        with patch.object(cloud.time, "monotonic", side_effect=[10, 10.25, 11.01]):
            with self.assertRaises(DeepSeekUnavailable) as failed:
                client.complete(MESSAGES)
        self.assertEqual(failed.exception.code, "timeout")
        self.assertEqual(transport.call_args.kwargs["deadline"], 11)
        transport.reset_mock()
        with patch.object(cloud.time, "monotonic", side_effect=[10, 11.01]):
            with self.assertRaises(DeepSeekUnavailable):
                client.complete(MESSAGES)
        transport.assert_not_called()

    def test_response_transport_bounds_even_for_injected_transport(self):
        response = reply()
        response["oversized_extra"] = ["x" * 60_000] * 36
        client, _ = self.client(response)
        with self.assertRaises(DeepSeekError) as failed:
            client.complete(MESSAGES)
        self.assertEqual(failed.exception.code, "response_too_large")

    def test_dns_accepts_public_numeric_addresses_and_deduplicates(self):
        records = PUBLIC * 2 + [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:4860:4860::8888", 443, 0, 0))]
        with patch.object(cloud.socket, "getaddrinfo", return_value=records) as dns:
            result = cloud._resolve_public(time.monotonic() + 1)
        self.assertEqual(result, ((socket.AF_INET, ("8.8.8.8", 443)),
                                  (socket.AF_INET6, ("2001:4860:4860::8888", 443, 0, 0))))
        dns.assert_called_once_with("api.deepseek.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def test_dns_rejects_any_private_mixed_multicast_reserved_or_scoped_address(self):
        for address in ("127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.0.1", "169.254.169.254",
                        "100.64.0.1", "0.0.0.0", "192.0.2.1", "224.0.0.1", "240.1.2.3",
                        "::", "::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "fe80::1%en0"):
            ipv6 = ":" in address
            item = (socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                    (address, 443, 0, 0) if ipv6 else (address, 443))
            with self.subTest(address=address), patch.object(cloud.socket, "getaddrinfo", return_value=PUBLIC + [item]):
                with self.assertRaises(DeepSeekError) as failed:
                    cloud._resolve_public(time.monotonic() + 1)
            self.assertEqual(failed.exception.code, "unsafe_destination")

    def test_dns_shape_port_family_and_result_count_are_bounded(self):
        invalid = [[], PUBLIC * 33, ["secret"], [(socket.AF_UNIX, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
                   [(socket.AF_INET, socket.SOCK_DGRAM, 6, "", ("8.8.8.8", 443))],
                   [(socket.AF_INET, socket.SOCK_STREAM, 17, "", ("8.8.8.8", 443))],
                   [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 444))],
                   [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443))],
                   [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443, 0, 1))]]
        for records in invalid:
            with self.subTest(records=records), patch.object(cloud.socket, "getaddrinfo", return_value=records):
                with self.assertRaises(DeepSeekError) as failed:
                    cloud._resolve_public(time.monotonic() + 1)
            self.assertEqual(failed.exception.code, "unsafe_destination")

    def test_dns_failure_and_stall_return_sanitized_bounded_errors(self):
        with patch.object(cloud.socket, "getaddrinfo", side_effect=socket.gaierror(KEY)):
            with self.assertRaises(DeepSeekUnavailable) as failed:
                cloud._resolve_public(time.monotonic() + 1)
        self.assertEqual(failed.exception.code, "unavailable")
        self.assertIsNone(failed.exception.__context__)
        self.assertNotIn(KEY, str(failed.exception))
        release = threading.Event()

        def blocked_dns(*_):
            release.wait(1)
            return PUBLIC

        started = time.monotonic()
        try:
            with patch.object(cloud.socket, "getaddrinfo", side_effect=blocked_dns):
                with self.assertRaises(DeepSeekUnavailable) as failed:
                    cloud._resolve_public(time.monotonic() + 0.02)
            self.assertEqual(failed.exception.code, "timeout")
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            release.set()

    def test_pinned_tls_connect_uses_public_numeric_ip_and_official_sni(self):
        raw, secured, context = Mock(), Mock(), Mock()
        context.wrap_socket.return_value = secured
        addresses = ((socket.AF_INET, ("8.8.8.8", 443)),)
        with patch.object(cloud.ssl, "create_default_context", return_value=context) as tls:
            connection = cloud._PinnedHTTPSConnection(addresses, time.monotonic() + 3)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        with patch.object(cloud.socket, "socket", return_value=raw) as sockets:
            with patch.object(cloud.socket, "getaddrinfo", side_effect=AssertionError("No second DNS lookup")):
                connection.connect()
        sockets.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw.connect.assert_called_once_with(("8.8.8.8", 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname="api.deepseek.com", do_handshake_on_connect=False)
        secured.do_handshake.assert_called_once_with()
        self.assertIs(connection.sock, secured)
        connection.close()
        secured.close.assert_called()
        tls.assert_called_once_with()

    def test_certificate_failure_does_not_fallback_to_another_address(self):
        raw, context = Mock(), Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("secret cert")
        addresses = ((socket.AF_INET, ("8.8.8.8", 443)), (socket.AF_INET, ("1.1.1.1", 443)))
        with patch.object(cloud.ssl, "create_default_context", return_value=context):
            connection = cloud._PinnedHTTPSConnection(addresses, time.monotonic() + 3)
        with patch.object(cloud.socket, "socket", return_value=raw) as sockets:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connection.connect()
        self.assertEqual(sockets.call_count, 1)
        raw.close.assert_called()

    def test_network_connect_failover_is_pinned_without_new_dns(self):
        first, second, secured, context = Mock(), Mock(), Mock(), Mock()
        first.connect.side_effect = OSError(KEY)
        context.wrap_socket.return_value = secured
        addresses = ((socket.AF_INET, ("8.8.8.8", 443)), (socket.AF_INET, ("1.1.1.1", 443)))
        with patch.object(cloud.ssl, "create_default_context", return_value=context):
            connection = cloud._PinnedHTTPSConnection(addresses, time.monotonic() + 3)
        with patch.object(cloud.socket, "socket", side_effect=[first, second]):
            connection.connect()
        first.close.assert_called()
        second.connect.assert_called_once_with(("1.1.1.1", 443))
        connection.close()

    def test_http_request_destination_headers_and_cleanup(self):
        response = FakeResponse(reply())
        result, connection, factory, resolve = self.transport(response)
        self.assertEqual(result, reply())
        self.assertEqual(factory.call_args.args[0], ((socket.AF_INET, ("8.8.8.8", 443)),))
        self.assertEqual(connection.request.call_args.args[:2], ("POST", "/chat/completions"))
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Bearer " + KEY)
        self.assertEqual(headers["Host"], "api.deepseek.com")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["Connection"], "close")
        self.assertNotIn(KEY.encode(), connection.request.call_args.kwargs["body"])
        self.assertTrue(connection.closed)
        self.assertTrue(response.closed)
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(connection.request.call_count, 1)

    def test_connection_close_response_can_clear_connection_socket(self):
        response = FakeResponse(reply())
        connection = FakeConnection(response)

        def transferred_socket():
            connection.sock = None
            return response

        connection.getresponse.side_effect = transferred_socket
        result, _, _, _ = self.transport(response, connection=connection)
        self.assertEqual(result, reply())

    def test_http_errors_are_typed_without_reading_error_body_or_following_redirects(self):
        statuses = {301: "redirect", 302: "redirect", 307: "redirect", 308: "redirect",
                    401: "authentication", 403: "authentication", 402: "quota_exhausted",
                    429: "rate_limited", 408: "timeout", 504: "timeout",
                    500: "unavailable", 502: "unavailable", 503: "unavailable", 400: "http_error", 404: "http_error"}
        for status, code in statuses.items():
            response = FakeResponse(KEY.encode(), status=status, headers={"Location": "https://secret@127.0.0.1/", "Retry-After": "300"})
            connection = FakeConnection(response)
            with self.subTest(status=status), self.assertRaises(DeepSeekError) as failed:
                self.transport(response, connection=connection)
            self.assertEqual(failed.exception.code, code)
            self.assertNotIn(KEY, str(failed.exception))
            self.assertIsNone(failed.exception.__context__)
            self.assertEqual(response.reads, 0)
            self.assertEqual(connection.request.call_count, 1)
            self.assertTrue(response.closed)
            self.assertTrue(connection.closed)
            if status in (401, 403):
                self.assertIsInstance(failed.exception, DeepSeekAuthenticationError)
            if status == 429:
                self.assertEqual(failed.exception.retry_after, 60)
                self.assertIsInstance(failed.exception, ModelUnavailable)

    def test_rate_limit_retry_after_is_sanitized_without_automatic_retry(self):
        for header, expected in (("2", 2), ("999999", 60), ("-1", None), (KEY, None), ("Wed, 01 Jan", None)):
            response = FakeResponse(status=429, headers={"Retry-After": header})
            with self.assertRaises(DeepSeekUnavailable) as failed:
                self.transport(response)
            self.assertEqual(failed.exception.retry_after, expected)
            self.assertNotIn(KEY, str(failed.exception))

    def test_http_encoding_type_lengths_and_response_bytes_are_bounded(self):
        cases = [
            FakeResponse(reply(), headers={"Content-Type": "text/html"}),
            FakeResponse(reply(), headers={"Content-Encoding": "gzip"}),
            FakeResponse(reply(), headers={"Content-Length": "secret"}),
            FakeResponse(reply(), headers={"Content-Length": "1"}),
            FakeResponse(reply(), headers={"Content-Length": str(cloud.MAX_RESPONSE_BYTES + 1)}),
            FakeResponse(b"x" * (cloud.MAX_RESPONSE_BYTES + 1)),
        ]
        for response in cases:
            with self.subTest(headers=response.headers), self.assertRaises(DeepSeekError) as failed:
                self.transport(response)
            self.assertIn(failed.exception.code, ("invalid_response", "response_too_large"))
            self.assertTrue(response.closed)

    def test_strict_response_json_rejects_duplicates_nonfinite_and_wrong_shape(self):
        for body in (b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'{secret',
                     b'{"error":{"message":"secret"}}'):
            response = FakeResponse(body)
            with self.subTest(body=body), self.assertRaises(DeepSeekError) as failed:
                self.transport(response)
            self.assertNotIn("secret", str(failed.exception))
            self.assertIsNone(failed.exception.__context__)

    def test_http_transport_timeout_provider_errors_and_cleanup_are_safe(self):
        for raw in (socket.timeout(KEY), OSError(KEY), http_error()):
            response = FakeResponse(reply())
            connection = FakeConnection(response)
            connection.getresponse.side_effect = raw
            with self.assertRaises(DeepSeekError) as failed:
                self.transport(response, connection=connection)
            self.assertEqual(failed.exception.code, "timeout" if isinstance(raw, TimeoutError) else "unavailable")
            self.assertNotIn(KEY, str(failed.exception))
            self.assertIsNone(failed.exception.__context__)
            self.assertTrue(connection.closed)

    def test_header_budget_also_bounds_chunk_trailers(self):
        from aicti_core.gateway import _HeaderBudgetFile, MAX_HTTP_HEADER_BYTES
        stream = _HeaderBudgetFile(io.BytesIO(b"x" * (MAX_HTTP_HEADER_BYTES + 1)))
        with self.assertRaises(ModelError) as failed:
            stream.readline()
        self.assertEqual(failed.exception.code, "response_too_large")


def http_error():
    import http.client
    return http.client.HTTPException("provider secret " + KEY)


if __name__ == "__main__":
    unittest.main()
