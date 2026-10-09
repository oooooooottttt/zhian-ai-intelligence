"""Offline tests only: no model server, download, credentials, or network."""
import io
import json
import math
import socket
import unittest
from unittest.mock import Mock, patch

from aicti_core import gateway
from aicti_core.gateway import ModelError, ModelGateway, ModelUnavailable


LOCAL_META = {"details": {"format": "gguf"}, "model_info": {"general.architecture": "llama"}}
CHAT = {"model": "local:latest", "done": True, "message": {"role": "assistant", "content": "事实答案"}}
TOOL = {"type": "function", "function": {
    "name": "get_event", "description": "Read a current event",
    "parameters": {"type": "object", "properties": {"event_id": {"type": "integer"}}, "required": ["event_id"], "additionalProperties": False},
}}


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
        self.getresponse = Mock(return_value=response)

    def connect(self):
        pass

    def close(self):
        self.closed = True


class ModelGatewayTests(unittest.TestCase):
    def configured(self):
        return ModelGateway(model="local")

    def mocked_complete(self, response=CHAT, **kwargs):
        mocked = patch.object(gateway, "_post", side_effect=[LOCAL_META, response])
        with mocked as post:
            result = self.configured().complete([{"role": "user", "content": "请解释"}], **kwargs)
        return result, post

    def transport(self, response, payload=None):
        connection = FakeConnection(response)
        with patch.object(gateway, "_LoopbackConnection", return_value=connection) as factory:
            value = gateway._post("/api/chat", payload or {"model": "local"}, gateway.time.monotonic() + 5)
        return value, connection, factory

    def test_default_disabled_and_no_network(self):
        client = ModelGateway()
        self.assertFalse(client.enabled)
        self.assertFalse(client.embedding_enabled)
        with patch.object(gateway, "_post") as post:
            with self.assertRaises(ModelUnavailable) as failure:
                client.complete([{"role": "user", "content": "secret"}])
            self.assertEqual(failure.exception.code, "disabled")
            with self.assertRaises(ModelUnavailable):
                client.embed(["secret"])
            post.assert_not_called()

    def test_url_allowlist_no_credentials_paths_redirect_targets_or_alternate_ports(self):
        for url in (
            "https://localhost:11434", "http://localhost", "http://localhost:11435",
            "http://localhost:11434/api/chat", "http://localhost:11434/?x=secret",
            "http://localhost:11434/#secret", "http://secret@localhost:11434",
            "http://127.0.0.2:11434", "http://[::1]:11434", "http://ollama.com:11434",
            "http://localhost.evil:11434", "http://localhost:11434\\@evil.test",
            "http://127.1:11434", "http://2130706433:11434", "file:///tmp/model",
            "http://localhost.:11434", " http://localhost:11434", "http://LOCALHOST:11434",
        ):
            with self.subTest(url=url), self.assertRaises(ModelError) as failure:
                ModelGateway(url, "local")
            self.assertNotIn("secret", str(failure.exception))
        for url in gateway._BASE_URLS:
            self.assertEqual(ModelGateway(url, "local").base_url, "http://127.0.0.1:11434")

    def test_bad_timeout_and_model_configuration(self):
        for value in (0, -1, True, 61, 1 << 10_000, math.inf, math.nan, "secret", None):
            with self.subTest(timeout=value), self.assertRaises(ModelError):
                ModelGateway(model="local", timeout=value)
        for model in ("", "https://evil.test/model", "../secret", "local\nsecret", "gemma:cloud", "x:31b-cloud", "a" * 129, {}, 1):
            with self.subTest(model=model), self.assertRaises(ModelError) as failure:
                ModelGateway(model=model)
            self.assertNotIn("secret", str(failure.exception))

    def test_chat_request_uses_shared_deadline_and_non_streaming_token_limit(self):
        result, post = self.mocked_complete(max_tokens=300)
        self.assertEqual(result, {"content": "事实答案", "tool_calls": [], "model": "local:latest"})
        self.assertEqual(post.call_args_list[0].args[:2], ("/api/show", {"model": "local"}))
        payload = post.call_args_list[1].args[1]
        self.assertEqual(post.call_args_list[1].args[0], "/api/chat")
        self.assertFalse(payload["stream"])
        self.assertEqual(payload["options"], {"num_predict": 300})
        self.assertEqual(post.call_args_list[0].args[2], post.call_args_list[1].args[2])

    def test_tool_feedback_wire_normalization_and_no_caller_mutation(self):
        messages = [
            {"role": "assistant", "content": "", "tool_calls": [{"name": "get_event", "arguments": {"event_id": 7}}]},
            {"role": "tool", "name": "get_event", "content": '{"facts":[]}', "tool_call_id": "host-call-1"},
        ]
        reply = {"model": "local", "done": True, "message": {"content": "", "tool_calls": [
            {"type": "function", "function": {"name": "get_event", "index": 0, "arguments": {"event_id": 9}}},
        ]}}
        with patch.object(gateway, "_post", side_effect=[LOCAL_META, reply]) as post:
            result = self.configured().complete(messages, tools=[TOOL])
        self.assertEqual(result["tool_calls"], [{"name": "get_event", "arguments": {"event_id": 9}}])
        wire = post.call_args_list[1].args[1]
        self.assertEqual(wire["messages"][0]["tool_calls"][0], {"type": "function", "function": {"name": "get_event", "arguments": {"event_id": 7}}})
        self.assertEqual(wire["messages"][1], {"role": "tool", "tool_name": "get_event", "content": '{"facts":[]}'})
        self.assertEqual(wire["tools"], [TOOL])
        wire["tools"][0]["function"]["name"] = "changed"
        self.assertEqual(TOOL["function"]["name"], "get_event")
        self.assertIn("name", messages[1])

    def test_invalid_input_is_rejected_before_network(self):
        cyclic = {"role": "user", "content": "hello"}
        cyclic["tool_calls"] = [cyclic]
        invalid_messages = (
            [], "secret", [{"role": "developer", "content": "secret"}],
            [{"role": "user", "content": 1}], [{"role": "user", "content": "secret", "images": ["base64"]}],
            [{"role": "user", "content": "secret", "tool_calls": []}],
            [{"role": "tool", "content": "secret", "tool_name": "../unsafe"}],
            [{"role": "assistant", "tool_calls": [{"name": "get_event", "arguments": "{}"}]}],
            [{"role": "user", "content": "x" * (gateway.MAX_TEXT_BYTES + 1)}],
            [{"role": "user", "content": "\ud800"}], [cyclic],
            [{"role": "user", "content": "secret"}] * (gateway.MAX_MESSAGES + 1),
        )
        with patch.object(gateway, "_post") as post:
            for messages in invalid_messages:
                with self.subTest(messages=type(messages)), self.assertRaises(ModelError):
                    self.configured().complete(messages)
            for token_limit in (0, True, -1, 2049, "secret"):
                with self.assertRaises(ModelError):
                    self.configured().complete([{"role": "user", "content": "secret"}], max_tokens=token_limit)
            post.assert_not_called()

    def test_request_byte_budget_and_nested_json_limits(self):
        messages = [{"role": "user", "content": "界" * 20_000}] * 5
        with patch.object(gateway, "_post") as post:
            with self.assertRaises(ModelError):
                self.configured().complete(messages)
            post.assert_not_called()
        too_deep = {}
        for _ in range(gateway.MAX_JSON_DEPTH + 1):
            too_deep = {"nested": too_deep}
        for arguments in ({"score": math.nan}, {"score": math.inf}, too_deep, {"integer": 1 << 300}):
            with self.assertRaises(ModelError):
                gateway._calls([{"name": "get_event", "arguments": arguments}], code="invalid_input")

    def test_malformed_tool_declarations(self):
        for tools in ({}, [TOOL, TOOL], [{"type": "function", "function": {"name": "unsafe-url", "parameters": {"type": "object"}}}],
                      [{"type": "function", "function": {"name": "get_event", "parameters": {"type": "string"}}}],
                      [TOOL] * (gateway.MAX_TOOLS + 1), [lambda: None]):
            with patch.object(gateway, "_post") as post, self.assertRaises(ModelError):
                self.configured().complete([{"role": "user", "content": "hello"}], tools=tools)
            post.assert_not_called()

    def test_malformed_chat_reply(self):
        replies = (
            {**CHAT, "done": False}, {**CHAT, "model": "another"}, {**CHAT, "model": "https://secret.test"},
            {**CHAT, "message": []}, {**CHAT, "message": {"content": 5}},
            {**CHAT, "message": {"role": "user", "content": "secret"}},
            {**CHAT, "message": {"content": "", "tool_calls": None}},
            {**CHAT, "message": {"content": "", "tool_calls": [{"function": {"name": "get_event", "arguments": "secret"}}]}},
            {**CHAT, "message": {"content": "", "tool_calls": [{"function": {"name": "unsafe(url)", "arguments": {}}}]}},
            {**CHAT, "message": {"content": "", "tool_calls": [{"name": "get_event", "arguments": {}}] * 9}},
        )
        for reply in replies:
            with self.subTest(reply=reply), patch.object(gateway, "_post", side_effect=[LOCAL_META, reply]), self.assertRaises(ModelError) as failure:
                self.configured().complete([{"role": "user", "content": "secret"}])
            self.assertNotIn("secret", str(failure.exception))

    def test_preflight_rejects_remote_metadata_before_prompt(self):
        for metadata in (
            {"remote_host": "https://secret.test", "details": {"format": "gguf"}},
            {"remote_model": "secret", "details": {"format": "gguf"}},
            {"details": {}}, {"details": {"format": "remote"}}, {},
        ):
            # Exercise _decode as production does, not just the test stub.
            response = FakeResponse(metadata)
            connection = FakeConnection(response)
            with patch.object(gateway, "_LoopbackConnection", return_value=connection) as factory, self.assertRaises(ModelError):
                self.configured().complete([{"role": "user", "content": "secret"}])
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(connection.request.call_args.args[1], "/api/show")
            self.assertNotIn(b"secret", connection.request.call_args.kwargs["body"])

    def test_embedding_requires_explicit_profile_preserving_chat(self):
        original = self.configured()
        client = original.with_embedding_model("embed-model")
        self.assertEqual(client.model, original.model)
        self.assertEqual(client.embedding_model, "embed-model")
        self.assertTrue(client.embedding_enabled)
        self.assertFalse(original.embedding_enabled)
        with self.assertRaises(ModelUnavailable):
            original.embed(["hello"])
        response = {"model": "embed-model", "embeddings": [[0.2, 1], [-0.3, 0.5]]}
        with patch.object(gateway, "_post", side_effect=[LOCAL_META, response]) as post:
            self.assertEqual(client.embed(["first", "second"]), [[0.2, 1.0], [-0.3, 0.5]])
        self.assertEqual(post.call_args_list[0].args[1], {"model": "embed-model"})
        self.assertEqual(post.call_args_list[1].args[0], "/api/embed")
        self.assertEqual(post.call_args_list[1].args[1], {"model": "embed-model", "input": ["first", "second"], "truncate": False})
        self.assertEqual(post.call_args_list[0].args[2], post.call_args_list[1].args[2])
        self.assertFalse(ModelGateway().with_embedding_model("embed-model").enabled)

    def test_host_can_tighten_timeout_preserving_independent_profiles(self):
        original = ModelGateway(model="local", timeout=15).with_embedding_model("embed-model")
        bounded = original.with_timeout(0.5)
        self.assertEqual(bounded.timeout, 0.5)
        self.assertEqual(original.timeout, 15)
        self.assertEqual(bounded.model, "local")
        self.assertEqual(bounded.embedding_model, "embed-model")
        self.assertEqual(original.with_timeout(60).timeout, 15)
        for value in (0, -1, math.nan, math.inf, True, 1 << 10_000):
            with self.assertRaises(ModelError):
                original.with_timeout(value)

    def test_invalid_embedding_requests_and_vectors(self):
        client = ModelGateway().with_embedding_model("embed-model")
        for texts in ([], "secret", [""], [None], ["a"] * 33, ["a" * 65_537]):
            with patch.object(gateway, "_post") as post, self.assertRaises(ModelError):
                client.embed(texts)
            post.assert_not_called()
        for vectors in ([], [[]], [[0.0, 0.0]], [[True]], [[math.inf]], [[math.nan]], [[1e308]], [[1.0] * 4_097], [[1], [1]], "secret"):
            with patch.object(gateway, "_post", side_effect=[LOCAL_META, {"model": "embed-model", "embeddings": vectors}]), self.assertRaises(ModelError):
                client.embed(["hello"])
        with patch.object(gateway, "_post", side_effect=[LOCAL_META, {"model": "embed-model", "embeddings": [[1], [1, 2]]}]), self.assertRaises(ModelError):
            client.embed(["first", "second"])

    def test_transport_fixed_destination_identity_encoding_and_cleanup(self):
        response = FakeResponse(CHAT)
        result, connection, factory = self.transport(response)
        self.assertEqual(result, CHAT)
        self.assertEqual(factory.call_args.args, ("127.0.0.1", 11434))
        self.assertGreater(factory.call_args.kwargs["timeout"], 0)
        self.assertEqual(connection.request.call_args.args, ("POST", "/api/chat"))
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertNotIn("Authorization", headers)
        self.assertTrue(connection.closed)
        self.assertTrue(response.closed)
        connection.sock.close.assert_called_once()

    def test_real_connection_uses_numeric_af_inet_socket_without_dns(self):
        local_socket = Mock()
        with patch.object(gateway.socket, "socket", return_value=local_socket) as factory, patch.object(gateway.socket, "getaddrinfo") as dns:
            connection = gateway._LoopbackConnection("ignored.test", 9999, timeout=2)
            connection.connect()
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        local_socket.connect.assert_called_once_with(("127.0.0.1", 11434))
        local_socket.settimeout.assert_called_once_with(2)
        dns.assert_not_called()

    def test_complete_transport_with_real_parser_and_content_length_socket_ownership(self):
        # A socketpair is local IPC, with no listening service or IP network.
        client_socket, peer_socket = socket.socketpair()
        body = json.dumps(CHAT, ensure_ascii=False).encode()
        wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        peer_socket.sendall(wire)
        peer_socket.shutdown(socket.SHUT_WR)
        connection = gateway._LoopbackConnection("127.0.0.1", 11434, timeout=5)
        try:
            with patch.object(connection, "connect", side_effect=lambda: setattr(connection, "sock", client_socket)), patch.object(gateway, "_LoopbackConnection", return_value=connection):
                self.assertEqual(gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5), CHAT)
            self.assertEqual(client_socket.fileno(), -1)
        finally:
            client_socket.close()
            peer_socket.close()

    def test_transport_does_not_follow_redirect_or_read_error_body(self):
        for status in (301, 302, 303, 307, 308, 401, 403, 500):
            response = FakeResponse(b"secret", status=status, headers={"Location": "https://secret.test"})
            connection = FakeConnection(response)
            with patch.object(gateway, "_LoopbackConnection", return_value=connection) as factory, self.assertRaises(ModelError) as failure:
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(response.reads, 0)
            self.assertNotIn("secret", str(failure.exception))
            self.assertTrue(connection.closed)

    def test_transport_rate_limit_failure_and_bounded_retry_after(self):
        for retry_header, expected in (("12", 12), ("99999", 60), ("secret", None), ("-5", None)):
            response = FakeResponse(b"secret", status=429, headers={"Retry-After": retry_header})
            connection = FakeConnection(response)
            with patch.object(gateway, "_LoopbackConnection", return_value=connection), self.assertRaises(ModelUnavailable) as failure:
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)
            self.assertEqual(failure.exception.code, "rate_limited")
            self.assertEqual(failure.exception.retry_after, expected)
            self.assertEqual(response.reads, 0)
        for status in (404, 502, 503, 504):
            with patch.object(gateway, "_LoopbackConnection", return_value=FakeConnection(FakeResponse(status=status))), self.assertRaises(ModelUnavailable):
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)

    def test_timeout_and_connection_errors_are_sanitized(self):
        for error in (socket.timeout("secret"), ConnectionRefusedError("secret"), OSError("secret")):
            connection = FakeConnection(FakeResponse())
            connection.getresponse.side_effect = error
            with patch.object(gateway, "_LoopbackConnection", return_value=connection), self.assertRaises(ModelUnavailable) as failure:
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)
            self.assertNotIn("secret", str(failure.exception))
            self.assertTrue(connection.closed)
        with patch.object(gateway, "_LoopbackConnection") as factory, self.assertRaises(ModelUnavailable) as failure:
            gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() - 1)
        self.assertEqual(failure.exception.code, "timeout")
        factory.assert_not_called()

    def test_slow_trickle_hits_total_deadline_and_still_closes(self):
        response = FakeResponse(CHAT, chunk_size=1)
        connection = FakeConnection(response)
        # No real wait: each clock observation advances by one second.
        with patch.object(gateway.time, "monotonic", side_effect=range(100)), patch.object(gateway, "_LoopbackConnection", return_value=connection), self.assertRaises(ModelUnavailable) as failure:
            gateway._post("/api/chat", {"model": "local"}, 7)
        self.assertEqual(failure.exception.code, "timeout")
        self.assertLess(response.reads, 7)
        self.assertTrue(response.closed)

    def test_watchdog_shutdown_keeps_socket_reference_after_header_transfer(self):
        response = FakeResponse(CHAT)
        connection = FakeConnection(response)
        with patch.object(gateway.threading, "Timer") as timer:
            with patch.object(gateway, "_LoopbackConnection", return_value=connection):
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)
        timer.return_value.start.assert_called_once()
        timer.return_value.cancel.assert_called_once()
        self.assertTrue(timer.return_value.daemon)
        callback = timer.call_args.args[1]
        callback(*timer.call_args.args[2])
        connection.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)

    def test_large_declared_and_incrementally_large_body(self):
        for response in (
            FakeResponse(b"secret", headers={"Content-Length": str(gateway.MAX_RESPONSE_BYTES + 1)}),
            FakeResponse(b"x" * (gateway.MAX_RESPONSE_BYTES + 1)),
        ):
            connection = FakeConnection(response)
            with patch.object(gateway, "_LoopbackConnection", return_value=connection), self.assertRaises(ModelError) as failure:
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)
            self.assertEqual(failure.exception.code, "response_too_large")
            self.assertTrue(response.closed)

    def test_transport_malformed_json_headers_shapes_and_nonfinite_values(self):
        for response in (
            FakeResponse(b"{secret"), FakeResponse(b"[]"), FakeResponse(b"\xff"),
            FakeResponse(b'{"x":1,"x":2}'), FakeResponse(b'{"x":NaN}'), FakeResponse(b'{"x":1e999}'),
            FakeResponse({"error": "secret"}), FakeResponse(CHAT, headers={"Content-Type": "text/html"}),
            FakeResponse(CHAT, headers={"Content-Encoding": "gzip"}),
            FakeResponse(CHAT, headers={"Content-Length": "-1"}),
            FakeResponse(CHAT, headers={"Content-Length": "1, 2"}),
            FakeResponse(CHAT, headers={"Content-Length": "9999"}),
        ):
            connection = FakeConnection(response)
            with patch.object(gateway, "_LoopbackConnection", return_value=connection), self.assertRaises(ModelError) as failure:
                gateway._post("/api/chat", {"model": "local"}, gateway.time.monotonic() + 5)
            self.assertNotIn("secret", str(failure.exception))

    def test_real_http_response_header_budget_and_chunked_parsing(self):
        class MemorySocket:
            def __init__(self, wire):
                self.wire = wire

            def makefile(self, mode):
                return io.BytesIO(self.wire)

        wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"x\":1}\r\n0\r\n\r\n"
        response = gateway._BoundedHTTPResponse(MemorySocket(wire))
        response.begin()
        self.assertEqual(response.read1(8192), b'{"x":1}')
        self.assertEqual(response.read1(8192), b"")
        giant = b"HTTP/1.1 200 OK\r\nX-Secret: " + b"a" * gateway.MAX_HTTP_HEADER_BYTES + b"\r\n\r\n"
        response = gateway._BoundedHTTPResponse(MemorySocket(giant))
        with self.assertRaises(ModelError) as failure:
            response.begin()
        self.assertEqual(failure.exception.code, "response_too_large")


if __name__ == "__main__":
    unittest.main()
