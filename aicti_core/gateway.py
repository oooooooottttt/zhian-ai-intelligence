"""Bounded, opt-in local Ollama transport; no model installation or startup.

Protocol references (checked 2026-10-03):
https://docs.ollama.com/api/chat
https://docs.ollama.com/api/embed
https://docs.ollama.com/capabilities/tool-calling
https://github.com/ollama/ollama/blob/main/api/types.go

A model-only /api/show check precedes every inference request because a local
Ollama daemon can relay cloud models. Remote metadata and known cloud names are
refused. The daemon remains a trusted local administrator boundary: a malicious
daemon, or one changing a model between inspection and use, cannot be attested
by this client. Operators must also disable cloud features in the daemon.
"""
from __future__ import annotations

import http.client
import json
import math
import re
import socket
import threading
import time
from typing import Any

MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 2_097_152
MAX_HTTP_HEADER_BYTES = 16_384
MAX_MESSAGES = 64
MAX_TEXT_BYTES = 65_536
MAX_TOOLS = 16
MAX_TOOL_CALLS = 8
MAX_EMBED_TEXTS = 32
MAX_EMBED_DIMENSIONS = 4_096
MAX_EMBED_COMPONENT = 1_000_000.0
MAX_JSON_NODES = 150_000
MAX_JSON_DEPTH = 16
MAX_TOKENS = 2_048

_BASE_URLS = frozenset({
    "http://localhost:11434", "http://localhost:11434/",
    "http://127.0.0.1:11434", "http://127.0.0.1:11434/",
})
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?(?::[A-Za-z0-9][A-Za-z0-9._-]*)?\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_CLOUD = re.compile(r"(?:^|[-_:])cloud(?:$|[-_:])", re.I)
_ERROR_MESSAGES = {
    "disabled": "Local model inference is disabled.",
    "embedding_disabled": "Local semantic retrieval is disabled.",
    "invalid_configuration": "Invalid local model configuration.",
    "invalid_input": "Invalid or oversized model request.",
    "unavailable": "Local model service is unavailable.",
    "timeout": "Local model request exceeded its deadline.",
    "rate_limited": "Local model service is rate limited.",
    "remote_model": "Remote model inference is not permitted.",
    "local_model_unverified": "Local model metadata could not be verified.",
    "http_error": "Local model service rejected the request.",
    "redirect": "Model service redirects are not permitted.",
    "invalid_response": "Invalid model service response.",
    "response_too_large": "Model service response exceeded its size limit.",
}


class ModelError(Exception):
    """Safe diagnostic: never carries a request, server body, URL, or secret."""

    def __init__(self, code: str = "invalid_response", *, retry_after: int | None = None):
        self.code = code if code in _ERROR_MESSAGES else "invalid_response"
        self.retry_after = retry_after if type(retry_after) is int and 0 <= retry_after <= 60 else None
        super().__init__(_ERROR_MESSAGES[self.code])


class ModelUnavailable(ModelError):
    """Disabled, unavailable, throttled, or timed-out inference."""

    def __init__(self, code: str = "unavailable", *, retry_after: int | None = None):
        super().__init__(code, retry_after=retry_after)


def _model_name(value: Any) -> str:
    if type(value) is not str or len(value) > 128 or not _MODEL.fullmatch(value):
        raise ModelError("invalid_configuration") from None
    if _CLOUD.search(value):
        raise ModelError("remote_model") from None
    return value


def _json_shape(value: Any, *, code: str) -> None:
    """Bound depth, nodes, strings and finite numbers before serialization/use."""
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ModelError(code)
        kind = type(item)
        if item is None or kind is bool:
            return
        if kind is str:
            try:
                if len(item) > MAX_TEXT_BYTES or len(item.encode("utf-8")) > MAX_TEXT_BYTES:
                    raise ModelError(code)
            except UnicodeError:
                raise ModelError(code) from None
        elif kind is int:
            if item.bit_length() > 256:
                raise ModelError(code)
        elif kind is float:
            if not math.isfinite(item):
                raise ModelError(code)
        elif kind in (dict, list):
            if id(item) in active or len(item) > MAX_JSON_NODES:
                raise ModelError(code)
            active.add(id(item))
            try:
                if kind is dict:
                    for key, val in item.items():
                        if type(key) is not str:
                            raise ModelError(code)
                        visit(key, depth + 1)
                        visit(val, depth + 1)
                else:
                    for val in item:
                        visit(val, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise ModelError(code)

    visit(value, 0)


def _encode(value: Any) -> bytes:
    _json_shape(value, code="invalid_input")
    try:
        body = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ModelError("invalid_input") from None
    if len(body) > MAX_REQUEST_BYTES:
        raise ModelError("invalid_input")
    return body


def _decode(body: bytes) -> dict:
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError()

    try:
        result = json.loads(body.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ModelError("invalid_response") from None
    if type(result) is not dict:
        raise ModelError("invalid_response")
    _json_shape(result, code="invalid_response")
    if "error" in result:
        raise ModelError("http_error")
    for field in ("remote_host", "remote_model"):
        if field in result:
            if type(result[field]) is not str:
                raise ModelError("invalid_response")
            if result[field]:
                raise ModelError("remote_model")
    return result


class _HeaderBudgetFile:
    """Also bounds chunk framing and trailer lines read by HTTPResponse."""

    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_HTTP_HEADER_BYTES

    def readline(self, limit: int = -1) -> bytes:
        limit = min(limit, self.remaining + 1) if limit >= 0 else self.remaining + 1
        line = self.stream.readline(limit)
        self.remaining -= len(line)
        if self.remaining < 0:
            raise ModelError("response_too_large")
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fp = _HeaderBudgetFile(self.fp)


class _LoopbackConnection(http.client.HTTPConnection):
    response_class = _BoundedHTTPResponse

    def connect(self) -> None:
        # A numeric AF_INET connection bypasses DNS, proxies, and environment.
        local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            local_socket.settimeout(self.timeout)
            local_socket.connect(("127.0.0.1", 11434))
            self.sock = local_socket
        except Exception:
            local_socket.close()
            raise


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ModelUnavailable("timeout")
    return remaining


def _interrupt_socket(local_socket) -> None:
    try:
        local_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _post(path: str, payload: dict, deadline: float) -> dict:
    if path not in ("/api/show", "/api/chat", "/api/embed"):
        raise ModelError("invalid_configuration")
    body = _encode(payload)
    connection = _LoopbackConnection("127.0.0.1", 11434, timeout=_remaining(deadline))
    response = None
    watchdog = None
    local_socket = None
    try:
        connection.connect()
        local_socket = connection.sock
        # Per-read timeouts alone do not stop a server slowly trickling headers.
        # Retain the socket even when HTTPConnection transfers it to a response.
        watchdog = threading.Timer(_remaining(deadline), _interrupt_socket, (local_socket,))
        watchdog.daemon = True
        watchdog.start()
        local_socket.settimeout(_remaining(deadline))
        connection.request("POST", path, body=body, headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        local_socket.settimeout(_remaining(deadline))
        response = connection.getresponse()
        _remaining(deadline)
        status = response.status
        if 300 <= status < 400:
            raise ModelError("redirect")
        if status == 429:
            header = response.getheader("Retry-After", "")
            retry_after = min(int(header), 60) if re.fullmatch(r"[0-9]{1,6}", header) else None
            raise ModelUnavailable("rate_limited", retry_after=retry_after)
        if status in (404, 502, 503, 504):
            raise ModelUnavailable()
        if status != 200:
            raise ModelError("http_error")
        media_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json" or response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ModelError("invalid_response")
        declared = response.getheader("Content-Length")
        if declared is not None:
            if not re.fullmatch(r"[0-9]{1,10}", declared):
                raise ModelError("invalid_response")
            if int(declared) > MAX_RESPONSE_BYTES:
                raise ModelError("response_too_large")
        parts = []
        size = 0
        while True:
            # With Connection: close, HTTPResponse owns the socket. A final
            # Content-Length read can close it before an extra EOF read.
            if response.isclosed():
                break
            local_socket.settimeout(_remaining(deadline))
            block = response.read1(min(8192, MAX_RESPONSE_BYTES - size + 1))
            _remaining(deadline)
            if not block:
                break
            size += len(block)
            if size > MAX_RESPONSE_BYTES:
                raise ModelError("response_too_large")
            parts.append(block)
        if declared is not None and size != int(declared):
            raise ModelError("invalid_response")
        result = _decode(b"".join(parts))
        _remaining(deadline)
        return result
    except ModelError:
        raise
    except (TimeoutError, socket.timeout):
        raise ModelUnavailable("timeout") from None
    except (OSError, http.client.HTTPException, ValueError, UnicodeError):
        if time.monotonic() >= deadline:
            raise ModelUnavailable("timeout") from None
        raise ModelUnavailable() from None
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if response is not None:
            response.close()
        connection.close()
        if local_socket is not None:
            local_socket.close()


def _calls(value: Any, *, code: str) -> list[dict]:
    if type(value) is not list or len(value) > MAX_TOOL_CALLS:
        raise ModelError(code)
    _json_shape(value, code=code)
    result = []
    for call in value:
        if type(call) is not dict:
            raise ModelError(code)
        function = call.get("function", call)
        if call.get("type", "function") != "function" or type(function) is not dict:
            raise ModelError(code)
        name = function.get("name")
        arguments = function.get("arguments")
        if type(name) is not str or not _NAME.fullmatch(name) or type(arguments) is not dict:
            raise ModelError(code)
        # JSON round-trip copies caller-owned structures and drops wire extras.
        result.append({"name": name, "arguments": json.loads(json.dumps(arguments, allow_nan=False))})
    return result


def _messages(messages: Any) -> list[dict]:
    if type(messages) is not list or not 1 <= len(messages) <= MAX_MESSAGES:
        raise ModelError("invalid_input")
    _json_shape(messages, code="invalid_input")
    result = []
    for message in messages:
        if type(message) is not dict or message.get("role") not in ("system", "user", "assistant", "tool"):
            raise ModelError("invalid_input")
        if set(message) - {"role", "content", "tool_calls", "tool_name", "name", "tool_call_id"}:
            raise ModelError("invalid_input")
        content = message.get("content", "")
        if type(content) is not str:
            raise ModelError("invalid_input")
        item = {"role": message["role"], "content": content}
        if "tool_calls" in message:
            if message["role"] != "assistant":
                raise ModelError("invalid_input")
            item["tool_calls"] = [
                {"type": "function", "function": call}
                for call in _calls(message["tool_calls"], code="invalid_input")
            ]
        name = message.get("tool_name", message.get("name"))
        if name is not None:
            if message["role"] != "tool" or type(name) is not str or not _NAME.fullmatch(name):
                raise ModelError("invalid_input")
            item["tool_name"] = name
        if "tool_call_id" in message and (message["role"] != "tool" or type(message["tool_call_id"]) is not str):
            raise ModelError("invalid_input")
        result.append(item)
    return result


def _tools(tools: Any) -> list[dict] | None:
    if tools is None:
        return None
    if type(tools) is not list or len(tools) > MAX_TOOLS:
        raise ModelError("invalid_input")
    _json_shape(tools, code="invalid_input")
    names = set()
    for tool in tools:
        if type(tool) is not dict or tool.get("type") != "function" or type(tool.get("function")) is not dict:
            raise ModelError("invalid_input")
        function = tool["function"]
        name = function.get("name")
        if type(name) is not str or not _NAME.fullmatch(name) or name in names:
            raise ModelError("invalid_input")
        if type(function.get("parameters")) is not dict or function["parameters"].get("type") != "object":
            raise ModelError("invalid_input")
        if "description" in function and type(function["description"]) is not str:
            raise ModelError("invalid_input")
        if set(tool) != {"type", "function"} or set(function) - {"name", "description", "parameters"}:
            raise ModelError("invalid_input")
        names.add(name)
    return json.loads(json.dumps(tools, allow_nan=False))


class ModelGateway:
    """Generation is opt-in; embeddings require their own explicit profile.

    ``ModelGateway(model="installed-model")`` uses the fixed local endpoint.
    ``gateway.with_embedding_model("installed-embedding-model")`` returns a new
    gateway with an independent embedding profile, preserving generation config.
    No environment variables, credentials, file paths, or remote URLs are read.
    """

    __slots__ = ("_model", "_embedding_model", "_timeout")
    provider = "ollama"

    def __init__(self, base_url=None, model=None, *, timeout=15.0):
        if base_url is not None and (type(base_url) is not str or base_url not in _BASE_URLS):
            raise ModelError("invalid_configuration")
        if type(timeout) not in (float, int) or not 0 < timeout <= 60 or not math.isfinite(timeout):
            raise ModelError("invalid_configuration")
        self._model = None if model is None else _model_name(model)
        self._embedding_model = None
        self._timeout = float(timeout)

    @property
    def enabled(self) -> bool:
        return self._model is not None

    @property
    def configured(self) -> bool:
        return self.enabled

    @property
    def embedding_enabled(self) -> bool:
        return self._embedding_model is not None

    @property
    def model(self) -> str | None:
        return self._model

    @property
    def embedding_model(self) -> str | None:
        return self._embedding_model

    @property
    def base_url(self) -> str:
        return "http://127.0.0.1:11434"

    @property
    def timeout(self) -> float:
        return self._timeout

    def with_embedding_model(self, model: str) -> ModelGateway:
        configured = ModelGateway(self.base_url, self.model, timeout=self.timeout)
        configured._embedding_model = _model_name(model)
        return configured

    def with_timeout(self, timeout: float) -> ModelGateway:
        """A host can tighten each call to its remaining global run budget."""
        if type(timeout) not in (float, int) or not 0 < timeout <= 60 or not math.isfinite(timeout):
            raise ModelError("invalid_configuration")
        configured = ModelGateway(self.base_url, self.model, timeout=min(timeout, self.timeout))
        configured._embedding_model = self.embedding_model
        return configured

    def _verify_local(self, model: str, deadline: float) -> None:
        metadata = _post("/api/show", {"model": model}, deadline)
        details = metadata.get("details")
        if type(details) is not dict or details.get("format") not in ("gguf", "safetensors"):
            raise ModelError("local_model_unverified")

    @staticmethod
    def _response_model(response: dict, expected: str) -> str:
        actual = response.get("model")
        try:
            valid = _model_name(actual)
        except ModelError:
            raise ModelError("invalid_response") from None
        if valid.removesuffix(":latest") != expected.removesuffix(":latest"):
            raise ModelError("invalid_response")
        return valid

    def complete(self, messages: list[dict], *, tools=None, max_tokens=800) -> dict:
        deadline = time.monotonic() + self.timeout
        if not self.enabled:
            raise ModelUnavailable("disabled")
        if type(max_tokens) is not int or not 1 <= max_tokens <= MAX_TOKENS:
            raise ModelError("invalid_input")
        payload = {
            "model": self.model, "messages": _messages(messages), "stream": False,
            "options": {"num_predict": max_tokens},
        }
        tool_list = _tools(tools)
        if tool_list is not None:
            payload["tools"] = tool_list
        # Reject oversized inference before even the metadata-only request.
        _encode(payload)
        self._verify_local(self.model, deadline)
        response = _post("/api/chat", payload, deadline)
        message = response.get("message")
        if response.get("done") is not True or type(message) is not dict or message.get("role", "assistant") != "assistant":
            raise ModelError("invalid_response")
        if type(message.get("content")) is not str:
            raise ModelError("invalid_response")
        calls = _calls(message.get("tool_calls", []), code="invalid_response")
        return {"content": message["content"], "tool_calls": calls, "model": self._response_model(response, self.model)}

    def embed(self, texts: list[str]) -> list[list[float]]:
        deadline = time.monotonic() + self.timeout
        if not self.embedding_enabled:
            raise ModelUnavailable("embedding_disabled")
        if type(texts) is not list or not 1 <= len(texts) <= MAX_EMBED_TEXTS or any(type(item) is not str or not item for item in texts):
            raise ModelError("invalid_input")
        inputs = list(texts)
        payload = {"model": self.embedding_model, "input": inputs, "truncate": False}
        _encode(payload)
        self._verify_local(self.embedding_model, deadline)
        response = _post("/api/embed", payload, deadline)
        self._response_model(response, self.embedding_model)
        vectors = response.get("embeddings")
        if type(vectors) is not list or len(vectors) != len(inputs):
            raise ModelError("invalid_response")
        result = []
        dimensions = None
        for vector in vectors:
            if type(vector) is not list or not 1 <= len(vector) <= MAX_EMBED_DIMENSIONS:
                raise ModelError("invalid_response")
            if dimensions is None:
                dimensions = len(vector)
            if len(vector) != dimensions or any(type(value) not in (int, float) or not math.isfinite(value) or abs(value) > MAX_EMBED_COMPONENT for value in vector):
                raise ModelError("invalid_response")
            # An all-zero vector cannot support cosine retrieval.
            if not any(value != 0 for value in vector):
                raise ModelError("invalid_response")
            result.append([float(value) for value in vector])
        return result
