"""Opt-in, bounded standard-library transport for the official DeepSeek API.

The only endpoint is https://api.deepseek.com/chat/completions. DNS answers are
validated as public addresses and numeric socket connections pin those answers;
TLS still verifies api.deepseek.com. Proxies, redirects, retries and arbitrary
endpoints are deliberately absent. This module does not supply embeddings.

Protocol references checked 2026-10-04:
https://api-docs.deepseek.com/api/create-chat-completion/
https://api-docs.deepseek.com/guides/tool_calls/
https://api-docs.deepseek.com/guides/thinking_mode/
https://api-docs.deepseek.com/guides/json_mode/

``reasoning_content`` is bounded, ephemeral protocol state for the Harness, not
an explanation or answer. In thinking mode it must be replayed unchanged when
tools are used; overlong reasoning is rejected, never silently truncated.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import queue
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable

from .gateway import (
    MAX_MESSAGES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_TEXT_BYTES,
    MAX_TOKENS, MAX_TOOL_CALLS, ModelError, ModelUnavailable,
    _BoundedHTTPResponse, _encode, _json_shape, _tools,
)

OFFICIAL_HOST = "api.deepseek.com"
OFFICIAL_MODEL = "deepseek-v4-pro"
OFFICIAL_PATH = "/chat/completions"
MAX_REASONING_BYTES = 16_384
MAX_CONTENT_BYTES = 32_768
MAX_TOOL_ARGUMENT_BYTES = 8_192
MAX_DNS_ADDRESSES = 32
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_CALL_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_EFFORTS = frozenset({"none", "low", "high", "max"})
_MESSAGES = {
    "disabled": "Cloud model inference is disabled; no API key is configured.",
    "invalid_configuration": "Invalid cloud model configuration.",
    "invalid_input": "Invalid or oversized cloud model request.",
    "unavailable": "Cloud model service is unavailable.",
    "timeout": "Cloud model request exceeded its deadline.",
    "rate_limited": "Cloud model service is rate limited.",
    "authentication": "Cloud model authentication was rejected.",
    "quota_exhausted": "Cloud model account quota is unavailable.",
    "http_error": "Cloud model service rejected the request.",
    "redirect": "Cloud model redirects are not permitted.",
    "unsafe_destination": "Cloud model DNS did not resolve exclusively to public addresses.",
    "invalid_response": "Invalid cloud model service response.",
    "response_too_large": "Cloud model response exceeded its size limit.",
    "output_truncated": "Cloud model output was incomplete at its token limit.",
    "content_filtered": "Cloud model output was withheld by the provider.",
    "secret_in_payload": "Cloud model payload was rejected by the secret boundary.",
}


class DeepSeekError(ModelError):
    """Safe typed error; no provider body, request, credential or URL attached."""

    def __init__(self, code: str = "invalid_response", *, retry_after: int | None = None):
        self.code = code if code in _MESSAGES else "invalid_response"
        self.retry_after = retry_after if type(retry_after) is int and 0 <= retry_after <= 60 else None
        Exception.__init__(self, _MESSAGES[self.code])


class DeepSeekUnavailable(DeepSeekError, ModelUnavailable):
    """Disabled, unavailable, throttled or timed-out cloud inference."""


class DeepSeekAuthenticationError(DeepSeekError):
    def __init__(self):
        super().__init__("authentication")


def _safe_error(code: str, retry_after: int | None = None) -> DeepSeekError:
    if code == "authentication":
        return DeepSeekAuthenticationError()
    cls = DeepSeekUnavailable if code in {
        "disabled", "unavailable", "timeout", "rate_limited", "quota_exhausted",
    } else DeepSeekError
    return cls(code, retry_after=retry_after)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DeepSeekUnavailable("timeout")
    return remaining


def _shape(value: Any, code: str) -> None:
    problem = None
    try:
        _json_shape(value, code=code)
    except ModelError:
        problem = _safe_error(code)
    if problem is not None:
        raise problem


def _json_object(text: str, code: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError()

    problem = None
    result = None
    try:
        result = json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        problem = _safe_error(code)
    if problem is not None:
        raise problem
    if type(result) is not dict:
        raise DeepSeekError(code)
    _shape(result, code)
    return result


def _decode(body: bytes) -> dict:
    problem = None
    text = None
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        problem = _safe_error("invalid_response")
    if problem is not None:
        raise problem
    result = _json_object(text, "invalid_response")
    if "error" in result:
        raise DeepSeekError("http_error")
    return result


def _text(value: Any, *, code: str, limit: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str:
        raise DeepSeekError(code)
    problem = None
    try:
        if len(value) > limit or len(value.encode("utf-8")) > limit:
            problem = _safe_error(code)
    except UnicodeError:
        problem = _safe_error(code)
    if problem is not None:
        raise problem
    return value


def _encode_request(payload: dict) -> bytes:
    problem = None
    body = None
    try:
        body = _encode(payload)
    except ModelError:
        problem = _safe_error("invalid_input")
    if problem is not None:
        raise problem
    return body


def _contains_secret(value: Any, secret: str) -> bool:
    """Only inspect already bounded JSON; never return matching content."""
    if type(value) is str:
        return secret in value
    if type(value) is dict:
        return any(secret in key or _contains_secret(item, secret) for key, item in value.items())
    if type(value) is list:
        return any(_contains_secret(item, secret) for item in value)
    return False


def _call_id(value: Any, code: str) -> str:
    if type(value) is not str or not _CALL_ID.fullmatch(value):
        raise DeepSeekError(code)
    return value


def _calls(value: Any, *, code: str, wire: bool) -> list[dict]:
    """Wire arguments are JSON strings; Harness arguments are detached objects."""
    if type(value) is not list or len(value) > MAX_TOOL_CALLS:
        raise DeepSeekError(code)
    _shape(value, code)
    result = []
    ids = set()
    for call in value:
        if type(call) is not dict or call.get("type", "function") != "function":
            raise DeepSeekError(code)
        function = call.get("function", call)
        if type(function) is not dict:
            raise DeepSeekError(code)
        name = function.get("name")
        if type(name) is not str or not _NAME.fullmatch(name):
            raise DeepSeekError(code)
        identity = _call_id(call.get("id"), code)
        if identity in ids:
            raise DeepSeekError(code)
        ids.add(identity)
        arguments = function.get("arguments")
        if wire:
            arguments = _json_object(_text(arguments, code=code, limit=MAX_TOOL_ARGUMENT_BYTES), code)
        elif type(arguments) is not dict:
            raise DeepSeekError(code)
        _shape(arguments, code)
        encoded = json.dumps(arguments, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_TOOL_ARGUMENT_BYTES:
            raise DeepSeekError(code)
        result.append({"id": identity, "name": name, "arguments": json.loads(encoded)})
    return result


def _messages(messages: Any, *, thinking: bool) -> list[dict]:
    if type(messages) is not list or not 1 <= len(messages) <= MAX_MESSAGES:
        raise DeepSeekError("invalid_input")
    _shape(messages, "invalid_input")
    result = []
    pending: dict[str, str] = {}
    seen = set()
    for message in messages:
        if type(message) is not dict or message.get("role") not in ("system", "user", "assistant", "tool"):
            raise DeepSeekError("invalid_input")
        if set(message) - {"role", "content", "tool_calls", "tool_name", "name", "tool_call_id", "reasoning_content"}:
            raise DeepSeekError("invalid_input")
        role = message["role"]
        if pending and role != "tool":
            raise DeepSeekError("invalid_input")
        content = message.get("content", "")
        if role == "assistant" and content is None:
            content = ""
        item = {"role": role, "content": _text(content, code="invalid_input")}
        if "reasoning_content" in message:
            if role != "assistant":
                raise DeepSeekError("invalid_input")
            reasoning = message["reasoning_content"]
            if reasoning is None:
                reasoning = ""
            reasoning = _text(reasoning, code="invalid_input", limit=MAX_REASONING_BYTES)
            if thinking:
                item["reasoning_content"] = reasoning
        if "tool_calls" in message:
            if role != "assistant":
                raise DeepSeekError("invalid_input")
            calls = _calls(message["tool_calls"], code="invalid_input", wire=False)
            if calls and thinking and "reasoning_content" not in item:
                raise DeepSeekError("invalid_input")
            item["tool_calls"] = []
            for call in calls:
                if call["id"] in seen:
                    raise DeepSeekError("invalid_input")
                seen.add(call["id"])
                pending[call["id"]] = call["name"]
                item["tool_calls"].append({"id": call["id"], "type": "function", "function": {
                    "name": call["name"], "arguments": json.dumps(call["arguments"], ensure_ascii=False, allow_nan=False, separators=(",", ":")),
                }})
        name = message.get("tool_name", message.get("name"))
        if name is not None and (role != "tool" or type(name) is not str or not _NAME.fullmatch(name)):
            raise DeepSeekError("invalid_input")
        if role == "tool":
            identity = _call_id(message.get("tool_call_id"), "invalid_input")
            if identity not in pending or name is not None and pending[identity] != name:
                raise DeepSeekError("invalid_input")
            pending.pop(identity)
            item["tool_call_id"] = identity
        elif "tool_call_id" in message:
            raise DeepSeekError("invalid_input")
        result.append(item)
    if pending:
        raise DeepSeekError("invalid_input")
    return result


def _public_address(value: str) -> bool:
    problem = False
    try:
        if "%" in value:
            return False
        address = ipaddress.ip_address(value)
        mapped = getattr(address, "ipv4_mapped", None)
        candidates = (address, mapped) if mapped is not None else (address,)
        return all(item.is_global and not item.is_multicast and not item.is_reserved
                   and not item.is_unspecified and not item.is_loopback
                   and not item.is_link_local for item in candidates)
    except (TypeError, ValueError):
        problem = True
    return not problem


def _resolve_public(deadline: float) -> tuple[tuple[int, tuple], ...]:
    """A bounded wait for libc DNS; the daemon resolver sees no credentials.

    libc getaddrinfo has no portable cancellation API. If it stalls, the calling
    request returns at its deadline; that single daemon resolver may finish later.
    """
    output: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(OFFICIAL_HOST, 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            output.put((True, records))
        except Exception:
            # Never enqueue an exception carrying resolver/provider data.
            output.put((False, None))

    threading.Thread(target=resolve, name="deepseek-public-dns", daemon=True).start()
    problem = None
    records = None
    try:
        ok, records = output.get(timeout=_remaining(deadline))
        if not ok:
            problem = _safe_error("unavailable")
    except queue.Empty:
        problem = _safe_error("timeout")
    if problem is not None:
        raise problem
    _remaining(deadline)
    if type(records) is not list or not 1 <= len(records) <= MAX_DNS_ADDRESSES:
        raise DeepSeekError("unsafe_destination")
    addresses = []
    for record in records:
        if type(record) is not tuple or len(record) != 5:
            raise DeepSeekError("unsafe_destination")
        family, kind, protocol, _, address = record
        length = 2 if family == socket.AF_INET else 4 if family == socket.AF_INET6 else 0
        if (not length or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP
                or type(address) is not tuple or len(address) != length
                or type(address[0]) is not str or not _public_address(address[0])
                or type(address[1]) is not int or address[1] != 443
                or length == 4 and address[2:] != (0, 0)):
            raise DeepSeekError("unsafe_destination")
        parsed = ipaddress.ip_address(address[0])
        if parsed.version != (4 if family == socket.AF_INET else 6):
            raise DeepSeekError("unsafe_destination")
        numeric = (str(parsed), 443) if length == 2 else (str(parsed), 443, 0, 0)
        destination = (family, numeric)
        if destination not in addresses:
            addresses.append(destination)
    return tuple(addresses)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    response_class = _BoundedHTTPResponse

    def __init__(self, addresses: tuple[tuple[int, tuple], ...], deadline: float):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(OFFICIAL_HOST, 443, timeout=_remaining(deadline), context=context)
        self._addresses = addresses
        self._deadline = deadline
        self._active_socket = None

    def abort(self) -> None:
        active = self._active_socket
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                active.close()
            except OSError:
                pass

    def connect(self) -> None:
        for family, destination in self._addresses:
            _remaining(self._deadline)
            active = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self._active_socket = active
            try:
                active.settimeout(_remaining(self._deadline))
                active.connect(destination)
                active.settimeout(_remaining(self._deadline))
                secured = self._context.wrap_socket(active, server_hostname=OFFICIAL_HOST, do_handshake_on_connect=False)
                self._active_socket = secured
                secured.settimeout(_remaining(self._deadline))
                secured.do_handshake()
                _remaining(self._deadline)
                self.sock = secured
                return
            except ssl.SSLCertVerificationError:
                # Never retry a certificate failure as a weaker transport.
                self.abort()
                raise
            except (OSError, ssl.SSLError):
                self.abort()
                self._active_socket = None
                if time.monotonic() >= self._deadline:
                    raise DeepSeekUnavailable("timeout") from None
        raise DeepSeekUnavailable("unavailable")

    def close(self) -> None:
        super().close()
        self.abort()
        self._active_socket = None


def _post(payload: dict, *, api_key: str, deadline: float) -> dict:
    body = _encode_request(payload)
    addresses = _resolve_public(deadline)
    connection = _PinnedHTTPSConnection(addresses, deadline)
    response = None
    watchdog = None
    problem = None
    result = None
    try:
        watchdog = threading.Timer(_remaining(deadline), connection.abort)
        watchdog.daemon = True
        watchdog.start()
        connection.connect()
        connection.sock.settimeout(_remaining(deadline))
        connection.request("POST", OFFICIAL_PATH, body=body, headers={
            "Host": OFFICIAL_HOST, "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json", "Accept": "application/json",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        connection.sock.settimeout(_remaining(deadline))
        # HTTPConnection may clear .sock for a Connection: close response.
        active = connection.sock
        response = connection.getresponse()
        _remaining(deadline)
        status = response.status
        if type(status) is not int:
            raise DeepSeekError("invalid_response")
        if 300 <= status < 400:
            raise DeepSeekError("redirect")
        if status in (401, 403):
            raise DeepSeekAuthenticationError()
        if status == 402:
            raise DeepSeekUnavailable("quota_exhausted")
        if status == 429:
            header = response.getheader("Retry-After", "")
            retry = min(int(header), 60) if type(header) is str and re.fullmatch(r"[0-9]{1,6}", header) else None
            raise DeepSeekUnavailable("rate_limited", retry_after=retry)
        if status in (408, 504):
            raise DeepSeekUnavailable("timeout")
        if status in (500, 502, 503):
            raise DeepSeekUnavailable("unavailable")
        if status != 200:
            raise DeepSeekError("http_error")
        media_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json" or response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise DeepSeekError("invalid_response")
        declared = response.getheader("Content-Length")
        if declared is not None:
            if type(declared) is not str or not re.fullmatch(r"[0-9]{1,10}", declared):
                raise DeepSeekError("invalid_response")
            if int(declared) > MAX_RESPONSE_BYTES:
                raise DeepSeekError("response_too_large")
        parts = []
        size = 0
        # Keep the socket even if HTTPConnection transfers ownership to response.
        while not response.isclosed():
            active.settimeout(_remaining(deadline))
            block = response.read1(min(8192, MAX_RESPONSE_BYTES - size + 1))
            _remaining(deadline)
            if not block:
                break
            size += len(block)
            if size > MAX_RESPONSE_BYTES:
                raise DeepSeekError("response_too_large")
            parts.append(block)
        if declared is not None and size != int(declared):
            raise DeepSeekError("invalid_response")
        result = _decode(b"".join(parts))
        _remaining(deadline)
    except DeepSeekError as failure:
        problem = _safe_error(failure.code, failure.retry_after)
    except ModelError as failure:
        problem = _safe_error(failure.code, failure.retry_after)
    except (TimeoutError, socket.timeout):
        problem = _safe_error("timeout")
    except Exception:
        problem = _safe_error("timeout" if time.monotonic() >= deadline else "unavailable")
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        try:
            connection.close()
        except Exception:
            pass
    # Raise outside the handler: even exception.__context__ contains no raw error.
    if problem is not None:
        raise problem
    return result


class DeepSeekGateway:
    """An API key is memory-only and never appears in repr or public status.

    ``api_key=None`` reads only DEEPSEEK_API_KEY. An explicit empty string creates
    a disabled instance regardless of environment. Constructing/status/timeout
    cloning never performs a network request. ``transport`` is a trusted host
    injection seam for offline tests; signature: (payload, *, api_key, deadline).
    The Harness supplies already minimized, pseudonymous question/evidence data.
    """
    __slots__ = ("_api_key", "_timeout", "_reasoning_effort", "_transport")
    provider = "deepseek"
    supports_json_output = True

    def __init__(self, api_key=None, *, model=OFFICIAL_MODEL, timeout=20.0,
                 reasoning_effort="none", transport: Callable | None = None):
        if (type(model) is not str or model != OFFICIAL_MODEL
                or type(reasoning_effort) is not str or reasoning_effort not in _EFFORTS
                or type(timeout) not in (int, float) or not 0 < timeout <= 30 or not math.isfinite(timeout)
                or transport is not None and not callable(transport)):
            raise DeepSeekError("invalid_configuration")
        if api_key is None:
            api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if (type(api_key) is not str or len(api_key) > 512
                or any(not 33 <= ord(char) <= 126 for char in api_key)):
            raise DeepSeekError("invalid_configuration")
        self._api_key = api_key
        self._timeout = float(timeout)
        self._reasoning_effort = reasoning_effort
        self._transport = _post if transport is None else transport

    def __repr__(self) -> str:
        return (f"DeepSeekGateway(provider='deepseek', model='{OFFICIAL_MODEL}', "
                f"configured={self.configured}, timeout={self.timeout!r}, "
                f"reasoning_effort={self.reasoning_effort!r})")

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    @property
    def credential_configured(self) -> bool:
        return self.configured

    @property
    def enabled(self) -> bool:
        return self.configured

    @property
    def model(self) -> str:
        return OFFICIAL_MODEL

    @property
    def base_url(self) -> str:
        return "https://" + OFFICIAL_HOST

    @property
    def endpoint(self) -> str:
        return self.base_url + OFFICIAL_PATH

    @property
    def timeout(self) -> float:
        return self._timeout

    @property
    def reasoning_effort(self) -> str:
        return self._reasoning_effort

    @property
    def embedding_enabled(self) -> bool:
        return False

    @property
    def embedding_model(self) -> None:
        return None

    def with_timeout(self, timeout: float) -> DeepSeekGateway:
        if type(timeout) not in (int, float) or not 0 < timeout <= 30 or not math.isfinite(timeout):
            raise DeepSeekError("invalid_configuration")
        return DeepSeekGateway(self._api_key, timeout=min(self.timeout, timeout),
                               reasoning_effort=self.reasoning_effort, transport=self._transport)

    def complete(self, messages: list[dict], *, tools=None, max_tokens=800, response_format=None) -> dict:
        deadline = time.monotonic() + self.timeout
        problem = None
        result = None
        try:
            result = self._complete(messages, tools=tools, max_tokens=max_tokens,
                                    response_format=response_format, deadline=deadline)
        except ModelError as failure:
            problem = _safe_error(failure.code, failure.retry_after)
        except (TimeoutError, socket.timeout):
            problem = _safe_error("timeout")
        except Exception:
            problem = _safe_error("timeout" if time.monotonic() >= deadline else "unavailable")
        if problem is not None:
            raise problem
        return result

    def _complete(self, messages, *, tools, max_tokens, response_format, deadline) -> dict:
        if not self.enabled:
            raise DeepSeekUnavailable("disabled")
        if type(max_tokens) is not int or not 1 <= max_tokens <= MAX_TOKENS:
            raise DeepSeekError("invalid_input")
        thinking = self.reasoning_effort != "none"
        payload = {
            "model": OFFICIAL_MODEL, "messages": _messages(messages, thinking=thinking),
            "stream": False, "max_tokens": max_tokens,
            "thinking": {"type": "enabled" if thinking else "disabled"},
            "reasoning_effort": self.reasoning_effort,
        }
        tool_list = _tools(tools)
        if tool_list is not None:
            payload["tools"] = tool_list
        if response_format is not None:
            if type(response_format) is not dict or response_format not in ({"type": "json_object"}, {"type": "text"}):
                raise DeepSeekError("invalid_input")
            if response_format["type"] == "json_object" and not any(
                item["role"] in ("system", "user") and "json" in item["content"].lower()
                for item in payload["messages"]
            ):
                raise DeepSeekError("invalid_input")
            payload["response_format"] = dict(response_format)
        _encode_request(payload)
        if _contains_secret(payload, self._api_key):
            raise DeepSeekError("secret_in_payload")
        _remaining(deadline)
        response = self._transport(payload, api_key=self._api_key, deadline=deadline)
        _remaining(deadline)
        _shape(response, "invalid_response")
        if type(response) is not dict:
            raise DeepSeekError("invalid_response")
        if len(json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")) > MAX_RESPONSE_BYTES:
            raise DeepSeekError("response_too_large")
        if _contains_secret(response, self._api_key):
            raise DeepSeekError("secret_in_payload")
        if "error" in response:
            raise DeepSeekError("http_error")
        if response.get("model") != OFFICIAL_MODEL or response.get("object", "chat.completion") != "chat.completion":
            raise DeepSeekError("invalid_response")
        choices = response.get("choices")
        if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
            raise DeepSeekError("invalid_response")
        choice = choices[0]
        if type(choice.get("index")) is not int or choice["index"] != 0:
            raise DeepSeekError("invalid_response")
        finish = choice.get("finish_reason")
        if finish == "length":
            raise DeepSeekError("output_truncated")
        if finish == "content_filter":
            raise DeepSeekError("content_filtered")
        if finish in ("insufficient_system_resource", "aborted"):
            raise DeepSeekUnavailable("unavailable")
        if finish not in ("stop", "tool_calls"):
            raise DeepSeekError("invalid_response")
        message = choice.get("message")
        if type(message) is not dict or message.get("role") != "assistant":
            raise DeepSeekError("invalid_response")
        calls_value = message.get("tool_calls", [])
        calls = _calls([] if calls_value is None else calls_value, code="invalid_response", wire=True)
        if bool(calls) != (finish == "tool_calls"):
            raise DeepSeekError("invalid_response")
        content = message.get("content")
        if content is None and calls:
            content = ""
        content = _text(content, code="invalid_response", limit=MAX_CONTENT_BYTES)
        result = {"content": content, "tool_calls": calls, "model": OFFICIAL_MODEL, "provider": self.provider}
        reasoning = message.get("reasoning_content")
        if reasoning is not None:
            reasoning = _text(reasoning, code="invalid_response", limit=MAX_REASONING_BYTES)
        if thinking:
            # Include even an empty value so followup serialization is explicit.
            result["reasoning_content"] = "" if reasoning is None else reasoning
        _remaining(deadline)
        return result
