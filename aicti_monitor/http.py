"""Bounded HTTPS transport with DNS pinning, public-network and rate boundaries."""
from __future__ import annotations

import email.utils
import hashlib
import http.client
import ipaddress
import math
import queue
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit

from .models import FetchBudgetExceeded, FetchError, HttpResponse, SourceConfig

MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_RETRY_SECONDS = 365 * 86400
USER_AGENT = "AICTI-Monitor/0.1 (academic security-intelligence metadata client)"
RATE_DIR = Path(__file__).resolve().parent.parent / ".data" / "http-rate"
_lock = threading.RLock()
DNS_TIMEOUT_SECONDS = 5.0
_dns_slots = threading.BoundedSemaphore(4)


def validate_url(url: str, allowed_hosts: tuple[str, ...]) -> tuple[str, str]:
    try:
        p = urlsplit(url)
        if (p.scheme != "https" or not p.hostname or p.username is not None
                or p.password is not None or p.port not in (None, 443)
                or p.fragment or any(ord(c) < 32 for c in url)):
            raise ValueError()
        host = p.hostname.lower()
        if host not in allowed_hosts:
            raise ValueError()
        if len(url) > 16000:
            raise ValueError()
        return host, p.path or "/"
    except ValueError:
        raise FetchError("URL 不符合白名单 HTTPS 访问策略") from None


def resolve_public(host: str) -> str:
    # The OS resolver has no Python timeout. Daemon workers plus a fixed slot
    # budget bound waiting and prevent an unbounded accumulation of stuck DNS.
    slots = _dns_slots
    if not slots.acquire(blocking=False):
        raise FetchError("DNS 解析任务繁忙，稍后重试")
    answer = queue.Queue(maxsize=1)
    def lookup():
        try:
            answer.put((True, socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)))
        except Exception:
            answer.put((False, None))
        finally:
            slots.release()
    threading.Thread(target=lookup, daemon=True, name="monitor-dns").start()
    try:
        success, addresses = answer.get(timeout=DNS_TIMEOUT_SECONDS)
    except queue.Empty:
        raise FetchError("数据源 DNS 解析超过时间限制") from None
    if not success:
        raise FetchError("数据源 DNS 解析失败") from None
    ips = []
    for family, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise FetchError("拒绝连接私网、保留或特殊用途地址")
        ips.append((family, str(ip)))
    if not ips:
        raise FetchError("数据源未返回可连接的公网地址")
    ips.sort(key=lambda x: x[0] != socket.AF_INET)
    return ips[0][1]


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, timeout: float):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            self._transport_sock = self.sock
        except Exception:
            sock.close()
            raise


def bounded_retry(value) -> float | None:
    try:
        delay = float(value)
        return min(MAX_RETRY_SECONDS, max(0, delay)) if math.isfinite(delay) else None
    except (ValueError, TypeError, OverflowError):
        return None


def retry_delay(headers: dict[str, str], now: float | None = None) -> float | None:
    current = time.time() if now is None else now
    value = headers.get("retry-after")
    if value:
        try:
            return bounded_retry(float(value))
        except ValueError:
            try:
                return bounded_retry(email.utils.parsedate_to_datetime(value).timestamp() - current)
            except (ValueError, TypeError, OverflowError):
                pass
    if headers.get("x-ratelimit-remaining") == "0":
        try:
            return bounded_retry(float(headers["x-ratelimit-reset"]) - current)
        except (KeyError, ValueError):
            pass
    return None


class HttpClient:
    def __init__(self, source: SourceConfig, max_requests: int = 6, timeout: float = 15.0):
        self.source = source
        self.max_requests = max_requests
        self.timeout = timeout
        self.requests = 0

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        supplied = dict(headers or {})
        for _ in range(4):
            host, _ = validate_url(url, self.source.allowed_hosts)
            if self.requests >= self.max_requests:
                raise FetchBudgetExceeded("本周期请求预算已用完")
            self.requests += 1
            ip = resolve_public(host)
            # arXiv limits apply jointly to its API and feeds, across processes.
            group = "arxiv" if host.endswith(".arxiv.org") or host == "arxiv.org" else host
            gap = max(self.source.min_request_interval_seconds, 3.1 if group == "arxiv" else 0)
            RATE_DIR.mkdir(parents=True, exist_ok=True)
            path = RATE_DIR / (hashlib.sha256(group.encode()).hexdigest() + ".lock")
            with _lock, path.open("a+", encoding="utf-8") as rate_file:
                import fcntl
                fcntl.flock(rate_file.fileno(), fcntl.LOCK_EX)
                rate_file.seek(0)
                try:
                    last = float(rate_file.read() or "0")
                except ValueError:
                    last = 0
                delay = max(0, last + gap - time.time())
                if delay > 60:
                    raise FetchError("请求节奏状态异常，稍后重试", retry_after=delay)
                if delay:
                    time.sleep(delay)
                rate_file.seek(0)
                rate_file.truncate()
                rate_file.write(str(time.time()))
                rate_file.flush()
                response = self._request(url, host, ip, supplied)
                fcntl.flock(rate_file.fileno(), fcntl.LOCK_UN)
            if response.status in {301, 302, 303, 307, 308}:
                target = urljoin(url, response.headers.get("location", ""))
                target_host, _ = validate_url(target, self.source.allowed_hosts)
                if target_host != host:
                    supplied = {k: v for k, v in supplied.items()
                                if k.lower() not in {"authorization", "apikey", "cookie"}}
                url = target
                continue
            if response.status >= 400:
                raise FetchError(f"数据源返回 HTTP {response.status}", status=response.status,
                                 retry_after=retry_delay(response.headers))
            return response
        raise FetchError("重定向次数超过限制")

    def _request(self, url, host, ip, supplied):
        p = urlsplit(url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml", "Accept-Encoding": "identity"}
        for key, value in supplied.items():
            if any(c in str(key) + str(value) for c in "\r\n"):
                raise FetchError("请求头包含非法换行")
            if key.lower() in {"host", "connection", "proxy-authorization"}:
                raise FetchError("禁止覆盖传输边界请求头")
            headers[key] = value
        conn = _PinnedHTTPS(host, ip, self.timeout)
        # Socket timeouts alone reset on every chunk. An absolute deadline also
        # interrupts slow response headers and continuous drip-feed bodies.
        expired = threading.Event()
        def abort():
            expired.set()
            transport = getattr(conn, "_transport_sock", None)
            if transport is not None:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        deadline = time.monotonic() + min(30.0, self.timeout * 2)
        timer = threading.Timer(min(30.0, self.timeout * 2), abort)
        timer.daemon = True
        timer.start()
        try:
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            rh = {key.lower(): value for key, value in response.getheaders()
                  if key.lower() != "set-cookie"}
            length = rh.get("content-length")
            if length and int(length) > MAX_BODY_BYTES:
                raise FetchError("数据源响应超过大小限制")
            if rh.get("content-encoding", "identity").lower() not in {"", "identity"}:
                raise FetchError("不接受未协商的压缩响应")
            chunks, size = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if expired.is_set() or remaining <= 0:
                    raise FetchError("数据源响应超过时间限制")
                transport = getattr(conn, "_transport_sock", None)
                if transport is not None:
                    transport.settimeout(min(self.timeout, remaining))
                chunk = response.read1(min(65536, MAX_BODY_BYTES + 1 - size))
                if not chunk:
                    if response.length not in (None, 0):
                        raise FetchError("数据源响应提前中断")
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_BODY_BYTES:
                    raise FetchError("数据源响应超过大小限制")
            if expired.is_set():
                raise FetchError("数据源响应超过时间限制")
            body = b"".join(chunks)
            return HttpResponse(response.status, body, rh, url)
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise FetchError("数据源连接或 TLS 验证失败") from None
        finally:
            timer.cancel()
            conn.close()
