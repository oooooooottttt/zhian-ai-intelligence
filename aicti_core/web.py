"""Loopback-only local application; state changes require same-origin nonce."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
from urllib.parse import unquote, urlsplit

from .store import StaleResult

MAX_BODY = 1_000_000

def _decode(body):
    def unique(pairs):
        out = {}
        for key,value in pairs:
            if key in out:
                raise ValueError("Duplicate JSON key")
            out[key] = value
        return out
    def invalid(_):
        raise ValueError("Non-finite JSON")
    value = json.loads(body.decode("utf-8"),object_pairs_hook=unique,parse_constant=invalid)
    if not isinstance(value,dict):
        raise ValueError("JSON object required")
    return value

def make_server(application, port=8849):
    token = secrets.token_urlsafe(32)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def log_message(self,*args):
            pass
        def reply(self,status,payload,*,html=False,nonce=None):
            if html:
                data = payload.encode("utf-8")
            else:
                data = json.dumps(payload,ensure_ascii=False,allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type","text/html; charset=utf-8" if html else "application/json; charset=utf-8")
            self.send_header("Content-Length",str(len(data)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("X-Frame-Options","DENY")
            self.send_header("Content-Security-Policy",f"default-src 'none'; script-src 'nonce-{nonce or 'none'}'; style-src 'nonce-{nonce or 'none'}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
            self.end_headers()
            self.wfile.write(data)
        def host_ok(self):
            hosts = self.headers.get_all("Host",[])
            bound = self.server.server_port
            return len(hosts) == 1 and hosts[0] in {f"127.0.0.1:{bound}",f"localhost:{bound}"}
        def check_host(self):
            if not self.host_ok():
                self.reply(403,{"error":"仅允许本机访问"})
                return False
            return True
        def do_GET(self):
            if not self.check_host():
                return
            try:
                route = urlsplit(self.path)
                if route.query or route.fragment or not self.path.startswith("/") or self.path.startswith("//"):
                    raise ValueError("Invalid route")
                path = unquote(route.path)
                if path == "/":
                    from .ui import PAGE
                    nonce = secrets.token_urlsafe(24)
                    self.reply(200,PAGE.replace("__TOKEN__",token).replace("__NONCE__",nonce),html=True,nonce=nonce)
                    return
                if path == "/api/system":
                    payload = application.system()
                elif path == "/api/model":
                    payload = {"model":application.model_status()}
                elif path == "/api/knowledge":
                    payload = application.knowledge()
                elif path.startswith("/api/events/") and path[12:].isdigit():
                    payload = application.event(int(path[12:]))
                elif path.startswith("/api/evidence/"):
                    payload = application.store.evidence(path[14:])
                elif path.startswith("/api/sessions/"):
                    payload = application.store.session_detail(path[14:])
                else:
                    self.reply(404,{"error":"页面不存在"}); return
                self.reply(200 if payload else 404,payload or {"error":"记录不存在或未获授权"})
            except (ValueError,TypeError,UnicodeError,RecursionError):
                self.reply(400,{"error":"请求参数无效"})
            except Exception:
                self.reply(503,{"error":"本地数据暂不可用，请稍后重试"})
        def do_POST(self):
            if not self.check_host():
                return
            origins = self.headers.get_all("Origin",[])
            tokens = self.headers.get_all("X-Monitor-Token",[])
            if len(origins)!=1 or origins[0] != f"http://{self.headers['Host']}" or len(tokens)!=1 or not secrets.compare_digest(tokens[0],token):
                self.reply(403,{"error":"请求未获本地页面授权"}); return
            lengths = self.headers.get_all("Content-Length",[])
            if self.headers.get("Transfer-Encoding") or len(lengths)!=1 or not lengths[0].isdigit():
                self.reply(400,{"error":"需要明确的请求长度"}); return
            size = int(lengths[0])
            if size>MAX_BODY:
                self.reply(413,{"error":"请求过大"}); return
            if self.headers.get("Content-Type","").split(";",1)[0].strip().lower()!="application/json":
                self.reply(415,{"error":"需要 JSON 请求"}); return
            try:
                self.connection.settimeout(5)
                body = self.rfile.read(size)
                if len(body)!=size:
                    raise ValueError("Truncated body")
                value = _decode(body)
                route = self.path
                if route == "/api/assets" and set(value)=={"assets"}:
                    result = application.import_assets(value["assets"])
                elif route == "/api/assets/sbom" and set(value)=={"document"}:
                    result = application.import_sbom(value["document"])
                elif route == "/api/model":
                    result = application.configure_model(value)
                elif route == "/api/model/test" and not value:
                    result = application.test_model()
                elif route == "/api/model/clear" and not value:
                    result = application.clear_model()
                elif route == "/api/process" and not value:
                    result = application.process()
                elif route == "/api/ask" and set(value) <= {"question","session_id"} and "question" in value:
                    result = application.ask(value["question"],value.get("session_id"))
                elif route == "/api/collect" and not value:
                    result = application.collect_now()
                elif route == "/api/demo/withdraw" and not value:
                    result = application.withdraw_demo()
                elif route == "/api/entities/confirm" and set(value)=={"event_id","groups","reason","expected_generation"} and type(value["event_id"]) is int and type(value["expected_generation"]) is int:
                    result = application.store.confirm_groups(value["event_id"],value["groups"],value["reason"],expected_generation=value["expected_generation"])
                    application.wake_event.set()
                else:
                    raise ValueError("Unsupported route or schema")
                self.reply(200,result)
            except StaleResult:
                self.reply(409,{"error":"资料已变化，请刷新后重试"})
            except (ValueError,TypeError,UnicodeError,RecursionError,TimeoutError):
                self.reply(400,{"error":"请求内容无效或当前操作不可用"})
            except Exception:
                self.reply(503,{"error":"处理暂不可用，请稍后重试"})
    server = ThreadingHTTPServer(("127.0.0.1",port),Handler)
    server.daemon_threads = True
    server.application = application
    return server

def serve(application,port=8849):
    server = make_server(application,port)
    application.process()
    application.start()
    print(f"AI 安全情报系统：http://127.0.0.1:{server.server_port}/",flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        application.stop()
