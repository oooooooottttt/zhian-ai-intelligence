from email.message import Message
from io import BytesIO
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aicti_core.demo import seed_demo,default_assets
from aicti_core.service import Application
from aicti_core.store import CoreStore
from aicti_core.web import make_server,_decode

class CoreWebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        store = CoreStore(Path(self.temp.name)/"system.sqlite3")
        seed_demo(store.monitor_store)
        self.app = Application(store,demo=True)
        self.app.import_assets(default_assets()); self.app.process()
        capture = {}
        def fake_server(address,handler):
            capture["handler"] = handler
            return SimpleNamespace(server_port=8849)
        with patch("aicti_core.web.ThreadingHTTPServer",side_effect=fake_server):
            self.server = make_server(self.app)
        self.handler = capture["handler"]
        _,_,page = self.request("GET","/")
        import re
        # UI token is a literal generated secret, never a fixed default.
        match = re.search(rb"[A-Za-z0-9_-]{43}",page)
        self.token = match[0].decode() if match else ""
    def tearDown(self):
        self.temp.cleanup()
    def request(self,method,path,body=b"",headers=None):
        handler = self.handler.__new__(self.handler)
        handler.headers = Message()
        for key,value in (headers or {"Host":"127.0.0.1:8849"}).items():
            handler.headers[key] = value
        handler.server = self.server
        handler.command,handler.path = method,path
        handler.requestline = method+" "+path+" HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.rfile,handler.wfile = BytesIO(body),BytesIO()
        handler.connection = SimpleNamespace(settimeout=lambda _:None)
        getattr(handler,"do_"+method)()
        raw = handler.wfile.getvalue()
        head,data = raw.split(b"\r\n\r\n",1)
        return int(head.split(b" ")[1]),head,data
    def post(self,path,value,**changes):
        body = json.dumps(value).encode()
        headers = {"Host":"127.0.0.1:8849","Origin":"http://127.0.0.1:8849",
                   "X-Monitor-Token":self.token,"Content-Type":"application/json","Content-Length":str(len(body))}
        headers.update(changes)
        return self.request("POST",path,body,headers)
    def test_page_nonce_and_token_security(self):
        status,headers,page = self.request("GET","/")
        self.assertEqual(status,200)
        self.assertIn(b"Content-Security-Policy",headers)
        self.assertIn(b"frame-ancestors 'none'",headers)
        self.assertNotIn(b"__TOKEN__",page)
        self.assertNotIn(b"__NONCE__",page)
        self.assertTrue(self.token)
    def test_host_rebinding_rejected(self):
        self.assertEqual(self.request("GET","/api/system",headers={"Host":"attacker.example:8849"})[0],403)
    def test_system_and_detail_get(self):
        status,_,data = self.request("GET","/api/system")
        self.assertEqual(status,200)
        snapshot = json.loads(data)["snapshot"]
        event = snapshot["events"][0]
        self.assertEqual(self.request("GET",f"/api/events/{event['id']}")[0],200)
        self.assertEqual(self.request("GET","/api/evidence/obs:1:r:1")[0],200)
    def test_csrf_origin_and_token_rejected(self):
        self.assertEqual(self.post("/api/process",{},Origin="https://attacker.example")[0],403)
        self.assertEqual(self.post("/api/process",{},**{"X-Monitor-Token":"bad"})[0],403)
    def test_json_content_type_and_size_limits(self):
        self.assertEqual(self.post("/api/process",{},**{"Content-Type":"text/plain"})[0],415)
        self.assertEqual(self.post("/api/process",{},**{"Content-Length":"1000001"})[0],413)
    def test_chunked_or_missing_length_rejected(self):
        self.assertEqual(self.post("/api/process",{},**{"Transfer-Encoding":"chunked"})[0],400)
    def test_duplicate_nonfinite_and_array_json_rejected(self):
        for data in (b'{"a":1,"a":2}',b'{"value":NaN}',b'[]'):
            with self.assertRaises(ValueError):
                _decode(data)
    def test_strict_route_schemas(self):
        self.assertEqual(self.post("/api/process",{"extra":1})[0],400)
        self.assertEqual(self.post("/api/assets",{"assets":[{"url":"http://127.0.0.1"}]})[0],400)
        self.assertEqual(self.request("GET","/api/system?secret=1")[0],400)
    def test_question_returns_supported_citations(self):
        status,_,data = self.post("/api/ask",{"question":"CVE-2099-99001 如何修复？"})
        self.assertEqual(status,200)
        self.assertTrue(json.loads(data)["citations"])
    def test_withdrawal_and_historical_citation(self):
        self.assertEqual(self.post("/api/demo/withdraw",{})[0],200)
        self.assertEqual(self.post("/api/process",{})[0],200)
        self.assertFalse(json.loads(self.request("GET","/api/evidence/obs:1:r:1")[2])["current"])
    def test_saved_session_get_for_browser_reload(self):
        status,_,data = self.post("/api/ask",{"question":"CVE-2099-99001 如何修复？"})
        answer = json.loads(data)
        status,_,data = self.request("GET","/api/sessions/"+answer["session_id"])
        self.assertEqual(status,200)
        self.assertEqual(json.loads(data)["messages"][1]["payload"]["claims"],answer["claims"])
        self.assertEqual(self.request("GET","/api/sessions/invalid")[0],400)

    def test_model_settings_read_configuration_and_clear_without_secret_echo(self):
        key = "test-memory-only-credential"
        status,_,data = self.post("/api/model",{"provider":"deepseek","api_key":key})
        self.assertEqual(status,200)
        self.assertNotIn(key.encode(),data)
        self.assertTrue(json.loads(data)["model"]["credential_configured"])
        status,_,data = self.request("GET","/api/model")
        self.assertEqual(status,200)
        self.assertNotIn(key.encode(),data)
        status,_,data = self.post("/api/model/clear",{})
        self.assertEqual(status,200)
        self.assertFalse(json.loads(data)["model"]["enabled"])

    def test_new_model_routes_keep_csrf_and_strict_schema(self):
        self.assertEqual(self.post("/api/model",{"provider":"deepseek"},Origin="https://attacker.example")[0],403)
        self.assertEqual(self.post("/api/model",{"provider":"deepseek","base_url":"https://evil.example"})[0],400)
        self.assertEqual(self.post("/api/model/test",{"api_key":"must-not-be-used"})[0],400)
        self.assertEqual(self.post("/api/model/clear",{"extra":True})[0],400)

    def test_knowledge_directory_and_passive_sbom_http_import(self):
        status,_,data = self.request("GET","/api/knowledge")
        self.assertEqual(status,200)
        self.assertTrue(json.loads(data)["items"])
        status,_,data = self.post("/api/assets/sbom",{"document":{
            "bomFormat":"CycloneDX","specVersion":"1.5","components":[
                {"type":"library","name":"vllm","version":"99.1.0","purl":"pkg:pypi/vllm@99.1.0"}]}})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(data)["count"],1)
        self.assertEqual(self.post("/api/assets/sbom",{"document":{},"extra":True})[0],400)
