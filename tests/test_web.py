from email.message import Message
from io import BytesIO
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aicti_monitor.storage import Store
from aicti_monitor.web import make_server


class DashboardBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / 'test.sqlite3')
        self.monitor = SimpleNamespace(busy=False, trigger=Mock(return_value=True))
        with patch('aicti_monitor.web.secrets.token_urlsafe', side_effect=['fixture-token', 'fixture-nonce']), patch('aicti_monitor.web.ThreadingHTTPServer') as server:
            make_server(self.store, [], self.monitor, port=8849)
        self.handler_type = server.call_args.args[1]

    def request(self, method='GET', path='/', **headers):
        handler = self.handler_type.__new__(self.handler_type)
        handler.headers = Message()
        handler.headers['Host'] = headers.pop('Host', '127.0.0.1:8849')
        for k, v in headers.items():
            handler.headers[k] = v
        handler.server = SimpleNamespace(server_address=('127.0.0.1', 8849))
        handler.path = path
        handler.request_version = 'HTTP/1.1'
        handler.requestline = f'{method} {path} HTTP/1.1'
        handler.command = method
        handler.wfile = BytesIO()
        getattr(handler, 'do_'+method)()
        return handler.wfile.getvalue().decode('utf-8')

    def test_local_only_and_cross_site_rejected(self):
        self.assertIn('200 OK', self.request())
        self.assertIn('403 Forbidden', self.request(Host='attacker.example:8849'))
        self.assertIn('403 Forbidden', self.request(**{'Sec-Fetch-Site': 'cross-site'}))

    def test_state_change_requires_same_origin_and_unpredictable_token(self):
        for headers in [{}, {'Origin': 'http://127.0.0.1:8849'},
                        {'Origin': 'https://attacker.example', 'X-Monitor-Token': 'fixture-token'}]:
            self.assertIn('403 Forbidden', self.request('POST', '/api/collect', **headers))
        self.monitor.trigger.assert_not_called()
        self.assertIn('202 Accepted', self.request('POST', '/api/collect', Origin='http://127.0.0.1:8849', **{'X-Monitor-Token': 'fixture-token'}))
        self.monitor.trigger.assert_called_once()

    def test_html_uses_text_nodes_and_strict_security_headers(self):
        page = self.request()
        self.assertIn("script-src 'nonce-fixture-nonce'", page)
        self.assertIn("frame-ancestors 'none'", page)
        self.assertIn('X-Content-Type-Options: nosniff', page)
        self.assertIn('n.textContent=String(text)', page)
        self.assertNotIn('innerHTML', page)

    def test_read_api_pagination_boundaries(self):
        self.assertIn('200 OK', self.request(path='/api/records?limit=20'))
        for query in ['limit=501', 'limit=-1', 'offset=-1', 'limit=bad']:
            self.assertIn('400 Bad Request', self.request(path='/api/records?'+query))
