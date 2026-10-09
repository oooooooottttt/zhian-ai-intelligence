import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aicti_monitor.http import HttpClient, resolve_public, retry_delay, validate_url
from aicti_monitor.models import FetchBudgetExceeded, FetchError, HttpResponse, SourceConfig


class HttpBoundaryTests(unittest.TestCase):
    def source(self):
        return SourceConfig('test', 'Test', 'rss', 'security_blog', 'https://example.org/feed',
                            ('example.org', 'other.example.org'), min_request_interval_seconds=0)

    def test_url_rejects_credentials_private_protocol_and_unlisted_redirects(self):
        for url in ['http://example.org/', 'https://a:b@example.org/', 'https://127.0.0.1/',
                    'https://example.org:8443/', 'https://example.org/#x', 'https://evil.org/',
                    'https://example.org/\r\nheader']:
            with self.subTest(url=url), self.assertRaises(FetchError):
                validate_url(url, self.source().allowed_hosts)

    def test_dns_rejects_mixed_public_private_and_ipv6(self):
        for addresses in [['93.184.216.34', '127.0.0.1'], ['::1'], ['169.254.169.254'], ['10.0.0.2']]:
            fake = [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in addresses]
            with self.subTest(addresses=addresses), patch('socket.getaddrinfo', return_value=fake), self.assertRaises(FetchError):
                resolve_public('example.org')

    def test_dns_wall_time_and_worker_capacity_are_bounded(self):
        import threading
        release = threading.Event()
        slots = threading.BoundedSemaphore(1)
        def stuck(*args, **kwargs):
            release.wait(1)
            return []
        try:
            with patch('aicti_monitor.http._dns_slots', slots), patch('aicti_monitor.http.DNS_TIMEOUT_SECONDS', .01), patch('socket.getaddrinfo', side_effect=stuck):
                with self.assertRaises(FetchError):
                    resolve_public('example.org')
                with self.assertRaises(FetchError):
                    resolve_public('example.org')
        finally:
            release.set()

    def test_retry_after_date_and_nonfinite_values(self):
        self.assertEqual(retry_delay({'retry-after': '120'}, now=0), 120)
        self.assertEqual(retry_delay({'retry-after': 'Thu, 01 Jan 1970 00:02:00 GMT'}, now=0), 120)
        self.assertEqual(retry_delay({'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '100'}, now=20), 80)
        for value in ['inf', 'nan', '-inf', 'nonsense']:
            self.assertIsNone(retry_delay({'retry-after': value}))

    def test_budget_and_cross_host_auth_removal(self):
        client = HttpClient(self.source(), max_requests=2)
        responses = [HttpResponse(302, b'', {'location': 'https://other.example.org/feed'}, 'https://example.org/feed'),
                     HttpResponse(200, b'ok', {}, 'https://other.example.org/feed')]
        with tempfile.TemporaryDirectory() as directory, patch('aicti_monitor.http.RATE_DIR', Path(directory)), patch('aicti_monitor.http.resolve_public', return_value='93.184.216.34'), patch.object(client, '_request', side_effect=responses) as request:
            self.assertEqual(client.get(self.source().endpoint, {'Authorization': 'Bearer fixture-secret', 'apiKey': 'fixture-secret'}).status, 200)
            self.assertEqual(request.call_args_list[1].args[3], {})
            with self.assertRaises(FetchBudgetExceeded):
                client.get(self.source().endpoint)

    def test_unsafe_redirect_is_never_requested(self):
        client = HttpClient(self.source())
        with tempfile.TemporaryDirectory() as directory, patch('aicti_monitor.http.RATE_DIR', Path(directory)), patch('aicti_monitor.http.resolve_public', return_value='93.184.216.34'), patch.object(client, '_request', return_value=HttpResponse(302, b'', {'location': 'https://127.0.0.1/secret'}, self.source().endpoint)) as request:
            with self.assertRaises(FetchError):
                client.get(self.source().endpoint)
            self.assertEqual(request.call_count, 1)

    def test_429_preserves_retry_and_does_not_echo_body(self):
        client = HttpClient(self.source())
        with tempfile.TemporaryDirectory() as directory, patch('aicti_monitor.http.RATE_DIR', Path(directory)), patch('aicti_monitor.http.resolve_public', return_value='93.184.216.34'), patch.object(client, '_request', return_value=HttpResponse(429, b'fixture-secret', {'retry-after': '600'}, self.source().endpoint)):
            with self.assertRaises(FetchError) as error:
                client.get(self.source().endpoint)
            self.assertEqual(error.exception.retry_after, 600)
            self.assertNotIn('fixture-secret', str(error.exception))

    def test_absolute_deadline_stops_continuously_arriving_body(self):
        class Response:
            status = 200
            length = None
            def getheaders(self):
                return []
            def read1(self, size):
                return b'one chunk'
        class Connection:
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        client = HttpClient(self.source())
        with patch('aicti_monitor.http._PinnedHTTPS', return_value=Connection()), patch('aicti_monitor.http.time.monotonic', side_effect=[0, 1, 31]):
            with self.assertRaises(FetchError):
                client._request(self.source().endpoint, 'example.org', '93.184.216.34', {})

    def test_premature_content_length_eof_rejected(self):
        class Response:
            status = 200
            length = 10
            def getheaders(self):
                return [('Content-Length', '10')]
            def read1(self, size):
                return b''
        class Connection:
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        with patch('aicti_monitor.http._PinnedHTTPS', return_value=Connection()), self.assertRaises(FetchError):
            HttpClient(self.source())._request(self.source().endpoint, 'example.org', '93.184.216.34', {})
