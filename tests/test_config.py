import json
import tempfile
import unittest
from pathlib import Path

from aicti_monitor.config import DEFAULT_CONFIG, load_sources


class ConfigTests(unittest.TestCase):
    def configured(self, change):
        values = json.loads(DEFAULT_CONFIG.read_text(encoding='utf-8'))
        change(values['sources'][0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sources.json'
            path.write_text(json.dumps(values), encoding='utf-8')
            return load_sources(path)

    def test_default_config_is_consistent_with_adapters(self):
        sources = {s.id: s for s in load_sources()}
        self.assertEqual(sources['nvd-ai'].params['lookback_days'], 30)
        self.assertEqual(sources['github-ai'].params['per_page'], 50)
        self.assertEqual(sources['arxiv-security'].params['initial_lookback_days'], 30)
        self.assertTrue(sources['owasp-news'].enabled)

    def test_pending_license_review_cannot_be_enabled(self):
        with self.assertRaises(ValueError):
            self.configured(lambda s: s['params'].update(policy_status='review_required'))

    def test_credentials_and_private_links_rejected(self):
        for change in [lambda s: s.update(endpoint='https://u:p@services.nvd.nist.gov/'),
                       lambda s: s.update(terms_url='https://127.0.0.1/'),
                       lambda s: s['params'].update(api_key='fixture-secret'),
                       lambda s: s.update(endpoint=s['endpoint']+'?api_key=fixture-secret'),
                       lambda s: s.update(terms_url='https://example.org/?api%5Fkey=fixture-secret')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.configured(change)

    def test_bad_interval_and_misspelled_time_parameters_rejected(self):
        for change in [lambda s: s.update(interval_seconds=True),
                       lambda s: s.update(min_request_interval_seconds=float('nan')),
                       lambda s: s['params'].update(initial_days=30),
                       lambda s: s.update(allowed_hosts='services.nvd.nist.gov')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.configured(change)
