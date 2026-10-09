from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aicti_monitor.models import FetchError, FetchResult, Record, SourceConfig
from aicti_monitor.runner import Monitor, iso
from aicti_monitor.storage import Store

NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / 'test.sqlite3')
        self.source = SourceConfig('fixture', 'Fixture', 'nvd', 'vulnerability_database',
                                   'https://example.org/api', ('example.org',), interval_seconds=3600,
                                   terms_url='https://example.org/terms', params={'license': 'fixture'})
        self.monitor = Monitor(self.store, [self.source], http_factory=lambda s: object())

    def record(self):
        return Record('fixture', 'example-1', 'vulnerability', 'Ollama configuration issue', 'Test fixture',
                      'https://example.org/advisory', updated_at=iso(NOW), components=['ollama'])

    def test_partial_commit_resumes_pending_and_then_completes(self):
        responses = [FetchResult([self.record()], {'pending': {'offset': 1}}, complete=False),
                     FetchResult([], {'committed_end': iso(NOW)}, complete=True)]
        with patch('aicti_monitor.adapters.nvd.fetch', side_effect=responses) as fetch:
            self.assertEqual(self.monitor.run_once(now=NOW)[0]['status'], 'partial')
            self.assertEqual(self.store.get_cursor('fixture'), {'pending': {'offset': 1}})
            self.assertEqual(self.monitor.run_once(now=NOW + timedelta(seconds=60))[0]['status'], 'ok')
            self.assertEqual(fetch.call_args.args[1], {'pending': {'offset': 1}})
        self.assertEqual(self.store.stats()['total_records'], 1)

    def test_transaction_failure_keeps_data_and_cursor_unchanged(self):
        result = FetchResult([self.record()], {'committed_end': iso(NOW)})
        with patch('aicti_monitor.adapters.nvd.fetch', return_value=result), patch.object(self.store, '_ingest_record', side_effect=RuntimeError('fixture-secret')):
            self.assertEqual(self.monitor.run_once(now=NOW)[0]['status'], 'failed')
        self.assertEqual(self.store.get_cursor('fixture'), {})
        self.assertEqual(self.store.stats()['total_records'], 0)
        self.assertEqual(self.store.list_runs()[0]['status'], 'failed')
        self.assertNotIn('fixture-secret', self.store.get_source_state('fixture')['last_error'])

    def test_rate_limit_not_bypassed_by_force(self):
        with patch('aicti_monitor.adapters.nvd.fetch', side_effect=FetchError('sensitive fixture', status=429, retry_after=600)) as fetch:
            self.monitor.run_once(now=NOW)
            self.assertEqual(self.monitor.run_once(force=True, now=NOW + timedelta(seconds=120))[0]['status'], 'backoff')
            self.assertEqual(fetch.call_count, 1)

    def test_nonfinite_retry_cannot_leave_running_run(self):
        with patch('aicti_monitor.adapters.nvd.fetch', side_effect=FetchError('fixture', status=429, retry_after=float('inf'))):
            self.assertEqual(self.monitor.run_once(now=NOW)[0]['status'], 'failed')
        self.assertEqual(self.store.list_runs()[0]['status'], 'failed')
        self.assertEqual(self.store.get_source_state('fixture')['consecutive_failures'], 1)

    def test_failed_fetch_never_moves_existing_cursor(self):
        with patch('aicti_monitor.adapters.nvd.fetch', return_value=FetchResult([self.record()], {'end': 'old'})):
            self.monitor.run_once(now=NOW)
        with patch('aicti_monitor.adapters.nvd.fetch', side_effect=ValueError('fixture-secret')):
            self.monitor.run_once(force=True, now=NOW + timedelta(hours=1))
        self.assertEqual(self.store.get_cursor('fixture'), {'end': 'old'})

    def test_two_monitors_cannot_collect_same_database_concurrently(self):
        second = Monitor(self.store, [self.source])
        def during_fetch(*args):
            self.assertEqual(second.run_once(now=NOW), [{'status': 'busy'}])
            return FetchResult([], {'done': True})
        with patch('aicti_monitor.adapters.nvd.fetch', side_effect=during_fetch):
            self.monitor.run_once(now=NOW)

    def test_lock_open_failure_releases_in_process_lock(self):
        with patch.object(Path, 'open', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                self.monitor.run_once(now=NOW)
        self.assertFalse(self.monitor.lock.locked())

    def test_interrupted_run_is_observable_and_resumes_committed_position(self):
        run = self.store.begin_run('fixture', iso(NOW))
        self.store.ingest_and_finish(run, 'fixture', [], {'pending': {'offset': 2}},
                                     iso(NOW), iso(NOW + timedelta(seconds=60)), False)
        interrupted = self.store.begin_run('fixture', iso(NOW + timedelta(seconds=60)))
        with patch('aicti_monitor.adapters.nvd.fetch', return_value=FetchResult([], {'done': True})) as fetch:
            self.monitor.run_once(now=NOW + timedelta(seconds=120))
            self.assertEqual(fetch.call_args.args[1], {'pending': {'offset': 2}})
        old = next(r for r in self.store.list_runs() if r['id'] == interrupted)
        self.assertEqual(old['status'], 'failed')
        self.assertIn('中断', old['error'])
