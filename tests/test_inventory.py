import json
import copy
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inventory import Inventory, asset_id, compare_runs, manifest


class InventoryTests(unittest.TestCase):
    def test_identity_is_stable_and_view_specific(self):
        self.assertEqual(asset_id('Example.COM.', 'API.example.com.'),
                         asset_id('example.com', 'api.example.com'))
        self.assertNotEqual(asset_id('example.com', 'api.example.com'),
                            asset_id('example.com', 'api.example.com', 'internal'))

    def test_record_run_is_idempotent_and_preserves_older_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'inventory.sqlite3'
            with Inventory(path) as store:
                rows = [{'hostname': 'api.example.com', 'status': 'resolved', 'records': {'A': ['192.0.2.1']}}]
                summary = {'root': 'example.com', 'time_utc': '2026-01-01T00:00:00+00:00',
                           'stages': [{'stage': 'crtsh', 'state': 'ok'}]}
                first = store.record_run(Path(tmp) / 'first', summary, rows)
                self.assertEqual(store.record_run(Path(tmp) / 'first', summary, rows), first)
                self.assertIn('asset_id', rows[0])
                rows[0]['records'] = {'A': ['192.0.2.2']}
                store.record_run(Path(tmp) / 'second', dict(summary, time_utc='2026-01-02T00:00:00+00:00'), rows)
                history = store.asset_history('API.EXAMPLE.COM.', 'example.com')
                self.assertEqual(len(history), 2)
                self.assertEqual(history[0]['records']['A'], ['192.0.2.1'])
                self.assertEqual(history[1]['records']['A'], ['192.0.2.2'])
                self.assertEqual(store.connection.execute('SELECT count(*) FROM source_health').fetchone()[0], 2)
            with Inventory(path) as reopened:
                self.assertEqual(len(reopened.asset_history('api.example.com')), 2)

    def test_concurrent_writers_deduplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'inventory.sqlite3'
            with Inventory(path):
                pass
            errors = []
            def write():
                try:
                    with Inventory(path) as store:
                        for _ in range(4):
                            store.record_run(tmp, {'root': 'example.com'}, [{'hostname': 'api.example.com'}])
                except Exception as exc:
                    errors.append(exc)
            workers = [threading.Thread(target=write) for _ in range(3)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            self.assertEqual(errors, [])
            with Inventory(path) as store:
                self.assertEqual(len(store.asset_history('api.example.com')), 1)

    def test_transaction_rolls_back_invalid_batch(self):
        with tempfile.TemporaryDirectory() as tmp, Inventory(Path(tmp) / 'db') as store:
            with self.assertRaises(KeyError):
                store.record_run(tmp, {'root': 'example.com'}, [{'hostname': 'a.example.com'}, {}])
            self.assertEqual(store.asset_history('a.example.com'), [])
            self.assertEqual(store.connection.execute('SELECT count(*) FROM runs').fetchone()[0], 0)

    def test_checkpoints_jobs_events_survive_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db'
            with Inventory(path) as store:
                store.checkpoint('run', 'providers', {'cursor': 50, 'done': ['crtsh']})
                store.put_job('run', 'dns:a.example.com', {'host': 'a.example.com'})
                store.put_job('run', 'dns:a.example.com', {'host': 'a.example.com'}, state='done')
                event = {'type': 'DNS_NAME', 'data': 'a.example.com', 'source': 'fixture'}
                self.assertEqual(store.record_event('run', event), store.record_event('run', event))
            with Inventory(path) as store:
                self.assertEqual(store.load_checkpoint('run', 'providers')['cursor'], 50)
                self.assertEqual(store.jobs('run', ['pending']), [])
                self.assertEqual(store.jobs('run')[0]['state'], 'done')
                self.assertEqual(store.connection.execute('SELECT count(*) FROM events').fetchone()[0], 1)

    def _saved(self, parent, name, rows, **updates):
        directory = Path(parent) / name
        directory.mkdir()
        summary = dict(root='example.com', mode='passive', settings={},
                       stages=[{'stage': 'crtsh', 'state': 'ok'}])
        summary.update(updates)
        (directory / 'summary.json').write_text(json.dumps(summary))
        (directory / 'assets.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return directory

    def test_diff_reports_changes_and_absence_without_deletion_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._saved(tmp, 'old', [{'hostname': 'a.example.com', 'status': 'resolved'},
                                          {'hostname': 'old.example.com'}])
            new = self._saved(tmp, 'new', [{'hostname': 'a.example.com', 'status': 'unresolved'},
                                          {'hostname': 'new.example.com'}])
            result = compare_runs(old, new)
            self.assertTrue(result['comparable'])
            self.assertEqual(result['new'], ['new.example.com'])
            self.assertEqual(result['not_observed'], ['old.example.com'])
            self.assertEqual(result['changed'][0]['fields']['status']['before'], 'resolved')
            self.assertIn('not proof', result['absence_meaning'])

    def test_diff_flags_failed_and_missing_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._saved(tmp, 'old', [])
            new = self._saved(tmp, 'new', [], stages=[{'stage': 'crtsh', 'state': 'failed'}])
            result = compare_runs(old, new)
            self.assertFalse(result['comparable'])
            self.assertEqual(result['coverage_regressions'][0]['after'], 'failed')
            other = self._saved(tmp, 'other', [], root='other.example')
            with self.assertRaises(ValueError):
                compare_runs(old, other)

    def test_diff_ignores_dns_rrset_order_and_observation_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._saved(tmp, 'old', [{'hostname': 'a.example.com', 'checked_at': 'yesterday',
                'records': {'A': ['192.0.2.1', '192.0.2.2']}}])
            new = self._saved(tmp, 'new', [{'hostname': 'a.example.com', 'checked_at': 'today',
                'records': {'A': ['192.0.2.2', '192.0.2.1']}}])
            self.assertEqual(compare_runs(old, new)['changed'], [])

    def test_manifest_hash_changes_when_file_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'words.txt'
            path.write_text('api')
            a = manifest({'mode': 'passive'}, [path])
            path.write_text('www')
            b = manifest({'mode': 'passive'}, [path])
            self.assertNotEqual(a['files_sha256'], b['files_sha256'])
            self.assertEqual(a['settings_sha256'], b['settings_sha256'])

    def test_nested_metadata_and_rrsets_do_not_create_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = {'hostname': 'a.example.com', 'sr_no': 1,
                'discoveries': [{'collected_at': 'yesterday', 'source': 'crtsh'}],
                'review': {'confidence': 'low'},
                'records': {'A': ['192.0.2.1', '192.0.2.2']},
                'dns_evidence': {'A': {'state': 'ANSWER', 'checked_at': 'yesterday',
                    'ttl': 3600, 'resolver': '192.0.2.53', 'cached': False,
                    'values': ['192.0.2.1', '192.0.2.2'],
                    'verification': {'state': 'AGREES', 'observation': {
                        'state': 'ANSWER', 'checked_at': 'yesterday', 'ttl': 3600,
                        'values': ['192.0.2.2', '192.0.2.1']}}}},
                'tls': {'timestamp': 'yesterday', 'status': 'valid',
                    'not_after': '2027-01-01', 'subject_an': ['b.example.com', 'a.example.com']}}
            other = copy.deepcopy(row)
            other['sr_no'] = 20
            other['discoveries'] = [{'collected_at': 'today', 'source': 'archive'}]
            other['review'] = {'confidence': 'high'}
            other['records']['A'].reverse()
            observation = other['dns_evidence']['A']
            observation.update(checked_at='today', ttl=150, resolver='192.0.2.54', cached=True)
            observation['values'].reverse()
            observation['verification']['observation'].update(checked_at='today', ttl=140)
            other['tls']['timestamp'] = 'today'
            other['tls']['subject_an'].reverse()
            old = self._saved(tmp, 'old', [row])
            new = self._saved(tmp, 'new', [other])
            self.assertEqual(compare_runs(old, new)['changed'], [])
            # Semantic normalization does not mutate original evidence files.
            persisted = json.loads((new / 'assets.jsonl').read_text())
            self.assertEqual(persisted['dns_evidence']['A']['ttl'], 150)

    def test_nested_ip_tls_status_and_certificate_validity_are_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = {'hostname': 'a.example.com', 'dns_evidence': {'A': {
                'state': 'ANSWER', 'values': ['192.0.2.1']}},
                'tls': {'status': 'valid', 'not_after': '2027-01-01'}}
            other = copy.deepcopy(row)
            other['dns_evidence']['A']['values'] = ['192.0.2.2']
            other['tls'].update(status='expired', not_after='2026-01-01')
            result = compare_runs(self._saved(tmp, 'old', [row]), self._saved(tmp, 'new', [other]))
            self.assertEqual(set(result['changed'][0]['fields']), {'dns_evidence', 'tls'})

    def test_depth_budget_and_resolver_policy_affect_comparability(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = self._saved(tmp, 'old', [], settings={'recursive_depth': 1,
                'max_queries': 100, 'trusted_resolvers': ['192.0.2.53']})
            new = self._saved(tmp, 'new', [], settings={'recursive_depth': 2,
                'max_queries': 500, 'trusted_resolvers': ['192.0.2.54']})
            self.assertFalse(compare_runs(old, new)['comparable'])


if __name__ == '__main__':
    unittest.main()
