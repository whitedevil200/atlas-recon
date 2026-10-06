import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
import urllib.error
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atlas
import availability

class Tests(unittest.TestCase):
    def test_http_error_is_reachable_and_redirect_is_disabled(self):
        opener = MagicMock()
        opener.open.side_effect = urllib.error.HTTPError('https://api.example.com/', 403, 'Forbidden', {}, None)
        with patch('availability.urllib.request.build_opener', return_value=opener):
            result = availability.http_probe('api.example.com', 'https', 2, MagicMock())
        self.assertEqual(result['code'], 403)
        self.assertIsNone(availability.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.org'))

    def test_up_and_http_fallback(self):
        records = {'A': ['192.0.2.1'], 'AAAA': [], 'CNAME': []}
        with patch('availability.lookup_dns', return_value=(records, {})), \
                patch('availability.http_probe', side_effect=[{'error': 'TLS failure'}, {'code': 301}]) as probe:
            result = availability.probe('api.example.com', 2, MagicMock())
        self.assertEqual(result['availability'], 'UP')
        self.assertEqual(probe.call_count, 2)

    def test_dns_failure_and_timeout_differ(self):
        records = {'A': [], 'AAAA': [], 'CNAME': []}
        for errors, expected in [({}, 'NO_DNS'), ({'A': 'LifetimeTimeout'}, 'CHECK_ERROR')]:
            with patch('availability.lookup_dns', return_value=(records, errors)), patch('availability.http_probe') as http:
                result = availability.probe('api.example.com', 2, MagicMock())
            self.assertEqual(result['availability'], expected)
            http.assert_not_called()

    def test_no_web_response_does_not_claim_down(self):
        with patch('availability.lookup_dns', return_value=({'A': ['192.0.2.1'], 'AAAA': [], 'CNAME': []}, {})), \
                patch('availability.http_probe', return_value={'error': 'timed out'}):
            self.assertEqual(availability.probe('api.example.com', 2, MagicMock())['availability'], 'NO_RESPONSE')

    def test_all_names_are_processed_once(self):
        completed = []
        with patch('availability.probe', return_value={'availability': 'UP'}):
            availability.check_all(['a.example.com', 'b.example.com', 'c.example.com'], 2, 2, 10, False,
                                   lambda name, result: completed.append(name))
        self.assertEqual(sorted(completed), ['a.example.com', 'b.example.com', 'c.example.com'])

    def test_checks_saved_and_exported_without_changing_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            scanargs = atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', directory])
            with contextlib.redirect_stdout(io.StringIO()):
                run = atlas.Run(scanargs)
                run.add('api.example.com old.example.com', 'fixture')
                run.save()
            original = (run.out / 'assets.jsonl').read_text()
            def fake_all(names, workers, timeout, rate, dns_only, callback):
                for name in names:
                    callback(name, {'availability': 'UP' if name.startswith('api.') else 'NO_DNS',
                                    'records': {'A': ['192.0.2.1'] if name.startswith('api.') else [], 'AAAA': [], 'CNAME': []},
                                    'checked_at': '2026-10-06T00:00:00+00:00', 'http': []})
            dns = types.ModuleType('dns')
            resolver = types.ModuleType('dns.resolver')
            dns.resolver = resolver
            args = atlas.parser().parse_args(['check', str(run.out), '--authorized'])
            with patch.dict(sys.modules, {'dns': dns, 'dns.resolver': resolver}), \
                    patch('availability.check_all', side_effect=fake_all), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(atlas.check_report(args), 0)
            checked = next(Path(directory).glob('example.com-checked-*'))
            self.assertEqual((run.out / 'assets.jsonl').read_text(), original)
            self.assertEqual((checked / 'up.txt').read_text().strip(), 'api.example.com')
            self.assertIn('old.example.com', (checked / 'availability.csv').read_text())
            self.assertEqual(json.loads((checked / 'summary.json').read_text())['checked'], 2)
            with contextlib.redirect_stdout(io.StringIO()) as display:
                atlas.show_report(checked, all_rows=True)
            self.assertIn('UP', display.getvalue())
            self.assertIn('NO DNS', display.getvalue())
            output = Path(directory) / 'all.txt'
            with contextlib.redirect_stdout(io.StringIO()):
                atlas.export_report(checked, output)
            self.assertEqual(set(output.read_text().splitlines()), {'api.example.com', 'old.example.com'})
            with self.assertRaises(FileExistsError):
                atlas.export_report(checked, output)

    def test_check_authorization_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            atlas.main(['check', 'some-run'])

    def test_interruption_leaves_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()):
                run = atlas.Run(atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', directory]))
                run.add('api.example.com other.example.com', 'fixture')
                run.save()
            dns = types.ModuleType('dns')
            dns.resolver = types.ModuleType('dns.resolver')
            def interrupt(names, workers, timeout, rate, dns_only, callback):
                callback(names[0], {'availability': 'UP', 'records': {'A': ['192.0.2.1']}})
                raise KeyboardInterrupt()
            args = atlas.parser().parse_args(['check', str(run.out), '--authorized'])
            with patch.dict(sys.modules, {'dns': dns, 'dns.resolver': dns.resolver}), \
                    patch('availability.check_all', side_effect=interrupt), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(atlas.check_report(args), 130)
            checked = next(Path(directory).glob('example.com-checked-*'))
            summary = json.loads((checked / 'summary.json').read_text())
            self.assertEqual(summary['check_state'], 'interrupted')
            self.assertEqual(summary['availability_counts']['PENDING'], 1)

if __name__ == '__main__':
    unittest.main()
