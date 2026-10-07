import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atlas
import lookups


def dns_fixture(*ips):
    return {'records': {kind: {'values': [x for x in ips if (':' in x) == (kind == 'AAAA')], 'ttl': 60}
                        for kind in ('A', 'AAAA')}, 'errors': {}, 'checked_at': 'fixture'}


class Tests(unittest.TestCase):
    def saved(self, directory):
        args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', directory])
        with contextlib.redirect_stdout(io.StringIO()):
            run = atlas.Run(args)
            run.add('z.example.com api.example.com a1.example.com deep.api.example.com', 'fixture')
            run.save()
        return run.out

    def test_parent_psl_multilabel_private_and_idna(self):
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('hidden network request')):
            self.assertEqual(lookups.registered_domain('api.example.co.uk'), 'example.co.uk')
            self.assertEqual(lookups.registered_domain('alice.github.io'), 'github.io')
            self.assertEqual(lookups.registered_domain('www.xn--bcher-kva.de'), 'xn--bcher-kva.de')
        with self.assertRaises(ValueError):
            lookups.registered_domain('api.internal')

    def test_lookup_serial_matches_full_and_filtered_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.saved(directory)
            result = {'hostname': 'api.example.com', 'kind': 'whois', 'partial': False}
            with patch('lookups.enrich', return_value=result) as enrich, patch('lookups.show'), \
                    contextlib.redirect_stdout(io.StringIO()) as display:
                self.assertEqual(atlas.main(['lookup', str(run), '--serial', '1', '--kind', 'whois']), 0)
            self.assertEqual(enrich.call_args.args[0], 'api.example.com')
            self.assertIn('SR NO 1: api.example.com', display.getvalue())
            with patch('lookups.enrich', return_value=dict(result, hostname='a1.example.com')) as enrich, \
                    patch('lookups.show'), contextlib.redirect_stdout(io.StringIO()):
                atlas.main(['lookup', str(run), '--serial', '1', '--kind', 'whois', '--find', 'a1.'])
            self.assertEqual(enrich.call_args.args[0], 'a1.example.com')

    def test_invalid_serial_scope_and_output_do_not_query(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.saved(directory)
            output = Path(directory) / 'existing.json'
            output.write_text('original')
            with patch('lookups.enrich') as enrich, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(atlas.main(['lookup', str(run), '--serial', '99']), 2)
                self.assertEqual(atlas.main(['lookup', str(run), '--serial', '1', '-o', str(output)]), 2)
                summary = json.loads((run / 'summary.json').read_text())
                summary['settings']['exclude'] = ['api.example.com']
                (run / 'summary.json').write_text(json.dumps(summary))
                self.assertEqual(atlas.main(['lookup', str(run), '--serial', '1']), 2)
            enrich.assert_not_called()
            self.assertEqual(output.read_text(), 'original')

    def test_browse_selection_preserves_filter(self):
        with patch('atlas.show_report'), patch('atlas.export_report'), \
                patch('atlas.lookup_dashboard') as dashboard, \
                patch('builtins.input', side_effect=['s', 'api.', 'l', 'q']):
            atlas.browse_report('fixture')
        dashboard.assert_called_once_with('fixture', find='api.', show_list=False)

    def test_export_serials_follow_report_order(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.saved(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                atlas.export_report(run, Path(directory) / 'export.csv', 'csv')
            with (Path(directory) / 'export.csv').open(newline='') as stream:
                rows = list(csv.DictReader(stream))
            summary, assets = atlas.load_assets(run)
            self.assertEqual([x['hostname'] for x in rows], [x['hostname'] for x in atlas.ordered_subdomains(summary, assets)])
            self.assertEqual(rows[0]['sr_no'], '1')

    def test_menu_ten_routes_to_lookup(self):
        with patch('atlas.show_report'), patch('atlas.lookup_dashboard') as dashboard, \
                patch('builtins.input', side_effect=['10', 'fixture', '0']), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(atlas.main(['menu']), 0)
        dashboard.assert_called_once_with('fixture', '')

    def test_domain_rdap_bootstrap_cached_and_no_subdomain_registration(self):
        data = {'status': ['active'], 'entities': [{'roles': ['registrar'],
                'vcardArray': ['vcard', [['fn', {}, 'text', 'Demo Registrar']]]}],
                'nameservers': [{'ldhName': 'ns.example.net'}], 'events': []}
        bootstrap = {'services': [[['uk'], ['https://rdap.example.net/']]]}
        with tempfile.TemporaryDirectory() as directory, \
                patch('lookups.request_text', side_effect=[json.dumps(bootstrap), json.dumps(data)]) as request:
            cache = lookups.Cache(directory)
            first = lookups.domain_rdap('api.example.co.uk', cache, 5)
            second = lookups.domain_rdap('www.example.co.uk', cache, 5)
        self.assertEqual(request.call_args_list[1].args[0], 'https://rdap.example.net/domain/example.co.uk')
        self.assertEqual(first['registrar'], ['Demo Registrar'])
        self.assertFalse(first['cached'])
        self.assertTrue(second['cached'])

    def test_cache_expiry_refresh_and_failures_not_cached(self):
        with tempfile.TemporaryDirectory() as directory:
            function = Mock(return_value={'value': 1})
            cache = lookups.Cache(directory)
            with patch('lookups.time.time', return_value=100):
                cache.get('test', function, 10)
            with patch('lookups.time.time', return_value=105):
                self.assertTrue(cache.get('test', function, 10)[1])
                lookups.Cache(directory, refresh=True).get('test', function, 10)
            with patch('lookups.time.time', return_value=200):
                self.assertFalse(cache.get('test', function, 10)[1])
            self.assertEqual(function.call_count, 3)
            bad = Mock(side_effect=ValueError('quota'))
            for _ in range(2):
                with self.assertRaises(ValueError):
                    cache.get('bad', bad)
            self.assertEqual(bad.call_count, 2)

    def test_reverse_quota_invalid_no_records_and_legitimate_limit_name(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = lookups.Cache(directory, refresh=True)
            for text in ('API count exceeded', 'error check your search parameter', '<html>bad</html>'):
                with patch('lookups.request_text', return_value=text), self.assertRaises(ValueError):
                    lookups.reverse_provider('8.8.8.8', cache, 5)
            with patch('lookups.request_text', return_value='no DNS A records found'):
                self.assertEqual(lookups.reverse_provider('8.8.8.8', cache, 5)['state'], 'no-records')
            with patch('lookups.request_text', return_value='unlimited.example.com\napi.example.com\napi.example.com'):
                self.assertEqual(lookups.reverse_provider('8.8.8.8', cache, 5)['hostnames'],
                                 ['api.example.com', 'unlimited.example.com'])
            with patch('lookups.request_text') as request:
                self.assertEqual(lookups.reverse_provider('2001:4860:4860::8888', cache, 5)['state'], 'unsupported')
                request.assert_not_called()

    def test_reverse_scope_exclusions_and_local_correlation_without_probing_neighbours(self):
        rows = [{'hostname': 'api.example.com', 'records': {'A': ['8.8.8.8']}},
                {'hostname': 'mail.example.com', 'records': {'A': ['8.8.8.8']}}]
        with tempfile.TemporaryDirectory() as directory, \
                patch('lookups.dns_records', return_value=dns_fixture('8.8.8.8')) as dns, \
                patch('lookups.ptr_lookup', return_value={'records': {'PTR': {'values': []}}, 'errors': {}}), \
                patch('lookups.reverse_provider', return_value={'state': 'ok', 'hostnames':
                      ['api.example.com', 'excluded.example.com', 'neighbour.org']}):
            result = lookups.enrich('api.example.com', 'example.com', rows, 'reverse-ip', directory,
                                    exclusions=['excluded.example.com'])
        dns.assert_called_once()
        self.assertEqual(dns.call_args.args[0], 'api.example.com')
        self.assertEqual(result['ips'][0]['local_matches'], ['api.example.com', 'mail.example.com'])
        self.assertEqual([x['in_scope'] for x in result['ips'][0]['reverse_ip']['hosts']], [True, False, False])
        self.assertEqual(len(rows), 2)

    def test_non_public_ips_skipped_and_max_ips_reported(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('lookups.domain_rdap', return_value={'registered_domain': 'example.com'}), \
                patch('lookups.dns_records', return_value=dns_fixture('10.0.0.1', '10.0.0.2')), \
                patch('lookups.ptr_lookup') as ptr, patch('lookups.ip_rdap') as rdap, \
                patch('lookups.reverse_provider') as reverse:
            result = lookups.enrich('api.example.com', 'example.com', [], 'all', directory, max_ips=1)
        self.assertEqual(result['omitted_ips'], ['10.0.0.2'])
        self.assertIn('skipped', result['ips'][0])
        ptr.assert_not_called()
        rdap.assert_not_called()
        reverse.assert_not_called()

    def test_independent_provider_failure_preserves_dns_and_other_sections(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('lookups.domain_rdap', side_effect=ValueError('rate limited')), \
                patch('lookups.dns_records', return_value=dns_fixture('8.8.8.8')), \
                patch('lookups.ptr_lookup', return_value={'records': {'PTR': {'values': []}}, 'errors': {}}), \
                patch('lookups.ip_rdap', return_value={'asn': '15169'}), \
                patch('lookups.reverse_provider', side_effect=ValueError('quota')):
            result = lookups.enrich('api.example.com', 'example.com', [], 'all', directory)
            path = lookups.save(result, directory)
            saved = json.loads(path.read_text())
            with self.assertRaises(FileExistsError):
                lookups.save(result, directory, path)
        self.assertTrue(saved['partial'])
        self.assertEqual(saved['ips'][0]['registration']['asn'], '15169')
        self.assertIn('reverse_ip', saved['ips'][0]['errors'])
        self.assertIn('whois', saved['errors'])

    def test_ipwhois_settings_bounded_and_asn_failure_falls_back(self):
        from ipwhois.exceptions import ASNLookupError
        with tempfile.TemporaryDirectory() as directory, patch('ipwhois.IPWhois') as client:
            client.return_value.lookup_rdap.side_effect = [ASNLookupError('DNS unavailable'), {'network': {'name': 'test'}}]
            result = lookups.ip_rdap('8.8.8.8', lookups.Cache(directory), 5)
            calls = client.return_value.lookup_rdap.call_args_list
        self.assertEqual(calls[0].kwargs['retry_count'], 0)
        self.assertFalse(calls[0].kwargs['root_ent_check'])
        self.assertTrue(calls[1].kwargs['bootstrap'])
        self.assertEqual(result['network']['name'], 'test')

    def test_https_routing_fallback_when_asn_dns_unavailable(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('lookups.dns_records', return_value=dns_fixture('8.8.8.8')), \
                patch('lookups.ptr_lookup', return_value={'records': {'PTR': {'values': []}}, 'errors': {}}), \
                patch('lookups.ip_rdap', return_value={'asn': None, 'network': {'name': 'test'}}), \
                patch('lookups.request_text', return_value=json.dumps({'status': 'ok', 'data': {'asns': [15169], 'prefix': '8.8.8.0/24'}})):
            result = lookups.enrich('api.example.com', 'example.com', [], 'ip', directory)
        self.assertEqual(result['ips'][0]['routing']['asns'], [15169])
        self.assertEqual(result['ips'][0]['registration']['network']['name'], 'test')

    def test_dns_absence_timeout_and_ptr_not_reverse_ip(self):
        import dns.resolver
        import dns.exception
        with patch('dns.resolver.Resolver') as resolver:
            resolver.return_value.resolve.side_effect = [dns.resolver.NXDOMAIN(), dns.exception.Timeout()]
            result = lookups.dns_records('api.example.com', 1, ('A', 'AAAA'))
        self.assertEqual(result['records']['A']['values'], [])
        self.assertNotIn('A', result['errors'])
        self.assertIn('AAAA', result['errors'])

    def test_http_rate_limit_size_limit_and_https_redirect(self):
        error = urllib.error.HTTPError('https://provider.test', 429, 'rate limited', {'Retry-After': '60'}, None)
        self.assertIn('Retry-After: 60', lookups.error_text(error))
        error.close()
        with self.assertRaises(ValueError):
            lookups.HTTPSOnly().redirect_request(None, None, 302, '', {}, 'http://provider.test')
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'x' * (lookups.MAX_BODY + 1)
            with self.assertRaises(ValueError):
                lookups.request_text('https://provider.test', 5)


if __name__ == '__main__':
    unittest.main()
