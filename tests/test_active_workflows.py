"""Run the actual active workflow against a loopback UDP authoritative fixture."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import dns.message
import dns.query
import dns.rcode
import dns.resolver
import atlas
import integrations

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('active_dns_lab', ROOT / 'scripts' / 'benchmark-lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class ActiveWorkflowTests(unittest.TestCase):
    def execute(self, directory, *, permute=False, partial_aaaa=False):
        words = Path(directory) / 'words.txt'
        words.write_text('ipv4\nipv6\nmissing\ndangling\n', encoding='utf-8')
        args = atlas.parser().parse_args(['scan', '-d', lab.ZONE, '--offline', '--mode', 'active',
            '--authorized', '--no-lookup', '--wordlist', str(words), '-o', directory,
            '--max-candidates', '12', '--wildcard-tests', '1', '--rate', '100000'])
        args.permute, args.http = permute, permute
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [lab.LOOPBACK]
        original_udp = dns.query.udp
        with lab.FixtureServer() as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
            thread.start()
            def routed(request, address, **kwargs):
                self.assertEqual(address, lab.LOOPBACK)
                if partial_aaaa and str(request.question[0].name) == 'ipv4.example.test.' and request.question[0].rdtype == 28:
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.SERVFAIL)
                    return response
                kwargs['port'] = server.server_address[1]
                return original_udp(request, address, **kwargs)
            run = atlas.Run(args)
            def mutate(key, command):
                self.assertIn('ipv4.example.test', (run.out / 'seeds.txt').read_text())
                return 'ipv4-dev.example.test\n'
            def probe(command, path, timeout):
                Path(path).write_text(json.dumps({'host': '192.0.2.10', 'input': 'ipv4.example.test',
                                                 'url': 'https://ipv4.example.test', 'status_code': 403}), encoding='utf-8')
                return 'complete'
            try:
                with patch('dns.resolver.Resolver', return_value=resolver), \
                        patch('dns_evidence.dns.query.udp', side_effect=routed), \
                        patch.object(run, 'tool', side_effect=mutate), \
                        patch.object(integrations.shutil, 'which', return_value='fixture-httpx'), \
                        patch.object(integrations, '_execute', side_effect=probe), \
                        contextlib.redirect_stdout(io.StringIO()):
                    run.active()
                    run.save()
                self.assertGreater(server.packet_count, 0)
            finally:
                server.shutdown()
                thread.join(timeout=2)
        return run

    def test_wordlist_resolves_ipv4_ipv6_and_retains_cname_only_as_indeterminate(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.execute(directory)
            self.assertEqual(run.dns['ipv4.example.test']['status'], 'resolved')
            self.assertEqual(run.dns['ipv6.example.test']['status'], 'resolved')
            self.assertEqual(run.dns['dangling.example.test']['status'], 'indeterminate')
            self.assertNotIn('missing.example.test', run.names)

    def test_permutation_http_works_with_zero_passive_seeds_and_real_httpx_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.execute(directory, permute=True)
            self.assertEqual(run.metrics['generation']['mutations'], 1)
            self.assertEqual(run.dns['ipv4.example.test']['availability'], 'UP')
            self.assertEqual(run.dns['ipv4.example.test']['http']['status_code'], 403)
            self.assertEqual(run.dns['ipv6.example.test']['availability'], 'NO_RESPONSE')
            with contextlib.redirect_stdout(io.StringIO()) as display:
                atlas.show_report(run.out, details=True)
            self.assertIn('UP', display.getvalue())

    def test_valid_address_is_not_discarded_when_another_record_type_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.execute(directory, partial_aaaa=True)
            self.assertEqual(run.dns['ipv4.example.test']['status'], 'resolved')
            self.assertEqual(run.dns['ipv4.example.test']['dns_evidence']['AAAA']['state'], 'SERVFAIL')
            self.assertTrue(run.dns['ipv4.example.test']['wildcard_test_uncertain'])

    def test_explicit_active_engines_run_when_only_passive_collection_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(atlas.Run, 'active'), \
                patch.object(atlas.Run, 'free_engine_enrichment') as enrich, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(atlas.main(['scan', '-d', 'example.com', '--offline', '--mode', 'active',
                '--authorized', '--free-engines', '--no-lookup', '-o', directory]), 0)
            enrich.assert_called_once()

    def test_active_menu_options_use_bounded_quick_collection_and_accept_lowercase_yes(self):
        for choice in ('2', '3'):
            with self.subTest(choice=choice), patch('builtins.input',
                    side_effect=[choice, 'example.com', 'yes', '', '0']), \
                    patch('atlas.execute_scan', return_value=0) as execute, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(atlas.main(['menu']), 0)
                args = execute.call_args.args[0]
                self.assertEqual(args.mode, 'active')
                self.assertEqual(args.profile, 'quick')
                self.assertEqual(args.tool_timeout, 30)
                self.assertEqual(args.timeout, 3)
                self.assertEqual(args.sources, 'certspotter,subfinder')
                self.assertEqual(args.permute, choice == '3')
                self.assertEqual(args.http, choice == '3')
                self.assertEqual(args.free_engines, choice == '3')


if __name__ == '__main__':
    unittest.main()
