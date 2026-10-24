import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import integrations as api


class IntegrationTests(unittest.TestCase):
    def test_scope_boundaries_and_idna(self):
        self.assertEqual(api.normalize_host('API.Example.com.', 'example.com'), 'api.example.com')
        self.assertEqual(api.normalize_host('*.example.com', 'example.com'), 'example.com')
        for value in ('badexample.com', 'example.com.evil.org', '-bad.example.com', 'a..example.com'):
            self.assertIsNone(api.normalize_host(value, 'example.com'))

    def test_registry_is_explicit_about_import_engines(self):
        self.assertEqual(len(api.ENGINES), 17)
        self.assertEqual(api.ENGINES['amass']['mode'], 'import')
        self.assertEqual(api.ENGINES['shuffledns']['license'], 'GPL-3.0')
        self.assertEqual(api.ENGINES['baddns']['license'], 'AGPL-3.0')

    def test_every_executable_builder_has_bounded_curated_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / 'names.txt'
            input_path.write_text('api.example.com\n')
            options = dict(resolvers=str(input_path), trusted_resolvers=str(input_path),
                           permutations=str(input_path), provider_config=str(input_path), send=True)
            for name, metadata in api.ENGINES.items():
                if metadata['mode'] == 'import':
                    continue
                with self.subTest(name=name):
                    command = api.build_command(name, '/engine', input_path, 'example.com', 5, 50, options)
                    self.assertEqual(command[0], '/engine')
                    self.assertTrue(all(isinstance(value, str) for value in command))
                    self.assertNotIn('-up', command)

    def test_missing_engine_does_not_install(self):
        with patch.object(api.shutil, 'which', return_value=None), patch.object(api.subprocess, 'Popen') as spawn:
            result = api.run_engine('httpx', ['api.example.com'], 'example.com', '.')
            self.assertEqual(result['state'], 'not_installed')
            spawn.assert_not_called()

    def test_unknown_options_rejected(self):
        with self.assertRaises(ValueError):
            api.run_engine('httpx', [], 'example.com', '.', extra_options={'args': ['-follow-redirects']})

    def test_limits_rejected(self):
        for kwargs in ({'timeout': 0}, {'rate': 10000}, {'extra_options': {'limit': 10001}}):
            with self.assertRaises(ValueError):
                api.run_engine('httpx', [], 'example.com', '.', **kwargs)

    def test_notifications_need_explicit_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_text('api.example.com\n')
            with self.assertRaisesRegex(ValueError, 'explicit send'):
                api.build_command('notify', 'notify', path, 'example.com', 1, 50, {})

    def test_resolver_engines_require_configuration(self):
        for engine in ('massdns', 'puredns', 'shuffledns'):
            with self.subTest(engine=engine), self.assertRaisesRegex(ValueError, 'resolvers'):
                api.build_command(engine, engine, 'input', 'example.com', 1, 50, {})

    def test_baddns_restricts_single_selected_host(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_text('a.example.com\nb.example.com\n')
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                api.build_command('baddns', 'baddns', path, 'example.com', 1, 50, {})

    def test_run_scopes_inputs_and_output_and_preserves_sources(self):
        captured = []
        def fake_execute(command, artifact, timeout):
            captured.extend(command)
            Path(artifact).write_text(json.dumps({'host': 'API.Example.com.', 'sources': ['crtsh', 'certspotter'], 'status_code': 200}) + '\n' +
                                      json.dumps({'host': 'outside.org'}) + '\n')
            return 'complete'
        with tempfile.TemporaryDirectory() as directory, patch.object(api.shutil, 'which', return_value='subfinder'), \
                patch.object(api, '_execute', side_effect=fake_execute):
            result = api.run_engine('subfinder', ['api.example.com', 'outside.org'], 'example.com', directory)
            self.assertEqual(result['hosts'], ['api.example.com'])
            self.assertEqual(result['observations'][0]['providers'], ['crtsh', 'certspotter'])
            self.assertEqual(result['observations'][0]['evidence']['status_code'], 200)
            self.assertNotIn('outside.org', Path(result['artifact']).read_text())
            self.assertIn('-cs', captured)

    def test_engine_failure_is_not_success(self):
        def fake_execute(command, path, timeout):
            Path(path).write_text('')
            return 'timeout'
        with tempfile.TemporaryDirectory() as directory, patch.object(api.shutil, 'which', return_value='httpx'), \
                patch.object(api, '_execute', side_effect=fake_execute):
            result = api.run_engine('httpx', ['api.example.com'], 'example.com', directory)
            self.assertEqual(result['state'], 'timeout')

    def test_amass_and_bbot_import_scopes_without_executing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'engine.jsonl'
            path.write_text(json.dumps({'name': 'a.example.com'}) + '\n' + json.dumps({'data': 'b.example.com', 'type': 'DNS_NAME'}) + '\n' + json.dumps({'name': 'outside.org'}))
            for engine in ('amass', 'bbot'):
                with self.subTest(engine=engine), patch.object(api, '_execute') as execute:
                    result = api.run_engine(engine, [], 'example.com', directory, extra_options={'import_file': str(path)})
                    self.assertEqual(result['state'], 'imported')
                    self.assertEqual(result['hosts'], ['a.example.com', 'b.example.com'])
                    execute.assert_not_called()

    def test_import_configuration_required(self):
        self.assertEqual(api.run_engine('amass', [], 'example.com', '.')['state'], 'configuration_required')

    def test_owner_export_never_auto_probes_and_scopes(self):
        fixtures = {'aws': {'ResourceRecordSets': [{'Name': '*.example.com.', 'Type': 'A'}, {'Name': 'outside.org'}]},
                    'cloudflare': {'result': [{'name': 'api.example.com', 'type': 'AAAA'}]},
                    'gcp': [{'name': 'dev.example.com.', 'type': 'CNAME'}]}
        for provider, fixture in fixtures.items():
            with self.subTest(provider=provider):
                result = api.owner_inventory(provider, 'example.com', fixture, authorized=True)
                self.assertTrue(result['hosts'])
                self.assertNotIn('outside.org', result['hosts'])
                for observation in result['observations']:
                    self.assertEqual(observation['view'], 'private')
                    self.assertFalse(observation['probe_allowed'])

    def test_owner_export_requires_root_authorization(self):
        with self.assertRaisesRegex(ValueError, 'authorization'):
            api.owner_inventory('aws', 'example.com', [])

    def test_securitytrails_auth_missing(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(api, '_fetch_json') as fetch:
            self.assertEqual(api.collect_source('securitytrails', 'example.com')['state'], 'auth_required')
            fetch.assert_not_called()

    def test_securitytrails_normalized_and_partial(self):
        with patch.dict(os.environ, {'SECURITYTRAILS_API_KEY': 'secret'}), \
                patch.object(api, '_fetch_json', return_value={'subdomains': ['api', 'dev']}):
            result = api.collect_source('securitytrails', 'example.com', limit=1)
            self.assertEqual(result['hosts'], ['api.example.com'])
            self.assertEqual(result['state'], 'partial')
            self.assertNotIn('secret', json.dumps(result))

    def test_censys_requires_credits_consent(self):
        with patch.dict(os.environ, {'CENSYS_PAT': 'secret'}, clear=True), patch.object(api, '_fetch_json') as fetch:
            self.assertEqual(api.collect_source('censys', 'example.com')['state'], 'consent_required')
            fetch.assert_not_called()

    def test_censys_v3_body_and_certificate_schema(self):
        fixture = {'result': {'hits': [{'certificate_v1': {'resource': {'names': ['a.example.com', 'outside.org']}}}]}}
        with patch.dict(os.environ, {'CENSYS_PAT': 'secret', 'CENSYS_SEARCH_ENABLED': '1'}, clear=True), \
                patch.object(api, '_fetch_json', return_value=fixture) as fetch:
            result = api.collect_source('censys', 'example.com', limit=1000)
            self.assertEqual(result['hosts'], ['a.example.com'])
            args = fetch.call_args.args
            self.assertEqual(args[0], 'https://api.platform.censys.io/v3/global/search/query')
            self.assertEqual(args[3]['page_size'], 100)
            self.assertEqual(args[3]['query'], 'cert.names: "example.com"')

    def test_censys_schema_failure_is_visible(self):
        with patch.dict(os.environ, {'CENSYS_PAT': 'secret', 'CENSYS_SEARCH_ENABLED': '1'}), \
                patch.object(api, '_fetch_json', return_value={'unexpected': []}):
            self.assertEqual(api.collect_source('censys', 'example.com')['state'], 'schema_error')

    def test_commoncrawl_rejects_foreign_index_endpoint(self):
        with patch.object(api, '_fetch_json', return_value=[{'cdx-api': 'https://evil.org/'}]), \
                patch.object(api.urllib.request, 'urlopen') as request:
            self.assertEqual(api.collect_source('commoncrawl', 'example.com')['state'], 'failed')
            request.assert_not_called()

    def test_commoncrawl_partial_scoped_historical_observations(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = (json.dumps({'url': 'https://API.Example.com/path', 'timestamp': '20260101000000'}) + '\n' +
                                                            json.dumps({'url': 'https://outside.org/'})).encode()
        with patch.object(api, '_fetch_json', return_value=[{'cdx-api': 'https://index.commoncrawl.org/CC-MAIN-test-index'}]), \
                patch.object(api.urllib.request, 'urlopen', return_value=response):
            result = api.collect_source('commoncrawl', 'example.com')
            self.assertEqual(result['state'], 'partial')
            self.assertEqual(result['hosts'], ['api.example.com'])
            self.assertEqual(result['observations'][0]['evidence']['timestamp'], '20260101000000')

    def test_response_byte_budget(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'x' * 33
        with patch.object(api, 'MAX_BYTES', 32), patch.object(api.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                api._fetch_json('https://index.commoncrawl.org/collinfo.json', {}, 1)

    def test_owner_wildcard_is_identified_without_probe_permission(self):
        result = api.owner_inventory('aws', 'example.com', {'ResourceRecordSets': [{'Name': '*.example.com.', 'Type': 'A'}]}, authorized=True)
        row = result['observations'][0]
        self.assertTrue(row['evidence']['wildcard'])
        self.assertEqual(row['evidence']['record_name'], '*.example.com.')
        self.assertFalse(row['probe_allowed'])

    def test_bbot_v3_builder_disables_dependency_installation_and_dns(self):
        command = api.build_command('bbot', 'bbot', Path('input'), 'example.com', 1, 50, {})
        self.assertIn('--no-deps', command)
        self.assertIn('--strict-scope', command)
        self.assertIn('dnsresolve=false', command)
        self.assertIn('passive', command)

    def test_rich_http_and_tls_fields_survive_evidence_normalization(self):
        fixture = {'host': 'api.example.com', 'url': 'https://api.example.com', 'title': 'Control\x1b[31m Panel',
                   'webserver': 'nginx', 'tech': ['Nginx', 'React'], 'cdn': True, 'cdn_name': 'cloudflare',
                   'asn': {'as_number': 'AS13335', 'as_name': 'CLOUDFLARENET', 'secret': 'omit'},
                   'port': '443', 'scheme': 'https', 'status_code': 403, 'content_type': 'text/html',
                   'content_length': 42, 'location': 'https://login.example.com',
                   'tls': {'tls_version': 'tls13', 'not_before': '2026-01-01', 'not_after': '2027-01-01',
                           'subject_an': ['api.example.com', 'elsewhere.org'], 'subject_cn': 'api.example.com',
                           'issuer_org': ['Example CA'], 'fingerprint_hash': {'sha256': 'abc'},
                           'private_key': 'omit'}, 'headers': {'Authorization': 'secret'}, 'body': 'omit'}
        names, observations = api._observations([json.dumps(fixture)], 'httpx', 'example.com', 10)
        evidence = observations[0]['evidence']
        self.assertEqual(names, {'api.example.com'})
        self.assertEqual(evidence['tech'], ['Nginx', 'React'])
        self.assertEqual(evidence['tls']['fingerprint_hash'], {'sha256': 'abc'})
        self.assertEqual(evidence['tls']['subject_an'], ['api.example.com', 'elsewhere.org'])
        self.assertNotIn('secret', json.dumps(evidence))
        self.assertNotIn('body', evidence)
        self.assertNotIn('\x1b', evidence['title'])

    def test_rich_probe_flags_are_explicit_without_invented_tls_date_flags(self):
        http = api.build_command('httpx', 'httpx', 'input', 'example.com', 2, 50, {})
        for flag in ('-sc', '-title', '-td', '-ip', '-cname', '-tls-grab', '-cdn', '-asn'):
            self.assertIn(flag, http)
        tls = api.build_command('tlsx', 'tlsx', 'input', 'example.com', 2, 50, {})
        for flag in ('-san', '-cn', '-so', '-hash'):
            self.assertIn(flag, tls)
        self.assertNotIn('-not-before', tls)
        self.assertNotIn('-not-after', tls)

    def test_rich_artifact_is_bounded_known_schema(self):
        def execute(command, path, timeout):
            Path(path).write_text(json.dumps({'host': 'API.Example.com.', 'title': 'Demo',
                                             'not_after': '2027-01-01', 'subject_an': ['api.example.com'],
                                             'headers': {'Authorization': 'secret'}}))
            return 'complete'
        with tempfile.TemporaryDirectory() as directory, patch.object(api.shutil, 'which', return_value='httpx'), \
                patch.object(api, '_execute', side_effect=execute):
            result = api.run_engine('httpx', ['api.example.com'], 'example.com', directory)
            row = json.loads(Path(result['raw_artifact']).read_text())
            self.assertEqual(row['host'], 'api.example.com')
            self.assertEqual(row['title'], 'Demo')
            self.assertEqual(row['not_after'], '2027-01-01')
            self.assertNotIn('headers', row)

    def test_notify_accepts_exact_watch_payload_call_without_host_parsing_or_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            payload = base / 'changes.txt'
            payload.write_text('Changes: new a.example.com; old foreign.example.org. private-message-secret\n')
            config = base / 'notify.yaml'
            config.write_text('token: provider-secret\n')
            captured = []
            sent_payloads = []
            def execute(command, output, timeout):
                captured.extend(command)
                sent_payloads.append(Path(command[command.index('-data') + 1]).read_text())
                Path(output).write_text('private-message-secret provider-secret')
                return 'complete'
            with patch.object(api.shutil, 'which', return_value='notify'), patch.object(api, '_execute', side_effect=execute), \
                    patch.object(api, '_observations') as parse:
                result = api.run_engine('notify', [], 'example.com', base / 'output', 30, 1,
                                        {'send': True, 'import_file': str(payload), 'provider_config': str(config)})
                self.assertEqual(result['state'], 'complete')
                self.assertEqual(result['hosts'], [])
                self.assertEqual(result['observations'], [])
                parse.assert_not_called()
            self.assertEqual(sent_payloads, [payload.read_text()])
            self.assertNotIn('provider-secret', ' '.join(captured))
            persisted = Path(result['artifact']).read_text()
            self.assertNotIn('provider-secret', persisted)
            self.assertNotIn('private-message-secret', persisted)
            self.assertNotIn('foreign.example.org', persisted)
            self.assertNotIn('private-message-secret', json.dumps(result))
            self.assertEqual(list((base / 'output').iterdir()), [Path(result['artifact'])])

    def test_notify_missing_config_does_not_execute_or_create_output(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(api, '_execute') as execute:
            output = Path(directory) / 'out'
            result = api.run_engine('notify', [], 'example.com', output, 30, 1,
                                    {'send': True, 'import_file': 'not-read.txt'})
            self.assertEqual(result['state'], 'configuration_required')
            self.assertIn('provider_config', result['reason'])
            self.assertFalse(output.exists())
            execute.assert_not_called()

    def test_notify_oversize_payload_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(api, '_execute') as execute:
            base = Path(directory)
            payload = base / 'message'
            payload.write_bytes(b'x' * (128 * 1024 + 1))
            config = base / 'config'
            config.write_text('secret')
            result = api.run_engine('notify', [], 'example.com', base / 'out', 30, 1,
                                    {'send': True, 'import_file': str(payload), 'provider_config': str(config)})
            self.assertEqual(result['state'], 'configuration_required')
            self.assertIn('128 KiB', result['reason'])
            self.assertFalse((base / 'out').exists())
            execute.assert_not_called()

    def test_notify_failure_not_reported_as_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            payload = base / 'message'
            payload.write_text('Changes')
            config = base / 'config'
            config.write_text('secret')
            with patch.object(api.shutil, 'which', return_value='notify'), patch.object(api, '_execute', return_value='timeout'):
                result = api.run_engine('notify', [], 'example.com', base / 'out', 1, 1,
                                        {'send': True, 'import_file': str(payload), 'provider_config': str(config)})
            self.assertEqual(result['state'], 'timeout')
            self.assertNotIn('delivered', result)

    def test_doctor_handles_absent_programs_without_execution(self):
        with patch.object(api.shutil, 'which', return_value=None), patch.object(api, '_execute') as execute:
            records = api.doctor()
            self.assertEqual(len(records), 17)
            self.assertTrue(all(row['path'] is None for row in records))
            execute.assert_not_called()

    def test_subprocess_never_uses_shell(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(api.subprocess, 'Popen') as popen:
            process = popen.return_value
            process.poll.return_value = 0
            process.returncode = 0
            result = api._execute(['engine', 'literal;not-shell'], Path(directory) / 'out', 1)
            self.assertEqual(result, 'complete')
            self.assertFalse(popen.call_args.kwargs['shell'])


if __name__ == '__main__':
    unittest.main()
