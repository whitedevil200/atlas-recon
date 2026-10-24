import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import zipfile

import engine_bundle as bundle


class BundleTests(unittest.TestCase):
    def archive(self, filename='subfinder.exe'):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr(filename, b'fixture executable')
            archive.writestr('LICENSE', 'fixture license')
        return data.getvalue()

    def test_hash_mismatch_rejected_before_unpack(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            bundle.unpack(self.archive(), 'subfinder', '0' * 64, True)

    def test_extracts_only_expected_binary_and_keeps_license(self):
        data = self.archive('../../subfinder.exe')
        binary, notices = bundle.unpack(data, 'subfinder', hashlib.sha256(data).hexdigest(), True)
        self.assertEqual(binary, b'fixture executable')
        self.assertEqual(notices['LICENSE'], 'fixture license')

    def test_missing_binary_rejected(self):
        data = self.archive('other.exe')
        with self.assertRaisesRegex(ValueError, 'Unexpected executable'):
            bundle.unpack(data, 'subfinder', hashlib.sha256(data).hexdigest(), True)

    def test_pins_cover_all_supported_platforms_and_seven_engines(self):
        for key, engines in bundle.manifest().items():
            self.assertIn(key, ['linux_amd64', 'linux_arm64', 'windows_amd64'])
            self.assertEqual(len(engines), 7)
            for record in engines.values():
                self.assertRegex(record['sha256'], r'^[0-9a-f]{64}$')
                self.assertTrue(record['url'].startswith('https://github.com/'))
                self.assertNotIn('/latest/', record['url'])

    def test_install_is_idempotent_and_detects_tampering(self):
        data = self.archive()
        record = {'version': 'v1', 'license': 'MIT', 'url': 'https://github.com/fixture/repo/releases/download/v1/tool.zip',
                  'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        response = MagicMock()
        response.__enter__.return_value.read.return_value = data
        with tempfile.TemporaryDirectory() as directory, patch.object(bundle, 'platform_key', return_value='windows_amd64'), \
                patch.object(bundle, 'manifest', return_value={'windows_amd64': {'subfinder': record}}), \
                patch.dict(os.environ, {'ATLAS_ENGINE_HOME': directory}), \
                patch.object(bundle.urllib.request, 'urlopen', return_value=response) as fetch:
            self.assertEqual(bundle.install(), 0)
            self.assertEqual(bundle.install(), 0)
            self.assertEqual(fetch.call_count, 1)
            (Path(directory) / 'windows_amd64' / 'bin' / 'subfinder.exe').write_bytes(b'tampered')
            self.assertEqual(bundle.install(), 0)
            self.assertEqual(fetch.call_count, 2)

    def test_failed_download_retains_previous_binary(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'ATLAS_ENGINE_HOME': directory}), \
                patch.object(bundle, 'platform_key', return_value='windows_amd64'), \
                patch.object(bundle.urllib.request, 'urlopen', side_effect=OSError('offline')):
            binary = Path(directory) / 'windows_amd64' / 'bin' / 'subfinder.exe'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'previous')
            self.assertEqual(bundle.install(['subfinder']), 1)
            self.assertEqual(binary.read_bytes(), b'previous')

    def test_list_does_not_download(self):
        with patch.object(bundle, 'platform_key', return_value='linux_amd64'), \
                patch.object(bundle.urllib.request, 'urlopen') as fetch:
            self.assertEqual(bundle.install(list_only=True), 0)
            fetch.assert_not_called()

    def test_enrichment_is_retained_and_successful_stages_resume_without_relaunch(self):
        import atlas
        import integrations
        with tempfile.TemporaryDirectory() as directory:
            args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--mode', 'active',
                        '--authorized', '--http', '--free-engines', '-o', directory])
            run = atlas.Run(args)
            run.add('api.example.com', 'fixture')
            run.dns['api.example.com'] = {'status': 'resolved', 'records': {}}
            def response(name, hosts, root, output, **kwargs):
                self.assertEqual(hosts, ['api.example.com'])
                return {'state': 'complete', 'observations': [{'host': 'api.example.com', 'source': name,
                        'evidence': {'status_code': 200}}]}
            with patch.object(integrations, 'run_engine', side_effect=response) as execute:
                run.free_engine_enrichment()
                run.free_engine_enrichment()
                self.assertEqual(execute.call_count, 3)
            self.assertEqual(set(run.dns['api.example.com']['enrichment']), {'dnsx', 'httpx', 'tlsx'})
            self.assertTrue((run.out / 'engines' / 'httpx' / 'result.json').exists())

    def test_enrichment_timeout_is_visible_and_retryable(self):
        import atlas
        import integrations
        with tempfile.TemporaryDirectory() as directory:
            args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--mode', 'active',
                        '--authorized', '--free-engines', '-o', directory])
            run = atlas.Run(args)
            run.add('api.example.com', 'fixture')
            with patch.object(integrations, 'run_engine', return_value={'state': 'timeout', 'observations': []}):
                run.free_engine_enrichment()
            self.assertNotIn('bundle:dnsx', run.progress)
            self.assertEqual(run.status[-1]['state'], 'timeout')


if __name__ == '__main__':
    unittest.main()
