import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atlas

class Tests(unittest.TestCase):
    def test_no_arguments_opens_colorful_menu(self):
        with patch.dict(atlas.os.environ, {}, clear=True), patch('builtins.input', return_value='0'), \
                contextlib.redirect_stdout(io.StringIO()) as display:
            self.assertEqual(atlas.main([]), 0)
            self.assertIn('OPERATIONS', display.getvalue())
            self.assertIn('\033[', display.getvalue())

    def test_import_preserves_provider_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'subfinder.jsonl'
            evidence.write_text(json.dumps({'host': 'api.example.com', 'sources': ['crtsh', 'certspotter']}) + '\n' +
                                json.dumps({'host': 'evil.org', 'source': 'crtsh'}))
            args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', directory])
            with contextlib.redirect_stdout(io.StringIO()):
                run = atlas.Run(args)
                run.import_file(evidence)
            self.assertEqual(set(run.names), {'api.example.com'})
            self.assertTrue(any(x.endswith(':certspotter') for x in run.names['api.example.com']))

    def test_ct_cursor_and_pagination(self):
        with tempfile.TemporaryDirectory() as directory:
            args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--sources', 'certspotter',
                                             '--ct-pages', '3', '--ct-after', '100', '-o', directory])
            with patch('atlas.fetch', side_effect=[json.dumps([{'id': '101', 'dns_names': ['api.example.com', 'evil.org']}]), '[]']) as fetch, \
                    patch('atlas.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
                run = atlas.Run(args)
                run.passive()
            self.assertIn('after=100', fetch.call_args_list[0].args[0])
            self.assertIn('after=101', fetch.call_args_list[1].args[0])
            self.assertEqual(set(run.names), {'api.example.com'})
            self.assertEqual(run.status[-1]['state'], 'ok')

    def test_full_numbered_report_and_search(self):
        with tempfile.TemporaryDirectory() as directory:
            args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', directory])
            with contextlib.redirect_stdout(io.StringIO()):
                run = atlas.Run(args)
                run.add('a.example.com b.example.com c.example.com example.com', 'fixture')
                run.save()
            with contextlib.redirect_stdout(io.StringIO()) as display:
                atlas.show_report(run.out)
            self.assertIn('b.example.com', display.getvalue())
            self.assertIn('a.example.com', display.getvalue())
            self.assertIn('c.example.com', display.getvalue())
            self.assertRegex(display.getvalue(), r'1\s+a\.example\.com')
            self.assertRegex(display.getvalue(), r'3\s+c\.example\.com')
            self.assertIn('TOTAL SUBDOMAINS: 3', display.getvalue())
            self.assertNotIn('Page 1/', display.getvalue())
            self.assertNotIn('{}', display.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as display:
                atlas.show_report(run.out, find='c.')
            self.assertIn('c.example.com', display.getvalue())
            self.assertNotIn('b.example.com', display.getvalue())

    def test_menu_returns_after_help(self):
        with patch('builtins.input', side_effect=['5', '0']), contextlib.redirect_stdout(io.StringIO()) as display:
            self.assertEqual(atlas.main(['menu']), 0)
        self.assertGreaterEqual(display.getvalue().count('OPERATIONS'), 2)

    def test_terminal_color_and_no_color(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        with patch.dict(atlas.os.environ, {}, clear=True), contextlib.redirect_stdout(Terminal()) as display:
            atlas.say('test', 35)
            self.assertIn('\033[35m', display.getvalue())
        with patch.dict(atlas.os.environ, {'NO_COLOR': '1'}), contextlib.redirect_stdout(Terminal()) as display:
            atlas.say('test', 35)
            self.assertNotIn('\033', display.getvalue())

    def test_banner_legacy_encoding(self):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding='cp1252')
        with contextlib.redirect_stdout(stream):
            atlas.banner()
        stream.flush()
        self.assertIn(b'A T L A S', buffer.getvalue())

    def test_scope_boundary_and_exclusion(self):
        self.assertTrue(atlas.scoped('api.example.com', 'example.com'))
        self.assertFalse(atlas.scoped('evilexample.com', 'example.com'))
        self.assertFalse(atlas.scoped('example.com.evil.org', 'example.com'))
        self.assertFalse(atlas.scoped('x.dev.example.com', 'example.com', ['dev.example.com']))

    def test_names(self):
        self.assertEqual(atlas.normalize('*.API.Example.com.'), 'api.example.com')
        for value in ['127.0.0.1', '-x.example.com', 'https://example.com', 'x..example.com', 'x;id.com']:
            self.assertIsNone(atlas.normalize(value))
        self.assertEqual(atlas.normalize('bücher.example'), 'xn--bcher-kva.example')

    def test_offline_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / 'evidence.txt'
            seed.write_text('https://API.example.com/a\n*.api.example.com\nevilexample.com\n<script>alert(1)</script>\nx.dev.example.com')
            with contextlib.redirect_stdout(io.StringIO()):
                code = atlas.main(['scan', '-d', 'example.com', '--offline', '--import', str(seed),
                                   '--exclude', 'dev.example.com', '-o', directory])
            self.assertEqual(code, 0)
            out = next(Path(directory).glob('example.com-*'))
            rows = [json.loads(x) for x in (out / 'assets.jsonl').read_text().splitlines()]
            self.assertEqual([r['hostname'] for r in rows], ['api.example.com'])
            self.assertEqual(rows[0]['status'], 'passive-unverified')
            self.assertTrue((out / 'report.txt').exists())
            self.assertFalse((out / 'report.html').exists())
            with contextlib.redirect_stdout(io.StringIO()) as display:
                self.assertEqual(atlas.main(['report', str(out)]), 0)
            self.assertIn('api.example.com', display.getvalue())

    def test_active_requires_acknowledgment(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            atlas.main(['scan', '-d', 'example.com', '--mode', 'active'])

    def test_wildcard_and_ipv6(self):
        # No target traffic: synthetic resolver responses.
        class Fake:
            def resolve(self, name, kind, **kwargs):
                if name == 'api.example.com' and kind == 'AAAA':
                    return ['2001:db8::1']
                if name != 'api.example.com' and kind == 'A':
                    return ['192.0.2.10']
                return []
        with tempfile.TemporaryDirectory() as directory:
            words = Path(directory) / 'words.txt'
            words.write_text('api\nwww\n')
            args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--mode', 'active',
                '--authorized', '--offline', '-w', str(words), '-o', directory, '--rate', '100000'])
            resolver_module = types.ModuleType('dns.resolver')
            resolver_module.Resolver = Fake
            dns_module = types.ModuleType('dns')
            dns_module.resolver = resolver_module
            with patch.dict(sys.modules, {'dns': dns_module, 'dns.resolver': resolver_module}), contextlib.redirect_stdout(io.StringIO()):
                run = atlas.Run(args)
                run.active()
                run.save()
            self.assertEqual(run.dns['api.example.com']['status'], 'resolved')
            self.assertEqual(run.dns['www.example.com']['status'], 'wildcard-suspect')
            self.assertIn('api.example.com', (run.out / 'resolved.txt').read_text())
            self.assertNotIn('www.example.com', (run.out / 'resolved.txt').read_text())

if __name__ == '__main__':
    unittest.main()
