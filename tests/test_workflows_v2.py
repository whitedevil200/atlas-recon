import contextlib
import csv
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atlas
import integrations
import inventory
import run_state
import workflows


class WorkflowV2Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'results'
        self.source = self.root / 'input.txt'
        self.source.write_text('example.com\nz.example.com\na.example.com\n', encoding='utf-8')

    def command(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            result = atlas.main(arguments)
        return result, captured.getvalue()

    def scan(self, **extra):
        args = ['scan', '-d', 'example.com', '--offline', '--import', str(self.source),
                '-o', str(self.output), '--no-lookup']
        for key, value in extra.items():
            args += ['--' + key.replace('_', '-'), str(value)]
        before = set(self.output.glob('example.com-*'))
        code, text = self.command(args)
        self.assertEqual(code, 0, text)
        return next(p for p in self.output.glob('example.com-*') if p not in before)

    def test_scan_manifest_checkpoint_sqlite_history_and_stable_asset_ids(self):
        first, second = self.scan(), self.scan()
        summary, rows = atlas.load_assets(first)
        self.assertTrue((first / 'manifest.json').is_file())
        self.assertEqual(run_state.read_state(first)['state'], 'complete')
        self.assertIn(str(self.source.resolve()), summary['manifest']['files'])
        self.assertFalse(summary['complete_enumeration_guaranteed'])
        _, later = atlas.load_assets(second)
        self.assertEqual({r['hostname']: r['asset_id'] for r in rows},
                         {r['hostname']: r['asset_id'] for r in later})
        with inventory.Inventory(self.output / 'atlas.sqlite3') as store:
            self.assertEqual(len(store.asset_history('a.example.com', 'example.com')), 2)
        with contextlib.closing(sqlite3.connect(self.output / 'atlas.sqlite3')) as database:
            self.assertEqual(database.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0], 2)

    def test_csv_export_serials_match_report_order_and_exclude_apex(self):
        run = self.scan()
        summary, rows = atlas.load_assets(run)
        ordered = atlas.ordered_subdomains(summary, rows)
        with (run / 'assets.csv').open(newline='', encoding='utf-8') as stream:
            saved = list(csv.DictReader(stream))
        self.assertEqual([r['hostname'] for r in saved], [r['hostname'] for r in ordered])
        self.assertEqual([r['sr_no'] for r in saved], ['1', '2'])
        self.assertNotIn('example.com', [r['hostname'] for r in saved])
        export = self.root / 'export.csv'
        with contextlib.redirect_stdout(io.StringIO()):
            atlas.export_report(run, export, 'csv')
        with export.open(newline='', encoding='utf-8') as stream:
            self.assertEqual([r['hostname'] for r in csv.DictReader(stream)], ['a.example.com', 'z.example.com'])

    def test_resume_from_different_cwd_keeps_run_and_rejects_changed_input(self):
        run = self.scan()
        other = self.root / 'elsewhere'
        other.mkdir()
        previous = Path.cwd()
        try:
            os.chdir(other)
            code, text = self.command(['resume', str(run), '--no-lookup'])
        finally:
            os.chdir(previous)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(list(self.output.glob('example.com-*'))), 1)
        self.source.write_text('changed.example.com\n', encoding='utf-8')
        code, text = self.command(['resume', str(run), '--no-lookup'])
        self.assertEqual(code, 2)
        self.assertIn('input changed', text)

    def test_active_resume_requires_new_explicit_authorization(self):
        args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--mode', 'active', '--authorized',
                                         '--offline', '-o', str(self.output), '--no-lookup'])
        run = atlas.Run(args)
        run.checkpoint()
        code, text = self.command(['resume', str(run.out), '--no-lookup'])
        self.assertEqual(code, 2)
        self.assertIn('requires --authorized', text)
        with patch('atlas.execute_scan', return_value=0) as execute:
            code, text = self.command(['resume', str(run.out), '--authorized', '--no-lookup'])
        self.assertEqual(code, 0, text)
        self.assertTrue(execute.call_args.args[0].authorized)

    def test_diff_history_evidence_health_workflow_commands(self):
        first = self.scan()
        self.source.write_text('a.example.com\nnew.example.com\n', encoding='utf-8')
        second = self.scan()
        destination = self.root / 'diff.json'
        code, text = self.command(['diff', str(first), str(second), '-o', str(destination)])
        self.assertEqual(code, 0, text)
        diff = json.loads(destination.read_text())
        self.assertEqual(diff['new'], ['new.example.com'])
        self.assertIn('z.example.com', diff['not_observed'])
        self.assertIn('not proof', diff['absence_meaning'])
        for args, expected in [(['history', 'a.example.com', '--database', str(self.output / 'atlas.sqlite3')], '2 saved observations'),
                               (['evidence', str(second), '--serial', '1-2'], 'Asset ID:'),
                               (['health', str(second)], 'Completeness is not guaranteed')]:
            code, text = self.command(args)
            self.assertEqual(code, 0, text)
            self.assertIn(expected, text)

    def test_batch_serial_bounds_and_duplicate_selection(self):
        run = self.scan()
        self.assertEqual([r['hostname'] for r in workflows.chosen(run, '2,1-2')[2]], ['a.example.com', 'z.example.com'])
        for serial in ('0', '3', '2-1', '1-999999999', 'a', '1,,2'):
            with self.assertRaises(ValueError, msg=serial):
                workflows.chosen(run, serial)
        with self.assertRaises(ValueError):
            workflows.chosen(run, 'all', limit=1)

    def test_owner_import_normalized_names_and_private_public_views(self):
        export = self.root / 'owner.json'
        export.write_text(json.dumps({'ResourceRecordSets': [{'Name': 'API.Example.COM.', 'Type': 'A'},
                                                            {'Name': 'outside.invalid.', 'Type': 'A'}]}))
        ids = []
        for view in ('public', 'private'):
            before = set(self.output.glob('example.com-*'))
            code, text = self.command(['owner-import', 'aws', str(export), '-d', 'example.com',
                                       '--authorized', '--view', view, '-o', str(self.output)])
            self.assertEqual(code, 0, text)
            run = next(p for p in self.output.glob('example.com-*') if p not in before)
            summary, rows = atlas.load_assets(run)
            self.assertEqual(summary['view'], view)
            self.assertEqual([r['hostname'] for r in rows], ['api.example.com'])
            self.assertEqual(rows[0]['enrichment']['view'], view)
            ids.append(rows[0]['asset_id'])
        self.assertNotEqual(*ids)

    def test_two_cycle_watch_offline_has_no_false_changes(self):
        with patch('workflows.time.sleep') as sleep, patch('atlas.fetch', side_effect=AssertionError('network forbidden')):
            code, text = self.command(['watch', '-d', 'example.com', '--offline', '--import', str(self.source),
                                       '--cycles', '2', '--interval', '10', '-o', str(self.output)])
        self.assertEqual(code, 0, text)
        sleep.assert_called_once_with(10)
        diffs = list(self.output.glob('example.com-*/diff.json'))
        self.assertEqual(len(diffs), 1)
        diff = json.loads(diffs[0].read_text())
        self.assertEqual(diff['new'], [])
        self.assertEqual(diff['not_observed'], [])
        self.assertEqual(diff['changed'], [])

    def test_missing_engine_returns_explicit_graceful_state(self):
        with patch('integrations.shutil.which', return_value=None):
            result = integrations.run_engine('dnsx', ['api.example.com'], 'example.com', self.root / 'engine')
        self.assertEqual(result['state'], 'not_installed')
        self.assertEqual(result['hosts'], [])

    def test_streaming_tool_timeout_retains_complete_partial_observations(self):
        args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', str(self.output),
                                         '--no-lookup', '--tool-timeout', '1'])
        run = atlas.Run(args)
        started = time.monotonic()
        with patch('atlas.shutil.which', return_value=sys.executable), contextlib.redirect_stdout(io.StringIO()):
            run.tool('assetfinder', ['assetfinder', '-c', "import time; print('partial.example.com',flush=True); time.sleep(30)"])
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn('partial.example.com', run.names)
        self.assertEqual(run.status[-1]['state'], 'partial')

    def test_manifest_settings_tampering_is_rejected_before_resume(self):
        run = self.scan()
        path = run / 'checkpoint.json'
        saved = json.loads(path.read_text())
        saved['manifest']['settings']['max_candidates'] += 1
        path.write_text(json.dumps(saved), encoding='utf-8')
        code, text = self.command(['resume', str(run), '--no-lookup'])
        self.assertEqual(code, 2)
        self.assertIn('manifest changed', text)

    def test_resume_availability_skips_completed_and_retains_asset_ids(self):
        run = self.scan()
        _, original_rows = atlas.load_assets(run)
        identifiers = {r['hostname']: r['asset_id'] for r in original_rows}
        def interrupted(names, workers, timeout, rate, dns_only, callback):
            callback(names[0], {'availability': 'UP', 'records': {'A': ['192.0.2.1'], 'AAAA': [], 'CNAME': []},
                                'checked_at': 'completed-before-interruption'})
            raise KeyboardInterrupt()
        with patch('availability.check_all', side_effect=interrupted):
            code, text = self.command(['check', str(run), '--authorized'])
        self.assertEqual(code, 130, text)
        checked = next(self.output.glob('example.com-checked-*'))
        observed = []
        def finish(names, workers, timeout, rate, dns_only, callback):
            observed.extend(names)
            for name in names:
                callback(name, {'availability': 'NO_DNS', 'records': {'A': [], 'AAAA': [], 'CNAME': []}})
        with patch('availability.check_all', side_effect=finish):
            code, text = self.command(['resume', str(checked), '--authorized', '--no-lookup'])
        self.assertEqual(code, 0, text)
        self.assertEqual(observed, ['z.example.com'])
        summary, rows = atlas.load_assets(checked)
        self.assertEqual(summary['checked'], 2)
        self.assertEqual(summary['check_state'], 'complete')
        self.assertEqual(next(r for r in rows if r['hostname'] == 'a.example.com')['checked_at'], 'completed-before-interruption')
        self.assertEqual({r['hostname']: r['asset_id'] for r in rows}, {k: v for k, v in identifiers.items() if k != 'example.com'})

    def test_availability_history_uses_custom_database(self):
        database = self.root / 'custom' / 'observations.sqlite3'
        run = self.scan(database=database)
        def checks(names, workers, timeout, rate, dns_only, callback):
            for name in names:
                callback(name, {'availability': 'NO_DNS', 'records': {'A': [], 'AAAA': [], 'CNAME': []}})
        with patch('availability.check_all', side_effect=checks):
            code, text = self.command(['check', str(run), '--authorized'])
        self.assertEqual(code, 0, text)
        with inventory.Inventory(database) as store:
            history = store.asset_history('a.example.com', 'example.com')
        self.assertEqual(len(history), 2)
        self.assertIn('NO_DNS', [r.get('availability') for r in history])
        self.assertFalse((self.output / 'atlas.sqlite3').exists())

    def test_private_inventory_blocks_lookup_and_checks_before_network(self):
        run = self.scan(view='private')
        for arguments, blocked in [(['lookup', str(run), '--serial', '1', '--kind', 'whois'], 'lookups.enrich'),
                                   (['check', str(run), '--authorized'], 'availability.check_all')]:
            with patch(blocked) as network:
                code, text = self.command(arguments)
            self.assertEqual(code, 2, text)
            self.assertIn('--allow-private', text)
            network.assert_not_called()
        parsed = atlas.parser().parse_args(['lookup', str(run), '--serial', '1', '--kind', 'whois', '--allow-private'])
        self.assertTrue(parsed.allow_private)
        with patch('lookups.enrich', return_value={'partial': False}) as lookup, patch('lookups.show'), patch('lookups.save', return_value='fixture.json'):
            code, text = self.command(['lookup', str(run), '--serial', '1', '--kind', 'whois', '--allow-private'])
        self.assertEqual(code, 0, text)
        lookup.assert_called_once()

    def test_successful_streaming_process_is_recorded_ok(self):
        args = atlas.parser().parse_args(['scan', '-d', 'example.com', '--offline', '-o', str(self.output), '--no-lookup'])
        run = atlas.Run(args)
        with patch('atlas.shutil.which', return_value=sys.executable), contextlib.redirect_stdout(io.StringIO()):
            text = run.tool('assetfinder', ['assetfinder', '-c', "print('complete.example.com',flush=True)"])
        self.assertIn('complete.example.com', text)
        self.assertIn('complete.example.com', run.names)
        self.assertEqual(run.status[-1]['state'], 'ok')

    def test_failed_notification_retained_then_explicit_retry_delivers(self):
        base = ['watch', '-d', 'example.com', '--offline', '--import', str(self.source),
                '--cycles', '1', '--interval', '10', '-o', str(self.output)]
        code, text = self.command(base)
        self.assertEqual(code, 0, text)
        self.source.write_text('a.example.com\nz.example.com\nnew.example.com\nexample.com\n', encoding='utf-8')
        config = self.root / 'notify.yaml'
        config.write_text('fixture: no-real-credentials\n')
        notify = base + ['--notify', '--notify-config', str(config)]
        with patch('integrations.run_engine', return_value={'state': 'failed'}) as engine:
            code, text = self.command(notify)
        self.assertEqual(code, 0, text)
        engine.assert_called_once()
        state_path = self.output / 'watch-example.com.json'
        failed = json.loads(state_path.read_text())
        self.assertEqual(len(failed['pending_alerts']), 1)
        self.assertEqual(failed['pending_alerts'][0]['attempts'], 1)
        digest = failed['pending_alerts'][0]['digest']
        with patch('integrations.run_engine', return_value={'state': 'complete'}) as engine:
            code, text = self.command(notify + ['--retry-notifications'])
        self.assertEqual(code, 0, text)
        engine.assert_called_once()
        delivered = json.loads(state_path.read_text())
        self.assertEqual(delivered['pending_alerts'], [])
        self.assertEqual(delivered['last_digest'], digest)


if __name__ == '__main__':
    unittest.main()
