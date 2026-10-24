#!/usr/bin/env python3
"""Build and smoke-test an installed wheel away from the source checkout.

Build isolation may download the declared Python build backend. No target scan,
engine installer or network reconnaissance is performed. All artifacts are kept
in an automatically removed temporary directory.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile


def run(args, cwd, env):
    subprocess.run([str(value) for value in args], cwd=cwd, env=env, check=True)


def main():
    source = Path(__file__).resolve().parents[1]
    modules = ['atlas', 'availability', 'lookups', 'dns_evidence', 'inventory',
               'integrations', 'workflows', 'run_state', 'engine_bundle']
    with tempfile.TemporaryDirectory(prefix='atlas-wheel-check-') as temporary:
        base = Path(temporary)
        build = base / 'source'
        build.mkdir()
        for filename in ['pyproject.toml', 'README.md', 'LICENSE', 'THIRD_PARTY.md']:
            shutil.copy2(source / filename, build / filename)
        for module in modules:
            shutil.copy2(source / (module + '.py'), build / (module + '.py'))
        for directory in ['atlas_data', 'man']:
            shutil.copytree(source / directory, build / directory,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        environment = os.environ.copy()
        environment.pop('PYTHONPATH', None)
        environment['ATLAS_COLOR'] = 'never'
        wheels = base / 'wheels'
        run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--wheel-dir', wheels, build], base, environment)
        wheel = next(wheels.glob('atlas_recon-*.whl'))
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            expected = {module + '.py' for module in modules} | {
                'atlas_data/__init__.py', 'atlas_data/starter.txt', 'atlas_data/atlas.1', 'atlas_data/engines.lock.json'}
            if expected - names:
                raise RuntimeError('Wheel missing files: ' + ', '.join(sorted(expected - names)))
            if not any(name.endswith('/share/man/man1/atlas.1') for name in names):
                raise RuntimeError('Wheel missing installable man page')
            if any('/results/' in name or '.venv' in name for name in names):
                raise RuntimeError('Wheel contains local runtime artifacts')
        target = base / 'installed'
        venv.EnvBuilder(with_pip=True).create(target)
        binary = target / ('Scripts' if os.name == 'nt' else 'bin')
        python = binary / ('python.exe' if os.name == 'nt' else 'python')
        atlas = binary / ('atlas.exe' if os.name == 'nt' else 'atlas')
        run([python, '-m', 'pip', 'install', wheel], base, environment)
        run([atlas, '--version'], base, environment)
        run([atlas, '--help'], base, environment)
        code = ("import importlib.resources as r; "
                "assert r.files('atlas_data').joinpath('starter.txt').read_text().strip(); "
                "assert 'ATLAS' in r.files('atlas_data').joinpath('atlas.1').read_text(); "
                "import inventory,run_state,workflows,dns_evidence,integrations")
        run([python, '-c', code], base, environment)
        fixture = base / 'names.txt'
        fixture.write_text('api.example.com\nwww.example.com\n', encoding='utf-8')
        run([atlas, 'scan', '-d', 'example.com', '--offline', '--import', fixture,
             '-o', base / 'offline-results'], base, environment)
        print('Installed-wheel smoke check passed; no reconnaissance requests performed.')


if __name__ == '__main__':
    main()
