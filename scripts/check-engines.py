#!/usr/bin/env python3
"""Exercise the installed free binaries without scanning any target."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import engine_bundle

engine_bundle.activate()
engines = engine_bundle.manifest()[engine_bundle.platform_key()]
for name in engines:
    path = shutil.which(name)
    if not path:
        raise RuntimeError('Missing managed engine: ' + name)
    process = subprocess.run([path, '--version' if name == 'findomain' else '-version'],
                             capture_output=True, timeout=20)
    if process.returncode:
        raise RuntimeError('Version check failed: ' + name)
    print(name + ': executable started successfully')
process = subprocess.run(['subfinder', '-ls', '-oJ', '-duc'], capture_output=True, timeout=20, check=True)
sources = {}
for line in process.stdout.decode('utf-8', 'replace').splitlines():
    try:
        row = json.loads(line)
        sources[row['name']] = row
    except (ValueError, KeyError, TypeError):
        pass
for name in ['crtsh', 'waybackarchive', 'rapiddns', 'digitorus', 'shodanct']:
    if sources.get(name, {}).get('keyRequirement') != 'none':
        raise RuntimeError('Subfinder source is no longer keyless: ' + name)
print('Seven real binary checks and keyless provider metadata passed; no target was scanned.')
