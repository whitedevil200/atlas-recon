"""Atomic JSON recovery, reproducibility and bounded observation utilities."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=True, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def manifest(settings, files=()):
    data = {'schema_version': 2, 'python': sys.version.split()[0], 'settings': settings,
            'files': {str(Path(p).resolve()): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                      for p in files if p and Path(p).is_file()}}
    data['configuration_hash'] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return data


def verify_manifest(data):
    original = {k: v for k, v in data.items() if k != 'configuration_hash'}
    expected = hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest()
    if data.get('configuration_hash') != expected:
        raise ValueError('Checkpoint configuration manifest changed; start a new run')
    for filename, expected in data.get('files', {}).items():
        path = Path(filename)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Resume input changed or is missing: ' + filename + '; start a new scan instead')


def read_state(directory):
    path = Path(directory) / 'checkpoint.json'
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError('Checkpoint exceeds the supported 100 MiB recovery limit')
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != 2:
        raise ValueError('Unsupported checkpoint schema; import the saved inventory into a new run')
    verify_manifest(data.get('manifest', {}))
    if data.get('settings') != data['manifest']['settings']:
        raise ValueError('Checkpoint settings differ from the original run manifest')
    return data


def select_serials(text, count, maximum=100):
    selected = set()
    for part in text.split(','):
        values = part.strip().split('-')
        if len(values) not in (1, 2) or any(not x.isdecimal() for x in values):
            raise ValueError('Serial selection must look like 2,5,8-12')
        first, last = int(values[0]), int(values[-1])
        if first < 1 or last < first or last > count or last - first >= maximum:
            raise ValueError(f'Serials must be within 1..{count}; maximum selection {maximum}')
        selected.update(range(first, last + 1))
        if len(selected) > maximum:
            raise ValueError('Selection exceeds the batch limit')
    return sorted(selected)


def assessment(row):
    """Explainable review leads, never a claim of vulnerability or ownership."""
    findings = []
    records = row.get('records') or {}
    if records.get('CNAME') and not records.get('A') and not records.get('AAAA'):
        findings.append({'type': 'cname-without-address', 'priority': 'review',
                         'reason': 'Alias returned without a usable address; inspect the full chain. Not confirmed takeover.'})
    if row.get('status') == 'wildcard-suspect':
        findings.append({'type': 'wildcard', 'priority': 'review', 'reason': 'Answer overlaps randomized wildcard evidence.'})
    for answer in row.get('http', []):
        if 'error' in answer and any(x in answer['error'].lower() for x in ('certificate', 'ssl', 'tls')):
            findings.append({'type': 'tls-error', 'priority': 'review', 'reason': answer['error'][:200]})
    return findings
