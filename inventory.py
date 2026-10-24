"""Durable local observations, provenance, checkpoints, and honest run comparisons.

Only the standard library is required. A run directory is the idempotency key;
recording it again updates that snapshot while retaining other runs' history.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

NAMESPACE = uuid.UUID('5594429b-396c-49fd-8d55-f006b02bb1ae')


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, default=str)


def asset_id(root, hostname, view='public'):
    """Stable UUID independent of report ordering, sources, and run location."""
    return str(uuid.uuid5(NAMESPACE, canonical([root.lower().rstrip('.'),
                     hostname.lower().rstrip('.'), view])))


def load_run(directory):
    directory = Path(directory)
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    rows = [json.loads(line) for line in (directory / 'assets.jsonl').read_text(
        encoding='utf-8').splitlines() if line.strip()]
    return summary, rows


def _stages(summary):
    return {str(s['stage']): s for s in summary.get('stages', []) if 'stage' in s}


_OBSERVATION_METADATA = {
    'sr_no', 'asset_id', 'sources', 'discoveries', 'review', 'timestamp',
    'observed_at', 'checked_at', 'collected_at', 'time_utc', 'first_seen',
    'last_seen', 'updated_at', 'created_at', 'duration', 'elapsed',
    'duration_seconds', 'elapsed_seconds', 'latency', 'latency_seconds',
    'response_time', 'response_time_seconds', 'cached', 'cache', 'cache_hit',
    'ttl', 'remaining_ttl', 'resolver', 'resolver_metrics',
    'metrics', 'queries', 'retries', 'attempts', 'samples',
}
_UNORDERED_VALUES = {
    'a', 'aaaa', 'cname', 'ns', 'mx', 'txt', 'ptr', 'caa', 'srv', 'soa',
    'values', 'answers', 'cnames', 'ips', 'ip_addresses', 'subject_an',
    'subject_alt_names', 'sans', 'dns_names', 'technologies', 'tech',
}


def _comparison_value(key, value):
    """Normalize semantic evidence only; raw records in SQLite stay untouched.

    Certificate validity dates, DNS state/rcode, trusted-resolver agreement,
    HTTP status and TLS identity/status remain meaningful. Collection clocks,
    TTL countdowns, caches, resolver identity and presentation/provenance do not.
    Ordered structures (e.g. redirect chains) retain their ordering.
    """
    if isinstance(value, dict):
        return {name: _comparison_value(name, item) for name, item in value.items()
                if name.lower() not in _OBSERVATION_METADATA}
    if isinstance(value, list):
        normalized = [_comparison_value(key, item) for item in value]
        if key.lower() in _UNORDERED_VALUES or key.lower() == 'records':
            return sorted(normalized, key=canonical)
        return normalized
    return value


def compare_runs(old_directory, new_directory):
    """Compare saved observations, never treating absence as confirmed deletion."""
    old, old_rows = load_run(old_directory)
    new, new_rows = load_run(new_directory)
    old_root, new_root = old['root'].lower().rstrip('.'), new['root'].lower().rstrip('.')
    old_view = old.get('view', old.get('settings', {}).get('view', 'public'))
    new_view = new.get('view', new.get('settings', {}).get('view', 'public'))
    if (old_root, old_view) != (new_root, new_view):
        raise ValueError('Run comparisons require the same root and DNS view')
    old_map = {r['hostname'].lower().rstrip('.'): r for r in old_rows}
    new_map = {r['hostname'].lower().rstrip('.'): r for r in new_rows}
    before_stages, after_stages = _stages(old), _stages(new)
    regressions = []
    for stage, previous in sorted(before_stages.items()):
        current = after_stages.get(stage, {'stage': stage, 'state': 'not-run'})
        if previous.get('state') == 'ok' and current.get('state') != 'ok':
            regressions.append({'stage': stage, 'before': previous.get('state'),
                                'after': current.get('state'), 'detail': current.get('detail', '')})
    notes = []
    if old.get('mode') != new.get('mode'):
        notes.append('Run modes differ')
    if set(before_stages) != set(after_stages):
        notes.append('Provider/stage coverage differs')
    if not before_stages or not after_stages:
        notes.append('Provider coverage evidence is missing')
    if any(s.get('state') != 'ok' for s in list(before_stages.values()) + list(after_stages.values())):
        notes.append('One or more provider/stages did not finish successfully')
    # Collection scope and depth affect absence claims; output paths/rate do not.
    scope_keys = ('exclude', 'sources', 'mode', 'wordlist', 'max_candidates', 'ct_pages',
                  'recursive_depth', 'view', 'engine', 'engines', 'resolvers',
                  'trusted_resolvers', 'max_queries')
    if any(old.get('settings', {}).get(k) != new.get('settings', {}).get(k) for k in scope_keys):
        notes.append('Collection scope or depth settings differ')
    changed = []
    for host in sorted(old_map.keys() & new_map.keys()):
        a, b = old_map[host], new_map[host]
        fields = {}
        for key in sorted(k for k in (a.keys() | b.keys())
                          if k != 'hostname' and k.lower() not in _OBSERVATION_METADATA):
            if canonical(_comparison_value(key, a.get(key))) != canonical(_comparison_value(key, b.get(key))):
                fields[key] = {'before': a.get(key), 'after': b.get(key)}
        if fields:
            changed.append({'hostname': host, 'asset_id': asset_id(old_root, host, old_view), 'fields': fields})
    return {'root': new_root, 'view': new_view,
            'old_directory': str(Path(old_directory).resolve()),
            'new_directory': str(Path(new_directory).resolve()),
            'old_run_id': old.get('run_id'), 'new_run_id': new.get('run_id'),
            'new': sorted(new_map.keys() - old_map.keys()),
            'not_observed': sorted(old_map.keys() - new_map.keys()),
            'changed': changed, 'coverage_regressions': regressions,
            'comparable': not notes and not regressions, 'comparison_notes': notes,
            'absence_meaning': 'Not observed in this run; not proof of deletion or downtime'}


class Inventory:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA foreign_keys=ON')
        self.connection.execute('PRAGMA busy_timeout=30000')
        self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, directory TEXT UNIQUE NOT NULL,
                root TEXT NOT NULL, view TEXT NOT NULL, observed_at TEXT NOT NULL,
                summary_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY, root TEXT NOT NULL, hostname TEXT NOT NULL,
                view TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                UNIQUE(root, hostname, view));
            CREATE TABLE IF NOT EXISTS observations (
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                asset_id TEXT NOT NULL REFERENCES assets(asset_id),
                observed_at TEXT NOT NULL, record_json TEXT NOT NULL,
                PRIMARY KEY(run_id, asset_id));
            CREATE TABLE IF NOT EXISTS source_health (
                run_id TEXT NOT NULL REFERENCES runs(run_id), source TEXT NOT NULL,
                record_json TEXT NOT NULL, PRIMARY KEY(run_id, source));
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL, event_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoints (
                run_id TEXT NOT NULL, name TEXT NOT NULL, updated_at TEXT NOT NULL,
                snapshot_json TEXT NOT NULL, PRIMARY KEY(run_id, name));
            CREATE TABLE IF NOT EXISTS jobs (
                run_id TEXT NOT NULL, job_id TEXT NOT NULL, state TEXT NOT NULL,
                updated_at TEXT NOT NULL, payload_json TEXT NOT NULL,
                PRIMARY KEY(run_id, job_id));
            CREATE INDEX IF NOT EXISTS history_assets ON observations(asset_id, observed_at);
        ''')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        self.connection.close()

    def record_run(self, directory, summary, rows):
        directory = str(Path(directory).resolve())
        root, view = summary['root'].lower().rstrip('.'), summary.get('view', 'public')
        timestamp = summary.get('time_utc') or now()
        existing = self.connection.execute('SELECT run_id, root, view FROM runs WHERE directory=?',
                                            (directory,)).fetchone()
        if existing and (existing['root'], existing['view']) != (root, view):
            raise ValueError('An inventory run directory cannot be reused for another root or view')
        run_id = existing['run_id'] if existing else str(uuid.uuid5(NAMESPACE, directory))
        summary['run_id'] = run_id
        with self.connection:
            self.connection.execute('''INSERT INTO runs VALUES(?,?,?,?,?,?)
                ON CONFLICT(run_id) DO UPDATE SET observed_at=excluded.observed_at,
                summary_json=excluded.summary_json''',
                (run_id, directory, root, view, timestamp, canonical(summary)))
            # Upsert a single snapshot per run/asset without losing older runs.
            for row in rows:
                host = row['hostname'].lower().rstrip('.')
                identifier = asset_id(root, host, view)
                row['asset_id'] = identifier
                self.connection.execute('''INSERT INTO assets VALUES(?,?,?,?,?,?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                    first_seen=MIN(first_seen,excluded.first_seen),
                    last_seen=MAX(last_seen,excluded.last_seen)''',
                    (identifier, root, host, view, timestamp, timestamp))
                self.connection.execute('''INSERT INTO observations VALUES(?,?,?,?)
                    ON CONFLICT(run_id,asset_id) DO UPDATE SET
                    observed_at=excluded.observed_at, record_json=excluded.record_json''',
                    (run_id, identifier, timestamp, canonical(row)))
            self.connection.execute('DELETE FROM source_health WHERE run_id=?', (run_id,))
            for source, stage in _stages(summary).items():
                self.connection.execute('INSERT INTO source_health VALUES(?,?,?)',
                                        (run_id, source, canonical(stage)))
        return run_id

    def asset_history(self, hostname, root=None):
        host = hostname.lower().rstrip('.')
        query = '''SELECT o.record_json,o.observed_at,r.run_id,r.root,r.view,r.directory
            FROM observations o JOIN assets a ON o.asset_id=a.asset_id
            JOIN runs r ON o.run_id=r.run_id WHERE a.hostname=?'''
        params = [host]
        if root:
            query += ' AND a.root=?'
            params.append(root.lower().rstrip('.'))
        query += ' ORDER BY o.observed_at,r.run_id'
        return [dict(json.loads(r['record_json']), run_id=r['run_id'], root=r['root'],
                     view=r['view'], observed_at=r['observed_at'], directory=r['directory'])
                for r in self.connection.execute(query, params)]

    def run_diff(self, old_directory, new_directory):
        return compare_runs(old_directory, new_directory)

    def source_health(self, run_id):
        return [json.loads(row[0]) for row in self.connection.execute(
            'SELECT record_json FROM source_health WHERE run_id=? ORDER BY source', (run_id,))]

    def record_event(self, run_id, event):
        """Idempotent provenance events; caller may supply an event_id for updates."""
        timestamp = event.get('timestamp') or now()
        identifier = event.get('event_id') or str(uuid.uuid5(NAMESPACE, run_id + canonical(event)))
        with self.connection:
            self.connection.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?)',
                                    (identifier, run_id, timestamp, canonical(event)))
        return identifier

    def checkpoint(self, run_id, name, snapshot):
        """Persist JSON-compatible external state atomically; contains no Python pickle."""
        with self.connection:
            self.connection.execute('''INSERT INTO checkpoints VALUES(?,?,?,?)
                ON CONFLICT(run_id,name) DO UPDATE SET updated_at=excluded.updated_at,
                snapshot_json=excluded.snapshot_json''', (run_id, name, now(), canonical(snapshot)))

    def load_checkpoint(self, run_id, name):
        row = self.connection.execute('SELECT snapshot_json FROM checkpoints WHERE run_id=? AND name=?',
                                       (run_id, name)).fetchone()
        return json.loads(row[0]) if row else None

    def put_job(self, run_id, job_id, payload, state='pending'):
        if state not in {'pending', 'running', 'done', 'failed', 'cancelled'}:
            raise ValueError('Invalid job state')
        with self.connection:
            self.connection.execute('''INSERT INTO jobs VALUES(?,?,?,?,?)
                ON CONFLICT(run_id,job_id) DO UPDATE SET state=excluded.state,
                updated_at=excluded.updated_at,payload_json=excluded.payload_json''',
                (run_id, job_id, state, now(), canonical(payload)))

    def jobs(self, run_id, states=None):
        rows = self.connection.execute('SELECT * FROM jobs WHERE run_id=? ORDER BY job_id', (run_id,))
        return [dict(job_id=r['job_id'], state=r['state'], updated_at=r['updated_at'],
                     payload=json.loads(r['payload_json'])) for r in rows
                if not states or r['state'] in states]


def history(path, hostname, root=None):
    with Inventory(path) as inventory:
        return inventory.asset_history(hostname, root)


def manifest(settings, files=()):
    """Portable reproducibility metadata; caller must omit secrets from settings."""
    hashes = {}
    for filename in files:
        path = Path(filename)
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'schema_version': 1, 'created_at': now(), 'settings': settings,
            'settings_sha256': hashlib.sha256(canonical(settings).encode()).hexdigest(),
            'files_sha256': hashes}
