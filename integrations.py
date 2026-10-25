"""Optional, bounded external integrations. Nothing is installed automatically.

Registry presence is not a claim that an executable was tested locally. Complex
engines deliberately require import of their output rather than guessed flags.
"""
from __future__ import annotations

import engine_bundle
engine_bundle.activate()
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

_REPOS = {
    'subfinder': ('projectdiscovery/subfinder', 'MIT', 'passive'),
    'assetfinder': ('tomnomnom/assetfinder', 'MIT', 'passive'),
    'findomain': ('Findomain/Findomain', 'GPL-3.0', 'passive'),
    'dnsx': ('projectdiscovery/dnsx', 'MIT', 'dns'),
    'puredns': ('d3mondev/puredns', 'GPL-3.0', 'dns'),
    'massdns': ('blechschmidt/massdns', 'GPL-3.0', 'dns'),
    'shuffledns': ('projectdiscovery/shuffledns', 'GPL-3.0', 'dns'),
    'alterx': ('projectdiscovery/alterx', 'MIT', 'generation'),
    'gotator': ('Josue87/gotator', 'GPL-3.0', 'generation'),
    'httpx': ('projectdiscovery/httpx', 'MIT', 'http'),
    'tlsx': ('projectdiscovery/tlsx', 'MIT', 'tls'),
    'bbot': ('blacklanternsecurity/bbot', 'AGPL-3.0', 'recursive'),
    'amass': ('owasp-amass/amass', 'Apache-2.0; see subcomponents', 'recursive'),
    'chaos': ('projectdiscovery/chaos-client', 'MIT', 'passive'),
    'notify': ('projectdiscovery/notify', 'MIT', 'notification'),
    'katana': ('projectdiscovery/katana', 'MIT', 'crawl'),
    'baddns': ('blacklanternsecurity/baddns', 'AGPL-3.0', 'dns-analysis'),
}
_SUPPORTED = set(_REPOS)
ENGINES = {name: {'name': name, 'executable': name,
                  'repository': 'https://github.com/' + repo,
                  'docs': 'https://github.com/' + repo + '#readme',
                  'license': license_, 'capability': capability,
                  'execution_supported': name in _SUPPORTED,
                  'mode': 'import' if name == 'amass' else 'executable',
                  'installation': ('atlas setup-engines' if name in {'subfinder', 'dnsx', 'alterx', 'httpx', 'tlsx', 'katana', 'findomain'} else 'manual; select a reviewed release from https://github.com/' + repo + '/releases')}
           for name, (repo, license_, capability) in _REPOS.items()}
for _engine_name, _metadata in ENGINES.items():
    _metadata['required_configuration'] = {
        'puredns': ['resolvers', 'trusted_resolvers'],
        'shuffledns': ['resolvers', 'trusted_resolvers'],
        'massdns': ['resolvers'], 'gotator': ['permutations'],
        'notify': ['provider_config', 'send=True'], 'amass': ['import_file'],
        'chaos': ['PDCP_API_KEY environment variable'],
    }.get(_engine_name, [])
    _metadata['dependencies'] = ['massdns'] if _engine_name in {'puredns', 'shuffledns'} else []
    _metadata['input_mode'] = ('root-domain discovery' if _engine_name in {'subfinder', 'assetfinder', 'findomain', 'chaos'}
                               else 'existing JSONL export' if _engine_name == 'amass'
                               else 'selected scoped hostnames')
    _metadata['bundled'] = _engine_name in {'subfinder', 'dnsx', 'alterx', 'httpx', 'tlsx', 'katana', 'findomain'}
    _metadata['enabled'] = _engine_name != 'chaos'
    _metadata['validation'] = 'Mocked command/schema fixtures; installed binaries not claimed live-tested'
MAX_BYTES = 8 * 1024 * 1024
MAX_HOSTS = 10000
_EVIDENCE_KEYS = {
    'host', 'input', 'type', 'record_name', 'wildcard', 'status_code', 'a', 'aaaa', 'ip', 'cname',
    'title', 'webserver', 'tech', 'cdn', 'cdn_name', 'cdn_type', 'asn', 'port', 'scheme', 'url',
    'content_type', 'content_length', 'location', 'response_time', 'method', 'probe_status',
    'tls', 'tls_version', 'cipher', 'not_before', 'not_after', 'subject_dn', 'subject_cn',
    'subject_an', 'subject_org', 'issuer_dn', 'issuer_cn', 'issuer_org', 'fingerprint_hash',
    'fingerprint_hashes', 'fingerprint', 'hash', 'md5', 'sha1', 'sha256', 'sha512',
    'tls_connection', 'sni', 'server_name', 'serial', 'serial_number', 'timestamp',
    'expired', 'self_signed', 'mismatched', 'revoked', 'untrusted', 'names', 'dns_names',
    'as_number', 'as_name', 'as_country', 'as_range', 'as_description', 'country', 'name',
}


def _safe_evidence(value, depth=0):
    """Retain bounded known HTTP/DNS/TLS schema; omit bodies, headers and credentials."""
    if depth > 5:
        return None
    if isinstance(value, dict):
        return {key: _safe_evidence(item, depth + 1) for key, item in value.items()
                if key in _EVIDENCE_KEYS}
    if isinstance(value, list):
        return [_safe_evidence(item, depth + 1) for item in value[:256]]
    if isinstance(value, str):
        # Untrusted titles/certificate names cannot inject terminal escape sequences.
        return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value[:4096])
    return value if value is None or isinstance(value, (bool, int, float)) else str(value)[:4096]
_OPTIONS = {'limit', 'resolvers', 'trusted_resolvers', 'permutations', 'provider_config',
            'send', 'import_file'}


def _input_file(options, name):
    value = options.get(name)
    if not value:
        raise ValueError('Required configuration: ' + name)
    path = Path(value).resolve()
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(name + ' must be an existing file smaller than 8 MiB')
    return str(path)


def build_command(name, executable, input_path, root, rate, limit, options):
    """Curated arguments only; no arbitrary extra command arguments accepted."""
    commands = {
        'subfinder': ['-d', root, '-s', 'crtsh,waybackarchive,rapiddns,digitorus,shodanct', '-silent', '-oJ', '-cs', '-rl', str(rate), '-duc'],
        'assetfinder': ['--subs-only', root],
        'findomain': ['-t', root, '-q', '--exclude-sources', 'certspotter,facebook,spyse,virustotalapikey,urlscan,securitytrails,c99,bufferover_free,bufferover_paid'],
        'dnsx': ['-l', str(input_path), '-silent', '-json', '-rl', str(rate), '-duc'],
        'alterx': ['-l', str(input_path), '-silent', '-limit', str(limit), '-duc'],
        'gotator': ['-sub', str(input_path), '-depth', '1', '-mindup', '-silent', '-t', '1'],
        'httpx': ['-l', str(input_path), '-silent', '-json', '-rl', str(rate), '-duc',
                  '-sc', '-title', '-td', '-ip', '-cname', '-tls-grab', '-cdn', '-asn', '-server', '-ct', '-cl', '-location'],
        # JSON always includes certificate validity dates; not-before/after are not CLI flags.
        'tlsx': ['-l', str(input_path), '-silent', '-json', '-c', '1', '-delay', str(1 / rate) + 's',
                 '-retry', '0', '-duc', '-so', '-tv', '-cipher', '-hash', 'sha256'],
        'chaos': ['-d', root, '-silent'],
        'katana': ['-list', str(input_path), '-silent', '-jsonl', '-d', '1', '-rl', str(rate),
                   '-c', '1', '-p', '1', '-fs', 'fqdn', '-duc'],
        'bbot': ['-t', str(input_path), '--strict-scope', '-p', 'subdomain-enum', '-rf', 'passive',
                 '--no-deps', '--json', '--yes', '--no-color', '--event-types', 'DNS_NAME',
                 '-o', str(Path(input_path).parent / 'bbot-output'),
                 '-c', 'dnsresolve=false', 'modules.stdout.in_scope_only=false'],
    }
    if name == 'gotator':
        commands[name] += ['-perm', _input_file(options, 'permutations')]
    elif name == 'puredns':
        commands[name] = ['resolve', str(input_path), '-q', '-r', _input_file(options, 'resolvers'),
                          '--resolvers-trusted', _input_file(options, 'trusted_resolvers'),
                          '--rate-limit', str(rate), '--rate-limit-trusted', str(rate)]
    elif name == 'massdns':
        commands[name] = ['-r', _input_file(options, 'resolvers'), '-t', 'A', '-o', 'J',
                          '-s', '1', '-c', '1', '-q', str(input_path)]
    elif name == 'shuffledns':
        commands[name] = ['-d', root, '-l', str(input_path), '-mode', 'resolve', '-r',
                          _input_file(options, 'resolvers'), '-tr', _input_file(options, 'trusted_resolvers'),
                          '-t', '1', '-wt', '1', '-retries', '1', '-silent', '-j', '-duc']
    elif name == 'notify':
        if options.get('send') is not True:
            raise ValueError('notify requires explicit send=True and a provider_config')
        commands[name] = ['-data', str(input_path), '-provider-config', _input_file(options, 'provider_config'),
                          '-bulk', '-rate-limit', '1', '-silent', '-duc']
    elif name == 'baddns':
        names = Path(input_path).read_text(encoding='utf-8').splitlines()
        if len(names) != 1:
            raise ValueError('baddns requires exactly one selected hostname per invocation')
        commands[name] = ['-s', '-m', 'CNAME', names[0]]
    if name not in commands:
        raise ValueError('Use import_file for the version-sensitive ' + name + ' adapter')
    return [executable] + commands[name]


def normalize_host(value, root):
    """Strict DNS-label normalization and suffix boundary checking."""
    if not isinstance(value, str):
        return None
    value = value.strip().lower().rstrip('.')
    if '://' in value:
        try:
            value = urllib.parse.urlsplit(value).hostname or ''
        except ValueError:
            return None
    value = value.removeprefix('*.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                               for x in value.split('.')):
        return None
    return value if value == root or value.endswith('.' + root) else None


def _root(value):
    candidate = str(value).strip().lower().rstrip('.')
    candidate = candidate.encode('idna').decode('ascii')
    if '.' not in candidate or not normalize_host(candidate, candidate):
        raise ValueError('An explicit DNS root such as example.com is required')
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise ValueError('Root must be a domain, not an IP address')


def _limits(timeout, limit=MAX_HOSTS):
    if not 0 < float(timeout) <= 600 or not 1 <= int(limit) <= MAX_HOSTS:
        raise ValueError('timeout must be 0..600 seconds; limit must be 1..10000')


def _execute(argv, stdout_path, timeout, merge_errors=False):
    """Bound wall time and output while avoiding shell evaluation/pipe deadlocks."""
    with open(stdout_path, 'wb') as output, tempfile.TemporaryFile() as errors:
        launch_options = ({'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
                          if os.name == 'nt' else {'start_new_session': True})
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT if merge_errors else errors, shell=False,
                                   **launch_options)
        deadline = time.monotonic() + timeout
        state = 'complete'
        while process.poll() is None:
            if time.monotonic() > deadline:
                state = 'timeout'
                break
            if os.path.getsize(stdout_path) > MAX_BYTES or errors.tell() > MAX_BYTES:
                state = 'output_limit'
                break
            time.sleep(0.05)
        if state != 'complete':
            if os.name == 'nt':
                # Kill wrapper children (massdns etc.) as well as the wrapper.
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
        process.wait()
        if os.path.getsize(stdout_path) > MAX_BYTES:
            state = 'output_limit'
        # Errors may contain provider secrets. Never return their content.
        return state if state != 'complete' else ('complete' if process.returncode == 0 else 'failed')


def doctor():
    """Inspect PATH and bounded version output; no network/install operations."""
    records = []
    for name, metadata in ENGINES.items():
        record = dict(metadata, path=shutil.which(name), version=None,
                      compatibility='not_checked')
        if record['path']:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'version.txt'
                flag = '--version' if name in {'findomain', 'bbot', 'baddns'} else '-version'
                try:
                    state = _execute([record['path'], flag], path, 3, merge_errors=True)
                    text = path.read_bytes()[:4096].decode('utf-8', 'replace')
                    match = re.search(r'\b[vV]?(\d+\.\d+(?:\.\d+)?(?:[-.][\w.-]+)?)', text)
                    record['version'] = match.group(1) if match else None
                    record['compatibility'] = ('version_detected; adapter not live-validated'
                                               if state == 'complete' and match else 'version_unknown')
                except OSError:
                    record['compatibility'] = 'executable_error'
        records.append(record)
    return records


def _result(name, root, state, hosts=(), observations=(), **extra):
    return dict(source=name, root=root, state=state, hosts=sorted(set(hosts)),
                observations=list(observations), **extra)


def _observations(lines, name, root, limit):
    observations = []
    names = set()
    now = datetime.now(timezone.utc).isoformat()
    for line in lines:
        if len(observations) >= limit:
            break
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            row = {'host': line.strip()}
        if not isinstance(row, dict):
            continue
        request = row.get('request') if isinstance(row.get('request'), dict) else {}
        # HTTPx reports an IP in `host` and the requested DNS name in `input`.
        # Try each known identity field instead of discarding valid input names
        # whenever an earlier field contains an IP or an unrelated TLS name.
        host = next((normalized for candidate in
                     (row.get('input'), row.get('host'), row.get('url'), row.get('name'),
                      row.get('data'), request.get('endpoint'))
                     if (normalized := normalize_host(candidate, root))), None)
        if not host:
            continue
        if host not in names and len(names) >= limit:
            break
        names.add(host)
        providers = row.get('sources') or [row.get('source') or name]
        if isinstance(providers, str):
            providers = [providers]
        providers = [str(p)[:100] for p in providers if isinstance(p, (str, int))][:100]
        evidence = _safe_evidence(row)
        observations.append({'host': host, 'source': name, 'providers': providers,
                             'observed_at': now, 'evidence': evidence,
                             'view': 'public', 'probe_allowed': True})
    return names, observations


def run_engine(name, hosts, root, output_directory, timeout=60, rate=10, extra_options=None):
    """Execute curated compatible CLI modes, or return an explicit unsupported state.

    extra_options permits bounded configuration paths and explicit notification consent;
    arbitrary command arguments are intentionally rejected.
    Active outputs/redirects are never recursively re-probed here. Generation output
    is candidates, not DNS evidence. Engine flags must be validated against versions
    reported by doctor before production use.
    """
    root = _root(root)
    options = extra_options or {}
    if set(options) - _OPTIONS:
        raise ValueError('Unknown configuration; arbitrary engine flags are disabled')
    limit = int(options.get('limit', MAX_HOSTS))
    _limits(timeout, limit)
    if not 1 <= int(rate) <= 100:
        raise ValueError('rate must be 1..100')
    rate = int(rate)
    if name == 'chaos-client':
        name = 'chaos'
    if name == 'chaos':
        return _result(name, root, 'disabled', reason='Account-dependent services are disabled in the free-only edition')
    if name not in ENGINES:
        raise ValueError('Unknown engine')
    if name == 'notify':
        # Notification payloads are explicitly authorized text, not hostname input.
        # Validate consent/configuration before creating files or launching anything.
        if options.get('send') is not True:
            return _result(name, root, 'configuration_required', reason='notify requires explicit send=True')
        try:
            config_path = _input_file(options, 'provider_config')
            message_path = _input_file(options, 'import_file')
            if Path(message_path).stat().st_size > 128 * 1024:
                raise ValueError('Notification payload exceeds 128 KiB')
            with open(message_path, 'rb') as message_file:
                message_bytes = message_file.read(128 * 1024 + 1)
            if len(message_bytes) > 128 * 1024:
                raise ValueError('Notification payload exceeds 128 KiB')
            try:
                message_bytes.decode('utf-8')
            except UnicodeError:
                raise ValueError('Notification payload must be UTF-8 text') from None
        except (ValueError, OSError) as error:
            return _result(name, root, 'configuration_required',
                           reason=str(error) if isinstance(error, ValueError) else 'Notification configuration file error')
        executable = shutil.which(name)
        if not executable:
            return _result(name, root, 'not_installed', reason='Install Notify manually from the official repository')
        directory = Path(output_directory)
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='atlas-notify-', dir=directory) as temporary:
            status_output = Path(temporary) / 'status.txt'
            bounded_message = Path(temporary) / 'message.txt'
            bounded_message.write_bytes(message_bytes)
            try:
                command = build_command(name, executable, bounded_message, root, 1, limit,
                                        {'send': True, 'provider_config': config_path})
                state = _execute(command, status_output, float(timeout))
            except OSError:
                state = 'failed'
            # stdout/stderr can echo payloads or provider diagnostics: discard both.
            # Persist status only, without message/config contents or command arguments.
            result = _result(name, root, state, mode='notification',
                             limitations=['Process success is not independent confirmation of message delivery'])
            artifact = directory / 'notify-result.json'
            artifact.write_text(json.dumps(result, indent=2), encoding='utf-8')
            result['artifact'] = str(artifact)
            return result
    if name == 'amass' or (name == 'bbot' and options.get('import_file')):
        if not options.get('import_file'):
            return _result(name, root, 'configuration_required', reason='Version-sensitive engine: provide import_file containing existing JSONL results; ATLAS does not invoke or install engine modules')
        path = _input_file(options, 'import_file')
        names, observations = _observations(Path(path).read_text(encoding='utf-8').splitlines(), name, root, limit)
        return _result(name, root, 'imported', names, observations,
                       artifact=path, mode='import', limitations=['Existing output import only; no engine execution'])
    executable = shutil.which(name)
    if not executable:
        return _result(name, root, 'not_installed', reason='Install manually from the official repository')
    if name == 'chaos' and not os.environ.get('PDCP_API_KEY'):
        return _result(name, root, 'auth_required', reason='Set PDCP_API_KEY; provider entitlement required')
    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='atlas-', dir=directory) as temporary:
        input_path = Path(temporary) / 'input.txt'
        scoped = sorted({h for x in hosts if (h := normalize_host(x, root))})[:limit]
        input_path.write_text('\n'.join(scoped) + '\n', encoding='utf-8')
        if name == 'bbot':
            version_output = Path(temporary) / 'version.txt'
            version_state = _execute([executable, '--version'], version_output, min(3, float(timeout)), merge_errors=True)
            if version_state != 'complete' or not re.search(r'\b3\.\d+\.\d+\b', version_output.read_text(encoding='utf-8', errors='replace')):
                return _result(name, root, 'unsupported_version', reason='Live adapter requires BBOT 3.x; use import_file for other versions')
        if not scoped and name not in {'subfinder', 'assetfinder', 'findomain', 'chaos'}:
            return _result(name, root, 'empty_input')
        try:
            command = build_command(name, executable, input_path, root, rate, limit, options)
        except ValueError as error:
            return _result(name, root, 'configuration_required', reason=str(error))
        artifact = Path(temporary) / 'output.jsonl'
        try:
            state = _execute(command, artifact, float(timeout))
            names, observations = _observations(artifact.read_bytes()[:MAX_BYTES].decode('utf-8', 'replace').splitlines(), name, root, limit)
            # Persist only normalized, scoped evidence, never foreign raw engine output.
            saved = directory / (name + '-observations.jsonl')
            records_path = directory / (name + '-records.jsonl')
            with saved.open('w', encoding='utf-8') as output:
                for row in observations:
                    output.write(json.dumps(row) + '\n')
            with records_path.open('w', encoding='utf-8') as output:
                for row in observations:
                    # SANs/redirect locations are evidence only, never additional probe inputs.
                    output.write(json.dumps({**row['evidence'], 'host': row['host']}) + '\n')
            return _result(name, root, state, names, observations, artifact=str(saved),
                           raw_artifact=str(records_path),
                           truncated=len(names) >= limit, classification='candidate' if name in {'alterx', 'gotator'} else 'observation',
                           limitations=['timeout bounds total runtime; concurrency-only engines do not guarantee requests/second',
                                        'no automatic installation or recursive probing'])
        except OSError as error:
            return _result(name, root, 'failed', reason=type(error).__name__)


def _fetch_json(url, headers, timeout, payload=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'ATLAS-Recon', **headers},
                                     data=json.dumps(payload).encode() if payload is not None else None)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError('Provider response exceeds byte budget')
    return json.loads(body)


def collect_source(name, root, timeout=30, limit=1000):
    """Read bounded official APIs. Single page only: explicitly report partial coverage."""
    root = _root(root)
    _limits(timeout, limit)
    if name in {'securitytrails', 'censys'}:
        return _result(name, root, 'disabled', reason='Paid/account-dependent services are disabled in the free-only edition')
    if name == 'commoncrawl':
        try:
            indexes = _fetch_json('https://index.commoncrawl.org/collinfo.json', {}, timeout)
            # Endpoint comes from provider data but must still stay on the official origin.
            endpoint = indexes[0]['cdx-api']
            if not endpoint.startswith('https://index.commoncrawl.org/'):
                raise ValueError('Unexpected index endpoint')
            query = urllib.parse.urlencode({'url': '*.' + root, 'output': 'json', 'matchType': 'domain', 'pageSize': min(limit, 1000)})
            with urllib.request.urlopen(urllib.request.Request(endpoint + '?' + query, headers={'User-Agent': 'ATLAS-Recon'}), timeout=timeout) as response:
                body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('Provider response exceeds byte budget')
            records = [json.loads(line) for line in body.decode().splitlines() if line]
            lines = [json.dumps({'url': row.get('url'), 'timestamp': row.get('timestamp')}) for row in records]
        except Exception as error:
            return _result(name, root, 'failed', reason=type(error).__name__)
    else:
        raise ValueError('Unknown source')
    names, observations = _observations(lines, name, root, limit)
    return _result(name, root, 'partial', names, observations,
                   limitations=['Single bounded page/latest crawl; not exhaustive; historical evidence is not current DNS validity'])


def owner_inventory(provider, root, records, *, authorized=False, view='private', limit=1000):
    """Import an explicitly authorized official inventory export without probing.

    AWS: ResourceRecordSets array; Cloudflare: result array; GCP: rrsets array.
    Exports avoid ambient cloud-account credentials and accidental zone enumeration.
    """
    root = _root(root)
    _limits(1, limit)
    if not authorized:
        raise ValueError('Explicit authorization for this root is required')
    if view not in {'public', 'private'}:
        raise ValueError('view must be public or private')
    keys = {'aws': 'ResourceRecordSets', 'cloudflare': 'result', 'gcp': 'rrsets'}
    if provider not in keys:
        raise ValueError('Supported exports: aws, cloudflare, gcp')
    rows = records.get(keys[provider], []) if isinstance(records, dict) else records
    if not isinstance(rows, list):
        raise ValueError('Expected official JSON record array')
    names, observations = _observations([json.dumps({'host': row.get('Name') or row.get('name'),
                                                    'record_name': row.get('Name') or row.get('name'),
                                                    'wildcard': str(row.get('Name') or row.get('name')).startswith('*.'),
                                                    'type': row.get('Type') or row.get('type')})
                                       for row in rows[:limit] if isinstance(row, dict)], 'owner:' + provider, root, limit)
    for row in observations:
        row.update(view=view, probe_allowed=False)
    return _result('owner:' + provider, root, 'complete' if len(rows) <= limit else 'partial', names, observations,
                   limitations=['Official export import only; no cloud writes, no network probes; export pagination must be completed by owner'])
