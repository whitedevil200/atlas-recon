#!/usr/bin/env python3
"""ATLAS: scoped passive discovery and opt-in DNS reconnaissance."""
import argparse
import collections
import csv
import datetime as dt
import ipaddress
import json
import os
import hashlib
import queue
import threading
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import run_state

VERSION = '2.0.0'
BASE = Path(__file__).resolve().parent
from importlib.resources import files as resource_files
DEFAULT_WORDLIST = resource_files('atlas_data').joinpath('starter.txt')
TOOLS = ['subfinder', 'assetfinder', 'findomain', 'alterx', 'puredns', 'massdns', 'httpx']

def normalize(value):
    value = value.strip().lower().rstrip('.')
    if value.startswith('*.'):
        value = value[2:]
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    labels = value.split('.')
    if len(labels) < 2 or len(value) > 253:
        return None
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
        return None
    return value

def scoped(name, root, exclusions=()):
    return bool(name and (name == root or name.endswith('.' + root)) and
                not any(name == x or name.endswith('.' + x) for x in exclusions))

def extract(text):
    for token in re.findall(r'(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+\.?', text):
        name = normalize(token)
        if name:
            yield name

def paint(message, color=36):
    mode = os.environ.get('ATLAS_COLOR', 'auto')
    enabled = mode == 'always' or (mode != 'never' and sys.stdout.isatty() and 'NO_COLOR' not in os.environ)
    encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
    message = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', str(message))
    message = message.encode(encoding, errors='replace').decode(encoding)
    return f'\033[{color}m{message}\033[0m' if enabled else message

def say(message, color=36):
    print(paint(message, color), flush=True)

def banner():
    executable = shutil.which('figlet')
    if executable:
        art = subprocess.run([executable, 'ATLAS'], capture_output=True, text=True, check=False).stdout
    else:
        art = '    A T L A S\n    RECON TERMINAL / v' + VERSION
    for index, line in enumerate(art.splitlines()):
        say(line, ('1;95', '1;96', '1;94')[index % 3])
    say('    PASSIVE INTELLIGENCE  /  DNS VALIDATION', '1;94')
    say('    ' + '=' * 52, '1;95')

def panel(title, lines, color=36):
    width = max(40, min(shutil.get_terminal_size((88, 24)).columns - 2, 110))
    if sys.stdout.isatty() and os.environ.get('ATLAS_COLOR') != 'never' and 'NO_COLOR' not in os.environ:
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text
            safe = lambda x: re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', str(x))
            Console(highlight=False).print(Panel(Text('\n'.join(safe(x) for x in lines), style='bright_cyan'),
                                                title=Text(safe(title), style='bold bright_magenta'),
                                                border_style='bright_blue', width=width))
            return
        except ImportError:
            pass
    say('+' + '-' * (width - 2) + '+', color)
    say('| ' + title[:width - 4].ljust(width - 4) + ' |', '1;97;45')
    say('+' + '-' * (width - 2) + '+', color)
    for line in lines:
        # Wrap long evidence without depending on a full-screen terminal library.
        import textwrap
        for part in textwrap.wrap(str(line), width - 4) or ['']:
            say('| ' + part.ljust(width - 4) + ' |', '1;96')
    say('+' + '-' * (width - 2) + '+', color)

def ordered_subdomains(summary, rows, find='', status='', availability=''):
    selected = [r for r in rows if r['hostname'] != summary['root'] and
                find.lower() in r['hostname'].lower() and (not status or r['status'] == status) and
                (not availability or r.get('availability') == availability)]
    return sorted(selected, key=lambda r: (bool(re.search(r'\d', r['hostname'])), len(r['hostname'].split('.')), r['hostname']))


def show_report(directory, page=1, page_size=15, find='', status='', details=False, all_rows=False, availability=''):
    directory = Path(directory)
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    rows = [json.loads(x) for x in (directory / 'assets.jsonl').read_text(encoding='utf-8').splitlines() if x.strip()]
    banner()
    counts = collections.Counter(r['status'] for r in rows if r['hostname'] != summary['root'])
    subdomains = sum(r['hostname'] != summary['root'] for r in rows)
    say(f"    TARGET  {summary['root']}    MODE  {summary['mode'].upper()}", '1;96')
    say(f'    DISCOVERED {subdomains:,}   DNS VERIFIED {counts["resolved"]:,}', '1;92')
    say(f'    UNVERIFIED {counts["passive-unverified"]:,}   WILDCARD REVIEW {counts["wildcard-suspect"]:,}', '1;93')
    live = collections.Counter(r.get('availability', 'NOT_CHECKED') for r in rows if r['hostname'] != summary['root'])
    if any(r.get('availability') for r in rows):
        say(f'    HTTP UP {live["UP"]:,}   NO RESPONSE {live["NO_RESPONSE"]:,}   NO DNS {live["NO_DNS"]:,}', '1;92')
        say(f'    PENDING {live["PENDING"]:,}   CHECK ERRORS {live["CHECK_ERROR"]:,}   DNS ONLY {live["DNS_ONLY"]:,}', '1;93')
    say('    Discovered names are not necessarily live hosts.', 90)
    say('    ' + '-' * 52, 94)
    for stage in summary['stages']:
        say(f"    {stage['state'].upper():7} {stage['stage']}", 92 if stage['state'] == 'ok' else 93)
        if details:
            say('      Asset ID: ' + row.get('asset_id', 'legacy inventory; reimport to index'), '1;95')
            say('            ' + stage['detail'], 90)
    selected = ordered_subdomains(summary, rows, find, status, availability)
    visible = selected
    serial_width = max(7, len(str(len(selected))) + 2)
    width = max(28, min(shutil.get_terminal_size((90, 24)).columns - 25 - serial_width, 75))
    labels = {'passive-unverified': ('NOT CHECKED', '1;93'), 'resolved': ('DNS OK', '1;92'),
              'wildcard-suspect': ('REVIEW', '1;95'), 'unresolved': ('NO DNS', '1;91'),
              'indeterminate': ('DNS ERROR', '1;91')}
    live_labels = {'UP': ('UP', '1;92'), 'NO_RESPONSE': ('NO RESPONSE', '1;91'),
                   'NO_DNS': ('NO DNS', '1;91'), 'DNS_ONLY': ('DNS ONLY', '1;94'),
                   'CHECK_ERROR': ('CHECK ERROR', '1;93'), 'PENDING': ('CHECKING', '1;93')}
    say('\n    ' + 'SR NO'.ljust(serial_width) + 'HOSTNAME'.ljust(width) + 'STATUS', '1;97;44')
    for serial, row in enumerate(visible, 1):
        label, color = labels.get(row['status'], (row['status'], 93))
        label, color = live_labels.get(row.get('availability'), (label, color))
        name = row['hostname']
        # Preserve the entire hostname; use a second line on narrow terminals.
        if len(name) > width - 2:
            print('    ' + paint(str(serial).ljust(serial_width), '1;95') + paint(name, '1;96'), flush=True)
            print('    ' + ' '.ljust(width + serial_width) + paint(label, color), flush=True)
        else:
            print('    ' + paint(str(serial).ljust(serial_width), '1;95') + paint(name.ljust(width), '1;96') + paint(label, color), flush=True)
        if details:
            say('      Sources: ' + ', '.join(row['sources']), 94)
            if row['records']:
                say('      DNS: ' + json.dumps(row['records']), 90)
            if row.get('http'):
                say('      HTTP: ' + json.dumps(row['http']), 90)
            if row.get('checked_at'):
                say('      Checked UTC: ' + row['checked_at'], 90)
    say(f'\n    TOTAL SUBDOMAINS: {subdomains:,} | SHOWN: {len(visible):,}', '1;95')
    say('    NOT CHECKED = passive evidence; DNS OK = DNS response verified.', 90)
    say('    UP = HTTP response (including errors); NO RESPONSE is not proof of downtime.', 90)
    say('    Full list displayed. Use terminal scrollback to review earlier rows.', 94)
    say('    Service-like names first; no records hidden except the apex.', 90)
    return len(visible)

def browse_report(directory):
    find = ''
    while True:
        show_report(directory, find=find)
        choice = input('\n[r] refresh  [s] search  [l] lookup by SR NO  [w] save  [q] menu > ').strip().lower()
        if choice == 'q':
            return
        if choice == 's':
            find = input('Hostname contains [blank shows all]: ').strip()
        elif choice == 'w':
            export_report(directory, input('Save full domain list to: ').strip(), 'txt', '')
        elif choice == 'l':
            lookup_dashboard(directory, find=find, show_list=False)

def load_assets(directory):
    directory = Path(directory)
    summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    rows = [json.loads(x) for x in (directory / 'assets.jsonl').read_text(encoding='utf-8').splitlines() if x.strip()]
    return summary, rows


def lookup_report(args):
    import lookups
    summary, rows = load_assets(args.directory)
    if summary.get('view') == 'private' and not args.allow_private:
        raise ValueError('Private DNS inventory: use lookup --allow-private to explicitly query this view')
    root = normalize(summary['root'])
    exclusions = summary.get('settings', {}).get('exclude', [])
    if not root or root != summary['root'] or any(normalize(x) != x for x in exclusions):
        raise ValueError('invalid saved scope')
    selected = ordered_subdomains(summary, rows, args.find)
    if args.serial < 1 or args.serial > len(selected):
        raise ValueError(f'SR NO must be between 1 and {len(selected)} in the displayed list')
    hostname = selected[args.serial - 1]['hostname']
    if normalize(hostname) != hostname or not scoped(hostname, root, exclusions):
        raise ValueError('selected hostname is invalid or excluded from the saved scope')
    # Preflight output and dependencies before making provider requests.
    if args.output and Path(args.output).exists():
        raise FileExistsError('lookup output already exists; choose a new file')
    if args.output and not Path(args.output).parent.is_dir():
        raise ValueError('lookup output parent directory does not exist')
    import tldextract
    if args.kind in ('ip', 'all'):
        import ipwhois
    if args.kind != 'whois':
        import dns.resolver
    say(f'    SELECTED SR NO {args.serial}: {hostname}', '1;95')
    say('    Looking up selected host; provider limits and timeouts apply.', '1;94')
    result = lookups.enrich(hostname, root, rows, args.kind, args.directory, args.timeout,
                           args.max_ips, args.refresh, args.no_external, args.legacy_whois, exclusions)
    result['serial'] = args.serial
    result['selection_filter'] = args.find
    lookups.show(result)
    path = lookups.save(result, args.directory, args.output)
    say(f'    Saved lookup evidence: {path}', '1;92')
    return 1 if result['partial'] else 0


def lookup_dashboard(directory, find='', show_list=True):
    if show_list:
        show_report(directory, find=find)
    while True:
        serial = input('\nSubdomain SR NO [q returns]: ').strip()
        if serial.lower() == 'q':
            return
        if not serial.isdecimal() or int(serial) < 1:
            say('Enter a positive SR NO from the displayed list.', '1;93')
            continue
        panel('LOOKUP OPTIONS', ['[1] WHOIS / domain RDAP', '[2] IP / ASN / DNS details',
                               '[3] Reverse IP + PTR + saved shared-IP matches', '[4] All lookups', '[q] Return'], 35)
        choice = input('lookup > ').strip().lower()
        if choice == 'q':
            return
        kind = {'1': 'whois', '2': 'ip', '3': 'reverse-ip', '4': 'all'}.get(choice)
        if not kind:
            say('Choose lookup 1, 2, 3 or 4.', '1;93')
            continue
        main(['lookup', str(directory), '--serial', serial, '--kind', kind, '--find', find])


def offer_scan_lookup(directory):
    """Offer enrichment of the just-displayed results without changing scan status."""
    try:
        summary, rows = load_assets(directory)
        if not ordered_subdomains(summary, rows):
            return
        say('\n    NEXT: Look up any discovered subdomain using its SR NO above.', '1;95')
        choice = input('[l] WHOIS / IP / reverse-IP lookup  [Enter] Finish > ').strip().lower()
        if choice == 'l':
            lookup_dashboard(directory, show_list=False)
    except (EOFError, KeyboardInterrupt):
        say('Lookup selection closed; discovery results are saved.', 93)
    except (OSError, ValueError, KeyError, TypeError) as error:
        say('Cannot open lookup selection: ' + str(error), 93)

def export_report(directory, filename, format='txt', availability='', force=False):
    summary, rows = load_assets(directory)
    rows = ordered_subdomains(summary, rows, availability=availability)
    target = Path(filename)
    # Exclusive creation avoids accidentally replacing an existing export.
    with target.open('w' if force else 'x', encoding='utf-8', newline='') as stream:
        if format == 'txt':
            stream.write(''.join(r['hostname'] + '\n' for r in rows))
        elif format == 'jsonl':
            stream.write(''.join(json.dumps(r) + '\n' for r in rows))
        else:
            writer = csv.writer(stream)
            writer.writerow(['sr_no', 'hostname', 'availability', 'dns_status', 'checked_at', 'http_codes'])
            for serial, row in enumerate(rows, 1):
                writer.writerow([serial, row['hostname'], row.get('availability', 'NOT_CHECKED'), row['status'],
                                 row.get('checked_at', ''), ','.join(str(x['code']) for x in row.get('http', []) if 'code' in x)])
    say(f'Saved {len(rows):,} subdomains to {target}', '1;92')

def check_report(args):
    import availability as checker
    import dns.resolver  # Fail before creating output if dependency is missing.
    summary, rows = load_assets(args.directory)
    if summary.get('view') == 'private' and not getattr(args, 'allow_private', False):
        raise ValueError('Private DNS inventory requires check --allow-private --authorized')
    root = normalize(summary['root'])
    exclusions = summary.get('settings', {}).get('exclude', [])
    if not root or any(normalize(x) != x for x in exclusions):
        raise ValueError('invalid saved scope')
    # Validate every hostname before any network operation.
    for row in rows:
        name = row['hostname']
        if normalize(name) != name or not scoped(name, root, exclusions):
            raise ValueError('saved inventory contains an invalid or out-of-scope hostname')
    rows = [r for r in rows if r['hostname'] != root]
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    resuming = getattr(args, '_resume_checked_dir', None)
    output = Path(resuming) if resuming else Path(args.output or Path(args.directory).parent) / (root + '-checked-' + stamp)
    output.mkdir(parents=True, exist_ok=bool(resuming))
    args._checked_output = str(output.resolve())
    by_name = {r['hostname']: dict(r, availability=r.get('availability', 'PENDING') if resuming else 'PENDING') for r in rows}
    summary = dict(summary, version=VERSION, mode='availability', input_run=summary.get('input_run', str(args.directory)) if resuming else str(args.directory),
                   time_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                   check_settings={'workers': args.workers, 'rate': args.rate, 'timeout': args.timeout, 'dns_only': args.dns_only})
    checked = sum(r['availability'] != 'PENDING' for r in by_name.values())
    def checkpoint(state):
        inventory = list(by_name.values())
        summary['availability_counts'] = dict(collections.Counter(r['availability'] for r in inventory))
        summary['check_state'] = state
        summary['checked'] = checked
        summary['counts'] = dict(collections.Counter(r['status'] for r in inventory))
        from inventory import Inventory
        with Inventory(summary.get('settings', {}).get('database') or output.parent / 'atlas.sqlite3') as store:
            store.record_run(output, summary, inventory)
        for filename, content in [('assets.jsonl', ''.join(json.dumps(r) + '\n' for r in inventory)),
                                  ('summary.json', json.dumps(summary, indent=2))]:
            temp = output / (filename + '.tmp')
            temp.write_text(content, encoding='utf-8')
            temp.replace(output / filename)
        (output / 'subdomains.txt').write_text(''.join(n + '\n' for n in sorted(by_name)), encoding='utf-8')
    checkpoint('running')
    panel('BACKGROUND AVAILABILITY CHECKS', [f'Target: {root}  Names: {len(by_name):,}',
        f'Workers: {args.workers}  Rate: {args.rate} operation starts/s',
        f'Live saved view: atlas browse "{output}"', 'Every discovered subdomain is queued; no candidate guesses added.'])
    def completed(name, result):
        nonlocal checked
        row = by_name[name]
        row.update(result)
        if result.get('records'):
            row['status'] = ('wildcard-suspect' if row['status'] == 'wildcard-suspect' else 'resolved') if any(result['records'].get(k) for k in ('A', 'AAAA')) else (
                'indeterminate' if result.get('dns_errors') else 'unresolved')
        elif result['availability'] == 'CHECK_ERROR':
            row['status'] = 'indeterminate'
        checked += 1
        if checked == 1 or checked % 25 == 0 or checked == len(by_name):
            checkpoint('running')
            live = collections.Counter(r['availability'] for r in by_name.values())
            say(f'[{checked:,}/{len(by_name):,}] UP {live["UP"]:,} | NO RESPONSE {live["NO_RESPONSE"]:,} | NO DNS {live["NO_DNS"]:,} | ERRORS {live["CHECK_ERROR"]:,}', '1;96')
    interrupted = False
    try:
        checker.check_all(sorted(n for n, row in by_name.items() if row['availability'] == 'PENDING'),
                          args.workers, args.timeout, args.rate, args.dns_only, completed)
    except KeyboardInterrupt:
        interrupted = True
    checkpoint('interrupted' if interrupted else 'complete')
    export_report(output, output / 'availability.csv', 'csv', force=bool(resuming))
    export_report(output, output / 'up.txt', 'txt', 'UP', force=bool(resuming))
    (output / 'report.txt').write_text('ATLAS AVAILABILITY REPORT\n' +
        '\n'.join(f"{serial} | {r['hostname']} | {r['availability']}" for serial, r in enumerate(by_name.values(), 1)) +
        f'\nTOTAL SUBDOMAINS: {len(by_name):,}\n', encoding='utf-8')
    say(f'Checks saved: {output}', '1;92')
    show_report(output)
    if not interrupted and getattr(args, 'lookup', False):
        offer_scan_lookup(output)
    return 130 if interrupted else 0

def positive(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return result

def fetch(url, timeout):
    request = urllib.request.Request(url, headers={'User-Agent': 'ATLAS-Recon/1.0'})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(20_000_001)
                if len(data) > 20_000_000:
                    raise ValueError('response exceeded 20 MB; source incomplete')
                return data.decode('utf-8', errors='replace')
        except urllib.error.HTTPError as error:
            retry_after = error.headers.get('Retry-After', '')
            code = error.code
            error.close()
            if code == 429 or code in (401, 403, 404) or retry_after:
                raise ValueError(f'HTTP {code}; provider unavailable/rate-limited; Retry-After={retry_after or "not specified"}')
            if attempt == 2:
                raise
            time.sleep(2 ** attempt + secrets.randbelow(100) / 100)
        except (OSError, urllib.error.URLError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)

class Run:
    def __init__(self, args):
        for field in ('wordlist', 'resolvers', 'trusted_resolvers', 'database'):
            if getattr(args, field, None):
                setattr(args, field, str(Path(getattr(args, field)).resolve()))
        args.imports = [str(Path(x).resolve()) for x in args.imports]
        self.args = args
        self.root = normalize(args.domain)
        if not self.root:
            raise ValueError('provide a hostname, without URL, IP, port or path')
        self.exclusions = [normalize(x) for x in args.exclude]
        if any(x is None for x in self.exclusions):
            raise ValueError('invalid exclusion hostname')
        resume = getattr(args, '_resume_dir', None)
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        self.out = Path(resume) if resume else Path(args.output) / (self.root + '-' + stamp)
        self.out.mkdir(parents=True, exist_ok=bool(resume))
        (self.out / 'raw').mkdir(exist_ok=True)
        self.names = collections.defaultdict(set)
        self.status = []
        self.dns = {}
        self.wildcards = {}
        self.last_query = 0.0
        self.resolver = None
        self.cursor = args.ct_after
        self.progress = {}
        self.provenance = {}
        self.metrics = {}
        self.query_count = 0
        self._started = time.monotonic()
        self._elapsed = 0
        self.dns_client = None
        self._state = 'running'
        settings = {k: v for k, v in vars(args).items() if not k.startswith('_')}
        files = [args.wordlist or DEFAULT_WORDLIST, args.resolvers, args.trusted_resolvers, *args.imports]
        self.manifest = run_state.manifest(settings, files)
        if resume:
            state = run_state.read_state(resume)
            if state['root'] != self.root:
                raise ValueError('Saved scope changed')
            for name, sources in state['names'].items():
                if normalize(name) != name or not scoped(name, self.root, self.exclusions):
                    raise ValueError('Checkpoint contains an invalid/out-of-scope name')
                self.names[name].update(sources)
            for field in ('dns', 'wildcards', 'cursor', 'progress', 'provenance', 'metrics', 'query_count', 'manifest'):
                setattr(self, field, state.get(field, getattr(self, field)))
            self.status = state.get('stages', [])
            self._elapsed = state.get('elapsed', 0)
        self.checkpoint()

    def checkpoint(self):
        run_state.atomic_json(self.out / 'checkpoint.json', {
            'schema_version': 2, 'root': self.root, 'settings': self.manifest['settings'],
            'manifest': self.manifest, 'names': {n: sorted(v) for n, v in self.names.items()},
            'dns': self.dns, 'wildcards': self.wildcards, 'stages': self.status,
            'cursor': self.cursor, 'progress': self.progress, 'provenance': self.provenance,
            'metrics': self.metrics, 'query_count': self.query_count,
            'elapsed': self._elapsed + time.monotonic() - self._started, 'state': self._state})

    def budget(self):
        if self._elapsed + time.monotonic() - self._started >= self.args.max_seconds:
            raise ValueError('Elapsed-time budget reached; checkpoint saved for inspection/resume')
        if self.query_count >= self.args.max_queries:
            raise ValueError('DNS query budget reached; checkpoint saved')

    def add(self, text, source, parent=None):
        for name in extract(text):
            if scoped(name, self.root, self.exclusions):
                self.names[name].add(source)
                events = self.provenance.setdefault(name, [])
                parent = parent if normalize(parent or '') and scoped(parent, self.root, self.exclusions) else self.root
                if not any(x['source'] == source and x.get('parent') == parent for x in events):
                    events.append({'source': source, 'collected_at': run_state.timestamp(),
                                   'parent': parent, 'source_family': source.split(':')[-1]})
        if len(self.names) and len(self.names) % 100 == 0:
            self.checkpoint()

    def provider_fetch(self, source, url):
        self.budget()
        metrics = self.metrics.setdefault(source, {})
        metrics['logical_requests'] = metrics.get('logical_requests', 0) + 1
        return fetch(url, self.args.timeout)

    def import_file(self, filename):
        text = Path(filename).read_text(encoding='utf-8')
        source = 'import:' + Path(filename).name
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                self.add(line, source)
                continue
            if isinstance(row, dict) and isinstance(row.get('host') or row.get('hostname'), str):
                sources = row.get('sources') or row.get('source') or ['unknown']
                if isinstance(sources, str):
                    sources = [sources]
                for provider in sources:
                    self.add(row.get('host') or row['hostname'], source + ':' + str(provider))
            else:
                self.add(line, source)
        self.record(source, 'ok', 'imported scope-filtered evidence')

    def record(self, stage, state, detail=''):
        if state == 'failed' and 'HTTP 429' in detail:
            state = 'rate-limited'
        self.status.append({'stage': stage, 'state': state, 'detail': detail})
        say(f'[{state.upper()}] {stage}: {detail}', 33 if state != 'ok' else 32)
        self.metrics[stage] = dict(self.metrics.get(stage, {}), state=state, detail=detail,
                                   names=len(self.names), updated_at=run_state.timestamp())
        self.checkpoint()

    def tool(self, key, argv):
        executable = shutil.which(argv[0])
        if not executable:
            self.record(key, 'skipped', f'{argv[0]} not installed')
            return None
        try:
            with (self.out / 'raw' / (key + '.stdout')).open('wb') as stdout, \
                    (self.out / 'raw' / (key + '.stderr')).open('wb') as stderr:
                process = subprocess.Popen([executable, *argv[1:]], stdout=subprocess.PIPE, stderr=stderr)
                chunks, stop = queue.Queue(maxsize=16), threading.Event()
                def reader():
                    try:
                        while not stop.is_set():
                            data = process.stdout.read1(65536)
                            if not data:
                                break
                            while not stop.is_set():
                                try:
                                    chunks.put(data, timeout=.1)
                                    break
                                except queue.Full:
                                    pass
                    finally:
                        while not stop.is_set():
                            try:
                                chunks.put(None, timeout=.1)
                                break
                            except queue.Full:
                                pass
                thread = threading.Thread(target=reader, daemon=True)
                thread.start()
                start, size, pending, truncated = time.monotonic(), 0, b'', False
                try:
                    while True:
                        self.budget()
                        if time.monotonic() - start > self.args.tool_timeout or size > self.args.max_output_mb * 1024 ** 2 or (self.out / 'raw' / (key + '.stderr')).stat().st_size > self.args.max_output_mb * 1024 ** 2:
                            truncated = True
                            break
                        try:
                            data = chunks.get(timeout=.1)
                        except queue.Empty:
                            continue
                        if data is None:
                            try:
                                process.wait(timeout=max(.01, min(2, self.args.tool_timeout - (time.monotonic() - start))))
                            except subprocess.TimeoutExpired:
                                truncated = True
                            break
                        size += len(data)
                        stdout.write(data)
                        pending += data
                        if len(pending) > 1024 ** 2:
                            raise ValueError('External tool output line exceeds 1 MiB')
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            if key in ('subfinder', 'assetfinder', 'findomain'):
                                self.ingest_tool_line(key, line.decode('utf-8', errors='replace'))
                finally:
                    stop.set()
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=10)
                    process.stdout.close()
                    thread.join(timeout=2)
                self.metrics[key] = {'elapsed_seconds': round(time.monotonic() - start, 3), 'output_bytes': size}
            text = (self.out / 'raw' / (key + '.stdout')).read_text(encoding='utf-8')
            self.record(key, 'partial' if truncated else ('ok' if process.returncode == 0 else 'failed'),
                        f'exit {process.returncode}; valid complete observations retained; see raw logs')
            return text
        except subprocess.TimeoutExpired:
            self.record(key, 'failed', 'timeout; partial output retained but not ingested')
            return None

    def ingest_tool_line(self, source, line):
        if source == 'subfinder':
            try:
                row = json.loads(line)
                providers = row.get('sources') or row.get('source') or ['unknown']
                for provider in ([providers] if isinstance(providers, str) else providers):
                    self.add(row['host'], 'subfinder:' + str(provider))
            except (ValueError, KeyError, TypeError, AttributeError):
                return
        else:
            self.add(line, source)

    def passive(self):
        urls = {
            'crtsh': 'https://crt.sh/?q=' + urllib.parse.quote('%.' + self.root) + '&output=json',
            'wayback': 'https://web.archive.org/cdx/search/cdx?' + urllib.parse.urlencode({
                'url': '*.' + self.root + '/*', 'output': 'json', 'fl': 'original',
                'collapse': 'urlkey', 'limit': self.args.archive_limit}),
            'hackertarget': 'https://api.hackertarget.com/hostsearch/?q=' + self.root,
        }
        for source in self.args.sources.split(','):
            if self.progress.get('source:' + source) == 'done':
                continue
            self.budget()
            initial, started = len(self.names), time.monotonic()
            if source == 'certspotter':
                after = self.cursor
                try:
                    for page in range(self.args.ct_pages):
                        params = {'domain': self.root, 'include_subdomains': 'true', 'expand': 'dns_names'}
                        if after:
                            params['after'] = after
                        text = self.provider_fetch(source, 'https://api.certspotter.com/v1/issuances?' + urllib.parse.urlencode(params))
                        (self.out / 'raw' / f'certspotter-{page + 1}.json').write_text(text, encoding='utf-8')
                        rows = json.loads(text)
                        if not isinstance(rows, list):
                            raise ValueError('unexpected Cert Spotter response')
                        if not rows:
                            break
                        for row in rows:
                            self.add('\n'.join(row.get('dns_names', [])), source)
                        after = str(rows[-1]['id'])
                        self.cursor = after
                        self.checkpoint()
                        time.sleep(1)
                    self.record(source, 'ok', 'page limit reached; partial coverage' if rows else 'available pages exhausted')
                    self.progress['source:' + source] = 'done'
                    self.metrics[source]['coverage'] = 'capped' if rows else 'exhausted'
                except Exception as error:
                    self.record(source, 'failed', str(error) + '; any earlier pages retained')
                continue
            if source in ('commoncrawl', 'securitytrails', 'censys'):
                import integrations
                result = integrations.collect_source(source, self.root, self.args.timeout, self.args.archive_limit)
                self.add('\n'.join(result.get('hosts', [])), source)
                run_state.atomic_json(self.out / 'raw' / (source + '.json'), result)
                self.record(source, result['state'], result.get('detail', 'provider result'))
                self.progress['source:' + source] = 'done' if result['state'] in ('ok', 'partial', 'capped') else 'pending'
                self.checkpoint()
                continue
            if source in urls:
                try:
                    text = self.provider_fetch(source, urls[source])
                    (self.out / 'raw' / (source + '.json')).write_text(text, encoding='utf-8')
                    if source == 'hackertarget':
                        valid = [line.split(',')[0] for line in text.splitlines() if ',' in line]
                        if not valid:
                            raise ValueError('no host rows: ' + text[:150])
                        self.add('\n'.join(valid), source)
                        self.record(source, 'ok', 'provider-limited response; not exhaustive')
                        self.progress['source:' + source] = 'done'
                        self.metrics[source].update(unique_new=len(self.names) - initial, coverage='provider-limited')
                        self.checkpoint()
                        continue
                    rows = json.loads(text)
                    if source == 'crtsh':
                        for row in rows:
                            self.add(row.get('name_value', ''), source)
                    else:
                        for row in rows[1:]:
                            if row:
                                host = urllib.parse.urlsplit(row[0]).hostname
                                if host:
                                    self.add(host, source)
                    self.record(source, 'ok', 'archive capped' if source == 'wayback' else 'historical certificates')
                except Exception as error:
                    self.record(source, 'failed', str(error))
            else:
                commands = {
                    'subfinder': ['subfinder', '-d', self.root, '-all', '-silent', '-oJ', '-cs',
                                  '-rl', str(self.args.rate), '-duc'],
                    'assetfinder': ['assetfinder', '--subs-only', self.root],
                    'findomain': ['findomain', '-t', self.root, '-q'],
                }
                text = self.tool(source, commands[source])
                if text:
                    if source == 'subfinder':
                        for line in text.splitlines():
                            try:
                                row = json.loads(line)
                                providers = row.get('sources') or row.get('source') or ['unknown']
                                if isinstance(providers, str):
                                    providers = [providers]
                                for provider in providers:
                                    self.add(row['host'], 'subfinder:' + str(provider))
                            except (ValueError, KeyError, TypeError):
                                self.record('subfinder-parser', 'failed', 'invalid JSONL row ignored')
                    else:
                        self.add(text, source)
            outcome = next((x['state'] for x in reversed(self.status) if x['stage'] == source), 'failed')
            if outcome in ('ok', 'skipped'):
                self.progress['source:' + source] = 'done'
            self.metrics[source] = dict(self.metrics.get(source, {}), unique_new=len(self.names) - initial,
                                        elapsed_seconds=round(time.monotonic() - started, 3))
            self.checkpoint()

    def query(self, name, kind):
        self.budget()
        if self.dns_client is not None:
            observed = self.dns_client.query(name, kind)
            self.query_count = self._query_offset + self.dns_client.health()['queries']
            self._dns_observations.setdefault(name, {})[kind] = observed
            if observed['state'] in ('ANSWER', 'NXDOMAIN', 'NODATA'):
                return observed['values']
            return {'error': observed['state']}
        delay = 1 / self.args.rate - (time.monotonic() - self.last_query)
        if delay > 0:
            time.sleep(delay)
        self.last_query = time.monotonic()
        self.query_count += 1
        try:
            return sorted(str(x).rstrip('.') for x in self.resolver.resolve(name, kind, lifetime=self.args.timeout))
        except Exception as error:
            category = type(error).__name__
            if category in ('NXDOMAIN', 'NoAnswer'):
                return []
            return {'error': category}

    def resolve(self, name):
        return {kind: self.query(name, kind) for kind in ('A', 'AAAA', 'CNAME')}

    def active(self):
        import dns.resolver
        self.resolver = dns.resolver.Resolver()
        def read_resolvers(filename):
            if not filename:
                return None
            values = [str(ipaddress.ip_address(x.strip())) for x in Path(filename).read_text().splitlines()
                      if x.strip() and not x.lstrip().startswith('#')]
            if not values:
                raise ValueError('resolver file is empty')
            return values
        nameservers, trusted = read_resolvers(self.args.resolvers), read_resolvers(self.args.trusted_resolvers)
        if nameservers:
            self.resolver.nameservers = nameservers
        self._query_offset = self.query_count
        self._dns_observations = {}
        if hasattr(self.resolver, 'nameservers'):
            from dns_evidence import DNSClient
            self.dns_client = DNSClient(timeout=self.args.timeout, rate=self.args.rate, resolvers=nameservers,
                                         trusted_resolvers=trusted,
                                         max_queries=max(1, self.args.max_queries - self.query_count))
        words = [x.strip() for x in Path(self.args.wordlist or DEFAULT_WORDLIST).read_text().splitlines()
                 if x.strip() and not x.startswith('#')]
        seeds, generated = sorted(self.names), set(self.progress.get('generated', []))
        if self.args.profile == 'deep':
            learned = set()
            for seed in seeds:
                prefix = seed[:-len(self.root)].strip('.')
                for label in prefix.split('.'):
                    learned.update(x for x in re.split(r'[-_]', label) if 1 < len(x) <= 40)
                    match = re.fullmatch(r'(.*?)(\d{1,4})', label)
                    if match:
                        for neighbour in (int(match[2]) - 1, int(match[2]) + 1):
                            if neighbour >= 0:
                                learned.add(match[1] + str(neighbour).zfill(len(match[2])))
            words = list(dict.fromkeys(sorted(learned)[:1000] + words))
            self.metrics['learned-patterns'] = {'tokens': len(learned), 'used': min(1000, len(learned)),
                                               'candidate_ceiling': self.args.max_candidates}
        done = set(self.progress.get('dns_done', []))
        expanded = set(self.progress.get('expanded', []))
        frontier = {self.root}
        if self.args.recursive_depth:
            frontier.update(n for n in seeds if len(n.split('.')) - len(self.root.split('.')) <= self.args.recursive_depth)
        generation_stats = self.metrics.setdefault('generation', {'wordlist': 0, 'mutations': 0, 'validated': 0})
        word_budget = self.args.max_candidates // 2 if self.args.permute else self.args.max_candidates
        for round_number in range(self.args.recursive_depth + 1):
            self.budget()
            for parent in sorted(frontier - expanded):
                if len(parent.split('.')) - len(self.root.split('.')) > self.args.recursive_depth:
                    continue
                for word in words:
                    if len(generated) >= word_budget:
                        break
                    candidate = normalize(word + '.' + parent)
                    if scoped(candidate, self.root, self.exclusions):
                        generated.add(candidate)
                        generation_stats['wordlist'] += 1
                expanded.add(parent)
            if self.args.permute and round_number == 0:
                seedfile = self.out / 'seeds.txt'
                seedfile.write_text('\n'.join(seeds) + '\n', encoding='utf-8')
                text = self.tool('alterx', ['alterx', '-l', str(seedfile), '-silent', '-en',
                                           '-limit', str(self.args.max_candidates - len(generated)), '-duc'])
                for name in extract(text or ''):
                    if len(generated) >= self.args.max_candidates:
                        break
                    if scoped(name, self.root, self.exclusions):
                        generated.add(name)
                        generation_stats['mutations'] += 1
            targets = sorted((set(self.names) | generated | {self.root}) - done)
            targets = [n for n in targets if scoped(n, self.root, self.exclusions)]
            (self.out / 'candidates.txt').write_text('\n'.join(sorted(generated | set(self.names))) + '\n', encoding='utf-8')
            if self.args.engine == 'puredns':
                if not self.args.resolvers or not self.args.trusted_resolvers or not shutil.which('massdns'):
                    raise ValueError('puredns requires massdns plus public and trusted resolver files')
                # Retain input candidates as evidence; independent validation remains explicit.
                text = self.tool('puredns', ['puredns', 'resolve', str(self.out / 'candidates.txt'), '-q',
                    '--resolvers', self.args.resolvers, '--resolvers-trusted', self.args.trusted_resolvers,
                    '--rate-limit', str(self.args.rate), '--rate-limit-trusted', str(self.args.rate),
                    '--wildcard-tests', str(self.args.wildcard_tests),
                    '--write-wildcards', str(self.out / 'puredns-wildcards.txt')])
                if text is None:
                    raise ValueError('puredns could not run')
                accepted = {n for n in extract(text) if scoped(n, self.root, self.exclusions)}
                targets = [n for n in targets if n in accepted or n in self.names]
            elif self.args.engine in ('dnsx', 'shuffledns'):
                import integrations
                options = {'limit': self.args.max_candidates}
                if self.args.resolvers:
                    options['resolvers'] = self.args.resolvers
                if self.args.trusted_resolvers:
                    options['trusted_resolvers'] = self.args.trusted_resolvers
                engine_result = integrations.run_engine(self.args.engine, targets, self.root, self.out / 'engines',
                                                        self.args.tool_timeout, self.args.rate, options)
                run_state.atomic_json(self.out / (self.args.engine + '-result.json'), engine_result)
                self.record(self.args.engine, engine_result['state'], engine_result.get('detail', 'engine output'))
            next_frontier = set()
            for index, name in enumerate(targets):
                self.budget()
                parent = name.split('.', 1)[1] if name != self.root else self.root
                if parent not in self.wildcards:
                    self.wildcards[parent] = [self.resolve(secrets.token_hex(12) + '.' + parent)
                                               for _ in range(self.args.wildcard_tests)]
                answer = self.resolve(name)
                signatures = {kind: {value for sample in self.wildcards[parent]
                                     for value in sample[kind] if isinstance(sample[kind], list)}
                              for kind in answer}
                hit = any(isinstance(answer[k], list) and set(answer[k]) & signatures[k] for k in answer)
                resolved = any(isinstance(v, list) and v for v in answer.values())
                uncertain = any(isinstance(v, dict) for v in answer.values()) or any(
                    isinstance(v, dict) for sample in self.wildcards[parent] for v in sample.values())
                if self.dns_client:
                    uncertain |= any(v.get('verification', {}).get('state') in ('DISAGREES', 'INDETERMINATE')
                                     for v in self._dns_observations.get(name, {}).values())
                state = 'wildcard-suspect' if hit else ('indeterminate' if uncertain else ('resolved' if resolved else 'unresolved'))
                if resolved or name in self.names:
                    self.add(name, 'dns:' + ('candidate' if name in generated else 'validation'), parent=parent)
                    self.dns[name] = {'status': state, 'records': answer, 'wildcard_test_uncertain': uncertain,
                                      'dns_evidence': self._dns_observations.get(name, {}),
                                      'checked_at': run_state.timestamp()}
                    if state == 'resolved':
                        next_frontier.add(name)
                        generation_stats['validated'] += 1
                done.add(name)
                if index % 25 == 0:
                    say(f'DNS round {round_number + 1}: {len(done):,} tested / {len(generated):,} generated')
                    self.progress.update(dns_done=sorted(done), generated=sorted(generated), expanded=sorted(expanded))
                    self.checkpoint()
            self.progress.update(dns_done=sorted(done), generated=sorted(generated), expanded=sorted(expanded))
            self.checkpoint()
            frontier = next_frontier
            if not frontier or len(generated) >= word_budget:
                break
        if self.dns_client:
            self.metrics['resolvers'] = self.dns_client.health()
        self.progress['active'] = 'done'
        self.record('dns', 'ok', f'{len(done)} candidates tested; suspects and disagreements retained')
        if self.args.http:
            import integrations
            selected = [n for n in self.dns if self.dns[n]['status'] == 'resolved']
            result = integrations.run_engine('httpx', selected, self.root, self.out / 'engines',
                                             self.args.tool_timeout, self.args.rate, {'limit': self.args.max_candidates})
            run_state.atomic_json(self.out / 'httpx-result.json', result)
            self.record('httpx', result['state'], result.get('detail', 'HTTP observations saved'))

    def save(self):
        rows = [{'hostname': n, 'sources': sorted(self.names[n]), 'discoveries': self.provenance.get(n, []),
                 **self.dns.get(n, {'status': 'passive-unverified', 'records': {}})} for n in sorted(self.names)]
        (self.out / 'subdomains.txt').write_text('\n'.join(n for n in sorted(self.names) if n != self.root) + '\n')
        (self.out / 'resolved.txt').write_text('\n'.join(n for n in sorted(self.dns) if self.dns[n]['status'] == 'resolved') + '\n')
        (self.out / 'assets.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (self.out / 'wildcards.json').write_text(json.dumps(self.wildcards, indent=2))
        summary = {'version': VERSION, 'root': self.root, 'mode': self.args.mode,
                   'time_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'stages': self.status,
                   'counts': dict(collections.Counter(row['status'] for row in rows)),
                   'settings': self.manifest['settings'], 'complete_enumeration_guaranteed': False,
                   'view': getattr(self.args, 'view', 'public'), 'state': self._state,
                   'provider_health': self.metrics, 'manifest': self.manifest,
                   'artifacts': {str(p.relative_to(self.out)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (self.out / 'raw').glob('*') if p.is_file()}}
        from inventory import Inventory
        database = getattr(self.args, 'database', None) or self.out.parent / 'atlas.sqlite3'
        with Inventory(database) as store:
            store.record_run(self.out, summary, rows)
            for row in rows:
                for edge in row.get('discoveries', []):
                    store.record_event(summary['run_id'], dict(edge, hostname=row['hostname'],
                                                               asset_id=row['asset_id'], type='discovered-from'))
            store.checkpoint(summary['run_id'], 'scan', {'directory': str(self.out.resolve()),
                                                        'state': self._state, 'progress': self.progress})
        run_state.atomic_json(self.out / 'manifest.json', self.manifest)
        # Use the exact same subdomain order for every serial-numbered view.
        numbered = ordered_subdomains(summary, rows)
        for serial, row in enumerate(numbered, 1):
            row['sr_no'] = serial
            row['review'] = run_state.assessment(row)
        rows = numbered + [r for r in rows if r['hostname'] == self.root]
        (self.out / 'assets.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        (self.out / 'summary.json').write_text(json.dumps(summary, indent=2))
        with (self.out / 'assets.csv').open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(['sr_no', 'hostname', 'status', 'sources', 'A', 'AAAA', 'CNAME'])
            for serial, row in enumerate(numbered, 1):
                writer.writerow([serial, row['hostname'], row['status'], ';'.join(row['sources']),
                                 *(json.dumps(row['records'].get(k, [])) for k in ('A', 'AAAA', 'CNAME'))])
        document = 'ATLAS CLI REPORT\nRoot: ' + self.root + '\nMode: ' + self.args.mode + '\n'
        document += 'No completeness guarantee. Wildcard suspects require review.\n\n'
        document += '\n'.join(f"{serial} | {r['hostname']} | {r['status']} | {','.join(r['sources'])} | {json.dumps(r['records'])}" for serial, r in enumerate(numbered, 1))
        (self.out / 'report.txt').write_text(document + '\n', encoding='utf-8')
        display_counts = collections.Counter(r['status'] for r in rows if r['hostname'] != self.root)
        panel('SCAN SUMMARY', [f'Root: {self.root}   Mode: {self.args.mode}',
            f'Subdomains discovered: {sum(r["hostname"] != self.root for r in rows):,}',
            f'DNS verified: {display_counts["resolved"]:,}   Not checked: {display_counts["passive-unverified"]:,}',
            f'Stages: {len(self.status)}   Failed: {sum(x["state"] == "failed" for x in self.status)}',
            f'Read results: atlas report "{self.out}"'], 32)
        say(f'Report saved: {self.out}', 32)
        self.checkpoint()

def parser():
    p = argparse.ArgumentParser(description='ATLAS: Linux subdomain discovery and evidence mapping')
    p.add_argument('--version', action='version', version=VERSION)
    p.add_argument('--color', choices=['auto', 'always', 'never'], default=None,
                   help='terminal color policy; put before the command')
    commands = p.add_subparsers(dest='command', required=True)
    commands.add_parser('menu', help='colorful interactive menu')
    commands.add_parser('doctor', help='check optional tool dependencies')
    report = commands.add_parser('report', help='view a saved run in the terminal dashboard')
    report.add_argument('directory')
    report.add_argument('--page', type=positive, default=1, help=argparse.SUPPRESS)
    report.add_argument('--page-size', type=positive, default=15, help=argparse.SUPPRESS)
    report.add_argument('--find', default='')
    report.add_argument('--status', choices=['passive-unverified', 'resolved', 'wildcard-suspect', 'unresolved', 'indeterminate'], default='')
    report.add_argument('--details', action='store_true')
    report.add_argument('--all', dest='all_rows', action='store_true', help=argparse.SUPPRESS)
    report.add_argument('--availability', choices=['UP', 'NO_RESPONSE', 'NO_DNS', 'DNS_ONLY', 'CHECK_ERROR', 'PENDING'], default='')
    browse = commands.add_parser('browse', help='full numbered results with refresh, search and save')
    browse.add_argument('directory')
    lookup = commands.add_parser('lookup', help='WHOIS, IP and reverse-IP enrichment selected by report SR NO')
    lookup.add_argument('directory')
    lookup.add_argument('--serial', type=positive, help='SR NO from the report (or its --find filtered list); omit for interactive selection')
    lookup.add_argument('--find', default='', help='same hostname filter used in the displayed report')
    lookup.add_argument('--kind', choices=['whois', 'ip', 'reverse-ip', 'all'], default='all')
    lookup.add_argument('--timeout', type=positive, choices=range(1, 31), default=8, metavar='SECONDS', help='per-request timeout in seconds (1..30)')
    lookup.add_argument('--max-ips', type=positive, choices=range(1, 33), default=8, metavar='COUNT', help='bound IP enrichment (1..32); omitted addresses remain listed')
    lookup.add_argument('--refresh', action='store_true', help='bypass successful provider response cache')
    lookup.add_argument('--no-external', action='store_true', help='disable HackerTarget reverse-IP index; DNS/PTR and RDAP still run')
    lookup.add_argument('--legacy-whois', action='store_true', help='use optional system whois instead of domain RDAP')
    lookup.add_argument('-o', '--output', help='save JSON evidence to this new file instead of the run lookups folder')
    lookup.add_argument('--allow-private', action='store_true', help='explicitly query a private-view saved inventory')
    check = commands.add_parser('check', help='background DNS/HTTP checks for every discovered subdomain')
    check.add_argument('directory')
    check.add_argument('--authorized', action='store_true')
    check.add_argument('--dns-only', action='store_true', help='DNS checks without HTTP; does not certify a web service is up')
    check.add_argument('--workers', type=positive, choices=range(1, 33), default=8)
    check.add_argument('--rate', type=positive, default=10)
    check.add_argument('--timeout', type=positive, default=5)
    check.add_argument('-o', '--output', help='parent folder for a new checked run')
    check.add_argument('--allow-private', action='store_true')
    export = commands.add_parser('export', help='save full domain list or status records to a chosen file')
    export.add_argument('directory')
    export.add_argument('-o', '--output', required=True)
    export.add_argument('--format', choices=['txt', 'csv', 'jsonl'], default='txt')
    export.add_argument('--availability', choices=['UP', 'NO_RESPONSE', 'NO_DNS', 'DNS_ONLY', 'CHECK_ERROR', 'PENDING'], default='')
    export.add_argument('--force', action='store_true', help='replace an existing export file')
    scan = commands.add_parser('scan', help='discover names under one scoped root')
    scan.add_argument('-d', '--domain', required=True)
    scan.add_argument('--mode', choices=['passive', 'active'], default='passive')
    scan.add_argument('--authorized', action='store_true', help='acknowledge authorization for active DNS/HTTP checks')
    scan.add_argument('--sources', default='crtsh,certspotter,hackertarget,wayback,subfinder,assetfinder,findomain')
    scan.add_argument('--ct-pages', type=positive, default=5, help='maximum Cert Spotter pages; provider quotas still apply')
    scan.add_argument('--ct-after', default='', help='Cert Spotter issuance cursor for continuing an earlier scan')
    scan.add_argument('--import', dest='imports', action='append', default=[], metavar='FILE', help='import text/JSON/URL evidence')
    scan.add_argument('--offline', action='store_true', help='skip all passive network sources; active checks still require active mode')
    scan.add_argument('--exclude', action='append', default=[], help='exclude a hostname and all descendants')
    scan.add_argument('-o', '--output', default='results')
    scan.add_argument('-w', '--wordlist')
    scan.add_argument('--rate', type=positive, default=10, help='built-in DNS queries/s; per-tool rate where supported')
    scan.add_argument('--timeout', type=positive, default=10)
    scan.add_argument('--tool-timeout', type=positive, default=600)
    scan.add_argument('--archive-limit', type=positive, default=10000)
    scan.add_argument('--max-candidates', type=positive, default=10000, help='maximum generated guesses, excluding passive names')
    scan.add_argument('--recursive-depth', type=int, choices=range(0, 4), default=0, help='expand wordlist under known names up to this depth')
    scan.add_argument('--wildcard-tests', type=positive, default=3)
    scan.add_argument('--permute', action='store_true', help='use optional alterx candidate generator')
    scan.add_argument('--engine', choices=['builtin', 'puredns', 'dnsx', 'shuffledns'], default='builtin')
    scan.add_argument('--resolvers', help='DNS resolver IP list')
    scan.add_argument('--trusted-resolvers', help='trusted resolver IP list for puredns')
    scan.add_argument('--http', action='store_true', help='optional HTTP metadata collection using ProjectDiscovery httpx')
    scan.add_argument('--check-live', action='store_true', help='background DNS/HTTP verification after discovery; requires --authorized')
    scan.add_argument('--workers', type=positive, choices=range(1, 33), default=8)
    followup = scan.add_mutually_exclusive_group()
    followup.add_argument('--lookup', dest='lookup', action='store_true', default=None,
                          help='offer SR NO lookup after discovery; automatic in an interactive terminal')
    followup.add_argument('--no-lookup', dest='lookup', action='store_false',
                          help='finish after discovery without an interactive lookup prompt')
    scan.add_argument('--max-queries', type=positive, default=100000, help='DNS packet budget across wildcard and candidate queries')
    scan.add_argument('--max-seconds', type=positive, default=3600, help='total discovery elapsed-time budget')
    scan.add_argument('--max-output-mb', type=positive, default=16, help='maximum per-tool output size')
    scan.add_argument('--database', help='persistent SQLite inventory (default OUTPUT/atlas.sqlite3)')
    scan.add_argument('--view', choices=['public', 'private'], default='public')
    scan.add_argument('--profile', choices=['quick', 'balanced', 'deep'], default='balanced')
    import workflows
    workflows.add_commands(commands)
    return p

def main(argv=None):
    p = parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ['menu']
    args = p.parse_args(arguments)
    if args.command == 'menu' and not args.color and 'NO_COLOR' not in os.environ:
        os.environ.setdefault('ATLAS_COLOR', 'always')
    if args.color:
        os.environ['ATLAS_COLOR'] = args.color
    import workflows
    if args.command in workflows.COMMANDS:
        try:
            return workflows.execute(args)
        except (ImportError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            say('Cannot complete operation: ' + str(error), '1;91')
            return 2
        except (KeyboardInterrupt, EOFError):
            say('Operation stopped; saved observations are retained.', 93)
            return 130
    if args.command == 'lookup':
        try:
            if args.serial is None:
                if args.output or args.refresh or args.no_external or args.legacy_whois or args.allow_private or args.kind != 'all' or args.timeout != 8 or args.max_ips != 8:
                    p.error('lookup flags require --serial; interactive selection uses default lookup settings')
                lookup_dashboard(args.directory, args.find)
                return 0
            return lookup_report(args)
        except ImportError:
            say('Install/update requirements.txt to enable lookups (dnspython, ipwhois, tldextract).', '1;91')
            return 2
        except (EOFError, KeyboardInterrupt):
            say('Lookup closed.', 93)
            return 0
        except (OSError, ValueError, KeyError, TypeError) as error:
            say('Cannot run lookup: ' + str(error), '1;91')
            return 2
    if args.command in ('check', 'export'):
        if args.command == 'check' and not args.authorized:
            p.error('checks contact target hosts; --authorized is required')
        try:
            if args.command == 'check':
                return check_report(args)
            export_report(args.directory, args.output, args.format, args.availability, args.force)
            return 0
        except ImportError:
            say('Install requirements.txt to enable DNS/HTTP checks.', 91)
            return 2
        except (OSError, ValueError, KeyError) as error:
            say(str(error), 91)
            return 2
    if args.command == 'browse':
        try:
            browse_report(args.directory)
            return 0
        except (EOFError, KeyboardInterrupt):
            return 0
        except (OSError, ValueError, KeyError) as error:
            say(f'Cannot read report: {error}', 91)
            return 2
    if args.command == 'report':
        try:
            show_report(args.directory, args.page, args.page_size, args.find, args.status, args.details, args.all_rows, args.availability)
            return 0
        except (OSError, ValueError, KeyError) as error:
            say(f'Cannot read report: {error}', 31)
            return 2
    if args.command == 'doctor':
        banner()
        for tool in TOOLS + ['figlet']:
            say(f'{tool:12} {shutil.which(tool) or "not installed (optional)"}')
        try:
            import dns
            say('dnspython    available')
        except ImportError:
            say('dnspython    missing: needed for active mode', 33)
        for module in ('ipwhois', 'tldextract'):
            try:
                __import__(module)
                say(f'{module:12} available')
            except ImportError:
                say(f'{module:12} missing: install/update requirements.txt', 33)
        say(f'whois        {shutil.which("whois") or "not installed (optional legacy lookup)"}')
        say('Use atlas engines --check for repository adapter versions and configuration requirements.', '1;95')
        return 0
    if args.command == 'menu':
        banner()
        while True:
            panel('OPERATIONS', ['[1] Passive discovery', '[2] Active DNS + wordlist',
                '[3] Active DNS + permutations + HTTP', '[4] Dependency doctor',
                '[5] Command help', '[6] View saved results', '[7] Check all discovered subdomains',
                '[8] Save full domain list', '[9] Discover + check every result',
                '[10] WHOIS / IP / reverse IP by SR NO',
                '[11] Unified evidence cards / batch selection', '[12] Provider health / budgets',
                '[13] Compare saved runs', '[14] Asset history', '[15] Resume interrupted discovery',
                '[16] Optional repository engine', '[17] Engine versions / requirements',
                '[18] Import owned cloud DNS inventory', '[19] Watch / change snapshots',
                '[20] Resolver health diagnostics', '[21] Scoped HTTP/JS/CSP discovery', '[0] Exit'], 35)
            try:
                choice = input('atlas > ').strip()
                if choice == '0':
                    return 0
                if choice == '4':
                    main(['doctor'])
                elif choice == '5':
                    parser().parse_args(['--help'])
                elif choice == '6':
                    try:
                        browse_report(input('Run directory: ').strip())
                    except (OSError, ValueError, KeyError) as error:
                        say(f'Cannot read report: {error}', 91)
                elif choice == '7':
                    directory = input('Saved run directory: ').strip()
                    if input('Authorized to contact every in-scope host? Type YES: ').strip() == 'YES':
                        main(['check', directory, '--authorized'])
                elif choice == '8':
                    main(['export', input('Saved run directory: ').strip(), '-o', input('Save domains to file: ').strip()])
                elif choice == '10':
                    main(['lookup', input('Saved run directory: ').strip()])
                elif choice in {str(n) for n in range(11, 22)}:
                    workflows.menu(choice)
                elif choice in ('1', '2', '3', '9'):
                    options = ['scan', '--lookup', '-d', input('Root domain: ').strip()]
                    if choice == '9':
                        if input('Authorized for DNS/HTTP checks? Type YES: ').strip() != 'YES':
                            continue
                        options += ['--check-live', '--authorized']
                    if choice in ('2', '3'):
                        if input('Authorized for DNS/HTTP reconnaissance? Type YES: ').strip() != 'YES':
                            continue
                        options += ['--mode', 'active', '--authorized']
                        wordlist = input('Wordlist path [bundled starter]: ').strip()
                        if wordlist:
                            options += ['--wordlist', wordlist]
                    if choice == '3':
                        options += ['--permute', '--http']
                    main(options)
                else:
                    say('Choose an option from 0 to 21.', 33)
            except SystemExit as error:
                if error.code:
                    say('Command input was invalid; returning to dashboard.', 33)
            except (EOFError, KeyboardInterrupt):
                say('Dashboard closed.')
                return 0
    if args.mode == 'active' and not args.authorized:
        p.error('active mode requires --authorized')
    if args.check_live and not args.authorized:
        p.error('--check-live requires --authorized')
    if args.mode == 'passive' and (args.http or args.permute or args.recursive_depth or args.wordlist or args.engine != 'builtin'):
        p.error('DNS generation/HTTP options require --mode active')
    allowed = {'crtsh', 'certspotter', 'hackertarget', 'wayback', 'subfinder', 'assetfinder', 'findomain',
               'commoncrawl', 'securitytrails', 'censys'}
    if not set(args.sources.split(',')) <= allowed:
        p.error('unknown passive source; use ' + ','.join(sorted(allowed)))
    if args.mode == 'active' or args.check_live:
        try:
            import dns.resolver
        except ImportError:
            p.error('install requirements.txt for active mode')
    if args.profile == 'quick':
        args.sources = 'certspotter,subfinder' if args.sources == 'crtsh,certspotter,hackertarget,wayback,subfinder,assetfinder,findomain' else args.sources
        args.ct_pages = min(args.ct_pages, 2)
        args.max_candidates = min(args.max_candidates, 1000)
    elif args.profile == 'deep':
        args.ct_pages = max(args.ct_pages, 10)
        if args.mode == 'active':
            args.recursive_depth = max(args.recursive_depth, 2)
    return execute_scan(args)


def execute_scan(args):
    run = None
    try:
        banner()
        run = Run(args)
        for filename in args.imports:
            if run.progress.get('import:' + filename) != 'done':
                run.import_file(filename)
                run.progress['import:' + filename] = 'done'
                run.checkpoint()
        if not args.offline:
            run.passive()
        if args.mode == 'active' and run.progress.get('active') != 'done':
            run.active()
        run._state = 'complete'
        run.save()
        lookup_after_scan = args.lookup if args.lookup is not None else (sys.stdin.isatty() and sys.stdout.isatty())
        if args.check_live:
            check_args = argparse.Namespace(directory=str(run.out), output=args.output, workers=args.workers,
                                            rate=args.rate, timeout=args.timeout, dns_only=False,
                                            lookup=lookup_after_scan, allow_private=args.view == 'private')
            check_code = check_report(check_args)
            run.progress['checked_directory'] = check_args._checked_output
            run.checkpoint()
            if check_code:
                return check_code
        else:
            show_report(run.out)
            if lookup_after_scan:
                offer_scan_lookup(run.out)
        latest = {x['stage']: x['state'] for x in run.status}
        return 1 if any(x not in ('ok', 'skipped') for x in latest.values()) else 0
    except KeyboardInterrupt:
        if run:
            run._state = 'interrupted'
            run.record('run', 'failed', 'interrupted; partial evidence')
            run.save()
        return 130
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if run:
            run._state = 'incomplete'
            run.record('run', 'failed', str(error))
            run.save()
        else:
            say(str(error), 31)
        return 2

if __name__ == '__main__':
    sys.exit(main())
