"""CLI workflows for durable recon, optional engines and scoped enrichment."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import time
import hashlib
import urllib.parse
import urllib.request
import urllib.error

import run_state

COMMANDS = {'resume', 'diff', 'history', 'evidence', 'health', 'engines', 'engine',
            'source', 'owner-import', 'watch', 'resolver-check', 'crawl', 'menu-action'}


def add_commands(commands):
    wizard = commands.add_parser('menu-action', help='run one advanced menu action (also used by the Bash launcher)')
    wizard.add_argument('choice', choices=[str(n) for n in range(11, 22)])
    resume = commands.add_parser('resume', help='resume checkpointed discovery with the original scope and inputs')
    resume.add_argument('directory')
    resume.add_argument('--authorized', action='store_true')
    resume.add_argument('--no-lookup', action='store_true')
    resume.add_argument('--allow-private', action='store_true')
    diff = commands.add_parser('diff', help='compare two inventories without treating absence as deletion')
    diff.add_argument('old')
    diff.add_argument('new')
    diff.add_argument('-o', '--output')
    history = commands.add_parser('history', help='show persistent observations for a hostname')
    history.add_argument('hostname')
    history.add_argument('--database', default='results/atlas.sqlite3')
    history.add_argument('--root')
    evidence = commands.add_parser('evidence', help='unified saved evidence cards, selected by serial or batch')
    evidence.add_argument('directory')
    evidence.add_argument('--serial', required=True, help='e.g. 1 or 2,5,8-12')
    evidence.add_argument('--find', default='')
    evidence.add_argument('--database')
    health = commands.add_parser('health', help='show source coverage, marginal yield, resolver and budget metrics')
    health.add_argument('directory')
    engines = commands.add_parser('engines', help='list optional repository adapters and capability/version diagnostics')
    engines.add_argument('--check', action='store_true', help='inspect installed executable versions')
    engine = commands.add_parser('engine', help='explicitly run an optional engine on selected scoped inventory')
    engine.add_argument('name')
    engine.add_argument('directory')
    engine.add_argument('--serial', default='all')
    engine.add_argument('--find', default='')
    engine.add_argument('--authorized', action='store_true')
    engine.add_argument('--allow-private', action='store_true')
    engine.add_argument('--timeout', type=int, default=60)
    engine.add_argument('--rate', type=int, default=10)
    engine.add_argument('--limit', type=int, default=1000)
    engine.add_argument('--resolvers')
    engine.add_argument('--trusted-resolvers')
    engine.add_argument('--import-file', help='existing structured engine output (required for Amass v5)')
    engine.add_argument('--permutations', help='reviewed permutation dictionary for Gotator')
    source = commands.add_parser('source', help='collect a bounded complementary passive source')
    source.add_argument('name', choices=['commoncrawl'])
    source.add_argument('-d', '--domain', required=True)
    source.add_argument('--limit', type=int, default=1000)
    source.add_argument('--timeout', type=int, default=10)
    source.add_argument('-o', '--output', default='results')
    owner = commands.add_parser('owner-import', help='import authorized read-only cloud DNS JSON exports')
    owner.add_argument('provider', choices=['aws', 'route53', 'cloudflare', 'gcp'])
    owner.add_argument('file')
    owner.add_argument('-d', '--domain', required=True)
    owner.add_argument('--authorized', action='store_true')
    owner.add_argument('--view', choices=['public', 'private'], default='private')
    owner.add_argument('--limit', type=int, default=10000)
    owner.add_argument('-o', '--output', default='results')
    watch = commands.add_parser('watch', help='bounded or continuous CLI snapshots with honest change detection')
    watch.add_argument('-d', '--domain', required=True)
    watch.add_argument('--sources', default='certspotter,subfinder')
    watch.add_argument('--interval', type=int, default=300)
    watch.add_argument('--cycles', type=int, default=1, help='1 by default; 0 continuously until interrupted')
    watch.add_argument('--mode', choices=['passive', 'active'], default='passive')
    watch.add_argument('--authorized', action='store_true')
    watch.add_argument('--offline', action='store_true')
    watch.add_argument('--import', dest='imports', action='append', default=[])
    watch.add_argument('-o', '--output', default='results')
    watch.add_argument('--notify', action='store_true', help='explicit opt-in: send deduplicated changes via installed Notify')
    watch.add_argument('--notify-config')
    watch.add_argument('--incremental', action='store_true', help='continue CT cursor and retain prior candidate evidence')
    watch.add_argument('--retry-notifications', action='store_true', help='retry retained notification delivery failures')
    resolver = commands.add_parser('resolver-check', help='bounded resolver connectivity and response telemetry')
    resolver.add_argument('--resolvers', required=True)
    resolver.add_argument('--timeout', type=int, default=3)
    crawl = commands.add_parser('crawl', help='bounded same-scope HTTP/JS/CSP candidate discovery (opt-in)')
    crawl.add_argument('directory')
    crawl.add_argument('--serial', default='1')
    crawl.add_argument('--authorized', action='store_true')
    crawl.add_argument('--requests', type=int, default=20)
    crawl.add_argument('--depth', type=int, default=1)
    crawl.add_argument('--timeout', type=int, default=5)
    crawl.add_argument('--allow-private', action='store_true')
    crawl.add_argument('--max-seconds', type=int, default=300)


def menu(choice):
    import atlas
    run = lambda: input('Saved run directory: ').strip()
    serial = lambda: input('SR NO or batch [1]: ').strip() or '1'
    authorized = lambda: input('Authorized for this operation? Type YES: ').strip() == 'YES'
    if choice == '11':
        return atlas.main(['evidence', run(), '--serial', serial()])
    if choice == '12':
        return atlas.main(['health', run()])
    if choice == '13':
        return atlas.main(['diff', input('Older run directory: ').strip(), input('Newer run directory: ').strip()])
    if choice == '14':
        return atlas.main(['history', input('Hostname: ').strip(), '--database', input('Database [results/atlas.sqlite3]: ').strip() or 'results/atlas.sqlite3'])
    if choice == '15':
        options = ['resume', run(), '--no-lookup']
        if authorized():
            options.append('--authorized')
        return atlas.main(options)
    if choice == '16':
        name = input('Engine name (atlas engines lists repositories): ').strip()
        options = ['engine', name, run(), '--serial', serial()]
        if authorized():
            options.append('--authorized')
        for key, question in [('resolvers', 'puredns, massdns, shuffledns') , ('trusted-resolvers', 'puredns, shuffledns'),
                              ('permutations', 'gotator'), ('import-file', 'amass')]:
            if name in question.split(', '):
                options += ['--' + key, input(key + ' file: ').strip()]
        return atlas.main(options)
    if choice == '17':
        return atlas.main(['engines', '--check'])
    if choice == '18':
        options = ['owner-import', input('Provider [aws/cloudflare/gcp]: ').strip(), input('DNS JSON export file: ').strip(),
                   '-d', input('Authorized root domain: ').strip(), '--view', input('DNS view [private/public; default private]: ').strip() or 'private']
        if authorized():
            options.append('--authorized')
        return atlas.main(options)
    if choice == '19':
        return atlas.main(['watch', '-d', input('Root domain: ').strip(), '--cycles', input('Cycles [1; 0 until stopped]: ').strip() or '1',
                           '--interval', input('Interval seconds [300]: ').strip() or '300'])
    if choice == '20':
        return atlas.main(['resolver-check', '--resolvers', input('Resolver IP file: ').strip()])
    if choice == '21':
        options = ['crawl', run(), '--serial', serial()]
        if authorized():
            options.append('--authorized')
        return atlas.main(options)
    raise ValueError('Unknown menu action')


def chosen(directory, serials, find='', limit=100):
    import atlas
    summary, rows = atlas.load_assets(directory)
    root = atlas.normalize(summary['root'])
    exclusions = summary.get('settings', {}).get('exclude', [])
    if root != summary['root'] or not root or any(atlas.normalize(x) != x for x in exclusions):
        raise ValueError('Invalid saved scope')
    candidates = atlas.ordered_subdomains(summary, rows, find)
    numbers = list(range(1, len(candidates) + 1)) if serials == 'all' else run_state.select_serials(serials, len(candidates), limit)
    if len(numbers) > limit:
        raise ValueError(f'Selection exceeds {limit}; use smaller batches')
    selected = [candidates[n - 1] for n in numbers]
    if any(atlas.normalize(r['hostname']) != r['hostname'] or not atlas.scoped(r['hostname'], root, exclusions)
           for r in selected):
        raise ValueError('Inventory contains an invalid, excluded or out-of-scope host')
    return summary, rows, selected


def new_inventory(root, hosts, source, output, view='public', observations=(), state='ok', detail=''):
    import atlas
    args = atlas.parser().parse_args(['scan', '-d', root, '--offline', '--view', view, '-o', str(output), '--no-lookup'])
    run = atlas.Run(args)
    run.add('\n'.join(hosts), source)
    by_name = {o.get('host', o.get('hostname')): o for o in observations}
    for name in list(run.names):
        if name in by_name:
            if by_name[name].get('parent'):
                run.add(name, source, parent=by_name[name]['parent'])
            run.dns[name] = {'status': 'passive-unverified', 'records': {}, 'enrichment': by_name[name]}
    run._state = 'complete' if state in ('ok', 'complete', 'imported') else 'incomplete'
    run.record(source, 'ok' if state in ('ok', 'complete', 'imported') else state, detail)
    run.save()
    atlas.show_report(run.out)
    return run.out


def print_diff(data):
    from atlas import panel, say
    panel('CHANGE INTELLIGENCE', ['Root: ' + data['root'],
        f"New: {len(data['new'])} | Changed: {len(data['changed'])} | Not observed: {len(data['not_observed'])}",
        'Comparable coverage: ' + str(data['comparable']), data['absence_meaning']])
    for label, names, color in [('NEW', data['new'], '1;92'), ('NOT OBSERVED', data['not_observed'], '1;93')]:
        for name in names:
            say(f'    {label}: {name}', color)
    for change in data['changed']:
        say('    CHANGED: ' + change['hostname'] + ' / ' + ', '.join(change['fields']), '1;95')
    for note in data['comparison_notes']:
        say('    Coverage note: ' + note, 93)


def resume(args):
    import atlas
    summary_path = Path(args.directory) / 'summary.json'
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding='utf-8'))
        if summary.get('mode') == 'availability':
            if not args.authorized:
                raise ValueError('Availability resume requires --authorized')
            settings = summary['check_settings']
            checker = argparse.Namespace(directory=args.directory, output=None, workers=settings['workers'],
                                         rate=settings['rate'], timeout=settings['timeout'], dns_only=settings['dns_only'],
                                         _resume_checked_dir=args.directory, lookup=not args.no_lookup,
                                         allow_private=args.allow_private)
            return atlas.check_report(checker)
    state = run_state.read_state(args.directory)
    original = state['settings']
    root = atlas.normalize(state['root'])
    if not root or original.get('domain') != root:
        raise ValueError('Invalid saved domain')
    defaults = atlas.parser().parse_args(['scan', '-d', root])
    allowed = vars(defaults)
    for key, value in original.items():
        if key in allowed:
            expected = allowed[key]
            if expected is not None and not isinstance(value, type(expected)):
                raise ValueError('Invalid checkpoint setting: ' + key)
            setattr(defaults, key, value)
    if defaults.mode not in ('active', 'passive') or defaults.engine not in ('builtin', 'puredns', 'dnsx', 'shuffledns'):
        raise ValueError('Invalid checkpoint mode/engine')
    if defaults.mode == 'active' or defaults.check_live:
        if not args.authorized:
            raise ValueError('Active resume requires --authorized')
        defaults.authorized = True
    previous_checked = state.get('progress', {}).get('checked_directory')
    if defaults.check_live and previous_checked and (Path(previous_checked) / 'summary.json').exists():
        args.directory = previous_checked
        return resume(args)
    defaults._resume_dir = str(Path(args.directory).resolve())
    if args.no_lookup:
        defaults.lookup = False
    # These ceilings are the original run limits. A new larger budget requires a new run.
    return atlas.execute_scan(defaults)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def crawl(args):
    import atlas
    import dns_evidence
    import ipaddress
    import re
    import socket
    import ssl
    import http.client
    summary, rows, selected = chosen(args.directory, args.serial)
    if not args.authorized:
        raise ValueError('Crawling requires --authorized')
    if summary.get('view') == 'private' and not args.allow_private:
        raise ValueError('Private inventory requires --allow-private in addition to --authorized')
    if not 1 <= args.requests <= 1000 or not 0 <= args.depth <= 3 or not 1 <= args.timeout <= 30 or not 1 <= args.max_seconds <= 3600:
        raise ValueError('Crawl limits: requests 1..1000, depth 0..3, timeout 1..30')
    root, exclusions = summary['root'], summary.get('settings', {}).get('exclude', [])
    queue = [('https://' + r['hostname'] + '/', 0) for r in selected]
    seen, names, evidence, discoveries, count = set(), set(), [], [], 0
    client = dns_evidence.DNSClient(timeout=args.timeout, rate=5, max_queries=args.requests * 4)
    from availability import RateLimit
    limiter, started = RateLimit(5), time.monotonic()
    while queue and count < args.requests:
        if time.monotonic() - started >= args.max_seconds:
            break
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        parts = urllib.parse.urlsplit(url)
        host = atlas.normalize(parts.hostname or '')
        if not atlas.scoped(host, root, exclusions) or parts.scheme not in ('http', 'https') or parts.username or parts.password:
            continue
        addresses = client.resolve(host, ('A', 'AAAA'))
        ips = [ip for r in addresses.values() for ip in r['values']]
        if not ips or (not args.allow_private and any(not ipaddress.ip_address(ip).is_global for ip in ips)):
            evidence.append({'url': url, 'state': 'blocked-or-unresolved'})
            continue
        count += 1
        limiter.acquire()
        # Pin the validated address; preserve Host and TLS SNI. No DNS rebinding gap.
        ip, port = ips[0], parts.port or (443 if parts.scheme == 'https' else 80)
        connection = http.client.HTTPSConnection(host, port, timeout=args.timeout, context=ssl.create_default_context()) if parts.scheme == 'https' else http.client.HTTPConnection(host, port, timeout=args.timeout)
        def connect(address, timeout=None, source_address=None, **kwargs):
            return socket.create_connection((ip, port), timeout=timeout, source_address=source_address)
        connection._create_connection = connect
        try:
            connection.request('GET', parts.path + ('?' + parts.query if parts.query else ''), headers={'User-Agent': 'ATLAS-Recon/2.0', 'Host': host})
            response = connection.getresponse()
            body = response.read(256 * 1024 + 1)
            if len(body) > 256 * 1024:
                evidence.append({'url': url, 'state': 'body-capped'})
                body = body[:256 * 1024]
            headers = '\n'.join(str(v) for _, v in response.getheaders())
            text = body.decode('utf-8', errors='replace')
            candidates = {n for n in atlas.extract(text + '\n' + headers) if atlas.scoped(n, root, exclusions)}
            names.update(candidates)
            discoveries.extend({'host': name, 'parent': host, 'evidence': {'url': url, 'depth': depth}}
                               for name in candidates)
            evidence.append({'url': url, 'status_code': response.status, 'ip': ip, 'hosts': sorted(candidates), 'depth': depth})
            if depth < args.depth:
                for link in re.findall(r'''(?:href|src)\s*=\s*["']([^"']+)["']''', text)[:200]:
                    child = urllib.parse.urljoin(url, link)
                    if atlas.scoped(atlas.normalize(urllib.parse.urlsplit(child).hostname or ''), root, exclusions):
                        queue.append((child, depth + 1))
                location = response.getheader('Location')
                if location:
                    queue.append((urllib.parse.urljoin(url, location), depth + 1))
        except (OSError, ValueError, http.client.HTTPException) as error:
            evidence.append({'url': url, 'error': type(error).__name__})
        finally:
            connection.close()
    target = new_inventory(root, names, 'scoped-crawl', Path(args.directory).parent,
                           observations=discoveries, state='partial' if queue else 'ok',
                           detail=f'{count} bounded requests; extracted names are candidates')
    run_state.atomic_json(target / 'crawl.json', {'requests': count, 'evidence': evidence, 'pending_urls': len(queue)})
    return 0


def execute(args):
    import atlas
    import inventory
    if args.command == 'menu-action':
        return menu(args.choice)
    if args.command == 'resume':
        return resume(args)
    if args.command == 'diff':
        result = inventory.compare_runs(args.old, args.new)
        print_diff(result)
        if args.output:
            with Path(args.output).open('x', encoding='utf-8') as stream:
                json.dump(result, stream, indent=2)
        return 0
    if args.command == 'history':
        host = atlas.normalize(args.hostname)
        if not host:
            raise ValueError('Invalid hostname')
        observations = inventory.history(args.database, host, args.root)
        for observed in observations:
            atlas.panel(host, [observed['observed_at'], 'Root/view: ' + observed['root'] + '/' + observed['view'],
                               'Run: ' + observed['directory'], json.dumps(observed, ensure_ascii=True)])
        atlas.say(f'{len(observations)} saved observations', '1;95')
        return 0
    if args.command == 'health':
        summary, _ = atlas.load_assets(args.directory)
        for name, value in summary.get('provider_health', {}).items():
            atlas.panel(name.upper(), [f'{k}: {v}' for k, v in value.items()] if isinstance(value, dict) else [str(value)])
        atlas.say('Stage coverage: ' + json.dumps(summary.get('stages', [])), '1;93')
        atlas.say('Completeness is not guaranteed; cached/history evidence is not proof of current availability.', 90)
        return 0
    if args.command == 'engines':
        import integrations
        records = integrations.doctor() if args.check else list(integrations.ENGINES.values())
        for engine in records:
            atlas.panel(str(engine.get('name', 'ENGINE')).upper(), [f'{k}: {v}' for k, v in engine.items()])
        return 0
    if args.command == 'evidence':
        summary, rows, selected = chosen(args.directory, args.serial, args.find)
        database = args.database or Path(args.directory).parent / 'atlas.sqlite3'
        for row in selected:
            atlas.panel('ASSET ' + row['hostname'], ['Asset ID: ' + row.get('asset_id', 'legacy'),
                       'DNS: ' + row['status'] + ' | Web: ' + row.get('availability', 'NOT_CHECKED'),
                       'Sources: ' + ', '.join(row['sources'])])
            for key, label in [('records', 'DNS RECORDS'), ('dns_evidence', 'DNS RESPONSE EVIDENCE'),
                               ('http', 'HTTP / TLS'), ('enrichment', 'ENGINE ENRICHMENT'), ('discoveries', 'WHY DISCOVERED')]:
                value = row.get(key)
                if value:
                    lines = [f'{k}: {json.dumps(v, ensure_ascii=True)}' for k, v in value.items()] if isinstance(value, dict) else [json.dumps(v, ensure_ascii=True) for v in value]
                    atlas.panel(label, lines)
            findings = run_state.assessment(row)
            if findings:
                atlas.panel('REVIEW LEADS / NOT CONFIRMED VULNERABILITIES', [x['reason'] for x in findings], 33)
            if Path(database).exists():
                with inventory.Inventory(database) as store:
                    old = store.asset_history(row['hostname'], summary['root'])
                atlas.say(f'    History: {len(old)} observations; asset ID {row.get("asset_id", "legacy inventory")}', '1;95')
                if old:
                    atlas.say('    First observed: ' + old[0]['observed_at'] + ' | Last observed: ' + old[-1]['observed_at'], '1;94')
            lookups = Path(args.directory) / 'lookups'
            if lookups.exists():
                for path in sorted(lookups.glob('*.json')):
                    data = json.loads(path.read_text(encoding='utf-8'))
                    if data.get('hostname') == row['hostname']:
                        import lookups as lookup_module
                        lookup_module.show(data)
        return 0
    if args.command == 'engine':
        import integrations
        if not args.authorized:
            raise ValueError('Engine execution requires --authorized; engine profiles declare their actions')
        if not 1 <= args.limit <= 10000:
            raise ValueError('Engine selection limit must be 1..10000')
        summary, rows, selected = chosen(args.directory, args.serial, args.find, args.limit)
        if summary.get('view') == 'private' and not args.allow_private:
            raise ValueError('Private inventory requires --allow-private')
        options = {'limit': args.limit}
        for field in ('resolvers', 'trusted_resolvers', 'import_file', 'permutations'):
            if getattr(args, field):
                options[field] = getattr(args, field)
        destination = Path(args.directory) / 'engines' / dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        result = integrations.run_engine(args.name, [r['hostname'] for r in selected], summary['root'], destination,
                                         args.timeout, args.rate, options)
        exclusions = summary.get('settings', {}).get('exclude', [])
        hosts = [n for n in result.get('hosts', []) if atlas.scoped(n, summary['root'], exclusions)]
        destination.mkdir(parents=True, exist_ok=True)
        run_state.atomic_json(destination / 'result.json', result)
        atlas.panel('ENGINE RESULT', [args.name, 'State: ' + result['state'],
                     'Names: ' + str(len(hosts)), result.get('reason', result.get('detail', '')), str(destination)])
        if hosts:
            # Preserve original inventory and keep candidate status distinct from DNS validation.
            new_inventory(summary['root'], hosts, 'engine:' + args.name, Path(args.directory).parent,
                          summary.get('view', 'public'), result.get('observations', []), result['state'])
        return 0 if result['state'] in ('ok', 'complete', 'imported') else 1
    if args.command == 'source':
        import integrations
        result = integrations.collect_source(args.name, args.domain, args.timeout, args.limit)
        new_inventory(result['root'], result['hosts'], args.name, args.output,
                      observations=result['observations'], state=result['state'], detail=result.get('reason', result.get('detail', '')))
        return 0 if result['state'] in ('ok', 'complete') else 1
    if args.command == 'owner-import':
        import integrations
        if Path(args.file).stat().st_size > 16 * 1024 ** 2:
            raise ValueError('Owner export exceeds 16 MiB; split it into batches')
        records = json.loads(Path(args.file).read_text(encoding='utf-8'))
        result = integrations.owner_inventory('aws' if args.provider == 'route53' else args.provider, args.domain, records, authorized=args.authorized,
                                               view=args.view, limit=args.limit)
        new_inventory(result['root'], result['hosts'], result['source'], args.output, args.view,
                      result['observations'], result['state'], result.get('reason', 'Authorized DNS export; no probing'))
        patterns = [o.get('evidence', {}).get('record_name') for o in result['observations'] if o.get('evidence', {}).get('wildcard')]
        if patterns:
            atlas.panel('CONFIGURED WILDCARD PATTERNS / NOT CONCRETE HOSTNAMES', patterns)
        return 0 if result['state'] == 'complete' else 1
    if args.command == 'resolver-check':
        from dns_evidence import DNSClient
        resolvers = [x.strip() for x in Path(args.resolvers).read_text().splitlines() if x.strip() and not x.startswith('#')]
        if len(resolvers) > 50 or not 1 <= args.timeout <= 10:
            raise ValueError('Use at most 50 resolvers and timeout 1..10')
        client = DNSClient(timeout=args.timeout, rate=5, resolvers=resolvers, max_queries=200)
        atlas.panel('RESOLVER HEALTH', [json.dumps(client.validate_resolvers(), indent=2)])
        return 0
    if args.command == 'crawl':
        return crawl(args)
    if args.command == 'watch':
        if args.interval < 10 or args.cycles < 0:
            raise ValueError('Watch interval >=10 seconds; cycles >=0')
        if args.notify and not args.notify_config:
            raise ValueError('Explicit notification delivery requires --notify-config FILE')
        previous, cycle, last_digest, pending = None, 0, None, []
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        state_path = out / ('watch-' + (atlas.normalize(args.domain) or 'invalid') + '.json')
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding='utf-8'))
            previous, last_digest = state.get('previous'), state.get('last_digest')
            pending = state.get('pending_alerts', [])
        if args.retry_notifications:
            for message in pending:
                message.update(attempts=0, retry_at=0)
        def persist(current):
            run_state.atomic_json(state_path, {'previous': current, 'last_digest': last_digest,
                                               'cycles_completed': cycle, 'pending_alerts': pending})
        while args.cycles == 0 or cycle < args.cycles:
            settings = ['scan', '-d', args.domain, '--sources', args.sources, '--mode', args.mode,
                        '-o', str(out), '--no-lookup']
            if args.authorized:
                settings.append('--authorized')
            if args.offline:
                settings.append('--offline')
            for filename in args.imports:
                settings += ['--import', filename]
            before = {p for p in out.glob('*') if p.is_dir() and (p / 'summary.json').exists()}
            if args.incremental and previous and Path(previous).exists():
                previous_state = Path(previous) / 'checkpoint.json'
                if previous_state.exists():
                    saved = json.loads(previous_state.read_text(encoding='utf-8'))
                    if saved.get('cursor'):
                        settings += ['--ct-after', saved['cursor']]
                settings += ['--import', str(Path(previous) / 'assets.jsonl')]
            code = atlas.main(settings)
            current = [p for p in out.glob('*') if p.is_dir() and p not in before and (p / 'summary.json').exists()]
            if not current:
                return code or 2
            directory = max(current, key=lambda p: p.name)
            if previous and Path(previous).exists():
                result = inventory.compare_runs(previous, directory)
                print_diff(result)
                run_state.atomic_json(directory / 'diff.json', result)
                changes = {k: result[k] for k in ('new', 'not_observed', 'changed', 'coverage_regressions')}
                digest = hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest()
                if args.notify and any(changes.values()) and digest != last_digest:
                    if digest not in {m['digest'] for m in pending}:
                        if len(pending) >= 1000:
                            raise ValueError('Notification outbox full; retained messages require attention')
                        pending.append({'digest': digest, 'root': result['root'], 'changes': changes,
                                        'attempts': 0, 'retry_at': 0})
                        persist(str(directory.resolve()))
            if args.notify:
                import integrations
                for message in list(pending)[:3]:
                    if message['attempts'] >= 8 or message['retry_at'] > time.time():
                        continue
                    note = directory / ('changes-' + message['digest'][:16] + '.txt')
                    note.write_text('ATLAS changes for ' + message['root'] + '\n' + json.dumps(message['changes'], ensure_ascii=True), encoding='utf-8')
                    notification = integrations.run_engine('notify', [], message['root'], directory / 'notification', 30, 1,
                                                          {'send': True, 'import_file': str(note), 'provider_config': args.notify_config})
                    run_state.atomic_json(directory / ('notification-' + message['digest'][:16] + '.json'), notification)
                    message['attempts'] += 1
                    message['retry_at'] = time.time() + min(3600, 30 * 2 ** message['attempts'])
                    if notification['state'] == 'complete':
                        last_digest = message['digest']
                        pending.remove(message)
                    else:
                        atlas.say('Notification retained for retry: ' + notification['state'], 93)
                    persist(str(directory.resolve()))
            previous, cycle = str(directory.resolve()), cycle + 1
            persist(previous)
            if args.cycles == 0 or cycle < args.cycles:
                time.sleep(args.interval)
        return 0
    raise ValueError('Unknown workflow')
