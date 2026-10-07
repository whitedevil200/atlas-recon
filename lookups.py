"""Selected-host enrichment: domain RDAP, IP RDAP/ASN, PTR and reverse IP.

No newly discovered neighbour is probed or added to the scan inventory.
"""
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'
REVERSE_API = 'https://api.hackertarget.com/reverseiplookup/'
MAX_BODY = 2 * 1024 * 1024


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def error_text(error):
    if isinstance(error, urllib.error.HTTPError):
        if error.code == 429:
            return 'HTTP 429: rate limited; retry later (Retry-After: ' + str(error.headers.get('Retry-After', 'unspecified')) + ')'
        return f'HTTP {error.code}: provider request failed'
    return (type(error).__name__ + ': ' + str(error))[:350]


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('refusing a non-HTTPS redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request_text(url, timeout):
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise ValueError('lookup providers must use HTTPS')
    request = urllib.request.Request(url, headers={
        'User-Agent': 'ATLAS-Recon/1.6', 'Accept': 'application/rdap+json, application/json, text/plain'})
    opener = urllib.request.build_opener(HTTPSOnly())
    with opener.open(request, timeout=timeout) as response:
        data = response.read(MAX_BODY + 1)
    if len(data) > MAX_BODY:
        raise ValueError('provider response exceeded the 2 MiB limit')
    return data.decode('utf-8', errors='replace')


class Cache:
    """Successful provider results only; fresh DNS is never served from this cache."""
    def __init__(self, directory, refresh=False):
        self.directory = Path(directory)
        self.refresh = refresh

    def get(self, key, function, ttl=3600):
        path = self.directory / (hashlib.sha256(key.encode()).hexdigest() + '.json')
        if not self.refresh:
            try:
                saved = json.loads(path.read_text(encoding='utf-8'))
                age = time.time() - saved['time']
                if 0 <= age < ttl:
                    return saved['data'], True, saved['retrieved_at']
            except (OSError, ValueError, KeyError, TypeError):
                pass
        data = function()
        retrieved = utcnow()
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'time': time.time(), 'retrieved_at': retrieved, 'data': data}), encoding='utf-8')
        temporary.replace(path)
        return data, False, retrieved


def registered_domain(hostname):
    import tldextract
    # Use the packaged PSL snapshot: deterministic, no hidden download on startup.
    extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)
    result = extract(hostname)
    if not result.domain or not result.suffix:
        raise ValueError('no registered parent in the bundled Public Suffix List')
    return result.top_domain_under_public_suffix


def entity_names(entities, role):
    names = []
    for entity in entities or []:
        if role in (entity.get('roles') or []):
            card = entity.get('vcardArray') or []
            fields = card[1] if len(card) > 1 else []
            names.extend(str(item[3]) for item in fields if len(item) > 3 and item[0] in ('fn', 'org'))
        names.extend(entity_names(entity.get('entities'), role))
    return sorted(set(names))


def domain_rdap(hostname, cache, timeout):
    domain = registered_domain(hostname)
    bootstrap, _, _ = cache.get('iana-dns', lambda: json.loads(request_text(BOOTSTRAP, timeout)), 86400)
    tld = domain.rsplit('.', 1)[-1]
    servers = [url for labels, urls in bootstrap['services'] if tld in labels
               for url in urls if url.startswith('https://')]
    if not servers:
        raise ValueError(f'no HTTPS RDAP service in IANA bootstrap for .{tld}; try --legacy-whois if installed')
    # A single authoritative endpoint per invocation; no quota-bypassing retries.
    url = servers[0].rstrip('/') + '/domain/' + urllib.parse.quote(domain, safe='')
    data, cached, retrieved = cache.get('domain:' + url, lambda: json.loads(request_text(url, timeout)))
    return {'registered_domain': domain, 'method': 'RDAP', 'source': url,
            'cached': cached, 'retrieved_at': retrieved,
            'registrar': entity_names(data.get('entities'), 'registrar'),
            'registrant': entity_names(data.get('entities'), 'registrant'),
            'status': data.get('status', []), 'events': data.get('events', []),
            'nameservers': [x.get('ldhName', x.get('unicodeName', '')) for x in data.get('nameservers', [])],
            'dnssec': data.get('secureDNS', {}), 'raw': data}


def legacy_whois(hostname, timeout):
    domain = registered_domain(hostname)
    executable = shutil.which('whois')
    if not executable:
        raise ValueError('legacy WHOIS needs the optional system whois command; RDAP works without it')
    result = subprocess.run([executable, domain], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=timeout, check=False)
    if result.returncode:
        raise ValueError(f'whois exited with status {result.returncode}')
    return {'registered_domain': domain, 'method': 'legacy WHOIS', 'source': 'system whois command',
            'retrieved_at': utcnow(), 'raw_text': result.stdout[:MAX_BODY]}


def dns_records(hostname, timeout, kinds=('A', 'AAAA', 'CNAME')):
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.retry_servfail = False
    records, errors = {}, {}
    for kind in kinds:
        try:
            answer = resolver.resolve(hostname, kind, lifetime=timeout)
            records[kind] = {'values': sorted(str(x).rstrip('.') for x in answer), 'ttl': answer.rrset.ttl}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[kind] = {'values': [], 'ttl': None}
        except (dns.exception.DNSException, OSError) as error:
            records[kind] = {'values': [], 'ttl': None}
            errors[kind] = error_text(error)
    return {'records': records, 'errors': errors, 'checked_at': utcnow(), 'source': 'system DNS resolver'}


def addresses(dns):
    found = set()
    for kind in ('A', 'AAAA'):
        for value in dns['records'].get(kind, {}).get('values', []):
            found.add(str(ipaddress.ip_address(value)))
    return sorted(found, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))


def ptr_lookup(ip, timeout):
    import dns.reversename
    return dns_records(str(dns.reversename.from_address(ip)), timeout, ('PTR',))


def ip_rdap(ip, cache, timeout):
    from ipwhois import IPWhois
    from ipwhois.exceptions import ASNLookupError, ASNRegistryError
    def query():
        client = IPWhois(ip, timeout=timeout)
        options = dict(depth=0, retry_count=0, rate_limit_timeout=0, inc_nir=False,
                       root_ent_check=False, asn_methods=['dns'], get_asn_description=True)
        try:
            return client.lookup_rdap(**options)
        except (ASNLookupError, ASNRegistryError):
            # RDAP can still succeed when the separate ASN DNS service fails.
            return client.lookup_rdap(bootstrap=True, **options)
    data, cached, retrieved = cache.get('ip-rdap:' + ip, query)
    return {'source': 'ipwhois / regional internet registry RDAP + ASN DNS',
            'cached': cached, 'retrieved_at': retrieved, 'asn': data.get('asn'),
            'asn_description': data.get('asn_description'), 'asn_cidr': data.get('asn_cidr'),
            'asn_country': data.get('asn_country_code'), 'registry': data.get('asn_registry'),
            'network': data.get('network', {}), 'raw': data}


def reverse_provider(ip, cache, timeout):
    from atlas import normalize
    if ipaddress.ip_address(ip).version != 4:
        return {'state': 'unsupported', 'source': REVERSE_API, 'hostnames': [],
                'detail': 'HackerTarget reverse-IP supports IPv4; IPv6 PTR/local correlation still run.'}
    url = REVERSE_API + '?' + urllib.parse.urlencode({'q': ip})
    def query():
        text = request_text(url, timeout).strip()
        low = text.lower()
        if low in ('no records found', 'no dns a records found', 'no dns a records found for this ip'):
            return {'hostnames': [], 'state': 'no-records'}
        # APIs can return quota/errors with HTTP 200. Never parse error messages as hosts.
        if re.match(r'^(?:error\b|api\s|quota\b|invalid\b|rate limit\b|limit\s)', low):
            raise ValueError('reverse-IP provider: ' + text[:250])
        names = []
        for line in text.splitlines():
            name = normalize(line)
            if not name:
                raise ValueError('unexpected reverse-IP response; no names accepted')
            names.append(name)
        return {'hostnames': sorted(set(names)), 'state': 'ok'}
    data, cached, retrieved = cache.get('reverse:' + ip, query)
    return dict(data, source=url, cached=cached, retrieved_at=retrieved,
                coverage='Partial passive index; free API quotas/result limits apply. Not proof of current hosting.')


def routing_info(ip, cache, timeout):
    url = 'https://stat.ripe.net/data/network-info/data.json?' + urllib.parse.urlencode({'resource': ip, 'sourceapp': 'atlas-recon'})
    def query():
        response = json.loads(request_text(url, timeout))
        if response.get('status') != 'ok':
            raise ValueError('RIPEstat did not return a successful response')
        data = response['data']
        return {'asns': data.get('asns', []), 'prefix': data.get('prefix'), 'raw': response}
    data, cached, retrieved = cache.get('routing:' + ip, query)
    return dict(data, source=url, cached=cached, retrieved_at=retrieved)


def local_neighbours(ip, rows):
    names = set()
    for row in rows:
        saved = row.get('records') or {}
        if ip in list(saved.get('A') or []) + list(saved.get('AAAA') or []):
            names.add(row['hostname'])
    return sorted(names)


def enrich(hostname, root, rows, kind, directory, timeout=8, max_ips=8,
           refresh=False, no_external=False, legacy=False, exclusions=()):
    from atlas import normalize, scoped
    if normalize(hostname) != hostname or not scoped(hostname, root, exclusions):
        raise ValueError('selected hostname is outside the saved scope or invalid')
    cache = Cache(Path(directory) / 'lookups' / 'cache', refresh)
    result = {'hostname': hostname, 'scope_root': root, 'kind': kind,
              'started_at': utcnow(), 'errors': {}, 'ips': []}
    if kind in ('whois', 'all'):
        try:
            result['whois'] = legacy_whois(hostname, timeout) if legacy else domain_rdap(hostname, cache, timeout)
        except Exception as error:
            result['errors']['whois'] = error_text(error)
    if kind in ('ip', 'reverse-ip', 'all'):
        kinds = ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA') if kind in ('ip', 'all') else ('A', 'AAAA', 'CNAME')
        result['dns'] = dns_records(hostname, timeout, kinds)
        all_ips = addresses(result['dns'])
        result['ip_count'] = len(all_ips)
        result['omitted_ips'] = all_ips[max_ips:]
        if not all_ips:
            result['errors']['dns'] = 'No A/AAAA addresses returned; IP enrichment cannot run.'
        if result['dns']['errors']:
            result['errors']['dns_queries'] = result['dns']['errors']
        for ip in all_ips[:max_ips]:
            item = {'address': ip, 'version': ipaddress.ip_address(ip).version, 'errors': {}}
            result['ips'].append(item)
            if not ipaddress.ip_address(ip).is_global:
                item['skipped'] = 'Non-public IP: no PTR/provider enrichment performed.'
                continue
            item['ptr'] = ptr_lookup(ip, timeout)
            if item['ptr']['errors']:
                item['errors']['ptr'] = item['ptr']['errors']
            if kind in ('ip', 'all'):
                try:
                    item['registration'] = ip_rdap(ip, cache, timeout)
                except Exception as error:
                    item['errors']['ip_rdap'] = error_text(error)
                if not item.get('registration', {}).get('asn'):
                    try:
                        item['routing'] = routing_info(ip, cache, timeout)
                    except Exception as error:
                        item['errors']['routing'] = error_text(error)
            if kind in ('reverse-ip', 'all'):
                item['local_matches'] = local_neighbours(ip, [r for r in rows if scoped(r['hostname'], root, exclusions)])
                try:
                    provider = {'state': 'disabled', 'hostnames': []} if no_external else reverse_provider(ip, cache, timeout)
                    provider['hosts'] = [{'hostname': name, 'in_scope': scoped(name, root, exclusions),
                                          'scope_note': 'within saved scope' if scoped(name, root, exclusions) else 'OUTSIDE SCOPE'}
                                         for name in provider.pop('hostnames')]
                    item['reverse_ip'] = provider
                except Exception as error:
                    item['errors']['reverse_ip'] = error_text(error)
    result['completed_at'] = utcnow()
    result['partial'] = bool(result['errors'] or result.get('omitted_ips') or
                             any(x['errors'] or x.get('skipped') or x.get('reverse_ip', {}).get('state') == 'unsupported'
                                 for x in result['ips']))
    return result


def show(result):
    from atlas import panel, say
    panel('SELECTED HOST', [result['hostname'], 'Lookup: ' + result['kind'], 'Saved root: ' + result['scope_root']], 35)
    whois = result.get('whois')
    if whois:
        lines = ['Registered parent: ' + whois['registered_domain'], 'Method: ' + whois['method'],
                 'Source: ' + whois['source'], 'Retrieved UTC: ' + whois['retrieved_at']]
        if whois.get('cached'):
            lines.append('Cached response; --refresh requests new data.')
        if 'raw_text' in whois:
            lines.extend(whois['raw_text'].splitlines())
        else:
            lines += ['Registrar: ' + (', '.join(whois['registrar']) or 'not disclosed'),
                      'Registrant: ' + (', '.join(whois['registrant']) or 'not disclosed'),
                      'Status: ' + ', '.join(whois['status']), 'Nameservers: ' + ', '.join(whois['nameservers']),
                      'DNSSEC: ' + json.dumps(whois['dnssec'])]
            lines.extend(str(x.get('eventAction')) + ': ' + str(x.get('eventDate')) for x in whois['events'])
        lines.append('Registration belongs to the parent domain; subdomains usually have no separate WHOIS record.')
        panel('WHOIS / REGISTRATION', lines, 34)
    if result.get('dns'):
        panel('DNS DETAILS', [kind + ': ' + (', '.join(data['values']) or 'no records') + ' | TTL ' + str(data['ttl'] if data['ttl'] is not None else '-')
                              for kind, data in result['dns']['records'].items()], 36)
    for item in result['ips']:
        say('\n    IP ' + item['address'] + ' / IPv' + str(item['version']), '1;95')
        if item.get('skipped'):
            say('    ' + item['skipped'], '1;93')
            continue
        ptr = item['ptr']['records']['PTR']['values']
        say('    PTR (reverse DNS): ' + (', '.join(ptr) or 'no records'), '1;94')
        reg = item.get('registration')
        if reg:
            network = reg.get('network') or {}
            panel('IP REGISTRATION / ASN', [
                'ASN (DNS source): ' + str(reg['asn'] or 'not returned') + ' | ' + str(reg['asn_description'] or 'not returned'),
                'ASN prefix: ' + str(reg['asn_cidr'] or 'not returned') + ' | Registry: ' + str(reg['registry'] or 'not returned'),
                'Network: ' + str(network.get('name') or 'not returned') + ' | CIDR: ' + str(network.get('cidr') or 'not returned'),
                'Range: ' + str(network.get('start_address') or 'not returned') + ' - ' + str(network.get('end_address') or 'not returned'),
                'Registration country: ' + str(network.get('country') or reg['asn_country'] or 'not returned') + ' (not device geolocation)',
                'Source: ' + reg['source'], 'Retrieved UTC: ' + reg['retrieved_at'] + (' (cached)' if reg['cached'] else '')], 32)
        if item.get('routing'):
            routing = item['routing']
            panel('ROUTING / HTTPS ASN FALLBACK', [
                'Origin ASNs: ' + (', '.join('AS' + str(x) for x in routing['asns']) or 'no observed origin'),
                'BGP prefix: ' + str(routing['prefix']), 'Source: ' + routing['source'],
                'Retrieved UTC: ' + routing['retrieved_at'] + (' (cached)' if routing['cached'] else ''),
                'Routing origin and IP registration are separate datasets.'], 32)
        if 'local_matches' in item:
            panel('SAVED INVENTORY: SHARED IP', item['local_matches'] or ['No other saved A/AAAA matches.'], 34)
        reverse = item.get('reverse_ip')
        if reverse:
            say('    REVERSE-IP INDEX: ' + reverse['state'].upper() + (' (cached)' if reverse.get('cached') else ''), '1;96')
            if reverse.get('source'):
                say('    Source: ' + reverse['source'], 90)
            for serial, host in enumerate(reverse['hosts'], 1):
                say(f"    {serial:4} {host['hostname']}  [{host['scope_note']}]", '1;92' if host['in_scope'] else '1;93')
            say('    Index hosts returned: ' + str(len(reverse['hosts'])), 94)
            say('    ' + reverse.get('detail', reverse.get('coverage', 'External reverse-IP index disabled.')), 90)
        for key, value in item['errors'].items():
            say('    ' + key + ': ' + str(value), '1;93')
    for key, value in result['errors'].items():
        say('    ' + key + ': ' + str(value), '1;93')
    if result.get('omitted_ips'):
        say('    IP limit reached; omitted: ' + ', '.join(result['omitted_ips']) + '. Increase --max-ips (max 32).', '1;93')
    say('    Shared IP/PTR does not establish ownership or authorize testing. No neighbours were probed.', 90)


def save(result, directory, output=None):
    if output:
        path = Path(output)
    else:
        target = Path(directory) / 'lookups'
        target.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        label = result['hostname']
        if len(label) > 100:
            label = label[:100] + '-' + hashlib.sha256(label.encode()).hexdigest()[:12]
        path = target / (label + '-' + result['kind'] + '-' + stamp + '.json')
    with path.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, ensure_ascii=True)
        stream.write('\n')
    return path
