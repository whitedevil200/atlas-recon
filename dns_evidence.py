"""Bounded DNS observations; negative answers are evidence, not host availability."""
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import threading
import time
import uuid

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver


def _stamp():
    return datetime.now(timezone.utc).isoformat()


def normalize_name(name):
    value = str(name).strip().rstrip('.').encode('idna').decode('ascii').lower()
    if not value or len(value) > 253 or any(not x or len(x) > 63 for x in value.split('.')):
        raise ValueError('Invalid DNS name')
    if any(not (c.isalnum() or c in '-_.') for c in value):
        raise ValueError('Invalid DNS name')
    return value


def classify(records):
    """Classify DNS only, without claiming HTTP service health or ownership."""
    observations = list(records.values())
    if any(r.get('values') for k, r in records.items() if k in ('A', 'AAAA')):
        return 'RESOLVED'
    if any(r.get('cnames') or (k == 'CNAME' and r.get('values')) for k, r in records.items()):
        return 'CNAME_ONLY'
    if observations and all(r.get('state') == 'NXDOMAIN' for r in observations):
        return 'NXDOMAIN'
    if any(r.get('state') not in ('NXDOMAIN', 'NODATA', 'ANSWER') for r in observations):
        return 'INDETERMINATE'
    return 'NODATA'


class DNSClient:
    def __init__(self, timeout=5, rate=10, resolvers=None, trusted_resolvers=None,
                 max_queries=100000, cache_size=10000):
        if timeout <= 0 or rate <= 0 or max_queries < 1 or cache_size < 0:
            raise ValueError('DNS timeout, rate and query budget must be positive')
        self.timeout, self.rate = float(timeout), float(rate)
        self.max_queries, self.cache_size = int(max_queries), int(cache_size)
        configured = dns.resolver.Resolver().nameservers if resolvers is None else resolvers
        self.resolvers = self._addresses(configured)
        self.trusted_resolvers = self._addresses(trusted_resolvers or [])
        if not self.resolvers:
            raise ValueError('At least one IP DNS resolver is required')
        self._lock = threading.Lock()
        self._stripes = [threading.Lock() for _ in range(64)]
        self._cache = OrderedDict()
        self._queries = self._hits = self._misses = self._cursor = 0
        self._next = 0.0
        self._metrics = {}
        self._preferred_resolver = None
        self.failure_threshold = 3
        self.cooldown_seconds = 30.0

    @staticmethod
    def _empty_metric():
        return {'queries': 0, 'responses': 0, 'errors': 0, 'latency_seconds': 0.0,
                'states': {}, 'failure_streak': 0, 'quarantined_until': 0.0}

    def _effective_rate(self):
        # A conservative feedback controller, never an automatic speed increase.
        worst = max((m['failure_streak'] for m in self._metrics.values()), default=0)
        return self.rate / min(4, 1 + worst)

    @staticmethod
    def _unavailable(name, kind, resolver, reason):
        return dict(name=name, kind=kind, values=[], cnames=[], rcode=None,
                    state='ERROR', ttl=0, resolver=resolver, checked_at=_stamp(),
                    errors=[reason], cached=False)

    @staticmethod
    def _addresses(values):
        if isinstance(values, str):
            values = values.split(',')
        return list(dict.fromkeys(str(ipaddress.ip_address(str(x).strip())) for x in values))

    def _reserve(self, resolver):
        with self._lock:
            if self._queries >= self.max_queries:
                raise RuntimeError('DNS query budget exhausted')
            self._queries += 1
            now = time.monotonic()
            scheduled = max(now, self._next)
            self._next = scheduled + 1 / self._effective_rate()
            metric = self._metrics.setdefault(resolver, self._empty_metric())
            metric['queries'] += 1
        delay = scheduled - now
        if delay > 0:
            time.sleep(delay)

    def _network(self, resolver, request):
        self._reserve(resolver)
        try:
            return dns.query.udp(request, resolver, timeout=self.timeout,
                                 raise_on_truncation=True)
        except dns.message.Truncated:
            self._reserve(resolver)
            return dns.query.tcp(request, resolver, timeout=self.timeout)

    def _observation(self, name, kind, resolver):
        result = dict(name=name, kind=kind, values=[], cnames=[], rcode=None,
                      state='ERROR', ttl=0, resolver=resolver, checked_at=_stamp(), errors=[])
        started = time.monotonic()
        try:
            request = dns.message.make_query(name + '.', kind)
            response = self._network(resolver, request)
            code = dns.rcode.to_text(response.rcode())
            result['rcode'] = code
            result['flags'] = {'aa': bool(response.flags & dns.flags.AA),
                               'ad': bool(response.flags & dns.flags.AD)}
            # AD is a resolver assertion; it is not local DNSSEC validation.
            result['dnssec'] = 'RESOLVER_ASSERTED' if result['flags']['ad'] else 'NOT_VALIDATED'
            wanted = dns.rdatatype.from_text(kind)
            ttls = []
            allowed = {name}
            # Only follow names reachable from the queried owner. Unrelated
            # records in a polluted response must never become asset evidence.
            for _ in range(min(len(response.answer), 32)):
                previous = len(allowed)
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME and str(rrset.name).rstrip('.').lower() in allowed:
                        allowed.update(str(item.target).rstrip('.').lower() for item in rrset)
                if len(allowed) == previous:
                    break
            for rrset in response.answer:
                if str(rrset.name).rstrip('.').lower() not in allowed:
                    continue
                if rrset.rdtype == dns.rdatatype.CNAME:
                    result['cnames'].extend(str(item.target).rstrip('.') for item in rrset)
                if rrset.rdtype == wanted:
                    result['values'].extend(item.to_text().rstrip('.') if kind in ('CNAME', 'NS', 'PTR')
                                            else item.to_text() for item in rrset)
                ttls.append(rrset.ttl)
            if code == 'NOERROR':
                result['state'] = 'ANSWER' if result['values'] else 'NODATA'
            elif code in ('NXDOMAIN', 'SERVFAIL', 'REFUSED'):
                result['state'] = code
            else:
                result['errors'].append('DNS response: ' + code)
            if result['state'] in ('NXDOMAIN', 'NODATA'):
                negatives = [min(rr.ttl, item.minimum) for rr in response.authority
                             if rr.rdtype == dns.rdatatype.SOA for item in rr]
                # No SOA means no reusable negative-cache lifetime.
                result['ttl'] = min(negatives + ttls) if negatives else 0
            else:
                result['ttl'] = min(ttls) if ttls else 0
        except dns.exception.Timeout as exc:
            result['state'] = 'TIMEOUT'
            result['errors'].append(type(exc).__name__)
        except (OSError, dns.exception.DNSException, RuntimeError, ValueError) as exc:
            result['errors'].append(str(exc))
        elapsed = time.monotonic() - started
        with self._lock:
            metric = self._metrics.setdefault(resolver, self._empty_metric())
            metric['responses' if result['rcode'] else 'errors'] += 1
            metric['latency_seconds'] += elapsed
            metric['states'][result['state']] = metric['states'].get(result['state'], 0) + 1
            if result['state'] in ('ANSWER', 'NODATA', 'NXDOMAIN'):
                metric['failure_streak'] = 0
                metric['quarantined_until'] = 0.0
            elif result['state'] in ('TIMEOUT', 'SERVFAIL', 'REFUSED') or (
                    result['state'] == 'ERROR' and not any('budget exhausted' in e for e in result['errors'])):
                metric['failure_streak'] += 1
                if metric['failure_streak'] >= self.failure_threshold:
                    metric['quarantined_until'] = time.monotonic() + self.cooldown_seconds
        return result

    def _query(self, name, kind, resolver):
        key = (name, kind, resolver)
        with self._stripes[hash(key) % len(self._stripes)]:
            with self._lock:
                cached = self._cache.get(key)
                if cached and cached[0] > time.monotonic():
                    self._hits += 1
                    self._cache.move_to_end(key)
                    result = deepcopy(cached[1])
                    result['cached'] = True
                    return result
                if cached:
                    del self._cache[key]
                self._misses += 1
                metric = self._metrics.get(resolver)
                if metric and metric['quarantined_until'] > time.monotonic():
                    return self._unavailable(name, kind, resolver, 'Resolver temporarily quarantined after repeated failures')
            result = self._observation(name, kind, resolver)
            if self.cache_size and result['ttl'] > 0 and result['state'] in ('ANSWER', 'NODATA', 'NXDOMAIN'):
                with self._lock:
                    self._cache[key] = (time.monotonic() + result['ttl'], deepcopy(result))
                    while len(self._cache) > self.cache_size:
                        self._cache.popitem(last=False)
            result['cached'] = False
            return result

    def query(self, name, kind):
        name, kind = normalize_name(name), str(kind).upper()
        dns.rdatatype.from_text(kind)
        with self._lock:
            available = [r for r in self.resolvers
                         if self._metrics.get(r, {}).get('quarantined_until', 0) <= time.monotonic()]
            if self._preferred_resolver in available:
                available.remove(self._preferred_resolver)
                available.insert(0, self._preferred_resolver)
        result = self._unavailable(name, kind, None,
            'All configured resolvers are temporarily quarantined; retry after cooldown')
        attempts = []
        # Retry transport/server failures, never a definitive negative response.
        # Only configured resolvers are used; no public resolver is silently added.
        for resolver in available[:3]:
            result = self._query(name, kind, resolver)
            attempts.append({'resolver': resolver, 'state': result['state'],
                             'errors': list(result.get('errors', []))})
            if result['state'] in {'ANSWER', 'NODATA', 'NXDOMAIN'}:
                with self._lock:
                    self._preferred_resolver = resolver
                break
            if self.health()['queries'] >= self.max_queries:
                break
        result['resolver_attempts'] = attempts
        if self.trusted_resolvers:
            trusted = self._query(name, kind, self.trusted_resolvers[0])
            definite = {'ANSWER', 'NODATA', 'NXDOMAIN'}
            comparable = result['state'] in definite and trusted['state'] in definite
            agrees = (result['state'], sorted(result['values']), sorted(result['cnames'])) == (
                trusted['state'], sorted(trusted['values']), sorted(trusted['cnames']))
            result['verification'] = {'state': ('AGREES' if agrees else 'DISAGREES') if comparable else 'INDETERMINATE',
                                      'observation': trusted}
        return result

    def resolve(self, name, kinds=('A', 'AAAA', 'CNAME')):
        return {str(kind).upper(): self.query(name, kind) for kind in kinds}

    def health(self):
        with self._lock:
            return {'queries': self._queries, 'max_queries': self.max_queries,
                    'configured_rate': self.rate, 'effective_rate': self._effective_rate(),
                    'cooldown_seconds': self.cooldown_seconds,
                    'preferred_resolver': self._preferred_resolver,
                    'cache': {'hits': self._hits, 'misses': self._misses, 'entries': len(self._cache)},
                    'resolvers': deepcopy(self._metrics)}

    def validate_resolvers(self):
        """Two diagnostic queries per resolver, always subject to the shared budget.

        Responses test connectivity/negative behavior, not resolver trustworthiness.
        """
        diagnostics = {}
        for resolver in dict.fromkeys(self.resolvers + self.trusted_resolvers):
            positive = self._query('example.com', 'A', resolver)
            negative = self._query(uuid.uuid4().hex + '.invalid', 'A', resolver)
            diagnostics[resolver] = {'positive': positive, 'negative': negative,
                                     'status': 'RESPONSIVE' if positive['rcode'] and negative['rcode'] else 'DEGRADED'}
        return {'diagnostics': diagnostics, 'health': self.health()}

    def sample_wildcard(self, parent, tests=3):
        """Sample a parent, including rotating answers. Never silently remove names."""
        if not 1 <= tests <= 50:
            raise ValueError('Wildcard tests must be between 1 and 50')
        parent = normalize_name(parent)
        samples = [self.resolve(uuid.uuid4().hex + '.' + parent) for _ in range(tests)]
        signatures = {kind: sorted({value for sample in samples for value in sample[kind]['values']})
                      for kind in ('A', 'AAAA', 'CNAME')}
        failed = any(row['state'] not in ('ANSWER', 'NODATA', 'NXDOMAIN')
                     for sample in samples for row in sample.values())
        state = 'WILDCARD_SUSPECT' if any(signatures.values()) else ('INDETERMINATE' if failed else 'NOT_OBSERVED')
        return {'parent': parent, 'state': state,
                'signatures': signatures, 'samples': samples, 'checked_at': _stamp()}
