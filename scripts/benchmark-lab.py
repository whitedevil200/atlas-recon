#!/usr/bin/env python3
"""Controlled DNS classification benchmark using real loopback UDP packets.

No public target or resolver is contacted. The only patched behavior routes
dnspython's real UDP transport to the ephemeral local fixture port. This tests
classification of a declared fixture, not subdomain discovery recall or speed.
"""
import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import socketserver
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns_evidence

LOOPBACK = '127.0.0.1'
ZONE = 'example.test'


class FixtureServer(socketserver.UDPServer):
    allow_reuse_address = False

    def __init__(self):
        super().__init__((LOOPBACK, 0), FixtureHandler)
        self.packet_count = 0
        self.rotations = 0
        self.errors = []


class FixtureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, channel = self.request
        try:
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            response.flags |= dns.flags.AA
            response.flags &= ~dns.flags.RA
            question = request.question[0]
            name = str(question.name).lower().rstrip('.')
            kind = dns.rdatatype.to_text(question.rdtype)
            self.server.packet_count += 1
            state, values = 'NOERROR', []
            if name == 'ipv4.' + ZONE:
                if kind == 'A':
                    values = ['192.0.2.10']
            elif name == 'ipv6.' + ZONE:
                if kind == 'AAAA':
                    values = ['2001:db8::10']
            elif name == 'empty.' + ZONE:
                pass
            elif name == 'dangling.' + ZONE:
                response.answer.append(dns.rrset.from_text(name + '.', 120, 'IN', 'CNAME', 'missing.' + ZONE + '.'))
                state = 'NXDOMAIN'
            elif name == 'servfail.' + ZONE:
                state = 'SERVFAIL'
            elif name == 'refused.' + ZONE:
                state = 'REFUSED'
            elif name.endswith('.nested.wild.' + ZONE):
                if kind == 'A':
                    self.server.rotations += 1
                    values = ['192.0.2.' + str(20 + self.server.rotations % 2)]
            else:
                state = 'NXDOMAIN'
            response.set_rcode(dns.rcode.from_text(state))
            if values:
                response.answer.append(dns.rrset.from_text(name + '.', 120, 'IN', kind, *values))
            if state in ('NOERROR', 'NXDOMAIN') and not values:
                response.authority.append(dns.rrset.from_text(ZONE + '.', 120, 'IN', 'SOA',
                    'ns.' + ZONE + '. hostmaster.' + ZONE + '. 1 60 60 60 30'))
            channel.sendto(response.to_wire(), self.client_address)
        except Exception as error:
            self.server.errors.append(type(error).__name__ + ': ' + str(error))


def peak_rss():
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == 'darwin' else value * 1024)
    except (ImportError, AttributeError, OSError):
        return None


def measure():
    started = time.perf_counter()
    original_udp = dns.query.udp
    results, health = [], []
    with FixtureServer() as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        def routed_udp(request, resolver, *args, **kwargs):
            if resolver != LOOPBACK:
                raise RuntimeError('Lab benchmark refuses non-loopback DNS traffic')
            kwargs['port'] = server.server_address[1]
            return original_udp(request, LOOPBACK, *args, **kwargs)
        def client():
            return dns_evidence.DNSClient(resolvers=[LOOPBACK], rate=1000, timeout=1,
                                          max_queries=100, cache_size=100)
        try:
            with patch('dns_evidence.dns.query.udp', side_effect=routed_udp):
                cases = [('ipv4', 'RESOLVED'), ('ipv6', 'RESOLVED'), ('empty', 'NODATA'),
                         ('missing', 'NXDOMAIN'), ('dangling', 'CNAME_ONLY'),
                         ('servfail', 'INDETERMINATE'), ('refused', 'INDETERMINATE')]
                for label, expected in cases:
                    resolver = client()
                    records = resolver.resolve(label + '.' + ZONE)
                    actual = dns_evidence.classify(records)
                    results.append({'case': label, 'expected': expected, 'actual': actual,
                                    'passed': actual == expected, 'observations': records})
                    if label == 'ipv4':
                        before = resolver.health()['queries']
                        resolver.resolve(label + '.' + ZONE)
                        cache_ok = resolver.health()['queries'] == before and resolver.health()['cache']['hits'] == 3
                        results.append({'case': 'positive-cache', 'expected': 'NO_EXTRA_PACKETS',
                                        'actual': 'NO_EXTRA_PACKETS' if cache_ok else 'CACHE_MISS', 'passed': cache_ok})
                    health.append(resolver.health())
                for parent, expected in [('nested.wild.' + ZONE, 'WILDCARD_SUSPECT'),
                                         ('no-wild.' + ZONE, 'NOT_OBSERVED')]:
                    resolver = client()
                    observation = resolver.sample_wildcard(parent, tests=3)
                    actual = observation['state']
                    rotation_ok = expected != 'WILDCARD_SUSPECT' or len(observation['signatures']['A']) == 2
                    results.append({'case': parent, 'expected': expected, 'actual': actual,
                                    'passed': actual == expected and rotation_ok,
                                    'rotating_answers_detected': rotation_ok if expected == 'WILDCARD_SUSPECT' else None,
                                    'observation': observation})
                    health.append(resolver.health())
        finally:
            server.shutdown()
            thread.join(timeout=2)
        errors = list(server.errors)
        packets = server.packet_count
    classified = [r for r in results if r['expected'] in {'RESOLVED', 'NODATA', 'NXDOMAIN', 'CNAME_ONLY', 'INDETERMINATE'}]
    true_addresses = sum(r['expected'] == 'RESOLVED' and r['actual'] == 'RESOLVED' for r in classified)
    reported_addresses = sum(r['actual'] == 'RESOLVED' for r in classified)
    base = Path(__file__).resolve().parents[1]
    return {'schema_version': 1, 'benchmark': 'ATLAS controlled loopback DNS classification',
        'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'scope': '127.0.0.1 UDP ephemeral port only; documentation addresses are response data, never probe targets',
        'zone': ZONE, 'python': platform.python_version(), 'platform': platform.platform(),
        'dnspython': importlib.metadata.version('dnspython'),
        'input_sha256': {str(path.name): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in [Path(__file__), base / 'dns_evidence.py']},
        'cases': results, 'cases_passed': sum(r['passed'] for r in results), 'cases_total': len(results),
        'classification_accuracy': sum(r['passed'] for r in classified) / len(classified),
        'resolved_fixture_precision': true_addresses / reported_addresses if reported_addresses else None,
        'dns_packets_received': packets, 'client_queries': sum(h['queries'] for h in health),
        'elapsed_seconds': round(time.perf_counter() - started, 6),
        'peak_process_rss_bytes': peak_rss(), 'rss_scope': 'process lifetime peak, not benchmark-only delta; null if unavailable',
        'server_errors': errors, 'passed': all(r['passed'] for r in results) and not errors,
        'limitations': ['Controlled known-answer classification, not internet discovery recall',
            'Single execution timing includes Python/fixture scheduling; no throughput claim',
            'No public network, comparative tool benchmark, HTTP/TLS testing or vulnerability validation']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new JSON file; existing files are preserved')
    args = parser.parse_args(argv)
    target = Path(args.output)
    if target.exists():
        parser.error('Output already exists; choose a new filename')
    target.parent.mkdir(parents=True, exist_ok=True)
    result = measure()
    with target.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(f"Lab cases: {result['cases_passed']}/{result['cases_total']}; "
          f"DNS classifications: {result['classification_accuracy']:.0%}; "
          f"loopback packets: {result['dns_packets_received']}; output: {target}")
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
