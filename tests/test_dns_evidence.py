import concurrent.futures
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns.exception
import dns.message
import dns.rcode
import dns.rrset
import dns_evidence as evidence


def response(kind='A', value='192.0.2.1', code='NOERROR', soa=False):
    answer = dns.message.make_response(dns.message.make_query('api.example.com.', kind))
    answer.set_rcode(dns.rcode.from_text(code))
    if value:
        answer.answer.append(dns.rrset.from_text('api.example.com.', 60, 'IN', kind, value))
    if soa:
        answer.authority.append(dns.rrset.from_text('example.com.', 120, 'IN', 'SOA',
                               'ns.example.com. hostmaster.example.com. 1 60 60 60 30'))
    return answer


class DNSEvidenceTests(unittest.TestCase):
    def client(self, **kwargs):
        return evidence.DNSClient(resolvers=['192.0.2.53'], rate=1000000, **kwargs)

    @patch('dns_evidence.dns.query.udp')
    def test_positive_cache_is_shared_and_thread_safe(self, udp):
        udp.return_value = response()
        client = self.client()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            rows = list(pool.map(lambda _: client.query('api.example.com', 'A'), range(20)))
        self.assertEqual(udp.call_count, 1)
        self.assertEqual(client.health()['cache']['hits'], 19)
        rows[0]['values'].append('bad')
        self.assertEqual(client.query('api.example.com', 'A')['values'], ['192.0.2.1'])

    @patch('dns_evidence.dns.query.udp')
    def test_negative_types_and_soa_cache(self, udp):
        udp.side_effect = [response(value=None, code='NXDOMAIN', soa=True),
                           response('AAAA', value=None, soa=True)]
        client = self.client()
        self.assertEqual(client.query('api.example.com', 'A')['ttl'], 30)
        self.assertEqual(client.query('api.example.com', 'A')['state'], 'NXDOMAIN')
        self.assertEqual(client.query('api.example.com', 'AAAA')['state'], 'NODATA')
        self.assertEqual(udp.call_count, 2)

    @patch('dns_evidence.dns.query.udp')
    def test_negative_without_soa_not_cached(self, udp):
        udp.return_value = response(value=None, code='NXDOMAIN')
        client = self.client()
        client.query('api.example.com', 'A')
        client.query('api.example.com', 'A')
        self.assertEqual(udp.call_count, 2)

    @patch('dns_evidence.dns.query.udp')
    def test_cname_survives_negative_final_target(self, udp):
        answer = response(value=None, code='NXDOMAIN', soa=True)
        answer.answer.append(dns.rrset.from_text('api.example.com.', 60, 'IN', 'CNAME', 'gone.example.net.'))
        udp.return_value = answer
        records = self.client().resolve('api.example.com')
        self.assertEqual(records['A']['cnames'], ['gone.example.net'])
        self.assertEqual(evidence.classify(records), 'CNAME_ONLY')

    @patch('dns_evidence.dns.query.udp')
    def test_budget_blocks_more_packets(self, udp):
        udp.return_value = response()
        client = self.client(max_queries=1, cache_size=0)
        client.query('api.example.com', 'A')
        self.assertIn('budget exhausted', client.query('other.example.com', 'A')['errors'][0])
        self.assertEqual(udp.call_count, 1)

    @patch('dns_evidence.dns.query.tcp')
    @patch('dns_evidence.dns.query.udp', side_effect=dns.message.Truncated)
    def test_tcp_fallback_uses_budget(self, udp, tcp):
        tcp.return_value = response()
        client = self.client(max_queries=2)
        self.assertEqual(client.query('api.example.com', 'A')['state'], 'ANSWER')
        self.assertEqual(client.health()['queries'], 2)
        client = self.client(max_queries=1)
        self.assertEqual(client.query('api.example.com', 'A')['state'], 'ERROR')
        self.assertEqual(tcp.call_count, 1)

    @patch('dns_evidence.dns.query.udp')
    def test_timeout_servfail_and_refused_are_not_absence(self, udp):
        udp.side_effect = [dns.exception.Timeout(), response(value=None, code='SERVFAIL'),
                           response(value=None, code='REFUSED')]
        client = self.client()
        rows = client.resolve('api.example.com')
        self.assertEqual([r['state'] for r in rows.values()], ['TIMEOUT', 'SERVFAIL', 'REFUSED'])
        self.assertEqual(evidence.classify(rows), 'INDETERMINATE')

    @patch('dns_evidence.dns.query.udp')
    def test_trusted_disagreement_preserves_both_answers(self, udp):
        udp.side_effect = [response(), response(value='192.0.2.2')]
        row = self.client(trusted_resolvers=['192.0.2.54']).query('api.example.com', 'A')
        self.assertEqual(row['verification']['state'], 'DISAGREES')
        self.assertEqual(row['values'], ['192.0.2.1'])
        self.assertEqual(row['verification']['observation']['values'], ['192.0.2.2'])

    @patch('dns_evidence.dns.query.udp')
    def test_ttl_expiration_and_lru_bound(self, udp):
        def reply(request, *args, **kwargs):
            answer = response()
            answer.answer[0].name = request.question[0].name
            return answer
        udp.side_effect = reply
        client = self.client(cache_size=1)
        client.query('api.example.com', 'A')
        client.query('other.example.com', 'A')
        self.assertEqual(client.health()['cache']['entries'], 1)
        client.query('api.example.com', 'A')
        with client._lock:
            for key, (_, value) in list(client._cache.items()):
                client._cache[key] = (0, value)
        client.query('api.example.com', 'A')
        self.assertEqual(udp.call_count, 4)

    @patch('dns_evidence.dns.query.udp')
    def test_wildcard_sampling_preserves_rotation(self, udp):
        answers = iter([response(), response('AAAA', '2001:db8::1'), response('CNAME', 'edge.example.com.'),
                        response(value='192.0.2.2'), response('AAAA', '2001:db8::2'), response('CNAME', 'edge2.example.com.')])
        def reply(request, *args, **kwargs):
            answer = next(answers)
            answer.answer[0].name = request.question[0].name
            return answer
        udp.side_effect = reply
        row = self.client().sample_wildcard('dev.example.com', tests=2)
        self.assertEqual(row['state'], 'WILDCARD_SUSPECT')
        self.assertEqual(row['signatures']['A'], ['192.0.2.1', '192.0.2.2'])
        self.assertEqual(row['parent'], 'dev.example.com')

    @patch('dns_evidence.dns.query.udp')
    def test_resolver_diagnostics_are_bounded(self, udp):
        udp.return_value = response()
        client = self.client(max_queries=1)
        result = client.validate_resolvers()
        self.assertEqual(result['health']['queries'], 1)
        self.assertEqual(result['diagnostics']['192.0.2.53']['status'], 'DEGRADED')

    @patch('dns_evidence.dns.query.udp', side_effect=dns.exception.Timeout)
    def test_failed_wildcard_sampling_is_not_negative_evidence(self, udp):
        self.assertEqual(self.client().sample_wildcard('example.com', tests=1)['state'], 'INDETERMINATE')

    def test_name_normalization_and_validation(self):
        self.assertEqual(evidence.normalize_name(' API.Example.COM. '), 'api.example.com')
        for value in ('', 'x..example.com', 'a/b.example.com'):
            with self.assertRaises(ValueError):
                evidence.normalize_name(value)

    @patch('dns_evidence.dns.query.udp')
    def test_unrelated_answer_owner_is_not_asset_evidence(self, udp):
        answer = response(value=None)
        answer.answer.append(dns.rrset.from_text('unrelated.example.net.', 60, 'IN', 'A', '192.0.2.99'))
        udp.return_value = answer
        self.assertEqual(self.client().query('api.example.com', 'A')['values'], [])

    @patch('dns_evidence.dns.query.udp', side_effect=dns.exception.Timeout)
    def test_repeated_failures_quarantine_and_slow_rate_without_false_absence(self, udp):
        client = self.client()
        for _ in range(3):
            self.assertEqual(client.query('api.example.com', 'A')['state'], 'TIMEOUT')
        result = client.query('api.example.com', 'A')
        self.assertEqual(result['state'], 'ERROR')
        self.assertIn('quarantined', result['errors'][0])
        self.assertEqual(udp.call_count, 3)
        self.assertEqual(client.health()['effective_rate'], client.rate / 4)

    @patch('dns_evidence.dns.query.udp')
    def test_healthy_alternative_is_retried_immediately_and_preferred(self, udp):
        def reply(request, resolver, **kwargs):
            if resolver == '192.0.2.53':
                raise dns.exception.Timeout()
            return response()
        udp.side_effect = reply
        client = evidence.DNSClient(resolvers=['192.0.2.53', '192.0.2.54'], rate=1000000, cache_size=0)
        for _ in range(6):
            client.query('api.example.com', 'A')
        self.assertEqual(client.query('api.example.com', 'A')['resolver'], '192.0.2.54')
        failed_calls = [call for call in udp.call_args_list if call.args[1] == '192.0.2.53']
        self.assertEqual(len(failed_calls), 1)
        self.assertEqual(client.health()['preferred_resolver'], '192.0.2.54')

    @patch('dns_evidence.dns.query.udp')
    def test_success_after_cooldown_restores_configured_rate(self, udp):
        udp.side_effect = [dns.exception.Timeout(), dns.exception.Timeout(), dns.exception.Timeout(), response()]
        client = self.client()
        for _ in range(3):
            client.query('api.example.com', 'A')
        with client._lock:
            client._metrics['192.0.2.53']['quarantined_until'] = 0
        self.assertEqual(client.query('api.example.com', 'A')['state'], 'ANSWER')
        self.assertEqual(client.health()['effective_rate'], client.rate)

    @patch('dns_evidence.dns.query.udp')
    def test_failover_retains_attempts_and_definitive_negatives_do_not_retry(self, udp):
        udp.side_effect = [dns.exception.Timeout(), response()]
        client = evidence.DNSClient(resolvers=['192.0.2.53', '192.0.2.54'], rate=1000000)
        row = client.query('api.example.com', 'A')
        self.assertEqual(row['state'], 'ANSWER')
        self.assertEqual([r['state'] for r in row['resolver_attempts']], ['TIMEOUT', 'ANSWER'])
        udp.reset_mock()
        udp.side_effect = None
        udp.return_value = response(value=None, code='NXDOMAIN')
        self.assertEqual(client.query('missing.example.com', 'A')['state'], 'NXDOMAIN')
        self.assertEqual(udp.call_count, 1)

    @patch('dns_evidence.dns.query.udp', side_effect=dns.exception.Timeout)
    def test_failover_obeys_shared_packet_budget(self, udp):
        client = evidence.DNSClient(resolvers=['192.0.2.53', '192.0.2.54', '192.0.2.55'],
                                    rate=1000000, max_queries=2)
        self.assertEqual(client.query('api.example.com', 'A')['state'], 'TIMEOUT')
        self.assertEqual(udp.call_count, 2)
        self.assertEqual(client.health()['queries'], 2)


if __name__ == '__main__':
    unittest.main()
