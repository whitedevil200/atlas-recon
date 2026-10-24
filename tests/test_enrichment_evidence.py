from pathlib import Path
import ssl
import sys
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability
from dns_evidence import DNSClient
import lookups


def row(kind, state='NODATA', values=None):
    return {'kind': kind, 'state': state, 'values': values or [], 'cnames': [],
            'rcode': 'NOERROR', 'ttl': 30, 'resolver': '192.0.2.53',
            'checked_at': 'fixture', 'errors': []}


class EnrichmentEvidenceTests(unittest.TestCase):
    def test_background_probe_retains_cname_without_claiming_web_up(self):
        client = DNSClient(resolvers=['192.0.2.53'])
        observations = {k: row(k, 'NXDOMAIN') for k in ('A', 'AAAA', 'CNAME')}
        observations['A']['cnames'] = ['missing.example.net']
        limiter = MagicMock()
        limiter.dns_client = client
        with patch.object(client, 'resolve', return_value=observations), patch('availability.http_probe') as http:
            result = availability.probe('api.example.com', 2, limiter)
        self.assertEqual(result['availability'], 'NO_DNS')
        self.assertEqual(result['dns_state'], 'CNAME_ONLY')
        self.assertEqual(result['dns_evidence']['A']['cnames'], ['missing.example.net'])
        http.assert_not_called()

    def test_timeout_stays_check_error_with_structured_evidence(self):
        client = DNSClient(resolvers=['192.0.2.53'])
        observations = {k: row(k, 'TIMEOUT') for k in ('A', 'AAAA', 'CNAME')}
        limiter = MagicMock()
        limiter.dns_client = client
        with patch.object(client, 'resolve', return_value=observations):
            result = availability.probe('api.example.com', 2, limiter)
        self.assertEqual(result['availability'], 'CHECK_ERROR')
        self.assertEqual(result['dns_state'], 'INDETERMINATE')

    def test_tls_certificate_error_does_not_claim_http_response(self):
        opener = MagicMock()
        opener.open.side_effect = urllib.error.URLError(ssl.SSLCertVerificationError('invalid cert'))
        with patch('availability.urllib.request.build_opener', return_value=opener):
            result = availability.http_probe('api.example.com', 'https', 2, MagicMock())
        self.assertEqual(result['tls'], 'CERTIFICATE_ERROR')
        self.assertEqual(result['http'], 'NO_RESPONSE')
        self.assertNotIn('code', result)

    def test_modern_records_and_explicit_service_owners_share_client(self):
        client = MagicMock()
        client.resolve.return_value = {'A': row('A', 'ANSWER', ['192.0.2.1']), 'HTTPS': row('HTTPS')}
        client.query.return_value = row('SRV')
        result = lookups.inspect_selected('api.example.com', client=client, srv_services=['_sip._tcp'])
        kinds = client.resolve.call_args.args[1]
        self.assertIn('HTTPS', kinds)
        self.assertIn('SVCB', kinds)
        self.assertIn('SRV', kinds)
        client.query.assert_called_once_with('_sip._tcp.api.example.com', 'SRV')
        self.assertEqual(result['dns_state'], 'RESOLVED')

    def test_trust_disagreement_is_reported_without_discarding_answers(self):
        client = MagicMock()
        observation = row('A', 'ANSWER', ['192.0.2.1'])
        observation['verification'] = {'state': 'DISAGREES'}
        client.resolve.return_value = {'A': observation}
        result = lookups.dns_records('api.example.com', 2, ('A',), client)
        self.assertEqual(result['trust_disagreements'], ['A'])
        self.assertEqual(result['records']['A']['values'], ['192.0.2.1'])


if __name__ == '__main__':
    unittest.main()
