"""Bounded background DNS and HTTP availability checks for ATLAS."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import datetime as dt
import threading
import ssl
import time
import urllib.error
import urllib.request

class RateLimit:
    def __init__(self, rate):
        self.interval = 1 / rate
        self.next = 0.0
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next)
            self.next = slot + self.interval
        time.sleep(max(0, slot - now))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class EvidenceRecords(dict):
    """Keep legacy records/errors tuples while carrying structured observations."""
    def __init__(self, observations):
        super().__init__((kind, row['values']) for kind, row in observations.items())
        self.evidence = observations

def lookup_dns(hostname, timeout, limiter):
    client = getattr(limiter, 'dns_client', None)
    # A real configured client is explicit; arbitrary Mock attributes must not
    # accidentally switch the legacy resolver contract used by integrations.
    from dns_evidence import DNSClient
    if isinstance(client, DNSClient):
        observations = client.resolve(hostname)
        errors = {kind: row['state'] + ': ' + '; '.join(row['errors'])
                  for kind, row in observations.items()
                  if row['state'] not in ('ANSWER', 'NODATA', 'NXDOMAIN')}
        return EvidenceRecords(observations), errors
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.retry_servfail = False
    records, errors = {}, {}
    for kind in ('A', 'AAAA', 'CNAME'):
        limiter.acquire()
        try:
            records[kind] = sorted(str(x).rstrip('.') for x in resolver.resolve(hostname, kind, lifetime=timeout))
        except Exception as error:
            records[kind] = []
            if type(error).__name__ not in ('NXDOMAIN', 'NoAnswer'):
                errors[kind] = type(error).__name__
    return records, errors

def http_probe(hostname, scheme, timeout, limiter):
    limiter.acquire()
    url = f'{scheme}://{hostname}/'
    request = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'ATLAS-Recon/1.3'})
    # No redirects, proxy environment, bodies, cookies or disabled TLS validation.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return {'url': url, 'code': response.status, 'scheme': scheme,
                    'tcp': 'CONNECTED', 'tls': 'VERIFIED' if scheme == 'https' else 'NOT_APPLICABLE', 'http': 'RESPONDED'}
    except urllib.error.HTTPError as error:
        # 3xx/4xx/5xx still prove an HTTP service responded.
        code = error.code
        error.close()
        return {'url': url, 'code': code, 'scheme': scheme, 'tcp': 'CONNECTED',
                'tls': 'VERIFIED' if scheme == 'https' else 'NOT_APPLICABLE', 'http': 'RESPONDED'}
    except (urllib.error.URLError, OSError, ValueError) as error:
        reason = getattr(error, 'reason', error)
        tls_error = isinstance(reason, ssl.SSLError)
        # A failed HTTP attempt alone does not prove TCP or TLS succeeded.
        return {'url': url, 'error': str(error)[:250], 'error_type': type(reason).__name__,
                'scheme': scheme, 'tcp': 'UNKNOWN',
                'tls': ('CERTIFICATE_ERROR' if isinstance(reason, ssl.SSLCertVerificationError) else 'TLS_ERROR')
                       if tls_error else ('UNKNOWN' if scheme == 'https' else 'NOT_APPLICABLE'),
                'http': 'NO_RESPONSE'}

def probe(hostname, timeout, limiter, dns_only=False):
    records, errors = lookup_dns(hostname, timeout, limiter)
    result = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'records': records, 'dns_errors': errors, 'http': [], 'tcp_tls_http': []}
    observations = getattr(records, 'evidence', None)
    if observations:
        from dns_evidence import classify
        result['dns_evidence'] = observations
        result['dns_state'] = classify(observations)
    if not records['A'] and not records['AAAA']:
        result['availability'] = 'CHECK_ERROR' if errors else 'NO_DNS'
        return result
    if dns_only:
        result['availability'] = 'DNS_ONLY'
        return result
    for scheme in ('https', 'http'):
        answer = http_probe(hostname, scheme, timeout, limiter)
        result['http'].append(answer)
        result['tcp_tls_http'].append({key: answer[key] for key in
                                      ('scheme', 'tcp', 'tls', 'http', 'code', 'error_type', 'error') if key in answer})
        if 'code' in answer:
            result['availability'] = 'UP'
            return result
    result['availability'] = 'NO_RESPONSE'
    return result

def check_all(names, workers, timeout, rate, dns_only, callback, dns_client=None):
    """Keep at most workers tasks queued; deliver results on the foreground thread."""
    iterator = iter(names)
    limiter = RateLimit(rate)
    from dns_evidence import DNSClient
    limiter.dns_client = dns_client or DNSClient(timeout=timeout, rate=rate)
    pool = ThreadPoolExecutor(max_workers=workers)
    pending = {}
    try:
        def submit():
            name = next(iterator, None)
            if name is not None:
                pending[pool.submit(probe, name, timeout, limiter, dns_only)] = name
        for _ in range(workers):
            submit()
        while pending:
            completed, _ = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
            for future in completed:
                name = pending.pop(future)
                try:
                    result = future.result()
                except Exception as error:
                    result = {'availability': 'CHECK_ERROR', 'records': {}, 'error': str(error)[:250],
                              'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()}
                callback(name, result)
                submit()
    finally:
        # Pending/inflight results are not claimed completed on interruption.
        pool.shutdown(wait=False, cancel_futures=True)
