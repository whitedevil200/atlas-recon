"""Bounded background DNS and HTTP availability checks for ATLAS."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import datetime as dt
import threading
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

def lookup_dns(hostname, timeout, limiter):
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
            return {'url': url, 'code': response.status}
    except urllib.error.HTTPError as error:
        # 3xx/4xx/5xx still prove an HTTP service responded.
        code = error.code
        error.close()
        return {'url': url, 'code': code}
    except (urllib.error.URLError, OSError, ValueError) as error:
        return {'url': url, 'error': str(error)[:250]}

def probe(hostname, timeout, limiter, dns_only=False):
    records, errors = lookup_dns(hostname, timeout, limiter)
    result = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'records': records, 'dns_errors': errors, 'http': []}
    if not records['A'] and not records['AAAA']:
        result['availability'] = 'CHECK_ERROR' if errors else 'NO_DNS'
        return result
    if dns_only:
        result['availability'] = 'DNS_ONLY'
        return result
    for scheme in ('https', 'http'):
        answer = http_probe(hostname, scheme, timeout, limiter)
        result['http'].append(answer)
        if 'code' in answer:
            result['availability'] = 'UP'
            return result
    result['availability'] = 'NO_RESPONSE'
    return result

def check_all(names, workers, timeout, rate, dns_only, callback):
    """Keep at most workers tasks queued; deliver results on the foreground thread."""
    iterator = iter(names)
    limiter = RateLimit(rate)
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
