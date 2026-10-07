# Lookup implementation research — 7 October 2026

Primary repositories and official protocol/provider documentation were reviewed through Browser and web research. There is no universally best lookup repository: these integrations were selected for protocol coverage, Python compatibility and a clear API. No third-party source was copied into ATLAS.

| Source | Decision |
|---|---|
| [ICANN RDAP transition](https://www.icann.org/en/announcements/details/icann-update-launching-rdap-sunsetting-whois-27-01-2025-en) | WHOIS menu defaults to RDAP for gTLD registration. Legacy TCP WHOIS is an optional installed executable, not a required scraper. |
| [IANA domain bootstrap](https://www.iana.org/assignments/rdap-dns/) / [JSON registry](https://data.iana.org/rdap/dns.json) | Discover authoritative domain endpoints rather than hardcoding a commercial registration proxy. One HTTPS endpoint is used per request; absent ccTLD entries are explained. |
| [secynic/ipwhois](https://github.com/secynic/ipwhois) / [RDAP API](https://ipwhois.readthedocs.io/en/stable/RDAP.html) | Integrate `IPWhois.lookup_rdap` for IPv4/IPv6 registration and ASN parsing. Disable retries, contact recursion and NIR scraping to bound network work. Bootstrap fallback preserves RDAP when ASN DNS fails. BSD-2-Clause dependency, installed through PyPI. |
| [john-kurkowski/tldextract](https://github.com/john-kurkowski/tldextract) | Avoid naive last-two-label parent selection. Use the bundled PSL snapshot without hidden startup downloads; exclude private suffix rules because the lookup concerns registry registration. BSD-3-Clause dependency, installed through PyPI. |
| [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info.html) | HTTPS routing/ASN fallback when ASN DNS is unavailable. Retain all observed origin ASNs and keep routing evidence distinct from allocation/registration. |
| [HackerTarget reverse-IP](https://hackertarget.com/reverse-ip-lookup/) | Keyless IPv4 passive-index adapter, plus independent PTR and local saved-IP correlation. Quotas/result limits mean incomplete coverage. HTTP 200 error bodies are rejected, not ingested as domains. No automatic retries/pagination to evade limits. |
| [ICANN Rust RDAP implementation](https://github.com/icann/icann-rdap) / [OpenRDAP client](https://github.com/openrdap/rdap) | Considered as external CLI alternatives. The small domain-bootstrap client and Python IP parser avoid requiring another language runtime/executable for the default ATLAS workflow. |

The provider's documented free quotas on review were 20 requests/day and 50 results/request; actual returned counts and access limits can vary. ATLAS reports returned evidence and coverage limitations rather than promising a fixed result count or completeness. No membership/API key is required by this adapter and no credentials are stored.

Domain registration, live DNS, PTR, passive reverse-IP indexes, historical saved A/AAAA records and observed BGP routing answer different questions. The CLI labels sources, scope and retrieval timestamps; cache hits retain their original time. CDN/shared IPs do not establish common ownership, and registration country does not locate a device.

Network use: selected name -> recursive DNS; registered parent -> IANA/registry RDAP; resolved public IP -> RIR/ASN services and optional reverse-IP provider. Neighbour hostnames are displayed only; no neighbour DNS/HTTP probes or inventory mutation occur. TLS verification remains enabled. Raw responses are saved locally, not published to the repository.

Tests exercise serial/filter consistency, scope/exclusions, cache refresh/expiry, provider errors with HTTP 200, HTTP 429, malformed/oversized responses, IPv6 unsupported indexing, private addresses, IP limits, missing DNS records vs timeout, ASN/bootstrap/HTTPS fallback and output protection. Public smoke testing uses `www.example.com` for DNS/registration/index queries without target HTTP probes. See [validation notes](../VALIDATION.md).
