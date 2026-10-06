# Research notes

Reviewed official project documentation on 2026-10-05/06. Browser research inspected
Subfinder and PureDNS repositories; additional primary repositories were read via
web research. Upstream development branches are not stable compatibility contracts.

| Primary source | Finding and implementation decision |
|---|---|
| https://github.com/projectdiscovery/subfinder | Passive aggregation, all sources, JSONL provenance, optional provider API keys. Used as executable adapter. |
| https://github.com/tomnomnom/assetfinder | Related-name discovery with --subs-only. Results are independently scope filtered. |
| https://github.com/Findomain/Findomain | Complementary passive providers; target/quiet CLI adapter. |
| https://github.com/projectdiscovery/alterx | Candidate generation and enrichment, output limit. Optional active workflow generator. |
| https://github.com/d3mondev/puredns | Bulk resolution, wildcard cleanup and trusted validation; requires massdns. Optional resolution backend. |
| https://github.com/projectdiscovery/dnsx | DNS record collection and wildcard capabilities. Considered; imports supported rather than duplicate resolution adapter. |
| https://github.com/projectdiscovery/httpx | HTTP metadata and TLS capture. Optional adapter without redirect or extracted-domain probing. |
| https://github.com/owasp-amass/amass | Broader attack surface ecosystem; changing architecture makes a generic version-independent CLI wrapper unreliable. Import exports. |
| https://crt.sh/ | Public certificate search endpoint. Historical names need current DNS validation. |
| https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server | CDX reference; web fetch was blocked, so live endpoint compatibility is unverified. Bounded archived host collection; cap means incomplete coverage. |

Independent passive tools overlap sources; three tool confirmations are not necessarily
three independent datasets. API-backed providers may require paid access or credentials.
Do not confuse DNS response existence with an independently configured host. Keep wildcard
uncertainty and historical evidence visible. Resolver quality matters as much as query rate.

No production benchmark or real target enumeration was performed during development.

Version 1.2: Cert Spotter API reference verified at https://sslmate.com/help/reference/ct_search_api_v1 (include_subdomains, expand=dns_names, after pagination). HackerTarget limits verified at https://hackertarget.com/find-dns-host-records/ (50 free results per query). Subfinder v2.16.0 official Windows release used for passive validation, SHA256 checked against its release checksums.
