# Third-party software and services

ATLAS source is licensed under MIT. This document identifies dependencies and
optional interoperability targets; it does not relicense them. ATLAS installers fetch seven free upstream release executables into a managed
directory; other adapters remain optional. The source wheel/ZIP contains the
installer and lock manifest, not third-party binaries. Installing or invoking an
engine separately does not imply that all possible integrations avoid license
obligations. Review the license and notices of the exact version distributed.

## Python dependencies

The wheel pins direct runtime versions in `pyproject.toml`.
`requirements-runtime.lock` additionally pins their transitive runtime graph,
resolved for Python 3.10, with PyPI artifact SHA-256 values for cross-platform
installs. Install it with `python -m pip install --require-hashes -r
requirements-runtime.lock` before installing the local wheel with `--no-deps`.
The lock excludes development tools and the optional Rich extra. Retain the lock
and review dependency updates explicitly; use an audited index or wheelhouse.

| Dependency | Direct version | Upstream license | Role |
| --- | --- | --- | --- |
| [dnspython](https://github.com/rthalley/dnspython) | 2.8.0 | ISC | DNS queries |
| [ipwhois](https://github.com/secynic/ipwhois) | 1.3.0 | BSD | IP registration/RDAP enrichment |
| [tldextract](https://github.com/john-kurkowski/tldextract) | 5.4.0 | BSD-3-Clause | Registrable-domain parsing |
| [Rich](https://github.com/Textualize/rich) | 14.1.0, optional `terminal` extra | MIT | Optional terminal presentation dependency; installing it does not enable a different interface automatically |

The Public Suffix List data used by tldextract has its own upstream provenance;
see [the Public Suffix List](https://publicsuffix.org/list/) and
[Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/). Keep data provenance
and snapshot dates when redistributing or replacing data. Inspect transitive
dependency notices in an SBOM rather than assuming they share a parent license.

## Optional engine adapters and research references

| Project | Upstream license | Integration / limitation |
| --- | --- | --- |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | MIT | Optional passive-discovery executable; API-backed providers may require separate accounts |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | MIT | Optional passive-discovery executable |
| [Findomain](https://github.com/Findomain/Findomain) | GPL-3.0 | Optional standalone discovery executable; review license before redistribution |
| [AlterX](https://github.com/projectdiscovery/alterx) | MIT | Optional bounded name-mutation executable |
| [PureDNS](https://github.com/d3mondev/puredns) | GPL-3.0 | Optional DNS-validation executable, with its own resolver/runtime prerequisites |
| [httpx](https://github.com/projectdiscovery/httpx) | MIT | Optional Go HTTP enrichment executable, distinct from Python's HTTPX library |
| [tlsx](https://github.com/projectdiscovery/tlsx) | MIT | Optional TLS evidence executable |
| [OWASP Amass](https://github.com/owasp-amass/amass) | Apache-2.0, separate subcomponent licenses may apply | Optional import/engine reference; version 5 CLI and schema must be tested independently of older examples |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | AGPL-3.0 | Recursive engine/architecture reference; not embedded or included in ATLAS's default dependencies |
| [Notify](https://github.com/projectdiscovery/notify) | MIT | Optional notification transport; users must configure and authorize destinations |

Listing a project does not promise its executable is installed or that every
upstream capability is exposed by ATLAS. The installed ATLAS help and adapter
health checks define supported operations. No automatic exploitation or takeover
confirmation is implied by DNS, TLS, fingerprint, or dangling-reference evidence.

## Service terms, quotas, and data

Certificate Transparency, RDAP, WHOIS, archival, reverse-IP, DNS and free public
data providers have different terms, rate limits, geographic coverage, retention,
and credit models. Open-source client licensing does not grant unlimited use of
a service or redistribution rights to returned data. Reverse-IP co-location and
certificate SAN overlap are associations, not proof of organizational ownership.

## Release hygiene

Before adding or updating an adapter: review its tagged source, license,
transitive dependencies and security policy; pin an audited release; verify
publisher-supplied checksums/signatures using an independently obtained expected
value; and run the adapter contract fixtures. Record binary SHA-256, version,
configuration and schema in the run manifest. See `scripts/install-engines.sh`
for the pinned, hash-verified free bundle installer. Installed metadata preserves
archive notices, version, hashes and upstream repository URLs.
