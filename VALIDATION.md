# Validation record

## Version 2.1 � 25 October 2026

132 tests passed on the Windows development host. The seven pinned Windows
engines were downloaded, SHA-256 verified, installed and answered version
commands successfully. Subfinder source metadata confirms the configured
allowlist is keyless. The clean installed-wheel test passed. Tests cover
installer hash rejection, bounded extraction, license retention, idempotence,
tamper repair, failed-download preservation and paid-provider no-request policy.
This does not claim all optional adapters are installed or every provider works
live. No public target was scanned for these checks.


## Version 2.0 — 24 October 2026

125 offline unit/integration tests pass on the Windows development host with
Python 3.14.3. Coverage includes all legacy flows plus SQLite durability/history,
stable IDs and numbering, interrupted/partial process recovery, discovery and
availability resume, unchanged input manifests, pending-only checks, source/API
schemas, owner exports/views, engine configuration and scope, notification outbox
recovery with mocked delivery, DNS error distinctions/TTL caching/wildcards,
trusted comparison, resolver quarantine/adaptive rate, and HTTP/TLS evidence.

A clean installed-wheel smoke check passed outside the checkout, verifying the
console entry point, every module, bundled wordlist/man page and an offline
two-name scan. The runtime lock was resolved for Python 3.10 and hash-checked
on the local interpreter. No public target collection was needed for this upgrade.

Three real loopback DNS lab executions each passed 10 assertions, with 39 DNS
packets matching client counts. The lab uses an ephemeral localhost port,
documentation addresses and controlled DNS wire responses, not public targets.
See docs/BENCHMARK.md for measurements and limitations.

External repository adapters have mocked command/schema tests. Their presence
does not establish that all optional executables are installed or live-tested.
Amass integration is explicit structured export import; cloud DNS integration
imports owner-authorized exports rather than making cloud account changes.
Linux/Windows Python 3.10/3.13 CI includes the full suite, loopback lab,
installed wheel, bundled resources, Linux installer and Bash menu workflows.

The implementation matrix in docs/UPGRADE-2.md describes remaining boundaries;
there is no claim of internet-wide completeness, comparative superiority or
absence of all possible third-party failures.

## Version 1.6.1 — post-discovery selection

41 tests pass locally. New checks verify automatic lookup offers in interactive
terminals, explicit post-scan selection of the displayed SR NO, non-interactive
and --no-lookup behavior, cancellation without marking discovery failed, and
selection from the new checked run after --check-live. Both menus request the
follow-up explicitly. The user no longer needs to re-enter a saved run directory
after discovery. Linux CI also exercises the explicit post-discovery prompt
using offline evidence; no new public scan is required for this UI change.

## Version 1.6 — 7 October 2026

36 offline tests passed on Windows/Python 3.14.3 with dnspython 2.8.0,
ipwhois 1.3.0 and tldextract 5.4.0. Tests cover selected serials and filtered
views, CSV/report numbering consistency, menu/browse routing, PSL parent
extraction without hidden downloads, cached domain RDAP/bootstrap, refresh/expiry,
scope/exclusions, output protection, reverse-index HTTP 200 quota/error bodies,
IPv6/private IP handling, bounded IP work, DNS absence versus timeout, independent
provider failure, ASN/bootstrap fallback, HTTPS routing fallback, HTTP 429 and
oversized responses. The earlier 20 core/availability tests remain passing.

Public lookup smoke test: imported only `www.example.com`, then selected SR NO 1
for all lookups with max-ips=1 and timeout=5. Verisign domain RDAP, current DNS,
Cloudflare IP registration and HackerTarget reverse-IP indexing returned results;
273 index names were returned in this specific response (coverage/limits vary).
No target HTTP probes, neighbour probes, range scans or out-of-scope additions
occurred. IP work was deliberately capped and omitted IPs were reported with a
partial exit status. The system's ASN DNS lookup failed, so registry bootstrap
preserved IP registration. A second smoke test verified the HTTPS RIPEstat
fallback returned origin AS13335 and BGP prefix 104.20.16.0/20.

Python byte compilation and Windows launcher help/version passed. Local Linux
Bash remains unavailable; expanded GitHub CI validates Bash syntax/menu routing,
the installer and installed lookup help on Ubuntu, plus Windows launchers, on
Python 3.10 and 3.13. Provider integrations are covered by mocks and the limited
live smoke test, not an exhaustive production benchmark. Legacy whois binary
and every ccTLD/RIR/provider combination have not been validated live.

Earlier development records follow.

Development host: Windows, Python 3.14.3, Earlier core validation used dnspython 2.8.0.

Passed Python byte compilation, CLI scan help, dependency doctor, and eight offline unit tests (DNS mocked without a runtime dependency):
scope boundaries/exclusions, input normalization/IDNA, offline import/report,
active acknowledgment requirement, synthetic wildcard/IPv6 classification, and
banner compatibility with a legacy Windows terminal encoding.

No real target was scanned. No external enumeration binaries were installed or
executed. Linux/WSL and Bash were unavailable, so the Bash installer/launcher,
man-page rendering and optional executable adapters remain unverified on Linux.
Provider availability, upstream flag compatibility and performance need Linux
integration validation before operational use.

Version 1.1 adds the terminal dashboard, saved-run terminal viewer, and text reports. The offline report test confirms report.txt exists, no HTML is emitted, and the terminal viewer displays imported assets.

Menu returns after help; ANSI color and NO_COLOR behavior passed dedicated checks.

Version 1.2: 11 tests passed, adding CT cursor/pagination, import provenance and scope, and readable report pagination/search. Live google.com passive run used official checksum-verified Subfinder v2.16.0 plus 30 Cert Spotter pages; merged inventory contains 27,667 distinct scoped subdomains. No active DNS/HTTP checks were performed. AlienVault rate-limited, and earlier crt.sh/Wayback failed. Counts represent public historical evidence, not confirmed live hosts. Linux installer remains unverified.

Version 1.3: 19 offline tests passed. New coverage: every name processed once by bounded worker pool, HTTP errors count as reachable, redirects not followed, HTTP fallback, DNS absence vs timeout, no-response classification, original discovery preservation, exports and overwrite protection, authorization requirement and interrupted pending results. Availability checks are mocked; no live Google host verification was performed for v1.3. Linux installer remains unverified.

Version 1.4: 19 tests passed after full-list rendering replaced pagination. Updated report test verifies all rows, serial numbers and total count. Saved Facebook evidence is displayed without new network checks.

Version 1.5: 20 Python tests passed, including no-argument startup opening a colored menu. Bash launcher now implements menu routing directly with arrays and quoted arguments. Bash is unavailable on the development host; Linux execution and installer validation remain outstanding.

Windows startup repair: atlas.cmd version/doctor and no-argument menu successfully executed in PowerShell. Session PATH setup resolves atlas by name. install-windows.cmd created a workspace-local virtual environment and installed dnspython 2.8.0 successfully. Core test suite passed in that environment. Linux Bash installer remains unverified.
