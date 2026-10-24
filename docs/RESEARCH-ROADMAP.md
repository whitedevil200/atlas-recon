# ATLAS: research and proposed product roadmap

Implementation update: this is the v1.6.1 research snapshot. The subsequent
v2.0 implementation and its explicit limits are documented in [UPGRADE-2.md](UPGRADE-2.md).

Research date: 24 October 2026. Reviewed baseline: ATLAS v1.6.1.

## Decision

The strongest direction is a CLI reconnaissance workspace that explains each asset, preserves observations, resumes interrupted work and highlights meaningful changes. More source wrappers can improve coverage, but their value must be measured against duplicate results, false positives, time and provider credits.

The next release should prioritize **correct DNS evidence, stable asset identity, recoverable collection and transparent source coverage**. Add structured DNS/HTTP/TLS enrichment and change tracking on that foundation. Keep the colorful terminal, the full numbered list and post-discovery serial selection.

This is a research recommendation, not an implemented release or a performance benchmark. Research used Browser, official repositories, release documentation, provider APIs and standards. Three specialist workstreams covered discovery, DNS accuracy and product architecture. It is not an exhaustive review of every website/repository. No public targets were scanned for this research, no paid services were purchased, and no additional scanning engines were installed.

## Existing strengths and gaps verified in the local code

ATLAS already has multiple passive sources, per-provider Subfinder attribution, scoped imports, bounded wordlist generation, optional AlterX/PureDNS/httpx, wildcard review labels, background availability checks, saved reports, WHOIS/RDAP/IP/reverse-IP enrichment, and post-discovery SR NO selection. These should be extended rather than presented as new discoveries.

| Local finding | Relevant code | Improvement |
|---|---|---|
| Subfinder already uses JSONL and collected sources, and stores individual provider names. | `atlas.py`, `Run.passive` | Add observation timestamps, provenance edges, upstream evidence dates and source-family overlap. Do not simply add another `source=subfinder` field. |
| Passive stages execute sequentially; external-tool output is read only after completion. | `atlas.py`, `Run.passive`, `Run.tool` | Stream valid observations into bounded queues with per-provider concurrency. |
| Tool timeouts preserve raw files but explicitly discard partial results from ingestion. | `atlas.py`, `Run.tool` | Ingest complete valid JSONL records already received; mark the source incomplete. A timeout must not silently lose all valid work. |
| CT accepts an initial cursor but does not persist a durable automatically advancing cursor for the next run. | `atlas.py`, Cert Spotter adapter | Commit a cursor only after the associated page has been ingested transactionally. |
| General HTTP fetching retries failures three times with a simple delay. | `atlas.py`, `fetch` | Classify throttling, quota exhaustion and transient failures; honor Retry-After, with bounded backoff/jitter and durable retry state. |
| Active recursion expands only the passive seed snapshot, rather than repeatedly feeding newly validated discoveries back into generation. | `atlas.py`, `Run.active` | Add a deduplicated, depth-limited discovery frontier with total request/candidate/time budgets. |
| DNS resolution reduces NXDOMAIN and NoAnswer to empty lists; the main discovery/check paths do not retain full DNS response evidence. | `atlas.py`, `Run.query`; `availability.py`, `lookup_dns` | Preserve RCODE, RRtype, CNAME chain, resolver, TTL and error category. Selected-host lookup already retains some TTLs, so unify the models. |
| PureDNS narrows targets, then built-in DNS queries run serially over the remaining names. | `atlas.py`, `Run.active` | Define an explicit validation contract and reuse structured trusted evidence; avoid redundant work unless revalidation adds value. |
| `Run.save` numbers its lexically ordered asset rows, while terminal display uses a different order and excludes the apex. | `atlas.py`, `Run.save`, `ordered_subdomains` | Unify saved/display serial mappings. The newer explicit export path already uses display ordering; initial assets.csv/report.txt still need the same contract. |
| HTTP availability uses HEAD and records errors, but the compact status cannot express DNS, TCP, TLS and HTTP independently. | `availability.py`, `http_probe`, `probe` | Add layered evidence/statuses. A responding HTTP error remains reachable; a TLS failure should remain visible independently. |
| JSONL files and check checkpoints exist, but there is no durable cross-run job queue, history database or resume command. | `atlas.py`, `Run.save`, `check_report` | Add persistence and resume rather than describing current checkpoints as full recovery. |
| Windows startup depends on using the correct folder/launcher. | `atlas.cmd`, `install-windows.cmd` | Package a real console entry point and provide clearer PATH/location diagnostics. Earlier user startup errors make this a product priority. |

These are static implementation observations. They are not claims that the whole program is unsafe or that upstream tools are defective.

## Ranked feature backlog

Priority expresses recommended implementation order, not an external benchmark. Effort is relative: S = localized change; M = several modules; L = architectural or integration work.

| Rank | Feature | User-visible result | Priority / effort |
|---|---|---|---|
| 1 | Stable asset IDs and consistent serial mapping | A displayed/exported SR NO selects the same hostname; persistent references survive sorting and refresh. | P0 / M |
| 2 | SQLite asset and observation history | First/last observed times, evidence sources and previous DNS/HTTP/TLS states for every name. | P0 / L |
| 3 | Resume and valid partial-output recovery | Restart interrupted collections without losing complete observations or repeating finished pages. | P0 / L |
| 4 | DNS evidence and wildcard validation | Distinguish absent record types, nonexistent names, broken aliases, timeouts and wildcard uncertainty. | P0 / L |
| 5 | Provider health, quota and coverage dashboard | See exactly which sources completed, failed, skipped, throttled or stopped at a result cap. | P0 / M |
| 6 | Resolver health and shared TTL-aware cache | Fewer repeated queries and clearer resolver disagreements; rate adapts to measured failures. | P0/P1 / M |
| 7 | Snapshot comparison and change history | Show new assets, new web responses, changed CNAME/IP/TLS and coverage regressions. | P1 / M |
| 8 | Bounded iterative discovery | New verified names can feed another discovery round, with visible depth and stop reasons. | P1 / L |
| 9 | Unified per-host evidence card | After selecting SR NO, browse DNS, HTTP, TLS, registration, IP/ASN, provenance and history together. | P1 / M |
| 10 | Structured httpx/tlsx ingestion | Rich HTTP/TLS observations become searchable inventory data rather than separate raw artifacts. | P1 / M |
| 11 | Owner-authorized DNS inventory imports | Import configured records from Route 53, Cloudflare or Cloud DNS, then compare them with public evidence. | P1 / L |
| 12 | Complementary archives/passive DNS | Common Crawl, supported provider history and current Censys integration, with explicit account/credit limits. | P1 / M per adapter |
| 13 | Learned, measured candidate generation | Use observed naming patterns; estimate/cap mutations and report validated yield by strategy. | P1 / M |
| 14 | SVCB/HTTPS/SRV and delegation relationships | Capture modern service bindings and zone boundaries missed by an A/AAAA-only view. | P1 / M |
| 15 | Optional scoped web hostname extraction | Extract in-scope candidate names from links, scripts, CSP and TLS SANs under crawl/response-size limits. | P2 / M |
| 16 | Explainable review priorities | Surface changed exposure, certificate problems and dangling references with evidence and uncertainty. | P2 / M |
| 17 | Watch and opt-in change notifications | Notify on deduplicated meaningful changes, with grouping, cooldowns and delivery state. | P2 / M |
| 18 | Reproducible package/adapters and benchmark suite | Reliable installation, verified tool versions, dependency locks, release manifests and measured quality. | P0 foundation, P2 expansion / L |

## Feature design details

### 1. Evidence-backed persistent inventory

Keep Bash as launcher/menu; put orchestration and storage in Python. Use SQLite for the portable single-user default, with a single coordinated writer, transactions and WAL mode where appropriate. A separate graph server should not be required.

Proposed tables: workspaces, scope_rules, runs, assets, observations, relationships, jobs, provider_state and optional notification_outbox. Distinguish an asset's identity from its observations. Include DNS view/network context so private and public answers are not merged incorrectly.

Store source/provider, parent discovery, collection time, upstream observation time if available, raw artifact path/hash, installed tool version, queried type, and uncertainty. A certificate reference, a current DNS answer, an HTTP response and organization ownership are separate claims. Do not fabricate a numerical confidence percentage without calibration.

BBOT's event relationships and Amass's asset storage are useful precedents for this design. They do not require ATLAS to adopt those systems wholesale. [BBOT architecture](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/), [BBOT events](https://github.com/blacklanternsecurity/bbot/blob/stable/docs/scanning/events.md), [Amass asset-db](https://github.com/owasp-amass/asset-db).

Acceptance: a selected asset shows its discovery path and previous observations, even after sorting, interruption and restart. SR NO remains a presentation index; an internal asset ID is persistent.

### 2. Correct DNS state and wildcard uncertainty

Store per-query evidence and distinguish NXDOMAIN, NODATA, SERVFAIL, REFUSED, TIMEOUT, usable addresses, CNAME-only answers and unresolved alias targets. RFC 2308 explains the negative-answer distinction, including CNAME-chain cases. [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html).

Test randomized labels at relevant parent levels; allow bounded repeated samples for rotating wildcard pools. Compare A/AAAA/CNAME observations, record resolver disagreement and retain suspects for review. PureDNS documents limitations from rotating wildcard answers and provides bulk filtering/trusted-validation stages. [PureDNS](https://github.com/d3mondev/puredns).

Add a shared bounded TTL-aware DNS cache; dnspython documents that its cache implementations are thread-safe and that caching is not enabled by default. Cache expiry and negative answers must be handled correctly. [dnspython caching](https://dnspython.readthedocs.io/en/stable/resolver-caching.html).

Acceptance: a real name with no A record is not automatically labeled nonexistent; rotating/nested wildcards remain identifiable; disagreement and timeout never become false certainty.

### 3. Recoverable streaming pipeline and provider economics

Stream tool output and provider pages into bounded queues. Commit valid observations incrementally. Record each job's stage, attempts and completion state, and recover unfinished jobs idempotently. Bind resume to the original scope/configuration/tool manifest; a changed scope should produce an explicit new run or migration.

Track actual requests, elapsed time, new unique names, validated yield, duplicates, provider limits and estimated credit use when known. A source should report complete, capped, unavailable, missing-key, throttled or failed rather than collapsing every outcome to success/failure.

Persist Cert Spotter cursor state only after ingestion. Distinguish throttling from exhausted quota. [Cert Spotter API](https://sslmate.com/help/reference/ct_search_api_v1), [SecurityTrails quotas](https://docs.securitytrails.com/docs/quotas-rate-limits). Subfinder already supports provider-level rate controls, which can be exposed through a tested adapter. [Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage).

Acceptance: kill/restart loses no committed observations; quota exhaustion does not cause a retry loop; a capped source remains visibly incomplete.

### 4. Changes and controlled recursive discovery

Proposed comparison categories: newly observed hostname, newly DNS-resolved asset, newly responding web service, changed CNAME/IP, changed certificate and no longer observed. Missing from a run with worse provider coverage is not proof of deletion. Retire assets only under an explicit repeated-observation policy.

For recursion, enqueue only genuinely new candidates. Each candidate retains the mechanism that generated it: archive, certificate, service binding, wordlist or mutation. Bound maximum depth, rounds, candidate count, DNS requests, provider credits and elapsed time.

Do not interpret Subfinder's recursive-source selector as a complete iterative discovery engine. Its documented flag selects sources that accept nested domains. [Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage).

Acceptance: the same candidate is not queried indefinitely; each round shows useful yield and the reason collection stopped.

### 5. HTTP/TLS evidence integrated with the inventory

ATLAS already invokes optional httpx. Parse its structured output into the common observation schema rather than leaving enrichment only in a separate output file. Add TLS collection through a tested tlsx adapter. Preserve the minimal built-in checker.

Show DNS, connection, TLS and HTTP independently, including SNI/hostname context. HTTP 403/404 proves a response; certificate failure is a separate observation. Configure any HEAD-to-GET fallback with strict body/time budgets. Optional redirect handling must check scope at every hop; keep out-of-scope locations as references rather than silently following them.

httpx supplies structured response metadata and tlsx specializes in TLS collection. [httpx usage](https://docs.projectdiscovery.io/opensource/httpx/usage), [tlsx](https://github.com/projectdiscovery/tlsx).

Acceptance: the SR-NO card can explain why a web service is responding while still having a TLS problem, and identify when each observation was collected.

### 6. Better coverage through owner inventory and complementary sources

For customer-controlled zones, add read-only inventory imports. These APIs enumerate configured DNS records that public indexes may never have observed. Start with Route 53, Cloudflare and Google Cloud DNS. Handle pagination, permissions, delegated zones and public/private views explicitly. Treat results as configured records, not proof that a service is reachable. [Route 53 listing](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html), [Cloudflare listing](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/), [Cloud DNS listing](https://docs.cloud.google.com/dns/docs/reference/rest/v1/resourceRecordSets/list).

This still is not a global completeness guarantee: delegated child zones, application-defined labels, wildcard synthesis and resources outside the imported accounts need separate treatment.

For external reconnaissance, evaluate Common Crawl and optional historical/passive DNS providers. Attribute historical names with timestamps. Avoid querying the same underlying provider through several wrappers without measuring incremental value. Common Crawl asks clients not to overload its index and offers bulk-oriented alternatives. [Common Crawl index](https://index.commoncrawl.org/).

Censys integration must target its current Platform API and SDKs, not assume legacy endpoint compatibility. Its documentation says free accounts have lookup endpoints, while search access and credit consumption depend on tier and roles. [Migration guide](https://docs.censys.com/docs/platform-api-transition-guide), [API access](https://docs.censys.com/reference/get-started).

Acceptance: a discovery run states what inventories/accounts/datasets were checked and which were inaccessible; it does not claim universal coverage from a large count.

### 7. Modern DNS, naming patterns and scoped web discoveries

Add service relationships from SRV, SVCB and HTTPS records, while retaining AAAA and CNAME chains. SVCB/HTTPS may identify alternative service endpoints and connection parameters; these are relationships, not proof of ownership. [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html).

Improve the existing AlterX path using observed tokens, environment/region labels and numeric neighbours. Estimate generation size before execution. Divide the candidate budget between wordlist and mutation strategies so the first generator cannot silently consume the entire allowance. Measure validated names per strategy. [AlterX](https://github.com/projectdiscovery/alterx).

An optional shallow, scoped crawler can collect hostname candidates from web content and CSP. Katana is a candidate adapter, but should not be a required dependency or automatically browse every related URL. Bound crawl depth, requests, bytes and runtime. [Katana](https://github.com/projectdiscovery/katana).

### 8. Review priorities, CLI experience and installation

Preserve the full results list and readable numbered selection. Add a compact progress summary above it, with source health, stage, budgets and newly observed counts. Use Rich for optional formatting and live summaries while maintaining NO_COLOR/plain output and full final scrollback. Rich live tables can truncate when the terminal is short; do not place the only complete inventory inside that live region. [Rich live display](https://rich.readthedocs.io/en/stable/live.html).

Extend selection to batches such as `2,5,8-12`, with the snapshot/filter shown before work starts. Evidence-card tabs or numbered sections can expose DNS, HTTP, TLS, registration, IP/ASN, reverse-IP, history and why-discovered details.

Prioritize evidence-backed observations: changed exposure, certificate expiration, broken CNAME chains or risky delegation. Label suspicious dangling references as review candidates, not confirmed takeovers. BadDNS is a specialist project to evaluate behind an explicit profile; provider-specific checks and signatures require independent validation. [BadDNS](https://github.com/blacklanternsecurity/baddns).

Package ATLAS with a `pyproject.toml` console entry point and platform-tested installation paths. Offer a conventional isolated install through pipx or uv tool; retain Bash/Windows launchers. Run doctor before deep scans, explaining command-not-found errors, missing credentials and adapter compatibility. uv is a possible distribution tool, not a mandatory scanner runtime. [uv](https://github.com/astral-sh/uv).

## Repository selection

These are integration/reference choices, not a recommendation to install all engines at once. Version observations are research snapshots, not guarantees that a local binary matches current documentation.

| Repository | Role | Observed release/license signal | Decision |
|---|---|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive aggregation | v2.17.0; MIT | Deepen existing adapter, budgets and source analytics. |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Structured DNS backend | v1.3.1; MIT | First new optional DNS engine. |
| [PureDNS](https://github.com/d3mondev/puredns) | Bulk/wildcard/trusted validation | v2.1.1; GPL-3.0 | Improve existing adapter before adding a duplicate backend. |
| [MassDNS](https://github.com/blechschmidt/massdns) | Bulk resolution primitive | GPL-3.0 | Keep behind validation and healthy resolver policies. |
| [ShuffleDNS](https://github.com/projectdiscovery/shuffledns) | Alternative bulk DNS | v1.2.1; GPL-3.0 | Optional alternative to PureDNS, not another default stage. |
| [AlterX](https://github.com/projectdiscovery/alterx) | Candidate generation | MIT | Deepen existing integration and budget allocation. |
| [Gotator](https://github.com/Josue87/gotator) | Specialist permutations | GPL-3.0 | Optional; numeric/depth expansion needs strict bounds. |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP observations | v1.12.0; MIT | Integrate existing raw results into inventory. |
| [tlsx](https://github.com/projectdiscovery/tlsx) | TLS observations | v1.4.0; MIT | Add dedicated optional adapter. |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | Recursive event architecture | v3.0.2; AGPL-3.0 | Reference architecture or separately installed optional engine/import. |
| [Amass](https://github.com/owasp-amass/amass) | Broader attack-surface mapping | v5.1.1; Apache-2.0 text plus separate component notices | Add a version-tested import/adapter after persistence exists. |
| [Findomain](https://github.com/Findomain/Findomain) | Complementary discovery/monitoring | stable 10.0.1; 11.0.0-beta.2 prerelease; GPL-3.0 | Retain existing adapter; distinguish stable and beta capabilities. |
| [Chaos Client](https://github.com/projectdiscovery/chaos-client) | Additional dataset | v0.5.2; MIT | Optional if it provides useful incremental data. |
| [Notify](https://github.com/projectdiscovery/notify) | Alert delivery transport | v1.0.7; MIT | Optional after diff/outbox features; not a substitute for change detection. |

Release observations come from the respective linked repository release pages, inspected by the research workstreams. License labels require retaining the actual upstream notices and reviewing the intended integration/distribution model; this report is not a legal compatibility determination.

### Integration pitfalls found in current documentation

- dnsx streaming mode disables wildcard handling/statistics/resume. Its broad recon option includes AXFR, so choose explicit record types for ordinary enrichment. Wildcard modes have mutually exclusive options. ASN enrichment also has authenticated-service requirements in release documentation. Use capability-tested adapter profiles. [dnsx](https://github.com/projectdiscovery/dnsx), [releases](https://github.com/projectdiscovery/dnsx/releases).
- PureDNS and ShuffleDNS overlap. More default engines can duplicate work without adding evidence. MassDNS itself warns against assuming its bundled public resolver list is reliable. [MassDNS](https://github.com/blechschmidt/massdns).
- Findomain master documentation describes functionality introduced in v11 beta, including its larger source set and storage changes. Stable and beta are not interchangeable contracts. [Findomain releases](https://github.com/Findomain/Findomain/releases).
- Current dnsx dev and AlterX main module files require Go 1.25.0, while their README requirements lag. Pin and test releases rather than building arbitrary latest branches. [dnsx go.mod](https://github.com/projectdiscovery/dnsx/blob/dev/go.mod), [AlterX go.mod](https://github.com/projectdiscovery/alterx/blob/main/go.mod).
- Separate overlapping upstream datasets in analytics. Three wrappers returning a CT name are not necessarily three independent observations of a live service.

## Proposed delivery sequence

These release labels describe a suggested plan, not published versions or delivery promises.

| Stage | Deliverable | Exit criteria |
|---|---|---|
| Reliability release | Consistent IDs/serials, stream recovery, provider states, bounded retry policy, installation diagnostics | Valid partial output survives; every export selection matches the displayed snapshot; provider failure never means complete coverage. |
| Inventory foundation | SQLite observations, transactional cursor/job state, resume, schema-versioned exports | Forced interruption/restart is idempotent; original evidence and configuration remain inspectable. |
| Discovery depth | DNS validation/cache/resolver health, optional dnsx, bounded iterative frontier, better AlterX allocation | Controlled DNS fixtures pass; each generator/source has measurable yield and a documented stop reason. |
| Attack-surface intelligence | Unified httpx/tlsx evidence, diff/history, selected-host cards, optional owner DNS inventories | Users can explain every change and its provenance without re-running the entire reconnaissance job. |
| Continuous monitoring | Persistent schedules/watch mode and opt-in notifications, complementary sources, selected crawl profiles | Alerts are meaningful, deduplicated, recoverable and constrained by user budgets. |

## Quality and product success measures

Use an owned authoritative-DNS testbed with known labels and controlled services. Include nested and rotating wildcards, IPv6-only hosts, NODATA, NXDOMAIN, a valid CNAME with a failing target, delegated children, transient failures, UDP truncation/TCP fallback, TLS problems and HTTP error responses. Some records should be deliberately absent from CT/public archives.

Measure classification precision, recall against the controlled ground truth, wildcard false positives/false exclusions, time to first validated asset, validated names per query, provider incremental yield, requests/credits, memory, interruption recovery and repeatability. Compare engines with equivalent credentials, scope, time/query budgets, wordlists and resolver policies. Public-source union is not ground truth for all real-world domains.

Test Linux and Windows launchers, clean installs, current supported Python versions, adapter schemas/flags and output limits. Record dependency/tool versions, resolver set, wordlist hash and scope configuration in the run manifest. Maintain pinned/locked release inputs, checksums or signatures where available, dependency inventories and third-party notices.

Product priorities should follow user time saved and trustworthy evidence: installation success, time to a useful asset, source-failure visibility, reproducible findings and useful changes between runs. Avoid unmeasured speed claims, inflated hostname counts, uncalibrated AI risk scores or an assurance that every subdomain has been found.

## Recommended first implementation scope

Build one coherent upgrade: **SQLite observations + consistent serial/asset identity + resume/partial-output recovery + provider coverage dashboard + better DNS evidence**. Then add structured HTTP/TLS and diffs. This foundation gives additional discovery engines and providers a reliable place to contribute, and creates a useful distinction for ATLAS beyond its existing colorful wrapper workflow.
