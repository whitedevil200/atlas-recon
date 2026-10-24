# Optional engines, passive sources and owner inventory

ATLAS keeps its Bash/Python CLI and adds optional adapters around specialist tools. The normal installer installs seven pinned free engines. Additional adapters remain manual; no paid API is required. Start with:

```bash
atlas engines
atlas engines --check
atlas engine --help
```

`engines` lists repositories, licenses, input modes, configuration requirements and manual installation links. `--check` inspects PATH and runs bounded version diagnostics. A detected version means the executable answered a version request; it does **not** mean every feature or target was tested successfully. An unrecognized version is reported as unknown rather than assumed compatible.

The automated integration suite validates command construction, mocked provider schemas, scope filtering, errors and bounded artifacts. It does not claim all 17 upstream binaries are installed or live-tested. Upstream flags and provider schemas can change; install a reviewed release and check its help before production use. The upstream licenses apply to those separate tools; ATLAS does not relicense their code.

## Select saved assets by serial number

Replace `RUN` in these examples with the saved results folder printed by your scan. On Windows, use `atlas.cmd` or the full launcher path instead of `atlas` when the command is not on PATH.

```bash
atlas report RUN
atlas engine httpx RUN --serial 1-3 --authorized --rate 10 --timeout 60 --limit 100
atlas evidence RUN --serial 1-3
```

Serials can be a single number, comma-separated numbers or ranges: `--serial 2,5,8-12`. They refer to the current displayed inventory order. `--find api` filters the saved list before selection; inspect the resulting list when combining filters and serials.

`--authorized` is required for an explicit engine action. Private owner inventories additionally require `--allow-private` before any external engine action. An owner import itself never probes the imported names.

Important distinction: **Subfinder, Assetfinder, Findomain and Chaos query the run's root domain.** Their serial selection does not turn their domain-wide API enumeration into a single-host probe. DNS, HTTP, TLS, generation and crawling adapters use the selected, scope-filtered hostname input. BBOT uses exact selected-host scope and passive modules.

## Adapter matrix

| Engine and upstream | Mode and actual adapter behavior | Additional requirements / limits |
| --- | --- | --- |
| [Subfinder](https://github.com/projectdiscovery/subfinder) · MIT | Root-domain passive discovery; explicit keyless `-s` allowlist plus `-silent -oJ -cs -rl RATE -duc`; actual provider names retained. | Provider keys/configuration are managed by Subfinder. ATLAS uses only `crtsh,waybackarchive,rapiddns,digitorus,shodanct`; no `-all` or paid/keyed providers. |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) · MIT | Root-domain passive discovery; `--subs-only ROOT`. | No adapter-level requests/second flag; upstream API behavior applies. |
| [Findomain](https://github.com/Findomain/Findomain) · GPL-3.0 | Root-domain passive discovery; `-t ROOT -q`. | Account/paid sources are explicitly excluded. Free endpoint quotas still apply; registry presence does not enable beta-only features. |
| [DNSx](https://github.com/projectdiscovery/dnsx) · MIT | Resolve selected input; `-l INPUT -silent -json -rl RATE -duc`. | DNS observation, not HTTP availability. This adapter uses upstream resolver defaults; supplied resolver paths belong to the adapters listed below. |
| [PureDNS](https://github.com/d3mondev/puredns) · GPL-3.0 | Resolve selected input, validate answers and filter wildcards; `resolve INPUT -q -r RESOLVERS --resolvers-trusted TRUSTED --rate-limit RATE --rate-limit-trusted RATE`. | Requires installed MassDNS plus both resolver files. Wildcard detection/validation can issue additional DNS queries. |
| [MassDNS](https://github.com/blechschmidt/massdns) · GPL-3.0 | Resolve selected input to A records; JSON output, one concurrent lookup and one attempt: `-r RESOLVERS -t A -o J -s 1 -c 1 -q INPUT`. | Requires resolver file. Concurrency one is not an exact requests/second guarantee. It does not perform PureDNS-style wildcard validation. |
| [ShuffleDNS](https://github.com/projectdiscovery/shuffledns) · GPL-3.0 | Selected-input resolve mode with wildcard handling; `-mode resolve -r RESOLVERS -tr TRUSTED -t 1 -wt 1 -retries 1 -silent -j -duc`. | Requires installed MassDNS and both resolver files. Concurrency controls do not guarantee exact requests/second. |
| [AlterX](https://github.com/projectdiscovery/alterx) · MIT | Generate scoped candidate names from selected seeds; `-l INPUT -silent -limit LIMIT -duc`. | Candidate generation only; output is not evidence that DNS exists or a website is up. |
| [Gotator](https://github.com/Josue87/gotator) · GPL-3.0 | Generate candidates with a supplied reviewed dictionary; `-sub INPUT -perm FILE -depth 1 -mindup -silent -t 1`. | Requires `--permutations FILE`. Runtime/output limits bound expansion; generated names still need DNS validation. |
| [HTTPx](https://github.com/projectdiscovery/httpx) · MIT | Selected-host HTTP/TLS enrichment; JSON, rate control, title/status, technology, IP/CNAME, CDN/ASN, server, content type/length, Location and TLS metadata. | No screenshot, headless browser, TLS-domain follow-up or CSP-domain follow-up flags are enabled. A 403/404 response still demonstrates an HTTP response. |
| [TLSx](https://github.com/projectdiscovery/tlsx) · MIT | Selected-host TLS enrichment on default port 443; JSON, SAN/CN/organization, TLS version/cipher and SHA-256 fingerprint. One worker, request delay and retries disabled. | Certificate validity dates already appear in JSON. `-not-before` and `-not-after` are not invented CLI flags. SANs are evidence only and are not automatically probed. |
| [BBOT](https://github.com/blacklanternsecurity/bbot) · AGPL-3.0 | Curated **BBOT 3.x** executable profile: selected-host targets, `--strict-scope -p subdomain-enum -rf passive --no-deps --json --yes --no-color --event-types DNS_NAME`; `dnsresolve=false`. Also accepts existing JSONL import. | Actual version must identify 3.x before execution. Dependencies are not installed. This is not BBOT's full active reconnaissance preset. Passive modules may still require configured API keys. |
| [OWASP Amass](https://github.com/owasp-amass/amass) · Apache-2.0; subcomponents vary | **Existing JSONL import mode**, not live Amass execution. Normalizes exported `name`, `host` or compatible hostname records. | Requires `--import-file FILE`. No guessed Amass v5 command or claim that every raw Asset Database schema is accepted. |
| [Chaos Client](https://github.com/projectdiscovery/chaos-client) · MIT | Root-domain passive lookup; `chaos -d ROOT -silent`. `chaos-client` is also accepted as the adapter name. | Disabled in the free-only edition, including when credentials exist. |
| [Notify](https://github.com/projectdiscovery/notify) · MIT | Explicit opt-in delivery adapter for scoped change notifications. Bounded bulk/file input; provider configuration passed by path, never printed. | Use the `watch --notify --notify-config FILE` workflow below. The generic engine CLI intentionally does not offer arbitrary notification arguments. |
| [Katana](https://github.com/projectdiscovery/katana) · MIT | Selected-host crawling; JSONL, depth one, FQDN scope, one worker/input and explicit rate. | No headless mode, automatic form fill, model download or out-of-scope display is enabled. Crawling is an explicit action; it is not part of a passive source lookup. |
| [BadDNS](https://github.com/blacklanternsecurity/baddns) · AGPL-3.0 | Exactly one selected hostname; `-s -m CNAME HOST`. | No automatic resource claiming or takeover exploitation. Output is an investigation lead, not proof of exploitability. The actual LICENSE is AGPL-3.0; a README badge may differ. |

## Engine examples

```bash
# DNS validation and wildcard filtering with reviewed resolver files
atlas engine puredns RUN --serial 1-3 --authorized --resolvers resolvers.txt --trusted-resolvers trusted.txt
atlas engine shuffledns RUN --serial 1-3 --authorized --resolvers resolvers.txt --trusted-resolvers trusted.txt
atlas engine massdns RUN --serial 1-3 --authorized --resolvers resolvers.txt
atlas engine dnsx RUN --serial 1-3 --authorized --rate 10

# Generate candidate names, then validate them separately
atlas engine alterx RUN --serial 1-3 --authorized --limit 100
atlas engine gotator RUN --serial 1-3 --authorized --permutations permutations.txt --limit 100

# Enrich selected hosts and retain HTTP/TLS evidence
atlas engine httpx RUN --serial 1-3 --authorized --rate 10
atlas engine tlsx RUN --serial 1-3 --authorized --rate 5
atlas engine katana RUN --serial 1-3 --authorized --rate 5
atlas engine baddns RUN --serial 2 --authorized

# Optional passive BBOT 3.x profile, with no dependency installation
atlas engine bbot RUN --serial 1-3 --authorized --timeout 60

# Import compatible existing engine exports; no engine is launched
atlas engine amass RUN --authorized --import-file amass-export.jsonl
atlas engine bbot RUN --authorized --import-file bbot-export.jsonl

# Root-wide passive engines: selection does not restrict their root-domain query
atlas engine subfinder RUN --authorized --rate 10
atlas engine assetfinder RUN --authorized
atlas engine findomain RUN --authorized
 # Chaos is disabled in the free-only edition
```

The accepted configuration file paths are explicit; arbitrary passthrough shell or engine flags are rejected. Resolver, trusted resolver, permutation and provider configuration files must exist and be at most 8 MiB. No resolver list is silently downloaded.

Compatible existing JSONL examples:

```jsonl
{"name":"api.example.com"}
{"host":"mail.example.com","sources":["example-provider"]}
{"type":"DNS_NAME","data":"dev.example.com"}
```

Amass/BBOT import records outside the explicit root are excluded. A successful import means those records were read; it does not imply fresh network validation.

## Runtime, selection and artifact budgets

The engine API accepts timeout greater than zero and at most **600 seconds**, rate **1–100**, and host/result limit **1–10,000**. CLI timeout/rate values are integers. Defaults for an explicit engine action are 60 seconds, rate 10 and limit 1,000. These bounds do not guarantee how many internal queries an upstream engine performs per hostname. Engines without native requests/second controls use conservative concurrency or upstream defaults, as declared above.

Executable stdout/stderr have an 8 MiB output budget with periodic checks; output can briefly exceed that threshold between checks. On timeout/output-limit detection, the process tree is stopped. Partial observations may still be retained, but the state remains `timeout` or `output_limit`. The version check for BBOT has its own bounded diagnostic step.

Each explicit engine action writes under a new folder beneath `RUN/engines/`. Typical artifacts are:

| File | Meaning |
| --- | --- |
| `result.json` | Action state, scoped host list, observations and limitations. |
| `ENGINE-observations.jsonl` | Normalized observations with collection timestamps and source providers. |
| `ENGINE-records.jsonl` | Known-schema HTTP/DNS/TLS record evidence, with normalized primary hostname. The API returns its path as `raw_artifact`. |

The record artifact is a validated schema projection, **not** an unfiltered dump of arbitrary upstream stdout. It preserves HTTP titles, server/technology/CDN/ASN details and TLS identity/validity/fingerprints. Bodies, headers, private keys and unknown fields are excluded; strings, collections and depth are bounded and terminal control characters are removed. Certificate SANs, CNAME destinations and redirect locations can mention other domains as relationship evidence; they do not become automatic probe targets.

Useful states include `complete`, `imported`, `not_installed`, `configuration_required`, `auth_required`, `consent_required`, `unsupported_version`, `empty_input`, `failed`, `timeout`, `output_limit` and `schema_error`. `partial` means useful records were collected with an explicit coverage limit. Inspect the state and limitations rather than interpreting an empty list as a complete negative result. Bounded passive source collection currently returns a nonzero CLI status for `partial`, while retaining the collected inventory.

## Free installation and sources

```bash
atlas setup-engines
atlas setup-engines --list
atlas setup-engines --only subfinder,dnsx
atlas scan -d example.com --mode active --authorized --permute --http --free-engines
atlas source commoncrawl -d example.com --limit 100 --timeout 10 -o results
```

The default installer downloads seven pinned free release executables: Subfinder,
Findomain, DNSx, AlterX, HTTPx, TLSx and Katana. SHA-256/size checks precede
extraction. Engine and license/source provenance are retained in adjacent
`.atlas.json` metadata. Linux x86_64/arm64 and Windows x86_64 are supported.
ATLAS prepends its own managed engine directory to the process PATH only.
No compiler, paid subscription or API key is needed for this bundle.

Subfinder queries only sources declaring `keyRequirement=none` in v2.17.0:
`crtsh,waybackarchive,rapiddns,digitorus,shodanct`. Findomain excludes certspotter,
facebook, spyse, virustotalapikey, urlscan, securitytrails, c99 and both bufferover
variants. Native Cert Spotter requests remain anonymous public API requests.
Censys, SecurityTrails and Chaos are disabled even when credentials are present.
No account-credit consent option can re-enable them.

`--free-engines` enables DNSx evidence after built-in active validation, adding
HTTPx/TLSx with `--http`; AlterX already runs with `--permute`. Menu 3 selects
these options. Each stage retains `engines/NAME/result.json` and normalized
observations in asset evidence; successful stages are checkpointed. Offline
scans skip this pipeline. Katana crawling is an explicit selected-host action.
External tools have individual rate/time/output caps; their internal DNS packets
are not included in the built-in DNS query counter.

Only Common Crawl remains available through `atlas source`. It fetches the
latest official crawl index and one bounded response, not all historical indexes.
Free endpoints can throttle/fail; `partial` is retained as incomplete coverage.
Other adapters in the matrix are optional/manual, not part of this seven-engine
bundle. `atlas setup-engines` reports failures and exits nonzero; re-run it to
retry. `ATLAS_SKIP_ENGINES=1` enables core-only installation for CI/offline labs.

## Authorized owner DNS exports

Owner inventories can reveal records absent from public sources, including private DNS. Export a zone you administer through the provider's official read APIs/CLI, then import it:

```bash
atlas owner-import aws route53.json -d example.com --authorized --view private -o results
atlas owner-import cloudflare cloudflare.json -d example.com --authorized --view public -o results
atlas owner-import gcp gcp.json -d example.com --authorized --view private -o results
```

The import performs no cloud writes, no automatic credential discovery and no DNS/HTTP probes. Every owner observation is marked `probe_allowed=false`; the chosen `public`/`private` view is retained. Wildcard record names are recorded in evidence as `record_name` and `wildcard=true`; their normalized root entry must not be mistaken for evidence that the apex itself has the wildcard's record. Unsupported/private routing views are not inferred from public DNS.

Accepted JSON formats:

**AWS Route53** — the `ResourceRecordSets` array from [ListResourceRecordSets](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html), or that array alone:

```json
{"ResourceRecordSets":[{"Name":"api.example.com.","Type":"A","TTL":300,"ResourceRecords":[{"Value":"192.0.2.10"}]}]}
```

An owner can obtain this read-only export with `aws route53 list-resource-record-sets --hosted-zone-id YOUR_ZONE_ID --output json`. Complete upstream pagination before importing a full-zone export.

**Cloudflare** — the `result` array from the [List DNS Records API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/), or that array alone:

```json
{"result":[{"name":"api.example.com","type":"A","content":"192.0.2.10","proxied":false}]}
```

Export from an explicitly selected zone using a DNS read token. Combine all requested pages yourself; an API page is not a complete zone inventory.

**Google Cloud DNS** — an `rrsets` array or the raw record-set list produced by [`gcloud dns record-sets list`](https://cloud.google.com/sdk/gcloud/reference/dns/record-sets/list):

```json
{"rrsets":[{"name":"api.example.com.","type":"A","ttl":300,"rrdatas":["192.0.2.10"]}]}
```

For example: `gcloud dns record-sets list --zone=YOUR_ZONE --format=json`. Keep private/public view explicit when selecting and exporting zones.

Only scoped record names and known evidence fields are imported; this is an asset-name inventory, not a zone restore/backup feature. Out-of-root records are excluded. `complete` means the supplied batch was imported within its limit, not that every provider page or DNS view was obtained. The CLI file-size limit is 16 MiB and the record limit is at most 10,000; split larger exports deliberately.

## Opt-in change delivery

```bash
atlas watch -d example.com --sources certspotter,subfinder --cycles 2 --interval 300 --incremental --notify --notify-config notify-provider.yaml
```

This is explicit authorization to send change notifications through the configured Notify destinations. Configure those destinations in the local provider file first. Keep that file outside version control. ATLAS does not enable delivery merely because Notify is installed. Notification configuration contents and credentials are not printed in engine arguments or reports.

## Validation references

- [HTTPx flags and output](https://github.com/projectdiscovery/httpx#usage)
- [TLSx JSON schema and certificate validity dates](https://github.com/projectdiscovery/tlsx#json-output)
- [BBOT 3.x CLI and scope behavior](https://github.com/blacklanternsecurity/bbot/blob/stable/bbot/scanner/preset/args.py)
- [Integration contract tests](../tests/test_integrations.py)

Use `atlas health RUN` to see the run's coverage and `atlas evidence RUN --serial 1` to inspect why an asset was discovered. Public certificate/archive evidence, generated candidates, current DNS responses and HTTP availability answer different questions and remain distinct.
