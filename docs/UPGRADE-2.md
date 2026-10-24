> Version 2.1 supersedes the 2.0 provider/installation entries below: seven free
> engines install automatically; Censys, SecurityTrails and Chaos are disabled.
> See README and ENGINES.md for current commands. Other 2.0 features remain.

# ATLAS 2.0: implemented features and upgrade guide

Version 2.0 extends the existing Bash/Python terminal workflow. It keeps the full
numbered results, SR-NO lookups, availability checks and exports. It adds durable
observations, explicit specialist adapters and bounded follow-up workflows.
This matrix records implementation and limits; it is not a claim of exhaustive
discovery, vulnerability confirmation or superiority over every other tool.

## Upgrade an existing checkout

```bash
git pull
bash install.sh
atlas --version
atlas doctor
atlas engines --check
```

Windows PowerShell:

```powershell
git pull
.\install-windows.cmd
.\atlas.cmd --version
.\atlas.cmd
```

Python package users can run `python -m pip install -e .` in their existing
isolated environment. To use the hashed runtime graph, install
`requirements-runtime.lock` with `--require-hashes`, then install the checkout
with `--no-deps -e .`. The lock excludes build/development packages and optional
Rich; `python -m pip install '.[terminal]'` installs the optional terminal extra.
For a separately managed environment use `pipx install .`, or upgrade an existing
pipx installation from the same checkout. No PyPI release is assumed.

Preserve existing result directories and databases. Version 1.x inventories can
still be viewed/exported where their documented fields exist; import
`subdomains.txt` or `assets.jsonl` into a new offline run for 2.0 IDs/history.
Importing names does not reconstruct missing original evidence or provider
coverage. Only 2.0 checkpoints support 2.0 discovery resume. Changed checkpoint
inputs require a new run, not manual hash bypassing.

## Research-to-implementation matrix

| # | Recommendation | Implemented workflow | Practical limits |
| --- | --- | --- | --- |
| 1 | Complementary passive discovery | Existing crt.sh, Cert Spotter, HackerTarget, Wayback and optional passive executables; native Common Crawl/SecurityTrails/Censys actions and root-wide Chaos adapter. | Quotas, credentials and indexing gaps remain. Native complementary sources use bounded pages and disclose partial coverage; no exhaustive provider promise. |
| 2 | DNS evidence beyond a boolean | Built-in `DNSClient` retains state, rcode, values, aliases, resolver/time, DNSSEC resolver assertion, negative responses and errors. | A resolver's AD flag is not local DNSSEC validation. Resolution does not prove an HTTP service responds. |
| 3 | Cache, wildcard and resolver reliability | TTL-aware positive/negative cache, randomized sibling evidence, trusted-resolver comparisons, `resolver-check`, conservative suspect/indeterminate classifications. | Resolver agreement is not truth; rotating/geo DNS and complex wildcard configurations need review. Caches are bounded and in-process, not a distributed DNS cache. |
| 4 | Bounded recursive candidate generation | `--recursive-depth 0..3`, global candidate/query/time budgets, quick/balanced/deep profiles, optional AlterX/Gotator. | Generated names remain guesses until validated. Profiles alter depth/page budgets; larger raw lists are not automatically better coverage. |
| 5 | Specialist repository interoperability | 17 adapter entries: **16 executable profiles plus Amass import-only**. `engines --check`, explicit selected input, declared prerequisites, time/output/record bounds and version diagnostics. | Binaries are separately installed. Fixture/command-contract coverage does not claim every upstream binary is installed or live-tested. Amass v5 execution is not guessed. |
| 6 | Rich HTTP evidence | Optional Go httpx projection retains selected status/title/server/technology/content/IP/CDN/ASN/redirect/TLS fields; built-in availability checker remains available. | No default headless browser, screenshot capture, arbitrary methods or automatic full web assessment. HTTP errors can still demonstrate a response. |
| 7 | TLS identity and expiry evidence | Optional tlsx profile retains identity, SANs, protocol/cipher, fingerprints and validity fields in structured artifacts. | SAN overlap is association, not ownership proof. Certificate findings require context. Global CT firehose replay/streaming is not implemented. |
| 8 | Scoped web/JS/CSP leads | Explicit `crawl` with request/depth/time limits and selected seed hosts; optional constrained Katana adapter. | Body-derived names are candidates. Built-in fetches validate/pin public addresses and recheck scope; third-party engines retain their own network behavior. No automatic form submission/headless mode. |
| 9 | Durable inventory and identity | SQLite/WAL runs, assets and observations, stable root/host/view IDs, idempotent per-run writes, `history` and schema-preserved evidence. | Single-machine local inventory; no multi-tenant service, distributed scheduler or automatic Neo4j deployment. SR NO remains a display index. |
| 10 | Explainable provenance | Discovery source/time/parent metadata, provider families, stable IDs, persisted discovery edges, saved engine/source observations and unified `evidence` cards. Generated and crawled candidates retain their discovered parent; passive collection defaults to the scoped root. | This is not a complete inferred organization-ownership graph or arbitrary multi-hop relationship inference. |
| 11 | Provider health and marginal yield | `health` shows source states, counts/yield, available logical-request instrumentation, DNS/resolver metrics, budgets and explicit incomplete stages. | Logical operations are not exact wire-level HTTP attempts or audited billing counters. Missing source results do not establish negative coverage. |
| 12 | Checkpoints and recovery | Atomic JSON state and input/configuration hashes; completed provider/DNS progress skipped on resume; availability `PENDING` rows resume without replaying completed rows. | Original limits remain. An interrupted external tool may restart its current action. No claim of distributed exactly-once delivery, hostile checkpoint authentication or reconstruction of 1.x progress. |
| 13 | Meaningful change intelligence | `diff OLD NEW`: new, changed, not observed, scope/coverage comparability and regressions; recursive semantic comparison filters collection metadata and TTL countdowns. | Not observed is not deleted/down. Provider tier/index freshness and incompatible settings affect comparisons. Raw evidence remains available for review. |
| 14 | Incremental monitoring and delivery | `watch` persists snapshots/previous run/CT cursor and candidate carry-forward; explicit Notify delivery with deduplication and a persistent bounded outbox, retry backoff and capped attempts. | Default one cycle, no background daemon automatically installed. `--cycles 0` needs a running process. Incremental candidate retention supports additions, not authoritative disappearance detection. Review failed deliveries; `--retry-notifications` explicitly retries them. |
| 15 | Owned DNS views and scope controls | Authorized AWS/Cloudflare/GCP JSON export imports, root/exclusion checks, explicit public/private view, `probe_allowed=false`; private follow-up requires `--allow-private`. | Import-only cloud workflow; no live SDK credential discovery, API pagination or zone writes. Provider export completeness is the owner's responsibility. Public/private scope does not establish legal ownership of every association. |
| 16 | Explainable prioritization | Saved review leads for wildcard overlap, aliases lacking usable addresses and TLS errors; selected BadDNS CNAME investigation profile. | No opaque universal risk score, CVE confirmation, automatic resource claiming or takeover exploitation. Impact/confidence require human context and evidence. |
| 17 | Usable terminal workflow | Default colorful menu with actions 1–21, full lists, SR-NO lookup immediately after discovery, batch evidence/engine selection, optional Rich, export/help/man pages. | Terminal previews are labeled rendered CLI output, not proof of installed GUI/screenshots. Large result sets use terminal scrollback; no graphical application is introduced. |
| 18 | Reproducible packaging and measurement | Python console package/resources, direct pins and hashed runtime lock, third-party credits, instruction-only engine guide, clean installed-wheel smoke script, controlled benchmark protocol. | Upstream binary licenses/dependencies require separate review. Build tools are not locked by the runtime file. No comparative performance or internet-wide completeness numbers are invented; benchmark execution is separate from its protocol. |

## Minimal workflow

```bash
# Start with offline evidence, no provider/target requests
printf 'api.example.com\nwww.example.com\n' > names.txt
atlas scan -d example.com --offline --import names.txt --no-lookup

# Replace RUN with the saved path printed above
atlas report RUN
atlas evidence RUN --serial 1-2
atlas lookup RUN --serial 1 --kind all
atlas health RUN
atlas history api.example.com --database results/atlas.sqlite3
```

The `lookup` command performs network registration/DNS/provider lookups, unlike
the preceding offline import and saved-evidence commands. For full lookup UX,
run discovery interactively, press **l**, select the displayed **SR NO**, then
choose WHOIS/IP/reverse-IP/all. This preserves the established post-discovery
workflow without requiring the run path again.

## Resume, views and notifications

```bash
atlas resume RUN --no-lookup
atlas resume CHECKED_RUN --authorized --no-lookup
atlas owner-import cloudflare zone.json -d example.com --authorized --view private
atlas engine httpx PRIVATE_RUN --serial 1 --authorized --allow-private
atlas watch -d example.com --cycles 2 --interval 300 --incremental
atlas watch -d example.com --cycles 2 --notify --notify-config notify-provider.yaml
```

Private access is explicit; prefer saved evidence inspection before choosing any
network follow-up. Notify configuration determines real external destinations;
keep it out of source control. Watch does not send messages unless `--notify`
is explicit. Its state/outbox is persisted under the chosen output parent;
delivery failure remains visible and retained rather than being called success.

## Validation boundaries

Run the offline unit/integration suite and inspect [VALIDATION.md](../VALIDATION.md)
for recorded results. `python scripts/check-wheel.py` builds/installs a wheel
in temporary directories and runs an offline synthetic import. It downloads
Python build/runtime packages as needed, but performs no target reconnaissance.
See [BENCHMARK.md](BENCHMARK.md) for a reproducible lab protocol and
[ENGINES.md](ENGINES.md) for exact adapter/source/configuration details.
