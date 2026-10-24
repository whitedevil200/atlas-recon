# Reproducible reconnaissance benchmark and lab results

The measured local DNS fixture below and the broader test protocol are separate.
The fixture checks declared classification cases, not internet discovery recall,
throughput superiority or all-tool comparisons. No tool can establish that it
found every subdomain of an arbitrary organization.

## Executable loopback lab

```bash
python scripts/benchmark-lab.py --output lab-benchmark.json
```

Choose a new filename on every run: existing output files are preserved. A failed
classification/assertion returns exit code 1; successful cases return 0. The
script binds an unprivileged ephemeral UDP port on **127.0.0.1** and exchanges real
DNS wire packets with a local authoritative fixture. A transport-routing shim
changes only the port passed to dnspython's real UDP query; production DNSClient
classification, parsing, caching and wildcard handling remain in use. Any
non-loopback resolver passed to the shim is rejected. No public resolver/target
is queried, and documentation IPs in DNS responses are never probed.

Fixture cases: IPv4 A, IPv6-only AAAA, NOERROR/NODATA, NXDOMAIN, dangling CNAME
with negative final target, SERVFAIL, REFUSED, a nested rotating wildcard, an
absent wildcard, and a repeated positive lookup served from cache. The two
wildcard scenarios use three randomized sibling names each; expected outcomes
and rotating answer sets are deterministic, while the temporary labels vary.

The JSON result records UTC time, Python/platform/dnspython, SHA-256 of the lab
script and `dns_evidence.py`, per-case expected/actual observations, packet/query
counts, elapsed time and process peak RSS when available. RSS is null on the
tested Windows interpreter because the standard `resource` module is unavailable;
on supported systems it is the process-lifetime peak, not a benchmark-only delta.

### Recorded local execution — 2026-10-24

Three sequential executions on Windows 11 build 26200, Python 3.14.3,
dnspython 2.8.0:

| Measurement | Observed result |
| --- | --- |
| Case assertions | 10/10 in each execution |
| DNS classification accuracy | 7/7 declared DNS cases in each execution |
| Resolved-fixture precision | 2 true resolved cases / 2 cases classified resolved |
| Loopback packets / client query count | 39 / 39 in each execution |
| Positive cache | Repeating A/AAAA/CNAME lookup sent no additional packets |
| Nested rotating wildcard | Both fixture A values retained; classified wildcard suspect |
| Elapsed time | 0.355359–0.468061 seconds; median 0.367636 seconds, n=3 |
| Peak RSS | Unavailable on this Windows interpreter |
| Server errors / exit status | No server errors; exit 0 for all three |

Timing includes local Python/fixture scheduling and is context, **not a DNS
throughput claim**. These small known-answer measurements must not be presented
as 100% accuracy against arbitrary internet DNS or 100% subdomain recall.
Raw measured JSON files were retained outside the repository in the task's work
folder as `atlas-v2-lab-benchmark.json`, `atlas-v2-lab-benchmark-2.json` and
`atlas-v2-lab-benchmark-3.json`; rerun the command to produce your own portable
evidence. This lab does not exercise HTTP/TLS, external provider coverage, live
third-party engines, takeover claims or large-inventory scaling.

## Controlled corpus

Use an isolated local authoritative DNS test zone and local HTTP/TLS services,
or an explicitly authorized dedicated benchmark domain. Keep the exact zone and
service fixtures under version control. Include A/AAAA, multi-hop CNAME, wildcard
and rotating wildcard answers, wildcard exceptions, delegation, NXDOMAIN,
NOERROR/NODATA, SERVFAIL, timeouts, IDNA names, split views, dangling test CNAMEs,
expired/self-signed/mismatched certificates, HTTP 200/301/401/403/404/500,
out-of-scope redirects, and blocked ports. Never manufacture a takeover proof by
registering or claiming a third-party resource.

Keep seeded names hidden from discovery wordlists when measuring discovery.
Publish the declared ground truth and generator seed with aggregate results;
do not publish private engagement data. Compare passive provider tests separately
because a local zone is not representative of internet indexing coverage.

## Run manifest

Record ATLAS commit/version, OS/architecture, Python and dependency versions,
binary versions and SHA-256, tool flags, zone/corpus/wordlist SHA-256, resolver and
DNS view, UTC time, network conditions, credentials' provider/tier without secret
values, concurrency, request/credit/time budgets, retry policy and cache state.
Pin engines and use a dependency lock with hashes for the selected platform.
Exclude warm-cache results or report cold and warm runs separately.

## Metrics

| Metric | Definition |
| --- | --- |
| Validated unique yield | Distinct in-scope hostnames supported by the stated validation policy |
| Precision | True fixture hostnames / reported fixture hostnames; publish wildcard policy |
| Recall on fixture | Found seeded fixture hostnames / all seeded fixture hostnames; not internet completeness |
| Provider contribution | Unique and overlapping names per source plus source failures and pagination state |
| Resource use | Wall time, peak resident memory, database/output bytes, requests and retries |
| Cost | API credits and known account charges, with provider tier and budget |
| Change accuracy | Correctly observed added/changed/not-observed assets against controlled mutations |
| Recovery | Repeated/omitted jobs and evidence after controlled interruption and restart |
| Scope correctness | Requests made to excluded roots, addresses or redirect destinations; expected zero |

Run each deterministic scenario at least three times, retain raw machine-readable
results, and report median plus range with sample count. Use identical scope,
provider tiers, resolvers, time windows and budgets when comparing engines.
If configurations cannot be equivalent, disclose the difference instead of
ranking by raw output line count. CT and archive records may be historical;
separate discovered, DNS-resolved, and HTTP-responsive names.

## Failure and recovery drills

Inject malformed JSONL, oversized records, invalid encodings, tool timeouts,
truncated output, credential rejection, 429 with Retry-After, provider outages,
SQLite contention and process interruption during each stage. Verify atomic
state files, checkpoint integrity, bounded queues, transaction rollback,
idempotent imports, preserved raw evidence and explicit partial-run labeling.
Restart a run without losing completed observations or silently duplicating
records. A comparison with lower provider coverage must disclose that regression.

## Packaging and release checks

Build a wheel and source distribution, inspect their manifests, and install the
wheel into a clean virtual environment outside the source directory. Verify
`atlas --version`, `atlas --help`, an offline imported run, bundled starter-list
access through importlib.resources, installed man-page presence, and history/diff.
Run supported Linux and Windows CI and inspect artifacts for credentials, scan
results, local paths and virtual environments before publishing.
