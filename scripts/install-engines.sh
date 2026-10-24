#!/usr/bin/env bash
# Instruction-only helper: no remote code, downloads, or package manager calls.
set -euo pipefail

if [[ "${1:-}" == --verify ]]; then
    if [[ $# -ne 3 || ! "$3" =~ ^[[:xdigit:]]{64}$ ]]; then
        printf 'Usage: bash scripts/install-engines.sh --verify FILE EXPECTED_SHA256\n' >&2
        exit 2
    fi
    if [[ ! -f "$2" ]]; then
        printf 'File does not exist: %s\n' "$2" >&2
        exit 2
    fi
    actual=$(sha256sum -- "$2")
    actual=${actual%% *}
    if [[ "${actual,,}" != "${3,,}" ]]; then
        printf 'SHA-256 mismatch; do not install this file.\n' >&2
        exit 1
    fi
    printf 'SHA-256 verified: %s\n' "$2"
    exit 0
fi

if [[ $# -gt 0 && "${1:-}" != --list && "${1:-}" != --help ]]; then
    printf 'Unknown argument. Use --list, --help, or --verify FILE EXPECTED_SHA256.\n' >&2
    exit 2
fi

cat <<'GUIDE'
ATLAS optional-engine installation guide (instruction-only)

The Python package works without these engines. This helper does not install
anything or access the network. The following reviewed release references were
checked on 2026-10-24; they are explicit pins, not auto-updating latest versions.

httpx v1.12.0  https://github.com/projectdiscovery/httpx/releases/tag/v1.12.0
tlsx v1.4.0    https://github.com/projectdiscovery/tlsx/releases/tag/v1.4.0
Amass v5.1.1   https://github.com/owasp-amass/amass/releases/tag/v5.1.1
BBOT v3.0.2    https://github.com/blacklanternsecurity/bbot/releases/tag/v3.0.2
Notify v1.0.7  https://github.com/projectdiscovery/notify/releases/tag/v1.0.7

1. Open the official release page, review release notes, LICENSE/NOTICE and
   supported platform/runtime. Select the exact architecture and pinned version.
2. Obtain the publisher's checksums/signature and verify their provenance.
   A hash you computed from the same untrusted download is not authenticity proof.
   Verification helper (requires sha256sum):
     bash scripts/install-engines.sh --verify ./ARCHIVE EXPECTED_64_HEX_SHA256
3. Extract reviewed binaries into a dedicated, user-owned tools directory and
   add that directory to PATH. Never overwrite an unrelated Python httpx command.
   For Go builds, pin the module version explicitly instead of @latest:
     go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
     go install github.com/projectdiscovery/tlsx/cmd/tlsx@v1.4.0
   Go must meet each tagged module's go.mod requirement; downloaded build
   dependencies still require review. Preserve go.sum/build metadata.
4. BBOT is a large optional AGPL engine. Read its platform and dependency
   instructions before using pipx or a container. Do not mix its dependency
   environment into ATLAS's environment or assume all modules are passive.
5. Run the engine's version/help command and ATLAS doctor. Test adapters with
   offline fixtures or your controlled lab before an authorized engagement.
6. Record version, binary SHA-256, operating system and adapter schema. Updates
   are an explicit maintenance action followed by contract tests, not a scan step.

For discovery engines already supported by ATLAS, review each upstream's release
page linked in THIRD_PARTY.md and use the same pinned-version procedure. No
arbitrary upstream repository is automatically downloaded or executed by ATLAS.
GUIDE
