# Validation record

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
