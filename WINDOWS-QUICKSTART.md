# Windows PowerShell quick start

`atlas: The term 'atlas' is not recognized` means PowerShell cannot find a
command named atlas. Linux Bash launchers do not run directly in PowerShell.
Use the supplied Windows launcher; no WSL or Bash is needed for the Python core.

1. Extract atlas-recon.zip fully. Do not run files inside the ZIP preview.
2. Open PowerShell inside the extracted atlas-recon folder (the folder containing
   atlas.py and atlas.cmd).
3. Install the Python dependencies into a local virtual environment:

```powershell
.\install-windows.cmd
```

Python 3.10 or newer must be installed. The installer uses py -3 if available,
otherwise python. It creates .venv-windows in the toolkit folder and does not
modify your system PATH or PowerShell execution policy.

4. Open the automatic colorful menu:

```powershell
.\atlas.cmd
```

5. Run commands:

```powershell
.\atlas.cmd doctor
.\atlas.cmd scan -d google.com
.\atlas.cmd scan --help
```

The `.\` prefix tells PowerShell to run a program in the current folder.

To use the shorter `atlas` command in the current PowerShell session:

```powershell
$env:Path = "$($PWD.Path);$env:Path"
atlas
atlas scan -d google.com
```

Run that PATH command while inside the atlas-recon folder. It lasts only for the
current PowerShell session. Repeat it in a new terminal; no restart is necessary.

## Discovery, checks and saving

```powershell
# Discover names from public passive sources
.\atlas.cmd scan -d example.com

# Discover and check DNS/HTTP on a target you are authorized to assess
.\atlas.cmd scan -d example.com --check-live --authorized

# Display the full numbered list; use the exact directory printed by the scan
.\atlas.cmd report "results\ACTUAL_RUN_FOLDER"

# Check an existing inventory
.\atlas.cmd check "results\ACTUAL_RUN_FOLDER" --authorized

# Save all domain names, or names with status
.\atlas.cmd export "results\ACTUAL_RUN_FOLDER" -o domains.txt
.\atlas.cmd export "results\ACTUAL_CHECKED_FOLDER" -o status.csv --format csv
```

Replace ACTUAL_RUN_FOLDER with a real saved folder; it is not a literal command
argument. `Get-ChildItem .\results -Directory` lists the saved runs.

Missing optional tools in doctor do not stop built-in passive sources or built-in
availability checks. For Subfinder, Findomain, AlterX, PureDNS/massdns and
ProjectDiscovery httpx, install compatible official binaries and add their folder
to PATH separately. Provider errors or skipped tools mean reduced coverage.
No tool guarantees every subdomain. UP means a web server answered, including
HTTP errors; NO RESPONSE is not proof of downtime.

## Common errors

| Error | Resolution |
|---|---|
| atlas is not recognized | Use .\atlas.cmd, or add the toolkit folder to session PATH. |
| .\atlas.cmd is not recognized | You are in the wrong folder or using an older ZIP; extract the updated package. |
| Python is not found | Install Python 3.10+ and open a new terminal. |
| No module named dns / missing DNS dependency | Run .\install-windows.cmd. |
| summary.json not found | Use an actual completed run folder from the scan output. |
| HTTP 429, 502 or source timeout | Provider failure; check saved stage outcomes. This is not a startup error. |

On Linux, use `bash install.sh` and `atlas`; on Windows, use the commands above.
