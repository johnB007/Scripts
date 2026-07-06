# Browser Logs collector for MDE Live Response

A single PowerShell script that runs as SYSTEM inside Microsoft Defender for
Endpoint Live Response, collects Chrome and Edge artifacts from every user
profile on the device, parses the SQLite databases into CSV, optionally
scans free pages and cache files for URLs the user already deleted, and
ships everything back as a single zip you can pull with `getfile`.

## Files in this folder

| File | Purpose |
|------|---------|
| `Collect-BrowserArtifacts.ps1` | Main script. Upload this to the Live Response Library. |
| `sqlite3.exe` (you provide) | Optional but recommended. Enables the `Parsed\` CSV output. Excluded from git via `.gitignore` so it never gets committed. |
| `edge-browser-history-deletion.kql` | Advanced Hunting KQL to detect Edge browser history deletion events in real time across your fleet. Optimized for 999 days of historical data. |
| `README.md` | This file. |
| `README.html` | Rendered HTML copy. |

## One time setup

1. Open the Microsoft Defender portal at `https://security.microsoft.com`.
2. Go to Settings, Endpoints, Rules, Live Response, Library.
3. Upload `Collect-BrowserArtifacts.ps1`.
4. Strongly recommended: grab the official `sqlite3.exe` from `https://sqlite.org/download.html` (the `sqlite-tools-win-x64-*.zip` bundle), extract `sqlite3.exe`, and upload it to the same Library. Without it the script still works, you just do not get the `Parsed\` CSV output or the recoverable URL scan.

When you change the script locally, re upload it through the Library: find the file, click Edit, upload the new copy, confirm overwrite. The `run` command always serves the Library copy.

## Run it from Live Response

Connect to the device and run:

```text
connect <device>
run Collect-BrowserArtifacts.ps1
```

Common variants:

```text
# Kill chrome.exe and msedge.exe first for clean SQLite snapshots
run Collect-BrowserArtifacts.ps1 -parameters "-StopBrowsers"

# Full forensic mode: clean snapshots + raw byte URL recovery from free
# pages, WAL files, journals, and the disk cache
run Collect-BrowserArtifacts.ps1 -parameters "-StopBrowsers -IncludeRecoverable"

# Leave the staging folder, skip the zip
run Collect-BrowserArtifacts.ps1 -parameters "-NoZip"

# Custom output root
run Collect-BrowserArtifacts.ps1 -parameters "-OutputRoot D:\Forensics"
```

The last line of script output is the zip path:

```text
ZIP_PATH=C:\ProgramData\BrowserLogs\DESKTOP-ABC_20260617-142233.zip
```

Pull it back:

```text
getfile "C:\ProgramData\BrowserLogs\DESKTOP-ABC_20260617-142233.zip"
```

The downloaded file lands in your Live Response downloads folder on your workstation.

## Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| `-OutputRoot` | `C:\ProgramData\BrowserLogs` | Where the staging folder and final zip are written. |
| `-StopBrowsers` | off | Kills `chrome.exe` and `msedge.exe` before copying so SQLite snapshots are consistent. |
| `-IncludeRecoverable` | off | Performs a raw byte regex scan over the history db, its WAL and journal, the cookies db, and the disk cache files to surface URLs that no longer exist as live rows. Writes `Parsed\<Browser>\<user>_<profile>_recoverable_urls.csv`. Slower, larger CSVs. |
| `-NoZip` | off | Leaves the staging folder in place and skips zipping. Useful for debugging. |

## What you get inside the zip

![Browser Forensics Collection Structure](https://raw.githubusercontent.com/johnB007/Scripts/main/Live%20Response/Browser%20Logs/browser-forensics-structure.svg)

## What survives "Clear browsing data" and what does not

A common SOC question: the user clicked Settings, Privacy, Clear browsing data, Last hour or All time. Can you still get those URLs?

**What is wiped from the live `History` rows:**

* `urls` and `visits` rows are deleted, so `history.csv` and `visits.csv` will not show them.

**What this script still captures (no extra flag needed):**

* `Top Sites` SQLite. Only wiped when the user picks "All time" plus "Cookies and other site data".
* `Web Data` (autofill, search terms, addresses, payment methods).
* `Shortcuts` (typed prefix completions, often hold the URLs the user tried to hide).
* `Sessions\` folder. Currently open and last closed tab URLs in the binary session blobs.
* `Bookmarks`. Only gone if the user manually removed them.
* `Preferences` and `Secure Preferences` (last_visited_url, profile state).
* `Favicons` SQLite. Icons fetched for visited sites stay after history clear in most configs.
* `Network\Cookies`. Only gone if the user also checked "Cookies and other site data".

**What `-IncludeRecoverable` adds:**

SQLite does not zero deleted rows. They sit in free pages until the database is VACUUM'd, which Chrome does opportunistically and not very often. The `History-wal` file and the journal hold pre delete state. The disk cache `index` and `data_*` files reference every cached URL.

`-IncludeRecoverable` does a raw byte regex scan for `http(s)://...` across:

* `History`, `History-journal`, `History-wal`
* `Cookies`, `Cookies-journal`, `Cookies-wal`
* `cache\Cache_Data\index`, `data_0`, `data_1`, `data_2`, `data_3`

Output goes to `Parsed\<Browser>\<user>_<profile>_recoverable_urls.csv` with two columns: `Source` (which file the URL came from) and `Url`. Deduped per profile.

The scan treats bytes as ISO-8859-1 so every byte maps 1:1 to a char and the regex sees the raw stream including content inside SQLite free pages.

**Why this script exists in the first place:**

MDE does **not** log every URL the user visits. That is the whole reason this collector exists. What MDE Advanced Hunting actually has for browser activity is sparse and event driven:

* `DeviceNetworkEvents` records connection level events (process, RemoteIP, RemotePort, sometimes RemoteUrl) and is generally populated only when something triggers it: Network Protection block, SmartScreen verdict, suspicious destination, indicator match, or an active investigation. Normal browsing to a benign site is usually not in this table.
* `DeviceEvents` with `ActionType == "BrowserLaunchedToOpenUrl"` fires only when a URL is launched **outside** the browser (Office app, mail client, chat, protocol handler). It does not capture URLs the user typed or clicked inside Chrome or Edge.
* Plain user web browsing leaves no MDE telemetry in most cases. The cleanest source of truth for "what did this user actually browse" is the on disk artifacts this script collects.

Advanced Hunting is still useful as a **supplemental** lookup for the small subset of URLs MDE did capture (alerts, blocks, redirects to known bad). Example:

```kql
DeviceNetworkEvents
| where DeviceName == "<HOST>"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe")
| where isnotempty(RemoteUrl)
| where Timestamp > ago(30d)
| project Timestamp, InitiatingProcessAccountName, InitiatingProcessFileName,
          RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

And for externally launched URLs:

```kql
DeviceEvents
| where DeviceName == "<HOST>"
| where ActionType == "BrowserLaunchedToOpenUrl"
| project Timestamp, AccountName, InitiatingProcessFileName, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

Treat the on disk artifacts as the primary record. Treat MDE telemetry as a partial corroborating signal.

## Validation flow

1. Run with no flags first. Confirm the zip lands and `Parsed\Chrome\*_history.csv` contains real URLs.
2. For a "deleted history" test, open a few sites in the test profile, clear browsing data Last hour Browsing history only, then re run with `-StopBrowsers -IncludeRecoverable`. Confirm the cleared URLs appear in `recoverable_urls.csv` but not in `history.csv`.
3. Optional partial cross check: run the Advanced Hunting query in the section above for the same time window. Only URLs that triggered MDE telemetry (Network Protection, SmartScreen, alerts, externally launched) will appear there. Absence in MDE does not mean the user did not visit the site, that is exactly why the local artifacts are the primary evidence.

## KQL-Based Detection: Browser History Deletion Events

While this folder focuses on **post-incident forensics** (what artifacts survive after deletion), you can also hunt for the **deletion event itself** in real time using Advanced Hunting KQL queries. This complements the Live Response approach: KQL catches the behavior as it happens across your fleet; Live Response recovers the evidence after the fact.

### Edge Browser History Deletion Detection

Microsoft Edge stores browsing history in SQLite files under `%AppData%\Microsoft\Edge\User Data\Default\`:
- **`History`** - The main SQLite database with visited URLs
- **`History-journal`** - Write-ahead logging (WAL) file that tracks uncommitted changes before they're committed to the main database

When a user clears browsing history (or uses a script to delete it), MDE's NTFS minifilter driver captures `FileModified` and `FileDeleted` events on these files. The query `edge-browser-history-deletion.kql` hunts for these events optimized across 999 days of data:

**Key detection signals:**

1. **Risky locations:** `.lnk` shortcut files in Startup, Desktop, Quick Access, Recent, or Links folders (covered by `suspicious-lnk-file-activity.kql`)
2. **Unusual processes:** File modifications by processes other than `msedge.exe`, `MicrosoftEdgeUpdate.exe`, or `explorer.exe` may indicate anti-forensic tooling
3. **Timing correlation:** Multiple history file modifications in a short window suggest automated deletion or scripted cleanup
4. **False positive mitigation:** Filter on bulk creation/modification patterns to surface genuine anti-forensic activity over routine browser operation

**When to use this query:**
- Hunting across hundreds or thousands of devices for history deletion behavior
- Finding devices where a user or malware attempted to cover tracks
- Building a timeline of suspicious activity before escalating to Live Response collection
- Correlating with other suspicious events (unexpected admin account creation, lateral movement, data exfiltration)

**Query location:** `edge-browser-history-deletion.kql` in this folder. Validates against SOC-Central and returns 999 days optimized results.

### Why Chrome History Deletion Cannot Be Detected via KQL (Yet)

This is the critical gap. Google Chrome stores the same history structure (SQLite `History`, `History-journal`) in `%AppData%\Google\Chrome\User Data\Default\`, but **MDE does not emit file operation events for Chrome database files in most environments**. Here is why:

**The telemetry blind spot:**

1. **Minifilter driver scope:** MDE's NTFS minifilter operates at the file system level and captures file open, close, read, write, and delete operations. However, it does not capture every single file access on the system for performance reasons. Selective hooking prioritizes:
   - System critical files
   - Known persistence locations (Startup, Scheduled Tasks, Registry, Services)
   - Security-sensitive operations (authentication, process injection, registry modification)
   - User profile folders (selective, not comprehensive)

2. **Chrome database files are not prioritized:** Unlike Edge (which Microsoft directly supports), Chrome's user data folder is treated as generic user application data. When Chrome opens the History database, SQLite locks it with an exclusive handle and uses Memory Mapped IO (MMIO) to avoid repeated reads. The minifilter sees the initial open but may not capture the granular writes to individual WAL pages, and crucially, **many write operations bypass minifilter capture when SQLite uses memory mapped file ranges**.

3. **WAL and journal handling:** Chrome's History-journal is a temporary file that SQLite creates, writes to, and deletes as part of transaction management. The minifilter may see the create and delete, but the writes in between are often below the reporting threshold or are merged into one event, losing the forensic signal that history deletion occurred.

4. **Comparison with Edge:** Microsoft Edge, being a Microsoft product, has explicit logging hooks in the minifilter driver for its profile folder structure. The telemetry is richer and more reliable because the collection was purpose-built.

**Bottom line:** Do NOT rely on KQL-based Chrome history deletion detection. There is no schema-correct query that will reliably surface Chrome history deletion events because the telemetry is unreliable or missing. Treat Chrome history deletion as a forensic-only question: use Live Response with `-IncludeRecoverable` to scan the free pages and WAL files for deleted URLs after the fact.

**Detection alternatives for Chrome (none are good):**

1. **Behavioral pattern matching:** Look for unusual process execution followed shortly by a process spawning chrome.exe with suspicious command line flags (but Chrome is closed during history clear, so the correlation is weak). Not implemented here because of high false positive rate.
2. **Artifact-based:** Scan the `Shortcuts` file, `Web Data`, or `Top Sites` for absence of recently visited sites, infer deletion. Only works if the user did not also clear other data, and misses deletions entirely if the user has a small history to begin with.
3. **Third-party browser monitoring:** Chrome Extensions or EDR agents that hook Chrome's process can log history clear events, but this requires deployment of additional software and is outside MDE's scope.

**When Chrome history deletion matters most:** During incident response, the presence of cleared history combined with other suspicious artifacts (lateral movement, data staging, malware artifacts, etc.) becomes a data point that confirms the user was trying to cover tracks. Collect with Live Response and review the recoverable URLs alongside the timeline of other attack events.

### One Query, One Browser: The Asymmetry

This asymmetry (Edge detectable, Chrome not) reflects the current state of Windows telemetry:
- **First-party Microsoft products** (Edge, OneDrive, Registry operations, Services, Scheduled Tasks) have rich, reliable telemetry.
- **Third-party applications** (Chrome, Firefox, Brave, etc.) are treated as user data, not security-critical, and telemetry coverage is thin.

If you need to hunt Chrome activity at scale, combine MDE telemetry with EDR agents or endpoint detection rules that monitor process behavior, not just file operations.

## Important caveats

* **Cookies and saved passwords are not decrypted.** They are protected with per user DPAPI keys wrapped by an AES key in `Local State`. Live Response runs as SYSTEM, which cannot impersonate the user, so the CSVs contain metadata only (host, name, path, expiry, flags for cookies, URL, username, timestamps, usage count for logins). The raw encrypted files are still in the zip if you want to decrypt them offline with proper user keys.
* **Locked files.** If a browser is running, `History`, `Cookies`, `Login Data`, and `Web Data` are locked. The script copies them through a shared read handle, so the copy succeeds, but the snapshot may be slightly inconsistent. Use `-StopBrowsers` if you want clean snapshots.
* **All user profiles.** The script walks every folder under `C:\Users` and skips well known non user folders (Default, Public, WDAGUtilityAccount, defaultuser0, etc). It collects every Chrome and Edge profile per user (Default, Profile 1, Profile 2, Guest Profile).
* **Size.** Profiles with large history, many extensions, or busy caches can produce multi hundred MB zips. The zip uses Optimal compression. `-IncludeRecoverable` adds one CSV per profile and is small compared to the raw artifacts.
* **Permissions.** Designed for SYSTEM in Live Response. If you run it locally as a normal user, it will only see your own profile, and locked files for the running browser will fail to copy.
* **DPAPI scope.** No part of the script attempts to read user DPAPI keys. SYSTEM can extract LSA secrets and the wrapped key from `Local State`, but decrypting requires the user logon password or the master key. Out of scope for this collector.

## Troubleshooting

* **No `Parsed\` folder in the zip.** `sqlite3.exe` was not found. Upload it to the Live Response Library next to the script and run again. The script checks `script folder`, `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\`, and `C:\Windows\System32\` in that order.
* **`Copy failed` warnings in `collection.log`.** The file was missing or the browser had it open with an exclusive write lock. Try `-StopBrowsers`. Locked WAL and journal files are normal when the browser is alive.
* **Empty `profiles_collected.csv`.** No Chrome or Edge profiles exist on the device, or the user folders were redirected (Folder Redirection, roaming profile). Check `collection.log` for the user enumeration messages.
* **`sqlite(...)` WARN lines in the log.** The sqlite3 invocation returned a non zero exit code. Common cause is a corrupted db. The script copies the db to `<dbname>.copy` before parsing so the live file is never touched. Check the warning for the parse error.
* **No `recoverable_urls.csv` even with `-IncludeRecoverable`.** Either `sqlite3.exe` is missing (the recoverable scan also lives under the `if ($sqlite)` block) or the scanned files truly had no `http(s)://` strings. Confirm `_summary\collection.log` shows the `Recoverable URLs ... hits` line.
* **MDE PS 5.1 host quirks.** This script avoids two known traps: `Split-Path -LiteralPath ... -Parent` (replaced with `[System.IO.Path]::GetDirectoryName`) and PS 5.1 native command stdin pipe corruption (replaced with `System.Diagnostics.Process` writing raw UTF-8 no BOM to `StandardInput.BaseStream`). If you fork the script, keep these workarounds.

## Repo hygiene

`Scripts\.gitignore` excludes `sqlite3.exe`. Drop the binary anywhere under `Scripts\` for local Live Response staging and it will not be committed. Verify with:

```powershell
cd <your local clone of this repo>
git check-ignore -v "Live Response/Browser Logs/sqlite3.exe"
```
