# Case Study 04 — Phishing → Browser Download → Execution → Exfiltration

**Scenario class:** Classic data-theft chain (the 80% case)
**Evidence:** bundled at `examples/sample-evidence/disk/Users/jbang/`
**Functions used:** `parse_browser_history`, `analyze_downloads`,
  `correlate_download_to_execution`, `detect_exfiltration`

## Why this case matters

Most real intrusions do NOT start with a magical root exploit. They start
with a user clicking a link in an email. The chain goes:

```
phishing email → browser opens URL → file downloads → user runs it
    → malware calls home → sensitive data compressed → uploaded
```

Earlier YuShin case studies proved **execution** and **persistence**
detection (Case 01, 02) and **macOS system coverage** (Case 03). This
case closes the two largest remaining gaps: **how the malware got in**
and **whether data left**.

## The scenario (bundled evidence)

At 14:15, user `jbang` opened an email in Outlook containing a link to
`https://finance-update-secure.tk/download?token=abc123`. The link
redirected to `https://203.0.113.42:8080/payload` which served
`quarterly-report.pdf.exe`. The user ran it 6 minutes later. The
payload then compressed local files and uploaded them to `bashupload.com`
and `transfer.sh`.

## YuShin walkthrough

### Iteration 1 — Browser history

`parse_browser_history('.../Chrome/User Data/Default/History')` returns
7 visits, **3 flagged suspicious** by the URL pattern engine:

| Suspicious URL | Why |
|---|---|
| `https://finance-update-secure.tk/download?token=abc123` | `.tk` TLD |
| `https://203.0.113.42:8080/payload` | raw IPv4 + non-standard port |
| `https://transfer.sh` | known file-drop service |

The referrer chain reveals the user came FROM `outlook.office.com/mail` —
establishing phishing email as the entry vector.

### Iteration 2 — Download records + MOTW

`analyze_downloads(..., mode='browser_db')` returns 3 downloads, of which
**2 are executables** (.exe). One critical record:

```json
{
  "target_path": "C:\\Users\\jbang\\Downloads\\quarterly-report.pdf.exe",
  "url": "https://203.0.113.42:8080/payload",
  "referrer": "https://finance-update-secure.tk/download?token=abc123",
  "file_size": 847392,
  "url_is_suspicious": true
}
```

Then `analyze_downloads(..., mode='zone_identifier')` reads Zone.Identifier
ADS files on disk and confirms **2 files are MOTW-tagged** with
`ZoneId=3` (Internet). This is forensic proof the file genuinely came
from the web — not planted locally.

### Iteration 3 — Correlate download → execution

This is the smoking gun. `correlate_download_to_execution()` joins the
download records against process-tree / Prefetch evidence:

```json
{
  "download_url": "https://203.0.113.42:8080/payload",
  "download_target": "C:\\Users\\jbang\\Downloads\\quarterly-report.pdf.exe",
  "execution_image": "C:/Users/jbang/Downloads/quarterly-report.pdf.exe",
  "delay_seconds": 390,
  "severity": "critical"
}
```

Downloaded at 14:16:30, executed at 14:23:00 — a 6.5-minute gap.
**Classic "user clicks attachment" window.** Severity "critical" because
the source URL was flagged suspicious.

### Iteration 4 — Exfiltration detection

`detect_exfiltration(fsevents_or_mft=..., network_events=..., browser_history=...)`
ties everything together across multiple data sources:

```
max_severity: critical
signals:
  [medium]    archive_creation — 1 .zip in Temp
  [high]      upload_to_suspicious_domain — 2 uploads to bashupload.com + transfer.sh
  [medium]    large_outbound_transfer — 2 (45MB + 23MB outbound)
  [critical]  archive_then_upload_chain — 4 archive-to-upload sequences within 1h
  [medium]    browser_visited_upload_service — 2

stats:
  archives_created: 1
  uploads_to_known_dropsites: 2
  large_uploads: 2
  exfil_chains: 4
  browser_visited_dropsites: 2
```

**This is the answer to the most important customer question:**
"Did data leave the building?"

## Complete attack reconstruction (what the analyst writes in the report)

> At 14:15:45 UTC, user jbang clicked a link in an Outlook email that
> directed to `finance-update-secure.tk` (a freshly registered TLD).
> The link redirected to `203.0.113.42:8080/payload`, from which
> `quarterly-report.pdf.exe` was downloaded (MOTW confirmed from-Internet).
> At 14:23:00, the user executed the binary — exactly 6 minutes 30
> seconds after download, consistent with casual user behavior.
>
> Between 14:27 and 14:35, a `.zip` archive was created in the Temp
> directory and subsequently removed after two large outbound transfers
> to `bashupload.com` (45MB) and `transfer.sh` (23MB) — both known
> public file-drop services. The browser also visited these services
> directly.
>
> Findings F-042 through F-047 reference the audit entries that produced
> this conclusion. Evidence SHA-256 hashes verified pre/post analysis.

## What the judges should run

```bash
# Each function end-to-end against bundled evidence
python3 -c "
from yushin_mcp import call_tool
import json

hist = call_tool('parse_browser_history', {
    'history_db': 'disk/Users/jbang/AppData/Local/Google/Chrome/User Data/Default/History',
})
print(f'Browser history: {hist[\"total\"]} visits, {hist[\"suspicious_url_count\"]} suspicious')

dl = call_tool('analyze_downloads', {
    'downloads_source': 'disk/Users/jbang/AppData/Local/Google/Chrome/User Data/Default/History',
})
print(f'Downloads: {dl[\"total_downloads\"]} total, {dl[\"executable_download_count\"]} executables')

motw = call_tool('analyze_downloads', {
    'downloads_source': 'disk/Users/jbang/Downloads',
    'mode': 'zone_identifier',
})
print(f'MOTW: {motw[\"total_downloads\"]} Internet-zone files')
"
```
