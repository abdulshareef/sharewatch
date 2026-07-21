# Talfor ShareWatch

**Real-time SMB share access monitoring with source attribution — a lightweight DLP tripwire for Windows.**

ShareWatch watches a sensitive folder shared over your network and tells you — instantly and audibly — every time someone opens, reads, copies, modifies, renames, deletes, or encrypts a file in it. Every event is written to a forensic-grade log with the **source IP address, hostname, and username** of the accessing machine.

Built and maintained by [Talfor Cybersecurity & Digital Forensics](https://talfor.com), Bengaluru, India.

---

## Why ShareWatch?

Most small organisations have one folder that matters — contracts, case files, payroll, source code — sitting on a network share with no visibility into who touches it. Full DLP suites are expensive and heavy. ShareWatch gives you the core insider-threat signal in a single PowerShell script:

- **Audible tripwire** — a beep the moment the share is accessed
- **Source attribution** — client IP, reverse-DNS hostname, and domain username for every access, sourced from Windows Security Event 5145 and live SMB session correlation
- **Read detection** — catches file *opens and reads*, not just modifications (something `FileSystemWatcher`-only tools fundamentally cannot do)
- **Noise filtering** — Explorer keep-alive polling, metadata-only touches, and duplicate events are suppressed so every log line means something
- **Forensic-ready log** — timestamped (ms precision), append-only text log suitable for evidence preservation workflows

## How it works

ShareWatch runs two detection layers in parallel:

| Layer | Detects | Attribution |
|---|---|---|
| `FileSystemWatcher` | Create / Change / Delete / Rename | SMB open-file → session correlation (`Get-SmbOpenFile` / `Get-SmbSession`) |
| Security Event **5145** (Detailed File Share auditing) | Opens / reads / all SMB access, incl. denied attempts | Native: client IP, username, access mask recorded by Windows |

## Requirements

- Windows 10/11 or Windows Server (PowerShell 5.1+)
- Administrator rights on the machine hosting the share
- The monitored folder shared over SMB

## Quick start

1. Clone or download this repository to the file server (e.g. `C:\Talfor\ShareWatch`).
2. Open the configuration block at the top of `src\ShareWatch-Monitor.ps1` and set:
   - `$Global:MonitorPath` — the folder to watch (e.g. `D:\Important`)
   - `$Global:LogDirectory` — where `log.txt` is written (e.g. `D:\file_access_logs`)
   - `$Global:ShareName` — the SMB share name (check with `Get-SmbShare`)
3. In an **elevated** PowerShell:

```powershell
# One-time: enable the audit policy that makes read/open detection possible
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Test-run interactively
powershell -ExecutionPolicy Bypass -File .\src\ShareWatch-Monitor.ps1
```

4. When you're happy with it, install it as an auto-start scheduled task (runs at boot as SYSTEM, hidden, auto-restarts on failure):

```powershell
powershell -ExecutionPolicy Bypass -File .\src\Install-ShareWatch.ps1
```

## Example log output

```
[2026-07-21 14:32:07.481] EVENT=SMB_ACCESS(5145) | PATH=\\*\Important\case_notes.docx | SRC_IP=192.168.1.45 | SRC_HOST=WS-ANALYST2.corp.local | USER=CORP\jsmith | ACCESS=0x120089
[2026-07-21 14:33:12.007] EVENT=Changed | PATH=D:\Important\case_notes.docx | SRC_IP=192.168.1.45 | SRC_HOST=WS-ANALYST2.corp.local | USER=CORP\jsmith | ACCESS=N/A
```

## Built-in self-diagnostics

On startup ShareWatch verifies that it is elevated, that the monitor path exists, that Detailed File Share auditing is enabled, and that an SMB share actually covers the monitored folder — and tells you exactly what to fix if not. No silent failures.

## Configuration reference

| Setting | Default | Purpose |
|---|---|---|
| `$Global:MonitorPath` | `D:\Important` | Folder to monitor |
| `$Global:LogDirectory` | `D:\file_access_logs` | Log destination |
| `$Global:ShareName` | `Important` | SMB share filter (empty = log all shares) |
| `$Global:BeepFrequency` / `$Global:BeepDuration` | 1000 Hz / 1000 ms | Alert tone |
| `$Global:IgnoreShareRoot` | `$true` | Drop Explorer share-root keep-alive noise |
| `$Global:IgnoreAccessMasks` | `0x100080`, `0x80` | Drop metadata-only touches |
| `$Global:DedupWindowSec` | `15` | Suppress duplicate events window |

## Known limitations

- **Local access on the server** (including RDP sessions into it) generates no SMB events — only filesystem change events are seen, without remote attribution.
- The audible beep is not available when running as SYSTEM at boot (session 0 has no audio); the log captures everything regardless.
- On domain-joined machines, Group Policy refresh may revert the local audit policy — configure the *Detailed File Share* audit subcategory via GPO for persistence.
- IPv6-preferring clients are logged with their link-local IPv6 address; reverse DNS resolution provides the hostname.

## Roadmap

- [ ] Windows Service packaging
- [ ] Failure-audit (access denied) alerting mode
- [ ] Toast / email / webhook notifications
- [ ] Log rotation and JSON/CSV output formats
- [ ] Authenticode-signed releases

## Legal and ethical use

ShareWatch is intended for monitoring systems and shares **you own or are authorised to monitor**, as part of legitimate data loss prevention and insider-threat programmes. Access logging of employees may be subject to notice and privacy requirements in your jurisdiction — consult applicable law and your organisation's policies before deployment.

## License

MIT — see [LICENSE](LICENSE).

## About Talfor

Talfor Cybersecurity & Digital Forensics provides digital forensics, incident response, expert witness, and cybersecurity training services. ShareWatch is released to the community as part of our open tooling initiative.
