# ShareWatch — Detailed Setup Guide

## 1. Prerequisites checklist

- [ ] Windows 10/11 or Windows Server hosting the shared folder
- [ ] The folder is shared over SMB (`Get-SmbShare` shows it)
- [ ] You have local Administrator rights
- [ ] PowerShell 5.1 or later

## 2. Enable Detailed File Share auditing (one-time)

This is what allows Windows to record *who* accessed the share, from *which IP*, with *what access rights* — including plain reads that no filesystem watcher can see.

```powershell
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /get /subcategory:"Detailed File Share"   # must show: Success and Failure
```

**Domain-joined machines:** a Group Policy refresh can revert this. Set it permanently via GPO:
`Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > Audit Detailed File Share`

## 3. Configure the monitor

Edit the configuration block at the top of `src\ShareWatch-Monitor.ps1`. At minimum set `MonitorPath`, `LogDirectory`, and `ShareName`.

Tip: while testing, set `$Global:ShareName = ""` to log ALL share activity and confirm the pipeline works, then narrow it.

## 4. Test interactively

```powershell
powershell -ExecutionPolicy Bypass -File .\src\ShareWatch-Monitor.ps1
```

From another machine, open a file on the share. Within ~2 seconds you should hear a beep and see an `SMB_ACCESS(5145)` log line with the client's IP and username.

If nothing appears, the startup diagnostics will have told you why (not elevated, auditing off, no matching share). Note that accessing the folder *locally on the server* or via RDP into the server does not generate SMB events.

## 5. Install as auto-start

```powershell
powershell -ExecutionPolicy Bypass -File .\src\Install-ShareWatch.ps1
```

This registers a scheduled task that starts at boot as SYSTEM, hidden, with automatic restart on failure, and starts it immediately.

To remove: `Unregister-ScheduledTask -TaskName "TalforShareWatch"`

## 6. Reading the log

```
[timestamp] EVENT=<type> | PATH=<file> | SRC_IP=<client IP> | SRC_HOST=<reverse DNS> | USER=<domain\user> | ACCESS=<mask>
```

Common access masks:
- `0x1` ReadData present → the file content was actually read
- `0x2` WriteData → modified
- `0x10000` Delete
- `0x120089` typical full read open
- `0x100080` / `0x80` metadata-only (filtered by default)

Event types: `SMB_ACCESS(5145)` (network access), `Created`, `Changed`, `Deleted`, `Renamed` (filesystem layer), `MONITOR_START` / `MONITOR_STOP` (lifecycle).
