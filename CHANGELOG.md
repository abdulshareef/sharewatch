# Changelog

## v1.2 (2026-07-21)
- Noise filtering: share-root keep-alive events, metadata-only access masks (0x100080, 0x80)
- Event deduplication within configurable window (default 15s)
- Reverse-DNS caching per client IP
- Share filter defaults to configured share name

## v1.1 (2026-07-21)
- Startup self-diagnostics: admin, monitor path, audit policy, SMB share coverage
- Fixed invalid $using: scope in FileSystemWatcher event actions
- Case-insensitive, optional share filtering for Event 5145
- Event-timestamp-based polling cursor (no missed events)

## v1.0 (2026-07-21)
- Initial release: FileSystemWatcher (Created/Changed/Deleted/Renamed) + Security Event 5145 polling
- SMB session correlation for source IP/hostname/username attribution
- Audible alert + forensic text log
- Auto-start installer via Task Scheduler (boot, SYSTEM, hidden)
