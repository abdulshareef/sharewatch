<#
.SYNOPSIS
    Talfor ShareWatch v1.2
    Real-time file access alerting + forensic logging with SMB source attribution.

.FIXES IN v1.1
    - Removed invalid $using: scope in event actions (silently broke beeps/actions)
    - Share name matching now case-insensitive and optional (was silently
      discarding all 5145 events on mismatch)
    - Startup self-diagnostics: admin check, audit policy check, share check
    - LastEventTime now advances from actual event timestamps (no missed events)
    - Global-scope config so event action blocks can read it reliably

.REQUIREMENTS
    - Run as ADMINISTRATOR (mandatory)
    - One-time:  auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
#>

# ============================ CONFIGURATION ============================
$Global:MonitorPath   = "D:\Important"
$Global:LogDirectory  = "D:\file_access_logs"
$Global:LogFile       = Join-Path $Global:LogDirectory "log.txt"
$Global:BeepFrequency = 1000
$Global:BeepDuration  = 1000
# Set to your SMB share name (see: Get-SmbShare). Set to "" to log ALL
# 5145 events regardless of share (recommended while testing).
$Global:ShareName     = "Important"

# --- Noise filtering (v1.2) ---
# Ignore accesses to the share root itself (Explorer keep-alive polling)
$Global:IgnoreShareRoot   = $true
# Access masks that are metadata-only touches, not real file access.
# 0x100080 = Synchronize+ReadAttributes (Explorer refresh)
# 0x80     = ReadAttributes only
$Global:IgnoreAccessMasks = @("0x100080", "0x80")
# Suppress duplicate events (same IP + path + mask) within this window (seconds)
$Global:DedupWindowSec    = 15
# =======================================================================

# ---------------------- STARTUP SELF-DIAGNOSTICS ----------------------
$issues = @()

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "FATAL: Not running as Administrator. SMB attribution and Security log access will fail." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator, then re-run this script." -ForegroundColor Red
    exit 1
}

# Monitor path check
if (-not (Test-Path $Global:MonitorPath)) {
    Write-Host "FATAL: $($Global:MonitorPath) does not exist." -ForegroundColor Red
    exit 1
}

# Audit policy check
$audit = auditpol /get /subcategory:"Detailed File Share" 2>$null | Out-String
if ($audit -notmatch "Success") {
    $issues += "Detailed File Share auditing is NOT enabled. Read/open events (5145) will NOT be captured."
    $issues += "  Fix: auditpol /set /subcategory:`"Detailed File Share`" /success:enable /failure:enable"
}

# Share check
$shares = Get-SmbShare -ErrorAction SilentlyContinue
$matchingShare = $shares | Where-Object { $_.Path -like "$($Global:MonitorPath)*" -or $Global:MonitorPath -like "$($_.Path)*" }
if (-not $matchingShare) {
    $issues += "No SMB share found covering $($Global:MonitorPath). Remote access won't generate share events."
} else {
    Write-Host "[i] Detected share(s) covering monitor path: $(($matchingShare.Name) -join ', ')" -ForegroundColor Cyan
    if ($Global:ShareName -and ($matchingShare.Name -notcontains $Global:ShareName)) {
        $issues += "Configured ShareName '$($Global:ShareName)' does not match detected share(s): $(($matchingShare.Name) -join ', ')"
    }
}

if ($issues.Count -gt 0) {
    Write-Host "`n===== CONFIGURATION WARNINGS =====" -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Yellow }
    Write-Host "==================================`n" -ForegroundColor Yellow
}

# --- Ensure log directory exists + write test ---
if (-not (Test-Path $Global:LogDirectory)) {
    New-Item -ItemType Directory -Path $Global:LogDirectory -Force | Out-Null
}
try {
    Add-Content -Path $Global:LogFile -Value "" -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Host "FATAL: Cannot write to $($Global:LogFile): $_" -ForegroundColor Red
    exit 1
}

# ---------------------------- FUNCTIONS -------------------------------
function Global:Write-AccessLog {
    param(
        [string]$EventType,
        [string]$FilePath,
        [string]$SourceIP    = "LOCAL/UNKNOWN",
        [string]$SourceHost  = "N/A",
        [string]$SourceUser  = "N/A",
        [string]$AccessMask  = "N/A"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $entry = "[$timestamp] EVENT=$EventType | PATH=$FilePath | SRC_IP=$SourceIP | SRC_HOST=$SourceHost | USER=$SourceUser | ACCESS=$AccessMask"
    try { Add-Content -Path $Global:LogFile -Value $entry -Encoding UTF8 } catch { }
    Write-Host $entry
}

function Global:Get-SmbSourceInfo {
    param([string]$FilePath)
    $result = [PSCustomObject]@{ IP = "LOCAL/UNKNOWN"; HostName = "N/A"; User = "N/A" }
    try {
        $open = Get-SmbOpenFile -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -eq $FilePath } | Select-Object -First 1
        if (-not $open) {
            $open = Get-SmbOpenFile -ErrorAction SilentlyContinue |
                    Where-Object { $_.Path -like "$($Global:MonitorPath)*" } | Select-Object -First 1
        }
        if ($open) {
            $session = Get-SmbSession -ErrorAction SilentlyContinue |
                       Where-Object { $_.SessionId -eq $open.SessionId } | Select-Object -First 1
            if ($session) {
                $result.IP   = $session.ClientComputerName
                $result.User = $session.ClientUserName
                try { $result.HostName = [System.Net.Dns]::GetHostEntry($session.ClientComputerName).HostName }
                catch { $result.HostName = "unresolved" }
            }
        }
    } catch { }
    return $result
}

# ------------------- FILESYSTEMWATCHER (changes) ----------------------
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path                  = $Global:MonitorPath
$watcher.IncludeSubdirectories = $true
$watcher.NotifyFilter          = [System.IO.NotifyFilters]::FileName -bor
                                 [System.IO.NotifyFilters]::DirectoryName -bor
                                 [System.IO.NotifyFilters]::LastWrite -bor
                                 [System.IO.NotifyFilters]::Size -bor
                                 [System.IO.NotifyFilters]::Security -bor
                                 [System.IO.NotifyFilters]::Attributes
$watcher.EnableRaisingEvents   = $true

$fswAction = {
    try {
        $path       = $Event.SourceEventArgs.FullPath
        $changeType = $Event.SourceEventArgs.ChangeType.ToString()
        if ($changeType -eq "Renamed") {
            $path = "$($Event.SourceEventArgs.OldFullPath) -> $($Event.SourceEventArgs.FullPath)"
        }
        $src = Get-SmbSourceInfo -FilePath $Event.SourceEventArgs.FullPath
        Write-AccessLog -EventType $changeType -FilePath $path `
                        -SourceIP $src.IP -SourceHost $src.HostName -SourceUser $src.User
        [Console]::Beep($Global:BeepFrequency, $Global:BeepDuration)
    } catch {
        Write-AccessLog -EventType "FSW_ACTION_ERROR" -FilePath "$_"
    }
}

Register-ObjectEvent $watcher "Created" -SourceIdentifier "TFAM_Created" -Action $fswAction | Out-Null
Register-ObjectEvent $watcher "Changed" -SourceIdentifier "TFAM_Changed" -Action $fswAction | Out-Null
Register-ObjectEvent $watcher "Deleted" -SourceIdentifier "TFAM_Deleted" -Action $fswAction | Out-Null
Register-ObjectEvent $watcher "Renamed" -SourceIdentifier "TFAM_Renamed" -Action $fswAction | Out-Null

# ----------------- EVENT 5145 POLLING (reads/opens) -------------------
$LastEventTime = (Get-Date).AddSeconds(-5)
$Script:DedupCache = @{}    # key = "ip|path|mask" -> last logged time
$Script:DnsCache   = @{}    # key = ip -> hostname

function Poll-AuditEvents {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 5145
        StartTime = $script:LastEventTime
    } -ErrorAction SilentlyContinue

    if (-not $events) { return }

    # Advance cursor from real event timestamps (oldest-first processing)
    $events = $events | Sort-Object TimeCreated
    $script:LastEventTime = ($events[-1].TimeCreated).AddMilliseconds(1)

    foreach ($ev in $events) {
        $xml  = [xml]$ev.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $share     = $data['ShareName']       # e.g. \\*\Important
        $relTarget = $data['RelativeTargetName']
        $access    = $data['AccessMask']
        $clientIP  = $data['IpAddress']

        # Filter 1: share filter (case-insensitive). Empty ShareName = log everything.
        if ($Global:ShareName -and ($share -notmatch [regex]::Escape($Global:ShareName) )) { continue }

        # Filter 2: ignore share-root keep-alive polling (Explorer refresh noise)
        $isShareRoot = [string]::IsNullOrWhiteSpace($relTarget) -or $relTarget -in @("\\", "/", ".")
        if ($Global:IgnoreShareRoot -and $isShareRoot) { continue }

        # Filter 3: ignore metadata-only access masks (attribute reads, not real file access)
        if ($access -in $Global:IgnoreAccessMasks) { continue }

        # Filter 4: deduplicate identical events within the window
        $dedupKey = "$clientIP|$share\$relTarget|$access"
        $now = Get-Date
        if ($Script:DedupCache.ContainsKey($dedupKey) -and
            ($now - $Script:DedupCache[$dedupKey]).TotalSeconds -lt $Global:DedupWindowSec) {
            continue
        }
        $Script:DedupCache[$dedupKey] = $now
        # Prune stale dedup entries occasionally
        if ($Script:DedupCache.Count -gt 500) {
            $stale = $Script:DedupCache.GetEnumerator() |
                     Where-Object { ($now - $_.Value).TotalSeconds -gt $Global:DedupWindowSec } |
                     ForEach-Object { $_.Key }
            $stale | ForEach-Object { $Script:DedupCache.Remove($_) }
        }

        $user     = "$($data['SubjectDomainName'])\$($data['SubjectUserName'])"
        $fullPath = "$share\$relTarget"

        # Cached reverse DNS (avoids a lookup per event)
        if (-not $Script:DnsCache.ContainsKey($clientIP)) {
            try { $Script:DnsCache[$clientIP] = [System.Net.Dns]::GetHostEntry($clientIP).HostName }
            catch { $Script:DnsCache[$clientIP] = "unresolved" }
        }
        $hostName = $Script:DnsCache[$clientIP]

        Write-AccessLog -EventType "SMB_ACCESS(5145)" -FilePath $fullPath `
                        -SourceIP $clientIP -SourceHost $hostName `
                        -SourceUser $user -AccessMask $access
        [Console]::Beep($Global:BeepFrequency, $Global:BeepDuration)
    }
}

# ----------------------------- MAIN -----------------------------------
Write-AccessLog -EventType "MONITOR_START" -FilePath $Global:MonitorPath -SourceIP "SYSTEM"
Write-Host "`nTalfor ShareWatch v1.2 active on $($Global:MonitorPath)" -ForegroundColor Green
Write-Host "Logging to $($Global:LogFile)" -ForegroundColor Green
Write-Host "TIP: open a file from the remote PC now - a 5145 line should appear within ~2s.`n" -ForegroundColor Cyan

try {
    while ($true) {
        Poll-AuditEvents
        Start-Sleep -Seconds 2
    }
} finally {
    "TFAM_Created","TFAM_Changed","TFAM_Deleted","TFAM_Renamed" |
        ForEach-Object { Unregister-Event -SourceIdentifier $_ -ErrorAction SilentlyContinue }
    $watcher.Dispose()
    Write-AccessLog -EventType "MONITOR_STOP" -FilePath $Global:MonitorPath -SourceIP "SYSTEM"
}
