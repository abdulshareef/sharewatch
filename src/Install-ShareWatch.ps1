<#
.SYNOPSIS
    Installs Talfor ShareWatch as an auto-start scheduled task.
    Run once as Administrator. The monitor will start at boot as SYSTEM
    (no login required, survives logoff, runs hidden).

    Also enables the "Detailed File Share" audit policy needed for
    read/open detection with source IP (Event 5145).
#>

$ScriptPath = "C:\Talfor\ShareWatch-Monitor.ps1"   # Adjust to where you place the monitor script

if (-not (Test-Path $ScriptPath)) {
    Write-Host "ERROR: Monitor script not found at $ScriptPath. Copy it there first." -ForegroundColor Red
    exit 1
}

# 1. Enable Detailed File Share auditing (captures reads/opens + client IP)
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
Write-Host "[+] Detailed File Share auditing enabled." -ForegroundColor Green

# 2. Create the scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650)

Register-ScheduledTask -TaskName "TalforShareWatch" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Talfor DLP file access monitor" -Force | Out-Null

Write-Host "[+] Scheduled task 'TalforShareWatch' registered (runs at boot as SYSTEM)." -ForegroundColor Green

# 3. Start it now without rebooting
Start-ScheduledTask -TaskName "TalforShareWatch"
Write-Host "[+] Monitor started. Check the configured log directory for log.txt" -ForegroundColor Green
