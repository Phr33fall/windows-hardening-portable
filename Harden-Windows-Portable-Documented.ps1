# =============================================================================
# Harden-Windows-Portable-Documented.ps1
# Portable Windows Hardening Script - Fully Documented Edition
# Auto-detects machine, admin account, and paths at runtime
# Last updated: April 2026
# Run as Administrator
# =============================================================================
#
# PURPOSE
# A portable hardening script that works on any Windows machine without
# modification. All paths, usernames, and machine names are detected at
# runtime from environment variables. Nothing is hardcoded.
#
# HOW TO USE
# 1. Copy this script to any Windows machine
# 2. Open PowerShell as Administrator
# 3. Unblock-File .\Harden-Windows-Portable-Documented.ps1
# 4. Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# 5. .\Harden-Windows-Portable-Documented.ps1
# 6. Review the detected context, select mode, and proceed
#
# PHASES
# Phase 0 - Detect:   machine context, rollback check, pre-change backup
# Phase 1 - Apply:    15 hardening sections with optional interactive mode
# Phase 2 - Verify:   independent state checks with drift detection
# Phase 3 - Backup:   post-hardening state export
# Phase 4 - Tasks:    weekly scheduled task registration
# Phase 5 - Update:   Windows OS updates via PSWindowsUpdate + winget
# Final    - Summary: colour-coded results table and cipher wipe prompt
#
# INTERRUPTION PROTECTION
# A progress log is written to disk after each section completes. If the
# script is interrupted, the log shows exactly what completed. On next run
# the script detects an incomplete log and offers to resume from the last
# completed section or start fresh. Windows Update service is suspended
# during Phase 1 to prevent forced reboots mid-run and re-enabled at the
# end regardless of how the script exits.
#
# =============================================================================


# =============================================================================
# PHASE 0: DETECT MACHINE CONTEXT
#
# INFO:
#   Everything the script needs is derived from Windows environment variables
#   at runtime. No paths, usernames, SIDs, or machine names are hardcoded.
#   OneDrive is detected via three environment variables in priority order.
#   If not found, backup falls back to C:\Maintenance-Stuff locally.
#
# BENEFITS:
#   Completely portable. Copy to any Windows machine and run without editing
#   a single line. Works for any admin account name, any machine name,
#   with or without OneDrive present.
#
# CONSIDERATIONS APPLYING:
#   If OneDrive is not set up for the current user, backups stay local.
#   Manually copy the backup folder to an external location in this case.
# =============================================================================

$AdminUser    = $env:USERNAME
$AdminProfile = $env:USERPROFILE
$MachineName  = $env:COMPUTERNAME
$CurrentUserId = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$AdminUser" } else { $AdminUser }
$Date         = Get-Date -Format "yyyy-MM-dd"
$Warnings     = @()
$SectionResults = @()
$ModeUsed     = "Automatic"

Write-Host "`n=== Portable Windows Hardening Script (Documented Edition) ===" -ForegroundColor Cyan
Write-Host "Detecting machine context..." -ForegroundColor Gray

$OneDrivePath = $env:OneDrive
if (!$OneDrivePath) { $OneDrivePath = $env:OneDriveConsumer }
if (!$OneDrivePath) { $OneDrivePath = $env:OneDriveCommercial }

if ($OneDrivePath -and (Test-Path $OneDrivePath)) {
    $ScriptBase = "$OneDrivePath\Documents\Maintenance-Stuff"
    $BackupRoot = "$OneDrivePath\Documents\Maintenance-Stuff"
    Write-Host "  OneDrive detected: $OneDrivePath" -ForegroundColor Green
} else {
    $ScriptBase = "C:\Maintenance-Stuff"
    $BackupRoot = "C:\Maintenance-Stuff"
    Write-Host "  OneDrive not found. Using local path: C:\Maintenance-Stuff" -ForegroundColor Yellow
    $Warnings += "OneDrive not detected. Backup stored locally. Copy offsite manually."
}

$BackupPath   = "$BackupRoot\$Date"
$ProgressLog  = "$ScriptBase\hardening-progress.log"

New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
New-Item -ItemType Directory -Force -Path $ScriptBase | Out-Null

$LocalUsers = Get-LocalUser | Select-Object -ExpandProperty Name
$AdminSID   = (Get-LocalUser -Name $AdminUser -ErrorAction SilentlyContinue).SID.Value

# Helper functions defined here after variables are set so $ProgressLog is available

function Write-Progress-Log {
    param([string]$Message)
    "$((Get-Date -Format 'HH:mm:ss')) $Message" | Out-File $ProgressLog -Append -Encoding UTF8
}

function Confirm-Section {
    param(
        [string]$SectionName,
        [string]$Info,
        [string]$Benefits,
        [string]$Considerations
    )
    if (-not $Interactive) { return $true }

    Write-Host "`n============================================================" -ForegroundColor DarkGray
    Write-Host "  SECTION: $SectionName" -ForegroundColor White
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  INFO:" -ForegroundColor Cyan
    $Info -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    Write-Host "`n  BENEFITS:" -ForegroundColor Green
    $Benefits -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    Write-Host "`n  CONSIDERATIONS:" -ForegroundColor Yellow
    $Considerations -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    Write-Host "============================================================" -ForegroundColor DarkGray

    $Choice = Read-Host "`nApply this section? (Y/N)"
    return ($Choice -eq "Y" -or $Choice -eq "y")
}

function Record-Section {
    param([string]$Name, [string]$Status)
    $script:SectionResults += [PSCustomObject]@{ Section = $Name; Status = $Status }
    Write-Progress-Log "SECTION $Name : $Status"
}

function Should-Skip {
    param([string]$SectionName)
    if (!$ResumeFrom) { return $false }
    $CompletedSections = @()
    if (Test-Path $ProgressLog) {
        $CompletedSections = (Get-Content $ProgressLog | Where-Object { $_ -like "*SECTION*APPLIED*" }) |
            ForEach-Object { (($_ -split "SECTION ")[1] -split " :")[0] }
    }
    return $CompletedSections -contains $SectionName
}

Write-Host "`n  Machine:      $MachineName" -ForegroundColor Gray
Write-Host "  Admin user:   $AdminUser" -ForegroundColor Gray
Write-Host "  Admin SID:    $AdminSID" -ForegroundColor Gray
Write-Host "  Profile path: $AdminProfile" -ForegroundColor Gray
Write-Host "  Script base:  $ScriptBase" -ForegroundColor Gray
Write-Host "  Backup path:  $BackupPath" -ForegroundColor Gray
Write-Host "  Local users:  $($LocalUsers -join ', ')" -ForegroundColor Gray


# =============================================================================
# ROLLBACK CHECK
#
# INFO:
#   If a PRE-CHANGE-LATEST folder exists in Maintenance-Stuff, a previous
#   pre-hardening backup is available. The operator is offered the option
#   to restore from it before proceeding, effectively rolling back any
#   previous hardening run. Rollback restores registry keys, security policy,
#   and service states from the pre-change snapshot.
#
# BENEFITS:
#   Provides a safe recovery path if a previous hardening run caused an
#   unexpected problem. No need to manually hunt for backup files or remember
#   registry paths. One prompt, one answer, full rollback.
#
# CONSIDERATIONS APPLYING:
#   Rollback only restores the items captured in the pre-change backup: registry
#   keys, security policy, and service startup types. It does not undo file
#   deletions (thumbnail cache, prefetch, WER dumps etc) as those are gone.
#   It also does not remove scheduled tasks registered during hardening.
#   After rollback the script exits. Re-run to apply fresh hardening.
# =============================================================================
$PreCopyDest = "$ScriptBase\PRE-CHANGE-LATEST"
$RegistryRollbackTargets = @(
    [PSCustomObject]@{ Name = "Telemetry";            RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection";                                   PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection";                                   Values = @("AllowTelemetry") },
    [PSCustomObject]@{ Name = "PrefetchParameters";   RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; PsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Values = @("EnablePrefetcher","EnableSuperfetch") },
    [PSCustomObject]@{ Name = "ActivityHistory";      RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System";                                           PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";                                           Values = @("EnableActivityFeed","PublishUserActivities","UploadUserActivities") },
    [PSCustomObject]@{ Name = "DeliveryOptimisation"; RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";                            PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";                            Values = @("DODownloadMode") },
    [PSCustomObject]@{ Name = "WindowsInk";           RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace";                                      PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace";                                      Values = @("AllowWindowsInkWorkspace") },
    [PSCustomObject]@{ Name = "ErrorReporting";       RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting";                         PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting";                         Values = @("Disabled") },
    [PSCustomObject]@{ Name = "LLMNR";                RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";                                    PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";                                    Values = @("EnableMulticast") },
    [PSCustomObject]@{ Name = "LocationTracking";     RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors";                              PsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors";                              Values = @("DisableLocation") },
    [PSCustomObject]@{ Name = "AuditPolicy";          RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog";                                           PsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog";                                           Values = @() },
    [PSCustomObject]@{ Name = "DoH";                  RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";                               PsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";                               Values = @("EnableAutoDoh") },
    [PSCustomObject]@{ Name = "CloudflareDoH";        RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\1.1.1.1";    PsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\1.1.1.1";    Values = @("DohFlags","Template") }
)

if (Test-Path $PreCopyDest) {
    Write-Host "`n--- ROLLBACK AVAILABLE ---" -ForegroundColor Yellow
    Write-Host "  A pre-change backup exists at: $PreCopyDest" -ForegroundColor Gray
    $RollbackChoice = Read-Host "Restore machine to pre-hardening state before proceeding? (Y/N)"
    if ($RollbackChoice -eq "Y" -or $RollbackChoice -eq "y") {
        Write-Host "`nRestoring from pre-change backup..." -ForegroundColor Cyan

        # Restore registry keys
        Get-ChildItem "$PreCopyDest\Registry_*.reg" -ErrorAction SilentlyContinue | ForEach-Object {
            reg import $_.FullName 2>$null
            Write-Host "  Restored: $($_.Name)" -ForegroundColor Green
        }

        # Remove hardening keys/values that did not exist in the pre-change snapshot
        $PreRegistryStateCsv = "$PreCopyDest\Registry_State_PRE.csv"
        if (Test-Path $PreRegistryStateCsv) {
            $PreRegistryState = Import-Csv $PreRegistryStateCsv
            foreach ($KeyGroup in ($PreRegistryState | Group-Object PsPath)) {
                $Rows = @($KeyGroup.Group)
                $PsPath = $Rows[0].PsPath
                $KeyExisted = [System.Convert]::ToBoolean($Rows[0].KeyExisted)
                if (-not $KeyExisted) {
                    Remove-Item -Path $PsPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  Removed key created by hardening: $PsPath" -ForegroundColor Green
                    continue
                }
                foreach ($Row in $Rows | Where-Object { $_.ValueName }) {
                    $ValueExisted = [System.Convert]::ToBoolean($Row.ValueExisted)
                    if (-not $ValueExisted) {
                        Remove-ItemProperty -Path $PsPath -Name $Row.ValueName -ErrorAction SilentlyContinue
                    }
                }
            }
            Write-Host "  Registry-created values cleaned up." -ForegroundColor Green
        }

        # Restore security policy
        $PreSecPol = "$PreCopyDest\SecurityPolicy_PRE.cfg"
        if (Test-Path $PreSecPol) {
            secedit /configure /db secedit.sdb /cfg $PreSecPol /quiet
            Write-Host "  Security policy restored." -ForegroundColor Green
        }

        # Restore service startup types from CSV
        $PreServicesCsv = "$PreCopyDest\Services_State_PRE.csv"
        if (Test-Path $PreServicesCsv) {
            $PreServices = Import-Csv $PreServicesCsv
            foreach ($svc in $PreServices) {
                $StartTypeMap = @{ "Automatic" = "Automatic"; "Manual" = "Manual"; "Disabled" = "Disabled" }
                if ($StartTypeMap.ContainsKey($svc.StartType)) {
                    Set-Service -Name $svc.Name -StartupType $StartTypeMap[$svc.StartType] -ErrorAction SilentlyContinue
                }
                if ($svc.StartValue -match '^\d+$') {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name "Start" -Value ([int]$svc.StartValue) -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  Service startup types restored." -ForegroundColor Green
        }

        # Restore DNS server settings changed by the DoH section
        $PreDnsCsv = "$PreCopyDest\DnsClientServerAddress_PRE.csv"
        if (Test-Path $PreDnsCsv) {
            Import-Csv $PreDnsCsv | ForEach-Object {
                if ($_.ServerAddresses) {
                    Set-DnsClientServerAddress -InterfaceIndex ([int]$_.InterfaceIndex) -ServerAddresses ($_.ServerAddresses -split ';') -ErrorAction SilentlyContinue
                } else {
                    Set-DnsClientServerAddress -InterfaceIndex ([int]$_.InterfaceIndex) -ResetServerAddresses -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  DNS server settings restored." -ForegroundColor Green
        }

        Write-Host "`nRollback complete. Reboot recommended." -ForegroundColor Green
        Write-Host "Registry keys, security policy, and service startup types have been restored." -ForegroundColor Gray
        Write-Host "Note: Deleted files (cache, prefetch, WER dumps) cannot be restored." -ForegroundColor Yellow
        exit 0
    }
}


# =============================================================================
# PRE-CHANGE BACKUP
#
# INFO:
#   Before making any changes, the current machine state is captured to a
#   clearly labelled pre-hardening backup. This runs before the confirmation
#   prompt so a snapshot exists even if the operator aborts.
#
# BENEFITS:
#   Rollback reference if anything goes wrong. Comparison point between
#   pre and post hardening state. Audit trail of what the machine looked
#   like before any changes were applied.
#
# CONSIDERATIONS APPLYING:
#   Registry keys not yet hardened on this machine will show as Skipped.
#   This is expected on a first-time run and does not indicate a problem.
#   The PRE-CHANGE-LATEST folder in Maintenance-Stuff root is always
#   overwritten with the most recent pre-change snapshot.
# =============================================================================
Write-Host "`n--- PRE-CHANGE BACKUP ---" -ForegroundColor Cyan
Write-Host "Capturing current state before any changes..." -ForegroundColor Gray

$PreBackupPath = "$BackupPath\PRE-CHANGE"
New-Item -ItemType Directory -Force -Path $PreBackupPath | Out-Null

$PreRegistryState = @()
foreach ($Target in $RegistryRollbackTargets) {
    $KeyExisted = Test-Path $Target.PsPath
    if ($Target.Values.Count -eq 0) {
        $PreRegistryState += [PSCustomObject]@{
            Name         = $Target.Name
            PsPath       = $Target.PsPath
            KeyExisted   = $KeyExisted
            ValueName    = ""
            ValueExisted = $false
        }
    } else {
        $Props = if ($KeyExisted) { Get-ItemProperty -Path $Target.PsPath -ErrorAction SilentlyContinue } else { $null }
        foreach ($ValueName in $Target.Values) {
            $ValueExisted = $false
            if ($Props) { $ValueExisted = ($Props.PSObject.Properties.Name -contains $ValueName) }
            $PreRegistryState += [PSCustomObject]@{
                Name         = $Target.Name
                PsPath       = $Target.PsPath
                KeyExisted   = $KeyExisted
                ValueName    = $ValueName
                ValueExisted = $ValueExisted
            }
        }
    }
}
$PreRegistryState | Export-Csv "$PreBackupPath\Registry_State_PRE.csv" -NoTypeInformation

foreach ($Target in $RegistryRollbackTargets) {
    reg export $Target.RegPath "$PreBackupPath\Registry_$($Target.Name).reg" /y 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "  Exported: $($Target.Name)" -ForegroundColor Green }
    else { Write-Host "  Skipped (key not yet present): $($Target.Name)" -ForegroundColor Gray }
}

gpresult /h "$PreBackupPath\GroupPolicy_Report_PRE.html" /f 2>$null
secedit /export /cfg "$PreBackupPath\SecurityPolicy_PRE.cfg" /quiet

$PreServicesReport = @()
foreach ($SvcName in @("WSearch","DiagTrack","WerSvc","SysMain","DoSvc","CDPSvc","CDPUserSvc","FileSyncHelper","OneSyncSvc","VMAuthdService","SCardSvr","ScDeviceEnum","wuauserv")) {
    $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($Svc) {
        $StartValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName" -Name "Start" -ErrorAction SilentlyContinue).Start
        $PreServicesReport += [PSCustomObject]@{ Name = $Svc.Name; Display = $Svc.DisplayName; Status = $Svc.Status; StartType = $Svc.StartType; StartValue = $StartValue }
    }
}
$PreServicesReport | Export-Csv "$PreBackupPath\Services_State_PRE.csv" -NoTypeInformation

Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Where-Object { $_.AddressFamily -eq 2 } |
    Select-Object InterfaceAlias, InterfaceIndex, @{Name="ServerAddresses";Expression={$_.ServerAddresses -join ';'}} |
    Export-Csv "$PreBackupPath\DnsClientServerAddress_PRE.csv" -NoTypeInformation

"Pre-hardening backup captured on $Date for $MachineName ($AdminUser).`nRepresents machine state BEFORE hardening. Use for rollback if needed." | Out-File "$PreBackupPath\README.txt" -Encoding UTF8

# Copy to Maintenance-Stuff root for easy access and rollback detection
New-Item -ItemType Directory -Force -Path $PreCopyDest | Out-Null
Copy-Item "$PreBackupPath\*" -Destination $PreCopyDest -Recurse -Force

Write-Host "  Pre-change backup complete." -ForegroundColor Green
Write-Host "  Dated copy: $PreBackupPath" -ForegroundColor Gray
Write-Host "  Latest copy: $PreCopyDest" -ForegroundColor Gray


# =============================================================================
# INTERRUPTION PROTECTION
#
# INFO:
#   The Windows Update service (wuauserv) is stopped before Phase 1 begins
#   to prevent Windows from scheduling a forced reboot mid-run. A progress
#   log file is written after each section completes. If the script is
#   interrupted, the log shows exactly what completed. On next run, if an
#   incomplete log is detected, the operator is offered the choice to resume
#   from the last completed section or start fresh. A try/finally block
#   ensures Windows Update is always re-enabled even if the script crashes.
#
# BENEFITS:
#   Prevents the most common cause of mid-run interruptions: Windows deciding
#   to reboot for updates at an inconvenient time. The progress log provides
#   a clear audit trail of what happened and when. Resume capability means
#   a partial run does not have to be repeated from scratch.
#
# CONSIDERATIONS APPLYING:
#   Stopping Windows Update temporarily means the machine will not receive
#   update notifications or automatic downloads during the hardening run.
#   This is intentional and the service is always restored at the end.
#   The resume feature checks section names in the log file. If you rename
#   sections, existing logs will not match and resume will not work correctly.
# =============================================================================
Write-Host "`n--- INTERRUPTION PROTECTION ---" -ForegroundColor Cyan

function Restore-WindowsUpdateService {
    if ($script:WUOriginalStartType) {
        Set-Service -Name "wuauserv" -StartupType $script:WUOriginalStartType -ErrorAction SilentlyContinue
    }
    if ($script:WUWasRunning) {
        Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    } else {
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    }
}

# Stop Windows Update service to prevent forced reboots mid-run
$WUService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
$script:WUOriginalStartType = if ($WUService) { $WUService.StartType } else { $null }
$script:WUWasRunning = ($WUService -and $WUService.Status -eq "Running")
if ($WUService -and $WUService.Status -eq "Running") {
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Write-Host "  Windows Update service suspended for duration of run." -ForegroundColor Green
}

# Check for incomplete previous run
$ResumeFrom = $null
if (Test-Path $ProgressLog) {
    $ProgressEntries = Get-Content $ProgressLog
    $CompletedRun = $ProgressEntries | Where-Object { $_ -like "*=== Script completed successfully ===*" } | Select-Object -Last 1
    $LastLog = $ProgressEntries | Where-Object { $_ -like "*SECTION*APPLIED*" } | Select-Object -Last 1
    if ($CompletedRun) {
        Write-Host "  Previous hardening run completed successfully. Starting a new run." -ForegroundColor Gray
        Clear-Content $ProgressLog -ErrorAction SilentlyContinue
    } elseif ($LastLog) {
        $LastSection = (($LastLog -split "SECTION ")[1] -split " :")[0]
        Write-Host "`n  Incomplete run detected. Last completed section: $LastSection" -ForegroundColor Yellow
        $ResumeChoice = Read-Host "  Resume from next section after '$LastSection'? (Y = resume, N = start fresh)"
        if ($ResumeChoice -eq "Y" -or $ResumeChoice -eq "y") {
            $ResumeFrom = $LastSection
            Write-Host "  Resuming from after: $LastSection" -ForegroundColor Green
        } else {
            Clear-Content $ProgressLog -ErrorAction SilentlyContinue
            Write-Host "  Starting fresh." -ForegroundColor Green
        }
    }
}

Write-Progress-Log "=== Hardening run started on $MachineName by $AdminUser ==="


# Confirmation and mode selection
Write-Host "`nReview the detected context above." -ForegroundColor Yellow
$Confirm = Read-Host "Proceed with hardening on $MachineName as $AdminUser? (Y/N)"
if ($Confirm -ne "Y" -and $Confirm -ne "y") {
    Write-Host "Aborted. Pre-change backup retained at: $PreCopyDest" -ForegroundColor Yellow
    Restore-WindowsUpdateService
    exit 0
}

Write-Host "`n--- MODE SELECTION ---" -ForegroundColor Cyan
Write-Host "  I = Interactive (pause at each section, confirm before applying)" -ForegroundColor Gray
Write-Host "  A = Automatic   (apply all sections without pausing)" -ForegroundColor Gray
$ModeChoice  = Read-Host "Select mode (I/A)"
$Interactive = ($ModeChoice -eq "I" -or $ModeChoice -eq "i")

if ($Interactive) {
    Write-Host "`nInteractive mode. You will be prompted before each section." -ForegroundColor Yellow
    $ModeUsed = "Interactive"
} else {
    Write-Host "`nAutomatic mode. All sections will be applied." -ForegroundColor Green
}


# =============================================================================
# PHASE 1: APPLY HARDENING
# Wrapped in try/finally to ensure Windows Update is always re-enabled
# =============================================================================
Write-Host "`n--- PHASE 1: APPLYING HARDENING ---" -ForegroundColor Cyan

try {

# -----------------------------------------------------------------------------
# SECTION 1: THUMBNAIL CACHE
# -----------------------------------------------------------------------------
Write-Host "`n[1/17] Thumbnail Cache..." -ForegroundColor Yellow

if (Should-Skip "ThumbnailCache") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "ThumbnailCache" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Thumbnail Cache" `
    -Info "Windows Explorer generates thumbnail images of photos, videos, and documents and stores them in thumbcache_*.db in AppData. This database persists even after original files are deleted. A forensic examiner can extract it to see images of files that no longer exist on the system." `
    -Benefits "Disabling thumbnail caching prevents creation of this forensic artefact. Existing cache files are deleted. Reduces unnecessary disk writes. No meaningful performance impact on modern SSDs." `
    -Considerations "Applied via HKCU registry key so applies to whoever runs the script only. Explorer thumbnails still display for the current session until restarted. After reboot, folder views show generic icons for image files instead of previews.") {

    $ThumbKey = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
    If (!(Test-Path $ThumbKey)) { New-Item -Path $ThumbKey -Force | Out-Null }
    Set-ItemProperty -Path $ThumbKey -Name "DisableThumbnails" -Value 1 -Type DWord
    $ThumbDB = "$AdminProfile\AppData\Local\Microsoft\Windows\Explorer"
    If (Test-Path $ThumbDB) {
        Get-ChildItem "$ThumbDB\thumbcache_*.db" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "ThumbnailCache" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "ThumbnailCache" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 2: WINDOWS SEARCH INDEX
# -----------------------------------------------------------------------------
Write-Host "`n[2/17] Windows Search Index..." -ForegroundColor Yellow

if (Should-Skip "WindowsSearch") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "WindowsSearch" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Windows Search Index" `
    -Info "Windows Search maintains a database of metadata about files including names, content, authors, and dates. The WSearch service runs constantly in the background. The index database Windows.edb can be several gigabytes." `
    -Benefits "Disabling the index removes a persistent metadata store that documents file activity. Frees significant disk space. Reduces background CPU and disk usage. Start menu app search remains fast on SSD machines without the index." `
    -Considerations "File content search in File Explorer will no longer work. Start menu app search still works. Outlook search may be slower for large mailboxes. Enterprise environments may have GPO that re-enables WSearch after reboot.") {

    Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
    $IndexDB = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
    If (Test-Path $IndexDB) { Remove-Item $IndexDB -Force -ErrorAction SilentlyContinue }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "WindowsSearch" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "WindowsSearch" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 3: HIBERNATION AND FAST STARTUP
# -----------------------------------------------------------------------------
Write-Host "`n[3/17] Hibernation and Fast Startup..." -ForegroundColor Yellow

if (Should-Skip "Hibernation") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "Hibernation" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Hibernation and Fast Startup" `
    -Info "Hibernation saves entire RAM contents to hiberfil.sys on the system drive, as large as total installed RAM. Fast Startup uses a partial hibernate to speed up boot times by saving the kernel session to disk." `
    -Benefits "hiberfil.sys contains a complete RAM snapshot including encryption keys and credentials. Deleting it removes this forensic artefact and reclaims disk space. Fast Startup can cause issues with BitLocker and dual-boot setups." `
    -Considerations "If the machine uses hibernate for power saving (lid close on a laptop) this will change that behaviour. Sleep (RAM-powered) still works. On SSD machines boot time difference is imperceptible. Do not apply if hibernate is used intentionally.") {

    powercfg /h off 2>$null
    $FastStartup = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    Set-ItemProperty -Path $FastStartup -Name "HiberbootEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "Hibernation" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "Hibernation" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 4: TELEMETRY
# -----------------------------------------------------------------------------
Write-Host "`n[4/17] Telemetry..." -ForegroundColor Yellow

if (Should-Skip "Telemetry") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "Telemetry" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Telemetry" `
    -Info "Windows collects and transmits diagnostic and usage data to Microsoft continuously via the DiagTrack service. This includes app usage, hardware configuration, error reports, browser history via Edge, search queries, and behavioural patterns. Data is queued locally before being sent." `
    -Benefits "Setting AllowTelemetry to 0 instructs Windows to collect and transmit minimum data. Stopping DiagTrack prevents the service from running. Clearing the Diagnosis folder removes queued data. Reduces background network activity." `
    -Considerations "On Windows 11 Home and Pro, value 0 is the most restrictive available. Microsoft may still collect some data. On child accounts managed via Microsoft Family Safety, AllowTelemetry 0 may interfere with activity reporting. Use value 1 on Family Safety machines.") {

    $TelemetryKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    If (!(Test-Path $TelemetryKey)) { New-Item -Path $TelemetryKey -Force | Out-Null }
    Set-ItemProperty -Path $TelemetryKey -Name "AllowTelemetry" -Value 0 -Type DWord
    Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    $DiagFolder = "C:\ProgramData\Microsoft\Diagnosis"
    If (Test-Path $DiagFolder) {
        Get-ChildItem $DiagFolder -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "Telemetry" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "Telemetry" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 5: WINDOWS ERROR REPORTING
# -----------------------------------------------------------------------------
Write-Host "`n[5/17] Windows Error Reporting..." -ForegroundColor Yellow

if (Should-Skip "ErrorReporting") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "ErrorReporting" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Windows Error Reporting" `
    -Info "When an application crashes, WER packages a diagnostic report that can include a full or partial memory dump. Memory dumps can contain sensitive data including credentials, encryption keys, and document contents that were in memory at the time of the crash." `
    -Benefits "Disabling WER prevents memory dumps from being created and sent to Microsoft. Clears existing dumps. Removes the 'Windows is looking for a solution' dialog after crashes. Reduces data exfiltration risk from crash artefacts." `
    -Considerations "Disabling WER removes the ability to receive suggested fixes from Microsoft based on crash data. Developers or IT support staff who rely on crash dump analysis will lose that capability. Application stability is not affected.") {

    Stop-Service -Name "WerSvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WerSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    $WERKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    If (!(Test-Path $WERKey)) { New-Item -Path $WERKey -Force | Out-Null }
    Set-ItemProperty -Path $WERKey -Name "Disabled" -Value 1 -Type DWord
    foreach ($folder in @(
        "C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
        "C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
        "$AdminProfile\AppData\Local\CrashDumps"
    )) {
        If (Test-Path $folder) {
            Get-ChildItem $folder -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "ErrorReporting" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "ErrorReporting" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 6: PREFETCH AND SUPERFETCH
# -----------------------------------------------------------------------------
Write-Host "`n[6/17] Prefetch and Superfetch..." -ForegroundColor Yellow

if (Should-Skip "Prefetch") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "Prefetch" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Prefetch and Superfetch (SysMain)" `
    -Info "Windows Prefetch logs every executable that has run, when it ran, and how many times. SysMain analyses usage patterns and preloads frequently used applications into RAM. Together these create detailed forensic logs of system activity." `
    -Benefits "Disabling Prefetch removes a log that records every programme ever executed including deleted malware. On SSD machines application load times are already fast enough. Disabling SysMain frees RAM used for speculative preloading." `
    -Considerations "On HDD-based machines disabling Superfetch will noticeably slow application launch times. Only disable on SSD machines. Setting EnablePrefetcher to 0 disables both Prefetch file creation and the boot prefetcher.") {

    $PrefetchKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    Set-ItemProperty -Path $PrefetchKey -Name "EnablePrefetcher" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $PrefetchKey -Name "EnableSuperfetch" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
    $PrefetchFolder = "C:\Windows\Prefetch"
    If (Test-Path $PrefetchFolder) {
        Get-ChildItem $PrefetchFolder -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "Prefetch" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "Prefetch" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 7: RECENT FILES AND JUMP LISTS
# -----------------------------------------------------------------------------
Write-Host "`n[7/17] Recent Files, Jump Lists and Orphaned Run Keys..." -ForegroundColor Yellow

if (Should-Skip "RecentFiles") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "RecentFiles" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Recent Files, Jump Lists and Orphaned Run Keys" `
    -Info "Windows maintains a history of recently opened files and applications in the RecentDocs registry key, the Recent folder, and Jump List databases. These create a ready-made timeline of user activity. Orphaned Run keys are startup entries left behind by uninstalled software." `
    -Benefits "Disabling recent document tracking prevents Windows from building an activity timeline going forward. Clearing existing files removes the current history. Removing orphaned Run keys eliminates startup errors and reduces boot time." `
    -Considerations "Run key cleanup operates on the current session HKCU hive only and targets common orphaned keys. No hardcoded SIDs are used so this is safe on any machine. Users who rely on Quick Access in File Explorer to navigate recent files will lose that convenience.") {

    $RecentKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $RecentKey -Name "Start_TrackDocs" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    foreach ($folder in @(
        "$AdminProfile\AppData\Roaming\Microsoft\Windows\Recent",
        "$AdminProfile\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
        "$AdminProfile\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
    )) {
        If (Test-Path $folder) {
            Get-ChildItem $folder -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name * -ErrorAction SilentlyContinue

    function Test-StartupCommandTargetExists {
        param([string]$Command)
        if ([string]::IsNullOrWhiteSpace($Command)) { return $false }
        $Expanded = [Environment]::ExpandEnvironmentVariables($Command)
        $ExePath = $null
        if ($Expanded -match '^\s*"([^"]+\.exe)"') { $ExePath = $Matches[1] }
        elseif ($Expanded -match '^\s*([^\s]+\.exe)') { $ExePath = $Matches[1] }
        elseif ($Expanded -match '^\s*([^\s]+\.(cmd|bat|ps1))') { $ExePath = $Matches[1] }
        if (!$ExePath) { return $true }
        return (Test-Path $ExePath)
    }

    foreach ($RunPath in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
        $RunProps = Get-ItemProperty -Path $RunPath -ErrorAction SilentlyContinue
        if (!$RunProps) { continue }
        foreach ($key in @("Teams","OneDrive")) {
            $Prop = $RunProps.PSObject.Properties[$key]
            if ($Prop -and -not (Test-StartupCommandTargetExists $Prop.Value)) {
                Remove-ItemProperty -Path $RunPath -Name $key -ErrorAction SilentlyContinue
                Write-Host "  Removed orphaned startup entry: $key" -ForegroundColor Green
            }
        }
    }
    $RunProps = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($RunProps) {
        $RunProps.PSObject.Properties | Where-Object { $_.Name -like "MicrosoftEdgeAutoLaunch*" } | ForEach-Object {
            Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "RecentFiles" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "RecentFiles" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 8: LOCATION TRACKING
# -----------------------------------------------------------------------------
Write-Host "`n[8/17] Location Tracking..." -ForegroundColor Yellow

if (Should-Skip "LocationTracking") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "LocationTracking" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Location Tracking" `
    -Info "Windows includes a location service that allows applications to request the device's physical location via GPS, WiFi triangulation, or IP geolocation. Location history is stored locally and can be queried by applications in the background without prominent user notification." `
    -Benefits "Disabling location services prevents applications from accessing location data silently. Clearing the history log removes stored location records. Reduces the amount of sensitive personal data stored on the machine." `
    -Considerations "Applied via Group Policy registry keys which is more persistent than the Settings toggle. Apps that legitimately need location will stop working correctly. Microsoft Family Safety uses a separate location mechanism and is not affected.") {

    $LocationKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    If (!(Test-Path $LocationKey)) { New-Item -Path $LocationKey -Force | Out-Null }
    Set-ItemProperty -Path $LocationKey -Name "DisableLocation" -Value 1 -Type DWord
    $LocationHistory = "C:\ProgramData\Microsoft\Windows\LocationHistory"
    If (Test-Path $LocationHistory) {
        Get-ChildItem $LocationHistory -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "LocationTracking" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "LocationTracking" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 9: DELIVERY OPTIMISATION
# -----------------------------------------------------------------------------
Write-Host "`n[9/17] Delivery Optimisation..." -ForegroundColor Yellow

if (Should-Skip "DeliveryOptimisation") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "DeliveryOptimisation" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Delivery Optimisation" `
    -Info "Windows Delivery Optimisation uses your machine's internet connection as a peer-to-peer relay to distribute Windows updates to other computers, both on your local network and across the internet. Enabled by default with no prominent notification. Can consume significant bandwidth and disk space." `
    -Benefits "Disabling stops your machine acting as an upload relay for Microsoft's update distribution network. Prevents unexpected bandwidth consumption. Clears the local cache. Your machine still receives its own updates normally." `
    -Considerations "DoSvc resists being disabled via Set-Service even as Administrator. The registry Start value is set directly to 4 (Disabled). A reboot is required for full effect. In enterprise environments this may conflict with WSUS or Intune-managed update policies.") {

    $DOKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    If (!(Test-Path $DOKey)) { New-Item -Path $DOKey -Force | Out-Null }
    Set-ItemProperty -Path $DOKey -Name "DODownloadMode" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name "Start" -Value 4 -ErrorAction SilentlyContinue
    $DOCache = "C:\Windows\SoftwareDistribution\DeliveryOptimization"
    If (Test-Path $DOCache) {
        Get-ChildItem $DOCache -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "DeliveryOptimisation" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "DeliveryOptimisation" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 10: ACTIVITY HISTORY AND CONNECTED DEVICES PLATFORM
# -----------------------------------------------------------------------------
Write-Host "`n[10/17] Activity History and CDP..." -ForegroundColor Yellow

if (Should-Skip "ActivityHistory") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "ActivityHistory" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Activity History and Connected Devices Platform" `
    -Info "Windows Activity History logs every app opened, file accessed, and website visited in Edge, syncing to Microsoft servers when signed into a Microsoft account. CDP services (CDPSvc and CDPUserSvc) manage device connectivity and this activity data. The database ActivitiesCache.db is stored in ConnectedDevicesPlatform." `
    -Benefits "Disabling activity history prevents creation of a detailed usage timeline. Stopping CDP services closes the sync channel to Microsoft. Deleting the ConnectedDevicesPlatform folder removes the existing activity database." `
    -Considerations "CDPSvc resists Set-Service even as Administrator. The registry Start value is set directly to 4. The CDP folder must be deleted while CDP services are stopped otherwise ActivitiesCache.db will be locked. Does not affect OneDrive, Microsoft 365, or standard Windows functionality.") {

    $ActivityKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    If (!(Test-Path $ActivityKey)) { New-Item -Path $ActivityKey -Force | Out-Null }
    Set-ItemProperty -Path $ActivityKey -Name "EnableActivityFeed" -Value 0 -Type DWord
    Set-ItemProperty -Path $ActivityKey -Name "PublishUserActivities" -Value 0 -Type DWord
    Set-ItemProperty -Path $ActivityKey -Name "UploadUserActivities" -Value 0 -Type DWord
    Stop-Service -Name "CDPUserSvc" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "CDPSvc" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc" -Name "Start" -Value 4 -ErrorAction SilentlyContinue
    $CDPFolder = "$AdminProfile\AppData\Local\ConnectedDevicesPlatform"
    If (Test-Path $CDPFolder) { Remove-Item $CDPFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "ActivityHistory" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "ActivityHistory" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 11: WINDOWS INK AND HANDWRITING
# -----------------------------------------------------------------------------
Write-Host "`n[11/17] Windows Ink and Handwriting..." -ForegroundColor Yellow

if (Should-Skip "WindowsInk") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "WindowsInk" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Windows Ink and Handwriting Personalisation" `
    -Info "Windows Ink Workspace is designed for stylus and touchscreen use and phones home with usage analytics. Windows Handwriting Personalisation collects samples of everything you type or write to improve handwriting recognition, stored in the InputPersonalization folder." `
    -Benefits "Disabling Windows Ink removes an unnecessary background process on machines without a touchscreen or stylus. Disabling handwriting personalisation stops collection of typed and written input samples. Clearing the InputPersonalization folder removes previously collected samples." `
    -Considerations "On touchscreen or stylus machines, disabling Windows Ink removes convenient access to sketchpad and screen sketch tools. Handwriting recognition accuracy may decrease over time though pre-trained models remain functional.") {

    $InkKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    If (!(Test-Path $InkKey)) { New-Item -Path $InkKey -Force | Out-Null }
    Set-ItemProperty -Path $InkKey -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
    foreach ($folder in @(
        "$AdminProfile\AppData\Roaming\Microsoft\InputPersonalization",
        "$AdminProfile\AppData\Local\Microsoft\InputPersonalization"
    )) {
        If (Test-Path $folder) {
            Get-ChildItem $folder -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "WindowsInk" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "WindowsInk" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 12: NETWORK HARDENING - LLMNR AND NETBIOS
# -----------------------------------------------------------------------------
Write-Host "`n[12/17] Network Hardening (LLMNR and NetBIOS)..." -ForegroundColor Yellow

if (Should-Skip "NetworkHardening") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "NetworkHardening" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Network Hardening - LLMNR and NetBIOS" `
    -Info "LLMNR resolves hostnames on the local network when DNS fails by broadcasting a query to the entire subnet. An attacker running Responder on the same subnet can respond to these broadcasts and capture NTLMv2 credential hashes. LLMNR has been a standard internal pentest initial access technique for over a decade. NetBIOS broadcasts your machine name, domain name, and logged-on username." `
    -Benefits "Disabling LLMNR via the EnableMulticast policy key prevents Windows from sending or responding to LLMNR broadcasts, eliminating the Responder attack surface. Disabling NetBIOS via WMI SetTcpipNetbios applies to all active network adapters including VPN and virtual adapters. Both changes take effect immediately." `
    -Considerations "LLMNR is only used when DNS resolution fails. On a correctly configured network with working DNS, disabling LLMNR has no functional impact. NetBIOS is required for legacy SMB1 file sharing in very old environments. Modern SMB2/3 does not require NetBIOS.") {

    $DNSClientKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    If (!(Test-Path $DNSClientKey)) { New-Item -Path $DNSClientKey -Force | Out-Null }
    Set-ItemProperty -Path $DNSClientKey -Name "EnableMulticast" -Value 0 -Type DWord
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) { $adapter.SetTcpipNetbios(2) | Out-Null }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "NetworkHardening" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "NetworkHardening" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 13: POWER PLAN
# -----------------------------------------------------------------------------
Write-Host "`n[13/17] Power Plan..." -ForegroundColor Yellow

if (Should-Skip "PowerPlan") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "PowerPlan" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Power Plan" `
    -Info "Windows power plans control CPU frequency scaling, disk spin-down, display sleep, and other hardware behaviour. The default Balanced plan reduces CPU clock speeds during low-load periods. Ultimate Performance is a hidden plan that keeps CPU at maximum frequency at all times. The script auto-detects whether a battery is present and selects the appropriate plan." `
    -Benefits "Ultimate Performance eliminates CPU frequency scaling latency. High Performance is used on laptops as a compromise between responsiveness and battery life. Battery detection is automatic via WMI Win32_Battery." `
    -Considerations "Ultimate Performance should never be used on a battery-powered device as it significantly reduces battery life. If a battery is detected, High Performance is applied instead. The powercfg /duplicatescheme command creates a new plan with a random GUID each time if Ultimate Performance does not already exist.") {

    $IsBattery = (Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue) -ne $null
    if ($IsBattery) {
        $HighPerf = powercfg /list 2>$null | Select-String "High performance"
        if ($HighPerf) {
            $PlanGUID = ($HighPerf -split '\s+')[3]
            powercfg /setactive $PlanGUID 2>$null
            Write-Host "  Battery detected. High Performance plan activated." -ForegroundColor Green
        }
    } else {
        $ExistingUltimate = powercfg /list 2>$null | Select-String "Ultimate Performance"
        if ($ExistingUltimate) {
            $PlanGUID = ($ExistingUltimate -split '\s+')[3]
            powercfg /setactive $PlanGUID 2>$null
            Write-Host "  Ultimate Performance already present. Activated." -ForegroundColor Green
        } else {
            $NewPlan = powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
            if ($NewPlan) {
                $PlanGUID = ($NewPlan | Select-String -Pattern '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}').Matches[0].Value
                powercfg /setactive $PlanGUID 2>$null
                Write-Host "  Ultimate Performance plan created and activated." -ForegroundColor Green
            }
        }
    }
    Record-Section "PowerPlan" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "PowerPlan" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 14: SCHEDULED TASK CLEANUP
# -----------------------------------------------------------------------------
Write-Host "`n[14/17] Scheduled Task Cleanup..." -ForegroundColor Yellow

if (Should-Skip "TaskCleanup") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "TaskCleanup" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Scheduled Task Cleanup" `
    -Info "Third-party software installers often register scheduled tasks that run in the background without user awareness. SoftLanding is OEM bloatware installed by some laptop manufacturers that manages software promotions. CCleanerSkipUAC allows CCleaner to bypass User Account Control prompts by running with elevated privileges without triggering a UAC dialog." `
    -Benefits "Removing SoftLanding eliminates an unnecessary background process. Removing CCleanerSkipUAC closes a UAC bypass that contradicts the security model. UAC exists to require explicit approval for privilege elevation." `
    -Considerations "These tasks are removed only if they exist. Safe on any machine regardless of what software is installed. CCleaner will continue to function normally after CCleanerSkipUAC is removed and will simply prompt for UAC approval as it should.") {

    foreach ($task in @("SoftLandingCreativeManagementTask","SoftLandingDeferralTask*","CCleanerSkipUAC*")) {
        $found = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        if ($found) {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "  Removed: $task" -ForegroundColor Green
        }
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "TaskCleanup" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "TaskCleanup" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 15: SERVICE DEPENDENCIES
# -----------------------------------------------------------------------------
Write-Host "`n[15/17] Service Dependencies..." -ForegroundColor Yellow

if (Should-Skip "ServiceDependencies") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "ServiceDependencies" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Service Dependencies" `
    -Info "Hardening scripts can inadvertently disable services that legitimate software depends on. This section checks for and protects three categories: OneDrive sync services (FileSyncHelper and OneSyncSvc), VMware virtualisation services (VMAuthdService), and YubiKey smart card services (SCardSvr and ScDeviceEnum). All checks are conditional and safe on machines without any of this software." `
    -Benefits "Prevents the common failure mode where hardening disables OneDrive sync services causing OneDrive to appear running but not actually syncing. Ensures VMware VMs remain usable. Enables smart card services automatically if YubiKey software is detected." `
    -Considerations "FileSyncHelper is reset to Automatic if disabled. OneSyncSvc is set to Manual (value 3) rather than Automatic because it is a per-session service. VMAuthdService is only touched if currently Disabled. YubiKey detection uses Get-Package to check for installed YubiKey Manager.") {

    foreach ($svc in @("FileSyncHelper","OneSyncSvc")) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s -and $s.StartType -eq "Disabled") {
            $startVal = if ($svc -eq "FileSyncHelper") { 2 } else { 3 }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name "Start" -Value $startVal -ErrorAction SilentlyContinue
            Start-Service -Name $svc -ErrorAction SilentlyContinue
            $Warnings += "$svc was Disabled. Reset. OneDrive sync should now work."
        }
    }
    $VMAuth = Get-Service -Name "VMAuthdService" -ErrorAction SilentlyContinue
    if ($VMAuth -and $VMAuth.StartType -eq "Disabled") {
        Set-Service -Name "VMAuthdService" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "VMAuthdService" -ErrorAction SilentlyContinue
        $Warnings += "VMAuthdService was Disabled. Reset to Automatic."
    }
    $YubiKeyInstalled = Get-Package -Name "*YubiKey*" -ErrorAction SilentlyContinue
    if ($YubiKeyInstalled) {
        Set-Service -Name "SCardSvr" -StartupType Automatic -ErrorAction SilentlyContinue
        Set-Service -Name "ScDeviceEnum" -StartupType Automatic -ErrorAction SilentlyContinue
        Write-Host "  YubiKey detected. Smart Card services set to Automatic." -ForegroundColor Green
    } else {
        Write-Host "  No YubiKey software detected. Smart Card services unchanged." -ForegroundColor Gray
    }
    Write-Host "  Done." -ForegroundColor Green
    Record-Section "ServiceDependencies" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "ServiceDependencies" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 16: AUDIT POLICY BASELINE
#
# INFO:
#   Windows audit policy controls what security events are written to the
#   Security Event Log. By default most audit categories are disabled,
#   meaning there is minimal forensic visibility into what happens on the
#   machine. Enabling a basic audit baseline means logon events, privilege
#   use, and policy changes are logged locally and can be reviewed if
#   something goes wrong post-hardening.
#
# BENEFITS:
#   Provides forensic visibility that is currently a known gap on hardened
#   machines. If an account is compromised or an unusual privilege escalation
#   occurs, the audit log gives you something to investigate. Logon event
#   auditing specifically captures failed login attempts which is useful
#   for detecting brute force attempts on local accounts.
#
# CONSIDERATIONS APPLYING:
#   Audit logging increases Security Event Log size over time. The default
#   log size may need to be increased if the machine is active. This can be
#   done via gpedit.msc > Windows Settings > Security Settings > Event Log.
#   Enabling too many audit categories on a busy machine can generate a very
#   large volume of events. This section enables only the most useful
#   categories: logon/logoff, account logon, privilege use, and policy change.
#   This is a deliberate minimal baseline, not a full audit configuration.
# -----------------------------------------------------------------------------
Write-Host "`n[16/17] Audit Policy Baseline..." -ForegroundColor Yellow

if (Should-Skip "AuditPolicy") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "AuditPolicy" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "Audit Policy Baseline" `
    -Info "Windows audit policy controls what security events are written to the Security Event Log. By default most audit categories are disabled, meaning minimal forensic visibility into what happens on the machine. A basic audit baseline covers logon events, privilege use, and policy changes." `
    -Benefits "Provides forensic visibility that is currently a known gap. If an account is compromised or unusual privilege escalation occurs, the audit log gives you something to investigate. Logon event auditing captures failed login attempts useful for detecting brute force attempts on local accounts." `
    -Considerations "Audit logging increases Security Event Log size over time. The default log size may need increasing if the machine is very active. This section enables only the most useful categories as a minimal baseline: logon/logoff, account logon, privilege use, and policy change.") {

    # Enable basic audit categories via auditpol
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
    auditpol /set /subcategory:"Logoff" /success:enable 2>$null
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>$null
    auditpol /set /subcategory:"Special Logon" /success:enable 2>$null
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable 2>$null
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable 2>$null
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable 2>$null
    auditpol /set /subcategory:"Security Group Management" /success:enable 2>$null
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>$null

    Write-Host "  Audit policy baseline applied." -ForegroundColor Green
    Write-Host "  Categories enabled: Logon, Logoff, Account Lockout, Privilege Use, Policy Change, Account Management." -ForegroundColor Gray
    Record-Section "AuditPolicy" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "AuditPolicy" "SKIPPED" }


# -----------------------------------------------------------------------------
# SECTION 17: DNS OVER HTTPS (SYSTEM-WIDE)
#
# INFO:
#   By default Windows resolves DNS queries in plaintext via the OS DNS
#   client, which sends queries to whatever DNS server the network provides.
#   This means your ISP or network operator can see every domain you visit.
#   Windows 11 supports DNS over HTTPS (DoH) natively at the OS level,
#   encrypting DNS queries before they leave the machine. This is separate
#   from browser-level DoH settings.
#
# BENEFITS:
#   Encrypts all DNS queries from the OS itself, not just the browser.
#   Prevents your ISP or local network from logging your DNS queries.
#   Uses Cloudflare 1.1.1.1 which has a strong privacy policy and does
#   not log queries. Applies to every application on the machine, not
#   just the browser, closing the gap left by browser-only DoH settings.
#
# CONSIDERATIONS APPLYING:
#   System-wide DoH is configured via registry under the DnsCache service.
#   The DoH server URL must be pre-registered in the Windows DoH server list
#   or added manually. Cloudflare (1.1.1.1) and Google (8.8.8.8) are both
#   pre-registered in Windows 11. A reboot is required for this to take full
#   effect. This setting does not affect applications that implement their
#   own DNS resolution stack (some corporate VPN clients do this).
#   If the machine is on a corporate network with internal DNS, enabling
#   system-wide DoH may break internal name resolution. Check with the
#   network team before applying in an enterprise environment.
# -----------------------------------------------------------------------------
Write-Host "`n[17/17] DNS over HTTPS (System-wide)..." -ForegroundColor Yellow

if (Should-Skip "DoH") {
    Write-Host "  Already completed in previous run. Skipping." -ForegroundColor DarkGray
    Record-Section "DoH" "RESUMED-SKIP"
} elseif (Confirm-Section -SectionName "DNS over HTTPS (System-wide)" `
    -Info "By default Windows resolves DNS queries in plaintext, meaning your ISP or network operator can see every domain you visit. Windows 11 supports DNS over HTTPS natively at the OS level, encrypting DNS queries before they leave the machine. This is separate from browser-level DoH settings and applies to all applications." `
    -Benefits "Encrypts all DNS queries from the OS, not just the browser. Prevents ISP or local network from logging DNS queries. Uses Cloudflare 1.1.1.1 which has a strong privacy policy. Applies to every application on the machine closing the gap left by browser-only DoH." `
    -Considerations "A reboot is required for full effect. If the machine is on a corporate network with internal DNS, enabling system-wide DoH may break internal name resolution. Check with the network team before applying in an enterprise environment. Does not affect apps with their own DNS implementation.") {

    # Set DoH policy for Cloudflare 1.1.1.1
    $DoHKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    Set-ItemProperty -Path $DoHKey -Name "EnableAutoDoh" -Value 2 -Type DWord -ErrorAction SilentlyContinue

    # Register Cloudflare DoH server
    $CloudflareDoH = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\1.1.1.1"
    If (!(Test-Path $CloudflareDoH)) { New-Item -Path $CloudflareDoH -Force | Out-Null }
    Set-ItemProperty -Path $CloudflareDoH -Name "DohFlags" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $CloudflareDoH -Name "Template" -Value "https://cloudflare-dns.com/dns-query" -Type String -ErrorAction SilentlyContinue

    $ActivePhysicalAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    foreach ($Adapter in $ActivePhysicalAdapters) {
        Set-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
    }

    Write-Host "  DoH configured. Using Cloudflare 1.1.1.1. Reboot required to take full effect." -ForegroundColor Green
    Record-Section "DoH" "APPLIED"
} else { Write-Host "  Skipped." -ForegroundColor DarkGray; Record-Section "DoH" "SKIPPED" }


} finally {
    # Always restore Windows Update to its original startup and running state.
    Write-Host "`nRestoring Windows Update service state..." -ForegroundColor Gray
    Restore-WindowsUpdateService
    Write-Host "  Windows Update service restored to pre-run state." -ForegroundColor Green
    Write-Progress-Log "Windows Update service restored."
}


# =============================================================================
# PHASE 2: VERIFY STATE
# =============================================================================
Write-Host "`n--- PHASE 2: VERIFYING STATE ---" -ForegroundColor Cyan

$VerifyFailed = @()

foreach ($svc in @("WSearch","DiagTrack","WerSvc","SysMain")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.StartType -ne "Disabled") { $VerifyFailed += "FAIL: $svc should be Disabled but is $($s.StartType)" }
    else { Write-Host "  OK: $svc Disabled" -ForegroundColor Green }
}

# CDPUserSvc is a per-user service with a dynamic suffix (e.g. CDPUserSvc_1a2b3c)
# Check via registry Start value rather than service name match
$CDPUserSvcStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc" -Name "Start" -ErrorAction SilentlyContinue).Start
if ($CDPUserSvcStart -ne 4) { Write-Host "  NOTE: CDPUserSvc template not fully disabled - this is expected on some builds. Check CDPSvc registry instead." -ForegroundColor Yellow }
else { Write-Host "  OK: CDPUserSvc Disabled (registry template)" -ForegroundColor Green }

$DoSvcStart  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc"  -Name "Start" -ErrorAction SilentlyContinue).Start
$CDPSvcStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc" -Name "Start" -ErrorAction SilentlyContinue).Start
if ($DoSvcStart  -ne 4) { $VerifyFailed += "FAIL: DoSvc registry Start should be 4 but is $DoSvcStart" }
else { Write-Host "  OK: DoSvc Disabled (registry)" -ForegroundColor Green }
if ($CDPSvcStart -ne 4) { $VerifyFailed += "FAIL: CDPSvc registry Start should be 4 but is $CDPSvcStart" }
else { Write-Host "  OK: CDPSvc Disabled (registry)" -ForegroundColor Green }

$FSync = Get-Service -Name "FileSyncHelper" -ErrorAction SilentlyContinue
if ($FSync -and $FSync.Status -ne "Running") { $VerifyFailed += "FAIL: FileSyncHelper not Running. OneDrive sync will not work." }
elseif ($FSync) { Write-Host "  OK: FileSyncHelper Running" -ForegroundColor Green }

$LLMNR = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
if ($LLMNR -ne 0) { $VerifyFailed += "FAIL: LLMNR EnableMulticast should be 0 but is $LLMNR" }
else { Write-Host "  OK: LLMNR disabled" -ForegroundColor Green }

$NetBIOSBad = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true -and $_.TcpipNetbiosOptions -ne 2}
if ($NetBIOSBad) { $VerifyFailed += "FAIL: NetBIOS still active on: $($NetBIOSBad.Description -join ', ')" }
else { Write-Host "  OK: NetBIOS disabled on all adapters" -ForegroundColor Green }

$Telemetry = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
if ($Telemetry -ne 0) { $VerifyFailed += "FAIL: AllowTelemetry should be 0 but is $Telemetry" }
else { Write-Host "  OK: Telemetry disabled" -ForegroundColor Green }

if (Test-Path "C:\hiberfil.sys") { $VerifyFailed += "FAIL: hiberfil.sys still exists. Reboot may be required." }
else { Write-Host "  OK: Hibernation disabled" -ForegroundColor Green }

$BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($BitLocker -and $BitLocker.ProtectionStatus -eq "On") { Write-Host "  OK: BitLocker active on C:" -ForegroundColor Green }
else { $VerifyFailed += "FAIL: BitLocker is not active on C:. Enable immediately." }

$DoHValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -ErrorAction SilentlyContinue).EnableAutoDoh
$CloudflareDnsActive = $false
$ActivePhysicalAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
foreach ($Adapter in $ActivePhysicalAdapters) {
    $DnsServers = (Get-DnsClientServerAddress -InterfaceIndex $Adapter.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object { $_.AddressFamily -eq 2 }).ServerAddresses
    if ($DnsServers -contains "1.1.1.1") { $CloudflareDnsActive = $true }
}
if ($DoHValue -eq 2 -and $CloudflareDnsActive) { Write-Host "  OK: DNS over HTTPS enabled with Cloudflare DNS on active physical adapter" -ForegroundColor Green }
else { $VerifyFailed += "FAIL: DNS over HTTPS/Cloudflare DNS not configured. Reboot may be required or section was skipped." }

$SuspiciousTasks = Get-ScheduledTask | Where-Object {
    $_.State -ne "Disabled" -and
    $_.TaskPath -notlike "\Microsoft\*" -and
    $_.TaskName -notlike "CCleaner*" -and
    $_.TaskName -notlike "Dropbox*" -and
    $_.TaskName -notlike "Google*" -and
    $_.TaskName -notlike "*Winget*" -and
    $_.TaskName -notlike "*Backup*" -and
    $_.TaskName -notlike "*Cleanup*" -and
    $_.TaskName -notlike "NordVPN*" -and
    $_.TaskName -notlike "*Canon*" -and
    $_.TaskName -notlike "*Intel*" -and
    $_.TaskName -notlike "MicrosoftEdge*" -and
    $_.TaskName -notlike "OneDrive*"
}
if ($SuspiciousTasks) {
    foreach ($t in $SuspiciousTasks) { $VerifyFailed += "REVIEW: Unexpected task: $($t.TaskName) at $($t.TaskPath)" }
} else { Write-Host "  OK: No unexpected scheduled tasks" -ForegroundColor Green }

if ($VerifyFailed.Count -gt 0) {
    Write-Host "`n  VERIFICATION FAILURES:" -ForegroundColor Red
    foreach ($f in $VerifyFailed) { Write-Host "  $f" -ForegroundColor Red }
} else {
    Write-Host "`n  All verification checks passed." -ForegroundColor Green
}

Write-Progress-Log "Phase 2 verification complete. Failures: $($VerifyFailed.Count)"


# =============================================================================
# PHASE 3: BACKUP EXPORT
# =============================================================================
Write-Host "`n--- PHASE 3: EXPORTING BACKUP ---" -ForegroundColor Cyan

$RegistryExports = @{
    "Telemetry"            = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    "PrefetchParameters"   = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    "ActivityHistory"      = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
    "DeliveryOptimisation" = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    "WindowsInk"           = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    "ErrorReporting"       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    "LLMNR"                = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    "LocationTracking"     = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    "DoH"                  = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
}

foreach ($Name in $RegistryExports.Keys) {
    $OutFile = "$BackupPath\Registry_$Name.reg"
    reg export $RegistryExports[$Name] $OutFile /y 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "  Exported: $Name" -ForegroundColor Green }
    else { Write-Host "  Skipped (key not found): $Name" -ForegroundColor Yellow }
}

gpresult /h "$BackupPath\GroupPolicy_Report.html" /f 2>$null
Write-Host "  GPO report exported." -ForegroundColor Green

secedit /export /cfg "$BackupPath\SecurityPolicy.cfg" /quiet
Write-Host "  Security policy exported." -ForegroundColor Green

$MonitoredServices = @("WSearch","DiagTrack","WerSvc","SysMain","DoSvc","CDPSvc","CDPUserSvc","FileSyncHelper","OneSyncSvc","VMAuthdService","SCardSvr","ScDeviceEnum")
$ServicesReport = @()
foreach ($SvcName in $MonitoredServices) {
    $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($Svc) {
        $ServicesReport += [PSCustomObject]@{ Name = $Svc.Name; Display = $Svc.DisplayName; Status = $Svc.Status; StartType = $Svc.StartType }
    }
}
$ServicesReport | Export-Csv "$BackupPath\Services_State.csv" -NoTypeInformation
Write-Host "  Services state exported." -ForegroundColor Green

$VerifyStatus = if ($VerifyFailed.Count -eq 0) { "All checks passed." } else { "$($VerifyFailed.Count) failure(s) detected." }

$Summary = @"
Portable Windows Hardening - State Backup
Date: $Date
Machine: $MachineName
Admin user: $AdminUser
Run mode: $ModeUsed
Script base: $ScriptBase
Verification: $VerifyStatus

HARDENING APPLIED
1.  Thumbnail cache disabled and cleared
2.  Windows Search disabled and index database deleted
3.  Hibernation disabled. Fast Startup disabled
4.  Telemetry set to 0. DiagTrack service disabled
5.  Windows Error Reporting disabled. Dump folders cleared
6.  Prefetch and Superfetch disabled. SysMain service disabled
7.  Recent files, Jump Lists, and orphaned run keys cleared
8.  Location tracking disabled and history cleared
9.  Delivery Optimisation disabled. DoSvc disabled via registry
10. Activity History disabled. CDPSvc disabled via registry. CDP folder deleted
11. Windows Ink disabled. Handwriting data cleared
12. LLMNR disabled via registry. NetBIOS disabled on all adapters
13. Power plan set automatically (Ultimate on desktop, High Performance on laptop)
14. Bloatware scheduled tasks removed if present
15. OneDrive, VMware, and YubiKey service dependencies protected
16. Audit policy baseline applied (Logon, Privilege Use, Policy Change, Account Management)
17. DNS over HTTPS configured system-wide (Cloudflare 1.1.1.1)

RESTORE PROCEDURE ON REBUILD
1. Copy Harden-Windows-Portable-Documented.ps1 to the machine
2. Open PowerShell as Administrator
3. Unblock-File .\Harden-Windows-Portable-Documented.ps1
4. .\Harden-Windows-Portable-Documented.ps1
5. Select rollback if PRE-CHANGE-LATEST exists, or proceed with fresh hardening
6. Run each Registry_*.reg file as Administrator
7. In gpedit.msc reapply settings using GroupPolicy_Report.html as reference
8. Run: secedit /configure /db secedit.sdb /cfg SecurityPolicy.cfg

VERIFICATION RESULTS
$($VerifyFailed | ForEach-Object { "- $_" } | Out-String)
"@

$Summary | Out-File "$BackupPath\README.txt" -Encoding UTF8
Write-Host "  README written." -ForegroundColor Green
Write-Progress-Log "Phase 3 backup complete."


# =============================================================================
# PHASE 4: REGISTER SCHEDULED TASKS
#
# INFO:
#   Two weekly scheduled tasks are registered. The backup task is now fully
#   self-contained: it embeds the backup logic directly as a PowerShell
#   scriptblock saved to the Maintenance-Stuff folder at run time, so no
#   separate Backup-WindowsAdmin.ps1 file is required. The winget upgrade
#   task runs every Sunday at 09:00, one hour after the backup task, so
#   the two do not overlap. Both tasks run as SYSTEM and use
#   StartWhenAvailable so a missed run fires on next startup.
# =============================================================================
Write-Host "`n--- PHASE 4: REGISTERING SCHEDULED TASKS ---" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Embed backup logic directly into a script file written at runtime.
# This makes the portable script fully self-contained with no prerequisites.
# ---------------------------------------------------------------------------
$EmbeddedBackupScript = "$ScriptBase\Backup-WindowsAdmin.ps1"

$BackupScriptContent = @'
# =============================================================================
# Backup-WindowsAdmin.ps1 - Auto-generated by Harden-Windows-Portable-Documented.ps1
# Weekly state backup. Runs every Sunday at 08:00 via scheduled task.
# Do not delete this file. The WindowsAdminBackup scheduled task calls it directly.
# =============================================================================

$AdminUser    = $env:USERNAME
$Date         = Get-Date -Format "yyyy-MM-dd"
$OneDrivePath = $env:OneDrive
if (!$OneDrivePath) { $OneDrivePath = $env:OneDriveConsumer }
if (!$OneDrivePath) { $OneDrivePath = $env:OneDriveCommercial }

if ($OneDrivePath -and (Test-Path $OneDrivePath)) {
    $ScriptBase = "$OneDrivePath\Documents\Maintenance-Stuff"
} else {
    $ScriptBase = "C:\Maintenance-Stuff"
}

$BackupPath = "$ScriptBase\$Date"
New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null

$RegistryExports = @{
    "Telemetry"            = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    "PrefetchParameters"   = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    "ActivityHistory"      = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
    "DeliveryOptimisation" = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    "WindowsInk"           = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
    "ErrorReporting"       = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    "LLMNR"                = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    "LocationTracking"     = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
    "DoH"                  = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
}

foreach ($Name in $RegistryExports.Keys) {
    reg export $RegistryExports[$Name] "$BackupPath\Registry_$Name.reg" /y 2>$null
}

gpresult /h "$BackupPath\GroupPolicy_Report.html" /f 2>$null
secedit /export /cfg "$BackupPath\SecurityPolicy.cfg" /quiet

$MonitoredServices = @("WSearch","DiagTrack","WerSvc","SysMain","DoSvc","CDPSvc","CDPUserSvc","FileSyncHelper","OneSyncSvc","VMAuthdService","SCardSvr","ScDeviceEnum")
$ServicesReport = @()
foreach ($SvcName in $MonitoredServices) {
    $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($Svc) {
        $StartValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName" -Name "Start" -ErrorAction SilentlyContinue).Start
        $ServicesReport += [PSCustomObject]@{ Name = $Svc.Name; Display = $Svc.DisplayName; Status = $Svc.Status; StartType = $Svc.StartType; StartValue = $StartValue }
    }
}
$ServicesReport | Export-Csv "$BackupPath\Services_State.csv" -NoTypeInformation

"Weekly backup completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" | Out-File "$BackupPath\README.txt" -Encoding UTF8
'@

# Write the embedded backup script to Maintenance-Stuff
$BackupScriptContent | Out-File -FilePath $EmbeddedBackupScript -Encoding UTF8 -Force
Write-Host "  Backup script written to: $EmbeddedBackupScript" -ForegroundColor Green

# Register the backup scheduled task pointing to the embedded script
$BackupAction    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$EmbeddedBackupScript`""
$BackupTrigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "08:00"
$BackupPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$BackupSettings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -StartWhenAvailable
$ExistingBackup  = Get-ScheduledTask -TaskName "WindowsAdminBackup" -ErrorAction SilentlyContinue
if ($ExistingBackup) { Unregister-ScheduledTask -TaskName "WindowsAdminBackup" -Confirm:$false }
Register-ScheduledTask -TaskName "WindowsAdminBackup" -Description "Weekly state backup. Sunday 08:00. Catches up on next startup if missed." -Trigger $BackupTrigger -Action $BackupAction -Principal $BackupPrincipal -Settings $BackupSettings -Force | Out-Null
if (Get-ScheduledTask -TaskName "WindowsAdminBackup" -ErrorAction SilentlyContinue) {
    Write-Host "  WindowsAdminBackup registered. Runs Sunday 08:00." -ForegroundColor Green
} else {
    $Warnings += "WindowsAdminBackup task registration failed."
    Write-Host "  WARNING: WindowsAdminBackup task registration failed." -ForegroundColor Red
}

$WingetLogPath   = "$ScriptBase\winget-upgrade-log.txt"
$WingetAction    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"winget upgrade --all --accept-source-agreements --accept-package-agreements | Out-File '$WingetLogPath' -Append`""
$WingetTrigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "09:00"
$WingetPrincipal = New-ScheduledTaskPrincipal -UserId $CurrentUserId -LogonType Interactive -RunLevel Highest
$WingetSettings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -MultipleInstances IgnoreNew -StartWhenAvailable
$ExistingWinget  = Get-ScheduledTask -TaskName "WeeklyWingetUpgrade" -ErrorAction SilentlyContinue
if ($ExistingWinget) { Unregister-ScheduledTask -TaskName "WeeklyWingetUpgrade" -Confirm:$false }
Register-ScheduledTask -TaskName "WeeklyWingetUpgrade" -Description "Weekly winget upgrade. Sunday 09:00." -Trigger $WingetTrigger -Action $WingetAction -Principal $WingetPrincipal -Settings $WingetSettings -Force | Out-Null
if (Get-ScheduledTask -TaskName "WeeklyWingetUpgrade" -ErrorAction SilentlyContinue) {
    Write-Host "  WeeklyWingetUpgrade registered. Runs Sunday 09:00." -ForegroundColor Green
} else {
    $Warnings += "WeeklyWingetUpgrade task registration failed."
}

Write-Progress-Log "Phase 4 scheduled tasks registered."


# =============================================================================
# PHASE 5: WINDOWS UPDATE AND APPLICATION UPDATES
#
# INFO:
#   winget upgrade --all handles third-party application updates. However it
#   does not patch the Windows OS itself or drivers. PSWindowsUpdate is a
#   PowerShell module that interfaces with the Windows Update API directly,
#   allowing OS patches, driver updates, and Microsoft product updates to be
#   applied programmatically. A hardened but unpatched machine is still
#   vulnerable, so patching is considered part of the hardening process.
#
# BENEFITS:
#   Ensures the machine is fully patched at the OS level immediately after
#   hardening rather than waiting for the next automatic update cycle.
#   PSWindowsUpdate is installed from the PowerShell Gallery if not already
#   present. The update check runs non-interactively and logs results.
#   winget is also run here to patch any third-party applications that have
#   updates available at the time of hardening.
#
# CONSIDERATIONS APPLYING:
#   PSWindowsUpdate requires internet access to the Microsoft Update servers
#   and to the PowerShell Gallery (for module installation). If the machine
#   is air-gapped or behind a restrictive proxy, this phase may fail. Errors
#   are caught and logged but do not stop the script. Some Windows updates
#   require a reboot. The script lists any pending reboots at the end but
#   does not force one. Always review and reboot after the script completes
#   if updates were installed. The update phase can take significant time
#   depending on how many updates are pending.
# =============================================================================
Write-Host "`n--- PHASE 5: WINDOWS UPDATE AND APPLICATION UPDATES ---" -ForegroundColor Cyan

# Install PSWindowsUpdate module if not present
if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "  Installing PSWindowsUpdate module..." -ForegroundColor Yellow
    try {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
        Write-Host "  PSWindowsUpdate installed." -ForegroundColor Green
    } catch {
        Write-Host "  PSWindowsUpdate installation failed. Skipping OS update check." -ForegroundColor Red
        $Warnings += "PSWindowsUpdate could not be installed. Run Windows Update manually."
    }
}

if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    Write-Host "  Checking for Windows updates..." -ForegroundColor Yellow
    try {
        $Updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -ErrorAction Stop
        if ($Updates.Count -eq 0) {
            Write-Host "  No Windows updates pending. Machine is fully patched." -ForegroundColor Green
        } else {
            Write-Host "  $($Updates.Count) update(s) found. Installing..." -ForegroundColor Yellow
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue |
                ForEach-Object { Write-Host "  Installed: $($_.Title)" -ForegroundColor Green }
            $RebootRequired = (Get-WURebootStatus -Silent)
            if ($RebootRequired) {
                $Warnings += "Windows updates installed. A reboot is required to complete installation."
                Write-Host "  Reboot required after updates. Do not skip this." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  Windows Update check failed: $_" -ForegroundColor Red
        $Warnings += "Windows Update check failed. Run Windows Update manually via Settings."
    }
} else {
    Write-Host "  PSWindowsUpdate not available. Skipping OS update check." -ForegroundColor Yellow
}

# Run winget upgrade for third-party applications
Write-Host "`n  Running winget upgrade for third-party applications..." -ForegroundColor Yellow
try {
    winget upgrade --all --accept-source-agreements --accept-package-agreements 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Winget upgrade complete." -ForegroundColor Green
    } else {
        Write-Host "  Winget upgrade exited with code $LASTEXITCODE. Run manually: winget upgrade --all" -ForegroundColor Red
        $Warnings += "Winget upgrade exited with code $LASTEXITCODE. Run manually after script completes."
    }
} catch {
    Write-Host "  Winget upgrade failed. Run manually: winget upgrade --all" -ForegroundColor Red
    $Warnings += "Winget upgrade failed. Run manually after script completes."
}

Write-Progress-Log "Phase 5 update check complete."


# =============================================================================
# FINAL: COLOUR-CODED SUMMARY TABLE
# =============================================================================
Write-Host "`n--- FINAL SUMMARY ---" -ForegroundColor Cyan
Write-Host ("=" * 65) -ForegroundColor DarkGray
Write-Host ("{0,-35} {1,-15} {2}" -f "SECTION", "STATUS", "NOTE") -ForegroundColor White
Write-Host ("-" * 65) -ForegroundColor DarkGray

foreach ($result in $SectionResults) {
    $colour = switch ($result.Status) {
        "APPLIED"       { "Green" }
        "SKIPPED"       { "DarkGray" }
        "RESUMED-SKIP"  { "Gray" }
        default         { "Yellow" }
    }
    $note = switch ($result.Status) {
        "APPLIED"       { "Change applied successfully" }
        "SKIPPED"       { "Operator chose to skip" }
        "RESUMED-SKIP"  { "Already applied in previous run" }
        default         { "" }
    }
    Write-Host ("{0,-35} {1,-15} {2}" -f $result.Section, $result.Status, $note) -ForegroundColor $colour
}

Write-Host ("-" * 65) -ForegroundColor DarkGray
Write-Host "`nVERIFICATION:" -ForegroundColor White
if ($VerifyFailed.Count -eq 0) {
    Write-Host "  All checks passed." -ForegroundColor Green
} else {
    foreach ($f in $VerifyFailed) { Write-Host "  $f" -ForegroundColor Red }
}

if ($Warnings.Count -gt 0) {
    Write-Host "`nWARNINGS:" -ForegroundColor Yellow
    foreach ($w in $Warnings) { Write-Host "  $w" -ForegroundColor Yellow }
}

Write-Host "`nMachine:  $MachineName" -ForegroundColor Green
Write-Host "Admin:    $AdminUser" -ForegroundColor Green
Write-Host "Mode:     $ModeUsed" -ForegroundColor Green
Write-Host "Backup:   $BackupPath" -ForegroundColor Green
Write-Host "Scripts:  $ScriptBase" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor DarkGray

Write-Progress-Log "=== Hardening run completed. Verify failures: $($VerifyFailed.Count) ==="


# =============================================================================
# CIPHER FREE SPACE WIPE
#
# INFO:
#   When files are deleted in Windows, the file system marks the space as
#   available but does not immediately overwrite the data. The deleted file's
#   content remains on disk until that space is used by a new file. A forensic
#   tool can recover deleted files by reading unallocated space. cipher /w:C
#   performs a three-pass wipe writing 0x00, then 0xFF, then random data over
#   every sector of unallocated space on C:.
#
# BENEFITS:
#   Makes deleted files unrecoverable after hardening. Particularly useful
#   after clearing the thumbnail cache, prefetch files, activity history,
#   jump lists, and other forensic artefacts deleted in Phase 1. Without this
#   step, those deleted files may still be recoverable.
#
# CONSIDERATIONS APPLYING:
#   cipher /w typically takes 10 to 60 minutes depending on free space.
#   The window must remain open until it completes. It writes heavily to the
#   SSD but for a one-time post-hardening wipe this is not a meaningful
#   concern. Enter N to defer and run cipher /w:C manually when ready.
# =============================================================================
Write-Host "`n--- FINAL STEP: FREE SPACE WIPE ---" -ForegroundColor Cyan
Write-Host "cipher /w:C overwrites all deleted file remnants on C: drive." -ForegroundColor Yellow
Write-Host "This can take 10-60 minutes. Do not close this window while it runs." -ForegroundColor Yellow

$CipherChoice = Read-Host "Run cipher /w:C now? (Y/N)"
if ($CipherChoice -eq "Y" -or $CipherChoice -eq "y") {
    Write-Host "`nRunning cipher /w:C - do not close this window..." -ForegroundColor Cyan
    cipher /w:C
    Write-Host "`nFree space wipe complete." -ForegroundColor Green
    Write-Progress-Log "Cipher free space wipe completed."
} else {
    Write-Host "`nFree space wipe skipped. Run 'cipher /w:C' manually when ready." -ForegroundColor Yellow
    Write-Progress-Log "Cipher free space wipe skipped by operator."
}

# Mark progress log as complete
Write-Progress-Log "=== Script completed successfully ==="
