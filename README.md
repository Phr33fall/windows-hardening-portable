# Harden-Windows-Portable-Documented

A portable, fully documented Windows hardening script that works on any Windows machine without modification. Drop it on a machine, run it as Administrator, and it self-configures everything from the environment.

---

## TL;DR

Run this script as Administrator on any Windows machine. It auto-detects the admin account, machine name, and OneDrive path. It takes a pre-change backup before touching anything, applies 17 hardening sections, verifies the result, installs Windows and application updates, registers two weekly maintenance tasks, and produces a colour-coded summary at the end. Interactive mode lets you step through each change and approve or skip it individually.

---

## Features

- **Fully portable** — no hardcoded usernames, paths, or machine names. Works on any Windows machine.
- **Interactive or Automatic mode** — step through each section with full documentation, or apply everything unattended.
- **Pre-change backup** — captures registry state, Group Policy report, security policy, and service states before making any change. Stored in a dated subfolder and copied to `PRE-CHANGE-LATEST` for quick access.
- **Rollback capability** — if a previous run's pre-change backup exists, the script offers to restore the machine to its pre-hardening state before proceeding.
- **Interruption protection** — Windows Update service is suspended during the run to prevent forced reboots mid-session. A progress log is written after each section. If interrupted, the next run detects the incomplete log and offers to resume from the last completed section.
- **Post-hardening verification** — independently checks every key control after applying changes and flags any drift.
- **Windows Update integration** — installs OS patches via PSWindowsUpdate and upgrades all third-party applications via winget immediately after hardening.
- **Weekly scheduled tasks** — registers `WindowsAdminBackup` (Sunday 08:00) and `WeeklyWingetUpgrade` (Sunday 09:00) with `StartWhenAvailable` so missed runs catch up on next startup. The backup script is self-contained and written to disk automatically — no separate file required.
- **Colour-coded summary table** — every section, its status, and all verification results displayed clearly at the end.
- **Free space wipe** — optional `cipher /w:C` at the end to overwrite deleted file remnants (3-pass: 0x00, 0xFF, random).

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (included in Windows)
- Administrator account
- Internet access (for PSWindowsUpdate and winget upgrade phases)

---

## How to Use

1. Download `Harden-Windows-Portable-Documented.ps1`
2. Copy it to the machine you want to harden
3. Open PowerShell as Administrator
4. Run the following commands:

```powershell
Unblock-File .\Harden-Windows-Portable-Documented.ps1
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\Harden-Windows-Portable-Documented.ps1
```

5. Review the auto-detected machine context displayed at startup
6. Choose whether to restore from a previous pre-change backup if one exists
7. Confirm you want to proceed
8. Select **I** for Interactive mode or **A** for Automatic mode
9. Follow the prompts

---

## What It Does

The script runs in five phases plus a final step.

### Phase 0 — Detect
Auto-detects the admin username, profile path, machine name, and OneDrive path from environment variables. Creates the Maintenance-Stuff folder if it does not exist. Captures a full pre-change backup. Checks for an incomplete previous run and offers to resume.

### Phase 1 — Apply (17 sections)

| Section | What it does |
|---|---|
| 1. Thumbnail Cache | Disables Explorer thumbnail database. Clears existing cache files. |
| 2. Windows Search Index | Disables WSearch service. Deletes Windows.edb index database. |
| 3. Hibernation and Fast Startup | Runs `powercfg /h off`. Disables HiberbootEnabled. Removes hiberfil.sys. |
| 4. Telemetry | Sets AllowTelemetry to 0. Stops and disables DiagTrack. Clears queued telemetry. |
| 5. Windows Error Reporting | Disables WerSvc. Clears ReportArchive, ReportQueue, and crash dumps. |
| 6. Prefetch and Superfetch | Disables EnablePrefetcher and EnableSuperfetch. Stops SysMain. Clears Prefetch folder. |
| 7. Recent Files and Jump Lists | Disables Start_TrackDocs. Clears Recent, AutomaticDestinations, CustomDestinations. Removes common orphaned Run keys. |
| 8. Location Tracking | Disables DisableLocation via policy. Clears LocationHistory folder. |
| 9. Delivery Optimisation | Sets DODownloadMode to 0. Disables DoSvc via registry. Clears DO cache. |
| 10. Activity History and CDP | Disables activity feed policy keys. Stops CDPSvc. Disables CDPSvc via registry. Deletes ConnectedDevicesPlatform folder. |
| 11. Windows Ink and Handwriting | Disables AllowWindowsInkWorkspace. Clears InputPersonalization data. |
| 12. Network Hardening | Disables LLMNR via EnableMulticast=0. Disables NetBIOS on all adapters via WMI SetTcpipNetbios(2). |
| 13. Power Plan | Applies Ultimate Performance on desktops, High Performance on laptops. Auto-detects via WMI Win32_Battery. |
| 14. Scheduled Task Cleanup | Removes SoftLanding OEM tasks and CCleanerSkipUAC if present. |
| 15. Service Dependencies | Protects OneDrive sync services, VMware, and YubiKey smart card services from being accidentally disabled. |
| 16. Audit Policy Baseline | Enables logon/logoff, account lockout, privilege use, policy change, and account management auditing. |
| 17. DNS over HTTPS | Configures system-wide DoH via Cloudflare 1.1.1.1 at the OS registry level. |

### Phase 2 — Verify
Independently checks all key controls and flags any that did not apply correctly. Checks include service startup types, registry values, BitLocker status, and scheduled task inventory.

### Phase 3 — Backup
Exports post-hardening registry keys, Group Policy report, security policy, and services state CSV. Writes a README with verification results and restore procedure.

### Phase 4 — Tasks
Registers `WindowsAdminBackup` (Sunday 08:00) and `WeeklyWingetUpgrade` (Sunday 09:00). Both run as SYSTEM with `StartWhenAvailable`. The backup script is written directly to Maintenance-Stuff so no prerequisite files are needed.

### Phase 5 — Update
Installs PSWindowsUpdate module if not present. Applies all pending Windows OS and driver patches. Runs `winget upgrade --all` for third-party applications.

### Final — Cipher Wipe
Prompts whether to run `cipher /w:C` to overwrite all deleted file remnants on C: with a three-pass wipe (0x00, 0xFF, random). Can be deferred and run manually.

---

## Output Files

All output is written to `Maintenance-Stuff` inside the admin's OneDrive Documents folder. If OneDrive is not present, falls back to `C:\Maintenance-Stuff`.

```
Maintenance-Stuff\
  2026-04-26\
    PRE-CHANGE\
      Registry_*.reg           ← pre-hardening registry snapshots
      GroupPolicy_Report_PRE.html
      SecurityPolicy_PRE.cfg
      Services_State_PRE.csv
      Registry_State_PRE.csv   ← per-value existence tracking for smart rollback
      DnsClientServerAddress_PRE.csv
      README.txt
    Registry_*.reg             ← post-hardening registry snapshots
    GroupPolicy_Report.html
    SecurityPolicy.cfg
    Services_State.csv
    README.txt
  PRE-CHANGE-LATEST\           ← copy of most recent pre-run state for rollback
  Backup-WindowsAdmin.ps1      ← auto-generated backup script called by weekly task
  hardening-progress.log       ← section completion log for resume capability
  winget-upgrade-log.txt       ← weekly winget upgrade output
```

---

## Rollback

If something goes wrong after hardening, re-run the script. It will detect the `PRE-CHANGE-LATEST` folder and offer to restore:

- Registry keys (only removes keys/values that did not exist before hardening)
- Security policy via secedit
- Service startup types via registry Start values
- DNS server addresses per adapter

Note: file deletions (thumbnail cache, prefetch, WER dumps) cannot be restored. Full disk encryption via BitLocker provides the stronger guarantee for data at rest.

---

## What Is Not Hardened

The following are deliberately omitted from this script because they would break legitimate software or require manual configuration specific to each machine:

- **BitLocker** — must be enabled manually via Settings > Privacy & Security > Device Encryption
- **Windows Firewall rules** — network-specific and not portable
- **User Account Control level** — left at system default
- **Microsoft Defender settings** — left at system default
- **Browser hardening** — browser-specific and not portable

---

## Scheduled Tasks Registered

| Task name | Schedule | Purpose |
|---|---|---|
| WindowsAdminBackup | Every Sunday 08:00 | Exports registry, GPO, security policy, and service state to Maintenance-Stuff |
| WeeklyWingetUpgrade | Every Sunday 09:00 | Upgrades all winget-managed packages |

Both tasks use `StartWhenAvailable`. If the machine is off at the scheduled time, both tasks run on the next startup.

---

## Compatibility

Tested on Windows 11 Pro. Compatible with Windows 10 and Windows 11 Home and Pro. Some sections (BitLocker verification, Ultimate Performance power plan) behave differently on Home editions. All sections handle missing features gracefully via `-ErrorAction SilentlyContinue`.

---

## Important Notes

- Run as Administrator. The script will fail silently on many sections if run as a standard user.
- Do not run this script on machines managed by Microsoft Family Safety. It will break parental controls. Use the companion script `Maintain-ChildAccount-Portable` instead.
- Do not run this script on corporate-managed machines without checking Group Policy first. Enterprise GPO may override or conflict with some settings.
- A reboot is recommended after the script completes, particularly after the DNS over HTTPS and Delivery Optimisation sections.

---

## Licence

MIT. Use freely, modify as needed, no warranty expressed or implied.
