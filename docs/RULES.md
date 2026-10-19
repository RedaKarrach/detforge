# DetForge rules

One row per rule. Every rule must be defensible: what it looks for, what legitimately trips it,
and how an attacker gets around it. Grouped by ATT&CK tactic.

## Execution

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [powershell_encoded_command](../rules/windows/execution/powershell_encoded_command.yml) | T1059.001 PowerShell | Process creation where the binary is PowerShell (Image ends with `\powershell.exe`/`\pwsh.exe`, or OriginalFileName `PowerShell.EXE`/`pwsh.dll`, so renamed copies still match) AND the command line contains `-EncodedCommand` or any accepted abbreviation (`-e`, `-ec`, `-en`, `-enc` ... `-encodedcommand`), each surrounded by spaces; `windash` also matches the `/`, en-dash, em-dash and horizontal-bar forms. | SCCM, Intune and other deployment or RMM tools that launch encoded scripts; some vendor installers. | Pass the payload without the parameter: pipe it on stdin (`powershell -`), decode it inline in `-Command`, or read it from a file or environment variable. Host the PowerShell engine in a custom binary with no powershell.exe process. Flag followed by a tab instead of a space. |

## Persistence

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [registry_run_key_persistence](../rules/windows/persistence/registry_run_key_persistence.yml) | T1547.001 Registry Run Keys | Registry value set (Sysmon event 13) where the key path contains `\CurrentVersion\Run\` or `\RunOnce\` AND the value data points into `\AppData\`, `\Temp\`, `\Users\Public\`, `\Downloads\`, or names a script host (`powershell`, `mshta`, `rundll32`, `regsvr32`, `wscript`, `cscript`). The data filter is the point: every machine writes Run keys, only dropped malware writes them from a user-writable folder. | Per-user installers that live in AppData by design (Discord, Spotify, Teams). Allowlist the exact `Details` value, not the key. | Persist elsewhere (service, scheduled task, WMI subscription, Startup-folder shortcut, `Winlogon\Userinit`, COM hijack). Copy the payload into Program Files or ProgramData first, then point the key there. |
| [scheduled_task_from_user_writable_path](../rules/windows/persistence/scheduled_task_from_user_writable_path.yml) | T1053.005 Scheduled Task | Process creation of `schtasks.exe` (by image or OriginalFileName) with `/create` on the command line AND a task action under `\AppData\`, `\Temp\`, `\Users\Public\` or `\Downloads\`. | Per-user updaters scheduled from AppData (Chrome, Edge, OneDrive). Allowlist by task name or the updater binary. | Create the task through the Task Scheduler COM API or `Register-ScheduledTask`; stage the payload in ProgramData first; import the task from an XML file (`/xml`) so the path is not on the command line. |

## Privilege Escalation

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [uac_bypass_fodhelper](../rules/windows/privilege_escalation/uac_bypass_fodhelper.yml) | T1548.002 Bypass User Account Control | Registry value set under `\Software\Classes\ms-settings\shell\open\command`. The auto-elevating `fodhelper.exe` reads that key, so a command planted there runs high-integrity with no UAC prompt. | None expected; no legitimate software writes this key. | Use a different auto-elevating binary and its hijack key (`computerdefaults.exe`, `sdclt.exe`, `eventvwr.exe` with `mscfile`); write the hive directly so Sysmon does not see event 13. |

## Defense Evasion

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [regsvr32_remote_scriptlet](../rules/windows/defense_evasion/regsvr32_remote_scriptlet.yml) | T1218.010 Regsvr32 | Process creation of `regsvr32.exe` whose command line contains both `scrobj` and `http`: the scriptlet host DLL plus a remote location for the `/i:` scriptlet (the "Squiblydoo" pattern). Matching the pair avoids the plain `/i` install switch. | Essentially none. | Host the scriptlet on a local share or drop it to disk and use a file path; use another LOLBin that runs scriptlets (`mshta`, `rundll32`); rename a copy of regsvr32.exe (still caught by OriginalFileName unless the PE header is patched). |
| [wevtutil_clear_log](../rules/windows/defense_evasion/wevtutil_clear_log.yml) | T1070.001 Clear Windows Event Logs | Process creation of `wevtutil.exe` with ` cl ` or ` clear-log ` on the command line (spaces included so `cl` is the verb). Pair with Security event 1102 where that channel is collected; this is the process-side view. | Golden-image and sysprep scripts that clear logs before capture. | `Clear-EventLog`/`Remove-EventLog` in PowerShell, the EventLog COM API, or deleting the `.evtx` file after stopping the service; separate the verb with a tab; disable collection instead of clearing. |

## Credential Access

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [lsass_memory_access](../rules/windows/credential_access/lsass_memory_access.yml) | T1003.001 LSASS Memory | Process access (Sysmon event 10) where TargetImage ends with `\lsass.exe` and GrantedAccess is one of the read/query masks dumpers request (`0x1010`, `0x1038`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`), excluding known readers (Defender, WMI, csrss, taskmgr, lsm, Defender for Endpoint sensors). | EDR, antivirus and performance agents not already in the filter; add them by SourceImage. | Request an access mask not in the list and duplicate the handle; access lsass through a driver or a signed process you already control; dump from a process that legitimately holds a handle; use a technique that reads the page file or a prior dump instead of opening lsass live. |

## Discovery

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [net_domain_group_discovery](../rules/windows/discovery/net_domain_group_discovery.yml) | T1087.002 Domain Account, T1069.002 Domain Groups | Process creation of `net.exe`/`net1.exe` whose command line enumerates high-value groups or domain accounts (`group "domain admins"`, `group "enterprise admins"`, `group /domain`, `user /domain`, `localgroup administrators`). | Administrators and inventory scripts. Tune by parent process and the running account. | Use LDAP/ADSI, `dsquery`, PowerShell AD cmdlets, BloodHound's SharpHound, or WMI instead of `net`; query a single known account by name rather than listing a group. |

## Lateral Movement

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [psexec_service_install](../rules/windows/lateral_movement/psexec_service_install.yml) | T1021.002 SMB/Admin Shares, T1569.002 Service Execution | System log event 7045 (a service was installed) where the service name is `PSEXESVC` or the binary path ends with `\PSEXESVC.exe`. Fires on the target host. Matching the binary path too catches a renamed service whose binary was not renamed. | Admins and deployment scripts using PsExec legitimately. Tune by source account or source host. | `psexec -r <name>` renames the service and binary; clones with different names (PAExec, Impacket `psexec.py`, RemCom); run over WMI, WinRM or a scheduled task instead, which creates no service. |

## Impact

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [shadow_copy_deletion](../rules/windows/impact/shadow_copy_deletion.yml) | T1490 Inhibit System Recovery | Process creation of `vssadmin.exe` with `delete`+`shadows`, or `wmic.exe` with `shadowcopy`+`delete`. Ransomware deletes shadow copies before encrypting so victims cannot roll back. | Backup software pruning old shadow copies; tune by parent process. | Delete via the WMI/VSS COM API or `Win32_ShadowCopy.Delete()` in PowerShell; use `wbadmin delete catalog` or `bcdedit` recovery tweaks; resize shadow storage to zero so copies are dropped without a delete verb. |
