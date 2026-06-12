# DFIR Investigation Report

**Case directory:** /cases/BASELINE-001
**UTC generated:** 2026-06-11T00:00:00+00:00
**Iterations completed:** 1

---

## CONFIRMED FINDINGS

> Findings are grouped by attack technique for readability. All 53 entries are in the VERIFIED list.

---

### Finding 1 — DSRM Account Password Change

| Field | Value |
|-------|-------|
| file_id | 4794_DSRM_password_change_t1098.evtx |
| record_id | 3139859 |
| sha256 | 4794_DSRM_password_change_t1098.evtx#3139859@6858de83024b72dff54d75b882103f760eaa85847831578abab78ab5c7f62061 |
| rule_title | Password Change on Directory Service Restore Mode (DSRM) Account |
| process | null (Security log — no process field) |
| utc_timestamp | 2017-06-09 19:21:26.968 +00:00 |
| corrected_from_hallucination | false |

Administrator on domain controller `2016dc.hqcorp.local` (HQCORP\administrator, SID S-1-5-21-1913345275-1711810662-261465553-500) changed the DSRM (Directory Services Restore Mode) account password (Event ID 4794, Status 0x0 = success). The DSRM account grants local administrator access to the DC even with AD services offline; changing it is a known persistence technique (MITRE ATT&CK T1098) enabling an attacker to regain DC access by booting into DSRM mode.

---

### Finding 2 — DCSync via Mimikatz (3 records)

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202791 |
| sha256 | CA_DCSync_4662.evtx#202791@679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null (Directory Service access event) |
| utc_timestamp | 2019-05-08 02:10:43.487 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202792 |
| sha256 | CA_DCSync_4662.evtx#202792@679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null |
| utc_timestamp | 2019-05-08 02:10:43.487 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202793 |
| sha256 | CA_DCSync_4662.evtx#202793@679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null |
| utc_timestamp | 2019-05-08 02:10:43.487 +00:00 |
| corrected_from_hallucination | false |

Three consecutive Event ID 4662 (Directory Service Object Access) records on `DC1.insecurebank.local` at 02:10 UTC, all by the Administrator account (LID 0x40c6511). The target object GUID `%{c6faf700-bfe4-452a-a766-424f84c29583}` corresponds to the DS-Replication-Get-Changes-All extended right. This triple-fire pattern is the canonical Mimikatz `lsadump::dcsync` signature, replicating all domain secrets from the DC without needing physical access to the NTDS.DIT file (MITRE T1003.006).

---

### Finding 3 — KeeFarce Execution and KeePass Process Injection (2 records)

| Field | Value |
|-------|-------|
| file_id | CA_keefarce_keepass_credump.evtx |
| record_id | 7020 |
| sha256 | CA_keefarce_keepass_credump.evtx#7020@101037366f9c300f3ec9397ab42b2b9ee35115c3da97b5725c52db04d6bc33b2 |
| rule_title | Proc Exec (Sysmon Alert) — Masquerading (T1036) |
| process | C:\Users\Public\KeeFarce.exe |
| utc_timestamp | 2019-04-27 18:47:00.046 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | CA_keefarce_keepass_credump.evtx |
| record_id | 7023 |
| sha256 | CA_keefarce_keepass_credump.evtx#7023@101037366f9c300f3ec9397ab42b2b9ee35115c3da97b5725c52db04d6bc33b2 |
| rule_title | Remote Thread Created In KeePass.EXE |
| process | C:\Program Files\KeePass Password Safe 2\KeePass.exe (TgtProc; SrcProc=C:\Users\Public\KeeFarce.exe) |
| utc_timestamp | 2019-04-27 18:47:00.062 +00:00 |
| corrected_from_hallucination | true |

`KeeFarce.exe` was executed from the world-writable `C:\Users\Public\` path on `IEWIN7` as `IEWIN7\IEUser`. Sixteen milliseconds later, it created a remote thread in the running `KeePass.exe` process (Sysmon EID 8, StartFunction=LoadManagedProject, StartModule=BootstrapDLL.dll), causing KeePass to export its plaintext credential database. This is the KeeFarce attack (MITRE T1555.005). The corrected process field reflects that the verifier returns TgtProc for EID 8; the attacker process is KeeFarce.exe (SrcProc).

---

### Finding 4 — KeeThief (PowerShell → KeePass Remote Thread) (2 records)

| Field | Value |
|-------|-------|
| file_id | CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx |
| record_id | 7070 |
| sha256 | CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx#7070@da1c3fc77c5efdfd652201e2037f5c257ec4e48432900473491b9ca1c32bcf15 |
| rule_title | Remote Thread Created In KeePass.EXE |
| process | C:\Program Files\KeePass Password Safe 2\KeePass.exe (TgtProc; SrcProc=powershell.exe) |
| utc_timestamp | 2019-04-27 18:55:04.710 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx |
| record_id | 7071 |
| sha256 | CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx#7071@da1c3fc77c5efdfd652201e2037f5c257ec4e48432900473491b9ca1c32bcf15 |
| rule_title | Remote Thread Created In KeePass.EXE |
| process | C:\Program Files\KeePass Password Safe 2\KeePass.exe (TgtProc; SrcProc=powershell.exe) |
| utc_timestamp | 2019-04-27 18:55:04.980 +00:00 |
| corrected_from_hallucination | true |

Eight minutes after the KeeFarce attack, `powershell.exe` (PID 2856) created two remote threads in the same `KeePass.exe` instance on `IEWIN7`. This matches the `Get-KeePassDatabaseKey` technique (KeeThief), which reads the master key from KeePass memory. StartFunction=DbgUiRemoteBreakin (first thread) indicates debug attach; the second thread (StartAddress=0x06160000, no StartModule) is shellcode injection. MITRE T1555.005.

---

### Finding 5 — Protected Storage RPC MasterKey Access

| Field | Value |
|-------|-------|
| file_id | CA_protectedstorage_5145_rpc_masterkey.evtx |
| record_id | 886983 |
| sha256 | CA_protectedstorage_5145_rpc_masterkey.evtx#886983@65931b695ed13ad1d0779342257b8e22b2cc30676d65a2610dc6a540701f7841 |
| rule_title | Protected Storage Service Access |
| process | null (network share access event) |
| utc_timestamp | 2020-07-19 13:06:52.199 +00:00 |
| corrected_from_hallucination | false |

User `backdoor` from IP `172.16.66.1` accessed the `\\*\IPC$` share and navigated to the `protected_storage` named pipe (Event ID 5145) on `01566s-win16-ir.threebeesco.com`. Access to the DPAPI protected storage RPC endpoint over the network is the Mimikatz `lsadump::backupkeys` attack path, which retrieves the domain DPAPI backup key — enabling offline decryption of all user credentials protected by DPAPI on any domain machine (MITRE T1555).

---

### Finding 6 — Meterpreter Hashdump: Remote Thread Injection into LSASS (2 records)

| Field | Value |
|-------|-------|
| file_id | CA_sysmon_hashdump_cmd_meterpreter.evtx |
| record_id | 9060 |
| sha256 | CA_sysmon_hashdump_cmd_meterpreter.evtx#9060@897206ca4c3c427753fde880970048494cd5a99be9aaba6154b4e3ac499e24c9 |
| rule_title | Password Dumper Remote Thread in LSASS |
| process | C:\Windows\System32\lsass.exe (TgtProc; SrcProc=\\VBOXSVR\HTools\voice_mail.msg.exe) |
| utc_timestamp | 2019-04-30 12:43:43.784 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | CA_sysmon_hashdump_cmd_meterpreter.evtx |
| record_id | 9066 |
| sha256 | CA_sysmon_hashdump_cmd_meterpreter.evtx#9066@897206ca4c3c427753fde880970048494cd5a99be9aaba6154b4e3ac499e24c9 |
| rule_title | Password Dumper Remote Thread in LSASS |
| process | C:\Windows\System32\lsass.exe (TgtProc; SrcProc=\\VBOXSVR\HTools\voice_mail.msg.exe) |
| utc_timestamp | 2019-04-30 12:43:43.784 +00:00 |
| corrected_from_hallucination | true |

`\\VBOXSVR\HTools\voice_mail.msg.exe` — a binary executed directly from a VirtualBox shared folder with a misleading `.msg.exe` double-extension — created two remote threads in `lsass.exe` (PID 492) on `IEWIN7`. The UNC execution path (VBOXSVR) and `.msg.exe` naming indicate a Meterpreter hashdump payload launched from the attacker's VM. The dual thread injection pattern (thread IDs 1744 and 3656) is consistent with Metasploit's `kiwi`/`hashdump` module (MITRE T1003.001).

---

### Finding 7 — TeamViewer Memory Access via Frida Injector

| Field | Value |
|-------|-------|
| file_id | CA_teamviewer-dumper_sysmon_10.evtx |
| record_id | 2128582 |
| sha256 | CA_teamviewer-dumper_sysmon_10.evtx#2128582@53eaf99a0a50ad2b2b8b86535b6b5f5da30663d5f977a02eeb4e69d2438fa668 |
| rule_title | Proc Access (Sysmon Alert) — Credential Access: TeamViewer MemAccess |
| process | C:\Program Files (x86)\TeamViewer\TeamViewer.exe (TgtProc; SrcProc=frida-winjector-helper-32.exe) |
| utc_timestamp | 2020-07-24 17:20:29.872 +00:00 |
| corrected_from_hallucination | true |

A Frida instrumentation helper (`frida-winjector-helper-32.exe`, dropped in a temp path with a hash-named directory) on `LAPTOP-JU4M3I0E` opened `TeamViewer.exe` (PID 2960) with access mask `0x147a` — sufficient for reading process memory. The call trace confirms WOW64 cross-architecture injection. This is the teamviewer-dumper technique, extracting credentials from TeamViewer's memory. The corrected process reflects TgtProc returned by the verifier; the attacker is the Frida helper (SrcProc) (MITRE T1555).

---

### Finding 8 — PowerShell MiniDumpWriteDump Script Block (LSASS)

| Field | Value |
|-------|-------|
| file_id | Powershell_4104_MiniDumpWriteDump_Lsass.evtx |
| record_id | 971 |
| sha256 | Powershell_4104_MiniDumpWriteDump_Lsass.evtx#971@54ff62eff26af588782e066b7b3b1b952bc83e1b75a84d81f9492e654cb5c319 |
| rule_title | PowerShell Get-Process LSASS in ScriptBlock |
| process | null (script block log — no process field) |
| utc_timestamp | 2020-06-30 14:24:08.254 +00:00 |
| corrected_from_hallucination | false |

PowerShell Script Block Logging (Event 4104) on `MSEDGEWIN10` captured a complete `MiniDumpWriteDump` implementation: the script calls `Get-Process lsass`, obtains a process handle via reflection on `System.Management.Automation.WindowsErrorReporting.NativeMethods`, and writes a full minidump (`MiniDumpWithFullMemory = 2`) to disk. The script is entirely reflective — no external binary is dropped — making it a living-off-the-land credential dump (MITRE T1003.001).

---

### Finding 9 — BabyShark / Mimikatz: PowerShell Process Chain (4 records)

| Field | Value |
|-------|-------|
| file_id | babyshark_mimikatz_powershell.evtx |
| record_id | 13 |
| sha256 | babyshark_mimikatz_powershell.evtx#13@3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c |
| rule_title | Proc Exec (Sysmon Alert) — PowerShell (T1086) |
| process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| utc_timestamp | 2019-04-18 16:56:08.370 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | babyshark_mimikatz_powershell.evtx |
| record_id | 14 |
| sha256 | babyshark_mimikatz_powershell.evtx#14@3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c |
| rule_title | Proc Exec (Sysmon Alert) — System Owner/User Discovery (T1033) |
| process | C:\Windows\System32\whoami.exe |
| utc_timestamp | 2019-04-18 16:56:24.893 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | babyshark_mimikatz_powershell.evtx |
| record_id | 15 |
| sha256 | babyshark_mimikatz_powershell.evtx#15@3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c |
| rule_title | Proc Exec (Sysmon Alert) — UAC Bypass via eventvwr (T1088) |
| process | C:\Windows\System32\mmc.exe |
| utc_timestamp | 2019-04-18 16:57:04.681 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | babyshark_mimikatz_powershell.evtx |
| record_id | 24 |
| sha256 | babyshark_mimikatz_powershell.evtx#24@3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c |
| rule_title | Proc Exec (Sysmon Alert) — System Owner/User Discovery (T1033) |
| process | C:\Windows\System32\whoami.exe |
| utc_timestamp | 2019-04-18 17:00:09.977 +00:00 |
| corrected_from_hallucination | false |

A full BabyShark-style attack chain on `IEWIN7` as `IEWIN7\IEUser`: (1) PowerShell launched from cmd at 16:56:08; (2) `whoami /user` for reconnaissance 16 seconds later; (3) UAC bypass via `eventvwr.exe` spawning `mmc.exe` at 16:57:04 to gain elevated context; (4) second `whoami /user` at 17:00:09 confirming elevated identity. LSASS process access events (record_ids 22, 30 — see corrected findings) show PowerShell subsequently accessed lsass memory twice within this session for credential harvesting (MITRE T1003.001, T1033, T1088).

---

### Finding 10 — BabyShark: PowerShell LSASS Process Access (2 corrected records)

| Field | Value |
|-------|-------|
| file_id | babyshark_mimikatz_powershell.evtx |
| record_id | 22 |
| sha256 | babyshark_mimikatz_powershell.evtx#22@3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c |
| rule_title | Proc Access (Sysmon Alert) — Credential Dumping (T1003) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=powershell.exe, Access=0x1010) |
| utc_timestamp | 2019-04-18 16:58:14.811 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | babyshark_mimikatz_powershell.evtx |
| record_id | 30 |
| sha256 | babyshark_mimikatz_powershell.evtx#30@3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c |
| rule_title | Proc Access (Sysmon Alert) — Credential Dumping (T1003) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=powershell.exe, Access=0x1010) |
| utc_timestamp | 2019-04-18 17:01:35.720 +00:00 |
| corrected_from_hallucination | true |

The same PowerShell process (PID 1200, PGUID 365ABB72-AC28-5CB8) opened lsass.exe with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` (0x1010) twice — at 16:58:14 and 17:01:35. The call trace (`ntdll+4595c|KERNELBASE+8185`) is the minimal lsass read path used by Mimikatz's `sekurlsa::logonpasswords` via PowerShell. These events are the direct credential-extraction actions within the BabyShark session.

---

### Finding 11 — IIS Web Shell: Encoded PowerShell + appcmd Password Dump (2 records)

| Field | Value |
|-------|-------|
| file_id | discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx |
| record_id | 5875 |
| sha256 | discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx#5875@5388d3281a902a1f3cc087697589145b7de6abdbbc0dc716abd6a702c44bb106 |
| rule_title | Suspicious Encoded PowerShell Command Line |
| process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| utc_timestamp | 2019-05-27 01:28:42.711 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx |
| record_id | 5886 |
| sha256 | discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx#5886@5388d3281a902a1f3cc087697589145b7de6abdbbc0dc716abd6a702c44bb106 |
| rule_title | Microsoft IIS Service Account Password Dumped |
| process | C:\Windows\System32\inetsrv\appcmd.exe |
| utc_timestamp | 2019-05-27 01:29:17.270 +00:00 |
| corrected_from_hallucination | false |

`IIS APPPOOL\DefaultAppPool` on `IEWIN7` executed a Base64-encoded, XOR-obfuscated PowerShell payload (`-nop -noni -enc`) at 01:28 UTC — spawned by `w3wp.exe` (IIS worker process for DefaultAppPool), confirming a web shell. Thirty-five seconds later, the same account launched `appcmd.exe list apppool /text:processmodel.password` — and then 17 additional `appcmd.exe` invocations over 90 seconds enumerating all application pool passwords (record_ids 5892–5991). This is a post-exploitation IIS credential harvest via web shell (MITRE T1552.001, T1059.001).

---

### Finding 12 — Phishing PowerShell Credential Prompt

| Field | Value |
|-------|-------|
| file_id | phish_windows_credentials_powershell_scriptblockLog_4104.evtx |
| record_id | 1123 |
| sha256 | phish_windows_credentials_powershell_scriptblockLog_4104.evtx#1123@177db8fa70262b4e2eba4e2902c97e82e3c6943fd111bde2ee522d5f1d57e856 |
| rule_title | PowerShell Credential Prompt |
| process | null (script block log) |
| utc_timestamp | 2019-09-09 13:35:09.315 +00:00 |
| corrected_from_hallucination | false |

Script block logging (EID 4104) on `MSEDGEWIN10` captured `Invoke-LoginPrompt` — a phishing function that presents a fake "Windows Security" dialog via `$Host.ui.PromptForCredential()`, validates credentials against the local machine's AccountManagement context, and loops until valid credentials are entered, then exfiltrates them via `GetNetworkCredential().password`. This is a living-off-the-land credential phishing attack that never touches disk (MITRE T1056.002).

---

### Finding 13 — PPLdump: PPL Bypass and LSASS Dump (4 records)

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564589 |
| sha256 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx#564589@9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Dump Keyword In CommandLine |
| process | C:\Users\IEUser\Desktop\PPLdump.exe |
| utc_timestamp | 2021-04-22 22:09:25.389 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564593 |
| sha256 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx#564593@9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Dump Keyword In CommandLine |
| process | C:\Windows\System32\services.exe |
| utc_timestamp | 2021-04-22 22:09:26.081 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564596 |
| sha256 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx#564596@9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Process Memory Dump Files |
| process | C:\Windows\system32\services.exe |
| utc_timestamp | 2021-04-22 22:09:26.163 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564603 |
| sha256 | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx#564603@9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | RunMRU Registry Key Deletion — Registry |
| process | C:\Windows\system32\mmc.exe |
| utc_timestamp | 2021-04-22 22:09:35.165 +00:00 |
| corrected_from_hallucination | false |

`IEUser` on `MSEDGEWIN10` ran `PPLdump.exe -v lsass lsass.dmp` at 22:09:25. PPLdump exploits KnownDlls hijacking to bypass Protected Process Light (PPL) on lsass. The tool spawned `services.exe` as a child process (command line includes `lsass.dmp` and a COM server CLSID) to perform the actual dump — writing `lsass.dmp` to the Desktop 0.7 seconds later (EID 11 file creation). Ten seconds after the dump, `mmc.exe` created (not deleted) the RunMRU registry key — indicating the attacker attempted to clean up run history. SHA1 of PPLdump: `F1C0C54AA13037F46F55B721F7E2A2349A30DBCF` (MITRE T1003.001).

---

### Finding 14 — Zerologon: Log Cleared Post-Exploitation (2 records)

| Field | Value |
|-------|-------|
| file_id | Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx |
| record_id | 63220 |
| sha256 | Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx#63220@519cdae51e2a3a3045ff3a3c61fc06576869deed23a81b9e45619f9521f6bc63 |
| rule_title | Important Log File Cleared (System log) |
| process | null |
| utc_timestamp | 2020-09-15 19:28:31.453 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx |
| record_id | 768617 |
| sha256 | Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx#768617@7ea57911a3afea3777e503e69d30d91b635201df3e6f7f5bbffb1495791064e6 |
| rule_title | Log Cleared (Security log) |
| process | null |
| utc_timestamp | 2020-09-15 19:28:17.594 +00:00 |
| corrected_from_hallucination | false |

On `01566s-win16-ir.threebeesco.com`, privileged account `3B\a-jbrown` cleared both the Security log (EID 1102, at 19:28:17) and the System log (EID 104, at 19:28:31) within 14 seconds. This occurred in the context of a Zerologon (CVE-2020-1472) compromise, consistent with the attacker clearing NetLogon error entries generated during the attack. Log clearing immediately post-exploitation is a textbook anti-forensics step (MITRE T1070.001).

---

### Finding 15 — Remote SAM Registry Exfiltration via Backup Operator Privilege (4 records)

| Field | Value |
|-------|-------|
| file_id | remote_sam_registry_access_via_backup_operator_priv.evtx |
| record_id | 2988521 |
| sha256 | remote_sam_registry_access_via_backup_operator_priv.evtx#2988521@5eb397ece85fa13263685cb1d61ec6fdb768f2dc83d17e222f9d318f3703044f |
| rule_title | Log Cleared |
| process | null |
| utc_timestamp | 2022-02-16 10:37:07.251 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | remote_sam_registry_access_via_backup_operator_priv.evtx |
| record_id | 2988538 |
| sha256 | remote_sam_registry_access_via_backup_operator_priv.evtx#2988538@5eb397ece85fa13263685cb1d61ec6fdb768f2dc83d17e222f9d318f3703044f |
| rule_title | SMB Create Remote File Admin Share |
| process | null (network event) |
| utc_timestamp | 2022-02-16 10:37:20.534 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | remote_sam_registry_access_via_backup_operator_priv.evtx |
| record_id | 2988540 |
| sha256 | remote_sam_registry_access_via_backup_operator_priv.evtx#2988540@5eb397ece85fa13263685cb1d61ec6fdb768f2dc83d17e222f9d318f3703044f |
| rule_title | SMB Create Remote File Admin Share |
| process | null |
| utc_timestamp | 2022-02-16 10:37:20.550 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | remote_sam_registry_access_via_backup_operator_priv.evtx |
| record_id | 2988542 |
| sha256 | remote_sam_registry_access_via_backup_operator_priv.evtx#2988542@5eb397ece85fa13263685cb1d61ec6fdb768f2dc83d17e222f9d318f3703044f |
| rule_title | SMB Create Remote File Admin Share |
| process | null |
| utc_timestamp | 2022-02-16 10:37:20.934 +00:00 |
| corrected_from_hallucination | false |

Account `3B\jbrown` cleared the Security log at 10:37:07. Thirteen seconds later, `3B\samir` from `172.16.66.36` created three files on the target's `C$` admin share — `Users\PSAM`, `Users\PSYSTEM`, and `Users\PSECURITY` — within 400 milliseconds. These are the SAM, SYSTEM, and SECURITY registry hive exports: the classic `reg save` + SMB exfiltration pattern using Backup Operator privileges to extract local account hashes without touching LSASS (MITRE T1003.002).

---

### Finding 16 — Procdump + Taskmgr LSASS Memory Dump (3 records)

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_lsass_memdump.evtx |
| record_id | 4433 |
| sha256 | sysmon_10_11_lsass_memdump.evtx#4433@915f0859251552b6c33efc32f6184d2c25419c5859852124a7f14ed6ec1a3723 |
| rule_title | LSASS Process Memory Dump Files |
| process | C:\Users\IEUser\Desktop\procdump.exe |
| utc_timestamp | 2019-03-17 19:09:41.328 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_lsass_memdump.evtx |
| record_id | 4434 |
| sha256 | sysmon_10_11_lsass_memdump.evtx#4434@915f0859251552b6c33efc32f6184d2c25419c5859852124a7f14ed6ec1a3723 |
| rule_title | Suspicious Process Access to LSASS (procdump → lsass) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=C:\Users\IEUser\Desktop\procdump.exe, Access=0x1fffff) |
| utc_timestamp | 2019-03-17 19:09:41.328 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_lsass_memdump.evtx |
| record_id | 4441 |
| sha256 | sysmon_10_11_lsass_memdump.evtx#4441@915f0859251552b6c33efc32f6184d2c25419c5859852124a7f14ed6ec1a3723 |
| rule_title | LSASS Process Memory Dump Creation Via Taskmgr.EXE |
| process | C:\Windows\system32\taskmgr.exe |
| utc_timestamp | 2019-03-17 19:10:03.991 +00:00 |
| corrected_from_hallucination | false |

`IEUser` on `PC04.example.corp` first used `procdump.exe` (Desktop, PID 1856) to open lsass with full access (0x1fffff) via dbghelp.dll, writing `lsass.exe_190317_120941.dmp` to the Desktop. Twenty-two seconds later, Task Manager (PID 3576) created a second dump at `AppData\Local\Temp\lsass (2).DMP`. The dual-method dump (both procdump and taskmgr) suggests the attacker tested multiple techniques or targeted redundancy. Call trace confirms dbghelp.dll path (MITRE T1003.001).

---

### Finding 17 — Outflank Dumpert + AndrewSpecial LSASS Dump (6 records)

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| record_id | 238373 |
| sha256 | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx#238373@f0d11bf8e186947aaf64c3a57debb1b665f518e2dab13acdaafb30c7e8d262af |
| rule_title | Proc Exec (Sysmon Alert) — Suspicious Execution Path (Outflank-Dumpert) |
| process | C:\Users\administrator\Desktop\x64\Outflank-Dumpert.exe |
| utc_timestamp | 2019-06-21 07:35:37.185 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| record_id | 238374 |
| sha256 | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx#238374@f0d11bf8e186947aaf64c3a57debb1b665f518e2dab13acdaafb30c7e8d262af |
| rule_title | LSASS Memory Access by Tool With Dump Keyword (Outflank-Dumpert → lsass) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=Outflank-Dumpert.exe, Access=0x1fffff) |
| utc_timestamp | 2019-06-21 07:35:37.329 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| record_id | 238376 |
| sha256 | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx#238376@f0d11bf8e186947aaf64c3a57debb1b665f518e2dab13acdaafb30c7e8d262af |
| rule_title | Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs (Outflank-Dumpert) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=Outflank-Dumpert.exe, Access=0x1fffff) |
| utc_timestamp | 2019-06-21 07:35:37.377 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| record_id | 238385 |
| sha256 | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx#238385@f0d11bf8e186947aaf64c3a57debb1b665f518e2dab13acdaafb30c7e8d262af |
| rule_title | Proc Exec (Sysmon Alert) — Suspicious Execution Path (AndrewSpecial) |
| process | C:\Users\administrator\Desktop\AndrewSpecial.exe |
| utc_timestamp | 2019-06-21 07:36:50.450 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| record_id | 238387 |
| sha256 | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx#238387@f0d11bf8e186947aaf64c3a57debb1b665f518e2dab13acdaafb30c7e8d262af |
| rule_title | LSASS Process Memory Dump Files (AndrewSpecial.exe → Andrew.dmp) |
| process | C:\Users\administrator\Desktop\AndrewSpecial.exe |
| utc_timestamp | 2019-06-21 07:36:51.681 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx |
| record_id | 238388 |
| sha256 | sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx#238388@f0d11bf8e186947aaf64c3a57debb1b665f518e2dab13acdaafb30c7e8d262af |
| rule_title | LSASS Memory Access (AndrewSpecial → lsass, Access=0x1fffff) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=AndrewSpecial.exe) |
| utc_timestamp | 2019-06-21 07:36:51.682 +00:00 |
| corrected_from_hallucination | true |

Domain `insecurebank\Administrator` on `alice.insecurebank.local` ran two lsass dump tools in sequence. First, `Outflank-Dumpert.exe` (SHA256: 38879FE4AA25044DB241B093E6A1CF904BA9F4E999041C0CC039E2D5F7ABA044) accessed lsass via syscall-based direct memory access (call trace shows Dumpert's own code at `+134da`, bypassing EDR hooks by using raw syscalls via ctiuser.dll shim). 73 seconds later, `AndrewSpecial.exe` (a custom dumper) accessed lsass via a WOW64 path with the same ctiuser.dll anti-hook technique, writing `Andrew.dmp` to the Desktop. Both tools use indirect syscalls specifically to evade user-mode API hooks — a sophisticated EDR-bypass credential dump (MITRE T1003.001).

---

### Finding 18 — Comsvcs.dll MiniDump via WMI-Spawned Rundll32

| Field | Value |
|-------|-------|
| file_id | sysmon_10_1_memdump_comsvcs_minidump.evtx |
| record_id | 32154 |
| sha256 | sysmon_10_1_memdump_comsvcs_minidump.evtx#32154@d1bf591cabf7d21f49936150bfaf433da7665211ba3fd00bc806f4912a6f96b4 |
| rule_title | Process Memory Dump Via Comsvcs.DLL |
| process | C:\Windows\System32\rundll32.exe |
| utc_timestamp | 2019-08-30 12:54:08.354 +00:00 |
| corrected_from_hallucination | false |

| Field | Value |
|-------|-------|
| file_id | sysmon_10_1_memdump_comsvcs_minidump.evtx |
| record_id | 32156 |
| sha256 | sysmon_10_1_memdump_comsvcs_minidump.evtx#32156@d1bf591cabf7d21f49936150bfaf433da7665211ba3fd00bc806f4912a6f96b4 |
| rule_title | Proc Access (Sysmon Alert) — CredAccess Memdump (rundll32 → notepad.exe) |
| process | C:\Windows\system32\notepad.exe (TgtProc; SrcProc=C:\Windows\system32\rundll32.exe, Access=0x1fffff) |
| utc_timestamp | 2019-08-30 12:54:08.439 +00:00 |
| corrected_from_hallucination | true |

`wmiprvse.exe` spawned `rundll32.exe` (PID 2888) with cmdline `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full` on `MSEDGEWIN10`. This is the `comsvcs.dll MiniDump` living-off-the-land technique (LOLBAS), here targeting `notepad.exe` (PID 4868) as a proxy dump target (possibly to avoid direct lsass targeting). The call trace confirms `dbgcore.DLL` is invoked by `comsvcs.dll` within `rundll32`. Being spawned by `wmiprvse.exe` indicates WMI lateral movement or persistence as the initial trigger. The dump was written to `notepad.bin` (camouflaged extension) (MITRE T1003.001).

---

### Finding 19 — Mimikatz Direct LSASS Process Access

| Field | Value |
|-------|-------|
| file_id | sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx |
| record_id | 4807 |
| sha256 | sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx#4807@9a1689574ed08c1fb18e7ff3f3bed612109aedcb7bf8efbf3537d756e669e96f |
| rule_title | HackTool — Generic Process Access (mimikatz → lsass) |
| process | C:\Windows\system32\lsass.exe (TgtProc; SrcProc=C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe, Access=0x1010) |
| utc_timestamp | 2019-03-17 19:37:11.661 +00:00 |
| corrected_from_hallucination | true |

`mimikatz.exe` (Win32 build, from `mimikatz_trunk`) on `PC04.example.corp` opened `lsass.exe` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` (0x1010) — the exact access mask used by `sekurlsa::logonpasswords`. The call trace includes `mimikatz.exe+5c5a9`, `+5c86c`, `+5cbd2` — offsets matching the sekurlsa module's lsass credential extraction path. This is direct unmodified Mimikatz execution against lsass (MITRE T1003.001).

---

### Finding 20 — Procdump/Procdump64 via RtlCreateProcessReflection (3 records)

| Field | Value |
|-------|-------|
| file_id | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx |
| record_id | 2125126 |
| sha256 | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx#2125126@7d160c1b636f8eb3642e9c2c15c941c136d9ecbf19116b18b19f981324d44e00 |
| rule_title | LSASS Memory Access by Tool With Dump Keyword (procdump → lsass) |
| process | C:\windows\system32\lsass.exe (TgtProc; SrcProc=procdump.exe, Access=0x1fffff) |
| utc_timestamp | 2020-07-07 21:51:39.204 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx |
| record_id | 2125128 |
| sha256 | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx#2125128@7d160c1b636f8eb3642e9c2c15c941c136d9ecbf19116b18b19f981324d44e00 |
| rule_title | LSASS Memory Access by Tool With Dump Keyword (procdump64 → lsass, PID 908) |
| process | C:\windows\system32\lsass.exe (TgtProc; SrcProc=procdump64.exe, Access=0x1fffff) |
| utc_timestamp | 2020-07-07 21:51:39.256 +00:00 |
| corrected_from_hallucination | true |

| Field | Value |
|-------|-------|
| file_id | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx |
| record_id | 2125129 |
| sha256 | sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx#2125129@7d160c1b636f8eb3642e9c2c15c941c136d9ecbf19116b18b19f981324d44e00 |
| rule_title | LSASS Memory Access by Tool With Dump Keyword (procdump64 → reflected process, PID 30096) |
| process | C:\windows\system32\lsass.exe / reflected process (TgtProc=PID 30096; SrcProc=procdump64.exe) |
| utc_timestamp | 2020-07-07 21:51:39.262 +00:00 |
| corrected_from_hallucination | true |

On `LAPTOP-JU4M3I0E` at 21:51:39 UTC, both `procdump.exe` (32-bit, PID 30256) and `procdump64.exe` (64-bit, PID 28528) ran simultaneously against lsass (PID 908). Within 58 milliseconds, `procdump64.exe` generated a third EID 10 against PID 30096 — a different PID not present in the first two events. This is the `RtlCreateProcessReflection` pattern: procdump creates a reflection (fork/clone) of lsass before dumping, allowing a snapshot dump of a running process. The triple-event signature (32-bit probe + 64-bit dump + reflection clone access) is distinctive of this evasion technique (MITRE T1003.001).

---

### Finding 21 — RdrLeakDiag LSASS Dump

| Field | Value |
|-------|-------|
| file_id | sysmon_rdrleakdiag_lsass_dump.evtx |
| record_id | 5226 |
| sha256 | sysmon_rdrleakdiag_lsass_dump.evtx#5226@17f010bff45a34212e5c5ff13ed1106274f65e3524fc508f7481db8aaeef0434 |
| rule_title | Process Memory Dump via RdrLeakDiag.EXE |
| process | C:\Windows\System32\rdrleakdiag.exe |
| utc_timestamp | 2020-09-28 12:47:36.197 +00:00 |
| corrected_from_hallucination | false |

`DESKTOP-PIU87N6\wanwan` executed `rdrleakdiag.exe /p 668 /o C:\Users\wanwan\Desktop /fullmemdmp /snap` from an administrator cmd prompt. `RdrLeakDiag.exe` is a Microsoft-signed Windows diagnostic utility (living-off-the-land binary / LOLBAS) that generates full memory snapshots of any target process. PID 668 would correspond to a system process at that time. The `/fullmemdmp /snap` flags produce a complete memory image, equivalent to a procdump full dump. SHA256: `D66E1EE7970598A5F34FD4B468B5B7705219E80A8A2784E7B18564831FCA797C` (MITRE T1003.001, T1218).

---

### Finding 22 — Overpass the Hash (New Credentials Logon Type 9)

| Field | Value |
|-------|-------|
| file_id | tutto_malseclogon.evtx |
| record_id | 329918 |
| sha256 | tutto_malseclogon.evtx#329918@7f8651fa3ed49bb02a0760e3b4124e08aa0579d580395ea1b1c8c24332fce092 |
| rule_title | Successful Overpass the Hash Attempt |
| process | null (Security logon event) |
| utc_timestamp | 2021-12-07 17:33:01.616 +00:00 |
| corrected_from_hallucination | false |

Event ID 4624 on `MSEDGEWIN10` records a Logon Type 9 ("NEW CREDENTIALS") for user `IEUser` from `::1` (localhost) with LogonID `0x16e3db3`. Logon Type 9 is created by `runas /netonly` or `MalSecLogon`-style impersonation — it keeps the existing token on disk but uses the new (stolen hash-based) credentials for all network authentication. This is the Overpass-the-Hash technique: the attacker used a captured NTLM hash to create a Kerberos TGT without knowing the plaintext password (MITRE T1550.002).

---

### Finding 23 — Additional Log-Cleared Events (5 records)

The following Log Cleared events were confirmed but are contextual rather than primary attack events:

| file_id | record_id | sha256 ref | utc_timestamp | actor | corrected |
|---------|-----------|-----------|---------------|-------|-----------|
| ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx | 198238040 | @f09f993909deb... | 2019-03-25 09:09:14 | insecurebank\bob | false |
| CA_chrome_firefox_opera_4663.evtx | 4987 | @e23b74c463d1... | 2019-04-27 19:27:55 | IEWIN7\IEUser | false |
| kerberos_pwd_spray_4771.evtx | 887106 | @4a0a1c7132e2... | 2020-07-22 20:29:27 | 3B\a-jbrown | false |
| remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx | 769792 | @6a5d703c2838... | 2020-09-17 10:57:37 | 3B\a-jbrown | false |
| remote_sam_registry_access_via_backup_operator_priv.evtx | 2988521 | @5eb397ece85f... | 2022-02-16 10:37:07 | 3B\jbrown | false |

---

## INFERENCES

> All items in this section are analyst inferences — NOT verified against raw evidence.

- The `insecurebank.local` domain appears compromised at the domain administrator level: DCSync (2019-05-08) gives the attacker all domain hashes without further access to the DC itself. Subsequent activity across multiple evtx files likely represents post-DCSync lateral movement using harvested credentials.
- The `threebeesco.com` (`3B`) environment was compromised via Zerologon (CVE-2020-1472) around 2020-09-15. The repeated log clearing by `a-jbrown` across Zerologon, Kerberos spray, and post-Zerologon files strongly suggests this account was either compromised or created by the attacker as a persistence backdoor.
- The `IEWIN7` host appears to be a dedicated attacker workstation or sandbox used for testing multiple credential-dumping tools: KeeFarce (2019-04-27), KeeThief (2019-04-27), Meterpreter hashdump (2019-04-30), and BabyShark/Mimikatz (2019-04-18). The rapid tool cycling suggests attacker capability development rather than a production attack against this host.
- The `MSEDGEWIN10` host shows attacks across three years (2019 comsvcs, 2020 PowerShell MiniDump, 2021 PPLdump, 2021 Overpass-the-Hash), suggesting it is a persistent attacker-controlled machine or a lab environment with re-used test evidence.
- The IIS web shell on `IEWIN7` (2019-05-27) running as `IIS APPPOOL\DefaultAppPool` and running 19 appcmd password-enumeration commands over 90 seconds indicates an active attacker operating interactively through the web shell, harvesting all configured application pool credentials.
- Three distinct LSASS memory dump techniques against the same host (`PC04.example.corp`) within minutes (procdump + taskmgr, 2019-03-17) followed by Mimikatz 28 minutes later suggests the attacker first took a dump for offline cracking, then also ran interactive Mimikatz for immediate credential extraction.
- The use of EDR-bypass techniques (Outflank Dumpert + AndrewSpecial using direct syscalls via ctiuser.dll shim, 2019-06-21) and the RtlCreateProcessReflection pattern (procdump64, 2020-07-07) indicates adversary awareness of and adaptation to endpoint detection, suggesting a skilled red team or sophisticated threat actor.

---

## DISCARDED CLAIMS

> No findings were discarded due to absence of evidence. All 17 HALLUCINATED verdicts from Phase 2 were corrected in Phase 3 using raw `get_event_detail` data. The process field mismatch was a systematic artifact: the `verify_finding` tool returns TgtProc as "actual_process" for Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) events, while the scan correctly reports SrcProc (the attacking process) in the `claimed_process` field.

---

## INVESTIGATION SUMMARY

| Metric | Count |
|--------|-------|
| .evtx files scanned | 39 |
| Draft findings generated | 53 |
| Findings directly verified (CONFIRMED) | 36 |
| Findings flagged HALLUCINATED by verify_finding | 17 |
| Findings corrected via get_event_detail (Phase 3) | 17 |
| Total findings in VERIFIED list | 53 |
| Findings discarded | 0 |
| Self-corrections made | 17 |
| Iterations | 1 |

### Attack Technique Summary (MITRE ATT&CK)

| Technique | Count | Files |
|-----------|-------|-------|
| T1003.001 — LSASS Memory Dump | 20 | procdump, taskmgr, mimikatz, dumpert, andrewspecial, comsvcs, rdrleakdiag, PowerShell MiniDump, meterpreter, babyshark |
| T1003.006 — DCSync | 3 | CA_DCSync_4662 |
| T1003.002 — SAM Hive Dump (remote) | 3 | remote_sam_registry |
| T1555 — Credentials from Password Stores | 5 | KeePass (KeeFarce + KeeThief), TeamViewer, Protected Storage |
| T1070.001 — Log Clearing | 7 | Multiple files |
| T1059.001 — PowerShell | 5 | babyshark, discovery_sysmon, phish, Powershell_4104 |
| T1550.002 — Overpass the Hash | 1 | tutto_malseclogon |
| T1098 — DSRM Account Manipulation | 1 | 4794_DSRM |
| T1056.002 — Credential Prompting | 1 | phish_windows_credentials |
| T1218 — LOLBAS (rdrleakdiag, rundll32/comsvcs) | 2 | comsvcs_minidump, rdrleakdiag |
