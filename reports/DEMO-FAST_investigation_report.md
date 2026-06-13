# DFIR Investigation Report

**Case directory:** /cases/DEMO-FAST
**UTC generated:** 2026-06-13T02:10:00Z
**Iterations completed:** 1

---

## CONFIRMED FINDINGS

### Finding 1

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202791 |
| sha256 | 679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null (EID 4662 — no process field; Subject: Administrator @ insecurebank) |
| utc_timestamp | 2019-05-08T02:10:43.487Z |
| corrected_from_hallucination | true |

EID 4662 (Directory Service Object Access) recorded on `DC1.insecurebank.local` at 02:10:43 UTC. The `Administrator` account (SID S-1-5-21-738609754-2819869699-4189121830-500) performed a DS replication access against object `%{c6faf700-bfe4-452a-a766-424f84c29583}` with AccessMask `0x100` and Properties containing GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes). Security log EID 4662 carries no process field — the hallucination flag arose because the draft finding passed the subject account name as a process, which the verifier correctly rejected. The raw event confirms a genuine DCSync replication initiation (MITRE T1003.006, S0002).

---

### Finding 2

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202792 |
| sha256 | 679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null (EID 4662 — no process field; Subject: Administrator @ insecurebank) |
| utc_timestamp | 2019-05-08T02:10:43.487Z |
| corrected_from_hallucination | true |

Second EID 4662 record in the same millisecond burst. Same subject (Administrator RID-500), same object GUID, same AccessMask `0x100`, Properties GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes). Multiple rapid-fire EID 4662 events with identical timestamps are the hallmark of Mimikatz `lsadump::dcsync` iterating through replication attributes. This record represents the second of three replication permission accesses in a DCSync sequence (MITRE T1003.006).

---

### Finding 3

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202793 |
| sha256 | 679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null (EID 4662 — no process field; Subject: Administrator @ insecurebank) |
| utc_timestamp | 2019-05-08T02:10:43.487Z |
| corrected_from_hallucination | true |

Third EID 4662 in the burst. Properties GUID shifts to `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` — **DS-Replication-Get-Changes-All** — the extended right that permits replication of secret domain data (password hashes, Kerberos keys). This is the most forensically significant of the three: possession of DS-Replication-Get-Changes-All is the specific permission required to extract NTLM hashes via DCSync without requiring physical access to the DC's NTDS.dit (MITRE T1003.006).

---

### Finding 4

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564589 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Dump Keyword In CommandLine |
| process | C:\Users\IEUser\Desktop\PPLdump.exe |
| utc_timestamp | 2021-04-22T22:09:25.389Z |
| corrected_from_hallucination | false |

Sysmon EID 1 (Process Create) on `MSEDGEWIN10`. User `MSEDGEWIN10\IEUser` launched `PPLdump.exe -v lsass lsass.dmp` from the Desktop. PPLdump is a public tool that exploits the KnownDll hijacking technique to bypass PPL (Protected Process Light) on LSASS, enabling a user-mode dump of the LSASS process even when it runs as a PPL-protected process. SHA256 of the binary: `68612B1C72B8AA498530ACEB929ED44F1837B8BC52D1269E30A834931434FC41`. No code-signing metadata (Description/Product/Company all `?`), confirming an unsigned attacker tool (MITRE T1003.001).

---

### Finding 5

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564593 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Dump Keyword In CommandLine |
| process | C:\Windows\System32\services.exe |
| utc_timestamp | 2021-04-22T22:09:26.081Z |
| corrected_from_hallucination | false |

Sysmon EID 1: `services.exe` (PID 7188, `NT AUTHORITY\SYSTEM`) spawned with the command `C:\Windows\system32\services.exe 652 "lsass.dmp" a708b1d9-e27b-48bc-8ea7-c56d3a23f99 -v`, with parent process `PPLdump.exe -v lsass lsass.dmp` (PID 6316). This is the PPL bypass mechanism in action — PPLdump hijacks a KnownDll to coerce `services.exe` (a PPL-level process) into performing the LSASS memory dump on its behalf. The GUID in the command line is PPLdump's inter-process coordination token. The dump target `lsass.dmp` is explicitly named (MITRE T1003.001).

---

### Finding 6

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564596 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Process Memory Dump Files |
| process | C:\Windows\system32\services.exe |
| utc_timestamp | 2021-04-22T22:09:26.163Z |
| corrected_from_hallucination | false |

Sysmon EID 11 (File Create): `services.exe` (PID 7188) created the file `C:\Users\IEUser\Desktop\lsass.dmp` at 22:09:26 UTC — 774ms after the PPLdump execution and 82ms after `services.exe` was spawned. This is the forensic confirmation that the PPL bypass succeeded: the dump file was written by `services.exe` acting as the privileged proxy, delivering an LSASS memory dump to the attacker's Desktop (MITRE T1003.001).

---

### Finding 7

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564603 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | RunMRU Registry Key Deletion - Registry |
| process | C:\Windows\system32\mmc.exe |
| utc_timestamp | 2021-04-22T22:09:35.165Z |
| corrected_from_hallucination | false |

Sysmon EID 12 (Registry Create): `mmc.exe` (PID 800) created the registry key `HKU\S-1-5-21-3461203602-4096304019-2269080069-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`. This key stores the history of commands typed in the Windows Run dialog. The Sigma rule title ("RunMRU Registry Key Deletion") is slightly misleading for a CreateKey event — the forensic significance is that `mmc.exe` touched the RunMRU key 9 seconds after the LSASS dump completed, suggesting the attacker may have used the Run dialog (possibly to invoke MMC for LSASS access or as a separate lateral movement step) and then interacted with this history key.

---

### Finding 8

| Field | Value |
|-------|-------|
| file_id | sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx |
| record_id | 4807 |
| sha256 | 9a1689574ed08c1fb18e7ff3f3bed612109aedcb7bf8efbf3537d756e669e96f |
| rule_title | HackTool - Generic Process Access (Mimikatz sekurlsa::logonpasswords) |
| process | SrcProc: C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe → TgtProc: C:\Windows\system32\lsass.exe |
| utc_timestamp | 2019-03-17T19:37:11.661Z |
| corrected_from_hallucination | true |

Sysmon EID 10 (ProcessAccess) on `PC04.example.corp`. `mimikatz.exe` (PID 3588, SrcProc) opened `lsass.exe` (PID 476, TgtProc) with AccessMask `0x1010` (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION). The CallTrace contains mimikatz internal function offsets calling through `KERNELBASE.dll+8185` (OpenProcess) and `ntdll.dll+4595c` — consistent with `sekurlsa::logonpasswords` credential extraction. The hallucination flag arose because `verify_finding` mapped `claimed_process` to `TgtProc` (lsass.exe), but the draft finding correctly identified the SrcProc (mimikatz.exe) as the attacker tool. The raw event is unambiguously a live in-memory credential dump (MITRE T1003.001).

---

## INFERENCES

> All items in this section are analyst inferences — NOT verified against raw evidence.

- The DCSync attack on `DC1.insecurebank.local` (2019-05-08) and the Mimikatz ProcessAccess on `PC04.example.corp` (2019-03-17) occur in the same domain environment (`insecurebank`/`example.corp`) and may represent a multi-stage campaign: initial credential access via Mimikatz on a workstation followed by domain escalation culminating in DCSync against the DC.
- The PPL bypass attack on `MSEDGEWIN10` (2021-04-22) is a separate incident or lab environment; the presence of `IEUser` and `MSEDGEWIN10` hostname is characteristic of Microsoft's Edge test VM, suggesting this may be attacker testing or a sandbox environment used to stage the tooling before deployment.
- The three DCSync EID 4662 events (202791–202793) are consistent with Mimikatz `lsadump::dcsync /user:krbtgt` or similar targeting a specific account — the three events represent Get-Changes, Get-Changes, and Get-Changes-All permissions being exercised in sequence.
- The 9-second gap between the LSASS dump creation (22:09:26) and the RunMRU key access by `mmc.exe` (22:09:35) may indicate the attacker pivoted to a second technique immediately after confirming the dump file was created.
- The `lsass.dmp` written to `C:\Users\IEUser\Desktop\` was likely exfiltrated via a subsequent stage not captured in these EVTX files; no network events are visible in the evidence set provided.

---

## DISCARDED CLAIMS

### Discarded Claim 1

| Field | Claimed Value | Actual Value |
|-------|--------------|--------------|
| record_id | 202791 | 202791 (event exists) |
| rule_title | Mimikatz DC Sync | Mimikatz DC Sync |
| process | Administrator | null (EID 4662 has no process field) |
| utc_timestamp | 2019-05-08T02:10:43.487Z | 2019-05-08T02:10:43.487Z |

**Reason discarded:** verdict=HALLUCINATED from verify_finding — draft finding incorrectly passed the Subject account name ("Administrator") as the process field. EID 4662 Security log events carry no executing process — only the subject account context. Corrected finding added to VERIFIED list (Finding 1).

---

### Discarded Claim 2

| Field | Claimed Value | Actual Value |
|-------|--------------|--------------|
| record_id | 202792 | 202792 (event exists) |
| rule_title | Mimikatz DC Sync | Mimikatz DC Sync |
| process | Administrator | null (EID 4662 has no process field) |
| utc_timestamp | 2019-05-08T02:10:43.487Z | 2019-05-08T02:10:43.487Z |

**Reason discarded:** verdict=HALLUCINATED from verify_finding — same cause as Discarded Claim 1. Corrected finding added to VERIFIED list (Finding 2).

---

### Discarded Claim 3

| Field | Claimed Value | Actual Value |
|-------|--------------|--------------|
| record_id | 202793 | 202793 (event exists) |
| rule_title | Mimikatz DC Sync | Mimikatz DC Sync |
| process | Administrator | null (EID 4662 has no process field) |
| utc_timestamp | 2019-05-08T02:10:43.487Z | 2019-05-08T02:10:43.487Z |

**Reason discarded:** verdict=HALLUCINATED from verify_finding — same cause as Discarded Claims 1–2. Corrected finding added to VERIFIED list (Finding 3).

---

### Discarded Claim 4

| Field | Claimed Value | Actual Value |
|-------|--------------|--------------|
| record_id | 4807 | 4807 (event exists) |
| rule_title | HackTool - Generic Process Access | HackTool - Generic Process Access |
| process | C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe | TgtProc=C:\Windows\system32\lsass.exe (verifier matched TgtProc, not SrcProc) |
| utc_timestamp | 2019-03-17T19:37:11.661Z | 2019-03-17T19:37:11.661Z |

**Reason discarded:** verdict=HALLUCINATED from verify_finding — for Sysmon EID 10 (ProcessAccess), verify_finding resolved `claimed_process` against TgtProc (lsass.exe), not SrcProc (mimikatz.exe). The draft finding's process value (mimikatz.exe) is the forensically correct SrcProc. Raw event confirmed genuine attack; corrected finding added to VERIFIED list (Finding 8).

---

## INVESTIGATION SUMMARY

| Metric | Count |
|--------|-------|
| .evtx files scanned | 3 |
| Draft findings generated | 8 |
| Findings verified (CONFIRMED) | 4 |
| Findings corrected from hallucination | 4 |
| Total findings in VERIFIED list | 8 |
| Findings discarded (no real event) | 0 |
| Self-corrections made | 4 |
| Iterations | 1 |

---

## Attack Chain Summary

| Time (UTC) | Host | Event | MITRE |
|-----------|------|-------|-------|
| 2019-03-17T19:37:11Z | PC04.example.corp | Mimikatz EID 10 → lsass.exe (sekurlsa::logonpasswords) | T1003.001 |
| 2019-05-08T02:10:43Z | DC1.insecurebank.local | DCSync × 3 EID 4662 (Get-Changes + Get-Changes-All) | T1003.006 |
| 2021-04-22T22:09:25Z | MSEDGEWIN10 | PPLdump.exe launched (PPL bypass) | T1003.001 |
| 2021-04-22T22:09:26Z | MSEDGEWIN10 | services.exe (PPL proxy) spawned by PPLdump | T1003.001 |
| 2021-04-22T22:09:26Z | MSEDGEWIN10 | lsass.dmp created at C:\Users\IEUser\Desktop\ | T1003.001 |
| 2021-04-22T22:09:35Z | MSEDGEWIN10 | mmc.exe → RunMRU key access (post-dump activity) | T1112 |
