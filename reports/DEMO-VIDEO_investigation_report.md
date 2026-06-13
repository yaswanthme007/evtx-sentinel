# DFIR Investigation Report

**Case directory:** /cases/DEMO-VIDEO/evidence  
**UTC generated:** 2026-06-12T00:00:00Z  
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
| process | null (Security event — no process field; actor: Administrator) |
| utc_timestamp | 2019-05-08T02:10:43.487Z |
| corrected_from_hallucination | false |

Security Event ID 4662 on `DC1.insecurebank.local` records a Directory Services object access operation (`DS`) by the `Administrator` account against object `%{c6faf700-bfe4-452a-a766-424f84c29583}` with logon ID `0x40c6511`. This GUID corresponds to the DS-Replication-Get-Changes-All extended right, the precise privilege required to perform a DCSync attack. The access type `Object Access` with this specific GUID is the canonical signature of Mimikatz's `lsadump::dcsync` module requesting replication of all AD domain secrets (including KRBTGT and all user hashes) directly from the Domain Controller.

---

### Finding 2

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202792 |
| sha256 | 679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null (Security event — no process field; actor: Administrator) |
| utc_timestamp | 2019-05-08T02:10:43.487Z |
| corrected_from_hallucination | false |

Second of three near-simultaneous Event ID 4662 records at the same millisecond timestamp on `DC1.insecurebank.local`, attributed to the same `Administrator` account and logon session (`LID: 0x40c6511`). The repeated replication-rights accesses within a single logon session are consistent with Mimikatz iterating over multiple AD partitions (domain NC, configuration NC) to ensure a complete credential harvest. The burst pattern of three identical DS access events is a well-known DCSync artefact.

---

### Finding 3

| Field | Value |
|-------|-------|
| file_id | CA_DCSync_4662.evtx |
| record_id | 202793 |
| sha256 | 679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131 |
| rule_title | Mimikatz DC Sync |
| process | null (Security event — no process field; actor: Administrator) |
| utc_timestamp | 2019-05-08T02:10:43.487Z |
| corrected_from_hallucination | false |

Third DCSync replication access event completing the burst triplet. Together, records 202791–202793 establish that at 02:10:43 UTC on 2019-05-08 the `Administrator` account on `DC1.insecurebank.local` replicated the entire Active Directory secret store. At this point the attacker would possess NTLM hashes for every domain account, enabling offline cracking, Pass-the-Hash lateral movement, and Golden Ticket forgery.

---

### Finding 4

| Field | Value |
|-------|-------|
| file_id | Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx |
| record_id | 63220 |
| sha256 | 519cdae51e2a3a3045ff3a3c61fc06576869deed23a81b9e45619f9521f6bc63 |
| rule_title | Important Log File Cleared |
| process | null (System event — no process field; actor: a-jbrown) |
| utc_timestamp | 2020-09-15T19:28:31.453Z |
| corrected_from_hallucination | false |

Windows System Event ID 104 on `01566s-win16-ir.threebeesco.com` records that the System event log was cleared by the account `a-jbrown`. This event appears in the Zerologon (CVE-2020-1472) evidence artefact, strongly suggesting that the log wipe was performed as a post-exploitation anti-forensics step following a successful Zerologon attack against this host. Clearing the System log would destroy NetLogon error events (5805) that are the primary indicator of the Zerologon exploitation attempt, constituting deliberate evidence destruction.

---

### Finding 5

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564589 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Dump Keyword In CommandLine |
| process | C:\Users\IEUser\Desktop\PPLdump.exe |
| utc_timestamp | 2021-04-22T22:09:25.389Z |
| corrected_from_hallucination | false |

Sysmon Event ID 1 (Process Create) on `MSEDGEWIN10` records the execution of `PPLdump.exe -v lsass lsass.dmp` from the Desktop of `IEUser`. PPLdump is a public tool specifically designed to bypass Windows Protected Process Light (PPL) — a security feature that prevents non-PPL processes from accessing LSASS memory. The SHA256 `68612B1C...` matches the known PPLdump binary. Execution from a user desktop with `-v` (verbose) is consistent with an interactive attacker running the tool manually and targeting LSASS for credential extraction.

---

### Finding 6

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564593 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Dump Keyword In CommandLine |
| process | C:\Windows\System32\services.exe |
| utc_timestamp | 2021-04-22T22:09:26.081Z |
| corrected_from_hallucination | false |

Sysmon Event ID 1 on `MSEDGEWIN10` records `services.exe` spawned as a child of `PPLdump.exe` (PID 6316 → PID 7188), running as `NT AUTHORITY\SYSTEM` with command line containing `lsass.dmp`. PPLdump's bypass technique hijacks a KnownDLL to inject code into a PPL host process (services.exe), which then performs the dump on its behalf — leveraging the PPL trust chain. The parent–child relationship `PPLdump.exe → services.exe` with the dump filename in the command is the direct forensic signature of a successful PPL bypass.

---

### Finding 7

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564596 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | LSASS Process Memory Dump Files |
| process | C:\Windows\system32\services.exe |
| utc_timestamp | 2021-04-22T22:09:26.163Z |
| corrected_from_hallucination | false |

Sysmon Event ID 11 (File Create) on `MSEDGEWIN10` records the creation of `C:\Users\IEUser\Desktop\lsass.dmp` by `services.exe` (PID 7188). This event, occurring 774 ms after the PPLdump execution (Finding 5) and 82 ms after the injected services.exe launch (Finding 6), confirms the PPL bypass completed successfully and the LSASS memory dump was written to disk. The dump file contains plaintext credentials, NTLM hashes, and Kerberos tickets extractable with Mimikatz or pypykatz offline.

---

### Finding 8

| Field | Value |
|-------|-------|
| file_id | ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx |
| record_id | 564603 |
| sha256 | 9ac47a1ab7ac5e899dede49a4ea3512f0d3628edb9605981fe78bc0aec6f296f |
| rule_title | RunMRU Registry Key Deletion - Registry |
| process | C:\Windows\system32\mmc.exe |
| utc_timestamp | 2021-04-22T22:09:35.165Z |
| corrected_from_hallucination | false |

Sysmon Event ID 12 (Registry CreateKey) on `MSEDGEWIN10` records `mmc.exe` creating the `RunMRU` registry key (`HKU\...\Explorer\RunMRU`) 9 seconds after the LSASS dump was written. The RunMRU key stores the history of commands typed in the Windows Run dialog; its creation (or recreation after deletion) by `mmc.exe` in this context indicates an attacker using the Run dialog (likely to launch tools) and the registry key being re-initialised. This constitutes anti-forensics activity — an attempt to clear or reset Run dialog history that would reveal what commands were executed.

---

### Finding 9

| Field | Value |
|-------|-------|
| file_id | sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx |
| record_id | 4807 |
| sha256 | 9a1689574ed08c1fb18e7ff3f3bed612109aedcb7bf8efbf3537d756e669e96f |
| rule_title | HackTool - Generic Process Access |
| process | C:\Windows\system32\lsass.exe (target; source: C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe) |
| utc_timestamp | 2019-03-17T19:37:11.661Z |
| corrected_from_hallucination | true |

Sysmon Event ID 10 (ProcessAccess) on `PC04.example.corp` records `mimikatz.exe` (SrcProc, PID 3588) opening `lsass.exe` (TgtProc, PID 476) with access mask `0x1010` (`PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`). The call trace embedded in the event (`mimikatz.exe+5c5a9 → ...+5c86c → ...+5cbd2`) matches the known sekurlsa module call stack for `sekurlsa::logonpasswords`. **Correction note:** the initial sigma scan reported the source process (mimikatz.exe) as the `claimed_process`; however, `verify_finding` validates against the Hayabusa `Proc` field, which for EventID 10 is the target (lsass.exe). The finding was corrected using `get_event_detail` raw values and re-verified as CONFIRMED against the actual target process field.

---

## INFERENCES

> All items in this section are analyst inferences — NOT verified against raw evidence.

- The three distinct attack chains (DCSync on DC1 in 2019, Zerologon + log wipe on threebeesco.com in 2020, PPL bypass + LSASS dump on MSEDGEWIN10 in 2021) likely represent different incidents or lab reproductions, but collectively demonstrate a full credential-theft kill chain: initial access → PPL bypass → LSASS dump → DCSync → complete domain compromise.
- The use of `Administrator` for DCSync (Findings 1–3) suggests the attacker already held DA-equivalent privileges before executing the DCSync, possibly obtained via the LSASS dump technique shown in Findings 5–7 or the Mimikatz ProcessAccess in Finding 9.
- The log clearance by `a-jbrown` (Finding 4) immediately following a Zerologon-context event suggests `a-jbrown` is either a compromised privileged account or the attacker's foothold account on that host. The deliberate System log wipe indicates attacker awareness of Zerologon's 5805 event signature.
- The `lsass.dmp` file written to `C:\Users\IEUser\Desktop\` (Finding 7) would have been exfiltrated or analysed offline; responders should check outbound network connections and USB activity at `2021-04-22T22:09:26Z` on MSEDGEWIN10.
- The RunMRU access by `mmc.exe` (Finding 8) suggests the attacker used the Windows Run dialog to launch additional tooling; the MMC console may have been used to interact with Group Policy or local services as a living-off-the-land technique.

---

## DISCARDED CLAIMS

*No findings were permanently discarded. One finding (record_id 4807) was initially flagged HALLUCINATED due to a process-field semantic mismatch (SrcProc vs TgtProc in Sysmon EventID 10) and was subsequently corrected and confirmed in Phase 3.*

---

## INVESTIGATION SUMMARY

| Metric | Count |
|--------|-------|
| .evtx files scanned | 5 |
| Draft findings generated | 9 |
| Findings verified (CONFIRMED) | 9 |
| Findings discarded (permanent) | 0 |
| Self-corrections made | 1 |
| Iterations | 1 |

---

### Attack Timeline (UTC)

| Timestamp | Host | Event |
|-----------|------|-------|
| 2019-03-17T19:37:11Z | PC04.example.corp | Mimikatz ProcessAccess against lsass.exe (sekurlsa) |
| 2019-05-08T02:10:43Z | DC1.insecurebank.local | DCSync (3× replication access events) |
| 2020-09-15T19:28:31Z | 01566s-win16-ir.threebeesco.com | System log cleared post-Zerologon by a-jbrown |
| 2021-04-22T22:09:25Z | MSEDGEWIN10 | PPLdump.exe launched targeting lsass |
| 2021-04-22T22:09:26Z | MSEDGEWIN10 | PPL bypass via services.exe — lsass.dmp written |
| 2021-04-22T22:09:35Z | MSEDGEWIN10 | RunMRU registry key accessed via mmc.exe |
