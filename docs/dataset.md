# Evidence Dataset Documentation

---

## Source

**Dataset:** EVTX-ATTACK-SAMPLES  
**Author:** Samir Bousseaden ([@SBousseaden](https://github.com/sbousseaden))  
**Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  
**License:** MIT  
**Access method:** Cloned locally; no network access during analysis  

The dataset is a curated collection of real Windows Event Log captures taken during live
adversary-simulation exercises. Files were recorded on Windows 10 / Windows Server 2016–2019
endpoints with Sysmon deployed. Each file isolates one attack technique or tool execution.

---

## Contents

**Total files:** 39 Windows Event Log (`.evtx`) files  
**Primary channel:** Microsoft-Windows-Sysmon/Operational (with supporting Security and System logs)

### Attack Techniques Represented

| Category | Techniques / Tools |
|----------|--------------------|
| Credential dumping — LSASS | Mimikatz sekurlsa, ProcDump, Task Manager dump, comsvcs MiniDump, Out-Minidump, PPLdump, Nanodump |
| DCSync (domain replication) | Mimikatz dcsync, Impacket secretsdump |
| Kerberos attacks | AS-REP roasting, Kerberoasting spray, Pass-the-Ticket |
| Active Directory database | NTDS.DIT volume shadow copy backup, ntdsutil IFM |
| DSRM persistence | Registry DSRM admin flag modification |
| Zerologon (CVE-2020-1472) | Netlogon privilege escalation proof-of-concept |
| LSASS protection bypass | PPLdump (Protected Process Light bypass) |
| Password manager theft | KeePass memory dump / export |
| Remote access credential harvest | TeamViewer log + memory credential theft |
| PetitPotam (CVE-2021-36942) | LSARPC-based NTLM coercion |
| MalSecLogon | Abusing CreateProcessWithLogonW for LSASS handle |
| Keylogger | User-mode keystroke capture |
| PowerShell credential phishing | Fake credential prompt via PowerShell GUI |
| Process injection | CreateRemoteThread (Sysmon EID 8) across multiple tools |
| Process access | OpenProcess on LSASS (Sysmon EID 10) |

### Time Range

Events span **2017 – 2022**, reflecting the collection timeline of the public dataset.
All timestamps were treated as UTC for analysis purposes.

---

## What the Agent Found

After running the full 4-phase self-correcting investigation loop:

| Metric | Value |
|--------|-------|
| Verified findings | 53 |
| Attack technique groups identified | 23 |
| MITRE ATT&CK techniques mapped | 20 |

### MITRE ATT&CK Technique Coverage

| Technique ID | Name |
|-------------|------|
| T1003.001 | OS Credential Dumping: LSASS Memory |
| T1003.003 | OS Credential Dumping: NTDS |
| T1003.006 | OS Credential Dumping: DCSync |
| T1055.001 | Process Injection: Dynamic-link Library Injection |
| T1055.002 | Process Injection: Portable Executable Injection |
| T1055.003 | Process Injection: Thread Execution Hijacking |
| T1055.012 | Process Injection: Process Hollowing |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1078 | Valid Accounts |
| T1098 | Account Manipulation |
| T1110.003 | Brute Force: Password Spraying |
| T1134.002 | Access Token Manipulation: Create Process with Token |
| T1187 | Forced Authentication |
| T1484.001 | Domain Policy Modification: Group Policy Modification |
| T1543 | Create or Modify System Process |
| T1547 | Boot or Logon Autostart Execution |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting |
| T1555 | Credentials from Password Stores |
| T1556.004 | Modify Authentication Process: Network Provider DLL |

All 53 findings carry a source EVTX file path, EventRecordID, UTC timestamp, and SHA-256
digest enabling independent reproduction from the public dataset.
