# Architecture — evtx-sentinel

---

## Overview

evtx-sentinel is a read-only MCP (Model Context Protocol) server that wraps Hayabusa Windows
Event Log analysis as typed, audited tools consumable by Claude Code. The agent running inside
Claude Code follows a four-phase self-correcting investigation protocol: it scans every EVTX
file for Sigma rule matches, validates each draft finding against raw evidence via
`verify_finding`, corrects wrong field values by calling `get_event_detail`, and emits a
structured report only after every finding has been confirmed or discarded. No analysis result
is accepted without a ground-truth check against the raw event record.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Claude Code Agent                    │
│   (agent/CLAUDE.md — 4-phase investigation protocol)    │
└───────────────────────────┬─────────────────────────────┘
                            │  stdio  (MCP protocol)
                            ▼
┌─────────────────────────────────────────────────────────┐
│            evtx-sentinel MCP Server                     │
│            (server/mcp_server.py)                       │
│                                                         │
│  register_evidence   list_evtx_files                    │
│  run_sigma_scan      get_logon_summary                  │
│  get_event_detail    verify_finding                     │
│                          │                              │
│          ┌───────────────┤                              │
│          │               │                              │
│          ▼               ▼                              │
│   Hayabusa binary   EvtxECmd binary                     │
│   (/opt/hayabusa/   (/opt/zimmermantools/                │
│    hayabusa)         EvtxeCmd/EvtxECmd.dll)             │
│          │                                              │
│          ▼                                              │
│   EVTX evidence files  (read-only, case directory)      │
└─────────────────────────────┬───────────────────────────┘
                              │  append-only
                              ▼
                   logs/execution_log.jsonl
```

---

## Trust Boundaries

### ARCHITECTURAL Guardrails
*Enforced in code — cannot be bypassed by prompt manipulation.*

| Control | Where enforced |
|---------|---------------|
| All evidence files opened `"rb"` / `"r"` only | `mcp_server.py` — every `open()` call |
| SHA-256 computed at registration before any analysis | `register_evidence()` — `_sha256_file()` |
| Unregistered `file_id` rejected before any subprocess | `_require_registered()` called at top of every tool |
| No generic shell-exec tool exposed | MCP server exposes exactly 6 named tools; no passthrough |
| `found: false` returned when record absent — no fabrication | `verify_finding` and `get_event_detail` return structured error, never invented values |
| Every tool call logged to `execution_log.jsonl` before return | `_log_tool_call()` runs inside every tool's finally block |
| Hayabusa runs in temp directory with fixed argument list | `_run_json_timeline()` — no user-controlled shell expansion |

### PROMPT-BASED Guardrails
*Behavioural instructions in `agent/CLAUDE.md` — reinforce architecture but rely on LLM compliance.*

| Instruction | Purpose |
|-------------|---------|
| Four-phase loop (triage → validate → correct → report) | Ensures every finding passes `verify_finding` |
| Maximum 3 iterations | Prevents runaway loops on large case directories |
| Write output to `./reports/` only | Keeps evidence directory clean |
| Never fabricate — all findings must have `verdict=CONFIRMED` | Reinforces server-side `found: false` behaviour |
| UTC-only timestamps in report | Forensic time-zone consistency |

---

## Tool Reference

| Tool | Inputs | Output |
|------|--------|--------|
| `register_evidence(path)` | `path: str` — absolute path to `.evtx` file | `{file_id, sha256, size_bytes, mtime_utc}` |
| `list_evtx_files(directory)` | `directory: str` — path to scan (optional; defaults to `EVTX_CASE_DIR`) | `[{path, filename, size_bytes}]` |
| `run_sigma_scan(file_id, min_level)` | `file_id: str`, `min_level: str` (informational/low/medium/high/critical) | `{file_id, source_file, findings: [{record_id, rule_title, level, utc_timestamp, process, ...}]}` |
| `get_logon_summary(file_id)` | `file_id: str` | `{file_id, source_file, logon_events: [{record_id, utc_timestamp, logon_type, account, ...}]}` |
| `get_event_detail(file_id, record_id)` | `file_id: str`, `record_id: int` | `{found: bool, record_id, utc_timestamp, raw_fields: {...}}` |
| `verify_finding(file_id, record_id, rule_title, claimed_process, claimed_timestamp)` | `file_id: str`, `record_id: int`, `rule_title: str`, `claimed_process: str \| null`, `claimed_timestamp: str` | `{found: bool, verdict: CONFIRMED\|HALLUCINATED, sha256, matched_fields, ...}` |

All six tools append a JSON audit line to `logs/execution_log.jsonl` before returning.
All findings returned by any tool carry the four mandatory fields: `source_file`, `record_id`,
`tool_name`, `utc_timestamp` (Rule 3, `CLAUDE.md`).

---

## Self-Correction Flow

The following sequence describes how a hallucinated verdict is resolved in Phase 3.

```
1. Phase 1 — run_sigma_scan() returns draft finding:
      record_id=4821, rule_title="LSASS Access via ProcessAccess",
      claimed_process="mimikatz.exe", claimed_timestamp="2021-03-04T14:22:11Z"

2. Phase 2 — verify_finding() is called with the draft values.
      The raw event at record_id=4821 shows TargetImage=lsass.exe,
      SourceImage=mimikatz.exe, but verify_finding compared claimed_process
      against TargetImage — mismatch.
      → verdict=HALLUCINATED returned.
      → Finding moved to DISCARDED list.

3. Phase 3 — get_event_detail() is called on the same record_id.
      Raw fields returned:
        SourceImage:  C:\Users\Attacker\mimikatz.exe
        TargetImage:  C:\Windows\System32\lsass.exe
        GrantedAccess: 0x1fffff
      The event is genuinely suspicious — ProcessAccess on LSASS with full access mask.

4. Correction — A new finding is constructed using actual field values:
      process = "lsass.exe" (TargetImage — what the rule fired on)
      utc_timestamp = value from raw event
      corrected_from_hallucination = true
      → Finding added to VERIFIED list.

5. Phase 4 — Corrected finding appears in final report with
      corrected_from_hallucination = true annotation.
```

This loop ran once across all 39 files, catching and correcting all 17 Sysmon EID 8/10
field-mismatch hallucinations in a single automated pass (19 minutes total runtime).
