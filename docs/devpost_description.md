# evtx-sentinel — Devpost Project Description

---

## What it does

Windows event log investigations are typically performed by AI agents that are *told* not to hallucinate — the guardrails are entirely prompt-based. Protocol SIFT, the proof-of-concept baseline we built first, demonstrates the problem clearly: give an agent a folder of EVTX files and ask it to find credential-theft activity, and it will produce plausible-looking findings where field values are occasionally wrong — wrong process name, wrong record ID, wrong direction of a logon. Nothing in the system *prevents* this. The agent is instructed to stay grounded but has no mechanism that enforces it.

evtx-sentinel makes the guardrails architectural instead of advisory. The agent connects to a read-only typed MCP server: it can list files, run Hayabusa sigma scans, look up individual records, summarize logon patterns, and verify a specific finding against the raw EVTX record — and that is the complete surface area. There is no tool to execute a shell command, no tool to write a file, no tool that could destroy evidence even if the agent tried. Every finding produced in Phase 2 (Triage) is passed through `verify_finding()` in Phase 3 (Validate/Correct) before it enters the final report. On our benchmark run across 39 credential-theft EVTX files, the system generated 53 findings, automatically caught and corrected 17 field-level hallucinations, and finished with 0 false positives discarded from the confirmed set.

---

## How we built it

The MCP server is written in Python using the official `mcp` SDK (v1.27.2) over stdio transport. It exposes six typed read-only tools: `list_evtx_files`, `register_evidence`, `run_sigma_scan`, `get_event_detail`, `get_logon_summary`, and `verify_finding`. Each tool shells out to Hayabusa v3.9.0 in analysis-only mode — no tool can write, rename, move, or delete any evidence file. Every call appends a structured JSON line to `logs/execution_log.jsonl` containing the ISO 8601 UTC timestamp, tool name, arguments, a SHA-256 digest of the serialized result, and wall-clock duration. This audit trail satisfies chain-of-custody requirements and makes every inference traceable to a specific raw tool invocation.

The agent runs a four-phase protocol. Phase 1 (Triage) calls `run_sigma_scan` across all registered EVTX files to surface candidate findings ranked by severity. Phase 2 (Validate) passes each finding through `verify_finding()`, which re-reads the actual EVTX record and compares every field the agent reported against ground truth. Phase 3 (Correct) calls `get_event_detail()` for any finding where verification failed, extracts the correct field values from the raw record, and rewrites the finding with a `CORRECTED` annotation. Phase 4 (Report) emits a structured final report with three sections — `CONFIRMED`, `CORRECTED`, and `DISCARDED` — so reviewers can see exactly what changed and why.

The development methodology was baseline-first. We ran stock Protocol SIFT on the same 39-file dataset, audited its output by hand, and catalogued every error. The most instructive was the PPLdump detection at EventRecordID 564592: the agent reported `lsass.exe` as the target process, but the actual record contained `winlogon.exe`. That single error — a field-attribution mistake rather than a fabricated event — defined the threat model we designed against. Every design decision in evtx-sentinel (the `verify_finding` tool, the mandatory four-field schema, the correction phase) traces back to that one audited error.

---

## Challenges

- **Hayabusa outputs pretty-printed multi-line JSON, not JSONL.** Naively splitting on newlines produced broken records. We fixed this by feeding raw stdout through Python's `json.JSONDecoder.raw_decode()` in a streaming loop, advancing the cursor after each successfully decoded object.
- **Hayabusa refuses to overwrite existing output files.** Between repeated runs during development the output path was already present and Hayabusa would exit early rather than clobber it. Fixed by passing the `-C` (clobber) flag so reruns are idempotent.
- **The MCP server registration did not follow the agent into case subdirectories.** When the agent changed working directory to a case folder, the project-scoped server registration was no longer in scope. Fixed by registering the server with an absolute path and always launching investigations from the `evtx-sentinel` root directory.

---

## What we learned

- **Architectural guardrails are fundamentally stronger than prompt-based guardrails.** A typed function that exposes no destructive surface cannot be argued, jailbroken, or misunderstood into causing harm. An instruction that says "do not hallucinate" can be — and routinely is — ignored under the right generation conditions. The difference is not a matter of degree; it is a categorical difference in the class of errors each approach can prevent.
- **The difference between a hallucination and a field-attribution error matters for detection.** The agent found the correct event — right timestamp, right EventRecordID, right channel — but reported the value from the wrong field (source process instead of target process). Human review that only checks "did the event exist?" passes this error. Automated verification that compares every reported field against the raw record catches it. This distinction shaped the design of `verify_finding()` and explains why field-level comparison, not just record-level existence, is the right unit of verification.

---

## What's next

- **Expand beyond Credential Access to all MITRE ATT&CK tactics.** The current sigma rule set is scoped to credential theft. The MCP server architecture is tactic-agnostic; adding Memory, Persistence, and Lateral Movement coverage is a matter of broadening the Hayabusa rule selection and adding tactic-specific verification heuristics.
- **Add EvtxECmd Maps integration for richer field extraction.** Hayabusa provides detection-oriented output; EvtxECmd with community Maps surfaces the full parsed field set for any event. Wrapping `EvtxECmd.dll` as an additional MCP tool would give the correction phase much richer raw data to work with.
- **Build a multi-agent variant where a Memory agent and a Disk agent cross-correlate findings.** EVTX logs record what Windows thought happened; memory and disk artifacts record what actually happened at the binary level. A coordinator that routes findings across both agents and flags contradictions would catch a class of anti-forensic evasion that neither source alone can detect.
