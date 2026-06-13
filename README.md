# evtx-sentinel

evtx-sentinel is a read-only MCP (Model Context Protocol) server for Windows Event Log
analysis, purpose-built for DFIR investigations on SANS SIFT Workstation. It exposes six
typed tools — evidence registration, Sigma scanning via Hayabusa, logon summarisation,
raw event retrieval, and finding verification — each with mandatory SHA-256 audit logging
and strict read-only evidence access enforced at the code level, not just by prompt instruction.

Claude Code drives the server through a four-phase self-correcting investigation protocol:
triage all EVTX files, validate every draft finding against raw event records, correct
field-attribution errors discovered during validation, then emit a structured Markdown report.
On the EVTX-ATTACK-SAMPLES benchmark (39 files, 53 draft findings) the system caught and
corrected 17 hallucinations in a single automated pass, ending with 53 verified findings,
zero false positives discarded, and zero uncorrected field errors — completing in 19 minutes.

---

## Quick Start for Judges

```bash
# 1. Install the MCP server dependency (on SIFT)
pip3 install mcp==1.9.3

# 2. Register the MCP server with Claude Code
claude mcp add evtx-sentinel -- python3 /home/sansforensics/work/evtx-sentinel/server/mcp_server.py

# 3. Run an investigation against your case directory
bash /home/sansforensics/work/evtx-sentinel/agent/run_investigation.sh /path/to/case/evtx/

# The script:
#   - exports HAYABUSA_BIN and EVTXECMD_BIN
#   - installs the investigation protocol (CLAUDE.md) into the case directory
#   - launches Claude Code with the case directory added to its context
```

The agent runs fully autonomously. Final report is written to `<case_dir>/reports/`.

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| SIFT Workstation | 2026-04-22 or later | Ubuntu 24.04 base |
| Claude Code | 2.x | CLI; `claude` must be on PATH |
| Python | 3.12 | System Python on SIFT |
| Hayabusa | 3.9.0 | Must be at `/opt/hayabusa/hayabusa` or set `HAYABUSA_BIN` |
| dotnet runtime | 6.0 | Required for EvtxECmd; runtime-only, no SDK needed |
| mcp (Python) | 1.9.3 | Only non-stdlib dependency; pinned in `requirements.txt` |

---

## Architecture Summary

The MCP server (`server/mcp_server.py`) runs as a subprocess of Claude Code over stdio
transport. It enforces evidence integrity architecturally: every file handle is opened
read-only, SHA-256 is computed at intake, unregistered file IDs are rejected before any
subprocess spawns, and no generic shell execution is exposed. The agent layer adds a
behavioural protocol (four-phase loop, max-3-iterations cap, UTC-only timestamps) on top.
See [docs/architecture.md](docs/architecture.md) for the full component diagram, trust
boundary breakdown, and self-correction flow.

---

## Accuracy

| | Run 1 — Demo (Video) | Run 2 — Full Benchmark |
|---|---|---|
| EVTX files | 3 | 39 |
| Draft findings generated | 8 | 53 |
| Findings confirmed | 8 | 53 |
| Self-corrections applied | 4 | 17 |
| Self-correction iterations | 1 | 1 |
| Runtime | 4 minutes 16 seconds | 19 minutes |

The demo video shows Run 1. The full benchmark report is committed at reports/BASELINE-001_investigation_report.md.

- **Zero false positives discarded** across both runs
- **Hallucinations caught**: Sysmon EID 8/10 SrcProc vs. TgtProc field mismatch
- Baseline (Protocol SIFT stock) produced 1 uncaught process attribution error on the same dataset

See [docs/accuracy_report.md](docs/accuracy_report.md) for the full self-assessment including
known limitations and failure modes tested.

---

## License

MIT License © 2026 yaswanthme007
