# evtx-sentinel

A read-only typed MCP server for Windows Event Log analysis on SIFT Workstation, driven by Claude Code with a 4-phase self-correcting validation loop. Built for the SANS FIND EVIL! Hackathon 2026.

## Overview

evtx-sentinel exposes Windows Event Log (`.evtx`) analysis capabilities as MCP tools consumable by Claude Code. It integrates Hayabusa and EvtxECmd as read-only analysis backends, wrapping their output in structured, typed responses with full audit logging.

## Architecture

```
Claude Code
    │
    ▼  stdio
MCP Server (server/)
    │
    ├── Hayabusa  (/opt/hayabusa/hayabusa)
    └── EvtxECmd  (/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll)
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the MCP server
python server/main.py
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HAYABUSA_BIN` | `/opt/hayabusa/hayabusa` | Path to Hayabusa binary |
| `EVTXECMD_BIN` | `/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` | Path to EvtxECmd DLL |

## Audit Logging

Every tool call is appended to `logs/execution_log.jsonl` with timestamp, tool name, arguments, result hash (SHA-256), and duration.

## Platform

SIFT Workstation · Ubuntu 24.04 · Python 3.12 · MCP stdio transport

## License

MIT License © 2026 kbyas
