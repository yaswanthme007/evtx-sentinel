# evtx-sentinel — Permanent Rules for Claude Code

## Rule 1 — Read-Only MCP Server

The MCP server is **strictly read-only**. Never create tools that execute shell commands that write, delete, or modify evidence files. Every file handle opened against evidence must use read-only mode (`open(..., "rb")` or `"r"`). Tools may invoke Hayabusa and EvtxECmd in read-only analysis modes only. No tool may write to, rename, move, or delete any evidence file.

## Rule 2 — Mandatory Audit Logging

Every MCP tool call **must** append a JSON line to `logs/execution_log.jsonl` before returning. The line must contain exactly these keys:

```json
{
  "iso_timestamp": "<ISO 8601 UTC>",
  "tool_name": "<name of the MCP tool>",
  "arguments": { /* tool input args */ },
  "result_sha256": "<SHA-256 hex digest of the serialized result>",
  "duration_ms": 123
}
```

Logging failures must not suppress the tool result — log the error to stderr and continue.

## Rule 3 — Required Finding Fields

Every finding object returned by any tool **must** carry these four fields:

| Field | Description |
|---|---|
| `source_file` | Absolute path to the source `.evtx` file |
| `record_id` | The EventRecordID from the event record |
| `tool_name` | Name of the MCP tool that produced the finding |
| `utc_timestamp` | UTC timestamp of the event (ISO 8601) |

## Rule 4 — Platform and Binary Locations

- **Platform**: SIFT Workstation, Ubuntu 24.04, Python 3.12
- **MCP transport**: stdio (official `mcp` Python SDK)
- **Hayabusa binary**: `/opt/hayabusa/hayabusa` — override via `HAYABUSA_BIN` env var
- **EvtxECmd binary**: `/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` — override via `EVTXECMD_BIN` env var

Always read binary paths from environment variables at runtime; never hardcode paths in tool logic.

## Rule 5 — Minimal Pinned Dependencies

All runtime dependencies must be minimal and version-pinned in `requirements.txt`. No unpinned ranges (no `>=`, `~=`, or bare package names). Add a new dependency only when it has no reasonable stdlib equivalent. Dev/test dependencies go in `requirements-dev.txt`.
