#!/usr/bin/env python3
"""
evtx-sentinel MCP Server
Read-only Windows Event Log analysis via Hayabusa, exposed over stdio transport.

Rules enforced (per CLAUDE.md):
  Rule 1 — all evidence files opened read-only; no write/delete operations.
  Rule 2 — every tool call appended to logs/execution_log.jsonl.
  Rule 3 — every finding carries source_file, record_id, tool_name, utc_timestamp.
  Rule 4 — binary paths resolved from HAYABUSA_BIN / EVTXECMD_BIN env vars.
  Rule 5 — minimal stdlib-only deps; only mcp pinned in requirements.txt.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# ── Project-relative paths ────────────────────────────────────────────────────

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
_LOG_FILE: Path = _PROJECT_ROOT / "logs" / "execution_log.jsonl"

# ── Severity ordering (ascending) ─────────────────────────────────────────────

_LEVEL_ORDER: list[str] = ["informational", "low", "medium", "high", "critical"]

# ── In-memory evidence manifest ───────────────────────────────────────────────
# Keyed by file_id (basename). Value: {path, sha256, size_bytes, mtime_utc}.
# Populated by register_evidence(); all other tools refuse unregistered file_ids.

_manifest: dict[str, dict[str, Any]] = {}

# ── MCP server instance ───────────────────────────────────────────────────────

mcp = FastMCP("evtx-sentinel")


# ═════════════════════════════════════════════════════════════════════════════
# Private helpers
# ═════════════════════════════════════════════════════════════════════════════


def _sha256_file(path: Path) -> str:
    """Return SHA-256 hex digest of *path* using read-only binary access."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def _now_utc() -> str:
    """ISO 8601 UTC timestamp of the current moment."""
    return datetime.now(timezone.utc).isoformat()


def _log_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    result: Any,
    duration_ms: float,
) -> None:
    """Append one audit JSON line to logs/execution_log.jsonl (Rule 2).

    A failure here prints to stderr and never suppresses the tool result.
    """
    serialised = json.dumps(result, default=str, sort_keys=True)
    entry = {
        "iso_timestamp": _now_utc(),
        "tool_name": tool_name,
        "arguments": arguments,
        "result_sha256": hashlib.sha256(serialised.encode()).hexdigest(),
        "duration_ms": round(duration_ms, 3),
    }
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as exc:  # noqa: BLE001
        print(f"[audit-log-error] {exc}", file=sys.stderr)


def _require_registered(file_id: str) -> dict[str, Any]:
    """Return the manifest entry for *file_id* or raise ValueError."""
    if file_id not in _manifest:
        raise ValueError(
            f"file_id '{file_id}' is not registered — call register_evidence() first."
        )
    return _manifest[file_id]


def _hayabusa_bin() -> str:
    """Hayabusa binary path: HAYABUSA_BIN env var or default (Rule 4)."""
    return os.environ.get("HAYABUSA_BIN", "/opt/hayabusa/hayabusa")


def _make_tmp(suffix: str = ".jsonl") -> Path:
    """Create a uniquely named temp file and return its Path."""
    fd, path_str = tempfile.mkstemp(suffix=suffix, prefix="evtx_sentinel_")
    os.close(fd)
    return Path(path_str)


def _level_at_or_above(level: str, min_level: str) -> bool:
    """True when *level* >= *min_level* in Hayabusa severity order."""

    def _norm(s: str) -> str:
        s = s.lower()
        return "informational" if s == "info" else s

    try:
        return _LEVEL_ORDER.index(_norm(level)) >= _LEVEL_ORDER.index(_norm(min_level))
    except ValueError:
        return False


def _field(event: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first non-None value found under any of *keys* in *event*."""
    for k in keys:
        v = event.get(k)
        if v is not None:
            return v
    return default


def _parse_hayabusa_output(filepath: str) -> list[dict]:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    if not content:
        return []
    decoder = json.JSONDecoder()
    results = []
    pos = 0
    while pos < len(content):
        while pos < len(content) and content[pos].isspace():
            pos += 1
        if pos >= len(content):
            break
        try:
            obj, end_pos = decoder.raw_decode(content, pos)
            results.append(obj)
            pos = end_pos
        except json.JSONDecodeError:
            break
    return results


def _run_json_timeline(source_file: str) -> list[dict[str, Any]]:
    """Run ``hayabusa json-timeline`` and return all parsed JSONL event dicts.

    The temp output file is unconditionally cleaned up in the finally block.
    Uses ``check=False`` so partial or no-finding runs are handled gracefully.
    """
    tmp = _make_tmp(".jsonl")
    events: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(
            [
                _hayabusa_bin(),
                "json-timeline",
                "-f", source_file,
                "-o", str(tmp),
                "-p", "verbose",
                "-w",
                "-U",
                "-C",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode not in (0, 1):
            # Return code 1 is "no alerts found" — still valid.
            print(f"[hayabusa stderr] {proc.stderr[:500]}", file=sys.stderr)

        if tmp.exists() and tmp.stat().st_size > 0:
            events = _parse_hayabusa_output(str(tmp))
    finally:
        tmp.unlink(missing_ok=True)
    return events


def _fetch_event_by_record_id(
    source_file: str, record_id: int
) -> dict[str, Any]:
    """Find the single event matching *record_id* in *source_file*.

    Returns the enriched event dict (with Rule-3 fields set) on success,
    or ``{"found": False, ...}`` when the record is absent.
    """
    for event in _run_json_timeline(source_file):
        raw_rid = _field(event, "RecordID", "EventRecordID", "record_id")
        try:
            if int(raw_rid) == record_id:
                ts = _field(event, "Timestamp", "DateTime", "timestamp")
                return {
                    **event,
                    # Rule 3 required fields — overlaid to guarantee presence
                    "source_file": source_file,
                    "record_id": record_id,
                    "tool_name": "get_event_detail",
                    "utc_timestamp": ts,
                    "found": True,
                }
        except (TypeError, ValueError):
            continue
    return {"found": False, "record_id": record_id, "source_file": source_file}


# ═════════════════════════════════════════════════════════════════════════════
# Tool 1 — register_evidence
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def register_evidence(path: str) -> dict:
    """Register an evidence file for analysis.

    Computes SHA-256, records size and mtime, and stores the file in the
    in-memory manifest keyed by basename (``file_id``).  Every other tool
    refuses to operate on a file that has not been registered first.

    Returns ``file_id``, ``sha256``, ``size_bytes``, ``mtime_utc``.
    """
    t0 = time.monotonic()
    call_args: dict[str, Any] = {"path": path}

    file_path = Path(path).resolve()
    if not file_path.is_file():
        result: dict[str, Any] = {"error": f"Not a regular file or does not exist: {path}"}
        _log_tool_call("register_evidence", call_args, result, (time.monotonic() - t0) * 1000)
        return result

    file_id = file_path.name
    sha256 = _sha256_file(file_path)
    stat = file_path.stat()
    mtime_utc = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

    _manifest[file_id] = {
        "path": str(file_path),
        "sha256": sha256,
        "size_bytes": stat.st_size,
        "mtime_utc": mtime_utc,
    }

    result = {
        "file_id": file_id,
        "sha256": sha256,
        "size_bytes": stat.st_size,
        "mtime_utc": mtime_utc,
    }
    _log_tool_call("register_evidence", call_args, result, (time.monotonic() - t0) * 1000)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Tool 2 — list_evtx_files
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def list_evtx_files() -> list:
    """Return all registered ``.evtx`` files with their ``file_id`` and ``sha256``."""
    t0 = time.monotonic()
    result: list[dict[str, str]] = [
        {"file_id": fid, "sha256": entry["sha256"]}
        for fid, entry in _manifest.items()
        if fid.lower().endswith(".evtx")
    ]
    _log_tool_call("list_evtx_files", {}, result, (time.monotonic() - t0) * 1000)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Tool 3 — run_sigma_scan
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def run_sigma_scan(file_id: str, min_level: str = "medium") -> dict:
    """Run Hayabusa sigma/detection scan and return filtered findings.

    Executes ``hayabusa json-timeline -f <file> -o <tmp> -p verbose -w -U``
    then filters the JSONL output to events at or above *min_level*.
    Severity order: ``informational`` < ``low`` < ``medium`` < ``high`` < ``critical``.

    Each finding carries the four Rule-3 required fields:
    ``source_file``, ``record_id``, ``tool_name``, ``utc_timestamp``.

    Returns ``file_id``, ``total_scanned``, ``findings_count``, ``findings``.
    """
    t0 = time.monotonic()
    call_args: dict[str, Any] = {"file_id": file_id, "min_level": min_level}

    try:
        entry = _require_registered(file_id)
    except ValueError as exc:
        result: dict[str, Any] = {"error": str(exc)}
        _log_tool_call("run_sigma_scan", call_args, result, (time.monotonic() - t0) * 1000)
        return result

    source_file = entry["path"]
    events = _run_json_timeline(source_file)
    total_scanned = len(events)
    findings: list[dict[str, Any]] = []

    for event in events:
        level = str(_field(event, "Level", "level", default="")).lower()
        if not _level_at_or_above(level, min_level):
            continue

        findings.append({
            # Rule 3 required fields
            "source_file": source_file,
            "record_id": _field(event, "RecordID", "EventRecordID", "record_id"),
            "tool_name": "run_sigma_scan",
            "utc_timestamp": _field(event, "Timestamp", "DateTime", "timestamp"),
            # Finding-specific fields
            "rule_title": _field(event, "RuleTitle", "Title", "rule_title", default=""),
            "level": level,
            "event_id": _field(event, "EventID", "event_id"),
            "channel": _field(event, "Channel", "channel", default=""),
            "computer": _field(event, "Computer", "computer", default=""),
            "details": _field(event, "Details", "details", default=""),
        })

    result = {
        "file_id": file_id,
        "total_scanned": total_scanned,
        "findings_count": len(findings),
        "findings": findings,
    }
    _log_tool_call("run_sigma_scan", call_args, result, (time.monotonic() - t0) * 1000)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Tool 4 — get_logon_summary
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def get_logon_summary(file_id: str) -> dict:
    """Run Hayabusa logon-summary on a registered ``.evtx`` file.

    Executes ``hayabusa logon-summary -f <file> -U -o <tmp>`` and parses the
    output (CSV file preferred; stdout fallback).

    Returns ``successful_logons``, ``failed_logons``,
    ``top_accounts`` (list of ``{username, count}``),
    ``top_source_ips`` (list of ``{ip, count}``).
    """
    t0 = time.monotonic()
    call_args: dict[str, Any] = {"file_id": file_id}

    try:
        entry = _require_registered(file_id)
    except ValueError as exc:
        result: dict[str, Any] = {"error": str(exc)}
        _log_tool_call("get_logon_summary", call_args, result, (time.monotonic() - t0) * 1000)
        return result

    source_file = entry["path"]
    tmp = _make_tmp(".csv")
    successful_logons = 0
    failed_logons = 0
    top_accounts: list[dict[str, Any]] = []
    top_source_ips: list[dict[str, Any]] = []

    try:
        proc = subprocess.run(
            [
                _hayabusa_bin(),
                "logon-summary",
                "-f", source_file,
                "-U",
                "-o", str(tmp),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode not in (0, 1):
            print(f"[hayabusa stderr] {proc.stderr[:500]}", file=sys.stderr)

        # Prefer the output file; fall back to stdout if the file is empty.
        raw = ""
        if tmp.exists() and tmp.stat().st_size > 0:
            with open(tmp, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        if not raw.strip():
            raw = proc.stdout

        current_section: Optional[str] = None

        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lower = line.lower()

            # ── Aggregate totals written as "Key: Value" ──────────────────
            if "total successful" in lower:
                try:
                    successful_logons = int(line.split(":")[-1].strip().replace(",", ""))
                except ValueError:
                    pass
                continue
            if "total failed" in lower:
                try:
                    failed_logons = int(line.split(":")[-1].strip().replace(",", ""))
                except ValueError:
                    pass
                continue

            # ── Section header detection ──────────────────────────────────
            if "source ip" in lower:
                current_section = "ips"
                continue
            if any(kw in lower for kw in ("successful logon", "failed logon", "logon summary")):
                current_section = "logons"
                continue
            if any(kw in lower for kw in ("username", "account name")):
                current_section = "accounts"
                continue

            # Skip CSV column-header rows
            if lower.startswith(("username", "account", "logon type", "ip address")):
                continue

            # ── Parse CSV data rows ───────────────────────────────────────
            if "," not in line:
                continue
            cols = [c.strip().strip('"') for c in line.split(",")]
            if len(cols) < 2:
                continue

            # Last numeric column is the primary count
            count_val = 0
            for col in reversed(cols):
                try:
                    count_val = int(col.replace(",", ""))
                    break
                except ValueError:
                    continue

            if current_section == "ips":
                top_source_ips.append({"ip": cols[0], "count": count_val})
            elif current_section in ("accounts", "logons"):
                # Three-column rows carry per-user successful + failed counts
                if len(cols) >= 3:
                    try:
                        successful_logons += int(cols[1].replace(",", ""))
                        failed_logons += int(cols[2].replace(",", ""))
                    except ValueError:
                        pass
                top_accounts.append({"username": cols[0], "count": count_val})

    finally:
        tmp.unlink(missing_ok=True)

    result = {
        "file_id": file_id,
        "successful_logons": successful_logons,
        "failed_logons": failed_logons,
        "top_accounts": top_accounts[:20],
        "top_source_ips": top_source_ips[:20],
    }
    _log_tool_call("get_logon_summary", call_args, result, (time.monotonic() - t0) * 1000)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Tool 5 — get_event_detail
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def get_event_detail(file_id: str, record_id: int) -> dict:
    """Return the full Hayabusa JSONL record for a specific EventRecordID.

    Runs ``hayabusa json-timeline`` and searches all output for the matching
    ``RecordID`` / ``EventRecordID``.  Returns ``{"found": false, ...}`` when
    the record is absent.  The result includes the four Rule-3 required fields.
    """
    t0 = time.monotonic()
    call_args: dict[str, Any] = {"file_id": file_id, "record_id": record_id}

    try:
        entry = _require_registered(file_id)
    except ValueError as exc:
        result: dict[str, Any] = {"error": str(exc)}
        _log_tool_call("get_event_detail", call_args, result, (time.monotonic() - t0) * 1000)
        return result

    result = _fetch_event_by_record_id(entry["path"], record_id)
    _log_tool_call("get_event_detail", call_args, result, (time.monotonic() - t0) * 1000)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Tool 6 — verify_finding
# ═════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def verify_finding(
    file_id: str,
    record_id: int,
    claimed_process: Optional[str] = None,
    claimed_event_id: Optional[int] = None,
    claimed_timestamp: Optional[str] = None,
) -> dict:
    """Verify claimed forensic values against the actual event record.

    Fetches the event identified by *record_id* and compares each provided
    ``claimed_*`` value against the corresponding field extracted from the
    actual JSONL record.

    ``verdict`` is ``CONFIRMED`` when every checked field matches (or no
    claims were provided), ``HALLUCINATED`` if any mismatch is detected or
    the record does not exist.

    ``evidence_reference`` is formatted as ``<file_id>#<record_id>@<sha256>``.
    """
    t0 = time.monotonic()
    call_args: dict[str, Any] = {
        "file_id": file_id,
        "record_id": record_id,
        "claimed_process": claimed_process,
        "claimed_event_id": claimed_event_id,
        "claimed_timestamp": claimed_timestamp,
    }

    try:
        entry = _require_registered(file_id)
    except ValueError as exc:
        result: dict[str, Any] = {"error": str(exc)}
        _log_tool_call("verify_finding", call_args, result, (time.monotonic() - t0) * 1000)
        return result

    # Use the private helper to avoid a second audit-log entry for the internal
    # event lookup (verify_finding is already logged as the MCP tool call).
    detail = _fetch_event_by_record_id(entry["path"], record_id)

    if not detail.get("found", False):
        result = {
            "record_id": record_id,
            "verdict": "HALLUCINATED",
            "reason": "record_id not found in evidence file",
            "file_id": file_id,
            "source_file": entry["path"],
            "tool_name": "verify_finding",
            "utc_timestamp": None,
        }
        _log_tool_call("verify_finding", call_args, result, (time.monotonic() - t0) * 1000)
        return result

    # ── Extract actual field values ────────────────────────────────────────
    details_val = _field(detail, "Details", "details")
    details_str = str(details_val) if details_val is not None else ""
    actual_event_id = _field(detail, "EventID", "event_id")
    actual_timestamp = _field(detail, "Timestamp", "DateTime", "utc_timestamp", "timestamp")

    # Ordered key preference: TgtProc covers Sysmon EID-10 process-access events.
    _PROC_KEYS = ("TgtProc", "Proc", "Image", "ProcessName", "TargetImage")

    # Process name — check Details dict directly first, then fall back to string
    # parsing for older / flat Hayabusa output formats.
    actual_process: Optional[str] = None
    if isinstance(details_val, dict):
        for k in _PROC_KEYS:
            v = details_val.get(k)
            if v:
                actual_process = str(v)
                break

    if actual_process is None:
        for proc_key in _PROC_KEYS:
            for sep in (":", "="):
                marker = f"{proc_key}{sep}"
                if marker in details_str:
                    idx = details_str.index(marker) + len(marker)
                    tail = details_str[idx:].strip()
                    # Find end of this sub-field value (Hayabusa uses ¦ as separator)
                    end = len(tail)
                    for delim in ("¦", "|", "\n"):
                        pos = tail.find(delim)
                        if pos != -1 and pos < end:
                            end = pos
                    actual_process = tail[:end].strip() or None
                    break
            if actual_process:
                break

    # ── Compare claimed vs actual ──────────────────────────────────────────
    field_matches: dict[str, bool] = {}

    if claimed_process is not None:
        if actual_process is None:
            field_matches["process"] = False
        else:
            # Case-insensitive; allow basename / suffix matching for full paths
            cp = claimed_process.lower().strip()
            ap = actual_process.lower().strip()
            field_matches["process"] = cp == ap or ap.endswith(cp) or cp.endswith(ap)

    if claimed_event_id is not None:
        try:
            field_matches["event_id"] = int(actual_event_id) == int(claimed_event_id)
        except (TypeError, ValueError):
            field_matches["event_id"] = False

    if claimed_timestamp is not None:
        def _norm_ts(ts: str) -> str:
            # Truncate to minute precision to tolerate sub-second differences
            return ts.replace("Z", "").replace("+00:00", "").replace(" ", "T")[:16]

        actual_ts_str = str(actual_timestamp) if actual_timestamp is not None else ""
        field_matches["timestamp"] = _norm_ts(actual_ts_str) == _norm_ts(str(claimed_timestamp))

    # Vacuously CONFIRMED when no claims are provided; otherwise require all True
    verdict = "HALLUCINATED" if field_matches and not all(field_matches.values()) else "CONFIRMED"

    result = {
        "record_id": record_id,
        "actual_process": actual_process,
        "actual_event_id": actual_event_id,
        "actual_timestamp": actual_timestamp,
        "claimed_process": claimed_process,
        "claimed_event_id": claimed_event_id,
        "claimed_timestamp": claimed_timestamp,
        "field_matches": field_matches,
        "verdict": verdict,
        "evidence_reference": f"{file_id}#{record_id}@{entry['sha256']}",
        # Rule 3 required fields
        "source_file": entry["path"],
        "tool_name": "verify_finding",
        "utc_timestamp": actual_timestamp,
    }
    _log_tool_call("verify_finding", call_args, result, (time.monotonic() - t0) * 1000)
    return result


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Start the evtx-sentinel MCP server on stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
