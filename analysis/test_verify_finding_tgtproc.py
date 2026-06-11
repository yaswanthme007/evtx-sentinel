#!/usr/bin/env python3
"""Test: verify_finding extracts TgtProc from Sysmon EID-10 Details dict."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import mcp_server as srv

_FAKE_EVENT = {
    "Timestamp": "2023-11-15T08:22:31.000Z",
    "RecordID": 564592,
    "EventID": 10,
    "Level": "high",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "WORKSTATION01",
    "RuleTitle": "Credential Dumping via LSASS Access",
    "Details": {
        "TgtProc": r"C:\Windows\system32\winlogon.exe",
        "SrcProc": r"C:\Windows\system32\svchost.exe",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+...",
    },
}

FILE_ID = "test_sysmon.evtx"
FAKE_PATH = "/fake/evidence/test_sysmon.evtx"


class TestVerifyFindingTgtProc(unittest.TestCase):
    def setUp(self):
        srv._manifest[FILE_ID] = {
            "path": FAKE_PATH,
            "sha256": "deadbeef" * 8,
            "size_bytes": 1024,
            "mtime_utc": "2023-11-15T00:00:00+00:00",
        }

    def tearDown(self):
        srv._manifest.pop(FILE_ID, None)

    def test_record_564592_lsass_is_hallucinated(self):
        with patch.object(srv, "_run_json_timeline", return_value=[_FAKE_EVENT]):
            result = srv.verify_finding(
                file_id=FILE_ID,
                record_id=564592,
                claimed_process="lsass.exe",
            )

        actual_process = result.get("actual_process")
        verdict = result.get("verdict")

        print(f"\n  actual_process : {actual_process!r}")
        print(f"  verdict        : {verdict!r}")
        print(f"  field_matches  : {result.get('field_matches')}")

        self.assertEqual(
            actual_process,
            r"C:\Windows\system32\winlogon.exe",
            f"actual_process mismatch: {actual_process!r}",
        )
        self.assertEqual(verdict, "HALLUCINATED", f"verdict mismatch: {verdict!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
