#!/usr/bin/env bash
# run_investigation.sh — launch a self-correcting evtx-sentinel investigation
# Usage: ./run_investigation.sh <case_directory>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTOCOL="${SCRIPT_DIR}/CLAUDE.md"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <case_directory>" >&2
    exit 1
fi

CASE_DIR="$(realpath "$1")"

export HAYABUSA_BIN=/opt/hayabusa/hayabusa
export EVTXECMD_BIN=/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll

if [[ ! -d "${CASE_DIR}" ]]; then
    echo "Error: case directory does not exist: ${CASE_DIR}" >&2
    exit 1
fi

if [[ ! -f "${PROTOCOL}" ]]; then
    echo "Error: investigation protocol not found: ${PROTOCOL}" >&2
    exit 1
fi

cp "${PROTOCOL}" "${CASE_DIR}/CLAUDE.md"
echo "Investigation protocol installed: ${CASE_DIR}/CLAUDE.md"

mkdir -p "${CASE_DIR}/evidence" "${CASE_DIR}/reports"

echo "Launching investigation in: ${CASE_DIR}"
cd /home/sansforensics/work/evtx-sentinel
export EVTX_CASE_DIR="${CASE_DIR}"
exec claude --add-dir "${CASE_DIR}"
