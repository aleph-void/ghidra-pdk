#!/usr/bin/env bash
# test/sem.sh <language-id> <cases> <out>   run SemCheck.java (single-instruction emulation) headless
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; IN=$(readlink -f "$2"); OUT=$(readlink -m "$3")
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/pdk-sem.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0 -processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript SemCheck.java "$IN" "$OUT" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
