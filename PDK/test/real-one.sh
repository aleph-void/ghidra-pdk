#!/usr/bin/env bash
# test/real-one.sh <language-id> <image.bin> <out.txt>   import (flat little-endian words at word address 0),
# analyse, then run RealCheck.java.   (GHIDRA_INSTALL_DIR set)
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; IMG=$(readlink -f "$2"); OUT=$(readlink -m "$3")
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/pdk-real.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$IMG" -loader BinaryLoader \
	-loader-baseAddr 0 -processor "$LANG_ID" -scriptPath "$HERE" \
	-postScript RealCheck.java "$OUT" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
