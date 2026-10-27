#!/usr/bin/env bash
# P-code emulation test: test/emu-test.sh [cases.txt] [outdir]
# Runs test/emu/cases.txt for each instruction set (PDK13, PDK14, PDK15, PDK16).  Exit status 0 only if every case
# passes and the deliberately broken expectation is detected.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
CASES=$(readlink -f "${1:-$HERE/emu/cases.txt}")
OUTD=$(readlink -m "${2:-${TMPDIR:-/tmp}/pdk-emu}")
mkdir -p "$OUTD"
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/pdk-emu.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
rc=0
for lang in pdk13:LE:16:default pms132:LE:16:default pms134:LE:16:default pmc884:LE:16:default; do
	out="$OUTD/${lang%%:*}.txt"
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" \
		-loader BinaryLoader -loader-baseAddr 0 -processor "$lang" -noanalysis -scriptPath "$HERE" \
		-postScript EmuTest.java "$CASES" "$out" -deleteProject >"$PROJ/log.txt" 2>&1 \
		|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
	[[ -s $out ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
	grep -v "^PASS (broken" "$out" | grep -v "^PASS " || true
	grep -q " 0 failed, broken expectation detected" "$out" || rc=1
done
exit $rc
