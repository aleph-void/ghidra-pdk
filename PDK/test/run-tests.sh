#!/usr/bin/env bash
# Runs every PDK check that needs no non-redistributable input.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/PDK> \
#   SDCC_ROOT=<prefix holding an SDCC install with the pdk backends>   (or sdcc/ucsim_pdk/sdaspdk* on PATH) \
#     test/run-tests.sh [--real] [--per-form N] <workdir>
#
# Reference tools, all used as black boxes: SDCC's ucsim_pdk and sdaspdk13/14/15 (GPL), and the MIT-licensed
# fppa-pdk-tools disassembler (fetched by pinned archive + SHA-256 and built here).  --real also fetches the free-pdk
# showcase projects (GPL-3.0; pinned), builds them with SDCC and imports the images (nothing is committed).
# Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0; PER=8
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; --per-form) PER=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "$1" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }
# language id per instruction set and the chip table used for I/O register names
LANGS="13:pdk13:pdk13:LE:16:default 14:PMS132:pms132:LE:16:default 14:PMS152:pms152:LE:16:default 15:PMS134:pms134:LE:16:default 16:PMC884:pmc884:LE:16:default"

step "the generators reproduce the checked-in SLEIGH"
mkdir -p "$W/gen"
python3 -I "$MOD/tools/gen_pdk.py" "$W/gen" >/dev/null
python3 -I "$MOD/tools/gen_chips.py" "$W/gen"
for f in "$W"/gen/*.sinc; do ok diff -q "$f" "$MOD/data/languages/$(basename "$f")"; done

step "specs compile (sleigh -l: no unresolved pattern conflicts)"
for s in pdk13 PMS152 PMS132 PMS134 PMC884; do
	out=$("$GHIDRA_INSTALL_DIR/support/sleigh" -l "$MOD/data/languages/$s.slaspec" 2>&1)
	if grep -q "ERROR" <<<"$out"; then echo "$out" | grep ERROR | head; echo "FAILED: $s"; fail=1; else echo "$s compiles, no conflicts"; fi
done

step "reference dumps (fppa-pdk-tools dispdk, ucsim)"
ok "$HERE/fetch-oracles.sh" "$W"
O="$W/oracle"

step "decode vs dispdk and ucsim: every opcode word, bucketed differences"
for l in $LANGS; do
	IFS=: read -r w chip lang <<<"$l"
	python3 -I -c "
for i in range(1 << $w): print('%02x%02x' % (i & 255, i >> 8))" > "$W/cases$w.txt"
	ok "$HERE/dis.sh" "$lang" "$W/cases$w.txt" "$W/g-$chip.txt"
	ok python3 -I "$HERE/diff_decode.py" $w $chip "$W/g-$chip.txt" "$O/dispdk$w.txt" "$O/uc$w.txt"
done
step "decode check can fail (a corrupted result must be reported)"
sed '1,100s/NOP/ADDC A/; 3s/ .*/ BAD/' "$W/g-pdk13.txt" | sed '2s/ [^ ]* [^ ]*$/ 2 XOR A,#0x1/' > "$W/g-broken.txt"
if python3 -I "$HERE/diff_decode.py" 13 pdk13 "$W/g-broken.txt" "$O/dispdk13.txt" "$O/uc13.txt" >/dev/null 2>&1; then
	echo "FAILED: the corrupted result was not detected"; fail=1; else echo "corrupted result detected"; fi

step "assembler round trip (sdaspdk13/14/15 assemble Ghidra's disassembly back to the same words)"
for l in $LANGS; do
	IFS=: read -r w chip lang <<<"$l"
	[[ $w == 16 || $chip == PMS152 ]] && continue
	ok python3 -I "$HERE/sdas_roundtrip.py" $w $chip "$W/g-$chip.txt" "$W/rt"
done

step "every constructor is reached"
for l in $LANGS; do
	IFS=: read -r w chip lang <<<"$l"
	out=$("$HERE/every-entry.sh" "$lang" "$W/cases$w.txt" "$W/ee.$chip.txt" | tail -1)
	echo "$chip: $out"
	grep -q " 0 not reached" <<<"$out" || { echo FAILED; fail=1; }
done

step "p-code: hand-computed emulator cases (and deliberately wrong expectations)"
ok "$HERE/emu-test.sh" "$HERE/emu/cases.txt" "$W/emu"

step "p-code vs ucsim: single instructions from random states"
for l in $LANGS; do
	IFS=: read -r w chip lang <<<"$l"
	[[ $chip == PMS152 ]] && continue
	ok python3 -I "$HERE/sem_diff.py" $w $chip "$lang" "$W/g-$chip.txt" "$W/sem" --per-form $PER
done

if ((REAL)); then
	step "real programs: free-pdk showcase projects built with SDCC"
	ok "$HERE/fetch-real.sh" "$W"
	ok python3 -I "$HERE/real_check.py" "$W/real/check" $(cat "$W/real/images.txt")
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
