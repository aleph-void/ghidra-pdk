#!/usr/bin/env bash
# test/fetch-oracles.sh <workdir>
# Builds the MIT-licensed fppa-pdk-tools disassembler (pinned archive) into a per-width dump tool, and dumps the
# disassembly of every opcode word of PDK13/14/15/16 with it and with SDCC's ucsim_pdk (black boxes).
# Needs: curl, a C compiler, python3, ucsim_pdk (SDCC) on PATH or in UCSIM_PDK.
# Writes <workdir>/oracle/{dispdk,uc}{13,14,15,16}.txt
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
URL=https://github.com/free-pdk/fppa-pdk-tools/archive/670e7bc9c1b33469fe8c80cd4c1eeb053d20c191.tar.gz
SHA=$(cat "$HERE/pins/fppa-pdk-tools.sha256")
mkdir -p "$W/oracle"; cd "$W/oracle"
if [[ ! -f fppa-tools.tar.gz ]]; then curl -sSL -o fppa-tools.tar.gz "$URL"; fi
echo "$SHA  fppa-tools.tar.gz" | sha256sum -c - >/dev/null
[[ -d src ]] || { mkdir src && tar -xzf fppa-tools.tar.gz -C src --strip-components=1; }
if [[ ! -x dispall ]]; then
	( cd src && cc -O2 -std=c99 -Iinclude -o ../dispall "$HERE/oracle_dispall.c" emucpu/emucpu.c opcode/opcode1?.c \
		disass/disass1?.c cpuvariant/*.c pdkformat/pdkformat.c ihex/fpdkihex8.c )
fi
for w in 13 14 15 16; do
	[[ -s dispdk$w.txt ]] || ./dispall $w > dispdk$w.txt
	[[ -s uc$w.txt ]] || python3 -I "$HERE/oracle_dump.py" $w > uc$w.txt
done
echo "oracle dumps in $W/oracle"
