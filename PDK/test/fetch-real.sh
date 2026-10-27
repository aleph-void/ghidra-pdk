#!/usr/bin/env bash
# test/fetch-real.sh <workdir>
# Fetches the free-pdk "easy-pdk-showcase-projects" (GPL-3.0; pinned archive + SHA-256), builds every project for every
# target it supports with SDCC (-mpdk13 / -mpdk14 / -mpdk15) and converts the Intel HEX images to flat binaries
# (little-endian 16-bit words, byte offset = 2 * word address).  Nothing built or fetched is committed.
# Needs: curl, make, sdcc + makebin (SDCC 4.x with the pdk backends; SDCC_ROOT=<prefix containing usr/bin/sdcc> if not on PATH).
# Writes <workdir>/real/out/*.bin and <workdir>/real/images.txt  (lines: <image>:<width>:<chip>:<language-id>)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
URL=https://github.com/free-pdk/easy-pdk-showcase-projects/archive/6a42c21fe7da5a35af5cb2002a9e8c0c1bd3234d.tar.gz
SHA=$(cat "$HERE/pins/easy-pdk-showcase-projects.sha256")
if [[ -n ${SDCC_ROOT:-} ]]; then export PATH=$SDCC_ROOT/usr/bin:$PATH SDCC_HOME=$SDCC_ROOT/usr/share/sdcc; fi
command -v sdcc >/dev/null || { echo "sdcc not found (set SDCC_ROOT)" >&2; exit 2; }
mkdir -p "$W/real/out"; cd "$W/real"
[[ -f showcase.tar.gz ]] || curl -sSL -o showcase.tar.gz "$URL"
echo "$SHA  showcase.tar.gz" | sha256sum -c - >/dev/null
rm -rf src build; mkdir src build
tar -xzf showcase.tar.gz -C src --strip-components=1
: > images.txt
for p in audioplayer noiseplug polysound ws2812animation16x16; do
	cp -r "src/$p" "build/$p"
	for t in $(grep -o 'MAKECMDGOALS),[A-Z0-9]*' "build/$p/Makefile" | sed 's/.*,//' | sort -u); do
		( cd "build/$p" && rm -rf build && make "$t" >/dev/null 2>&1 ) || { echo "build of $p $t failed" >&2; exit 1; }
		for ihx in build/$p/build/*."$t".ihx; do
			out="out/$(basename "${ihx%.ihx}").bin"
			makebin -p < "$ihx" > "$out"
			case $t in
				PMS150C) echo "$W/real/$out:13:pdk13:pdk13:LE:16:default" >> images.txt ;;
				PFS173)  echo "$W/real/$out:15:PMS134:pms134:LE:16:default" >> images.txt ;;
				*)       echo "$W/real/$out:14:PMS132:pms132:LE:16:default" >> images.txt ;;
			esac
		done
	done
done
echo "$(wc -l < images.txt) images in $W/real/out"
