#!/usr/bin/env python3
"""Dump ucsim_pdk's (black box) disassembly of every opcode word: oracle_dump.py <13|14|15|16> > out
(8192 words per simulator run: ROM of the simulated chip)"""
import os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools_path

UCSIM = tools_path.find("ucsim_pdk", "UCSIM_PDK")
w = int(sys.argv[1]); n = 1 << w
for base in range(0, n, 8192):
    cnt = min(8192, n - base)
    cmds = "".join(f"set mem rom {i} {base + i}\n" for i in range(cnt)) + f"dc 0 {cnt - 1}\nquit\n"
    out = subprocess.run([UCSIM, "-t", f"pdk{w}", "-b"], input=cmds, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, timeout=900).stdout
    # a disassembly line is "0xAAAA  <marker> WWWW   text"; the echoes of the set commands have wide gaps instead
    seen = {}
    for line in out.splitlines():
        m = re.search(r"0x([0-9a-f]{4})  \S ([0-9a-f]{4}) {2,}(\S.*?)\s*$", line)
        if m and int(m.group(2), 16) == base + int(m.group(1), 16):
            seen[int(m.group(1), 16)] = m.group(3).strip()
    for a in sorted(seen):
        print("%04x %s" % (base + a, seen[a]))
    got = len(seen)
    if got != cnt:
        sys.exit(f"ucsim returned {got} of {cnt} lines at {base}")
