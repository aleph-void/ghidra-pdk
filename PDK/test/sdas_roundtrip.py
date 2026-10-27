#!/usr/bin/env python3
"""Assembler round trip: Ghidra's disassembly of every PDK13/14/15 opcode is turned into SDCC assembler syntax,
assembled with sdaspdk13/14/15 (black box) and the produced words must equal the original opcode.

usage: sdas_roundtrip.py <13|14|15> <chip> <ghidra.txt> <workdir>
GOTO/CALL are not compared here: the assembler scales absolute operands (see GHIDRA-RARE.md); they are covered by
the link test.
"""
import os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff_decode as D

import tools_path
SDAS = "sdaspdk%d"
SYN = {"DISGINT": "disgint", "PUSHAF": "push af", "POPAF": "pop af"}


def sdas_line(canon):
    mn, _, rest = canon.partition(" ")
    m = mn.lower()
    if mn in SYN:
        return SYN[mn]
    if not rest:
        return m
    ops = rest.split(",")
    io = any(o.startswith("IO:") for o in ops)
    out = []
    for o in ops:
        if o == "A":
            out.append("a")
        elif o.startswith("k:"):
            out.append("#0x" + o[2:])
        elif o.startswith("M:") or o.startswith("IO:"):
            v = o.split(":", 1)[1]
            if "." in v:
                v, b = v.split(".")
                out.append("0x" + v)
                out.append("#" + b)
            else:
                out.append("0x" + v)
        elif o.startswith("N:"):
            out.append("0x" + o[2:])
        else:
            raise ValueError(o)
    return m + (".io" if io else "") + " " + ", ".join(out)


def main():
    W = int(sys.argv[1]); chip = sys.argv[2]; gfile = sys.argv[3]; work = sys.argv[4]
    os.makedirs(work, exist_ok=True)
    ion = D.ionames(chip)
    rows = []
    for l in open(gfile):
        h, n, t = l.rstrip("\n").split(" ", 2)
        op = int(h[2:4] + h[0:2], 16)
        c = D.finalize_ghidra(D.canon_ghidra(t, ion))
        if c is None or c.split(" ")[0] in ("GOTO", "CALL", "PMODE", "PUSHWPC", "POPWPC"):
            continue
        rows.append((op, c))
    src = os.path.join(work, f"rt{W}.s")
    with open(src, "w") as f:
        f.write("\t.area CODE (ABS)\n\t.org 0\n")
        for op, c in rows:
            f.write("\t" + sdas_line(c) + "\n")
    subprocess.run([tools_path.find(SDAS % W), "-l", "-o", "-s", src], capture_output=True, text=True, cwd=work)
    lst = open(os.path.join(work, f"rt{W}.lst")).read().splitlines()
    got = {}
    for l in lst:
        m = re.match(r"\s*([0-9A-F]{6}) ([0-9A-F]{2}) ([0-9A-F]{2})\s+(\d+)\s", l)
        if m:
            got[int(m.group(4)) - 3] = int(m.group(3) + m.group(2), 16)
    ok = bad = rej = 0
    badl = []
    rejmn = {}
    for i, (op, c) in enumerate(rows):
        if i not in got:
            rej += 1
            rejmn[c.split(" ")[0]] = rejmn.get(c.split(" ")[0], 0) + 1
        elif got[i] == op:
            ok += 1
        else:
            bad += 1
            badl.append((op, c, got[i]))
    print(f"PDK{W} ({chip}) vs sdaspdk{W}: {ok} assemble to the same word, {bad} differ, {rej} not accepted by the assembler")
    for op, c, g in badl[:20]:
        print(f"   {op:04x} {c} -> sdas {g:04x}")
    for k, v in sorted(rejmn.items()):
        print(f"   assembler rejects {k}: {v}")
    sys.exit(1 if bad else 0)


main()
