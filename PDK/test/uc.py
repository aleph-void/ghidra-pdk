#!/usr/bin/env python3
"""Black-box driver for ucsim_pdk (SDCC's simulator): run one instruction from a given state, read the state back.
One simulator process per case (the interpreter loop is asynchronous, so a persistent session is not reliable)."""
import subprocess, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools_path
from multiprocessing import Pool

UCSIM = tools_path.find("ucsim_pdk", "UCSIM_PDK")
RAMN = 64


class Case:
    def __init__(s, w, op, A, F, SP, ram, rom=None, io=None):
        s.w, s.op, s.A, s.F, s.SP, s.ram, s.rom, s.io = w, op, A, F, SP, ram, rom or {}, io or {}


def script(c):
    L = [f"fill ram 0 {RAMN - 1} 0"]
    for i, b in enumerate(c.ram):
        L.append(f"set mem ram {i} {b}")
    L.append(f"set mem rom 0 {c.op}")
    for i in range(1, 4):
        L.append(f"set mem rom {i} 0")
    for a, v in c.rom.items():
        L.append(f"set mem rom {a} {v}")
    for a, v in c.io.items():
        L.append(f"set mem regs8 {a} {v}")
    L.append(f"set mem regs8 2 {c.SP}")
    L.append(f"expr A={c.A}")
    L.append(f"set mem regs8 0 {c.F}")
    L.append("pc 0")
    L.append("step")
    L.append(f"dump /h ram 0 {RAMN - 1}")
    L.append("quit")
    return "\n".join(L) + "\n"


def run1(c):
    out = subprocess.run([UCSIM, "-t", f"pdk{c.w}", "-b"], input=script(c), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, timeout=60).stdout
    if "Stop at" not in out:
        return None
    rep = out[out.rindex("Stop at"):]
    if "Invalid instruction" in rep.split("\n")[0]:
        return None
    ma = re.search(r"\nA=([0-9a-f]+)", rep)
    if ma is None:
        return None
    A = int(ma.group(1), 16)
    sp = int(re.search(r"\nSP=([0-9a-f]+)", rep).group(1), 16)
    F = int(re.search(r"\nF=([01]+)", rep).group(1), 2)
    pc = int(re.search(r"\+FPP0\*: 0x([0-9a-f]+)", rep).group(1), 16)
    ram = [0] * RAMN
    for l in rep.splitlines():
        m = re.match(r"0x([0-9a-f]{3}) ((?:[0-9a-f]{2} ){8})", l)
        if m:
            a = int(m.group(1), 16)
            for j, b in enumerate(m.group(2).split()):
                if a + j < RAMN:
                    ram[a + j] = int(b, 16)
    return dict(A=A, F=F, SP=sp, PC=pc, ram=ram)


def run(cases, procs=12):
    with Pool(procs) as p:
        return p.map(run1, cases, chunksize=16)
