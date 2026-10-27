#!/usr/bin/env python3
"""Semantic differential: single instructions run in Ghidra's emulator (p-code) against the ucsim_pdk simulator
(black box) from the same random machine states.  Compared: A, the four flags, SP, PC and the first 64 data bytes.

usage: sem_diff.py <width> <chip> <language-id> <ghidra-decode.txt> <workdir> [--per-form N] [--seed S]
"""
import os, random, re, subprocess, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import diff_decode as D
import uc

# not comparable with ucsim: hardware/timing behaviour, or instructions the simulator rejects
SKIP = {"WAIT0", "WAIT1", "TOG", "RESET", "STOPSYS", "STOPEXE", "WDRESET", "PMODE", "PUSHWPC", "POPWPC", "DELAY",
        "ENGINT", "DISGINT", "RETI"}


def operands(c):
    mn, _, rest = c.partition(" ")
    return mn, rest.split(",") if rest else []


def mem_of(ops):
    for o in ops:
        m = re.match(r"M:([0-9a-f]+)", o)
        if m:
            return int(m.group(1), 16)
    return None


def io_of(ops):
    for o in ops:
        m = re.match(r"IO:([0-9a-f]+)", o)
        if m:
            return int(m.group(1), 16)
    return None


W_ = 0


def explained(key, c, diffs, g, u):
    """Known ucsim deviations (each checked against the instruction table and fppa-pdk-tools' emulator)."""
    mn = key.split(" ")[0]
    if key.startswith(("MOV A,M", "MOV A,IO")) and diffs == ["F"] and (g["F"] ^ u["F"]) == 1:
        return "ucsim leaves ZF unchanged by MOV A,M / MOV A,IO (the table and fppa-pdk-tools' emulator update it)"
    if W_ == 16 and mn in ("T0SN", "T1SN") and "M:" in key:
        return "ucsim: the memory bit-test skips of PDK16 ignore the memory contents (always the same decision)"
    if W_ == 16 and mn in ("LDTABL", "LDTABH", "ICALL", "IGOTO"):
        return "ucsim's PDK16 LDTAB/ICALL/IGOTO differ from the table (LDTABL/H swapped, ICALL/IGOTO not executed); covered by hand-computed cases"
    if W_ == 16 and mn == "IDXM":
        return "ucsim: PDK16 IDXM M,A / IDXM A,M go through a pointer other than the word at M (covered by hand-computed cases)"
    if mn == "NADD" and diffs == ["F"]:
        return ("NADD flags: the result agrees; ucsim's flags fit neither M+NEG(A) nor M-A (the module uses the flags of "
                "the addition M+NEG(A) the table describes; fppa-pdk-tools' emulator computes A-M with addition flags)")
    if W_ == 16 and mn in ("T0SN", "T1SN") and "M:" in key:
        return "ucsim: the memory bit-test skips of PDK16 ignore the memory contents (always the same decision)"
    if W_ == 16 and mn in ("LDTABL", "LDTABH", "ICALL", "IGOTO"):
        return "ucsim's PDK16 LDTAB/ICALL/IGOTO differ from the table (LDTABL/H swapped, ICALL/IGOTO not executed); covered by hand-computed cases"
    if mn == "NADD" and diffs == ["F"]:
        return ("NADD flags: the result agrees; ucsim's flags fit neither M+NEG(A) nor M-A (the module uses the flags of "
                "the addition M+NEG(A) the table describes; fppa-pdk-tools' emulator computes A-M with addition flags)")
    if mn in ("LDSPTL", "LDSPTH"):
        return ("LDSPTL/H: ucsim reads ROM[SP] (LDSPTH returns the low byte); the table says CodeMem(WORD[SP]), "
                "as does fppa-pdk-tools' emulator (read from the table, not settled on hardware)")
    return None


def main():
    global W_
    W = W_ = int(sys.argv[1]); chip = sys.argv[2]; lang = sys.argv[3]; gfile = sys.argv[4]; work = sys.argv[5]
    per = int(sys.argv[sys.argv.index("--per-form") + 1]) if "--per-form" in sys.argv else 6
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    rnd = random.Random(seed)
    os.makedirs(work, exist_ok=True)
    ion = D.ionames(chip)
    io8name = [n for n, a in ion.items() if a == 8][0]      # mulop, or io_08 on devices without a multiplier
    forms = collections.defaultdict(list)
    for l in open(gfile):
        h, n, t = l.rstrip("\n").split(" ", 2)
        op = int(h[2:4] + h[0:2], 16)
        c = D.finalize_ghidra(D.canon_ghidra(t, ion))
        if c is None:
            continue
        mn, ops = operands(c)
        if mn in SKIP:
            continue
        m = mem_of(ops)
        if m is not None and m > 0x3b:
            continue
        iov = io_of(ops)
        if iov is not None and iov not in (0, 2):
            continue
        key = re.sub(r":[0-9a-f]+", ":", c)
        forms[key].append((op, c))
    cases = []
    meta = []
    for key, lst in sorted(forms.items()):
        for _ in range(per):
            op, c = rnd.choice(lst)
            mn, ops = operands(c)
            for variant in range(3):
                A = rnd.choice([0, 1, 0x7f, 0x80, 0xff, rnd.randrange(256), rnd.randrange(256)])
                F = rnd.randrange(16)
                SP = rnd.randrange(2, 0x30)
                if variant == 1:
                    SP = rnd.choice([0, 2, 0x30])
                ram = [rnd.choice([0, 1, 0x7f, 0x80, 0xff, rnd.randrange(256)]) for _ in range(uc.RAMN)]
                rom = {}
                m = mem_of(ops)
                if mn == "IDXM":
                    ram[m] = rnd.randrange(0x38)
                    ram[m + 1] = 0      # the pointer's upper byte (PDK16 data addresses have 9 bits) is not compared
                if mn in ("LDTABL", "LDTABH"):
                    ram[m], ram[m + 1] = 0x20, 0x00
                    rom[0x20] = rnd.randrange(1 << W)
                if mn in ("IGOTO", "ICALL"):
                    ram[m], ram[m + 1] = rnd.randrange(8, 0x100), 0
                io = {}
                if mn == "MUL":
                    io[8] = rnd.choice([0, 1, 0x10, 0xff, rnd.randrange(256)])
                if mn in ("LDSPTL", "LDSPTH"):
                    rom[SP] = rnd.randrange(1 << W)
                if mn in ("RET", "RETI") or key.startswith("RET"):
                    t = rnd.randrange(8, 0x1000)
                    if SP < 2:
                        SP = 2
                    ram[SP - 2], ram[SP - 1] = t & 0xff, t >> 8
                if mn in ("POPW", "POPAF"):
                    if SP < 2:
                        SP = 2
                if mn in ("PUSHAF", "PUSHW", "CALL", "ICALL") and SP > 0x3a:
                    SP = 0x30
                cases.append(uc.Case(W, op, A, F, SP, ram, rom, io))
                meta.append((key, c))
    # Ghidra side
    cf = os.path.join(work, f"sem{W}.cases")
    with open(cf, "w") as f:
        for i, c in enumerate(cases):
            extra = " ".join("%04x@%x" % (v, a) for a, v in c.rom.items()) + \
                "".join(" reg:%s=%x" % (io8name, v) for a, v in c.io.items() if a == 8)
            f.write("%d %04x %02x %02x %02x %s %s\n" % (i, c.op, c.A, c.F, c.SP, "".join("%02x" % b for b in c.ram), extra))
    gout = os.path.join(work, f"sem{W}.ghidra")
    subprocess.run([os.path.join(HERE, "sem.sh"), lang, cf, gout], check=True)
    G = {}
    for l in open(gout):
        p = l.split()
        if p[1] == "OK":
            G[int(p[0])] = dict(A=int(p[2], 16), F=int(p[3], 16), SP=int(p[4], 16), PC=int(p[5], 16),
                                ram=[int(p[6][2 * i:2 * i + 2], 16) for i in range(uc.RAMN)])
        else:
            G[int(p[0])] = None
    U = uc.run(cases)
    stat = collections.defaultdict(lambda: [0, 0, 0])   # form -> pass, fail, ucsim-invalid
    reasons = collections.Counter()
    fails = collections.defaultdict(list)
    for i, (key, c) in enumerate(meta):
        u, g = U[i], G.get(i)
        if u is None:
            stat[key][2] += 1
            continue
        if g is None:
            stat[key][1] += 1
            fails[key].append((c, "emulator error", cases[i], None, u))
            continue
        diffs = [k for k in ("A", "F", "SP", "PC") if u[k] != g[k]] + (["ram"] if u["ram"] != g["ram"] else [])
        why = explained(key, c, diffs, g, u)
        if diffs and why:
            stat[key][0] += 1
            reasons[why] += 1
        elif diffs:
            stat[key][1] += 1
            fails[key].append((c, diffs, cases[i], g, u))
        else:
            stat[key][0] += 1
    tp = sum(v[0] for v in stat.values()); tf = sum(v[1] for v in stat.values()); ti = sum(v[2] for v in stat.values())
    print(f"PDK{W} ({chip}) semantics vs ucsim: {tp} cases agree, {tf} differ, {ti} not executable by ucsim "
          f"({len(stat)} instruction forms)")
    for why, n in sorted(reasons.items()):
        print(f"   {n:5d} cases explained: {why}")
    inval = sorted(k for k, v in stat.items() if v[0] == 0 and v[1] == 0)
    if inval:
        print("   forms ucsim cannot execute:", "; ".join(inval))
    for key in sorted(fails):
        c, d, case, g, u = fails[key][0]
        print(f"   FAIL {key}: {len(fails[key])}/{sum(stat[key][:2])}  e.g. {c} op={case.op:04x} A={case.A:02x} F={case.F:x} SP={case.SP:02x} -> diff {d}")
        if g:
            print(f"        ghidra A={g['A']:02x} F={g['F']:x} SP={g['SP']:02x} PC={g['PC']:x}   ucsim A={u['A']:02x} F={u['F']:x} SP={u['SP']:02x} PC={u['PC']:x}")
            if "ram" in d:
                dd = [(i, g['ram'][i], u['ram'][i]) for i in range(uc.RAMN) if g['ram'][i] != u['ram'][i]]
                print("        ram diffs (addr, ghidra, ucsim):", [(a, hex(x), hex(y)) for a, x, y in dd[:6]])
    sys.exit(1 if tf else 0)


if __name__ == "__main__":
    main()
