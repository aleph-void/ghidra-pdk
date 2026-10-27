#!/usr/bin/env python3
"""Decode differential: Ghidra's disassembly of every PDK opcode word against fppa-pdk-tools' dispdk (MIT)
and SDCC's ucsim_pdk, both used as black boxes, bucketed by difference class.

usage: diff_decode.py <width 13|14|15|16> <chip> <ghidra.txt> <dispdk.txt> <ucsim.txt> [--list <class>]

ghidra.txt   lines "<hex bytes, little endian> <len> <text>"  (test/dis.sh)
dispdk.txt   lines "<4 hex> <text>"   (test/oracle-dump.sh)
ucsim.txt    lines "<4 hex> <text>"
"""
import json, os, re, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
CHIPS = json.load(open(os.path.join(HERE, "..", "tools", "chips.json")))


def ionames(chip):
    names = {}
    c = CHIPS[chip]
    n = {13: 32, 14: 64, 15: 128, 16: 64}[c["width"]]
    for a in range(n):
        names[c["io"].get(str(a), "io_%02x" % a)] = a
    return names


def hx(s):
    return "%x" % int(s, 16)


NOARG = {"NOP", "RET", "RETI", "RESET", "STOPSYS", "STOPEXE", "ENGINT", "DISGINT", "WDRESET", "PUSHAF", "POPAF",
         "MUL", "LDSPTL", "LDSPTH", "TRAP"}
A_ONLY = {"ADDC", "SUBC", "IZSN", "DZSN", "PCADD", "NOT", "NEG", "SR", "SL", "SRC", "SLC", "SWAP", "DELAY"}
BITOPS = {"T0SN", "T1SN", "SET0", "SET1", "TOG", "WAIT0", "WAIT1", "SWAPC"}


# ------------------------------------------------------------------ Ghidra
def canon_ghidra(text, ion):
    if text == "BAD":
        return None
    m = re.match(r"(\S+)\s*(.*)$", text)
    mn, rest = m.group(1).upper(), m.group(2)
    if not rest:
        return mn
    ops = []
    for o in rest.split(","):
        o = o.strip()
        if o == "A":
            ops.append("A")
        elif o.startswith("#"):
            ops.append("k:" + hx(o[1:]))
        elif "." in o:
            base, n = o.rsplit(".", 1)
            if base in ion:
                ops.append("IO:%x.%s" % (ion[base], n))
            else:
                ops.append("M:%x.%s" % (int(base, 16), n))
        elif o in ion:
            ops.append("IO:%x" % ion[o])
        elif mn in ("PUSHWPC", "POPWPC"):
            ops.append("N:%x" % int(o))
        else:
            ops.append("X:" + hx(o))
    return mn + " " + ",".join(ops)


def fix_x(mn, ops):
    """bare numbers are memory operands, except for jumps, PMODE, POPWPC..."""
    return ops


def finalize_ghidra(c):
    if c is None:
        return None
    if " " not in c:
        return c
    mn, rest = c.split(" ", 1)
    ops = rest.split(",")
    out = []
    for o in ops:
        if o.startswith("X:"):
            if mn in ("GOTO", "CALL", "PMODE", "PUSHWPC", "POPWPC"):
                out.append("N:" + o[2:])
            else:
                out.append("M:" + o[2:])
        else:
            out.append(o)
    return mn + " " + ",".join(out)


# ------------------------------------------------------------------ dispdk
def canon_dispdk(text):
    if text.startswith("?????"):
        return None
    text = text.replace(";", "").strip()
    text = re.sub(r"\s+", " ", text)
    m = re.match(r"(\S+)\s*(.*)$", text)
    mn, rest = m.group(1).upper(), m.group(2)
    syn = {"INCM": "INC", "DECM": "DEC"}
    mn = syn.get(mn, mn)
    if mn in ("POPW", "PUSHW") and rest.startswith("PC "):
        return mn + "PC " + "N:%x" % int(rest[3:])
    if not rest:
        return mn
    ops = []
    for o in [x.strip() for x in rest.split(",")]:
        if o == "A":
            ops.append("A")
        elif re.fullmatch(r"\[\[0x[0-9a-fA-F]+\]\]", o):
            ops.append("M:" + hx(o[2:-2]))
        elif re.fullmatch(r"\[0x[0-9a-fA-F]+\]\.\d", o):
            ops.append("M:%s.%s" % (hx(o[1:o.index("]")]), o[-1]))
        elif re.fullmatch(r"\[0x[0-9a-fA-F]+\]", o):
            ops.append("M:" + hx(o[1:-1]))
        elif re.fullmatch(r"IO\(0x[0-9a-fA-F]+\)\.\d", o):
            ops.append("IO:%s.%s" % (hx(o[3:o.index(")")]), o[-1]))
        elif re.fullmatch(r"IO\(0x[0-9a-fA-F]+\)", o):
            ops.append("IO:" + hx(o[3:-1]))
        elif re.fullmatch(r"0x[0-9a-fA-F]+", o):
            ops.append("K:" + hx(o))
        elif re.fullmatch(r"\d+", o):
            ops.append("N:%x" % int(o))
        else:
            ops.append("??" + o)
    # NEG A,[M] / NOT A,[M]  == NEG M / NOT M
    if mn in ("NEG", "NOT") and ops[0] == "A" and len(ops) == 2:
        ops = [ops[1]]
    if mn == "XCH" and ops[0] == "A":
        ops = ops[1:]
    # K:... immediates: GOTO/CALL/PMODE/DELAY k / RET k handled by mnemonic
    out = []
    for o in ops:
        if o.startswith("K:"):
            if mn in ("GOTO", "CALL"):
                out.append("N:" + o[2:])
            else:
                out.append("k:" + o[2:])
        else:
            out.append(o)
    return mn + " " + ",".join(out)


# ------------------------------------------------------------------ ucsim
def canon_ucsim(text, W):
    if "INVALID" in text or text.startswith("-- "):
        return None
    text = re.sub(r"\s+", " ", text.strip())
    m = re.match(r"(\S+)\s*(.*)$", text)
    mn, rest = m.group(1).upper(), m.group(2)
    syn = {"DISINT": "DISGINT", "LTABL": "LDTABL", "LTABH": "LDTABH", "PMOD": "PMODE"}
    mn = syn.get(mn, mn)
    if mn == "POP" and rest == "af":
        return "POPAF"
    if mn == "PUSH" and rest == "af":
        return "PUSHAF"
    if mn in ("PUSHW", "POPW") and rest.startswith("pc"):
        return mn + "PC N:%x" % int(rest[2:])
    if mn == "PMODE":
        return "PMODE N:%x" % int(rest)
    if not rest:
        if mn in A_ONLY and mn != "DELAY":
            return mn + " A" if mn not in NOARG else mn
        return mn
    if mn in A_ONLY and rest == "a":
        return mn + " A"
    ops = []
    for o in rest.split(","):
        o = o.strip()
        if o == "a":
            ops.append("A")
        elif re.fullmatch(r"#0x[0-9a-f]+", o):
            ops.append("k:" + hx(o[1:]))
        elif re.fullmatch(r"\[0x[0-9a-f]+\]", o):
            ops.append("M:" + hx(o[1:-1]))
        elif re.fullmatch(r"0x[0-9a-f]+", o):
            ops.append("U:" + hx(o))
        elif re.fullmatch(r"\d", o):
            ops.append("bit" + o)
        else:
            ops.append("??" + o)
    # bit operand forms "N,b" / "[N],b"
    if mn in BITOPS and len(ops) == 2 and ops[1].startswith("bit"):
        b = ops[1][3:]
        if ops[0].startswith("U:"):
            return "%s IO:%s.%s" % (mn, ops[0][2:], b)
        if ops[0].startswith("M:"):
            return "%s M:%s.%s" % (mn, ops[0][2:], b)
    # implicit accumulator forms: "add #k" == ADD A,k   "ceqsn [M]" == CEQSN A,M
    if W != 16 and mn in ("ADD", "SUB", "AND", "OR", "XOR", "CEQSN", "CNEQSN") and len(ops) == 1 and \
            (ops[0].startswith("k:") or (mn in ("CEQSN", "CNEQSN") and ops[0].startswith("M:"))):
        ops = ["A"] + ops
    if mn in ("GOTO", "CALL"):
        if not ops:
            return mn + " ??nooperand"
        return mn + " N:" + ops[0][2:]
    if mn == "RET" and ops and ops[0].startswith("k:"):
        return "RET " + ops[0]
    out = []
    for o in ops:
        if o.startswith("U:"):
            out.append("IO:" + o[2:])      # mov a,N / mov N,a / xor N,a : io addresses
        else:
            out.append(o)
    return mn + " " + ",".join(out)


# ------------------------------------------------------------------ driver
def load(path):
    d = {}
    for l in open(path):
        l = l.rstrip("\n")
        if not l:
            continue
        k, _, t = l.partition(" ")
        d[int(k, 16)] = t
    return d


def mnop(x):
    if not x:
        return None, ""
    mn, _, ops = x.partition(" ")
    return mn, ops


def mval(ops):
    m = re.search(r"M:([0-9a-f]+)", ops)
    return int(m.group(1), 16) if m else None


def explain(W, name, cls, a, b):
    """Known classes of reference-tool gaps and bugs (each confirmed against the Free PDK table, sdaspdk or both)."""
    am, ao = mnop(a)
    bm, bo = mnop(b)
    if cls == "module valid, oracle invalid":
        if am == "CALL" and ao == "N:%x" % ((1 << (W - 3)) - 1 if W != 13 else 0x3ff):
            pass
        if am == "CALL" and a.split(":")[1] == {13: "3ff", 14: "7ff", 15: "fff", 16: "1fff"}[W] and name == "dispdk":
            return "dispdk: the all-ones word (erased ROM) is treated as an illegal opcode; the table calls it CALL"
        if name == "dispdk" and W == 15 and am in ("NMOV", "SWAP"):
            return "dispdk has no NMOV/SWAP M for PDK15 (the table and the device list have them)"
        if name == "dispdk" and W == 16 and (mval(ao) or 0) >= 0x20:
            return "dispdk accepts data addresses below 0x20 only in PDK16"
        if name == "ucsim" and W == 15 and am in ("NMOV", "SWAP"):
            return "ucsim has no NMOV/SWAP M for PDK15 (sdaspdk15 assembles SWAP M)"
        if name == "ucsim" and am == "SUBC" and W == 13:
            return "ucsim has no SUBC M for PDK13 (table and dispdk have it)"
        if name == "ucsim" and am == "COMP" and W == 14:
            return "ucsim has no COMP M,A for PDK14 (table and dispdk have it)"
        if name == "ucsim" and am == "TOG":
            return "ucsim has no TOG for PDK16 (table and dispdk have it)"
        if name == "ucsim" and am in ("T0SN", "T1SN", "SET0", "SET1") and W in (13, 15):
            return "ucsim cannot print the memory bit-operand forms of PDK13/15"
        if name == "ucsim" and W == 16 and am == "CALL":
            return "reserved word"
    if cls == "oracle valid, module invalid":
        if bm == "TRAP":
            return "TRAP (0x0020) is named only by dispdk; no table, assembler or simulator has it"
        if bm in ("LDSPTL", "LDSPTH") and W == 16:
            return "dispdk names LDSPTL/H in PDK16, ucsim and the table do not"
        if name == "ucsim" and bm == "CNEQSN" and W == 13:
            return "ucsim decodes CNEQSN in PDK13; the table marks the slots unknown and sdaspdk13 rejects cneqsn"
    if cls == "differ":
        if name == "dispdk" and W == 16 and am == bm and am in ("NMOV", "NADD", "CEQSN", "COMP"):
            return "dispdk swaps the A,M / M,A forms of NMOV/NADD/CEQSN/COMP in PDK16 (table and ucsim agree with the module)"
        if name == "dispdk" and W == 16 and {am, bm} == {"GOTO", "CALL"}:
            return "dispdk swaps GOTO and CALL in PDK16 (table and ucsim agree with the module)"
        if name == "ucsim" and am in ("GOTO", "CALL") and bo in ("", "??nooperand"):
            return "ucsim omits the GOTO/CALL operand in PDK15"
        if name == "ucsim" and am in ("LDTABL", "LDTABH") and bm in ("LDTABL", "LDTABH"):
            return "ucsim swaps LDTABL/LDTABH (sdaspdk15 and dispdk agree with the module)"
        if name == "ucsim" and am in ("T0SN", "T1SN", "SET0", "SET1") and "??" in (bo or ""):
            return "ucsim cannot print the memory bit-operand forms of PDK13/15"
        if name == "ucsim" and {am, bm} == {"POPWPC", "PUSHWPC"}:
            return "ucsim shows POPWPC n (0x006n) as PUSHWPC (table and dispdk agree with the module)"
        if name == "ucsim" and am == bm == "ICALL":
            return "ucsim prints the raw odd address of ICALL (the encoding bit) instead of the word-aligned M"
        if name == "ucsim" and am == "WDRESET" and bm == "WDTRESET":
            return "spelling"
    return None


def main():
    W = int(sys.argv[1])
    chip = sys.argv[2]
    ion = ionames(chip)
    g = {}
    for l in open(sys.argv[3]):
        h, n, t = l.rstrip("\n").split(" ", 2)
        g[int(h[2:4] + h[0:2], 16)] = canon_ghidra(t, ion)
    g = {k: finalize_ghidra(v) for k, v in g.items()}
    d = load(sys.argv[4])
    u = load(sys.argv[5])
    D = {k: canon_dispdk(v) for k, v in d.items()}
    U = {k: canon_ucsim(v, W) for k, v in u.items()}
    listcls = sys.argv[sys.argv.index("--list") + 1] if "--list" in sys.argv else None
    for name, O in (("dispdk", D), ("ucsim", U)):
        buckets = collections.Counter()
        examples = collections.defaultdict(list)
        sigs = collections.Counter()
        sigex = {}
        reasons = collections.Counter()
        for op in range(1 << W):
            a, b = g.get(op), O.get(op)
            if a is None and b is None:
                cls = "both invalid"
            elif a == b:
                cls = "agree"
            elif a is None:
                cls = "oracle valid, module invalid"
            elif b is None:
                cls = "module valid, oracle invalid"
            else:
                cls = "differ"
            if cls not in ("agree", "both invalid"):
                why = explain(W, name, cls, a, b)
                if why:
                    reasons[why] += 1
                    cls = "explained"
                else:
                    cls = "UNEXPLAINED: " + cls
            buckets[cls] += 1
            if cls not in ("agree", "both invalid"):
                strip = lambda x: re.sub(r":[0-9a-f]+", ":", x) if x else x
                sg = (cls, strip(a), strip(b))
                sigs[sg] += 1
                sigex.setdefault(sg, (op, a, b))
            if len(examples[cls]) < 400 and cls not in ("agree", "both invalid"):
                examples[cls].append((op, a, b))
        print(f"PDK{W} ({chip}) vs {name}: " + ", ".join(f"{k}={v}" for k, v in sorted(buckets.items())))
        global UNEXPLAINED
        UNEXPLAINED += sum(v for k, v in buckets.items() if k.startswith("UNEXPLAINED"))
        for why, n in sorted(reasons.items()):
            print(f"      {n:6d} explained: {why}")
        if "--summary" in sys.argv:
            for sg, c in sorted(sigs.items(), key=lambda kv: (kv[0][0], -kv[1])):
                op, a, b = sigex[sg]
                print(f"   {c:6d}  {sg[0]:30s} module={sg[1]!s:22} {name}={sg[2]!s:22} e.g. {op:04x} {a} / {b}")
        if listcls:
            for cls, ex in examples.items():
                if listcls in cls:
                    for op, a, b in ex[:200]:
                        print(f"   {op:04x} module={a!s:28} {name}={b}")


UNEXPLAINED = 0
if __name__ == "__main__":
    main()
    sys.exit(1 if UNEXPLAINED else 0)
