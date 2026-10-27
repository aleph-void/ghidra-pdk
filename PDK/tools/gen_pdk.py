#!/usr/bin/env python3
"""Generates the PDK13/14/15/16 instruction sets (data/languages/pdkNN_ops.sinc).

The bit patterns come from the Free PDK instruction-set tables (https://free-pdk.github.io/instruction-sets/),
saved as tools/doc/PDKnn.tab by tools/parse_doc.py; the semantics are written here by hand from the Padauk
datasheets / Free PDK descriptions and checked against the ucsim simulator (test/).

usage: gen_pdk.py <outdir>
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse_doc import parse_tab

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- semantics
# Operands: A, M (data memory byte), MW (data memory word), K (8-bit immediate), IO (io register), n (bit number)
SKIP = "skiptgt"   # sub-constructor that exports the address after the next instruction


def skip_if(cond):
    return f"\tif (!({cond})) goto <ns>;\n\tgoto {SKIP};\n\t<ns>\n"


def addf(dst_expr, a, b, c, write):
    """r = a + b + c with flags; write(r) stores the result."""
    s = f"\tlocal a:1 = {a};\n\tlocal b:1 = {b};\n\tlocal c:1 = {c};\n\tlocal r:1;\n\taddflags(r, a, b, c);\n"
    return s + write("r")


def subf(a, b, c, write):
    s = f"\tlocal a:1 = {a};\n\tlocal b:1 = {b};\n\tlocal c:1 = {c};\n\tlocal r:1;\n\tsubflags(r, a, b, c);\n"
    return s + (write("r") if write else "")


def operand_kind(tok):
    tok = tok.strip()
    if tok == "A":
        return "A"
    if tok == "M":
        return "M"
    if tok == "k":
        return "K"
    if tok == "IO":
        return "IO"
    return tok


def sem(form, W):
    """Returns the SLEIGH body for a doc mnemonic form, or None if unknown."""
    mn, _, rest = form.partition(" ")
    ops = [operand_kind(o) for o in rest.split(",")] if rest else []
    ZF = "\tZF = (r == 0);\n"
    # --- no operand
    simple = {
        "NOP": "",
        "WDRESET": "\twatchdog_reset();\n",
        "RESET": "\tchip_reset();\n\tlocal rv:2 = 0;\n\tgoto [rv];\n",
        "STOPSYS": "\tstop_sys();\n",
        "STOPEXE": "\tstop_exe();\n",
        "ENGINT": "\tGIE = 1;\n",
        "DISGINT": "\tGIE = 0;\n",
        "PUSHAF": "\tlocal spa:2 = zext(sp);\n\t*[ram]:1 spa = A;\n\tspa = spa + 1;\n\t*[ram]:1 spa = flag;\n\tsp = sp + 2;\n",
        "POPAF": "\tsp = sp - 2;\n\tlocal spa:2 = zext(sp);\n\tA = *[ram]:1 spa;\n\tspa = spa + 1;\n\tflag = *[ram]:1 spa;\n",
        "RET": "\tsp = sp - 2;\n\tlocal spa:2 = zext(sp);\n\tlocal t:2 = *[ram]:2 spa;\n\treturn [t];\n",
        "RETI": "\tsp = sp - 2;\n\tlocal spa:2 = zext(sp);\n\tlocal t:2 = *[ram]:2 spa;\n\tGIE = 1;\n\treturn [t];\n",
        "MUL": "\t# operand register mulop = I/O 0x08, result high byte mulrh = I/O 0x09 (their names depend on the device)\n\tlocal mo:1 = *[register]:1 0x108:2;\n\tlocal p:2 = zext(A) * zext(mo);\n\tA = p:1;\n\t*[register]:1 0x109:2 = p(1);\n",
        "LDSPTL": "\tlocal spa:2 = zext(sp);\n\tlocal ca:2 = *[ram]:2 spa;\n\tlocal w:2 = *[rom]:2 ca;\n\tA = w:1;\n",
        "LDSPTH": "\tlocal spa:2 = zext(sp);\n\tlocal ca:2 = *[ram]:2 spa;\n\tlocal w:2 = *[rom]:2 ca;\n\tA = w(1);\n",
        "PCADD": "\tlocal t:2 = inst_start >> 1;\n\tt = t + zext(A);\n\tgoto [t];\n",
    }
    if not ops and mn in simple:
        return simple[mn]
    if mn == "PMODE":
        return "\tpmode(K);\n"
    if mn in ("PUSHWPC",):
        return "\tlocal spa:2 = zext(sp);\n\t*[ram]:2 spa = fppa_getpc(nn:1);\n\tsp = sp + 2;\n"
    if mn in ("POPWPC",):
        return "\tsp = sp - 2;\n\tlocal spa:2 = zext(sp);\n\tlocal v:2 = *[ram]:2 spa;\n\tfppa_setpc(nn:1, v);\n"
    # --- A-only (accumulator) forms and M-only forms share semantics, on a different 'x'
    def single(x, w):
        """x = lvalue text, w = write(r) for local r"""
        if mn == "ADDC":
            return addf(x, x, "0", "zext(CF)", w)
        if mn == "SUBC":
            return subf(x, "0", "zext(CF)", w)
        if mn == "IZSN":
            return addf(x, x, "1", "0", w) + skip_if("r == 0")
        if mn == "DZSN":
            return subf(x, "1", "0", w) + skip_if("r == 0")
        if mn == "INC":
            return addf(x, x, "1", "0", w)
        if mn == "DEC":
            return subf(x, "1", "0", w)
        if mn == "NOT":
            return f"\tlocal r:1 = ~{x};\n" + ZF + w("r")
        if mn == "NEG":
            return f"\tlocal r:1 = -{x};\n" + ZF + w("r")
        if mn == "SR":
            return f"\tlocal v:1 = {x};\n\tCF = (v & 1) != 0;\n\tlocal r:1 = v >> 1;\n" + w("r")
        if mn == "SL":
            return f"\tlocal v:1 = {x};\n\tCF = (v >> 7) != 0;\n\tlocal r:1 = v << 1;\n" + w("r")
        if mn == "SRC":
            return (f"\tlocal v:1 = {x};\n\tlocal c:1 = zext(CF);\n\tCF = (v & 1) != 0;\n"
                    f"\tlocal r:1 = (v >> 1) | (c << 7);\n" + w("r"))
        if mn == "SLC":
            return (f"\tlocal v:1 = {x};\n\tlocal c:1 = zext(CF);\n\tCF = (v >> 7) != 0;\n"
                    f"\tlocal r:1 = (v << 1) | c;\n" + w("r"))
        if mn == "SWAP":
            return f"\tlocal v:1 = {x};\n\tlocal r:1 = (v << 4) | (v >> 4);\n" + w("r")
        if mn == "CLEAR":
            return w("0")
        if mn == "DELAY":
            return "\tA = 0;\n"       # the delay itself (x+1 cycles) is timing, not state
        if mn == "PCADD":
            return simple["PCADD"]
        return None

    if mn == "DELAY" and ops == ["K"]:
        return "\tA = 0;\n"
    if ops == ["A"]:
        return single("A", lambda r: f"\tA = {r};\n")
    if ops == ["M"]:
        if mn == "XCH":
            return "\tlocal t:1 = M;\n\tM = A;\n\tA = t;\n"
        if mn == "DELAY":
            return "\tA = 0;\n"
        return single("M", lambda r: f"\tM = {r};\n")
    # --- two-operand ALU
    if len(ops) == 2:
        d, s = ops
        src = {"A": "A", "M": "M", "K": "K", "IO": "IO"}[s]
        dst = d
        wr = lambda r: f"\t{dst} = {r};\n"
        if mn == "ADD":
            return addf(dst, dst, src, "0", wr)
        if mn == "ADDC":
            return addf(dst, dst, src, "zext(CF)", wr)
        if mn == "SUB":
            return subf(dst, src, "0", wr)
        if mn == "SUBC":
            return subf(dst, src, "zext(CF)", wr)
        if mn in ("AND", "OR", "XOR"):
            o = {"AND": "&", "OR": "|", "XOR": "^"}[mn]
            if d == "IO" and mn == "XOR":    # XOR IO, A: no flags
                return f"\tIO = IO ^ A;\n"
            return f"\tlocal r:1 = {dst} {o} {src};\n" + ZF + wr("r")
        if mn == "MOV":
            if d == "A" and s in ("M", "IO"):
                return f"\tlocal r:1 = {src};\n" + ZF + "\tA = r;\n"
            return f"\t{dst} = {src};\n"
        if mn == "CEQSN":
            return subf(dst, src, "0", None) + skip_if("r == 0")
        if mn == "CNEQSN":
            return subf(dst, src, "0", None) + skip_if("r != 0")
        if mn == "COMP":
            return subf(dst, src, "0", None)
        if mn == "NADD":   # d <- s + NEG(d): an addition, so the flags are those of an addition
            return addf(dst, src, "-" + dst, "0", wr)
        if mn == "NMOV":
            if d == "A":
                return f"\tlocal r:1 = -{src};\n" + ZF + "\tA = r;\n"
            return f"\t{dst} = -{src};\n"
        if mn == "IDXM":
            # the pointer is the byte at M (data memory up to 256 bytes); PDK16 has 9 bit data addresses: the word at M
            ptr = "\tlocal p:2 = MW & 0x1ff;\n" if W == 16 else "\tlocal p:2 = zext(MW:1);\n"
            if d == "A":
                return ptr + "\tA = *[ram]:1 p;\n"
            return ptr + "\t*[ram]:1 p = A;\n"
    # --- word memory / table forms (operand MW)
    if ops == ["MW"]:
        raise AssertionError
    return None


def sem_word(form, W):
    mn = form.split()[0]
    if mn == "STT16":
        return "\tT16 = MW;\n"
    if mn == "LDT16":
        return "\tMW = T16;\n"
    if mn == "PUSHW":
        return "\tlocal spa:2 = zext(sp);\n\t*[ram]:2 spa = MW;\n\tsp = sp + 2;\n"
    if mn == "POPW":
        return "\tsp = sp - 2;\n\tlocal spa:2 = zext(sp);\n\tMW = *[ram]:2 spa;\n"
    if mn == "IGOTO":
        return "\tlocal t:2 = MW;\n\tgoto [t];\n"
    if mn == "ICALL":
        return ("\tlocal t:2 = MW;\n\tlocal spa:2 = zext(sp);\n\tlocal ret:2 = inst_next >> 1;\n\t*[ram]:2 spa = ret;\n"
                "\tsp = sp + 2;\n\tcall [t];\n")
    if mn in ("LDTABL", "LDTABH"):
        lo = mn == "LDTABL"
        return ("\tlocal ca:2 = MW & 0x0fff;\n\tlocal w:2 = *[rom]:2 ca;\n\tA = " + ("w:1" if lo else "w(1)") + ";\n")
    return None


def errata(W, tab):
    """PDK16 page: the bit cells of ADD M,A .. MOV A,M (hex 0x40..0x5F) hold 0010000..0011111 instead of the
    0100000..0101111 given by the hex column; the oracles (ucsim, dispdk) agree with the hex column."""
    out = []
    for hexs, pat, rest in tab:
        if W == 16 and rest and hexs[:3] in ("0x4", "0x5") and pat[0][0] == "0" and pat[1][0] == "0" and pat[2][0] == "1":
            top = format(int(hexs[2:4], 16) >> 1, "07b")
            pat = [[b, 1] for b in top] + [list(c) for c in pat[7:]]
        out.append((hexs, pat, rest))
    if W == 15:
        # LDSPTL / LDSPTH are not in the PDK15 page, but sdaspdk15, ucsim and dispdk all decode them like PDK14
        for code, nm in ((6, "LDSPTL"), (7, "LDSPTH")):
            out.append(("0x%04X" % code, [[b, 1] for b in format(code, "015b")],
                        [nm, "", "", "", "", "A <- code word at address SP (not in the Free PDK PDK15 table)"]))
    return out


def build(W, tab):
    """Returns (token_defs, subtables, constructors) text for one ISA."""
    tab = errata(W, tab)
    fields = {}           # name -> (lo, hi, kind)
    subs = {}
    cons = []
    flagops = []
    for hexs, pat, rest in tab:
        if not rest or rest[0] in ("?", ""):
            continue
        form = rest[0]
        # expand pattern into list of (kind, lo, hi, value)
        parts = []
        pos = W
        for t, sp in pat:
            hi, lo = pos - 1, pos - sp
            pos -= sp
            parts.append((t, hi, lo))
        # merge adjacent bit runs and same-letter runs (PMODE k[4:4] k[3:3] ..., POPWPC n ...)
        merged = []
        for t, hi, lo in parts:
            if merged and merged[-1][0] == t and t not in "01" and merged[-1][2] == hi + 1:
                merged[-1] = (t, merged[-1][1], lo)
            elif merged and t in "01" and set(merged[-1][0]) <= set("01") and merged[-1][2] == hi + 1:
                merged[-1] = (merged[-1][0] + t, merged[-1][1], lo)
            else:
                merged.append((t, hi, lo))
        constraint = []
        opfield = {}
        for t, hi, lo in merged:
            if t[0] in "01":
                nm = f"b{hi}_{lo}"
                fields[nm] = (lo, hi, "plain")
                constraint.append(f"{nm}=0b{t}")
            else:
                nm = "ioa" if t == "IO" else f"{t}{hi}_{lo}"
                fields[nm] = (lo, hi, t)
                opfield[t] = (nm, hi, lo)
        cons.append((form, constraint, opfield))
    return fields, cons


def main(outdir):
    for W in (13, 14, 15, 16):
        tab = parse_tab(os.path.join(HERE, "doc", f"PDK{W}.tab"))
        gen(W, tab, outdir)


def gen(W, tab, outdir):
    fields, cons = build(W, tab)
    out = []
    out.append("# GENERATED by tools/gen_pdk.py from the Free PDK PDK%d instruction-set table. Do not edit.\n" % W)
    out.append("define token inst (16)\n")
    for nm in sorted(fields):
        lo, hi, kind = fields[nm]
        extra = " hex" if kind in ("k", "M") else ""
        out.append(f"\t{nm}=({lo},{hi}){extra}\n")
    out.append(";\n")
    for nm in sorted(fields):
        if fields[nm][2] == "n":
            cnt = 1 << (fields[nm][1] - fields[nm][0] + 1)
            out.append(f'attach names [ {nm} ] [ ' + " ".join(f'"{i}"' for i in range(cnt)) + ' ];\n')
    tok = "".join(out)
    out = []
    subs = {}
    body = []
    count = 0
    unknown = []
    for form, constraint, opfield in cons:
        mn = form.split()[0]
        sig = form
        wordform = mn in ("STT16", "LDT16", "PUSHW", "POPW", "IGOTO", "ICALL", "LDTABL", "LDTABH") or (
            mn == "IDXM")
        text = None
        # display and operand-table selection
        disp = mn
        ops = [o.strip() for o in form[len(mn):].split(",")] if form[len(mn):].strip() else []
        shown = []
        for o in ops:
            if o == "A":
                shown.append('"A"')
            elif o == "k":
                if mn in ("GOTO", "CALL"):
                    nm = opfield["k"][0]
                    shown.append(f"T_{nm}")
                    subs[f"T_{nm}"] = f"T_{nm}: {nm} is {nm} {{ export *[rom]:1 {nm}; }}\n"
                elif mn == "PMODE":
                    shown.append(opfield["k"][0])
                else:
                    shown.append(f'"#"^{opfield["k"][0]}')
            elif o == "M":
                nm = opfield["M"][0]
                if wordform:
                    shown.append(f"MW_{nm}")
                    subs[f"MW_{nm}"] = (f"MW_{nm}: wa is {nm} [ wa = {nm} << 1; ] "
                                        f"{{ export *[ram]:2 wa; }}\n")
                else:
                    shown.append(f"M_{nm}")
                    subs[f"M_{nm}"] = f"M_{nm}: {nm} is {nm} {{ export *[ram]:1 {nm}; }}\n"
            elif o == "IO":
                shown.append(opfield["IO"][0])
            elif o == "IO.n":
                shown.append(opfield["IO"][0] + '^"."^' + opfield["n"][0])
            elif o == "M.n":
                nm = opfield["M"][0]
                shown.append(f"M_{nm}" + '^"."^' + opfield["n"][0])
                subs[f"M_{nm}"] = f"M_{nm}: {nm} is {nm} {{ export *[ram]:1 {nm}; }}\n"
            elif o == "n":
                shown.append(opfield["n"][0])
            else:
                raise SystemExit(f"unhandled operand {o} in {form}")
        # semantics
        b = None
        if mn in ("T0SN", "T1SN", "SET0", "SET1", "TOG", "WAIT0", "WAIT1", "SWAPC"):
            b = bitop(mn, ops[0], opfield)
        elif wordform and mn != "IDXM":
            b = sem_word(form, W)
        elif mn in ("GOTO", "CALL"):
            nm = opfield["k"][0]
            if mn == "GOTO":
                b = f"\tgoto T_{nm};\n"
            else:
                b = ("\tlocal spa:2 = zext(sp);\n\tlocal ret:2 = inst_next >> 1;\n\t*[ram]:2 spa = ret;\n\tsp = sp + 2;\n"
                     f"\tcall T_{nm};\n")
        elif form == "RET k":
            b = ("\tA = " + opfield["k"][0] + ":1;\n"
                 "\tsp = sp - 2;\n\tlocal spa:2 = zext(sp);\n\tlocal t:2 = *[ram]:2 spa;\n\treturn [t];\n")
        else:
            b = sem(form, W)
            if mn == "IDXM":
                b = sem(form, W)
        if b is None:
            unknown.append(form)
            continue
        # operand-name substitution in the body
        b = subst(b, form, opfield, wordform)
        # dest display text
        text = ":" + mn + ((" " + ",".join(shown)) if shown else "") + " is " + " & ".join(
            constraint + [x.split("^")[0] for x in shown if x and not x.startswith('"')]
        )
        # operands that are subtable symbols must appear in the 'is' part
        syms = []
        for x in shown:
            for part in x.split("^"):
                if part.startswith('"'):
                    continue
                syms.append(part)
        if SKIP in b:
            syms.append(SKIP)
        text = ":" + mn + (" " + ",".join(shown) if shown else "") + " is " + " & ".join(constraint + syms)
        body.append(text + " {\n" + b + "}\n")
        count += 1
    # sub tables and skip target
    out.append("skiptgt: addr is epsilon [ addr = inst_next + 1; ] { export *[rom]:1 addr; }\n\n")
    out.extend(subs[k] for k in sorted(subs))
    out.append("\n")
    out.extend(body)
    if unknown:
        sys.stderr.write(f"PDK{W}: no semantics for {unknown}\n")
    with open(os.path.join(outdir, f"pdk{W}_tok.sinc"), "w") as f:
        f.write(tok)
    with open(os.path.join(outdir, f"pdk{W}_ops.sinc"), "w") as f:
        f.write("# GENERATED by tools/gen_pdk.py from the Free PDK PDK%d instruction-set table. Do not edit.\n" % W + "".join(out))
    print(f"PDK{W}: {count} constructors, {len(fields)} fields")


def bitop(mn, target, opfield):
    """bit operations on IO or M"""
    if target == "IO.n":
        x = "IO"
    else:
        x = "M"
    n = "n"
    get = f"((x >> n) & 1)"
    s = f"\tlocal x:1 = {x};\n\tlocal m:1 = (1:1 << n);\n"
    if mn == "T0SN":
        return s + skip_if("(x & m) == 0")
    if mn == "T1SN":
        return s + skip_if("(x & m) != 0")
    if mn == "SET0":
        return s + f"\t{x} = x & ~m;\n"
    if mn == "SET1":
        return s + f"\t{x} = x | m;\n"
    if mn == "TOG":
        return s + f"\t{x} = x ^ m;\n"
    if mn == "WAIT0":
        return s + "\tif ((x & m) == 0) goto <done>;\n\tgoto inst_start;\n\t<done>\n"
    if mn == "WAIT1":
        return s + "\tif ((x & m) != 0) goto <done>;\n\tgoto inst_start;\n\t<done>\n"
    if mn == "SWAPC":
        return (s + "\tlocal c:1 = zext(CF);\n\tCF = (x & m) != 0;\n"
                f"\t{x} = (x & ~m) | (c << n);\n")
    raise AssertionError(mn)


def subst(b, form, opfield, wordform):
    """replace the generic operand names by the real field names"""
    def rep(name, real):
        nonlocal b
        b = re.sub(r"(?<![A-Za-z_0-9])" + name + r"(?![A-Za-z_0-9])", real, b)
    mn = form.split()[0]
    # the generic names used in the bodies: M, MW, K, IO, n, nn
    if "IO" in opfield:
        rep("IO", opfield["IO"][0])
    if "M" in opfield:
        nm = opfield["M"][0]
        if wordform and mn != "IDXM":
            rep("MW", f"MW_{nm}")
        elif mn == "IDXM":
            rep("MW", f"MW_{nm}")
        else:
            rep("M", f"M_{nm}")
    if "k" in opfield:
        rep("K", opfield["k"][0] + ":1" if "k" in opfield else "K")
    if "n" in opfield:
        rep("nn", opfield["n"][0])
        rep("n", opfield["n"][0])
    return b


if __name__ == "__main__":
    main(sys.argv[1])
