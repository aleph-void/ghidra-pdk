#!/usr/bin/env python3
"""Real-code check: import each flat PDK image headless (analysis on), then compare Ghidra's disassembly with ucsim's
at every address Ghidra decoded, and report counts.

usage: real_check.py <workdir> <image.bin>:<width>:<chip>:<language-id> ...
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools_path, re, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import diff_decode as D

UCSIM = tools_path.find("ucsim_pdk", "UCSIM_PDK")


def ucsim_dis(binfile, W, nwords):
    data = open(binfile, "rb").read()
    cmds = "".join(f"set mem rom {i} {data[2 * i] | (data[2 * i + 1] << 8 if 2 * i + 1 < len(data) else 0)}\n"
                   for i in range(nwords)) + f"dc 0 {nwords - 1}\nquit\n"
    out = subprocess.run([UCSIM, "-t", f"pdk{W}", "-b"], input=cmds, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, timeout=120).stdout
    res = {}
    for l in out.splitlines():
        # a disassembly line is "0xAAAA  <marker> WWWW   text"; the echoes of the set commands have wide gaps instead
        m = re.search(r"0x([0-9a-f]{4})  \S ([0-9a-f]{4}) {2,}(\S.*?)\s*$", l)
        if m:
            res[int(m.group(1), 16)] = (int(m.group(2), 16), m.group(3))
    return res


def main():
    work = sys.argv[1]
    os.makedirs(work, exist_ok=True)
    tot = dict(ins=0, agree=0, explained=0, unexplained=0, func=0, bad=0, err=0, dfail=0)
    for spec in sys.argv[2:]:
        img, W, chip, lang = spec.split(":", 3)[0], *spec.split(":", 3)[1:]
        W = int(W)
        name = os.path.basename(img)
        out = os.path.join(work, name + ".ghidra")
        subprocess.run([os.path.join(HERE, "real-one.sh"), lang, img, out], check=True)
        ion = D.ionames(chip)
        uc = ucsim_dis(img, W, (os.path.getsize(img) + 1) // 2)
        agree = expl = unexp = n = 0
        summ = ""
        examples = []
        for l in open(out):
            if l.startswith("summary"):
                summ = l.strip()
            if not l.startswith("ins "):
                continue
            _, a, w, text = l.rstrip("\n").split(" ", 3)
            a = int(a, 16); w = int(w, 16)
            n += 1
            g = D.finalize_ghidra(D.canon_ghidra(text, ion))
            if a not in uc:
                unexp += 1; examples.append((a, w, text, None)); continue
            uw, ut = uc[a]
            u = D.canon_ucsim(ut, W)
            if uw != w:
                unexp += 1; examples.append((a, w, text, "word mismatch")); continue
            if g == u:
                agree += 1
            else:
                cls = "differ" if (g and u) else ("oracle valid, module invalid" if u else "module valid, oracle invalid")
                why = D.explain(W, "ucsim", cls, g, u)
                if why:
                    expl += 1
                else:
                    unexp += 1; examples.append((a, w, text, ut))
        print(f"{name}: {summ.replace('summary ', '')}; vs ucsim at the same addresses: {agree} agree, {expl} explained, {unexp} unexplained")
        for e in examples[:5]:
            print("     unexplained:", e)
        m = dict(kv.split("=") for kv in summ.replace("summary ", "").split())
        tot["ins"] += int(m["instructions"]); tot["func"] += int(m["functions"]); tot["bad"] += int(m["bad_instruction_bookmarks"])
        tot["err"] += int(m["error_bookmarks"]); tot["dfail"] += int(m["decompile_failures"])
        tot["agree"] += agree; tot["explained"] += expl; tot["unexplained"] += unexp
    print("TOTAL", " ".join(f"{k}={v}" for k, v in tot.items()))
    sys.exit(1 if tot["unexplained"] or tot["bad"] or tot["err"] or tot["dfail"] else 0)


main()
