#!/usr/bin/env python3
"""Parse the Free PDK instruction-set HTML pages into (pattern, mnemonic, flags, description) rows.
usage: parse_doc.py PDKnn.html  -> JSON lines"""
import sys, re, json, html
from html.parser import HTMLParser
class P(HTMLParser):
    def __init__(s): super().__init__(); s.rows=[]; s.cur=None; s.cell=None; s.span=1
    def handle_starttag(s,t,a):
        if t=='tr': s.cur=[]
        if t in('td','th'):
            s.cell=''; s.span=int(dict(a).get('colspan','1'))
    def handle_endtag(s,t):
        if t in('td','th') and s.cell is not None: s.cur.append((s.cell.strip(),s.span)); s.cell=None
        if t=='tr' and s.cur is not None: s.rows.append(s.cur); s.cur=None
    def handle_data(s,d):
        if s.cell is not None: s.cell+=d
def parse(path):
    W=int(re.search(r'PDK(\d\d)',path).group(1))
    p=P(); p.feed(open(path).read()); out=[]
    for r in p.rows:
        if len(r)<5 or not r[0][0].startswith('0x'): continue
        cells=r[1:]; pat=[]; tot=0; i=0
        while tot<W and i<len(cells):
            txt,sp=cells[i]; i+=1; pat.append((txt.strip(),sp)); tot+=sp
        rest=[c[0].replace('\n',' ') for c in cells[i:]]
        out.append((r[0][0],pat,rest))
    return W,out
if __name__=='__main__':
    W,rows=parse(sys.argv[1])
    for h,pat,rest in rows: print(h,' '.join(f"{t}x{s}" if s>1 else t for t,s in pat),'|',rest[:1])


def dump_tab(html_path, tab_path):
    """Saves the parsed table as JSON lines (the HTML page is not committed; this table is)."""
    import json
    W, rows = parse(html_path)
    with open(tab_path, "w") as f:
        for h, pat, rest in rows:
            f.write(json.dumps([h, pat, rest]) + "\n")


def parse_tab(tab_path):
    import json
    return [tuple(json.loads(l)) for l in open(tab_path)]
