#!/usr/bin/env python3
"""P4 inventory: which drafts use commitment-construction vocabulary, and whose.

Run from the repository root. For every paragraph (blank-line separated)
in every draft other than the OAuth binding and the substrate that uses
commitment vocabulary (species names, "commitment mechanisms", the
agility or unrecognized-prefix rules, "prefixed commitment", "Default
Commitment Construction"), report which source the paragraph cites:
the OAuth binding, the substrate, both, or neither. A paragraph that
names a species but cites neither inherits its source from elsewhere in
the draft, so read those by hand.
"""
import glob
import re

SKIP = {"draft-mcguinness-oauth-mission.md", "draft-mcguinness-mission-substrate.md"}
VOCAB = re.compile(
    r"raw-octet|canonical-object|envelope anchor|commitment mechanisms|"
    r"algorithm[- ]agility|unrecogni[sz]ed[- ]prefix|unknown[- ]prefix|"
    r"prefixed commitment|Default Commitment Construction", re.I)
BINDING = "{{I-D.draft-mcguinness-oauth-mission}}"
SUBSTRATE = "{{I-D.draft-mcguinness-mission-substrate}}"

for f in sorted(glob.glob("draft-*.md")):
    if f in SKIP:
        continue
    text = open(f).read()
    lines = text.split("\n")
    para, start, out = [], 1, []
    for i, line in enumerate(lines + [""], start=1):
        if line.strip():
            if not para:
                start = i
            para.append(line)
            continue
        if para:
            p = " ".join(para)
            terms = sorted({m.group(0).lower() for m in VOCAB.finditer(p)})
            if terms:
                src = ("both" if BINDING in p and SUBSTRATE in p else
                       "binding" if BINDING in p else
                       "substrate" if SUBSTRATE in p else "neither")
                out.append((start, src, ", ".join(terms)))
            para = []
    if out:
        tally = {s: sum(1 for o in out if o[1] == s)
                 for s in ("binding", "substrate", "both", "neither")}
        print(f"{f}: {tally}")
        for start, src, terms in out:
            if src != "neither":
                print(f"    line {start}: {src}: {terms}")
