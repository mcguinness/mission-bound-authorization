#!/usr/bin/env python3
"""Measure the OAuth binding's prose budget (exit condition 8) at an explicit git revision.

Regions:
- body: from "# Introduction" to before "# IANA Considerations";
- extensibility: the "# Extensibility" chapter, to the next level-1 heading
  (Conformance at the frozen baseline);
- appendices: from "--- back" to before "# Document History", reported
  separately so that moving text out of the body cannot hide reading.

The regions assume the headings Introduction, IANA Considerations,
Extensibility and Document History keep those exact titles and that no
level-1 section is inserted after Extensibility; a run after either change
must re-check its regions before comparing.

Each count is whitespace-separated tokens, excluding fenced code blocks
(``` or ~~~) and kramdown attribute lines ("{: ...}"). The bibliography is
outside every region, and Document History is excluded.
"""

import argparse
import json
import re
import subprocess

PATH = "draft-mcguinness-oauth-mission.md"


def words(text):
    count, fenced = 0, False
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fenced = not fenced
            continue
        if fenced or stripped.startswith("{:"):
            continue
        count += len(line.split())
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision", help="Commit or ref to measure")
    args = parser.parse_args()
    rev = subprocess.check_output(["git", "rev-parse", f"{args.revision}^{{commit}}"], text=True).strip()
    text = subprocess.check_output(["git", "show", f"{rev}:{PATH}"], text=True)
    intro = re.search(r"^# Introduction\b.*$", text, re.M).start()
    iana = re.search(r"^# IANA Considerations\b.*$", text, re.M).start()
    ext = re.search(r"^# Extensibility\b.*$", text, re.M).start()
    ext_end = re.search(r"^# ", text[ext + 1:], re.M).start() + ext + 1
    back = text.index("\n--- back")
    history = re.search(r"^# Document History\b.*$", text, re.M).start()
    print(json.dumps({
        "revision": rev,
        "body": words(text[intro:iana]),
        "extensibility": words(text[ext:ext_end]),
        "appendices": words(text[back:history]),
    }))


if __name__ == "__main__":
    main()
