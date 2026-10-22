"""List companion citations of named sections of the OAuth binding.

Run from the repository root. Prints one line per citation:
TAG file:line section
"""
import glob
import re
import sys

GROUPS = {
    "DELEG": {
        "Delegation Within a Mission", "Designation", "Delegated Exchange",
        "Instance Context in Delegated Tokens", "Self-Exchange Down-Scoping",
        "Delegation Constraints", "Delegated Token Example",
    },
    "SC": {
        "Standing-Consent Bases", "Standing-Consent Instances",
        "Activation Policy Commitment", "Standing-Consent Recency",
    },
    "CM": {"Commitment Mechanisms"},
    "BIND": {"OAuth Binding Mapping Assessment", "Role Mapping"},
}
CORE = "draft-mcguinness-oauth-mission.md"
PAT = re.compile(
    r'\{\{I-D\.draft-mcguinness-oauth-mission\}\},? \(?(?:Sections? )?"([^"]+)"'
    r'|Section "([^"]+)" of \{\{I-D\.draft-mcguinness-oauth-mission\}\}'
)

for f in sorted(glob.glob("draft-*.md")):
    if f == CORE:
        continue
    text = open(f).read()
    flat = re.sub(r"\s+", " ", text)
    # map flat offsets back to line numbers
    starts, pos = [], 0
    for line in text.split("\n"):
        starts.append(pos)
        pos += len(line) + 1
    for m in PAT.finditer(flat):
        sec = m.group(1) or m.group(2)
        for tag, names in GROUPS.items():
            if sec in names:
                # approximate line: count words before the match
                words_before = len(flat[: m.start()].split())
                acc, lineno = 0, 1
                for i, line in enumerate(text.split("\n")):
                    acc += len(line.split())
                    if acc > words_before:
                        lineno = i + 1
                        break
                print(f"{tag:5s} {f}:{lineno}  {sec}")
