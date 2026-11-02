#!/usr/bin/env python3
"""Inventory draft citations at an explicit git revision without a checkout."""

import argparse
import collections
import json
from pathlib import Path
import re
import subprocess


def source(revision, path):
    return subprocess.check_output(
        ["git", "show", f"{revision}:{path}"], text=True
    )


def package(slug, anchor):
    if slug == "draft-mcguinness-mission-approval-governance":
        return "P3", "Audit the direct contract and transfer adopter duties explicitly."
    if slug in {
        "draft-mcguinness-oauth-client-instance-id",
        "draft-mcguinness-oauth-client-attesters",
    }:
        return "Separate", "Retain unless issue #1412's destination conditions are met."
    if slug == "draft-mcguinness-oauth-actor-profile":
        return "Retain", "Keep the dependency where retained Delegation requirements use it."
    if slug == "draft-mcguinness-oauth-mission-resource-access":
        example = any(x in anchor for x in ["example", "first-mission", "stage-"])
        return ("P4" if example else "P2"), (
            "Replace the baseline type example; preserve shared fixture consumers."
            if example else
            "Keep the generic type contract; inspect for unique type-specific duties."
        )
    if slug in {
        "draft-mcguinness-oauth-mission-cross-domain",
        "draft-mcguinness-oauth-mission-submission-evidence",
        "draft-mcguinness-oauth-mission-expansion",
        "draft-mcguinness-oauth-mission-child-delegation",
        "draft-mcguinness-oauth-mission-template",
        "draft-mcguinness-oauth-mission-continuation",
        "draft-mcguinness-oauth-mission-device-authorization",
        "draft-mcguinness-oauth-mission-approval",
        "draft-mcguinness-oauth-mission-status",
        "draft-mcguinness-mission-authority-server",
    }:
        return "P2", "Separate a generic invariant from any mechanism-specific duty."
    return "P1", "Remove explanatory detours only after checking for a unique obligation."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision", help="Commit or ref to audit")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    revision = subprocess.check_output(
        ["git", "rev-parse", f"{args.revision}^{{commit}}"], text=True
    ).strip()
    path = "draft-mcguinness-oauth-mission.md"
    text = source(revision, path)
    family = json.loads(source(revision, "family-manifest.json"))
    family_slugs = {item["slug"] for item in family["drafts"]}
    start = text.index("--- abstract")
    end = text.index("# Document History")
    headings = []
    for match in re.finditer(r"^(#{1,6}) (.*?) \{#([^}]+)\}\s*$", text, re.M):
        headings.append((match.start(), match.group(2), match.group(3)))

    rows = []
    for citation in re.finditer(r"\{\{(.*?)\}\}", text[start:end], re.S):
        offset = start + citation.start()
        preceding = [h for h in headings if h[0] <= offset]
        _, section, anchor = preceding[-1] if preceding else (0, "Abstract", "")
        para_start = text.rfind("\n\n", start, offset)
        para_end = text.find("\n\n", offset, end)
        context = " ".join(text[max(start, para_start + 2):para_end if para_end >= 0 else end].split())
        for slug in re.findall(r"I-D\.(draft-mcguinness-[A-Za-z0-9-]+)", citation.group(1)):
            work_package, candidate = package(slug, anchor)
            rows.append({
                "id": f"C{len(rows) + 1:03}",
                "line": text.count("\n", 0, offset) + 1,
                "section": section,
                "anchor": anchor,
                "target": slug,
                "in_family": slug in family_slugs,
                "candidate_package": work_package,
                "candidate_review": candidate,
                "context": context,
            })
    counts = collections.Counter(r["target"] for r in rows if r["in_family"])
    result = {
        "base_commit": revision,
        "source": path,
        "method": "Citation markup from abstract to before Document History; bibliography and history excluded. Targets are McGuinness drafts; family membership comes from family-manifest.json at the same commit.",
        "family_occurrences": sum(counts.values()),
        "family_documents": len(counts),
        "adjacent_occurrences": sum(not r["in_family"] for r in rows),
        "rows": rows,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "citations.json").write_text(json.dumps(result, indent=2) + "\n")
    url = f"https://github.com/mcguinness/mission-bound-authorization/blob/{revision}/{path}"
    lines = [
        "# OAuth binding companion citation inventory",
        "",
        f"Source: [{revision[:8]}]({url}).",
        "",
        f"The inventory contains {sum(counts.values())} occurrences citing {len(counts)} in-repository family documents and {result['adjacent_occurrences']} occurrences citing adjacent McGuinness documents outside that family. It excludes bibliography declarations and Document History. Counts measure citation markup, not semantic dependencies or distinct requirements.",
        "",
        "Package assignments are review candidates, not approved deletions. Read the full paragraph and follow the requirement disposition procedure in [the plan](PLAN.md). Exact paragraph context is retained in [citations.json](citations.json). A unique condition found during review moves an item out of editorial P1.",
        "",
        "## Counts by family document",
        "",
        "| Document | Occurrences |",
        "| --- | ---: |",
    ]
    lines += [f"| `{slug}` | {count} |" for slug, count in counts.most_common()]
    lines += [
        "", "## Occurrences in source order", "",
        "| ID | Source section | Cited document | Candidate package |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['id']} | [{row['section']}]({url}#L{row['line']}) | `{row['target']}` | {row['candidate_package']} |"
        )
    lines += [
        "", "## Regeneration", "",
        "Run this from the repository root, supplying the exact revision to compare:",
        "", "```sh",
        f"python3 notes/audits/2026-10-31-core-independence/inventory.py {revision}",
        "```", "",
        "Use `--output /tmp/core-independence-comparison` for a later revision to preserve this baseline. The generator reads git objects and writes only its output files; it does not switch branches or fetch.", "",
    ]
    (args.output / "CITATIONS.md").write_text("\n".join(lines))
    print(json.dumps({k: result[k] for k in ["base_commit", "family_occurrences", "family_documents", "adjacent_occurrences"]}))


if __name__ == "__main__":
    main()
