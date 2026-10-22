#!/usr/bin/env python3
"""Reproduce the measurements in PLAN.md.

Run from the repository root:

    python3 notes/audits/2026-10-22-oauth-binding-layering/measure.py

Self-contained: it parses kramdown headings ("# Title {#anchor}") itself
and needs only the Python standard library. Sections are the text
between one heading and the next, at any level, so a parent heading's
counts exclude its subsections.
"""
import collections
import glob
import json
import re

CORE = "draft-mcguinness-oauth-mission.md"
KW = re.compile(r"\b(MUST NOT|SHALL NOT|SHOULD NOT|MUST|SHALL|SHOULD|"
                r"REQUIRED|RECOMMENDED|NOT RECOMMENDED|MAY|OPTIONAL)\b")
FAM = re.compile(r"\{\{I-D\.draft-mcguinness-((?:oauth-)?mission[a-z0-9-]*)\}\}")
HEAD = re.compile(r"^(#+) (.*?) \{#([a-z0-9-]+)\}\s*$")

# Job buckets (PLAN.md Section 2). Every middle-matter anchor is in one.
JOBS = {
    "1 issuance protocol (incl. approval)": """introduction protocol-flow
      conventions-and-terminology terminology principal-model mission-intent
      intent-members submission-via-par authority-proposal
      submission-processing authorization-derivation derivation-modes
      consented-authority-set derivation-policy-tasks subset other-types
      approval-event approval-code-protection direct-approval-steps
      approval-preparation approval-commit subject-establishment
      approval-context-changes lifecycle termination revocation
      mission-bound-tokens grant-binding grant-binding-resolution
      grant-binding-state mission-response-parameters issuance-gating
      token-claims token-response refresh-tokens
      token-authentication-lifetime scope-projection mission-claim
      rs-enforcement rs-requirements rs-mission-unaware rs-carried-authority
      rs-denials rs-responsibilities error-mapping introspection
      caller-authorization-and-minimization composite-active
      only-issuer-reports-state introspected-consumption mission-record
      record-identity-members record-content-members
      record-provenance-members mission-id integrity-and-commitments
      integrity-anchors canonicalization discovery
      protected-resource-metadata conformance conformance-roles
      claiming-conformance iana oauth-parameters-registration
      oauth-extensions-error-registration json-web-token-claims-registration
      oauth-token-introspection-response-registration
      oauth-authorization-server-metadata-registration
      oauth-protected-resource-metadata-registration iana-lifecycle-states
      iana-termination-reasons iana-intent-members rendering-safeguards
      approval-comprehension authority-sources approval-authentication
      multi-party-approval intent-submission-evidence""",
    "2 RFC 8693 delegation profile": """delegation designation
      delegated-exchange delegated-instance-context self-exchange
      delegation-constraints worked-example-delegated-token
      optional-capabilities""",
    "3 companion hooks and extension framework": """implementation-map
      standing-consent-bases standing-consent-instances
      activation-policy-commitment standing-consent-recency
      transformation-capabilities policy-language-types remediation-grains
      grant-binding-related extensibility extension-points
      namespace-taxonomy record-principal-members commitment-mechanisms""",
    "5 tutorial and examples (middle matter)": """overview first-mission
      examples worked-example""",
    "6 security, privacy, i18n, applicability": """security-considerations
      sec-commitment consent-binding downgrade-by-omission sec-agent
      prompt-injection information-propagation sec-enforcement
      runtime-boundary denial-disclosure sec-credentials token-theft
      delegation-and-chain-compromise client-id-misattribution key-rotation
      sec-composition compromised-or-over-broad-derivation
      authority-hash-is-not-a-mission-identifier
      composition-and-the-effective-ceiling
      the-containment-materialized-capability-residual
      privacy-considerations mission-identifier-correlation
      token-payload-disclosure intent-retention-and-anchor-disclosure
      third-party-data-subjects record-access i18n applicability""",
}
JOB_OF = {a: j for j, s in JOBS.items() for a in s.split()}


def sections(path):
    """Yield (anchor, title, level, first_line, text, in_back)."""
    lines = open(path).read().split("\n")
    # start at the middle matter; front matter and abstract are skipped
    start = [i for i, l in enumerate(lines) if l.startswith("--- middle")][0] + 1
    back = False
    cur = None
    buf = []
    for i in range(start, len(lines)):
        l = lines[i]
        if l.startswith("--- back"):
            if cur:
                yield (*cur, "\n".join(buf), back)
            cur, buf, back = None, [], True
            continue
        m = HEAD.match(l)
        if m:
            if cur:
                yield (*cur, "\n".join(buf), back)
            cur = (m.group(3), m.group(2), len(m.group(1)), i + 1)
            buf = []
        elif cur:
            buf.append(l)
    if cur:
        yield (*cur, "\n".join(buf), back)


def main():
    secs = list(sections(CORE))
    mid = [s for s in secs if not s[5]]
    back = [s for s in secs if s[5]]

    print("== Middle matter by job (words, BCP 14 keywords, sections)")
    agg = collections.defaultdict(lambda: [0, 0, 0])
    unknown = []
    for a, t, lvl, ln, txt, _ in mid:
        j = JOB_OF.get(a)
        if not j:
            unknown.append(a)
            continue
        agg[j][0] += len(txt.split())
        agg[j][1] += len(KW.findall(txt))
        agg[j][2] += 1
    for j in sorted(agg):
        w, k, n = agg[j]
        print(f"  {j:45s} words={w:6d} kw={k:4d} sections={n}")
    print("  unclassified:", unknown or "none")
    print("  total middle words:", sum(v[0] for v in agg.values()),
          "keywords:", sum(v[1] for v in agg.values()))

    print("\n== Back matter, top-level appendices (words, keywords)")
    tops = collections.OrderedDict()
    cur = None
    for a, t, lvl, ln, txt, _ in back:
        if lvl == 1:
            cur = f"{t} (line {ln})"
            tops[cur] = [0, 0]
        if cur:
            tops[cur][0] += len(txt.split())
            tops[cur][1] += len(KW.findall(txt))
    for k, (w, kw) in tops.items():
        print(f"  {w:6d} kw={kw:3d} {k}")

    print("\n== Family citations ({{I-D.draft-mcguinness-*mission*}})")
    allc = collections.Counter()
    midc = 0
    per = []
    for a, t, lvl, ln, txt, isback in secs:
        c = collections.Counter(FAM.findall(txt))
        allc.update(c)
        if not isback:
            midc += sum(c.values())
            if c:
                per.append((ln, a, c))
    print(f"  total={sum(allc.values())} middle={midc} drafts={len(allc)}")
    for k, v in allc.most_common():
        print(f"    {v:4d} {k}")
    print("  by middle-matter section (line, anchor, count, drafts):")
    for ln, a, c in per:
        names = ", ".join(f"{k}x{v}" if v > 1 else k for k, v in c.most_common())
        print(f"    {ln:5d} {a:44s} {sum(c.values()):2d} {names}")

    print("\n== Normative I-D references and where the body cites them")
    fm = open(CORE).read().split("\n--- abstract", 1)[0]
    norm = fm.split("normative:", 1)[1].split("informative:", 1)[0]
    ids = re.findall(r"^  (I-D\.[a-z0-9.-]+):", norm, re.M)
    for ref in ids:
        where = collections.Counter()
        for a, t, lvl, ln, txt, isback in secs:
            n = txt.count("{{" + ref + "}}") + len(
                re.findall(r"of " + re.escape(ref) + r"\}\}", txt))
            if n:
                where[a + (" (appendix)" if isback else "")] += n
        print(f"  {ref}: {dict(where)}")

    print("\n== Ledger rows anchored in sections this plan moves or touches")
    m = json.load(open("conformance-manifest.json"))
    rows = [r for r in m["requirements"] if r["spec"] == CORE]
    # P1 variant B: the exchange mechanics move; Delegation Constraints
    # and Self-Exchange stay. One self-exchange-anchored row is about
    # designations and moves with them.
    mech = set("""delegation designation delegated-exchange
        delegated-instance-context worked-example-delegated-token""".split())
    desig_row = "core.self-exchange.designation-not-self-exchange"
    groups = {
        "P1-B moves": lambda r: r["anchor"] in mech or r["id"] == desig_row,
        "P1-B stays: constraints": lambda r: r["anchor"] == "delegation-constraints",
        "P1-B stays: self-exchange": lambda r: r["anchor"] == "self-exchange"
        and r["id"] != desig_row,
        "P2 standing consent": lambda r: r["anchor"] in {
            "standing-consent-bases", "standing-consent-instances",
            "activation-policy-commitment", "standing-consent-recency"},
        "P4 commitment mechanisms": lambda r: r["anchor"] == "commitment-mechanisms",
    }
    print(f"  core rows total: {len(rows)}")
    for g, pred in groups.items():
        rs = [r for r in rows if pred(r)]
        cov = collections.Counter(r.get("coverage") for r in rs)
        print(f"  {g:24s} rows={len(rs):3d} {dict(cov)}")
        for r in rs:
            ap = r.get("applicability", {})
            gate = ap.get("capability", ap.get("kind"))
            print(f"      {r['id']:60s} {r.get('coverage'):8s} {gate}")


IDENTS = """consent_principal activation_actor root_commitment approved_at
    adjudication governance_record governed_policy policy_drawdown
    ceiling_drawdown mission_resource_access
    mission_transformation_capabilities""".split()


def identifiers():
    """Where each identifier appears: binding sections vs other drafts."""
    print("\n== Identifier use: binding sections vs other drafts")
    secs = [s for s in sections(CORE) if not s[5]]
    others = [f for f in sorted(glob.glob("draft-*.md")) if f != CORE]
    texts = {f: open(f).read() for f in others}
    for ident in IDENTS:
        tick = "`" + ident + "`"
        hits = [s[0] for s in secs if tick in s[4]]
        word = re.compile(r"\b" + re.escape(ident) + r"\b")
        users = {f: len(word.findall(t)) for f, t in texts.items()}
        users = {f: n for f, n in users.items() if n}
        print(f"  {ident:36s} binding-sections={len(hits):2d} "
              f"other-drafts={len(users):2d} other-mentions={sum(users.values()):4d}"
              f"  [{', '.join(hits[:6])}]")


if __name__ == "__main__":
    main()
    identifiers()
