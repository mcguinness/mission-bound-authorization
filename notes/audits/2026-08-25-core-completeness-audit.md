# Core Completeness Audit, 2026-08-25

This is a read-only audit record, not an attestation. It documents a FAIL
verdict against the `#723` five-criterion candidate gate for
`draft-mcguinness-oauth-mission.md` (the OAuth Mission core), reached by
the 2026-08-25 audit wave against main at commit `8623171e` (the merge of
PR #723). No `candidate-gate.json` entry cites this record, because no
attestation resulted: the gap list below is the queue toward a future
attestation, and any future attestation must cite a fresh audit commit
of its own, never this record. PR #727 is the historical review venue
this finding first appeared in; it is not the tracker for the gap list,
which lives here.

Anchors are cited primarily. Line numbers, where given, are as of main
`8623171e` and are marked as such; they are not claimed current at HEAD.

## Verdict

FAIL, criterion 1 (complete requirement inventory).

61 conformance-manifest rows across 18 anchors stand against
approximately 322 BCP-14 keyword hits in the document body. Of the
sections carrying zero rows, 35 had at least one BCP-14 keyword hit; 7 of
those were hand-verified as genuine gaps (listed below); the remaining 28
were flagged by the mechanical pass but not individually hand-verified.

## C1: hand-verified rowless sections (as of main `8623171e`)

| Anchor | Line | Section | Note |
|---|---:|---|---|
| `{{rs-enforcement}}` | 3238 | Resource Server Enforcement | The section core's own Conformance heading names as the RS-side floor. Approximately 20 BCP-14 hits uncovered: JWT and `cnf` validation, `authorization_details` as authoritative, fail-closed on an unimplementable entry, MUST NOT disclosure-only constraints, MUST NOT let scope broaden past `authorization_details`, `client_id` non-reinterpretation, conditional mission-claim rejection, the cnf-after-introspection MUST, delegated-token routing MUST NOT. |
| `{{authority-proposal}}` | 1184 | The Authority Proposal | 6 or more uncovered MUSTs. |
| `{{canonicalization}}` | 2290 | Canonicalization Rules | The array-order MUST is uncovered; the duplicate-member MUST is covered under the sibling commitment-mechanisms anchor, not this one. |
| `{{revocation}}` | 3801 | Revocation | Uncovered. |
| `{{discovery}}` | 4472 | Authorization Server Metadata (Discovery and AS Metadata) | 7 or more uncovered MUSTs. |
| `{{mission-claim}}` | 3122 | The Mission Claim | Uncovered. |
| `{{denial-disclosure}}` | 4996 | Denial Detail Disclosure | Uncovered. |

28 further sections were flagged by the mechanical keyword pass as
carrying at least one BCP-14 hit with zero conformance rows, but were not
individually hand-verified in this wave. They remain unresolved; a future
audit should either hand-verify each as a genuine gap or record a
rationale for exclusion, the same discipline the substrate audit applied.

## C2: decide-issue scope

Pass, with one item still open. `#663` is resolved in tree at commit
`f95ff26d96ec9768a6732fadfa3acd6d48a90e82`. `#660` remains open: the
core's high-risk classification is the canonical account, and the fix
burden sits on the template and progressive companions, not on the core
itself.

## C3: named conformance floor

Pass in substance, undercounted in extent. Real implementation evidence
exists behind the 61 rows: 18 tested, 7 partial with honestly disclosed
limits, 36 todo. The floor is real; the row set undercounts the
requirement surface it should cover, per C1 above.

## C4: examples or waiver

Pass. 74 example blocks, an end-to-end worked example, and
integrity-anchor test vectors are present; the document builds clean.

## C5: disclosed unstable external dependencies

Pass. Every normative reference is a ratified RFC or ISO 4217; zero
Internet-Drafts.

## Gap list (queue toward a future attestation)

- Add conformance-manifest rows for Resource Server Enforcement
  (`{{rs-enforcement}}`), Authority Proposal (`{{authority-proposal}}`),
  Canonicalization array-order (`{{canonicalization}}`), Revocation
  (`{{revocation}}`), Discovery and AS Metadata (`{{discovery}}`), the
  Mission Claim (`{{mission-claim}}`), and Denial Detail Disclosure
  (`{{denial-disclosure}}`).
- Hand-verify the remaining 28 flagged sections: either row the gap or
  record an exclusion rationale.
- Resolve `#660` (template/progressive prohibited-set divergence from the
  core's high-risk classification).
- A fresh audit commit, postdating the above, is required before any
  `candidate-gate.json` attestation for this document.
