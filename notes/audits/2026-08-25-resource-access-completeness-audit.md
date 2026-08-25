# Resource-Access Completeness Audit, 2026-08-25

This is a read-only audit record, not an attestation. It documents a
FAIL verdict against the `#723` five-criterion candidate gate for
`draft-mcguinness-oauth-mission-resource-access.md` (the Mission
Resource Access RAR profile), reached by the 2026-08-25 audit wave
against main at commit `8623171e` (the merge of PR #723). No
`candidate-gate.json` entry cites this record, because no attestation
resulted: the gap list below is the queue toward a future attestation,
and any future attestation must cite a fresh audit commit of its own,
never this record. PR #727 is the historical review venue this finding
first appeared in; it is not the tracker for the gap list, which lives
here.

Anchors are cited primarily. Line numbers, where given, are as of main
`8623171e` and are marked as such; they are not claimed current at HEAD.

## Verdict

FAIL, criterion 1 (complete requirement inventory).

13 conformance-manifest rows exist for this document, all `coverage:
"todo"`: zero tested, zero `src` paths.

## C1: rowless requirements

The Subset Rule (`{{subset}}`, the document's namesake algebra) carries
zero rows: resource containment, action-family containment, the per-key
constraint subset test, and 3 derived-delegation-narrower MUSTs are all
uninventoried.

The 9 Common Constraint registry entries defined under
`{{common-constraints}}` each carry their own subset and intersection
rule; only one generic cross-cutting row exists in the ledger for the
whole registry. Individually uninventoried: `max_amount`,
`resource_issued_after`, `resource_issued_before`, `tenant`,
`recipient_domain`, `time_window`, `data_classification`,
`allowed_tools`, `requires_action_approval`.

Also uninventoried:

- The decimal-string grammar and arithmetic rules for `max_amount` and
  related numeric constraints (5 distinct MUSTs).
- The consent-rendering family-breadth MUST.
- The delegation-absent-non-delegable MUST NOT.
- The AS MUST apply delegation policy at every exchange.
- The self-asserted `sub_profile` MUST NOT.
- Most of `{{resource-boundary-canonicalization}}`'s concrete
  deployment MUSTs.

Overall estimate: roughly 25 to 30 distinct testable requirements exist
beyond the 13 already rowed.

## C2: decide-issue scope

Pass. `#722` is resolved in tree at commit
`c37dd584f513f828d864b09a67b3926fbe06e64c`: the missing `},\n  {` object
boundary is repaired, and the recovered row,
`cross-domain.resource-as.client-id-identifies-redeemer`, is added with
`coverage: "tested"` against the two tests #722 itself named. This
commit is an ancestor of both the audit wave's reference commit
(`8623171e`) and current main.

Correction disclosed: the relayed finding originally cited
`2cabef2d531b7a635ba17e6d0b99ed0129031984` for this resolution. That
commit's own diff to `conformance-manifest.json` does not touch the
recovered row (`git log -S` on the row's id name finds only
`c37dd584` in the full history), and its subject line names an
unrelated restructure. `c37dd584` is cited above instead as the
verified resolution.

## C3: named conformance floor

Structurally satisfies the gate: a real Conformance heading exists,
split by AS and RS role. Zero implementation evidence stands behind it.

## C4: examples or waiver

Pass. 6 example blocks are present; the document builds clean.

## C5: disclosed unstable external dependencies

Pass. The only Internet-Draft normative reference is in-family: the
OAuth Mission core itself.

## Gap list (queue toward a future attestation)

- Inventory the Subset Rule algebra (`{{subset}}`): resource
  containment, action-family containment, per-key constraint subset,
  and the 3 derived-delegation-narrower MUSTs.
- Inventory the 9 Common Constraint registry entries' individual
  subset and intersection rules (`{{common-constraints}}`), plus the
  decimal-string grammar and arithmetic MUSTs.
- Row the consent-rendering family-breadth MUST, the
  delegation-absent-non-delegable MUST NOT, the per-exchange
  delegation-policy MUST, the self-asserted `sub_profile` MUST NOT, and
  the remaining `{{resource-boundary-canonicalization}}` deployment
  MUSTs.
- Move rows off `todo` with real tests, not only inventory entries.
- A fresh audit commit, postdating the above, is required before any
  `candidate-gate.json` attestation for this document.
