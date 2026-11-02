# Core independence plan critique disposition

The plan is revised for the owner's direction to be aggressive for `-02`. Publication waits for the full independence pass. The existing package IDs are retained for the citation inventory, but execution order is P0, P3, P2, P1, P4, P5.

| Critique | Disposition in revision 2 |
| --- | --- |
| Do the actual Governance dependency removal first. | Accepted. P3 precedes the relocations and editorial cuts. It is the first independently useful result, but does not alone satisfy the full release gate. |
| Assign the extension-contract rewrite. | Accepted. It is P3's first commit, with explicit scope and acceptance. The import remains in force until the destination duties and local contract are ready. |
| Add a size budget. | Accepted. The finished protocol body and Extensibility chapter must not grow against the frozen execution baseline. Measurement boundaries and exception handling are specified. Counts control scope; they do not prove readability. |
| Remove the arbitrary single-pointer cap. | Accepted. Informative citations may remain at their extension hooks when the local baseline contract is complete. Each remaining citation needs a purpose, not a numerical exemption. |
| Do not silently reverse D1057. | Accepted. P0 states the exact proposed supersession and records its authority before implementation treats it as a decision. The owner's independence and aggressive `-02` directions are distinguished from an already-written D-row. P3 remains a substantive normative review. |
| Treat #1895 as undecided. | Corrected on evidence. The issue remains open with `decide`, but an explicit owner ruling was posted. The plan now cites it and separates ruling, stale bookkeeping and unmerged implementation. |
| Reuse an RFC 9396 example. | Accepted with qualification. Reuse `payment_initiation`, but do not imply the RFC standardizes a complete payment API. State the example's limited semantics and add a dedicated fixture, generator, independent digest witness and check against displayed objects. |
| Do not retain source-prefixed IDs across documents automatically. | Accepted as the default for new transfers, with a qualification about existing practice. The ledger already contains Governance-owned `core.approval-basis.*` rows. Ownership is explicit in `spec`; cross-document moves need a deliberate ID decision, an old-to-new map, and updates to tags, test paths and all live references. No bulk renaming or new coverage state is introduced. |
| State publication timing. | Resolved by the owner's latest direction. `-02` waits for P1 to P5. Review one main implementation PR at a time; do not defer the substantive pass merely to preserve the old schedule. |
| Address the pinned Mapping Assessment. | Accepted. Preserve its historical snapshot and warning, run check (t), and make no claim that it assesses the new binding. Refreshing it requires a separate substantive reassessment, not a pin bump. |
| Use a small defect review instead of a scored study. | Accepted. Two independent readers and Karl as adjudicator are specified, with identities recorded before execution. Resolve findings individually; no aggregate score substitutes for complete baseline requirements. |
| Check incoming title references in P2 and P3. | Accepted. Both packages require anchor and section-title checks, including whether the destination still states the cited obligation. |

## Addendum: Revision 3 (2026-11-02)

The rows above are kept as written. Since then:

- **"Do the actual Governance dependency removal first":** done (#1974, D1167).
- **"Assign the extension-contract rewrite":** overtaken by D1134. The import was removed under option B before any contract commit. The contract review remains its own step, and exit condition 5 is not demonstrated (D1195).
- **"Do not silently reverse D1057":** D1134 records the supersession, in its own wording, not in P0's proposed text.
- **"Treat #1895 as undecided":** ruled (D1114) and implemented (PR #1960, D1123); #1895 is closed.
- **"State publication timing":** confirmed by D1112 and D1195. `-02` waits for the full gate: the eight exit conditions, P5 and the completion record, subject to D1134.

## Addendum: the execution baseline (2026-11-02, after #2007)

- **"Add a size budget":** the baseline is frozen at `c79d84ad` with `measure.py`. The extension contract is funded from Extensibility's existing text, unless the owner rules a single body budget.
- **The tracking issue:** #2009 tracks the gate (D1204). D1211 supersedes D1206, which had assigned it to #1944.
- **P3's remaining items:** A1, the adopter review and the Governance member explanations are listed beside the extension-contract review.
- **"Reuse an RFC 9396 example":** the delegated example carries its entry unchanged, since the payment fields define no subset relation.

## Evidence for the qualifications

The [posted owner ruling for #1895](https://github.com/mcguinness/mission-bound-authorization/issues/1895#issuecomment-6553145841) explicitly adopts A with B's clarification. It preserves the token-independent requirement and authorizes one reviewable PR. An open issue and stale label do not negate that ruling, but the comment does not prove implementation has landed.

[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html#section-2.1) leaves interpretation of an authorization-details type to the AS and API. Its payment example is useful familiar material, not a complete standardized schema that can replace the example's validation and enforcement assumptions.

At `3d3185378604c70e655a663c7b6ef103366ba5d5`, the [conformance manifest](https://github.com/mcguinness/mission-bound-authorization/blob/3d3185378604c70e655a663c7b6ef103366ba5d5/conformance-manifest.json) includes `core.approval-basis.standing-consent-root-commitment-required` and other `core.*` IDs with Approval Governance as their `spec`. The critique identifies a naming and traceability risk, but a source-prefixed ID does not by itself establish the wrong normative owner.

## Status

Committed with the plan in Revision 3 (#1944, 2026-11-02). Its later records are D1134, D1167, D1189, D1192, D1195, D1198, D1204 and D1211; the execution baseline is frozen at `c79d84ad`. The baseline citation inventory remains pinned to its original commit. No review exercise or example implementation is claimed complete.
