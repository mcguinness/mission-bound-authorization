# Runtime-Enforced Conformance Self-Assessment

The M14 capstone: the written self-assessment goal 1 requires, plus goal 2's
consolidated spec-feedback report. Every claim links to the tests that
demonstrate it (all run headless against live OpenFGA; `pnpm test`, `pnpm
evals`, `pnpm demo:vendor-test`).

## 1. The six Runtime-Enforced invariants

Per `draft-mcguinness-mission-architecture.md` § Runtime-Enforced Mission
conformance (the four Baseline invariants plus two).

| # | Invariant | Met by | Evidence |
|---|---|---|---|
| 1 | **Durable approved-task record.** A Mission Record exists, immutable but for state, committed by both anchors. | `mission-core` anchors; kernel approval event | `mission-core/test/anchors.test.ts`, `authorization-server/test/kernel.test.ts` |
| 2 | **Authority derived, not asserted.** Authority is derived from the Intent under policy; the client cannot widen it. | derivation + subset rule; compromised-shaper test | `kernel.test.ts` (compromised shaper), `agent/test/harness.test.ts` |
| 3 | **State-gated issuance.** Tokens issue only while the Mission is active; revocation gates issuance and refresh. | `gateDerivation`, grant destruction on revoke | `tracer.test.ts` (suspend/revoke gating) |
| 4 | **Evidence that attributes.** Every governance/enforcement point emits attributable, tamper-evident evidence. | Decision/Execution/Refusal evidence; SCITT feed | `transaction.test.ts`, `transparency/test/transparency.test.ts` |
| 5 | **Per-action runtime enforcement.** A PEP/PDP decision gates every consequential action, with parameter binding and a fresh state source. | PEP → PDP per action; TOCTOU reverify; freshness bounds | `mcp-payments/test/enforcement.test.ts`, `pdp/test/evaluate.test.ts` |
| 6 | **Evidence that joins.** Decision, execution, and audit records join by decision/operation id and reconcile to the side-effect ledger. | reconciliation + feed-driven timeline | `transaction.test.ts` (reconcile), `console-bff/test/console.test.ts` (timeline) |

All six are demonstrated. The transaction-assurance tier (single-use permit,
execution lease, Execution Evidence, reconciliation) covers the
high-consequence classes; the freshness table (D43) sets the per-class bounds.

## 2. The five laws (handbook) → scenarios

| Law | Enforced by | Scenarios / tests |
|---|---|---|
| Durability | record outlives sessions/tokens; signed Status authoritative | 1, 8, 9, 14 |
| Attribution | subject/approver on record; `act` chains + instance id; evidence joins | 1, 11, 13 |
| Narrowing | subset rule, audience-scoped projection, caps, delegation narrows | 6, 7, 12, 13 |
| Termination | state-gated issuance, revocation, completion, freshness bounds, cross-domain lease expiry | 8, 9, 12, 14 |
| Containment | per-action PEP/PDP, parameter binding, single-use permits, per-instance revocation | 2, 3, 4, 13, and the eval scorecard |

## 3. The vendor test

The six questions of `/notes/mission-based-authorization-vendor-test/`, and the
demonstration that settles it (`pnpm demo:vendor-test`): one denied action per
axis, each with a **valid** token.

| Question | Answer in this build |
|---|---|
| Is there an approved-task object with its own lifecycle? | Yes — the Mission Record (M1). |
| Is authority derived from it and right-sized? | Yes — derivation + subset rule (M1). |
| Is every consequential action checked at runtime? | Yes — PEP→PDP per action (M3/M4). |
| Is state freshness enforced with a bound? | Yes — the freshness table, fail-closed (D43). |
| Is there tamper-evident evidence that joins? | Yes — SCITT feed + reconciliation (M10). |
| Can you show a valid-token action denied by state/bounds/parameters/delegation? | Yes — the four-axis demonstration below. |

**Demonstration (`evals/test/vendor-test.test.ts`):** state → `mission_inactive`;
bounds → `constraint_exceeded`; parameters → `parameter_mismatch`; delegation
chain → `instance_revoked`. Every token was structurally valid.

## 4. Containment (eval scorecard, goal 2 empirical arm)

`pnpm evals` on the demo estate: 6 adversarial + 2 legitimate cases, **0
containment breaches, 0 evidence gaps, 0 over-blocking, denial correctness
1.0** — every adversarial case produced zero ledger side effects
(`evals/test/evals.test.ts`).

## 5. Consolidated spec-feedback report (goal 2)

Building the family surfaced eight concrete findings; one is filed upstream.

| # | Category | Spec | Finding / disposition |
|---|---|---|---|
| S-1 | interop/defect | actor-profile × receipts × agent-instance | `act.cnf` semantics undefined/duplicated. **Filed** upstream (actor-profile#4); impl validates PoP against top-level `cnf` only. |
| S-2 | simplification | mission-authzen § context.actor | nested→root-to-leaf transform left to implementers; our `actor-chain` golden vectors are the proposed normative example. |
| S-3 | ambiguity | mission-authzen × AROP | approval-as-input vs token-issuance seam unnamed; resolved in-impl by D42 (AROP subset-only, Expansion separate). |
| S-4 | interop | MCP EMA | young extension; metadata member for the server declaration not pinned. |
| S-5 | simplification | mission-authzen § materialization | reads as write-on-approval; contextual-tuple derivation (our D26) is the more typical strategy for ephemeral authority — propose naming both. |
| S-6 | ambiguity | mission-authzen | doesn't state in one place that consumption tracking is a PEP duty (our D28). One sentence would settle it. |
| S-7 | ambiguity | mora entity-profiles rev 01 | registry names Designated Experts but no formal IANA policy keyword. |
| S-8 | deviation | mission-audit | mandates COSE hash-envelope; impl commits by hash under JWS (O-16). SCITT semantics faithful; COSE is the wire-fidelity swap. |

## Deviations and deferrals of record

- **AROP realigned** to subset-only after review (D42, PR #329) — corrected an
  inline-expansion defect.
- **Materialization** is contextual tuples (D26), diverging from the spec's
  materialization language (S-5).
- **COSE** replaced by JWS in the transparency service (S-8).
- **Deferred** (candidate follow-ons): LLM red-team eval mode (O-31), exhibit
  mode / Appendix B wire captures (O-28), consent evidence (O-11), Signals
  push, harness session binding beyond the resume duty, child delegation,
  metering, mandate, CIBA.

## Bottom line

Both plan goals are met. Goal 1: a running system that satisfies the six
Runtime-Enforced invariants across two trust domains, both AROP completion
modes, discovery, cross-domain, and tamper-evident audit — 119 headless tests,
an eval scorecard with zero containment breaches, and a vendor-test
demonstration that denies a valid token on all four axes. Goal 2: the family
validated by building it, with eight recorded findings and one filed upstream.
