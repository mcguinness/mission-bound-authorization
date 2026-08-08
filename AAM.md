# Cloudflare Agent Access Model, realized on Missions

Cloudflare's Agent Access Model (AAM) names six components plus a grant review
loop. The Mission family already realizes each of the six as a first-class
mechanism, so AAM's "Nightly Reconciliation" story needs no new vocabulary: it
is a Mission Template consented once, dispatched at machine speed, run
disconnected, mediated per action, ratcheted down on a protected event, and
read back from the Activity Log.

The authoritative proof is the end-to-end test, not this document:
`src/services/authorization-server/test/aam-nightly-reconciliation.test.ts`
drives all seven steps against the live stack (real Authorization Server over
HTTP, the OpenFGA-backed PDP, the real payments PEP, the real harness egress
gate, and the console-bff Activity Log join).

## The mapping

| AAM component | Mission realization | Draft anchor | Code anchor |
| --- | --- | --- | --- |
| Agent Identity Broker | Approval-gated Mission issuance; the mission-dispatch grant re-issues a clipped instance in one round trip; ICA and async-delegation refresh-token families carry a Mission across a disconnected run. | `draft-mcguinness-oauth-mission.md` (issuance), `draft-mcguinness-oauth-mission-issuance-grant.md`, `draft-mcguinness-oauth-mission-continuation.md` (ICA + async-delegation) | `src/services/authorization-server/src/adapters/provider.ts` (`/token`, `MISSION_DISPATCH_GRANT_TYPE`), `.../adapters/continuation-grant.ts` (`handleAsyncDelegationExchange`), `.../kernel/delegation-family-store.ts` |
| Task-Scoped Access Engine | A stateless PDP evaluating a per-check MissionView (the Authority Set plus the containment delta) over OpenFGA; no mission tuples are stored. | `draft-mcguinness-mission-authzen.md`, `draft-mcguinness-mission-runtime.md` | `src/services/pdp/src/evaluate.ts`, `.../pdp/src/policy-view.ts` |
| Mediation Layer | The mediated harness (the MCP tool channel plus the resource-server PEP) for tool calls, and the egress gate for the otherwise-unmediated network path. | `draft-mcguinness-mission-harness.md` | `src/services/mcp-payments/src/pep.ts`, `src/services/agent/src/mediated-harness.ts`, `.../agent/src/egress-gate.ts`, `.../agent/src/harness-scope.ts` |
| Trust Ratchet | Mission Containment: an authenticated protected event narrows the effective Authority Set deterministically; the PDP then denies the removed action `authority_contained` while everything else still permits. | `draft-mcguinness-oauth-mission-containment.md` | `src/services/authorization-server/src/kernel/kernel.ts` (`contain`, `containOnEvent`), `.../kernel/containment.ts`, `.../adapters/provider.ts` (`/missions/:id/protected-events`), `.../kernel/issuer-evidence.ts` |
| Task Template + capability ceiling | Mission Templates: consent once to a ceiling and a bounded per-instance lifetime, then dispatch many instances, each clipped to the template ceiling and refused `out_of_template_ceiling` past it. | `@spec draft-mcguinness-oauth-mission-template` (template profile), `draft-mcguinness-oauth-mission-approval.md` (consent) | `src/services/authorization-server/src/kernel/template.ts` (`dispatchFromTemplate`), `.../kernel/template-store.ts`, `.../adapters/provider.ts` (`POST /templates`, `handleMissionDispatchGrant`) |
| Agent Activity Log | A pure read-model join over the family's evidence: PEP Decision Evidence, egress evidence, issuer ingestion records, Containment Evidence, and Mission lineage, threaded into a per-Mission task-run graph. | `draft-mcguinness-mission-audit.md`, `draft-mcguinness-mission-authzen.md` (Decision Evidence) | `src/services/console-bff/src/activity-log.ts` (`buildActivityLog`), `.../console-bff/src/index.ts` (`ConsoleBff.activityLog`) |
| Grant Review Loop | Not adopted. See below. | `draft-mcguinness-oauth-mission-expansion.md`, `draft-mcguinness-oauth-mission-approval-revision.md`, `draft-mcguinness-oauth-mission-management.md` | (none) |

## The run, step by step

The AAM Nightly Reconciliation walk maps one-to-one onto the seven `it()` steps
in the test.

1. Consent once. `POST /templates` records a read-only reconciliation ceiling
   plus one external-communication capability (`payments:remittance.send`, the
   "post to one finance channel"), a bounded per-instance lifetime, and the
   human approver of record. The response carries the `template_hash`.
2. Machine-speed dispatch. The scheduler redeems the mission-dispatch grant at
   `/token`. The result is a fresh Mission with template lineage, the template's
   human as approver of record, and an Authority Set equal to the
   template-clipped effective set. A dispatch past the ceiling is refused
   `out_of_template_ceiling`.
3. Disconnected run. The dispatched Mission's access token is exchanged
   (`request_refresh_token`) for a rotated, sender-constrained refresh-token
   family whose absolute lifetime is clamped to the Mission expiry. A
   disconnected refresh yields a fresh access token.
4. Per-action mediation. A tool call (`get_invoice`) is permitted through the
   PEP over the live PDP and recorded as Decision Evidence; an off-allowlist
   egress is refused by the egress gate and recorded.
5. Protected event to containment (AAM Baseline to Restricted). A trusted SOC
   source signs a `content.tainted_read` event to
   `/missions/:id/protected-events`. `payments:remittance.send` becomes
   `authority_contained` at the PDP while the invoice read stays permitted.
6. Restore only in a new task. A fresh dispatch from the same Template restores
   the external-communication capability. The contained Mission never regains it
   mid-run.
7. Activity Log. `ConsoleBff.activityLog()` returns the joined task-run graph:
   the ingestion, its Containment Evidence (same event id), and the subsequent
   `authority_contained` decision appear in order, alongside the egress refusal,
   all threaded under the dispatched Mission.

## Why the Grant Review Loop is not adopted

AAM's grant review loop is a periodic human re-approval of standing grants.
Missions are not standing grants, so the loop has nothing to stand over. Consent
is captured once at the Template and re-checked against the ceiling at every
dispatch; a Mission is lifetime-bounded, so reliance expires on its own rather
than persisting until a review revokes it; drift during a run is handled by
Containment (the Trust Ratchet), not by a scheduled review; and a genuine change
of capability goes through Expansion or Approval Revision, which is a fresh
approval, not a review cycle. The Activity Log already gives a reviewer the
joined task-run graph on demand. A standing review loop would duplicate the
expansion, containment, and audit surfaces the family already carries.

## Honesty boundaries

These are stated plainly because the mapping is only as strong as what it does
not claim.

- In-process egress makes no containment claim. The reference egress gate runs
  inside the agent process (`transport: "in_memory"`), so its scope statement
  reports `containment_claim: "none"`: a compromised agent can bypass an
  in-process gate. Its value is an honest allowlist and an evidence trail, not
  containment. A deployment states a stronger claim only when the egress
  boundary sits outside the agent's process.
- Authenticated does not mean honest. Containment fires on a signed protected
  event from a trusted source, verified against the source identity rather than
  the transport origin, and the issuer narrows authority deterministically from
  it. The issuer does not, and cannot, prove that the agent reported the tainted
  read honestly. Honest self-reporting is never assumed.
- The PEP and PDP are the backstop. Because neither an in-process gate nor
  honest self-reporting can be trusted against a compromised agent, enforcement
  rests on the PEP mediating every tool call against the PDP, which reads the
  issuer-narrowed effective authority. A contained capability is denied at the
  resource server no matter what the agent attempts.
