# Cloudflare Agent Access Model, realized on Missions

Cloudflare's Agent Access Model (AAM) names six components plus a grant review
loop. The Mission family already realizes each of the six as a first-class
mechanism, so AAM's "Nightly Reconciliation" story needs no new vocabulary: the
read and reconcile slice is a Mission Template consented once, dispatched at
machine speed, run disconnected, and mediated per action; the one
external-communication step (posting a finance remittance) is human-gated, a
Mission approved directly rather than dispatched; and both kinds of Mission are
ratcheted down on a protected event and read back from the same Activity Log.

The Mission Template draft holds a Dispatch to a prohibited-class rule: a
Dispatch MUST NOT instantiate a Mission bearing an irreversible,
external-commitment, privileged-administration, external-communication, or
cross-domain capability, even when that capability sits inside the consented
Template Ceiling
(`draft-mcguinness-oauth-mission-template.md#prohibited-classes`). Bob's
consent ceiling below still names `payments:remittance.send` (the whole
nightly job's scope, consented once), but every Dispatch that would confer it
is refused `dispatch_prohibited_class`. The Template only ever instantiates the
low-consequence read/reconcile/contain slice at machine speed; the actual
remittance runs under a separate, ordinarily-approved Mission that a human
approved.

The authoritative proof is the end-to-end test, not this document:
`src/services/authorization-server/test/aam-nightly-reconciliation.test.ts`
drives all eight steps against the live stack (real Authorization Server over
HTTP, the OpenFGA-backed PDP, the real payments PEP, the real harness egress
gate, and the console-bff Activity Log join).

## The mapping

| AAM component | Mission realization | Draft anchor | Code anchor |
| --- | --- | --- | --- |
| Agent Identity Broker | Approval-gated Mission issuance, on two paths: the mission-dispatch grant re-issues a clipped, low-consequence instance in one round trip with no human in the loop; a prohibited class (external-commitment among them) is never dispatched and instead requires an ordinary Mission approval, a fresh human decision (`direct` approval_basis). ICA and async-delegation refresh-token families carry either kind of Mission across a disconnected run. | `draft-mcguinness-oauth-mission.md` (issuance), `draft-mcguinness-oauth-mission-issuance-grant.md`, `draft-mcguinness-oauth-mission-continuation.md` (ICA + async-delegation), `draft-mcguinness-oauth-mission-template.md#prohibited-classes` | `src/services/authorization-server/src/adapters/provider.ts` (`/token`, `MISSION_DISPATCH_GRANT_TYPE`), `.../adapters/continuation-grant.ts` (`handleAsyncDelegationExchange`), `.../kernel/delegation-family-store.ts`, `.../kernel/kernel.ts` (`approve`, the `direct` approval_basis) |
| Task-Scoped Access Engine | A stateless PDP evaluating a per-check MissionView (the Authority Set plus the containment delta) over OpenFGA; no mission tuples are stored. | `draft-mcguinness-mission-authzen.md`, `draft-mcguinness-mission-runtime.md` | `src/services/pdp/src/evaluate.ts`, `.../pdp/src/policy-view.ts` |
| Mediation Layer | The mediated harness (the MCP tool channel plus the resource-server PEP) for tool calls, and the egress gate for the otherwise-unmediated network path. | `draft-mcguinness-mission-harness.md` | `src/services/mcp-payments/src/pep.ts`, `src/services/agent/src/mediated-harness.ts`, `.../agent/src/egress-gate.ts`, `.../agent/src/harness-scope.ts` |
| Trust Ratchet | Mission Containment: an authenticated protected event narrows the effective Authority Set deterministically; the PDP then denies the removed action `authority_contained` while everything else still permits. | `draft-mcguinness-oauth-mission-containment.md` | `src/services/authorization-server/src/kernel/kernel.ts` (`contain`, `containOnEvent`), `.../kernel/containment.ts`, `.../adapters/provider.ts` (`/missions/:id/protected-events`), `.../kernel/issuer-evidence.ts` |
| Task Template + capability ceiling | Mission Templates: consent once to a ceiling and a bounded per-instance lifetime, then dispatch many instances, each clipped to the template ceiling and refused `out_of_template_ceiling` past it. A ceiling entry in a prohibited class is consentable but never dispatchable: a Dispatch that would confer it is refused `dispatch_prohibited_class` regardless of ceiling membership. | `@spec draft-mcguinness-oauth-mission-template` (template profile, `#prohibited-classes`), `draft-mcguinness-oauth-mission-approval.md` (consent) | `src/services/authorization-server/src/kernel/template.ts` (`dispatchFromTemplate`), `.../kernel/template-store.ts`, `.../adapters/provider.ts` (`POST /templates`, `handleMissionDispatchGrant`), `src/config/policy.json` (`dispatch_prohibited_actions`) |
| Agent Activity Log | A pure read-model join over the family's evidence: PEP Decision Evidence, egress evidence, issuer ingestion records, Containment Evidence, and Mission lineage, threaded into a per-Mission task-run graph. | `draft-mcguinness-mission-audit.md`, `draft-mcguinness-mission-authzen.md` (Decision Evidence) | `src/services/console-bff/src/activity-log.ts` (`buildActivityLog`), `.../console-bff/src/index.ts` (`ConsoleBff.activityLog`) |
| Grant Review Loop | Not adopted. See below. | `draft-mcguinness-oauth-mission-expansion.md`, `draft-mcguinness-oauth-mission-approval-revision.md`, `draft-mcguinness-oauth-mission-management.md` | (none) |

## The run, step by step

The AAM Nightly Reconciliation walk maps one-to-one onto the eight `it()` steps
in the test.

1. Consent once. `POST /templates` records a read-only reconciliation ceiling
   plus one external-communication capability (`payments:remittance.send`, the
   "post to one finance channel"; the whole nightly job's scope, consented a
   single time), a bounded per-instance lifetime, and the human approver of
   record. The response carries the `template_hash`. Consenting to the ceiling
   is not consent for a Dispatch to ever confer `remittance.send`.
2. Machine-speed dispatch, kept low-consequence. The scheduler redeems the
   mission-dispatch grant at `/token` for a read-only intent. The result is a
   fresh Mission with template lineage, the template's human as approver of
   record, and an Authority Set clipped to `payments:invoice.read` alone. A
   Dispatch of an intent that also names `payments:remittance.send` is refused
   `dispatch_prohibited_class`, even though the capability sits inside the
   consented ceiling; a Dispatch past the ceiling entirely is refused
   `out_of_template_ceiling`, a different reason for a different failure.
3. Disconnected run. The dispatched (read-only) Mission's access token is
   exchanged (`request_refresh_token`) for a rotated, sender-constrained
   refresh-token family whose absolute lifetime is clamped to the Mission
   expiry. A disconnected refresh yields a fresh access token.
4. Per-action mediation. A tool call (`get_invoice`) is permitted through the
   PEP over the live PDP and recorded as Decision Evidence; `send_remittance_email`
   is denied `out_of_authority` on this same Mission, since it was never
   granted; an off-allowlist egress is refused by the egress gate and recorded.
5. The human path. The SAME intent step 2's Dispatch refused is approved
   directly by Bob: an ordinary Mission, a `direct` approval_basis, no template
   lineage. `payments:remittance.send` is genuinely granted only here.
6. Protected event to containment (AAM Baseline to Restricted), targeting the
   human-approved Mission. A trusted SOC source signs a `content.tainted_read`
   event to `/missions/:id/protected-events`. `payments:remittance.send`
   becomes `authority_contained` at the PDP on that Mission, while the
   low-consequence dispatched Mission from step 2 (a different Mission the
   event never named) is untouched.
7. Restore only in a new task. A fresh human approval restores the
   external-communication capability. The contained Mission never regains it
   mid-run.
8. Activity Log. `ConsoleBff.activityLog()` returns two joined task-run graphs:
   the dispatched Mission's read decision and egress refusal (template lineage
   present), and the human-approved Mission's ingestion, its Containment
   Evidence (same event id), and the subsequent `authority_contained` decision
   (no template lineage).

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
