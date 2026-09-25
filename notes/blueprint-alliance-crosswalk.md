# Blueprint Alliance Crosswalk

A decision aid for readers of the Blueprint Alliance reference
architecture. Every row answers one question: what does Mission-Bound
Authorization contribute to this Blueprint component, under which
assumptions, and what must still be supplied elsewhere? The note
overlays the Blueprint onto the family's verb spine and does not
regroup the family. Nothing here is normative. Sources are pinned in
[Evidence](#evidence).

## Thesis

The Blueprint identifies the governance control points. Mission-Bound
Authorization supplies a specified record of approved work that
connects approval, bounded authority, delegation, lifecycle, and
evidence across those points. It complements agent identity and
infrastructure controls and replaces neither.

In the family's terms, a governed action rests on three facts: the
identity fact (who is acting), the authority fact (what it holds), and
the work fact (whether approved work still justifies the action). The
Blueprint's Pillar 1 owns the identity fact. The Mission is the work
fact that Pillars 2 through 4 act on.

## Reading This Note

The four coverage questions map onto the family's existing axes:

- **Specified.** Spec maturity, from `family-manifest.json`. Every
  named binding and companion is an editor's copy at experimental
  maturity, except Substrate (candidate) and Evidence Envelope
  (sketch); the Architecture and Intent Shaping are guides. The OAuth
  binding is the one published Internet-Draft. Maturity labels are
  document design maturity, never deployment history. `DRAFTS.md` is
  authoritative.
- **Implemented and tested.** Only within the reference
  implementation's scope: `src/`, one deployment, a single-writer
  kernel (#250). The [appendix](#implementation-evidence) gives each
  cited document's ledger rows and test files. A test is not a
  conformance, interoperability, or production claim. No production
  Mission deployment is known today on any binding.
- **Proposed.** Appears only in [Engagement
  Proposals](#engagement-proposals).
- **External responsibility.** The "Deployment dependency and
  residual" column: what a row assumes, and what is supplied
  elsewhere.

"p. N" is the whitepaper PDF page; the printed header number is N - 1.

## Where the Blueprint Says "Aspirational"

| Blueprint text | Mission contribution | Evidence and open questions |
|---|---|---|
| "While task-scoped dynamic grants represent the aspirational goal, practical implementations pair short-lived task grants with resilient baseline permissions" (p. 6) | The Mission is the approved-work record grants derive from. The short mission ramp (Architecture, Entry Ramps) is a short-lived task grant with a record behind it | OAuth binding tested (appendix) |
| "pairing static permission ceilings with dynamic real-time scoping" (p. 6) | Template: "A human consents once to a task template, a ceiling of resources, actions, and constraints ... Each dispatch then instantiates an ordinary Mission from the template by policy, at machine speed" | Specified only. Bounded standing approval for useful unattended work is an open design question (#813) |
| "end-to-end multi-hop delegation remains an aspirational target given today's tooling" (p. 6) | In-Mission delegation (`act` chain), Child Delegation, Offline Attenuation, Cross-Organizational Delegation, Continuation | Child Delegation has tests but 14 ledger rows todo; Cross-Organizational Delegation 9 rows tested |
| "Purpose binding: Enforcing strict linkage between the delegating user, agent identity, approved workflow, and requested task" (p. 20) | The Mission record, carried as the `mission` claim on Mission-bound credentials or joined at the PDP under standalone MAS | OAuth binding and MAS tested |
| "the system that detects risk publishes a Kill Switch event, the subscribing systems act, and the outcome is published back as a confirmation signal" (p. 23) | Signals and Status carry the first two legs | The confirmation leg is Proposal 2 |
| "It also publishes positive execution context, structural confirmation of what's already known to be valid, not just alerts" (p. 25) | Status and Signals are a positive state source: a Mission is `active` at `version` N | Tested |
| "reinstatement is deliberate, documented, and traceable, rather than an automatic reversal" (p. 24) | Containment removes capability; restoration only through a successor Mission under Expansion, with disclosed history | Containment has tests and no ledger rows; Expansion has tests and 3 ledger rows todo |

## The Five Board Questions

| Blueprint question (p. 5) | Mission contribution |
|---|---|
| 1. Where are our AI agents, and who owns them? | None. Identity fact: Governed Agent Profiles, workload identity |
| 2. How do we restrict what agents can execute and stay on task? | Propose, Approve and Record, Enforce Each Action |
| 3. Can we audit and explain autonomous decision-making after the fact? | Prove: Runtime Evidence, Audit, Consent Evidence, Mandate |
| 4. What is our data exposure and third-party risk across the agent supply chain? | Partial: Work Products for propagation provenance; Cross-Domain Projection and Cross-Organizational Delegation for third-party authority. Supply-chain scanning is external |
| 5. Do we have a verified kill switch and rollback plan if an agent goes rogue? | Govern: Status, Signals, Containment, within published bounds (Architecture, Composed Kill-Switch Reality). Completed actions are not undone |

## Component Crosswalk

### Pillar 1: Where are my agents?

| Blueprint component | Verb | Mission contribution | Deployment dependency and residual |
|---|---|---|---|
| Agent Directory, agent classes, identity substrate (p. 14-15) | (identity fact) | None: the Mission names the actor it binds and registers none | Supplied elsewhere: registration, ownership, attestation (Governed Agent Profiles, workload identity) |
| Sub-agents "governed by inherited session scopes rather than individual directory registration" (p. 14) | Delegate | Inline sub-agent: a delegated token under the same Mission (in-Mission delegation). Work that outlives the delegator, waits on a queue, or needs its own revocation and audit: a Child Mission inside the parent's Authority Set | Assumes: the sub-agent authenticates as its own actor or client; no directory entry does not mean no authenticated identity. Supplied elsewhere: the isolated execution boundary the Blueprint requires for sub-agents |
| Orchestrators: "the directory must track delegation chains and spawn relationships" (p. 14) | Delegate, Prove | Authority ancestry: the `act` chain, Child Mission parent linkage, Audit | Authority ancestry is not spawn history. Supplied elsewhere: the orchestration hierarchy |
| A2A across organizations, using "token-exchange standards" to preserve delegation chains (p. 15) | Delegate, Project, Continue | Cross-Organizational Delegation, Cross-Domain Projection (XAA via ID-JAG), Continuation | Assumes: a trust relationship between the domains; the relying domain enforces locally. Residual: a redeemed projection runs to its own lifetime |
| Governed execution path as a detection surface (p. 12) | Enforce Each Action | A Mission-aware PEP sees an action that lacks the Mission context its path requires: a Mission-bound credential under the OAuth binding, or a joinable Mission reference under standalone MAS, whose ordinary tokens carry no `mission` claim by design | Assumes: PEP placement covers the path. Supplied elsewhere: agents that never cross a PEP |
| Discovery, shadow AI, AIASPM (p. 9-13) | | None | Supplied elsewhere: all |

### Pillar 2: What can they do?

| Blueprint component | Verb | Mission contribution | Deployment dependency and residual |
|---|---|---|---|
| Fine-grained access (p. 16) | Approve and Record | Authority Set in RAR syntax; issuance bounded by the subset rule | Assumes: the resource understands the constraints, or a mandatory gateway enforces them; Scope Projection refuses an unsafe mapping onto legacy scopes. Supplied elsewhere: data classification |
| Relationship-based access (p. 16) | Delegate | `act` chain and Child Mission parent linkage as policy input | Supplied elsewhere: the ReBAC engine |
| Intent-based: "Inspecting a plan is achievable with current tooling; treating a literal user prompt as the sole trigger is aspirational" (p. 16) | Propose | Intent Shaping: the proposal is untrusted input; `proposal_hash` and `authority_hash` keep what was asked apart from what was granted | Assumes: issuer derivation policy bounds authority. Residual: prompt injection is constrained, not prevented. Supplied elsewhere: semantic prompt analysis |
| Time-bound, paired "with the anomaly detection ... rather than treating expiry alone as the safeguard" (p. 17) | Approve and Record, Govern | `expires_at`; the short mission ramp; Status or Signals as the state source | Residual: issued credentials run to `exp` on paths without runtime enforcement |
| Cross-app access (p. 17) | Project | Cross-Domain Projection (XAA via ID-JAG) | Assumes: IdP-mediated trust between the apps. Residual: a redeemed grant runs to its own lifetime |
| Delegation and inheritance: "intersection ... cap the breadth and depth of delegation" (p. 17) | Delegate | Three controls on three dimensions: in-Mission delegation (`allowed_delegates`, `max_depth`); Child Delegation (subset rule, `children.max_child_depth` for generations, `max_children` for fan-out); Offline Attenuation (`del_max_depth` for attenuation hops) | Assumes: current resource policy is conjoined with Mission authority at the PDP, so the Mission bounds from above and grants nothing the delegate lacks (#828) |
| Guardrails (p. 17) | Enforce Each Action | High-consequence classes stay on a fresh human decision; the runtime contract fails closed | Supplied elsewhere: output safety filters |
| Contingent Review above a threshold (p. 17) | Approve and Record | Deferred Approval; Transaction Authorization (approval bound to the concrete action, as decision input); Progressive | Assumes: an approval surface and approver authentication. Supplied elsewhere: threshold values |
| Access requests: "agent-initiated requests must be strictly evaluated against static permission ceilings" (p. 17) | Govern | Expansion: widening needs a fresh approval and a successor Mission. Template ceilings bound policy dispatch | Assumes: governance policy permits widening. Template dispatch is open (#813) |
| Separation of Duties: "both generating and approving financial transactions" (p. 17) | Approve and Record | Structural: the agent proposes, the Approver at the control point decides, and no proposal is authoritative. Approval Governance Record evaluates threshold, veto, and separation-of-duty rules; Metering defines an `exclusive` control | Supplied elsewhere: the SoD rule set across an agent's standing entitlements |
| Access reviews, JML (p. 17) | Govern | Status per Mission; Management for fleet enumeration and bulk lifecycle | Supplied elsewhere: identity lifecycle and ownership changes |

### Pillar 3: What are they doing?

| Blueprint component | Verb | Mission contribution | Deployment dependency and residual |
|---|---|---|---|
| Gateways as PEPs; the agent gateway governs "agent actions, not just access" (p. 18-19) | Enforce Each Action | Runtime contract, AuthZEN binding, Capability Binding; the gateway evaluates work state from the Mission context its path is configured for | Assumes: trusted, complete PEP placement on consequential paths, and a freshness source with a published bound. Residual: a gateway cannot manufacture resource-side atomicity. Supplied elsewhere: traffic inspection, credential brokering |
| Purpose binding; "Plan vs. action evaluation" (p. 20) | Approve and Record, Enforce Each Action | The Mission record; runtime evaluation against the Authority Set | Residual: enforcement is only as precise as the Authority Set's vocabulary, so a deployment can faithfully enforce the wrong envelope. Supplied elsewhere: behavioral drift detection |
| Context-aware enforcement, PEP duties: allow, deny, authentication step-up (p. 20) | Enforce Each Action | The runtime decision; AuthZEN obligations for mandatory PEP work under it. An obligation "confers no authority, has no approver, and creates no governance state" | Supplied elsewhere: redaction engines |
| Context-aware enforcement, governance changes: step-up approval, scope reduction, suspension, containment (p. 20) | Approve and Record, Govern | Fresh approval: AuthZEN governance lane (ARAP), Deferred Approval, Transaction Authorization. Authority change: Expansion. Suspension: Status lifecycle. Scope reduction without revocation: Containment | Assumes: an approver and a governance policy |
| Traceable decision evidence (p. 20) | Prove | Runtime Evidence (Mission Receipt), signed PDP decisions, Audit; Evidence Envelope (sketch) | Assumes: evidence originates at the enforcement boundary. Supplied elsewhere: retention infrastructure |
| Workflow-in-the-loop (p. 20) | Approve and Record | Deferred Approval; the AuthZEN governance lane | Supplied elsewhere: the workflow engine |
| Tracing (p. 20) | Prove | The issuer-qualified Mission id as the join key across traces | Supplied elsewhere: trace collection |
| Cost and performance (p. 20) | Govern, Enforce Each Action | Metering: cumulative bounds (`max_budget`, `max_calls`, `max_duration`, `max_egress_volume`) enforced by atomic check-and-decrement, reserve and commit, leases, and settlement; a deployment that does not meter a bound refuses rather than ignores it | Assumes: a metering-capable runtime. Specified only; implementation is #816. Supplied elsewhere: latency monitoring |
| Purpose-aware data security (p. 22) | Prove, Delegate | Work Products: provenance; information may propagate, authority may not | Supplied elsewhere: classification, DLP, inference detection |
| Sandboxing, endpoint isolation, prompt-injection scanning, anomaly detection (p. 19-20) | | None; these produce the events that trigger Containment | Supplied elsewhere: all |

### Pillar 4: How do I respond?

| Blueprint component | Verb | Mission contribution | Deployment dependency and residual |
|---|---|---|---|
| Kill Switch event; subscribing systems act (p. 23) | Govern | Signals (SSF lifecycle-change SET) and Status | Assumes: consumers subscribe or poll within a published staleness bound |
| Confirmation signal published back (p. 23) | Govern, Prove | None today | Proposal 2 |
| Token and session revocation (p. 23) | Govern | Mission revocation stops new issuance and derivation at the issuer. A Runtime-Enforced class denies once the revoked state reaches its gate | Residual: worst case, the published staleness bound plus the permit validity window plus the class's execution bound; ungated paths run to credential lifetime (Architecture, Composed Kill-Switch Reality) |
| Continuous authorization: "downgrades permissions the exact moment a risk posture changes" (p. 23) | Govern | Containment (monotonic narrowing); Signals `authority_changed` | Residual: narrowing takes effect at a gate within the same published bounds. Supplied elsewhere: risk scoring; the containment draft keeps event-to-policy mapping deployment-defined |
| Throttling and rate limiting (p. 24) | Govern, Enforce Each Action | Metering's cumulative bounds | Specified only (#816). Supplied elsewhere: request-rate throttling |
| Process, network, cloud, and platform termination (p. 24) | Run and Wind Down | Partial: the Harness stops on a non-active Mission; Orchestration unwinds | Supplied elsewhere: infrastructure kill, forensic preservation |
| Re-attestation (p. 24) | (identity fact) | None | Supplied elsewhere: workload attestation |
| Staged re-enrollment, "read-only before write" (p. 24) | Govern | Restoration through a successor Mission under Expansion; a narrower successor first | Assumes: a fresh approval |
| Root-cause sign-off (p. 24) | Approve and Record | The successor's approval, with disclosed history | Supplied elsewhere: the incident workflow and its findings |
| Audit trail closure (p. 24) | Prove | Audit; the successor's `predecessor` lineage | The enforcement-confirmation leg is Proposal 2 |

### Cross-Cutting Foundation

| Blueprint component | Verb | Mission contribution | Deployment dependency and residual |
|---|---|---|---|
| Execution context and risk signals over SSF/CAEP (p. 25) | Govern | Signals: the Mission Issuer is an SSF transmitter, so a deployment running a CAEP stream adds one event type | Supplied elsewhere: risk correlation. The event type's home is Proposal 4 |
| Telemetry over OCSF (p. 25) | Prove | None today | Proposal 1 |
| "Tamper-resistance telemetry origin: Capturing telemetry at the execution boundary rather than relying on self-reported agent logs" (p. 25) | Prove | Agent-isolated evidence emission (a runtime condition); Runtime Evidence | Assumes: an emission path the agent cannot write to |
| HTTP Message Signatures, RFC 9421 (p. 29) | (binding) | Standalone MAS: a deployed signature covers `Mission-Reference`. AAuth Management: the AAuth HTTP Message Signatures profile | |

### Operationalizing

| Blueprint component | Family construct | Evidence and residual |
|---|---|---|
| Risk tiering; "Isolation depth scaled to risk tier" (p. 27) | Mission Assurance Levels, plus the Assurance Claims axis | The levels are adoption bundles, never a conformance class; a relying party compares claims, not level names. Isolation depth is external |
| Current-state assessment and phased rollout (p. 26) | Entry Ramps by Estate | Informative guidance in the Architecture |
| Audit-ready evidence packages (p. 28) | Audit; Consent Evidence; Mandate | Audit has tests; Consent Evidence and Mandate are specified only. Supplied elsewhere: examiner-specific packaging |
| "Business-impact scoring" thresholds for human-in-the-loop approval (p. 27) | High-consequence classes; Transaction Authorization | Transaction Authorization tested. Supplied elsewhere: threshold values |

## Where the Mission Enters the Rollout

The Blueprint's "Best Practices for Getting Started" (p. 32) orders
the work. The Mission enters at step 4:

| Blueprint step | Mission position |
|---|---|
| 1. Stand up unified logging and telemetry first | The issuer-qualified Mission id as a join key (Proposal 1) |
| 2. Start with discovery, not policy | External |
| 3. Register before you restrict | External (identity fact) |
| 4. Layer authorization: FGA and ReBAC come "before intent-based authorization can correctly scope down agent permissions" | Baseline Issuance: the Mission is the task layer over FGA and ReBAC. Lowest-cost entry: the short mission in records mode |
| 5. Instrument runtime before you automate the response | Runtime-Enforced: PEP/PDP coverage per class and its Enforcement Scope Statement |
| 6. Pressure-test the kill switch before you need it | The Composed Kill-Switch Reality table is the test plan: what stops at commit, what runs to its own bound |
| 7. Treat governance as continuous, not a project | Status, Signals, Containment, Expansion |

## Worked Flow: The Refund

Proposed composite, built on the whitepaper's scenario (p. 30). No
single runnable demonstration covers it; each step names the nearest
scenario in `src/DEMO.md` or the test that exercises it.

| Step | Artifact that connects it | Nearest evidence | Where the family stops |
|---|---|---|---|
| 1. Approved task: a support agent's Mission to resolve one ticket, with read authority over the customer platform and a refund class marked high-consequence and bounded by `max_amount` | Mission record: `intent_hash`, `authority_hash`, Approver | Scenario 1 (issuance) | Agent identity and client registration |
| 2. Lookup of the customer record | Mission-bound token; runtime decision on the read | Scenario 2 (in-authority read) | The platform's own current policy, conjoined at the PDP (#828) |
| 3. Refund attempt needs action-bound approval | Transaction Authorization: a challenge bound to the order and amount; the approval is decision input, never a bearer credential. If the refund class is outside the Authority Set: a requestable denial, then an Expansion successor | Scenarios 5 (ARAP) and 7 (transaction challenge); `arop.test.ts` for Expansion | Approver authentication; the threshold value |
| 4. Payment executes | Single-use permit; execution evidence (Mission Receipt) | Scenario 4 (wire transfer: permit, lease, evidence, reconciliation) | "Executing the refund within an ephemeral runtime" is sandboxing; resource-side atomicity belongs to the connector |
| 5. Risk signal: monitoring flags an anomaly | A protected event under the containment policy | None; event-to-policy mapping is deployment-defined | Anomaly detection, correlation, and delivery of the signal to the issuer |
| 6. Containment: refund capability removed while the Mission stays `active` | Contain transition, `containment_version`, Signals `authority_changed` | `containment.test.ts`, `containment-pdp-e2e.test.ts` (tests, not a demo scenario). Full revocation instead: scenario 8 (denied within bound) | Ungated paths run to credential lifetime |
| 7. Enforcement confirmation | None | Proposal 2 | |
| 8. Recovery and closure | A successor Mission with disclosed history; the audit log | `arop.test.ts`; scenario 11 (transparent audit) | Root-cause analysis and the incident record |

## Engagement Proposals

In priority order. Each supplies an audience for work already ranked
in #842 and does not reorder it.

1. **An informative OCSF mapping** (Audit or Runtime Evidence). OCSF
   1.9.0's AI Operation profile carries a `delegation` object: "A
   durable authorization context that a principal issues to a
   delegate", with `uid` required and generated "by a trusted issuing
   authority ... rather than self-asserted by the delegate", plus
   `issuer_uid`, `created_time`, and `parent_uid`. The OCSF text states
   that this authority graph "is distinct from any agent instantiation
   or orchestration hierarchy". Lifecycle state, `expires_at`, and
   `authority_hash` have no standardized delegation members and ride
   OCSF's `unmapped` attribute; standardized members would be an
   upstream OCSF proposal. Acceptance: an OCSF consumer joins Mission
   events by `issuer_uid` with `uid`, never `uid` alone; reconstructs
   authority ancestry from `parent_uid` without spawn history; and
   finds the remaining members under `unmapped`.
2. **A receiver-applied enforcement confirmation**, scoped (Signals or
   Runtime Evidence). The record: receiver R applied lifecycle version
   N for Mission M at time T, for classes C under its Enforcement Scope
   Statement. It never asserts that everything stopped. The whitepaper's
   anomaly composite already asks for "a closed-loop confirmation
   record" (p. 31). Acceptance: after a contain or revoke, the issuer
   can list, per class, which receivers confirmed version N and which
   have not.
3. **One cross-vendor demonstration** of the refund flow above.
   Acceptance, testable today: a non-family AuthZEN PDP or SSF
   receiver denies the contained or revoked action within a bound it
   states before the test (staleness plus permit plus execution).
   Additive once Proposals 1 and 2 land: it emits the Proposal 2
   confirmation, and its OCSF events join to the issuer's by
   issuer-qualified id.

Lower priority: the lifecycle-change event type moves from
`https://schemas.karlmcguinness.com/mission/lifecycle-change` to an
OpenID SSF Working Group track (Proposal 4); the multi-agent CRM
composite (p. 30) and the anomaly composite (p. 31) get the same
treatment as the refund.

## Not This Family

Agent discovery, shadow AI detection, AIASPM, agent registration and
attestation, sandboxing and isolation, network quarantine,
prompt-injection scanning, DLP and output filtering, anomaly
detection, and the telemetry pipeline. The Mission supplies these the
task, authority, and lifecycle context they lack, and consumes their
signals as lifecycle triggers.

## Evidence

**Blueprint Alliance**, retrieved 2026-09-25. The PDFs carry no
version identifier.

| Artifact | URL | SHA-256 | ETag |
|---|---|---|---|
| Whitepaper, "Governing Agentic Execution" (32 pages) | <https://blueprintalliance.ai/blueprint-alliance-whitepaper.pdf> | `fbc4cebef9abd9d909d0009a6e7d2bb5129f066c4e9d71ea2e426409f77f63e1` | `945d3a88fc6aca67b0fe761efe5e32d8` |
| Reference architecture poster (1 page) | <https://blueprintalliance.ai/blueprint-alliance-architecture.pdf> | `77802221ccb85174aecd0bdf638c86ecb649aab6ecbcda9d9babaac4b440e243` | `f982d7321227abb751b18ce2e3691900` |

**OCSF**, release tag `1.9.0`, commit
`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`:

| File | SHA-256 |
|---|---|
| [`objects/delegation.json`](https://raw.githubusercontent.com/ocsf/ocsf-schema/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/objects/delegation.json) | `fbd8bbdb5abcffe6270b0845faef39bf117ea64247033ad9a074960cf505dae5` |
| [`profiles/ai_operation.json`](https://raw.githubusercontent.com/ocsf/ocsf-schema/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/profiles/ai_operation.json) | `a5cee2b4bda486c5b9ba260d056a6686827d3c515fd03135f1fa56a4e137c876` |
| [`events/base_event.json`](https://raw.githubusercontent.com/ocsf/ocsf-schema/856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba/events/base_event.json) (`unmapped`) | `53782cf02a503d7c5559fa9bedb7d60d742b0fa68c46aa958ab9481cd8a53095` |

**This family**, at `origin/main` `85a5ed2d`. The README section
"Work, identity, and authority" exists only on branch
`readme-work-identity-authority` (`386cf24e`), one commit ahead of
main.

### Implementation Evidence

Transcribed at `85a5ed2d` from `family-manifest.json` (spec maturity),
`conformance-manifest.json` (ledger rows: tested / partial / todo),
`src/SPEC_VERSIONS.md` (implementation rows and their tests), and
`src/DEMO.md` (scenario numbers). A ledger `tested` row carries its
own test file (the ledger checker refuses one without), so "no row"
in the tracker column means only that `src/SPEC_VERSIONS.md` has no
row for the document. "Not inventoried" means the ledger has no rows
for the document, which is not evidence either way.

| Document | Spec maturity | Ledger | Tracker row | Demo |
|---|---|---|---|---|
| OAuth binding | experimental; published I-D | 38 / 8 / 31 | yes | 1, 2, 8, 9 |
| Substrate | candidate | 10 / 6 / 72 | yes | |
| Mission Authority Server | experimental | 13 / 0 / 13 | no row | |
| Status | experimental | 4 / 0 / 2 | yes | 8, 10 |
| Signals | experimental | 5 / 1 / 1 | yes | |
| Management | experimental | not inventoried | partial | |
| Containment | experimental | not inventoried | yes (`containment.test.ts`, `containment-pdp-e2e.test.ts`, named in the tracker's notes, no table row) | |
| Expansion | experimental | 0 / 0 / 3 | yes | |
| Child Delegation | experimental | 0 / 0 / 14 | yes | |
| Offline Attenuation | experimental | not inventoried | yes | |
| Cross-Organizational Delegation | experimental | 9 / 0 / 0 | yes | |
| Cross-Domain Projection | experimental | 4 / 2 / 2 | yes | 12 |
| Continuation | experimental | not inventoried | no row for this draft (the external continuation-assertion and async-delegation drafts have tests) | |
| Template | experimental | 0 / 1 / 2 | no row (#813) | |
| Progressive | experimental | 0 / 0 / 2 | no row | |
| Deferred Approval | experimental | not inventoried | no row for this draft (DTR and AROP have tests) | 6 |
| Approval Governance Record | experimental | 7 / 1 / 7 | no row | |
| Transaction Authorization | experimental | 21 / 6 / 8 | yes | 7 |
| Runtime | experimental | 37 / 22 / 90 | yes | 2, 3, 4, 8 |
| AuthZEN binding | experimental | 15 / 6 / 66 | yes | 5 |
| Capability Binding | experimental | 8 / 1 / 0 | yes | |
| Runtime Evidence | experimental | 45 / 11 / 38 | yes | 4 |
| Evidence Envelope | sketch | 0 / 0 / 23 | no row | |
| Audit | experimental | not inventoried | yes | 11 |
| Consent Evidence | experimental | not inventoried | no row | |
| Mandate | experimental | not inventoried | no row | |
| Metering | experimental | not inventoried | no row (#816) | |
| Work Products | experimental | not inventoried | yes | |
| Harness | experimental | not inventoried | partial | 14 |
| Orchestration | experimental | 2 / 3 / 0 | yes | |
| Resource Access | experimental | 0 / 0 / 13 | no row | |
| Intent Shaping | guide | not applicable | yes | |
| AAuth Management | experimental | not inventoried | no row | |
