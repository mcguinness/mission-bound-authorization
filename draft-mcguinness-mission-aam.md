---
title: "Mission-Bound Authorization for the Agent Access Model"
abbrev: "Mission AAM"
category: exp

docname: draft-mcguinness-mission-aam-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - agent access model
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aam.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

informative:
  AAM:
    title: "The Agent Access Model"
    target: https://blog.cloudflare.com/the-agent-access-model/
    author:
      -
        org: Cloudflare
    date: 2026
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval-revision:
    title: "Mission Approval Revision for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval-revision.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-management:
    title: "Mission Management for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-management.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The Agent Access Model names six components for securing task-scoped
agents: an agent identity broker, a task-scoped access engine, a
mediation layer, a trust ratchet, task templates with capability
ceilings, and an agent activity log, plus a grant review loop as a
supporting system. This document maps each component onto
Mission-Bound Authorization: every component is realized by an
existing mechanism of the family's OAuth lane, so the model's
reference scenario runs end to end in Mission vocabulary with no new
protocol surface.
The mapping also states what it deliberately does not adopt (the
grant review loop, which has no standing grants to stand over) and
the honesty boundaries any deployment of it inherits.

--- middle

# Introduction

The Agent Access Model ({{AAM}}, "AAM") is an architecture for
securing task-scoped agents through strict identity brokering,
continuous mediation, and stateful trust. It names four active
controls on the request path (an Agent Identity Broker, a
Task-Scoped Access Engine, a Mediation Layer, and a Trust Ratchet),
two structuring surfaces (task templates with capability ceilings,
and an Agent Activity Log), and one supporting process (a Grant
Review Loop).

The Mission model's OAuth binding and its companions
({{I-D.draft-mcguinness-oauth-mission}}, with the companions cited
throughout; the family map is
{{I-D.draft-mcguinness-mission-architecture}}) realize each of the
six components as a first-class mechanism already defined. The
mapping is expressed on the OAuth lane, as the Conformance section
scopes precisely; a peer binding maps only the components its
declared capabilities and companions support, realized and omitted
components named per that section's rule. This document is that mapping, stated
in both vocabularies: which Mission mechanism realizes each AAM
component, how the model's reference scenario (a nightly
reconciliation job with one human-gated external communication) runs
end to end on Missions, why the Grant Review Loop is deliberately
not adopted, and which claims the mapping refuses to make.

This document defines no wire protocol, no new Mission mechanism,
and no binding; it is not a Mission Substrate binding and carries no
Mission Substrate Statement. Each mechanism's own document governs
its conformance. The contribution is the correspondence, so that a
deployment planning against AAM's component list can name the
Mission surface that realizes each entry and the documents whose
conformance targets it is thereby claiming.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses Mission, Mission Intent, Authority Set, Mission
Issuer, Approver, and `approval_basis` as the issuance profile
defines them ({{I-D.draft-mcguinness-oauth-mission}}); Template
Ceiling, Dispatch, and the prohibited-class rule as the template
companion defines them
({{I-D.draft-mcguinness-oauth-mission-template}}); and protected
event, effective Authority Set, and Containment Evidence as the
containment companion defines them
({{I-D.draft-mcguinness-oauth-mission-containment}}). AAM component
names are capitalized as {{AAM}} presents them.

# The Component Mapping {#mapping}

| AAM component | Mission realization | Governing documents |
| --- | --- | --- |
| Agent Identity Broker | Approval-gated Mission issuance, on two paths: machine-speed Dispatch of a clipped, low-consequence instance from a consented Template, or an ordinary human-approved Mission (`direct` approval basis) for everything a Dispatch is prohibited from conferring | {{I-D.draft-mcguinness-oauth-mission}}, {{I-D.draft-mcguinness-oauth-mission-issuance-grant}}, {{I-D.draft-mcguinness-oauth-mission-template}}, {{I-D.draft-mcguinness-oauth-mission-continuation}} |
| Task-Scoped Access Engine | A stateless Policy Decision Point evaluating a per-check view of the Mission (the Authority Set plus the containment delta) | {{I-D.draft-mcguinness-mission-authzen}}, {{I-D.draft-mcguinness-mission-runtime}} |
| Mediation Layer | The mediated harness (the tool channel plus the resource-server Policy Enforcement Point) for tool calls, and an egress gate for the otherwise-unmediated network path | {{I-D.draft-mcguinness-mission-harness}}, {{I-D.draft-mcguinness-mission-runtime}} |
| Trust Ratchet | Mission Containment: an authenticated protected event narrows the effective Authority Set deterministically, and restoration requires a fresh approval | {{I-D.draft-mcguinness-oauth-mission-containment}} |
| Task template and capability ceiling | Mission Templates: consent once to a ceiling and a bounded per-instance lifetime, then Dispatch many instances, each clipped to the ceiling | {{I-D.draft-mcguinness-oauth-mission-template}}, {{I-D.draft-mcguinness-oauth-mission-approval}} |
| Agent Activity Log | A pure read-model join over the family's evidence: decision, execution, egress, ingestion, and containment records threaded by Mission lineage into a per-task-run graph | {{I-D.draft-mcguinness-mission-audit}}, {{I-D.draft-mcguinness-mission-authzen}} |
| Grant Review Loop | Not adopted ({{grant-review}}) | {{I-D.draft-mcguinness-oauth-mission-expansion}}, {{I-D.draft-mcguinness-oauth-mission-approval-revision}}, {{I-D.draft-mcguinness-oauth-mission-management}} |
{: title="AAM components and their Mission realizations"}

## Agent Identity Broker {#identity-broker}

AAM's broker exchanges a service's broad identity for a task-scoped
credential inside an established capability ceiling. The family
splits that exchange by consequence class. The mission-dispatch
grant re-issues a clipped, low-consequence instance from a consented
Template in one round trip with no human in the loop; a prohibited
class (irreversible, external-commitment, privileged-administration,
external-communication, or cross-domain capability) is never
dispatched, and instead requires an ordinary Mission approval, a
fresh human decision recorded as a `direct` approval basis. Both
kinds of Mission ride the same continuation transports across a
disconnected run ({{I-D.draft-mcguinness-oauth-mission-continuation}}):
a rotated, sender-constrained refresh-token family whose absolute
lifetime is clamped to the Mission expiry. The credential is
task-scoped and sender-constrained in exactly AAM's sense; the split
adds the property that the machine-speed path structurally cannot
mint the high-consequence credential.

## Task-Scoped Access Engine {#access-engine}

AAM's engine decides per action against the task's ceiling. The
realization is a stateless Policy Decision Point evaluating, on
every consequential action, a per-check view of the Mission: the
consented Authority Set intersected with the containment delta
({{I-D.draft-mcguinness-mission-authzen}}). No standing grant state
is provisioned into the decision engine; the view is assembled per
check, so a containment that landed between two checks is visible to
the second with no propagation step.

## Mediation Layer {#mediation}

Tool calls traverse the mediated harness and the resource-server
Policy Enforcement Point, each consequential action carrying a
decision and its evidence ({{I-D.draft-mcguinness-mission-harness}},
{{I-D.draft-mcguinness-mission-runtime}}). The network path an agent
could use around its tools is covered by an egress gate whose
allowlist and refusals are recorded as evidence. The gate's
containment claim is bounded honestly ({{limitations}}): an
in-process gate mediates the honest path and contains nothing.

## Trust Ratchet {#trust-ratchet}

AAM ratchets trust downward on signal. The realization is Mission
Containment ({{I-D.draft-mcguinness-oauth-mission-containment}}): a
trusted source signs a protected event to the issuer, the issuer
narrows the effective Authority Set deterministically under its
containment policy, and the Policy Decision Point denies the removed
capability with the containment-specific reason while everything
else still permits. The ratchet is monotonic: restoration never
happens mid-run, only through a fresh approval on a new Mission. The
narrowing targets the Mission the event names; other Missions,
including low-consequence dispatched instances, are untouched unless
named.

## Task Template and Capability Ceiling {#template}

AAM's template is consented once and dispatched many times. Mission
Templates realize this with two distinct refusals that keep the
ceiling honest. A Dispatch past the consented Template Ceiling is
refused as out of ceiling. A Dispatch that would confer a
prohibited-class capability is refused as a prohibited class even
when that capability sits inside the consented ceiling: consenting
to the ceiling is not consent for a Dispatch to ever confer the
high-consequence entry, which is only ever granted by a fresh human
approval ({{I-D.draft-mcguinness-oauth-mission-template}}). The
ceiling therefore names the whole job's scope, consented a single
time, while every machine-speed instance is clipped to the
low-consequence slice.

## Agent Activity Log {#activity-log}

AAM's log is a supporting system off the request path. The
realization is a read-model join, not a new store: Policy
Enforcement Point decision evidence, egress evidence, issuer
ingestion records, Containment Evidence, and Mission lineage,
threaded into a per-Mission task-run graph
({{I-D.draft-mcguinness-mission-audit}}). Because every producer
retains its own evidence under its own document's rules, the log
adds no write path and cannot become a second source of truth.

# The Reference Scenario {#walk}

AAM's reference scenario is a nightly reconciliation job whose one
external communication (posting a finance remittance) is
human-gated. The run, in Mission vocabulary:

1. Consent once. A Template is recorded with a read-only
   reconciliation ceiling plus one external-communication capability
   (the whole nightly job's scope), a bounded per-instance lifetime,
   and the human approver of record.
2. Machine-speed Dispatch, kept low-consequence. A scheduler redeems
   the mission-dispatch grant for a read-only intent, yielding a
   fresh Mission with Template lineage, the Template's human as
   approver of record, and an Authority Set clipped to the read
   slice. A Dispatch whose intent also names the remittance
   capability is refused as a prohibited class; a Dispatch past the
   ceiling entirely is refused as out of ceiling, a different reason
   for a different failure.
3. Disconnected run. The dispatched Mission's access token is
   exchanged for a rotated, sender-constrained refresh-token family
   whose absolute lifetime is clamped to the Mission expiry.
4. Per-action mediation. A read tool call is permitted through the
   Policy Enforcement Point over the live Policy Decision Point and
   recorded as decision evidence; a send on the same Mission is
   denied as out of authority, since it was never granted; an
   off-allowlist egress is refused by the egress gate and recorded.
5. The human path. The same intent the Dispatch refused is approved
   directly by a human: an ordinary Mission, a `direct` approval
   basis, no Template lineage. The remittance capability is
   genuinely granted only here.
6. Protected event to containment, targeting the human-approved
   Mission. A trusted security source signs a tainted-read event to
   the issuer; the remittance capability becomes contained at the
   Policy Decision Point on that Mission, while the dispatched
   Mission, which the event never named, is untouched.
7. Restore only in a new task. A fresh human approval restores the
   external-communication capability on a new Mission; the contained
   Mission never regains it mid-run.
8. Activity Log. The join returns two task-run graphs: the
   dispatched Mission's read decision and egress refusal, with
   Template lineage present, and the human-approved Mission's
   ingestion, Containment Evidence, and subsequent contained
   decision, with no Template lineage.

# The Grant Review Loop Is Not Adopted {#grant-review}

AAM's grant review loop is a periodic human re-approval of standing
grants. Missions are not standing grants, so the loop has nothing to
stand over:

- consent is captured once at the Template and re-checked against
  the ceiling at every Dispatch;
- a Mission is lifetime-bounded, so reliance expires on its own
  rather than persisting until a review revokes it;
- drift during a run is handled by containment, not by a scheduled
  review;
- a genuine change of capability goes through Expansion
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}) or Approval
  Revision ({{I-D.draft-mcguinness-oauth-mission-approval-revision}}),
  a fresh approval rather than a review cycle; and
- the Activity Log gives a reviewer the joined task-run graph on
  demand, and lifecycle operations on a live Mission are the
  management surface
  ({{I-D.draft-mcguinness-oauth-mission-management}}).

A standing review loop would duplicate the expansion, containment,
and audit surfaces the family already carries. A deployment that
wants a periodic review as organizational practice can run one over
the Activity Log without any new mechanism.

# Limitations {#limitations}

The mapping is only as strong as what it does not claim.

In-process egress makes no containment claim.
: An egress gate that runs inside the agent process mediates the
  honest path only: a compromised agent can bypass it. Such a gate's
  scope statement reports no containment claim; its value is an
  honest allowlist and an evidence trail. A deployment states a
  stronger claim only when the egress boundary sits outside the
  agent's process.

Authenticated does not mean honest.
: Containment fires on a signed protected event from a trusted
  source, verified against the source identity rather than the
  transport origin, and the issuer narrows authority
  deterministically from it. The issuer does not, and cannot, prove
  that the agent reported a tainted read honestly. Honest
  self-reporting is never assumed.

The Policy Enforcement Point and Policy Decision Point are the
backstop.
: Because neither an in-process gate nor honest self-reporting can
  be trusted against a compromised agent, enforcement rests on the
  Policy Enforcement Point mediating every tool call against the
  Policy Decision Point, which reads the issuer-narrowed effective
  authority. A contained capability is denied at the resource server
  no matter what the agent attempts.

# Conformance {#conformance}

This document defines no conformance targets of its own. A
deployment claiming to realize AAM through this mapping is claiming,
per component, the conformance targets of the governing documents in
{{mapping}}: the issuance profile for approval and issuance, the
template companion for ceilings and Dispatch (including the
prohibited-class refusal), the AuthZEN and runtime profiles for the
decision and enforcement path, the harness document for mediation,
the containment companion for the ratchet, and the audit companion
for the evidence the Activity Log joins. A deployment that omits a
component MUST NOT present this mapping as realized; it names which
components it realizes and which it omits.

# Security Considerations

The security considerations of the governing documents in
{{mapping}} apply to their respective components. The
mapping-specific considerations are the three limitations of
{{limitations}}, which bound what the mediation and containment
components may claim, and the prohibited-class rule of {{template}},
which is what keeps the machine-speed issuance path from becoming a
high-consequence credential minter: a deployment that widens its
Dispatch policy past the prohibited classes has removed the
property, not tuned it.

# Privacy Considerations

The Activity Log join correlates a Mission's decisions, refusals,
egress attempts, and containment history into one graph, which is
more than any single evidence producer discloses. The audit
companion's access-scoping guidance applies to the join as a whole:
the graph is for parties with a governance need, not for every
credential audience. Template lineage links every dispatched
instance to its Template and approver of record; that linkage is the
model's accountability feature and is subject to the same scoping.

# IANA Considerations {#iana}

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The Agent Access Model and its component vocabulary are Cloudflare's
({{AAM}}). This document maps that model onto Mission-Bound
Authorization and makes no claim about the model's own deployments.
