---
title: "Mission Progressive Authorization for OAuth 2.0"
abbrev: "OAuth Mission Progressive Authorization"
category: exp

docname: draft-mcguinness-oauth-mission-progressive-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - expansion
 - progressive
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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

informative:
  I-D.draft-mcguinness-mission-discovery:
    title: "Mission Open-World Discovery"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-discovery.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission-Bound Authorization for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
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
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-completion:
    title: "Mission Completion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-completion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission Expansion for OAuth 2.0 widens an agent's authority only
through a fresh human approval that creates a successor Mission. An
open-ended agentic task often cannot have its full authority enumerated
at the initial approval, which leaves a deployment choosing between
over-provisioning a broad standing Mission and interrupting the user
for a fresh approval at every step. This document defines an
experimental third option, progressive authorization: at the initial
approval the Approver additionally consents to a bounded authority
ceiling and a drawdown policy, and the Mission Issuer may then
adjudicate an expansion that stays within that ceiling by policy rather
than by a fresh human approval. Authority can grow within the consented
envelope at runtime while the active authority any single Mission
yields stays narrow. Authority classes named by the runtime profile's
high-consequence classification always require a fresh human approval,
even within the ceiling.

--- middle

# Introduction

Mission Expansion for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission-expansion}} (the "expansion
profile") defines the governed path from an authority shortfall to a
new approval: a successor Mission, freshly consented, that supersedes
its predecessor. Every expansion under that profile is adjudicated by a
fresh human approval. For a task whose growth is anticipated, that
discipline has a human cost: each expansion is another approval
moment, and an Approver asked too often stops reading what is asked
(the consent-fatigue residual of
{{I-D.draft-mcguinness-mission-security-model}}). This profile is the
structural mitigation: one considered consent to a ceiling replaces
many hurried consents to increments, without widening what any single
Mission actively holds.

An open-ended agentic task often cannot have its full authority
enumerated at the initial approval, which leaves a deployment choosing
between over-provisioning a broad standing Mission and interrupting the
user for a fresh approval at every step. Progressive authorization is a
third option: the Approver consents once to a bounded envelope and a
rule for drawing authority from it, so authority can grow within the
envelope at runtime without a fresh human approval each time, while the
active authority any single Mission yields stays narrow.

# Status: An EXPERIMENTAL Extension {#optional-status}

This document is OPTIONAL and **experimental**: adopt it for
evaluation, not as a stable interface. It removes the per-expansion
human from a consented envelope, which is the highest-consequence
capability in the expansion family; deploy it only with the rate
bounds, prohibited-class rules, and audit linkage this document
requires, and prefer plain expansion where task authority can be
anticipated per step.

A Mission Issuer that does not implement this document adjudicates
every expansion as a fresh human approval and is a fully conforming
expansion-capable Mission Issuer
({{I-D.draft-mcguinness-oauth-mission-expansion}}). Nothing here places
a new requirement back on the expansion profile or the issuance
profile.

# Relationship to the Expansion Profile {#relationship}

This document depends normatively on the expansion profile
{{I-D.draft-mcguinness-oauth-mission-expansion}} and on the issuance
profile {{I-D.draft-mcguinness-oauth-mission}}, and is not
implementable alone. It reuses, without restating, the expansion
profile's expansion request, adjudication, `predecessor` member,
`superseded` state, and reconciliation, and the issuance profile's
approval event, integrity-anchor envelope, and subset rule. It uses
Predecessor Mission, Successor Mission, and Expansion request as the
expansion profile defines them.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

Authority ceiling:
: The pre-consented maximum authority any expansion of a Mission may
  reach without a further human approval ({{progressive-authorization}}).

Drawdown policy:
: The policy under which the Mission Issuer may adjudicate an
  in-ceiling expansion by policy rather than by a fresh human approval
  ({{progressive-authorization}}).

# Progressive Authorization {#progressive-authorization}

At the initial approval event ({{I-D.draft-mcguinness-oauth-mission}}),
the Approver MAY additionally consent to:

- an **authority ceiling**, recorded as an `authority_ceiling` member on
  the Mission: an array of authorization-details-shaped entries, each the
  shape of an Authority Set entry ({{I-D.draft-mcguinness-oauth-mission}}),
  that is the pre-consented maximum any expansion of this Mission may
  reach without a further human approval and that every in-ceiling
  successor MUST be within ({{in-ceiling-expansion}}); and
- a **drawdown policy**, recorded as a `drawdown_policy` member on the
  Mission: a string or URI identifying the policy under which the Mission
  Issuer MAY adjudicate an in-ceiling expansion by policy rather than by
  a fresh human approval. The policy's content is deployment-defined.

Where present, `authority_ceiling` and `drawdown_policy` are recorded on
the Mission and committed by a `ceiling_hash`, computed with the issuance
profile's integrity-anchor envelope
({{I-D.draft-mcguinness-oauth-mission}}) under the `typ`
`mission-authority-ceiling` over an object carrying both members. They
are not committed under `authority_hash`: `authority_hash` commits only
the consented Authority Set ({{I-D.draft-mcguinness-oauth-mission}}), and
the ceiling is a bound on future expansions, not present authority. The
consent disclosure MUST render the ceiling and the fact that in-ceiling
expansion is policy-adjudicated
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}). A Mission
that carries no `authority_ceiling` has no progressive authorization:
every expansion of it is an ordinary, freshly approved expansion
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

## In-ceiling expansion {#in-ceiling-expansion}

An **in-ceiling expansion** is an expansion, adjudicated per the
expansion profile ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
whose successor Authority Set is within the predecessor's consented
`authority_ceiling`. A requested successor Authority Set is in-ceiling
when every one of its entries is a subset of some `authority_ceiling`
entry under the issuance profile's subset rule
({{I-D.draft-mcguinness-oauth-mission}}); a `constraints`-bounded ceiling
uses the same subset semantics. A ceiling entry MAY name a resource
family rather than a single resource, under the same
resource-narrowing semantics the subset rule fixes: a successor
entry's `resource` is in-ceiling when it narrows the ceiling entry's.
This is what lets an Approver consent once to a class of resources
an agent will only meet during execution, while every concrete
binding stays inside the consented family. When the predecessor consented to a
drawdown policy that authorizes the requested widening, the Mission
Issuer MAY satisfy the adjudication's approval event by policy rather
than by a fresh human approval, exactly as a parent Mission's Authority
Set may permit policy-approved child creation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). This is an
explicit override of the expansion profile's consent step for the
in-ceiling case only. The successor is created as the expansion profile
requires: its Authority Set freshly derived and bound by the ceiling,
its `predecessor` member set, the predecessor superseded. An in-ceiling
successor MUST carry the predecessor's `authority_ceiling` and
`drawdown_policy` unchanged or narrowed, committed under the same or,
when narrowed, a recomputed `ceiling_hash`. Any change to either beyond
narrowing requires a fresh human approval, never policy adjudication.

When the adjudication is by the pre-consented drawdown policy, the
Mission Issuer MAY complete the authorization request without prompting
the Approver, issuing the authorization code directly on redemption of
the expansion's `request_uri`. The successor is still created through the
full approval-event machinery of the expansion profile; only the
interactive prompt is skipped.

This does not widen authority without consent
({{I-D.draft-mcguinness-oauth-mission-expansion}}). The consent is the
human consent given at the initial approval to the ceiling and the
drawdown policy; policy adjudication only draws within that pre-given
consent and can never exceed the ceiling. The Mission Issuer MUST
refuse, with `out_of_ceiling` ({{denial-reason}}), a requested authority
that is not within the consented `authority_ceiling`; exceeding the
ceiling requires a fresh human approval that raises it, which is an
ordinary expansion.

Policy adjudication is bounded, so a pre-consented ceiling cannot become
a standing grant a compromised agent walks up to unattended. Each
in-ceiling drawdown creates a successor Mission, so a per-Mission bound
would reset at every step. A deployment MUST rate-bound
policy-adjudicated expansions per expansion chain, keyed by the chain's
root Mission or its `ceiling_hash` and counted across `predecessor`
links per unit time, and MUST record each as an approval event whose
approver context is the drawdown policy that authorized it
({{audit-linkage}}).

Some authority classes always require a fresh human approval even within
the ceiling. To make that testable, a deployment MUST publish a mapping
from its action identifiers to the runtime profile's action classes
({{I-D.draft-mcguinness-mission-runtime}}), or an equivalent
declared classification. A drawdown that grants authority mapped to an
irreversible, external-commitment, or privileged-administration class, or
that grants cross-domain authority, MUST be adjudicated by a fresh human
approval; the drawdown policy MUST NOT permit policy-only adjudication of
those. An in-ceiling request the drawdown policy does not authorize is not
refused with `out_of_ceiling`; it falls back to an ordinary, freshly
human-approved expansion. The drawdown policy MUST NOT policy-adjudicate
a successor Authority Set entry structurally equal to a predecessor
entry discharged under the completion profile
({{I-D.draft-mcguinness-oauth-mission-completion}}); such a request
falls back to a fresh human approval.

## What it bounds, and what it does not {#progressive-limits}

The ceiling is broad by construction, since it must cover the
open-ended task. What stays narrow is the active authority any single
Mission in the chain yields: each in-ceiling successor is derived for
the authority actually needed at that step and is independently gated
and revocable. A compromised agent cannot instantly wield the ceiling;
it can exercise only the current active authority and request in-ceiling
drawdown, which is policy-gated, recorded for audit ({{audit-linkage}}),
rate-limitable, and enforced per action by the runtime layer
({{I-D.draft-mcguinness-mission-runtime}}). Progressive
authorization bounds, and does not eliminate, standing-authority
exposure; a deployment SHOULD pair it with short successor lifetimes,
constraint-bounded ceilings, and runtime enforcement. The drawdown
policy is enforced by the Mission Issuer and is part of its trusted
governance: a misconfigured policy can over-grant within the ceiling, so
it is reviewed and versioned like other approval policy.

## Realizing an approved access request {#arap-feedback}

Progressive authorization grows authority that a deployment anticipated
well enough to express as a ceiling. The runtime enforcement layer
handles the unanticipated case: it can let an agent request authority it
discovers it needs at the point of use, through an access-request and
approval workflow ({{I-D.draft-mcguinness-mission-runtime}}). That
workflow yields a permit for the single re-evaluated action. To persist
the newly approved authority for the rest of the task, rather than have
the agent re-request it on every call, the Mission Issuer MAY realize an
approved access request as an expansion:

- a request whose authority is within the Mission's consented ceiling is
  realized as a policy-adjudicated in-ceiling expansion
  ({{in-ceiling-expansion}}); and
- a request whose authority exceeds the ceiling is realized only on the
  fresh human approval the request carries, as an ordinary expansion
  that creates the successor and, where the Approver consents, raises
  the ceiling.

Realizing a request as an expansion is subject to every rule of the
expansion profile: the successor's authority is freshly derived and
bound, the predecessor is superseded, and authority is never widened
without the consent the request carries
({{I-D.draft-mcguinness-oauth-mission-expansion}}). An access request
not realized as an expansion grants only the single runtime permit and
no durable Mission authority.

# The out_of_ceiling Denial Reason {#denial-reason}

This document extends the expansion profile's closed set of expansion
denial reasons ({{I-D.draft-mcguinness-oauth-mission-expansion}}) by
specification, as that profile's IANA considerations anticipate, with
one value, carried in `mission_expansion_status` exactly as that
profile's reasons are:

`out_of_ceiling`:
: The requested authority is not a subset of the Mission's consented
  authority ceiling ({{progressive-authorization}}), so it cannot be
  granted by policy drawdown; raising the ceiling requires a fresh human
  approval.

A consumer that does not implement this document treats
`out_of_ceiling` as it treats any unrecognized reason code: the
expansion stays denied.

# Audit Linkage {#audit-linkage}

Each policy-adjudicated in-ceiling expansion is an approval event and
MUST be recorded as one: the approver context is the drawdown policy
(its identifier and version) rather than a human principal, and the
successor's `predecessor` member links the drawdown chain for an
authorized auditor exactly as for human-approved expansions
({{I-D.draft-mcguinness-oauth-mission-expansion}}). The record MUST
carry the chain's cumulative drawdown count, so the rate bound of
{{in-ceiling-expansion}} is auditable from the records alone. A
deployment MUST retain the consented `authority_ceiling`,
`drawdown_policy`, and `ceiling_hash` with every Mission record in the
chain for the audit horizon, so an auditor can verify every drawdown
was within the consented envelope.

Where a drawdown is triggered by the agent encountering a resource
not named at approval, and the resource self-declares its operations
and consequences in a content-addressed form (the AAuth binding
composes one such substrate,
{{I-D.draft-mcguinness-mission-aauth}}), the adjudication MUST
evaluate the declaration against the ceiling and the record MUST
carry the declaration's digest as `resource_declaration_digest`, so
the encounter is reproducible in audit: what the resource claimed to
be when authority bound to it. The discovery companion
({{I-D.draft-mcguinness-mission-discovery}}) defines the encounter
adjudication contract, the identity pinning, and the floors this
drawdown path carries.

# Conformance {#conformance}

A Mission Issuer that claims **Expansion with Progressive
Authorization** is a conforming expansion-capable Mission Issuer
({{I-D.draft-mcguinness-oauth-mission-expansion}}) and MUST:

- for a Mission whose Approver consented to a ceiling, record the
  consented `authority_ceiling` and `drawdown_policy` on the Mission
  and commit them with `ceiling_hash` ({{progressive-authorization}});
- evaluate a requested successor Authority Set as in-ceiling by the
  subset rule, and refuse an out-of-ceiling request with `out_of_ceiling`
  ({{in-ceiling-expansion}}, {{denial-reason}});
- enforce the prohibited-class rule, requiring a fresh human approval for
  a drawdown that grants an irreversible, external-commitment, or
  privileged-administration authority, or cross-domain authority
  ({{in-ceiling-expansion}}); and
- rate-bound policy-adjudicated drawdowns per expansion chain, keyed by
  the chain's root Mission or its `ceiling_hash` and counted across
  `predecessor` links, and record each as an approval event carrying
  the chain's cumulative drawdown count ({{in-ceiling-expansion}},
  {{audit-linkage}}).

# Security Considerations {#security-considerations}

The expansion profile's security considerations apply in full. This
document adds the drawdown surface:

- The ceiling is consented once and drawn on many times. A compromised
  agent can request in-ceiling drawdown unattended; the mitigations are
  the rate bound, the prohibited-class rule, the fall-back to human
  approval for unauthorized drawdowns ({{in-ceiling-expansion}}), and
  per-action runtime enforcement
  ({{I-D.draft-mcguinness-mission-runtime}}).
- The drawdown policy is authority-bearing governance. A misconfigured
  policy over-grants within the ceiling; it MUST be reviewed and
  versioned like approval policy, and its identity and version are part
  of the recorded approver context ({{audit-linkage}}).
- The ceiling is a consent artifact. It MUST be rendered to the
  Approver at the initial approval with the fact that in-ceiling
  expansion is policy-adjudicated ({{progressive-authorization}}); a
  ceiling the Approver did not knowingly consent to is standing
  authority obtained by omission.

# Privacy Considerations {#privacy-considerations}

The ceiling discloses, at initial approval time, the full envelope a
task may grow into, which can reveal more about the anticipated task
than any single Mission's Authority Set. The expansion profile's
predecessor-chain correlation considerations apply to the drawdown
chain; access to the ceiling and drawdown records SHOULD be scoped to
parties with a governance need.

# IANA Considerations {#iana}

This document has no IANA actions. Following the expansion profile's
restraint, `out_of_ceiling` is documented here as a
specification-defined extension of that profile's denial-reason set,
`authority_ceiling` and `drawdown_policy` are Mission record members
defined by this profile, and the `mission-authority-ceiling` anchor
`typ` follows the issuance profile's collision-resistant `typ`
convention, none of which require registration.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and extends Mission Expansion with an experimental pre-consented
drawdown mechanism.
