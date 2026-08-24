---
title: "Mission Template for OAuth 2.0"
abbrev: "OAuth Mission Template"
category: exp

docname: draft-mcguinness-oauth-mission-template-latest
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
 - template
 - dispatch
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6755:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
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
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-approval-governance:
    title: "Mission Approval Governance"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

An agent that dispatches work at machine speed cannot pause for a fresh
human approval at every run, and a standing Mission broad enough to
cover every run over-provisions authority the agent holds the whole
time. This document defines an experimental option between those two:
the Mission Template. A human consents once to a task template, a
ceiling of resources, actions, and constraints, a dispatch policy, and
a set of bounds. Each dispatch then instantiates an ordinary Mission
from the template by policy, at machine speed, with no fresh human
approval. The instance is an ordinary Mission: it is bounded by its own
freshly derived Authority Set, is independently gated and revocable,
and never exceeds the template ceiling. High-consequence authority
classes are never dispatched by policy: they stay on a fresh human
decision. Consent is given once, to the ceiling; dispatch draws within
it deterministically.

--- middle

# Introduction

An agent that runs a recurring task dispatches it many times: once per
ticket, per document, per scheduled window. Mission-Bound Authorization
for OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}} (the "issuance
profile") commits a Mission's authority at a single human approval
event. Requiring that event at every dispatch does not scale to machine
speed, and the alternative, a single standing Mission broad enough to
cover every dispatch, over-provisions: the agent holds the full breadth
the whole time, and a fresh approval per run is what the deployment was
trying to avoid.

This document defines an experimental third option: the Mission
Template. A human consents once to a template, which fixes a ceiling of
resources, actions, and constraints, names a dispatch policy, and
publishes a set of bounds. Each **dispatch** then instantiates an
ordinary Mission from the template by that policy, at machine speed,
with no fresh human approval. Consent is given once, to the ceiling;
each instance draws within it deterministically.

This concretizes the blessed semantics the architecture's Approve verb
states: a deterministic, versioned policy can approve at machine speed
within a ceiling a human consented to, because the policy approves the
instance and a human approved the policy, with a policy version keeping
that chain re-checkable ({{I-D.draft-mcguinness-mission-architecture}}).
The accountable principal for every dispatched Mission is the human who
approved the template. The high-consequence classes stay on a fresh
human decision, exactly as that verb requires
({{prohibited-classes}}).

# Status: An Experimental Extension {#optional-status}

This document is optional and experimental: adopt it for evaluation,
not as a stable interface. It removes the per-dispatch human from a
consented template, which is a high-consequence capability. This
document therefore conditions the capability on the ceiling, the
bounds, the prohibited-class rule, and the audit linkage it requires,
and an ordinary human-approved Mission ({{I-D.draft-mcguinness-oauth-mission}})
remains the better fit where each run can carry its own approval. No
Standards-Track document depends on this one.

A Mission Issuer that does not implement this document creates every
Mission through a fresh human approval and is a fully conforming
issuance-profile Mission Issuer ({{I-D.draft-mcguinness-oauth-mission}}).
Nothing here places a new requirement back on the issuance profile.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Maturity: experimental. Maintenance: lab-best-effort.
Adopt when: Machine-speed dispatch makes per-run approval infeasible; consent once to a ceiling.
Requires: Mission-Bound Runtime Enforcement; Mission-Bound Authorization for OAuth 2.0; Mission Consent Evidence for OAuth 2.0; Mission Expansion for OAuth 2.0.
<!-- family-status: END -->

# Relationship to Other Profiles {#relationship}

This document depends normatively on the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and on the Consent Evidence
profile {{I-D.draft-mcguinness-oauth-mission-consent-evidence}}, and is
not implementable alone. It reuses, without restating, the issuance
profile's approval event, integrity-anchor envelope, subset rule,
Authority Set derivation, Mission record, and `active`/`revoked`/`expired`
lifecycle; and the Consent Evidence profile's rule that a consented
object's disclosure is committed. It uses Agent, Subject, Approver,
Mission Issuer, Mission Intent, Authority Set, and Mission as the
issuance profile defines them.

The runtime enforcement profile {{I-D.draft-mcguinness-mission-runtime}}
is a normative dependency for its action classes, which the
prohibited-class rule tests against ({{prohibited-classes}}).

The expansion profile {{I-D.draft-mcguinness-oauth-mission-expansion}}
is also a normative dependency: Dispatch adopts its creation
idempotency apparatus (the operation fingerprint, the durable
reservation, revalidation, and recovery-as-delivery) by reference,
under its own `op: dispatch` fingerprint value, rather than restating
it ({{dispatch}}).

Progressive authorization
({{I-D.draft-mcguinness-oauth-mission-progressive}}) is an informative
sibling. Progressive removes the per-expansion human from a consented
authority ceiling on a single evolving Mission; this document removes
the per-dispatch human from a consented template that mints many
independent Missions. Both concentrate one considered human consent to
a ceiling in place of many hurried consents, and both hold the
high-consequence classes back for a human. Where progressive draws a
successor within one chain, a template dispatches independent
instances.

Terminology disambiguation:
: The Consent Evidence profile
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) already uses
  `template_id` and `template_version` to name a **disclosure-rendering
  template**, the presentation template a Consent Disclosure object was
  rendered from. The **Mission Template** of this document is a
  different object on a different surface: a consented ceiling and
  dispatch policy that instances are minted from, not a rendering of a
  disclosure. The two never share a member. Where this document commits
  a Mission Template's disclosure under Consent Evidence, that
  disclosure carries the Consent Evidence profile's `template_id` and
  `template_version` for its own rendering template, which are unrelated
  to the Mission Template being disclosed.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

Mission Template:
: A consented object that fixes a Template Ceiling, a Dispatch Policy,
  the allowed dispatchers and recipients, per-instance bounds, and a
  review cadence, and from which Missions are dispatched by policy
  without a fresh human approval ({{the-mission-template}}).

Template Ceiling:
: The pre-consented maximum authority any Mission dispatched from a
  Mission Template may reach: an array of authorization-details-shaped
  entries, each the shape of an Authority Set entry
  ({{I-D.draft-mcguinness-oauth-mission}}), that every dispatched
  instance MUST be within ({{dispatch}}).

Dispatch:
: The act of instantiating an ordinary Mission from a Mission Template
  by policy, at machine speed, with no fresh human approval
  ({{dispatch}}).

Dispatcher:
: The authenticated principal that requests a Dispatch. A Dispatcher is
  not an Approver: it triggers instantiation within a template a human
  already approved, and its authority to do so is fixed by the
  template's allowed dispatchers.

Dispatch Policy:
: The deployment-defined policy, identified and versioned, under which
  the Mission Issuer instantiates a Mission from a Mission Template. It
  is the policy the human approved when consenting to the template
  ({{the-mission-template}}), and it is trusted governance held by the
  Mission Issuer.

Mission Deployment Profile:
: The deployment-level manifest the architecture defines
  ({{I-D.draft-mcguinness-mission-architecture}}). The bounds, the
  action-class mapping, and the review cadence this document requires a
  deployment to publish are published there.

# The Mission Template {#the-mission-template}

A Mission Template is a consented object with these members:

`id`:
: REQUIRED. A string. The Mission Template Identifier, stable across the
  template's lifetime.

`issuer`:
: REQUIRED. A string. The Mission Issuer that holds and dispatches from
  the template.

`template_version`:
: REQUIRED. A string. The version of this template's consented content.
  A change to any consented member is a new `template_version` and, per
  {{template-consent}}, a new human approval.

`ceiling`:
: REQUIRED. An array of authorization-details-shaped entries, each the
  shape of an Authority Set entry
  ({{I-D.draft-mcguinness-oauth-mission}}). This is the Template
  Ceiling: the pre-consented maximum any dispatched instance may reach.
  A ceiling entry MAY name a resource family rather than a single
  resource, under the resource-narrowing semantics the subset rule fixes
  ({{I-D.draft-mcguinness-oauth-mission}}).

`dispatch_policy`:
: REQUIRED. An object carrying `id` and `version`, identifying the
  Dispatch Policy under which the Mission Issuer instantiates from this
  template. Its content is deployment-defined. Committing only `id` and
  `version` leaves the policy body itself uncommitted, so a change to
  its logic between template consent and a given dispatch is not
  detectable from the template alone. A deployment SHOULD additionally
  commit the Dispatch Policy body under an integrity anchor, computed
  the way the issuance profile computes `authority_hash`
  ({{I-D.draft-mcguinness-oauth-mission}}), or disclose it under
  Consent Evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), so a
  machine-speed dispatch decision stays auditable against the policy
  content a human actually consented to, not only its identifier.

`allowed_dispatchers`:
: REQUIRED. An array identifying the principals permitted to dispatch
  from this template. A Dispatch request from a principal not in this
  set is refused ({{dispatch}}).

`allowed_recipients`:
: REQUIRED. An array bounding which Subjects and Agents a Mission
  dispatched from this template may be created for. The Mission Issuer
  establishes the instance's Subject as the issuance profile requires,
  never from Dispatcher input
  ({{I-D.draft-mcguinness-oauth-mission}}), and refuses a Dispatch whose
  established Subject or Agent falls outside this set, so a template
  cannot mint a Mission for a party the human did not consent to.

`instance_lifetime`:
: REQUIRED. A duration. The per-instance lifetime clamp: a dispatched
  Mission's `expires_at` is clamped to no more than this from its
  committed `created_at` ({{dispatch}}).

`max_active`:
: REQUIRED. An integer. The maximum number of Missions dispatched from
  this template that may be `active` at once. A Dispatch that would
  exceed it is refused until an active instance terminates.

`dispatch_rate`:
: REQUIRED. A rate bound on Dispatch from this template per unit time.

`expires_at`:
: REQUIRED. The template's own expiry ({{I-D.draft-mcguinness-oauth-mission}}).
  After it, the template dispatches nothing.

`review_cadence`:
: REQUIRED. The maximum age of the template's most recent human approval
  past which the Mission Issuer MUST NOT dispatch ({{template-consent}}).

The concrete values of `instance_lifetime`, `max_active`,
`dispatch_rate`, and `review_cadence`, and the action-class mapping the
prohibited-class rule needs ({{prohibited-classes}}), MUST be published
in the Mission Deployment Profile
({{I-D.draft-mcguinness-mission-architecture}}).

## Template integrity anchor {#template-hash}

The consented Mission Template is committed by a `template_hash`,
computed with the issuance profile's integrity-anchor envelope
({{I-D.draft-mcguinness-oauth-mission}}):

- `typ`: `mission-template`;
- hashed object: the Mission Template object above, canonicalized as
  the integrity-anchor envelope requires, so member order follows that
  canonicalization.

It is an envelope anchor under the issuance profile's commitment
mechanisms, which this document imports normatively.

`template_hash` is to the template what `authority_hash` is to a
Mission's Authority Set: the anchor over the consented object. It plays
the same role the progressive profile's `ceiling_hash` plays for a
consented authority ceiling
({{I-D.draft-mcguinness-oauth-mission-progressive}}). A dispatched
Mission commits its own `intent_hash` and `authority_hash` over its own
Intent and final Authority Set ({{dispatch}}); the template commits the
ceiling once, under `template_hash`. The Mission's anchors and the
template's anchor are never merged.

## Template lifecycle {#template-lifecycle}

A Mission Template has the issuance profile's Mission lifecycle
({{I-D.draft-mcguinness-oauth-mission}}), interpreted for a template:

- `active`: the template dispatches, subject to its bounds and review
  cadence;
- `revoked`: a human or administrator has retired the template; it
  dispatches nothing;
- `expired`: the template is past its `expires_at`; it dispatches
  nothing.

Revoking or expiring a template stops further dispatch. It does not
retroactively terminate Missions already dispatched: each runs to its
own clamped `expires_at` and is independently revocable
({{instance-composition}}). A deployment that needs a faster cutoff on
outstanding instances uses a short `instance_lifetime` or revokes the
instances directly, exactly as the issuance profile bounds an ordinary
Mission's outstanding tokens.

# Template Consent {#template-consent}

Creating a Mission Template is itself a human approval event under the
issuance profile ({{I-D.draft-mcguinness-oauth-mission}}). Its consent
object is the Mission Template: the human consents to the ceiling, the
dispatch policy, the allowed dispatchers and recipients, and the
bounds, and the approval commits them under `template_hash`
({{template-hash}}), the anchor over the object consented to.

Where Consent Evidence is claimed, the template-creation approval's
disclosure is committed as that profile commits any disclosure
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}). The template
is consented before any Mission exists, so, as the Consent Evidence
profile already handles for an approval that commits no Mission, the
disclosure and its evidence carry the Mission Issuer's `issuer` and the
committed anchor and no Mission `id`.

The consent disclosure MUST render, at minimum:

- the Template Ceiling, as the maximum authority any dispatched Mission
  may reach;
- that instances issue at machine speed, by policy, with no
  per-instance human approval; and
- that the high-consequence classes ({{prohibited-classes}}) are never
  dispatched by policy and still require a fresh human decision.

A consent that does not render these is standing dispatch authority
obtained by omission. A template the human did not knowingly consent to
is not a Mission Template under this document.

A Mission Template's consent is standing consent, and standing consent
decays. The Mission Issuer MUST NOT dispatch from a template whose most
recent human approval is older than the published `review_cadence`
({{the-mission-template}}): dispatch stops until a fresh human approval
re-consents, or narrows, the template. The review approval is an
ordinary template-creation approval; its disclosure SHOULD render the
template's dispatch record since the prior review, so the reviewer sees
the cycle they renew.

# Dispatch {#dispatch}

A Dispatch instantiates an ordinary Mission from a Mission Template. It
is submitted on the binding's existing Mission creation surface as a
single authenticated back-channel request that references the template
by `id` and carries the dispatch intent, and it is answered in one
round trip. This document defines no new endpoint and no new
Authorization Server metadata: dispatch is a non-interactive Mission
creation under the pre-consented template, at the token endpoint under
the grant type this document defines ({{grant-type}}).

Because the human decision was made once, at template creation, a
Dispatch uses no Pushed Authorization Request, no front-channel
authorization request, and no interactive consent surface, and the
Mission Issuer never answers a Dispatch with `authorization_pending`:
there is no pending human step to wait for. A deployment that needs a
human in the loop for a given run does not dispatch it; it creates an
ordinary Mission through a fresh approval.

The Mission Issuer adjudicates a Dispatch in this order:

1. **Authenticate the Dispatcher.** Resolve and authenticate the
   principal making the request.
2. **Authorize the Dispatcher.** Verify the Dispatcher is in the
   template's `allowed_dispatchers`. Refuse a request from any other
   principal.
3. **Derive the instance Authority Set.** Derive an Authority Set from
   the dispatch intent, and from the Dispatcher's authority proposal
   where one was submitted ({{grant-type}}), and bound it by the
   deployment's derivation
   policy, exactly as for any Mission
   ({{I-D.draft-mcguinness-oauth-mission}}). This document adds no
   authority-derivation rule.
4. **Double intersection.** The derived instance Authority Set MUST be a
   subset, under the issuance profile's subset rule
   ({{I-D.draft-mcguinness-oauth-mission}}), of **both** the
   deployment's derivation-policy ceiling **and** the Template Ceiling.
   Each surviving instance entry MUST be a subset of some `ceiling`
   entry. If no entry survives the intersection with the Template
   Ceiling, the Mission Issuer MUST refuse the Dispatch with
   `out_of_template_ceiling` ({{denial-reasons}}). Raising the ceiling
   is a new template consent, not a dispatch.
5. **Prohibited-class check.** Apply the prohibited-class rule
   ({{prohibited-classes}}) to the surviving post-intersection set. If
   it would grant a high-consequence class, refuse the Dispatch with
   `dispatch_prohibited_class` ({{denial-reasons}}).
6. **Enforce the bounds.** Refuse the Dispatch if it would exceed
   `max_active` or `dispatch_rate`, or if the instance's
   Mission-Issuer-established Subject or its Agent falls outside
   `allowed_recipients` ({{the-mission-template}}).
7. **Commit the instance.** Commit an ordinary Mission whose Authority
   Set is the surviving set and whose:

   - `approver` is the template's human approver, the accountable
     principal ({{I-D.draft-mcguinness-oauth-mission}}). The Dispatcher
     is not the approver. The instance is rooted in the
     `approval_basis` authorization basis the issuance profile defines
     ({{I-D.draft-mcguinness-oauth-mission}}), with `type: "template"`:
     `consent_principal` is the template's human approver (equal to
     `approver`); `activation` carries the template's `id` (as
     `template_id`, the same value the Dispatch grant names
     {{grant-type}}), `template_version`, and `template_hash` (the
     `template` lineage member's fields, {{template-member}}), plus
     this Dispatch's `dispatch_event_id`; `activation_actor` is the
     Dispatcher, distinct from `consent_principal`;
     `root_commitment` is `template_hash`; and `approved_at` (the
     issuance profile's standing-consent requirement) is the instant
     the consenting human approved this exact `template_version`,
     read from the Mission Issuer's retained template record at
     Dispatch, never from the Dispatch request. This makes the
     approver-of-record shift from a fresh human decision to policy
     adjudication under a prior human consent structured and flagged
     consistently across the family, superseding a bare
     policy-adjudicated marking. The `template` lineage member
     ({{template-member}}), present on every dispatched Mission and
     absent on an ordinarily approved one, remains the claim-carried
     record of which template and Dispatch Policy adjudicated the
     instance; `approval_basis` is the structured authorization-basis
     record, and the two are consistent by construction;
   - `subject` is established as the issuance profile requires, never
     taken from Dispatcher input, and is within `allowed_recipients`
     ({{I-D.draft-mcguinness-oauth-mission}});
   - `intent_hash` and `authority_hash` are computed over the instance's
     own Intent and final Authority Set, never over the template; the
     template commits the ceiling under `template_hash`
     ({{template-hash}});
   - `expires_at` is the effective Mission expiry of the issuance
     profile's requested-versus-effective rule
     ({{I-D.draft-mcguinness-oauth-mission}}): the minimum of the
     dispatch intent's requested `expires_at`, the committed Mission
     `created_at` plus the template's `instance_lifetime`, and the
     template's `expires_at`. The lifetime addend is measured from the
     committed `created_at`, not a separate clock read, so audit
     recomputation is exact. These are the complete expiry inputs for
     Dispatch: a deployment that needs a tighter standing-consent
     lifetime records it in `instance_lifetime` or the template's
     `expires_at` under a newly consented `template_version`, rather
     than applying an undisclosed fourth clamp; and
   - `template` lineage member is set ({{template-member}}).

A Dispatch MUST be idempotent per `dispatch_event_id`. The Dispatcher
supplies a `dispatch_event_id` with the request, adopting the
expansion profile's creation idempotency apparatus by reference
under its own domain-separating `op` value, `dispatch`
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Creation
Idempotency").

The identifier and reservation key are `(authenticated client,
dispatch_event_id)`, the Dispatcher being the authenticated client of
{{grant-type}}. In the operation fingerprint, `op` is `dispatch`;
`iss` and `client` are as the expansion profile defines them;
`source` is this Dispatch's `template_id`, since a Dispatch has no
source Mission or `subject_token` to resolve one from; `cnf` is the
Dispatcher's verified presenter confirmation, the DPoP proof key's
`jkt` or the mTLS certificate's `x5t#S256`; `intent` and `evidence`
are the parsed `mission_intent` Submission envelope's members
({{grant-type}}); `proposal` is the parsed `authorization_details`
array, when present. `actor`, `child_actor`, `requested_token_type`,
and `cross_check` are absent: a Dispatch carries no acting-agent
token, no child actor, no token-exchange requested token type, and no
predecessor or parent cross-check to compare against a resolved
source. A dispatch-specific parameter affecting derivation, approval,
output, or side effects extends the fingerprint the same way an
extension parameter would under the expansion profile's own rule
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "The
operation fingerprint").

The reservation, its `(client, dispatch_event_id)` uniqueness, and
the fingerprint-comparison outcomes on a repeated presentation are
the expansion profile's, applied by reference: same fingerprint and
completed, recover it; same fingerprint and reserved or pending,
return the same in-progress result; different fingerprint, refuse
with `invalid_request`
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "The
durable reservation"). The reservation and the dispatched Mission's
identifier MUST be committed atomically with instance derivation and
`max_active`/`dispatch_rate` accounting. Evidence emission is not
part of that same atomic commit: the Mission Issuer atomically
commits the evidence record, or a durable outbox entry for it, with
Mission creation, and delivers or publishes it idempotently
afterward, since external emission cannot generally participate in
the datastore transaction.

A revalidated retry's obligations depend on whether the original
operation already committed creation. For a **completed** operation,
the Mission Issuer MUST verify the recorded template identity,
`template_version`, and fingerprint; the requester's continued
membership in `allowed_dispatchers` and possession of the recorded
`cnf`; and that the created Mission remains `active`, before
recovering it. Current template applicability, including whether the
checked `template_version` is still in force, is NOT re-evaluated for
a completed operation: a template's own lifecycle already governs
retirement, which stops further dispatch but does not terminate a
Mission already dispatched ({{template-lifecycle}}), so recovery of
that Mission MUST survive later retirement of the template version
that created it. For a **reserved or pending** operation, which has
not yet committed creation, the Mission Issuer instead revalidates
the retry exactly as a fresh Dispatch: current `allowed_dispatchers`
membership, possession of `cnf`, and current template applicability
all apply, since no Mission yet exists for the retry to recover
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section
"Revalidation and lookup order").

Recovery is delivery of the already-dispatched Mission, never a
second instantiation and never a second count against `max_active` or
`dispatch_rate`. A retry recovered while the original access token
remains valid returns that token; a retry recovered after it has
expired is answered by minting a fresh access token for the same,
still-`active` instance, an ordinary delivery event that repeats no
creation accounting, exactly as the expansion profile's recovery
defines for an expired delivery credential
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Recovery
is delivery"). Tombstone retention follows the expansion profile's
rule, against the deployment's published retry horizon
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Tombstone
retention"). This makes retry safe at machine speed and keeps
`max_active` and `dispatch_rate` accounting exact.

## The template lineage member {#template-member}

A dispatched Mission records a `template` lineage member, on both its
`mission` claim and its Mission record, linking it to the Mission
Template it was dispatched from:

`template`:
: An object carrying `id`, `issuer`, `template_version`,
  `template_hash`, and `dispatch_policy` (the policy `id` and
  `version`). Present on every dispatched Mission and absent on a
  Mission created by ordinary approval.

Consistent with the issuance profile's open-`mission`-claim rule
({{I-D.draft-mcguinness-oauth-mission}}), the `template` member is
lineage and audit context only: it MUST NOT grant or widen authority,
and a consumer that does not understand it MUST ignore it. The
instance's authority comes only from its own `authority_hash`. The
`template` member exists so the dispatch is re-checkable in audit
({{audit-linkage}}).

## Grant Type {#grant-type}

This document binds Dispatch to the token endpoint through a
dedicated grant type, adding no new endpoint. A Dispatcher requests an
instance with:

`grant_type`:
: REQUIRED. `urn:ietf:params:oauth:grant-type:mission-dispatch`.

`template_id`:
: REQUIRED. The Mission Template's `id` ({{the-mission-template}}).

`mission_intent`:
: REQUIRED. The dispatch submission, in the issuance profile's
  Mission Intent Submission envelope shape
  ({{I-D.draft-mcguinness-oauth-mission}}): its `intent` is the
  dispatch intent from which the instance Authority Set is derived
  ({{dispatch}}), and its OPTIONAL `evidence` array carries Intent
  Submission Evidence under that profile's dispatch, refusal, and
  never-authority rules.

`authorization_details`:
: OPTIONAL. The Dispatcher's authority proposal: the standard
  {{RFC9396}} parameter carried on the same token request, itself
  ordinary {{RFC9396}} token-request usage. This parameter is this
  grant's proposal carriage, replacing the issuance profile's
  PAR-only carriage rule; that profile's validation, derivation,
  recording, and hashing semantics apply unchanged
  ({{I-D.draft-mcguinness-oauth-mission}}). It is a proposal, never
  authority: it bounds the derivation of step 3 of {{dispatch}} in
  narrowing mode, and the double intersection of step 4 applies to
  the result unchanged, so a proposal narrows the instance and never
  widens it beyond the Template Ceiling. Absent a proposal, the
  instance derives from the dispatch intent alone. An instance
  created from a Dispatch carrying one records `proposed_authority`
  and `proposal_hash`.

`dispatch_event_id`:
: REQUIRED. The dispatch event identifier that makes the Dispatch
  idempotent ({{dispatch}}). A redemption bearing an identifier the
  Mission Issuer has already committed MUST return the previously
  committed instance and MUST NOT derive a second Mission.

The Dispatcher authenticates at the token endpoint with its own client
credential; the Mission Issuer authorizes it against the template's
`allowed_dispatchers` as step 2 of {{dispatch}} requires. This grant
performs exactly one derivation per `dispatch_event_id`: the
adjudication order of {{dispatch}} runs once for a new identifier, and
a repeated identifier is gated to the previously committed instance
rather than a fresh derivation. This is the single gated derivation
this document permits per dispatch event.

On success the Mission Issuer responds with an access token bound to
the instance, sender-constrained to the Dispatcher's key:

`access_token`:
: REQUIRED. A Mission-bound access token for the dispatched instance.

`token_type`:
: REQUIRED. The token type of the issued access token, reflecting the
  sender-constraining mechanism in use (`DPoP` where the deployment
  uses DPoP).

`expires_in`:
: REQUIRED. The access token's lifetime in seconds.

`mission_id`:
: REQUIRED. The dispatched Mission's identifier.

`mission_expires_at`:
: REQUIRED. The instance's effective Mission expiry, the issuance
  profile's common Mission-creating response member
  ({{I-D.draft-mcguinness-oauth-mission}}). `expires_in` above
  describes only the access token.

`authorization_details`:
: REQUIRED. The instance's committed Authority Set.

A Dispatch refused under {{dispatch}} or {{prohibited-classes}} carries
the OAuth `error` member together with `mission_denial_reason`
({{denial-reasons}}), exactly as any other adjudication denial in this
family.

# Prohibited Classes {#prohibited-classes}

Some authority classes are too consequential to activate without a
human at the moment of the decision. A Dispatch MUST NOT instantiate a
Mission that grants authority in any of these classes, even when the
class is within the Template Ceiling:

- the irreversible, external-commitment, or privileged-administration
  class;
- authority satisfying the runtime profile's external-communication
  predicate, the exfiltration leg
  ({{I-D.draft-mcguinness-mission-runtime}}); or
- cross-domain authority.

Progressive holds back this same set from its own policy adjudication
({{I-D.draft-mcguinness-oauth-mission-progressive}}), applied here to
dispatch. To make the rule testable, a deployment MUST publish in the
Mission Deployment Profile a mapping from its action identifiers to
the runtime profile's action classes
({{I-D.draft-mcguinness-mission-runtime}}), or an equivalent declared
classification.

The issuance profile's fourth high-risk class, a consumption bound
({{I-D.draft-mcguinness-oauth-mission}}), is not on this list: it is
the containment mechanism a dispatched instance draws down under, not
a hazard dispatch amplifies. The template's `approval_basis` already
carries the trace the issuance profile's approval-authentication floor
requires for that class, through `consent_principal` and
`approved_at` ({{dispatch}}); a deployment recording Consent Evidence
renders the bound at the same surface under the metering profile's
consent-integrity rule ({{I-D.draft-mcguinness-mission-metering}}).

Where a deployment adopts Approval Governance
({{I-D.draft-mcguinness-mission-approval-governance}}) and records a
Governance Record for a dispatched instance, the template's
`approval_basis` satisfies that profile's accountable-approver rule
directly, through the same `consent_principal`, `root_commitment`,
and `approved_at` this document already requires: no assertion is
fabricated in the name of the Dispatcher or the Dispatch Policy to
stand in for a fresh human decision that did not occur. Approval
Governance's own high-risk-class default still binds that record: a
dispatched instance carrying a consumption bound activates only where
a committed, class-named exception admits it; absent the exception,
the Mission fails to activate under that profile's atomic-commitment
rule.

The deployment's configured dispatch-prohibited action set MUST cover
every action the published mapping classifies as irreversible,
external-commitment, or privileged-administration, as satisfying the
runtime profile's external-communication predicate
({{I-D.draft-mcguinness-mission-runtime}}), or as cross-domain. A
configured set narrower than the mapping is nonconformant: it lets a
Dispatch confer a class the deployment's own mapping already
identifies as prohibited, which is exactly the outcome this section
forbids.

A Dispatch that would grant a prohibited class is refused with
`dispatch_prohibited_class` ({{denial-reasons}}). Unlike the
progressive profile, which falls back to a fresh human approval in
band, a Dispatch has no interactive surface to escalate on: the human
path is an ordinary Mission created through a fresh approval
({{I-D.draft-mcguinness-oauth-mission}}), requested out of band. The
Dispatch Policy MUST NOT dispatch a Mission bearing a prohibited class.

# The Denial Reasons {#denial-reasons}

This document defines a closed set of dispatch denial reasons, carried
in the shared `mission_denial_reason` member that the expansion profile
established for adjudication denials
({{I-D.draft-mcguinness-oauth-mission-expansion}}):

`out_of_template_ceiling`:
: The dispatched instance's Authority Set is not within the Template
  Ceiling ({{dispatch}}), so it cannot be instantiated by policy.
  Raising the ceiling requires a fresh human template consent.

`dispatch_prohibited_class`:
: The dispatched instance would grant a high-consequence class
  ({{prohibited-classes}}), which a Dispatch never auto-approves. The
  authority is available only through a fresh human approval.

A consumer that does not implement this document treats either value as
it treats any unrecognized reason code: the Dispatch stays denied, with
no further semantics.

# Instance Composition {#instance-composition}

A dispatched Mission is an ordinary Mission. Nothing about its origin
makes it special to the rest of the family; the template bounded its
creation and then steps out of the way.

- **Containable.** A dispatched Mission is subject to Mission
  Containment ({{I-D.draft-mcguinness-oauth-mission-containment}}): its
  effective authority can be narrowed by event-triggered containment
  exactly as any Mission's can.
- **Continuable.** A dispatched Mission's work continues under the
  continuation profile's transports
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}). Async
  delegation is the natural scheduled-dispatch path: a scheduled run
  dispatches an instance and carries it forward on that transport.
- **Expandable, but not by the template.** A dispatched Mission MAY be
  expanded through a human-approved expansion
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}). Such an expansion
  is **not** bound by the Template Ceiling: it is a fresh human consent
  that supersedes the instance, and its successor derives its authority
  from that new approval, not from the template. The successor
  therefore MUST NOT carry the `template` lineage member
  ({{template-member}}): it was not dispatched, and an auditor
  re-running the ceiling check ({{audit-linkage}}) MUST NOT be led to
  test a freshly consented successor against the template.
- **Child-delegable within the ceiling.** A dispatched Mission MAY
  create Child Missions
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). As a
  consequence of the child-delegation profile's strict-subset rule, a
  Child Mission is a strict subset of the instance's Authority Set,
  which is itself within the Template Ceiling, so the whole delegation
  tree stays within the ceiling without any new rule here.

# Audit Linkage {#audit-linkage}

A dispatched Mission is re-checkable in audit with no per-dispatch human
in the record, because the human is at the template. For a dispatched
Mission an authorized auditor can:

- recompute `template_hash`, the envelope anchor of {{template-hash}},
  from the stored Mission Template object and match it to the committed
  anchor the template-creation consent evidence carries in its
  `source_hashes` ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}};
  that disclosure's own `rendering_template_digest` commits the
  rendering template, a different object) and to the instance's
  `template` lineage member ({{template-member}}), so the ceiling the
  instance was checked against is the one the human consented to;
- re-run the subset check of the instance's Authority Set against the
  Template Ceiling ({{dispatch}}), confirming the instance is within the
  ceiling;
- recompute the instance's effective `expires_at` as the minimum of
  the dispatch intent's requested `expires_at`, the committed
  `created_at` plus `instance_lifetime`, and the template's
  `expires_at` ({{dispatch}}), and match it to the recorded value, so
  the granted lifetime is exactly the three-way clamp; and
- verify that the instance's `approver` equals the template's approver
  at the recorded `template_version`, so the accountable principal is
  the human who consented to that version of the template.

Each Dispatch MUST record the Dispatch Policy `id` and `version` that
instantiated the Mission, and the dispatch event identifier
({{dispatch}}), so the policy chain the architecture's Approve verb
requires stays re-checkable
({{I-D.draft-mcguinness-mission-architecture}}). A deployment MUST
retain the consented template, `template_hash`, and dispatch records for
each instance's audit horizon
({{I-D.draft-mcguinness-oauth-mission}}), so every dispatch is
verifiable to have stayed within the consented template.

# Security Considerations {#security-considerations}

The issuance profile's security considerations apply in full. This
document adds the dispatch surface.

- **Standing consent decays.** A template consented once and dispatched
  from indefinitely is a standing grant with a calendar. The bounds
  (`instance_lifetime`, `max_active`, `dispatch_rate`) cap breadth and
  rate, not duration; the `review_cadence` ({{template-consent}}) is the
  temporal bound, and dispatch stops past it until a human re-consents.
  The tells of decay are checkable from the dispatch record: reviews
  that never narrow the ceiling, ceilings that only grow, and a
  `dispatch_rate` raised without a task that needs it. A review that
  cannot cite the cycle it renews has not reviewed it.

- **A compromised Dispatcher is bounded.** A Dispatcher is authenticated
  and is not an Approver: it can trigger instantiation only within the
  template a human approved. A compromised Dispatcher cannot exceed the
  Template Ceiling (double intersection, {{dispatch}}), cannot dispatch
  a high-consequence class ({{prohibited-classes}}), and cannot outrun
  `max_active` or `dispatch_rate`. Its blast radius is therefore bounded
  to no more than the human consented to when approving the template,
  and every instance it dispatched is independently gated, revocable,
  and enforced per action by the runtime layer
  ({{I-D.draft-mcguinness-mission-runtime}}).

- **The Dispatch Policy is authority-bearing governance.** A
  misconfigured policy can over-instantiate within the ceiling, so it is
  reviewed and versioned like other approval policy, and its `id` and
  `version` are part of every dispatch record ({{audit-linkage}}).

- **The template bounds, and does not eliminate, standing exposure.** A
  deployment SHOULD pair a Mission Template with short
  `instance_lifetime` values, constraint-bounded ceilings, and runtime
  enforcement, so the authority any single dispatched Mission actively
  holds stays narrow.

# Privacy Considerations {#privacy-considerations}

The Template Ceiling discloses, at template-consent time, the full
envelope every future dispatch may draw within, which can reveal more
about the anticipated recurring task than any single dispatched
Mission's Authority Set. The `template` lineage member correlates every
instance dispatched from one template across distinct Missions. Access
to the template, its ceiling, and the dispatch records SHOULD be scoped
to parties with a governance need. The issuance profile's Mission
Identifier correlation considerations apply to each dispatched Mission.

# Conformance {#conformance}

A Mission Issuer that claims **Dispatch from a Mission Template** is a
conforming issuance-profile Mission Issuer
({{I-D.draft-mcguinness-oauth-mission}}) and MUST:

- record a consented Mission Template with the required members and
  commit it under `template_hash` with `typ` `mission-template`
  ({{the-mission-template}}, {{template-hash}}), and treat template
  creation as a human approval event whose disclosure renders the
  ceiling, the no-per-instance-approval fact, and the prohibited-class
  reservation ({{template-consent}});
- adjudicate a Dispatch in the order of {{dispatch}}: authenticate and
  authorize the Dispatcher, derive the instance Authority Set,
  double-intersect it with the derivation-policy ceiling and the
  Template Ceiling, apply the prohibited-class check, enforce the
  bounds, and commit an ordinary Mission whose `approver` is the
  template's human approver and whose anchors are over the instance's
  own Intent and Authority Set;
- record every dispatched Mission's `approval_basis` with `type:
  "template"`: `consent_principal` the template's human approver,
  `activation` the template lineage and this Dispatch's
  `dispatch_event_id`, `activation_actor` the Dispatcher, and
  `root_commitment` the `template_hash` ({{dispatch}});
- refuse a Dispatch outside the ceiling with `out_of_template_ceiling`
  and a Dispatch of a prohibited class with `dispatch_prohibited_class`
  ({{denial-reasons}});
- make every Dispatch idempotent per `dispatch_event_id`, adopting the
  expansion profile's creation idempotency apparatus by reference
  under `op: dispatch`, with the `(client, dispatch_event_id)`
  reservation, fingerprint, revalidation, and delivery-as-recovery
  bindings of {{dispatch}};
- answer a Dispatch in one authenticated back-channel round trip, using
  no PAR, no interactive consent surface, and never
  `authorization_pending` ({{dispatch}});
- record the `template` lineage member on the dispatched Mission
  ({{template-member}});
- stop dispatch past the published `review_cadence` until a fresh human
  approval ({{template-consent}}); and
- publish the bounds and the action-class mapping in the Mission
  Deployment Profile ({{the-mission-template}}, {{prohibited-classes}})
  and retain the audit linkage of {{audit-linkage}}.

A Resource Server requires no new behavior: it enforces a dispatched
Mission's tokens exactly as it enforces any Mission-bound token, and
treats the `template` member, if it reads it at all, as audit context
it MUST NOT use to grant authority ({{template-member}}).

# IANA Considerations {#iana}

This document requests registration of the following value in the
"OAuth URI" registry established by {{RFC6755}}:

URN:
: `urn:ietf:params:oauth:grant-type:mission-dispatch`

Common Name:
: Mission Dispatch Grant Type

Change Controller:
: IETF

Specification Document:
: this document, {{grant-type}}

This is a proposed registration. The value is used under the reserved
`urn:ietf:params:oauth` arc by implementations of this document in
advance of registration completing; this document is the specification
that names and defines it.

This document also registers one parameter in the "OAuth Parameters"
registry:

- Name: `dispatch_event_id`
- Parameter Usage Location: token request
- Change Controller: IETF
- Reference: this document, {{grant-type}}, {{dispatch}}

`dispatch_event_id` is a distinct name from the expansion profile's
`creation_request_id` ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
even though it plays the identifier-and-reservation-key role that
parameter's registration defines: it is already load-bearing as the
`template` lineage member's field and in `approval_basis.activation`
({{dispatch}}), and in the Dispatch grant-type parameter list
({{grant-type}}), so this document keeps the name rather than
reusing the expansion profile's own registered parameter under
`op: dispatch`.

Beyond these two registrations, this document requests no further
IANA action. Following the restraint of the sibling profiles:

- `template_hash` is a Mission integrity anchor whose `typ`,
  `mission-template`, follows the issuance profile's collision-resistant
  `typ` convention ({{I-D.draft-mcguinness-oauth-mission}}) and requires
  no registration;
- the `template` member of the `mission` claim ({{template-member}}) is
  carried inside the already-open `mission` claim and needs no separate
  registration;
- `out_of_template_ceiling` and `dispatch_prohibited_class` are
  requested as registrations in the expansion profile's
  Mission Denial Reasons registry
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}), each with its
  semantics as defined in this document and Reference this document;
  and
- the Mission Template's type identifier,
  `application/mission-template+json`, is used by local agreement
  pending registration; an audit or transparency profile registers the
  object by that value.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and expresses, in family terms, a define-a-template-once,
dispatch-per-run lifecycle: one considered human consent to a ceiling
in place of a fresh approval at every machine-speed run.
