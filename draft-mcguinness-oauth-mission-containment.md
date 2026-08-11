---
title: "Mission Containment for OAuth 2.0"
abbrev: "OAuth Mission Containment"
category: exp

docname: draft-mcguinness-oauth-mission-containment-latest
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
 - containment
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7519:
  RFC8259:
  RFC8785:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
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
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
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
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
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
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
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
  I-D.draft-mcguinness-mission-discovery:
    title: "Mission Open-World Discovery"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-discovery.html
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

--- abstract

Mission-Bound Authorization for OAuth 2.0 commits a Mission's
authority at a single approval event: the approved Authority Set and
its integrity anchors never change. This document defines Mission
Containment, an optional layered extension for narrowing a live
Mission without ending it. When a declared protected event fires (a
tainted read, an anomaly signal, an open-world discovery
tainted-session event), the Mission Issuer commits a contain
transition: an issuer-held, versioned overlay removes capability from
the Mission's effective authority while the Mission stays `active`
and the approved anchors stay immutable. Containment is monotonic and
removal-only. Token derivation, child delegation, cross-domain
projection, and offline attenuation are gated on the effective
authority; a derivation that asks only for contained capability fails
with `authority_contained`. Removed authority returns only through a
new approval, as a successor Mission under the expansion profile,
with the predecessor's containment history disclosed to the Approver.
A deployment that never contains a Mission is unaffected by this
document.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes
a Mission a first-class OAuth artifact: a structured, human-approved,
integrity-bound task whose authority bounds and outlives every token
an agent derives. It commits the Authority Set once, at the approval
event, and gates every derivation on Mission state.

Incident response against a live Mission has, under the profiles so
far, two grains: revoke the Mission and end one body of work across
every resource, or suspend it and pause all of it. A mid-task signal
is often finer than either. A session reads tainted content and the
right response is to remove the Mission's egress capability, not its
read capability; an anomaly fires against a payment action and the
right response is to remove that action, not the reconciliation work
around it. This document defines that finer control: capability kill
within one Mission, with the Mission still running.

The mechanism is a narrowing overlay, not a change to the Mission.
The approved Authority Set and its `intent_hash` and `authority_hash`
anchors are immutable; whether capability is contained is evaluated
state, not part of `authority_hash`, and folding it into the anchor
would make the committed authority time-varying. This is the same
argument by which the Status profile keeps an entry's fired
completion status out of the anchor
({{I-D.draft-mcguinness-oauth-mission-status}}). The overlay is held
by the Mission Issuer, versions independently, and only ever grows.

# Status: An Experimental Extension {#optional-status}

This document is optional and experimental: adopt it for evaluation,
not as a stable interface. It is a layered extension to the issuance
profile, not a change to it. A deployment that implements
{{I-D.draft-mcguinness-oauth-mission}} and never contains a Mission
is fully conformant to that profile and is unaffected by this
document: it holds no containment overlay, commits no contain
transition, and never emits the `authority_contained` denial reason.
No lifecycle state is added; a contained Mission is an `active` (or
`suspended`) Mission with a non-empty overlay.

A Mission Issuer claims conformance to this document only when it
contains a Mission; otherwise it remains a plain issuance-profile
Mission Issuer. Nothing here places a new requirement back on the
issuance profile.

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and is not
implementable alone. It reuses, without restating, that profile's
Mission, Mission Intent, Authority Set and entry shape, integrity
anchors, `mission` claim, subset rule, and lifecycle gating, and the
Status profile's state version and event-source verification
({{I-D.draft-mcguinness-oauth-mission-status}}). It uses the terms
Agent (Client), Subject, Approver, Mission Issuer, Authority Set,
Mission, and derived token as defined in the issuance profile.

Where this document refers to "the issuance profile" without a
section, it means {{I-D.draft-mcguinness-oauth-mission}} as a whole.

# Scope

This document defines:

- the containment overlay: `containment_version` and the contained
  set ({{overlay}});
- the contain transition and its monotonicity, idempotency, and
  state-legality rules ({{contain-transition}});
- protected events and the fail-closed rule for indeterminate
  reports ({{protected-events}});
- derivation gating on the Effective Authority Set
  ({{derivation-gating}});
- the Baseline and Runtime-Enforced containment properties
  ({{containment-properties}});
- the `authority_contained` denial reason ({{denial-reason}});
- visibility of containment on status and introspection surfaces
  ({{visibility}});
- propagation over the existing state machinery ({{propagation}});
- restoration, only through an approved successor Mission
  ({{restoration}});
- the containment policy and its consent seam
  ({{containment-policy}}); and
- the Containment Evidence object ({{containment-evidence}}).

This document does NOT define:

- constraint tightening within an entry (for example, lowering a
  `max_amount` ceiling); the overlay is removal-only ({{removal-only}});
- any transition that reverts containment in place; restoration is a
  successor Mission ({{restoration}});
- a dedicated containment event type for Signals consumers; the
  metadata-only lifecycle event carries the change in the interim
  ({{propagation}});
- the content of the `controls.containment` Mission Intent member; it
  is named as an extension point only ({{containment-policy}}); or
- how a deployment detects a tainted read or an anomaly; detection
  belongs to the harness, runtime, and discovery layers
  ({{protected-events}}).

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

This document uses the terms Mission, Mission Intent, Authority Set,
Mission Issuer, Mission-bound token, and delegation from
{{I-D.draft-mcguinness-oauth-mission}}, and state version from
{{I-D.draft-mcguinness-oauth-mission-status}}.

Containment overlay:
: The issuer-held, versioned record of capability removed from a
  Mission's effective authority ({{overlay}}).

Contained capability:
: A `{resource, actions}` pair in the overlay's contained set. An
  entry with no `actions` member contains the whole Authority Set
  entry for that resource.

Effective Authority Set:
: The approved Authority Set minus contained capability and, where
  the Status profile's completion capability runs, minus discharged
  entries. Every derivation gated after a contain transition is
  bounded by it; authority that left the Mission before the
  transition keeps its own bound, not this one
  ({{derivation-gating}}).

Protected event:
: An event class the containment policy declares as a containment
  trigger, whose verified occurrence commits a contain transition
  ({{protected-events}}).

Contain transition:
: The committed, metadata-only change that adds capability to the
  contained set and increments `containment_version`
  ({{contain-transition}}).

The issuance profile uses "containment" for set containment in its
subset rule; this document uses Containment for the incident-response
control. Context distinguishes them.

This document's Containment is also distinct from trifecta containment,
the runtime enforcement layer's claim that private-data exposure,
untrusted-content taint, and external-communication paths are jointly
gated for a Mission's governed work
({{I-D.draft-mcguinness-mission-runtime}}, Section "Trifecta
Containment"). Mission Containment narrows what a Mission's authority
permits; trifecta containment is a property of how a deployment
executes a Mission's work. The two compose but neither implies the
other: a Mission can be contained under this document without trifecta
containment holding, and trifecta containment can hold for a Mission
that this document has never contained.

# The Containment Overlay {#overlay}

A Mission participating in this profile carries a containment
overlay on its Mission record:

`containment_version`:
: REQUIRED. An integer, 0 at the approval event, incremented by each
  contain transition, strictly monotonic per Mission. A Mission with
  `containment_version` 0 is uncontained.

`contained`:
: REQUIRED when `containment_version` is greater than 0. An array of
  contained-capability entries. Each entry is a JSON object
  {{RFC8259}} with `resource` (REQUIRED, the `resource` of an
  approved Authority Set entry) and `actions` (OPTIONAL, an array of
  that entry's action values). An entry with no `actions` member
  contains the whole Authority Set entry.

The overlay is held by the Mission Issuer. It is not part of the
Mission Intent and not part of the Authority Set, and it never enters
`intent_hash` or `authority_hash`: the approved Authority Set and its
anchors are immutable. Whether capability is contained is evaluated
state, not part of `authority_hash`; folding containment into the
anchor would make the committed authority time-varying, exactly as
folding an entry's fired completion status into it would
({{I-D.draft-mcguinness-oauth-mission-status}}).

## Removal-Only Expressiveness {#removal-only}

The overlay removes capability; it expresses nothing else. Constraint
tightening within an entry (for example, lowering a `max_amount`
ceiling) is a named deferral: removal keeps monotonicity trivially
decidable, set union over entries, where tightening would need a
per-constraint comparator to prove each successive overlay no broader
than the last. A deployment that needs a tighter constraint contains
the affected actions and re-approves them, tightened, through a
successor Mission ({{restoration}}).

## Relationship to Entry Discharge {#discharge-relationship}

Containment composes with the Status profile's entry discharge and
duplicates none of it. Discharge retires an entry because the task
the entry was granted for is done, under a `terminal_when` condition
the Approver committed inside the Authority Set; containment removes
capability because a protected event fired, under issuer-held policy
the anchor never carried. Both are evaluated state; both commit as
metadata-only state-version increments; derivation excludes both
({{derivation-gating}}).

# The Contain Transition {#contain-transition}

A contain transition commits additions to the contained set and
increments `containment_version`. Its rules:

- **Monotonic.** A contain transition MUST only add contained
  capability: the new contained set MUST be a superset of the prior
  one, and a transition MUST NOT remove an entry, restore an action,
  or otherwise revert containment. No operation of this profile
  shrinks the overlay ({{restoration}}).
- **Idempotent per event.** Each contain transition is attributed to
  a protected event by its `event_id`. A duplicate report of the same
  `event_id` MUST NOT commit a second transition; the Mission Issuer
  answers it with the already-committed result.
- **Legal states.** A contain transition is legal from `active` and
  from `suspended`, and MUST be refused in every terminal state. A
  `resume` does not clear the overlay: a Mission suspended, contained,
  and resumed returns to `active` still contained.
- **No state change.** The transition changes no lifecycle state: a
  contained `active` Mission remains `active`. Containment narrows
  what the Mission can do, never whether it runs.

Each contain transition is a committed metadata-only change for the
purposes of the state version, which the Status profile defines as
"incremented on each committed lifecycle transition (the approval
event is version 1) and each committed metadata-only change"
({{I-D.draft-mcguinness-oauth-mission-status}}): the Mission's state
version increments at the commit, so a materialized policy view that
commits a state version ({{I-D.draft-mcguinness-mission-runtime}}) is
detectably obsolete after a containment.

# Protected Events {#protected-events}

The containment policy ({{containment-policy}}) declares the event
classes that trigger containment. Representative classes, defined by
their own layers, not here: a tainted read under the harness taint
policy ({{I-D.draft-mcguinness-mission-harness}}), an anomaly signal
from the deployment's monitoring, and the tainted-session event of
open-world discovery ({{I-D.draft-mcguinness-mission-discovery}}).

A protected event is a trusted input to authority: the Mission Issuer
MUST authenticate and integrity-verify an event source outside its
own trust domain before acting on its report. The Status profile's
signed event-source profile, a JWS status document verified against
the `source` identity rather than the transport origin, is the
interoperable mechanism
({{I-D.draft-mcguinness-oauth-mission-status}}).

A protected event whose authenticity or applicability is
indeterminate fails closed. The Mission Issuer MUST either commit the
narrowing the policy maps to the event or withhold derivation of the
implicated capability until the report is resolved; it MUST NOT
ignore the event. An unverifiable report can cost the Mission
authority early; it can never preserve authority the policy would
have removed.

The Mission Issuer MUST record a Protected Event Receipt for every
protected event it receives, whether the event is applied as a contain
transition or rejected ({{protected-event-receipt}}). Fail-closed means
the event is rejected rather than acted on; it never means the event
goes unrecorded.

# Derivation Gating {#derivation-gating}

A credential derived or delegated after a contain transition MUST NOT
carry contained capability. Token derivation under a contained Mission
MUST evaluate the request against the Effective Authority Set, with
the issuance profile's subset rule unchanged:

- a derivation request whose authority lies entirely within the
  contained set MUST fail, with the `authority_contained` denial
  reason ({{denial-reason}});
- a derivation request covering both contained and uncontained
  capability MUST omit the contained capability: the issued token
  carries only the uncontained remainder; and
- tokens already issued before the transition are the same residual
  that revocation carries, bounded the same way by their own `exp`
  and the deployment's freshness rules ({{propagation}}).

The same bound applies wherever authority leaves the Mission, for every
derivation gated after the transition. A Child Mission attenuates from
the parent's Effective Authority Set, so a contained capability is
absent from every child derivation gated after the transition; a
contain transition also propagates entry-wise to every Child Mission
already justified by the contained entry, so an existing child does not
keep deriving it either
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
"Child Mission State"). A cross-domain projection issued after the
transition projects the Effective Authority Set, so a contained
capability is absent from it
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). An offline
attenuation root issued after the transition is derived from the
Effective Authority Set, so no offline chain minted from it can narrow
its way back to contained capability
({{I-D.draft-mcguinness-oauth-mission-attenuation}}).

What derivation gating and propagation do not reach is authority
already materialized, before the transition, into a standing minting
capability outside the issuer's control: a cross-domain projection
grant already redeemed at a Resource AS, or an offline attenuation root
already minted into a holder's possession. That residual is bounded on
its own terms, not by this document ({{materialized-residual}}).

# The Materialized-Capability Residual {#materialized-residual}

Derivation gating stops the Mission Issuer from minting new contained
authority, and propagation ({{propagation}}) carries a contain
transition to every existing Child Mission it justified. Neither
reaches authority the Mission already turned, before the transition,
into a standing minting capability the issuer does not hold:

- a cross-domain projection grant a Resource AS already redeemed
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) keeps minting
  local tokens from that grant for the grant's own lifetime, because
  the Resource AS re-derives nothing from the Mission and holds no
  overlay to consult; and
- an offline attenuation root already minted into a holder's
  possession ({{I-D.draft-mcguinness-oauth-mission-attenuation}})
  keeps minting narrower offline children for its own `del_max_depth`
  and lifetime, because the attenuation substrate defines no channel
  back to the issuer for either artifact to learn of the transition.

This residual is the same shape as the residual an already-issued
access token carries under revocation
({{I-D.draft-mcguinness-oauth-mission}}, Section "Revocation"):
authority materialized before a narrowing event outlives the event,
bounded by the artifact's own lifetime rather than by a check this
document adds. Containment does not widen what either artifact can do;
it only fails to reach it early.

Closing this gap is a lifetime problem, not a protocol gap this
document can add a check for: a deployment that relies on containment
to bound cross-domain projection or offline attenuation SHOULD keep
grant and root lifetimes short and lease or re-mint on a cadence
shorter than its containment response target, so the next lease or the
next root falls after the contain transition and picks up the narrowed
Effective Authority Set.

# Containment Properties {#containment-properties}

{{derivation-gating}} and {{materialized-residual}} together state one
containment property; a second exists only where the substrate
supports it. What a consumer actually gets depends on which one it
relies on:

Baseline:
: a new-derivation kill. From the transition forward, no derivation,
  delegation, projection, or attenuation root minted after it carries
  contained capability ({{derivation-gating}}). A token issued before
  the transition, or capability already materialized outside the
  issuer's reach, can still carry the removed capability until that
  artifact's own lifetime runs out ({{materialized-residual}}).
  Baseline needs nothing of a consumer beyond the ordinary bearer
  check, signature and `exp`: it is the property a lifecycle-gated
  substrate provides ({{I-D.draft-mcguinness-mission-substrate}}).

Runtime-Enforced:
: an action-time kill. A consumer that checks a fresh, authenticated
  state source at or near the time of the action, Mission Status,
  introspection, or the runtime layer's PDP, denies contained
  capability whether or not the credential it evaluates predates the
  transition, bounded by that source's staleness plus the permit and
  execution windows ({{I-D.draft-mcguinness-mission-runtime}}).
  Runtime-Enforced requires the substrate to be state-observable
  ({{I-D.draft-mcguinness-mission-substrate}}); a consumer that never
  consults such a source gets Baseline only, however long the Mission
  has been contained.

Neither property is a deployment failure: a consumer that only checks
`exp` is a fully conformant Baseline consumer, and its exposure to
contained capability is bounded by token lifetime, not by a defect in
this document.

# The authority_contained Denial Reason {#denial-reason}

`authority_contained`:
: The requested capability was approved for this Mission and is
  currently contained.

The distinction from the runtime enforcement layer's
`out_of_authority`, the action not within the Authority Set
({{I-D.draft-mcguinness-mission-authzen}}), is approval history:
`out_of_authority` reports capability that was never approved, and
`authority_contained` reports capability the Approver granted and the
issuer then contained. That history is what makes the denial
expansion-eligible: once-approved authority is a candidate for
re-adjudication ({{restoration}}), where never-approved authority is
an ordinary out-of-authority denial.

At the token endpoint the denial uses the issuance profile's error
vocabulary for a request outside the derivable authority and MAY
additionally carry `authority_contained` in the shared
`mission_denial_reason` member the expansion profile registers
({{I-D.draft-mcguinness-oauth-mission-expansion}}). A runtime
enforcement deployment carries it as a denial-reason identifier
alongside the classification set of
{{I-D.draft-mcguinness-mission-authzen}}. A consumer MUST treat an
unrecognized reason code as a denial with no further semantics.

Consistent with the expansion profile, the classification of a denial
as expansion-eligible belongs to the component that denies the
action; this document classifies `authority_contained` as
expansion-eligible, and eligibility is not an authorization in favor
of expansion.

# Visibility {#visibility}

A contained Mission MUST NOT present contained capability as live.
When this profile runs:

- the `mission` object of the Mission Status Response and the token
  introspection Mission projection MUST carry `containment_version`
  ({{I-D.draft-mcguinness-oauth-mission-status}});
- any surface of those profiles that discloses Mission authority MUST
  omit contained capability or annotate it as contained; and
- a `mission.lifecycle-change` event MUST carry `containment_version`,
  and MAY carry `authority_hash`
  ({{I-D.draft-mcguinness-oauth-mission-signals}}, {{propagation}}).

A consumer that does not understand `containment_version` ignores it;
the state version already makes the change observable
({{contain-transition}}). A consumer that reads it holds a precise
question: whether the authority view it materialized predates the
current overlay.

# Propagation {#propagation}

Containment rides the existing state-propagation machinery and adds
none:

- **Pull.** The contain transition's state-version increment moves
  the Mission Status Response: the next read reports the new
  `version` and `containment_version`, and a materialized view naming
  an older version is detectably obsolete ({{contain-transition}}).
- **Status List.** A contained `active` Mission stays `active`, so
  its Status List bit is unchanged: the list carries reliance bits
  only, and containment detail, like the state version, stays on the
  authoritative surfaces
  ({{I-D.draft-mcguinness-oauth-mission-status}}). Containment binds
  derivation at the issuer, so a list-only consumer's staleness never
  widens what a contained Mission can issue.
- **Push.** Where Signals runs, the commit is emitted as a
  `mission.lifecycle-change` whose `state` equals its `prior_state`,
  that profile's metadata-only shape, incrementing `version` like any
  other committed change, and carrying the Mission's current
  `containment_version` and, optionally, its `authority_hash` as a
  reference to the Authority Set the overlay narrows
  ({{I-D.draft-mcguinness-oauth-mission-signals}}). This makes an
  active-to-active version bump legible to a containment-aware
  consumer as an authorization change, rather than an opaque version
  increment. A dedicated containment event type is deferred; carrying
  `containment_version` on the existing event is what keeps that
  change legible in the interim.

How quickly a consumer must adopt the narrowed view is bounded by the
freshness and staleness rules it already operates under
({{I-D.draft-mcguinness-oauth-mission-status}},
{{I-D.draft-mcguinness-mission-runtime}}); this document does not
restate them.

# Restoration Through Expansion {#restoration}

Contained authority returns only as a new approval. No transition of
this profile removes capability from the overlay; the path back is a
successor Mission adjudicated under the expansion profile
({{I-D.draft-mcguinness-oauth-mission-expansion}}), whose authority
comes only from its own approval event. An `authority_contained`
denial is the expansion-eligible signal for that path
({{denial-reason}}).

Two rules close the laundering gap between containment and
expansion:

- Containment MUST NOT propagate to a successor: the successor's
  overlay starts empty, `containment_version` 0, because its
  authority is whatever its own approval yields, not the
  predecessor's minus a memory.
- An expansion whose predecessor has a non-empty containment overlay
  MUST surface the predecessor's containment history in the expansion
  consent disclosure: at minimum the contained capability and the
  event class that contained each entry.

Together they keep the successor clean without letting it launder:
capability removed for cause can return, but only past an Approver
who saw the cause.

That guarantee is only as strong as the disclosure's own integrity
reaching the Approver unaltered, and the issuance profile does not
itself anchor consent-disclosure integrity. Where an implementation
needs the containment history surfaced at expansion consent to be
non-repudiable, it SHOULD commit that disclosure under the Consent
Evidence companion's consent-disclosure commitment
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) rather than
rely on an unattested record of what the Approver was shown.

# Containment Policy {#containment-policy}

The map from protected event class to narrowing is the containment
policy. It is issuer-held, parallel to the derivation policy by which
the issuance profile derives the Authority Set: an input the issuer
applies at a committed change, never content of the anchor. The
client does not supply it, the Mission Intent does not carry it, and
an intent-shaping component does not write it: a compromised agent,
client, or shaping component MUST NOT be able to select which events
contain or how far a containment narrows.

A deployment may want the Approver to consent to tightened
containment behavior at approval time. `controls.containment`, a
member of the Mission Intent's `controls` object under the issuance
profile's extensibility rules, is named here as that extension point;
its content is explicitly not defined by this document. An
Approver-consented member can only tighten what the issuer-held
policy would do, never loosen it.

# Containment Evidence {#containment-evidence}

The Mission Issuer MUST record a Containment Evidence object for each
contain transition. This evidence is audit material and does not
grant authority.

## Containment Evidence Object {#evidence-object}

A Containment Evidence object is a JSON object {{RFC8259}} with:

`evidence_id`:
: REQUIRED. Unique identifier.

`mission`:
: REQUIRED. Mission reference: `id`, `issuer`, and `authority_hash`.

`event`:
: REQUIRED. The protected event: `type`, `source`, `observed_at` (an
  RFC 3339 {{RFC3339}} date-time), and `event_id`.

`policy`:
: REQUIRED. Identifier of the containment policy rule applied.

`prior_version`, `new_version`:
: REQUIRED. The Mission's state version before and after the
  transition.

`prior_containment_version`, `new_containment_version`:
: REQUIRED. The overlay's version before and after the transition.

`removed`:
: REQUIRED. The contained-capability entries this transition added
  ({{overlay}}).

`created_at`:
: REQUIRED. RFC 3339 {{RFC3339}} timestamp of the commit.

Example:

~~~ json
{
  "evidence_id": "cnt_4Tq9mV2xLp",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6"
  },
  "event": {
    "type": "session-taint",
    "source": "https://harness.example.com",
    "observed_at": "2026-11-02T09:41:00Z",
    "event_id": "evt_7pQ4mK1c"
  },
  "policy": "contain-egress-on-taint-v3",
  "prior_version": 4,
  "new_version": 5,
  "prior_containment_version": 0,
  "new_containment_version": 1,
  "removed": [
    { "resource": "https://mail.example.com",
      "actions": ["messages.send"] }
  ],
  "created_at": "2026-11-02T09:41:02Z"
}
~~~

## Canonical Bytes {#evidence-canonical}

A Containment Evidence object's canonical bytes are its JCS
{{RFC8785}} canonicalization, and its type identifier is
`application/mission-containment-evidence+json`, used by local
agreement pending registration. An audit or transparency profile
registers the object by these values.

# Protected Event Receipt {#protected-event-receipt}

Containment Evidence records the transition a protected event drove;
it has no object for a protected event the Mission Issuer rejected. The
Mission Issuer MUST also record a Protected Event Receipt for the
ingestion decision on every protected event it receives
({{protected-events}}), whatever the outcome, so a rejected report is
recorded rather than only silently withheld.

A Protected Event Receipt is a JSON object {{RFC8259}} with:

`receipt_id`:
: REQUIRED. Unique identifier.

`mission`:
: REQUIRED. Mission reference: `id`, `issuer`, and `authority_hash`.

`event`:
: REQUIRED. The protected event, in the form Containment Evidence
  carries it: `type`, `source`, `observed_at` (an RFC 3339 {{RFC3339}}
  date-time), and `event_id`.

`outcome`:
: REQUIRED. One of `applied` or `rejected`.

`policy`:
: CONDITIONAL. Identifier of the containment policy rule applied.
  REQUIRED when `outcome` is `applied`; matches the `policy` member of
  the Containment Evidence object the transition committed
  ({{evidence-object}}).

`rejection_reason`:
: CONDITIONAL. A string. REQUIRED when `outcome` is `rejected`: the
  reason the event was not applied (for example, an unverifiable
  signature, a source not trusted for the reported event type, or a
  Mission the event does not name or that is in a terminal state). A
  deployment MAY define additional values, which MUST be
  collision-resistant names, following the Collision-Resistant Name
  guidance of {{RFC7519}} Section 4.2.

`emitter`:
: REQUIRED. An object, in the form Decision Evidence defines
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}), with `role`
  `issuer`.

`created_at`:
: REQUIRED. RFC 3339 {{RFC3339}} timestamp of the ingestion decision.

Example, a rejected report:

~~~ json
{
  "receipt_id": "per_9wLq3XtN7m",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQrR6"
  },
  "event": {
    "type": "session-taint",
    "source": "https://harness.example.com",
    "observed_at": "2026-11-02T09:40:55Z",
    "event_id": "evt_2mK7pQ4c1x"
  },
  "outcome": "rejected",
  "rejection_reason": "source_not_trusted_for_type",
  "emitter": { "id": "as.example.com", "role": "issuer" },
  "created_at": "2026-11-02T09:40:56Z"
}
~~~

A Protected Event Receipt's canonical bytes are its JCS {{RFC8785}}
canonicalization, and its type identifier is
`application/mission-protected-event-receipt+json`, used by local
agreement pending registration, mirroring the Child and Discovery
Evidence registration conventions
({{I-D.draft-mcguinness-mission-audit}}). An audit or transparency
profile registers the object by these values.

An `applied` receipt's `event_id` correlates it to the Containment
Evidence object the same event produced ({{evidence-object}}); a
`rejected` receipt has no corresponding Containment Evidence, because
no transition committed.

# Conformance {#conformance}

An implementation claims conformance to this document only in the
Mission Issuer role and only when it contains a Mission. A conforming
**containment-capable Mission Issuer** MUST:

- hold the containment overlay per Mission and commit contain
  transitions under the monotonicity, idempotency, and state-legality
  rules of {{contain-transition}};
- verify protected events and fail closed on an indeterminate report
  ({{protected-events}});
- gate every derivation, delegation, projection, and attenuation root
  on the Effective Authority Set, and deny an all-contained request
  with `authority_contained` ({{derivation-gating}},
  {{denial-reason}});
- where it also implements Child Delegation, propagate a contain
  transition entry-wise to every existing Child Mission the contained
  entry justified ({{I-D.draft-mcguinness-oauth-mission-child-delegation}},
  Section "Child Mission State");
- carry `containment_version` on its status and introspection
  surfaces and never present contained capability as live
  ({{visibility}});
- record a Containment Evidence object per contain transition
  ({{containment-evidence}});
- record a Protected Event Receipt for the ingestion decision on every
  protected event received, applied or rejected
  ({{protected-event-receipt}}); and
- where it also adjudicates expansion, start the successor
  uncontained and surface the predecessor's containment history at
  the expansion consent ({{restoration}}).

A containment-capable Mission Issuer is also a conforming
issuance-profile Mission Issuer
({{I-D.draft-mcguinness-oauth-mission}}). Containment gives every
Resource Server the Baseline property with no change to the Resource
Server; the Runtime-Enforced property additionally requires it to
consult a fresh state source ({{containment-properties}}). "No new
behavior" holds only for a Resource Server that relies on Baseline: a
token issued after the contain transition never carries contained
capability, and a token issued before the transition can still carry
it until that token's own expiry ({{containment-properties}}).

# Security Considerations {#security-considerations}

Containment's guarantee is directional: every rule in this document
moves authority in one direction, down. The risks specific to it are
who can force that movement and what the movement discloses.

## Forced Premature Containment {#forced-containment}

Containment is monotonic by construction: it only removes capability,
so it is not a path to escalation, and a compromised or injected
agent cannot use a protected event to widen authority. The worst a
forged or forced event achieves is a forced premature containment, a
denial-of-service on the task: authority the task still needs is
withdrawn. This is the same residual the Status profile carries for
forced premature discharge, bounded the same way: the event-source
authentication, integrity, and fail-closed rules of
{{protected-events}} bound who can force it, and restoration remains
available through a fresh approval ({{restoration}}).

## The Containment Plane {#containment-plane}

Whatever surface applies contain transitions, the issuer's event
intake or an operator plane, holds a denial capability over live
work. It is operator trust: a deployment MUST authenticate and
authorize callers of that surface as it does lifecycle mutation, and
SHOULD govern bulk containment with the same dry-run-first posture as
bulk lifecycle operations
({{I-D.draft-mcguinness-oauth-mission-management}}).

## Compromised Event Source {#compromised-source}

A compromised event source can fire protected events at will.
Monotonicity bounds its blast radius: every transition it forces
yields too little authority, never too much. The overlay it inflates
cannot be spent, delegated, or projected in any derivation gated after
the transition, and propagation carries it to every Child Mission the
contained entry already justified
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
"Child Mission State"). The exception is the same one any adversary
faces: the materialized-capability residual
({{materialized-residual}}), bounded by the affected artifact's own
lifetime regardless of which event forced the transition. Recovery is
bounded too: the poisoned Missions are enumerable from their
Containment Evidence, and each restores only through an approval that
sees the containment history ({{restoration}}).

## Containment History at Expansion {#history-at-expansion}

The disclosure rule of {{restoration}} is load-bearing: without it,
expansion is a laundering path in which capability removed for cause
returns through a successor the Approver believes is clean. An
implementation that omits the predecessor's containment history from
the expansion consent defeats containment for any adversary patient
enough to ask again.

# Privacy Considerations {#privacy-considerations}

A containment overlay discloses incident posture: that an event
fired, which capability it implicated, and when. The Mission Status
Response and introspection surfaces carry `containment_version` and
any containment annotations only to callers those profiles already
authenticate and authorize; this document adds no anonymous surface
and preserves the Status profile's anti-oracle posture
({{I-D.draft-mcguinness-oauth-mission-status}}). Containment Evidence
and the Protected Event Receipt both carry event detail (`type`,
`source`, `event_id`) and are audit material: a deployment retains and
discloses them under the same access rules as its other Mission
evidence, and SHOULD NOT copy event detail onto broader surfaces than
the audit trail requires. A rejected receipt additionally discloses
that a report was made and refused, which is itself incident posture
under the same rule.

# IANA Considerations {#iana}

This document requires no IANA action.

The `containment_version` member and any containment annotation ride
surfaces whose defining profile establishes no per-member registry
(the `mission` object of the Mission Status Response and the
introspection Mission projection,
{{I-D.draft-mcguinness-oauth-mission-status}}); consistent with those
surfaces' rules, a consumer ignores an unrecognized member.

`authority_contained` extends, by specification, the closed set of
reason codes carried in the shared `mission_denial_reason` member;
that member's registrations are the expansion profile's, and this
document creates no registry for the codes, consistent with that
profile's plan for a future shared "Mission Denial Reason" registry
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

The Containment Evidence type identifier
`application/mission-containment-evidence+json` is used by local
agreement pending registration ({{evidence-canonical}}).

The Protected Event Receipt type identifier
`application/mission-protected-event-receipt+json` is used by local
agreement pending registration ({{protected-event-receipt}}).

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth
2.0 set and defines the in-Mission narrowing complement to Mission
Expansion's widening.

--- back
