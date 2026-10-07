---
title: "Mission Entry Discharge for OAuth 2.0"
abbrev: "OAuth Mission Discharge"
category: std

docname: draft-mcguinness-oauth-mission-discharge-latest
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
 - completion
 - discharge
 - lifecycle
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-discharge.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC5234:
  RFC6838:
  RFC7515:
  RFC7662:
  RFC8725:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
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

informative:
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The Mission Status and Lifecycle profile for OAuth 2.0 defines a
Mission Lifecycle endpoint with Mission-level `revoke`, `suspend`,
`resume`, and `complete` operations, but has no notion of a single
approved Authority Set entry being done independently of the Mission
as a whole. This document defines that entry grain: `terminal_when`,
an OPTIONAL Common Constraint on a `mission_resource_access` entry
naming one or more completion conditions, and the authenticated
`discharge` operation, registered as an extension on the Mission
Lifecycle endpoint, that commits a condition's firing. Discharge is
monotonic, entry-scoped, and safe against a compromised or
prompt-injected agent: it can only retire authority sooner, never
widen it. It is optional and builds on Mission-Bound Authorization
for OAuth 2.0, its Mission Resource Access Profile, and the Mission
Status and Lifecycle profile; a deployment that does not adopt it is
unaffected.

--- middle

# Introduction

This document is a satellite of the Mission Status and Lifecycle
profile {{I-D.draft-mcguinness-oauth-mission-status}} ("the Status
profile"), adding an entry-grain completion mechanism.

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") gates
issuance on Mission state but has no notion of an approved entry
being **done**, and the Status profile's Mission Lifecycle endpoint
operations ({{I-D.draft-mcguinness-oauth-mission-status}}) act on the
whole Mission, not one Authority Set entry.

This document supplies that enforceable counterpart. It registers
`terminal_when`, an OPTIONAL Common Constraint
({{I-D.draft-mcguinness-oauth-mission-resource-access}}) on a
`mission_resource_access` entry that carries one or more completion
conditions, and it registers `discharge` ({{discharge-operation}}) as
an extension `operation` value on the Status profile's Mission
Lifecycle endpoint, authenticated and authorized independently of
that endpoint's other operations, that commits a condition's firing.
When a condition is met, the entry is **discharged**: the
Authorization Server no longer derives a token carrying that entry
({{discharge}}), exactly as it refuses derivation for a non-`active`
Mission. {{completion}} states the properties this mechanism requires
and the threat analysis, including why a prompt-injected agent cannot
use discharge to escalate, is given in {{completion-security}}.

This document is optional and depends normatively on the issuance
profile, its Mission Resource Access Profile, and the Status profile;
it is not implementable alone. It places no new requirement on the
issuance profile or the Status profile: it defines one OPTIONAL entry
member, one OPTIONAL Mission Lifecycle extension operation, and the
rules for handling them. A deployment that ends an entry's authority
only by Mission revocation or expiry is fully conformant to
the issuance profile and is unaffected by this document. A deployment
claims this capability only when it issues or consumes entries
carrying `terminal_when`. The capability is newer and less exercised
than baseline issuance and runtime enforcement, and is not required by
any Mission Assurance Level; its details may change.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This document uses the terms defined in the issuance profile
{{I-D.draft-mcguinness-oauth-mission}}, in particular Mission, Mission
Issuer (the Mission `issuer`: in this document's OAuth binding the
Authorization Server), Authority Set, and `mission_id`; the
`mission_resource_access` authorization details type and Common
Constraints defined in its Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}); and the
Mission Lifecycle endpoint, Mission Status Response, Discharge, and
Effective Authority Set terms of the Status profile
({{I-D.draft-mcguinness-oauth-mission-status}}).

All JSON shown in this document is non-normative and illustrative;
the member definitions in the surrounding text are authoritative.

# Mission Entry Discharge {#completion}

Without entry discharge, a Mission granted authority to release a
record "for this enrollment" keeps deriving that authority after the
enrollment closes, until a clock or a revoke stops it. The Intent's
prose can say when the task is complete, but the issuance profile
keeps it inert: it is rendered and committed, and carries no machine
effect ({{I-D.draft-mcguinness-oauth-mission}}).

Three properties make discharge safe inside the Mission model, and
this section requires all three:

- **Discharge is monotonic.** It only removes an entry's authority; it
  can never widen the entry or the Mission.
- **Discharge composes with the subset rule.** A derived entry carries
  its parent's completion conditions unchanged and MAY add more, the same
  way constraints may be added or tightened but never dropped.
- **Discharge fails closed on the constraint.** A consumer that does
  not understand `terminal_when` refuses the entry rather than
  ignoring the condition.

The threat analysis of these properties, including why a
prompt-injected agent cannot use discharge to escalate and the
forced-premature-discharge residual, is given in
{{completion-security}}.

Discharge gates at the entry, not the Mission ({{discharge}}). It
strengthens the kill switch: a task that finishes stops issuing its
own authority without waiting for a clock or a revoke.

## Relationship to the Issuance Profile {#issuance-relationship}

The completion capability depends normatively on the issuance profile
and on its Mission Resource Access Profile
({{I-D.draft-mcguinness-oauth-mission-resource-access}}), and is not
implementable alone. It reuses, without restating, the issuance
profile's Mission, Authority Set, subset rule, integrity anchors,
lifecycle states, and issuance gating; and the Mission Resource Access
Profile's `mission_resource_access` entry and Common Constraints
registry. It uses Mission, Mission Issuer, Authority Set, and
derivation as the issuance profile defines them, and the
`mission_resource_access` entry as the Mission Resource Access Profile
defines it.

It extends the Mission Resource Access Profile in one narrow, additive
way: it registers `terminal_when`, an OPTIONAL Common Constraint on a
`mission_resource_access` entry ({{terminal-when}}), whose subset rule
that profile's existing subset comparison applies
({{subset-extension}}). It changes no Mission lifecycle state and no
meaning of any existing member.

## Entry Completion Conditions {#terminal-when}

This section defines `terminal_when`, a Common Constraint
({{I-D.draft-mcguinness-oauth-mission-resource-access}}) carried in
the `constraints` object of a `mission_resource_access` entry. It is a
specification-defined Common Constraint under the Mission Resource
Access Profile's naming convention ({{iana}}).

`terminal_when`:
: OPTIONAL. An array of one or more completion conditions. When any
  condition is
  met, the entry is discharged ({{discharge}}). Each condition is an
  object with these members:

  `event_type`:
  : REQUIRED. A string identifying the completion event. Its semantics
    are deployment- or registry-defined and opaque to this document, as
    `purpose` is ({{I-D.draft-mcguinness-oauth-mission}}).

  `discharge_authority`:
  : OPTIONAL. A string, `1*64( ALPHA / DIGIT / "-" / "_" / ":" / "." )`
    {{RFC5234}}, opaque. It names the authority approved to assert
    this condition, which the AS resolves to its discharge-authority
    mapping ({{discharge-authority}}).

The `terminal_when` array is part of the entry's `constraints` and so of
the Authority Set: it is committed by `authority_hash` and reproducible
under derivation ({{I-D.draft-mcguinness-oauth-mission}}). Condition
identity is byte equality of the condition object's canonical form
under the issuance profile's canonicalization; an AS refuses a value
carrying two identical conditions, and an intersection of two arrays
deduplicates by that identity and sorts by the lexicographic order of
the canonical bytes ({{iana-terminal-when}}), so the intersected entry
is one reproducible array. Whether a
condition has fired is evaluated state, not part of `authority_hash`;
folding fired status into the anchor would make the committed authority
time-varying.

`condition_digest`, used to select a condition on the `discharge`
operation ({{discharge-operation}}), is a canonical-object digest
({{I-D.draft-mcguinness-oauth-mission}}) over the exact canonical bytes
of the single condition object, in the issuance profile's encoded
form: the same canonical form the registration's no-duplicate rule
above already fixes as condition identity ({{iana-terminal-when}}).

`terminal_when` is the enforceable statement of when one entry is
complete. It says nothing about whether the task as a whole
succeeded, and the Intent's prose stays inert
({{I-D.draft-mcguinness-oauth-mission}}). It is distinct from a
cumulative
consumption bound, which meters volume;
a `terminal_when` condition is a single external event.

## Discharge and Issuance Gating {#discharge}

When a condition in an entry's `terminal_when` has been met, the entry is
discharged. The Authorization Server MUST NOT derive a token carrying a
discharged entry, at the token endpoint, on refresh, or on Token
Exchange, exactly as issuance is refused for a non-`active` Mission
({{I-D.draft-mcguinness-oauth-mission}}). A derivation that would carry
only discharged entries MUST fail. A derivation that carries a mix MUST
omit the discharged entries.

Discharge gates at the entry, not the Mission. The Mission remains
`active` and continues to derive its other entries: a multi-resource
Mission therefore completes partially, one entry at a time, as each
entry's task finishes. The issuance profile's Mission states are
unchanged; a deployment that also tracks Mission-level completion MAY
transition a Mission whose entries are all discharged to the
`completed` state the Status profile's Mission Lifecycle endpoint
defines ({{I-D.draft-mcguinness-oauth-mission-status}}), but this
section does not require it. Such a transition is performed through
the Status profile's `complete` operation, as an issuer-initiated
lifecycle operation, so the consolidated state machine's event sources
remain authoritative
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Consolidated
State Machine").

Discharge gates new derivations only. A token already issued for an entry
remains valid until it expires, as with revocation
({{I-D.draft-mcguinness-oauth-mission}}). A deployment that needs prompt
cutoff relies on short token lifetimes or on the runtime layer denying a
discharged entry at the point of use ({{runtime}}).

### Discharge Visibility {#visibility}

A discharged entry is no longer derivable, so the surfaces that report a
Mission's authority MUST reflect that. Where the Status profile's
Mission Status operation and the token introspection projection are
deployed, they MUST omit a discharged entry from the
`authorization_details` they return
({{I-D.draft-mcguinness-oauth-mission-status}}, Sections "Mission
Status Operation" and "Token Introspection Mission Projection"). This
is consistent with the audience filtering those surfaces already
apply: a discharged entry, like an entry addressed to another
audience, is not authority the caller may rely on.

Where Signals is deployed, a discharge commit rides the
`mission.lifecycle-change` event's generic `authority_changed`
discriminator {{I-D.draft-mcguinness-oauth-mission-signals}}: an
active-to-active event carrying it signals that the Mission's
effective authority narrowed even though `state` did not change.

## Subset Rule {#subset-extension}

Because `terminal_when` is a Common Constraint, the issuance profile's
subset comparison ({{I-D.draft-mcguinness-oauth-mission}}) applies its
defined subset rule with no new clause: for a key present in the
reference entry's `constraints`, the same key MUST be present in the
candidate entry and its value MUST be no broader under the key's
defined rule.

For `terminal_when`, a candidate value is no broader
than a reference value when the candidate's condition array contains
every condition of the reference, compared structurally after the
canonicalization of the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}); the candidate MAY add further
conditions.

Conditions are compared structurally, not by event semantics. A child
cannot drop or alter a parent's completion condition, only add more, so
discharge composes monotonically: an added condition can only make an
entry discharge sooner, which is a narrowing. Modifying a parent
condition is forbidden because a verifier cannot decide whether the
change discharges earlier or later from opaque `event_type` values.

## Forward Compatibility {#forward-compat}

Because `terminal_when` is a `constraints` member, a consumer that does
not recognize it fails closed by the issuance profile's Resource Server
enforcement rule directly: a consumer MUST fail closed on any
`constraints` key it does not understand, or understands but cannot
enforce, refusing the request rather than granting access while ignoring
the key ({{I-D.draft-mcguinness-oauth-mission}}). Discharge is
load-bearing narrowing, so ignoring `terminal_when` would silently widen
the grant. That enforcement rule is the honest basis of discharge's
safety: an unrecognized `terminal_when` is refused, never dropped.

An Authorization Server that does not implement this capability simply
does not emit `terminal_when`, and is unaffected. The fail-closed rule
binds a consumer that encounters the constraint without implementing
it.

## Derivation Guidance {#derivation-guidance}

This guidance is non-normative. When the Authorization Server derives an
entry from the Mission Intent, a reviewable rule governs what each
element of the Intent becomes:

- an `action` if removing it would leave the task undefined;
- an ordinary `constraints` member if removing it would merely make the
  task less restrictive; and
- a `terminal_when` completion condition, itself a `constraints` member,
  if it defines when the task is satisfied, retiring the entry's
  authority rather than widening or restricting it.

The third case is what this capability adds. A bound that holds
throughout the task is an ordinary constraint; an event that ends the
task is a `terminal_when` condition. For example, "only invoices under
500 USD" is a `max_amount` constraint, while "until the Q3 close is
finalized" is a completion condition.

## Relationship to Runtime Enforcement {#runtime}

Discharge is an issuance-gating signal and is fully meaningful at the
issuance profile alone: issuance-only discharge is a conforming
posture, with the residual that a credential issued before a discharge
stays valid until it expires ({{discharge}}). Where the deployment also
runs the runtime profile, that profile requires its PDP to refuse a
discharged entry at the point of use
({{I-D.draft-mcguinness-mission-runtime}}), closing the window between
discharge and token expiry the same way it refuses a revoked Mission. A
Policy Enforcement Point learns that an entry is discharged from the
Status profile's Mission Status operation or the token introspection
projection ({{visibility}}), the same way it learns a Mission is
revoked. A runtime Policy Enforcement Point that does not recognize
`terminal_when` fails closed for the entry per {{forward-compat}}.

For that point-of-use denial this document defines the denial-reason
identifier `authority_discharged`, a family-coordinated name under the
AuthZEN profile's denial-reason extension rule
({{I-D.draft-mcguinness-mission-authzen}}), carried wherever the
runtime layer's denial reasons travel: the decision response's
`context.reason` and the runtime evidence companion's
`denial_reason`. It means the entry was approved and its completion
condition fired, so the Mission Issuer discharged it: distinct from a
containment denial (trust withdrawn) and from an out-of-authority
denial (never approved). A consumer treats an unrecognized value as a
deny under the binding's own rule; no other semantics attach.

# Determining Discharge {#determining}

A discharge is committed one of two ways: through the `discharge`
operation ({{discharge-operation}}), or by deployment-internal
adjudication the issuer trusts ({{internal-adjudication}}). Either
way, {{discharge-commit}} governs the committed discharge. This
document defines no interoperable event-source polling profile of its
own: the `discharge` operation is the interoperable path. An
event-driven deployment wires its event bus to the lifecycle call.

## Discharge Commit {#discharge-commit}

Every committed discharge, whichever way it is determined, has these
semantics:

- **Entry-level OR latch.** The entry's `terminal_when` discharges on
  any condition being met ({{terminal-when}}). The committed state is
  one monotonic latch on the entry, or on its selector equivalence
  class, one state-version increment, one audit record, and one
  notification. Issuance gating for a discharged entry is unchanged
  ({{discharge}}).
- **Duplicate entries.** One `entry_digest` discharges every
  recorded entry resolving to that digest as a single
  equivalence-class transition, and therefore one version increment,
  under the Authority Set entry commitment's selector
  equivalence-class rule
  ({{I-D.draft-mcguinness-oauth-mission}}).
- **States.** Discharge applies while the Mission is `active` or
  `suspended`: a suspended Mission still narrows monotonically. A
  discharge determined after the Mission reaches `completed`,
  `revoked`, `expired`, or another terminal state MUST NOT create a
  transition or a version increment. Discharge never changes
  Mission-level state; a deployment that also tracks all-entry
  completion invokes the Status profile's `complete` operation
  separately ({{I-D.draft-mcguinness-oauth-mission-status}}).
- **Atomicity.** The entry latch (or its equivalence-class latch), the
  version increment, the audit and result record, and the durable
  propagation work (an outbox entry or a signal enqueue) commit as
  one unit. Where the deployment emits lifecycle events
  ({{I-D.draft-mcguinness-oauth-mission-signals}}), the signal enqueue
  is part of that same unit. Downstream materialization from the
  durable propagation work, including the child-delegation profile's
  entry-wise propagation to an already-justified Child Mission
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), is
  asynchronous and is not claimed atomic with this commit. Instead, a
  Child Mission's derivation MUST consult, or otherwise be gated by,
  the committed parent latch until that materialization completes, so
  no Child Mission can derive the discharged parent authority in the
  gap between the parent's commit and the child's materialized view.
- **Propagation.** The Mission Issuer MUST propagate a committed
  discharge to a Child Mission's entry exactly when that entry carries
  the fired condition and its recorded justification is the discharged
  entry, or, recursively, an entry the discharge has already reached.
  The recorded justification is the parent entry each child entry was
  derived from, which the child-delegation profile selects
  deterministically
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
  "Fan-Out Accounting"). Propagation runs downward only: the Mission
  Issuer MUST NOT discharge a parent's or a sibling's entry because a
  child entry was discharged.

Once committed, a discharge is recorded as Authorization-Server-side
state and MUST NOT revert: a later delivery presenting any valid
condition against an already-discharged entry is acknowledged
`already_discharged` ({{discharge-result}}) and does not restore the
entry's authority.

A committed discharge also places a discharge restriction on the
Mission's expansion chain, the successors linked to it through
`predecessor` ({{I-D.draft-mcguinness-oauth-mission-expansion}}). The
Mission Issuer MUST retain each restriction, with the discharged entry
and the condition that discharged it, across every later successor in
the chain. A restriction clears only for authority that a fresh human
approval explicitly restores with the discharged entry and its
condition disclosed; any authority that approval does not restore
stays restricted. An intervening successor, an approval of unrelated
authority, and a ceiling renewal under the progressive authorization
profile ({{I-D.draft-mcguinness-oauth-mission-progressive}}) do not
clear it. Restoration grants authority through the successor's own
approval: the discharge never reverts, and the predecessor's entry
stays discharged.

A committed discharge is a committed metadata-only change for the
purposes of the state version
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Response"):
the Mission's state version increments at the commit, so a
materialized policy view that commits a state version
({{I-D.draft-mcguinness-mission-runtime}}) is detectably obsolete
after a discharge. Where Signals is deployed, the commit is carried by
the generic `authority_changed` discriminator
({{I-D.draft-mcguinness-oauth-mission-signals}}); where Signals is not
deployed, the version movement is what makes the change observable.

Before the AS receives and commits a discharge, it continues issuing
against the entry. The posture this implies is stated plainly in
{{completion-security}}.

## Condition Selectors {#condition-selectors}

A condition selector is an opaque string the Mission Issuer issues for
one condition of one entry in one Mission record. It resolves to that
condition's target, the (`mission_id`, `entry_digest`,
`condition_digest`) triple of {{discharge-operation}}. A source that
holds only its token's narrowed projection can then name the target
without reconstructing the immutable record entry.

- A selector is lookup state the Mission Issuer holds. It is not
  committed: `terminal_when`, its Value Space, the subset rule, and
  `authority_hash` are unchanged by it.
- The Mission Issuer MUST issue at most one selector per target, and a
  selector MUST resolve to exactly one target. Byte-identical entries
  share one `entry_digest`, so they share one selector, as they share
  one equivalence-class latch ({{discharge-commit}}).
- A selector MUST NOT let its holder reconstruct the record entry or
  any part of it: it is never computed from the entry's content without
  a secret, so it is never an unsalted digest. Its syntax is
  `1*128( ALPHA / DIGIT / "-" / "_" )` {{RFC5234}}.
- Knowing a selector authorizes nothing. Discharge authority
  ({{discharge-authority}}) and the pinned mapping decide, exactly as
  for the digest form.
- The Mission Issuer MUST keep a selector resolvable while its target
  can still be discharged, directly or by forwarding after carryover
  ({{discharge-carryover}}), and for at least as long as
  {{discharge-idempotency}} requires event-deduplication state to be
  retained, so a delayed assertion and a fresh-`nonce` event replay
  can still resolve it.

Where the AS supports token introspection {{RFC7662}} for
Mission-bound tokens ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission State via Token Introspection"), the `mission` member of the
introspection response can carry `discharge_selectors`, a member this
document defines. It is an array of objects, each with:

`entry`:
: the zero-based index of a `mission_resource_access` entry in the
  response's `authorization_details` (number).

`condition`:
: the zero-based index of a condition in that entry's `terminal_when`
  (number).

`selector`:
: the condition selector for that condition's target (string).

The AS MUST NOT include a selector for an entry it does not return to
that caller in the same response. A projected condition that has no
counterpart in the immutable record entry, such as one a token
projection added, has no target and so no selector. The OAuth
binding's caller-authorization and minimization rules apply
({{I-D.draft-mcguinness-oauth-mission}}, Section "Caller Authorization
and Minimization"). An AS MUST NOT include `discharge_selectors` unless
it is the Mission `issuer` ({{I-D.draft-mcguinness-oauth-mission}},
Section "Only the Issuer Reports Mission State"). This document
defines introspection carriage only.

The following is an example of an introspection response carrying a
selector for the write entry of the worked example ({{example}}):

~~~ json
{
  "active": true,
  "client_id": "s6BhdRkqt3",
  "exp": 1790000000,
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" },
        "terminal_when": [
          { "event_type": "accounting-period-closed",
            "discharge_authority": "close-management-2026-q3" }
        ] } }
  ],
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "state": "active",
    "discharge_selectors": [
      { "entry": 0, "condition": 0,
        "selector": "dcs_4Kq9vT2mX7pL0sR3nB8wZ1" }
    ]
  }
}
~~~

## Entry Discharge Operation {#discharge-operation}

`discharge` commits that a `terminal_when` completion condition
({{terminal-when}}) has fired, discharging the named Mission-record
entry ({{discharge}}). It is registered as an extension `operation`
value on the Status profile's Mission Lifecycle endpoint
({{I-D.draft-mcguinness-oauth-mission-status}}). Beyond `mission_id`
and `nonce`, it names its target in exactly one of two forms, a
condition selector ({{condition-selectors}}) or the digest pair, and
carries:

`condition_selector`:
: CONDITIONAL. A string, a condition selector
  ({{condition-selectors}}). Present when the request does not carry
  `entry_digest` and `condition_digest`. The AS resolves it to its
  target.

`entry_digest`:
: CONDITIONAL. A string. Present, with `condition_digest`, when the
  request does not carry `condition_selector`. The Authority Set entry
  commitment
  ({{I-D.draft-mcguinness-oauth-mission}}) of the
  `mission_resource_access` entry to discharge, computed over the
  immutable Mission-record entry, never over a narrowed token
  projection.

`condition_digest`:
: CONDITIONAL. A string. Present with `entry_digest`. The digest
  identifying the single `terminal_when` condition that fired, defined
  beside that member ({{terminal-when}}).

The AS MUST refuse a request that carries both target forms, or
neither, with `invalid_request`. For a request carrying
`condition_selector`, the rest of this section and its subsections
apply to the resolved `entry_digest` and `condition_digest` exactly as
to the digest form.

`event_type`:
: REQUIRED. A string. Echoed from the fired condition and
  cross-checked against the condition the target names: a
  mismatch joins the `not_found` collapse, since distinguishing it
  would reveal information about a condition selected by digest
  ({{discharge-anti-oracle}}). `event_type` is never a selector by
  itself.

`event_id`:
: REQUIRED. A string, `1*128( ALPHA / DIGIT / "-" / "_" / ":" / "." )`
  {{RFC5234}}. The identifier of the asserted external occurrence,
  used for evidence correlation and for the event-level deduplication
  of {{discharge-idempotency}}. It is distinct from `nonce`, the HTTP
  retry key of the Status profile's Idempotency and Conflicts rule
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
  "Idempotency and Conflicts").

`evidence_ref`:
: OPTIONAL. A URI, maximum 512 characters. A reference to evidence of
  the asserted occurrence.

`evidence_digest`:
: OPTIONAL. A string, the family's prefixed digest form (`sha-256:`
  plus base64url, no-padding encoding), classified as a raw-octet
  digest ({{I-D.draft-mcguinness-oauth-mission}}, Section "Commitment
  Mechanisms"): computed over the exact octets of the referenced
  artifact as exchanged, with no canonicalization. `evidence_ref` and
  `evidence_digest` MAY both appear: when they do, `evidence_digest`
  MUST commit the bytes `evidence_ref` names. Present alone,
  `evidence_digest` is independent audit metadata.

`evidence_ref` and `evidence_digest` are bounded audit metadata about
the asserted occurrence. The AS MUST NOT dereference `evidence_ref`
in baseline processing and MUST NOT treat either member as
authorization input.

`observed_at`:
: OPTIONAL. An RFC 3339 {{RFC3339}} date-time: a caller assertion. The
  AS validates it for syntax and reasonable clock bounds only, never as
  trusted ordering or freshness, and records its own commit time as
  `received_at` in audit.

Semantics, beyond those every committed discharge has
({{discharge-commit}}):

- **Condition selection.** The request names the condition that
  fired. A later delivery presenting any valid condition against an
  already-discharged entry, a sibling condition, or the same
  condition under a different `event_id`, is acknowledged
  `already_discharged` ({{discharge-result}}) and MUST NOT discharge
  the entry again or increment the version again; an exact event
  replay (the same tuple and the same fingerprint) is handled first by
  the dedup rule of {{discharge-idempotency}}.
- **Terminal Missions.** A delivery reaching the endpoint after
  `completed`, `revoked`, `expired`, or another terminal state returns
  an authenticated `terminal_noop` acknowledgement
  ({{discharge-result}}). The AS reaches this determination only after
  the selector and authorization validation of
  {{discharge-anti-oracle}}, so a terminal Mission is never a shortcut
  past those checks.
- **No `expected_version`.** A stale-version refusal would delay a
  safety-reducing operation; the digest selectors above and the
  idempotency rules of {{discharge-idempotency}} are the guards
  instead.

### Discharge Authority {#discharge-authority}

Authorization for `discharge` requires a distinct `mission_discharge`
scope or an equivalent deployment-defined grant. Possession of the
Status profile's `mission_lifecycle` scope
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Mission
Lifecycle Endpoint"), or being the Mission's Subject, Approver, or an
administrator, MUST NOT by itself imply discharge authority: a
`terminal_when` condition is asserted by a resource or event
authority, not by whoever may revoke, suspend, resume, or complete
the Mission.

The baseline authority mapping is AS authorization policy keyed by
`event_type`: the deployment publishes which authenticated principal (a
client or workload identity, with its resource boundary where
applicable) may assert each event type. Authentication uses the
Status profile's mechanism set
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Mission
Status Operation", subsection "Authentication"), sender-constrained
where the deployment's profile requires it, and MUST bind the
asserting principal.

A `terminal_when` condition MAY carry `discharge_authority`
(OPTIONAL): a stable, opaque name for the authority approved to assert
that condition, which the AS resolves to its discharge-authority
mapping ({{iana-terminal-when}}). The AS MUST resolve and validate the
`discharge_authority` value whenever a condition first enters an
immutable Mission-record entry: at Mission creation, and at every later
point where a derived entry can carry a new condition (child creation,
expansion, Token Exchange or other derivation, and any further profile
that adds a condition), refusing the Intent or the derivation whose
value maps to nothing. The AS binds the resolved mapping's identifier
and version to that exact `condition_digest` in issuer-held metadata.

The approved meaning of a condition's authority is fixed for that
condition: the source authority the mapping names, with its resource
and tenant boundary. Because the binding pins the mapping's identifier
and version, a later policy change never re-points who may assert an
existing condition, and changing the authority itself takes a new
condition under a new approval. The operational credentials of the
same authority, such as its keys, can rotate or be revoked without
changing the condition. An approval interface that renders a condition
names the authority the AS resolved, not only the `discharge_authority`
string; controlling an `event_type` value confers no authority to
assert it.

A requesting client MUST NOT select an
arbitrary otherwise-valid authority merely because adding a condition
is narrowing: an unchecked choice of mapping for a newly added condition
could still force the premature discharge that {{completion-security}}
warns against, a denial-of-service on the task and an early
retirement of its own guardrail. The member is never a raw principal
or workload structure, and the requesting client cannot select an
unapproved fallback.

A carryover replacement inherits the old child's pinned mapping for
every carried condition. A carried condition does not first enter the
replacement, so the AS does not resolve it again, and forwarding after
carryover authorizes against the replacement's inherited pin
({{discharge-carryover}}).

### Discharge Anti-Oracle {#discharge-anti-oracle}

An unknown `mission_id`, an unknown `entry_digest`, an unknown
`condition_digest`, an entry with no `terminal_when`, an `event_type`
that does not match the condition `condition_digest` names, and a
caller not authorized for that target all collapse to the endpoint's
existing `not_found` treatment
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Error
Responses"). A `condition_selector` that does not resolve, or that
resolves to a target outside the request's `mission_id`, joins the
same collapse, and its resolution is part of selector existence
below. Authentication failure remains `unauthorized` (401).
Detailed refusal reasons live only in issuer audit records.

The AS validates selector existence (`mission_id`, `entry_digest`, and
`condition_digest` all resolve, the entry carries `terminal_when`, and
`event_type` matches the named condition), then condition membership
(the named condition belongs to the named entry), then target
authorization (the discharge authority mapping of
{{discharge-authority}}), before returning any `terminal_noop`
acknowledgement ({{discharge-result}}). This order keeps a terminal
Mission from acting as a selector-existence oracle: every case the
collapse above refuses is checked before a terminal Mission is ever
distinguished from one whose selectors do not resolve.

### Idempotency: `nonce` and `event_id` {#discharge-idempotency}

`discharge` keeps two identities apart. `nonce` stays the HTTP
operation retry key under the Status profile's Idempotency and
Conflicts rule ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
"Idempotency and Conflicts"): a retransmission with the same `nonce`
and a byte-identical request returns the stored signed response
verbatim. The same `nonce` with a different request is refused
`invalid_request`, never answered with an unrelated original
response.

`event_id` deduplicates the external occurrence, scoped by
(authenticated discharge authority, `mission_id`, `entry_digest`,
`condition_digest`, `event_id`). A response's `nonce` MUST equal the
one just sent ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
"Response"), so a retry that supplies a fresh `nonce`, as an
at-least-once sender legitimately does, cannot receive the original
signed response verbatim. Two cases follow:

- **Same `nonce`, same request.** The stored signed response is
  returned verbatim, per the `nonce` rule above.
- **New `nonce`, same event tuple and the same assertion
  fingerprint** (defined below). The AS performs no state-changing
  work: no re-latch, no version increment. It issues a new signed
  envelope that echoes the new `nonce` and carries the stored
  operation result: the same `outcome` and resolved target, and the
  original `prior_version` and `current_version` the first commit
  produced. The echoed target form and `event_id` are the current
  request's ({{discharge-result}}), so a selector-form retry of a
  digest-form original never receives digests.

**Event assertion fingerprint.** A semantic assertion object, never
raw form bytes: the JSON object with exactly the decoded members
`operation` (the literal string `discharge`), `mission_id`,
`entry_digest`, `condition_digest`, `event_type`, `event_id`, and,
when present, `evidence_ref`, `evidence_digest`, and `observed_at`.
The object is canonicalized under the issuance profile's
canonicalization ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Canonicalization Rules") and digested as a canonical-object digest
({{I-D.draft-mcguinness-oauth-mission}}, Section "Commitment
Mechanisms"), since protocol context already fixes what the object
commits. `nonce`, client authentication material, the DPoP proof, and
transport headers are outside the fingerprint: none of them enter the
assertion object, and none of them affect its value.

**The selector form.** For a request carrying `condition_selector`,
the AS MUST use the resolved `entry_digest` and `condition_digest` in
the event tuple and in the assertion fingerprint; the selector itself
is outside the fingerprint. A selector-form request and a digest-form
request for the same target and occurrence therefore share one
deduplication identity and an identical fingerprint.

Over the (discharge authority, `mission_id`, `entry_digest`,
`condition_digest`, `event_id`) tuple: the same tuple with the same
fingerprint is the replay case above; the same tuple with a different
fingerprint is refused `conflict`; the same `event_id` asserted
against another Mission, entry, or condition is a valid, independent
assertion, since one real-world event legitimately fans out to more
than one target.

When both rules could apply, the `nonce` rule is evaluated first,
since it governs the HTTP exchange; the `event_id` rule governs across
distinct exchanges.

**Retention.** Event-dedup state MUST be retained at least as long as
the deployment's published retry horizon and the replayable result's
usable lifetime, and MAY be bounded by the Mission record's own
retention. After eviction, a repeated assertion is processed fresh
against the latch and yields `already_discharged` with no version
increment, which is safe because the latch is monotonic.

### Discharge Result {#discharge-result}

On success, `discharge` returns the Status profile's existing signed
Mission Status Response envelope
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Response"),
carrying a `discharge_result` object as a sibling of `mission`:

`event_id` and the target form:
: echoed as the request sent them: `condition_selector`, or
  `entry_digest` and `condition_digest`. The AS MUST NOT add to the
  result a digest that a selector-form request did not carry.

`outcome`:
: one of `discharged` (this request committed the latch),
  `already_discharged` (a sibling condition, or the same condition
  under a different `event_id`, presented against an already-latched
  entry), or `terminal_noop` (the Mission was already in a terminal
  state). An exact event replay is handled first by the dedup rule
  ({{discharge-idempotency}}), never reaching this determination as a
  fresh `already_discharged`.

`prior_version`, `current_version`:
: the Mission's state version immediately before and after the
  commit this result reports. For a request that itself commits, that
  commit is this request's own. For the new-`nonce` fresh-envelope
  case of {{discharge-idempotency}}, which commits nothing, these are
  the versions the original commit produced, unchanged. They are equal
  for `already_discharged` and `terminal_noop`.

`forwarded_from`:
: present only when the discharge was forwarded after carryover
  ({{discharge-carryover}}): a qualified reference (`issuer` and
  Mission identifier) to the old child the request targeted. The
  envelope's `mission` and the versions then describe the replacement
  that changed.

With the echoed `nonce`, this is the durable acknowledgement an
at-least-once sender stops retrying against.

## Discharge After Carryover {#discharge-carryover}

A discharge can target a Child Mission that has since been carried over
to a replacement under a successor parent
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section "Child
Mission Carryover"). The targeted old child is then terminal and would
answer `terminal_noop`, while its replacement keeps deriving the same
authority until it expires. This section forwards the discharge
instead.

- **Resolution.** When Carryover Evidence records the targeted Mission
  as carried, the AS MUST apply the discharge to the replacement's
  corresponding entry. The correspondence is the per-entry pairing
  Carryover Evidence records (the old record `entry_digest` paired with
  the replacement's), and the AS MUST NOT resolve it any other way, such
  as by matching resource and condition
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
  "Carryover Evidence and Observation"). A chain of carryovers resolves
  through each recorded pairing in turn. The AS MUST check the targeted
  entry's own latch in the old child before forwarding: an entry the
  old child had already discharged answers `already_discharged`
  without forwarding, since the replacement's effective set excludes
  it, and an exact event replay is handled first by
  {{discharge-idempotency}}. A targeted entry with no recorded
  counterpart for any other reason holds no authority in the
  replacement, and the request answers `terminal_noop`.
- **Authorization.** The AS MUST authorize the caller against the
  replacement's pinned mapping for the fired condition
  ({{discharge-authority}}). A caller that mapping does not admit gets
  the `not_found` collapse ({{discharge-anti-oracle}}).
- **Commit.** The replacement's entry is discharged under
  {{discharge-commit}}, with its own latch, version increment and
  commit boundary, before the response returns.
- **Replay.** The AS MUST record the resolved target in the
  operation's result record at first processing. A retry, including
  one after a further carryover, recovers that result and never
  resolves a new target. A replacement created after the discharge
  committed inherits it under carryover's no-reset rule
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
  "No State, Authority, Expiry, or Budget Reset").
- **Response.** The result describes the record that changed. Where
  the caller is authorized for the Mission Status operation on the
  replacement ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
  "Mission Status Operation"), the response is the replacement's signed
  Mission Status Response envelope, whose `discharge_result` carries
  `forwarded_from` ({{discharge-result}}). A consumer verifies that
  response under the Status profile's procedure
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Response"),
  with one change: in place of checking that `mission.id`
  equals the requested `mission_id`, it MUST verify that
  `discharge_result.forwarded_from` names the requested Mission and
  that `mission.issuer` equals its `issuer`, and it then reads
  `mission` as the replacement the result reports. A consumer that does
  not implement this document rejects such a response at that check,
  which fails closed. Otherwise the response is a Discharge Receipt
  ({{discharge-receipt}}). Neither places the
  replacement's versions beside the old Mission's status.

### Discharge Receipt {#discharge-receipt}

A Discharge Receipt is a JWS Compact Serialization {{RFC7515}} signed
with a key published in the AS's `jwks_uri`. Its JWS header carries
`typ` of `mission-discharge-receipt+jwt` and a `kid` identifying the
signing key, and the HTTP `Content-Type` is
`application/mission-discharge-receipt+jwt` ({{iana-receipt}}). A
consumer MUST validate `typ` exactly and MUST NOT accept a Discharge
Receipt as a Mission Status Response, or a Mission Status Response as
a Discharge Receipt ({{RFC8725}}, Sections 3.11 and 3.12).

Its payload carries `iss`, `aud`, `nonce`, `iat`, `exp`, and a
`discharge_receipt` object. The AS MUST set `aud` to the authenticated
requester's identifier and `nonce` to the request's own `nonce`, as
for the Status profile's state-only response
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Response").
The `nonce` rules of {{discharge-idempotency}} apply to a receipt as to
the envelope: a byte-identical retransmission replays the stored
receipt bytes, and a fresh-`nonce` replay of the same event returns a
new receipt echoing the new `nonce`. The `discharge_receipt` object
has:

- `mission_id`: the Mission the request targeted;
- `event_id` and the target form, echoed as the request sent them; and
- `outcome`: the string `forwarded`.

A Discharge Receipt carries no `mission` member and no state versions.
It never names the replacement. With the echoed `nonce`, it is the
durable acknowledgement an at-least-once sender stops retrying against.

A consumer MUST verify, before relying on a Discharge Receipt, for
example before it stops retrying:

1. the JWS header `typ` is `mission-discharge-receipt+jwt`;
2. the JWS header `alg` is one the AS advertises in
   `mission_status_signing_alg_values_supported`
   ({{I-D.draft-mcguinness-oauth-mission-status}}, Section
   "Authorization Server Metadata"), rejecting `none` and any
   algorithm not listed;
3. the JWS signature against a current `jwks_uri` entry for the AS;
4. `iss` equals the expected AS issuer URL;
5. `aud` equals the consumer's own identifier, as the AS
   authenticated it;
6. `nonce` equals the request's `nonce`;
7. `discharge_receipt.mission_id` equals the requested `mission_id`,
   and its echoed target form and `event_id` equal the request's; and
8. `iat` is not in the future and `exp` is not in the past, with up to
   30 seconds clock-skew tolerance.

## Deployment-Internal Adjudication {#internal-adjudication}

A deployment that determines completion by means other than the
`discharge` operation, such as a private status query or a recorded
administrative action, invokes the same commit internally once it has
decided, recorded under the same audited basis as any other lifecycle
commit.

## Worked Example {#example}

A Mission for `alice` reconciles Q3 payables. Its Authority Set has two
entries: a read over the ledger, and a write to post journal entries,
bounded to under 500 USD and discharged when the Q3 close is finalized:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"] },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" },
      "terminal_when": [
        { "event_type": "accounting-period-closed",
          "discharge_authority": "close-management-2026-q3" } ] } }
]
~~~

`discharge_authority` names the authority approved to assert this
condition: the close-management system's workload identity, not
`alice`'s agent, may assert `accounting-period-closed`
({{discharge-authority}}). The agent cannot drive its own discharge: it
holds no `mission_discharge` authorization for that `event_type`.

While the period is open, the Authorization Server derives both entries.
When the finance team finalizes the Q3 close, the close-management
system calls `discharge` on the Mission Lifecycle endpoint, naming the
write entry's `entry_digest`, this condition's `condition_digest`,
`event_type` `accounting-period-closed`, and an `event_id` for its own
occurrence record. The Authorization Server authenticates the caller
against the resolved `discharge_authority` mapping, commits the latch,
and returns a signed `discharge_result` of outcome `discharged`
({{discharge-result}}). A Resource Server that holds a token for the
write entry, and so cannot compute the record entry's digest, names
the same target by the condition selector it reads from introspection
({{condition-selectors}}).

From then on the
Authorization Server refuses to derive the write entry: a refresh
returns a token carrying only the read entry. The Mission stays
`active`, so the agent can still read the ledger to finish its
reconciliation report, but it can no longer post journal entries. No
revoke and no clock was needed; the write authority retired itself
when the task it was granted for completed.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}} apply in full. This
section covers threats specific to this document's capability.

## Entry Discharge {#completion-security}

The completion capability ({{completion}}) adds the following:

- Monotonic by construction. Discharge only removes an entry's authority,
  so it is not a path to escalation; a compromised or injected agent
  cannot use `terminal_when` to widen authority, and the worst it can do
  is retire its own authority sooner. That is not an escalation, but a
  forced premature discharge is a denial-of-service on the task
  (authority the task still needs is withdrawn) and, where discharge is
  relied on as a guardrail, retires that guardrail early. Discharge
  authority ({{discharge-authority}}) bounds who can force it.
- Fail closed on unknown constraint. A consumer that does not understand
  the `terminal_when` constraint MUST refuse the entry
  ({{forward-compat}}); ignoring the constraint would let a discharged
  entry continue to be narrowed, projected, or enforced, defeating
  discharge.
- Notification delivery is a temporary widening, not a fail-closed
  property. Before the AS receives and commits a discharge, it
  continues issuing against the entry: a lost or suppressed
  notification is a temporary widening relative to the real-world
  event, bounded by authenticated at-least-once delivery with retries
  to an idempotent acknowledgement ({{discharge-result}}), monitoring
  and reconciliation, and the Mission's and its tokens' own lifetimes.
  This is not a fail-closed property: a deployment requiring
  cannot-determine-means-no-issuance runs a synchronous status or
  policy check outside this baseline.
- RS enforcement honesty. A stateless Resource Server cannot evaluate
  issuer-held discharge state from the token alone; it honors the
  issued token until expiry. Prompt cutoff on a discharged entry
  requires the Status profile's Mission Status operation or
  introspection projection, or runtime enforcement
  ({{I-D.draft-mcguinness-oauth-mission-status}}, {{runtime}}); an
  entry constraint the enforcing party does not understand still fails
  closed ({{forward-compat}}).
- Already-issued tokens. The window between discharge and the expiry
  of a token already issued is the same residual revocation carries,
  bounded the same way ({{discharge}}, {{runtime}}).
- Forwarding after carryover. A delayed completion reaches the active
  replacement only through recorded entry pairings, never by matching,
  and a caller not authorized to inspect the replacement learns
  nothing about it from the Discharge Receipt
  ({{discharge-carryover}}).

# Privacy Considerations {#privacy-considerations}

The privacy considerations of the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} and the Status profile
{{I-D.draft-mcguinness-oauth-mission-status}} apply in full. This
section covers privacy specific to this document's capability.

## Completion Condition Disclosure {#completion-privacy}

A `terminal_when` condition can reveal task structure: `event_type` may
name a business event, a case, or a record whose mere existence is
sensitive, and it rides the token where the entry is carried. A
deployment SHOULD treat it as it treats other authority detail, and
SHOULD avoid event identifiers that disclose more than the consuming
party needs. `discharge_authority` is an opaque name and does not
itself name a business event, but its resolution is deployment-defined
and MAY correlate with a class of sensitive events; a deployment
SHOULD weigh that when publishing its meaning. The `event_id`,
`evidence_ref`, `evidence_digest`, and `observed_at` a `discharge`
request carries ({{discharge-operation}}) do not ride the token; they
land only in issuer audit records, which deployments MUST treat as
Mission information-disclosure surfaces per the Status profile's
audit-logging rule
({{I-D.draft-mcguinness-oauth-mission-status}}, Section "Status Audit
Logging").

A condition selector ({{condition-selectors}}) prevents reconstructing
the record entry, but it is stable for its target and so can correlate
a caller's requests over time. Its disclosure is limited to parties
that already receive that entry's projection.

# IANA Considerations {#iana}

This document requests IANA actions for a registration in the Mission
Resource Access Profile's Mission Common Constraints registry and for
one media type ({{iana-receipt}}). It establishes no registry of its
own. `discharge_selectors` is a member
of the introspection `mission` member, under an extension point of
the OAuth binding that has no IANA registry
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission State via
Token Introspection"), so it requires no registration.

## Common Constraints Registry: terminal_when {#iana-terminal-when}

The completion capability ({{completion}}) registers one Common
Constraint in the Mission Resource Access Profile's Mission Common
Constraints registry
({{I-D.draft-mcguinness-oauth-mission-resource-access}}), under that
registry's Specification Required policy. This document supplies the
registration's required fields:

- Key Name: `terminal_when`
- Value Space: a JSON array of one or more completion-condition
  objects, each with a REQUIRED `event_type` (string) and an OPTIONAL
  `discharge_authority` (string, an opaque authority name); no two
  conditions in one array share a canonical form ({{terminal-when}}).
  This Value Space is a breaking change, while this experimental
  draft's registration is still open, to the one a prior revision
  registered: `event_source` and `max_staleness` are removed and
  `discharge_authority` is added.
- Subset Rule: a candidate value is no broader than a reference value
  when the candidate's condition array contains every condition of the
  reference, compared structurally after the issuance profile's
  canonicalization; the candidate MAY add further conditions
  ({{subset-extension}}).
- Intersection Rule: the union of the two condition arrays, where
  condition identity is byte equality of each condition object's
  canonical form under the issuance profile's canonicalization
  ({{I-D.draft-mcguinness-oauth-mission}}): byte-identical conditions
  collapse to one, and the union is sorted by the lexicographic order
  of those canonical bytes, so two implementations produce the
  identical array and the identical `authority_hash`.
- Change Controller: IETF
- Reference: this document, {{terminal-when}}

`terminal_when` is a `constraints` member of the `mission_resource_access`
authorization details type defined by the Mission Resource Access
Profile ({{I-D.draft-mcguinness-oauth-mission-resource-access}}).
`event_type` values are deployment- or registry-defined and opaque to
this document, as `purpose` is, so this document establishes no
registry of event types.

## Media Type Registration {#iana-receipt}

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-discharge-receipt+jwt

- Type name: application
- Subtype name: mission-discharge-receipt+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: OAuth Mission-Bound discharge
  sources
- Fragment identifier considerations: not applicable
- Restrictions on usage: none
- Provisional registration: no
- Magic number(s): none
- File extension(s): none
- Macintosh file type code(s): none
- Person & email address to contact: Karl McGuinness
  <public@karlmcguinness.com>
- Intended usage: COMMON
- Author/Change controller: IETF

# Conformance {#conformance}

An implementation claiming this document's capability MUST meet the
requirements of {{completion-conformance}}. An implementation that
does not claim it is unaffected and remains conformant to the
issuance profile, its Mission Resource Access Profile, and the Status
profile.

## Completion Conformance {#completion-conformance}

An Authorization Server claiming the completion capability MUST:

- treat an entry whose `terminal_when` has been discharged as
  discharged and refuse to derive it ({{discharge}});
- commit a discharge only through the `discharge` operation, meeting
  its authority, anti-oracle, and idempotency requirements
  ({{discharge-operation}}), or through an equivalently audited
  deployment-internal adjudication ({{internal-adjudication}});
- where it exposes the `discharge` operation, issue condition
  selectors and accept the operation's selector form as
  {{condition-selectors}} defines, disclosing them through token
  introspection where it supports introspection for Mission-bound
  tokens;
- forward a discharge that targets a carried-over child as
  {{discharge-carryover}} defines;
- meet the commit semantics of {{discharge-commit}}, including
  atomicity, whichever way a discharge is determined;
- record a committed discharge as latched state that MUST NOT revert
  ({{discharge-commit}});
- carry every parent completion condition into a derived entry when
  narrowing, permitting only added conditions ({{subset-extension}});
- where it offers the Status profile's Mission Status operation or the
  token introspection projection, omit a discharged entry from the
  `authorization_details` it returns ({{visibility}}); and
- keep the `terminal_when` condition array committed by `authority_hash`
  and keep fired status out of it ({{terminal-when}}).

A consumer claiming the completion capability MUST fail closed for an
entry carrying a `terminal_when` constraint it does not understand
({{forward-compat}}).

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Discharge Commit ({{discharge-commit}}): a committed discharge places
  a restriction on the Mission's expansion chain, retained across later
  successors and cleared only for the authority a fresh human approval
  explicitly restores with the discharged entry and its condition
  disclosed. The discharge itself never reverts.
- Relationship to Runtime Enforcement ({{runtime}}): issuance-only
  discharge stays conforming; where the runtime profile runs, its PDP
  refuses a discharged entry.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the Mission-Bound
Authorization work for feedback that shaped this extension.
