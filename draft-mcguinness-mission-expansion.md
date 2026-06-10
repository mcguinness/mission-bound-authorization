---
title: "Mission Expansion"
abbrev: "Mission Expansion"
category: std

docname: draft-mcguinness-mission-expansion-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - expansion
 - authorization
 - authzen
 - governance
 - delegation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-expansion.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-authzen-access-request:

informative:
  RFC4086:
  RFC9470:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-mcguinness-mission-aauth-profile:
  I-D.draft-mcguinness-mission-delegated-authority-validation:

--- abstract

This document defines the governance expansion mechanism for
Mission-Bound Authorization. When an action falls outside the
Authority Set of an active Mission but is eligible for governed
expansion, this specification defines, substrate-neutrally, the
eligibility-signaling abstract contract, the expansion-request
workflow built on the AuthZEN Access Request, the binding of a
successor Mission to its predecessor, and the reconciliation rules
for concurrent expansion. Substrate-specific wire bindings for
eligibility signaling live in the substrate profile specifications;
the OAuth and AAuth Profiles each bind these semantics to their
respective wires. Resource-side detection of out-of-bounds requests
is defined by the Delegated Authority Validation feature
specification.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
defines a Mission as a durable, integrity-anchored, lifecycle-governed
governance object that records an approved task. The Mission's
Authority Set bounds the maximum authority derivable on its behalf.
When a downstream action falls outside the Authority Set, a
credential issuer, a Resource Authorization Server, or a Policy
Decision Point will deny the request. In many such denials, the
deployment's governance policy permits expanding the Mission to
cover the requested action, subject to a new approval event.

This document defines that expansion mechanism. It is substrate-
neutral on semantics: it defines the abstract contract a substrate-
specific denial response carries when expansion is eligible, the
workflow by which an orchestrator submits an expansion request to
the state authority, the lifecycle binding between the predecessor
Mission and any successor Mission, and the reconciliation rules
that apply when multiple expansion requests are in flight.

This document does NOT define a wire format for eligibility
signaling. The OAuth Profile {{I-D.draft-mcguinness-mission-oauth-profile}}
defines the OAuth wire binding. The AAuth Profile
{{I-D.draft-mcguinness-mission-aauth-profile}} defines the AAuth
wire binding. Resource-side detection of out-of-bounds requests is
defined by Delegated Authority Validation
{{I-D.draft-mcguinness-mission-delegated-authority-validation}}.

Expansion is a governance operation. It is distinct from
authentication step-up {{RFC9470}}. A request denied because an
`acr` or `amr` constraint requires fresh authentication is
satisfied by step-up, not by expansion: the Authority Set does
not change. A request denied because the requested authority is
not in the Authority Set requires expansion: the Authority Set
must be enlarged through a new approval event.

## Relationship to the Framework

The Framework {{I-D.draft-mcguinness-mission-framework}} defines:

- The Mission record, including the canonical `mission.id`,
  `mission.origin`, integrity anchors, principal model, and
  lifecycle.
- The Authority Set and its typed entries.
- The Mission Status interface.
- The approval event semantics: atomic state-authority transition
  from Mission Proposal to Mission upon a binding consent signal.

This document composes those semantics with the AuthZEN Access
Request {{I-D.draft-mcguinness-authzen-access-request}} as the
request shape an orchestrator submits to the state authority when
seeking expansion of an existing Mission. The result of a successful
expansion is a new approval event that yields either a successor
Mission (replacement mode) or a child Mission (branch mode), each
permanently linked to its predecessor.

## Scope

This document defines:

- An abstract eligibility-signaling contract surfaced in
  substrate-specific denial responses.
- The Mission Expansion Ticket: an opaque, single-use, time-limited
  bearer carried from the denial to the expansion request.
- The expansion-request workflow using the AuthZEN Access Request.
- Workflow outcomes: synchronous approved, asynchronous approved,
  denied, expired.
- Replacement expansion and Branch expansion semantics, including
  the `mission.predecessor` and `mission.expansion_mode` lineage
  attributes.
- Concurrent expansion reconciliation, including a closed set of
  reconciliation status codes.

This document does NOT define:

- OAuth-wire bindings for eligibility signaling
  ({{I-D.draft-mcguinness-mission-oauth-profile}}).
- AAuth-wire bindings for eligibility signaling
  ({{I-D.draft-mcguinness-mission-aauth-profile}}).
- Resource-AS detection of out-of-bounds requests against the
  Authority Set
  ({{I-D.draft-mcguinness-mission-delegated-authority-validation}}).
- Runtime per-action enforcement and PDP-level denial classification.
- A substrate-specific transport for the Mission Expansion Ticket or
  the expansion request beyond the AuthZEN Access Request envelope.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms defined in the Framework {{I-D.draft-mcguinness-mission-framework}}
are inherited here without restatement. In particular, this document
uses Framework terms Mission, Mission Proposal, Mission Intent
(Submitted and Validated forms), Authority Set, Authority Set entry,
approval event, integrity anchor, state authority, canonical
`mission.id`, and `mission.origin` as defined there.

The following additional terms apply.

**Expansion Eligibility**:
: A property of a denial response indicating that the deployment's
governance policy permits the request to be re-submitted as an
expansion of the active Mission, subject to a new approval event.

**Mission Expansion Ticket** (also **Expansion Ticket**, **Ticket**):
: An opaque, single-use, time-limited bearer issued by the state
authority and surfaced in an eligibility-bearing denial response.
The holder presents the ticket to the state authority's expansion
request endpoint to initiate the AuthZEN Access Request workflow.

**Expansion Request**:
: An AuthZEN Access Request
{{I-D.draft-mcguinness-authzen-access-request}} submitted by an
authorized orchestrator carrying the Expansion Ticket and the
requested authority. The state authority adjudicates the request
through a new approval event.

**Requested Authority**:
: The Authority Set delta the orchestrator is asking the state
authority to add. Expressed as one or more Authority Set entries
in the Framework's typed entry shape.

**Predecessor Mission**:
: The active Mission whose Authority Set is the baseline for an
expansion. The predecessor is referenced by `mission.predecessor`
on any resulting successor or child Mission.

**Successor Mission**:
: The Mission created by a Replacement expansion. The successor
carries an Authority Set that contains the explicitly approved
unchanged authority of the predecessor plus the approved addition.
On activation of the successor the predecessor transitions to
`completed` atomically.

**Child Mission**:
: The Mission created by a Branch expansion. The child is a
separately scoped Mission that exists alongside the predecessor.
The predecessor remains `active`; its credentials retain
predecessor authority.

**Expansion Mode**:
: One of `replacement` or `branch`. Carried on the request and
recorded on the resulting Mission as `mission.expansion_mode`.

**Orchestrator**:
: The authorized party that drives the expansion workflow. This is
typically the requesting client of the predecessor Mission or a
delegated component. The orchestrator presents the Expansion Ticket
and the AuthZEN Access Request; the state authority authenticates
and authorizes the orchestrator before adjudicating.

# Substrate-Neutral Semantics

This document defines the semantics of expansion in three abstract
parts: eligibility signaling (a property of denial), the expansion
workflow (the request and its outcomes), and the predecessor-to-
successor binding.

## Eligibility-Signaling Abstract Contract

When a state authority, credential issuer, Resource Authorization
Server, or Policy Decision Point denies a request because the
requested authority is not in the active Mission's Authority Set,
and the deployment's governance policy permits expansion for that
class of request, the denial response MUST surface the following
abstract fields. Substrate profiles bind these to substrate-specific
transport.

**`eligible`** (boolean, REQUIRED):
: `true` if expansion is permitted for this denial. `false` if the
denial is terminal for the active Mission (e.g., the governance
policy does not permit the requested authority class under any
expansion).

**`access_request_uri`** (URI, REQUIRED when `eligible` is `true`):
: The endpoint at which the orchestrator submits the AuthZEN Access
Request to initiate expansion. The URI MUST identify an endpoint
operated by the Mission's state authority (i.e., resolvable from
`mission.origin`).

**`ticket`** (string, REQUIRED when `eligible` is `true`):
: The Mission Expansion Ticket. See {{ticket}} for ticket
requirements.

**`requested_authority`** (array of Authority Set entries, REQUIRED
when `eligible` is `true`):
: The minimum authority the issuer determined is needed to satisfy
the denied request. Each entry conforms to the Framework's Authority
Set entry shape (`urn:mbo:schema:authority-set-entry:1`), including
`type`, `specification_uri` or `schema_digest`, `schema_version`,
`authority`, and `narrowing_profile`. The state authority's approval
event MAY further narrow or refuse entries.

The denial response MAY include additional substrate-specific fields
(e.g., human-readable explanation, hints about the predecessor
Mission's identifier). Such fields are profile-specific and are
defined by the substrate profile.

An eligibility-bearing denial is not an authorization decision in
favor of expansion. It signals only that the deployment's governance
policy permits the orchestrator to attempt an expansion request. The
state authority remains the sole adjudicator.

A minimal denial response with eligibility signaling, shown in
substrate-neutral JSON for illustration only, has the shape:

~~~ json
{
  "eligible": true,
  "access_request_uri": "https://as.example.com/mission/expand",
  "ticket": "exp_3wKqf9N7Vt-2hY8Z...opaque-bearer",
  "requested_authority": [{
    "type": "mission_resource_access",
    "specification_uri": "https://example.com/specs/mra/v1",
    "schema_version": "1",
    "authority": {
      "resource": "https://docs.example.com",
      "actions": ["documents.share"]
    },
    "narrowing_profile": "urn:mbo:narrowing:default-v1"
  }]
}
~~~

Substrate profiles MAY embed the same fields in a substrate-native
envelope (e.g., an OAuth error response, an AAuth denial). The field
names and semantics are preserved across substrates.

## Expansion Request Workflow

The expansion workflow has four steps.

### Step 1: Denial with Eligibility

A credential issuer, Resource Authorization Server, or PDP returns
a denial that includes the eligibility signaling defined in
{{eligibility-signaling-abstract-contract}}. The orchestrator
receives the denial together with the Expansion Ticket and the
requested authority.

### Step 2: Expansion Request Submission

The orchestrator submits an AuthZEN Access Request
{{I-D.draft-mcguinness-authzen-access-request}} to the
`access_request_uri`. The request MUST include:

- The Expansion Ticket (presented as defined by the substrate
  profile's binding of the AuthZEN Access Request).
- The `requested_authority` from the denial, optionally further
  narrowed by the orchestrator. The orchestrator MUST NOT enlarge
  the requested authority beyond the denial's
  `requested_authority`.
- An `expansion_mode` value of `replacement` or `branch`. See
  {{replacement-and-branch}}.
- Authentication of the orchestrator. Authentication mechanisms are
  profile-defined (e.g., OAuth client authentication, AAuth-native
  signed request).

The state authority MUST validate the Expansion Ticket per
{{ticket}}. The state authority MUST authenticate and authorize the
orchestrator for the predecessor Mission before adjudicating.

### Step 3: Adjudication

Adjudication is a new approval event per the Framework
{{I-D.draft-mcguinness-mission-framework}}. The state authority
MUST:

1. Identify the predecessor Mission from the validated Expansion
   Ticket. The predecessor's identifier MUST NOT be derived solely
   from orchestrator-supplied input.
2. Validate that the predecessor is in the `active` state. A
   predecessor that is `suspended`, `revoked`, `completed`, or
   `expired` MUST cause the request to be denied with the
   reconciliation status `predecessor_state_changed` per
   {{concurrent-expansion-reconciliation}}.
3. Compute the proposed Authority Set for the successor or child
   Mission per the declared `expansion_mode`. The state authority's
   derivation policy MAY narrow the `requested_authority`. The state
   authority MUST NOT enlarge it beyond the requested values.
4. Render the consent disclosure object and obtain a binding consent
   signal from the approving principal. The form of consent
   (interactive, asynchronous, or policy-driven) is governance-policy
   defined.
5. On approval, create the resulting Mission atomically with the
   approval-event evidence and the predecessor lineage attributes.
6. On rejection, withdrawal, or expiry of the approval, leave the
   predecessor untouched and return the appropriate denial outcome.

### Step 4: Outcome

The state authority returns one of the workflow outcomes defined in
{{workflow-outcomes}}.

## Workflow Outcomes

The expansion workflow produces exactly one of four outcomes.

**Synchronous approved**:
: The approval event completes within the response window of the
expansion request. The state authority returns the resulting
canonical `mission.id`, the `expansion_mode`, and, in
replacement mode, the predecessor's transition to `completed`. The orchestrator MAY
re-derive credentials from the resulting Mission.

**Asynchronous approved**:
: The approval requires out-of-band approval (e.g., administrator
consent, deferred approval) and cannot complete within the response
window. The state authority returns a pending status with an
operation identifier and, optionally, a polling endpoint or
event-channel identifier. When approval completes the state
authority creates the resulting Mission and notifies the
orchestrator through the substrate profile's defined notification
mechanism.

**Denied**:
: The approval event terminated with rejection or withdrawal. The
state authority returns a denial outcome. The denial MAY include a
reason code from the Framework's denial vocabulary. A denial does
not invalidate the Expansion Ticket beyond its single-use semantics
(an expired or used ticket is rejected; an unused ticket whose
expansion was denied is consumed and MUST NOT be reused).

**Expired**:
: The Expansion Ticket expired before submission, or the AuthZEN
Access Request's response window elapsed before adjudication
completed in synchronous mode. The orchestrator MAY request a fresh
denial-with-eligibility from the denying party to obtain a new
ticket; the original ticket MUST NOT be reused.

## Replacement and Branch

A successful expansion creates either a successor Mission
(Replacement) or a child Mission (Branch). The orchestrator declares
the requested mode on the expansion request as
`expansion_mode`. The state authority's derivation policy MAY narrow
or refuse the requested mode. The resulting Mission records the
mode the state authority applied as `mission.expansion_mode`.

### Replacement Expansion

A Replacement expansion creates a successor Mission whose Authority
Set contains:

- The explicitly approved unchanged authority of the predecessor
  Mission (carried forward, not implicitly inherited).
- The approved addition (the narrowed `requested_authority`).

The state authority MUST:

- Create the successor atomically with the predecessor's transition
  to `completed`. Successor activation and predecessor completion
  are a single atomic operation.
- Record on the successor:
  - `mission.predecessor` referencing the predecessor's canonical
    `mission.id`.
  - `mission.expansion_mode` = `replacement`.
  - A new `proposal_id` and Mission `mission.id` distinct from the
    predecessor's.
  - Fresh integrity anchors (`proposal_hash`, `authority_hash`,
    `consent_disclosure_hash`) computed over the successor's
    Validated Mission Intent, Authority Set, and consent disclosure
    object, per the Framework.
- Reset Framework counters that the registered constraint rule
  declares as per-Mission (e.g., `max_derivations` for the
  successor begins at zero per
  {{I-D.draft-mcguinness-mission-framework}}); the predecessor's
  counter is final.

If the atomic activation fails, the predecessor remains `active`
and no successor record exists. The state authority MUST NOT
produce a partial Mission record.

Credentials bound to the completed predecessor follow the deployment's
advertised stale-state enforcement class per the substrate profile.
Such credentials MUST NOT be silently rebound to the successor. A
substrate profile MAY define a credential re-derivation path against
the successor; that derivation is a new derivation event and is
governed by the successor's Authority Set.

### Branch Expansion

A Branch expansion creates a child Mission that exists alongside the
predecessor. The predecessor remains `active`. The child's Authority
Set contains only the authority explicitly approved for the child
(the narrowed `requested_authority`); it does NOT carry forward any
predecessor authority.

The state authority MUST:

- Create the child Mission with its own approval event evidence and
  integrity anchors.
- Record on the child:
  - `mission.predecessor` referencing the predecessor's canonical
    `mission.id`.
  - `mission.expansion_mode` = `branch`.
  - A new `proposal_id` and Mission `mission.id`.

Predecessor credentials continue to derive against the predecessor
Authority Set. Child credentials derive against the child Authority
Set only. The two Missions evolve independently for lifecycle
purposes after creation; revoking the predecessor does NOT
automatically revoke the child, and revoking the child does NOT
affect the predecessor.

A deployment MAY define policy that propagates predecessor lifecycle
events (e.g., revocation) to branches. Such propagation is policy-
specific and MUST be documented by the deployment; it is not
implied by the Branch relationship alone.

### Rollback after activation

Rollback of a Replacement expansion is a new governed transition or
a new expansion request. The state authority MUST NOT implicitly
resurrect a `completed` predecessor when a successor is later
revoked, expired, or completed. If a deployment requires "revert to
predecessor" semantics, that semantic is expressed as a separate
approval event that establishes a new Mission carrying the relevant
authority; the lineage is preserved through `mission.predecessor`
chaining.

## Concurrent Expansion Reconciliation

More than one expansion request MAY be in flight against the same
predecessor Mission at the same time. Reconciliation rules ensure
that only one successor is created per predecessor in Replacement
mode, and that ticket and predecessor state are consistent at
adjudication.

The state authority MUST serialize adjudications against the same
predecessor with compare-and-set semantics. At the moment of
adjudication the state authority MUST verify:

1. The Expansion Ticket has not been consumed by an earlier
   adjudication.
2. The predecessor Mission is still in the `active` state.
3. No other Replacement expansion has already produced a successor
   for the predecessor.

If any check fails, the state authority returns one of the
reconciliation status codes defined in
{{reconciliation-status-codes}}. The closed set defined here is:

- `superseded_by_concurrent_expansion`: A concurrent Replacement
  expansion has already produced a successor; the predecessor is
  no longer `active`. The orchestrator SHOULD discover the
  successor Mission (e.g., via Mission Status) and re-evaluate
  whether expansion is still required.
- `predecessor_state_changed`: The predecessor transitioned out of
  `active` (e.g., to `suspended`, `revoked`, `completed`, or
  `expired`) before this request could be adjudicated. The
  orchestrator MUST NOT proceed against this predecessor with this
  request.
- `ticket_invalidated`: The Expansion Ticket is invalid: it has
  expired, has already been used, or does not match the
  predecessor or audience the issuing party recorded for it.
- `expansion_mode_unavailable`: The requested `expansion_mode` is
  not permitted by the state authority's derivation policy for
  this predecessor (e.g., Replacement is refused because the
  predecessor is bound to other in-flight workflows; Branch is
  refused because the requested authority overlaps the predecessor
  in a way the policy disallows).

Branch expansions MAY proceed concurrently with one another for the
same predecessor; each Branch is independent. Concurrent Branch
adjudications do not produce reconciliation conflicts unless the
state authority's policy explicitly serializes them.

A Replacement adjudication and a Branch adjudication MAY both be in
flight against the same predecessor. If the Replacement adjudication
commits first, in-flight Branch adjudications against the predecessor
MUST be returned `predecessor_state_changed`, because the predecessor
has transitioned to `completed`.

# Mission Expansion Ticket {#ticket}

The Mission Expansion Ticket is an opaque, single-use, time-limited
bearer issued by the state authority and surfaced through the
eligibility-bearing denial response. The Ticket carries no
information the holder is expected to parse; its sole function is to
identify, at the state authority, the predecessor Mission and the
denial context the eligibility was issued for.

Ticket requirements:

- **Opacity**: A Ticket MUST be an opaque URL-safe string. It MUST
  NOT encode the predecessor Mission identifier, the requested
  authority, or the orchestrator identity in a form the holder can
  parse.
- **Unpredictability**: A Ticket MUST be cryptographically
  unpredictable. Implementations MUST use a cryptographically
  secure random source meeting the requirements of {{RFC4086}}. A
  Ticket MUST carry at least 128 bits of entropy.
- **Single use**: A Ticket MUST NOT be reused. The state authority
  MUST invalidate the Ticket on first successful presentation,
  whether the resulting adjudication approves or denies the
  expansion. A Ticket presented a second time MUST be rejected with
  reconciliation status `ticket_invalidated`.
- **Time-limited**: A Ticket MUST be time-limited. The default
  eligibility window is 300 seconds from issuance. Deployments MAY
  shorten the window; deployments SHOULD NOT extend it without
  documented policy justification. A Ticket MUST be invalidated on
  expiry.
- **Binding**: The state authority MUST bind the Ticket internally to
  the predecessor Mission, the `requested_authority` recorded at
  issuance, the issuing party's audience, and the issuance
  timestamp. Adjudication MUST verify each binding.
- **Audience scoping**: A Ticket is scoped to the state authority
  that issued it. A Ticket presented to a different state authority
  MUST be rejected.
- **No bearer authority**: A Ticket is not an authorization
  credential. Possession of a Ticket does not grant access. The
  orchestrator's authentication is required at the expansion
  request endpoint; the Ticket only identifies the denial context.

The substrate profile defines the transport of the Ticket in the
denial response and on the expansion request. The Framework Mission
Status interface MAY also surface a Ticket's presence in audit
projections; substrate profiles define the projection if exposed.

A Ticket is distinct from any substrate-specific deferred-grant
token or step-up challenge. A Ticket initiates a new approval event;
it does not authenticate the approving principal.

# Security Considerations

## Ticket bearer risk

Although a Ticket is not an authorization credential, its
presentation initiates a state-authority adjudication that may lead
to a new approval event. An attacker who obtains a valid Ticket and
the orchestrator's authentication credentials could submit an
expansion request the legitimate orchestrator did not intend.

Mitigations:

- The Ticket MUST be transported over an authenticated, integrity-
  protected channel between the denying party and the orchestrator.
- The state authority MUST authenticate the orchestrator at the
  expansion request endpoint independently of the Ticket.
- The Ticket's short default window (300 seconds) limits exposure
  if a Ticket leaks.
- The state authority MUST enforce single-use semantics atomically.

## Approval event substitution

A denial-with-eligibility identifies a `requested_authority`. An
adversarial orchestrator could attempt to submit an expansion
request with a different requested authority than the denial issued.

Mitigations:

- The state authority MUST verify that the requested authority on
  the expansion request is a subset of the `requested_authority`
  recorded with the Ticket at issuance, per the Framework's
  registered narrowing rules for each Authority Set entry type.
- The state authority MUST reject any request that enlarges the
  requested authority beyond the issued denial's
  `requested_authority`.
- Consent disclosure rendered to the approving principal MUST
  reflect the requested authority being adjudicated.

## Predecessor confusion

An adversary could attempt to apply a Ticket against the wrong
predecessor Mission (e.g., a Mission belonging to a different tenant
or subject).

Mitigations:

- The state authority MUST bind the Ticket to the predecessor at
  issuance and resolve the predecessor from the Ticket at
  adjudication. The orchestrator's input MUST NOT change the
  predecessor.
- The Framework's authorization-domain-bound integrity envelope
  prevents cross-tenant transplantation of the predecessor's
  governance state.

## Expansion mode coercion

Branch expansion is intended to preserve unrelated predecessor
authority. A misuse of Branch could create a child Mission that
duplicates predecessor authority and produces an unintended cross-
audience surface.

Mitigations:

- The state authority's derivation policy SHOULD refuse Branch
  expansions whose authority overlaps the predecessor in ways the
  policy considers unsafe.
- The state authority MAY narrow a Branch request to a Replacement
  if policy requires.
- Audit projections for branches SHOULD make the predecessor
  lineage observable via `mission.predecessor`.

## Race against predecessor lifecycle

Between Ticket issuance and adjudication, the predecessor Mission
may be revoked, suspended, completed, or expired. Without a
serialization check, an expansion could appear to succeed against
a predecessor that is no longer authoritative.

Mitigations:

- The state authority MUST verify predecessor state at adjudication
  per {{concurrent-expansion-reconciliation}}.
- The `predecessor_state_changed` reconciliation status communicates
  the failure to the orchestrator without leaking the new state.
- Mission Status remains the authoritative interface for current
  predecessor state.

## Expansion vs step-up

Expansion is not authentication step-up. A request denied for
insufficient `acr` or `amr` is satisfied by fresh authentication
{{RFC9470}}, not by expansion. Conflating the two would route
authentication problems through an approval event the approving
principal did not need to perform, surfacing irrelevant consent and
risking principal fatigue.

Mitigation: substrate profiles MUST classify denials such that
authentication-related denials (`acr`, `amr`) route to step-up
and authority-shortfall
denials route to expansion. The `eligible` field signals expansion
eligibility specifically; it is not a generic "additional input
required" marker.

## Concurrent expansion exposure

A long-running orchestrator could in principle submit many
expansion requests for the same predecessor, attempting to discover
the state authority's policy boundary.

Mitigations:

- The state authority SHOULD rate-limit expansion requests per
  predecessor per orchestrator.
- Denial reasons SHOULD NOT leak unrequested policy boundaries; a
  denial returns whether the requested authority was approved, not
  the full surface of what would have been.

## Audit linkage

The `mission.predecessor` and `mission.expansion_mode` attributes
make expansion lineage observable in audit. Authorized auditors can
trace successor and child Missions back through the chain. An
implementation that omits these attributes breaks audit linkage and
defeats one of the core governance properties of expansion.

# Privacy Considerations {#privacy-considerations}

The privacy surface introduced by expansion is concentrated in the
lineage attributes and in the authority and consent detail disclosed
when a Mission is expanded. The considerations below are the
expansion-specific additions to the Framework's privacy treatment.

## Predecessor-chain correlation

The same `mission.predecessor` and `mission.expansion_mode`
attributes that provide governance audit linkage ({{audit-linkage}})
are also a correlation surface: they link a successor or child
Mission to its predecessor across distinct approval events. A party
authorized to read the lineage -- or to read Mission Status
projections that expose it -- can correlate the evolving task over
time and across the Missions in a chain, which is more than any
single Mission discloses on its own. This linkage is intrinsic to
the governance value of expansion and is not a defect, but
deployments SHOULD scope read access to lineage attributes and to
Mission Status lineage projections to the parties with a governance
need, rather than exposing the chain to every credential audience.

## Requested-authority and consent disclosure

The `requested_authority` carried in an eligibility-bearing denial,
and the consent disclosure rendered at the expansion approval event,
reveal how the approved task is evolving. A denial that surfaces
`requested_authority` to a party broader than the orchestrator
discloses intent that party may not need. Substrate profiles binding
the eligibility contract SHOULD surface `requested_authority` only to
the orchestrator entitled to act on it, and the state authority
SHOULD render consent disclosure only to the approving principal and
authorized governance consumers.

## Ticket non-correlation

The Mission Expansion Ticket is opaque, single-use, and carries no
parseable identity or authority ({{ticket}}); it is not a
correlation handle. A holder cannot derive the predecessor identity,
the subject, or the requested authority from the Ticket, and a used
or expired Ticket links nothing. The correlation surface of
expansion is the lineage attributes, not the Ticket.

# IANA Considerations

This document creates one new registry (the Mission Expansion
Reconciliation Status registry, {{reconciliation-status-codes}})
and defines two Mission record attributes. Consistent with the
Framework, which does not IANA-register the fields of the Mission
record, the `mission.predecessor` and `mission.expansion_mode`
attributes are defined by this specification rather than registered
in a dedicated IANA registry; substrate profiles
({{I-D.draft-mcguinness-mission-oauth-profile}},
{{I-D.draft-mcguinness-mission-aauth-profile}}) register the
substrate-specific wire names through which each attribute is
surfaced (e.g., JWT claim names, AAuth fields).

## `mission.predecessor` Attribute

- **Name**: `mission.predecessor`.
- **Type**: string. URL-safe ASCII matching the Framework's
  `mission.id` format. The predecessor is identified by canonical
  `mission.id`.
- **Defining specification**: This document.
- **Cardinality**: at most one per Mission record. A Mission record
  has at most one direct predecessor; chains are expressed by
  walking predecessor links.
- **Mutability**: Immutable. Set at the successor's or child's
  approval event; MUST NOT change thereafter.
- **Substrate registration**: The OAuth Profile
  {{I-D.draft-mcguinness-mission-oauth-profile}} registers the
  corresponding JWT-level claim or `mission` claim member that
  surfaces this attribute on derived credentials. The AAuth Profile
  {{I-D.draft-mcguinness-mission-aauth-profile}} registers the
  AAuth-side surfacing.

## `mission.expansion_mode` Attribute

- **Name**: `mission.expansion_mode`.
- **Type**: string. Closed enumeration: `replacement`, `branch`.
- **Defining specification**: This document.
- **Cardinality**: at most one per Mission record. Present only on
  Missions created through expansion; absent on Missions created
  from an initial Mission Proposal.
- **Mutability**: Immutable. Set at the successor's or child's
  approval event; MUST NOT change thereafter.
- **Substrate registration**: As for `mission.predecessor`,
  substrate profiles register the on-the-wire surfacing.

## Concurrent Expansion Reconciliation Status Codes {#reconciliation-status-codes}

This document registers a new "Mission Expansion Reconciliation
Status" registry.

- **Registration policy**: Specification Required.
- **Required fields per entry**: `name`, `summary`, defining
  specification, change controller.
- **Initial entries**:
  - `superseded_by_concurrent_expansion` (this document):
    A concurrent Replacement expansion has already produced a
    successor; the predecessor is no longer `active`.
  - `predecessor_state_changed` (this document):
    The predecessor transitioned out of `active` before this
    request could be adjudicated.
  - `ticket_invalidated` (this document):
    The Expansion Ticket is expired, used, or does not match the
    predecessor or audience the issuing party recorded.
  - `expansion_mode_unavailable` (this document):
    The requested `expansion_mode` is not permitted by the state
    authority's derivation policy for this predecessor.

Substrate profiles map these symbolic codes to substrate-appropriate
transport (e.g., HTTP status codes, OAuth error codes, AAuth error
codes).

## Eligibility-Signaling Field Names

This document defines, but does NOT itself register on any substrate
wire, the abstract field names `eligible`, `access_request_uri`,
`ticket`, and `requested_authority` for denial responses. The OAuth
Profile {{I-D.draft-mcguinness-mission-oauth-profile}} and the AAuth
Profile {{I-D.draft-mcguinness-mission-aauth-profile}} register
substrate-specific field names through which the abstract contract
is surfaced. Coordination with the AuthZEN Access Request
{{I-D.draft-mcguinness-authzen-access-request}} ensures that the
expansion request envelope carries the Ticket and
`requested_authority` consistently across substrates.

## What this document does NOT register

- A Mission Expansion Ticket media type. Tickets are opaque strings
  surfaced through substrate-defined transport; no new media type
  is required.
- A new endpoint name. The `access_request_uri` is a URI advertised
  by the state authority's metadata document per the Framework
  {{I-D.draft-mcguinness-mission-framework}}; the substrate profile
  registers the metadata field name that surfaces this URI.

# Acknowledgments
{:numbered="false"}

The author thanks the reviewers of the Mission-Bound Authorization
architecture and the OpenID AuthZEN working group for feedback on
the expansion model and its composition with the AuthZEN Access
Request.

--- back
