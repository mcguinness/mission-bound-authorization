---
title: "Mission Runtime Evidence"
abbrev: "Mission Runtime Evidence"
category: std

docname: draft-mcguinness-mission-runtime-evidence-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - evidence
 - audit
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6234:
  RFC6838:
  RFC7515:
  RFC7518:
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

informative:
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
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
  I-D.draft-mcguinness-mission-capability-binding:
    title: "Mission Capability Binding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-capability-binding.html
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

--- abstract

Mission-Bound Runtime Enforcement defines an abstract decision
contract: a Policy Decision Point evaluates each consequential
action against the established Mission and returns a permit or a
classified failure. This document defines the records a deployment
emits to make that decision durable and verifiable: the Decision
Evidence Object, the Execution Evidence Object, and the Refusal
Record, together with their integrity envelope, media types, and
retention rules. It also defines the Mission Receipt, a signed
manifest projecting these records into one portable object a holder
can present without shipping a log. The records are defined against
the runtime profile's abstract decision output and failure
classification, so any decision-API binding produces the same
records; the OpenID AuthZEN binding is one such producer.

--- middle

# Introduction

Mission-Bound Runtime Enforcement
{{I-D.draft-mcguinness-mission-runtime}} (the "runtime profile")
defines the abstract decision contract for enforcing a Mission-bound
credential at the point of use: a Policy Enforcement Point (PEP)
obtains a permit from a Policy Decision Point (PDP) before each
consequential action, and every decision or refusal MUST produce a
runtime enforcement evidence record. The runtime profile fixes the
minimum record content and leaves the concrete record schema and
integrity envelope to this document, so a Standards-Track
decision-API binding, and any future binding, emits the same
records.

This document defines three record types: the Decision Evidence
Object, for a PDP's decision on a consequential action; the
Execution Evidence Object, for the outcome of a permitted action;
and the Refusal Record, for a PEP or PDP refusal that occurs before
any PDP decision. It fixes their members, canonicalization, integrity
envelope, media types, and retention. A decision-API binding maps
its own wire request and response onto these records; the OpenID
AuthZEN Profile {{I-D.draft-mcguinness-mission-authzen}} is the
family's Standards-Track binding and the reference producer this
document's examples are drawn from. `evaluation_id` is the
correlation key across every record and wire artifact of one
evaluation; each record additionally carries its own record
identifier (`evidence_id`, `execution_id`, or `refusal_id`). This
document additionally defines the Mission Receipt
({{mission-receipt}}), the portable projection over these records
that a holder presents in place of the records themselves.

This document does not restate the runtime profile's decision
contract, action classification, or failure conditions; those are
normatively defined in {{I-D.draft-mcguinness-mission-runtime}} and
are referenced, not duplicated, here.

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This document uses JSON {{RFC8259}} as the data model for every
record it defines. JCS canonicalization {{RFC8785}} applies wherever
an integrity hash is computed, under the canonicalization rules of
{{I-D.draft-mcguinness-oauth-mission}}; this document does not
define a second canonicalization.

"SHA-256" refers to {{RFC6234}}. A digest is encoded in the
integrity-anchor encoded form of
{{I-D.draft-mcguinness-oauth-mission}}: `sha-256:` followed by the
base64url, no-padding encoding of the digest. Every digest this
document defines (`evaluation_request_digest`, `entry_digest`,
`effective_parameter_digest`, the Mission Receipt's evidence-reference
and chain-predecessor digests, {{mission-receipt}}) is a
canonical-object digest under the
substrate's default commitment construction, which this document
imports normatively ({{I-D.draft-mcguinness-mission-substrate}}),
except that an evidence reference to a compact-serialized artifact is
a raw-octet digest over the exact serialization octets
({{receipt-evidence}}).

The terms Policy Enforcement Point (PEP), Policy Decision Point
(PDP), consequential action, action class (and the action-class
names consequential read, consequential write, irreversible action,
external commitment, and privileged administration), high-consequence
classes, and parameter-bound are used as defined in
{{I-D.draft-mcguinness-mission-runtime}}. The Mission claim (`id`,
`issuer`, `authority_hash`), the integrity anchors (`intent_hash`,
`authority_hash`), and `authorization_details` entries of type
`mission_resource_access` are used as defined in
{{I-D.draft-mcguinness-oauth-mission}}.

Additional terms:

Decision Evidence:
: The record a PDP emits for a decision on a consequential action
  ({{decision-evidence-object}}).

Execution Evidence:
: The record a PEP or executor emits after a permitted action's
  outcome is determined ({{execution-evidence-object}}).

Refusal Record:
: The record a PEP or PDP emits for a refusal that occurs before any
  PDP decision ({{pre-decision-refusal}}).

Executor:
: The component that carries out a permitted action and emits
  Execution Evidence. It is the PEP in the common case, or a
  distinct component where the requesting PEP and the executing
  component differ.

Producer:
: The PDP, PEP, or executor that emits and signs a record defined by
  this document.

Consumer, Verifier:
: A component or role that reads a record defined by this document
  to reconstruct or verify a decision or execution after the fact.

Decision-API binding:
: The deployment-chosen wire protocol that maps the runtime profile's
  abstract decision contract onto a concrete PEP-PDP request and
  response ({{I-D.draft-mcguinness-mission-runtime}}). This document
  is defined against that abstract contract and is independent of
  any one binding's wire.

HTTP and JSON message examples in this document follow the wire
shape of the OpenID AuthZEN Authorization API binding
{{I-D.draft-mcguinness-mission-authzen}}, the family's reference
producer; a deployment using a different decision-API binding
produces the same records from its own wire inputs.

# Mission Substrate {#mission-substrate}

This document is defined against the Mission model rather than
against OAuth 2.0 mechanics: it is a substrate-neutral consumer, and
this section is its consumption declaration under the rule of Mission
Substrate Requirements ({{I-D.draft-mcguinness-mission-substrate}})
that a substrate-neutral profile declare the kernel functions and
optional capabilities it consumes.

It is a kernel-only consumer. From the contextual-governance kernel
it consumes the Mission identifier and issuer, the kernel's Mission
Reference and Controller, carried in every record's `mission` object.
Its records are not the kernel's ordered governance record: that
record is the Controller's own ordered record of governance events,
where this document's records form PDP, PEP, and executor emitter
streams, ordered per emitter by `sequence`, correlated per evaluation
by `evaluation_id`, and joinable to the Mission through the `mission`
object ({{decision-evidence-object}}). They are a separate, joinable
evidence stream, retained no shorter than the Mission's audit horizon
({{execution-evidence-object}}), which the audit profile may
incorporate ({{I-D.draft-mcguinness-mission-audit}}).

Its declaration against the optional capabilities:

| Capability | Consumption | Scope of consumption |
| --- | --- | --- |
| Structured Authority | not consumed | Recording `contributing_constraints`, `authorization_details` entry types, and cited anchors is correlation, not machine-evaluable authority consumption; the runtime profile consumes Structured Authority and supplies the decision facts these records carry ({{I-D.draft-mcguinness-mission-runtime}}, {{decision-evidence-object}}) |
| Lifecycle-Gated Authorization | not consumed | The decision contract, action classification, and failure conditions are the runtime profile's; this document records decisions, it does not gate them ({{I-D.draft-mcguinness-mission-runtime}}) |
| State-Observable | not consumed | `mission_state_version` records the state version a decision consulted, when the PDP tracks one; establishing Mission state is the runtime profile's concern ({{decision-evidence-object}}) |
| Monotonic Derivation | not consumed | No record derives or narrows authority; anchors are cited for correlation, never compared |
| Credential-Bound | not consumed | The Mission enters a record as the decision request's Mission reference object; this document verifies no credential binding ({{decision-evidence-object}}) |
| Independently Verifiable | not consumed | Not consumed, and supplied in scoped form: verification is anchored in the Enforcement Scope Statement's published keys, so a party with access to that statement verifies a record independently of the deployment that emitted it ({{evidence-integrity-signing-keys}}) |
| Portable Evidence | not consumed | Not supplied by this document alone: portability beyond a party with access to the deployment's published keys requires the transparency mechanisms of the audit profile ({{evidence-integrity-signing-keys}}, {{I-D.draft-mcguinness-mission-audit}}) |
{: title="Runtime evidence capability consumption"}

This document is defined against the runtime profile's abstract
decision contract and is independent of any one decision-API
binding's wire ({{conventions-and-definitions}}). The portability
claim is capability-scoped rather than substrate-wide for the reason
the substrate's Capability Confusion consideration states: every
property this document requires matches an explicit capability claim
and its scope, never the generic statement that a binding supports
Missions.

# Decision Evidence Object {#decision-evidence-object}

The runtime profile requires a decision evidence record for every PDP
decision on a consequential action and fixes the minimum content and
local integrity requirements. This section gives the concrete object,
canonicalization, and integrity envelope a deployment emits.

## Members

`evidence_id`:
: REQUIRED. A string. Unique record identifier for this Decision
  Evidence Object. ABNF: `1*64( ALPHA / DIGIT / "-" / "_" )`. At
  least 128 bits of entropy.

`evaluation_id`:
: REQUIRED. A string. The correlation identifier for the evaluation
  this record documents: the abstract evaluation identifier of the
  runtime profile's Decision Output
  ({{I-D.draft-mcguinness-mission-runtime}}), as carried by the
  deployment's decision-API binding (for example, the AuthZEN binding
  carries this as the decision-API response's evaluation identifier,
  {{I-D.draft-mcguinness-mission-authzen}}). Distinct
  from `evidence_id`: `evaluation_id` correlates this record with the
  evaluation and with every other record and wire artifact of the same
  evaluation; `evidence_id` names this evidence record alone.

`mission`:
: REQUIRED. An object. The decision request's Mission reference
  object, extended with the facts below, so the evidence chains back
  to the exact approved Mission. Sub-members:

    `id`, `issuer`, `authority_hash`:
    : REQUIRED. From the request's Mission reference.

    `policy_view_id`:
    : REQUIRED. The PDP's own view identifier; the PDP always knows
      and populates it, whatever the request carried.

    `intent_hash`:
    : OPTIONAL. It is carried in neither the `mission` claim nor
      introspection, so only a PDP with direct Mission-record access
      can record it.

    `policy_version`:
    : OPTIONAL. From the request's Mission reference, when known.

    Consent-disclosure commitment:
    : OPTIONAL. Recorded when known.

  These hashes are the issuing AS's
  commitments cited as anchors; the PDP does not recompute them.

`subject`:
: REQUIRED. An object. Subject identifiers and assurance metadata,
  never a raw claim set, minimized per the deployment's audit policy.

`resource`:
: REQUIRED. An object. The resource identifier and type; any further
  resource properties are minimized to what the deployment's audit
  policy declares.

`action`:
: REQUIRED. An object. The action's name or identifier and
  non-sensitive classification metadata only. It MUST NOT contain the
  request's `properties.parameters`, under any name: the parameter
  binding this record carries is `parameter_digest` alone, an
  evidence projection of the decision request rather than a
  pass-through of it.

`audience`:
: REQUIRED. A string. The audience the PDP evaluated: the runtime
  profile's audience input to the Decision Output
  ({{I-D.draft-mcguinness-mission-runtime}}), as carried by the
  deployment's decision-API binding (for example, the AuthZEN
  binding's decision-API request's audience member,
  {{I-D.draft-mcguinness-mission-authzen}}).

`mission_state_version`:
: OPTIONAL. An integer. The Mission lifecycle-state version the
  decision consulted, when the PDP tracks one: the mutable-state
  counterpart of the compiled-authority `policy_view_id`
  ({{I-D.draft-mcguinness-mission-runtime}}). The PDP computes and
  records it directly; no decision-API wire echo is required.

`action_class`:
: REQUIRED. A string. The runtime action class the PDP applied to the
  action: one of `consequential_read`, `consequential_write`,
  `irreversible_action`, `external_commitment`, or
  `privileged_administration`, naming the classes of
  {{I-D.draft-mcguinness-mission-runtime}}. Every decision this
  document records is on a consequential action, so the member is
  always present.

`class_source`:
: REQUIRED when `action_class` is present. A string. How the applied
  class was assigned: `default` (the runtime profile's default
  classification), `resource_floor` (the resource's published
  `mission_action_class_floors` floor set or raised it,
  {{I-D.draft-mcguinness-mission-runtime}}), or `deployment`
  (deployment policy assigned it).

`actor`:
: OPTIONAL. An object. Actor-chain identifiers and assurance
  metadata, never a raw claim set, minimized per the deployment's
  audit policy.

`credential`:
: OPTIONAL. An object. Credential-derived identifiers and assurance
  metadata, never a raw claim set, minimized per the deployment's
  audit policy. This member MUST contain only claims the PEP verified
  before invoking the PDP.

`parameter_digest`:
: OPTIONAL. A string. The parameter digest the decision was bound to
  ({{I-D.draft-mcguinness-mission-runtime}}); REQUIRED for a
  parameter-bound action.

`obligations`:
: REQUIRED whenever the decision response contained obligations, on
  either decision. An array of obligation objects, recorded as
  returned to the PEP (for example, as carried by the AuthZEN
  binding, {{I-D.draft-mcguinness-mission-authzen}}).

`conditions`:
: REQUIRED when `decision` is `permit` for a consequential action. An
  object recording the permit's decision conditions in this
  document's normalized form: `valid_until` (the validity bound) and
  `use_limit` (the consumption bound on `evaluation_id`; the PDP MUST
  set `use_limit: 1` for a permit in the high-consequence classes).
  The parameter binding is recorded once, in this record's
  `parameter_digest` member; the producer MUST ensure that value
  equals the binding carried by the wire conditions. A binding maps
  its wire members onto this form (for example the AuthZEN binding's
  `conditions` response member,
  {{I-D.draft-mcguinness-mission-authzen}}).

`evaluation_request_digest`:
: CONDITIONAL. A string. A privacy-preserving digest of the whole
  evaluation request, in the integrity-anchor encoded form
  ({{I-D.draft-mcguinness-oauth-mission}}). REQUIRED when
  `parameter_digest` is absent for a consequential action, so the closed
  object still carries the request digest the runtime profile requires
  of every decision record ({{I-D.draft-mcguinness-mission-runtime}}).
  Distinct from `parameter_digest`: that member records the parameter
  binding the decision was bound to;
  `evaluation_request_digest` is this record's fallback digest of the
  whole evaluation request, present whether the decision was a permit
  or a deny.

`compensates_evaluation_id`:
: OPTIONAL. A string. The `evaluation_id` of the action this decision
  compensates, carrying the runtime profile's compensation link
  ({{I-D.draft-mcguinness-mission-runtime}}) so a compensating
  action reconciles against the action it reverses.

`decision`:
: REQUIRED. A string. One of `permit` or `deny`.

`contributing_constraints`:
: REQUIRED when the decision turned on one or more authority or
  constraint entries. An array of strings: the identifiers of the
  constraints and entries the PDP evaluated (`constraints` keys,
  `authorization_details` entry types). For a permit it records every
  constraint key and entry type the decision relied on; for a deny it
  MUST list every entry that failed. Omitting an entry the decision
  turned on is non-conforming. The identifiers support correlation and
  targeted reconstruction of the decision, given access to the policy
  content and inputs those identifiers name; the array alone, without
  that access, does not reconstruct the decision basis.

`sequence`:
: REQUIRED. An integer. The per-Mission sequence indicator
  the runtime profile requires, so one emitter's decision stream has a
  verifiable order and gaps are detectable. MUST be zero or greater.
  The sequence is scoped to the emitter identified by `emitter`: each
  emitter maintains its own monotonically increasing per-Mission
  sequence, and a verifier detects gaps and orders records within
  (Mission, emitter). It does not reconstruct Mission-wide decision
  order across emitters: cross-emitter ordering is best-effort,
  established, where the deployment's evidence supports it, from the
  correlation members (`evaluation_id`, `mission.id`, `hop_reference`)
  together with each record's timestamps, not from `sequence` alone.

`emitter`:
: REQUIRED. An object. The identity of the component that emitted and
  signed this record, with members `id` (REQUIRED, a string identifying
  the emitting component) and `role` (REQUIRED, one of `pdp`, `pep`, or
  `executor`). For Decision Evidence `role` is `pdp`. A companion
  profile MAY register coordinated additional roles (`harness`,
  `egress`, `issuer`) for records emitted under these conventions at
  other enforcement points, or by the Mission Issuer's own retained
  producers (for example, protected-event ingestion,
  {{I-D.draft-mcguinness-oauth-mission-containment}}). A verifier MUST
  bind the emitter's signing key to the enforcement scope and audience
  the record serves ({{decision-evidence-integrity}}).

`denial_reason`:
: CONDITIONAL. A string. Present when `decision` is `deny`. A value
  naming the runtime profile's failure-condition classification
  ({{I-D.draft-mcguinness-mission-runtime}}), as carried by the
  deployment's decision-API binding, including any
  specification-defined extension under that binding's extensibility
  rule; a consumer MUST treat an unrecognized value as a deny and MUST
  NOT attach any other semantics to it. For example, the AuthZEN
  binding carries this as its wire denial-reason strings
  ({{I-D.draft-mcguinness-mission-authzen}}). When the denial
  is a constraint violation, the value is `parameter_violation` and the
  specific failing `constraints` keys are carried in
  `contributing_constraints`, not in `denial_reason`, so the reason
  enum and the open constraint-key space never mix in one field.

`evaluated_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp. The runtime profile's
  decision timestamp ({{I-D.draft-mcguinness-mission-runtime}}), as
  carried by the deployment's decision-API binding.

`authorizing_entry`:
: OPTIONAL. An object. The `authorization_details` entry the decision
  was evaluated against.

`entry_digest`:
: OPTIONAL. A string. The integrity-anchor encoded digest
  ({{I-D.draft-mcguinness-oauth-mission}}) of that entry, for a
  deployment that does not record the entry in full. A record of a
  permit MUST carry `authorizing_entry` or `entry_digest`, per the
  runtime record requirements
  ({{I-D.draft-mcguinness-mission-runtime}}).

`evidence_envelope`:
: REQUIRED. An object. Integrity protection
  ({{decision-evidence-integrity}}), carrying a `format` (string,
  required) and a `value` (string, required).

A Decision Evidence Object is closed to uncoordinated extension; see
{{evidence-extensions}} for the extension rule and the coordinated
extension members a deployment following the AuthZEN binding
commonly carries (`taint`, `mission_history`, `capability_source`,
`hop_reference`).

## Refusal Record {#pre-decision-refusal}

The Decision Evidence Object records a PDP decision, which is why its
PDP-derived members are REQUIRED. The runtime profile also requires an
evidence record for a refusal that occurs before any PDP decision,
whether the refusing component is the PEP or the PDP: a PEP refusal
for token validation failure, a missing `mission` claim, PEP-PDP
channel failure, PDP unreachability, or the PEP being unable to
establish Mission state ({{I-D.draft-mcguinness-mission-runtime}}); or
a PDP refusal of an in-scope request that reaches it without the
Mission decision context a runtime enforcement scope requires, per
the AuthZEN binding ({{I-D.draft-mcguinness-mission-authzen}}). Such a
refusal has no PDP decision and cannot populate the PDP-derived
members above. A deployment records it as a Refusal Record, carrying
only facts the refusing role verified: a PEP populates the members it
can attest from token validation and its own state establishment; a
PDP populates the members it can attest from the request it received.
Neither role attests facts only the other could verify: the PDP
cannot attest PEP-side token checks, and the PEP cannot attest the
PDP's own context-completeness check. The boundary is the PDP
decision: a Refusal Record is exclusively pre-decision, and once a
PDP has decided, every final disposition of a consequential permit,
whether completed, failed, or suppressed before release, is Execution
Evidence ({{execution-evidence-object}}), never a Refusal Record:

`refusal_id`:
: REQUIRED. A string. Unique refusal identifier. ABNF:
  `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of entropy.

`audience`:
: REQUIRED. A string. The audience or protected-resource identifier,
  as the refusing component established it.

`action`:
: REQUIRED. An object. The requested action descriptor, as the
  refusing component established it.

`resource`:
: OPTIONAL. An object. The target object identity, when the refusing
  component established one.

`decision`:
: REQUIRED. A string. Always `deny`.

`denial_reason`:
: REQUIRED. A string. For a PEP refusal, one of `token_invalid`,
  `mission_claim_missing`, `channel_failure`, `pdp_unreachable`, or
  `state_unavailable` (where the deployment's state-source placement
  has the PEP supply state, and it cannot establish it). For a PDP
  refusal of an in-scope request that reaches it without the Mission
  decision context a runtime enforcement scope requires,
  `mission_context_missing`. These name pre-evaluation conditions,
  PEP-side or PDP-side, and are disjoint from the runtime profile's
  PDP denial reasons for an evaluated decision (for example, as
  carried by the AuthZEN binding,
  {{I-D.draft-mcguinness-mission-authzen}}); a record that can
  populate the PDP-derived members of an evaluated decision is a
  Decision Evidence Object instead.

`evaluated_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`parameter_digest`:
: CONDITIONAL. A string. REQUIRED for a parameter-bound action class.

`evaluation_request_digest`:
: CONDITIONAL. A string. A privacy-preserving digest of the whole
  refused request, in the form of {{request-digest-worked}}. REQUIRED
  when `parameter_digest` is absent, so the record meets the runtime
  profile's record minimum
  ({{I-D.draft-mcguinness-mission-runtime}}). Distinct from a granted
  permit's `parameter_digest` condition
  ({{decision-evidence-object}}): a Refusal Record has no PDP decision
  and no permit.

`mission`:
: OPTIONAL. An object. The Mission reference (`id`, `issuer`,
  `authority_hash`), present only when the refusing component
  established it before the failure: for a PEP, for example, on
  `pdp_unreachable`; for a PDP refusing on
  `mission_context_missing`, the reference is typically absent,
  since that is exactly what the request lacked.

`subject`, `actor`, `credential`:
: OPTIONAL. Objects. Verified facts only, in the projected forms
  {{decision-evidence-object}} defines (for example, as carried in the
  AuthZEN binding's decision-API request,
  {{I-D.draft-mcguinness-mission-authzen}}). A PEP populates them from
  its own token validation; a PDP populates them from the request
  context it received, never asserting a check only the other role
  can perform. For a token-validation failure, the record MUST NOT
  describe unverified token claims as authenticated facts
  ({{I-D.draft-mcguinness-mission-runtime}}).

`sequence`:
: CONDITIONAL. An integer. REQUIRED when the record carries a verified
  `mission` reference, continuing that emitter's per-Mission sequence
  for that Mission ({{decision-evidence-object}}); absent when no
  Mission was established.

`emitter`:
: REQUIRED. An object. The identity of the refusing component that
  emitted and signed this record, in the form Decision Evidence
  defines ({{decision-evidence-object}}), with `role` `pep` or `pdp`.
  A verifier MUST bind the emitter's signing key to the enforcement
  scope and audience the record serves
  ({{decision-evidence-integrity}}).

`hop_reference`:
: OPTIONAL. An object, in the coordinated extension form
  {{evidence-extensions}} defines. Present only when the refusing
  component verified enough of the presented credential, before the
  failure, to establish it was a continued credential.

`evidence_envelope`:
: REQUIRED. An object. Integrity protection in the form of
  {{decision-evidence-integrity}}, emitted by the refusing component,
  whose JWS protected `typ` is `application/mission-refusal-record+json`
  ({{iana}}).

A Refusal Record is closed to uncoordinated extension under the same
rule as Decision Evidence ({{evidence-extensions}}).

Refusal Records are per-attempt, immutable, and append-only: a
sustained failure condition with a retrying agent yields one signed
record per attempt, never a record amended or replaced in place. A
deployment MAY maintain a separate derived summary over a series of
Refusal Records for reporting purposes (for example, a count of
refusals sharing `denial_reason`, `audience`, and `action` over a
window). That summary is not a Refusal Record, is not signed as one,
and adds no evidentiary standing beyond the inputs it summarizes.

When the deployment establishes the Mission binding externally under
the runtime profile's binding-establishment step
({{I-D.draft-mcguinness-mission-runtime}}), absence of the `mission`
claim is not a pre-decision refusal and `mission_claim_missing` does
not apply; the external join's verification governs instead.

A PDP outage on the ERP reconciliation Mission, recorded by the PEP
that failed closed:

~~~ json
{
  "refusal_id": "ref_3VtM9kQ2xN7rB4sL8eP1jY5wZc",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "audience": "https://erp.example.com",
  "action": { "name": "journal-entries.write" },
  "resource":
    { "type": "journal-entry", "id": "je_2026Q3_inv_8421" },
  "parameter_digest":
    "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
  "decision": "deny",
  "denial_reason": "pdp_unreachable",
  "sequence": 44,
  "emitter": { "id": "pep.example.com", "role": "pep" },
  "evaluated_at": "2026-11-02T08:16:11Z",
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXkt..."
  }
}
~~~

A PDP-side refusal, recorded by the PDP itself: an in-scope request
reached it without the Mission decision context the AuthZEN binding
requires, so no Mission reference is established and the PDP
populates only what it can attest from the request it received:

~~~ json
{
  "refusal_id": "ref_9NcT4wQ1xM6rB3sK7eV0jY2wLz",
  "audience": "https://erp.example.com",
  "action": { "name": "journal-entries.write" },
  "parameter_digest":
    "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
  "decision": "deny",
  "denial_reason": "mission_context_missing",
  "emitter": { "id": "pdp.example.com", "role": "pdp" },
  "evaluated_at": "2026-11-02T08:17:02Z",
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

## Integrity {#decision-evidence-integrity}

The `evidence_envelope` carries the integrity protection over the
Decision Evidence content. This document defines the concrete
serialization required by {{I-D.draft-mcguinness-mission-runtime}}:
the Decision Evidence object is serialized as JCS {{RFC8785}} canonical
JSON before integrity protection. The default `format` is
`jws-compact`, a JWS Compact Serialization {{RFC7515}} whose payload is
the JCS canonical bytes of the Decision Evidence object with the
`evidence_envelope` member removed during signing.

A verifier MUST perform the following steps, in order, and MUST NOT
treat a record as verified if any step fails:

1. Decode the JWS payload.
2. Compute the JCS {{RFC8785}} canonical bytes of the outer record
   with the `evidence_envelope` member removed.
3. Require byte-for-byte equality between the decoded payload of step
   1 and the canonical bytes of step 2, rejecting the record on any
   difference. The signature authenticates only its own embedded
   payload; an outer object that differs from that payload is
   unauthenticated, regardless of whether the signature itself
   verifies.
4. Verify the JWS signature and protected header against the
   emitter's published signing key.

For Decision Evidence emitted by a PDP, the emitter is the PDP. For
Execution Evidence emitted by a PEP or executor, the emitter is that
PEP or executor. For a Refusal Record, the emitter is the refusing
PEP. This procedure applies wherever verification of the
`evidence_envelope` is described in this document, including for
Execution Evidence and Refusal Records.

A verifier MUST confirm that the signing key selected by the JWS `kid`
is the published key of the component named in the record's `emitter`
member, and that this key is bound to the enforcement scope and
audience the record serves: the record's own `audience` member,
present directly on Decision Evidence, Execution Evidence, and
Refusal Records alike (for Decision Evidence, mirroring the
decision-API request's audience member,
{{I-D.draft-mcguinness-mission-authzen}}). A verifier MUST reject a
record whose signing key is not published for that scope, so one
component's key cannot sign evidence for a resource, audience, or
scope it does not serve.

The JWS protected header MUST carry:

- `kid`: a key identifier resolvable in the emitter's published JWKS
  ({{evidence-integrity-signing-keys}}), so a verifier can select the
  emitter's signing key independently.
- `alg`: `ES256` {{RFC7518}} is mandatory to implement; an
  implementation MAY offer other JOSE algorithms but MUST implement
  `ES256`.
- `typ`: the registered media type of the evidence object being signed
  (`application/mission-decision-evidence+json` for Decision Evidence,
  `application/mission-execution-evidence+json` for Execution Evidence,
  `application/mission-refusal-record+json` for Refusal Records,
  `application/mission-receipt+json` for Mission Receipts,
  {{iana}}). A verifier MUST reject a JWS whose protected `typ` is not
  the media type of the object it is verifying, so signatures over one
  record kind cannot be cross-used for another.

This rule is unaffected by the members Decision Evidence, Execution
Evidence, and Refusal Records share with each other and with other
evidence types, named once as a base shape
({{I-D.draft-mcguinness-mission-audit}}). Shared member names describe
a common shape for readability; they carry no exemption, and the `typ`
check above remains the sole authority for which kind a signature
covers.

~~~ json
{
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

This document defines only the `jws-compact` format. Additional formats
MAY be defined by future specifications; implementations MUST reject
envelopes with unsupported formats.

## Worked example

~~~ json
{
  "evidence_id": "evd_9Nq3TmR6xL2vP8kY4sD1eB7jH0wC5uA",
  "evaluation_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "intent_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
    "policy_version": "deploy-policy:v17",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  },
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": {
      "iss": "https://idp.example.com"
    }
  },
  "actor": {
    "client_id": "s6BhdRkqt3",
    "client_instance_id": "inst_macbook_7f3a",
    "act": [
      {
        "iss": "https://as.example.com",
        "sub": "s6BhdRkqt3"
      }
    ]
  },
  "credential": {
    "issuer": "https://as.example.com",
    "expires_at": "2026-11-02T09:14:00Z"
  },
  "resource": {
    "type": "journal-entry",
    "id": "je_2026Q3_inv_8421"
  },
  "action": { "name": "journal-entries.write" },
  "parameter_digest":
    "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
  "audience": "https://erp.example.com",
  "action_class": "irreversible_action",
  "class_source": "deployment",
  "conditions": {
    "valid_until": "2026-11-02T08:15:00Z",
    "use_limit": 1
  },
  "decision": "permit",
  "contributing_constraints": [
    "mission_resource_access", "max_amount"
  ],
  "sequence": 42,
  "emitter": { "id": "pdp.example.com", "role": "pdp" },
  "evaluated_at": "2026-11-02T08:14:03Z",
  "entry_digest":
    "sha-256:dPCNLHsZuzPXuhco_s21VTvDI4cagI_LMhPQsqfNJKQ",
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

Decision Evidence is durable and integrity-protected. It is the
authoritative record of what the PDP evaluated, not proof that the
action occurred.

## Evaluation request digest worked value {#request-digest-worked}

For a consequential action that is not parameter-bound (here a
consequential read), the record carries `evaluation_request_digest`
in place of `parameter_digest`. The runtime profile does not
standardize the digested request form, so the emitting deployment
states the exact input; this non-normative example digests exactly
the following evaluation-request summary object:

~~~ json
{
  "action": "journal-entries.read",
  "audience": "https://erp.example.com",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "resource": "je_2026Q3_inv_8421",
  "subject": "user_3p2q8mN1a0kV7tR"
}
~~~

The value is the integrity-anchor encoded form of the SHA-256 of the
JCS {{RFC8785}} canonical bytes of that object (one line, sorted
member names, no whitespace, shown here wrapped for layout only;
remove the layout line breaks, adding no characters, to recover the
canonical form):

~~~ text
{"action":"journal-entries.read","audience":"https://erp.example.com
","mission_id":"msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-","resource":
"je_2026Q3_inv_8421","subject":"user_3p2q8mN1a0kV7tR"}
~~~

~~~ text
evaluation_request_digest =
  sha-256:sK12VE_g01AHD2v-O1vsf1Gf_xT_htjX0UN0Oe0dDRU
~~~

# Execution Evidence Object {#execution-evidence-object}

The PEP or executor emits an Execution Evidence Object once the
authorized action's final outcome is determined: whether it completed,
failed, or was suppressed, linked to the Decision Evidence by
`evaluation_id`. A record is emitted once a final outcome exists, not
for the attempt in progress; `attempted_at` carries the attempt's
timing without asserting an `attempted` outcome. Emission follows
the runtime profile's class rule: Execution Evidence is required for
the high-consequence classes and for every further class the
deployment claims under the runtime profile's transaction-assurance
tier ({{I-D.draft-mcguinness-mission-runtime}}).

## Members

`execution_id`:
: REQUIRED. A string. Unique execution identifier, stable across
  delivery retries of this record: exactly one Execution Evidence
  Object exists per final disposition of a permit, and delivery of
  that record is at-least-once, so a consumer MUST deduplicate on
  `execution_id` rather than assume single delivery. ABNF:
  `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of entropy.

`evaluation_id`:
: REQUIRED. A string. Correlates this record with the linked Decision
  Evidence's own `evaluation_id` ({{decision-evidence-object}}), and
  with every other record and wire artifact of the same evaluation.

`mission_id`:
: REQUIRED. A string. The Mission `id`, mirrored from the
  linked Decision Evidence for join-key convenience.

`audience`:
: REQUIRED. A string. The audience the linked Decision Evidence
  recorded, mirrored for join-key convenience and so a verifier's
  key-to-audience binding ({{decision-evidence-integrity}}) has its
  input.

`authorized_parameter_digest`:
: CONDITIONAL. A string. REQUIRED when the linked Decision Evidence
  carries `parameter_digest`; MUST equal it. The link to what the
  permit authorized.

`effective_parameter_digest`:
: CONDITIONAL. A string. REQUIRED whenever
  `authorized_parameter_digest` is present. The digest, in the same
  form, over the normalized parameters actually attempted or
  executed. Equality with `authorized_parameter_digest` is the
  binding-held case. Inequality is a parameter deviation, and the
  record REMAINS VALID: evidence of an unauthorized execution is
  still evidence, never grounds to discard the record. A deviation
  recorded against `outcome` `suppressed` carries `error`
  `parameter_mismatch`. A deviation recorded against `outcome`
  `completed` or `failed`, a buggy or compromised executor having
  gone ahead despite the mismatch, is equally representable, and a
  consumer MUST flag it as an unauthorized execution.

`outcome`:
: REQUIRED. A string. One of `completed`, `failed`, or `suppressed`;
  a final outcome, recorded once one exists. `suppressed` means the
  action was permitted but the executor chose not to attempt it (for
  example, a kill-switch or a secondary deny).

`outcome_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`error`:
: CONDITIONAL. A string. Error identifier when `outcome` is `failed` or
  `suppressed`, from this closed set: `parameter_mismatch` (the
  executing PEP found the effective parameters differ from those the
  permit bound), `permit_expired` (the permit's validity window had
  passed at execution), `permit_consumed` (re-presentation of an
  already-consumed single-use evaluation identifier),
  `obligation_unfulfilled` (a permit suppressed before release because
  an attached obligation could not be fulfilled; the failing entry is
  named in `obligation_outcomes`), and `kill_switch` (execution
  suppressed by an operator or safety control). A deployment MAY
  define additional values, which MUST be collision-resistant names
  (a short name within a namespace the deployment controls, following
  the Collision-Resistant Name guidance of {{RFC7519}} Section 4.2) so
  they cannot collide with this set or another deployment's.

`obligation_outcomes`:
: CONDITIONAL. An array of objects. REQUIRED when the linked Decision
  Evidence carried obligations and a permit disposition exists. One
  object per attached obligation, with `id` (REQUIRED, a string, the
  obligation's identifier as returned by the decision), `type`
  (REQUIRED, a string, the obligation type), `outcome` (REQUIRED, a
  string, one of `fulfilled`, `failed`, or `unsupported`), and `error`
  (OPTIONAL, a string, an implementation-specific detail on a
  non-`fulfilled` outcome).

`sequence`:
: REQUIRED. An integer. The per-Mission sequence indicator the runtime
  profile requires of every record, so the execution stream has a
  verifiable order and gaps are detectable. MUST be zero or greater. It
  is scoped to `emitter` per (Mission, emitter) as Decision Evidence
  defines ({{decision-evidence-object}}).

`emitter`:
: REQUIRED. An object. The identity of the PEP or executor that emitted
  and signed this record, in the form Decision Evidence defines
  ({{decision-evidence-object}}), with `role` `pep` or `executor`. A
  verifier MUST bind the emitter's signing key to the enforcement scope
  and audience the record serves ({{decision-evidence-integrity}}).

`hop_reference`:
: OPTIONAL. An object, in the coordinated extension form
  {{evidence-extensions}} defines. Present when the linked Decision
  Evidence carries one.

`attempted_at`:
: OPTIONAL. An RFC 3339 timestamp. Timing context.

`completed_at`:
: OPTIONAL. An RFC 3339 timestamp. Timing context.

`result_summary`:
: OPTIONAL. An object. Minimal action result metadata
  (for example, affected resource counts). MUST NOT carry user-content
  payloads.

`evidence_envelope`:
: REQUIRED. An object. Integrity protection in the
  same form as Decision Evidence ({{decision-evidence-integrity}}),
  carrying a `format` (string, required) and a `value` (string,
  required).

An Execution Evidence Object is closed to uncoordinated extension
under the same rule as Decision Evidence ({{evidence-extensions}}):
coordinated companion members (for example, the metering companion's
`measured_duration`) are permitted, any other extension MUST use a
collision-resistant name, and a consumer MUST ignore members it does
not understand.

## Worked example

~~~ json
{
  "execution_id":  "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
  "evaluation_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission_id":    "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "audience":      "https://erp.example.com",
  "authorized_parameter_digest":
    "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
  "effective_parameter_digest":
    "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
  "outcome":      "completed",
  "sequence":     43,
  "emitter":      { "id": "pep.example.com", "role": "executor" },
  "attempted_at": "2026-11-02T08:14:04Z",
  "completed_at": "2026-11-02T08:14:05Z",
  "outcome_at":   "2026-11-02T08:14:05Z",
  "result_summary": {
    "rows_affected": 1
  },
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXkt..."
  }
}
~~~

Decision Evidence and Execution Evidence are linked but distinct.
Authorization is not proof that an action occurred; a Decision
Evidence record with no corresponding Execution Evidence record
indicates the action was not attempted, or that the executor failed to
emit evidence. Here the two Execution Evidence digests are equal: the
binding-held case, the executed parameters are the ones the permit
authorized.

## Worked example: parameter deviation {#example-parameter-deviation}

A later attempt on the same operation, a different permit
(`evaluation_id` `dec_9HtV3wN6xQ1rB8mP5kS2eL7jY4zA`) bound to the same
423.50 journal entry the runtime profile's parameter-digest example
digests ({{I-D.draft-mcguinness-mission-runtime}}). Between check and
use the parameters became
`{"amount_usd":"780.00","source_invoice_id":"inv_2026Q3_842"}`. The
executing PEP recomputed the digest over the parameters it was about
to use, found it differed from the authorized digest, and suppressed
the release before acting:

~~~ json
{
  "execution_id":  "exe_7QsK2wR4xN9mV3pB6tY8eJ1zH5uD0cA",
  "evaluation_id": "dec_9HtV3wN6xQ1rB8mP5kS2eL7jY4zA",
  "mission_id":    "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "audience":      "https://erp.example.com",
  "authorized_parameter_digest":
    "sha-256:WPVi6EnQ7H9Fh-qk9ADxmTg8zruOdVUX1esl-v3TfCI",
  "effective_parameter_digest":
    "sha-256:UdG-TiebDHTiKRXUVURs1Jeq_vDJp_Ro8jWbBAD8hgM",
  "outcome":      "suppressed",
  "error":        "parameter_mismatch",
  "sequence":     44,
  "emitter":      { "id": "pep.example.com", "role": "executor" },
  "attempted_at": "2026-11-02T09:03:28Z",
  "outcome_at":   "2026-11-02T09:03:29Z",
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXkt..."
  }
}
~~~

The two digests differ: a parameter deviation. The record REMAINS
VALID; it is evidence that the executing PEP caught the deviation and
suppressed the release, never an invalid record to be discarded. Had
the executor instead gone ahead with the 780.00 parameters despite the
mismatch, the same two-digest divergence would appear against
`outcome` `completed` or `failed`, and a consumer MUST flag that
record as an unauthorized execution regardless of the recorded
outcome.

## TOCTOU and parameter binding

The semantics of parameter binding and the time-of-check to
time-of-use gap are defined by the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}). The parameter-digest chain
runs from the decision-API request through Decision Evidence's
`parameter_digest` to Execution Evidence's
`authorized_parameter_digest` (REQUIRED to equal it) and
`effective_parameter_digest` (the digest over what the executing PEP
actually attempted or executed).

Equality between the two Execution Evidence digests is the
binding-held case. Inequality is a parameter deviation, and the
record REMAINS VALID: evidence of an unauthorized execution is still
evidence, never an invalid record to discard. When the executing PEP
detects the deviation before acting, it MUST refuse the action and
emit Execution Evidence with `outcome` `suppressed` and `error`
`parameter_mismatch` ({{example-parameter-deviation}}). A deviation
recorded against an `outcome` of `completed` or `failed`, a buggy or
compromised executor having gone ahead despite the mismatch, is
equally representable and is never grounds to reject the record.
Whatever the recorded `outcome`, when the two digests diverge the
audit consumer MUST classify the execution as a parameter deviation
and treat it as equivalent to an unauthorized action for compliance
purposes.

## Retention

Decision Evidence, Execution Evidence, and Refusal Records MUST be
retained for at least
the deployment's audit retention window, which the runtime profile
requires to be no shorter than the Mission's audit horizon, the term
defined in the Mission Record section of
{{I-D.draft-mcguinness-oauth-mission}}. Regulated deployments MAY
require longer retention.

# Mission Receipt {#mission-receipt}

A Mission Receipt is the portable, tamper-evident projection of a
Mission's runtime enforcement evidence: one signed object a holder
can present to answer what was decided, and for an executed action
what happened, without shipping a log.

A Mission Receipt is a signed manifest, never a second source of
truth. Its signer attests exactly two things: that it assembled the
stated projection, and that it verified every referenced evidence
record under the declared profile at assembly time. The emitters of
the referenced Decision Evidence, Execution Evidence, and Refusal
Records remain authoritative for their facts. A verifier MUST
verify the referenced records and the cross-record joins of
{{receipt-verification}} before relying on any copied field; where
transparency is claimed for a record, it additionally verifies the
transparency commitment, which proves registration and never
substitutes for verifying the record itself
({{I-D.draft-mcguinness-mission-audit}}). A deployment MAY instead
accept a copied field on the receipt signer's authority alone, but
only under an explicit policy that names the receipt issuer as
attesting that fact directly; that policy is the one path that
forgoes source verification. A receipt whose underlying evidence is
unavailable within its retention obligations is an integrity
reference, not portable proof: hashes alone do not make erased
evidence available.

A Mission Receipt is not a SCITT Receipt: the audit transparency
profile uses Receipt in the SCITT sense alone (an inclusion proof),
and the qualified names keep the two apart
({{I-D.draft-mcguinness-mission-audit}}).

## Receipt Kinds {#receipt-kinds}

A `kind` member fixes what a receipt may claim, with exactly three
values and the required evidence combination for each:

`decision`:
: The receipt projects a Decision Evidence record alone. It claims
  an authorization decision was rendered; it claims nothing about
  execution, and a verifier MUST NOT treat it as evidence that an
  action occurred.

`execution`:
: The receipt projects a permit Decision Evidence record and the
  final Execution Evidence record of the same action. Its `outcome`
  is copied from the Execution Evidence and carries that document's
  semantics unchanged; an action whose outcome is not yet terminal
  has no `execution` receipt, and an unresolved action MUST NOT be
  rewritten as terminal to issue one.

`refusal`:
: The receipt projects a Refusal Record alone. A refusal is
  exclusively pre-decision ({{pre-decision-refusal}}), so there is no
  Decision Evidence for the same evaluation to project beside it. A
  `refusal` receipt exists only for a Refusal Record whose own
  `mission` member carries the verified Mission reference the
  receipt's REQUIRED `mission` member repeats; a pre-decision refusal
  without an established Mission (a `mission_context_missing`
  refusal) remains a Refusal Record and never becomes a Mission
  Receipt.

## Members

A Mission Receipt is a JSON object. REQUIRED members:

`evidence_envelope`:
: REQUIRED. An object. Integrity protection in the same form as
  Decision Evidence ({{decision-evidence-integrity}}), carrying a
  `format` (string, required) and a `value` (string, required). The
  default `format` is `jws-compact`; the JWS protected `typ` is
  `application/mission-receipt+json` ({{iana}}).

`kind`:
: REQUIRED. A string. One of `decision`, `execution`, or `refusal`
  ({{receipt-kinds}}).

`mission`:
: REQUIRED. An object, with `id` (REQUIRED) and `issuer` (REQUIRED),
  plus `authority_hash` (OPTIONAL). The member is this exact object,
  never a union with another projection. A cross-domain grant or a
  Mandate that proves the tuple travels beside the receipt at its
  carriage layer, outside the closed evidence-reference type set of
  {{receipt-evidence}}, which a future profile MAY extend.

`emitter`:
: REQUIRED. An object, in the form Decision Evidence's `emitter`
  member defines ({{decision-evidence-object}}): `id` (a string
  identifying the receipt issuer) and `role` (a string; `receipt_issuer`,
  a role this document registers under that member's extensibility
  rule). Receipt issuance is limited to components the deployment's
  enforcement scope statement already names (the PDP, or an executing
  PEP), and the statement declares which of them issue receipts; the
  verifier resolves the signing key through that statement's
  published key sets ({{evidence-integrity-signing-keys}}) and
  rejects an emitter the statement does not name as a receipt
  issuer. A self-published key presenting `role` `receipt_issuer`
  establishes nothing ({{receipt-verification}}).

`evidence`:
: REQUIRED. An array of evidence references ({{receipt-evidence}}).

`issued_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`outcome`:
: REQUIRED when `kind` is `execution`; absent otherwise. A string,
  copied from the projected Execution Evidence's `outcome`
  ({{execution-evidence-object}}), carrying that member's semantics
  unchanged: one of `completed`, `failed`, or `suppressed`.

Everything beyond the join and integrity core is optional and
selected, never defaulted: a projection profile or a recipient
agreement names the optional members a receipt carries, and an
issuer minimizes to that selection. Actor chains, policy versions,
target detail, and custody topology are correlation surfaces; a
receipt carries them when its recipient needs them, not because the
underlying evidence has them. A Mission Receipt is evidence, never
reusable authorization, and confers no authority on its holder.

OPTIONAL members, each a projection from the evidence a receipt of
that content already carries:

`decision`:
: OPTIONAL. An object, with `id` (the projected Decision Evidence's
  own `evidence_id`) and `result` (its `decision` member, `permit` or
  `deny`) ({{decision-evidence-object}}).

`policy`:
: OPTIONAL. An object, with `pdp_policy_view` (the projected Decision
  Evidence's `mission.policy_view_id`) and `mission_policy_version`
  (its `mission.policy_version`, when the Decision Evidence carries
  it) ({{decision-evidence-object}}).

`executor`:
: OPTIONAL. An object, the projected Decision Evidence's `actor`
  member: the authenticated actor and any `act` chain
  ({{decision-evidence-object}}).

`target`:
: OPTIONAL. An object, with `resource` (the projected Decision
  Evidence's `resource` member) and `audience` (its `audience`
  member) ({{decision-evidence-object}}).

`profile`:
: OPTIONAL. A string, a URI naming the projection profile in force:
  the profile that selected the optional members this receipt
  carries and defines the semantics of any `issuer_assertions`
  members. REQUIRED when `issuer_assertions` is present.

`issuer_assertions`:
: OPTIONAL. An object. Facts the receipt issuer asserts on its own
  authority, structurally separate from the projections above:
  every member's name and semantics come from the `profile`, and
  relying on any of them takes the trust model's explicit-policy
  path, never the verified-projection path. The credential custody
  mode (whether a mediating PEP held the credential,
  {{I-D.draft-mcguinness-mission-runtime}}) is the motivating
  member: no Decision or Execution Evidence record carries it, so a
  profile that needs it defines it here.

`chain`:
: OPTIONAL. An object ({{receipt-chaining}}).

## Evidence References {#receipt-evidence}

Each `evidence` entry is an object. All members REQUIRED:

`type`:
: REQUIRED. A string. The referenced record's registered media type:
  `application/mission-decision-evidence+json`,
  `application/mission-execution-evidence+json`, or
  `application/mission-refusal-record+json` ({{iana}},
  {{decision-evidence-object}}, {{execution-evidence-object}},
  {{pre-decision-refusal}}).

`digest`:
: REQUIRED. A string. A `sha-256:` prefixed digest, classified under
  the core's commitment taxonomy
  ({{I-D.draft-mcguinness-oauth-mission}}) as a canonical-object
  digest for a JSON evidence record and a raw-octet digest for a
  JWS- or JWT-shaped artifact. For a JSON evidence record the digest
  input is the exact canonical bytes the convention fixes for that
  record: the complete object, `evidence_envelope` included, JCS
  {{RFC8785}} canonicalized ({{decision-evidence-integrity}}). For a
  compact-serialized artifact the digest input is the exact
  serialization octets, as issued.

`evidence_id`:
: REQUIRED. A string. The referenced record's own identifier member:
  `evidence_id` for a Decision Evidence record
  ({{decision-evidence-object}}), `execution_id` for an Execution
  Evidence record ({{execution-evidence-object}}), or `refusal_id`
  for a Refusal Record ({{pre-decision-refusal}}).

`emitter`:
: REQUIRED. An object, in the form Decision Evidence's `emitter`
  member defines ({{decision-evidence-object}}): `id` and `role`.
  Enough to select the emitting component's published key set before
  the referenced record is resolved; the specific signing key is
  selected, once resolved, by that record's own JWS `kid`.

An `evidence` array carries the combination {{receipt-kinds}} fixes
for the receipt's `kind`: one Decision Evidence reference alone for
`decision`; a permit Decision Evidence reference and the final
Execution Evidence reference of the same action for `execution`; one
Refusal Record reference alone for `refusal`. A reference to a record type
the verifier does not implement fails verification; it is not
skipped.

## Receipt Chaining {#receipt-chaining}

Chaining is OPTIONAL, orthogonal to transparency, and never a
substitute for it: a signer-controlled hash chain can be truncated,
forked, or presented differently to different verifiers, so it
gives tamper-evident linkage within the view a verifier is shown,
never global ordering or inclusion. A deployment that needs those
properties runs the audit transparency profile or anchors the chain
head independently; a deployment without either still MAY chain, or
MAY not.

A chain is scoped to one (Mission, receipt issuer, stream): the
`chain` member carries `stream` (an issuer-chosen identifier),
`sequence` (an integer, strictly increasing per stream), and
`previous` (an array of one or more digests of predecessor
receipts in the same scope, present on every receipt after the
stream's first). Concurrent issuance either serializes per stream
or records multiple predecessors; a verifier treats the result as a
DAG and checks only linkage and sequence monotonicity, never
completeness. The scope's receipt issuer is the `emitter` the
predecessor and successor receipts carry ({{receipt-verification}}).

A predecessor digest is a canonical-object digest
({{receipt-evidence}}): the complete predecessor Mission Receipt
object, `evidence_envelope` included, JCS canonicalized, the same
construction an evidence reference's digest uses over a Decision,
Execution, or Refusal record, so this digest too covers the signature
rather than only the unsigned payload. The predecessor object is
itself a Mission Receipt, typed `application/mission-receipt+json`,
so the digest cannot be read as committing to any other record type.

## Receipt Verification {#receipt-verification}

A verifier MUST perform the following steps, in order, and MUST NOT
rely on a receipt if any step fails:

1. Verify the receipt's `evidence_envelope`: decode the JWS payload,
   compute the JCS canonical bytes of the receipt with
   `evidence_envelope` removed, and require byte-for-byte equality,
   rejecting on any difference ({{decision-evidence-integrity}}).
   Confirm the JWS protected `typ` is `application/mission-receipt+json`
   and verify the signature against the published key resolved by the
   JWS `kid` for the party named in `emitter`, through the
   enforcement scope statement's published key sets
   ({{evidence-integrity-signing-keys}}). Confirm that statement
   names the `emitter` as a receipt issuer; the receipt's Mission
   binding is established by the verified records and the joins of
   step 4, never by key publication alone.
2. Confirm the `kind`'s required evidence combination is present
   ({{receipt-kinds}}, {{receipt-evidence}}).
3. Resolve each evidence reference. Verify each resolved record under
   its own rules ({{decision-evidence-integrity}}). Recompute each
   digest over the defined bytes ({{receipt-evidence}}) and require
   equality. Require the resolved record's own identifier to equal
   `evidence_id` and its emitter and key to match `emitter`.
4. Join the records: the same `mission.id` and `mission.issuer` as
   the receipt's `mission`; the Execution Evidence joins the Decision
   Evidence on `evaluation_id` ({{decision-evidence-object}},
   {{execution-evidence-object}}); audience and target, and the
   authorized and effective parameter digests, are consistent across
   the records per the runtime's rules
   ({{I-D.draft-mcguinness-mission-runtime}}); for `execution`, the
   receipt's `outcome` equals the Execution Evidence's terminal
   `outcome`.
5. Require every copied optional member to equal the corresponding
   member of the record it projects.
6. When `chain` is present ({{receipt-chaining}}): resolve each
   `previous` digest to a predecessor receipt, verify the
   predecessor's own envelope, require the same `mission`, `emitter`,
   and `chain.stream` as this receipt, recompute the predecessor
   digest over its complete canonical bytes and require equality, and
   require each predecessor's `chain.sequence` to be strictly less
   than this receipt's. Monotonicity is relative to the receipt's
   predecessors, never a claim of a globally serialized stream. A
   predecessor unresolvable within the retention obligations of
   {{receipt-retention}} fails chain verification.
7. Reject on: a missing required record, a record of an unimplemented
   type, digest mismatch, emitter or key mismatch, join failure, a
   chain-linkage failure, or a copied field that differs. A verifier
   MUST NOT treat the receipt as verified if any step fails
   ({{decision-evidence-integrity}}).

## Retention {#receipt-retention}

A Mission Receipt inherits the runtime's record-integrity and
retention floor ({{execution-evidence-object}}). A receipt is
retained at least as long as the records it projects; conversely, the
referenced evidence and the historical verification keys MUST remain
retained or resolvable for as long as verifiers are expected to
validate the receipt ({{I-D.draft-mcguinness-mission-runtime}}).

## Worked example

A complete `execution` receipt, projecting records carrying the
identifiers of {{decision-evidence-object}} and
{{execution-evidence-object}}'s worked examples;
{{mission-receipt-digest-worked}} fixes the exact bytes verified for
the execution reference:

~~~ json
{
  "kind": "execution",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "emitter": { "id": "receipts.example.com", "role": "receipt_issuer" },
  "evidence": [
    {
      "type": "application/mission-decision-evidence+json",
      "digest":
        "sha-256:fS_yB6-Yit7Gsz-6vw73q7YphoiRm3VwC-3Pk8xW9J0",
      "evidence_id": "evd_9Nq3TmR6xL2vP8kY4sD1eB7jH0wC5uA",
      "emitter": { "id": "pdp.example.com", "role": "pdp" }
    },
    {
      "type": "application/mission-execution-evidence+json",
      "digest":
        "sha-256:Ims1Xx5FAPYfFB6c6Y2gbqybB-Z2PxCi93yWPcIHmC8",
      "evidence_id": "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
      "emitter": { "id": "pep.example.com", "role": "executor" }
    }
  ],
  "issued_at": "2026-11-02T08:14:06Z",
  "outcome": "completed",
  "decision": {
    "id": "evd_9Nq3TmR6xL2vP8kY4sD1eB7jH0wC5uA",
    "result": "permit"
  },
  "policy": {
    "pdp_policy_view":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "mission_policy_version": "deploy-policy:v17"
  },
  "executor": {
    "client_id": "s6BhdRkqt3",
    "client_instance_id": "inst_macbook_7f3a",
    "act": [
      { "iss": "https://as.example.com", "sub": "s6BhdRkqt3" }
    ]
  },
  "target": {
    "resource": {
      "type": "journal-entry",
      "id": "je_2026Q3_inv_8421"
    },
    "audience": "https://erp.example.com"
  },
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InJlY2VpcHQta2V5..."
  }
}
~~~

## Digest vector {#mission-receipt-digest-worked}

A reproducible digest for the `execution` evidence reference above.
The referenced record is a minimal Execution Evidence stand-in
carrying only the members {{execution-evidence-object}} requires,
consistent with that section's worked example's identifiers. This is
a digest-only vector: the stand-in's `evidence_envelope.value` is an
illustrative placeholder, not a signature over these bytes, so the
object fixes digest computation alone and would fail the
byte-equality verification of {{decision-evidence-integrity}} by
design:

~~~ json
{
  "audience": "https://erp.example.com",
  "emitter": { "id": "pep.example.com", "role": "executor" },
  "evaluation_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "evidence_envelope": {
    "format": "jws-compact",
    "value":
      "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXktMSJ9.dGhlLXNpZ25lZC1wYXlsb2FkLWJ5dGVzLWFib3Zl.RVMyNTZfc2lnbmF0dXJlX2J5dGVzX2lsbHVzdHJhdGl2ZQ"
  },
  "execution_id": "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "outcome": "completed",
  "outcome_at": "2026-11-02T08:14:05Z",
  "sequence": 43
}
~~~

The digest input is the JCS {{RFC8785}} canonical bytes of that
object, member names sorted, no whitespace (one line, 506 bytes,
shown here wrapped for layout only; remove the layout line breaks,
adding no characters, to recover the canonical form):

~~~ text
{"audience":"https://erp.example.com","emitter":{"id":"pep.example.
com","role":"executor"},"evaluation_id":"dec_8K2nP4qV9rL3tY6sB1zN0e
F7jB","evidence_envelope":{"format":"jws-compact","value":"eyJhbGci
OiJFUzI1NiIsImtpZCI6InBlcC1rZXktMSJ9.dGhlLXNpZ25lZC1wYXlsb2FkLWJ5dG
VzLWFib3Zl.RVMyNTZfc2lnbmF0dXJlX2J5dGVzX2lsbHVzdHJhdGl2ZQ"},"execut
ion_id":"exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w","mission_id":"msn_8R
fX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-","outcome":"completed","outcome_at":
"2026-11-02T08:14:05Z","sequence":43}
~~~

~~~ text
digest = sha-256:Ims1Xx5FAPYfFB6c6Y2gbqybB-Z2PxCi93yWPcIHmC8
~~~

# Evidence Properties {#evidence-properties}

This section is informative: it names a property vocabulary for the
records of this document and the conditions under which the records
support each property, so the cluster is citable as one anchor. It
is a conditional capability map, not a checklist: each row separates
what base evidence conformance proves, the additional mechanism a
stronger reading requires, and what no reading proves. It adds no
requirement to this document or the runtime profile.

| Property | What the base evidence proves | Additional mechanism or condition | What it does not prove |
|---|---|---|---|
| Parameter-bound | A verified Decision Evidence record authenticates the digest of the parameters evaluated ({{decision-evidence-object}}), and linked Execution Evidence authenticates the authorized and effective digest pair, exposing equality or deviation ({{execution-evidence-object}}); the link to the parameters themselves is established by recomputing the digest over the normalized parameter object | Binding to what a human approved holds where action-bound approval is required and used, the rendering derives from the same normalized parameters by a trusted component, and the dynamic link verifies ({{I-D.draft-mcguinness-mission-runtime}}) | That the human understood the rendering, or that the action occurred: the outcome record is the emitter's signed assertion |
| Key-isolated | Origin and integrity: each record is signed by the emitter's published key, bound to its scope and audience ({{decision-evidence-integrity}}) | None in the current profiles. No requirement places the evidence-signing private key outside the agent's runtime; the runtime profile's custody rules govern the credential's confirmation key, a different key ({{I-D.draft-mcguinness-mission-runtime}}). A deployment that isolates evidence-signing keys does so by local mechanism and declares it in its Enforcement Scope Statement | That the agent's runtime could not access the signing key or emit records under the emitter's identity |
| Session-independent | A verifier can verify a retained record without a live session and without possession or validity of the credential that carried the action ({{evidence-integrity-signing-keys}}); retired keys stay resolvable for the retention window, and evidence signed after a declared key compromise is unverifiable rather than verified | None | That the session or credential was valid at decision or execution time, or that the Mission is active now: those are record contents and linked state evidence, not consequences of signature verification |
| Third-party-verifiable | Scoped independent verification: a party with access to the Enforcement Scope Statement's published keys verifies a record independently of the emitting deployment ({{evidence-integrity-signing-keys}}) | Durable offline verification: a party holding retained or configured producer and Transparency Service trust anchors verifies without contacting either operator, where a Receipt and the evidence bytes are retained; cross-domain verifiability additionally requires the audit profile's independent-operator condition ({{I-D.draft-mcguinness-mission-audit}}) | That an unknown producer key is trusted, that the signed assertion is true, or that the evidence feed is complete |
{: title="Evidence properties: what the records prove, and under which conditions"}

# Extension Members {#evidence-extensions}

A Decision Evidence Object, Execution Evidence Object, and Refusal
Record are each closed to uncoordinated extension: a companion or
binding specification MAY add a member, under a name coordinated
with this document or a collision-resistant name, and a consumer
MUST ignore a member it does not understand and MUST NOT derive
authority from any member it does not recognize. An extension member
is recorded as presented; this document does not otherwise define
its semantics.

The following members are coordinated extensions a deployment
following the family's Standards-Track AuthZEN binding commonly
carries. Each is registered and owned by the specification named,
not by this document or by the AuthZEN binding merely because it is
a common wire carrier.

`taint`:
: OPTIONAL. An object, recorded on Decision Evidence as presented.
  REQUIRED when the decision request carried a taint context. What
  taints a session and when a taint requirement applies are defined
  by the harness profile ({{I-D.draft-mcguinness-mission-harness}}),
  which owns this member's semantics; the AuthZEN binding is one wire
  carrier of the context this member records
  ({{I-D.draft-mcguinness-mission-authzen}}).

`mission_history`:
: OPTIONAL. An array of objects, recorded on Decision Evidence: the
  policy-selected history predicates the PDP evaluated, each with its
  `predicate` (and `action_class`, where applicable) and an `outcome`
  member (`satisfied`, `not_satisfied` for an established-false
  predicate, or `unavailable` for a predicate that could not be
  established, including an unrecognized `predicate` value or an
  evidence store that could not be consulted within its bound).
  REQUIRED when policy selected any history predicate for the
  decision, whether or not the request carried a Mission history
  member. Registered and owned by the AuthZEN binding
  ({{I-D.draft-mcguinness-mission-authzen}}).

`capability_source`:
: OPTIONAL. An object, recorded on Decision Evidence: the
  catalog-source binding the PDP evaluated for a catalog-sourced
  action. Registered and owned by the Mission Capability Binding
  companion ({{I-D.draft-mcguinness-mission-capability-binding}}).

`hop_reference`:
: OPTIONAL. An object, recorded on Decision Evidence, Execution
  Evidence, or a Refusal Record when the action or refusal concerns a
  credential authorized under a continuation profile's continued
  credential, attributing the record to the specific hop that carried
  the authorization. Sub-members: `jti` (REQUIRED, a string, the
  authorizing token's identifier) and `mission_id` (REQUIRED, a
  string, the Mission the continued credential carries);
  `continuation_handle` (OPTIONAL, a string, the hop's
  identity-continuation handle, when present). Registered and owned
  by the Mission Continuation profile
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}), which
  requires execution-time evidence to record the continuation hop
  reference; this member formalizes that requirement as a coordinated
  extension.

# Conformance {#conformance}

This document defines conformance for four roles: a PRODUCER that
emits the records themselves; a CONSUMER, or VERIFIER, that reads
and checks them after the fact; a RECEIPT ISSUER that assembles and
signs a Mission Receipt over them; and a RECEIPT VERIFIER that
verifies one. A decision-API binding's own conformance statement,
such as the AuthZEN binding's ({{I-D.draft-mcguinness-mission-authzen}}),
incorporates this document's PRODUCER role for its PDP, PEP, and
executor.

A PRODUCER conforming to this document MUST:

- emit a Decision Evidence Object for every PDP decision on a
  consequential action ({{decision-evidence-object}});
- emit a Refusal Record for a PEP or PDP refusal that occurs before
  any PDP decision ({{pre-decision-refusal}});
- emit an Execution Evidence Object for the classes the runtime
  profile's transaction-assurance tier covers
  ({{I-D.draft-mcguinness-mission-runtime}})
  ({{execution-evidence-object}}); and
- sign every record with the integrity envelope of
  {{decision-evidence-integrity}}, with a `kid` resolvable in its
  published key set and a `typ` matching the record's own media type.

A CONSUMER or VERIFIER conforming to this document MUST perform the
byte-equality verification procedure and key checks of
{{decision-evidence-integrity}} against the emitter's published keys
({{evidence-integrity-signing-keys}}), and classify orphaned Decision
Evidence and cross-record digest divergence as
{{security-considerations}} and {{execution-evidence-object}}
require, never as proof of action.

A RECEIPT ISSUER conforming to this document MUST:

- verify every referenced Decision Evidence, Execution Evidence, and
  Refusal Record under {{decision-evidence-integrity}} before
  assembling a Mission Receipt that projects it;
- minimize the receipt to the optional members a projection profile
  or recipient agreement selects, never defaulting to every available
  member ({{mission-receipt}});
- assemble only the evidence combination {{receipt-kinds}} fixes for
  the receipt's `kind` ({{receipt-evidence}});
- publish the signing key resolvable by `kid` for the `mission.id` and
  `mission.issuer` the receipt names ({{receipt-verification}}); and
- when chaining, maintain a strictly increasing `sequence` per
  (Mission, issuer, stream) and carry the predecessor digests
  {{receipt-chaining}} requires.

A RECEIPT VERIFIER conforming to this document MUST perform the
algorithm of {{receipt-verification}} and reject a Mission Receipt on
any of its failure conditions.

# Security Considerations {#security-considerations}

The runtime profile's Security Considerations
({{I-D.draft-mcguinness-mission-runtime}}) apply in full. This
section addresses only threats specific to these records.

## Decision Evidence versus Execution Evidence

Decision Evidence is not proof an action occurred. Implementations MUST
emit Execution Evidence to record outcomes, and auditors MUST NOT treat
Decision Evidence alone as evidence of action. An audit consumer MUST
classify orphaned Decision Evidence (no matching Execution Evidence
within the deployment's reconciliation window) as undetermined-outcome
or, per deployment policy, as action-attempted; it MUST NOT treat it as
proof of action.

## Evidence integrity and signing keys {#evidence-integrity-signing-keys}

The `evidence_envelope` binds each record to the emitting PDP or PEP.
The PDP's `jws-compact` signing key MUST be resolvable, by the JWS
protected `kid`, in the PDP's published JWKS so a verifier can check
Decision Evidence independently. The PEP or executor signing key used
for Execution Evidence and Refusal Records MUST be resolvable the same
way through a
deployment-published key set.

This document fixes one concrete discovery convention: the PDP
publishes its JWKS at a deployment-published location named in the
enforcement scope statement ({{I-D.draft-mcguinness-mission-runtime}}),
and the PEP or executor key set is published and named there
likewise. The retired-key rule of the issuance profile's key
management ({{I-D.draft-mcguinness-oauth-mission}}) extends to
evidence signing keys: a retired signing key MUST remain resolvable
in the published key set for at least the evidence retention window,
so records signed before a rotation stay verifiable after it. The
compromise exception carries over with it: a key known or suspected
compromised is published as revoked or marked with a compromise time,
per the core rule, and evidence signed under it after that time is
unverifiable rather than verified.

Implementations MUST reject evidence whose `format` is unsupported
rather than accepting it unverified.

Verification under this section is anchored in the Enforcement Scope
Statement's published keys: a party with access to that statement can
verify a record independently of the deployment that emitted it.
Portability beyond that, to a party without access to the deployment's
own published keys, is not a property this document provides; it
requires the transparency mechanisms of the audit profile
({{I-D.draft-mcguinness-mission-audit}}), where a deployment adopts
them.

## Transport

Audit channels carrying Decision Evidence and Execution Evidence MUST
be served over TLS 1.2 or later (TLS 1.3 RECOMMENDED). Evidence at
rest MUST be encrypted per the deployment's data-protection posture.

## Mission Receipt {#receipt-security-considerations}

A Mission Receipt that copies fields from its underlying evidence
invites a verifier to treat the receipt signer as authoritative for
those facts; the trust model ({{mission-receipt}}) and the
verification algorithm ({{receipt-verification}}) are the control,
not the receipt's signature alone.

Chaining gives view-local linkage only: a signer-controlled chain can
be truncated, forked, or presented differently to different
verifiers ({{receipt-chaining}}); a deployment that needs global
ordering or inclusion runs the audit transparency profile or anchors
the chain head independently.

A compromised receipt-issuer signing key inherits the emitter-key
considerations of {{evidence-integrity-signing-keys}}: a key known or
suspected compromised is published as revoked or marked with a
compromise time, and a receipt signed under it after that time is
unverifiable rather than verified.

# Privacy Considerations {#privacy-considerations}

The runtime profile's evidence-privacy guidance
({{I-D.draft-mcguinness-mission-runtime}}) applies in full. This
section addresses the concrete records this document defines.

## Evidence as PII sinks

Decision Evidence, Execution Evidence, and Refusal Records carry the
authenticated
`subject`, actor chain, resource and action identifiers,
credential-derived correlators, capability-source identifiers,
`parameter_digest` (or, on Execution Evidence,
`authorized_parameter_digest` and `effective_parameter_digest`), and
timing. These records are PII sinks and SHOULD
be access-controlled to audit consumers with a legitimate need,
encrypted at rest, and retained per the window of
{{execution-evidence-object}}.

## Parameter exposure

This restates, for the privacy reader, the `action` member's rule
({{decision-evidence-object}}): the durable Decision Evidence record
MUST NOT contain the raw `properties.parameters` object under any
name; it carries only `parameter_digest` and, at most,
non-sensitive action classification metadata, consistent with the
runtime profile's rule that raw parameters never appear in the
record. Where raw parameters must be retained for audit, they are
held in a separately access-controlled store keyed by
`evaluation_id`. When the parameters
are themselves PII, the PEP SHOULD supply only a parameter digest to
the PDP, omitting the raw parameters, so the PDP evaluates against
parameter-class policy without observing the raw values. The Execution
Evidence `result_summary` MUST NOT carry user-content payloads.

## Actor chain and Mission correlation

The `actor` member carries the delegation chain, which MAY reveal
service accounts, client instances, and organizational structure.
Evidence carrying the same Mission `id` and `authority_hash` across
resource boundaries can correlate a subject's activity; this is
inherent to the Mission's role as a governance handle. Deployments that
require unlinkability need an additional privacy design outside this
document.

## Mission Receipt {#receipt-privacy-considerations}

The Mission Receipt's optional members ({{mission-receipt}}) are
correlation surfaces, the same as the evidence they project from.
Minimization to the selection a projection profile or recipient
agreement names is the rule, not a default. A receipt crosses a trust
boundary by design, so an issuer carries only the members its
recipient needs.

# IANA Considerations {#iana}

This document requests the following IANA actions.

## Media Type Registry

This document registers four media types per {{RFC6838}}.

### Decision Evidence Media Type

- Type name: application
- Subtype name: mission-decision-evidence+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-bound runtime
  enforcement deployments
- Fragment identifier considerations: same as for `application/json`
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): `.json`
  - Macintosh file type code(s): TEXT
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

### Execution Evidence Media Type

- Type name: application
- Subtype name: mission-execution-evidence+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-bound runtime
  enforcement deployments
- Fragment identifier considerations: same as for `application/json`
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): `.json`
  - Macintosh file type code(s): TEXT
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

### Refusal Record Media Type

- Type name: application
- Subtype name: mission-refusal-record+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-bound runtime
  enforcement deployments
- Fragment identifier considerations: same as for `application/json`
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): `.json`
  - Macintosh file type code(s): TEXT
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

### Mission Receipt Media Type

- Type name: application
- Subtype name: mission-receipt+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JSON encoded in UTF-8
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-bound runtime
  enforcement deployments
- Fragment identifier considerations: same as for `application/json`
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): `.json`
  - Macintosh file type code(s): TEXT
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

--- back

# Acknowledgments
{:numbered="false"}

This document extracts the Decision Evidence, Execution Evidence, and
Refusal Record objects that Mission-Bound Runtime Enforcement's
AuthZEN binding first defined, so any decision-API binding can
produce them. The author thanks the Mission-Bound Authorization
implementer community for feedback.
