---
title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
abbrev: "Mission AuthZEN"
category: std

docname: draft-mcguinness-mission-authzen-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - authzen
 - pdp
 - enforcement
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-authzen.html"

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
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-runtime-latest
  AUTHZEN:
    target: https://openid.net/specs/authorization-api-1_0-final.html
    title: "OpenID AuthZEN Authorization API 1.0"
    author:
      -
        org: OpenID Foundation
    date: 2026

informative:
  RFC9457:
  RFC9470:
  ARAP:
    target: https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html
    title: "AuthZEN Access Request and Approval Profile - Draft 1"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  COAZ:
    target: https://openid.github.io/authzen/authzen-mcp-profile-1_0.html
    title: "AuthZEN Profile for Model Context Protocol Tool Authorization - Draft 1"
    author:
      -
        org: OpenID Foundation
    date: 2026
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest

--- abstract

Mission-Bound Runtime Enforcement specifies a
substrate-independent decision contract: before each consequential
action runs, a Policy Enforcement Point (PEP) obtains a permit from a
Policy Decision Point (PDP) that evaluates the action against the
Mission the acting token is bound to. That contract is independent of
the decision wire format. This document is the concrete OpenID AuthZEN
binding of that contract. It defines how a Mission is materialized
into an evaluable policy view, how the abstract decision inputs map
onto the AuthZEN Authorization API request and response, the Decision
Evidence and Execution Evidence objects a deployment emits and their
integrity, how runtime denials map onto AuthZEN decision context and
optional error details, how requestable denials can compose with the
AuthZEN Access Request and Approval Profile, and the AuthZEN
representation of the runtime metering the runtime profile meters. It
does not restate the enforcement semantics the runtime profile owns.

--- middle

# Introduction

Mission-Bound Runtime Enforcement
{{I-D.draft-mcguinness-mission-runtime}} (the "runtime profile")
specifies the runtime enforcement layer for Mission-bound access
tokens issued under Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile"). The
runtime profile is deliberately substrate-independent: it defines the
decision contract, action classification, PEP placement, parameter
binding and the time-of-check to time-of-use gap, consumption
metering, failure modes, runtime enforcement evidence, and the runtime
conformance scope, but it states that the decision API wire format is a
deployment choice and defines no binding of its own.

This document is that AuthZEN profile. It binds the runtime profile's
abstract decision contract to the OpenID AuthZEN Authorization API
{{AUTHZEN}}. It carries only the AuthZEN-binding deltas:

- how a Mission becomes a materialized policy view the PDP evaluates
  ({{mission-to-policy-materialization}});
- how the runtime profile's decision inputs map onto the AuthZEN
  `subject`/`resource`/`action`/`context` envelope, the worked PDP
  request, and the PDP-side consistency checks ({{pdp-request}});
- the Decision Evidence and Execution Evidence objects, their
  integrity, and worked examples ({{decision-evidence-object}},
  {{execution-evidence-object}});
- how runtime denials map onto AuthZEN decision context and optional
  error details ({{runtime-denial-classification}});
- how requestable denials can compose with the AuthZEN Access Request
  and Approval Profile {{ARAP}};
- the binding of a Mission's approved authority to concrete,
  catalog-sourced capabilities ({{capability-source-binding}}); and
- the AuthZEN representation of the runtime metering the runtime
  profile meters ({{consumption-metering-binding}}).

This document does not restate the enforcement contract. It does not
redefine which actions are consequential, where the PEP MUST sit, the
semantics of parameter binding, the semantics of metering, the failure
modes, or the runtime conformance scope; those are normatively defined
in {{I-D.draft-mcguinness-mission-runtime}} and are referenced,
not duplicated, here.

The end-to-end flow this binding realizes:

~~~
 Agent        PEP              PDP           Access Request Service
   |           |                |                     |
   |- action ->|                |                     |
   |           | validate token |                     |
   |           |- evaluation -->|                     |
   |           |  request       | decide vs Mission   |
   |           |<- permit ------|                     |
   |           |  (+ context)   |                     |
   |           | execute        |                     |
   |           |- Execution Evidence ->|  (commit/     |
   |           |                |        release)      |
   |<- result -|                |                     |
   |           |                |                     |
   |           |<- deny (+ access_request) -|          |
   |           |- submit access request -->|--------->|
   |           |<-------------- approval ------------- |
   |           |- re-evaluate ->|                     |
~~~

## Requirements Language

{::boilerplate bcp14-tagged}

# Conventions and Terminology {#conventions-and-definitions}

This document uses JSON {{RFC8259}} as the data model for all PDP
requests, responses, and evidence objects. JCS canonicalization
{{RFC8785}} applies wherever an integrity hash is computed, under the
canonicalization rules of {{I-D.draft-mcguinness-oauth-mission}}; this
document does not define a second canonicalization.

"SHA-256" refers to {{RFC6234}}. A digest is encoded in the
integrity-anchor encoded form of
{{I-D.draft-mcguinness-oauth-mission}}: `sha-256:` followed by the
base64url, no-padding encoding of the digest.

The terms Policy Enforcement Point (PEP), Policy Decision Point (PDP),
consequential action, Resource policy, decision, Mission state source,
enforcement scope, high-consequence classes, parameter-bound, and the
action-class names (consequential read, consequential write,
irreversible action, external commitment, and privileged
administration) are used as defined in
{{I-D.draft-mcguinness-mission-runtime}}. The Mission claim
(`id`, `origin`, `authority_hash`), the integrity anchors
(`intent_hash`, `authority_hash`), and `authorization_details`
entries of type `mission_resource_access` are used as defined in
{{I-D.draft-mcguinness-oauth-mission}}.

Additional terms specific to this binding:

Materialized policy view, trusted compiler:
: Defined by the runtime profile
  ({{I-D.draft-mcguinness-mission-runtime}}). This binding carries
  only the wire member `policy_view_id`
  ({{mission-to-policy-materialization}}).

Validating server:
: The component that, at derivation, validates the Mission's authority
  and records the derivation-time facts the PDP later checks (such as a
  capability `source_digest`, {{capability-source-binding}}). In the
  issuance profile this is the Mission Issuer; this profile uses the
  term where the recording role is what matters.

Decision Evidence:
: The runtime enforcement evidence record emitted by the PDP, in the
  concrete object form of {{decision-evidence-object}}.

Execution Evidence:
: The record emitted by the PEP or executor after the authorized
  action's outcome is determined ({{execution-evidence-object}}).

Executor:
: The component that carries out a permitted action and emits Execution
  Evidence. It is the PEP in the common case, or a distinct component
  where the requesting PEP and the executing component differ
  ({{execution-evidence-object}}).

Audit consumer:
: A component or role that reads Decision Evidence and Execution
  Evidence to reconstruct or verify a decision after the fact.

HTTP message examples follow the AuthZEN specification {{AUTHZEN}} for
the decision request and response, and {{RFC9457}} for problem-details
error bodies where a deployment carries them outside the AuthZEN
envelope.

# Mission Substrate {#mission-substrate}

This binding inherits the substrate requirements of the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}), whose decision
contract is defined against the Mission model rather than against
OAuth 2.0 mechanics. OAuth enters only through the credential-derived
decision inputs (the token's `sub`, `client_id`, `cnf`,
`authorization_details`, and `mission` claim), which the substrate's
Mission-bound credential supplies. A deployment on another Mission
substrate maps that substrate's credential to the same inputs and uses
this binding unchanged.

# Mission-to-Policy Materialization {#mission-to-policy-materialization}

The PDP evaluates a Mission against an action through a materialized
policy view. The materialized policy view, its trusted-compiler and
reproducibility rules, its bounded-fidelity property, and the
content-addressed `policy_view_id` with its `mission-policy-view`
integrity envelope are defined by the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}). That envelope's
committed payload binds the Mission's `mission_id` and `authority_hash`,
so a consistency check between a decision request and the loaded view is
an equality test on those values ({{pdp-request}}).

This binding carries only the wire member. `policy_view_id` appears in
the PDP request and response `context` ({{context-mission}},
{{runtime-denial-classification}}) as the content-addressed correlator
between a permit, its evidence, and the view the PDP evaluated against.
This profile does not pick a concrete policy-language wire form for the
materialized view. Implementations MAY use canonical input bundles the
AuthZEN PDP consumes directly, or an engine-native artifact. Compiling
a Mission into an engine-native policy artifact and standardizing a
policy-view carriage format are out of scope
({{I-D.draft-mcguinness-mission-runtime}}).

# PDP Request {#pdp-request}

The PDP request realizes the runtime profile's abstract decision
contract over the OpenID AuthZEN Authorization API {{AUTHZEN}}. AuthZEN
defines a top-level envelope with `subject`, `resource`, `action`, and
`context` members. This profile binds the Mission-bound decision inputs
into that envelope. It does not change which inputs MUST be evaluated;
those are defined by the runtime profile.

This binding is used after ordinary access-token validation under
{{I-D.draft-mcguinness-mission-runtime}}: the PEP MUST NOT ask a
PDP to authorize an action from unverified token claims, and the
PEP-PDP channel MUST be integrity-protected and mutually authenticated
as that profile requires.

## AuthZEN envelope binding

| AuthZEN member | Mission-bound binding |
|---|---|
| `subject` | The principal the decision is requested for. |
| `resource` | The fine-grained target object the action names (for example, a specific journal entry), for Resource-policy evaluation. It is NOT the field matched against the approved entry's `resource`; see below. |
| `action` | The requested action identifier (for example, `journal-entries.write`), which the PDP evaluates against the approved `actions` per {{I-D.draft-mcguinness-oauth-mission}}. |
| `context` | Carries the Mission-bound context object defined below. |

The runtime profile requires the PDP to confirm that the action falls
within an approved Authority Set entry by matching the action's
resource and action identity against that entry's `resource` and
`actions` ({{I-D.draft-mcguinness-mission-runtime}}). In this
binding, the approved entry's `resource` (the protected-resource or
audience URI, for example `https://erp.example.com`) is matched against
`context.audience`, not against the AuthZEN `resource` member. The
AuthZEN `resource` carries the finer-grained object identity used only
for Resource-policy evaluation. A PDP MUST perform the entry match
against `context.audience`; matching it against the AuthZEN `resource`
member is non-conforming and will diverge across deployments.

The AuthZEN `subject` is the token's authenticated `sub`: the Subject
the Mission's authority is exercised for
({{I-D.draft-mcguinness-oauth-mission}}). It does not change under
delegation. The acting agent's `client_id` and any `act` delegation
chain are carried in `context.actor`, never in `subject`. The PDP binds
the permit to `subject` together with the actor context, and the
confused-deputy check ({{I-D.draft-mcguinness-mission-runtime}})
re-verifies that the action is for the same Subject it was authorized
for.

`subject.type` is `user` unless the deployment profiles another value.
`subject.id` is the token's authenticated `sub`. `subject.properties.iss`
is REQUIRED when the Subject's issuer is known, carrying the issuer that
authenticated the Subject, so a `sub` is disambiguated across issuers;
a PEP that cannot establish the Subject's issuer omits it.

## Mission Decision Context {#context-mission}

The `mission` member identifies the governance record and its current
materialized view:

`id`:
: REQUIRED. A string. the Mission's `id`.

`origin`:
: REQUIRED. A string containing a URI. the Mission's `origin`.

`authority_hash`:
: REQUIRED. A string. the Authority Set integrity
  anchor, in the integrity-anchor encoded form
  ({{I-D.draft-mcguinness-oauth-mission}}).

`state`:
: REQUIRED. A string. the current Mission lifecycle state the
  PEP established from its Mission state source
  ({{I-D.draft-mcguinness-mission-runtime}}).

`policy_version`:
: REQUIRED when known. A string. the `policy_version` recorded at the
  approval event. It is a Mission-record field
  ({{I-D.draft-mcguinness-oauth-mission}}) and is not carried on the
  `mission` claim or the introspection projection, so a PEP that is not
  co-located with the Mission record may not have it; such a PEP omits
  it and relies on `policy_view_id` for view correlation. A PEP that can
  obtain it (for example, co-located with the origin) includes it.

`policy_view_id`:
: OPTIONAL. A string. the materialized view identifier
  ({{mission-to-policy-materialization}}). The PDP is authoritative for
  the current view, so a PEP need not supply it; a PEP that has the
  value supplies it and the PDP uses it as a content-addressed
  correlator. When present it is checked as in {{pdp-request}}.

## Actor Decision Context {#context-actor}

The `actor` member carries the authenticated actor context when
delegation is in effect, reconstructed from the access token's `act`
claim and the token's authenticated client identity per
{{I-D.draft-mcguinness-oauth-mission}}:

`client_id`:
: REQUIRED when known. A string. the authenticated client identity.

`client_instance_id`:
: OPTIONAL. A string. a deployment-defined client-instance correlator
  when the PEP can establish one.

`act`:
: OPTIONAL. An array of objects. the delegation chain projection,
  ordered root to leaf. For a single actor, the array has one member.

The `actor` member carries the delegation chain only. Provenance beyond
the delegation chain (the tool a request invoked, a named workflow
step, a human approver) MUST NOT be encoded inside the `act` chain;
the PDP evaluates the `act` chain as defined by the runtime profile,
and provenance is recorded in dedicated evidence fields where the
deployment captures it.

## Credential Decision Context {#context-credential}

The `credential` member carries token-derived facts the PEP has already
validated and that the PDP needs to enforce the runtime decision's
time, issuer, and sender-constraint checks:

`issuer`:
: REQUIRED when known. A string containing a URI. The token issuer.

`expires_at`:
: REQUIRED when the token carries an expiry. An RFC 3339 {{RFC3339}}
  timestamp corresponding to the token expiry.

`confirmation`:
: OPTIONAL. An object. A sender-constraint confirmation value or
  digest of that value, included only after the PEP has verified the
  proof-of-possession check for the presented token.

The PEP MUST NOT include unverified credential claims in this member.

## Action Parameters and Parameter Digest {#parameter-digest}

When parameter binding is required for the requested action's class
under {{I-D.draft-mcguinness-mission-runtime}}, the PEP supplies:

`parameters`:
: CONDITIONAL. An object. When present, it MUST be the
  operation-profile-normalized parameter object
  ({{I-D.draft-mcguinness-mission-runtime}}): the same bytes the
  `parameter_digest` is computed over, so the PDP's recomputation
  matches. The shape is action-specific. The PEP MAY omit `parameters`
  and supply only `parameter_digest` where the raw values are sensitive
  ({{privacy-considerations}}), but only when the PDP can still enforce
  the applicable parameter policy from the digest, supplied derived
  attributes, or local state. If the PDP needs raw parameter values to
  evaluate an applicable constraint and they are not supplied through an
  equivalent privacy-preserving form, it MUST deny with
  `parameter_violation`.

`parameter_digest`:
: REQUIRED for parameter-bound classes. A string.
  the `parameter_digest` defined by
  {{I-D.draft-mcguinness-mission-runtime}}. This profile carries
  that value on the wire; it does not define a second digest or
  canonicalization. The executing PEP recomputes and
  reverifies the digest immediately before acting, and the PDP
  recomputes it over any supplied `parameters`, both as that section
  requires.

## Audience and Freshness Context {#context-audience-freshness}

`audience`:
: REQUIRED. A string. the PEP's audience or
  protected-resource identifier.

`freshness`:
: REQUIRED. An object. the freshness of the Mission state
  the PEP relied on, conveying the runtime profile's freshness inputs
  on the wire. Members:

    `mode`:
    : REQUIRED. A string. one of `fresh`, `cached`, or `event_driven`
      ({{mission-status-composition}}).

    `freshness_at`:
    : REQUIRED in every mode. An RFC 3339 {{RFC3339}} timestamp. when the
      PEP's view of the Mission state was current.

    `mission_status_issued_at`:
    : REQUIRED for `cached` and `event_driven`, OPTIONAL for `fresh`. An
      RFC 3339 timestamp. when the relied-on Mission state was issued.

    `mission_status_expires_at`:
    : REQUIRED for `cached` and `event_driven`, OPTIONAL for `fresh`. An
      RFC 3339 timestamp. when the relied-on Mission state (or its
      lease) expires.

The deployment's maximum staleness bound, and the rule that a
consequential action MUST fail closed when the Mission cannot be
established as `active` within that bound, are defined by the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}); the
`freshness` object is only their wire representation.

## Capability Source Context {#context-capability-source}

For catalog-sourced actions, the PEP supplies the capability-source
binding in `context.capability_source` using the object defined in
{{capability-source-binding}}. For non-catalog actions, this member is
absent.

## Worked PDP request

For a Q3 invoicing Mission:

~~~ http-message
POST /pdp/access/v1/evaluation HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: ...

{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": {
      "iss": "https://idp.example.com"
    }
  },
  "resource": {
    "type": "journal-entry",
    "id": "je_2026Q3_inv_8421"
  },
  "action": {
    "name": "journal-entries.write"
  },
  "context": {
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "origin": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active",
      "policy_version": "deploy-policy:v17",
      "policy_view_id":
        "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
    },
    "actor": {
      "client_id": "client_erp-recon-agent",
      "client_instance_id": "inst_macbook_7f3a",
      "act": [
        {
          "iss": "https://as.example.com",
          "sub": "client_erp-recon-agent"
        }
      ]
    },
    "credential": {
      "issuer": "https://as.example.com",
      "expires_at": "2026-11-02T09:14:00Z"
    },
    "parameters": {
      "amount_usd": "423.50",
      "source_invoice_id": "inv_2026Q3_842"
    },
    "parameter_digest":
      "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA8dRn",
    "audience": "https://erp.example.com",
    "freshness": {
      "mission_status_issued_at": "2026-11-02T08:14:00Z",
      "mission_status_expires_at": "2026-11-02T08:15:00Z",
      "mode": "cached",
      "freshness_at": "2026-11-02T08:14:00Z"
    }
  }
}
~~~

## PDP-side consistency checks

In addition to evaluating the decision inputs the runtime profile
requires, the PDP MUST verify that the AuthZEN-carried envelope is
self-consistent:

1. The Mission state conveyed in `context.mission.state` is exactly
   `active`; every other value, recognized or not, is non-active per the
   issuance profile's forward-compatibility rule
   ({{I-D.draft-mcguinness-oauth-mission}}) and the PDP returns
   `mission_inactive` ({{runtime-denial-classification}}). A PDP with
   direct access to a Mission state source MUST prefer its own fresher
   view over `context.mission.state`, and MUST return `mission_inactive`
   when its view disagrees with the PEP-supplied state. PEP-supplied
   state is a floor, never a substitute for a state source the PDP can
   itself consult.
2. The `id` and `authority_hash` in `context.mission` equal the
   `mission_id` and `authority_hash` committed in the materialized
   policy view the PDP has loaded for this Mission
   ({{I-D.draft-mcguinness-mission-runtime}}); the PDP returns
   `stale_state` on any inequality. When `context.mission.policy_view_id`
   is present, it MUST equal the loaded view's `policy_view_id`, and the
   PDP returns `stale_state` on inequality. A PDP MUST NOT fail a
   decision solely because the optional `policy_view_id` or
   `policy_version` was omitted; the view the PDP loaded is
   authoritative.
3. When `context.credential.expires_at` is present, it has not passed;
   otherwise the PDP returns `credential_invalid`.
4. The `context.freshness` the PEP supplied is within the deployment's
   staleness bound; otherwise the PDP returns `stale_state`, with the
   freshness-window violation in the denial reason.
5. For an action whose class requires parameter binding
   ({{I-D.draft-mcguinness-mission-runtime}}),
   `context.parameter_digest` MUST be present; if it is absent the PDP
   returns `parameter_violation`. When `context.parameters` is also
   present, the PDP-recomputed digest MUST match
   `context.parameter_digest`, otherwise `parameter_violation`. When
   `parameters` is omitted under the privacy carve-out
   ({{parameter-digest}}), the PDP MUST still be able to evaluate every
   applicable parameter constraint from the digest, supplied derived
   attributes, or local state, and returns `parameter_violation` if it
   cannot. A parameter-bound action MUST NOT be permitted without a
   verified `parameter_digest`.
6. For a catalog-sourced action whose approved entry recorded a
   capability source digest at derivation
   ({{capability-source-binding}}), `context.capability_source` MUST be
   present and match the approved source binding; otherwise the PDP
   returns `capability_drift`. Whether an action is catalog-sourced, and
   whether a source digest was recorded, are determined from the
   materialized policy view, not from the PEP's request; where no source
   digest was recorded, this check does not apply.

## Batch evaluations {#batch-evaluations}

The AuthZEN evaluations (boxcar) endpoint MAY be used to submit several
Mission-bound decisions in one request. Each item is evaluated
independently and on the same terms as a single request: each item
yields its own Decision Evidence Object with its own `decision_id` and
`sequence`, assigned in request order; consumption metering applies per
item in request order ({{consumption-metering-binding}}); and permits
are per item, so a boxcar MAY return a mix of permits and denials.
Batching is a transport optimization and changes none of the per-item
enforcement semantics.

# Decision Evidence Object {#decision-evidence-object}

The runtime profile requires a decision evidence record for every PDP
decision on a consequential action and fixes the minimum content and
local integrity requirements. This section gives the concrete object,
canonicalization, and integrity envelope an AuthZEN deployment emits.

## Members

`decision_id`:
: REQUIRED. A string. unique decision identifier. ABNF:
  `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of entropy.

`mission`:
: REQUIRED. An object. the PDP request's `context.mission`
  object (`id`, `origin`, `authority_hash`, and, when known,
  `policy_version` and `policy_view_id`), extended with `intent_hash`
  and, when known, a consent-disclosure commitment, so the evidence
  chains back to the exact approved Mission. Within `mission`, `id`,
  `origin`, and `authority_hash` are REQUIRED; `intent_hash` is OPTIONAL
  (it is carried in neither the `mission` claim nor introspection, so
  only a PDP with direct Mission-record access can record it), and the
  remaining members are OPTIONAL. These hashes are the issuing AS's
  commitments cited as anchors; the PDP does not recompute them.

`subject`:
: REQUIRED. An object. PDP inputs as supplied, after PDP-side
  normalization.

`resource`:
: REQUIRED. An object. PDP inputs as supplied, after PDP-side
  normalization.

`action`:
: REQUIRED. An object. PDP inputs as supplied, after PDP-side
  normalization.

`audience`:
: REQUIRED. A string. PDP inputs as supplied, after PDP-side
  normalization.

`actor`:
: OPTIONAL. An object. PDP inputs as supplied, after PDP-side
  normalization.

`credential`:
: OPTIONAL. An object. token-derived inputs as supplied, after
  PDP-side normalization. This member MUST contain only claims the PEP
  verified before invoking the PDP.

`parameter_digest`:
: OPTIONAL. A string. PDP inputs as supplied, after PDP-side
  normalization.

`request_digest`:
: CONDITIONAL. A string. a privacy-preserving digest of the evaluation
  request, in the integrity-anchor encoded form
  ({{I-D.draft-mcguinness-oauth-mission}}). REQUIRED when
  `parameter_digest` is absent for a consequential action, so the closed
  object still carries the request digest the runtime profile requires
  of every decision record ({{I-D.draft-mcguinness-mission-runtime}}).

`capability_source`:
: OPTIONAL. An object. the catalog-source binding the PDP evaluated
  for catalog-sourced actions.

`compensates_decision_id`:
: OPTIONAL. A string. the `decision_id` of the action this decision
  compensates, carrying the runtime profile's compensation link
  ({{I-D.draft-mcguinness-mission-runtime}}) so a compensating
  action reconciles against the action it reverses.

`decision`:
: REQUIRED. A string. one of `permit` or `deny`.

`contributing_constraints`:
: REQUIRED when the decision turned on one or more authority or
  constraint entries. An array of strings: the identifiers of the
  constraints and entries the PDP evaluated (`constraints` keys,
  `authorization_details` entry types). For a permit it records every
  constraint key and entry type the decision relied on; for a deny it
  MUST list every entry that failed. Omitting an entry the decision
  turned on is non-conforming, so the array can be relied on to
  reconstruct the decision basis.

`sequence`:
: REQUIRED. An integer. the per-Mission sequence indicator
  the runtime profile requires, so the decision stream has a
  verifiable order and gaps are detectable. MUST be zero or greater.

`denial_reason`:
: CONDITIONAL. A string. Present when `decision` is `deny`. A value from
  the closed set in {{runtime-denial-classification}}. When the denial
  is a constraint violation, the value is `parameter_violation` and the
  specific failing `constraints` keys are carried in
  `contributing_constraints`, not in `denial_reason`, so the reason
  enum and the open constraint-key space never mix in one field.

`evaluated_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`evidence_envelope`:
: REQUIRED. An object. integrity protection
  ({{decision-evidence-integrity}}), carrying a `format` (string,
  required) and a `value` (string, required).

A Decision Evidence Object is a closed object: it MUST NOT contain
members other than those defined above.

## Pre-decision refusal records {#pre-decision-refusal}

The Decision Evidence Object records a PDP decision, which is why its
PDP-derived members are REQUIRED. The runtime profile also requires an
evidence record for a PEP refusal that occurs before any PDP decision:
token validation failure, a missing `mission` claim, PEP-PDP channel
failure, PDP unreachability, or the PEP being unable to establish
Mission state ({{I-D.draft-mcguinness-mission-runtime}}). Such a
refusal has no PDP decision and cannot populate the PDP-derived members
above. An AuthZEN deployment records it not as a Decision Evidence
Object but as a refusal record carrying only the fields the PEP
verified, at least `audience`, an action descriptor, `evaluated_at`,
`decision` of `deny`, and a `denial_reason` from this pre-decision set:
`token_invalid`, `mission_claim_missing`, `channel_failure`,
`pdp_unreachable`, or `state_unavailable` (the PEP cannot establish
Mission state to send to the PDP). These name PEP-side conditions and
are disjoint from the PDP denial reasons of
{{runtime-denial-classification}}; a record that can populate the
PDP-derived members is a Decision Evidence Object instead.

## Integrity {#decision-evidence-integrity}

The `evidence_envelope` carries the integrity protection over the
Decision Evidence content. This AuthZEN profile defines the concrete
serialization required by {{I-D.draft-mcguinness-mission-runtime}}:
the Decision Evidence object is serialized as JCS {{RFC8785}} canonical
JSON before integrity protection. The default `format` is
`jws-compact`, a JWS Compact Serialization {{RFC7515}} whose payload is
the JCS canonical bytes of the Decision Evidence object with the
`evidence_envelope` member removed during signing. Verification
re-removes `evidence_envelope` and verifies the JWS against the
emitter's published signing key. For Decision Evidence emitted by a
PDP, the emitter is the PDP. For Execution Evidence emitted by a PEP or
executor, the emitter is that PEP or executor.

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
  {{iana}}). A verifier MUST reject a JWS whose protected `typ` is not
  the media type of the object it is verifying, so Decision Evidence and
  Execution Evidence signatures cannot be cross-used.

~~~ json
{
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

This profile defines only the `jws-compact` format. Additional formats
MAY be defined by future specifications; implementations MUST reject
envelopes with unsupported formats.

## Worked example

~~~ json
{
  "decision_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
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
    "client_id": "client_erp-recon-agent",
    "client_instance_id": "inst_macbook_7f3a",
    "act": [
      {
        "iss": "https://as.example.com",
        "sub": "client_erp-recon-agent"
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
    "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA8dRn",
  "audience": "https://erp.example.com",
  "decision": "permit",
  "contributing_constraints": [
    "mission_resource_access", "max_amount_usd"
  ],
  "sequence": 42,
  "evaluated_at": "2026-11-02T08:14:03Z",
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

Decision Evidence is durable and integrity-protected. It is the
authoritative record of what the PDP evaluated, not proof that the
action occurred.

# Execution Evidence Object {#execution-evidence-object}

The PEP or executor emits an Execution Evidence Object after the
authorized action's outcome is determined. It records whether the
permitted action was attempted, completed, failed, or suppressed,
linked to the Decision Evidence by `decision_id`.

## Members

`execution_id`:
: REQUIRED. A string. unique execution identifier.
  ABNF: `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of
  entropy.

`decision_id`:
: REQUIRED. A string. the linked Decision Evidence.

`mission_id`:
: REQUIRED. A string. the Mission `id`, mirrored from the
  linked Decision Evidence for join-key convenience.

`parameter_digest`:
: CONDITIONAL. A string. MUST be present when the
  linked Decision Evidence carries one, and MUST match it.

`outcome`:
: REQUIRED. A string. one of `attempted`, `completed`,
  `failed`, or `suppressed`. `suppressed` means the action was
  permitted but the executor chose not to attempt it (for example, a
  kill-switch or a secondary deny).

`outcome_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`error`:
: CONDITIONAL. A string. error identifier when `outcome` is `failed` or
  `suppressed`, from this closed set: `parameter_mismatch` (the
  executing PEP found the effective parameters differ from those the
  permit bound), `permit_expired` (the permit's validity window had
  passed at execution), `permit_consumed` (re-presentation of an
  already-consumed single-use decision identifier), and `kill_switch`
  (execution suppressed by an operator or safety control). A deployment
  MAY define additional values, which MUST be collision-resistant names
  (a short name within a namespace the deployment controls, following
  the Collision-Resistant Name guidance of {{RFC7519}} Section 4.2) so
  they cannot collide with this set or another deployment's.

`sequence`:
: REQUIRED. An integer. the per-Mission sequence indicator the runtime
  profile requires of every record, so the execution stream has a
  verifiable order and gaps are detectable. MUST be zero or greater.

`measured_duration`:
: CONDITIONAL. A string. REQUIRED for a duration-metered action,
  otherwise absent. An ISO 8601 duration (the `duration` rule in
  Appendix A of {{RFC3339}}): the PEP's measured duration, the PDP's
  commit-or-release input for `max_duration`
  ({{consumption-metering-binding}}).

`attempted_at`:
: OPTIONAL. An RFC 3339 timestamp. timing context.

`completed_at`:
: OPTIONAL. An RFC 3339 timestamp. timing context.

`result_summary`:
: OPTIONAL. An object. minimal action result metadata
  (for example, affected resource counts). MUST NOT carry user-content
  payloads.

`evidence_envelope`:
: REQUIRED. An object. integrity protection in the
  same form as Decision Evidence ({{decision-evidence-integrity}}),
  carrying a `format` (string, required) and a `value` (string,
  required).

An Execution Evidence Object is a closed object: it MUST NOT contain
members other than those defined above.

## Worked example

~~~ json
{
  "execution_id": "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
  "decision_id":  "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission_id":   "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "parameter_digest":
    "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA8dRn",
  "outcome":      "completed",
  "sequence":     43,
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
emit evidence.

## TOCTOU and parameter binding

The semantics of parameter binding and the time-of-check to
time-of-use gap are defined by the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}). In this binding, the
`parameter_digest` chain runs from the PDP request through Decision
Evidence to Execution Evidence: if the executed action's effective
parameters differ from those the PDP evaluated, the digest mismatch is
detectable in audit.

The PEP MUST NOT emit Execution Evidence that claims an attempted or
completed execution under a `parameter_digest` that does not match the
linked Decision Evidence. When the executing PEP detects a mismatch
before acting, it MUST refuse the action and emit Execution Evidence
with `outcome` set to `suppressed` and `error` set to
`parameter_mismatch`, or emit an equivalent PEP-refusal evidence record
under the deployment's runtime evidence mechanism. When values
nonetheless diverge across the chain, the audit consumer MUST classify
the action as parameter-mismatch and treat it as equivalent to an
unauthorized action for compliance purposes.

## Retention

Decision Evidence and Execution Evidence MUST be retained for at least
the deployment's audit retention window, which the runtime profile
requires to be no shorter than the Mission's audit horizon, the term
defined in the Mission Record section of
{{I-D.draft-mcguinness-oauth-mission}}. Regulated deployments MAY
require longer retention.

# Runtime Denial Classification {#runtime-denial-classification}

When the PDP denies a consequential action, the failure condition is
one defined by the runtime profile. This section binds those
conditions to AuthZEN responses and gives the denial-reason identifiers
carried in Decision Evidence:

- `out_of_authority`: the action is not within the Authority Set.
- `step_up_required`: Resource policy requires a stronger authentication
  context for this action than the actor presents, and MAY be satisfied
  by {{RFC9470}} step-up authentication. This is a Resource-policy
  condition, not a Mission constraint: the issuance profile's `acr` is
  an approval-time requirement on the Approver, recorded on the Mission
  and neither carried on derived tokens nor evaluated per action
  ({{I-D.draft-mcguinness-oauth-mission}}), and the issuance profile
  defines no per-action `amr` constraint. It is a specialization of
  `resource_policy` that names the step-up affordance.
- `action_approval_required`: deployment or Resource policy requires an
  action-bound approval for this action
  ({{I-D.draft-mcguinness-mission-runtime}}) and a valid fresh
  approval bound to the action's parameters is not present. The PEP
  carries any such approval in the decision context; this profile does
  not define the approval artifact, which the runtime profile owns.
- `stale_state`: the PEP-supplied freshness is stale or inconsistent
  with the materialized policy view.
- `mission_inactive`: the Mission state is not `active`.
- `actor_invalid`: the required `act` chain is missing or malformed, so
  the PDP cannot establish the runtime actor context
  ({{I-D.draft-mcguinness-mission-runtime}}).
- `credential_invalid`: token-derived credential facts supplied by the
  PEP are expired, inconsistent, or otherwise not usable for a runtime
  decision.
- `parameter_violation`: parameters violate a constraint the PDP
  evaluated, the recomputed digest does not match, or a required
  `parameter_digest` is absent for a parameter-bound action.
- `resource_policy`: Resource policy refuses the action independently
  of Mission authority.
- `quota_exceeded`: a metered runtime bound is exhausted
  ({{consumption-metering-binding}}).
- `capability_drift`: a catalog-sourced action's current
  capability-source digest differs from the digest committed at
  derivation, or the presented `tool_id` is outside the approved set
  ({{capability-source-binding}}).
- `unsupported_authorization_type`: the action targets an
  `authorization_details` type the PDP does not understand or cannot
  enforce, so it refuses rather than guess the type's semantics
  ({{I-D.draft-mcguinness-mission-runtime}}).
- `constraint_unsupported`: an applicable constraint or consumption
  bound on the entry is unrecognized or unmetered, so the PDP cannot
  enforce it and refuses ({{I-D.draft-mcguinness-mission-runtime}}).
  This is distinct from `parameter_violation`, which is a constraint the
  PDP evaluated and found violated.

A deny is terminal for the attempted action: the agent does not proceed
on a denial. A deny need not end the task, however. For an
`out_of_authority` or `action_approval_required` denial, the PDP MAY
mark the denial **requestable** by including a `context.access_request`
object, composing this binding with the AuthZEN Access Request and
Approval Profile {{ARAP}}. The PEP then submits an ARAP access request
bound to the denied evaluation, an independent approver or policy
adjudicates it (synchronously when policy auto-approves, otherwise
asynchronously through the portable ARAP task handle), and on approval
the PEP re-evaluates against the PDP. This is the demand-driven,
runtime-initiated counterpart to the pre-consented drawdown of
progressive authorization
({{I-D.draft-mcguinness-oauth-mission-expansion}}): the agent starts
narrow and requests the authority it discovers it needs, instead of
holding it up front.

Auto-approval is bounded the same way in-ceiling drawdown is
({{I-D.draft-mcguinness-oauth-mission-expansion}}): a deployment SHOULD
rate-limit and anomaly-check synchronous auto-approval, and MUST NOT
auto-approve a request for an `action_approval_required` denial in the
irreversible, external-commitment, or privileged-administration classes
without an independent approver, so a compromised agent cannot drive the
request loop to escalate itself unattended.

Two ARAP properties carry weight here and match this profile's stance.
First, an ARAP approval is input context, not a bearer grant: the PDP
remains authoritative at enforcement, so the PEP MUST obtain a fresh
decision, and any resulting permit and evidence remain subject to this
profile. The action-bound approval an `action_approval_required` denial
calls for ({{I-D.draft-mcguinness-mission-runtime}}) is exactly
such an approval, and ARAP's `approval.id` or signed `approval.state` is
its carrier. Second, to persist authority beyond the single
re-evaluated action rather than re-requesting it per call, an approved
request MAY be realized as a Mission expansion
({{I-D.draft-mcguinness-oauth-mission-expansion}}): an in-ceiling
request as a policy-adjudicated in-ceiling expansion, a beyond-ceiling
request as the fresh human approval that creates the successor Mission.

## AuthZEN decision context

AuthZEN decisions use a boolean `decision` member and an optional
`context` object. This profile defines the following AuthZEN response
`context` members:

`decision_id`:
: REQUIRED. A string. The Decision Evidence identifier for this
  decision.

`denial_reason`:
: REQUIRED when `decision` is `false`. A string from the closed set in
  {{runtime-denial-classification}}. A constraint violation uses
  `parameter_violation`; the specific failing `constraints` keys are
  carried in the Decision Evidence `contributing_constraints`, not here.

`parameter_digest`:
: REQUIRED when the request was parameter-bound. A string. The digest
  bound to the decision.

`policy_view_id`:
: REQUIRED. A string. The materialized policy view the PDP evaluated.
  The PDP is authoritative for the view, so it always knows and returns
  this value.

`permit_expires_at`:
: REQUIRED when `decision` is `true`. An RFC 3339 timestamp after
  which the permit MUST NOT be used.

`single_use`:
: CONDITIONAL. A boolean. When `true`, the PEP MUST treat `decision_id`
  as a single-use decision identifier. Absent, the permit is not
  single-use. For an action in the high-consequence classes
  ({{I-D.draft-mcguinness-mission-runtime}}) the PDP MUST include
  `single_use: true`, and the PEP MUST treat a high-consequence permit
  lacking it as invalid.

`insufficient_claims`:
: OPTIONAL. An object. Present only for a `step_up_required` denial. It
  MAY contain `acr_values` and `amr_values` members that identify the
  authentication context Resource policy requires to lift the denial.

`access_request`:
: OPTIONAL. An object. Present on an `out_of_authority` or
  `action_approval_required` denial when the deployment exposes it as
  requestable under {{ARAP}}. It is the ARAP requestable-denial context,
  carrying the submission endpoint and the denial binding that ties a
  later access request to this evaluation. Its presence does not change
  the `decision: false` result and does not grant access.

## Permit response shape

When the PDP permits an action, it returns AuthZEN `decision: true` and
the context needed by the PEP to enforce the permit lease. The
`decision_id`, `policy_view_id`, and any `parameter_digest` bind the
response to the Decision Evidence and to the request inputs the PDP
evaluated. `permit_expires_at` and `single_use` express the permit
lifetime controls required by the runtime profile.

~~~ json
{
  "decision": true,
  "context": {
    "decision_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
    "parameter_digest":
      "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA8dRn",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "permit_expires_at": "2026-11-02T08:15:00Z",
    "single_use": true
  }
}
~~~

For a `step_up_required` denial, the PDP MAY include
`context.insufficient_claims`, so the caller can satisfy the
Resource-policy authentication requirement through an OAuth step-up
authentication challenge {{RFC9470}} at the protected resource and
re-authenticate, without a Mission expansion. Because the requirement is
Resource policy and not a Mission constraint, satisfying it changes the
actor's authentication context, not the Mission or its Authority Set.

## Permit binding in split topologies

A permit is valid only on the mutually authenticated channel and PEP
identity that requested it, and MUST NOT be relayed to another
component as a bearer grant. Where the requesting component and the
executing PEP differ, the executor MUST receive the signed Decision
Evidence ({{decision-evidence-object}}) and verify the runtime's binding
fields (the Mission reference, `audience`, `subject`, `client_id`, actor
context, action, resource, and `parameter_digest`) from it before
acting, rather than trusting a relayed `decision: true`. A PEP permit
cache MUST key on the complete request envelope, so a cached permit
cannot be reused for a request whose envelope differs in any bound
field.

## Error response shape

The PDP returns its permit or denial in the AuthZEN response
{{AUTHZEN}}. Runtime denials are successful evaluations and therefore
are represented as `decision: false` with the `context` members above,
not as transport errors.

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
    "denial_reason": "stale_state",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  }
}
~~~

Malformed requests, authentication failures, or PDP processing errors
that prevent evaluation MAY be returned as AuthZEN or transport-level
errors. A deployment MAY additionally carry {{RFC9457}} problem
details for structured error information when the PDP is consumed over
HTTP outside the AuthZEN envelope.

# Capability Source Binding {#capability-source-binding}

Consequential actions an agent discovers at runtime, through a Model
Context Protocol tool catalog, an OpenAPI document, a Protected
Resource Metadata-linked catalog, or an equivalent capability source,
identify the source they came from, so a Mission's approved authority
stays bound to concrete tools rather than to bare action names a later
catalog revision could redefine. The runtime profile assigns capability
identity to the approved `actions` and refuses an invoked identity
outside them ({{I-D.draft-mcguinness-mission-runtime}}); this
section gives the concrete binding an AuthZEN deployment presents for
catalog-sourced actions.

For MCP tools, this binding composes with the AuthZEN MCP profile's
COAZ mapping {{COAZ}}. COAZ maps MCP tool definitions and invocation
parameters into the AuthZEN Subject-Action-Resource-Context model; this
profile adds Mission governance, source binding, Mission evidence, and
runtime metering. A Mission-governed MCP deployment MAY use COAZ to
construct the AuthZEN `subject`, `resource`, `action`, and
parameter-bearing `context` members, but the Mission-specific
`context.mission`, `context.actor`, freshness, permit binding, and
evidence requirements in this document still apply.

The minimum binding, committed by the validating server at derivation
and presented by the executing component at request time in
`context.capability_source`, is:

~~~ json
{
  "tool_id": "mcp://docs.example.com/tools/write_document",
  "source_uri": "https://docs.example.com/.well-known/mcp",
  "source_digest": "sha-256:Qm0a...base64url-no-pad",
  "operation_ref": "tools/write_document"
}
~~~

`tool_id`:
: A string. a stable capability identifier the executing
  component asserts the action invokes.

`source_uri`:
: A string. the discovery source the capability was
  resolved from.

`source_digest`:
: A string. the integrity-anchor encoded form
  ({{I-D.draft-mcguinness-oauth-mission}}) over the exact retrieved
  source representation, recorded at derivation time.

`operation_ref`:
: A string. the source-format-specific operation
  reference (MCP tool name, OpenAPI `operationId`, or equivalent).

Rules:

- The validating server records `tool_id`, `source_uri`,
  `source_digest`, and `operation_ref` for every consequential action
  sourced from a discovered catalog. These values are part of the
  approved Mission's derived authority and are therefore covered by
  `authority_hash` ({{I-D.draft-mcguinness-oauth-mission}}).
- The PEP presents `tool_id` on consequential requests for
  catalog-sourced actions. The runtime profile owns the drift semantics:
  it requires the PDP to refuse an invoked identity outside the approved
  `actions` and, where a source digest was recorded at derivation, to
  refuse when the current source digest differs from it
  ({{I-D.draft-mcguinness-mission-runtime}}). This binding adds
  only the wire representation: such a refusal is carried as
  `capability_drift` ({{runtime-denial-classification}}). It defines no
  drift rule of its own.
- Actions not sourced from a discovered catalog (deployment-registered
  `authorization_details` types, first-party operations with stable
  identity) do not require this binding.

Cross-format canonicalization, signed capability manifests, and
media-type negotiation across catalog formats are out of scope
({{I-D.draft-mcguinness-mission-runtime}}); this binding requires
only the stable identifier plus source evidence above.

# AuthZEN binding of consumption metering {#consumption-metering-binding}

The runtime profile owns consumption-metering semantics: it meters the
Mission's `max_budget`, `max_calls`, and `max_duration` bounds, defines
the atomic check-and-decrement, the single-versus-distributed-PDP
consistency posture, retry and idempotency behavior, the deployment's
documented reserve/commit posture, and the rule that an unmetered or
unrecognized bound MUST cause refusal
({{I-D.draft-mcguinness-mission-runtime}}). This section adds
only the AuthZEN wire representation; it defines no new metering
semantics and no new constraint.

A deployment that meters a per-action invocation cap evaluates the cap
as part of the decision. When metering the cap would exceed it, the PDP
MUST deny with `quota_exceeded` ({{runtime-denial-classification}})
instead of returning a permit, and MUST record `quota_exceeded` as the
`denial_reason` in Decision Evidence. Whether a metered permit is
reserved at decision time and committed on settlement, or committed at
decision time, follows the deployment's documented reserve/commit
posture ({{I-D.draft-mcguinness-mission-runtime}}); this binding
fixes neither. The exactness of the cap is the consistency bound the
runtime profile's topology rules establish, not a property of this wire
binding.

## Settlement exchange {#settlement-exchange}

The runtime profile requires the PEP to signal actual use so the PDP
commits consumption and releases any reservation. In this binding,
delivery of the Execution Evidence Object
({{execution-evidence-object}}) to the PDP is that commit-or-release
signal: on receipt the PDP commits the consumption the linked action
used and releases any reserved excess, keyed to the Execution
Evidence's `decision_id`.

For a duration-metered action the PEP reports the measured duration in
the Execution Evidence `measured_duration` member, and the PDP commits
that duration against `max_duration`. A duration-lease renewal is a new
re-evaluation request that carries the prior permit's `decision_id` in
`context.prior_decision_id`, so the PDP continues the same metered
activity rather than opening a new reservation. This exchange requires
one request member and one evidence member:

`context.prior_decision_id`:
: OPTIONAL. A string. Present on a duration-lease renewal request,
  carrying the `decision_id` of the permit being renewed. Absent on an
  initial request.

`measured_duration` (Execution Evidence):
: REQUIRED for a duration-metered action, otherwise absent. A string
  containing an ISO 8601 duration (the `duration` rule in Appendix A of
  {{RFC3339}}): the PEP's measured duration for the executed action
  ({{execution-evidence-object}}).

# Mission Status Composition {#mission-status-composition}

The PDP relies on Mission state to decide. The runtime profile defines
the Mission state source, the maximum staleness bound, and the
fail-closed rule ({{I-D.draft-mcguinness-mission-runtime}}). This
binding conveys that state and its freshness on the wire through
`context.mission.state` and `context.freshness` ({{pdp-request}}),
using a `mode` member with one of three values that describe how the
PEP obtained the state:

- `fresh`: the PEP consulted the Mission state source synchronously
  before the action.
- `cached`: the PEP used cached Mission state within the deployment's
  staleness bound.
- `event_driven`: the PEP relies on event-channel invalidation, but the
  cached state remains bounded by the deployment's staleness bound, or
  the lease the state carries, exactly as for `cached`; it is not valid
  indefinitely. A missed or delayed invalidation event does not extend
  validity, and when the bound elapses without a confirming event the
  PEP MUST refresh from a Mission state source rather than continue on
  the cache.

When freshness cannot be established within the bound, the PDP fails
closed for consequential actions as the runtime profile requires; in
this binding that surfaces as a `stale_state` denial
({{runtime-denial-classification}}).

# Conformance {#conformance}

This binding adds AuthZEN-specific obligations on top of the runtime
profile's enforcement contract; an implementation conforms to this
binding only for the resources, action classes, and PDPs in the runtime
enforcement scope it documents
({{I-D.draft-mcguinness-mission-runtime}}).

A PEP conforming to this binding MUST:

- carry the Mission and actor decision inputs in the AuthZEN envelope as
  defined ({{pdp-request}}), and match the approved entry's `resource`
  against `context.audience`, not the AuthZEN `resource` member;
- supply `context.parameter_digest` for a parameter-bound action class
  ({{parameter-digest}}), and `context.capability_source` for a
  catalog-sourced action whose approved entry recorded a source digest
  ({{capability-source-binding}}); and
- emit a Decision Evidence Object for each PDP decision
  ({{decision-evidence-object}}), an Execution Evidence Object for each
  high-consequence action ({{execution-evidence-object}}), and a
  pre-decision refusal record for a refusal before any PDP decision
  ({{pre-decision-refusal}}).

A PDP conforming to this binding MUST:

- perform the PDP-side consistency checks ({{pdp-request}});
- return every denial with a denial-reason identifier from the closed
  set of {{runtime-denial-classification}}; and
- produce Decision Evidence with the required members and a verifiable
  integrity envelope ({{decision-evidence-object}},
  {{decision-evidence-integrity}}).

# Security Considerations {#security-considerations}

The runtime profile's Security Considerations
({{I-D.draft-mcguinness-mission-runtime}}) apply in full:
placement and bypass, classification integrity, freshness and
consumption honesty, Resource policy authority, TOCTOU and replay, and
the limits of a compromised PEP or PDP. This section addresses only
threats specific to the AuthZEN binding and the evidence objects.

## Access Request Service in the trusted base

A deployment that composes with ARAP adds the Access Request Service to
its trusted base: it adjudicates requestable denials and issues the
approvals the PDP consumes as input. A compromised or misconfigured
Access Request Service can auto-approve escalations, so it MUST be
trusted, authenticated, and access-controlled like the PDP, and its
auto-approval is bounded as above.

## Denial oracle

The denial-reason identifiers and any `contributing_constraints` are a
decision oracle: an agent can probe them to map authority it does not
hold. The PEP SHOULD minimize the denial detail it relays to the agent;
a generic refusal suffices to stop the action, and the full reason and
contributing constraints belong in evidence, not in the agent-facing
response. To bound probing through the request loop, deployments SHOULD
rate-limit access requests per Mission and surface request provenance to
Approvers, so a compromised agent driving repeated requestable denials
is visible to the humans adjudicating them.

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
for Execution Evidence MUST be resolvable the same way through a
deployment-published key set.

This profile fixes one concrete discovery convention: the PDP publishes
its JWKS at a deployment-published location named in the enforcement
scope statement ({{I-D.draft-mcguinness-mission-runtime}}), and
the PEP or executor key set is published and named there likewise. A
retired signing key MUST remain resolvable in the published key set for
at least the evidence retention window, so records signed before a
rotation stay verifiable after it.

Implementations MUST reject evidence whose `format` is unsupported
rather than accepting it unverified.

## Materialized view fidelity

A PDP that evaluates against a materialized view enlarging the
Authority Set's bounds violates the bounded property of
{{mission-to-policy-materialization}}. `authority_hash` is the upper
bound; `policy_view_id` lets the PDP detect that the view it loaded
does not match the Mission the PEP referenced and deny with
`stale_state`.

## Transport

The PDP endpoint and the audit channels carrying Decision Evidence and
Execution Evidence MUST be served over TLS 1.2 or later (TLS 1.3
RECOMMENDED). PEP-to-PDP authentication MUST be mutual, satisfying the
integrity and mutual-authentication requirement the runtime profile
places on the PEP-PDP channel
({{I-D.draft-mcguinness-mission-runtime}}). Evidence at rest
MUST be encrypted per the deployment's data-protection posture.

# Privacy Considerations {#privacy-considerations}

The runtime profile's evidence-privacy guidance
({{I-D.draft-mcguinness-mission-runtime}}) applies in full. This
section addresses the concrete evidence objects.

## Evidence as PII sinks

Decision Evidence and Execution Evidence carry the authenticated
`subject`, actor chain, resource and action identifiers,
credential-derived correlators, capability-source identifiers,
`parameter_digest`, and timing. These records are PII sinks and SHOULD
be access-controlled to audit consumers with a legitimate need,
encrypted at rest, and retained per the window of
{{execution-evidence-object}}.

## Parameter exposure

The durable Decision Evidence record MUST NOT contain the raw
`parameters` object; it carries only `parameter_digest` and, at most,
parameter-class metadata, consistent with the runtime profile's rule
that raw parameters never appear in the record. Where raw parameters
must be retained for audit, they are held in a separately
access-controlled store keyed by `decision_id`. When the parameters are
themselves PII, the PEP SHOULD supply only `context.parameter_digest`
to the PDP, omitting `context.parameters`, so the PDP evaluates against
parameter-class policy without observing the raw values. The Execution
Evidence `result_summary` MUST NOT carry user-content payloads.

## Actor chain and Mission correlation

The `actor` member carries the delegation chain, which MAY reveal
service accounts, client instances, and organizational structure.
Evidence carrying the same Mission `id` and `authority_hash` across
resource boundaries can correlate a subject's activity; this is
inherent to the Mission's role as a governance handle. Deployments that
require unlinkability need an additional privacy design outside this
profile.

# IANA Considerations {#iana}

This document requests the following IANA actions.

## Media Type Registry

This document registers two media types per {{RFC6838}}.

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

The `context.mission`, `context.actor`, `context.credential`,
`context.parameters`, `context.parameter_digest`, `context.audience`,
`context.freshness`, `context.capability_source`, and
`context.prior_decision_id` members carried inside the AuthZEN request
`context` object ({{pdp-request}}, {{consumption-metering-binding}}) are
AuthZEN extension data and are not registered in an IETF registry.
The response `context.decision_id`, `context.denial_reason`,
`context.parameter_digest`, `context.policy_view_id`,
`context.permit_expires_at`, `context.single_use`,
`context.insufficient_claims`, and `context.access_request` members
({{runtime-denial-classification}}) are likewise AuthZEN extension
data. The Mission-bound token claims this profile consumes are
registered by {{I-D.draft-mcguinness-oauth-mission}}.

--- back

# Acknowledgments
{:numbered="false"}

This document is the AuthZEN binding of Mission-Bound Runtime
Enforcement and builds on the OpenID AuthZEN
Authorization API. The author thanks the OpenID AuthZEN community and
the Mission-Bound Authorization implementer community for feedback.
