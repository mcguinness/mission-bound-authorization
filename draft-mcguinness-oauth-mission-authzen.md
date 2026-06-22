---
title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
abbrev: "Mission AuthZEN Profile"
category: std

docname: draft-mcguinness-oauth-mission-authzen-latest
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
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-authzen.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  RFC3339:
  RFC6234:
  RFC6838:
  RFC7515:
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
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest
  AUTHZEN:
    target: https://openid.net/specs/authorization-api-1_0-final.html
    title: "OpenID AuthZEN Authorization API 1.0"
    author:
      -
        org: OpenID Foundation
    date: 2025

informative:
  RFC9457:
  RFC9470:

--- abstract

Mission-Bound Runtime Enforcement for OAuth 2.0
({{I-D.draft-mcguinness-oauth-mission-runtime}}) specifies a
substrate-independent decision contract: before each consequential
action runs, a Policy Enforcement Point (PEP) obtains a permit from a
Policy Decision Point (PDP) that evaluates the action against the
Mission the acting token is bound to. That contract is independent of
the decision wire format. This document is the concrete OpenID AuthZEN
binding of that contract. It defines how a Mission is materialized
into an evaluable policy view, how the abstract decision inputs map
onto the AuthZEN Authorization API request and response, the Decision
Evidence and Execution Evidence objects a deployment emits and their
integrity, how runtime denials map onto AuthZEN error and
Insufficient-Claims responses, and the AuthZEN representation of the
runtime metering the base profile meters. It does not restate the
enforcement semantics the base profile owns.

--- middle

# Introduction

Mission-Bound Runtime Enforcement for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission-runtime}} (the "runtime profile")
specifies the runtime enforcement layer for Mission-bound access
tokens issued under Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile"). The
runtime profile is deliberately substrate-independent: it defines the
decision contract, action classification, PEP placement, parameter
binding and the time-of-check to time-of-use gap, consumption
metering, failure modes, runtime enforcement evidence, and the runtime
conformance scope, but it states that the decision API wire format is a
deployment choice and that it is "not an AuthZEN profile".

This document is that AuthZEN profile. It binds the runtime profile's
abstract decision contract ({{Section 6 of
I-D.draft-mcguinness-oauth-mission-runtime}}) to the OpenID AuthZEN
Authorization API {{AUTHZEN}}. It carries only the AuthZEN-binding
deltas:

- how a Mission becomes a materialized policy view the PDP evaluates
  ({{mission-to-policy-materialization}});
- how the runtime profile's decision inputs map onto the AuthZEN
  `subject`/`resource`/`action`/`context` envelope, the worked PDP
  request, and the PDP-side consistency checks ({{pdp-request}});
- the Decision Evidence and Execution Evidence objects, their
  integrity, and worked examples ({{decision-evidence-object}},
  {{execution-evidence-object}});
- how runtime denials map onto AuthZEN error and Insufficient-Claims
  responses ({{runtime-denial-classification}});
- the binding of a Mission's approved authority to concrete,
  catalog-sourced capabilities ({{capability-source-binding}}); and
- the AuthZEN representation of the runtime metering the runtime
  profile meters ({{max-invocations-constraint}}).

This document does not restate the enforcement contract. It does not
redefine which actions are consequential, where the PEP MUST sit, the
semantics of parameter binding, the semantics of metering, the failure
modes, or the runtime conformance scope; those are normatively defined
in {{I-D.draft-mcguinness-oauth-mission-runtime}} and are referenced,
not duplicated, here.

## Requirements Language

{::boilerplate bcp14-tagged}

# Conventions and Definitions {#conventions-and-definitions}

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
and enforcement scope are used as defined in
{{I-D.draft-mcguinness-oauth-mission-runtime}}. The Mission claim
(`id`, `origin`, `authority_hash`), the integrity anchors
(`proposal_hash`, `authority_hash`), and `authorization_details`
entries of type `mission_resource_access` are used as defined in
{{I-D.draft-mcguinness-oauth-mission}}.

Additional terms specific to this binding:

Materialized policy view:
: The reproducible, evaluable form of a Mission's approved authority
  produced by the issuing Authorization Server or a trusted compiler
  and consumed by the PDP ({{mission-to-policy-materialization}}).

Decision Evidence:
: The runtime enforcement evidence record
  ({{Section 10 of I-D.draft-mcguinness-oauth-mission-runtime}})
  emitted by the PDP, in the concrete object form of
  {{decision-evidence-object}}.

Execution Evidence:
: The record emitted by the PEP or executor after the authorized
  action's outcome is determined ({{execution-evidence-object}}).

HTTP message examples follow the AuthZEN specification {{AUTHZEN}} for
the decision request and response, and {{RFC9457}} for problem-details
error bodies where a deployment carries them outside the AuthZEN
envelope.

# Mission-to-Policy Materialization {#mission-to-policy-materialization}

The PDP evaluates a Mission against an action. The issuing
Authorization Server, or a trusted compiler, reproducibly materializes
the Mission's approved authority as an evaluable policy view the PDP
loads and addresses.

## Inputs

- The Mission's approved Authority Set (the `authorization_details`
  entries, including `mission_resource_access` entries with their
  `resource`, `actions`, and `constraints`), as committed by
  `authority_hash` ({{I-D.draft-mcguinness-oauth-mission}}).
- The derivation `policy_version` recorded at the approval event.

## Properties

The materialized policy view MUST satisfy:

- Reproducibility: the same inputs produce byte-identical materialized
  output under the canonicalization of
  {{I-D.draft-mcguinness-oauth-mission}}.
- Identifiable: the materialized view carries a `policy_view_id` so
  PDP cache entries are addressable.
- Bounded: materialization is faithful and does not enlarge the
  Authority Set's semantic bounds. A materialized view is an
  evaluation aid, never new authority.

### `policy_view_id`

`policy_view_id` is the integrity-anchor encoded form
({{I-D.draft-mcguinness-oauth-mission}}) of the SHA-256 of the
JCS-canonical bytes of the materialized view envelope:

~~~
SHA-256(JCS({
  "typ":   "mission-policy-view",
  "iss":   <mission.origin>,
  "value": <materialized view payload>
}))
~~~

The envelope reuses the domain-separated, issuer-bound integrity-anchor
envelope of {{I-D.draft-mcguinness-oauth-mission}} with a new `typ`;
this document defines no second canonicalization. Because
`policy_view_id` is a content hash, it uniquely addresses the
materialized form: any change to the view yields a new
`policy_view_id`, so equality on `policy_view_id` is the cache identity
and freshness test.

## Wire form

This profile does not pick a concrete policy-language wire form for the
materialized view. Implementations MAY use canonical input bundles the
AuthZEN PDP consumes directly, or an engine-native artifact. Compiling
a Mission into an engine-native policy artifact and standardizing a
policy-view carriage format are out of scope
({{Section 12 of I-D.draft-mcguinness-oauth-mission-runtime}}).

# PDP Request {#pdp-request}

The PDP request realizes the runtime profile's abstract decision
contract ({{Section 6 of I-D.draft-mcguinness-oauth-mission-runtime}})
over the OpenID AuthZEN Authorization API {{AUTHZEN}}. AuthZEN defines
a top-level envelope with `subject`, `resource`, `action`, and
`context` members. This profile binds the Mission-bound decision inputs
into that envelope. It does not change which inputs MUST be evaluated;
those are defined by the runtime profile.

This binding is used after ordinary access-token validation
({{Section 5 of I-D.draft-mcguinness-oauth-mission-runtime}}): the PEP
MUST NOT ask a PDP to authorize an action from unverified token claims,
and the PEP-PDP channel MUST be integrity-protected and mutually
authenticated as that section requires.

## AuthZEN envelope binding

| AuthZEN member | Mission-bound binding |
|---|---|
| `subject` | The principal the decision is requested for. |
| `resource` | The target resource, with the canonical resource identifier the PEP supplies. |
| `action` | The requested action identifier (for example, `journal-entries.write`), which the PDP evaluates against the approved `actions` per {{I-D.draft-mcguinness-oauth-mission}}. |
| `context` | Carries the Mission-bound context object defined below. |

## `context.mission`

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
  ({{Section 6.1 of I-D.draft-mcguinness-oauth-mission-runtime}}).

`policy_version`:
: REQUIRED. A string. the `policy_version` recorded at
  the approval event.

`policy_view_id`:
: REQUIRED. A string. the materialized view
  identifier ({{mission-to-policy-materialization}}).

## `context.actor`

The `actor` member carries the authenticated actor context when
delegation is in effect, reconstructed from the access token's `act`
claim and the token's authenticated client identity per
{{I-D.draft-mcguinness-oauth-mission}}:

`client_id`:
: A string. the authenticated client identity, and a client-instance
  identifier when present.

`act`:
: An object or array. the delegation chain, ordered root to leaf.

The `actor` member carries the delegation chain only. Provenance beyond
the delegation chain -- the tool a request invoked, a named workflow
step, a human approver -- MUST NOT be encoded inside the `act` chain;
the PDP evaluates the `act` chain as defined by the runtime profile,
and provenance is recorded in dedicated evidence fields where the
deployment captures it.

## `context.parameters` and `context.parameter_digest`

When parameter binding is required for the requested action's class
({{Section 3 of I-D.draft-mcguinness-oauth-mission-runtime}}), the PEP
supplies:

`parameters`:
: CONDITIONAL. An object. the action's parameters as a
  JSON object. The shape is action-specific. The PEP MAY omit
  `parameters` and supply only `parameter_digest` where the raw values
  are sensitive ({{privacy-considerations}}).

`parameter_digest`:
: REQUIRED for parameter-bound classes. A string.
  the `parameter_digest` defined by
  {{Section 7 of I-D.draft-mcguinness-oauth-mission-runtime}}. This
  profile carries that value on the wire; it does not define a second
  digest or canonicalization. The executing PEP recomputes and
  reverifies the digest immediately before acting, and the PDP
  recomputes it over any supplied `parameters`, both as that section
  requires.

## `context.audience` and `context.freshness`

`audience`:
: REQUIRED. A string. the PEP's audience or
  protected-resource identifier.

`freshness`:
: REQUIRED. An object. the freshness of the Mission state
  the PEP relied on, conveying the runtime profile's freshness inputs
  ({{Section 6.1 of I-D.draft-mcguinness-oauth-mission-runtime}}) on the
  wire. Members:

    `mission_status_issued_at`:
    : An RFC 3339 {{RFC3339}} timestamp.

    `mission_status_expires_at`:
    : An RFC 3339 timestamp.

    `mode`:
    : A string. one of `fresh`, `cached`, or `event_driven`
      ({{mission-status-composition}}).

    `freshness_at`:
    : An RFC 3339 timestamp. when the PEP's view of the
      Mission state was current.

The deployment's maximum staleness bound, and the rule that a
consequential action MUST fail closed when the Mission cannot be
established as `active` within that bound, are defined by the runtime
profile ({{Section 6.1 of I-D.draft-mcguinness-oauth-mission-runtime}});
the `freshness` object is only their wire representation.

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
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEd",
      "origin": "https://as.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE",
      "state": "active",
      "policy_version": "deploy-policy:v17",
      "policy_view_id":
        "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4"
    },
    "actor": {
      "client_id": "client_erp-recon-agent",
      "act": {
        "iss": "https://as.example.com",
        "sub": "client_erp-recon-agent"
      }
    },
    "parameters": {
      "amount_usd": 423.50,
      "source_invoice_id": "inv_2026Q3_842"
    },
    "parameter_digest":
      "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA",
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
requires ({{Section 6 of I-D.draft-mcguinness-oauth-mission-runtime}}),
the PDP MUST verify that the AuthZEN-carried envelope is
self-consistent:

1. The Mission state conveyed in `context.mission.state` is `active`;
   otherwise the PDP returns `mission_inactive`
   ({{runtime-denial-classification}}).
2. `authority_hash`, `policy_version`, and `policy_view_id` carried in
   `context.mission` are consistent with the materialized policy view
   the PDP has loaded for this Mission; otherwise the PDP returns
   `stale_state`.
3. The `context.freshness` the PEP supplied is within the deployment's
   staleness bound ({{Section 6.1 of
   I-D.draft-mcguinness-oauth-mission-runtime}}); otherwise the PDP
   returns `stale_state`, with the freshness-window violation in the
   denial reason.
4. When `context.parameters` is present, the PDP-recomputed digest
   matches `context.parameter_digest`; otherwise the PDP returns
   `parameter_violation`.

# Decision Evidence Object {#decision-evidence-object}

The runtime profile requires a decision evidence record for every PDP
decision on a consequential action, and fixes its content, canonical
form, and integrity ({{Section 10 of
I-D.draft-mcguinness-oauth-mission-runtime}}). This section gives the
concrete object an AuthZEN deployment emits.

## Members

`decision_id`:
: REQUIRED. A string. unique decision identifier. ABNF:
  `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of entropy.

`mission`:
: REQUIRED. An object. the PDP request's `context.mission`
  object (`id`, `origin`, `authority_hash`, and, when known,
  `policy_version` and `policy_view_id`), extended with `proposal_hash`
  and, when known, a consent-disclosure commitment, so the evidence
  chains back to the exact approved Mission. Within `mission`, `id`,
  `origin`, and `authority_hash` are required; the others are optional.
  These hashes are the issuing AS's commitments cited as anchors; the
  PDP does not recompute them ({{Section 10 of
  I-D.draft-mcguinness-oauth-mission-runtime}}).

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

`parameter_digest`:
: OPTIONAL. A string. PDP inputs as supplied, after PDP-side
  normalization.

`decision`:
: REQUIRED. A string. one of `permit` or `deny`.

`contributing_constraints`:
: REQUIRED when the decision turned on one or more authority or
  constraint entries. An array of strings. the
  identifiers of the constraints the PDP evaluated (`constraints`
  keys, `authorization_details` entry types). For a permit this
  records what was checked; for a deny, what failed.

`sequence`:
: REQUIRED. An integer. the per-Mission sequence indicator
  the runtime profile requires ({{Section 10 of
  I-D.draft-mcguinness-oauth-mission-runtime}}), so the decision stream
  has a verifiable order and gaps are detectable. MUST be zero or
  greater.

`denial_reason`:
: CONDITIONAL. A string. present when `decision` is
  `deny`. A value from {{runtime-denial-classification}} or a
  `constraints` key.

`evaluated_at`:
: REQUIRED. An RFC 3339 {{RFC3339}} timestamp.

`evidence_envelope`:
: REQUIRED. An object. integrity protection
  ({{decision-evidence-integrity}}), carrying a `format` (string,
  required) and a `value` (string, required).

A Decision Evidence Object is a closed object: it MUST NOT contain
members other than those defined above.

## Integrity {#decision-evidence-integrity}

The `evidence_envelope` carries the integrity protection over the
Decision Evidence content; it satisfies the runtime profile's
requirement that the record be serialized with JCS and
integrity-protected ({{Section 10 of
I-D.draft-mcguinness-oauth-mission-runtime}}). The default `format` is
`jws-compact`, a JWS Compact Serialization {{RFC7515}} whose payload is
the JCS {{RFC8785}} canonical bytes of the Decision Evidence object
with the `evidence_envelope` member removed during signing.
Verification re-removes `evidence_envelope` and verifies the JWS
against the PDP's published signing key.

~~~ json
{
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

Profiles MAY register additional formats (for example,
`jws-flattened`). Implementations MUST reject envelopes with
unregistered formats.

## Worked example

~~~ json
{
  "decision_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEd",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE",
    "proposal_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6s",
    "policy_version": "deploy-policy:v17",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4"
  },
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR"
  },
  "actor": {
    "client_id": "client_erp-recon-agent",
    "act": {
      "iss": "https://as.example.com",
      "sub": "client_erp-recon-agent"
    }
  },
  "resource": {
    "type": "journal-entry",
    "id": "je_2026Q3_inv_8421"
  },
  "action": { "name": "journal-entries.write" },
  "parameter_digest":
    "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA",
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
: CONDITIONAL. A string. error identifier when `outcome` is
  `failed`.

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
  "mission_id":   "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEd",
  "parameter_digest":
    "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA",
  "outcome":      "completed",
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
({{Section 7 of I-D.draft-mcguinness-oauth-mission-runtime}}). In this
binding, the `parameter_digest` chain runs from the PDP request
through Decision Evidence to Execution Evidence: if the executed
action's effective parameters differ from those the PDP evaluated, the
digest mismatch is detectable in audit.

The PEP MUST refuse to emit Execution Evidence with a `parameter_digest`
that does not match the linked Decision Evidence. When the values
nonetheless diverge across the chain, the audit consumer MUST classify
the action as parameter-mismatch and treat it as equivalent to an
unauthorized action for compliance purposes.

## Retention

Decision Evidence and Execution Evidence MUST be retained for at least
the deployment's audit retention window, which the runtime profile
requires to be no shorter than the Mission's effective audit horizon
({{Section 10 of I-D.draft-mcguinness-oauth-mission-runtime}}).
Regulated deployments MAY require longer retention.

# Runtime Denial Classification {#runtime-denial-classification}

When the PDP denies a consequential action, the failure condition is
one defined by the runtime profile
({{Section 9 of I-D.draft-mcguinness-oauth-mission-runtime}}). This
section binds those conditions to AuthZEN responses and gives the
denial-reason identifiers carried in Decision Evidence:

- `out_of_authority`: the action is not within the Authority Set.
- `acr_insufficient`: the actor's `acr` does not satisfy the Mission's
  `acr` constraint. MAY be satisfied by {{RFC9470}} step-up
  authentication.
- `amr_insufficient`: the actor's `amr` does not satisfy the Mission's
  `amr` constraint. MAY be satisfied by step-up authentication.
- `stale_state`: the PEP-supplied freshness is stale or inconsistent
  with the materialized policy view.
- `mission_inactive`: the Mission state is not `active`.
- `parameter_violation`: parameters violate a constraint or the digest
  check fails.
- `resource_policy`: Resource policy refuses the action independently
  of Mission authority.
- `quota_exceeded`: a metered runtime bound is exhausted
  ({{max-invocations-constraint}}).
- `capability_drift`: a catalog-sourced action's current
  capability-source digest differs from the digest committed at
  derivation, or the presented `tool_id` is outside the approved set
  ({{capability-source-binding}}).

A deny is terminal for the attempted action; Mission expansion and the
authority-expandable-denial workflow are out of scope
({{Section 6 of I-D.draft-mcguinness-oauth-mission-runtime}}).

## Insufficient Claims composition

For an `acr_insufficient` or `amr_insufficient` denial, the PDP MAY
signal which authenticated claims would lift the denial, so the caller
can satisfy the Mission's `acr` or `amr` constraint through OAuth
step-up authentication challenge {{RFC9470}} at the protected resource
and re-authenticate without a Mission expansion.

## Error response shape

The PDP returns its decision and any denial reason in the AuthZEN
response {{AUTHZEN}}. A deployment MAY additionally carry {{RFC9457}}
problem details for structured error information when the PDP is
consumed over HTTP outside the AuthZEN envelope.

# Capability Source Binding {#capability-source-binding}

Consequential actions an agent discovers at runtime -- through a Model
Context Protocol tool catalog, an OpenAPI document, a Protected
Resource Metadata-linked catalog, or an equivalent capability source --
identify the source they came from, so a Mission's approved authority
stays bound to concrete tools rather than to bare action names a later
catalog revision could redefine. The runtime profile assigns capability
identity to the approved `actions` and refuses an invoked identity
outside them ({{Section 6 of
I-D.draft-mcguinness-oauth-mission-runtime}}); this section gives the
concrete binding an AuthZEN deployment presents for catalog-sourced
actions.

The minimum binding, committed by the validating server at derivation
and presented by the executing component at request time, is:

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
  catalog-sourced actions. The PDP MUST return `capability_drift`
  ({{runtime-denial-classification}}) when the presented `tool_id` is
  outside the approved set.
- When the current source digest differs from the digest recorded at
  derivation, the PDP MUST treat the change as drift: return
  `capability_drift` and refuse, per declared policy.
- Actions not sourced from a discovered catalog (deployment-registered
  `authorization_details` types, first-party operations with stable
  identity) do not require this binding.

Cross-format canonicalization, signed capability manifests, and
media-type negotiation across catalog formats are out of scope
({{Section 12 of I-D.draft-mcguinness-oauth-mission-runtime}}); this
binding requires only the stable identifier plus source evidence
above.

# AuthZEN binding of consumption metering {#max-invocations-constraint}

The runtime profile owns consumption-metering semantics: it meters the
Mission's `max_budget`, `max_calls`, and `max_duration` bounds, defines
the atomic check-and-decrement, the single-versus-distributed-PDP
consistency posture, retry and idempotency behavior, and the rule that
an unmetered or unrecognized bound MUST cause refusal
({{Section 8 of I-D.draft-mcguinness-oauth-mission-runtime}}). This
section adds only the AuthZEN wire representation; it defines no new
metering semantics and no new constraint.

A deployment that meters a per-action invocation cap evaluates the cap
as part of the decision. When metering the cap would exceed it, the PDP
MUST deny with `quota_exceeded` ({{runtime-denial-classification}})
instead of returning a permit, and MUST record `quota_exceeded` as the
`denial_reason` in Decision Evidence. Because the runtime profile
counts a metered permit at decision time, the AuthZEN response surfaces
the cap purely as the permit-or-`quota_exceeded` outcome; a
permitted-but-failed action still counted, consistent with the runtime
profile's metering rules. The exactness of the cap is the consistency
bound the runtime profile's topology rules establish, not a property of
this wire binding.

# Mission Status Composition {#mission-status-composition}

The PDP relies on Mission state to decide. The runtime profile defines
the Mission state source, the maximum staleness bound, and the
fail-closed rule ({{Section 6.1 of
I-D.draft-mcguinness-oauth-mission-runtime}}). This binding conveys
that state and its freshness on the wire through `context.mission.state`
and `context.freshness` ({{pdp-request}}), using a `mode` member with
one of three values that describe how the PEP obtained the state:

- `fresh`: the PEP consulted the Mission state source synchronously
  before the action.
- `cached`: the PEP used cached Mission state within the deployment's
  staleness bound.
- `event_driven`: the PEP relies on event-channel invalidation; cached
  state is valid until an event invalidates it.

When freshness cannot be established within the bound, the PDP fails
closed for consequential actions as the runtime profile requires; in
this binding that surfaces as a `stale_state` denial
({{runtime-denial-classification}}).

# Security Considerations {#security-considerations}

The runtime profile's Security Considerations
({{Section 13 of I-D.draft-mcguinness-oauth-mission-runtime}}) apply in
full: placement and bypass, classification integrity, freshness and
consumption honesty, Resource policy authority, TOCTOU and replay, and
the limits of a compromised PEP or PDP. This section addresses only
threats specific to the AuthZEN binding and the evidence objects.

## Decision Evidence versus Execution Evidence

Decision Evidence is not proof an action occurred. Implementations MUST
emit Execution Evidence to record outcomes, and auditors MUST NOT treat
Decision Evidence alone as evidence of action. An audit consumer MUST
classify orphaned Decision Evidence (no matching Execution Evidence
within the deployment's reconciliation window) as undetermined-outcome
or, per deployment policy, as action-attempted; it MUST NOT treat it as
proof of action.

## Evidence integrity and PDP signing keys

The `evidence_envelope` binds each record to the emitting PDP or PEP.
The PDP's `jws-compact` signing key MUST be resolvable in the PDP's
published JWKS so a verifier can check Decision Evidence independently.
Implementations MUST reject evidence whose `format` is unregistered
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
({{Section 5 of I-D.draft-mcguinness-oauth-mission-runtime}}). Evidence
at rest MUST be encrypted per the deployment's data-protection posture.

# Privacy Considerations {#privacy-considerations}

The runtime profile's evidence-privacy guidance
({{Section 13 of I-D.draft-mcguinness-oauth-mission-runtime}}) applies
in full. This section addresses the concrete evidence objects.

## Evidence as PII sinks

Decision Evidence and Execution Evidence carry the authenticated
`subject`, actor chain, resource and action identifiers,
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

### `application/mission-decision-evidence+json`

- Type name: application
- Subtype name: mission-decision-evidence+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: UTF-8 JSON
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-bound runtime
  enforcement deployments
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Author/Change controller: IETF

### `application/mission-execution-evidence+json`

Registration fields are identical to the Decision Evidence media type
except the subtype name is `mission-execution-evidence+json`.

The non-normative `context.mission`, `context.actor`,
`context.parameters`, `context.parameter_digest`, `context.audience`,
and `context.freshness` members carried inside the AuthZEN `context`
object ({{pdp-request}}) are AuthZEN extension data and are not
registered in an IETF registry. The Mission-bound token claims this
profile consumes are registered by
{{I-D.draft-mcguinness-oauth-mission}}.

--- back

# Acknowledgments
{:numbered="false"}

This document is the AuthZEN binding of Mission-Bound Runtime
Enforcement for OAuth 2.0 and builds on the OpenID AuthZEN
Authorization API. The author thanks the OpenID AuthZEN community and
the Mission-Bound Authorization implementer community for feedback.
