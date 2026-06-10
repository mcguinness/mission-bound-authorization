---
title: "Mission-Bound Runtime Enforcement Profile"
abbrev: "Mission Runtime"
category: std

docname: draft-mcguinness-mission-runtime-profile-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - runtime
 - authzen
 - pdp
 - enforcement
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-profile.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  RFC6234:
  RFC6838:
  RFC7515:
  RFC8126:
  RFC8259:
  RFC8785:
  RFC9457:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-mission-expansion:
  OIDC-AUTHZEN:
    title: "OpenID AuthZEN Authorization API 1.0"
    author:
      org: "OpenID Foundation"
    date: 2025
    target: "https://openid.net/specs/authorization-api-1_0.html"

informative:
  RFC3339:
  RFC9396:
  RFC9470:
  RFC9701:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-mcguinness-mission-aauth-profile:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-insufficient-claims:

--- abstract

This document profiles the OpenID AuthZEN Authorization API to
enforce Mission-bound authority at runtime. The composition defines
Mission-to-policy materialization, the Resource-Side Enforcement
Contract, PEP placement rules, parameter binding, denial
classification with governed expansion eligibility, the Decision
Evidence Object emitted by the PDP, the Execution Evidence Object
emitted by the PEP or executor, and the runtime `max_invocations`
constraint. Each Mission-bound enforcement claim names a deployment-
published enforcement-scope manifest identifying covered action
classes and execution boundaries.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
governs credential issuance and derivation. This profile carries
those bounds to the execution boundary. Every consequential action
in a deployment's enforcement-scope manifest is evaluated by a
Policy Decision Point (PDP) against:

- Current Mission state (per Mission Status, from
  {{I-D.draft-mcguinness-mission-framework}}).
- The audience-relevant Authority Set projection.
- Authenticated actor context.
- Resource policy.

The PDP returns a permit, deny, or expandable-denial decision. The
PEP enforces the decision and emits Execution Evidence.

This profile is substrate-independent. OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} and AAuth Profile
{{I-D.draft-mcguinness-mission-aauth-profile}} adapters supply
substrate-native credential and actor context. The PDP interface
is the OpenID AuthZEN Authorization API {{OIDC-AUTHZEN}}.

## Submission venue

This document is an independent IETF Internet-Draft composing with
the OpenID AuthZEN Authorization API {{OIDC-AUTHZEN}}. AuthZEN is
an OpenID Foundation effort, not an IETF Working Group.

## Document Organization {#document-organization}

{{conventions-and-definitions}} introduces terminology and notation.

{{profile-structure}} explains the Core / Optional Modules split.

{{mission-to-policy-materialization}} defines how a Mission becomes
an evaluable policy view consumable by the PDP.

{{resource-side-enforcement-contract-rs-d}} and
{{pep-placement-rules}} define what an RS-D Resource Server commits
to and where the PEP MUST be placed.

{{pdp-request}} defines the PDP request shape and its mapping onto
AuthZEN's `subject`/`resource`/`action`/`context` envelope.

{{decision-evidence-object}} and {{execution-evidence-object}}
define the two linked evidence artifacts and their JSON Schemas.

{{runtime-denial-classification}} enumerates denial categories and
their composition with step-up and Mission Expansion.

{{max-invocations-constraint}} defines the reserve-on-permit /
finalize-on-outcome counter protocol.

{{enforcement-scope-manifest}} defines the deployment-published
manifest that scopes a conformance claim.

{{security-considerations}} and {{privacy-considerations}} address
security and privacy threats.

{{iana}} requests the IANA actions.

# Conventions and Definitions {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

## Notation

This document uses JSON {{RFC8259}} as the data model for all
PDP requests, responses, and evidence objects. JCS canonicalization
{{RFC8785}} applies wherever an integrity hash is computed.

"SHA-256" refers to {{RFC6234}}. Hash output is base64url-encoded
without padding and prefixed with `sha-256:` per the integrity-anchor
encoded form defined in
{{I-D.draft-mcguinness-mission-framework}}.

HTTP message examples follow the conventions of {{RFC9457}} for
problem-details responses and the AuthZEN specification
{{OIDC-AUTHZEN}} for decision request/response.

## Terminology

Terms from {{I-D.draft-mcguinness-mission-framework}} are inherited.
Additional definitions:

**PDP (Policy Decision Point)**:
: Component that evaluates per-action requests and produces a
permit, deny, or expandable-denial decision. Conforms to the
OpenID AuthZEN Authorization API.

**PEP (Policy Enforcement Point)**:
: The in-line component that calls the PDP before allowing a
consequential action and enforces the decision.

**Materialized Policy View**:
: The reproducible evaluable form of the Mission's approved tuple
(Validated Mission Intent, Authority Set, `policy_version`)
produced by the state authority or a trusted compiler.

**Decision Evidence**:
: A durable record emitted by the PDP capturing the inputs and
result of one runtime decision.

**Execution Evidence**:
: A durable record emitted by the PEP or executor capturing whether
the authorized action was attempted, completed, failed, or
suppressed.

**Enforcement-scope manifest**:
: A deployment-published document identifying the action classes,
PEP locations, and execution boundaries covered by a Mission-Bound
Runtime Enforcement conformance claim.

# Profile Structure {#profile-structure}

This profile is modular:

- **Core**: defines the required PDP contract, PEP placement,
  Decision Evidence, Execution Evidence, parameter binding, and
  denial classification.
- **Optional Modules**: separate per-module specifications adding
  Tool Binding, Decision Receipt, Purpose Registry, Attestation,
  Policy Projection.

Conformance claims name which modules the implementation supports.
The Core profile is the minimum for any Mission-Bound Runtime
Enforcement claim.

# Mission-to-Policy Materialization {#mission-to-policy-materialization}

The state authority (or a trusted compiler) reproducibly materializes
the approved Mission tuple as an evaluable policy view consumable by
the PDP.

## Inputs

- Validated Mission Intent.
- Authority Set (typed entries).
- `policy_version`.
- Schema versions for each Authority Set entry type.

## Properties

The materialized policy view MUST satisfy:

- **Reproducibility**: same inputs produce byte-identical materialized
  output.
- **Identifiable**: the materialized view carries `policy_view_id`
  and `policy_view_version` so PDP cache entries are addressable.
- **Bounded**: the materialized view does not enlarge the Authority
  Set's semantic bounds. Materialization is faithful.

### `policy_view_id` and `policy_view_version`

`policy_view_id` is computed deterministically as the integrity-anchor
encoded form ({{I-D.draft-mcguinness-mission-framework}}) over the
JCS-canonical bytes of the materialized view envelope:

~~~
SHA-256(JCS({
  "type":                "mission-policy-view",
  "schema_version":      "urn:mbo:schema:mission-policy-view:1",
  "authorization_domain": <mission.principals.tenant>,
  "state_authority":     <mission.origin>,
  "value":               <materialized view payload>
}))
~~~

`policy_view_version` is a monotonic counter (decimal-string integer)
incremented by the state authority each time the materialized view
changes for the same Mission. The pair (`policy_view_id`,
`policy_view_version`) uniquely addresses the materialized form.

## Wire form

This profile does not pick a concrete policy-language wire form for
the materialized view. Implementations MAY use:

- Cedar policies (`draft-cecchetti-oauth-rar-cedar`).
- OpenFGA tuples.
- Canonical input bundles consumed by the AuthZEN PDP directly.
- Engine-native artifacts.

The Policy Projection Optional Module (future spec) standardizes a
specific wire form when implementer demand justifies.

# Resource-Side Enforcement Contract (RS-D) {#resource-side-enforcement-contract-rs-d}

A Resource Server claiming RS-D MUST:

1. Identify every consequential action in its enforcement scope.
2. For each such action, call the PDP before allowing the action.
3. Pass to the PDP the inputs defined in Section 7.
4. Enforce the PDP decision.
5. Emit Execution Evidence after the action's outcome is determined.

A Resource Server claiming RS-D for a named scope but allowing
consequential actions outside that scope to bypass the PDP MUST NOT
claim RS-D for those actions. The enforcement-scope manifest names
covered action classes; uncovered actions are explicitly outside
the claim.

# PEP Placement Rules {#pep-placement-rules}

The PEP MUST be placed such that:

- Every action in the enforcement scope passes through the PEP.
- The PEP can prevent the action from being executed (not merely
  log it).
- The PEP has access to the authenticated subject, actor context,
  Mission reference, parameters, and Resource policy at decision
  time.

Acceptable placements include:

- In-process middleware in the Resource Server.
- A reverse-proxy interceptor.
- A sidecar enforcement gateway.
- The agent orchestrator's tool-call boundary (for local actions
  not exposed as resources).

PEP placements MUST be documented in the enforcement-scope manifest.

# PDP Request {#pdp-request}

The PDP request follows the OpenID AuthZEN Authorization API
{{OIDC-AUTHZEN}}. AuthZEN defines the top-level envelope with
`subject`, `resource`, `action`, and `context` members. This
profile binds Mission-Bound inputs into that envelope.

## AuthZEN envelope binding

| AuthZEN member | Mission-Bound binding |
|---|---|
| `subject` | AuthZEN subject object whose identity is a Mission Principal ({{I-D.draft-mcguinness-mission-framework}}). |
| `resource` | The target resource per AuthZEN. The PEP supplies the canonical resource identifier per substrate convention. |
| `action` | The requested action identifier (e.g., `journal-entries.write`). |
| `context` | Carries the Mission-Bound context object defined below. |

## `context.mission`

The Mission-Bound `context` object adds a `mission` member and
related per-request fields. The `mission` object identifies the
governance record and its current materialized view:

- `id` (string, required): the canonical `mission.id`.
- `origin` (string, required, URI): equal to the Mission's
  `mission.origin`.
- `authority_hash` (string, required): the integrity anchor for
  the Authority Set, in the integrity-anchor encoded form per
  {{I-D.draft-mcguinness-mission-framework}}.
- `policy_version` (string, required): the `policy_version`
  recorded at the approval event.
- `policy_view_id` (string, required): the materialized view
  identifier ({{mission-to-policy-materialization}}).
- `policy_view_version` (string, required): the materialized view
  monotonic counter.

## `context.actor`

The `actor` object carries the authenticated actor chain per
{{I-D.draft-mcguinness-oauth-actor-profile}}. Substrate profiles
populate this from the credential the PEP receives:

- OAuth Profile: the actor chain reconstructed from the access
  token's `act` claim and the token's authenticated client identity.
- AAuth Profile: the actor chain reconstructed from the AAuth
  resource-token's actor-context binding.

## `context.parameters` and `context.parameter_digest`

When parameter binding is required for the requested action, the
PEP supplies:

- `parameters` (object, conditional): the action's parameters as a
  JSON object. The shape is action-specific.
- `parameter_digest` (string, required when `parameters` is
  present): the integrity-anchor encoded form computed over the
  JCS-canonical bytes of:

~~~
SHA-256(JCS({
  "type":                "mission-action-parameters",
  "schema_version":      <action-parameters-schema-version>,
  "authorization_domain": <mission.principals.tenant>,
  "state_authority":     <mission.origin>,
  "value":               <parameters>
}))
~~~

The `parameter_digest` MUST be byte-equal to the digest computed by
the PDP over the same parameters object after normalization.
Implementations MUST reject `parameters` that contain duplicate JSON
object member names per the Framework's semantic normalization
rules.

## `context.audience` and `context.freshness`

- `audience` (string, required): the PEP's audience identifier.
- `freshness` (object, required): the Mission Status freshness the
  PEP relies on. Members:
  - `mission_status_issued_at` (RFC 3339 timestamp)
  - `mission_status_expires_at` (RFC 3339 timestamp)
  - `mode` (string): one of `fresh`, `cached`, `event_driven`
    (matches {{mission-status-composition}})
  - `freshness_at` (RFC 3339 timestamp): when the PEP's view of
    Mission Status was current

## Worked PDP request

For the Q3 invoicing Mission example:

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
      "iss": "https://idp.example.com",
      "sub_profile": { "type": "human" }
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
      "policy_version": "deploy-policy:v17",
      "policy_view_id":
        "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mT5L",
      "policy_view_version": "1"
    },
    "actor": {
      "act": {
        "iss": "https://as.example.com",
        "sub": "client_erp-recon-agent",
        "sub_profile": { "type": "service" }
      }
    },
    "parameters": {
      "amount_usd": 423.50,
      "source_invoice_id": "inv_2026Q3_842"
    },
    "parameter_digest":
      "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA1bRM",
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

The PDP MUST verify that:

1. The Mission state at decision time is `active` (from the
   Mission Status the PEP supplied).
2. `authority_hash`, `policy_version`, and `policy_view_id`
   carried by the PEP are consistent with the materialized policy
   view the PDP has loaded for this Mission.
3. The PEP-supplied `freshness` is within the deployment's
   declared `mission_max_stale_seconds`.
4. The `parameter_digest` (when present) matches a fresh digest
   computed by the PDP over the supplied `parameters`.

Failure of (1) returns `mission_inactive`; failure of (2) returns
`stale_state`; failure of (3) returns `stale_state` (with the
specific freshness-window violation in the denial reason); failure
of (4) returns `parameter_violation`.

# Decision Evidence Object {#decision-evidence-object}

The PDP emits a Decision Evidence Object for every runtime decision.

## Members

- `decision_id` (string, required): unique decision identifier.
  ABNF: `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of
  entropy.
- `mission` (object, required): a copy of the PDP request's
  `context.mission` object (carrying `id`, `origin`,
  `authority_hash`, `policy_version`, `policy_view_id`,
  `policy_view_version`).
- `actor`, `subject`, `resource`, `action`, `parameter_digest`,
  `audience`: PDP inputs as supplied (verbatim, after PDP-side
  normalization).
- `decision` (string, required): one of `permit`, `deny`,
  `expandable_deny`.
- `denial_reason` (string, conditional): when `decision` is `deny`
  or `expandable_deny`. Values from
  {{runtime-denial-classification}} or registered constraint
  names.
- `expansion` (object, conditional): when `decision` is
  `expandable_deny`, the eligibility-signaling fields per
  {{I-D.draft-mcguinness-mission-expansion}}: `eligible: true`,
  `access_request_uri`, `ticket`, `requested_authority`.
- `evaluated_at` (RFC 3339 timestamp, required).
- `evidence_envelope` (object, required): integrity protection
  (see {{decision-evidence-integrity}}).

## JSON Schema {#decision-evidence-schema}

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mission-decision-evidence:1",
  "title": "Mission Decision Evidence",
  "type": "object",
  "required": [
    "decision_id", "mission", "subject", "resource", "action",
    "audience", "decision", "evaluated_at", "evidence_envelope"
  ],
  "additionalProperties": false,
  "properties": {
    "decision_id": {
      "type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"
    },
    "mission": {
      "type": "object",
      "required": ["id", "origin", "authority_hash"],
      "properties": {
        "id":     { "type": "string" },
        "origin": { "type": "string", "format": "uri" },
        "authority_hash": { "type": "string" },
        "policy_version": { "type": "string" },
        "policy_view_id": { "type": "string" },
        "policy_view_version": { "type": "string" }
      }
    },
    "subject":   { "type": "object" },
    "actor":     { "type": "object" },
    "resource":  { "type": "object" },
    "action":    { "type": "object" },
    "parameter_digest": { "type": "string" },
    "audience":  { "type": "string" },
    "decision": {
      "type": "string",
      "enum": ["permit", "deny", "expandable_deny"]
    },
    "denial_reason": { "type": "string" },
    "expansion": {
      "type": "object",
      "properties": {
        "eligible":            { "type": "boolean" },
        "access_request_uri":  { "type": "string", "format": "uri" },
        "ticket":              { "type": "string" },
        "requested_authority": { "type": "object" }
      }
    },
    "evaluated_at": {
      "type": "string", "format": "date-time"
    },
    "evidence_envelope": {
      "type": "object",
      "required": ["format", "value"],
      "properties": {
        "format": { "type": "string" },
        "value":  { "type": "string" }
      }
    }
  }
}
~~~

## Integrity {#decision-evidence-integrity}

The `evidence_envelope` carries the integrity protection over the
Decision Evidence content. The default format is `jws-compact`,
which carries a JWS Compact Serialization {{RFC7515}} whose payload
is the JCS-canonical bytes of the Decision Evidence object with
the `evidence_envelope` member removed during signing. Verification
re-removes `evidence_envelope` and verifies the JWS against the
PDP's published signing key.

~~~ json
{
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

Profiles MAY register additional formats (e.g., `jws-flattened`,
`detached-receipt`). Implementations MUST reject envelopes with
unregistered formats.

## Worked example

~~~ json
{
  "decision_id": "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "policy_version": "deploy-policy:v17",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mT5L",
    "policy_view_version": "1"
  },
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR"
  },
  "actor": {
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
    "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA1bRM",
  "audience": "https://erp.example.com",
  "decision": "permit",
  "evaluated_at": "2026-11-02T08:14:03Z",
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBkcC1rZXkt..."
  }
}
~~~

Decision Evidence is durable and integrity-protected. It is the
authoritative record of what the PDP evaluated, NOT proof that the
action occurred.

# Execution Evidence Object {#execution-evidence-object}

The PEP or executor emits an Execution Evidence Object after the
authorized action's outcome is determined.

## Members

- `execution_id` (string, required): unique execution identifier.
  ABNF: `1*64( ALPHA / DIGIT / "-" / "_" )`. At least 128 bits of
  entropy.
- `decision_id` (string, required): the Decision Evidence this
  execution is linked to.
- `mission_id` (string, required): the canonical Mission ID
  (mirrored from the linked Decision Evidence for join-key
  convenience).
- `parameter_digest` (string, conditional): MUST be present when
  the linked Decision Evidence carries one. MUST match the
  `parameter_digest` in the linked Decision Evidence.
- `outcome` (string, required): one of `attempted`, `completed`,
  `failed`, `suppressed`. `suppressed` indicates the action was
  permitted by the PDP but the executor chose not to attempt it
  (e.g., kill-switch, secondary deny).
- `outcome_at` (RFC 3339 timestamp, required).
- `error` (string, conditional): error identifier when `outcome` is
  `failed`.
- `attempted_at`, `completed_at` (RFC 3339 timestamps, optional):
  timing context.
- `result_summary` (object, optional): minimal action result
  metadata (e.g., affected resource counts). MUST NOT carry
  user-content payloads.
- `evidence_envelope` (object, required): integrity protection
  (same format as Decision Evidence; see
  {{decision-evidence-integrity}}).

## JSON Schema {#execution-evidence-schema}

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mission-execution-evidence:1",
  "title": "Mission Execution Evidence",
  "type": "object",
  "required": [
    "execution_id", "decision_id", "mission_id",
    "outcome", "outcome_at", "evidence_envelope"
  ],
  "additionalProperties": false,
  "properties": {
    "execution_id": {
      "type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"
    },
    "decision_id": { "type": "string" },
    "mission_id":  { "type": "string" },
    "parameter_digest": { "type": "string" },
    "outcome": {
      "type": "string",
      "enum": ["attempted", "completed", "failed", "suppressed"]
    },
    "outcome_at":    { "type": "string", "format": "date-time" },
    "error":         { "type": "string" },
    "attempted_at":  { "type": "string", "format": "date-time" },
    "completed_at":  { "type": "string", "format": "date-time" },
    "result_summary": { "type": "object" },
    "evidence_envelope": {
      "type": "object",
      "required": ["format", "value"],
      "properties": {
        "format": { "type": "string" },
        "value":  { "type": "string" }
      }
    }
  }
}
~~~

## Worked example

~~~ json
{
  "execution_id": "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
  "decision_id":  "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  "mission_id":   "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "parameter_digest":
    "sha-256:t2Wq9pK7sR3mL6xT4bN1eY8jC5vH0nF2pV9zKqA1bRM",
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

Decision Evidence and Execution Evidence are **linked but
distinct**. Authorization is not proof that an action occurred; the
existence of a Decision Evidence record without a corresponding
Execution Evidence record indicates the action was not attempted,
or that the executor failed to emit evidence.

## TOCTOU and parameter binding

The `parameter_digest` chain (PEP request → Decision Evidence →
Execution Evidence) closes the time-of-check-to-time-of-use gap.
If the executed action's effective parameters differ from those
the PDP evaluated, the digest mismatch is detectable in audit.

When the Execution Evidence's `parameter_digest` does not match the
linked Decision Evidence's `parameter_digest`, the audit consumer
MUST classify the action as parameter-mismatch and treat it as
equivalent to an unauthorized action for compliance purposes. The
PEP itself MUST refuse to emit Execution Evidence with a mismatched
digest; only the audit consumer detects mismatches across the chain.

PEP MUST compute `parameter_digest` over the JCS-canonical bytes of
the parameter envelope defined in {{pdp-request}}.

## Retention

Decision Evidence and Execution Evidence MUST be retained for at
least the deployment's audit retention window, which SHOULD be at
least 90 days beyond the Mission's `mission_expiry`. Regulated
deployments MAY require longer retention per applicable regulation.

# Runtime Denial Classification

When the PDP returns a denial, the denial is one of:

- **`out_of_authority`**: the requested action is not within the
  Authority Set. MAY be `expandable_deny` if eligible.
- **`acr_insufficient`**: the actor's `acr` does not satisfy the
  Mission's `acr` constraint (either `acr_values` mismatch or
  `max_age` exceeded). MAY be satisfied by RFC 9470 step-up
  authentication without expansion.
- **`amr_insufficient`**: the actor's `amr` does not intersect the
  Mission's `amr` constraint `amr_values` set, or the authentication
  event's `auth_time` exceeds the constraint's `max_age`. MAY be
  satisfied by step-up authentication using one of the required
  methods without expansion.
- **`stale_state`**: the PEP-supplied freshness is stale or
  inconsistent with the materialized policy view.
- **`mission_inactive`**: the Mission state is not `active`.
- **`parameter_violation`**: parameters violate a registered
  constraint.
- **`resource_policy`**: Resource policy refuses the action
  independently of Mission authority.
- **`quota_exceeded`**: a runtime budget (e.g., `max_invocations`)
  has been exhausted.

## Expansion eligibility

The PDP returns `expandable_deny` when:

- The denial is `out_of_authority`, AND
- The Mission Expansion specification's eligibility predicate
  permits expansion for the requested authority delta.

The PEP MUST surface the expansion eligibility to the caller per
{{I-D.draft-mcguinness-mission-expansion}}'s wire binding for the
substrate.

## Insufficient Claims composition

The PDP MAY compose with
{{I-D.draft-mcguinness-oauth-insufficient-claims}} to signal which
authenticated claims would lift an `aal_insufficient` denial.

# `max_invocations` Constraint

This profile defines `max_invocations` as a runtime constraint
distinct from the Framework's `max_derivations` (which is an
issuance constraint).

## Semantics

`max_invocations` is the maximum number of authorized action
invocations permitted under the Mission, evaluated at the
enforcement boundary.

## Authoritative counter

The PEP maintains an authoritative atomic counter per Mission. The
counter is incremented through a reserve-on-permit, finalize-on-
outcome protocol:

1. On PDP `permit`, the PEP reserves one count slot.
2. On Execution Evidence `completed`, the slot is finalized as
   consumed.
3. On Execution Evidence `failed` or `suppressed`, the slot is
   released per the registered constraint semantics
   (default: failed = consumed, suppressed = released).
4. On Execution Evidence missing (timeout), the slot is finalized
   per the registered timeout semantics (default: consumed).

The counter MUST NOT exceed the value declared in the Mission's
`max_invocations` constraint.

## Multi-PEP coordination

When more than one PEP enforces a Mission's `max_invocations` (e.g.,
multiple Resource Servers under one deployment), the deployment
publishes a coordination policy in the enforcement-scope manifest.
Implementations:

- MAY use a centralized counter service.
- MAY use eventually-consistent counters with a per-PEP allocation
  budget.
- MUST NOT allow uncoordinated counters that would together exceed
  the declared maximum.

# Enforcement-Scope Manifest

A deployment publishing a Mission-Bound Runtime Enforcement claim
MUST publish an enforcement-scope manifest identifying:

- **Action classes covered**: the set of action identifiers the
  PEP intercepts.
- **PEP locations**: the components hosting the PEP for each action
  class.
- **Excluded execution boundaries**: action paths or execution
  contexts the deployment cannot intercept (e.g., debug shells,
  unsanctioned egress routes, agent-side tool invocations outside
  the orchestrator).
- **Mission state freshness mode**: `fresh`, `cached`, or
  `event_driven`.
- **Maximum tolerated stale interval**: in seconds.

The manifest is a JSON document published at a well-known URL or
linked from AS metadata.

# Mission Status Composition

The PDP relies on Mission Status to determine current Mission state.
The PEP MUST pass to the PDP the freshness of the Mission Status it
last consulted. The PDP applies the deployment's freshness mode:

- `fresh`: PEP MUST consult Mission Status synchronously before
  every consequential action.
- `cached`: PEP MAY use cached Mission Status within
  `mission_max_stale_seconds`.
- `event_driven`: PEP relies on event-channel invalidation; cached
  state is valid until an event invalidates it.

When freshness fails (cache miss, event-channel lag), the PEP MUST
classify the request as `stale_state` denial unless the deployment
explicitly defines a bounded degraded mode.

# Local-Action Boundary

For consequential actions that are NOT OAuth Resource Server calls
or AAuth resource-token calls (e.g., agent-orchestrator local tool
invocations, file-system writes, process launches), the orchestrator
MUST act as the PEP at the action boundary.

The orchestrator-PEP MUST:

- Identify the local action in its enforcement-scope manifest.
- Call the PDP before the action.
- Emit Decision Evidence and Execution Evidence per Sections 8 and 9.

The enforcement-scope manifest MUST explicitly list local-action
PEP placements and any local actions excluded from enforcement.

# Security Considerations

## Decision Evidence vs Execution Evidence

Decision Evidence is NOT proof an action occurred. Implementations
MUST emit Execution Evidence to record outcomes. Auditors MUST NOT
treat Decision Evidence alone as evidence of action.

## Stale state and TOCTOU

A PDP decision is valid only for the freshness window the PEP
supplied. The PEP MUST NOT execute an authorized action after the
freshness window has elapsed without re-consulting Mission Status.

The `parameter_digest` chain closes the parameter TOCTOU gap.
Implementations MUST verify the digest at execution time.

## PDP compromise

A compromised PDP can return arbitrary decisions. Mission-Bound
Runtime Enforcement assumes a trusted PDP. Deployments mitigate
PDP compromise through key hardware modules for PDP signing keys,
PDP redundancy with majority quorum, and audit-side cross-checks
against Mission Status.

## Authority enlargement at runtime

A PEP that interprets `permit` as authorization beyond the Authority
Set's bounds violates this profile. The Mission's `authority_hash`
is the upper bound; runtime evaluation NEVER enlarges authority.

## `max_invocations` counter correctness

The reserve-on-permit, finalize-on-outcome protocol depends on the
PEP correctly emitting Execution Evidence. A PEP that fails to
emit Execution Evidence leaks reserved slots over time, eventually
denying legitimate requests.

Implementations MUST timeout reserved slots and finalize them per
the registered constraint semantics (default: consumed).

## Bypass surfaces

Action paths outside the enforcement-scope manifest are NOT covered
by the conformance claim. Deployments MUST honestly document
bypass surfaces. A "complete" enforcement claim covering a narrow
manifest is more honest than a broad manifest with unenumerated
bypass surfaces.

# IANA Considerations

## Decision Evidence Object Media Type

This document registers `application/mission-decision-evidence+json`
per RFC 6838.

## Execution Evidence Object Media Type

This document registers `application/mission-execution-evidence+json`
per RFC 6838.

## Mission Common Constraints Registry

This document registers `max_invocations` in the Mission Common
Constraints registry created by
{{I-D.draft-mcguinness-mission-framework}}.

- Name: `max_invocations`
- Type: string (decimal-string integer).
- Specification: this document.
- Authoritative counter: PEP per Section 11.
- Narrowing: derived constraints MAY specify smaller values.

## Runtime metadata members

Deployments that implement this profile advertise runtime
capabilities through substrate-specific AS or PS metadata
documents. This document defines the following member names; each
substrate profile (OAuth, AAuth, MAS) registers these in its own
substrate metadata registry as needed.

- `mission_freshness_mode_supported`: array of `fresh`, `cached`,
  `event_driven`.
- `mission_enforcement_scope_manifest_uri`: URL of the
  deployment's enforcement-scope manifest.

Optional Runtime modules (`tool_binding`, `decision_receipt`,
`purpose_registry`, `attestation`, `policy_projection`) are
defined in separate companion specifications; each module
specification registers its own metadata member at its
substrate's metadata registry. The Runtime Profile does not
maintain a central registry of optional-module identifiers.

# Acknowledgments
{:numbered="false"}

The author thanks the OpenID AuthZEN working group and the
Mission-Bound Authorization implementer community for feedback.

--- back
