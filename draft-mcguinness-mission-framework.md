---
title: "Mission Framework"
abbrev: "Mission Framework"
category: std

docname: draft-mcguinness-mission-framework-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - authorization
 - oauth
 - aauth
 - governance
 - agent
 - delegation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-framework.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  RFC3339:
  RFC4648:
  RFC5234:
  RFC6234:
  RFC8259:
  RFC8615:
  RFC8785:

informative:
  RFC3986:
  RFC5646:
  RFC6749:
  RFC7515:
  RFC7517:
  RFC7662:
  RFC8414:
  RFC8693:
  RFC8705:
  RFC9068:
  RFC9126:
  RFC9396:
  RFC9449:
  RFC9470:
  RFC9701:
  NIST-SP-800-63:
    title: "Digital Identity Guidelines"
    author:
      org: "National Institute of Standards and Technology"
    date: 2017
    seriesinfo:
      "NIST": "Special Publication 800-63-3"
  W3C-UNICODE-NORM:
    title: "Unicode Normalization Forms"
    author:
      org: "Unicode Consortium"
    date: 2023
    seriesinfo:
      "Unicode Standard Annex": "#15"

--- abstract

This document defines the Mission as a durable, integrity-anchored,
lifecycle-governed governance object for an approved task. It defines
the abstract types, interfaces, and behaviors that profile
specifications map onto specific substrates: Mission Proposal and
Mission lifecycles, the Mission Intent JSON schema, typed Authority
Set, integrity anchors with domain-separated hash inputs, a canonical
and pairwise identifier model, common constraints framework, Mission
Status interface, principal model, evidence binding, and
capability-advertisement metadata. The framework is substrate-neutral
on semantics; profile specifications for OAuth, AAuth, and the Mission
Authority Server compose this framework with their respective wire
substrates and pick the concrete protection mechanism.

--- middle

# Introduction

OAuth 2.0 {{RFC6749}} and adjacent specifications standardized
credential issuance, delegation, and token exchange. They do not
standardize an explicit, durable governance object for the
user-approved task that credentials are issued to serve. As long-lived
agentic workloads derive credentials across audiences and over time,
the absence of such an object forces deployments to reconstruct task
governance from disconnected per-credential records, with no shared
identifier, integrity commitment, or lifecycle ownership across hops.

This document defines the **Mission** as that object. A Mission is
created by an authoritative state authority at the moment of approval
from a structured Mission Intent submitted by a client. The Mission
record carries the approved Intent, a typed Authority Set bounded by
the Intent, integrity anchors that commit the approved record, a
lifecycle state machine the state authority owns, a stable identifier
that every derived artifact references, and principal-model bindings
identifying who approved the task and on whose behalf. Profile
specifications map these abstract elements onto OAuth, AAuth, and
cross-substrate (Mission Authority Server) wires.

This document is the foundational spec of the Mission-Bound
Authorization architecture. The OAuth Profile, AAuth Composition
Profile, Mission Authority Server profile, Mission-Bound Runtime
Enforcement Profile, Mission Shaper Profile, and feature specs
(Mission Expansion, Delegated Authority Validation, Mission-Bound
Transaction Token Chaining) compose this framework with their
respective substrates. This document does not select a wire format,
signing mechanism, or transport. It defines what profiles must
preserve.

## A Motivating Example

A user asks an autonomous agent to "reconcile last quarter's
invoices and post adjustments under $500 to my accounting system".
Today, the agent would obtain one or more OAuth access tokens scoped
to the accounting system. The access tokens carry the scope, but
nothing carries the structured task: the $500 ceiling, the
quarter-bound time window, the user's identity as the approver, or
the relationship between the read activity (fetching invoices) and
the write activity (posting adjustments). When the agent rotates
its refresh token, exchanges credentials with a downstream service,
or hands off to another worker, the task identity is lost; only the
scope remains.

A Mission is the persistent record that carries that task identity.
The state authority records the goal, the constrained authority
("post adjustments < $500"), the integrity-anchored proposal, the
approving principal and the AAL of their approval, and a stable
identifier that every derived credential references. When the user
later revokes the Mission, every derived credential becomes
unusable. When an auditor asks why a particular adjustment was
posted, the credential's `mission` claim resolves to the recorded
approval. When a downstream service receives a derived credential,
it can independently verify the Mission state from the state
authority.

This document defines that record and the abstract operations on it.

## Document Organization

This document is organized as follows.

{{conventions-and-definitions}} introduces notation and terminology.

{{mission-proposal-and-mission}} defines the Mission Proposal and
Mission records, their lifecycle state machines, the approval event,
idempotency, concurrent modification, and retention.

{{mission-intent}} defines the Mission Intent JSON schema and the
distinction between Submitted and Validated forms.

{{authority-set}} defines the typed Authority Set entry shape, the
Authority Set Type registry framework, and the default narrowing
profile.

{{integrity-anchors}} defines semantic normalization, the
authorization-domain-bound envelope, and the three integrity anchors.

{{identifier-model}} defines the canonical Mission ID, the pairwise
Mission reference framework, and the state-authority discovery
metadata document.

{{mission-status-interface}} defines the abstract Mission Status
interface, its required properties, request and response shape, and
error model.

{{common-constraints-framework}} defines the Common Constraints
registry framework and two initial entries (`max_derivations` and
`aal`).

{{capability-advertisement-metadata}} defines the state-authority
capability-advertisement metadata document and its registry.

{{reference-test-vectors}} declares the required test vector classes.

{{security-considerations}} and {{privacy-considerations}} address
security and privacy threats and mitigations.

{{iana-considerations}} requests the IANA actions creating registries
and initial entries.

## Scope and non-scope

This document defines:

- The Mission Proposal and Mission data model, including required
  fields, lifecycle state machines, and integrity anchors.
- The Mission Intent JSON schema.
- The typed Authority Set entry shape and type registry framework.
- The principal model.
- The canonical Mission identifier and the pairwise reference
  framework.
- The abstract Mission Status interface and its required properties
  (authentication, freshness, audience binding, integrity,
  anti-oracle, request-binding, caching).
- The Common Constraints framework and initial entries
  (`max_derivations`, `aal`).
- Capability-advertisement metadata.
- Domain-separated, authorization-domain-bound hash envelopes for
  integrity anchors.

This document does NOT define:

- A wire format for any specific substrate. Profile specifications do
  that.
- A signing format for Mission Status responses. Profiles compose with
  RFC 9701 {{RFC9701}}, JWS {{RFC7515}}, or substrate-native signing as
  appropriate.
- Runtime per-action enforcement. The Mission-Bound Runtime Enforcement
  Profile defines that.
- Mission Expansion semantics. The Mission Expansion specification
  defines that.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Notation

This document uses JSON {{RFC8259}} as the data model for all
records, requests, and responses defined herein.

ABNF {{RFC5234}} is used to define wire-format strings.

"base64url" refers to the URL-safe base64 encoding defined in
{{RFC4648}} Section 5, with all trailing padding ("=") characters
removed.

"SHA-256" refers to the cryptographic hash function defined in
{{RFC6234}}, producing a 32-octet digest.

"JCS" refers to JSON Canonicalization Scheme {{RFC8785}}. Where
this document specifies "JCS-canonical" bytes, the input MUST be a
valid JSON value as defined in {{RFC8259}}; the output is the
deterministic byte sequence produced by {{RFC8785}}.

"RFC 3339 timestamp" refers to a date-time as defined in
{{RFC3339}}, normalized to UTC ("Z" zone designator), with seconds
resolution. Implementations MAY include fractional seconds when
finer resolution is required.

Hexadecimal byte sequences in examples are written with a "0x"
prefix or as space-separated pairs. Base64url-encoded values appear
verbatim.

The notation `obj.field` references the value of the JSON member
`field` in the object `obj` at the nesting path implied by the
reference. For example, `mission.id` is the value of the `id`
member of a top-level `mission` object.

## Terminology

This document uses the following terms with the meanings defined
here. Profile specifications inherit these meanings; substrate-
specific terms (e.g., "Authorization Server", "Person Server") are
defined in the relevant profile.

**Mission Proposal**:
: A pre-approval record carrying a Validated Mission Intent. Has its
own lifecycle (`pending_approval`, `rejected`, `withdrawn`,
`expired_as_pending`). Identified by a `proposal_id`.

**Mission**:
: The durable, integrity-anchored, lifecycle-governed governance
object that records an approved task. Created from a Mission Proposal
at the approval event. Has its own lifecycle (`active`, `suspended`,
`revoked`, `completed`, `expired`). Identified by a canonical
`mission.id`.

**Mission Intent**:
: The structured task proposal. Two forms are distinguished:
**Submitted Mission Intent** (untrusted, as the client provided it)
and **Validated Mission Intent** (the state authority's authoritative,
post-validation, post-narrowing form, recorded on the Mission
Proposal). When unqualified, "Mission Intent" refers to the Validated
form.

**Authority Set**:
: The substrate-neutral container of approved authority entries, each
typed. Bounded by the Validated Mission Intent.

**Authority Set entry**:
: A typed payload in the Authority Set, carrying `type`,
`specification_uri`, `schema_digest`, `schema_version`, `authority`,
and `narrowing_profile` fields.

**State authority**:
: The server that owns a Mission record. Realized as an OAuth
Authorization Server, an AAuth Person Server, or a Mission Authority
Server depending on topology. The state authority is authoritative
for Mission state and is the only party that can resolve Pairwise
Mission References to the canonical `mission.id`.

**Approval event**:
: The atomic state-authority transition from Mission Proposal to
Mission upon receiving a binding consent signal.

**Consent disclosure object**:
: The structured representation of the information shown to the
approving principal at the approval event. The state authority
records this object verbatim and computes
`consent_disclosure_hash` over its normalized canonical
serialization. The consent disclosure object's schema is the
state authority's consent template; this document binds its
integrity hash but does not standardize its template.

**Integrity anchor**:
: One of `proposal_hash`, `authority_hash`, `consent_disclosure_hash`.
Each is computed after registered semantic normalization, over a
domain-separated envelope, using SHA-256, base64url-encoded.

**Mission Status**:
: The authenticated state-authority view returning Mission state,
integrity anchors, audience-filtered Authority Set projection, and
freshness indicator. By-mission-reference operation, distinct from
token introspection.

**Pairwise Mission Reference**:
: An audience-sector-specific opaque identifier for a Mission,
resolvable to the canonical `mission.id` only at the state authority.

**Pairwise sector**:
: The boundary across which a single Pairwise Mission Reference is
constant. Within a sector, the same Mission resolves to the same
reference for every consumer. Across sectors, the same Mission
resolves to distinct references.

**Approving principal**:
: The principal who approved the Mission (may differ from the
subject for delegated approval).

**Subject**:
: The principal on whose behalf the task is approved.

**Requesting client**:
: The OAuth client or AAuth agent that submitted the Mission
Proposal.

**Tenant** / **Authorization domain**:
: A logical partitioning at the state authority. Missions in one
tenant are not visible to consumers of another tenant unless
explicit cross-tenant policy declares it. This document treats
"tenant" and "authorization domain" as interchangeable identifiers
for that partition.

**Credential derivation event**:
: Any state-authority-initiated emission of a substrate credential
that references a Mission. Examples include initial access-token
issuance, refresh-token rotation, Token Exchange grants, ID-JAG
emissions, AAuth resource-token emissions, and AAuth auth-token
emissions. Each derivation event is counted against
`max_derivations` (see {{common-constraints-framework}}).

**Policy version**:
: An immutable identifier (typically a content-addressable string)
naming the derivation policy in force at the approval event. The
state authority MUST record the `policy_version` on the Mission
record at the approval event. Policy versions are state-authority-
local; profile specifications MAY register a syntax for portable
policy-version references.

**Authentication Assurance Level (AAL)**:
: A measure of confidence in the approving principal's authentication
at the approval event. AAL identifiers are deployment-defined; this
document recommends compositions with {{NIST-SP-800-63}} levels
(`aal1`, `aal2`, `aal3`) or {{RFC9470}}-style `acr` values, and
provides the `aal` Common Constraint to bind required values.

**Audience**:
: A consumer of a Mission-bound credential or of Mission Status
responses. Audiences are named at issuance time and verified at
consumption time.

**Mission-bound credential**:
: Any substrate credential (OAuth access token, OAuth refresh
token, AAuth resource token, AAuth auth token, transaction token,
or similar) whose Mission claim or substrate-native binding
references a specific Mission.

# Mission Proposal and Mission {#mission-proposal-and-mission}

A **Mission Proposal** is created when a client submits a Mission
Intent to a state authority. A Mission Proposal carries the Validated
Mission Intent (after the state authority validates and narrows the
Submitted Mission Intent) and is identified by a stable
`proposal_id`. A Mission Proposal is in one of four states:

- `pending_approval`: awaiting consent.
- `rejected`: consent denied; terminal.
- `withdrawn`: client or administrator withdrew the Proposal; terminal.
- `expired_as_pending`: consent window elapsed; terminal.

A **Mission** is created by the state authority at the **approval
event** atomic transition. A Mission exists only post-approval. A
Mission is in one of five states:

- `active`: the only state in which credential derivation MAY proceed.
- `suspended`: temporarily blocked; the Mission MAY return to `active`
  by state-authority action.
- `revoked`: terminated by user, administrator, or policy; terminal.
- `completed`: the task finished or the Mission was superseded;
  terminal.
- `expired`: `mission_expiry` reached; terminal.

## Mission Proposal Record {#mission-proposal-record}

A Mission Proposal record carries the following members:

- `proposal_id` (string, required): the stable Proposal identifier
  (see {{proposal-id-format}}).
- `state` (string, required): one of `pending_approval`,
  `rejected`, `withdrawn`, `expired_as_pending`.
- `state_authority` (string, required): issuer URL of the state
  authority that holds the Proposal.
- `tenant` (string, required): tenant identifier under which the
  Proposal lives.
- `requesting_client` (string, required): client identifier that
  submitted the Proposal.
- `intent_submitted` (object, required): the Submitted Mission
  Intent as the client provided it. Preserved verbatim (after JSON
  parsing) for audit purposes.
- `intent_validated` (object, required after validation): the
  Validated Mission Intent. Absent before validation completes.
- `created_at` (string, required): RFC 3339 timestamp of Proposal
  creation.
- `consent_window_expires_at` (string, required): RFC 3339 timestamp
  after which the Proposal transitions to `expired_as_pending` if
  still `pending_approval`.
- `narrowing_decisions` (array, optional): structured record of
  narrowing decisions applied during validation (see
  {{narrowing-rules}}).
- `terminal_reason` (string, optional): present in terminal states.
  For `rejected`, an opaque deployment-defined reason. For
  `withdrawn`, an indication of which party withdrew.
- `successor_mission_id` (string, optional): present only after the
  approval event creates a Mission; the canonical `mission.id` of
  the created Mission.

### `proposal_id` format {#proposal-id-format}

`proposal_id` is an opaque URL-safe ASCII string. ABNF:

~~~
proposal-id    = 1*64( unreserved-char )
unreserved-char = ALPHA / DIGIT / "-" / "_"
~~~

`proposal_id` MUST contain at least 80 bits of entropy and MUST be
unique within the state authority's namespace. `proposal_id` MUST
NOT be reused after Proposal retention elapses (see
{{retention}}).

### Mission Proposal JSON Schema {#mission-proposal-schema}

The canonical JSON Schema for a Mission Proposal record is:

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mission-proposal:1",
  "title": "Mission Proposal",
  "type": "object",
  "required": [
    "proposal_id", "state", "state_authority", "tenant",
    "requesting_client", "intent_submitted",
    "created_at", "consent_window_expires_at"
  ],
  "additionalProperties": false,
  "properties": {
    "proposal_id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$" },
    "state": {
      "type": "string",
      "enum": [
        "pending_approval", "rejected", "withdrawn",
        "expired_as_pending"
      ]
    },
    "state_authority": { "type": "string", "format": "uri" },
    "tenant": { "type": "string" },
    "requesting_client": { "type": "string" },
    "intent_submitted": { "$ref": "urn:mbo:schema:mission-intent:1" },
    "intent_validated": { "$ref": "urn:mbo:schema:mission-intent:1" },
    "created_at": { "type": "string", "format": "date-time" },
    "consent_window_expires_at": {
      "type": "string", "format": "date-time"
    },
    "narrowing_decisions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["field", "submitted", "validated", "policy_ref"],
        "properties": {
          "field": { "type": "string" },
          "submitted": {},
          "validated": {},
          "policy_ref": { "type": "string", "format": "uri" }
        }
      }
    },
    "terminal_reason": { "type": "string" },
    "successor_mission_id": { "type": "string" }
  }
}
~~~

## Mission Record {#mission-record}

A Mission record carries the following members:

- `mission` (object, required): the Mission identity envelope, with
  members `id` (canonical `mission.id`) and `origin`
  (`mission.origin`, the state-authority issuer URL).
- `state` (string, required): one of `active`, `suspended`,
  `revoked`, `completed`, `expired`.
- `intent` (object, required): the Validated Mission Intent (see
  {{mission-intent}}).
- `authority_set` (array, required): the typed Authority Set entries
  (see {{authority-set}}).
- `integrity_anchors` (object, required): the three integrity
  anchors (see {{integrity-anchors}}): `proposal_hash`,
  `authority_hash`, `consent_disclosure_hash`.
- `principals` (object, required): the principal model (see
  {{principal-model}}): `subject`, `approving_principal`,
  `requesting_client`, `tenant`, `state_authority`,
  `delegation_policy`.
- `binding_evidence` (object, required): the evidence recorded at
  the approval event: `signer_kid` (state-authority key
  identifier), `approval_event_id`, `approval_event_at` (RFC 3339),
  `policy_version`, `intent_schema_version`,
  `consent_template_version`, `aal_at_approval`.
- `proposal_id` (string, required, immutable): the originating
  Proposal identifier.
- `created_at` (string, required): RFC 3339 timestamp of the
  approval event (Mission creation).
- `mission_expiry` (string, required): RFC 3339 timestamp; mirrors
  `intent.mission_expiry`. Carried at the top level for fast
  lifecycle checks.
- `lifecycle_history` (array, optional): structured record of state
  transitions, each carrying `from_state`, `to_state`, `at`, and
  `actor` (the principal who caused the transition, when known).

A Mission record MUST NOT carry mutable runtime context. Actor chains
and per-request actor identifiers are carried by projections (derived
credentials) and runtime requests, not by the Mission record.

### `mission.id` format {#mission-id-format}

`mission.id` is an opaque URL-safe ASCII string. ABNF:

~~~
mission-id      = 1*256( unreserved-char )
unreserved-char = ALPHA / DIGIT / "-" / "_"
~~~

`mission.id` MUST contain at least 128 bits of entropy. See
{{canonical-mission-id}} for additional requirements.

### Mission Record JSON Schema {#mission-record-schema}

The canonical JSON Schema for a Mission record is:

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mission:1",
  "title": "Mission",
  "type": "object",
  "required": [
    "mission", "state", "intent", "authority_set",
    "integrity_anchors", "principals", "binding_evidence",
    "proposal_id", "created_at", "mission_expiry"
  ],
  "additionalProperties": false,
  "properties": {
    "mission": {
      "type": "object",
      "required": ["id", "origin"],
      "additionalProperties": false,
      "properties": {
        "id": { "type": "string", "pattern": "^[A-Za-z0-9_-]{1,256}$" },
        "origin": { "type": "string", "format": "uri" }
      }
    },
    "state": {
      "type": "string",
      "enum": [
        "active", "suspended", "revoked", "completed", "expired"
      ]
    },
    "intent": { "$ref": "urn:mbo:schema:mission-intent:1" },
    "authority_set": {
      "type": "array",
      "items": { "$ref": "urn:mbo:schema:authority-set-entry:1" }
    },
    "integrity_anchors": {
      "type": "object",
      "required": [
        "proposal_hash", "authority_hash",
        "consent_disclosure_hash"
      ],
      "additionalProperties": false,
      "properties": {
        "proposal_hash": { "type": "string" },
        "authority_hash": { "type": "string" },
        "consent_disclosure_hash": { "type": "string" }
      }
    },
    "principals": { "$ref": "urn:mbo:schema:principal-model:1" },
    "binding_evidence": {
      "type": "object",
      "required": [
        "signer_kid", "approval_event_id", "approval_event_at",
        "policy_version", "intent_schema_version",
        "consent_template_version", "aal_at_approval"
      ],
      "additionalProperties": false,
      "properties": {
        "signer_kid": { "type": "string" },
        "approval_event_id": { "type": "string" },
        "approval_event_at": {
          "type": "string", "format": "date-time"
        },
        "policy_version": { "type": "string" },
        "intent_schema_version": { "type": "string" },
        "consent_template_version": { "type": "string" },
        "aal_at_approval": { "type": "string" }
      }
    },
    "proposal_id": { "type": "string" },
    "created_at": { "type": "string", "format": "date-time" },
    "mission_expiry": { "type": "string", "format": "date-time" },
    "lifecycle_history": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["from_state", "to_state", "at"],
        "properties": {
          "from_state": { "type": "string" },
          "to_state": { "type": "string" },
          "at": { "type": "string", "format": "date-time" },
          "actor": { "type": "string" }
        }
      }
    }
  }
}
~~~

### Worked Example: Mission record

Continuing the example from {{mission-intent}}:

~~~ json
{
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com"
  },
  "state": "active",
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $500.",
    "objects": [
      "https://erp.example.com/api/invoices",
      "https://erp.example.com/api/journal-entries"
    ],
    "constraints": [
      "Read only invoices issued in 2026-Q3.",
      "Post journal entries with absolute amount < $500."
    ],
    "success_criteria": [
      "All Q3 invoices processed.",
      "Each posted entry references a source invoice."
    ],
    "mission_expiry": "2026-12-31T23:59:59Z",
    "purpose": "urn:erp.example.com:purposes:quarterly-reconcile",
    "language": "en",
    "context": {
      "max_derivations": "200",
      "aal": {
        "value": "urn:mbo:aal:2",
        "freshness_seconds": 1800
      }
    }
  },
  "authority_set": [
    {
      "type": "mission_resource_access",
      "specification_uri":
        "https://datatracker.ietf.org/doc/draft-mcguinness-mission-oauth-profile",
      "schema_version": "1",
      "authority": {
        "resource": "https://erp.example.com",
        "actions": ["invoices.read", "journal-entries.write"],
        "constraints": {
          "issued_after": "2026-07-01T00:00:00Z",
          "issued_before": "2026-10-01T00:00:00Z",
          "max_amount_usd": 500
        }
      },
      "narrowing_profile": "urn:mbo:narrowing:default-v1"
    }
  ],
  "integrity_anchors": {
    "proposal_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "consent_disclosure_hash":
      "sha-256:nB2xK5qY7vM3rL9pT4cE6sZ8wQ1bN0fH5jX9kV2sRdM"
  },
  "principals": {
    "subject": "user_3p2q8mN1a0kV7tR",
    "approving_principal": "user_3p2q8mN1a0kV7tR",
    "requesting_client": "client_erp-recon-agent",
    "tenant": "tenant_acme",
    "state_authority": "https://as.example.com",
    "delegation_policy": "urn:mbo:delegation:default-v1"
  },
  "binding_evidence": {
    "signer_kid": "sa-key-2026-q3",
    "approval_event_id": "ape_8K2nP4qV9rL3tY6sB1z",
    "approval_event_at": "2026-10-15T14:32:11Z",
    "policy_version": "deploy-policy:v17",
    "intent_schema_version": "urn:mbo:schema:mission-intent:1",
    "consent_template_version": "consent-tpl:reconcile:v3",
    "aal_at_approval": "urn:mbo:aal:2"
  },
  "proposal_id": "prop_4kQ9pX2vN7sR1tY8mZ3",
  "created_at": "2026-10-15T14:32:11Z",
  "mission_expiry": "2026-12-31T23:59:59Z"
}
~~~

## Lifecycle state machines

### Mission Proposal lifecycle

The Mission Proposal lifecycle is:

~~~
            +------------------+
            | pending_approval |
            +--------+---------+
                     |
       +-------------+------------+--------------+
       |             |            |              |
       v             v            v              v
   approved      rejected     withdrawn   expired_as_pending
   (atomic
    transition
    to Mission)
~~~

The normative transition table for Mission Proposals is:

| From | Event | To | Required side effect |
|---|---|---|---|
| (none) | `submit_intent` | `pending_approval` | Validate and narrow Mission Intent; record `intent_validated`; persist Proposal |
| `pending_approval` | `consent_approved` | (Mission created) | Approval event ({{approval-event}}); Proposal transitions out atomically with Mission creation |
| `pending_approval` | `consent_rejected` | `rejected` | Record `terminal_reason`; emit lifecycle event |
| `pending_approval` | `withdraw` | `withdrawn` | Record `terminal_reason`; emit lifecycle event |
| `pending_approval` | `consent_window_elapsed` | `expired_as_pending` | Emit lifecycle event |
| `pending_approval` | `submit_intent` (same `proposal_id`) | `pending_approval` | Idempotent no-op (see {{approval-event}}) |
| terminal | any event | (refused) | Return concurrent-modification error ({{concurrent-modification}}) |

### Mission lifecycle

The Mission lifecycle is:

~~~
                  +----------+
                  |  active  | <----+
                  +-----+----+      |
                        |           | resume
                        |    +------+------+
                        +--->|  suspended  |
                        |    +-------------+
                        |
       +----------------+--------+-------------+
       |                |        |             |
       v                v        v             v
   revoked          completed  expired   (other terminal)
~~~

The normative transition table for Missions is:

| From | Event | To | Required side effect |
|---|---|---|---|
| (none) | `approval_event` | `active` | Create Mission record atomically with Proposal transition |
| `active` | `suspend` | `suspended` | Record event in `lifecycle_history`; emit lifecycle event; existing credentials remain valid but derivation is blocked |
| `suspended` | `resume` | `active` | Record event; emit lifecycle event |
| `active` | `revoke` | `revoked` | Record event; emit lifecycle event; in-flight credentials invalidated per profile |
| `suspended` | `revoke` | `revoked` | Same as above |
| `active` | `complete` | `completed` | Record event; emit lifecycle event |
| `active` | `mission_expiry_reached` | `expired` | Record event; emit lifecycle event |
| `suspended` | `mission_expiry_reached` | `expired` | Same as above |
| any terminal state | any event | (refused) | Return concurrent-modification error |

Profile specifications MAY add substrate-specific transitions
consistent with this state machine. Profile-specific transitions
MUST NOT bypass the terminal-state guard.

## Approval event {#approval-event}

The approval event is the atomic state-authority transition from
Mission Proposal to Mission upon receiving a binding consent signal.
At the approval event the state authority MUST:

1. Validate the Submitted Mission Intent and produce the Validated
   Mission Intent on the Proposal (see {{narrowing-rules}}).
2. Derive the Authority Set from the Validated Mission Intent.
3. Render the consent disclosure object presented to the approving
   principal.
4. Compute `proposal_hash`, `authority_hash`, and
   `consent_disclosure_hash` (see {{integrity-anchors}}).
5. Record binding evidence (approving principal identity,
   Authentication Assurance Level, timestamp, consent disclosure
   object, `policy_version`, schema versions, consent template
   version, signer key identifier).
6. Create the Mission record atomically with the above evidence.

The approval event MUST be atomic with Mission record creation. If
the state authority cannot complete the atomic commit, the Proposal
remains `pending_approval`; no partial Mission record exists.

### Approval-event identifier

Each approval event has a distinct identifier
(`approval_event_id`). ABNF:

~~~
approval-event-id = 1*64( unreserved-char )
unreserved-char   = ALPHA / DIGIT / "-" / "_"
~~~

`approval_event_id` MUST contain at least 128 bits of entropy and
MUST be unique within the state authority's namespace. It is
recorded on the Mission's `binding_evidence` and is the operation
key for approval idempotency.

### Idempotency

Approval submission MUST be idempotent on the pair
(`proposal_id`, `approval_event_id`). The state authority MUST
treat a repeated submission with the same pair (and the same
content for the originally-bound fields) as a no-op returning the
existing Mission record. The state authority MUST refuse a
repeated submission with the same pair but divergent content,
returning a concurrent-modification error.

Exactly one Mission may be created from a Proposal. The resulting
Mission permanently records its source `proposal_id`.

## Concurrent modification {#concurrent-modification}

Concurrent approve, reject, withdraw, and expiry operations MUST be
serialized with compare-and-set semantics on the Proposal's
`state` and a state-authority-local revision counter.

When a concurrent-modification conflict is detected (e.g., a
withdraw arrives after consent has been approved, or two
approve calls race), the state authority MUST refuse the losing
request and return an error of the form:

~~~ json
{
  "error": "mission_concurrent_modification",
  "error_description":
    "The proposal or mission was modified by a concurrent operation.",
  "current_state": "active",
  "observed_state": "pending_approval"
}
~~~

The fields are:

- `error` (string, required): `mission_concurrent_modification`.
- `error_description` (string, recommended): human-readable summary.
- `current_state` (string, required): the actual current state at
  conflict detection time.
- `observed_state` (string, required): the state the caller's
  request assumed.

Profile specifications bind this abstract error to substrate-specific
transport (HTTP 409 Conflict for OAuth/HTTP transports is RECOMMENDED).

## Retention {#retention}

A Mission record MUST be retained at least until: (a) all derived
credentials have expired, AND (b) the deployment's audit retention
period for the relevant Mission class has elapsed.

Deployments SHOULD set a minimum audit retention period of 90 days
beyond the Mission's `mission_expiry`. Regulated deployments
(financial, healthcare, government) SHOULD use longer retention
matching the applicable regulatory regime; this document does not
mandate a regulatory floor.

After retention, the state authority MAY garbage-collect the
Mission record. The canonical `mission.id` MUST NOT be reused
after garbage collection.

The Proposal record is retained alongside its resulting Mission for
the same audit retention window. After retention, the Proposal record
MAY be garbage-collected with the Mission record. `proposal_id`
MUST NOT be reused.

Terminal-state Proposals (`rejected`, `withdrawn`,
`expired_as_pending`) follow a deployment-defined Proposal-only
retention policy independent of Mission retention. Deployments
SHOULD retain such Proposals for at least 30 days to support
investigation of denied or abandoned approval attempts.

# Mission Intent

The Mission Intent is the structured task proposal a client submits
to a state authority. The Mission Intent is the input to the
approval event; the Validated form (defined below) is the recorded
output.

## Field Reference

The Mission Intent JSON object defines the following fields:

- `goal` (string, required): user-readable description of the task.
  Length 1 to 4096 characters. Implementations SHOULD normalize
  via Unicode NFC before storage and integrity-anchor computation.
- `objects` (array of string, required, minItems 1): the resources,
  datasets, tools, or domains the task touches. Each entry is a
  URI or a state-authority-registered identifier. Order is preserved
  in the Validated form; equality is computed as an order-independent
  set under semantic normalization (see {{integrity-anchors}}).
- `constraints` (array of string, required): user-readable bounds
  on the task. May be empty.
- `success_criteria` (array of string, required): conditions for
  the task being complete. May be empty.
- `mission_expiry` (string, required): RFC 3339 timestamp. The hard
  ceiling on the Mission's validity. Derived authority MUST NOT
  outlast it.
- `purpose` (string, optional): a URI {{RFC3986}} naming the task
  class. Stable per requesting client. The state authority MAY
  refuse a `purpose` URI not registered in deployment policy.
- `language` (string, optional): the natural-language tag {{RFC5646}}
  of the user-facing string fields (`goal`, `constraints`,
  `success_criteria`). Default `"en"` if absent.
- `context` (object, optional): machine-actionable bounds.
  Member names MUST be either registered Common Constraint keys
  (see {{common-constraints-framework}}) or extension keys prefixed
  with `x_`. Unknown non-`x_` keys MUST be refused.
- Extension fields (any member name prefixed with `x_`): MAY appear
  at the top level. See {{schema-evolution}}.

## JSON Schema {#mission-intent-schema}

The canonical JSON Schema for a Submitted Mission Intent (draft 2020-12)
is:

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mission-intent:1",
  "title": "Mission Intent",
  "type": "object",
  "required": [
    "goal", "objects", "constraints",
    "success_criteria", "mission_expiry"
  ],
  "additionalProperties": false,
  "patternProperties": {
    "^x_[A-Za-z0-9_-]+$": {}
  },
  "properties": {
    "goal": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4096
    },
    "objects": {
      "type": "array",
      "minItems": 1,
      "items": { "type": "string", "minLength": 1 }
    },
    "constraints": {
      "type": "array",
      "items": { "type": "string", "minLength": 1 }
    },
    "success_criteria": {
      "type": "array",
      "items": { "type": "string", "minLength": 1 }
    },
    "mission_expiry": {
      "type": "string",
      "format": "date-time"
    },
    "purpose": { "type": "string", "format": "uri" },
    "language": { "type": "string" },
    "context": {
      "type": "object",
      "additionalProperties": true
    }
  }
}
~~~

The Validated Mission Intent uses the same schema. The state
authority's post-narrowing form MAY differ from the Submitted form
only in field values (per the narrowing rules of
{{narrowing-rules}}); it MUST NOT add or remove fields except in
the case of unknown non-`x_` keys, which are refused at validation
time and absent from the Validated form by construction.

## Examples

### Submitted Mission Intent

A client submits the following Mission Intent for the invoicing
example of {{a-motivating-example}}:

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "objects": [
    "https://erp.example.com/api/invoices",
    "https://erp.example.com/api/journal-entries"
  ],
  "constraints": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries with absolute amount < $500."
  ],
  "success_criteria": [
    "All Q3 invoices processed.",
    "Each posted entry references a source invoice."
  ],
  "mission_expiry": "2026-12-31T23:59:59Z",
  "purpose": "urn:erp.example.com:purposes:quarterly-reconcile",
  "language": "en",
  "context": {
    "max_derivations": "500",
    "aal": {
      "value": "urn:mbo:aal:2",
      "freshness_seconds": 1800
    }
  }
}
~~~

### Validated Mission Intent

The state authority validates the Submitted Intent against its
deployment policy, observes that the deployment policy caps
`max_derivations` for `quarterly-reconcile` purposes at 200, and
narrows the value. The resulting Validated Mission Intent (which
is what `proposal_hash` covers and what every consumer ultimately
references) is:

~~~ json
{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "objects": [
    "https://erp.example.com/api/invoices",
    "https://erp.example.com/api/journal-entries"
  ],
  "constraints": [
    "Read only invoices issued in 2026-Q3.",
    "Post journal entries with absolute amount < $500."
  ],
  "success_criteria": [
    "All Q3 invoices processed.",
    "Each posted entry references a source invoice."
  ],
  "mission_expiry": "2026-12-31T23:59:59Z",
  "purpose": "urn:erp.example.com:purposes:quarterly-reconcile",
  "language": "en",
  "context": {
    "max_derivations": "200",
    "aal": {
      "value": "urn:mbo:aal:2",
      "freshness_seconds": 1800
    }
  }
}
~~~

The state authority records the Validated form on the Mission
Proposal and includes the narrowing decision (which fields it
narrowed and why) in the consent disclosure object presented to
the approving principal.

## Submitted vs Validated forms

The **Submitted Mission Intent** is the JSON object the client
provides. It is untrusted until the state authority validates it.

The **Validated Mission Intent** is the post-validation,
post-narrowing form the state authority records on the Mission
Proposal. The Validated Mission Intent is the form covered by
`proposal_hash`.

## Narrowing rules {#narrowing-rules}

When validating a Submitted Mission Intent into a Validated Mission
Intent, the state authority MAY narrow values according to
deployment policy. Permitted narrowings are:

- `mission_expiry`: MAY be shortened. MUST NOT be extended past
  the Submitted value or past the deployment-policy ceiling.
- `objects`: MAY be reduced (entries removed); MAY have entries
  replaced with stricter URI equivalents (e.g., adding query
  constraints) only if the replacement is a strict subset of the
  original by URI semantics. MUST NOT be enlarged.
- `constraints`: MAY add additional constraints; MUST NOT remove
  client-supplied constraints unless the constraint is invalid
  (in which case the entire Submitted Intent MUST be refused).
- `success_criteria`: MUST be preserved verbatim.
- `goal`: MUST be preserved verbatim.
- `purpose`: MUST be preserved verbatim.
- `language`: MUST be preserved verbatim.
- `context`: registered Common Constraints MAY be narrowed per
  the constraint's narrowing rule (e.g., `max_derivations` MAY be
  reduced). Unknown non-`x_` keys MUST be absent; this is enforced
  at validation, not narrowing.

The state authority MUST include in the consent disclosure object
a record of each narrowing decision (the field, the Submitted
value, the Validated value, and a deployment-policy justification
identifier).

If the Submitted Mission Intent cannot be narrowed to a deployment-
acceptable form, the state authority MUST refuse the Submitted Intent
rather than silently substitute.

## `purpose` URI

The optional `purpose` field carries a URI naming the task class.
Two registration models are permitted:

- **Client-registered**: a URI registered with the state authority
  by the requesting client at client registration time. The state
  authority MUST refuse a `purpose` URI not registered for the
  presenting client.
- **Deployment-registered**: a URI in a state-authority-published
  purpose vocabulary (e.g., `urn:mbo:purposes:*` or a deployment-
  scoped IRI). The state authority publishes the registered
  vocabulary in its metadata document under
  `mission_purposes_supported` (see
  {{state-authority-metadata-document}}).

Implementations SHOULD use deployment-registered purposes for
cross-organization audit consistency.

## `context` and Common Constraints

Members of `context` are either registered Common Constraint keys
(see {{common-constraints-framework}}) or extension keys prefixed
`x_`. Registered keys have semantics defined in the Mission Common
Constraints registry; their value structures (single value,
object, array) are constraint-specific and defined per registry
entry. Extension keys follow {{schema-evolution}}.

## Schema evolution {#schema-evolution}

The Mission Intent schema permits extension fields prefixed with
`x_` at the top level and inside `context`. Non-prefixed unknown
properties are reserved for future revisions of this specification
and MUST be rejected at validation time.

Extension fields MUST be included in semantic normalization and
therefore in `proposal_hash`. Implementations that do not recognize
an `x_*` extension MUST NOT grant or enlarge authority based on it.
If an `x_*` extension claims authority-relevant semantics and is
not registered for the deployment, the state authority MUST reject
the Mission Intent.

Deployments requiring stricter schemas MAY publish a deployment-
specific stricter schema via `mission_intent_schema_uri` in
state-authority metadata.

# Authority Set

The Authority Set is a substrate-neutral canonical container for the
maximum authority the state authority approved at the approval
event. The Authority Set is composed of **typed entries**.

Each Authority Set entry MUST carry the following fields:

- `type` (string, required): the registered type name.
- `specification_uri` (URI, required) OR `schema_digest` (string,
  required): an immutable reference to the type's specification. If
  both are present, `schema_digest` is authoritative.
- `schema_version` (string, required): the version of the type's
  schema.
- `authority` (object, required): the type-specific payload.
- `narrowing_profile` (URI, required): the narrowing rules applied
  to this entry. Default: `urn:mbo:narrowing:default-v1`.

The Framework defines a **Mission Authority Set Type** registry.
Each registered type provides:

- Specification reference (immutable).
- Schema digest (where applicable).
- Semantic normalization rules.
- Equality rules (when are two entries semantically equal).
- Subset rules (when does one entry's authority narrow another's).
- Intersection rules (the largest authority both entries permit).
- Unknown-field handling at narrowing time.

Profile specifications MAY register additional Authority Set entry
types. The OAuth Profile registers `mission_resource_access` as one
type with `resource`, `actions`, and `constraints` fields.

## Schema digest format

The `schema_digest` value MUST be `"sha-256:" || base64url(SHA-256(
JCS-canonical schema bytes))`. This format parallels the integrity-
anchor hash format. Future digest algorithms register prefixes like
`sha-384:`; consumers MUST reject digests using unregistered
prefixes.

# Integrity Anchors

A Mission record carries three integrity anchors that commit the
state authority to canonical objects: `proposal_hash`,
`authority_hash`, `consent_disclosure_hash`.

Integrity anchors are computed in three steps:

1. **Semantic normalization** under the registered normalization
   profile for the object's type.
2. **Domain-separated, authorization-domain-bound envelope** wraps
   the normalized value.
3. **JCS canonicalization** {{RFC8785}}, **SHA-256** {{RFC6234}},
   **base64url encoding**.

## Semantic normalization

JCS canonicalizes JSON syntax but does not make semantically
equivalent values identical. Before JCS, each committed object MUST
be normalized under its registered normalization profile. The
profile defines:

- Array ordering and duplicate handling.
- Unicode normalization policy (NFC by default).
- URI normalization or exact-comparison rules per field.
- Absent-member versus empty-member semantics.
- Rejection of duplicate JSON object member names before parsing
  into the data model.

Implementations MUST normalize before computing any integrity anchor.

## Domain-separated, authorization-domain-bound envelope

After normalization, the hash input is wrapped in an envelope:

~~~
SHA-256(JCS({
  "type":                "mission-intent" | "mission-authority-set"
                         | "mission-consent-disclosure",
  "schema_version":      <integer>,
  "authorization_domain": <tenant or authorization-domain identifier>,
  "state_authority":     <mission.origin URL>,
  "value":               <normalized content>
}))
~~~

The `type` field provides domain separation between object types.
The `authorization_domain` and `state_authority` fields bind the
hash to the authorization domain and to the issuing state authority,
preventing cross-tenant or cross-authority transplantation. Two
identical Validated Mission Intents in different tenants produce
different `proposal_hash` values.

The resulting hash is base64url-encoded without padding.

## Three integrity anchors

- `proposal_hash`: over the Validated Mission Intent (envelope
  `type=mission-intent`). Committed at the approval event; stable for
  the Mission's lifetime.
- `authority_hash`: over the Authority Set (envelope
  `type=mission-authority-set`). Committed at the approval event.
- `consent_disclosure_hash`: over the consent disclosure object
  presented to the approving principal (envelope
  `type=mission-consent-disclosure`). Committed at the approval
  event.

The integrity anchors collectively commit the state authority's
recorded approval. They do not prove faithful rendering to the
approving principal; that property requires trustworthy consent UX
above the protocol layer.

# Identifier Model

A Mission has a **canonical Mission ID** (`mission.id`) held by the
state authority. Consumers MAY interact with a Mission through the
canonical ID or through an audience-sector-specific
**Pairwise Mission Reference** (`mission.ref`).

## Canonical Mission ID

The canonical `mission.id` is a stable opaque identifier minted by
the state authority. It is URL-safe ASCII, maximum 256 octets. It
MUST be unique within the state authority's namespace and MUST NOT
be reused after Mission record garbage collection.

The `mission.origin` value is the state authority's issuer URL. It
resolves via the well-known URI `/.well-known/mission-authority` per
{{RFC8615}}.

## Pairwise Mission Reference

A Pairwise Mission Reference (`mission.ref`) is an opaque URL-safe
string containing at least 128 bits of entropy. It MUST contain no
audience label, tenant name, canonical-ID derivative, or other
correlatable input. The state authority binds the opaque reference
to an advertised **pairwise sector** in its metadata.

The pairwise sector type is one of:

- Resource Server
- Resource AS
- Tenant
- Trust domain

The state authority advertises its sector choice in
`mission_pairwise_sector` in its metadata document.

Pairwise references are stable for the Mission's lifetime within a
sector. Reference rotation creates an alias period sufficient for
outstanding credentials to drain, then retires the old reference.
Retired references MUST NOT be reassigned.

The state authority is the only party that can resolve a Pairwise
Mission Reference to the canonical `mission.id`. Other parties MUST
NOT be able to derive the canonical ID from a pairwise reference.

## `mission.origin` metadata document

The metadata document at `{mission.origin}/.well-known/mission-authority`
is a JSON object with fields:

- `issuer` (URL, required): MUST match `mission.origin`.
- `jwks_uri` (URL, required): state authority's public keys for
  response signing.
- `mission_status_endpoint` (URL, required): by-mission-reference
  Mission Status operation.
- `mission_lifecycle_endpoint` (URL, required): revoke, suspend,
  resume, complete operations.
- `mission_intent_schema_uri` (URL, required): JSON Schema for
  Mission Intent.
- `authority_set_types_supported` (array of strings, required): the
  Authority Set entry types this state authority issues.
- `mission_pairwise_supported` (boolean, required): whether the
  state authority emits pairwise references.
- `mission_pairwise_sector` (string, conditional): the sector type,
  required if `mission_pairwise_supported` is `true`.
- `mission_framework_versions_supported` (array, required): spec
  revisions of this Framework that the state authority supports.

Profile specifications MAY extend this metadata document.

# Principal Model

A Mission record carries the following principal fields:

- `subject` (string, required): the principal on whose behalf the
  task is approved. Format is substrate-specific (e.g., subject
  identifier per RFC 7519 in OAuth profiles, AAuth `approver` in
  AAuth profiles).
- `approving_principal` (string, required): the principal who
  approved the Mission. MAY equal `subject`. For delegated
  approval (administrator approval, headless approval anchors)
  `approving_principal` differs from `subject`.
- `requesting_client` (string, required): the OAuth client
  identifier or AAuth agent identifier that submitted the Mission
  Proposal.
- `tenant` (string, required): the tenant or authorization-domain
  identifier the Mission lives in.
- `state_authority` (URL, required): the issuer URL of the state
  authority. Equal to `mission.origin`.
- `delegation_policy` (string, required): a URI or named profile
  identifying the stable Mission-level bounds governing which actors
  may derive or exercise authority.

The principal model is recorded at the approval event and is
immutable thereafter (the Mission's `subject`, `approving_principal`,
and other principal fields MUST NOT change after activation).

Dynamic actor context (the current delegation chain at a derived
artifact) is carried on projections (derived credentials) and
runtime requests, not stored on the Mission record. The OAuth
Profile and AAuth Profile bind dynamic actor context to derived
credentials via the actor profile (e.g.,
`draft-mcguinness-oauth-actor-profile`).

# Mission Status Interface

The Mission Status interface is the authenticated state-authority view
returning Mission state and integrity-anchored evidence. It is
**distinct from token introspection** (which is by-token); Mission
Status is by-mission-reference.

## Operation

The Mission Status operation takes a Mission reference (canonical
`mission.id` or pairwise `mission.ref`), the requesting consumer's
authentication, the consumer's audience identifier, and a nonce. It
returns:

- `state` (one of `active`, `suspended`, `revoked`, `completed`,
  `expired`).
- The three integrity anchors.
- Audience-filtered Authority Set projection (the entries relevant
  to the requesting audience).
- `policy_version` of the derivation policy applied at approval.
- `issued_at` (RFC 3339 timestamp).
- `expires_at` (RFC 3339 timestamp).
- Freshness indicator (when the state was current).
- The nonce echoed from the request.

The wire format is profile-specific. Profile specifications bind
this abstract operation to a concrete request and response
representation, including the protection mechanism (e.g., RFC 9701
signed responses for OAuth introspection, JWS for the dedicated
operation).

## Required properties

A Mission Status response MUST satisfy:

- **Authentication property**: the response carries an integrity
  signal whose source is the state authority. Consumers verify the
  signal against the state authority's published keys.
- **Freshness property**: the response indicates when the state was
  current via `issued_at` and `expires_at`.
- **Audience property**: the response binds the requesting consumer's
  audience identifier. Replay against a different audience MUST be
  detectable.
- **Integrity property**: the response payload and its integrity
  anchors chain back to the canonical Mission record verifiably.
- **Anti-oracle property**: possession of a Mission reference is not
  authorization. The state authority MUST authenticate the caller and
  authorize the caller for the requested reference and audience.
  Unknown and unauthorized references MUST produce indistinguishable
  responses.
- **Request-binding property**: signed responses MUST bind the caller
  identity, the requested Mission reference, the audience, and the
  caller-provided nonce.
- **Caching property**: every response declares `issued_at` and
  `expires_at`. Consumers MUST fail closed after `expires_at` unless a
  profile explicitly defines a bounded degraded mode.

## Error model

A Mission Status response operates over the following error model.
Profile specifications map these to substrate-appropriate transport
codes.

| Symbol | Meaning |
|---|---|
| `ok` | Mission found and visible. Response carries state. |
| `unauthorized` | Request not authenticated. |
| `not_found` | Mission reference does not exist OR is not visible to this consumer. These cases are intentionally indistinguishable. |
| `terminated` | Mission is in a terminal state. Response includes state. |
| `suspended` | Mission is suspended. Response includes state. |
| `rate_limited` | Consumer is rate-limited. |
| `unavailable` | State authority temporarily can't serve status. |

Consumers MUST NOT distinguish an unknown Mission from a known but
unauthorized Mission. A terminal Mission is "found" only for an
authorized caller.

# Common Constraints Framework

The Mission Intent's `context` field carries machine-actionable
bounds. The Framework defines a **Mission Common Constraints**
registry that standardizes constraint key names and semantics so
cross-vendor deployments express common bounds consistently.

Each registered constraint provides:

- `name`: the key in `mission_intent.context`.
- `type`: the JSON type of the value (string, integer, array, etc.).
- `specification_uri`: immutable specification reference.
- `schema_digest` (optional): for richer constraint shapes.
- `schema_version`.
- Normalization rules.
- Equality and subset rules.
- Narrowing rules at derivation time.
- Runtime enforcement contract: where and how the constraint is
  enforced.

## Initial entries

This document defines two initial entries:

### `max_derivations`

The maximum number of credential derivation events permitted under
this Mission across its lifetime. Counts new access tokens, refresh
token rotations, Token Exchange grants, ID-JAGs, AAuth resource
tokens, and AAuth auth tokens.

- Value type: decimal string (e.g., `"100"`). String form chosen
  for IEEE 754 precision safety under JCS.
- Authoritative counter: the state authority. Each derivation event
  increments the counter atomically. Counter MUST NOT exceed the
  declared value.
- Narrowing: derived constraints MAY specify smaller values.
- Reset: the counter resets only when Mission Expansion creates a
  successor Mission; the predecessor's counter is final.
- Runtime relationship: this constraint governs issuance, not
  per-action invocation. Per-action runtime budgets are
  `max_invocations`, defined in the Mission-Bound Runtime
  Enforcement Profile.

### `aal`

The required Authentication Assurance Level for the approving
principal's authentication at the approval event, and for any
subsequent step-up authentication.

- Value type: string. Values follow {{RFC9470}}'s `acr` semantics or
  deployment-registered AAL identifiers.
- Freshness window (required): an integer number of seconds
  declaring the maximum age of an authentication event that
  satisfies the constraint.
- Composes with: {{RFC9470}} step-up authentication challenges. A
  denied request that would be permitted by satisfying the `aal`
  constraint via fresh authentication MAY be returned as a step-up
  challenge by the credential issuer.

## Future-work entries

The following constraint names are sketched in the architecture but
have unresolved semantics; they are NOT included in the initial
registry:

- `max_value`: requires currency, aggregation period, and
  authoritative counter to be specified.
- `max_duration`: requires units and start event to be specified.
- `geo`: requires subject vs actor vs resource vs execution-location
  semantics to be picked.
- `data_classification`: requires a registered classification
  vocabulary.

These will register as the design stabilizes and implementer
interest emerges.

# Capability-Advertisement Metadata

The Framework creates a **Mission Capability-Advertisement Metadata**
registry. State authorities advertise their capabilities through the
following metadata fields:

- `mission_authorization_domain_tiers_supported` (array): subset of
  registered Authorization Domain Tier identifiers.
- `mission_ladder_levels_supported` (array of integers): subset of
  Capability Ladder levels supported.
- `mission_profiles_supported` (array of strings): substrate
  profiles supported (e.g., `"oauth"`, `"aauth"`, `"mas"`,
  `"runtime_enforcement"`).
- `mission_optional_modules_supported` (array): registered optional
  modules supported.
- `mission_framework_versions_supported` (array): spec revisions of
  this Framework that the state authority supports.

The Capability Model specification (Mission-Bound Authorization
Capability Model) defines the Capability Ladder levels, Resource
Server Tiers, and Authorization Domain Tiers; this document creates
the metadata registry that names them.

# Reference Test Vectors

This specification includes reference test vectors as a first-class
deliverable. Test vectors are published in the `vectors/` directory
of the specification repository, tagged with the spec revision
(e.g., `vectors/draft-mcguinness-mission-framework-00/`).

An implementation that does not reproduce the published test vectors
byte-for-byte is non-conformant to that vector class.

The required vector classes are:

1. **Semantic-normalization and JCS vectors**: 20 or more input
   JSON objects with expected normalized data model and expected
   JCS bytes. Covers array ordering, duplicate elements, duplicate
   object member rejection, absent versus empty members, URI
   comparison, number formatting, key ordering, escapes, Unicode
   policy, nested objects, arrays, and nulls.
2. **Domain-separated and authorization-domain-bound hash vectors**:
   input value, normalized wrapped input, and expected SHA-256
   hash. Includes negative cross-tenant and cross-authority
   transplantation cases.
3. **State-transition vectors**: full state-machine traversals for
   Mission Proposal and Mission lifecycles, including invalid
   transitions that MUST be refused.
4. **Authority Set narrowing vectors** per registered type. For
   `mission_resource_access`: approved entry + derived entry →
   expected accept/refuse classification.
5. **Mission Status vectors**: authenticated request → expected
   response shape for success, stale state, replayed nonce, wrong
   audience, unknown reference, and unauthorized reference.
   Unknown and unauthorized cases MUST be observationally
   equivalent.
6. **`mission` claim vectors**: Mission record → expected claim
   shape including canonical and pairwise variants. (Defined in
   the OAuth Profile; vector class declared here.)

# Security Considerations

## State authority compromise

A compromised state authority can fabricate Mission records,
backdate evidence, and issue Mission Status responses without
constraint. The Framework assumes the state authority is trusted;
compromise of the state authority is outside the protection model
of this specification. Deployments mitigate state-authority
compromise through key hardware modules, audit logging,
independent attestation of state-authority operations, and
cross-organization audit anchoring.

## Integrity anchor non-guarantees

The integrity anchors prove the state authority committed to
specific canonical objects at the approval event. They do not
prove:

- **Faithful rendering**: the approving principal saw the consent
  disclosure object as the state authority recorded it. A
  compromised renderer can present different content while the
  state authority's record remains untouched.
- **Human comprehension**: the approving principal understood the
  rendered content. Consent UX assurance lives above the protocol
  layer.
- **State authority honesty in real time**: an honest auditor
  examining records after the fact cannot distinguish honest
  state-authority operation from in-the-moment fabrication that
  records itself consistently.
- **Approving-principal authenticity**: the approving principal
  was authentically the named person, beyond the AAL evidence
  recorded.

Deployments needing stronger guarantees compose with trustworthy
consent UX, principal authentication assurance, MAS-rendered
consent under cross-substrate governance, and transparency-log
anchoring of integrity hashes.

## JCS implementation correctness

Implementations that produce byte-divergent canonical output
produce divergent hashes and break content-addressability.

Mitigation: the spec's reference test vectors. An implementation
that does not reproduce the test vectors byte-for-byte is
non-conformant. Where possible, deployments SHOULD use known-good
JCS libraries rather than rolling their own.

## Number precision under JCS

IEEE 754 double precision applies to JSON numbers under JCS.
Constraint values where precision matters MUST use string
representation (e.g., `"max_derivations": "100"`), not number
representation.

## Pairwise identifier privacy and correlation

The pairwise reference framework prevents direct correlation of
Mission identifiers across audiences in the same sector. It does
not prevent indirect correlation through audience-side state
(e.g., user identifiers, timing, request patterns). Deployments
SHOULD assess the correlation surface of their chosen sector.

## Hash equality leakage and cross-tenant transplantation

Without authorization-domain binding in the hash envelope, two
identical Validated Mission Intents in different tenants would
produce identical `proposal_hash` values, leaking equality across
tenants and creating a transplantation surface.

This specification mitigates by binding `authorization_domain` and
`state_authority` into the hash envelope. Implementations MUST
include these fields per Section 6.2; omitting them produces
non-conformant hashes.

## Mission Status enumeration and authorization-oracle resistance

Mission Status responses MUST treat unknown references and
unauthorized references as observationally equivalent. An
attacker that can distinguish "unknown" from "unauthorized" can
enumerate the state authority's Mission space.

This specification mitigates via the anti-oracle property
(Section 8.2). Profile specifications MUST preserve this property
in transport.

## Trust-boundary violations

Profile specifications populate the trust boundary roles (Shaper,
state authority, credential issuer, PDP, evidence emitter).
Implementations MUST NOT permit a Shaper to act as an authorization
component. Output of the Shaper MUST be treated as untrusted by the
state authority.

## Approving principal AAL

This specification requires the AAL to be recorded in binding
evidence. It does not mandate an AAL floor for approval; deployment
policy declares the minimum AAL per Mission class. Deployments
SHOULD set appropriate AAL floors and document them.

# IANA Considerations

This document creates the following IANA registries:

## Mission Common Constraints Registry

A new registry tracking constraint key names and their semantics.

- **Registration Policy**: Specification Required.
- **Required fields per entry**: `name`, `type`, `specification_uri`,
  optional `schema_digest`, `schema_version`, normalization rules,
  equality and subset rules, narrowing rules, runtime enforcement
  contract, change controller.
- **Initial entries**:
  - `max_derivations` (this document).
  - `aal` (this document).

## Mission Authority Set Type Registry

A new registry tracking Authority Set entry types.

- **Registration Policy**: Specification Required.
- **Required fields per entry**: `type`, `specification_uri` or
  `schema_digest`, normalization rules, equality, subset,
  intersection, unknown-field handling, change controller.
- **Initial entries**: `mission_resource_access` (registered by the
  OAuth Profile, not by this document; reserved here).

## Mission Capability-Advertisement Metadata Registry

A new registry tracking capability-advertisement metadata names.

- **Registration Policy**: Specification Required.
- **Required fields per entry**: `name`, value semantics,
  defining specification, change controller.
- **Initial entries**: as listed in Section 11.

## Mission Lifecycle State Enumerations

This document defines closed enumerations for Mission Proposal
states (`pending_approval`, `rejected`, `withdrawn`,
`expired_as_pending`) and Mission states (`active`, `suspended`,
`revoked`, `completed`, `expired`). If extensibility is later
required, IANA registries can be created via subsequent revisions.

## Mission Status Response Media Types

Where a profile specification needs a new media type for Mission
Status responses (e.g., `application/mission-status-response+json`
or `application/mission-status-response+jwt`), the profile registers
the media type per RFC 6838. This document does NOT register media
types; profiles do.

## What this document does NOT register

- RAR `type` values: RFC 9396 {{RFC9396}} does not establish an IANA
  registry for every RAR `type`. The `mission_resource_access` RAR
  type is registered by the OAuth Profile in the Mission Authority
  Set Type Registry created by this document, not in a (nonexistent)
  RFC 9396 type registry.
- Generic JWT `typ` values: there is no IANA "JWT Media Type
  Registry" for arbitrary `typ` values. Where a profile needs a
  specific JWT `typ`, it registers a media type per RFC 6838.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the
Mission-Bound Authorization architecture for feedback that shaped
this specification.

--- back
