---
title: "Mission Authority Server"
abbrev: "Mission Authority Server"
category: std

docname: draft-mcguinness-mission-authority-server-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - governance
 - approval
 - enforcement
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-oauth-client-instance-id:
  RFC3339:
  RFC6838:
  RFC7519:
  RFC7638:
  RFC7662:
  RFC8259:
  RFC8615:
  RFC9110:
  RFC9421:
  RFC9651:
  MCP-META:
    title: "Model Context Protocol: Base Protocol"
    target: https://modelcontextprotocol.io/specification/2026-07-28/basic/index
    author:
      - org: Model Context Protocol Project
    date: 2026
  RFC8414:
  RFC9068:
  RFC9396:
  RFC9325:
  RFC9728:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-submission-evidence:
    title: "Mission Intent Submission Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-submission-evidence.html
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
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
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
  I-D.draft-mcguinness-mission-approval-governance:
    title: "Mission Approval Governance"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8725:
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC6749:
  RFC8126:
  RFC8693:
  RFC9449:
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
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
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-derivation-limits:
    title: "Mission Derivation Limits for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html
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
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
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

--- abstract

This specification defines the Mission Authority Server (MAS), a
standalone service that implements the Mission Issuer role of
Mission-Bound Authorization for OAuth 2.0 (the OAuth binding) without
being an OAuth Authorization Server. A MAS validates Mission Intents,
runs approval events, records Missions, operates the Mission
lifecycle, and serves Mission state. It derives no tokens. Access
tokens remain ordinary OAuth tokens; a Policy Decision Point joins
each presented credential to its Mission at the point of use and
enforces through the Mission-Bound Runtime Enforcement profile. This
standalone binding leaves Authorization Servers unchanged and
provides no Mission-bound credentials or issuance gating; the OAuth
binding provides both, and the issuance-grant companion restores them
at Authorization Servers that redeem its grants. This document
defines a conformance floor and an Enterprise Mission Authority
Profile.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "OAuth binding") binds
issued authority to a durable, human-approved Mission. In the OAuth
binding, the OAuth Authorization Server (AS) {{RFC6749}} plays the
Mission Issuer role: the AS validates the Mission Intent, runs the
approval event, records the Mission, derives Mission-bound tokens,
and gates issuance on Mission state. Deploying the OAuth binding
requires changing the AS.

Many deployments cannot make that change, because the AS is a shared
or third-party service. This document defines the **Mission
Authority Server (MAS)** for those deployments: a standalone service
that implements the Mission Issuer role of the OAuth binding without
being an OAuth Authorization Server. A MAS validates Mission Intents,
runs approval events, records Missions, operates the Mission
lifecycle, and serves Mission state. It derives no tokens, and it
requires no change to the deployment's existing AS.

Because tokens remain ordinary OAuth tokens with no `mission` claim,
the credential-to-Mission association is established at the point of
use instead of traveling in the credential. The Policy Enforcement
Point (PEP) presents the Mission reference explicitly, and the Policy
Decision Point (PDP) joins the credential to the Mission before
evaluating the action ({{mission-join}}). Per-action enforcement then
proceeds under the runtime profile
{{I-D.draft-mcguinness-mission-runtime}}, which applies unchanged.

The MAS mode does not provide Mission-bound credentials or issuance
gating; a deployment that changes its AS obtains both
({{limitations}}).

The MAS mode is a peer binding, not a staging area. A deployment can
keep governance decoupled from token issuance as its long-term
architecture. An enterprise that governs agent tasks across many
Authorization Servers, SaaS tenants, APIs, and tool gateways can use
a central MAS as the one place that holds the approved task, its
lifecycle, and its authority, independent of which system issued a
given token. A central MAS can remain in that role after some
Authorization Servers become Mission-aware.

A deployment that later wants Mission-bound tokens at a particular AS
can move issuance into that AS. The record, anchors, and lifecycle
carry over unchanged, because a MAS operates the OAuth binding's own
definitions of them. The MAS continues to govern the rest of the
estate ({{limitations}}).

## Protocol Overview {#overview}

This section is non-normative. The following figure shows the flow
for one Mission: submission, approval, polling, and an action decided
under the Mission Join.

~~~
 Client               MAS                Approver     PEP/PDP
   |                    |                  |            |
   | 1 submit Intent    |                  |            |
   |------------------->|                  |            |
   | 2 202 pending      |                  |            |
   |<-------------------|                  |            |
   |                    | 3 disclose       |            |
   |                    |----------------->|            |
   |                    | 4 approve        |            |
   |                    |<-----------------|            |
   |                    | Mission active   |            |
   | 5 poll             |                  |            |
   |------------------->|                  |            |
   | 6 approved,        |                  |            |
   |   mission_id       |                  |            |
   |<-------------------|                  |            |
   | 7 action, token,   |                  |            |
   |   Mission ref      |                  |            |
   |--------------------------------------------------->|
   |                    | 8 signed status: |            |
   |                    |   active         |            |
   |                    |<------------------------------|
   |                    |------------------------------>|
   |                    |                  | 9 join;    |
   |                    |                  |   evaluate |
   | 10 permit          |                  |            |
   |<---------------------------------------------------|
~~~
{: title="MAS-mode flow"}

- Steps 1 and 2: the client submits a Mission Intent to the mission
  submission endpoint and receives a pending-submission reference
  ({{intent-submission}}).
- Steps 3 and 4: the MAS routes the submission to its approval
  surface; on approval it records the Mission in the `active` state
  ({{mission-approval}}).
- Steps 5 and 6: the client polls submission status and receives the
  `mission_id` and the consented authority ({{mission-reference}}).
- Step 7: the client acts with an ordinary access token from the
  deployment's unchanged authorization server, and the PEP supplies
  the Mission reference from its Mission binding, deployment
  configuration, or a propagated reference ({{join-rules}},
  {{reference-propagation}}).
- Steps 8 and 9: the PDP resolves the Mission through the MAS's
  signed Mission Status ({{lifecycle-and-state}}), joins the presented
  credential to the Mission, and evaluates the action under the
  runtime profile ({{mission-join}}).
- Step 10: the PEP enforces the decision. A revocation at the MAS
  stops the next such action at step 8.

A Join Assertion moves the join's verification to the MAS
({{join-assertion}}). Mission Expansion and Child Creation use the
submission endpoint ({{native-surfaces}}). {{e2e-example}} shows the
same flow with concrete messages.

## Applicability

This profile targets deployments that need governed, approvable,
revocable agent tasks but cannot extend their Authorization Server,
and that can route consequential actions through the runtime profile's
enforcement. A deployment MAY also prefer a standalone Mission Issuer
even where it controls its AS, to keep governance decoupled from token
issuance or to govern with one Mission Issuer across many
Authorization Servers, accepting the enforcement posture of
{{limitations}}. A deployment that wants Mission-bound tokens and
issuance gating implements the OAuth binding. A deployment that
cannot deploy runtime enforcement over its consequential action paths
obtains records but no enforcement from this profile and SHOULD NOT
claim it ({{limitations}}).

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

This document uses Mission, Mission Intent, Mission Issuer, Authority
Set, Approver, Subject, `mission_id`, the integrity anchors, and the
audit horizon as defined by {{I-D.draft-mcguinness-oauth-mission}};
the Mission Status operation and Mission Lifecycle endpoint as defined
by {{I-D.draft-mcguinness-oauth-mission-status}}; and PEP, PDP,
consequential action, Mission state source, and enforcement scope as
defined by {{I-D.draft-mcguinness-mission-runtime}}. It also uses
the following terms:

Mission Authority Server (MAS):
: A service that implements the Mission Issuer role of the OAuth
  binding without being an OAuth Authorization Server. It is the
  `issuer` of the Missions it records, and it derives no tokens.

Mission-joining PDP:
: A PDP that resolves Missions at a MAS and verifies the join between
  a presented credential and the referenced Mission before evaluating
  an action ({{mission-join}}).

Standalone binding:
: The deployment mode this document defines: the Mission Issuer role
  implemented by a MAS, with the deployment's tokens unchanged. "MAS
  mode" and "AS-optional" are informal names for it.

Mapping join:
: The baseline Mission Join: the PDP compares the presented
  credential's authenticated subject and client with the Mission's
  recorded parties under the deployment's documented mappings
  ({{join-rules}}).

Mapping contract:
: The documented subject, client, delegate, and instance mappings a
  deployment's joins apply ({{join-rules}}); an Enterprise MAS
  publishes it ({{mapping-contract}}).

Join Assertion:
: A MAS-signed JWT stating that one access token, introspected or
  locally validated, joins a Mission ({{join-assertion}}).

Mission-selection assertion:
: The Mission reference a requester attaches to a request. It selects
  the Mission a join is evaluated against and grants nothing
  ({{reference-propagation}}).

High-consequence action classes:
: The irreversible-action, external-commitment, and
  privileged-administration classes of
  {{I-D.draft-mcguinness-mission-runtime}}.

# Mission Submission {#mission-submission}

A client proposes a Mission by submitting a Mission Intent to the
MAS's mission submission endpoint, published as
`mission_submission_endpoint` ({{discovery}}). The endpoint MUST be
served over TLS 1.2 or later (TLS 1.3 RECOMMENDED), following the
recommendations of {{RFC9325}}. The endpoint MUST authenticate the
client using the authentication mechanisms of the Mission Status
endpoint ({{I-D.draft-mcguinness-oauth-mission-status}}): mTLS client
authentication, a DPoP- or mTLS-bound access token, or private-key JWT,
with a token's audience and a client assertion's `aud` naming this
endpoint. The MAS advertises the accepted methods in the
`mission_submission_endpoint_auth_methods_supported` metadata member
({{discovery}}).

Client registration with a MAS is deployment-defined. The MAS records
the client identifier it authenticates as the Mission's `client_id`.

The endpoint serves two operations, dispatched by request media type:

- **Intent submission**: an HTTPS POST whose `application/json` body
  is the Mission Intent Submission envelope ({{intent-submission}}).
- **Submission status**: an HTTPS POST with an
  `application/x-www-form-urlencoded` body containing a `submission`
  parameter ({{submission-status}}).

## Intent Submission {#intent-submission}

The request body is a Mission Intent Submission envelope as the
OAuth binding defines it: `intent` plus OPTIONAL `evidence`. The
OAuth binding's validation and Intent Submission Evidence rules
({{I-D.draft-mcguinness-oauth-mission}}) and those of
{{I-D.draft-mcguinness-oauth-mission-submission-evidence}} apply
unchanged. The submission is untrusted client input and never
authority. The MAS MUST bound the submission's total size, array
lengths, evidence entry count, and evidence verification cost
({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}, Section
"Bounded Verification"). The envelope and the Intent are both closed
at the top level.

The OAuth binding's error outcomes map to this endpoint's error codes
({{submission-errors}}):

- If the body cannot be parsed as a JSON {{RFC8259}} object, is
  structurally invalid, exceeds the deployment's size bounds, or
  contains a top-level member the OAuth binding does not define, the
  MAS MUST reject it with the `invalid_mission_intent` error code (the
  MAS equivalent of the OAuth binding's
  `invalid_request` rejections, including
  reject-unknown-top-level-member).
- If the Intent is well formed but the MAS cannot derive a valid
  Authority Set from it under policy, the MAS MUST reject it with the
  `invalid_authority` error code, so a client can distinguish a syntax
  error from an authority-derivation failure. This code is the MAS's
  single equivalent of the OAuth binding's two derivation-failure
  outcomes ({{I-D.draft-mcguinness-oauth-mission}}):
  `invalid_authorization_details` for a submitted proposal and
  `access_denied` for configured-mapping mode.
- If an Intent Submission Evidence entry is of an unsupported type or
  fails its type's verification, or a policy-required evidence type is
  absent from the submission
  ({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}, Section
  "Required Evidence Is Resolved Before Derivation"), the MAS MUST
  reject the submission with the `invalid_mission_intent_evidence`
  error code. This is the code the OAuth binding registers for the
  same condition, carried here in the MAS error body. Presented
  evidence is never silently ignored.

The request body MAY additionally carry an `authorization_details`
member: the client's authority proposal, an array of
`authorization_details` objects {{RFC9396}}. This member is this
document's proposal carriage, replacing the OAuth binding's PAR-only
carriage rule. The OAuth binding's validation, derivation, recording,
and hashing semantics apply to it unchanged
({{I-D.draft-mcguinness-oauth-mission}}). It is a proposal, never
authority, and a submission member, not a Submission-envelope member
({{native-carriage}}): the MAS MUST remove it before applying the
envelope validation above.

The OAuth binding's intake refusals for a proposed entry map to
`invalid_authority` here. A Mission created from a submission
carrying a proposal records `proposed_authority` and `proposal_hash`
as the OAuth binding's Mission record defines them.

A MAS has no derivation event: no token is issued under the Mission,
so a `requested_derivation_limit` member
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}) binds
nothing here. A MAS implementing the issuance-grant companion
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) has a
derivation event per grant minted and applies that companion's
counting rule.

Where a MAS has no derivation event, it SHOULD refuse an Intent that
carries a `requested_derivation_limit` member, or record the member
and ensure the approval rendering marks it non-binding, per the OAuth
binding's rule that consent is not given to a limit that binds
nowhere. The same treatment applies to any future Mission Intent
member scoped to an issuance event.

On acceptance, the MAS derives the Authority Set from the Intent, and
from the authority proposal where one was submitted, under the OAuth
binding's derivation rules ({{I-D.draft-mcguinness-oauth-mission}})
and returns HTTP 202 with a pending-submission reference:

`submission_id`:
: REQUIRED. A string. An opaque URL-safe ASCII string of
  `[A-Za-z0-9_-]` characters with at least 128 bits of entropy,
  carrying no semantic content. It MUST NOT be reused. It is a
  reference, never a capability.

`status`:
: REQUIRED. A string. `pending` on acceptance.

`expires_at`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}} date-time after which an
  undecided submission lapses to `expired`.

The following example shows a submission and its response:

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $500.",
    "target_resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
~~~

~~~ http-message
HTTP/1.1 202 Accepted
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "pending",
  "expires_at": "2026-10-16T14:32:11Z"
}
~~~

## Submission Status {#submission-status}

The client polls for the outcome with a form-urlencoded POST
carrying:

`submission`:
: REQUIRED. A string. The `submission_id`.

A submission is in one of four states:

| `status` | Meaning |
|---|---|
| `pending` | Awaiting an approval decision. |
| `approved` | Approved; a Mission exists ({{mission-reference}}). |
| `denied` | Declined by the Approver or refused by policy. Terminal. |
| `expired` | `expires_at` passed undecided. Terminal. |

Only `approved` delivers a Mission. A consumer MUST treat every other
`status` value, recognized or not, as not approved, mirroring the
OAuth binding's only-`active` rule.

A resolved submission MUST remain resolvable for a deployment-defined
window. The reference is never reused.

The MAS MUST return submission status only to the authenticated client
that submitted the Intent. For any other caller, and for an unknown
`submission_id`, the MAS MUST return the `not_found` error with an
identical status code, body, and headers, preserving the anti-oracle
property of {{I-D.draft-mcguinness-oauth-mission-status}}.

## Mission Reference Delivery {#mission-reference}

The client learns its `mission_id` from the submission-status response
after approval. When `status` is `approved`, the response additionally
carries:

`mission_id`:
: REQUIRED. A string. The Mission's identifier.

`mission_expires_at`:
: REQUIRED. A string. The Mission's effective `expires_at`. It is the
  OAuth binding's common Mission-creating response member
  ({{I-D.draft-mcguinness-oauth-mission}}): this response is the
  success response that first delivers the Mission's identifier, and
  no OAuth credential accompanies it here.

`authorization_details`:
: REQUIRED. An array. The consented Authority Set, from which the
  client learns its granted authority. This response is the MAS
  counterpart of the OAuth binding's token-response
  `authorization_details` echo.

The following example shows an approved status response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "approved",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ]
}
~~~

A `mission_id` remains a reference, never a credential
({{I-D.draft-mcguinness-oauth-mission}}). Presenting it authorizes
nothing, and no MAS surface derives authority from possession of it.

## Error Responses {#submission-errors}

On a hard failure, the MAS returns the matching HTTP status with a
JSON object body:

`error`:
: REQUIRED. A string. A code from the table below.

`error_description`:
: OPTIONAL. A string. Human-readable detail.

`error_reason`:
: OPTIONAL. A string. A machine-readable refinement of `error`: for
  `invalid_mission_intent`, the name of the offending top-level
  member; for `invalid_authority`, the `target_resources` entry no
  authority could be derived for. It reflects the client's own input
  and MUST NOT disclose policy internals.

A consumer MUST ignore members it does not recognize.

| `error` | HTTP | Returned by | Description |
|---|---|---|---|
| `invalid_mission_intent` | 400 | submission | Unparseable, structurally invalid, oversized, or containing an undefined top-level member. |
| `invalid_authority` | 400 | submission | Well-formed Intent, but no valid Authority Set is derivable under policy. |
| `invalid_mission_intent_evidence` | 400 | submission | An evidence entry of unsupported type or failing its type's verification, or a policy-required evidence type absent from the submission. |
| `unauthorized` | 401 | submission, join assertion | Request not authenticated. |
| `join_failed` | 403 | join assertion | The acting token does not join the referenced Mission ({{join-assertion-request}}). |
| `not_found` | 404 | submission, join assertion | A referenced submission or Mission does not exist OR is not visible to the caller. |
| `conflict` | 409 | submission (expansion, child creation) | A resolved predecessor or parent whose state or serialization refuses the operation ({{native-carriage}}). |
| `rate_limited` | 429 | submission, join assertion | Caller is rate-limited. |
| `unavailable` | 503 | submission, join assertion | MAS temporarily cannot serve the request. |
{: title="MAS error codes"}

A companion profile's machine-readable codes are carried in the
members {{native-carriage}} names (`mission_expansion_status` and
`mission_denial_reason`), not as additional `error` values.

These responses follow the OAuth-shaped surfaces' shared error idiom
{{I-D.draft-mcguinness-oauth-mission-status}}: a JSON object body with
`error` and `error_description`, served as `application/json` with
`Cache-Control: no-store`; `error_description` is diagnostic and never
authorization input. On this surface, `error_description` and
`error_reason` are OPTIONAL, and `error_reason` is MAS-specific. The
MAS does not carry `nonce`: that member's requiredness on the status
and lifecycle surfaces ({{I-D.draft-mcguinness-oauth-mission-status}})
and on Mission Management does not extend here.

# Mission Approval {#mission-approval}

Approval at a MAS is natively asynchronous. There is no authorization
code ceremony, so no approval blocks a front-channel redirect. The MAS
routes each pending submission to its approval surface (a review
application, queue, or policy engine) and resolves it when the
decision is made.

The approval event executes steps 1 through 4 of the OAuth
binding's approval event unchanged
({{I-D.draft-mcguinness-oauth-mission}}):

1. Authenticate the Approver; this authentication MUST satisfy the
   deployment's published approval-authentication floor
   ({{I-D.draft-mcguinness-oauth-mission}}). The OAuth binding's
   direct flow carries a client-requested Approver authentication
   strength in the `acr_values` and `max_age` authorization request
   parameters. A MAS receives no authorization request, and this
   document defines no MAS-native carriage for that strength, so the
   floor alone governs.
2. Establish the Subject under the OAuth binding's rules: the MAS
   MUST itself establish the Subject's (`iss`, `sub`) and MUST NOT
   take it from unauthenticated client input.
3. Render the derived Authority Set for consent with the OAuth
   binding's rendering rules applied unchanged: client-supplied
   strings inert, direction-override and confusable presentation
   mitigated, derived authority visually distinguished from client
   text.
4. Compute the integrity anchors (`authority_hash`, `intent_hash`,
   and, where an authority proposal was submitted, `proposal_hash`)
   using the OAuth binding's envelope, with the MAS's issuer URL as
   `iss`.

Step 5 becomes: create the Mission record in the `active` state
atomically with the approval decision. The record is the OAuth
binding's Mission Record, member for member. Its `issuer` is the
MAS's issuer URL, and its `approval_event_id` is the approval
idempotency key. There is no authorization code to bind, so the
deferred-approval profile's re-sequencing of this step
({{I-D.draft-mcguinness-oauth-mission-approval}}) is not needed:
approval at a MAS is inherently deferred.

A declined submission resolves to `denied`.

Mission Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) composes
unchanged, with the MAS as the committing issuer for any
consent-disclosure commitment.

# Mission Lifecycle and State {#lifecycle-and-state}

In MAS mode, there are no Mission-bound tokens, so no token
introspection reports Mission state. The Mission Status profile's
surfaces are how a consumer observes or changes Mission state. A MAS
implements them as its state surface, by reference:

- The MAS MUST serve the Mission Status operation of
  {{I-D.draft-mcguinness-oauth-mission-status}}, including its signed
  responses, authentication, anti-oracle property, and caching rules.
- The MAS MUST serve the Mission Lifecycle endpoint of that profile
  with its full operation set (`revoke`, `suspend`, `resume`, and
  `complete`), following that profile's state machine unchanged. A MAS
  owns its state store, so partial support is not permitted.
- The MAS MAY emit Mission Lifecycle Signals
  ({{I-D.draft-mcguinness-oauth-mission-signals}}), which compose
  unchanged, with the MAS as the transmitting Mission Issuer.

The OAuth binding's token-introspection projection does not apply:
there is no token to introspect.

The MAS publishes the corresponding metadata members
(`mission_status_endpoint`,
`mission_status_signing_alg_values_supported`,
`mission_lifecycle_endpoint`, `mission_max_stale_seconds`, and, when
signals are supported, `mission_event_stream_endpoint`) in its
discovery document ({{discovery}}) with the semantics those profiles
define for the members of the same names.

# Mission Join {#mission-join}

In MAS mode the acting access token is an ordinary OAuth token from
the deployment's unchanged AS. It carries no `mission` claim and no
Mission-derived `authorization_details`, so it cannot identify its
Mission. The PEP names the Mission explicitly, and the PDP joins the
credential to it before evaluating the action. When no cryptographic
binding exists, a permit "under this Mission" rests on the join.

This section defines the baseline mapping join. The Mission Join
Assertion ({{join-assertion}}) builds on it. The Enterprise profile
requires Mission-bound credentials for the high-consequence classes
and Join Assertions on the other joined, PDP-gated paths
({{enterprise-profile}}).

## Join Rules {#join-rules}

A Mission-joining PDP and its PEPs MUST observe the following:

1. **The PEP supplies the Mission reference.** For governed work the
   PEP MUST supply the `mission_id` and `issuer` of the Mission the
   work is bound to, taken from its Mission binding (a Mission-aware
   harness records exactly this,
   {{I-D.draft-mcguinness-mission-harness}}) or from deployment
   configuration. In the AuthZEN binding
   ({{I-D.draft-mcguinness-mission-authzen}}) this reference is
   `context.mission`; the PEP additionally populates `state`, and
   `authority_hash` where the MAS's signed Mission Status response
   discloses it, as OPTIONAL enrichment beyond the required `id` and
   `issuer`.
2. **The PDP resolves the Mission at the MAS.** The PDP MUST resolve
   the referenced Mission through the MAS's Mission Status operation.
   The PDP MUST treat the MAS as the Mission state source under the
   runtime profile's state and freshness rules
   ({{I-D.draft-mcguinness-mission-runtime}}): fail closed when state
   cannot be established within the published staleness bound, and use
   an active freshness mechanism for the high-consequence classes.
3. **Subject join.** The PDP MUST verify that the presented
   credential's authenticated subject equals the Mission's
   `subject.sub` under the deployment's account mapping. Where the
   credential's issuer and the Mission's `subject.iss` name the same
   namespace, equality is byte-equality; otherwise the deployment MUST
   document the mapping, and a subject the mapping does not cover
   fails the join.
4. **Client join.** The PDP MUST verify that the presented
   credential's authenticated client identifier equals the Mission's
   `client_id`, or names a delegate that deployment policy explicitly
   authorizes to act under that Mission's client. Delegate
   authorization MUST be explicit, an enumerated policy, never a
   default. Where the AS and MAS client namespaces differ, the
   deployment MUST record the client mapping in its mapping contract
   ({{mapping-contract}}), exactly as for subjects.
5. **Delegate narrowing.** When the joined party is a delegate rather
   than the Mission's `client_id`, the PDP MUST narrow the effective
   Authority Set to the delegable subset under the OAuth binding's
   per-entry `delegation` rules
   ({{I-D.draft-mcguinness-oauth-mission}}): entries without a
   `delegation` member are excluded, `allowed_delegates` is applied,
   and `max_depth` is evaluated from the deployment's actor records
   rather than from a Mission-bound token's `act` chain. A delegate
   with no actor record under the Mission is not recorded as acting
   under it, and the join fails with `mission_mismatch`.
6. **Join failure is a deny.** A failure of the subject or client join
   MUST be denied with the `mission_mismatch` denial reason: the
   presented credential does not join to the referenced Mission
   because its authenticated subject or client identifier does not
   match the Mission's `subject.sub` or `client_id` under the
   deployment's documented mapping and delegate policy. The PDP MUST
   NOT fall back to evaluating the action against the referenced
   Mission's authority when the join fails.
7. **Authority comes from the Mission.** On a successful join, the PDP
   evaluates the action under the runtime profile's decision contract,
   drawing the Authority Set from the Mission (the audience-scoped
   Mission Status response or a materialized policy view), since the
   credential carries none. All other decision inputs and invariants
   of {{I-D.draft-mcguinness-mission-runtime}} apply unchanged.
8. **The permit intersects three bounds.** A permit under a join never
   exceeds any of three independently evaluated bounds: the authority
   the acting credential itself carries (the token as issued, enforced
   at the Resource Server or gateway), the Mission's approved
   authority, and current Resource policy. The join adds the Mission
   bound and MUST NOT widen either of the other two. A PEP MUST
   NOT treat a Mission permit as overriding what the credential or
   the resource would refuse.
9. **Joined-view evidence commitment.** A decision reached over a
   successful join MUST carry a joined-view commitment
   (`join_view_id`) separate from `policy_view_id`, which alone does
   not distinguish a joined decision from a direct one. `join_view_id`
   MUST change whenever the joining client identifier, the join
   disposition (the Mission's own `client_id` or an authorized
   delegate), or the resulting effective Authority Set differs, so a
   verifier can tell a joined decision's evidence from a direct
   Mission-bound decision's, and one joined view from a
   differently-joined one. This document does not specify the
   commitment's construction.

## What a Join Establishes {#join-scope}

The join proves that the credential belongs to the subject and client
the Mission names, never that the credential was issued for the
Mission. No MAS-mode mechanism can prove derivation under the Mission,
because the AS issues tokens with no knowledge of Missions
({{limitations}}, {{join-spoofing}}). No assertion raises this
ceiling.

For the high-consequence classes, association is therefore not the
end state. The issuance join
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) or native
Mission-bound issuance restores cryptographic derivation. A path
claiming the Enterprise profile's high-consequence credential property
MUST use Mission-bound issuance: an acting credential satisfying the
mission-credential-bound composition of the Mission Binding Properties
({{I-D.draft-mcguinness-mission-architecture}}).

A deployment without Mission-bound issuance still claims the runtime
and join capabilities its paths actually have, and states the
difference in its Mission Deployment Profile. No `residual_risks`
entry permits the stronger claim, and a Join Assertion cannot satisfy
it.

In the baseline mapping join, the PDP compares the authenticated
subject and client that the PEP attests in the decision request, not
the acting credential itself. The PEP authenticates the credential at
the enforcement boundary and populates the decision request from it;
the PDP neither receives nor inspects the credential. Baseline join
integrity therefore rests wholly within the PEP trust base, and a PEP
that misattests the subject or client widens the join. The
credential-bound join, in which the acting token itself is inspected,
is the Mission Join Assertion ({{join-assertion}}): the MAS resolves
the token centrally and binds its assertion to that token's digest
and key.

A deployment MAY move the join's verification from each PDP to the
MAS with the Mission Join Assertion ({{join-assertion}}). That
upgrade strengthens the join's verification, not what the join can
prove.

## Acting Credentials {#join-credentials}

The join binds identity, not possession. The acting credential's own
sender binding keeps a joined permit from being a bearer property.
Acting credentials for governed work SHOULD be sender-constrained,
with DPoP or mutual TLS at the unchanged AS. For the high-consequence
action classes, acting credentials for governed work MUST be
sender-constrained. With a pure bearer token, any holder inside the
(subject, client) equivalence class joins ({{join-spoofing}}).

## Instance-Bound Joins {#join-instance}

Where the deployment's Authorization Server conveys Instance Context in
its tokens ({{I-D.draft-mcguinness-oauth-client-instance-id}}: the
`client_instance` claim or introspection member), the acting credential
identifies a concrete runtime instance once the PDP has validated that
context and established its association with the presenter as a Context
Consumer ({{I-D.draft-mcguinness-oauth-client-instance-id}}, Section
7.5).

A sender-constraint key unique to the instance
({{I-D.draft-mcguinness-oauth-client-instance-id}}, Section 7.3)
establishes that association only where the token issuer conveys
context solely from direct Client Attestation validation. Context an
issuer may have preserved from an input token also needs a profile
that authenticates its provenance, since such a token can carry one
instance's context while bound to another's key.

Where the PDP has validated that Instance Context and established its
association with the presenter, the PDP SHOULD include that instance
in the join, so the client join binds (subject, client, instance)
rather than (subject, client). This restores
per-instance granularity behind a shared gateway `client_id`: the
validated instance joins, not every workload in the `client_id`
equivalence class.

In the PEP/PDP split, the PEP performs the credential, context, and
presenter-proof validation and supplies the established instance
through the authenticated decision context. The PDP relies on that
PEP under the decision API's trust boundary.

The mapping contract states which paths require an instance-bound join
and how the established instance maps to the Mission's permitted
parties. Where the mapping contract requires an instance-bound join,
the PDP MUST deny with `mission_mismatch` if the established instance
is absent or does not match that contract, without falling back to a
subject-and-client-only join.

A PEP unable to validate required instance attribution refuses before
requesting a decision, using the instance specification's Section 7.6
credential error and the runtime profile's pre-decision refusal
evidence ({{I-D.draft-mcguinness-mission-runtime}}).

## AuthZEN Encoding {#join-authzen}

The following example shows a decision request for a successful join
in the AuthZEN binding. The PEP supplies `context.mission` populated
from its Mission binding, with `state` (and `authority_hash` where
disclosed) taken from the MAS's signed Mission Status response, and
the other decision inputs per {{I-D.draft-mcguinness-mission-authzen}}:

~~~ json
{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": { "iss": "https://idp.example.com" }
  },
  "resource": { "type": "invoice", "id": "inv_2026Q3_842" },
  "action": { "name": "invoices.read" },
  "context": {
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://mas.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active"
    }
  }
}
~~~

The credential's authenticated subject and client match the Mission's
`subject.sub` and `client_id`, so the join holds, and the PDP evaluates
the action under the Mission's Authority Set. The following example
shows the resulting permit:

~~~ json
{
  "decision": true,
  "context": {
    "decision_id": "dec_7mQ2sV5rL9tY3sB8zN1eF4jB0K",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "join_view_id":
      "sha-256:dV7wM3sK9nQ2vL5tR8bY1eG4jF6xH0pC3nT9kV2mZ5t",
    "action_class": "consequential_read",
    "class_source": "resource_floor",
    "permit_expires_at": "2026-11-02T08:15:30Z"
  }
}
~~~

The `join_view_id` member accompanies `policy_view_id` because this
decision was reached over the join (rule 9 of {{join-rules}}). The
direct-client disposition and `client_id` it binds distinguish it from
a differently-joined decision (a narrowed delegate view) and from a
direct Mission-bound decision, which never carries `join_view_id`.

The AuthZEN profile's denial-reason extensibility rule permits a
companion profile to extend the denial-reason set by specification,
and requires a consumer to treat an unrecognized reason as a deny
({{I-D.draft-mcguinness-mission-authzen}}). Where this document is
implemented, `mission_mismatch` and `mission_reference_conflict`
({{reference-verification}}) are members of that set; neither requires
IANA action under that extension-by-specification model. A consumer
that does not implement this document treats them as that rule
requires, so the action stays refused.

The following is an example of an AuthZEN denial for a credential
whose `client_id` does not match the referenced Mission:

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_2nP4qV9rL3tY6sB1zN0eF7jB8K",
    "denial_reason": "mission_mismatch",
    "action_class": "consequential_read",
    "class_source": "resource_floor",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  }
}
~~~

# Mission Reference Propagation {#reference-propagation}

The Mission Join consumes a Mission reference the PEP supplies, and
rule 1 of {{join-rules}} names two sources: the PEP's own recorded
Mission binding and deployment configuration. When the gateway PEP
is not the process that holds the binding (an MCP gateway, an egress
proxy), neither source exists at the enforcement boundary. Mission
reference propagation is the channel through which the requesting
side names the Mission a given request runs under.

The carried value is an untrusted **Mission-selection assertion**: it
routes the request to a Mission for the join to verify. The Mission
Join verifies the referenced Mission and its subject and client
relationship, and supplies the authoritative state and anchors. In
the baseline same-party case, neither the carriage nor the join
proves that this particular request was created under that Mission.

The party that attaches the value determines attribution strength. A
trusted harness attaching it from its recorded Mission binding
({{I-D.draft-mcguinness-mission-harness}}) attests more than the
agent naming its own Mission. The deployment's Enforcement Scope
Statement records which party attaches it. Grading what an
established join proves is a join-assurance concern, not a concern
of this channel.

## The Reference Tuple {#reference-tuple}

The propagated value is exactly the Mission reference tuple:
`mission_id` and `issuer`, compared as the canonical (`issuer`,
`mission_id`) pair under the OAuth binding's comparison rules
({{I-D.draft-mcguinness-oauth-mission}}). The channel carries nothing
else. State, integrity anchors, authority, and policy data always
come from the MAS's signed Mission Status response
({{lifecycle-and-state}}), and a request carrying any of them in this
channel MUST be refused, never silently ignored, so ambiguity is
detectable rather than absorbed. Each carriage below maps this one
tuple, and an additional carrier profiles it rather than defining a
second.

## HTTP Carriage: Mission-Reference {#mission-reference-field}

`Mission-Reference` is an HTTP request field {{RFC9110}} whose value
is a Structured Fields Dictionary {{RFC9651}}. The following example
shows a request carrying the field (wrapped for display; the field is
one line):

~~~ http-message
POST /call HTTP/1.1
Host: gateway.example.com
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...
Mission-Reference: id="msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  issuer="https://mas.example.com"
~~~

- The field is a request header field and MUST NOT be sent as a
  trailer field.
- The value is a Dictionary carrying exactly two members, both
  REQUIRED: `id`, a String carrying the Mission identifier, and
  `issuer`, a String carrying the exact issuer identifier the MAS
  publishes in its metadata ({{discovery}}). A MAS participating in
  this profile MUST publish an ASCII issuer identifier (Structured
  Field Strings are ASCII). The sender copies that published string
  with no URI normalization of any kind, and equality is byte
  equality of the exact string.
- A sender MUST NOT emit an `id` longer than 256 characters or an
  `issuer` longer than 512 characters; a receiver MUST treat a longer
  value as malformed.
- {{RFC9651}} parsing keeps the last of duplicate Dictionary keys, so
  parse success alone is not sufficient. A receiver MUST reject as
  malformed, before map collapse: a duplicate `id` or `issuer`
  occurrence, a parameter on either member, an Inner List or any
  non-String value, and any member other than the two defined here.
  A profile the deployment adopts MAY define an additional member by
  specification. A receiver MUST NOT act on a member it does not
  implement.
- A sender MUST send exactly one field line. If the field lines do not
  combine into exactly one Dictionary satisfying every rule above, or
  if parsing fails, the reference is malformed.
- A malformed, missing, or stripped reference fails closed wherever
  Mission governance is required: governed work with no establishable
  Mission reference is refused before evaluation, per the runtime
  profile's preconditions
  ({{I-D.draft-mcguinness-mission-runtime}}).

## MCP Carriage {#mcp-reference}

For a tool call governed through MCP, the reference is carried in the
request's `params._meta` object on each `tools/call`, never in tool
arguments and never in session state. The key is
`com.karlmcguinness.mission/reference`, a reverse-DNS-prefixed key in
a namespace this family's author controls, per the pinned MCP
revision's `_meta` rules ({{MCP-META}}); MCP reserves its own `_meta`
prefixes. The following example shows a `tools/call` request carrying
the reference:

~~~ json
{
  "method": "tools/call",
  "params": {
    "name": "post_journal_entry",
    "arguments": { "amount": "500.00", "currency": "USD" },
    "_meta": {
      "com.karlmcguinness.mission/reference": {
        "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
        "issuer": "https://mas.example.com"
      }
    }
  }
}
~~~

The value carries exactly `mission_id` and `issuer`, with the tuple
semantics of {{reference-tuple}} unchanged. The value object is
closed the same way as the HTTP field: a receiver MUST reject
duplicate JSON member names at parse time, a member other than
`mission_id` and `issuer`, a non-string member value, and the
propagation key appearing more than once in `_meta`. Unknown `_meta`
keys are extensible metadata that an ordinary MCP server may ignore.
A server that silently ignores this key is not a conforming Mission
PEP.

Where a tool is governed as Mission-required, absent negotiated or
configured propagation support the call MUST be refused, never run
as ordinary ungoverned execution. An MCP extension or capability
mechanism may supersede this carriage; the tuple semantics remain
those of {{reference-tuple}}.

## Verification and Conflict {#reference-verification}

- The value is a selection assertion, never authority: its presence
  or content grants nothing, and the Mission is established only
  through the Mission Join ({{mission-join}}). An unverified reference
  MUST NOT establish the Mission; this is the runtime profile's
  externally-established rule
  ({{I-D.draft-mcguinness-mission-runtime}}).
- Where the acting credential carries a `mission` claim, the
  credential-carried reference governs, and a propagated reference
  naming a different Mission is a deny.
- Where the PEP's own binding source (a harness-recorded binding,
  deployment configuration) names a different Mission than the
  propagated reference, the conflict is a deny, never a silent
  pick-one.
- An attribution conflict, or a malformed reference where governance
  requires one, is denied with the `mission_reference_conflict`
  denial reason. This document adds that reason to the AuthZEN
  denial-reason set under its extensibility rule, beside
  `mission_mismatch` ({{mission-join}}). The `mission_mismatch` reason
  remains the subject-or-client join failure, and
  `mission_reference_conflict` covers reference sources naming
  different Missions or an unusable reference.
- If a PEP establishes the conflict before any evaluation, it surfaces
  the same reason as a coordinated pre-decision refusal, recorded as
  a Refusal Record with this `denial_reason`
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}). An evaluating
  PDP surfaces it as the AuthZEN denial reason above. Either way the
  conflict carries one reason and is never silently resolved.
- The selection assertion applies only to the request it accompanies.
  It selects the Mission the join is evaluated against and does not
  by itself establish request provenance or attribution.
  Session-scoped stickiness is a deployment choice recorded in the
  Enforcement Scope Statement, and per-request carriage is required
  wherever the runtime profile requires per-action evaluation.
- The field is protected by the deployment's TLS, which authenticates
  the channel endpoint, never which component attached the value.
  Transport protection therefore does not upgrade self-asserted
  attribution. Where HTTP Message Signatures {{RFC9421}} are deployed
  on the request, the signature MUST cover `Mission-Reference`.

The following is an example of a denial for a propagated reference
that conflicts with the PEP's recorded binding:

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_2nP4qV9rL3tY6sB1zN0eF7jB8K",
    "denial_reason": "mission_reference_conflict"
  }
}
~~~

## Forwarding and Privacy {#reference-forwarding}

The tuple is a stable correlator and is recorded in gateway logs. An
intermediary MUST NOT copy the field or the `_meta` key onto a
request to an unrelated authority domain. A terminating PEP SHOULD
remove the field or key before forwarding unless the downstream
recipient participates in the same verified binding. The OAuth
binding's Mission Identifier correlation considerations apply to
logged values.

# Mission Join Assertion {#join-assertion}

The Mission Join of {{mission-join}} rests on subject and client
mapping tables that every PDP operates and keeps correct. This section
defines an OPTIONAL upgrade from mapping-table equality to a
credential-bound proof: the MAS verifies the join centrally and mints
a signed assertion of it, so the PDP verifies one signature and one
token binding instead of operating a mapping table.

A MAS that supports the upgrade publishes its join-assertion endpoint
as `mission_join_assertion_endpoint` ({{discovery}}). The endpoint
MUST meet the TLS and caller-authentication requirements of the
mission submission endpoint ({{mission-submission}}). It accepts the
authentication methods and client-assertion algorithms advertised in
`mission_submission_endpoint_auth_methods_supported` and
`mission_submission_endpoint_auth_signing_alg_values_supported`.

A client assertion's `aud` claim and a caller-authentication access
token's audience MUST name the join-assertion endpoint.

For access-token authentication, the MAS publishes Protected Resource
Metadata {{RFC9728}} for this endpoint, identifying its resource,
required scope, and accepted sender constraints. That caller token is
distinct from the acting `access_token` that the request body carries
({{join-assertion-request}}), the credential whose join is asserted.

## Assertion Request {#join-assertion-request}

The PEP, or the client acting for it, sends a POST request whose body
is a JSON object with the following members:

`mission_id`:
: REQUIRED. A string. The Mission the join is asserted against; its
  `issuer` is the MAS.

`access_token`:
: A string. The acting access token. REQUIRED unless the digest pair
  is present.

`token_sha256`:
: A string. The unpadded base64url SHA-256 digest of the access
  token's ASCII bytes. This is a member-named digest construction
  outside the default prefixed form: the member name fixes the
  algorithm, and a successor algorithm enters as a new member, never
  by reinterpreting this one. For the same token, it equals the `ath`
  value of a DPoP proof ({{Section 4.2 of RFC9449}}).

`token_jkt`:
: A string. The JWK thumbprint {{RFC7638}}, using SHA-256, of the
  token's `cnf` public key.

The caller presents `access_token`, or `token_sha256` together with
`token_jkt`. The digest pair keeps the credential itself off this
wire, but it is usable only where the deployment's introspection
surface can resolve a token by digest. `access_token` is the
interoperable form.

The acting token MUST be sender-constrained. The MAS MUST NOT mint an
assertion for a token without a `cnf` key: such a token gives the
assertion nothing to bind.

The MAS verifies the join centrally, as follows:

1. The MAS establishes the acting token's validity, subject, and
   client:

   - Where the AS offers token introspection {{RFC7662}}, the MAS
     introspects the token under introspection credentials it holds
     there. A token the AS reports inactive fails the request.
   - Where the AS offers no third-party introspection but issues JWT
     access tokens, the MAS MAY instead validate the token locally
     under the semantics of {{RFC9068}}, resolving the AS's signing
     keys from its published metadata and taking the subject and
     client from the validated claims. A token that fails signature,
     `exp`, or `aud` validation fails the request.
   - An opaque token that no introspection surface will resolve
     cannot be verified, and the request fails.

   Calling the AS is permitted in MAS mode; changing it is not.

2. The MAS verifies the subject and client joins of {{mission-join}}
   against the introspection response or the validated token claims,
   under its own documented account and client mappings and delegate
   policy.

If the acting token does not join, the MAS rejects the request with
the `join_failed` error code (HTTP 403), in the error format of
{{submission-errors}}. If the `mission_id` is unknown or not
visible, the MAS returns the `not_found` error code, preserving the
anti-oracle property.

Visibility on this endpoint is bounded: a Mission is visible to its
`client_id`, its recorded delegates, and the PEPs and PDPs enrolled
for the Mission's enforcement scope. Any other caller MUST receive
`not_found`, so the `join_failed` (403) and `not_found` (404) split
never acts as a mapping oracle for callers outside that set.

An assertion's lifetime is capped by the acting token's, so with
short token lifetimes, minting is on the token-rotation path: each
rotation needs a fresh assertion and its introspection call, per
Mission and per workload. A deployment sizes agent token lifetimes to
the runtime layer's revocation cutoff rather than treating token
expiry as the revocation mechanism (the token-lifetime trade of
{{I-D.draft-mcguinness-mission-runtime}}). The MAS MAY reuse an
introspection result across mintings of the same token within the
deployment's staleness bound, so re-minting for an unchanged token
does not repeat the AS round trip.

Minting is a high-frequency path, invoked on every rotation for every
Mission and workload the MAS serves, and is therefore a
denial-of-service surface. The MAS MUST rate-limit assertion requests
per caller. The MAS SHOULD serve repeated requests for the same
(token digest, audience) pair from cache within the assertion's
lifetime, so a burst of re-mints for an unchanged token costs one
evaluation rather than many.

## The Assertion {#join-assertion-artifact}

On success, the MAS mints a Mission Join Assertion, a signed JWT
{{RFC7519}}. Its protected header carries the `typ` header parameter
with the value `mission-join+jwt` and a `kid` header parameter
resolvable in the MAS's `jwks_uri`. Exact validation of that `typ`,
with mutually exclusive validation rules for the artifact profiles,
implements the substitution defense of Sections 3.11 and 3.12 of
{{RFC8725}}. The assertion contains the following claims:

`iss`:
: REQUIRED. The MAS's issuer URL.

`mission`:
: REQUIRED. An object containing `id` and `issuer`
  ({{I-D.draft-mcguinness-oauth-mission}}). The MAS MAY additionally
  include `authority_hash` as an audit anchor; where it is included,
  the PDP Consumption cross-check applies to it too
  ({{join-assertion-pdp}}). This object MUST NOT carry
  `approval_context_commitment`: the Approval Context Commitment
  profile fixes this descriptor as a must-not-carry site alongside the
  baseline `mission` claim
  ({{I-D.draft-mcguinness-mission-approval-governance}}).

`token`:
: REQUIRED. An object containing `sha256`, the token digest as in
  {{join-assertion-request}}, and `jkt`, the thumbprint of the token's
  `cnf` public key {{RFC7638}}.

`iat`:
: REQUIRED. Issuance time.

`exp`:
: REQUIRED. Expiry. It MUST NOT exceed the access token's remaining
  lifetime.

`aud`:
: RECOMMENDED. The PDP or PDPs for which the assertion is minted.
  Audience scoping prevents replay of an assertion to a consumer it
  was not minted for.

`mapping_version`:
: OPTIONAL. A string. The mapping contract version
  ({{mapping-contract}}) under which the subject and client joins
  were evaluated. RECOMMENDED where the MAS publishes a mapping
  contract, so each join is attributable to the mapping that
  produced it.

The assertion carries no instance identifier. Where the acting token
is sender-constrained to a key unique to the instance
({{I-D.draft-mcguinness-oauth-client-instance-id}}, Section 7.3), the
`jkt` binding names one runtime instance, not any holder of a
client-shared key, so the assertion's token binding is materially
stronger. An instance-bound join on this path takes the instance only
from Instance Context whose association with the presenter has been
established ({{mission-join}}). The token digest and `jkt` alone do
not establish that association.

The endpoint returns HTTP 200 with a JSON object whose `assertion`
member carries the JWT.

Each minting is a join evidence event. The MAS records the following,
retained for the audit horizon:

- the Mission reference;
- the token digest and thumbprint;
- the authenticated caller;
- the mapping version, where one is published ({{mapping-contract}});
- the token's Instance Context, where the MAS validated it as a
  Context Consumer
  ({{I-D.draft-mcguinness-oauth-client-instance-id}}, Section 7.5);
  and
- the validity window.

Context for which the MAS has established only instance participation
is recorded as participation, not as proof of which instance presented
the credential.

The following is an example of the claims of a Mission Join
Assertion:

~~~ json
{
  "iss": "https://mas.example.com",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://mas.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "token": {
    "sha256": "rN2kQ4mZ7tP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2n",
    "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  },
  "iat": 1793606400,
  "exp": 1793608200
}
~~~

## PDP Consumption {#join-assertion-pdp}

A PDP presented with a Join Assertion verifies the following, in
place of the mapping checks of rules 3 and 4 of {{join-rules}}:

- the signature, under a key from the MAS's `jwks_uri`, and the `typ`
  header parameter value `mission-join+jwt`;
- that `iss` and the `mission` claim match the referenced Mission's
  `issuer` and `id`; when the assertion's `mission` also carries
  `authority_hash`, that it matches the referenced Mission's
  `authority_hash` too;
- that `exp` has not passed and any `aud` names this PDP; and
- the token binding: the presented credential's digest equals
  `token.sha256` and its `cnf` key's thumbprint equals `token.jkt`.

Every other join rule holds unchanged: the PDP resolves Mission state
at the MAS under the runtime profile's freshness rules, denies with
`mission_mismatch` when any check above fails, and draws authority
from the Mission.

For an instance-bound join, the PDP also applies the instance mapping
of {{mission-join}} to the validated presenter context supplied by the
PEP. The Join Assertion replaces only the subject and client mapping
checks. Its signature, token digest, and key thumbprint cannot replace
the instance check or satisfy a missing required instance association.

For the high-consequence action classes
({{I-D.draft-mcguinness-mission-runtime}}) in MAS mode, the
Enterprise profile requires Mission-bound issuance for the acting
credential ({{enterprise-profile}}). A Join Assertion strengthens
every joined path outside those classes, and that profile requires
one on those paths.

The mapping join of {{mission-join}} remains the conformance floor: a
deployment without the endpoint still joins, and a PDP MUST NOT treat
possession of an assertion as authority, per the family rule that
references and binding proofs grant nothing.

# Mission Expansion and Child Creation {#native-surfaces}

Mission Expansion ({{I-D.draft-mcguinness-oauth-mission-expansion}})
and Mission Child Delegation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) each rest on
one abstract requirement, stated normatively by each of those
profiles: that the requester prove possession of the predecessor or
parent Mission's authority through a sender-constrained proof rather
than a reusable bearer refresh credential. On the OAuth wire, those
profiles bind that requirement to an {{RFC8693}} token exchange whose
`subject_token` is the predecessor or parent Mission-bound access
token. A MAS issues no tokens, so that binding has no carrier here.

This section defines only the peer MAS binding: carriage on the
mission submission endpoint ({{native-carriage}}) and an
authenticated-client binding in place of the token-exchange
possession proof ({{native-binding}}). Every mechanism (supersession,
reconciliation, lineage, strict subset, fan-out, cascade, and the
closed code sets) remains owned by its profile and applies here by
reference ({{native-expansion}}, {{native-child}}). The capability is
OPTIONAL ({{conformance}}).

## Submission Carriage {#native-carriage}

The mission submission endpoint carries both operations as intent
submissions ({{intent-submission}}) with the following additional
top-level members of the request body:

`predecessor`:
: A string. The `mission_id` of the predecessor Mission this
  submission expands; semantics per the expansion profile. Its
  presence marks the submission as an expansion request.

`parent`:
: A string. The `mission_id` of the Parent Mission; semantics per the
  child-delegation profile.

`child_actor`:
: An object identifying the child actor, in the form the
  child-delegation profile defines. The presence of `parent` and
  `child_actor` together marks the submission as a child-creation
  request.

These members are submission members, not Mission Intent members. A
MAS that implements this capability MUST remove them before applying
the OAuth binding's Intent validation; the remainder of the body is
the Mission Intent Submission envelope, validated unchanged
({{intent-submission}}). On a MAS that does not implement this
capability, they are undefined top-level members, and the MAS rejects
the submission with the `invalid_mission_intent` error code, the
correct refusal for an unsupported operation.

If a submission carries both `predecessor` and either child member,
the MAS MUST reject it with the `invalid_mission_intent` error code:
the operations do not combine. If a submission carries `parent`
without `child_actor`, or `child_actor` without `parent`, the MAS
MUST reject it with the same error code.

The referenced profiles' OAuth error outcomes map onto this
endpoint's error surface as the OAuth binding's outcomes do
({{intent-submission}}): `invalid_request` outcomes map to
`invalid_mission_intent`, and authority-derivation failures map to
`invalid_authority`. Two rules cover the outcomes those profiles
express as `invalid_grant`:

- If the binding does not resolve a `predecessor` or `parent`,
  whether the Mission does not exist or is recorded under another
  client, the MAS MUST reject the submission with the `not_found`
  error code and a response identical in both cases, preserving the
  anti-oracle property of {{submission-status}}.
- If the binding resolves the reference but its state or
  serialization refuses the operation (the expansion profile's
  predecessor-active and reconciliation rules; the child-delegation
  profile's parent-active rule), the MAS MUST reject the submission
  with the `conflict` error code, returned with HTTP 409. `conflict` is
  used only by this section's operations.

The profile-defined machine-readable codes ride the MAS error surface
in the members their profiles define:

- A reconciliation status rides in `mission_expansion_status`
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}).
- An adjudication denial reason, for expansion and child creation
  alike, rides in the shared `mission_denial_reason` member that
  profile defines ({{I-D.draft-mcguinness-oauth-mission-expansion}},
  {{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

Each is carried as a member of the error response body
({{submission-errors}}) or, for a denial at adjudication, of the
`denied` submission-status response ({{submission-status}}).

## Request Binding {#native-binding}

On the OAuth wire, the predecessor or parent is resolved from the
Mission-bound access token presented as the token exchange's
`subject_token`, with possession proven against that token's
confirmation key, and any named identifier serves only as a
cross-check. A MAS holds no such tokens, so the named identifier is
itself the reference. The MAS binds the request to that reference as
follows:

- The MAS MUST verify that the authenticated submitting client is the
  client recorded as the predecessor Mission's `client_id` (for
  expansion) or the Parent Mission's `client_id` (for child creation).
  Both identifiers live in the MAS's own client namespace
  ({{mission-submission}}), so the comparison is ordinarily
  byte-equality. Where a deployment maps client identities, it MUST
  document the mapping, exactly as the client join requires
  ({{mission-join}}).
- For an expansion, the MAS MUST verify at the approval event that the
  Subject it establishes ({{mission-approval}}) equals the predecessor
  Mission's `subject`; a successor MUST NOT be created for a different
  Subject.

This binding is authentication-based, not possession-based. It proves
that the requester is the same registered client for which the
predecessor or parent was recorded, not that the requester holds and
can prove possession of that Mission's access token. The difference
from the OAuth wire is exactly this: a party able to authenticate as
the registered client can request these operations for any of that
client's Missions, whereas the token-exchange possession proof would
limit it to the Missions whose Mission-bound access token it holds
and can prove control of ({{sec-native-binding}}).

Where the deployment authenticates client instances
({{I-D.draft-mcguinness-oauth-client-instance-id}}), the MAS SHOULD
bind at instance granularity rather than at the bare `client_id`. In
such a deployment, a Mission Join Assertion for the predecessor or
parent ({{join-assertion}}), presented with the submission,
strengthens the proof to a named runtime instance holding a
sender-constrained credential that verifiably joins to that Mission.

## Expansion Semantics {#native-expansion}

An expansion submission is adjudicated under the expansion profile's
rules ({{I-D.draft-mcguinness-oauth-mission-expansion}}), applied by
reference:

- **Predecessor active.** The predecessor MUST be `active` when the
  submission is accepted, per that profile's predecessor-active rule.
- **Reconciliation.** Concurrent expansions against the same
  predecessor are serialized under that profile's compare-and-set
  reconciliation. Its closed reconciliation-status set applies: a
  refusal at submission carries the code per {{native-carriage}}, and
  a pending submission overtaken by a concurrent expansion resolves to
  `denied` with the code in the status response.
- **Supersession atomicity.** In one atomic operation on the MAS's
  records, the successor activates with its `predecessor` member set,
  and the predecessor transitions to `superseded` with its `successor`
  member set. The `successor` and `related_to` members carry that
  profile's semantics and surface through the MAS's Mission Status
  responses. The `superseded` state enters the state space the MAS
  reports ({{lifecycle-and-state}}).
- **Denial reasons.** That profile's closed denial-reason set applies;
  the code rides in `mission_denial_reason` per
  {{native-carriage}}.

Approval of the successor is this document's native asynchronous
approval event ({{mission-approval}}): fresh consent for the
successor's derived Authority Set, with no authorization-code leg to
re-sequence. On approval, the client's poll delivers the successor's
`mission_id` and consented authority ({{mission-reference}}). The
successor-expiry rule and every other expansion rule that does not
name the OAuth wire apply unchanged.

Progressive authorization is out of scope here, as it is out of the
expansion profile's base: every expansion on this surface is
adjudicated by a fresh approval. The policy-adjudicated variant
remains with the experimental companion
({{I-D.draft-mcguinness-oauth-mission-progressive}}).

## Child-Creation Semantics {#native-child}

A child-creation submission is adjudicated under the child-delegation
profile's rules
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), applied by
reference:

- **On-switch.** Child creation is permitted only where the applicable
  Parent Mission Authority Set entry's `delegation` member carries a
  `children` object; an entry without one permits no child.
- **Strict subset.** The child Authority Set MUST satisfy that
  profile's strict-subset evaluation against the parent, with no
  relaxation.
- **Fan-out.** Fan-out accounting and its serialization apply
  unchanged: the MAS counts non-terminal Child Missions against
  `max_children` and serializes creation against the same parent entry
  and fan-out bucket.
- **Parent member.** The Child Mission record carries the `parent`
  object constructed per that profile, including `depth`; with no
  token carrier, it surfaces through the record and the MAS's Mission
  Status responses.
- **Cascade.** Cascade applies with one simplification: the MAS owns
  its state store, so cascade transitions are native lifecycle
  transitions on its own records. The MAS implements that profile's
  `immediate` mode, and the `cascaded` state surfaces through Mission
  Status ({{lifecycle-and-state}}).
- **Denial reasons.** That profile's closed denial-reason set applies;
  the code rides in `mission_denial_reason` per {{native-carriage}}.
  The `parent_mismatch` reason has no analog on this surface: with no
  `subject_token` to resolve the parent against a cross-check, a binding
  failure is refused per {{native-carriage}}.

The child client identity rules hold unchanged: the child actor is
the Child Mission's client, recorded as its `client_id`; it
authenticates itself to the MAS for its own submissions, status, and
lifecycle operations; and child credentials MUST NOT transit the
parent.

The creating client learns the Child Mission's `mission_id` from its
own submission status. A `mission_id` is a reference, never a
capability, so conveying it to the child actor moves no authority. At
the point of use, the Mission Join ({{mission-join}}) binds the
child's ordinary OAuth credentials to the Child Mission through the
child's own `client_id`, never the parent's.

## Expansion Example {#native-example}

The following example shows an expansion submission. Mid-task, the
agent behind the Q3 reconciliation Mission finds a $1,200 adjustment,
outside its approved $500 cap. It submits a Mission Intent for the
broadened task whose body names the predecessor:

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $2,000.",
    "target_resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z"
  },
  "predecessor": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
}
~~~

The MAS authenticates the client, verifies that it is the
predecessor's recorded `client_id`, verifies that the predecessor is
`active`, removes `predecessor`, validates the remaining Submission
envelope, and derives the successor's Authority Set. The following
example shows the MAS accepting the submission:

~~~ http-message
HTTP/1.1 202 Accepted
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_7bD1eF4jB0K9wT2xM5nQ8rL3vZ",
  "status": "pending",
  "expires_at": "2026-10-16T15:07:42Z"
}
~~~

Adjudication proceeds per {{mission-approval}}: the Approver consents
to the widened cap, the MAS verifies that the established Subject
equals the predecessor's `subject`, and one atomic operation creates
the successor `active` and supersedes the predecessor. The client's
next poll returns `approved` with the successor's `mission_id`
({{mission-reference}}).

# Mission Authority Server Metadata {#discovery}

A MAS publishes a metadata document at the well-known URI {{RFC8615}}
path `/.well-known/mission-authority-server`, registered in {{iana}}.
The document is a JSON object served over TLS as `application/json`.
Its location is constructed from the `issuer`, following the
metadata-location rule of {{RFC8414}}:

1. For an `issuer` with no path component, the document is served at
   the well-known path under the issuer's host.
2. For an `issuer` that bears a path component, the
   `mission-authority-server` well-known segment is inserted between
   the host and the issuer's path (for `issuer`
   `https://host/tenant`, the document is at
   `https://host/.well-known/mission-authority-server/tenant`).

The document's members mirror the Mission suite's Authorization
Server metadata members where applicable, so a consumer reads the
same member names it would read from AS metadata {{RFC8414}},
resolved from the MAS metadata document instead:

`issuer`:
: REQUIRED. A string. The MAS's issuer URL. It equals the `issuer` of
  every Mission the MAS records and the `iss` of its integrity-anchor
  envelopes and signed status responses. A consumer MUST verify that
  applying the location-construction steps above to this `issuer`
  yields the URL the metadata was resolved from.

`mission_submission_endpoint`:
: REQUIRED. A string containing a URL. The mission submission endpoint
  ({{mission-submission}}).

`mission_submission_endpoint_auth_methods_supported`:
: REQUIRED. A JSON array of strings naming the authentication methods
  the mission submission endpoint accepts, from the value space of
  `mission_status_endpoint_auth_methods_supported`
  ({{I-D.draft-mcguinness-oauth-mission-status}}). Here `access_token`
  names a sender-constrained access token whose audience, required
  scope, and sender constraint the MAS publishes in this endpoint's
  Protected Resource Metadata {{RFC9728}}.

`mission_submission_endpoint_auth_signing_alg_values_supported`:
: REQUIRED when `mission_submission_endpoint_auth_methods_supported`
  lists `private_key_jwt`. A JSON array of strings: the client-assertion
  algorithms this endpoint accepts, with the semantics of
  `mission_status_endpoint_auth_signing_alg_values_supported`
  ({{I-D.draft-mcguinness-oauth-mission-status}}).

`mission_status_endpoint`:
: REQUIRED. A string containing a URL. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_status_endpoint_auth_methods_supported`:
: REQUIRED. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_status_endpoint_auth_signing_alg_values_supported`:
: REQUIRED when `mission_status_endpoint_auth_methods_supported` lists
  `private_key_jwt`. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_status_signing_alg_values_supported`:
: REQUIRED. A JSON array of strings. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_lifecycle_endpoint`:
: REQUIRED. A string containing a URL. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_lifecycle_endpoint_auth_methods_supported`:
: REQUIRED. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_lifecycle_endpoint_auth_signing_alg_values_supported`:
: REQUIRED when `mission_lifecycle_endpoint_auth_methods_supported`
  lists `private_key_jwt`. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_join_assertion_endpoint`:
: OPTIONAL. A string containing a URL. The join-assertion endpoint
  ({{join-assertion}}). Present when the MAS mints Mission Join
  Assertions.

`mission_event_stream_endpoint`:
: OPTIONAL. A string containing a URL. Present when the MAS supports
  Mission Lifecycle Signals; semantics per
  {{I-D.draft-mcguinness-oauth-mission-signals}}.

`mission_max_stale_seconds`:
: OPTIONAL. An integer. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`jwks_uri`:
: REQUIRED. A string containing a URL. The MAS's JSON Web Key Set:
  the issuer's signing keys, from which consumers resolve the keys
  for Mission Status responses, consent evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), Mission
  Mandates ({{I-D.draft-mcguinness-mission-mandate}}), and other
  issuer-signed artifacts, with the signing-key retention rules of
  {{I-D.draft-mcguinness-oauth-mission-status}}.

The following is an example of a MAS metadata document:

~~~ json
{
  "issuer": "https://mas.example.com",
  "mission_submission_endpoint":
    "https://mas.example.com/mas/mission/submit",
  "mission_submission_endpoint_auth_methods_supported":
    ["access_token", "private_key_jwt"],
  "mission_submission_endpoint_auth_signing_alg_values_supported":
    ["ES256"],
  "mission_status_endpoint":
    "https://mas.example.com/mas/mission/status",
  "mission_status_endpoint_auth_methods_supported":
    ["access_token", "private_key_jwt"],
  "mission_status_endpoint_auth_signing_alg_values_supported":
    ["ES256"],
  "mission_status_signing_alg_values_supported": ["ES256"],
  "mission_lifecycle_endpoint":
    "https://mas.example.com/mas/mission/lifecycle",
  "mission_lifecycle_endpoint_auth_methods_supported":
    ["access_token", "private_key_jwt"],
  "mission_lifecycle_endpoint_auth_signing_alg_values_supported":
    ["ES256"],
  "mission_join_assertion_endpoint":
    "https://mas.example.com/mas/mission/join-assertion",
  "mission_max_stale_seconds": 60,
  "jwks_uri": "https://mas.example.com/.well-known/jwks.json"
}
~~~

A consumer holding a Mission reference resolves the MAS metadata
document from the reference's `issuer`. Whether a given `issuer` is a
MAS or an OAuth AS is deployment configuration. The submission and
lifecycle surfaces follow a reference-plus-continuation shape: a
request yields an opaque reference that the client continues against.

# Limitations {#limitations}

This section states what MAS-only deployment does not provide. These
are structural properties of the mode, not implementation quality
issues, and a deployment claiming this profile MUST NOT overstate
them. The mode provides the contextual-governance kernel,
State-Observable, and Structured Authority capabilities. It does not
claim that an unchanged Authorization Server's credential was issued
under the Mission or that its issuance was lifecycle-gated.

Credential-Bound correlation and action-time lifecycle gating compose
through the runtime join and PEP coverage, within the conditional
scope declared by {{mission-substrate}}. Among the Mission Assurance
Levels, this is the Runtime-Enforced level reached through the MAS
binding, which provides no Mission-bound credential and no issuance
gating ({{I-D.draft-mcguinness-mission-architecture}}).

A deployment claiming this profile MUST state, alongside its
Enforcement Scope Statement:

- what the join proves (that the credential belongs to the Mission's
  subject and client) and what it does not (that the credential was
  issued under the Mission);
- the subject and client mapping granularity, and whether instance
  identity is included in the join
  ({{I-D.draft-mcguinness-oauth-client-instance-id}});
- whether Mission Join Assertions are required, which the Enterprise
  profile requires on joined, PDP-gated paths outside the
  irreversible, external-commitment, and privileged-administration
  classes, the classes it reserves for Mission-bound issuance
  ({{join-assertion}}, {{enterprise-profile}}); and
- which action paths are covered by runtime enforcement, since nothing
  at the token layer covers the rest.

An enterprise deployment carries this statement inside its mapping
contract ({{mapping-contract}}), not beside it, so the join's facts
have one home.

**No Mission-bound credentials.** Tokens carry no `mission` claim and
no Mission-derived `authorization_details`. Nothing cryptographically
binds a token to the approval event. No audit anchor travels in
credentials: `authority_hash` reaches consumers only through the MAS's
signed status responses and the PDP's evidence, never in the
credential a resource actually accepted. Resource Servers cannot
enforce Mission authority statelessly from the token.

**No issuance gating.** The AS issues and refreshes tokens with no
knowledge of Mission state. Revoking a Mission stops nothing at the
token layer: every outstanding token, and every token the AS issues
after revocation, remains valid OAuth. The Mission kill switch acts
only through the runtime layer's state re-check.

A MAS deployment MUST deploy the runtime profile's enforcement
({{I-D.draft-mcguinness-mission-runtime}}) over every consequential
action path within the scope it claims Mission governance for.
Because the mode has neither Mission-bound credentials nor issuance
gating, enforcement rests entirely on PEP coverage. The security
model's no-unmediated-path condition
({{I-D.draft-mcguinness-mission-security-model}}) is required for
every guarantee this document makes, not only for the runtime
profile's agent-compromise-resistant enforcement claim. A token
exercised outside PEP coverage is ungoverned: ordinary OAuth alone
bounds its use, and no Mission property applies to it.

**Weaker expansion and child-creation binding.** This mode carries
Mission Expansion and Child Delegation natively ({{native-surfaces}}),
so a standalone deployment can widen authority and delegate to
sub-agents. The mode does not provide the OAuth wire's token-exchange
possession proof. A request is bound to its predecessor or parent by
authenticated client identity ({{native-binding}}), which proves the
same registered client, not possession of a held Mission-bound access
token ({{sec-native-binding}}). Offline attenuation does not apply in
this mode, because it requires the Mission-bound credential
({{mission-substrate}}).

**Upgrade path.** Implementing the OAuth binding at the AS restores
what this mode lacks: Mission-bound credentials and issuance gating.
The MAS then serves as the AS's Mission store, or merges into the AS.
The Mission record, the integrity anchors, and the lifecycle carry
over unchanged, because a MAS operates the OAuth binding's own
definitions of all three. The enforcement join becomes unnecessary
for tokens issued after the upgrade, which carry the `mission` claim.

The Mission Issuance Grant companion
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) defines the
issuance join: a grant the MAS mints for an active Mission and an
estate Authorization Server redeems at its token endpoint for
Mission-bound tokens, state-gated at minting and at refresh. Where
deployed, it removes the credential and issuance-gating limitations
for the resources of each consuming Authorization Server, while
approval, the record, and the lifecycle remain with the MAS.

# The Enterprise Mission Authority Profile {#enterprise-profile}

The conformance floor ({{conformance}}) makes a MAS deployable. This
profile is the operating profile for a MAS used as an estate's
Mission control plane. It turns the floor's recommendations and
options into the guarantees an enterprise deployment needs.

A deployment claims the Enterprise Mission Authority Profile over a
declared coverage set: the Authorization Server, resource, and
action-class paths the claim names. The estate-level obligations
below hold deployment-wide. The per-path credential, join, and
runtime obligations hold for every path in the set. A path outside
the set is explicitly unclaimed and never inherits the profile from
the deployment's name.

The profile builds on the Runtime-Enforced level of the Mission
Assurance Levels under the MAS binding
({{I-D.draft-mcguinness-mission-architecture}}) and adds the
following obligations:

- **Status and lifecycle.** The MAS MUST serve the Mission Status
  operation and the Mission Lifecycle endpoint with signed responses
  ({{lifecycle-and-state}}), so state and the kill switch are
  available estate-wide.
- **Active freshness.** For the high-consequence action classes, the
  MAS-served state MUST be an active freshness source with a published
  staleness bound, meeting the runtime profile's requirement for those
  classes ({{I-D.draft-mcguinness-mission-runtime}}). Token-lifetime
  expiry alone does not qualify. Where per-class bounds differ, the
  metadata's single `mission_max_stale_seconds` member ({{discovery}})
  advertises the tightest bound in force, which a consumer may assume
  without knowing an action's class. The per-class bounds are
  published in the Enforcement Scope Statement.
- **Join Assertion.** The MAS MUST offer the Mission Join Assertion
  ({{join-assertion}}). For every joined, PDP-gated governed path not
  classified as irreversible, external commitment, or privileged
  administration ({{I-D.draft-mcguinness-mission-runtime}}), the PDP
  MUST require one.
- **Mission-bound issuance for the high-consequence classes.** For
  the high-consequence action classes
  ({{I-D.draft-mcguinness-mission-runtime}}), the PDP MUST require an
  acting credential satisfying the mission-credential-bound
  composition of the Mission Binding Properties
  ({{I-D.draft-mcguinness-mission-architecture}}): the
  credential-mission-bound equivalence plus presenter-key-bound
  possession, end to end; a Join Assertion does not satisfy it, and
  absence denies rather than falling back to a mapping or asserted
  join.
  - Where the Mission Issuance Grant
    ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) is the
    issuance path for such a class, the grant MUST carry `cnf` and
    redemption MUST produce an access token sender-constrained to
    that same key. The issuance upgrade thus opens no bearer interval
    between grant and action, and this profile defines no rotation
    exception.
  - Mission-bound issuance restores the issuance gate; it does not
    replace this profile's runtime active-freshness check for these
    classes.
  - When a client legitimately holds credentials for several
    Missions, issuance does not prove that a particular work item was
    supposed to run under the selected Mission. Work-item attribution
    stays with the reference propagation channel and the
    `work-item-bound` property.
  - The Enterprise claim is made per covered Authorization Server,
    resource, and action path; a mixed estate's weaker paths never
    inherit it from the deployment's name.
- **Instance-bound joins.** Where the acting credential carries
  Instance Context ({{I-D.draft-mcguinness-oauth-client-instance-id}})
  whose association with the presenter is established as
  {{mission-join}} describes, a high-consequence join MUST bind
  (`subject`, `client`, `instance`), not (`subject`, `client`), so a
  single workload joins rather than every workload sharing a gateway
  `client_id`. Client-instance identity rests on an unratified
  individual draft ({{I-D.draft-mcguinness-oauth-client-instance-id}}).
  Where a deployment has no instance-identity substrate, the
  high-consequence join binds only (`subject`, `client`), and the
  shared-`client_id` residual of {{join-spoofing}} remains, stated in
  the Mission Deployment Profile's `residual_risks`.
- **Runtime enforcement.** Consequential actions MUST be enforced
  under the runtime profile and its AuthZEN binding
  ({{I-D.draft-mcguinness-mission-authzen}}), with documented PEP
  coverage published in the runtime profile's Enforcement Scope
  Statement.
- **Audit evidence.** Joins and decisions MUST produce runtime
  evidence retained for the audit horizon
  ({{I-D.draft-mcguinness-mission-runtime}}).
- **Approval governance.** Where a recording trigger of Mission
  Approval Governance
  ({{I-D.draft-mcguinness-mission-approval-governance}}) holds for an
  approval event, the MAS MUST record the Approval Governance Record,
  committed atomically with the Mission's creation and retained for
  its audit horizon. That document defines the triggers: the Approver
  differs from the Subject, more than one principal contributes, a
  non-human assertion contributes, a threshold, veto, or
  separation-of-duty rule is evaluated, or validating an assertion
  requires authority standing outside the Mission record. The Mission
  record still carries
  exactly one accountable `approver`, the only principal any
  projection or enforcement consumes. Direct self-approval by one
  authenticated human remains the degenerate case, which the Mission
  record represents completely.

The Join Assertion obligation is what distinguishes this profile from
the conformance floor, whose join is the mapping join
({{mission-join}}). The Join Assertion centralizes subject and client
mapping at the MAS, binds the proof to one token digest and key
thumbprint, and produces audit evidence rather than leaving each PDP
to maintain mapping tables.

A deployment claiming this profile SHOULD publish its claims,
coverage, and residual risks as a Mission Deployment Profile
({{I-D.draft-mcguinness-mission-architecture}}).

## High-Consequence Binding {#high-consequence-binding}

The two binding-establishment modes are mutually exclusive per
action, as the runtime profile specifies
({{I-D.draft-mcguinness-mission-runtime}}). A high-consequence path
switches modes rather than layering them. The join algorithm of
{{mission-join}} assumes a credential that cannot identify its
Mission, and it never runs against one that can. For each action, the
PDP:

1. classifies the action under the runtime profile's classes;
2. for a high-consequence path in the declared coverage set, requires
   and validates a Mission-bound acting credential per the issuance
   obligation above; a mapping or asserted join never substitutes;
3. establishes the Mission from that credential's authenticated
   `mission` claim, never from an external selection;
4. where a propagated Mission-Reference is also present, requires
   exact equality of its issuer and Mission identifier with the
   credential's `mission` claim, and, where both convey
   `authority_hash`, a consistent value too, denying on any mismatch;
5. applies current Mission state, current authority, the subject,
   client, and actor checks, and the sender proof, as elsewhere in
   this profile; and
6. never uses a Join Assertion or a mapping join to select a
   different Mission than the credential's own: with concurrent
   Missions for one subject and client, the credential's `mission`
   claim is the binding, and nothing re-points it.

## Estate Prerequisites {#enterprise-prerequisites}

The profile's mandatory path runs through the deployment's unchanged
Authorization Server and assumes capabilities there. They require
configuration rather than code, but they are prerequisites. Before
claiming the profile, a deployment confirms that its estate AS
provides:

- **Token introspection or validatable JWT access tokens.**
  {{RFC7662}} introspection reachable by the MAS, under credentials the
  deployment protects ({{sec-join-assertion}}), or JWT access tokens
  the MAS can validate locally under {{RFC9068}}. The MAS cannot mint
  a Join Assertion for a token it can neither introspect nor validate
  ({{join-assertion-request}}).
- **Sender-constrained issuance.** DPoP-bound or mutual-TLS-bound
  access tokens for the agent clients acting in the high-consequence
  classes. The join requires sender-constraint for those classes
  ({{mission-join}}), and the MAS MUST NOT mint an assertion for a
  token without a `cnf` key ({{join-assertion-request}}).
- **`cnf` in introspection or token claims.** Introspection responses,
  or validated JWT claims, that report the token's `cnf` confirmation,
  since the assertion binds the key thumbprint they report.

An estate whose Authorization Server cannot provide these capabilities
still joins under the mapping join at the conformance floor
({{mission-join}}, {{conformance}}), but it does not claim this
profile.

The digest pair of {{join-assertion-request}} also assumes an
introspection surface that resolves a token by digest. Mainstream
Authorization Servers do not provide one, so a deployment plans for
the `access_token` form.

## The Enterprise Mapping Contract {#mapping-contract}

A join can be coarse or can drift: shared `client_id` values,
many-to-one directory mappings, and workload identity that the join
collapses ({{join-spoofing}}). An enterprise MAS MUST publish a
mapping contract stating, for the joins it performs:

- the subject namespace mapping (how a credential's authenticated
  subject maps to the Mission's `subject`);
- the client namespace mapping (how a credential's client maps to the
  Mission's `client_id`);
- the delegate policy applied to `act`-chain actors, which MUST state
  how the OAuth binding's per-entry `delegation` rules are
  evaluated at the join;
- whether client-instance identity is supported and required;
- a mapping version identifier, so a mapping change is detectable;
- an audit record for each mapping decision; and
- the failure semantics, which MUST fail closed with `mission_mismatch`
  on any unresolved or ambiguous mapping.

A MAS that mints Join Assertions SHOULD carry the version in each
assertion's `mapping_version` claim ({{join-assertion-artifact}}), so
a mapping change is attributable in join evidence, not only
detectable in documents.

## Policy View Distribution {#policy-distribution}

An enterprise MAS MAY serve audience-scoped Authority Set views, or
the runtime profile's materialized policy view
({{I-D.draft-mcguinness-mission-runtime}}), to the PDPs that enforce
for each audience, rather than each PDP resolving full Mission state
per action. In doing so, the MAS distributes bounded, audience-scoped
authority derived from the Mission, not tokens. The MAS serves the
view under the Mission Status operation's authentication and
anti-oracle rules. The view carries the Mission's `authority_hash` as
its consent anchor and does not widen authority beyond the Authority
Set.

# Conformance {#conformance}

An implementation conforms in one of three roles.

A **Mission Authority Server**:

- serves the mission submission endpoint with the validation,
  media-type dispatch, error, and anti-oracle rules of
  {{mission-submission}};
- executes the approval event of {{mission-approval}}, creating the
  Mission record `active` atomically with the approval decision;
- records Missions per the OAuth binding's Mission Record section
  and retains each record for the audit horizon;
- serves the Mission Status operation and the Mission Lifecycle
  endpoint with its full operation set (`revoke`, `suspend`, `resume`,
  `complete`) per {{lifecycle-and-state}};
- publishes the discovery document of {{discovery}} with every
  REQUIRED member; and
- issues no token and no artifact that grants access by possession:
  `submission_id` and `mission_id` are references.

**Expansion and Child Creation** ({{native-surfaces}}) is a named
OPTIONAL capability of the Mission Authority Server role. A MAS
claiming it additionally:

- accepts the `predecessor`, `parent`, and `child_actor` submission
  members, with the dispatch and refusal rules of {{native-carriage}};
- verifies the binding of {{native-binding}} before adjudicating: the
  authenticated submitting client equals the predecessor's or parent's
  recorded `client_id`, and, for expansion, the established Subject
  equals the predecessor's `subject`;
- applies the expansion profile's rules by reference: predecessor
  active, reconciliation serialization, supersession atomicity, and
  the lineage members ({{native-expansion}});
- applies the child-delegation profile's rules by reference: the
  `children` on-switch, strict subset, fan-out accounting, `parent`
  construction, cascade, and child client identity ({{native-child}});
  and
- carries the profiles' closed code sets, reconciliation statuses in
  `mission_expansion_status` and adjudication denial reasons in the
  shared `mission_denial_reason` member, on its error and
  submission-status surfaces ({{native-carriage}}).

**Join Assertion** ({{join-assertion}}) is a named optional
capability of the Mission Authority Server role, which the Enterprise
profile requires. A MAS claiming it serves the join-assertion
endpoint under {{join-assertion-request}} and mints assertions per
{{join-assertion-artifact}}. A Mission-joining PDP that accepts
assertions verifies them per {{join-assertion-pdp}}.

A **Mission-joining PDP**:

- resolves referenced Missions at the MAS through the Mission Status
  operation and treats the MAS as its Mission state source under the
  runtime profile's freshness rules ({{mission-join}});
- verifies the subject join and the client join before evaluating
  authority, and denies with `mission_mismatch` on any join failure;
- for a high-consequence path under the Enterprise profile, requires
  the mission-credential-bound acting credential and denies on its
  absence, never falling back to a mapping or asserted join
  ({{enterprise-profile}});
- evaluates joined actions under the runtime profile's decision
  contract, drawing authority from the Mission; and
- when the AuthZEN binding is in use, emits Decision Evidence per
  {{I-D.draft-mcguinness-mission-runtime-evidence}}, recording the
  Mission reference the join was verified against.

A **Mission-joining PEP**:

- supplies the Mission reference for governed work from its Mission
  binding, deployment configuration, or a propagated reference
  (rule 1 of {{join-rules}}, {{reference-propagation}});
- authenticates the acting credential and populates the decision
  request from it ({{join-scope}}), validating the presenter's
  Instance Context where the mapping contract requires an
  instance-bound join ({{join-instance}});
- parses `Mission-Reference` and the MCP `_meta` key under
  {{mission-reference-field}} and {{mcp-reference}}, and surfaces a
  reference conflict with `mission_reference_conflict`
  ({{reference-verification}});
- never treats a Mission permit as overriding what the credential or
  the resource would refuse (rule 8 of {{join-rules}}); and
- does not copy the reference onto a request to an unrelated
  authority domain ({{reference-forwarding}}).

A deployment claiming the **Enterprise Mission Authority Profile**
meets {{enterprise-profile}} over its declared coverage set; its MAS,
PDPs, and PEPs conform in their roles above with that section's
additional obligations.

# Mission Substrate Statement {#mission-substrate}

This Statement applies to the standalone MAS binding defined by this
document and declares conformance to
{{I-D.draft-mcguinness-mission-substrate}}.

The contextual-governance kernel maps as follows:

1. **Mission Reference**: the tuple (`issuer`, `mission_id`) names one
   Mission. The MAS issuer URL is the uniqueness namespace;
   `mission_id` follows the OAuth binding's comparison, retention,
   entropy, and non-reassignment rules.
2. **Controller**: the MAS controls approval, Mission state, and the
   governance record. Consumers establish its identity and keys from
   the MAS discovery document ({{discovery}}).
3. **Actor binding**: the authenticated submitting client is the
   Actor, recorded as `client_id`; the MAS establishes the Subject
   separately during approval. Later action decisions establish the
   Actor and Subject through the Mission Join, including the mapping
   assurance and ambiguity the deployment declares
   ({{mission-approval}}, {{mission-join}}).
4. **Approved Context**: the Mission Intent, the recorded authority
   proposal where one was submitted, and the derived Authority Set in
   the immutable Mission record are the Approved Context. This
   binding's chosen commitments are the OAuth binding's `intent_hash`
   and `authority_hash`, computed with the MAS issuer URL, plus
   `proposal_hash` where a proposal was submitted; they are not
   substrate-kernel requirements.
5. **Approval ceremony**: the asynchronous MAS approval surface
   authenticates the Approver, establishes the Subject and Actor,
   renders the derived authority, computes the commitments, and
   creates the record `active` atomically with approval
   ({{mission-approval}}).
6. **Governance gate**: only `active` permits a positive MAS decision;
   every other or unrecognized state fails closed. The lifecycle
   endpoint supplies authenticated transitions, including revocation
   by the authorized parties ({{lifecycle-and-state}}).
7. **Reliance bound**: a positive MAS decision requires current
   `active` state at decision time. Standing artifacts carry their own
   bounds: a signed Mission Status is relied on within its declared
   freshness window ({{lifecycle-and-state}}), and a Join Assertion
   within the acting token's remaining lifetime ({{join-assertion}}).
   Tokens of the unchanged Authorization Server are not represented as
   Mission-governed artifacts.
8. **Context propagation**: submission status and signed Mission
   Status responses carry the Mission Reference. A Mission-joining PDP
   verifies the reference against the acting credential before using
   Mission authority. That join establishes correlation, not that the
   unchanged Authorization Server issued the credential under the
   Mission ({{mission-reference}}, {{mission-join}}).
9. **Governance record**: the MAS audit log is the ordered governance
   record. The MAS MUST append approval, positive and negative
   Mission-dependent decisions, join decisions it makes, and lifecycle
   transitions in per-Mission append order; MUST protect the log under
   the same integrity and access controls as the Mission record; and
   MUST retain both for the declared audit horizon.

The capability table has one row per capability. Every supplied row
states its activation conditions, and states its temporal and failure
elements in its cells or by express inheritance of the Bounded
Reliance floor ({{I-D.draft-mcguinness-mission-substrate}}).

| Capability | Claim | Activation | Scope and defining sections | Limitations |
| --- | --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supplied | always for MAS-native authority operations; a Mission-joining PDP for joined decisions | A current-state check at each such operation or decision ({{lifecycle-and-state}}, {{mission-join}}) | The unchanged Authorization Server gates neither issuance nor refresh; the token-layer residual runs to expiry |
| State-Observable | supplied | always | Signed Mission Status with the `mission_max_stale_seconds` bound ({{lifecycle-and-state}}, {{discovery}}) | Consumers fail closed past the declared freshness bound |
| Structured Authority | supplied | always | The OAuth binding's Authority Set, held at the MAS and evaluated at the joining PDP ({{mission-join}}) | Semantics cover only declared authority-detail types and mappings |
| Monotonic Derivation | supplied | native child creation ({{native-child}}) | The no-broader-than relation at child creation | Enforcement and expansion are never derivation; unchanged AS tokens are outside the claim |
| Credential-Bound | supplied | the Join Assertion endpoint ({{join-assertion}}) | A signed assertion binds one token's digest and `cnf` thumbprint to the Mission; fact semantics: verified party correlation | Does not prove the Authorization Server issued the token under the Mission; mapping-join-only deployments are outside this row |
| Authorized Context Correlation | supplied | always | The mapping join and the Join Assertion, with the MAS and its joining PDPs as joining authority ({{mission-join}}, {{join-assertion}}) | Proves the credential belongs to the Mission's parties, never that it was issued for the Mission ({{join-scope}}) |
| Independently Verifiable | supplied | signed Mission Status ({{lifecycle-and-state}}) | Record and state as of the response's freshness window; Join Assertions add token correlation | Proves neither AS issuance under the Mission nor current state after the observation window |
| Portable Evidence | supplied | Consent Evidence, a Mission Mandate, or Audit Transparency adopted | The adopted profile's artifact and verification procedure | The base MAS audit log is Controller-local |
{: title="Standalone MAS Mission substrate capabilities"}

Unless a row states otherwise, each supplied row's temporal elements
inherit the signed Status freshness contract: facts are current as of
the response's `mission_max_stale_seconds` window, assertion lifetime
is capped by the introspected token's remaining lifetime, and the
residual after non-active is bounded by the consumer's declared
staleness bound.

Failure behavior is uniformly fail-closed. An unresolvable Mission, a
stale or failed Status response, a join failure (`mission_mismatch`,
never a fallback), an unknown or malformed authority-detail type, and
an incomparable or invalid constraint each refuse the evaluation
rather than comparing best-effort. A Join Assertion that fails
validation is an absent assertion, never a downgrade to an unverified
join.

The following qualifications apply to individual rows:

- Structured Authority includes each supported type's own constraint
  vocabulary; for `mission_resource_access`, that vocabulary is the
  Mission Resource Access Profile's Common Constraints.
- Monotonic Derivation covers native child creation only. PDP action
  evaluation is enforcement, never derivation; a separately approved
  expansion is a fresh approval ({{native-expansion}}); and tokens of
  the unchanged AS are outside the claim.
- For Authorized Context Correlation, the MAS and its joining PDPs
  are the joining authority under the enterprise mapping contract
  ({{mapping-contract}}), joining the introspected credential, the
  subject and client mappings, and the Mission. The bare mapping join
  carries the (`subject`, `client`) equivalence-class ambiguity, and
  substitution protection requires the `cnf`-bound Join Assertion
  ({{join-spoofing}}).
- Portable Evidence is supplied only when the deployment adopts
  Consent Evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), a Mission
  Mandate ({{I-D.draft-mcguinness-mission-mandate}}), or Audit
  Transparency ({{I-D.draft-mcguinness-mission-audit}}). The
  referenced profile defines the portable artifact and verification
  procedure; the base MAS audit log is not portable evidence.

These claims have the following composition consequences:

- Shaping, consent evidence, audit transparency, the security model,
  status, and signals compose with the capabilities they name. Where
  such a profile names the Mission Issuer or issuer AS, the MAS is that
  party.
- The runtime profile and its AuthZEN binding, the harness, and
  orchestration compose through the runtime profile's externally
  established binding mode
  ({{I-D.draft-mcguinness-mission-runtime}}), profiled here as the
  Mission Join ({{mission-join}}).
- Offline attenuation does not apply in MAS-only mode because no
  Mission-bound credential or offline-minting chain exists
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}). The
  token-carriage aspects of delegation likewise have no carrier.
- On the OAuth wire, Mission Expansion
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}) and Mission Child
  Delegation ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})
  bind their request to an {{RFC8693}} token exchange whose
  `subject_token` is the predecessor or parent Mission-bound access
  token. {{native-surfaces}} defines their MAS-native wire, which
  carries both operations on the mission submission endpoint with an
  authenticated-client binding in place of that token-exchange
  possession proof. Their models (supersession, lineage, cascade)
  apply to MAS-held Missions unchanged.

# Security Considerations

The security considerations of the OAuth binding
({{I-D.draft-mcguinness-oauth-mission}}), Mission Status
({{I-D.draft-mcguinness-oauth-mission-status}}), and the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}) apply to this
document. This section covers what the standalone binding adds.

## Join Spoofing {#join-spoofing}

A client cannot gain authority by asserting another party's
`mission_id`. The join requires the subject and client that the PEP
authenticates from the credential to match the values the MAS
recorded at approval, which the client cannot alter. A reference to
someone else's Mission therefore fails with `mission_mismatch`. Four
residuals remain:

- **Mapping coarseness.** Where the deployment's account mapping is
  many-to-one (several AS accounts map to one directory subject), any
  credential in the equivalence class joins. A deployment SHOULD keep
  the mapping one-to-one for subjects that hold Missions, with the
  granularity recorded in its mapping contract ({{mapping-contract}}).
  The client join is coarse in the same way where several workloads
  share one `client_id`: any of them joins. Client instance
  identification ({{I-D.draft-mcguinness-oauth-client-instance-id}})
  addresses this: the join then binds the validated instance
  ({{mission-join}}), and this residual remains only for deployments
  without instance identity.
- **Same-party misattribution.** Two Missions held by the same subject
  and client are distinguished only by the PEP-supplied reference. A
  faulty or compromised PEP can therefore attribute work to the wrong
  same-party Mission, bounded by that Mission's authority and visible
  in evidence.
- **Bearer possession.** With a pure bearer token, possession alone
  presents the credential, so any holder inside the (subject, client)
  equivalence class joins. For this reason {{mission-join}} requires
  sender-constraint for the high-consequence classes.
- **Same-party self-selection.** The propagation channel
  ({{reference-propagation}}) lets the requesting side name the
  Mission. An agent whose subject and client join more than one
  active Mission therefore chooses which one a request runs under.
  This is a confused-deputy pattern (least-restrictive-Mission
  selection), not merely spoofing. The join bounds the choice to
  Missions whose parties match, and each chosen Mission's own
  authority bounds what the choice yields. The party that attaches
  the reference bounds it further: the strong form is a trusted
  harness attaching from its recorded binding, or a Mission Join
  Assertion presented alongside. The Enforcement Scope Statement
  records the attachment provenance.

The Mission Join Assertion ({{join-assertion}}) mitigates the
coarse-mapping and shared-client residuals. The MAS evaluates the
mapping once, centrally, under its documented policy, and binds the
result to one introspected token by digest and key thumbprint. The
join then stops being a standing property of every credential in an
equivalence class and becomes a minted, audited, token-bound event.

## Join Assertion Trust {#sec-join-assertion}

A captured Join Assertion moves no authority. It names one token by
digest and key thumbprint, so a replay without that token and its
sender-constraint key proves nothing. The `exp` claim, capped at the
token's remaining lifetime, bounds the window in which the proof is
live.

The introspection call creates a trust relationship specific to this
upgrade. The MAS relies on the deployment's AS for the token's
validity, subject, and client, through RFC 7662 introspection or, for
JWT access tokens, local RFC 9068 validation of the AS-issued token.
The deployment documents that reliance and protects the MAS's
introspection credentials accordingly.

The assertion concentrates the join: the subject and client mappings
are evaluated at one audited point under one documented policy,
instead of configured independently at N PDPs, where one drifted
table silently widens the join.

## Expansion and Child-Creation Binding {#sec-native-binding}

The native surfaces of {{native-surfaces}} bind a request to its
predecessor or parent by authenticated client identity, not by the
token-exchange possession proof of the OAuth wire. The residual is
exactly that difference. A compromised or impersonated registered
client can request expansion or child creation for any Mission
recorded under its `client_id`; proving possession of the
Mission-bound access token would have limited it to the Missions
whose token it holds and can prove control of. The mitigations are:

- Instance-grade binding
  ({{I-D.draft-mcguinness-oauth-client-instance-id}}) narrows the
  `client_id` equivalence class to one runtime instance, and a Mission
  Join Assertion presented with the submission makes that instance a
  verified, token-bound party ({{native-binding}}).
- The expansion profile's fresh-approval requirement means no widening
  activates without the Approver, so a forged expansion request yields
  an approval prompt, not authority.
- The child-delegation profile's fan-out controls bound what child
  creation can amplify.
- The binding failure surface is anti-oracle ({{native-carriage}}), so
  a request against a Mission the client is not bound to is
  indistinguishable from one against a Mission that does not exist.

## Ambient Authority of Ungated Tokens

The central residual of this mode is that tokens are ordinary OAuth
tokens. Within their lifetime and scope they work wherever PEP
coverage is absent, and Mission revocation does not touch them.
Mitigations are short token lifetimes at the AS, narrow scope hygiene
for agent clients, and complete PEP coverage of consequential paths.
None eliminates the residual; only the OAuth binding's gating removes
it ({{limitations}}).

## MAS Availability

The runtime layer fails closed when Mission state cannot be
established within the staleness bound. A MAS outage therefore
becomes work stoppage for governed actions, not loosened enforcement,
which is the availability trade-off the security model states
({{I-D.draft-mcguinness-mission-security-model}}). A deployment
provisions MAS availability accordingly and sizes
`mission_max_stale_seconds` to the caching it can tolerate. The
Operational Considerations of the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}) and of Mission Status
({{I-D.draft-mcguinness-oauth-mission-status}}) describe
dependency-specific outage effects, remaining-window ride-through, and
recovery observations.

## Signing-Key Custody

The MAS's signing key is the estate's Mission root of trust. It signs
status and lifecycle responses, Join Assertions, and the issuer-signed
artifacts of the companions. A MAS SHOULD hold the key in a
non-exportable keystore (an HSM or equivalent KMS-grade custody) with
dual-controlled generation. A MAS SHOULD sign high-volume surfaces
(status, Join Assertions) and long-lived artifacts (Mandates, Issuance
Grants) under distinct `kid`s in one `jwks_uri`, so custody can follow
the consequence of each key's compromise.

The introspection credential that the MAS holds at the estate AS
({{join-assertion-request}}) is secret material of the same tier: its
compromise allows forged joins
({{I-D.draft-mcguinness-mission-security-model}}).

## MAS Compromise

Compromise of a MAS is equivalent to Mission Issuer compromise: a
compromised MAS can forge approvals, alter records, and report false
state. One consequence is specific to this mode. The PDP join is the
only credential-to-Mission binding, so a compromised MAS, combined
with the PDP's trust in it, yields arbitrary attribution of authority
to any credential the join accepts. Consent Evidence commitments
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) and audit
transparency ({{I-D.draft-mcguinness-mission-audit}}) make forgery
detectable after the fact. Signing-key custody and the status
profile's key-retention rules keep archived state evidence
verifiable.

## Approval Surface Authentication

The MAS's review surface is the approval event surface, and the
OAuth binding's approval rules apply to it unchanged
({{mission-approval}}). The Approver is authenticated to the `acr`
mapping, the Subject is never taken from client input, client text is
rendered inert, and derived authority is visually distinguished from
client text. The submission, status, and lifecycle endpoints reject
unauthenticated callers and preserve the anti-oracle property
({{I-D.draft-mcguinness-oauth-mission-status}}).

# Privacy Considerations

The privacy considerations of the OAuth binding
({{I-D.draft-mcguinness-oauth-mission}}), Mission Status
({{I-D.draft-mcguinness-oauth-mission-status}}), and the runtime
profile ({{I-D.draft-mcguinness-mission-runtime}}) apply to this
document. This section covers what the standalone binding adds.

A MAS holds task data centrally: every governed Mission Intent (goals,
constraints, purposes) and every Mission record, outside the AS that
holds the deployment's identity data. The OAuth binding's
minimization guidance applies: collect only the Intent members the
task needs, audience-filter every disclosure surface per the status
profile's rules, and treat submission, status, and lifecycle logs as
PII sinks.

Retention is anchored on the OAuth binding's audit horizon. A MAS
retains records at least that long and SHOULD NOT retain them
materially longer without a documented basis.

# IANA Considerations {#iana}

## HTTP Field Name Registration

IANA is requested to register the following in the "Hypertext
Transfer Protocol (HTTP) Field Name" registry ({{RFC9110}}):

- Field Name: Mission-Reference
- Status: permanent
- Structured Type: Dictionary
- Reference: this document, {{mission-reference-field}}
- Comments: none

## Well-Known URI Registration

IANA is requested to register the following in the "Well-Known URIs"
registry {{RFC8615}}:

- URI Suffix: `mission-authority-server`
- Change Controller: IETF
- Specification Document: this document, {{discovery}}
- Status: permanent
- Related Information: none

## Mission Authority Server Metadata Registry

IANA is requested to create the "Mission Authority Server Metadata"
registry. The registration policy is
Specification Required {{RFC8126}}. A Designated Expert reviews a
submission for: a Metadata Name following the metadata naming
conventions of {{discovery}} and not already registered; a definition
precise enough that a client can consume the member from its
specification alone; and no overlap with an existing member's
semantics (a refinement belongs in the defining specification, not a
parallel member). Registration does not require IETF review or a
Standards Track document.

Each entry has the fields of the
registration template in Section 7.1.1 of {{RFC8414}}: Metadata Name,
Metadata Description, Change Controller, and Specification
Document(s). The registry is seeded with the members of
{{discovery}}; for each, the Metadata Description is the member's
definition there, the Change Controller is IETF, and the
Specification Document is this document:

- `issuer`
- `mission_submission_endpoint`
- `mission_submission_endpoint_auth_methods_supported`
- `mission_submission_endpoint_auth_signing_alg_values_supported`
- `mission_status_endpoint`
- `mission_status_endpoint_auth_methods_supported`
- `mission_status_endpoint_auth_signing_alg_values_supported`
- `mission_status_signing_alg_values_supported`
- `mission_lifecycle_endpoint`
- `mission_lifecycle_endpoint_auth_methods_supported`
- `mission_lifecycle_endpoint_auth_signing_alg_values_supported`
- `mission_join_assertion_endpoint`
- `mission_event_stream_endpoint`
- `mission_max_stale_seconds`
- `jwks_uri`

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### Mission Join Assertion Media Type

- Type name: application
- Subtype name: mission-join+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{sec-join-assertion}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission Authority Server
  deployments and PDPs consuming Mission Join Assertions
- Fragment identifier considerations: not applicable
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): none
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

## Runtime Denial Reasons

`mission_mismatch` and `mission_reference_conflict` extend the
denial-reason set of {{I-D.draft-mcguinness-mission-authzen}} under
that profile's denial-reason extensibility rule ({{mission-join}},
{{reference-verification}}). That profile's denial reasons are AuthZEN
extension data and are not registered in an IETF registry, so this
document requests no IANA action for them.

--- back

# Deployment Guidance {#deployment}

This appendix is non-normative. It shows where a MAS sits in an
estate and how a deployment adopts it incrementally.

## Topology {#deployment-topology}

A typical MAS deployment runs the MAS beside the existing identity
provider and Authorization Server, changing neither:

- the MAS records Missions, runs approvals, operates the lifecycle,
  and signs Mission Status;
- a PEP at the enforcement boundary (an API gateway, a service-mesh
  sidecar, an MCP or tool gateway, a SaaS connector, a workflow
  orchestrator, or a legacy-API wrapper) presents the Mission
  reference and calls a PDP before each consequential action;
- the PDP runs the runtime profile's decision contract and its
  AuthZEN binding, drawing authority from the MAS-served Authority Set
  or a materialized policy view ({{policy-distribution}});
- the MAS mints a Join Assertion after introspecting the presented
  token, so the PDP verifies one signed proof rather than a mapping
  table; and
- runtime decision and execution evidence flows to the deployment's
  audit sink.

Which Mission Issuer governs a given resource is explicit deployment
configuration. Where more than one Mission Issuer operates, the
deployment documents the resource-to-issuer mapping alongside its
mapping contract, and a PEP treats a resource with no mapped issuer
as outside the governance this document defines rather than inventing
an issuer.

## Connector Patterns {#deployment-connectors}

A PEP sits wherever consequential effects can be refused before they
happen. Common placements, all non-normative:

- **API gateway PEP**: refuses at the gateway in front of a protected
  API.
- **Service-mesh sidecar PEP**: refuses at the sidecar for
  service-to-service calls.
- **SaaS connector PEP**: refuses in the connector mediating a SaaS
  API.
- **MCP or tool-server PEP**: refuses at the tool boundary an agent
  invokes.
- **Workflow or orchestrator PEP**: refuses at the step boundary of a
  governed workflow.
- **Legacy-API wrapper PEP**: refuses in a wrapper fronting a system
  that cannot itself enforce.

Each placement is credible only to the extent it has no unmediated
bypass. The runtime profile's Enforcement Scope Statement states that
coverage ({{I-D.draft-mcguinness-mission-runtime}}).

## Progressive Adoption {#deployment-adoption}

A MAS deployment adopts the Mission Assurance Levels in the order
deployments build them ({{I-D.draft-mcguinness-mission-architecture}}).
The levels are adoption bundles, not a ladder, and each phase is
independently useful.

The six phases group into three modes, and a deployment's claim is
bounded by its mode. **Records mode** (phases 1 and 2) is inventory,
approval, lifecycle, and audit, with no prevention claim of any kind.
**Enforced-paths mode** (phases 3 and 4) prevents on exactly the paths
the Enforcement Scope Statement enumerates and is records mode
everywhere else. **Issuance mode** (phases 5 and 6) restores the
token-layer gate.

"No AS code change" holds in records and enforced-paths modes (phases
1 through 4); what changes is the claim. Issuance mode needs each
consuming AS to redeem Issuance Grants (phase 5) or to become
Mission-aware (phase 6). A high-consequence enforcement claim requires
issuance mode's
machinery or the Estate Prerequisites' AS features
({{enterprise-prerequisites}}), never records alone. The phases are:

1. The MAS records Missions and approvals: governance and audit of
   what tasks were approved, with no enforcement change yet
   (Baseline Issuance under the MAS binding: governance and audit,
   with no kill switch of any kind).
2. Mission Status and lifecycle publish Mission state estate-wide:
   the freshness surface runtime enforcement relies on. Under the MAS
   binding this alone is no kill switch.
3. PEP/PDP runtime enforcement gates consequential actions per the
   runtime profile and, with phase 2's state surface, supplies the
   kill switch (the Runtime-Enforced level).
4. Join Assertions harden the join on joined paths outside the
   high-consequence classes, which the Enterprise profile reserves
   for Mission-bound issuance, and instance-bound joins narrow it to
   one workload (the Enterprise profile, {{enterprise-profile}}).
5. Estate Authorization Servers adopt the issuance join
   ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), redeeming
   MAS-minted grants for Mission-bound, state-gated tokens: the
   token-layer kill switch returns without moving approval into the
   AS.
6. Where a particular AS later becomes natively Mission-aware, it
   adds the OAuth binding's own issuance for its resources, while the
   MAS record, lifecycle, and authority model continue to govern the
   rest of the estate.

A deployment stops at the phase its risk warrants; nothing above the
floor is required to begin. The MAS remains the control plane of the
family's delegated-authority layer
({{I-D.draft-mcguinness-mission-architecture}}) even as individual
Authorization Servers become Mission-aware.

A common starting estate runs bots on standing service accounts with
broad, durable entitlements. Migration is per task, not per account.
Each recurring job becomes a durable Mission whose Authority Set is
derived from the entitlements the job actually exercises, with the
deployment's entitlement catalog as the derivation policy's input.
The service account retains only what no Mission yet governs, and
that shrinking residue is the adoption metric.

# MAS-Mode End-to-End Example {#e2e-example}

This appendix is non-normative. It follows one Mission through the
standalone binding end to end, in the order of {{overview}}. Each
stage points to the example that defines its messages.

## Submit

The client proposes the Mission by POSTing its Mission Intent to the
submission endpoint. The MAS validates it, derives the Authority Set
under policy, and returns a pending-submission reference
({{mission-submission}}). The examples in {{intent-submission}} show
the request and response.

## Poll to Approved

The MAS routes the submission to its approval surface. The Approver
authenticates, reviews the rendered Authority Set, and approves, and
the MAS creates the Mission `active` atomically with the decision
({{mission-approval}}). The client's next poll returns the Mission
reference and its consented authority; the example in
{{mission-reference}} shows the response.

## Join

The agent works under an ordinary OAuth token from the unchanged AS,
which carries no Mission signal. For the first consequential action,
the PEP supplies the Mission reference, with `state` (and
`authority_hash` where the response discloses it) from the MAS's
signed Mission Status response. The PDP verifies the subject and
client joins ({{mission-join}}). The first example in
{{join-authzen}} shows the decision request.

## Permit

The join holds and the action is within the Mission's Authority Set,
so the PDP permits. The PEP executes the call to
`https://erp.example.com`, and both record their evidence
({{I-D.draft-mcguinness-mission-runtime-evidence}}). A revocation at
the MAS stops the next such action at this step, through the runtime
state re-check. The permit example in {{join-authzen}} shows the
decision.

## Revoke

An authorized party revokes the Mission at the Mission Lifecycle
endpoint ({{lifecycle-and-state}}). The agent's token remains valid
OAuth ({{limitations}}). On the agent's next consequential action,
the PDP's state check reports `revoked`, and the PDP denies with the
AuthZEN profile's `mission_inactive` reason
({{I-D.draft-mcguinness-mission-authzen}}). The following example
shows the denial:

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_9tY3sB8zN1eF4jB0K7mQ2sV5rL",
    "denial_reason": "mission_inactive",
    "action_class": "consequential_read",
    "class_source": "resource_floor",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  }
}
~~~

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Reading order. A Protocol Overview with the MAS-mode flow figure
  opens the document. The Mission Join, Reference Propagation, and the
  Join Assertion follow Lifecycle and State; Expansion and Child
  Creation follow them; Metadata follows every endpoint it lists; and
  the Mission Substrate Statement follows Conformance. The Mission Join
  has subsections for its rules, what a join establishes, acting
  credentials, instance-bound joins, and the AuthZEN encoding. Mission
  Reference Delivery is a subsection of Mission Submission; the error
  table names the endpoints that return each code; Terminology defines
  the join vocabulary; Conformance adds the PEP role, the Join
  Assertion capability, and the Enterprise profile; Deployment is an
  appendix; and the end-to-end walkthrough points to the in-body
  examples and adds revocation.

- Corrections. Cross-references name the right sections (the
  propagation tuple's state source, a client-instance section);
  Join Spoofing counts four residuals; IANA names both runtime denial
  reasons; the error table lists `join_failed` and `conflict`; RFC 8414
  and RFC 9396 are normative references, and the metadata registry
  uses the RFC 8414 template; the examples show a DPoP-bound
  Mission-Reference request and classify reads as
  `consequential_read`; Estate Prerequisites name local RFC 9068
  validation; Progressive Adoption follows the architecture's
  Assurance Levels; and "the issuance profile" becomes "the OAuth
  binding" throughout.

- Authentication discovery mirrors the Status draft: per-endpoint
  `*_auth_methods_supported` and `*_auth_signing_alg_values_supported`
  members for the submission, status, and lifecycle endpoints replace
  `mission_auth_methods_supported`, and the submission endpoint accepts
  all three Status mechanisms, including mTLS-bound access tokens. The
  join-assertion endpoint shares the submission methods but names its
  own token audience and Protected Resource Metadata.

- Specify the PEP/PDP responsibilities for required instance-bound joins
  and their refusal behavior. Join Assertions continue to carry no
  instance identifier and do not replace the instance association check;
  MAS evidence distinguishes participation from presenter attribution.

- Client-instance references follow their successors:
  draft-mcguinness-oauth-client-instance-assertion is replaced by
  {I-D.draft-mcguinness-oauth-client-instance-id}, and the
  deprecated draft-mcguinness-oauth-ai-agent-instance is no longer
  cited. The Mission Join binds the
  instance from Instance Context whose association with the presenter is
  established (an instance-unique key, plus authenticated provenance for
  context preserved from an input token) rather than from an `act`
  entry; the Join Assertion carries no
  instance identifier, so an instance-bound join on that path takes the
  instance from the Instance Context the PEP validated, and the MAS
  records the token's Instance Context in its join evidence where it
  received it;
  and the Enterprise instance-bound join applies where the acting
  credential carries validated Instance Context.

- Pointed MAS Availability at the Runtime and Status Operational
  Considerations sections for the dependency-specific outage, ride-through,
  and recovery semantics (#310). No MAS requirement changed.

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work. It profiles the Mission Issuer role for deployments whose
Authorization Server cannot change, and builds on the Mission Status
and Lifecycle, Mission-Bound Runtime Enforcement, and AuthZEN profile
companions.
