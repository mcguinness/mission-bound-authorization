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
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-authority-server.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7519:
  RFC7638:
  RFC7662:
  RFC8259:
  RFC8615:
  RFC9325:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-runtime-latest
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-authzen-latest

informative:
  RFC6749:
  RFC8126:
  RFC8414:
  RFC9635:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-harness-latest
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-security-model.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-security-model-latest
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-consent-evidence-latest
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-approval-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-attenuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-attenuation-latest
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-audit-latest
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-mandate-latest
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-architecture-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 defines the Mission, a
durable, human-approved, integrity-bound authorization artifact, and
binds it to OAuth issuance: the Authorization Server derives tokens
under the Mission and gates them on its state. Many deployments cannot
change their Authorization Server. This document defines the Mission
Authority Server, a standalone service that implements the Mission
Issuer role without being an OAuth Authorization Server: it validates
Mission Intents, runs approval events, records Missions, operates the
Mission lifecycle, and serves Mission state. It derives no tokens.
Access tokens remain ordinary OAuth tokens; a Policy Decision Point
joins each presented credential to its Mission at the point of use and
enforces through the Mission-Bound Runtime Enforcement profile. This
is the standalone binding, the AS-optional
deployment mode: Mission governance and per-action enforcement with no
change to the deployment's Authorization Server, forgoing the
Mission-bound credentials and issuance gating that only the issuance
profile provides.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds
issued authority to a durable, human-approved Mission. Its Mission
Issuer role is played by the OAuth Authorization Server (AS)
{{RFC6749}}: the AS validates the Mission Intent, runs the approval
event, records the Mission, derives Mission-bound tokens, and gates
issuance on Mission state. That binding is the strongest deployment of
the Mission model, and it requires changing the AS.

Many deployments cannot make that change: the AS is a shared or
third-party service, while the need to govern agent tasks is
immediate. This document defines the **Mission Authority Server
(MAS)** for those deployments: a standalone service that implements
the Mission Issuer role of the issuance profile without being an OAuth
Authorization Server. A MAS validates Mission Intents, runs approval
events, records Missions, operates the Mission lifecycle, and serves
Mission state. It derives no tokens, and it requires no change to the
deployment's existing AS.

Because tokens remain ordinary OAuth tokens with no `mission` claim,
the credential-to-Mission association is established at the point of
use instead of traveling in the credential: the Policy Enforcement
Point (PEP) presents the Mission reference explicitly, and the Policy
Decision Point (PDP) joins the credential to the Mission before
evaluating the action ({{mission-join}}). Per-action enforcement then
proceeds under the runtime profile
{{I-D.draft-mcguinness-mission-runtime}} unchanged.

The OAuth binding remains the flagship of the family, and a
deployment that changes its AS gets Mission-bound credentials and
issuance gating, which the MAS mode does not provide
({{limitations}}). The MAS is nonetheless a peer binding, not a
staging area: decoupling governance from token issuance is an
architectural choice some deployments make deliberately and keep. For
deployments that want Mission-bound tokens later, the path is smooth:
the record, anchors, and lifecycle a MAS operates are the issuance
profile's own, so moving issuance into the AS carries them over
unchanged.

## Applicability

This profile targets deployments that need governed, approvable,
revocable agent tasks but cannot extend their Authorization Server,
and that can route consequential actions through the runtime profile's
enforcement. It is also a deliberate architectural choice in its own
right: a deployment MAY prefer a standalone Mission Issuer even where
it controls its AS, to keep governance decoupled from token issuance
or to govern with one Mission Issuer across many Authorization
Servers, accepting the enforcement posture of {{limitations}}. A
deployment that wants Mission-bound tokens and issuance gating
implements the issuance profile; a deployment that cannot deploy runtime
enforcement over its consequential action paths obtains records but no
enforcement from this profile and SHOULD NOT claim it
({{limitations}}).

The Mission Join ({{mission-join}}) is the newest mechanism in the
family and not yet exercised in deployment; a deployment that can
implement the issuance profile obtains the stronger, stable binding.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

This document uses Mission, Mission Intent, Mission Issuer, Authority
Set, Approver, Subject, `mission_id`, the integrity anchors, and the
audit horizon as defined by {{I-D.draft-mcguinness-oauth-mission}};
the Mission Status operation and Mission Lifecycle endpoint as defined
by {{I-D.draft-mcguinness-oauth-mission-status}}; and PEP, PDP,
consequential action, Mission state source, and enforcement scope as
defined by {{I-D.draft-mcguinness-mission-runtime}}. It additionally
uses:

Mission Authority Server (MAS):
: A service that implements the Mission Issuer role of the issuance
  profile without being an OAuth Authorization Server. It is the
  `origin` of the Missions it records, and it derives no tokens.

Mission-joining PDP:
: A PDP that resolves Missions at a MAS and verifies the join between
  a presented credential and the referenced Mission before evaluating
  an action ({{mission-join}}).

Standalone binding:
: This document's deployment mode: the Mission Issuer role implemented
  by a MAS, with the deployment's tokens unchanged. The rest of the
  Mission family cites this mode by this name; "AS-optional" is its
  informal gloss.

# Mission Substrate {#mission-substrate}

The companion profiles of the Mission suite are defined against the
Mission model's substrate primitives rather than against OAuth
mechanics. The issuance profile provides all of them. A MAS provides
these:

- the Mission identifier and `origin`;
- the lifecycle state space with the only-`active` rule and its
  forward-compatibility treatment of unrecognized states;
- the Authority Set representation, with the subset rule and Common
  Constraints;
- the integrity-anchor envelope, computed with the MAS's issuer URL as
  the envelope `iss`; and
- the audit horizon.

Each primitive is the issuance profile's, unchanged
({{I-D.draft-mcguinness-oauth-mission}}); a MAS re-defines none of
them.

A MAS does NOT provide the Mission-bound credential primitive or
issuance gating: no token carries the `mission` claim or
Mission-derived `authorization_details`, and no issuance event is
gated on Mission state.

The composition consequences follow from that split:

- The shaping, consent-evidence, audit-transparency, security-model,
  status, signals, and completion profiles consume only the primitives
  a MAS provides and compose with a MAS unchanged. Where such a
  profile names the Mission Issuer or origin AS, the MAS is that
  party.
- The runtime profile and its AuthZEN binding, the harness, and
  orchestration compose through the runtime profile's Mission binding
  establishment step ({{I-D.draft-mcguinness-mission-runtime}}): their
  Mission Substrate sections mark the Mission-bound credential
  binding-dependent, and this document profiles the step's
  externally established mode as the Mission Join ({{mission-join}}).
- A profile that requires the Mission-bound credential does not apply
  in MAS-only mode: offline attenuation
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}) attenuates a
  credential that does not exist here, and the token-carriage aspects
  of delegation (the `act` chain on Mission-bound tokens) have no
  carrier.
- Mission Expansion ({{I-D.draft-mcguinness-oauth-mission-expansion}})
  and Mission Child Delegation
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) define
  their request wire over OAuth Pushed Authorization Requests, so
  their models (supersession, lineage, cascade) apply to MAS-held
  Missions but their wire does not. A MAS-native expansion request
  surface is deferred to future work. A MAS-native child-creation
  surface is likewise deferred.

# Mission Submission {#mission-submission}

A client proposes a Mission by submitting a Mission Intent to the
MAS's mission submission endpoint, published as
`mission_submission_endpoint` ({{discovery}}). The endpoint MUST be
served over TLS 1.2 or later (TLS 1.3 RECOMMENDED), following the
recommendations of {{RFC9325}}, and MUST authenticate the client using
the authentication mechanisms of the Mission Status endpoint
({{I-D.draft-mcguinness-oauth-mission-status}}): mTLS, DPoP-bound
bearer, or private-key JWT. How clients register with a MAS is
deployment-defined; the identifier the MAS authenticates is recorded
as the Mission's `client_id`.

The endpoint serves two operations, dispatched by request media type:

- **Intent submission**: an HTTPS POST whose `application/json` body
  is the Mission Intent object itself ({{intent-submission}}).
- **Submission status**: an HTTPS POST with an
  `application/x-www-form-urlencoded` body containing a `submission`
  parameter ({{submission-status}}).

## Intent Submission {#intent-submission}

The request body is a Mission Intent as the issuance profile defines
it, and the issuance profile's validation rules apply unchanged
({{I-D.draft-mcguinness-oauth-mission}}): the Intent is untrusted
client input and never authority; the MAS MUST bound its total size
and array lengths; and the Intent is closed at the top level. The
issuance profile's OAuth error outcomes map to this endpoint's error
codes ({{submission-errors}}):

- A body that cannot be parsed as a JSON {{RFC8259}} object, is
  structurally invalid, exceeds the deployment's size bounds, or
  contains a top-level member the issuance profile does not define
  MUST be refused with `invalid_mission_intent` (the MAS equivalent of
  the issuance profile's `invalid_request` rejections, including
  reject-unknown-top-level-member).
- A well-formed Intent from which the MAS cannot derive a valid
  Authority Set under policy MUST be refused with `invalid_authority`
  (the MAS equivalent of `invalid_authorization_details`), so a client
  can distinguish a syntax error from an authority-derivation failure.

On acceptance the MAS derives the Authority Set from the Intent under
the issuance profile's derivation rules
({{I-D.draft-mcguinness-oauth-mission}}) and returns HTTP 202 with a
pending-submission reference:

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

Example:

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "resources": ["https://erp.example.com"],
  "mission_expiry": "2026-12-31T23:59:59Z"
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

The client polls the outcome with a form-urlencoded POST carrying:

`submission`:
: REQUIRED. A string. The `submission_id`.

A submission is in one of four states:

| `status` | Meaning |
|---|---|
| `pending` | Awaiting an approval decision. |
| `approved` | Approved; a Mission exists ({{mission-reference}}). |
| `denied` | Declined by the Approver or refused by policy. Terminal. |
| `expired` | `expires_at` passed undecided. Terminal. |

Only `approved` delivers a Mission: a consumer MUST treat every other
`status` value, recognized or not, as not approved, mirroring the
issuance profile's only-`active` rule. A resolved submission MUST
remain resolvable for a deployment-defined window; the reference is
never reused.

The MAS MUST return submission status only to the authenticated client
that submitted the Intent. For any other caller, and for an unknown
`submission_id`, the MAS MUST return the `not_found` error with an
identical status code, body, and headers, preserving the anti-oracle
property of {{I-D.draft-mcguinness-oauth-mission-status}}.

## Error Responses {#submission-errors}

A hard failure returns the matching HTTP status with a JSON object
body:

`error`:
: REQUIRED. A string. A code from the table below.

`error_description`:
: OPTIONAL. A string. Human-readable detail.

`error_reason`:
: OPTIONAL. A string. A machine-readable refinement of `error`: for
  `invalid_mission_intent`, the name of the offending top-level
  member; for `invalid_authority`, the `resources` entry no authority
  could be derived for. It reflects the client's own input and MUST
  NOT disclose policy internals.

A consumer MUST ignore members it does not recognize.

| `error` | HTTP | Description |
|---|---|---|
| `invalid_mission_intent` | 400 | Unparseable, structurally invalid, oversized, or containing an undefined top-level member. |
| `invalid_authority` | 400 | Well-formed Intent, but no valid Authority Set is derivable under policy. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | Submission reference does not exist OR is not visible. |
| `rate_limited` | 429 | Caller is rate-limited. |
| `unavailable` | 503 | MAS temporarily cannot serve the request. |

# Mission Approval {#mission-approval}

Approval at a MAS is natively asynchronous: there is no authorization
code ceremony, so no approval blocks a front-channel redirect. The MAS
routes each pending submission to its approval surface (a review
application, queue, or policy engine) and resolves it when the
decision is made.

The approval event executes steps 1 through 4 of the issuance
profile's approval event unchanged
({{I-D.draft-mcguinness-oauth-mission}}):

1. Authenticate the Approver; when the Intent's `context.acr` is
   present, the authentication MUST be one the deployment's policy
   maps as satisfying the named class (the issuance profile's `acr`
   mapping rule).
2. Establish the Subject under the issuance profile's rules: the MAS
   MUST itself establish the Subject's (`iss`, `sub`) and MUST NOT
   take it from unauthenticated client input.
3. Render the derived Authority Set for consent with the issuance
   profile's rendering rules applied unchanged: client-supplied
   strings inert, direction-override and confusable presentation
   mitigated, derived authority visually distinguished from client
   text.
4. Compute the integrity anchors, `authority_hash` and `intent_hash`,
   using the issuance profile's envelope with the MAS's issuer URL as
   `iss`.

Step 5 becomes: create the Mission record in the `active` state
atomically with the approval decision. The record is the issuance
profile's Mission Record, member for member; its `origin` is the MAS's
issuer URL and its `approval_event_id` is the approval idempotency
key. There is no authorization code to bind, so the deferred-approval
profile's re-sequencing of this step
({{I-D.draft-mcguinness-oauth-mission-approval}}) is not needed:
deferral is the MAS's native shape.

A declined submission resolves to `denied`. Mission Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) composes
unchanged: the MAS is the committing issuer for any
consent-disclosure commitment.

# Mission Reference Delivery {#mission-reference}

The client learns its `mission_id` from the submission-status response
after approval. When `status` is `approved`, the response additionally
carries:

`mission_id`:
: REQUIRED. A string. The Mission's identifier.

`authorization_details`:
: REQUIRED. An array. The consented Authority Set, so the client
  learns its granted authority here; this response is the MAS
  counterpart of the issuance profile's token-response
  `authorization_details` echo.

Example:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "approved",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "journal-entries.write"],
      "constraints": { "max_amount_usd": "500.00" } }
  ]
}
~~~

`mission_id` remains a reference, never a credential
({{I-D.draft-mcguinness-oauth-mission}}): presenting it authorizes
nothing, and no MAS surface derives authority from possession of it.

# Mission Lifecycle and State {#lifecycle-and-state}

In MAS mode there are no Mission-bound tokens and no token
introspection, so the Mission Status profile's surfaces are the only
way a consumer observes or changes Mission state. A MAS therefore
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

The issuance profile's token-introspection projection does not apply:
there is no token to introspect.

The MAS publishes the corresponding metadata members
(`mission_status_endpoint`,
`mission_status_signing_alg_values_supported`,
`mission_lifecycle_endpoint`, `mission_max_stale_seconds`, and, when
signals are supported, `mission_event_stream_endpoint`) in its
discovery document ({{discovery}}) with the semantics those profiles
define for the members of the same names.

# Mission Discovery {#discovery}

A MAS publishes a metadata document at the well-known URI {{RFC8615}}
path `/.well-known/mission-authority-server`, registered in {{iana}}:
a JSON object served over TLS as `application/json`. Its members
mirror the Mission suite's Authorization Server metadata members where
applicable, so a consumer reads the same member names it would read
from AS metadata {{RFC8414}}, resolved from this document instead:

`issuer`:
: REQUIRED. A string. The MAS's issuer URL. It equals the `origin` of
  every Mission the MAS records and the `iss` of its integrity-anchor
  envelopes and signed status responses. A consumer MUST verify it
  equals the URL the metadata was resolved from, with the well-known
  path removed.

`mission_submission_endpoint`:
: REQUIRED. A string containing a URL. The mission submission endpoint
  ({{mission-submission}}).

`mission_status_endpoint`:
: REQUIRED. A string containing a URL. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_status_signing_alg_values_supported`:
: REQUIRED. A JSON array of strings. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_lifecycle_endpoint`:
: REQUIRED. A string containing a URL. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_auth_methods_supported`:
: REQUIRED. A JSON array of strings. The caller authentication
  mechanisms the MAS accepts at the submission, status, and lifecycle
  endpoints, from the mechanism set of
  {{I-D.draft-mcguinness-oauth-mission-status}}. A value naming a
  client authentication method is an entry of the IANA "OAuth Token
  Endpoint Authentication Methods" registry (`tls_client_auth` for
  mTLS, `private_key_jwt`), following the discovery pattern of the
  {{RFC8414}} `*_endpoint_auth_methods_supported` members. The
  DPoP-bound access token mechanism is token presentation rather than
  client authentication, so no registry entry names it; this document
  uses `dpop_bound_token`.

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

Example:

~~~ json
{
  "issuer": "https://mas.example.com",
  "mission_submission_endpoint":
    "https://mas.example.com/mas/mission/submit",
  "mission_status_endpoint":
    "https://mas.example.com/mas/mission/status",
  "mission_status_signing_alg_values_supported": ["ES256"],
  "mission_lifecycle_endpoint":
    "https://mas.example.com/mas/mission/lifecycle",
  "mission_auth_methods_supported":
    ["dpop_bound_token", "private_key_jwt"],
  "mission_join_assertion_endpoint":
    "https://mas.example.com/mas/mission/join-assertion",
  "mission_max_stale_seconds": 60,
  "jwks_uri": "https://mas.example.com/.well-known/jwks.json"
}
~~~

A consumer holding a Mission reference resolves this document from the
reference's `origin`; whether a given `origin` is a MAS or an OAuth AS
is deployment configuration. The submission and lifecycle surfaces
follow a reference-plus-continuation shape (a request yields an opaque
reference the client continues against) that parallels the grant
continuation pattern of GNAP {{RFC9635}}.

# Mission Join {#mission-join}

In MAS mode the acting access token is an ordinary OAuth token from
the deployment's unchanged AS: it carries no `mission` claim and no
Mission-derived `authorization_details`, so it cannot identify its
Mission. The PEP names the Mission explicitly, and the PDP joins the
credential to it before evaluating the action. The join is this
profile's load-bearing mechanism: it is what a permit "under this
Mission" rests on when no cryptographic binding exists.

A Mission-joining PDP and its PEPs MUST observe the following:

1. **The PEP supplies the Mission reference.** For governed work the
   PEP MUST supply the `mission_id` and `origin` of the Mission the
   work is bound to, taken from its Mission binding (a Mission-aware
   harness records exactly this,
   {{I-D.draft-mcguinness-mission-harness}}) or from deployment
   configuration. In the AuthZEN binding
   ({{I-D.draft-mcguinness-mission-authzen}}) this is
   `context.mission`; the PEP populates `authority_hash` and `state`
   from the MAS's signed Mission Status response.
2. **The PDP resolves the Mission at the MAS.** The PDP MUST resolve
   the referenced Mission through the MAS's Mission Status operation
   and MUST treat the MAS as the Mission state source under the
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
   deployment MUST document the client mapping, exactly as for
   subjects.
5. **Join failure is a deny.** A failure of the subject or client join
   MUST be denied with the `mission_mismatch` denial reason. The PDP
   MUST NOT fall back to evaluating the action against the referenced
   Mission's authority when the join fails.
6. **Authority comes from the Mission.** On a successful join, the PDP
   evaluates the action under the runtime profile's decision contract,
   drawing the Authority Set from the Mission (the audience-scoped
   Mission Status response or a materialized policy view), since the
   credential carries none. All other decision inputs and invariants
   of {{I-D.draft-mcguinness-mission-runtime}} apply unchanged.

A successful join, in the AuthZEN binding: the PEP supplies
`context.mission` populated from its Mission binding, with
`authority_hash` and `state` taken from the MAS's signed Mission
Status response, and the other decision inputs per
{{I-D.draft-mcguinness-mission-authzen}}:

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
      "origin": "https://mas.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active"
    }
  }
}
~~~

The credential's authenticated subject and client match the Mission's
`subject.sub` and `client_id`, so the join holds; the PDP evaluates
the action under the Mission's Authority Set and permits:

~~~ json
{
  "decision": true,
  "context": {
    "decision_id": "dec_7mQ2sV5rL9tY3sB8zN1eF4jB0K"
  }
}
~~~

`mission_mismatch`:
: The presented credential does not join to the referenced Mission:
  its authenticated subject or client identifier does not match the
  Mission's `subject.sub` or `client_id` under the deployment's
  documented mapping and delegate policy.

The AuthZEN profile's denial-reason extensibility rule permits a
companion profile to extend the denial-reason set by specification,
and requires a consumer to treat an unrecognized reason as a deny
({{I-D.draft-mcguinness-mission-authzen}}). `mission_mismatch` is such
an extension: where this profile is implemented, it is a member of
that denial-reason set. A consumer that does not implement this
profile treats it as that rule requires: the action stays refused.

Example AuthZEN denial for a credential whose `client_id` does not
match the referenced Mission:

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_2nP4qV9rL3tY6sB1zN0eF7jB8K",
    "denial_reason": "mission_mismatch",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  }
}
~~~

The join proves that the credential belongs to the same subject and
client the Mission names. It does not prove the credential was derived
under the Mission; no MAS-mode mechanism can, because the AS issues
tokens with no knowledge of Missions ({{limitations}},
{{join-spoofing}}). A deployment MAY move the join's verification from
each PDP to the MAS with the Mission Join Assertion
({{join-assertion}}); that upgrade strengthens who verifies the join,
not what the join can prove.

Where the deployment's Authorization Server issues tokens under the
client-instance-assertion profile
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), the acting
credential identifies a concrete runtime instance: the token's `act`
entry carries the instance `sub` and an instance-specific `cnf` key.
The PDP SHOULD include that instance in the join, so the client join
binds (subject, client, instance) rather than (subject, client). This
restores per-instance granularity behind a shared gateway `client_id`:
the validated instance joins, not every workload in the `client_id`
equivalence class.

# Mission Join Assertion {#join-assertion}

The Mission Join of {{mission-join}} rests on subject and client
mapping tables that every PDP operates and keeps correct. This section
defines an OPTIONAL upgrade from mapping-table equality to a
credential-bound proof: the MAS verifies the join centrally and mints
a signed assertion of it, so the PDP verifies one signature and one
token binding instead of operating a mapping table. A MAS that
supports the upgrade publishes its join-assertion endpoint as
`mission_join_assertion_endpoint` ({{discovery}}). The endpoint MUST
meet the TLS and caller-authentication requirements of the mission
submission endpoint ({{mission-submission}}).

## Assertion Request {#join-assertion-request}

The PEP, or the client acting for it, POSTs a JSON object:

`mission_id`:
: REQUIRED. A string. The Mission the join is asserted against; its
  `origin` is the MAS.

`access_token`:
: A string. The acting access token. REQUIRED unless the digest pair
  is present.

`token_sha256`:
: A string. The unpadded base64url SHA-256 digest of the access
  token's ASCII bytes.

`token_jkt`:
: A string. The JWK thumbprint {{RFC7638}}, using SHA-256, of the
  token's `cnf` public key.

The caller presents `access_token`, or `token_sha256` together with
`token_jkt`. The digest pair keeps the credential itself off this
wire, but it is usable only where the deployment's introspection
surface can resolve a token by digest; `access_token` is the
interoperable form. The acting token MUST be sender-constrained: a
token without a `cnf` key gives the assertion nothing to bind, and the
MAS MUST NOT mint one for it.

The MAS verifies the join centrally:

1. It introspects the token at the deployment's Authorization Server
   {{RFC7662}}, under introspection credentials the MAS holds there.
   Calling the AS is permitted in MAS mode; changing it is not. A
   token the AS reports inactive fails the request.
2. It verifies the subject and client joins of {{mission-join}}
   against the introspection response, under its own documented
   account and client mappings and delegate policy.

A token that does not join is refused with the `join_failed` error
(HTTP 403), in the error format of {{submission-errors}}. An unknown
or not-visible `mission_id` returns `not_found`, preserving the
anti-oracle property.

## The Assertion {#join-assertion-artifact}

On success the MAS mints a Mission Join Assertion: a signed JWT
{{RFC7519}} whose protected header carries the `typ`
`mission-join+jwt` and a `kid` resolvable in the MAS's `jwks_uri`. Its
claims:

`iss`:
: REQUIRED. The MAS's issuer URL.

`mission`:
: REQUIRED. An object containing `id`, `origin`, and
  `authority_hash`.

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
: OPTIONAL. The PDP or PDPs the assertion is minted for.

When the introspected token carries instance identity
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), the MAS
SHOULD include the instance identifier in the `token` object: the
`act` entry's `sub`, and the `agent_instance_id` where the agent
profile ({{I-D.draft-mcguinness-oauth-ai-agent-instance}}) is in use.
Under that profile the `cnf` key the `jkt` thumbprint binds is
instance-specific, never shared across a client's instances, so the
assertion's token binding is materially stronger: it names one runtime
instance, not any holder of a client-shared key.

The endpoint returns HTTP 200 with a JSON object whose `assertion`
member carries the JWT. Each minting is a join evidence event: the MAS
records the Mission reference, the token digest and thumbprint, the
authenticated caller, and the validity window, retained for the audit
horizon.

Example claims:

~~~ json
{
  "iss": "https://mas.example.com",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://mas.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "token": {
    "sha256": "rN2kQ4mZ7tP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2n",
    "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  },
  "iat": 1797840000,
  "exp": 1797841800
}
~~~

## PDP Consumption {#join-assertion-pdp}

A PDP presented with a Join Assertion verifies, in place of the
mapping checks of {{mission-join}} steps 3 and 4:

- the signature, under a key from the MAS's `jwks_uri`, and the
  `mission-join+jwt` header `typ`;
- that `iss` and the `mission` claim match the referenced Mission's
  `origin`, `mission_id`, and `authority_hash`;
- that `exp` has not passed and any `aud` names this PDP; and
- the token binding: the presented credential's digest equals
  `token.sha256` and its `cnf` key's thumbprint equals `token.jkt`.

Every other join rule holds unchanged: the PDP resolves Mission state
at the MAS under the runtime profile's freshness rules, denies with
`mission_mismatch` when any check above fails, and draws authority
from the Mission.

For the high-consequence action classes
({{I-D.draft-mcguinness-mission-runtime}}) in MAS mode, the PDP SHOULD
require a Join Assertion. The mapping join of {{mission-join}} remains
the conformance floor: a deployment without the endpoint still joins,
and a PDP MUST NOT treat possession of an assertion as authority,
per the family rule that references and binding proofs grant nothing.

# Limitations {#limitations}

This section states what MAS-only deployment does not provide. These
are structural properties of the mode, not implementation quality
issues, and a deployment claiming this profile MUST NOT overstate
them.

**No Mission-bound credentials.** Tokens carry no `mission` claim and
no Mission-derived `authorization_details`. Nothing cryptographically
binds a token to the approval event, and no audit anchor travels in
credentials: `authority_hash` reaches consumers only through the MAS's
signed status responses and the PDP's evidence, never in the
credential a resource actually accepted. Resource Servers cannot
enforce Mission authority statelessly from the token.

**No issuance gating.** The AS issues and refreshes tokens with no
knowledge of Mission state. Revoking a Mission stops nothing at the
token layer: every outstanding token, and every token the AS issues
after revocation, remains valid OAuth. The Mission kill switch acts
only through the runtime layer's state re-check.

Because both properties are absent, enforcement rests entirely on PEP
coverage. A MAS deployment MUST deploy the runtime profile's
enforcement ({{I-D.draft-mcguinness-mission-runtime}}) over every
consequential action path within the scope it claims Mission
governance for, and the no-unmediated-path condition consolidated by
the security model ({{I-D.draft-mcguinness-mission-security-model}})
is load-bearing for all of this profile's guarantees, not only for the
runtime profile's agent-compromise-resistant tier. A token exercised
outside PEP coverage is ungoverned: its use is bounded by ordinary
OAuth alone, and no Mission property applies to it.

**No delegation or widening surface.** This mode currently has no
specified way to delegate to a sub-agent or to widen authority
mid-task: Mission Expansion and Child Delegation define their request
wire over OAuth Pushed Authorization Requests, and offline attenuation
requires the Mission-bound credential ({{mission-substrate}}).
MAS-native expansion and child creation remain deferred work, so a
standalone deployment whose agents must spawn sub-agents or widen
authority mid-task needs the issuance profile today.

**Upgrade path.** Implementing the issuance profile at the AS restores
what this mode lacks: Mission-bound credentials and issuance gating.
The MAS then serves as the AS's Mission store, or merges into the AS.
The Mission record, the integrity anchors, and the lifecycle carry
over unchanged, because a MAS operates the issuance profile's own
definitions of all three; the enforcement join becomes unnecessary for
newly issued tokens, which carry the `mission` claim.

# Conformance {#conformance}

An implementation conforms in one of two roles.

A **Mission Authority Server**:

- serves the mission submission endpoint with the validation,
  media-type dispatch, error, and anti-oracle rules of
  {{mission-submission}};
- executes the approval event of {{mission-approval}}, creating the
  Mission record `active` atomically with the approval decision;
- records Missions per the issuance profile's Mission Record section
  and retains each record for the audit horizon;
- serves the Mission Status operation and the Mission Lifecycle
  endpoint with its full operation set (`revoke`, `suspend`, `resume`,
  `complete`) per {{lifecycle-and-state}};
- publishes the discovery document of {{discovery}} with every
  REQUIRED member; and
- issues no token and no artifact that grants access by possession:
  `submission_id` and `mission_id` are references.

A **Mission-joining PDP**:

- resolves referenced Missions at the MAS through the Mission Status
  operation and treats the MAS as its Mission state source under the
  runtime profile's freshness rules ({{mission-join}});
- verifies the subject join and the client join before evaluating
  authority, and denies with `mission_mismatch` on any join failure;
- evaluates joined actions under the runtime profile's decision
  contract, drawing authority from the Mission; and
- when the AuthZEN binding is in use, emits Decision Evidence per
  {{I-D.draft-mcguinness-mission-authzen}}, recording the Mission
  reference the join was verified against.

# Security Considerations

## Join Spoofing {#join-spoofing}

A client cannot gain authority by asserting another party's
`mission_id`: the join requires the credential's authenticated subject
and client to match values the MAS recorded at approval, which the
client cannot alter, so a reference to someone else's Mission fails
with `mission_mismatch`. The residual is mapping coarseness. Where the
deployment's account mapping is many-to-one (several AS accounts map
to one directory subject), any credential in the equivalence class
joins; a deployment SHOULD keep the mapping one-to-one for subjects
that hold Missions and MUST document its granularity. The client join
is coarse the same way where several workloads share one `client_id`:
any of them joins. Client instance assertions
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}) are the
standard fix: the join then binds the validated instance
({{mission-join}}), and this residual remains only for deployments
without instance identity. A second residual: two Missions held by
the same subject and client are distinguished only by the PEP-supplied
reference, so a faulty or compromised PEP can attribute work to the
wrong same-party Mission, bounded by that Mission's authority and
visible in evidence.

The Mission Join Assertion ({{join-assertion}}) is the mitigation for
the coarse-mapping and shared-client residuals: the MAS evaluates the
mapping once, centrally, under its documented policy, and binds the
result to one introspected token by digest and key thumbprint, so the
join stops being a standing property of every credential in an
equivalence class and becomes a minted, audited, token-bound event.

## Join Assertion Trust {#sec-join-assertion}

A captured Join Assertion moves no authority: it names one token by
digest and key thumbprint, so a replay without that token and its
sender-constraint key proves nothing, and `exp`, capped at the token's
remaining lifetime, bounds the window in which the proof is live. The
introspection call names a trust relationship specific to this
upgrade: the MAS relies on the deployment's AS, through RFC 7662
introspection, for the token's validity, subject, and client, and the
deployment documents that reliance and protects the MAS's
introspection credentials accordingly. The structural gain is
concentration: the subject and client mappings are evaluated at one
audited point under one documented policy, instead of configured
independently at N PDPs, where one drifted table is a silent join
widening.

## Ambient Authority of Ungated Tokens

The central residual of this mode: tokens are ordinary OAuth tokens,
so within their lifetime and scope they work wherever PEP coverage is
absent, and Mission revocation does not touch them. Mitigations are
short token lifetimes at the AS, narrow scope hygiene for agent
clients, and complete PEP coverage of consequential paths; none
eliminates the residual, which only the issuance profile's gating
removes ({{limitations}}).

## MAS Availability

The runtime layer fails closed when Mission state cannot be
established within the staleness bound, so a MAS outage converts into
work stoppage for governed actions, not into loosened enforcement
(the availability trade the security model states,
{{I-D.draft-mcguinness-mission-security-model}}). A deployment
provisions MAS availability accordingly and sizes
`mission_max_stale_seconds` to the caching it can tolerate.

## MAS Compromise

Compromise of a MAS is equivalent to Mission Issuer compromise: it can
forge approvals, alter records, and report false state. One
consequence is specific to this mode: the PDP join is the only
credential-to-Mission binding, so a compromised MAS combined with the
PDP's trust in it yields arbitrary attribution of authority to any
credential the join accepts. Consent Evidence commitments
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) and audit
transparency ({{I-D.draft-mcguinness-mission-audit}}) make forgery
detectable after the fact; signing-key custody and the status
profile's key-retention rules keep archived state evidence verifiable.

## Approval Surface Authentication

The MAS's review surface is the approval event surface, and the
issuance profile's approval rules apply to it unchanged: the Approver
is authenticated to the `acr` mapping, the Subject is never taken from
client input, client text is rendered inert, and derived authority is
visually distinguished from it ({{mission-approval}}). The submission,
status, and lifecycle endpoints reject unauthenticated callers and
preserve the anti-oracle property
({{I-D.draft-mcguinness-oauth-mission-status}}).

# Privacy Considerations

A MAS holds task data centrally: every governed Mission Intent (goals,
constraints, purposes) and every Mission record, outside the AS that
holds the deployment's identity data. The issuance profile's
minimization guidance applies: collect only the Intent members the
task needs, audience-filter every disclosure surface per the status
profile's rules, and treat submission, status, and lifecycle logs as
PII sinks. Retention is anchored on the issuance profile's audit
horizon: records are retained at least that long, and SHOULD NOT be
retained materially longer without a documented basis.

# IANA Considerations {#iana}

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
registry, with a registration policy of Specification Required
{{RFC8126}}. Each entry has: Member Name, Change Controller, and
Reference. The registry is seeded with the members of {{discovery}};
for each, Change Controller IETF and Reference this document:

- `issuer`
- `mission_submission_endpoint`
- `mission_status_endpoint`
- `mission_status_signing_alg_values_supported`
- `mission_lifecycle_endpoint`
- `mission_auth_methods_supported`
- `mission_join_assertion_endpoint`
- `mission_event_stream_endpoint`
- `mission_max_stale_seconds`
- `jwks_uri`

## Runtime Denial Reason

`mission_mismatch` extends the denial-reason set of
{{I-D.draft-mcguinness-mission-authzen}} under that profile's
denial-reason extensibility rule
({{mission-join}}). That profile's denial reasons are AuthZEN
extension data and are not registered in an IETF registry, so this
document requests no IANA action for it.

--- back

# MAS-Mode End-to-End Example {#e2e-example}

This appendix is non-normative. It stages the standalone binding end
to end on one Mission; the architecture's MAS-mode sequence diagram
shows the same stages in temporal order
({{I-D.draft-mcguinness-mission-architecture}}).

## Submit

The client proposes the Mission by POSTing its Mission Intent to the
submission endpoint; the MAS validates it, derives the Authority Set
under policy, and returns a pending-submission reference
({{mission-submission}}).

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "goal": "Reconcile Q3 invoices and post adjustments under $500.",
  "resources": ["https://erp.example.com"],
  "mission_expiry": "2026-12-31T23:59:59Z"
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

## Poll to Approved

The MAS routes the submission to its approval surface; the Approver
authenticates, reviews the rendered Authority Set, and approves, and
the MAS creates the Mission `active` atomically with the decision
({{mission-approval}}). The client's next poll returns the Mission
reference and its consented authority ({{mission-reference}}).

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "approved",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "journal-entries.write"],
      "constraints": { "max_amount_usd": "500.00" } }
  ]
}
~~~

## Join

The agent works under an ordinary OAuth token from the unchanged AS,
which carries no Mission signal. For the first consequential action,
the PEP supplies the Mission reference, with `authority_hash` and
`state` from the MAS's signed Mission Status response, and the PDP
verifies the subject and client joins ({{mission-join}}).

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
      "origin": "https://mas.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active"
    }
  }
}
~~~

## Permit

The join holds and the action is within the Mission's Authority Set,
so the PDP permits; the PEP executes the call to
`https://erp.example.com`, and both record their evidence
({{I-D.draft-mcguinness-mission-authzen}}). A revocation at the MAS
stops the next such action at this step, through the runtime state
re-check.

~~~ json
{
  "decision": true,
  "context": {
    "decision_id": "dec_7mQ2sV5rL9tY3sB8zN1eF4jB0K"
  }
}
~~~

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work. It profiles the Mission Issuer role for deployments whose
Authorization Server cannot change, and builds on the Mission Status
and Lifecycle, Mission-Bound Runtime Enforcement, and AuthZEN profile
companions.
