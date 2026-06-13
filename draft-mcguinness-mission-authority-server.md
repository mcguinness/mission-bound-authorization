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
 - authorization
 - governance
 - oauth
 - aauth
 - mas
 - cross-substrate

venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html"

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
  RFC6570:
  RFC6838:
  RFC8259:
  RFC8417:
  RFC8615:
  RFC8785:
  RFC8935:
  RFC8936:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC8705:
  RFC9449:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-mission-oauth-profile:

informative:
  I-D.ietf-httpapi-idempotency-key:
  RFC6749:
  RFC8414:
  RFC9396:
  RFC9126:
  RFC9701:
  RFC7591:
  I-D.draft-hardt-oauth-aauth-protocol:
  I-D.draft-ietf-secevent-subject-identifiers:
  I-D.draft-ietf-oauth-identity-chaining:
  OIDC-SSF:
    title: "OpenID Shared Signals Framework Specification 1.0"
    author:
      org: "OpenID Foundation"
    date: 2025
    target: "https://openid.net/specs/openid-sharedsignals-framework-1_0.html"
  OIDC-CAEP:
    title: "OpenID Continuous Access Evaluation Profile 1.0"
    author:
      org: "OpenID Foundation"
    date: 2025
    target: "https://openid.net/specs/openid-caep-1_0.html"

--- abstract

A Mission Authority Server (MAS) holds the canonical Mission record so
that multiple OAuth Authorization Servers, AAuth Person Servers, and
future substrate state authorities can project credentials and
governance state from one shared governance object. This document
defines the MAS role and topology, the MAS metadata document, the
Mission submission and lifecycle endpoints, the MAS-side Mission
Status binding for the abstract interface defined in the Mission
Framework, a substrate-neutral Authority Set serialization, the
use of the canonical `mission.id` across all consumers, and the
cross-substrate revocation propagation contract using OpenID Shared
Signals events with a polling fallback. Cross-MAS federation and
MAS-to-MAS Mission migration are out of scope for this revision.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
defines the Mission as a durable, integrity-anchored,
lifecycle-governed governance object. The framework permits the
Mission record to live at any of three classes of state authority: an
OAuth Authorization Server (AS), an AAuth Person Server (PS), or a
**Mission Authority Server** (MAS) dedicated to governance.

A Mission Authority Server holds the canonical Mission record so that
multiple OAuth Authorization Servers, AAuth Person Servers, and future
substrate state authorities can project from one shared governance
object. The MAS topology is the topology a deployment chooses when a
single approved task must be projected onto more than one credential
substrate, or when governance is operationally separated from any one
credential issuer.

This document defines:

- The MAS role, the consumer roles (OAuth AS, AAuth PS, future
  substrates), and the trust relationship between them.
- The MAS metadata document extension of the Framework's
  `/.well-known/mission-authority` discovery anchor.
- The Mission submission endpoint, with a consumer-mediated default
  flow and an optional direct-to-MAS flow.
- The Mission lifecycle endpoint: revoke, suspend, resume, and
  complete.
- The MAS-side transport binding of the abstract Mission Status
  interface, using JWS-signed responses.
- A substrate-neutral Authority Set serialization with per-substrate
  projection at consumer time.
- Cross-substrate revocation propagation through OpenID Shared
  Signals Framework (SSF) and Continuous Access Evaluation Profile
  (CAEP) events, with a polling fallback for consumers that do not
  receive event streams.
- Consumer-binding sections specifying how an OAuth AS and an AAuth
  Person Server consume MAS state.

This document does NOT redefine the abstract Mission Status interface
(which lives in the Framework), substrate-local Mission state (which
lives in the OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} and the AAuth
Profile), runtime per-action enforcement, or cross-MAS federation.

## Scope statement (Resolved Decision 23)

This revision assumes a committed MAS implementer. The MAS role
contract is substrate-neutral; the OAuth and AAuth consumer bindings
in this document depend on the OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} and the AAuth Profile
respectively. The following are explicitly OUT of scope for this
revision:

- **Cross-MAS federation.** A MAS does not consume Mission state
  from another MAS in this revision. Mission state is authoritative
  at exactly one MAS.
- **MAS-to-MAS Mission migration.** A Mission record cannot be
  transferred from one MAS to another in this revision. A Mission's
  state authority is fixed at the approval event.

The following IS in scope:

- A MAS using the canonical `mission.id` in all responses to all
  registered consumers. Mission-identity isolation across consumers
  is out of scope for this revision and is addressed (if needed)
  by a profile extension to the Framework.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms defined in the Mission Framework
{{I-D.draft-mcguinness-mission-framework}} are inherited. The
following additional terms apply.

**Mission Authority Server (MAS)**:
: A dedicated state authority server that holds the canonical Mission
record and exposes Mission submission, lifecycle, and Mission Status
operations to one or more consumers. A MAS is one realization of the
Framework's abstract state authority role.

**Consumer**:
: A credential-issuing or governance-evaluating server that consumes
Mission state from a MAS. The two consumer roles defined by this
document are an OAuth Authorization Server consuming Mission state
from a MAS, and an AAuth Person Server consuming Mission state from
a MAS. Additional substrate consumer roles MAY be defined in future
specifications.

**Projection issuer**:
: A consumer that derives substrate-specific credentials or
assertions from MAS-held Mission state. An OAuth AS in this role
issues access tokens carrying the `mission` claim; an AAuth PS in
this role issues AAuth resource and auth tokens carrying the
Mission reference appropriate to AAuth.

**Consumer registration**:
: A MAS-side record binding a registered consumer identity to its
authentication keys, audience identifier, and authorized
operations. The MAS uses the consumer registration to authenticate
consumer requests and to project Mission state appropriately.

**Consumer-mediated submission (Flow A)**:
: The default Mission submission flow. The client interacts with a
consumer (typically an OAuth AS) using that consumer's substrate-
native submission interface; the consumer forwards the Mission Intent
to the MAS for atomic approval.

**Direct-to-MAS submission (Flow B)**:
: An optional submission flow in which a registered client interacts
directly with the MAS Mission submission endpoint, bypassing any
substrate-local consumer at submission time.

# MAS Role and Topology

## MAS as state authority

A MAS is a state authority per the Mission Framework
{{I-D.draft-mcguinness-mission-framework}}. As state authority the
MAS:

- Owns the canonical Mission record, its lifecycle state, integrity
  anchors, and principal-model evidence.
- Performs the approval event atomically, transitioning a Mission
  Proposal to a Mission.
- Owns the canonical `mission.id`.
- Publishes integrity-protected Mission Status responses.
- Performs the lifecycle operations (revoke, suspend, resume,
  complete) and propagates state changes to consumers.

A MAS MUST NOT delegate any of these responsibilities to a consumer.
A consumer in a MAS topology is a projection issuer, not a state
authority for that Mission.

## Consumer roles

Two consumer roles are defined by this document:

- **OAuth AS as MAS consumer**: an OAuth Authorization Server that
  binds the `mission` claim on its issued credentials to a Mission
  whose state authority is the MAS rather than the AS itself. The
  AS does not hold the Mission record; it holds a substrate-local
  projection of MAS state.
- **AAuth PS as MAS consumer**: an AAuth Person Server that issues
  AAuth resource tokens and auth tokens whose underlying Mission
  record lives at a MAS. The PS does not hold the Mission record.

Future substrate consumers (for example, a GNAP grant server, a
WIMSE workload identity issuer, or other emerging credential
substrates) MAY adopt the consumer contract defined in this document.

A consumer MUST advertise that it is operating as a MAS consumer in
its own substrate-local metadata (the AS metadata document for an
OAuth AS; the PS metadata for an AAuth PS) by carrying the MAS
issuer URL it is bound to. Consumers MUST NOT issue credentials
referencing a MAS for which they have no current registration.

## Trust establishment {#trust-establishment}

Trust between a MAS and a consumer is established out of band through
**consumer registration** at the MAS. Consumer registration binds:

- A stable consumer identifier (registered at the MAS).
- The consumer's authentication keys (JWKS URL or static JWK Set).
- The consumer's audience identifier (the value the MAS uses for the
  `aud` claim on signed responses to that consumer).
- The consumer's authorized operations (submission, status,
  lifecycle, event subscription).
- The consumer's substrate identifier (`oauth_as`, `aauth_ps`, or
  another registered substrate name).

Consumer registration is a deployment operation, not a wire protocol
defined by this document. Dynamic consumer registration MAY be
offered by the MAS using a registration protocol similar to RFC 7591
{{RFC7591}}; deployment policy decides whether dynamic registration
is permitted.

The MAS MUST authenticate every consumer request and MUST refuse
requests from consumers whose registrations do not authorize the
requested operation or the requested Mission's tenant.

## Trust establishment from the consumer side

A consumer MUST validate signed MAS responses against the MAS's
published keys at the MAS `jwks_uri`. The consumer MUST treat the
MAS issuer URL as the authoritative `iss` value on signed responses
and MUST refuse responses whose `iss` does not match a configured
MAS registration.

Consumers SHOULD pin the MAS's TLS certificate or use a deployment-
local certificate validation policy as defense in depth against
DNS or routing attacks against the discovery URL.

## Topology constraints

In a MAS topology:

- Exactly one MAS is the state authority for a given Mission.
- A Mission MAY be projected onto multiple substrates simultaneously
  by multiple consumers.
- A Mission's tenant identifier is owned by the MAS. Consumers
  inherit the tenant; consumers MUST NOT redefine the tenant
  identifier on projections.
- The `mission.origin` carried on projections is the MAS issuer URL,
  not the consumer's URL.

# MAS Metadata and Discovery {#mas-metadata-and-discovery}

## Well-known URL

The MAS metadata document is published at the well-known URL
`/.well-known/mission-authority` per RFC 8615 {{RFC8615}}. This is
the same well-known URL the Framework specifies for any state
authority; the MAS does not introduce a new well-known URL. A
deployment that operates a MAS at the issuer URL `https://mas.example.com`
publishes its metadata document at
`https://mas.example.com/.well-known/mission-authority`.

The MAS metadata document is a JSON object {{RFC8259}}: the
Framework metadata document with MAS-specific extensions; it does
not replace the Framework fields. The members are enumerated below
and registered in {{iana}}.

## REST resource model {#rest-resource-model}

A MAS is a RESTful HTTP API. Mission Proposals and Missions are
resources; state transitions are HTTP requests on those resources
or on action subresources of them. All resources are served over
TLS 1.2 or later (TLS 1.3 RECOMMENDED).

The MAS exposes the following resources, identified by URI
templates {{RFC6570}} published in the MAS metadata document:

| Resource | Method | Description |
|---|---|---|
| `proposals_collection` | `POST` | Submit a Mission Proposal. Returns the created Proposal. |
| `proposal` | `GET` | Read a Proposal's current state. |
| `proposal_approve` | `POST` | Consumer asserts approval received; creates the Mission. |
| `proposal_reject` | `POST` | Consumer or administrator rejects. Terminal. |
| `proposal_withdraw` | `POST` | Client or administrator withdraws a `pending_approval` Proposal. |
| `mission` | `GET` | Read a Mission's record (audience-scoped projection). |
| `mission_status` | `GET` | Retrieve a signed Mission Status Response. |
| `mission_revoke` | `POST` | Revoke an `active` or `suspended` Mission. |
| `mission_suspend` | `POST` | Suspend an `active` Mission. |
| `mission_resume` | `POST` | Resume a `suspended` Mission. |
| `mission_complete` | `POST` | Mark an `active` Mission as completed. |

All action endpoints (POSTs on the three Proposal lifecycle
action subresources and the four Mission lifecycle action
subresources) support the `Idempotency-Key` request header per
{{?I-D.ietf-httpapi-idempotency-key}}. A repeated request with
the same `Idempotency-Key` for the same authenticated consumer
returns the prior outcome rather than re-applying the operation.

Authentication for every endpoint is per consumer registration
({{trust-establishment}}); the authenticated consumer's identity
binds requests and responses (no separate `audience` parameter
is needed in the wire form).

## Required Framework metadata fields

The MAS metadata document MUST carry the fields required by the
Framework metadata document
({{I-D.draft-mcguinness-mission-framework}} Section 7.3). The MAS
substitutes URI-template members for the Framework's single-URL
status and lifecycle endpoint members:

- `issuer` (URL): the MAS issuer URL.
- `jwks_uri` (URL): the MAS's public keys for response signing.
- `mission_intent_schema_uri` (URL): JSON Schema for Mission Intent.
- `authority_set_types_supported` (array): the Authority Set entry
  types this MAS issues.
- `mission_framework_versions_supported` (array).
- `mission_normalization_profiles_supported` (array): the
  registered Normalization Profile identifiers the MAS understands,
  required of every state authority by the Framework.

## MAS-specific metadata fields

A MAS metadata document MUST additionally carry the following
URI-template members per {{RFC6570}}:

- `proposals_collection_endpoint` (URL, required): collection URL
  accepting Mission Proposal submission via `POST`.
- `proposal_endpoint_template` (URI template, required): template
  for a Proposal resource. Variable: `{proposal_id}`. Example:
  `https://mas.example.com/proposals/{proposal_id}`.
- `proposal_lifecycle_endpoint_template` (URI template, required):
  template for Proposal lifecycle action subresources. Variables:
  `{proposal_id}` and `{action}`, where `{action}` is one of
  `approve`, `reject`, `withdraw`. Example:
  `https://mas.example.com/proposals/{proposal_id}/{action}`.
- `mission_endpoint_template` (URI template, required): template
  for a Mission resource. Variable: `{mission_id}`. Example:
  `https://mas.example.com/missions/{mission_id}`.
- `mission_status_endpoint_template` (URI template, required):
  template for the Mission Status subresource. Variable:
  `{mission_id}`. Example:
  `https://mas.example.com/missions/{mission_id}/status`.
- `mission_lifecycle_endpoint_template` (URI template, required):
  template for lifecycle action subresources. Variables:
  `{mission_id}` and `{action}`, where `{action}` is one of
  `revoke`, `suspend`, `resume`, `complete`. Example:
  `https://mas.example.com/missions/{mission_id}/{action}`.

Additional MAS-specific members:

- `mission_supported_consumer_substrates` (array of strings,
  required): registered substrate consumer names the MAS supports,
  for example `["oauth_as", "aauth_ps"]`.
- `mission_event_delivery_modes_supported` (array of strings,
  required): subset of `["ssf_push", "ssf_poll", "status_poll"]`
  identifying the cross-substrate event delivery modes the MAS
  supports per {{cross-substrate-revocation-propagation}}.
- `mission_event_stream_endpoint` (URL, conditional): the MAS event
  stream endpoint, required if any SSF mode is advertised.
- `mission_status_polling_max_interval_seconds` (integer, required
  when `status_poll` is advertised): the maximum interval in seconds
  the MAS recommends consumers poll Mission Status to detect state
  changes when no event stream is used.
- `mission_submission_flow_b_supported` (boolean, required): whether
  the MAS accepts direct-to-MAS Proposal submission (Flow B).
  Default deployments MAY publish `false`.
- `mission_retention_policy_uri` (URL, required): a URL identifying
  the MAS's retention policy applied to Mission records and
  Proposal records, per Framework Section 5.3 and Resolved Decision
  20.
- `mission_consumer_registration_endpoint` (URL, optional): a URL
  the MAS publishes if it offers dynamic consumer registration.
- `mission_response_media_type` (string, required): the MAS-side
  signed Mission Status response media type registered by this
  document, namely `application/mas-mission-status-response+jwt`.

### Worked metadata document

~~~ json
{
  "issuer": "https://mas.example.com",
  "jwks_uri": "https://mas.example.com/.well-known/jwks.json",
  "mission_intent_schema_uri":
    "https://mas.example.com/.well-known/mission-intent-schema.json",
  "authority_set_types_supported": ["mission_resource_access"],
  "mission_framework_versions_supported": [
    "draft-mcguinness-mission-framework-00"
  ],
  "mission_normalization_profiles_supported": [
    "urn:mbo:norm:mission-intent:1",
    "urn:mbo:norm:mission-authority-set:1",
    "urn:mbo:norm:mission-consent-disclosure:1"
  ],

  "proposals_collection_endpoint":
    "https://mas.example.com/proposals",
  "proposal_endpoint_template":
    "https://mas.example.com/proposals/{proposal_id}",
  "proposal_lifecycle_endpoint_template":
    "https://mas.example.com/proposals/{proposal_id}/{action}",
  "mission_endpoint_template":
    "https://mas.example.com/missions/{mission_id}",
  "mission_status_endpoint_template":
    "https://mas.example.com/missions/{mission_id}/status",
  "mission_lifecycle_endpoint_template":
    "https://mas.example.com/missions/{mission_id}/{action}",

  "mission_supported_consumer_substrates":
    ["oauth_as", "aauth_ps"],
  "mission_event_delivery_modes_supported":
    ["ssf_push", "status_poll"],
  "mission_event_stream_endpoint":
    "https://mas.example.com/events",
  "mission_submission_flow_b_supported": false,
  "mission_retention_policy_uri":
    "https://mas.example.com/policies/retention",
  "mission_response_media_type":
    "application/mas-mission-status-response+jwt"
}
~~~

## JWKS publication {#jwks-publication}

The MAS MUST publish its public keys at `jwks_uri` per RFC 7517
{{RFC7517}}. The MAS MUST sign every Mission Status response, every
lifecycle response that carries state, and every SSF Security Event
Token (SET) it emits with a key whose `kid` resolves in the
currently published JWKS.

Key rotation rules:

- The MAS MAY publish multiple active signing keys at any time.
- The MAS MUST retain a rotated-out public key in `jwks_uri` for at
  least the maximum tolerated stale interval the MAS advertises for
  consumers operating in `status_poll` mode, plus the largest
  Mission Status response `expires_at` window the MAS issues.
- The MAS MUST NOT reuse `kid` values.
- Consumers MUST refresh the MAS `jwks_uri` periodically and on any
  unrecognized `kid`.

# Proposals Collection: Mission Submission

A Mission Proposal is created by `POST` to the
`proposals_collection_endpoint`. Two flows are defined: Flow A
(consumer-mediated, default) and Flow B (direct-to-MAS, optional).

A MAS MUST support Flow A. A MAS MAY support Flow B. A MAS that
supports Flow B advertises `mission_submission_flow_b_supported: true`.

## Flow A: Consumer-mediated submission (default) {#flow-a}

In Flow A the client submits Mission Intent to a consumer through
that consumer's substrate-native interface (for example, OAuth PAR
carrying `mission_intent`
{{I-D.draft-mcguinness-mission-oauth-profile}}). The consumer
forwards the submission to the MAS by `POST`ing to
`proposals_collection_endpoint`. The consumer is the intermediary;
the MAS performs the approval and commits the canonical record.

### Step 1: client submits to consumer

The client submits Mission Intent to a consumer using the consumer's
substrate-native interface. The consumer is, in this document, the
OAuth AS or AAuth PS that is registered at the MAS for the relevant
tenant.

### Step 2: consumer forwards to MAS

The consumer authenticates to the MAS and `POST`s to
`proposals_collection_endpoint` with content type
`application/json` and the `Idempotency-Key` header set to a
stable consumer-generated key:

~~~ http-message
POST /proposals HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Idempotency-Key: prop-corr_4kQ9pX2vN7sR1tY8mZ3
Authorization: ...

{
  "mission_intent": { ... },
  "tenant": "tenant_acme",
  "requesting_client": "client_erp-recon-agent",
  "submitting_consumer": "as_acme_primary",
  "subject": { "format": "iss_sub", "iss": "...", "sub": "..." }
}
~~~

Required body fields:

- `mission_intent` (object, required): the Submitted Mission Intent
  the client provided, normalized per Framework
  {{I-D.draft-mcguinness-mission-framework}} Section 6.1.
- `tenant` (string, required): the tenant identifier under which
  the Mission is being proposed. MUST match a tenant the consumer
  is registered for at the MAS.
- `requesting_client` (string, required): the substrate-local
  client identifier (the OAuth `client_id` or AAuth agent
  identifier) that submitted to the consumer.
- `submitting_consumer` (string, required): the consumer identifier
  as registered at the MAS.
- `subject` (Mission Principal, required): the principal on whose
  behalf the task is approved, as a Mission Principal object per
  the Framework ({{I-D.draft-mcguinness-mission-framework}}). The
  MAS MUST be able to map the supplied principal to its tenant
  subject namespace at validation time.
- `approving_principal` (Mission Principal, optional): if the
  approving principal is known to the consumer at submission, the
  value is forwarded as a Mission Principal object; otherwise the
  MAS records it at the approval event.
- `proposal_correlation_id` (string, required): a consumer-generated
  opaque value used to bind the consumer's local Proposal record to
  the MAS Proposal record. The consumer MUST use this same value as
  the `Idempotency-Key` request header; the header is the
  idempotency mechanism ({{?I-D.ietf-httpapi-idempotency-key}}) and
  `proposal_correlation_id` is its in-body echo, recorded by the MAS
  for consumer-side correlation. The two MUST be equal; the MAS MUST
  reject a submission whose header and `proposal_correlation_id`
  disagree with `invalid_request`.

Consumer authentication: the consumer MUST authenticate using one
of:

- mTLS {{RFC8705}} with a client certificate whose identity binds
  to the consumer registration; or
- a signed JWT bearer assertion whose signing key resolves in the
  consumer's registered JWKS.

The MAS MUST refuse forwarding requests that fail consumer
authentication or that name a `submitting_consumer` not authorized
for the named `tenant`.

### Step 3: MAS validates and creates a Proposal

The MAS validates the forwarded Mission Intent against the published
`mission_intent_schema_uri` and against MAS-side deployment policy.
On success the MAS creates a Mission Proposal record bound to:

- The forwarded `mission_intent`.
- The `tenant`, `requesting_client`, `subject`, and
  `submitting_consumer`.
- A MAS-minted `proposal_id`.
- The `Idempotency-Key` header value (recorded for idempotency
  and for consumer-side correlation).

The MAS responds:

~~~ http-message
HTTP/1.1 201 Created
Location: https://mas.example.com/proposals/prop_4kQ9pX2vN7sR1tY8mZ3
Content-Type: application/json
Idempotency-Key: prop-corr_4kQ9pX2vN7sR1tY8mZ3

{
  "proposal_id": "prop_4kQ9pX2vN7sR1tY8mZ3",
  "state": "pending_approval",
  "tenant": "tenant_acme"
}
~~~

The Proposal is in state `pending_approval`. A repeat `POST` with
the same `Idempotency-Key` for the same authenticated consumer
returns the original Proposal verbatim with the same status code.

### Step 4: approval event

The consumer drives the consent rendering and approval interaction
appropriate to its substrate (the OAuth AS uses its authorization
endpoint and consent UX; the AAuth PS uses its native approval
interface). On receiving a binding consent signal the consumer
`POST`s to the `proposal_lifecycle_endpoint_template` expanded
with `{action}=approve` and the target `{proposal_id}`. The
request body carries the consent disclosure object recorded at
the consumer. Withdrawals and rejections at the Proposal stage
use the same template expanded with `{action}=withdraw` or
`{action}=reject`. After
approval the Mission is governed exclusively through the lifecycle
endpoint ({{lifecycle-action-subresources}}).

The MAS performs the atomic approval event per Framework
{{I-D.draft-mcguinness-mission-framework}} Section 5.2 and creates
the Mission record. The MAS returns the canonical `mission.id` to
the consumer.

If the MAS refuses the Proposal at any step, declines the approval,
or fails the atomic commit, the MAS returns a structured error
({{submission-errors}}). The consumer MUST NOT issue any credential
referencing a Mission whose MAS approval has not completed.

### Step 5: consumer projection issuance

The consumer issues substrate-specific credentials carrying the
Mission reference returned by the MAS. The consumer-side projection
binds the credential to the Mission per the consumer's substrate
profile (OAuth `mission` claim per
{{I-D.draft-mcguinness-mission-oauth-profile}}; AAuth-specific
binding per the AAuth Profile).

## Flow B: Direct-to-MAS submission (optional)

A MAS MAY accept Mission submissions directly from a registered
client, bypassing any substrate-local consumer at submission time.
Flow B is appropriate where a client governs work across multiple
substrates and prefers a single submission interaction with the
governing MAS.

A MAS that supports Flow B advertises
`mission_submission_flow_b_supported: true` and accepts authenticated
client requests at `proposals_collection_endpoint`.

### Client authentication for Flow B

A client submitting through Flow B MUST authenticate. The MAS MUST
support at least one of:

- mTLS-authenticated request {{RFC8705}}.
- DPoP-bound bearer token {{RFC9449}} issued by the MAS for
  submission scope.
- Signed JWT bearer assertion using a client-registered JWKS.

The MAS MUST refuse anonymous or insufficiently authenticated
submissions.

### Direct submission request

The request is an HTTPS `POST` to `proposals_collection_endpoint`
with content type `application/json` and an `Idempotency-Key`
header. Required body fields:

- `mission_intent` (object, required).
- `tenant` (string, required).
- `requesting_client` (string, required): the registered client
  identifier at the MAS; MUST match the authenticated client.
- `subject` (Mission Principal, required).
- `approval_channel` (string, required): identifies how the consent
  signal will be supplied. Defined values are `"mas_native"`
  (the MAS renders consent itself, for example to a registered
  approving principal at the MAS) and `"out_of_band"` (the consent
  signal is supplied later through a separate authenticated request
  channel that the MAS deployment defines).

Direct submission produces a Mission Proposal at the MAS. The
Proposal lifecycle is identical to Flow A; only the submission and
consent channel differ.

### Consent under Flow B

Under `approval_channel: "mas_native"` the MAS renders the consent
disclosure object to the approving principal directly. The MAS owns
the consent UX and the `acr_at_approval` recording.

Under `approval_channel: "out_of_band"` the deployment is
responsible for ensuring the consent signal is bound to the
Proposal and carries the `acr_at_approval` evidence required by
deployment policy. A MAS MUST refuse out-of-band signals that do
not carry recorded `acr_at_approval` evidence sufficient for the
Mission class.

### Direct projection issuance

Once a Mission is created through Flow B, projection issuers
(OAuth ASes and AAuth PSes registered as MAS consumers for the
same tenant) may discover the Mission state and issue credentials
referencing the Mission. The mechanism by which a projection
issuer learns of a new Mission is either:

- Subscription to the MAS event stream
  (`mission.lifecycle-change` event with `state=active`); or
- Polling Mission Status on demand when a client presents a
  Mission handle for substrate-local credential issuance, as
  defined in {{flow-b-handle}}.

### Flow B Mission handle and client-to-AS handoff {#flow-b-handle}

When Flow B activates a Mission, the MAS returns to the client a
**Mission handle**: a sender-constrained, consumer-specific
reference the client presents to a projection issuer to obtain
substrate-local credentials, without the client ever holding the
canonical `mission.id`. The handle:

- is bound to the requesting client and to the specific projection
  issuer (consumer) the client will redeem it at, so a handle
  leaked to a different party is not usable;
- is sender-constrained to the client's proof-of-possession key
  (DPoP {{RFC9449}} or mTLS {{RFC8705}}); and
- resolves at the MAS, through Mission Status
  ({{mission-status}}), to the canonical Mission and to the
  named projection issuer's authorization
  (`projection_issuer_authorized`).

For an OAuth projection issuer, the client presents the handle as
the `mission_id` Pushed Authorization Request parameter defined in
the OAuth Profile
({{I-D.draft-mcguinness-mission-oauth-profile}}); the AS validates
the handle against MAS Mission Status, confirms it is bound to the
requesting client and to the AS as projection issuer, and issues a
Mission-bound authorization code. An AS MUST reject a request that
carries both `mission_id` and `mission_intent`: the former adopts
an existing MAS-held Mission, the latter proposes a new one. For an
AAuth projection issuer, the client presents the handle through the
PS's native submission interface and the PS performs the equivalent
validation before issuing AAuth credentials.

## Submission errors {#submission-errors}

The MAS uses the following structured error response form for both
flows. The response body is JSON with content type
`application/json`.

~~~ json
{
  "error": "<symbol>",
  "error_description": "<human readable>",
  "proposal_id": "<if assigned>",
  "tenant": "<if known>"
}
~~~

Defined error symbols, with their HTTP status mapping:

| Symbol | HTTP | Description |
|---|---|---|
| `invalid_request` | 400 | Malformed body, missing required fields. |
| `invalid_mission_intent` | 422 | The Mission Intent failed schema or policy validation. |
| `unauthorized_consumer` | 403 | The submitting consumer is not authorized for the named tenant or operation. |
| `unauthorized_client` | 403 | The submitting client (Flow B) is not authorized. |
| `tenant_not_found` | 404 | The named tenant is unknown. |
| `policy_refused` | 403 | Deployment policy refuses the Proposal. |
| `conflict` | 409 | The `Idempotency-Key` (or its bound `proposal_correlation_id`) was reused with a conflicting payload. |
| `unavailable` | 503 | The MAS temporarily cannot accept submissions. |

A request that fails authentication (as distinct from
authorization) is refused with HTTP 401 before any of the above
symbols apply.

# Mission Lifecycle: Action Subresources {#lifecycle-action-subresources}

The MAS exposes four lifecycle action subresources under each
Mission resource, expanded from
`mission_lifecycle_endpoint_template` with `{mission_id}` set to
the target Mission and `{action}` set to one of:

- `revoke`: `active`, `suspended` -> `revoked`. Terminal.
- `suspend`: `active` -> `suspended`. Reversible by `resume`.
- `resume`: `suspended` -> `active`.
- `complete`: `active`, `suspended` -> `completed`. Terminal.

Transitions not permitted by the Mission's current state MUST be
refused with HTTP 409 `Conflict` and an `invalid_state` error body.

## Request

Each lifecycle request is an HTTPS `POST` to the expanded action
subresource. Content type is `application/json`. The body MAY
carry an optional `reason` string (maximum 1024 characters); the
body MAY be empty.

The `Idempotency-Key` request header
({{?I-D.ietf-httpapi-idempotency-key}}) MUST be supplied and
serves as the operation's idempotency key. The MAS MUST treat
repeated requests with the same `Idempotency-Key` from the same
authenticated consumer as idempotent: the prior response is
returned without re-applying the operation.

~~~ http-message
POST /missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-/revoke HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Idempotency-Key: rev-req_8Y3vN0sM6tP1xR9bQ5
Authorization: ...

{
  "reason": "Quarterly reconcile completed early"
}
~~~

## Authentication

The MAS MUST authenticate the requester per consumer
registration. Permitted authentication mechanisms are identical
to those for Flow A consumer authentication (mTLS or signed JWT
bearer assertion) or, for an end-user-driven revocation, an
authenticated MAS administrative interface that maps to the same
action subresources internally.

## Response {#lifecycle-response}

On success the MAS returns HTTP 200 with a JWS-signed Mission
Status Response ({{mission-status}}) reflecting the new state. The signed
response binds the caller identity, the Mission, and the
`Idempotency-Key`.

## Audit recording {#audit-recording}

The MAS MUST atomically record:

- The transition (old state, new state).
- The caller identity (authenticated consumer or administrator).
- The wall-clock timestamp.
- The reason (if provided).
- The `Idempotency-Key` value.

Concurrent lifecycle operations on the same Mission are
serialized at the MAS with compare-and-set semantics.

## Propagation obligation

After committing a lifecycle transition the MAS MUST trigger
cross-substrate revocation propagation per
{{cross-substrate-revocation-propagation}} to all
registered consumers for the Mission's tenant.

A consumer MUST treat MAS lifecycle propagation as authoritative.
A consumer MUST NOT independently transition the underlying Mission
state; consumers may revoke their own substrate-local projections
in response to MAS state changes, but the MAS owns the Mission
state machine.

# Mission Status: GET on Resource {#mission-status}

This section defines the MAS-side transport binding for the abstract
Mission Status interface defined by the Framework
({{I-D.draft-mcguinness-mission-framework}} Section 8). The MAS
binding uses JWS-signed responses per RFC 7515 {{RFC7515}}.

The MAS Mission Status binding is the transport contract every MAS
consumer (OAuth AS, AAuth PS, future substrates) uses to obtain
authenticated Mission state. The dedicated OAuth Mission Status
operation defined in
{{I-D.draft-mcguinness-mission-oauth-profile}} is a parallel
substrate-local operation at an OAuth AS; the MAS operation defined
here is its cross-substrate counterpart at the MAS.

## JWS integrity envelope {#jws-envelope}

Every MAS-signed artifact -- the Mission Status response
({{response-payload}}), the lifecycle response ({{lifecycle-response}}),
and the `mission.lifecycle-change` SET ({{set-protection}}) -- is a
JWS Compact Serialization {{RFC7515}} whose protected header carries:

- `alg` (required): a digital-signature algorithm. The MAS MUST
  use an asymmetric algorithm whose public key is published at
  `jwks_uri`; it MUST NOT use `none` and MUST NOT use a MAC
  algorithm.
- `kid` (required): the key identifier of the signing key, resolving
  in the currently published JWKS ({{jwks-publication}}).
- `typ` (required): the media type of the artifact, without the
  `application/` prefix per {{RFC7515}} convention -- for a Mission
  Status response, `mas-mission-status-response+jwt`; for a SET,
  `secevent+jwt`.

The signing input is the JWS Signing Input over the protected
header and the UTF-8 JSON payload; the payload JSON SHOULD be
JCS-canonical {{RFC8785}} so that a consumer that re-serializes the
payload reproduces identical bytes. A consumer MUST reject any
MAS-signed artifact whose `alg` is `none` or symmetric, whose `kid`
does not resolve in the MAS JWKS, or whose signature does not verify.

## Request

The request is an HTTPS `GET` to the `mission_status_endpoint_template`
expanded with the target `{mission_id}`. The caller supplies the
binding nonce as a query parameter (`nonce`); the response is bound
to the authenticated caller's identity (no separate `audience` body
parameter is needed).

A caller MAY additionally supply a `credential_issuer` query
parameter naming a consumer (by its registered consumer identifier
or issuer URL) whose authorization to project this Mission the
caller wants verified. This lets a downstream party that holds a
credential issued by some other consumer ask the MAS whether that
issuer was in fact authorized to project the referenced Mission --
the cross-substrate check a Resource AS cannot perform on its own.
When `credential_issuer` is supplied, the response carries
`projection_issuer_authorized` and `projection_issuer`
({{response-payload}}).

~~~ http-message
GET /missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-/status?nonce=nonce_K9pV4nT2sR7mB1xQ&credential_issuer=as_acme_primary HTTP/1.1
Host: mas.example.com
Accept: application/mas-mission-status-response+jwt
Authorization: ...
~~~

The request MUST be authenticated using the consumer's registered
authentication mechanism (mTLS or signed JWT bearer assertion).

Consumers MAY include `If-None-Match` with a previously observed
`ETag`; the MAS MAY respond `304 Not Modified` if the response would
be byte-identical to the one identified by the supplied `ETag`.
Otherwise the MAS returns `200 OK` with a fresh signed response.

## Response media type

The MAS Mission Status response uses the media type
`application/mas-mission-status-response+jwt` registered by this
document in {{iana}}. This media type is distinct from the OAuth
Profile's `application/mission-status-response+jwt` because the MAS
response payload carries the cross-substrate Authority Set projection
shape defined in {{substrate-neutral-authority-set-serialization}}
of this document, whereas the OAuth
profile response carries the OAuth-substrate projection.

A consumer MUST NOT treat a MAS Mission Status response as
interchangeable with an OAuth AS Mission Status response. The media
type distinguishes them.

## Response payload {#response-payload}

The response is a JWS Compact Serialization with `typ` value
`application/mas-mission-status-response+jwt`. The JWS payload is a
JSON object with the following claims:

- `iss` (string, required): the MAS issuer URL.
- `aud` (string, required): the caller's registered audience
  identifier.
- `sub` (string, required): the registered consumer identifier of
  the caller.
- `nonce` (string, required): the caller-provided nonce, echoed.
- `iat` (number, required): issuance time, seconds since epoch.
- `exp` (number, required): expiration time, seconds since epoch.
- `mas_mission_status` (object, required): the structured Mission
  Status body, defined below.

The `mas_mission_status` body:

~~~ json
{
  "state": "active",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "origin": "https://mas.example.com",
  "tenant": "tenant_01J9...",
  "proposal_hash":           "sha-256:...",
  "authority_hash":          "sha-256:...",
  "consent_disclosure_hash": "sha-256:...",
  "policy_version":          "mas.example.com:standard@2026-06-01",
  "version":                 1,
  "mission_expiry":          "2026-12-31T23:59:59Z",
  "projection_issuer_authorized": true,
  "projection_issuer": {
    "issuer":    "https://as.example.com",
    "substrate": "oauth_as",
    "tenant":    "tenant_01J9...",
    "audience":  "https://erp.example.com"
  },
  "authority_set_projection": {
    "neutral":         [ /* neutral Authority Set entries */ ],
    "substrate_view": {
      "substrate":   "oauth_as",
      "projection":  [ /* substrate-specific projection */ ]
    }
  },
  "freshness_indicator": {
    "as_of":          "2026-06-09T15:00:00Z",
    "max_stale_secs": 60
  }
}
~~~

The `mission_id` member carries the canonical `mission.id` as
defined by the Framework. The `version` member mirrors the Mission
record version defined by the Framework
({{I-D.draft-mcguinness-mission-framework}}); it increments on
every committed lifecycle transition. The `mission_expiry` member
mirrors the Mission's expiry and carries the Framework's required
Mission Status expiry information that the response envelope `exp`
(response freshness) does not convey.

The `authority_set_projection.neutral` array contains the
substrate-neutral Authority Set serialization defined in
{{neutral-serialization}}. The `authority_set_projection.substrate_view`
object MAY be present when the calling consumer is bound to a single
substrate and the MAS pre-computes the substrate projection
({{per-substrate-projection}}).

The `projection_issuer_authorized` boolean and `projection_issuer`
object are present only when the request supplied a
`credential_issuer` parameter ({{request}}). `projection_issuer_authorized`
is `true` if and only if the named credential issuer holds a current
consumer registration authorizing it to project this Mission for the
Mission's tenant and the issuer's substrate; otherwise it is
`false`. When `true`, `projection_issuer` echoes the resolved
issuer's `issuer` URL, `substrate`, `tenant`, and registered
`audience`. A consumer that receives a Mission-bound credential
purportedly issued by some party MUST treat
`projection_issuer_authorized: false` as a rogue or
unauthorized projection and MUST refuse the credential, regardless
of the credential's own signature validity. The MAS MUST NOT reveal,
through this field, whether an unrelated consumer that is not the
named `credential_issuer` is registered.

### Mission Status response JSON Schema {#mas-status-response-schema}

The signed JWS payload validates against the following schema. The
`authority_set_projection.neutral` array contains entries matching
the Framework's Authority Set entry schema
(`urn:mbo:schema:authority-set-entry:1`).

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mas-mission-status-response:1",
  "title": "MAS Mission Status Response Payload",
  "type": "object",
  "required": [
    "iss", "aud", "sub", "nonce", "iat", "exp", "mas_mission_status"
  ],
  "properties": {
    "iss":   { "type": "string", "format": "uri" },
    "aud":   { "type": "string" },
    "sub":   { "type": "string" },
    "nonce": { "type": "string" },
    "iat":   { "type": "integer" },
    "exp":   { "type": "integer" },
    "mas_mission_status": {
      "type": "object",
      "required": [
        "state", "mission_id", "origin", "tenant",
        "proposal_hash", "authority_hash",
        "consent_disclosure_hash", "policy_version", "version",
        "mission_expiry", "authority_set_projection",
        "freshness_indicator"
      ],
      "properties": {
        "state": {
          "type": "string",
          "enum": [
            "active", "suspended", "revoked", "completed", "expired"
          ]
        },
        "mission_id": { "type": "string" },
        "origin":     { "type": "string", "format": "uri" },
        "tenant":     { "type": "string" },
        "proposal_hash":           { "type": "string" },
        "authority_hash":          { "type": "string" },
        "consent_disclosure_hash": { "type": "string" },
        "policy_version":          { "type": "string" },
        "version":                 { "type": "integer" },
        "mission_expiry": {
          "type": "string", "format": "date-time"
        },
        "projection_issuer_authorized": { "type": "boolean" },
        "projection_issuer": {
          "type": "object",
          "required": ["issuer", "substrate", "tenant", "audience"],
          "properties": {
            "issuer":    { "type": "string", "format": "uri" },
            "substrate": { "type": "string" },
            "tenant":    { "type": "string" },
            "audience":  { "type": "string" }
          }
        },
        "authority_set_projection": {
          "type": "object",
          "required": ["neutral"],
          "properties": {
            "neutral": {
              "type": "array",
              "items": {
                "$ref": "urn:mbo:schema:authority-set-entry:1"
              }
            },
            "substrate_view": {
              "type": "object",
              "required": ["substrate", "projection"],
              "properties": {
                "substrate":  { "type": "string" },
                "projection": { "type": "array" },
                "dropped_types": {
                  "type": "array", "items": { "type": "string" }
                }
              }
            }
          }
        },
        "freshness_indicator": {
          "type": "object",
          "required": ["as_of", "max_stale_secs"],
          "properties": {
            "as_of": { "type": "string", "format": "date-time" },
            "max_stale_secs": { "type": "integer", "minimum": 0 }
          }
        }
      }
    }
  }
}
~~~

## Properties

The MAS Mission Status response satisfies the Framework's required
properties for Mission Status:

- **Authentication**: the JWS signature is produced by a key
  resolvable in the MAS `jwks_uri`.
- **Freshness**: `iat`, `exp`, and `freshness_indicator.as_of` are
  required.
- **Audience**: `aud` binds the caller's registered audience.
- **Integrity**: the three integrity anchors are carried and
  signed.
- **Anti-oracle**: unknown Mission references and known-but-
  unauthorized references produce indistinguishable responses
  (HTTP 404 `not_found`).
- **Request-binding**: `iss`, `aud`, `sub`, `nonce`, and the
  Mission reference are all in the signed payload.
- **Caching**: `iat`, `exp`, and `freshness_indicator.max_stale_secs`
  are required. Consumers MUST fail closed after `exp`.

## Error model

The MAS uses the Framework error model mapped to HTTP:

| Symbol | HTTP | Description |
|---|---|---|
| `ok` | 200 | Mission found and visible. Signed body returned. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | Reference unknown OR not visible to caller. |
| `terminated` | 410 | Mission in a terminal state (`revoked`, `completed`, or `expired`). Signed body returned with the specific `state`. |
| `suspended` | 423 | Mission suspended. Signed body returned. |
| `rate_limited` | 429 | Caller rate limited. |
| `unavailable` | 503 | MAS cannot serve status temporarily. |

A `not_found` response MUST be indistinguishable between unknown
references and authorized-only references.

The `expired` state is reached by time-driven expiry of the
Mission, not by a lifecycle action subresource ({{lifecycle-action-subresources}}):
when a Mission's `mission_expiry` passes, the MAS transitions it to
`expired` and, on the next status query or scheduled sweep, emits a
`mission.lifecycle-change` event with `state=expired` per
{{cross-substrate-revocation-propagation}}. Expiry MUST be
propagated to consumers on the same contract as an explicit
lifecycle transition.

# Substrate-Neutral Authority Set Serialization {#substrate-neutral-authority-set-serialization}

The Authority Set on a MAS Mission is the canonical, substrate-
neutral container per the Framework. The MAS serves the Authority
Set in a substrate-neutral form on its Mission Status responses,
plus an optional per-substrate projection shaped for the receiving
consumer.

## Neutral serialization {#neutral-serialization}

The neutral Authority Set serialization is the JSON array of
Authority Set entries as defined by the Framework
({{I-D.draft-mcguinness-mission-framework}}). Each entry validates
against the Framework's Authority Set entry schema
(`urn:mbo:schema:authority-set-entry:1`) and carries `type`,
`specification_uri` or `schema_digest`, `schema_version`,
`authority`, and `narrowing_profile`. This document defines no new
schema for the neutral serialization; it is exactly the array form
of the inherited entry schema.

The neutral serialization is the same shape covered by
`authority_hash` and is the canonical form for content-addressable
integrity verification.

A MAS MUST produce JCS-canonical {{RFC8785}} output for the neutral
Authority Set when computing `authority_hash` and SHOULD use the
same canonical bytes when emitting the neutral serialization on
status responses.

The neutral serialization media type registered by this document is
`application/mission-authority-set+json`.

## Per-substrate projection at consumer time {#per-substrate-projection}

A consumer that holds an authoritative claim of substrate identity
(`oauth_as`, `aauth_ps`, etc.) MAY request a substrate-specific
projection by including the `substrate` form field in the Mission
Status request:

- `substrate` (string, optional): a registered substrate identifier
  matching one of the values declared in
  `mission_supported_consumer_substrates`.

When `substrate` is supplied and matches the caller's registration,
the MAS MAY include `authority_set_projection.substrate_view` in
the signed response.

Substrate projections defined by this document:

- `oauth_as`: each `mission_resource_access` entry in the neutral
  Authority Set is projected to an OAuth RAR
  `authorization_details` object {{RFC9396}} suitable for the OAuth
  AS to use as the seed for derivation. Other neutral entry types
  not registered for OAuth projection MUST be either passed through
  unchanged or dropped per consumer registration policy.
- `aauth_ps`: each Authority Set entry is projected to the AAuth-
  native authority representation per the AAuth Profile. Where the
  AAuth Profile does not yet bind a type, the MAS MUST drop that
  type from the AAuth projection and MUST flag the drop in the
  response.

## Projection integrity

The substrate projection MUST be derivable from the neutral Authority
Set under deterministic rules registered for the substrate. The MAS
MUST NOT introduce authority on the substrate projection that does
not appear in the neutral Authority Set.

The `authority_hash` integrity anchor is computed over the neutral
serialization only. Substrate projections are derived, not anchored;
their fidelity to the neutral form is the registration's
responsibility.

## Unknown types {#unknown-types}

If a consumer registration declares a substrate for which one or
more neutral Authority Set entry types have no registered
projection rule, the MAS MUST omit those types from the substrate
projection AND MUST include a `dropped_types` array in the
`substrate_view` listing the omitted type names. Consumers receiving
`dropped_types` MUST refuse to derive credentials covering authority
the consumer cannot project faithfully.

# Mission Identifier {#mission-identifier}

The MAS uses the canonical `mission.id` defined by the Framework
({{I-D.draft-mcguinness-mission-framework}}) in all responses to
all consumers: signed Mission Status responses, lifecycle
responses, and event payloads. Consumers carry the canonical
`mission.id` on their substrate-local credentials.

This document does not define an audience-pairwise Mission
identifier protocol; consumers operating under the same MAS for
the same Mission see the same `mission.id`. Cross-consumer user
correlation is addressed by OIDC pairwise `sub` (or the AAuth
equivalent) at the substrate profile level, not by Mission
identity. Deployments with stronger Mission-identity isolation
requirements (e.g., a MAS serving competing tenants whose
Mission identifiers must not link across consumers) define a
pairwise Mission identifier through a profile extension to the
Framework; such extensions are out of scope for this document.

# Cross-Substrate Revocation Propagation {#cross-substrate-revocation-propagation}

The MAS is the source of truth for Mission lifecycle. Consumers
project Mission state and issue substrate-local credentials whose
continued validity depends on the underlying Mission remaining in
`active` state. Mission state changes MUST be propagated to all
registered consumers for the affected tenant.

## Event delivery modes

A MAS MUST advertise the event delivery modes it supports in
`mission_event_delivery_modes_supported`. Defined values:

- `ssf_push`: the MAS pushes Security Event Tokens (SETs)
  {{RFC8417}} to a consumer's registered SSF receiver endpoint,
  using push-based delivery {{RFC8935}} per the OpenID Shared
  Signals Framework {{OIDC-SSF}}.
- `ssf_poll`: the MAS makes SETs available for the consumer to
  poll using poll-based delivery {{RFC8936}} per SSF {{OIDC-SSF}}.
- `status_poll`: the consumer polls the MAS Mission Status endpoint
  for state, at no greater than
  `mission_status_polling_max_interval_seconds` intervals.

A MAS MUST advertise at least one of these modes. A MAS that
advertises `status_poll` only is a valid implementation but trades
propagation latency for operational simplicity.

A consumer registration declares which mode the consumer uses. The
MAS MUST respect the consumer's declared mode and MUST NOT silently
fall back to a less-timely mode.

## Lifecycle events

The MAS emits the following event types, aligned with the
Continuous Access Evaluation Profile {{OIDC-CAEP}}, within SSF SETs
{{RFC8417}}. Event type URI registered by this document:

- `https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change`

### `mission.lifecycle-change` event {#lifecycle-change-event-schema}

Emitted when the MAS commits any Mission lifecycle transition or
the approval event. Event claims:

- `mission` (required): the canonical `mission.id`.
- `mission_origin` (required): the MAS issuer URL.
- `tenant` (required): the Mission's tenant.
- `prior_state` (conditional): the state immediately before the
  transition. REQUIRED on every transition emission; absent only on
  the approval-event emission, where there is no prior state.
- `state` (required): the new state, one of `active`, `suspended`,
  `revoked`, `completed`, `expired`.
- `version` (required): the new Mission record version.
- `committed_at` (required): {{RFC3339}} timestamp of the commit.
- `reason` (optional): human-readable reason.

The event is carried as the event-type-keyed value of the `events`
claim of a SET {{RFC8417}}, alongside the SET's own `iss`, `aud`,
`iat`, and `jti` claims. The event payload validates against:

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mas-lifecycle-change-event:1",
  "title": "MAS Mission lifecycle-change Event",
  "type": "object",
  "required": [
    "mission", "mission_origin", "tenant", "state", "version",
    "committed_at"
  ],
  "properties": {
    "mission":        { "type": "string" },
    "mission_origin": { "type": "string", "format": "uri" },
    "tenant":         { "type": "string" },
    "prior_state": {
      "type": "string",
      "enum": [
        "active", "suspended", "revoked", "completed", "expired"
      ]
    },
    "state": {
      "type": "string",
      "enum": [
        "active", "suspended", "revoked", "completed", "expired"
      ]
    },
    "version":      { "type": "integer" },
    "committed_at": { "type": "string", "format": "date-time" },
    "reason":       { "type": "string" }
  }
}
~~~

## SET protection {#set-protection}

Each SET {{RFC8417}} is a JWS Compact Serialization {{RFC7515}}
signed with a MAS key resolvable in `jwks_uri`, and carries the
JWS protected header defined in {{jws-envelope}}. Consumers MUST
verify the signature against the MAS issuer and MUST refuse SETs
whose `iss` does not match the registered MAS.

The SET `aud` MUST be the receiving consumer's registered audience
identifier.

## Polling fallback

Consumers in `status_poll` mode (and consumers in any mode using
polling as defense in depth) MUST poll the MAS Mission Status
endpoint at intervals no greater than
`mission_status_polling_max_interval_seconds`.

A consumer that fails to receive an expected event within the
advertised polling interval MUST issue a fresh Mission Status
request; consumers MUST NOT continue issuing credentials based on
stale state past the advertised maximum stale interval.

## Consumer-side responsibilities on receipt

On receiving a `mission.lifecycle-change` event, a consumer MUST:

- Refuse new credential issuance under the affected Mission if the
  new state is anything other than `active`.
- Where the consumer advertises substrate-local enforcement classes
  beyond `issuance` (introspection invalidation, event-driven push
  to its own Resource Servers, per-request status checks), apply
  them per the consumer's substrate profile.
- Acknowledge the event per the SSF delivery mode in use.

A consumer MUST NOT independently change the MAS-held Mission state
in response to a propagation event. If a consumer believes the MAS
state is wrong, the consumer escalates through the MAS lifecycle
endpoint or out-of-band operational channels; it does not invent a
new state.

# OAuth AS as a MAS Consumer

This section binds the consumer contract to an OAuth Authorization
Server. The OAuth AS implements
{{I-D.draft-mcguinness-mission-oauth-profile}} as its substrate
profile and additionally implements the MAS-consumer behavior in
this section.

## AS registration at the MAS

The OAuth AS is registered at the MAS as a consumer with
`substrate=oauth_as`. The registration declares the AS's audience
identifier, the AS's JWKS URL (for AS-to-MAS request authentication
and SET verification keys), and the tenant or tenants the AS may
operate on.

## AS metadata extensions

An OAuth AS operating as a MAS consumer MUST carry the following
additional members in its AS metadata document {{RFC8414}}:

- `mission_state_authority` (URL): the MAS issuer URL.
- `mission_state_authority_mode` (string): `mas_consumer`,
  identifying that the AS holds Mission state through a MAS rather
  than locally.

An OAuth AS MUST NOT carry both
`mission_state_authority_mode: mas_consumer` and self-hosted
Mission lifecycle endpoints for the same Mission class;
lifecycle operations on MAS-held Missions MUST be routed through
the MAS via the MAS's action subresources.

## Mission Intent forwarding (Flow A)

When a client submits `mission_intent` to the AS through PAR
{{RFC9126}} per
{{I-D.draft-mcguinness-mission-oauth-profile}}, the AS:

1. Validates the Mission Intent at the OAuth layer.
2. Generates a `proposal_correlation_id`.
3. Forwards the Mission Intent to the MAS Mission submission
   endpoint per {{flow-a}}.
4. Records the MAS-minted `proposal_id` against the OAuth
   authorization request.
5. Drives the OAuth consent UX at the authorization endpoint as
   normal.
6. On consent signal, sends the approval request to the MAS, then
   creates the Mission Proposal's promotion as recorded by the MAS.
7. Receives the MAS-minted canonical `mission.id` and uses it on
   subsequent credential issuance.

The AS MUST NOT mint a Mission identifier locally. The AS uses the
MAS-minted canonical `mission.id` on the `mission.id` of the
`mission` claim per
{{I-D.draft-mcguinness-mission-oauth-profile}} Section 9, with
`mission.origin` set to the MAS issuer URL.

## Issuance gating

The AS gates token issuance, refresh, and Token Exchange on Mission
state per
{{I-D.draft-mcguinness-mission-oauth-profile}}. In a MAS-consumer
topology the Mission state is obtained from the MAS, either:

- Lazily, by querying the MAS Mission Status endpoint at each
  derivation event (the simplest implementation, but adds latency
  per request); or
- From a locally cached projection refreshed by SSF events and by
  background polling within
  `mission_status_polling_max_interval_seconds`.

When the MAS reports any non-`active` Mission state at a derivation
event the AS MUST refuse derivation per the OAuth Profile error
model (`invalid_grant` with `mission_state`).

## Mission Status responses for AS consumers

A Resource Server that queries the AS's Mission Status endpoint
receives an OAuth-substrate Mission Status response per
{{I-D.draft-mcguinness-mission-oauth-profile}}. The AS MAY proxy
the underlying MAS state; the AS MUST NOT claim that the AS itself
is the state authority. The OAuth Profile response carries the
MAS issuer URL as `origin` and the AS's audience as `aud`.

An AS that proxies MAS state to a Resource Server MUST refresh the
MAS state freshly when the request requires per-request enforcement.

## Lifecycle operations on MAS-held Missions

A revocation, suspension, resumption, or completion request received
at the AS for a MAS-held Mission MUST be forwarded to the MAS
Mission lifecycle endpoint ({{lifecycle-action-subresources}}). The AS MUST NOT mark the
Mission terminal in its substrate-local projection ahead of MAS
confirmation; the AS marks its local projection terminal only on
MAS confirmation or on receipt of an authenticated
`mission.lifecycle-change` event.

## Cascaded credential revocation

On receipt of an authenticated `mission.lifecycle-change` event
with `state` other than `active`, the AS MUST:

- Refuse new derivations under the affected Mission.
- Apply the AS-advertised enforcement classes (issuance,
  introspection, event-driven push to RSes, per-request status) per
  {{I-D.draft-mcguinness-mission-oauth-profile}} Section 11.

# AAuth Person Server as a MAS Consumer

This section binds the consumer contract to an AAuth Person Server.
The AAuth PS implements the Mission-Bound AAuth Composition Profile
(`draft-mcguinness-mission-aauth-profile`, in development) as its
substrate profile and additionally implements the MAS-consumer
behavior in this section.

## PS registration at the MAS

The AAuth PS is registered at the MAS as a consumer with
`substrate=aauth_ps`. The registration declares the PS's audience
identifier, the PS's authentication keys, the tenant or tenants
the PS may operate on.

## PS metadata extensions

An AAuth PS operating as a MAS consumer carries the following
identifiers in its AAuth metadata:

- `mission_state_authority` (URL): the MAS issuer URL.
- `mission_state_authority_mode` (string): `mas_consumer`.

## AAuth lifecycle mapping

The AAuth substrate exposes two native states (`active` and
`terminated`) per the AAuth Profile. When a MAS-held Mission
transitions to `suspended`, the PS projects the suspension as
AAuth `terminated` for the suspension duration. On resumption the
MAS issues a `mission.lifecycle-change` event with `state=active`;
the PS triggers a new AAuth approval flow as required by the AAuth
Profile to issue new credentials.

The Mission's `revoked`, `completed`, and `expired` states all
project to AAuth `terminated` at the PS, with the MAS-held
fine-grained state observable through Mission Status responses
that the PS forwards upstream when consumers (auditors,
governance processes) request it.

## Approval forwarding (Flow A) at the PS

When an AAuth agent submits a task through the PS's native
submission interface, the PS:

1. Validates the submission at the AAuth layer.
2. Forwards the Mission Intent to the MAS per {{flow-a}}, using
   the AAuth agent identifier as `requesting_client` and the AAuth
   approver as `approving_principal`.
3. Receives the MAS Proposal ID and binds it to the PS-side AAuth
   submission record.
4. Drives the AAuth-native consent and approval flow.
5. On consent, sends the approval request to the MAS; receives the
   Mission reference.
6. Issues AAuth resource or auth tokens carrying the Mission
   reference as the AAuth Profile binds it.

## Mission Status responses for PS consumers

Resource consumers querying the PS receive AAuth-substrate Mission
state per the AAuth Profile. The PS forwards or proxies MAS-held
state for consumers needing the substrate-neutral form, with
`origin` set to the MAS issuer URL.

## Cascaded credential revocation

On receipt of an authenticated `mission.lifecycle-change` event,
the PS MUST refuse new AAuth derivations under the affected
Mission and apply the AAuth Profile's defined substrate-local
revocation behavior (typically by transitioning AAuth records to
`terminated`).

# Worked Example: End-to-End Flow A {#worked-example}

This non-normative example threads a single Mission through Flow A
with an OAuth AS consumer (`https://as.example.com`, audience
`https://as.example.com`) registered at a MAS
(`https://mas.example.com`) for tenant `tenant_acme`. Authentication
headers are elided.

## Step 1: consumer discovers the MAS

~~~ http-message
GET /.well-known/mission-authority HTTP/1.1
Host: mas.example.com
~~~

The MAS returns the metadata document of {{mas-metadata-and-discovery}};
the AS reads `proposals_collection_endpoint`,
`mission_status_endpoint_template`,
`mission_lifecycle_endpoint_template`, and
`mission_event_delivery_modes_supported` (here `["ssf_push",
"status_poll"]`).

## Step 2: client submits, AS forwards the Proposal

The client submits `mission_intent` to the AS through PAR
{{RFC9126}}. The AS validates at the OAuth layer, mints a
correlation id, and forwards:

~~~ http-message
POST /proposals HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Idempotency-Key: prop-corr_4kQ9pX2vN7sR1tY8mZ3

{
  "mission_intent": {
    "purpose": "urn:erp.example.com:purposes:quarterly-reconcile",
    "authority_set": [ /* requested authority */ ]
  },
  "tenant": "tenant_acme",
  "requesting_client": "client_erp-recon-agent",
  "submitting_consumer": "as_acme_primary",
  "subject": {
    "format": "iss_sub",
    "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR"
  },
  "proposal_correlation_id": "prop-corr_4kQ9pX2vN7sR1tY8mZ3"
}
~~~

~~~ http-message
HTTP/1.1 201 Created
Location: https://mas.example.com/proposals/prop_4kQ9pX2vN7sR1tY8mZ3
Content-Type: application/json

{
  "proposal_id": "prop_4kQ9pX2vN7sR1tY8mZ3",
  "state": "pending_approval",
  "tenant": "tenant_acme"
}
~~~

## Step 3: approval event creates the Mission

The AS drives its consent UX. On a binding consent signal it posts
to the Proposal `approve` action subresource:

~~~ http-message
POST /proposals/prop_4kQ9pX2vN7sR1tY8mZ3/approve HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Idempotency-Key: appr_7Y3vN0sM6tP1xR9bQ5

{ "consent_disclosure": { /* recorded at the AS */ } }
~~~

The MAS performs the atomic approval event, mints the canonical
`mission.id`, and returns a signed Mission Status response
({{response-payload}}) whose `mas_mission_status` reports
`state: "active"` and
`mission_id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"`. The AS records
this id and issues an access token carrying the `mission` claim
with `mission.origin` set to `https://mas.example.com` per
{{I-D.draft-mcguinness-mission-oauth-profile}}.

## Step 4: a Resource Server checks status

~~~ http-message
GET /missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-/status?nonce=nonce_K9pV4nT2sR7mB1xQ HTTP/1.1
Host: mas.example.com
Accept: application/mas-mission-status-response+jwt
~~~

The MAS returns `200 OK` with a JWS whose decoded payload is the
object of {{mas-status-response-schema}}: `aud` is the AS audience,
`nonce` is echoed, and `mas_mission_status.state` is `active`.

## Step 5: revocation propagates

An administrator revokes the Mission:

~~~ http-message
POST /missions/msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-/revoke HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Idempotency-Key: rev-req_8Y3vN0sM6tP1xR9bQ5

{ "reason": "Quarterly reconcile completed early" }
~~~

The MAS commits the transition (returning a signed status with
`state: "revoked"`, `version: 2`) and pushes a SET to the AS's SSF
receiver. The decoded SET event
(`https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change`)
carries the required claims of {{lifecycle-change-event-schema}} --
`mission: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"`,
`mission_origin: "https://mas.example.com"`, `tenant: "tenant_acme"`,
`state: "revoked"`, `version: 2`, and `committed_at` -- together
with `prior_state: "active"` and the `reason`. On receipt the AS
refuses all new derivations under the Mission and applies its
advertised enforcement classes per
{{cross-substrate-revocation-propagation}}.

# Out of Scope

The following are explicitly out of scope for this revision (per
Resolved Decision 23):

- **Cross-MAS federation.** A consumer in this revision is bound to
  exactly one MAS. Two MASes do not exchange Mission state. Any
  future cross-MAS federation requires a separate specification
  defining the trust model, mapping rules, and conflict resolution
  between authoritative MAS records.
- **MAS-to-MAS Mission migration.** A Mission's state authority is
  fixed at the approval event. Migration of a Mission from one MAS
  to another is not defined in this revision and is not permitted
  under conformance to this document.

A future revision MAY define federation or migration if deployment
demand justifies the design work.

# Security Considerations {#security-considerations}

## MAS compromise blast radius

The MAS is a concentrated state authority. A compromised MAS can:

- Fabricate Mission records and integrity anchors.
- Project arbitrary Authority Sets to multiple substrate consumers
  simultaneously, multiplying the substrate-local credential damage.
- Emit fraudulent `mission.lifecycle-change` events to cause
  consumers to refuse legitimate credential derivations
  (denial of service) or to omit revocations.

Because a MAS aggregates governance across substrates, the blast
radius of a MAS compromise is larger than that of a substrate-local
state authority. Deployments mitigate MAS compromise by:

- Hardware-protected signing keys for the MAS JWKS.
- Independent audit logging with cross-organization anchoring of
  integrity hashes.
- Operational separation of MAS administrative interfaces from
  substrate consumer interfaces.
- Periodic comparison of MAS-emitted state against substrate-local
  evidence (the Resource Server's recorded transactions, the
  consumer's recorded derivations) for after-the-fact detection of
  fabricated state.

Independent attestation, optional and recommended for MAS
deployments handling regulated or high-stakes Missions, is a
deployment concern and is not specified here.

## Trust establishment between MAS and consumers

Consumer registration is the trust root for every operational
interaction. A weak consumer registration (poorly authenticated
keys, lax tenant authorization) collapses the security of the
overall topology.

Deployments MUST:

- Authenticate consumer registration through an authoritative out-
  of-band channel.
- Restrict each consumer registration to the smallest set of
  tenants and operations the consumer needs.
- Rotate consumer authentication keys on a defined schedule and
  invalidate compromised keys immediately.

Dynamic consumer registration {{RFC7591}}, where offered, MUST be
gated by deployment policy.

## Mission identifier exposure across consumers

The canonical `mission.id` is emitted to every registered
consumer that holds a credential or queries Mission Status. Two
consumers participating in the same Mission can observe that they
share a Mission. This is inherent to the Mission's role as a
governance handle across substrates and is consented to at
approval time. Deployments that require Mission-identity
isolation across consumers (an unusual case typically arising
when a MAS serves competing tenants whose Mission identifiers
must not link) compose with a profile extension to the Framework;
such extensions are out of scope.

User-level cross-consumer correlation (a Resource Server linking
user activity across Missions) is addressed by pairwise `sub` (or
the AAuth equivalent) at the substrate level, not by Mission
identity.

## Cross-substrate token-leak surface

A Mission projected onto two substrates is exposed to the union of
both substrates' credential leak surfaces. A token leaked at the
OAuth substrate does not compromise the AAuth substrate's
credentials directly (each substrate sender-constrains its
credentials independently), but a leaked token may be replayable
against the OAuth substrate's Resource Servers until the Mission is
revoked or the token expires.

Cross-substrate revocation propagation per
{{cross-substrate-revocation-propagation}} is the primary
mitigation. Deployments that require tight propagation MUST advertise
and use `ssf_push` mode and SHOULD complement it with
`per_request` enforcement at high-assurance Resource Servers.

## Submission idempotency abuse

Both Flow A and Flow B rely on `proposal_correlation_id` for
idempotent submission. A consumer that reuses `proposal_correlation_id`
with conflicting payloads MUST be refused with `conflict` and MUST
NOT cause the MAS to create a second Proposal under the same
correlation key.

A consumer MUST treat `proposal_correlation_id` as deployment-secret
within its tenant boundary; predictable values invite collisions
under adversarial conditions.

## Event propagation timing

A consumer in `status_poll`-only mode learns of Mission lifecycle
changes only as fast as it polls. Deployments where prompt
revocation matters MUST NOT advertise `status_poll`-only for those
Missions; they MUST require `ssf_push` or `ssf_poll` and SHOULD
set substrate-local enforcement classes to include event-driven or
per-request modes per
{{I-D.draft-mcguinness-mission-oauth-profile}} Section 11.

## Direct-to-MAS submission (Flow B) risk

Flow B permits a client to submit Mission Intent directly to the
MAS, bypassing any substrate-local consumer at submission time.
This relaxes the substrate-local validation surface; the MAS becomes
solely responsible for input validation and policy enforcement on
the submitted Mission Intent.

Deployments enabling Flow B MUST:

- Authenticate the submitting client to MAS-grade standards (mTLS,
  signed assertion, or DPoP-bound bearer).
- Apply MAS-side validation at least as strict as the
  substrate-local validation a consumer would have performed.
- Record the `requesting_client` identity prominently in audit and
  in the Mission record.

A MAS that does not support Flow B advertises
`mission_submission_flow_b_supported: false` and MUST refuse direct
submissions.

## Anti-oracle preservation

Pairwise references presented to the wrong-sector caller MUST
produce `not_found`, indistinguishable from genuinely unknown
references. Implementations that return distinct error codes or
distinct response timing for wrong-sector references defeat the
anti-oracle property and expose the Mission space to enumeration.

## Replay across consumers

The MAS Mission Status response binds the recipient consumer's
audience and registered identifier. A signed response addressed to
consumer A MUST NOT be accepted by consumer B; consumer B's audience
identifier does not match. Consumers MUST validate `aud` before
trusting the body.

## Key rotation continuity

A consumer that depends on cached MAS-signed evidence (proxying
Mission Status responses to its own Resource Servers, for example)
MUST honor MAS key rotation. The MAS retains rotated keys per
{{jwks-publication}}; consumers MUST refresh the MAS JWKS on cache
miss and MUST NOT pin a single MAS key for the lifetime of a Mission.

# Privacy Considerations {#privacy-considerations}

## Cross-substrate activity correlation

A MAS is, by construction, a point at which a subject's governed
activity across multiple credential substrates converges on one
record. The canonical `mission.id` ({{mission-identifier}}) links
the OAuth-substrate and AAuth-substrate projections of the same
approved task. This linkage is intrinsic to the Mission's role as a
cross-substrate governance handle and is consented to at the
approval event, but it concentrates correlation capability at the
MAS that no single substrate authority holds on its own.
Deployments MUST treat the MAS Mission store as containing linked
cross-substrate activity and protect it accordingly.

## Concentration of subject and tenant data

The MAS holds, for every Mission, the Submitted Mission Intent, the
subject and approving principals (which may be RFC 9493 subject
identifiers carrying email, phone number, or account URIs
{{I-D.draft-ietf-secevent-subject-identifiers}}), the consent
disclosure, and the tenant identity -- across all tenants and
consumers it serves. This concentration is a higher-value target
than any single substrate authority's store. Deployments SHOULD
minimize the principal data forwarded at submission to what the MAS
requires to map the subject to its tenant namespace, and SHOULD
prefer opaque or pairwise subject formats where the substrate
profile permits.

## Mission identifier linkability across consumers

Because the MAS emits the same `mission.id` to every registered
consumer ({{mission-identifier}}), two consumers can determine that
they project the same Mission. This is the documented baseline; it
does not expose subject identity by itself, but a consumer that
also learns the subject can correlate that subject's tasks across
substrates. User-level correlation across distinct Missions is a
separate concern addressed by pairwise `sub` (or the AAuth
equivalent) at the substrate profile level, not by Mission
identity. Deployments requiring Mission-identity isolation across
mutually distrusting consumers compose a pairwise Mission
identifier through a Framework profile extension (out of scope
here).

## Mission Intent and consent-disclosure content

The integrity anchors carried on status responses
(`proposal_hash`, `authority_hash`, `consent_disclosure_hash`) are
one-way digests and do not expose the underlying content. The MAS,
however, retains the cleartext Mission Intent and consent
disclosure, which may carry purpose descriptions and business
context that are personal or commercially sensitive. The MAS MUST
NOT include this cleartext in status responses, events, or audit
projections shared with consumers that do not require it; consumers
receive integrity anchors and the Authority Set projection, not the
raw Intent.

## Authority Set projection minimization

A substrate projection ({{per-substrate-projection}}) MUST carry
only the authority the receiving consumer is registered to project.
The `dropped_types` mechanism ({{unknown-types}}) ensures a consumer
neither receives nor acts on authority outside its substrate, which
also limits the authority detail disclosed to each consumer to the
minimum it needs.

## Retention and erasure

The MAS advertises a retention policy at `mission_retention_policy_uri`.
Mission and Proposal records, and the audit log of lifecycle
transitions, are retained for governance and after-the-fact
detection of fabricated state ({{security-considerations}}); this
retention is in tension with data-subject erasure expectations.
Deployments subject to erasure obligations SHOULD separate
durable integrity anchors and pseudonymous identifiers (which may
be retained for audit) from directly identifying principal data
(which may be subject to erasure), and SHOULD document this split
in the published retention policy.

## Reason strings and audit logs

The optional `reason` string on lifecycle operations and the
caller identity recorded in the audit log
({{audit-recording}}) may contain personal data. Deployments SHOULD
avoid placing sensitive personal data in `reason` strings, which
propagate to consumers inside `mission.lifecycle-change` events.

# IANA Considerations {#iana}

This document creates registrations across several existing
registries and one new registry. Where the registration depends on
the Framework's registries, this document adds entries; the
registries themselves are created by the Framework.

## MAS Metadata Document and Well-Known URL

This document defines the MAS metadata document as an extension of
the Framework metadata document at the well-known URI
`/.well-known/mission-authority`, registered by the Framework. This
document does not register a new well-known URI; it adds members to
the metadata document.

This document defines the following member names for the MAS
metadata document. Each member is documented in this specification;
no central registry is created. Profile and consumer
specifications referencing these members SHOULD cite this
document.

- `proposals_collection_endpoint`
- `proposal_endpoint_template`
- `proposal_lifecycle_endpoint_template`
- `mission_endpoint_template`
- `mission_status_endpoint_template`
- `mission_lifecycle_endpoint_template`
- `mission_supported_consumer_substrates`
- `mission_event_delivery_modes_supported`
- `mission_event_stream_endpoint`
- `mission_status_polling_max_interval_seconds`
- `mission_submission_flow_b_supported`
- `mission_retention_policy_uri`
- `mission_consumer_registration_endpoint`
- `mission_response_media_type`
- `mission_state_authority`
- `mission_state_authority_mode`

Each entry's change controller is IETF; the reference is this
document; value semantics are as defined in Sections 5 and 11.

## Mission Status MAS Binding Media Type

This document registers the media type
`application/mas-mission-status-response+jwt` per {{RFC6838}}.

- Type: `application`
- Subtype: `mas-mission-status-response+jwt`
- Required parameters: none
- Optional parameters: none
- Encoding considerations: identical to those of `application/jwt`.
- Security considerations: see {{security-considerations}} of this
  document; in particular the response is JWS-signed and the
  signature is
  required for the consumer to trust the body.
- Interoperability considerations: distinct from the OAuth Profile's
  `application/mission-status-response+jwt` because the MAS payload
  carries the cross-substrate Authority Set serialization shape;
  the two media types are not interchangeable.
- Published specification: this document.
- Applications that use this media type: Mission Authority Servers
  and consumers per this specification.
- Change controller: IETF.

## Cross-Substrate Authority Set Serialization Media Type

This document registers the media type
`application/mission-authority-set+json` per {{RFC6838}} for the
substrate-neutral Authority Set serialization
({{neutral-serialization}}).

- Type: `application`
- Subtype: `mission-authority-set+json`
- Required parameters: none
- Optional parameters: `schema_version`
- Encoding considerations: UTF-8 JSON, JCS-canonical when used for
  integrity-anchor computation.
- Security considerations: see {{security-considerations}};
  integrity is provided via `authority_hash`, not by the media type
  itself.
- Published specification: this document.
- Applications that use this media type: Mission Authority Servers
  and consumers per this specification, and any other Mission-Bound
  Authorization component exchanging a substrate-neutral Authority
  Set.
- Change controller: IETF.

## MAS Lifecycle Event Shapes for SSF/CAEP Propagation

This document registers the following Security Event Token (SET)
event type URI:

- `https://schemas.karlmcguinness.com/secevent/mission/lifecycle-change`:
  event type for any Mission lifecycle transition or approval-event
  emission from a MAS. Required claims: `mission`, `mission_origin`,
  `tenant`, `state`, `version`, `committed_at`. Conditional claim:
  `prior_state` (required on transition emissions, absent on the
  approval-event emission). Optional claim: `reason`. See
  {{lifecycle-change-event-schema}} for the schema.

This event type follows the OpenID Shared Signals Framework SET
shape and the Continuous Access Evaluation Profile subject and
event conventions. The event-type URI is a stable identifier
under the `schemas.karlmcguinness.com/secevent` namespace.
Coordination with the OpenID Foundation Shared Signals and CAEP
working groups is anticipated for this event-type registration
when this document is submitted; until then, the URI is owned
by the author and may be aliased to an OpenID-registered URI by a
subsequent revision of this document.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the
Mission-Bound Authorization architecture for feedback that shaped
this specification. The MAS topology surfaced through the
Mission-Bound Authorization blog series and the spec breakdown's
Phase 3 substrate-breadth resolution.

--- back
