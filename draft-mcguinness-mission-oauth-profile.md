---
title: "Mission-Bound OAuth Profile"
abbrev: "Mission OAuth Profile"
category: std

docname: draft-mcguinness-mission-oauth-profile-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - authorization
 - rar
 - par
 - token-exchange
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-oauth-profile.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  RFC6749:
  RFC6750:
  RFC6838:
  RFC7009:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC7591:
  RFC7662:
  RFC8126:
  RFC8259:
  RFC8414:
  RFC8615:
  RFC8693:
  RFC8705:
  RFC8707:
  RFC9068:
  RFC9126:
  RFC9396:
  RFC9449:
  RFC9701:
  I-D.draft-mcguinness-mission-framework:

informative:
  RFC3339:
  RFC9110:
  RFC9470:
  RFC9700:
  RFC9728:
  I-D.draft-ietf-oauth-identity-chaining:
  I-D.draft-ietf-oauth-identity-assertion-authz-grant:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-id-continuation-assertion:
  I-D.draft-ietf-oauth-v2-1:

--- abstract

This document profiles OAuth 2.0 to bind issued credentials to a
durable, integrity-anchored Mission record per the Mission Framework.
A client submits a Mission Intent through Pushed Authorization
Requests (PAR); the Authorization Server validates and renders it,
creates a Mission on approval, derives `authorization_details`, and
binds issuance, refresh, and Token Exchange to Mission state. Tokens
carry a `mission` claim referencing the governance record. The
profile composes with RFC 9396 Rich Authorization Requests, RFC 9126
PAR, RFC 8693 Token Exchange, RFC 9449 DPoP, RFC 8705 mTLS, and RFC
9701 Signed Introspection Responses.

--- middle

# Introduction

This document profiles OAuth 2.0 {{RFC6749}} to compose the Mission
Framework {{I-D.draft-mcguinness-mission-framework}} with the OAuth
substrate. It defines the wire bindings, parameter names, claim
names, error codes, metadata fields, and operations a Mission-Bound
OAuth Authorization Server (AS) implements.

The profile makes the Mission a first-class OAuth artifact distinct
from authority. The client submits a structured Mission Intent
through PAR {{RFC9126}}. The Authorization Server validates and
renders it, records an Approved Mission per the Framework, derives
`authorization_details` {{RFC9396}}, and binds issuance, refresh,
and Token Exchange {{RFC8693}} to the Mission record. Tokens carry
a `mission` claim referencing the governance record.

The baseline `-00` of this profile does NOT define Mission Expansion
bindings. After Mission Expansion (separate specification)
stabilizes, this profile is revised to add the OAuth wire binding.

## OAuth versions

This profile composes with OAuth 2.0 {{RFC6749}} and is compatible
with OAuth 2.1 {{?I-D.draft-ietf-oauth-v2-1}}. Implementations
SHOULD adopt OAuth 2.1 baseline requirements (PKCE for public
clients, redirect-URI exact matching, no implicit grant) in
addition to the constraints this profile imposes.

## Document Organization {#document-organization}

This document is organized as follows.

{{conventions-and-definitions}} introduces terminology and notation.

{{profile-at-a-glance}} enumerates the wire surfaces a Mission-Bound
OAuth Authorization Server implements.

{{mission-intent-submission}} defines the `mission_intent` parameter
and its PAR-only submission rule.

{{authority-derivation}} defines AS-side derivation of
`authorization_details` from a Validated Mission Intent.

{{authority-set-entry-type-mission-resource-access}} defines the
`mission_resource_access` Authority Set entry type with its JSON
Schema and default narrowing rules.

{{the-mission-claim}} defines the `mission` JWT claim, including
canonical and pairwise modes.

{{mission-record-at-the-as}} describes the AS's role as state
authority and its Mission record.

{{lifecycle-gating}} defines which credential-derivation operations
gate on Mission state and the `mission_inactive` error.

{{mission-status}} defines the dedicated Mission Status operation
and the optional introspection projection.

{{mission-lifecycle-endpoint}} defines the Mission Lifecycle endpoint.

{{revocation-enforcement-classes}} defines the four enforcement
classes and their advertisement.

{{sender-constraint}} requires sender-constrained credentials.

{{as-metadata}} enumerates the discovery extensions.

{{composition-with-other-specifications}} addresses adjacent specs.

{{security-considerations}} and {{privacy-considerations}} address
security and privacy threats.

{{iana}} requests IANA actions.

## Relationship to the Framework

The Framework {{I-D.draft-mcguinness-mission-framework}} defines:

- The Mission Proposal and Mission data model and lifecycles.
- The Mission Intent JSON schema.
- The typed Authority Set entry shape.
- The Principal Model.
- The Mission Status interface (abstract).
- Integrity anchors.
- Pairwise reference framework.

This profile binds those abstract elements onto OAuth-specific wire
shapes. It does not redefine Framework semantics.

# Conventions and Definitions {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

## Notation

This document uses the notation defined in
{{I-D.draft-mcguinness-mission-framework}}. In addition:

- HTTP message examples follow the conventions of {{RFC9110}};
  long URLs and form parameters are wrapped for display.
- JWT examples are shown as decoded JSON payloads with separate
  header objects; on the wire the JWS Compact Serialization
  {{RFC7515}} applies.

## Terminology

Terms defined in the Framework
{{I-D.draft-mcguinness-mission-framework}} are inherited here.
This document additionally uses:

**Authorization Server (AS)**:
: The OAuth Authorization Server, acting as the state authority for
Missions per the Framework's terminology.

**Resource Server (RS)**:
: An OAuth Resource Server consuming Mission-bound access tokens.

**Resource AS**:
: An Authorization Server adjacent to a Resource Server in
cross-AS topology ({{RFC8693}} audience).

**Mission-bound access token**:
: An access token issued by the AS under this profile, carrying a
`mission` claim.

**Mission-bound refresh token**:
: A refresh token issued by the AS under this profile, bound to a
specific Mission (see {{refresh-token-binding}}).

**Mission Status Response (OAuth wire form)**:
: A JWS-signed payload returned by the AS's
`mission_status_endpoint`, matching the Framework's abstract
Mission Status Response object with OAuth-specific wire-form
members. See {{mission-status-response-wire-form}}.

# Profile at a Glance {#profile-at-a-glance}

A Mission-Bound OAuth AS implements these surfaces:

1. Accepts `mission_intent` as a top-level authorization request
   parameter, submitted through PAR {{RFC9126}}.
2. Validates the Mission Intent, creates a Mission Proposal, renders
   consent disclosure.
3. On approval, creates a Mission record per the Framework, derives
   `authorization_details` containing one or more `mission_resource_access`
   RAR entries {{RFC9396}}.
4. Issues access tokens (JWT per {{RFC9068}} or opaque) carrying a
   `mission` claim with `id`/`ref`, `origin`, `authority_hash`, and
   `version`.
5. Gates refresh, Token Exchange {{RFC8693}}, and any other
   credential-derivation path on Mission state.
6. Exposes a dedicated Mission Status operation (by mission
   reference) and an optional Mission-snapshot extension on token
   introspection {{RFC7662}}.
7. Exposes a Mission lifecycle endpoint distinct from RFC 7009
   {{RFC7009}} token revocation.
8. Sender-constrains credentials via DPoP {{RFC9449}} or mTLS
   {{RFC8705}}.
9. Advertises supported Mission capabilities in AS metadata
   {{RFC8414}}.

# Mission Intent Submission {#mission-intent-submission}

## `mission_intent` parameter {#mission-intent-parameter}

The `mission_intent` parameter is a top-level OAuth authorization
request parameter. Its value is a JSON object {{RFC8259}}
conforming to the Mission Intent schema defined in
{{I-D.draft-mcguinness-mission-framework}}.

This profile REQUIRES that `mission_intent` be submitted through PAR
{{RFC9126}}. A direct authorization-endpoint submission carrying
`mission_intent` MUST be refused with `invalid_request` and an
error description identifying the violation.

Encoding: the JSON object is serialized as UTF-8 and form-urlencoded
as the `mission_intent` parameter value within the PAR request body
(`application/x-www-form-urlencoded`).

### Worked PAR exchange {#par-exchange}

**PAR request** from the client to the AS's PAR endpoint:

~~~ http-message
POST /as/par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

response_type=code
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
&scope=openid
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&mission_intent=%7B%22goal%22%3A%22Reconcile%20Q3%20invoices...
%22%2C%22objects%22%3A%5B%22https%3A%2F%2Ferp.example.com%2Fapi%2Finvoices%22
%5D%2C%22constraints%22%3A%5B%5D%2C%22success_criteria%22%3A%5B%5D%2C
%22mission_expiry%22%3A%222026-12-31T23%3A59%3A59Z%22%7D
~~~

The form-urlencoded `mission_intent` value, when decoded, is a JSON
object matching the Framework's Mission Intent schema. The example
above abbreviates the JSON for display.

**PAR success response** from the AS:

~~~ http-message
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{
  "request_uri":
    "urn:ietf:params:oauth:request_uri:nq4SY-7uxIWnZqJqQABg",
  "expires_in": 60
}
~~~

The `request_uri` is then used by the client at the authorization
endpoint:

~~~ http-message
GET /as/authorize?client_id=s6BhdRkqt3&request_uri=urn%3Aietf%3Aparams
%3Aoauth%3Arequest_uri%3Anq4SY-7uxIWnZqJqQABg HTTP/1.1
Host: as.example.com
~~~

After the approving principal authenticates and approves, the AS
creates the Mission record per {{mission-record-at-the-as}} and
issues an authorization code:

~~~ http-message
HTTP/1.1 302 Found
Location: https://client.example.org/cb?code=SplxlOBeZQQYbYS6
WxSbIA&state=xyz&iss=https%3A%2F%2Fas.example.com
~~~

The client then redeems the code at the token endpoint
({{authorization-code-redemption}}).

### Validation rules

The AS MUST:

- Parse the `mission_intent` value as JSON {{RFC8259}}, rejecting
  parse failures with `invalid_request` and an error description
  identifying the parse error.
- Reject duplicate JSON object member names with `invalid_request`.
- Validate the Mission Intent against the published
  `mission_intent_schema_uri` and against deployment policy
  constraints.
- Reject Mission Intents whose validated form would exceed
  requester bounds (registered client maximums, deployment policy
  ceilings).
- Narrow values where deployment policy permits, per the narrowing
  rules of {{I-D.draft-mcguinness-mission-framework}}. The
  Validated Mission Intent is what is recorded on the Mission
  Proposal and what `proposal_hash` covers.

### Maximum size

The AS advertises `mission_intent_max_size` in its AS metadata
document as a positive integer number of octets, measured as the
length of the UTF-8 form-urlencoded `mission_intent` value before
PAR transport. The default value is 16384 octets. Submissions
exceeding the advertised size MUST be refused with
`invalid_request`.

## Interaction with `scope` and `authorization_details`

When `mission_intent` is submitted, the client MAY additionally
submit:

- `scope`: a space-separated list of OAuth scopes. The AS MUST
  treat client-submitted `scope` as a requested subset of the
  Authority Set derived from the Validated Mission Intent. The
  AS MUST narrow or refuse scopes not derivable from the
  Validated Mission Intent's `authorization_details` per
  {{authority-derivation}}.
- `resource` (Resource Indicators {{RFC8707}}): one or more URIs
  identifying intended Resource Servers. The AS MUST refuse
  resources not authorized under any
  `mission_resource_access` entry derived from the Validated
  Mission Intent.

Clients MUST NOT submit `authorization_details` directly when
submitting `mission_intent`; the AS derives `authorization_details`
from the Validated Mission Intent. A request carrying both
MUST be refused with `invalid_request`.

## Client registration extensions {#client-registration-extensions}

A client that submits Mission Intents declares its capabilities
through the following client-registration metadata members
({{RFC7591}}):

- `mission_purposes_registered` (array of strings, optional): the
  set of `purpose` URIs this client may submit in Mission Intents.
  The AS MUST refuse a `mission_intent` whose `purpose` is not in
  this set, when the AS uses client-registered purposes.
- `mission_intent_schema_uri_supported` (array of strings,
  optional): the deployment-specific Mission Intent schema
  identifiers this client supports.
- `mission_max_derivations_max` (string, optional): the maximum
  `max_derivations` value this client may request. The AS MUST
  refuse Mission Intents requesting values above this ceiling, or
  narrow.

The AS MAY refuse client registration that does not declare these
capabilities when the deployment's policy requires explicit client
declaration. Implementations using OAuth Dynamic Client Registration
{{RFC7591}} bind these as Client Metadata members.

# Authority Derivation {#authority-derivation}

The AS derives `authorization_details` from the Validated Mission
Intent on the Mission Proposal. The derivation MUST:

- Produce one or more Authority Set entries (typed per
  {{I-D.draft-mcguinness-mission-framework}}).
- Bound every entry's authority by the Validated Mission Intent's
  `objects`, `constraints`, and `context` fields.
- Compute `authority_hash` over the derived Authority Set per the
  Framework's domain-separated, authorization-domain-bound envelope.

This profile registers `mission_resource_access` as one Authority
Set entry type ({{authority-set-entry-type-mission-resource-access}}).

## Derivation algorithm

The AS executes the following algorithm at the approval event:

1. For each `objects` entry in the Validated Mission Intent that
   identifies a Resource Server URI:
   - Construct a `mission_resource_access` entry whose
     `authority.resource` matches the entry.
   - Derive `authority.actions` from the Validated Mission Intent's
     `constraints`, `success_criteria`, and deployment policy
     mapping rules. The AS MAY use either an explicit deployment-
     defined Intent-to-action mapping registry or a deployment-
     specific NLP-assisted derivation; in either case the AS MUST
     record the derivation policy version (`policy_version`) on
     the Mission's `binding_evidence`.
   - Derive `authority.constraints` by translating Validated
     Mission Intent `constraints` and `context` members to
     resource-applicable Common Constraints (the Mission-level
     `aal` and `max_derivations` are recorded at the Mission
     level, not duplicated per entry).
2. For each `objects` entry identifying a non-RS resource (e.g.,
   a registered tool URI, a data domain identifier), the AS MAY
   produce additional Authority Set entries of types other than
   `mission_resource_access` (deployment- or ecosystem-specific
   types) provided each entry is registered in the Mission
   Authority Set Type registry and is bounded by the Validated
   Mission Intent.
3. Compute `authority_hash` over the constructed Authority Set.

Implementations that produce non-deterministic Authority Sets
(e.g., NLP-assisted derivation that varies between runs over the
same input) MUST capture the resulting Authority Set on the Mission
record verbatim; the integrity anchor binds the recorded result,
not the derivation process.

## Client-submitted `authorization_details` interaction

This profile inverts the plain RAR client-submits-authority pattern:
the client submits Mission Intent (a task description), and the AS
derives `authorization_details` (the OAuth authority). The user
approves the rendered Validated Mission Intent plus the derived
Authority Set.

When the client submits `mission_intent`, the client MUST NOT
submit `authorization_details` in the same request; the AS rejects
such requests with `invalid_request` per
{{interaction-with-scope-and-authorization-details}}.

# Authority Set Entry Type: `mission_resource_access` {#authority-set-entry-type-mission-resource-access}

The `mission_resource_access` type is registered in the Mission
Authority Set Type Registry created by the Framework
{{I-D.draft-mcguinness-mission-framework}}.

## Schema

The canonical JSON Schema for a `mission_resource_access` entry's
`authority` payload is:

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:mission-resource-access:1",
  "title": "mission_resource_access authority payload",
  "type": "object",
  "required": ["resource", "actions"],
  "additionalProperties": false,
  "properties": {
    "resource": {
      "type": "string",
      "format": "uri",
      "minLength": 1
    },
    "actions": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": {
        "type": "string",
        "pattern": "^[A-Za-z0-9_.:-]+$"
      }
    },
    "constraints": {
      "type": "object",
      "additionalProperties": true
    }
  }
}
~~~

### Action identifier ABNF

Action identifiers in `actions[*]` follow the ABNF:

~~~
action-id   = 1*64( ALPHA / DIGIT / "_" / "." / ":" / "-" )
~~~

Action identifiers SHOULD use the dotted-namespace form
(`<noun>.<verb>`, e.g., `invoices.read`, `journal-entries.write`).
Identifiers are case-sensitive.

## Example entry

~~~ json
{
  "type": "mission_resource_access",
  "specification_uri":
    "https://mcguinness.github.io/mission-bound-authorization/specs/mission_resource_access-v1",
  "schema_digest":
    "sha-256:rcDpZQ4eFm0bKLqJv7M2sNHbR8tY9pXkE3sVrLqJpQQ",
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
~~~

## Authority payload semantics

The `authority` object carries:

- `resource` (string, required, URI format): the protected resource
  the authority applies to.
- `actions` (array of strings, required, minItems 1): permitted
  action identifiers per the ABNF above.
- `constraints` (object, optional): per-entry registered constraints
  applying to actions on this resource.

## Normalization Profile

The `mission_resource_access` type uses
`urn:mbo:norm:mission-resource-access:1`:

- `resource`: RFC 3986 syntax-based normalization {{RFC9728}}.
- `actions`: order-insensitive; sorted ascending by code-point
  order; duplicates removed.
- `constraints`: member rules per the registered Common Constraint
  for each member name. Unknown members refused at validation.

## Equality, subset, and intersection rules

**Equality**: two entries are equal when their normalized
`resource`, `actions` (as ordered set), and `constraints` are
identical.

**Subset**: entry A is a subset of entry B when:

- A.`resource` equals B.`resource` (after URI normalization).
- A.`actions` is a subset of B.`actions`.
- For every member key K in A.`constraints`, K is present in
  B.`constraints` and A.`constraints[K]` is a subset of
  B.`constraints[K]` per the registered Common Constraint's
  subset rule.

**Intersection**: when both entries reference the same `resource`,
the intersection's `actions` is the set-intersection of the two
entries' `actions`, and the intersection's `constraints[K]` is the
constraint-specific intersection of corresponding values for each
shared key. If the resources differ, the intersection is empty.

**Unknown-field handling**: members of `authority` not listed in
the schema MUST be refused. Members of `constraints` whose names
are not registered Common Constraints MUST be refused, unless the
entry's `narrowing_profile` registers explicit pass-through for
specific extension keys.

## Default narrowing rules

Under `urn:mbo:narrowing:default-v1` (the Framework's default
narrowing profile), derived `mission_resource_access` entries are
accepted at credential derivation only when they are subsets of
some Mission Authority Set entry per the subset rule above.

# The `mission` Claim

Access tokens issued under this profile carry a `mission` claim.
The claim value is a JSON object identifying the Mission record the
credential was derived under.

## Canonical mode

In canonical mode the claim is:

~~~ json
{
  "mission": {
    "id": "msn_01J9Z2P8BQ4Y3F0V0K9D6Z7M1",
    "origin": "https://as.example.com",
    "authority_hash": "sha-256:fS8h4w7Z3Lq...",
    "version": 1
  }
}
~~~

- `id` (string, required in canonical mode): canonical Mission ID.
- `origin` (URL, required): the AS issuer URL; resolves via
  `{origin}/.well-known/mission-authority`.
- `authority_hash` (string, required): the integrity anchor for the
  Authority Set from which this credential was derived.
- `version` (integer, required): Mission record version at issuance.

## Pairwise mode

When the AS emits pairwise references for this audience-sector, the
claim is:

~~~ json
{
  "mission": {
    "ref": "opq_mW8Jx0qN9PfBdC4LqRy2Xg",
    "origin": "https://as.example.com",
    "authority_hash": "sha-256:fS8h4w7Z3Lq...",
    "version": 1
  }
}
~~~

- `ref` (string, required in pairwise mode): the audience-sector
  pairwise Mission Reference.

`id` and `ref` are mutually exclusive. The AS MUST NOT emit both on
the same access token.

## Mode selection

The AS selects mode per audience-sector advertised in its metadata
document. The token audience determines which sector applies and
therefore which mode.

## Refresh and exchange continuity

When refresh produces a new credential for the same audience and
sector, the AS MUST preserve the chosen mode and the chosen
reference (pairwise references are stable within sector). When
Token Exchange {{RFC8693}} produces a credential for a different
audience, the AS mints the reference appropriate to the target
audience's sector. The AS MUST NOT copy an upstream pairwise
reference into a different sector.

## Opaque access tokens

Opaque access tokens expose the same `mission` claim members through
the token introspection extension (Section 9.2).

# Mission Record at the AS

Per {{I-D.draft-mcguinness-mission-framework}}, the AS creates a
Mission Proposal on `mission_intent` submission and creates a
Mission record at the approval event. The Mission record carries:

- Canonical `mission.id`.
- `mission.origin` = AS issuer URL.
- The Validated Mission Intent.
- The derived Authority Set.
- The three integrity anchors.
- The Principal Model fields.
- Binding evidence.
- Lifecycle state.
- Source `proposal_id`.

The AS's Mission record is the canonical record under this profile.
A cross-substrate deployment that introduces a Mission Authority
Server (see the MAS specification) makes the MAS the state
authority; the AS becomes a projection issuer per that profile.

# Lifecycle Gating

The AS MUST gate the following operations on Mission state:

- Authorization code redemption that derives a new access token.
- Refresh token rotation.
- Token Exchange {{RFC8693}} grants.
- Identity Assertion JWT Authorization Grant
  {{I-D.draft-ietf-oauth-identity-assertion-authz-grant}} issuance.
- Any other credential-derivation path.

When the Mission state is not `active` at the moment of derivation,
the AS MUST refuse the derivation. The refusal uses the OAuth error
response `invalid_grant` with an extension parameter
`mission_state` carrying the current Mission state value.

## `mission_inactive` error response

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "error_description":
    "Mission is not in 'active' state and cannot derive new credentials.",
  "mission_state": "revoked"
}
~~~

Profile-specific error code: `mission_inactive` (registered for
deployments preferring a distinct error code rather than reusing
`invalid_grant`).

# Mission Status

This profile binds the Framework's abstract Mission Status interface
to two OAuth operations:

1. A **dedicated Mission Status operation** (by mission reference)
   at a new endpoint.
2. An **optional Mission-snapshot projection** on token introspection
   {{RFC7662}}.

These are distinct operations.

## Dedicated Mission Status operation

The AS publishes a `mission_status_endpoint` URL in its AS metadata
document.

### Request

The request is an HTTPS POST with `application/x-www-form-urlencoded`
body containing:

- `mission` (string, required): the Mission reference. Either a
  canonical `mission.id` or a pairwise `mission.ref`.
- `audience` (string, required): the audience identifier of the
  requesting consumer.
- `nonce` (string, required): a client-generated nonce for
  request-binding.

The request MUST be authenticated. The AS MUST accept at least one
of:

- `client_credentials` client authentication with the AS.
- mTLS-authenticated request {{RFC8705}}.
- DPoP-bound bearer token issued by the AS for status queries
  {{RFC9449}}.

### Response

On success the AS returns a JWS signed with a key published in the
AS's `jwks_uri`. The JWS uses `typ` value
`application/mission-status-response+jwt` (registered in
{{iana}}). The JWS payload is:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://docs.example.com",
  "sub": "client_id_of_requester",
  "nonce": "client-provided-nonce",
  "iat": 1718380800,
  "exp": 1718380860,
  "mission_status": {
    "state": "active",
    "mission_id_or_ref": { "id": "msn_01J9Z2..." },
    "origin": "https://as.example.com",
    "proposal_hash": "sha-256:...",
    "authority_hash": "sha-256:...",
    "consent_disclosure_hash": "sha-256:...",
    "policy_version": "as.example.com:standard@2026-06-01",
    "authority_set_projection": [
      { "type": "mission_resource_access", "...": "..." }
    ],
    "issued_at": "2026-06-09T15:00:00Z",
    "expires_at": "2026-06-09T15:01:00Z",
    "version": 1
  }
}
~~~

### Anti-oracle property

The AS MUST authenticate the requester and authorize the requester
for the requested Mission reference and audience. A Mission reference
is never a bearer capability.

Unknown Mission references and known-but-unauthorized references
MUST produce indistinguishable responses (HTTP 404 with no
identifying body content beyond a generic `not_found` error symbol).

### Errors

Mission Status responses use the following error symbols, mapped to
HTTP status codes:

| Symbol | HTTP | Description |
|---|---|---|
| `ok` | 200 | Mission found and visible. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | Mission reference does not exist OR is not visible to this consumer. |
| `terminated` | 410 | Mission is in a terminal state. Response includes state. |
| `suspended` | 423 | Mission is suspended. Response includes state. |
| `rate_limited` | 429 | Consumer is rate-limited. |
| `unavailable` | 503 | AS temporarily can't serve status. |

## Token introspection Mission projection

When a consumer presents an access token to the AS's introspection
endpoint {{RFC7662}}, the AS MAY include a `mission` claim in the
introspection response containing a Mission snapshot.

This profile RECOMMENDS that introspection responses carrying a
Mission projection use RFC 9701 {{RFC9701}} signed responses.

The introspection projection is an OPTIMIZATION for consumers that
already query by token. It does NOT replace the dedicated Mission
Status operation. Consumers needing by-mission-reference lookups,
audience-pairwise resolution, or signed evidence independent of a
specific token MUST use the dedicated operation.

# Mission Lifecycle Endpoint

The AS publishes a `mission_lifecycle_endpoint` URL distinct from
RFC 7009 {{RFC7009}} token revocation.

## Operations

The endpoint accepts authenticated POST requests:

- `revoke`: terminate the Mission. Mission transitions to `revoked`.
- `suspend`: pause the Mission. Mission transitions to `suspended`.
- `resume`: return a suspended Mission to `active`.
- `complete`: mark the Mission as completed. Mission transitions to
  `completed`.

Each operation takes:

- `mission` (string, required): the Mission reference.
- `reason` (string, optional): a human-readable reason recorded in
  audit.

The AS MUST authenticate and authorize the requester for the
operation on the requested Mission.

## RFC 7009 cascade

Mission revocation cascades to all access tokens, refresh tokens,
and ID-JAGs derived from the Mission, per the AS's advertised
enforcement classes (Section 11).

The AS MAY additionally invoke RFC 7009 {{RFC7009}} token revocation
for specific outstanding tokens when the AS knows their `jti`. RFC
7009 alone does NOT revoke a Mission; the lifecycle endpoint is the
authoritative Mission state change.

# Revocation Enforcement Classes

A Mission-Bound OAuth deployment advertises its enforcement classes
in AS metadata under `mission_enforcement_classes_supported`. The
defined classes are:

- **`issuance`**: Mission state is consulted at each derivation
  event (refresh, exchange, ID-JAG issuance). Already-issued
  offline self-contained tokens are NOT invalidated; they remain
  valid until natural expiry.
- **`introspection`**: token introspection returns `active=false`
  for tokens whose Mission state disallows use, even if the token
  itself has not expired.
- **`event_driven`**: state changes propagate to Resource Servers
  via Shared Signals/CAEP or equivalent event channel.
- **`per_request`**: high-assurance Resource Servers query Mission
  Status or validate sufficiently fresh state for each consequential
  request.

A deployment also advertises `mission_max_stale_seconds` indicating
the maximum tolerated stale interval for revocation propagation.

## Recommended access-token TTL

For deployments where Mission revocation propagation matters but
only `issuance` class is deployed, Mission-Bound access tokens
SHOULD use TTLs aligned with the declared
`mission_max_stale_seconds`. Standard OAuth defaults (3600 seconds)
may be too long; values in the range 60-300 seconds are typical
for `issuance`-only deployments where revocation matters.

Deployments with `event_driven` or `per_request` enforcement may
use longer TTLs because revocation propagates out-of-band.

# Sender Constraint

Access tokens issued under this profile MUST be sender-constrained
using one of:

- DPoP {{RFC9449}}.
- mTLS {{RFC8705}}.

The AS advertises supported sender-constraint mechanisms in AS
metadata. Bearer-only tokens are NOT permitted under this profile.

# AS Metadata

The AS metadata document {{RFC8414}} carries the following
Mission-Bound members in addition to standard OAuth metadata:

- `mission_intent_schema_uri` (URL): JSON Schema for `mission_intent`.
- `mission_intent_max_size` (integer): octet limit on `mission_intent`.
- `mission_status_endpoint` (URL): dedicated Mission Status operation.
- `mission_lifecycle_endpoint` (URL): Mission lifecycle operations.
- `authority_set_types_supported` (array): Authority Set entry types
  this AS issues.
- `mission_pairwise_supported` (boolean): whether the AS emits
  pairwise references.
- `mission_pairwise_sector` (string, conditional): sector type if
  `mission_pairwise_supported` is `true`.
- `mission_enforcement_classes_supported` (array): one or more of
  `issuance`, `introspection`, `event_driven`, `per_request`.
- `mission_max_stale_seconds` (integer): maximum tolerated stale
  interval for revocation propagation.
- `mission_framework_versions_supported` (array): spec revisions of
  the Framework this AS supports.

# Composition with Other Specifications

## Identity-chaining decomposition

Three identity-chaining mechanisms compose with this profile, each
with a distinct role:

- {{I-D.draft-ietf-oauth-identity-assertion-authz-grant}} (ID-JAG):
  common-IdP case. The user is resolved by a single IdP; Resource
  ASes consume the ID-JAG. This profile defines how `mission` claims
  thread through ID-JAGs in the common-IdP scenario.
- {{I-D.draft-mcguinness-oauth-id-continuation-assertion}}: onward
  issuance in a common-IdP chain when SaaS1 calls SaaS2 calls
  SaaS3. Composes with ID-JAG.
- {{I-D.draft-ietf-oauth-identity-chaining}}: cross-domain mapping
  where issuer and subject identifiers differ across trust domains.
  This is the cross-IdP case.

This profile composes with all three, with explicit role per
scenario.

## Actor and instance identity

This profile composes with:

- {{I-D.draft-mcguinness-oauth-actor-profile}}: the `act` claim
  structure for delegation chains.
- {{I-D.draft-mcguinness-oauth-client-instance-assertion}}: client
  instance identity in Token Exchange `actor_token`.

## RFC 9470 step-up

RFC 9470 {{RFC9470}} performs authentication step-up. It MAY satisfy
an `aal` constraint (per the Mission Framework's Common Constraints
registry) but it does NOT perform Mission Expansion. Expansion is a
governance operation requiring approval; step-up is an authentication
operation.

This profile MAY compose with RFC 9470 step-up when a denied
request would be permitted by satisfying an `aal` constraint via
fresh authentication.

## What this profile does NOT cover

- Mission Expansion semantics: defined in a separate Mission
  Expansion specification. The baseline `-00` of this profile does
  NOT define expansion bindings; a coordinated revision will add
  them after the Mission Expansion specification stabilizes.
- Resource-AS authority validation for open-world tools: Delegated
  Authority Validation specification.
- Transaction Token Chaining composition: Mission-Bound Transaction
  Token Chaining specification.
- Runtime per-action enforcement: Mission-Bound Runtime Enforcement
  Profile.
- Cross-substrate (MAS) topology: Mission Authority Server
  specification.

# Security Considerations

## Mission revocation and offline tokens

Mission revocation does not claim to invalidate offline
self-contained tokens immediately unless `event_driven` or
`per_request` enforcement is deployed. Deployments where revocation
propagation matters MUST advertise their enforcement classes
honestly (Section 11). Implementers SHOULD NOT assume revocation is
instantaneous.

## Token-scope vs Mission-scope

A leaked or stolen access token cannot escalate Mission authority;
the Authority Set committed by `authority_hash` is the upper bound.
However, a leaked refresh token can produce new credentials
indefinitely until the Mission is revoked or the refresh token is
explicitly revoked. Refresh tokens MUST be sender-constrained per
Section 12.

## Mission Status enumeration

Per the anti-oracle property, the AS MUST NOT distinguish unknown
Mission references from known-but-unauthorized references at the
Mission Status endpoint. Implementations that leak this distinction
expose the Mission space to enumeration.

## RFC 9701 vs new media type

The introspection projection uses RFC 9701 {{RFC9701}}, an existing
specification scoped to token introspection. The dedicated Mission
Status operation uses a new media type
(`application/mission-status-response+jwt`) registered in
{{iana}} because RFC 9701 does not apply to by-reference status
lookups. Implementations MUST NOT use RFC 9701 for the dedicated
operation.

## Cross-substrate token-leak surface

When a Mission is consumed by both OAuth and AAuth substrates under
a Mission Authority Server topology, an OAuth-side token leak does
NOT compromise the Mission's AAuth-side derivations. Each substrate
issues its own credentials sender-constrained to its substrate.
However, lifecycle state propagation across substrates depends on
the MAS topology being correctly configured.

## General OAuth security

This profile inherits the OAuth 2.0 Best Current Practice
{{RFC9700}}. Implementers MUST follow current OAuth security
guidance for the OAuth surfaces this profile composes with.

# IANA Considerations {#iana}

## OAuth Parameters Registry

This document registers `mission_intent` as an OAuth parameter
applicable to the authorization request, per the registration
policy of the OAuth Parameters Registry.

## JWT Claims Registry

This document registers `mission` as a JWT claim per {{RFC7519}}.

- Claim Name: `mission`
- Claim Description: Reference to the governing Mission record.
- Change Controller: IETF
- Reference: this document
- Value type: JSON object with `id` or `ref`, `origin`,
  `authority_hash`, and `version` members.

## OAuth Error Codes Registry

This document registers `mission_inactive` as an OAuth error code
(profile-specific extension).

## Mission Authority Set Type Registry

This document registers `mission_resource_access` in the Mission
Authority Set Type Registry created by the Mission Framework.

- Type: `mission_resource_access`
- Specification URI: this document
- Schema version: `1`
- Normalization, equality, subset, intersection, and unknown-field
  rules: per Sections 5 and 6.

## Media Type Registry

This document registers the following media types per RFC 6838:

- `application/mission-status-response+jwt`: signed Mission Status
  response payload format. Format: JWS Compact Serialization with the
  payload structure defined in Section 9.1.

## OAuth Authorization Server Metadata

This document registers the following members in the OAuth
Authorization Server Metadata registry:

- `mission_intent_schema_uri`
- `mission_intent_max_size`
- `mission_status_endpoint`
- `mission_lifecycle_endpoint`
- `authority_set_types_supported`
- `mission_pairwise_supported`
- `mission_pairwise_sector`
- `mission_enforcement_classes_supported`
- `mission_max_stale_seconds`
- `mission_framework_versions_supported`

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the
Mission-Bound Authorization architecture for feedback that shaped
this specification.

--- back
