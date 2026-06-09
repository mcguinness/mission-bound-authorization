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
  RFC7521:
  RFC7591:
  RFC7662:
  RFC7800:
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

{{the-mission-claim}} defines the `mission` JWT claim.

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

## Interaction with `scope` and `authorization_details` {#interaction-with-scope-and-authorization-details}

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
     `acr`, `amr`, and `max_derivations` are recorded at the
     Mission level, not duplicated per entry).
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

# The `mission` Claim {#the-mission-claim}

Access tokens issued under this profile carry a `mission` claim.
The claim value is a JSON object identifying the Mission record the
credential was derived under.

## `mission` claim schema {#mission-claim-schema}

The canonical JSON Schema for the `mission` claim value is:

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:oauth-mission-claim:1",
  "title": "OAuth mission claim",
  "type": "object",
  "required": ["id", "origin", "authority_hash", "version"],
  "additionalProperties": false,
  "properties": {
    "id":     { "type": "string", "pattern": "^[A-Za-z0-9_-]{1,256}$" },
    "origin": { "type": "string", "format": "uri" },
    "authority_hash": {
      "type": "string",
      "pattern": "^sha-(256|384|512):[A-Za-z0-9_-]+$"
    },
    "version": { "type": "integer", "minimum": 1 }
  }
}
~~~

Members:

- `id` (string, required): canonical `mission.id` per the Framework.
- `origin` (string, required, URI format): the AS issuer URL.
  Equal to `mission.origin`. Consumers resolve via
  `{origin}/.well-known/mission-authority` per {{RFC8615}}.
- `authority_hash` (string, required): the integrity anchor for
  the Authority Set from which this credential was derived. Format
  per the Framework's integrity-anchor encoded form.
- `version` (integer, required, minimum 1): Mission record version
  at issuance. Increments on each AS-recorded state change to the
  Mission record's content; used by consumers to detect stale
  evidence.

## Example claim {#mission-claim-example}

~~~ json
{
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "version": 1
  }
}
~~~

## Refresh and exchange continuity {#refresh-token-binding}

A Mission-bound refresh token is bound to the Mission whose `id`
appears in the refresh token's `mission` claim (when the refresh
token is a JWT) or in the AS's per-token state (when the refresh
token is opaque). The AS MUST refuse a refresh-token rotation when
the bound Mission's state is not `active`.

When refresh produces a new credential the AS preserves the
Mission identity in the new credential's `mission` claim. Token
Exchange {{RFC8693}} producing a credential for a different
audience preserves the same `mission.id` in the new credential's
claim; the Mission is the same, only the audience differs.

## Opaque access tokens

Opaque access tokens carry the `mission` claim only through the
token introspection extension ({{token-introspection-mission-projection}}).
The opaque token itself is not parseable by Resource Servers; RSes
that need `mission` MUST introspect.

# Authorization Code Redemption {#authorization-code-redemption}

After the PAR exchange of {{par-exchange}} and approval-event
completion, the client redeems the authorization code at the token
endpoint:

**Token request** from the client:

~~~ http-message
POST /as/token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
~~~

**Token response** from the AS:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6...",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "rt_8sR3pYwL2qX5tZ7vB1nM4kF9eT0jC6yH",
  "scope": "openid",
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "specification_uri":
        "https://datatracker.ietf.org/doc/draft-mcguinness-mission-oauth-profile",
      "schema_version": "1",
      "authority": {
        "resource": "https://erp.example.com",
        "actions": ["invoices.read", "journal-entries.write"]
      },
      "narrowing_profile": "urn:mbo:narrowing:default-v1"
    }
  ]
}
~~~

The `access_token` is a JWT per {{RFC9068}} carrying the `mission`
claim. The decoded payload:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "client_id": "s6BhdRkqt3",
  "iat": 1797840000,
  "exp": 1797840300,
  "jti": "tok_8K2nP4qV9rL3tY6sB1z",
  "scope": "openid",
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "schema_version": "1",
      "authority": {
        "resource": "https://erp.example.com",
        "actions": ["invoices.read", "journal-entries.write"]
      },
      "narrowing_profile": "urn:mbo:narrowing:default-v1"
    }
  ],
  "cnf": {
    "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "version": 1
  }
}
~~~

The `cnf` claim per {{!RFC7800}} carries the DPoP JWK thumbprint
binding the token to the client's DPoP key; under mTLS the `cnf`
claim carries `x5t#S256` per {{RFC8705}}. Resource Servers MUST
verify the binding before honoring the token.

# Token Exchange {#token-exchange}

A client (or downstream service acting as a client) MAY use Token
Exchange {{RFC8693}} to obtain a new credential for a different
audience. The exchange MUST gate on Mission state.

**Token exchange request**:

~~~ http-message
POST /as/token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=eyJhbGciOiJFUzI1NiIsImtpZCI6...
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&audience=https%3A%2F%2Fdownstream.example.com
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
~~~

**Token exchange response**:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "issued_token_type":
    "urn:ietf:params:oauth:token-type:access_token",
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6...",
  "token_type": "DPoP",
  "expires_in": 300
}
~~~

The new access token carries the `mission` claim referencing the
same Mission as the `subject_token`, with the same `mission.id`.
Only the OAuth audience (`aud` claim) and the substrate-level
authority projection differ; the Mission identity is preserved
across the exchange.

If the Mission's state at exchange time is not `active`, the AS
MUST refuse the exchange with the `mission_inactive` error response
defined in {{lifecycle-gating}}.

# Mission Record at the AS {#mission-record-at-the-as}

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

# Lifecycle Gating {#lifecycle-gating}

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

# Mission Status {#mission-status}

This profile binds the Framework's abstract Mission Status interface
to two OAuth operations:

1. A **dedicated Mission Status operation** (by mission reference)
   at a new endpoint.
2. An **optional Mission-snapshot projection** on token introspection
   {{RFC7662}}.

These are distinct operations: the dedicated operation is
by-mission-reference; the introspection projection is by-token.

## Dedicated Mission Status operation {#dedicated-mission-status-operation}

The AS publishes a `mission_status_endpoint` URL in its AS metadata
document. The endpoint MUST be served over TLS 1.2 or later (TLS
1.3 RECOMMENDED) per the Framework's transport security requirement.

### Request {#mission-status-request}

The request is an HTTPS POST with
`application/x-www-form-urlencoded` body containing:

- `mission` (string, required): the canonical `mission.id`.
- `audience` (string, required): the audience identifier of the
  requesting consumer.
- `nonce` (string, required): a client-generated nonce for
  request-binding. ABNF per
  {{I-D.draft-mcguinness-mission-framework}}.

### Authentication {#mission-status-authentication}

The request MUST be authenticated. The AS MUST support and the
client MUST use exactly one of the following mechanisms per
request:

1. **mTLS client authentication** {{RFC8705}}. The AS validates
   the client's X.509 certificate against the configured trust
   anchors and against the client's registered
   `tls_client_auth_subject_dn` or related metadata.
2. **DPoP-bound bearer token** {{RFC9449}}. The client presents
   a Mission Status-scoped DPoP-bound token in the
   `Authorization` header along with a `DPoP` proof header. The
   token's `cnf.jkt` MUST match the proof key thumbprint.
3. **Private-key-JWT client authentication** {{RFC7521}}. The
   client presents a signed JWT assertion as
   `client_assertion`.

Plain Basic or POST client authentication MUST NOT be used for
this endpoint. The AS MUST refuse a request that does not
authenticate via one of the three mechanisms with
`unauthorized` (HTTP 401).

The AS MUST advertise the supported mechanisms in AS metadata
under `mission_status_auth_methods_supported` (an array of
`mtls`, `dpop_bearer`, `private_key_jwt`).

### Worked request example

~~~ http-message
POST /as/mission/status HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

mission=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
&audience=https%3A%2F%2Ferp.example.com
&nonce=nonce_K9pV4nT2sR7mB1xQ
~~~

### Response {#mission-status-response-wire-form}

On success the AS returns a JWS Compact Serialization {{RFC7515}}
signed with a key published in the AS's `jwks_uri`. The JWS
header carries `typ` =
`application/mission-status-response+jwt` (registered in
{{iana}}) and `kid` identifying the signing key.

**HTTP response wrapping**:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/mission-status-response+jwt
Cache-Control: no-store
Pragma: no-cache

eyJhbGciOiJFUzI1NiIsImtpZCI6InNhLWtleS0yMDI2LXEzIiwidHlwIjoiYXBwbGlj
YXRpb24vbWlzc2lvbi1zdGF0dXMtcmVzcG9uc2Urand0In0.eyJpc3MiOiJodHRwczo...
~~~

**Decoded JWS header**:

~~~ json
{
  "alg": "ES256",
  "kid": "sa-key-2026-q3",
  "typ": "application/mission-status-response+jwt"
}
~~~

**Decoded JWS payload** (matching the Framework's abstract
Mission Status Response object):

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.example.com",
  "sub": "client_erp-recon-agent",
  "nonce": "nonce_K9pV4nT2sR7mB1xQ",
  "iat": 1797840000,
  "exp": 1797840060,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com"
  },
  "state": "active",
  "integrity_anchors": {
    "proposal_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "consent_disclosure_hash":
      "sha-256:nB2xK5qY7vM3rL9pT4cE6sZ8wQ1bN0fH5jX9kV2sRdM"
  },
  "authority_projection": [
    {
      "type": "mission_resource_access",
      "specification_uri":
        "https://datatracker.ietf.org/doc/draft-mcguinness-mission-oauth-profile",
      "schema_version": "1",
      "authority": {
        "resource": "https://erp.example.com",
        "actions": ["invoices.read", "journal-entries.write"]
      },
      "narrowing_profile": "urn:mbo:narrowing:default-v1"
    }
  ],
  "policy_version": "deploy-policy:v17",
  "issued_at":     "2026-11-02T08:14:00Z",
  "expires_at":    "2026-11-02T08:15:00Z",
  "freshness_at":  "2026-11-02T08:14:00Z",
  "mission_expiry":"2026-12-31T23:59:59Z",
  "audience":      "https://erp.example.com",
  "version":       1
}
~~~

The standard JWT claims `iss`, `aud`, `sub`, `nonce`, `iat`, `exp`
carry the Framework's authentication, audience, and request-binding
properties. The remaining members carry the Framework's Mission
Status Response object verbatim. The `version` claim mirrors
`mission.version` for caller convenience.

Consumers MUST verify:

1. JWS signature against a current `jwks_uri` entry for the
   `origin` AS.
2. `iss` equals the expected AS issuer URL.
3. `aud` equals the consumer's own audience identifier.
4. `sub` equals the requesting client's identifier.
5. `nonce` equals the request's nonce.
6. `iat` is not in the future and `exp` is not in the past
   (with up to 30 seconds clock skew tolerance per the
   Framework).

### Caching {#mission-status-caching}

Consumers SHOULD cache the response keyed on
(mission reference, audience) until `expires_at`. Consumers MUST
NOT use a cached response after `expires_at` (with up to 30s
skew tolerance for `active` state only; no tolerance for
terminal states).

Consumers SHOULD honor a stale-while-revalidate window of up to
2x the response lifetime when the AS is unreachable, provided
the consumer's deployment policy permits degraded-mode operation
under the `mission_max_stale_seconds` advertisement.

### Anti-oracle property

The AS MUST authenticate the requester and authorize the requester
for the requested Mission reference and audience. A Mission
reference is never a bearer capability.

Unknown Mission references and known-but-unauthorized references
MUST produce indistinguishable responses (HTTP 404 with a generic
not-found body shape; see {{mission-status-error-responses}}). The
AS MUST NOT vary response timing, payload size, or headers in a
way that distinguishes the two cases.

### Error responses {#mission-status-error-responses}

Mission Status responses use the following error symbols, mapped
to HTTP status codes. The response body is a JSON object
({{RFC8259}}) matching the abstract error shape of the Framework:

| Symbol | HTTP | Description |
|---|---|---|
| `ok` | 200 | Mission found and visible. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | Mission reference does not exist OR is not visible to this consumer. |
| `terminated` | 200 | Mission is in a terminal state (state ∈ {`revoked`, `completed`, `expired`}). |
| `suspended` | 200 | Mission is suspended. |
| `rate_limited` | 429 | Consumer is rate-limited. |
| `unavailable` | 503 | AS temporarily cannot serve status. |

Terminal and suspended states return HTTP 200 with the standard
signed Mission Status Response carrying `state`. Hard errors
(`unauthorized`, `not_found`, `rate_limited`, `unavailable`)
return the matching HTTP status with a JSON body:

~~~ http-message
HTTP/1.1 404 Not Found
Content-Type: application/json
Cache-Control: no-store

{
  "error": "not_found",
  "error_description":
    "Mission reference is not found or not visible.",
  "nonce": "nonce_K9pV4nT2sR7mB1xQ"
}
~~~

The body MUST contain `error`, `error_description`, and `nonce`.
The body MUST NOT contain any member that would allow distinguishing
unknown from unauthorized references.

For `rate_limited`, the response SHOULD additionally include a
`Retry-After` header per {{RFC9110}} and a `retry_after` body
member in seconds.

## Token introspection Mission projection {#token-introspection-mission-projection}

When a consumer presents an access token to the AS's introspection
endpoint {{RFC7662}}, the AS MAY include a `mission` member in the
introspection response containing a Mission snapshot.

This profile RECOMMENDS that introspection responses carrying a
Mission projection use {{RFC9701}} signed responses to satisfy
the Framework's authentication and integrity properties without
relying on TLS alone.

**Introspection request**:

~~~ http-message
POST /as/introspect HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Accept: application/token-introspection+jwt
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

token=eyJhbGciOiJFUzI1NiIsImtpZCI6...
~~~

**Introspection response** (RFC 9701 signed, decoded payload):

~~~ json
{
  "iss":     "https://as.example.com",
  "aud":     "https://erp.example.com",
  "iat":     1797840000,
  "exp":     1797840060,
  "active":  true,
  "client_id": "s6BhdRkqt3",
  "sub":     "user_3p2q8mN1a0kV7tR",
  "scope":   "openid",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "version": 1,
    "state":   "active",
    "expires_at": "2026-11-02T08:15:00Z"
  }
}
~~~

The projection adds `state` and `expires_at` to the standard
`mission` claim shape so the consumer can act on Mission
lifecycle without a separate Mission Status round-trip. The
projection's `state` and `expires_at` are derived from the AS's
current Mission record at introspection time; the consumer MAY
use them up to `expires_at` per the caching rule of
{{mission-status-caching}}.

The introspection projection is an OPTIMIZATION for consumers
that already query by token. It does NOT replace the dedicated
Mission Status operation. Consumers needing by-mission-id lookups
or signed evidence independent of a specific token MUST use the
dedicated operation.

# Mission Lifecycle Endpoint {#mission-lifecycle-endpoint}

The AS publishes a `mission_lifecycle_endpoint` URL distinct from
{{RFC7009}} token revocation. The endpoint MUST be served over TLS
1.2 or later (TLS 1.3 RECOMMENDED).

## Operations

The endpoint accepts authenticated POST requests with form-urlencoded
body:

- `mission` (string, required): the canonical `mission.id`.
- `operation` (string, required): one of `revoke`, `suspend`,
  `resume`, `complete`.
- `reason` (string, optional): a human-readable reason recorded in
  audit. Maximum length 1024 characters.
- `nonce` (string, required): a client-generated nonce.

The four operations are:

- `revoke`: terminate the Mission. Mission transitions to `revoked`.
- `suspend`: pause the Mission. Mission transitions to `suspended`.
- `resume`: return a suspended Mission to `active`.
- `complete`: mark the Mission as completed. Mission transitions
  to `completed`.

## Authentication

Authentication for the lifecycle endpoint uses the same mechanisms
as the Mission Status endpoint ({{mission-status-authentication}}):
mTLS, DPoP-bound bearer, or private_key_jwt. The AS advertises
supported mechanisms under
`mission_lifecycle_auth_methods_supported`.

## Authorization

The AS authorizes lifecycle operations against deployment policy.
The Framework does not standardize the authorization policy;
typical deployments authorize:

- `revoke`: the Mission's `subject` or `approving_principal`; any
  administrator role.
- `suspend` / `resume`: administrator roles only.
- `complete`: the Mission's `requesting_client` or an
  administrator role.

The AS MUST refuse unauthorized lifecycle requests with the
not-found response shape of {{mission-status-error-responses}} so
the endpoint does not act as a Mission enumeration oracle.

## Worked example

**Revoke request**:

~~~ http-message
POST /as/mission/lifecycle HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

mission=msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-
&operation=revoke
&reason=Quarterly+reconcile+completed+early
&nonce=nonce_8Y3vN0sM6tP1xR9bQ5
~~~

**Revoke success response** (JWS-signed Mission Status Response
shape; the AS returns the updated status as evidence of the
transition):

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/mission-status-response+jwt
Cache-Control: no-store

eyJhbGciOiJFUzI1NiIsImtpZCI6InNhLWtleS0yMDI2LXEzIiwidHlwIjoi...
~~~

**Decoded JWS payload**:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://erp.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "nonce": "nonce_8Y3vN0sM6tP1xR9bQ5",
  "iat": 1797843200,
  "exp": 1797843260,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com"
  },
  "state": "revoked",
  "lifecycle_event": {
    "operation": "revoke",
    "at":        "2026-11-02T09:06:40Z",
    "actor":     "user_3p2q8mN1a0kV7tR",
    "reason":    "Quarterly reconcile completed early"
  },
  "integrity_anchors": {
    "proposal_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "consent_disclosure_hash":
      "sha-256:nB2xK5qY7vM3rL9pT4cE6sZ8wQ1bN0fH5jX9kV2sRdM"
  },
  "policy_version": "deploy-policy:v17",
  "issued_at":     "2026-11-02T09:06:40Z",
  "expires_at":    "2026-11-02T09:11:40Z",
  "freshness_at":  "2026-11-02T09:06:40Z",
  "mission_expiry":"2026-12-31T23:59:59Z",
  "audience":      "https://erp.example.com",
  "version":       2
}
~~~

The `lifecycle_event` member is added to the standard Mission
Status Response shape and records the transition. The
`version` increments from 1 (at approval) to 2.

## Idempotency

Lifecycle operations MUST be idempotent on the pair
(`mission`, `operation`). A repeated request that does not change
state returns success without side effect, returning the current
Mission Status Response.

## {{RFC7009}} cascade

Mission revocation cascades to all access tokens, refresh tokens,
and ID-JAGs derived from the Mission, per the AS's advertised
enforcement classes ({{revocation-enforcement-classes}}).

The AS MAY additionally invoke {{RFC7009}} token revocation for
specific outstanding tokens when the AS knows their `jti`. {{RFC7009}}
alone does NOT revoke a Mission; the lifecycle endpoint is the
authoritative Mission state change.

# Revocation Enforcement Classes {#revocation-enforcement-classes}

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

# Sender Constraint {#sender-constraint}

Access tokens issued under this profile MUST be sender-constrained
using one of:

- DPoP {{RFC9449}}: the access token's `cnf.jkt` member binds the
  token to a client-controlled DPoP key. Each request to the
  Resource Server carries a `DPoP` proof header.
- mTLS {{RFC8705}}: the access token's `cnf.x5t#S256` member binds
  the token to the client's X.509 certificate. Each request to the
  Resource Server uses the matching client certificate at the TLS
  layer.

The AS MUST advertise supported sender-constraint mechanisms under
`mission_sender_constraints_supported` (an array with one or both
of `dpop`, `mtls`). Bearer-only (unconstrained) tokens are NOT
permitted under this profile.

Refresh tokens MUST also be sender-constrained. The AS rotates
refresh tokens on use (per OAuth 2.1 RECOMMENDATION) and preserves
the sender-constraint binding across rotation.

# AS Metadata {#as-metadata}

The AS metadata document {{RFC8414}} carries the following
Mission-Bound members in addition to standard OAuth metadata.

## Mission-Bound metadata members

- `mission_intent_schema_uri` (string, required, URL): JSON Schema
  for `mission_intent`. Resolves to either the Framework's default
  Mission Intent schema or a deployment-specific stricter schema.
- `mission_intent_max_size` (integer, required): octet limit on
  `mission_intent`. Default 16384.
- `mission_status_endpoint` (string, required, URL): dedicated
  Mission Status operation.
- `mission_status_auth_methods_supported` (array of strings,
  required): one or more of `mtls`, `dpop_bearer`,
  `private_key_jwt`.
- `mission_lifecycle_endpoint` (string, required, URL): Mission
  lifecycle operations.
- `mission_lifecycle_auth_methods_supported` (array of strings,
  required): same value space as
  `mission_status_auth_methods_supported`.
- `authority_set_types_supported` (array of strings, required):
  Authority Set entry types this AS issues.
- `mission_enforcement_classes_supported` (array of strings,
  required): one or more of `issuance`, `introspection`,
  `event_driven`, `per_request`.
- `mission_max_stale_seconds` (integer, required): maximum
  tolerated stale interval for revocation propagation.
- `mission_sender_constraints_supported` (array of strings,
  required): one or both of `dpop`, `mtls`.
- `mission_framework_versions_supported` (array of strings,
  required): spec revisions of the Framework this AS supports.
- `mission_purposes_supported` (array of strings, optional):
  deployment-registered `purpose` URIs the AS accepts in Mission
  Intents.

## Worked metadata example

A discovery response from `https://as.example.com/.well-known/oauth-authorization-server`:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=3600

{
  "issuer": "https://as.example.com",
  "authorization_endpoint":
    "https://as.example.com/as/authorize",
  "token_endpoint": "https://as.example.com/as/token",
  "pushed_authorization_request_endpoint":
    "https://as.example.com/as/par",
  "require_pushed_authorization_requests": true,
  "introspection_endpoint":
    "https://as.example.com/as/introspect",
  "revocation_endpoint":
    "https://as.example.com/as/revoke",
  "jwks_uri":
    "https://as.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "code_challenge_methods_supported": ["S256"],
  "dpop_signing_alg_values_supported": ["ES256", "EdDSA"],
  "tls_client_certificate_bound_access_tokens": true,
  "introspection_signing_alg_values_supported": ["ES256"],
  "authorization_response_iss_parameter_supported": true,

  "mission_intent_schema_uri":
    "https://as.example.com/.well-known/mission-intent-schema.json",
  "mission_intent_max_size": 16384,
  "mission_status_endpoint":
    "https://as.example.com/as/mission/status",
  "mission_status_auth_methods_supported": [
    "mtls", "dpop_bearer", "private_key_jwt"
  ],
  "mission_lifecycle_endpoint":
    "https://as.example.com/as/mission/lifecycle",
  "mission_lifecycle_auth_methods_supported": [
    "mtls", "private_key_jwt"
  ],
  "authority_set_types_supported": ["mission_resource_access"],
  "mission_enforcement_classes_supported": [
    "issuance", "introspection"
  ],
  "mission_max_stale_seconds": 60,
  "mission_sender_constraints_supported": ["dpop", "mtls"],
  "mission_framework_versions_supported": [
    "draft-mcguinness-mission-framework-00"
  ],
  "mission_purposes_supported": [
    "urn:erp.example.com:purposes:quarterly-reconcile",
    "urn:erp.example.com:purposes:bulk-export"
  ]
}
~~~

The metadata document at
`{mission.origin}/.well-known/mission-authority` defined in the
Framework is ALSO published; this profile's AS metadata members
above are an OAuth-substrate complement, not a replacement.

# Composition with Other Specifications {#composition-with-other-specifications}

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
the Mission's `acr` constraint (per the Mission Framework's Common
Constraints registry) but it does NOT perform Mission Expansion.
Expansion is a governance operation requiring approval; step-up is
an authentication operation.

This profile MAY compose with RFC 9470 step-up when a denied
request would be permitted by satisfying the Mission's `acr`
constraint via fresh authentication. The step-up challenge carries
the Mission's `acr_values` and `max_age` verbatim as the RFC 9470
request parameters.

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

# Security Considerations {#security-considerations}

This section discusses security considerations specific to this
profile. Security considerations for the Mission Framework
({{I-D.draft-mcguinness-mission-framework}}) apply in full to
deployments using this profile.

## Mission revocation and offline tokens

Mission revocation does not claim to invalidate offline
self-contained tokens immediately unless `event_driven` or
`per_request` enforcement is deployed. Deployments where
revocation propagation matters MUST advertise their enforcement
classes honestly ({{revocation-enforcement-classes}}).
Implementers SHOULD NOT assume revocation is instantaneous and
SHOULD adjust access-token TTL to align with their declared
`mission_max_stale_seconds`.

## Token-scope vs Mission-scope

A leaked or stolen access token cannot escalate Mission authority;
the Authority Set committed by `authority_hash` is the upper bound.
However, a leaked refresh token can produce new credentials
indefinitely until the Mission is revoked or the refresh token is
explicitly revoked. Refresh tokens MUST be sender-constrained per
{{sender-constraint}}.

## Refresh-token rotation and Mission binding

The AS rotates refresh tokens on use. Each rotation MUST preserve
the Mission binding: the rotated token carries the same Mission
reference and sender-constraint binding as its predecessor. Two
refresh tokens for the same client and Mission SHOULD NOT be
valid simultaneously; the AS revokes the predecessor on
successful rotation. Detection of two-active-refresh-tokens
SHOULD be treated as a token-theft signal and trigger a Mission
revocation event per the AS's deployment policy.

## Mission Status enumeration

Per the anti-oracle property, the AS MUST NOT distinguish unknown
Mission references from known-but-unauthorized references at the
Mission Status endpoint. Implementations that leak this
distinction expose the Mission space to enumeration. The error
response shape of {{mission-status-error-responses}} mitigates
this by requiring identical body content, identical HTTP status,
and timing/size invariance between the two cases.

## RFC 9701 vs new media type

The introspection projection uses {{RFC9701}}, an existing
specification scoped to token introspection. The dedicated Mission
Status operation uses a new media type
(`application/mission-status-response+jwt`) registered in
{{iana}} because {{RFC9701}} does not apply to by-reference status
lookups. Implementations MUST NOT use {{RFC9701}} for the dedicated
operation.

## Cross-substrate token-leak surface

When a Mission is consumed by both OAuth and AAuth substrates under
a Mission Authority Server topology, an OAuth-side token leak does
NOT compromise the Mission's AAuth-side derivations. Each substrate
issues its own credentials sender-constrained to its substrate.
However, lifecycle state propagation across substrates depends on
the MAS topology being correctly configured.

## DPoP and mTLS deployment

DPoP {{RFC9449}} and mTLS {{RFC8705}} have different deployment
characteristics. DPoP is straightforward to deploy in
browser-hosted SPAs and mobile apps but requires the client to
hold a private key. mTLS provides stronger binding at the TLS
layer but requires per-client X.509 issuance.

This profile permits either; deployments SHOULD select based on
the threat model: stronger binding (mTLS) for high-value
deployments and confidential clients; DPoP for public clients
and where mTLS deployment overhead is impractical.

When DPoP is used, the AS MUST validate the DPoP proof per
{{RFC9449}} and reject reuse of `jti` within the proof's window.
When mTLS is used, the AS MUST validate the certificate against
its trust anchors and against the client's registered
`tls_client_auth_*` metadata members.

## Mission Status response replay

A Mission Status response is bound to (caller, audience, nonce,
issuance time). Replay against a different caller, audience, or
beyond `expires_at` is detectable by signature verification and
binding-claim verification. Consumers MUST verify all six bindings
listed in {{mission-status-response-wire-form}} before honoring a
response.

A Mission Status response cached and replayed by the same caller
within `expires_at` is correctly equivalent to a fresh response
(caching is permitted up to `expires_at`). Consumers MUST NOT use
a cached response after `expires_at` (plus permissible skew per
{{mission-status-caching}}).

## Mission Status DoS

The Mission Status endpoint is on the consumption path of every
Mission-bound credential validation in deployments that consult
it synchronously. The AS MUST implement per-consumer rate
limiting per the Framework's DoS mitigation. Deployments SHOULD
encourage consumer-side caching to reduce traffic.

## Authorization code injection and PKCE

This profile inherits the OAuth 2.0 Best Current Practice
{{RFC9700}} and {{?I-D.draft-ietf-oauth-v2-1}}. PKCE MUST be used
for public clients; PKCE SHOULD be used for confidential clients
as defense in depth. The PKCE `code_challenge_method` MUST be
`S256`.

## Resource Indicator binding

When the client submits {{RFC8707}} `resource` parameters at
authorization or token-exchange time, the AS MUST narrow issued
authority to the intersection of (Validated Mission Intent
authority, requested resources). The AS MUST refuse a request
whose `resource` set has no intersection with any
`mission_resource_access` entry derived from the Validated
Mission Intent.

## General OAuth security

This profile inherits the OAuth 2.0 Best Current Practice
{{RFC9700}}. Implementers MUST follow current OAuth security
guidance for the OAuth surfaces this profile composes with.

# Privacy Considerations {#privacy-considerations}

This section addresses privacy threats specific to the OAuth
binding. Privacy considerations for the Mission Framework
({{I-D.draft-mcguinness-mission-framework}}) apply in full.

## Mission identifier exposure in tokens

Access tokens issued under this profile carry the `mission` claim
containing the canonical `mission.id`. Resource Servers and other
audiences that observe the access token observe the same
`mission.id`. Audiences participating in the same Mission can
observe that they share a Mission; this is inherent to the
Mission's role as a governance handle and is consented to at
approval time.

User-level correlation across audiences (a Resource Server
linking activity across Missions of the same user) is independent
of the Mission identifier and addressed by OIDC pairwise `sub`.
Deployments where user-level cross-audience correlation matters
MUST configure pairwise `sub` claims at the AS. The `mission.id`
does not encode subject identity and does not undo `sub`-level
pairwise isolation.

Deployments with stronger Mission-identity isolation requirements
(an unusual case typically arising in multi-tenant SaaS state
authorities serving competing tenants) define a pairwise Mission
identifier through a profile extension to the Mission Framework;
such extensions are out of scope for this profile.

## Refresh token contents

A Mission-bound refresh token, when implemented as a JWT, MAY
expose the Mission reference and `authority_hash` to anyone who
obtains the refresh token. Deployments treating the refresh
token as bearer data (e.g., logging the token in plain text)
expose this information. The AS SHOULD prefer opaque refresh
tokens or encrypt JWT refresh tokens at rest.

## Introspection responses

Introspection responses include the Mission projection when the
AS chooses to emit it. The introspection response is delivered
to a Resource Server (or other token consumer) authenticated to
the introspection endpoint. The Mission projection therefore
exposes Mission state and `authority_hash` to that consumer.

Deployments MUST treat the introspection endpoint as a Mission
information disclosure surface with the same privacy posture as
the dedicated Mission Status endpoint.

## Audit and logging

The AS records Mission Proposal submission, approval events,
credential derivation, and lifecycle transitions in audit logs.
These logs contain Mission identifiers, audience identifiers,
principal identifiers, and timing information. Deployments MUST
treat AS audit logs as PII sinks per the Framework's privacy
considerations.

## Client-registration metadata

Client registration metadata under
{{client-registration-extensions}} (`mission_purposes_registered`,
`mission_intent_schema_uri_supported`,
`mission_max_derivations_max`) describes client capabilities. This
metadata is typically not user-PII but MAY reveal organizational
relationships and approved task classes. Deployments SHOULD
treat client registration data with the same care as other
client metadata.

## Resource indicator inference

When clients submit {{RFC8707}} `resource` parameters at
authorization or token-exchange time, the AS observes the
target audience and can correlate Missions by target. The AS
SHOULD limit retention of resource-parameter values beyond the
audit window or generalize them to deployment-internal audience
identifiers in logs.

# IANA Considerations {#iana}

This document requests IANA actions to register OAuth parameters,
claims, error codes, metadata members, media types, and one
Mission Authority Set Type Registry entry.

## OAuth Authorization Request Parameters

This document registers `mission_intent` in the OAuth Parameters
Registry under the "OAuth Authorization Request" parameter usage
location.

- Parameter Name: `mission_intent`
- Parameter Usage Location: Authorization Request (REQUIRED via PAR
  only; see {{mission-intent-parameter}})
- Change Controller: IETF
- Specification Document(s): this document

## OAuth Token Endpoint Authentication Methods

This document does not register new token-endpoint authentication
methods. The Mission Status and Mission Lifecycle endpoints reuse
existing methods (`tls_client_auth`,
`self_signed_tls_client_auth`, `private_key_jwt`,
`dpop_bound_access_token`).

## OAuth Error Codes Registry

This document registers the following error codes in the OAuth
Extensions Error Registry.

| Name | Usage Location | Reference |
|---|---|---|
| `mission_inactive` | Token Error Response | this document |
| `mission_concurrent_modification` | Token Error Response | this document |

For each:

- Change Controller: IETF
- Reference: this document

## JWT Claims Registry

This document registers `mission` in the JSON Web Token Claims
registry per {{RFC7519}}.

- Claim Name: `mission`
- Claim Description: Reference to the governing Mission record and
  related integrity-anchored evidence.
- Change Controller: IETF
- Reference: this document
- Value type: JSON object conforming to
  `urn:mbo:schema:oauth-mission-claim:1` ({{mission-claim-schema}}).

## OAuth Authorization Server Metadata

This document registers the following members in the OAuth
Authorization Server Metadata registry. For each registration:

- Change Controller: IETF
- Reference: this document
- Value type and definition: see {{as-metadata}}.

Registered members:

- `mission_intent_schema_uri`
- `mission_intent_max_size`
- `mission_status_endpoint`
- `mission_status_auth_methods_supported`
- `mission_lifecycle_endpoint`
- `mission_lifecycle_auth_methods_supported`
- `authority_set_types_supported`
- `mission_enforcement_classes_supported`
- `mission_max_stale_seconds`
- `mission_sender_constraints_supported`
- `mission_framework_versions_supported`
- `mission_purposes_supported`

## OAuth Dynamic Client Registration Metadata

This document registers the following members in the OAuth Dynamic
Client Registration Metadata registry per {{RFC7591}}. For each:

- Change Controller: IETF
- Reference: this document

Registered members:

- `mission_purposes_registered`
- `mission_intent_schema_uri_supported`
- `mission_max_derivations_max`

See {{client-registration-extensions}} for definitions.

## Mission Authority Set Type Registry

This document registers `mission_resource_access` in the Mission
Authority Set Type Registry created by the Mission Framework
({{I-D.draft-mcguinness-mission-framework}}).

- **Type**: `mission_resource_access`
- **Defining specification**: this document
- **`schema_digest`**: computed over the schema document at
  `https://datatracker.ietf.org/doc/draft-mcguinness-mission-oauth-profile/`
- **Schema document URL**: see definition in
  {{authority-set-entry-type-mission-resource-access}}
- **`schema_version` semantics**: integer-valued strings. Successor
  versions are backward-compatible when they add optional members
  and break-compatible when they add required members or change
  member semantics.
- **Normalization rule**: `urn:mbo:norm:mission-resource-access:1`
  (also registered by this document, see
  {{normalization-profile-registration}}).
- **Equality rule**: per
  {{authority-set-entry-type-mission-resource-access}}.
- **Subset rule**: per
  {{authority-set-entry-type-mission-resource-access}}.
- **Intersection rule**: per
  {{authority-set-entry-type-mission-resource-access}}.
- **Unknown-field handling**: refuse (default); per-entry
  `narrowing_profile` MAY declare pass-through.
- **Change controller**: IETF
- **Reference**: this document

## Mission Normalization Profile Registry {#normalization-profile-registration}

This document registers
`urn:mbo:norm:mission-resource-access:1` in the Mission
Normalization Profile registry created by the Framework.

- **Profile identifier**:
  `urn:mbo:norm:mission-resource-access:1`
- **Defining specification**: this document
- **Per-field rules**: see
  {{authority-set-entry-type-mission-resource-access}}.
- **Change controller**: IETF
- **Reference**: this document

## Media Type Registry

This document registers two media types per {{RFC6838}}.

### `application/mission-status-response+jwt`

- **Type name**: application
- **Subtype name**: mission-status-response+jwt
- **Required parameters**: none
- **Optional parameters**: none
- **Encoding considerations**: binary; JWS Compact Serialization
- **Security considerations**: see {{security-considerations}}
- **Interoperability considerations**: see this document
- **Published specification**: this document
- **Applications that use this media type**: OAuth Mission-Bound
  consumers
- **Fragment identifier considerations**: not applicable
- **Restrictions on usage**: none
- **Provisional registration**: no
- **Magic number(s)**: none
- **File extension(s)**: none
- **Macintosh file type code(s)**: none
- **Person & email address to contact for further information**:
  Karl McGuinness <public@karlmcguinness.com>
- **Intended usage**: COMMON
- **Author/Change controller**: IETF

### `application/mission-lifecycle-response+jwt`

This document registers a second media type for Mission Lifecycle
endpoint responses. The on-the-wire form is identical to
Mission Status (the AS returns the updated Mission Status
Response as evidence of the transition); the distinct media type
allows recipients to dispatch on response provenance.

Registration fields are identical to the above except:

- **Subtype name**: mission-lifecycle-response+jwt
- **Applications**: OAuth Mission-Bound consumers performing
  lifecycle operations.

## Well-Known URI

This document does NOT register a new Well-Known URI. The state
authority metadata document at
`/.well-known/mission-authority` is registered by the Framework.
The AS metadata document at
`/.well-known/oauth-authorization-server` is the OAuth Server
Metadata registration of {{RFC8414}}.

# Acknowledgments
{:numbered="false"}

The author thanks the implementers and reviewers of the
Mission-Bound Authorization architecture for feedback that shaped
this specification.

--- back
