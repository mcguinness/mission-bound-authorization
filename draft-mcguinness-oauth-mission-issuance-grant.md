---
title: "Mission Issuance Grant for OAuth 2.0"
abbrev: "Mission Issuance Grant"
category: std

docname: draft-mcguinness-oauth-mission-issuance-grant-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - issuance
 - grant
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6749:
  RFC6838:
  RFC7515:
  RFC7519:
  RFC7523:
  RFC7800:
  RFC9126:
  RFC9396:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
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

informative:
  RFC8693:
  RFC8705:
  RFC9449:
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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

--- abstract

The standalone Mission Authority Server binding governs Missions with
no change to an estate's Authorization Servers: tokens remain
ordinary, and enforcement joins them to Missions at the point of use.
That mode provides no Mission-bound credential and no issuance
gating. This document defines the Mission Issuance Grant: a
short-lived, audience-bound, one-time assertion, minted by a
standalone Mission Issuer for an approved, active Mission, that an
OAuth Authorization Server redeems at its token endpoint to issue
Mission-bound tokens gated on Mission state. Approval, record, and
lifecycle stay at the Mission Authority Server; the Authorization
Server keeps the token plane and adds only grant validation,
subset-bounded minting, and state-gated refresh. This issuance join
restores Mission-bound credentials and the issuance-gate kill switch
without the Authorization Server implementing the issuance profile's
intake, approval, or derivation surfaces.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile", here
"the core") binds issued authority to a durable, human-approved
Mission, with the Authorization Server (AS) as the Mission Issuer.
The Mission Authority Server (MAS,
{{I-D.draft-mcguinness-mission-authority-server}}) hosts the same
object without touching the AS: it validates Mission Intents, runs
approval, records Missions, and operates the lifecycle, while tokens
remain ordinary and a Policy Decision Point joins them to Missions at
the point of use. Between those two integrations there was none: an
estate either changed its AS completely or not at all.

This document defines the middle integration, the **issuance join**.
The MAS remains the Mission Issuer; the estate's AS consumes the
approved Mission at its token endpoint. The carrier is the **Mission
Issuance Grant**, a short-lived assertion the MAS mints for an
active Mission and the AS redeems under the JWT authorization grant
{{RFC7523}} to issue tokens that carry the `mission` claim and are
bounded by the Mission's derived authority. Because every grant is
minted against current Mission state and refresh is gated on that
state, the possession-independent kill switch returns to the
issuance gate, the property the MAS-only mode structurally lacks.

The Authorization Server's obligations are deliberately small:
validate the grant, mint within its bounds, gate refresh on Mission
state. It implements none of the core's intake, approval ceremony,
derivation, record, or lifecycle surfaces; those stay at the MAS.
The integration ladder is then: record-only governance, the runtime
join, the issuance join, and native Mission-awareness, each adopted
where its cost is warranted
({{I-D.draft-mcguinness-mission-authority-server}}).

## Requirements Language

{::boilerplate bcp14-tagged}

# Conventions and Terminology {#conventions}

This document uses Mission, Mission Intent, Authority Set, Mission
Issuer, the `mission` claim, the subset rule, and the integrity
anchors (`intent_hash`, `authority_hash`) as the core defines them,
and Mission Authority Server (MAS), Mission Join, and the Enterprise
Mapping Contract as {{I-D.draft-mcguinness-mission-authority-server}}
defines them. It additionally uses:

Issuance join:
: The integration this document defines: a MAS-approved Mission
  consumed at an Authorization Server's token endpoint.

Mission Issuance Grant (grant):
: The signed assertion of {{grant}}, minted by the Mission Issuer
  and redeemed for Mission-bound tokens.

Grant Minter:
: The standalone Mission Issuer minting grants; conformance role of
  {{conformance}}.

Consuming Authorization Server (consuming AS):
: An OAuth Authorization Server {{RFC6749}} that redeems Mission
  Issuance Grants at its token endpoint; conformance role of
  {{conformance}}.

# The Issuance Join {#issuance-join}

Trust is pre-established and bilateral. A consuming AS accepts
grants only from Mission Issuers its local policy names, resolving
their signing keys through the MAS's published key material (its
discovery `jwks_uri`,
{{I-D.draft-mcguinness-mission-authority-server}}); a MAS mints
grants only for Authorization Servers named as audiences by
deployment configuration. Subject and client correspondence between
the Mission record and the consuming AS's accounts is governed by
the deployment's mapping policy; where the Enterprise Mission
Authority Profile is claimed, its mapping contract governs
({{I-D.draft-mcguinness-mission-authority-server}}).

The division of duties is fixed. The MAS holds the approval event,
the record and its anchors, the lifecycle, and grant minting. The
consuming AS holds client authentication, token minting bounded by
the grant, refresh, and its ordinary token-plane obligations. An
auditor attributes what was approved to the MAS record and what was
issued to the consuming AS's log, joined by the Mission reference
the grant carries.

Tokens issued under this profile are Mission-bound in the core's
sense: they carry the `mission` claim, their authority is a subset
of the consented Authority Set, and issuance and refresh are gated
on Mission state. Runtime enforcement
({{I-D.draft-mcguinness-mission-runtime}}) composes
credential-carried for these tokens; the MAS-only mode's join caveat
(the credential's membership is mapped, not issued) does not apply
to them. Tokens the estate issues outside this profile are
unchanged and continue to compose through the Mission Join.

# The Mission Issuance Grant {#grant}

A Mission Issuance Grant is a JWT {{RFC7519}} signed as a JWS
{{RFC7515}} by the Mission Issuer. Its JOSE header MUST carry `typ`
`mission-issuance-grant+jwt` ({{iana}}), `alg`, and a `kid` that
resolves in the Mission Issuer's published key material. A consumer
MUST reject as a Mission Issuance Grant any JWT whose `typ` differs;
in particular a Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}) is evidence, authorizes
nothing, and MUST NOT redeem.

Claims:

`iss`:
: REQUIRED. The Mission's `issuer`: the MAS issuer URL.

`sub`:
: REQUIRED. The Mission's recorded Subject identifier
  (`subject.sub`), interpreted at the consuming AS under the
  deployment's mapping policy ({{issuance-join}}).

`aud`:
: REQUIRED. The consuming AS's issuer identifier. A consuming AS
  MUST reject a grant whose `aud` does not name it.

`iat`, `exp`:
: REQUIRED. The grant MUST NOT be valid longer than 300 seconds.

`jti`:
: REQUIRED. Unique per grant; single use ({{redemption}}).

`client_id`:
: REQUIRED. The Mission's recorded agent client identifier at the
  consuming AS. Only this authenticated client redeems the grant.

`mission`:
: REQUIRED. The core's `mission` claim object (`id`, `issuer`,
  `authority_hash`), exactly as recorded, extended with the
  `expires_at` member of {{expires-at-member}}.

`authorization_details`:
: REQUIRED. The `mission_resource_access` entries {{RFC9396}} the
  consuming AS may mint against: a subset of the Mission's consented
  Authority Set, scoped to the resources this AS serves.

`cnf`:
: OPTIONAL. A proof-of-possession key binding {{RFC7800}} for
  redemption; when present, the consuming AS MUST require proof of
  possession of the bound key at redemption.

An illustrative decoded grant (this Mission and its anchors are not
the core walkthrough's):

~~~ json
{
  "iss": "https://mas.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://as.example.com",
  "iat": 1793606400,
  "exp": 1793606580,
  "jti": "mig_7Kq2Rv9Lp4xW1nT8",
  "client_id": "s6BhdRkqt3",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://mas.example.com",
    "authority_hash":
      "sha-256:R6tY2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQr",
    "expires_at": "2026-12-31T23:59:59Z"
  },
  "authorization_details": [
    {
      "type": "mission_resource_access",
      "resource": "https://api.example.com/invoices",
      "actions": ["read"],
      "constraints": { "resource_issued_after": "2026-07-01" }
    }
  ]
}
~~~

## The `expires_at` Claim Member {#expires-at-member}

This profile adds one member to the `mission` claim object on the
credentials it governs, ahead of the issuance profile's revision:

`expires_at`:
: A string. An RFC 3339 {{RFC3339}} date-time mirroring the Mission
  record's `expires_at`, spelled identically per the issuance
  profile's record-fact naming rule.

The member is a bounding and audit commitment and carries no
liveness: expiry says nothing about revocation, and only `active`
permits reliance. It gives a consumer what a token's own `exp`
cannot: the Mission's remaining horizon for planning, a
deterministic ceiling enforceable on offline validation paths (the
value is immutable, so a credential-carried copy is always safe),
and a check that issuance respected the lifetime cap
({{redemption}}). A consumer that does not recognize the member
ignores it. A Mission Issuer under any binding MAY include the
member with these semantics.

# Obtaining a Grant {#minting}

A MAS implementing this profile serves a Mission Issuance Grant
endpoint, published as `mission_issuance_grant_endpoint` in its
discovery metadata ({{iana}}). The Grant Minter MUST observe:

1. **Requester.** The endpoint requires authentication. The
   requester MUST be the Mission's recorded client; any other caller
   receives the MAS's `not_found` anti-oracle response, under the
   same visibility rules as the Mission Join Assertion
   ({{I-D.draft-mcguinness-mission-authority-server}}).
2. **State gate.** A grant is minted only while the Mission is
   `active`, established from the MAS's own record at minting. Any
   other state refuses.
3. **Subset and audience.** The grant's `authorization_details` MUST
   be a subset of the Mission's consented Authority Set under the
   core's subset rule, and SHOULD carry only the entries the named
   consuming AS serves. The requester MAY request a narrower subset;
   it MUST NOT obtain a wider one.
4. **Derivation event.** Each grant minted is a derivation event.
   Where the Mission carries a consented `controls.max_derivations`,
   the MAS MUST count grants against it atomically and refuse beyond
   it, which gives that control a binding locus under the standalone
   binding.
5. **Evidence.** Each minting is recorded with the Mission record:
   the `jti`, audience, requested and granted entries, and time.

# Redemption {#redemption}

The client presents the grant to the consuming AS's token endpoint
as a JWT authorization grant {{RFC7523}}:

~~~
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJ0eXAiOiJtaXNzaW9uLWlzc3VhbmNlLWdyYW50K2p3dCIs...
~~~

The client authenticates as it ordinarily does at this AS; the grant
is an authorization, not a client credential. The consuming AS MUST
validate, in an order that fails closed:

1. the JOSE `typ` is `mission-issuance-grant+jwt`; any other type is
   not this profile ({{relationships}});
2. the signature, under a `kid` resolving in the published key
   material of an `iss` its local policy trusts for issuance joins;
3. `aud` names this AS; `exp` and `iat` are within the 300-second
   bound; the `jti` has not been seen, and is recorded until `exp`
   passes (single use);
4. the authenticated client is the grant's `client_id`;
5. when `cnf` is present, proof of possession of the bound key.

On success the consuming AS mints tokens under these rules:

- **The claim rides unchanged.** Issued tokens carry the grant's
  `mission` object verbatim as the core's `mission` claim, including
  the `expires_at` member ({{expires-at-member}}).
- **Subset.** Issued `authorization_details` MUST be a subset of the
  grant's; the token response SHOULD echo them as the core specifies
  for Mission-bound issuance. The consuming AS MUST NOT widen, remap,
  or supplement them from its own policy except to narrow.
- **Lifetime.** No access or refresh token issued under the grant
  may have an expiry later than the `mission` object's
  `expires_at`.
- **Refresh is state-gated.** A consuming AS MAY issue refresh
  tokens only if it gates each refresh on current Mission state,
  resolved through the Mission Status operation
  ({{I-D.draft-mcguinness-oauth-mission-status}}) or the MAS's state
  surface within a published staleness bound, refusing when the
  Mission is not established as `active`. A consuming AS without a
  state integration MUST NOT issue refresh tokens under a grant.
- **No re-approval.** The approval event already occurred at the
  Mission Issuer. The consuming AS MUST NOT prompt the Subject or
  any user for consent at redemption.

A grant redeems exactly once. Subsequent token needs are met by the
issued refresh token (state-gated) or a fresh grant (state-gated at
minting); either way, every path to new authority re-enters a
Mission-state gate, which is the issuance-gate kill switch this
profile restores.

## Authorization Code Flow Carriage {#par-carriage}

Deployments whose clients must traverse the authorization code flow
MAY carry the grant in a Pushed Authorization Request {{RFC9126}} as
the request parameter `mission_issuance_grant`. The AS applies the
validation of {{redemption}} at the PAR endpoint, treats the grant
as the authorization already obtained, and MUST NOT re-prompt for
consent; at most it renders the Mission reference. All redemption
rules apply unchanged, with the authorization code standing between
validation and minting.

# Relationship to Other Artifacts {#relationships}

**The Mandate is evidence; this grant authorizes.** Both are
issuer-signed statements about a Mission; the `typ` values keep them
apart mechanically, and a verifier of either MUST reject the other
({{I-D.draft-mcguinness-mission-mandate}}).

**The cross-domain grant is this shape across a trust boundary.**
Cross-domain projection
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) carries a
Mission to a Resource AS in another domain, with trust established
by federation agreement and identity chaining. The issuance join is
the same-estate case: bilateral, pre-configured trust between a MAS
and its own Authorization Servers, no identity-chaining substrate
required. A deployment does not use this profile across domains;
projection exists for that.

**The core is the destination, not a competitor.** An AS that
becomes natively Mission-aware implements the core and mints without
grants for its own resources; the record, anchors, and lifecycle it
consumes are the same ones the MAS already operates, so nothing is
re-approved in migration. Until then, the issuance join gives the
estate Mission-bound tokens at a fraction of the core's
implementation surface.

**The runtime join remains for everything else.** Tokens minted
under this profile compose credential-carried at the PDP; ordinary
tokens continue to compose through the Mission Join. The two joins
coexist per resource and per AS.

# Composite Provision {#composite}

In the substrate's terms ({{I-D.draft-mcguinness-mission-substrate}})
the MAS alone is a partial-provision binding: everything but the
Mission-bound credential and issuance gating. A MAS composed with
its consuming Authorization Servers under this profile provides
both, jointly: a composite full provision for the resources those
ASs serve. In the Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}), Baseline Issuance
and its issuance-gate kill switch become reachable under the
standalone binding through this profile, and the state-aware
half-step arrives with the consuming AS's refresh gating.

# Conformance {#conformance}

**Grant Minter** (the MAS): implements {{minting}} in full: the
authenticated, visibility-guarded endpoint; the `active`-only gate;
subset and audience scoping; derivation counting where consented;
minting evidence; and grants shaped exactly as {{grant}} requires.

**Consuming Authorization Server**: implements {{redemption}} in
full: `typ`, signature, audience, lifetime, single-use, and client
binding validation; verbatim `mission` claim carriage;
subset-bounded minting; `expires_at` capping; state-gated
refresh or no refresh; no re-approval. The PAR carriage of
{{par-carriage}} is OPTIONAL.

A deployment claiming this profile states, alongside its
enforcement-scope statement, which Authorization Servers consume
grants, the staleness bound of each one's refresh gating, and its
reconciliation posture ({{security-considerations}}): the window
within which minting and redemption logs are reconciled, or that
they are not.

# Security Considerations {#security-considerations}

**Grant theft.** The grant authorizes issuance, so it is defended in
depth: 300-second lifetime, single-use `jti`, audience binding to
one AS, redemption bound to the Mission's authenticated `client_id`,
and optional `cnf` key binding. A stolen grant is useless to any
party that cannot also authenticate as the recorded client at the
named AS within the window; deployments whose client credentials are
weak SHOULD require `cnf` (DPoP {{RFC9449}} or mTLS {{RFC8705}}
bindings serve).

**Mission Issuer compromise reaches issuance.** In MAS-only
deployment, MAS compromise corrupts records and state. Under this
profile it additionally mints grants every consuming AS honors:
compromise reaches token issuance across the estate. The consuming
ASs' audit logs of redeemed grants (each with `jti` and Mission
reference) are the independent record that bounds and exposes such
minting; a deployment SHOULD reconcile MAS minting evidence against
consuming-AS redemption logs and treat a redemption with no matching
minting record as a security event, and states its reconciliation
posture in its conformance statement ({{conformance}}). A deployment
operating under the Enterprise Mission Authority Profile
({{I-D.draft-mcguinness-mission-authority-server}}) MUST reconcile,
within the window its statement declares: at estate scale,
reconciliation is the only check on this compromise class.

**Trust inversion.** The consuming AS accepts externally derived
authority. Its exposure is bounded by the profile's own rules: it
mints only within the grant's `authorization_details`, only for the
grant's client, never longer than the Mission's `expires_at`, and
its local
policy MAY narrow further. The AS remains free to refuse any grant
its policy distrusts; nothing obliges issuance.

**Type confusion.** Three issuer-signed JWT artifacts about Missions
now exist: the Mandate (evidence), the cross-domain grant (foreign
domain), and this grant (same estate). The `typ` discipline is the
defense; every consumer checks it first, and none accepts another's
type.

**Revocation latency.** New grants stop at the MAS `active` gate at
the moment of state commit. Outstanding tokens end at the earlier of
their own expiry and the consuming AS's next state-gated refresh;
where the runtime layer is deployed, the PDP's re-check bounds
outstanding-token use independently. A deployment states the refresh
staleness bound it publishes ({{conformance}}).

**Consent integrity.** The approval the grant rests on was rendered
and committed at the Mission Issuer under the core's rules and,
where deployed, Consent Evidence. The consuming AS relies on that
event; it MUST NOT substitute a weaker consent of its own, and its
non-prompting duty ({{redemption}}) prevents consent-surface
confusion where the Subject holds accounts at both.

# Privacy Considerations {#privacy-considerations}

The grant carries the Mission reference and an authority subset to
the consuming AS, which may be operated by a different organizational
unit than the MAS. Minimization is structural: the MAS scopes
`authorization_details` to what the audience serves ({{minting}}),
and nothing else of the record (no `purpose` text, no Intent, no full
Authority Set) travels. The Mission identifier is a correlator across
MAS and AS logs by design; that correlation is the audit trail, and
deployments that need to limit broader correlation apply the
issuance profile's identifier guidance.

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-issuance-grant+jwt

- Type name: application
- Subtype name: mission-issuance-grant+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission Authority Servers
  and OAuth Authorization Servers implementing this profile
- Fragment identifier considerations: n/a
- Additional information: n/a
- Person and email address to contact for further information: see
  the Authors' Addresses section
- Intended usage: COMMON
- Restrictions on usage: none
- Author: see the Authors' Addresses section
- Change controller: IETF

## Mission Authority Server Metadata Registration

IANA is requested to register the following in the "Mission
Authority Server Metadata" registry established by
{{I-D.draft-mcguinness-mission-authority-server}}. Change Controller
IETF; Reference this document, {{minting}}.

- `mission_issuance_grant_endpoint`

--- back

# Acknowledgments
{:numbered="false"}

This document profiles the JWT authorization grant of RFC 7523 and
composes the Mission Authority Server with the issuance profile it
already mirrors; it defines no cryptography of its own.
