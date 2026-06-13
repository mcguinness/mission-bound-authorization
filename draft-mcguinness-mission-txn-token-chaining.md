---
title: "Mission-Bound Transaction Token Chaining Composition"
abbrev: "Mission Txn Token Chaining"
category: std

docname: draft-mcguinness-mission-txn-token-chaining-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - oauth
 - transaction-tokens
 - chaining
 - rar
 - cross-domain
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-txn-token-chaining.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  RFC7519:
  RFC8414:
  RFC8693:
  RFC9396:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-fletcher-transaction-token-chaining-profile:

informative:
  RFC9068:
  I-D.draft-ietf-oauth-transaction-tokens:
  I-D.draft-ietf-oauth-identity-chaining:

--- abstract

This document defines the composition between Mission-Bound
Authorization and the Transaction Token Chaining Profile. It
specifies how a Mission handle and the audience-filtered Authority
Set from a Mission-Bound access token are transcribed into the
`txn_claims` object of the JWT Authorization Grant exchanged between
Authorization Servers across trust domains. It defines validation
rules at the receiving Authorization Server, the cross-domain
Mission Status reach-back, and the trust-boundary considerations
that follow from carrying a governance reference across a
Cross-Domain Trust Agreement.

--- middle

# Introduction

The Transaction Token Chaining Profile
{{I-D.draft-fletcher-transaction-token-chaining-profile}} defines
how an Authorization Server in one trust domain (AS-A) converts an
internal Transaction Token (Txn-Token) into a JWT Authorization
Grant {{RFC7519}}{{RFC8693}} that an Authorization Server in a
different trust domain (AS-B) consumes to issue a partner-domain
access token. The grant carries a curated `txn_claims` object that
projects a minimized subset of the Txn-Token's claims for AS-B's
authorization decision.

Appendix B.1 of
{{I-D.draft-fletcher-transaction-token-chaining-profile}} notes
that Rich Authorization Requests {{RFC9396}} integration is not
defined in that profile and that a future revision may specify how
`authorization_details` from a Txn-Token are transcribed into the
JWT Authorization Grant. The Mission-Bound OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} carries authority as
`authorization_details` of type `mission_resource_access` bound to
a `mission` claim that references a Mission record per the Mission
Framework {{I-D.draft-mcguinness-mission-framework}}. Without an
explicit composition rule, deployments that chain Mission-Bound
credentials across trust domains either drop the governance
reference at the boundary or invent ad-hoc carriage that AS-B cannot
validate.

This document defines that composition. It places the Mission
handle and the audience-filtered Authority Set inside `txn_claims`,
specifies how `mission_resource_access` entries are filtered against
the Cross-Domain Trust Agreement (CDTA) that AS-A and AS-B have
pre-established, and specifies validation rules at AS-B including a
cross-domain Mission Status reach-back to AS-A's state authority.

This document does not modify the Mission Framework, the
Mission-Bound OAuth Profile, or the Transaction Token Chaining
Profile. It composes them.

## Relationship to Other Specifications

- {{I-D.draft-mcguinness-mission-framework}} (Framework) owns the
  Mission record, the Mission Status interface, the typed Authority
  Set, the canonical `mission.id` identifier model, and the
  integrity anchors. This document references these without
  redefining them.
- {{I-D.draft-mcguinness-mission-oauth-profile}} (OAuth Profile)
  owns the `mission` JWT claim, the `mission_resource_access` RAR
  type, and the AS-side derivation of `authorization_details`. This
  document reuses these shapes verbatim in `txn_claims`.
- {{I-D.draft-fletcher-transaction-token-chaining-profile}} (Txn
  Chaining Profile) owns the JWT Authorization Grant shape,
  `txn_claims` semantics, the Cross-Domain Trust Agreement (CDTA)
  concept, and the AS-A to AS-B exchange.
- {{I-D.draft-ietf-oauth-transaction-tokens}} (Txn-Tokens) is the
  intra-trust-domain substrate that AS-A's transcription draws
  from.
- {{I-D.draft-ietf-oauth-identity-chaining}} (Identity Chaining) is
  the cross-trust-domain identity-mapping neighbor; this document
  composes with Txn Chaining, not Identity Chaining directly,
  though deployments may use both.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

In this document the following terms are used as defined elsewhere:

- **Mission**, **Mission record**, **Mission Intent**, **Authority
  Set**, **Mission Status**, **`mission.id`**,
  **`mission.origin`**, **`authority_hash`**: per
  {{I-D.draft-mcguinness-mission-framework}}.
- **`mission` claim**, **`mission_resource_access`**: per
  {{I-D.draft-mcguinness-mission-oauth-profile}}.
- **JWT Authorization Grant**, **`txn_claims`**, **Txn-Token**,
  **Cross-Domain Trust Agreement (CDTA)**, **AS-A**, **AS-B**: per
  {{I-D.draft-fletcher-transaction-token-chaining-profile}}.

This document additionally defines:

- **Transcribing AS**: the Authorization Server that converts a
  Mission-Bound Txn-Token into a JWT Authorization Grant. Equivalent
  to AS-A in the chaining profile.
- **Receiving AS**: the Authorization Server in the partner trust
  domain that consumes the JWT Authorization Grant. Equivalent to
  AS-B.
- **Cross-Domain Mission Status Consumer**: a Receiving AS that has
  been pre-registered at the Transcribing AS's Mission Status
  endpoint per the CDTA.
- **Transcription Profile**: a named, registered rule set governing
  how Mission-bound `txn_claims` members are produced and validated.
  This document defines the initial entry
  `urn:mbo:txn-chain:transcription:default-v1`.

# Composition Model

The Transaction Token Chaining Profile treats `txn_claims` as the
curated, minimized projection of the Txn-Token's claims for the
partner AS's policy. Mission-bound members therefore live inside
`txn_claims`, not at the top level of the JWT Authorization Grant.
Top-level grant claims (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`,
`scope`, `resource`, `txn`) retain the semantics defined by
{{I-D.draft-fletcher-transaction-token-chaining-profile}}; this
document specifies only how Mission-bound state populates and
constrains them.

# Mission Carriage in `txn_claims`

A Transcribing AS that has issued a Mission-Bound access token, or
whose internal Txn-Token carries a Mission reference, MUST place
Mission-bound state into `txn_claims` as defined in this section
when producing a JWT Authorization Grant for AS-B.

## The `mission` Member of `txn_claims`

`txn_claims.mission` MUST carry the same object shape as the
`mission` claim defined in {{I-D.draft-mcguinness-mission-oauth-profile}}.

In canonical mode:

~~~ json
{
  "mission": {
    "id": "msn_01J9Z2P8BQ4Y3F0V0K9D6Z7M1",
    "origin": "https://as-a.example.com",
    "authority_hash": "sha-256:fS8h4w7Z3Lq...",
    "version": 1
  }
}
~~~

The members carry the following meaning at the trust boundary:

- `id`: the canonical `mission.id` identifying the Mission handle.
- `origin`: the Transcribing AS's issuer URL. This is the resolution
  anchor that AS-B uses to discover the Mission Status endpoint per
  {{I-D.draft-mcguinness-mission-framework}}.
- `authority_hash`: the integrity anchor for the Authority Set the
  Mission record holds at the time of transcription.
- `version`: the Mission record version used to produce this grant.

`txn_claims.mission` is a copy of the Mission reference captured by
AS-A at the moment of transcription. It is not a claim AS-B can
forge a Mission state from. AS-B MUST validate Mission state by
reach-back (see {{validation}}).

## Audience-Filtered Authority Set {#audience-filtered-authority-set}

`txn_claims.mission_resource_access` MUST carry a JSON array of
Authority Set entries of type `mission_resource_access` as defined
in {{I-D.draft-mcguinness-mission-oauth-profile}}. The array is the
audience-filtered projection of the Mission record's Authority Set
for AS-B.

An entry is included in `txn_claims.mission_resource_access` if and
only if all of the following hold:

1. The entry's `type` is `mission_resource_access`.
2. The entry's `authority.resource` lies within the resource scope
   that the CDTA grants AS-B.
3. The entry's `narrowing_profile` is one the CDTA permits for
   cross-domain projection.

Entries outside CDTA scope MUST be dropped. The Transcribing AS
MUST NOT widen any entry, MUST NOT alter `actions`, `constraints`,
or `narrowing_profile`, and MUST NOT introduce new keys. The
transcribed entry is byte-equal to the entry the Mission record
holds for the matching resource after audience filtering.

Entries of Authority Set types other than `mission_resource_access`
are out of scope for this document and MUST NOT be transcribed by
an implementation conforming to
`urn:mbo:txn-chain:transcription:default-v1`. Future Transcription
Profiles may define transcription rules for additional types.

## Top-Level `resource` and `scope` Mapping

The top-level `resource` claim in the JWT Authorization Grant MUST
contain the set of distinct `authority.resource` values drawn from
the included `txn_claims.mission_resource_access` entries. This
maintains the invariant defined by
{{I-D.draft-fletcher-transaction-token-chaining-profile}} that
top-level `resource` enumerates the Protected Resources the grant
authorizes.

The top-level `scope` claim MAY be derived from the union of the
included entries' `authority.actions` per a deployment-stated
mapping, or MAY be absent. Deployments that rely entirely on the
RAR-style `mission_resource_access` projection for authority MUST
NOT use `scope` to expand authority beyond what the Authority Set
expresses.

## Transcription Profile Identifier

The JWT Authorization Grant MUST carry the Transcription Profile
identifier as `txn_claims.transcription_profile`. The initial
registered value is `urn:mbo:txn-chain:transcription:default-v1`,
which incorporates the rules in this section verbatim.

## Mission-Bound `txn_claims` Members JSON Schema {#txn-claims-schema}

The Mission-bound members of `txn_claims` validate against the
following schema. The members reuse the inherited shapes verbatim:
`mission` is the OAuth Profile `mission` claim
(`urn:mbo:schema:oauth-mission-claim:1`) and each
`mission_resource_access` entry is a full Authority Set entry
(`urn:mbo:schema:authority-set-entry:1`) of type
`mission_resource_access`, whose inner `authority` payload conforms
to the OAuth Profile's `urn:mbo:schema:mission-resource-access:1`.
The schema describes the Mission-bound members only; the full
`txn_claims` object carries additional members defined by
{{I-D.draft-fletcher-transaction-token-chaining-profile}}, so
additional properties are permitted.

~~~ json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mbo:schema:txn-chain-mission-claims:1",
  "title": "Mission-Bound txn_claims Members",
  "type": "object",
  "required": [
    "mission", "mission_resource_access", "transcription_profile"
  ],
  "properties": {
    "mission": { "$ref": "urn:mbo:schema:oauth-mission-claim:1" },
    "mission_resource_access": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "urn:mbo:schema:authority-set-entry:1"
      }
    },
    "transcription_profile": {
      "type": "string", "format": "uri"
    }
  }
}
~~~

# Worked Example

A minimal JWT Authorization Grant payload illustrating
Mission-bound `txn_claims` carriage (signature and unrelated
optional claims omitted):

~~~ json
{
  "iss": "https://as-a.example.com",
  "sub": "user-mapped-for-partner-b@as-a.example.com",
  "aud": "https://as-b.partner.example.com",
  "iat": 1750000000,
  "exp": 1750000300,
  "jti": "kZ9q3-tj...",
  "txn": "txn-7f3c...",
  "resource": ["https://docs.partner.example.com"],
  "txn_claims": {
    "transcription_profile":
      "urn:mbo:txn-chain:transcription:default-v1",
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "origin": "https://as-a.example.com",
      "authority_hash": "sha-256:fS8h4w7Z3Lq...",
      "version": 1
    },
    "mission_resource_access": [
      {
        "type": "mission_resource_access",
        "specification_uri":
          "https://mcguinness.github.io/mission-bound-authorization/specs/mission_resource_access-v1",
        "schema_digest": "sha-256:9Hf...",
        "schema_version": "1",
        "authority": {
          "resource": "https://docs.partner.example.com",
          "actions": ["documents.read"],
          "constraints": { "folder": "shared-with-b" }
        },
        "narrowing_profile": "urn:mbo:narrowing:default-v1"
      }
    ]
  }
}
~~~

# Validation at the Receiving AS {#validation}

A Receiving AS that accepts a JWT Authorization Grant carrying
Mission-bound `txn_claims` MUST perform the validations in this
section in addition to the validations defined by
{{I-D.draft-fletcher-transaction-token-chaining-profile}}.

## Issuer Trust

The Receiving AS MUST validate that the top-level `iss` is a
Cross-Domain Trust Agreement (CDTA) partner per its issuer trust
policy. The Receiving AS MUST validate the JWT signature against
keys discovered through the issuer's metadata document per
{{RFC8414}} and the issuer trust agreement.

The Receiving AS MUST validate that `txn_claims.mission.origin`
matches a metadata document anchored to the trusted `iss`. The
Receiving AS MUST NOT accept a `txn_claims.mission.origin` that
resolves to a metadata document outside the CDTA-trusted issuer
set, even if the JWT signature is otherwise valid.

## Audience and Freshness

The Receiving AS MUST validate that the top-level `aud` matches its
own issuer URL, that `exp` has not passed, that `iat` is within
acceptable clock skew, and that `jti` has not been previously
consumed within the configured replay window.

The Receiving AS MUST validate that
`txn_claims.transcription_profile` is a value its policy permits.

## Mission State Reach-Back

The Receiving AS MUST query the Mission Status endpoint discovered
through `txn_claims.mission.origin` per
{{I-D.draft-mcguinness-mission-framework}} and
{{I-D.draft-mcguinness-mission-oauth-profile}}. The query MUST use
the canonical `mission.id` carried in `txn_claims.mission.id` and
MUST be authenticated as the Cross-Domain Mission Status Consumer
pre-registered at the Transcribing AS.

The Receiving AS MUST require all of the following from the Mission
Status response to issue a partner-domain access token:

1. The Mission state is `active`.
2. The returned `authority_hash` equals
   `txn_claims.mission.authority_hash`. A divergence indicates the
   Mission record has been re-derived since transcription and the
   grant is stale.
3. The returned `version` equals `txn_claims.mission.version`, or
   the deployment policy explicitly permits version drift within a
   bounded window.
4. The audience-filtered Authority Set projection the Transcribing
   AS returns for the Receiving AS's sector is a superset of the
   entries carried in `txn_claims.mission_resource_access`. The
   Receiving AS MUST NOT issue authority beyond the intersection of
   the projection it observes and the transcribed entries.
5. The response satisfies the authentication, freshness, audience,
   and integrity properties defined in
   {{I-D.draft-mcguinness-mission-framework}}.

A Mission Status response indicating any non-`active` state, an
unknown reference, an unauthorized reference, or an
integrity-mismatched response MUST cause the Receiving AS to refuse
the grant.

## Failure Modes

If the Mission Status endpoint is unreachable, the Receiving AS
MUST fail closed unless the Transcribing AS has advertised a
bounded degraded mode in its metadata per
{{I-D.draft-mcguinness-mission-oauth-profile}} and the Receiving AS
explicitly accepts it under the CDTA. A degraded mode that exceeds
the deployment's `mission_max_stale_seconds` advertisement is not a
permitted fallback.

## Derived Token Binding

When the Receiving AS issues a partner-domain access token (for
example, a JWT access token {{RFC9068}}) from a validated JWT
Authorization Grant, the issued token's `mission` claim MUST be set
as follows:

- `origin`: the Transcribing AS's issuer URL (unchanged).
- `id`: identical to `txn_claims.mission.id`. The Receiving
  AS is not the state authority for the Mission and MUST NOT mint
  a new Mission reference.
- `authority_hash` and `version`: identical to `txn_claims.mission`
  values, subject to the validation above.

Subsequent refresh or exchange at the Receiving AS is gated on
Mission state per {{I-D.draft-mcguinness-mission-oauth-profile}}.
The Receiving AS MAY re-query Mission Status on its own freshness
schedule and MUST refuse derivation when Mission state is not
`active`.

# Trust-Boundary Considerations Between Transaction Token Issuers

The Transaction Token Chaining Profile requires a Cross-Domain
Trust Agreement to bilaterally establish that AS-A and AS-B accept
each other for chained authorization. Mission carriage extends the
CDTA with three additional concerns.

## Mission Status Consumer Pre-Registration

The CDTA MUST establish AS-B as a Cross-Domain Mission Status
Consumer at AS-A's Mission Status endpoint. Pre-registration
covers:

- AS-B's client credentials at AS-A's Mission Status endpoint
  (`client_credentials`, mTLS, or DPoP-bound bearer per the
  applicable OAuth Profile authentication options).
- The maximum tolerated staleness AS-B will accept on responses
  from AS-A.

Without pre-registration, AS-A's Mission Status endpoint MUST
refuse the reach-back as an unauthorized reference,
indistinguishable from an unknown reference per
{{I-D.draft-mcguinness-mission-framework}}.

## Origin Resolution Trust

A Receiving AS MUST NOT accept a `txn_claims.mission.origin` value
solely because it appears inside a signed grant from a CDTA
partner. The CDTA enumerates which Mission Status endpoints AS-B
trusts for the partner. A grant whose `txn_claims.mission.origin`
resolves outside that enumeration MUST be refused, even when the
grant's `iss` is a CDTA partner. This prevents a compromised or
misconfigured AS-A from redirecting Mission Status to an attacker.

# Security Considerations

## Cross-Domain Mission Identifier

The canonical `mission.id` emitted into `txn_claims.mission`
reaches AS-B in plaintext within the signed grant. AS-B observes
the same `mission.id` that AS-A's other partners observe; cross-
partner correlation via Mission identifier is possible by design,
consistent with the Framework's canonical-only identifier model.
Deployments where cross-partner correlation matters compose with
a profile extension to the Framework defining a pairwise Mission
identifier; such extensions are out of scope.

A Transcribing AS MUST treat the grant payload as carrying
correlation-class data and SHOULD restrict its distribution
through CDTA terms rather than through wire confidentiality alone.

## Audience Confusion

The composition relies on two audience signals that MUST agree:
top-level `aud` and the partner identity in the CDTA. A mismatch
between these signals MUST cause the grant to be refused.

## Replay

The grant is bound by `jti`, `iat`, and `exp` per
{{I-D.draft-fletcher-transaction-token-chaining-profile}}. Mission
state reach-back additionally binds the grant to current Mission
state at the moment of consumption. A grant that successfully
validates against the chaining profile's anti-replay controls MUST
still be refused if Mission Status reports `suspended`, `revoked`,
`completed`, or `expired` at consumption time.

## Stale Authority Hash

`txn_claims.mission.authority_hash` is captured at transcription.
If the Mission record's Authority Set changes between transcription
and consumption (for example, narrowing during expansion review),
the hash returned by Mission Status diverges. The Receiving AS
MUST refuse on divergence rather than accepting either the
transcribed or the freshly returned Authority Set. The Transcribing
AS issues a new grant against the current Mission record on the
next chained request.

## Transcription Profile Negotiation

A Receiving AS MUST NOT accept Transcription Profiles outside the
CDTA-permitted set. Permitting unknown profiles permits a
Transcribing AS to alter transcription rules unilaterally, which
could widen authority beyond what AS-B's policy intended.

## Mission Status Endpoint as a High-Value Target

Aggregating cross-domain reach-back to a single Mission Status
endpoint concentrates trust. Operational guidance from
{{I-D.draft-mcguinness-mission-oauth-profile}} applies: the endpoint
authenticates callers, refuses bearer use of Mission references,
returns indistinguishable responses for unknown and unauthorized
references, and binds responses to the requesting caller, audience,
and nonce.

# Privacy Considerations {#privacy-considerations}

Carrying a Mission reference across a trust boundary introduces a
cross-domain correlation surface that does not exist when a Mission
stays within one domain. The considerations below are additional to
the Framework's privacy treatment.

## Cross-partner correlation

As described in {{cross-domain-mission-identifier}}, the canonical
`mission.id` reaches AS-B in plaintext inside the signed grant, and
it is the same identifier every CDTA partner of AS-A observes for
that Mission. Two partners that both receive grants for the same
Mission can therefore correlate the user's activity across their
domains through `mission.id`. This is inherent to the Framework's
canonical-only identifier model and is consented to at approval
time; deployments that require cross-partner Mission-identity
isolation compose with a Framework profile extension defining a
pairwise Mission identifier (out of scope here).

## The grant payload is correlation-class data

The JWT Authorization Grant carries the Mission reference, the
mapped subject, and the audience-filtered authority together. A
Transcribing AS MUST treat the grant as correlation-class data
({{cross-domain-mission-identifier}}) and SHOULD bound its
distribution and retention through CDTA terms rather than relying on
transport confidentiality alone. The audience-filtering requirement
({{audience-filtered-authority-set}}) limits what each partner
learns about the Mission's authority to the resources within that
partner's CDTA scope.

## No new identifier

This composition introduces no identifier of its own. It carries the
canonical `mission.id` already defined by the Framework and the
subject mapping already defined by
{{I-D.draft-fletcher-transaction-token-chaining-profile}}; it adds
no correlation handle beyond those.

# IANA Considerations

## `txn_claims` Mission-Bound Members

This document requests registration of the following members within
the `txn_claims` object defined by
{{I-D.draft-fletcher-transaction-token-chaining-profile}}, in the
registry that document creates for `txn_claims` members. If that
registry does not exist at the time of publication, these members
are documented descriptively in this document.

- `mission`: object carrying the Mission reference per
  {{I-D.draft-mcguinness-mission-oauth-profile}}. Members: `id`
  (string, canonical `mission.id`), `origin` (URL),
  `authority_hash` (string), `version` (integer).
- `mission_resource_access`: array of audience-filtered Authority
  Set entries of type `mission_resource_access` per
  {{I-D.draft-mcguinness-mission-oauth-profile}}.
- `transcription_profile`: string identifier of the Transcription
  Profile applied by the Transcribing AS.

Change Controller: IETF. Reference: this document.

## Mission Transcription Profile Registry

This document requests creation of a new IANA registry,
**Mission Transcription Profiles**, with the following columns:

- Profile identifier (URI).
- Specification reference (immutable).
- Permitted Authority Set entry types.
- Audience-filtering rule reference.
- Narrowing profiles permitted for cross-domain projection.
- Change controller.

Registration policy: Specification Required.

Initial entry:

- Identifier: `urn:mbo:txn-chain:transcription:default-v1`.
- Specification reference: this document.
- Permitted Authority Set entry types: `mission_resource_access`.
- Audience-filtering rule reference: {{audience-filtered-authority-set}}
  of this document.
- Narrowing profiles permitted: those advertised under the
  applicable CDTA; `urn:mbo:narrowing:default-v1` permitted by
  default.
- Change controller: IETF.

## Updates to Existing Registries

This document does not register new JWT claims. The top-level
grant claims (`iss`, `aud`, `sub`, `exp`, `iat`, `jti`, `scope`,
`resource`, `txn`, `txn_claims`) remain registered by
{{I-D.draft-fletcher-transaction-token-chaining-profile}} and
referenced specifications. The `mission` member nested inside
`txn_claims` is registered by this document at the `txn_claims`
level only; the top-level `mission` JWT claim is registered by
{{I-D.draft-mcguinness-mission-oauth-profile}} and unchanged here.

# Acknowledgments
{:numbered="false"}

The author thanks the editors and contributors of
{{I-D.draft-fletcher-transaction-token-chaining-profile}},
{{I-D.draft-ietf-oauth-transaction-tokens}}, and the
Mission-Bound Authorization architecture for the discussions that
shaped this composition.

--- back
