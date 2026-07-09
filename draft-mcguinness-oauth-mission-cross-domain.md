---
title: "Mission Cross-Domain Projection for OAuth 2.0"
abbrev: "OAuth Mission Cross-Domain"
category: std

docname: draft-mcguinness-oauth-mission-cross-domain-latest
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
 - cross-domain
 - identity-chaining
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC7523:
  RFC7662:
  RFC7800:
  RFC8693:
  RFC8705:
  RFC9396:
  RFC9449:
  I-D.draft-ietf-oauth-identity-chaining:
  I-D.draft-ietf-oauth-identity-assertion-authz-grant:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-ietf-oauth-transaction-tokens:
  I-D.draft-fletcher-transaction-token-chaining-profile:
  I-D.draft-mcguinness-oauth-id-assertion-framework:
  I-D.draft-mcguinness-oauth-domain-authorized-issuer:
  I-D.draft-mcguinness-oauth-actor-receipts:
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
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
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The Mission-Bound Authorization for OAuth 2.0 profile binds issued
authority to a durable, human-approved Mission held by a single
Authorization Server, the Mission Issuer. This document specifies that
profile's optional cross-domain projection: a single hop that lets an
Authorization Server in another trust domain, a Resource AS, honor a
Mission it did not issue. The Mission Issuer projects audience-scoped
Mission authority in a short-lived, sender-constrained cross-domain
grant of the OAuth identity chaining architecture; the Resource AS
validates the grant and mints its own local tokens, preserving the
Mission binding unchanged. The Mission record never crosses the
boundary, and honoring it needs no session with the Mission Issuer.
The Identity Assertion Authorization Grant
(ID-JAG) is the recommended grant profile. Single-domain deployments
of the base profile are unaffected by this document.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} makes a
Mission a durable, human-approved, integrity-bound OAuth authorization
artifact: one Authorization Server, the Mission Issuer, approves it,
records it, and derives every token under it. That profile is
deliberately single-domain: the AS that holds the Mission is the AS
that issues for it.

Real tasks cross trust domains. An agent reconciling invoices may need
a partner's ERP, behind a partner Authorization Server the home AS
does not control and whose accounts it does not manage. This document
specifies **cross-domain projection**: the originating Mission Issuer
projects a Mission's authority, audience-scoped and
integrity-anchored, to an Authorization Server in another trust
domain, which honors it by minting local tokens for its own resources.
The projection is a single hop, issuer to Resource AS; chaining a
Mission across more than one trust-domain boundary remains future work
({{I-D.draft-mcguinness-oauth-mission}}, Section "Non-Goals").

Two roles carry the model. The **Mission Issuer** (the Mission's
`issuer`) remains the only party that creates, holds, and gates the
Mission. A **Resource AS** honors a Mission it did not issue: it
validates the projected grant, applies its own local policy, and mints
its own tokens, preserving the Mission binding unchanged. A Resource
AS is never the Mission Issuer.

Three properties define the projection. The Mission does not cross:
the record, the Mission Intent, the full Authority Set, and lifecycle
authority stay with the Mission Issuer, and the Resource AS receives
only claim-shape facts and the entries scoped to it
({{what-crosses}}). Authority never widens: the projection carries
the agent's authority preserved and scoped to the audience, and
nothing the Resource AS mints may widen it
({{validation-at-resource-as}}). Honoring is session-less: the
Resource AS verifies pre-established issuer trust and a signature, so
the Mission Issuer is never on the partner's request path; the cost
of that independence is a bounded revocation lease
({{cross-domain-revocation}}).

# Status: An OPTIONAL Extension {#status}

This document is the Cross-Domain capability named by the base
profile's conformance model ({{I-D.draft-mcguinness-oauth-mission}},
Section "Conformance"). The capability is OPTIONAL: a deployment whose
Missions never leave their issuing AS does not implement this
document, and the base profile is complete without it.

Two external dependencies set its deployment posture. The OAuth
identity chaining architecture
{{I-D.draft-ietf-oauth-identity-chaining}} is approved for publication
and in the RFC Editor queue; the Identity Assertion Authorization
Grant {{I-D.draft-ietf-oauth-identity-assertion-authz-grant}} is a
working-group document. This document profiles them and cannot advance
ahead of them; confining them here keeps the base profile free of
in-progress cross-domain dependencies.

The capability is orthogonal to the family's Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}): projection changes
where a Mission is honored, not the strength at which either domain
enforces it. Each trust domain runs at its own level.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses the terms of the base profile
{{I-D.draft-mcguinness-oauth-mission}}: Mission, Mission Issuer (the
Mission's `issuer`), Mission Intent, Authority Set, Subject, `mission`
claim, derived token, derivation, the subset rule, and lifecycle
gating. Authority Set entries are {{RFC9396}} `authorization_details`
objects. All JSON shown in this document is non-normative and
illustrative; the member definitions in the surrounding text are
authoritative.

Resource AS:
: An Authorization Server in another trust domain that honors a
  Mission it did not issue, minting its own tokens for its resources
  from a cross-domain grant. A Resource AS is never the Mission
  Issuer.

Cross-domain grant:
: The short-lived JWT authorization grant the Mission Issuer issues
  toward a Resource AS ({{cross-domain-grant}}), carrying
  audience-scoped Mission authority and the `mission` claim. It is a
  Mission-bound token in the sense of the base profile.

Local token:
: An access token a Resource AS mints for its own resources from a
  cross-domain grant ({{validation-at-resource-as}}).

# Cross-Domain Projection {#model}

A Mission is approved and held by one Mission Issuer (its `issuer`).
This document lets a single Mission be honored by Authorization
Servers in other trust domains, so a Mission can span more than one
AS, using the cross-domain authorization grant of the OAuth identity
chaining architecture {{I-D.draft-ietf-oauth-identity-chaining}}: the
issuer AS issues, through an {{RFC8693}} token exchange, a short-lived
JWT authorization grant audienced to the target Authorization Server,
which the client redeems there with the {{RFC7523}} JWT-bearer grant.

This document calls that artifact the **cross-domain grant** and
attaches Mission context to it ({{cross-domain-grant}}). The Identity
Assertion Authorization Grant (ID-JAG)
{{I-D.draft-ietf-oauth-identity-assertion-authz-grant}} is the
RECOMMENDED profile of the cross-domain grant, and every example in
this document uses it; another identity-chaining JWT authorization
grant profile that meets the requirements of {{cross-domain-grant}}
MAY be used instead. Where a requirement elsewhere in this document
names the ID-JAG, it is illustrating with the recommended profile and
applies equally to any conforming cross-domain grant.

This document is a thin Mission-bound profile of the cross-domain
grant, not merely `mission`-claim carriage: beyond attaching and
validating Mission context, it imposes two security requirements on the
grant for Mission-bound use, proof-of-possession and single use
({{cross-domain-grant}}, {{validation-at-resource-as}}). The grant's
own format, signing, and token-exchange envelope remain defined by the
cross-domain grant profile (ID-JAG in the recommended case) and its
underlying {{RFC8693}} and {{RFC7523}}; this document does not redefine
them. The two added requirements are a floor: the cross-domain grant is
the highest-authority credential crossing a trust boundary, and its
profile does not by itself guarantee them.

In this model there is exactly one Mission Issuer per Mission (the
`issuer`) and one or more **Resource ASes** in other domains that
mint their own tokens for their resources. A Resource AS is never the
Mission Issuer and MUST NOT create or alter a Mission.

# What Crosses the Trust Boundary {#what-crosses}

The projection is exact about what leaves the issuing domain.

Three values cross unchanged: `mission.id`, `mission.issuer`, and
`authority_hash`, the claim-shape Mission binding every downstream
token preserves ({{validation-at-resource-as}}). They are audit and
correlation anchors, not credentials.

Two things cross scoped: the audience-scoped Authority Set entries
({{audience-scope}}), and the Mission's Subject in the form the
identity chaining architecture defines ({{cross-domain-grant}}).

Everything else stays home. The Mission record, the Mission Intent,
the full Authority Set, and lifecycle authority remain with the
Mission Issuer; a Resource AS never creates or alters a Mission
({{model}}). The grant is not refreshable and confers no standing
authority in the partner domain: when it expires, the client returns
to the issuer for a new one, which is how the issuer's lifecycle gate
keeps reaching across the boundary.

Nothing returns across the boundary at validation time. The Resource
AS honors the grant from pre-established trust
({{pre-established-trust}}) and the signature alone; its assurance
that the Mission was `active` is a lease bounded by the grant
lifetime ({{cross-domain-revocation}}).

## Audience-Scoped Authority {#audience-scope}

When projecting authority toward a Resource AS, the Mission Issuer
includes only the Authority Set entries whose `resource` that
Resource AS is authoritative for, under the deployment's
resource-to-AS mapping ({{pre-established-trust}}). Entries for other
Resource ASes MUST NOT be disclosed.

# Relationship to Transaction Token Chaining {#txn-chaining}

This section is informative. The Transaction Token chaining profile
({{I-D.draft-fletcher-transaction-token-chaining-profile}}) is a
sibling of this document: the same identity-chaining framework, the
same exchange-then-redeem shape at the same boundary, the same
short-grant discipline, a distinct `typ` (`txn-chain+jwt`). What
crosses differs. Its grant carries the in-flight transaction's
context, minted from a Transaction Token
({{I-D.draft-ietf-oauth-transaction-tokens}}) that never leaves its
domain; this document's grant carries the durable approved task. A
hop between the same two domains may legitimately need both facts,
and a deployment MAY run both profiles on one hop. They compose as
follows:

- **The Mission reference may ride the transaction chain as
  evidence, never as authority.** The `mission` claim object (`id`,
  `issuer`, `authority_hash`) MAY be carried inside that profile's
  minimized `txn_claims`, exactly as it rides an intra-domain
  Transaction Token in this document's end-to-end example. It is
  inert there: a consumer MUST NOT derive, widen, or gate authority
  from it, and a partner that needs the committed facts verifies a
  Mission Mandate ({{I-D.draft-mcguinness-mission-mandate}}).
  Mission-scoped authority reaches another domain only through this
  document's grant.
- **The transaction identifier may ride this document's evidence.**
  A Resource AS that redeems a Mission-bound grant while
  participating in a transaction chain MAY record the transaction
  identifier with its redemption and derivation evidence, so the
  transaction chain and the Mission projection correlate in audit
  across both domains.
- **Recursion does not extend projection.** That profile permits
  recursive chaining: the second domain repeats the pattern toward a
  third. A Mission's projection is single-hop by design
  ({{what-crosses}}); a recursive transaction chain carries the
  Mission reference onward as evidence only, and a third domain that
  must honor the Mission needs its own projection from the
  originating issuer.

# Pre-Established Trust {#pre-established-trust}

Projection is configured, not negotiated: nothing in the protocol
establishes trust between the domains, and every trust input below
exists before the first grant is issued.

- Issuer trust: which Mission Issuers the Resource AS accepts, by
  local policy or issuer metadata ({{validation-at-resource-as}}).
  The identity-assertion trust framework and its
  domain-authorized-issuer method
  ({{I-D.draft-mcguinness-oauth-id-assertion-framework}},
  {{I-D.draft-mcguinness-oauth-domain-authorized-issuer}}) are
  concrete ways to publish and evaluate this policy instead of
  hand-maintaining a list.
- The resource-to-AS mapping: which Resource AS is authoritative for
  which `resource` values, the mapping audience scoping is computed
  under ({{audience-scope}}).
- The grant profile in use (the ID-JAG in the RECOMMENDED case) and,
  where that profile defines no proof-of-possession, the
  sender-constraint mechanism ({{cross-domain-grant}}); binding and
  verification interoperate only if both domains fix the same one.
- Client registration: the presenting client is registered with and
  authenticates to the Resource AS's token endpoint, as the grant
  profile requires.
- Subject resolution: the account-linking policy by which the
  Resource AS resolves the conveyed Subject in its own namespace
  ({{validation-at-resource-as}}).
- Derivation records: whether the Resource AS keeps the per-token
  derivation record of {{validation-at-resource-as}}. An originating
  AS MAY condition projection on it.

A deployment that publishes a Mission Deployment Profile
({{I-D.draft-mcguinness-mission-architecture}}) records its
projection posture in these terms, and the accepted cross-domain
revocation window ({{cross-domain-revocation}}) among its residual
risks.

# Issuing the Cross-Domain Grant {#cross-domain-grant}

Issuing a cross-domain grant is a derivation event and is gated like
any other derivation ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Lifecycle and Gating"). It counts once against the Mission's
derivation budget, however many local tokens the partner domain later
mints: the issuer cannot observe those tokens and does not count
them, and the Resource AS bounds its own minting by the grant and by
local policy ({{validation-at-resource-as}}). Because each grant
lives at most 300 seconds, steady-state partner work re-issues grants
on a lease cadence and consumes at least 12 derivations per hour per
audience; a deployment sizes the Mission's `max_derivations` control
({{I-D.draft-mcguinness-oauth-mission}}) as a function of that
cadence times the projected audiences times the Mission's duration.
A Mission-bound cross-domain grant:

- MUST be a JWT authorization grant issued and signed by the Mission
  `issuer`, redeemable at the target Resource AS through the
  {{RFC7523}} JWT-bearer grant;
- MUST be explicitly typed with the JWT `typ` its grant profile
  defines (`oauth-id-jag+jwt` for the RECOMMENDED profile), so the
  grant is mechanically distinguishable from every other issuer-signed
  Mission artifact; a Mission Mandate
  ({{I-D.draft-mcguinness-mission-mandate}}) is never redeemable as a
  grant, and the `typ` is what a token endpoint separates them by;
- MUST be audienced to the target Resource AS, and MUST NOT have a
  lifetime exceeding 300 seconds (a short lifetime bounds cross-domain
  revocation latency; see {{cross-domain-revocation}});
- MUST have an `exp` that does not exceed the Mission's
  `expires_at`, per the base profile's expiry rule
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission-Bound
  Access Tokens");
- MUST be sender-constrained ({{RFC7800}}) to the presenting client by
  the proof-of-possession mechanism the cross-domain grant profile
  defines, where it defines one. This
  document does not define a new PoP mechanism; the originating AS and
  the Resource AS MUST use the mechanism of the profile in use, so that
  binding and verification interoperate. When the grant profile in use
  defines no proof-of-possession, as the ID-JAG profile does not (the
  ID-JAG is a bearer authorization grant, protected by audience
  restriction, short lifetime, and client authentication at
  redemption), the grant carries a `cnf` claim
  ({{RFC7800}}) binding the presenting client's DPoP key (`jkt`,
  {{RFC9449}}) or mTLS certificate (`x5t#S256`, {{RFC8705}}), and the
  Resource AS MUST verify possession at redemption
  ({{validation-at-resource-as}}). Binding and verification MUST use the
  same mechanism;
- MUST carry a `jti` for one-time use, so the bound party cannot
  replay it within its lifetime ({{validation-at-resource-as}},
  {{RFC7523}} Section 3);
- MUST carry the `mission` claim
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "The Mission
  Claim") with `id`, `issuer`, and `authority_hash` unchanged from the
  Mission, and the audience-scoped `authorization_details`
  ({{audience-scope}}); and
- MUST convey the Mission's Subject in the form the identity chaining
  architecture defines, so the Resource AS can resolve it locally
  ({{validation-at-resource-as}}).

The ID-JAG profile meets these requirements and is RECOMMENDED; in it
the artifact is the ID-JAG and the issuance request carries a
`requested_token_type` of `urn:ietf:params:oauth:token-type:id-jag`.

The client obtains the grant with an {{RFC8693}} token exchange. The
`subject_token` MUST be the Mission's refresh token, with
`subject_token_type` of
`urn:ietf:params:oauth:token-type:refresh_token`, and the `audience`
identifies the target Resource AS. The refresh-token subject is this
profile's deviation from the ID-JAG issuance request, which that
specification defines over an identity-assertion `subject_token`
(`id_token` or `saml2`); a Mission-bound deployment substitutes the
Mission's grant so the exchange resolves a Mission rather than a bare
subject assertion. This refresh-token mode is what
binds the request to a Mission: the AS resolves the Mission from the
presented grant per the base profile's grant binding
({{I-D.draft-mcguinness-oauth-mission}}, Section "Binding the Mission
to the Grant"), exactly as on any other refresh, and the grant
therefore projects the agent's full Mission authority
(audience-scoped), never a narrowed delegate's.

The refresh-token subject mode is the only mode this profile defines,
and fixing it is deliberate: the refresh token resolves to exactly
one Mission and its full authority, where an access token or
delegated token could carry a narrowed or actor-specific subset that
a trust-boundary crossing could re-widen. Other Mission-bound
subject-token modes, such as an access-token mode bounding the
projection by the presenting token, are left to future profiles. The
cost is that this OPTIONAL capability is unavailable to a deployment
that issues no refresh token; such a deployment uses the
single-domain base profile, which needs none.

The AS MUST reject an access token or a delegated token presented as
`subject_token` for cross-domain issuance. The AS MUST NOT resolve the
Mission from a client-supplied `mission_id`, nor from an identity
assertion that carries no Mission binding ({{error-responses}}).

Before issuing, the AS MUST verify the Mission is `active` (failing
otherwise with `invalid_grant`) and that the target Resource AS is
authorized for the requested resources under the Mission's Authority
Set (failing otherwise with `invalid_target`, {{RFC8693}}). The token-exchange
response carries `issued_token_type` of
`urn:ietf:params:oauth:token-type:id-jag` (for the RECOMMENDED
profile) and `token_type` of `N_A`, per {{RFC8693}} Section 2.2.1.

A delegate, rather than the agent, crossing a trust domain directly
and carrying its own narrowed authority into another domain is out of
scope for this document and deferred to future work. Cross-domain
issuance here always projects the agent's Mission authority; delegation
within the target domain is performed by the Resource AS
({{validation-at-resource-as}}). A sub-agent that must act in a
different trust domain under its own narrowed authority is therefore not
covered by a single hop; distributed multi-agent work across domains
composes only through the agent's projected authority or through
separate Missions per domain. A delegate-carries-its-own-authority mode
is future work.

Two roles MUST NOT be conflated. The grant the client presents to
*obtain* the cross-domain grant (the Mission's refresh token) is the
input to the exchange and selects the Mission; the Mission-bound
access token plays no part here. The identity the issued grant conveys
*to* the Resource AS is the Mission's Subject, which the AS populates
from the Mission's recorded `subject` and which the Resource AS
resolves locally per the identity chaining rules (this document
defines no cross-domain subject mapping, {{validation-at-resource-as}}).

Sender-constraining is REQUIRED for the cross-domain grant, stronger
than the RECOMMENDED level the base profile sets for the primary
access token ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission-Bound Access Tokens"): it is the highest-authority credential
in the chain and the only one that crosses a trust boundary, and the
underlying grant provides no replay backstop of its own.

# Validation at the Resource AS {#validation-at-resource-as}

A Resource AS consuming a Mission-bound cross-domain grant:

- MUST establish issuer trust in the originating AS by local policy
  or issuer metadata before accepting any Mission reference. It MUST
  NOT trust a `mission.issuer` merely because it appears inside a
  signed assertion.
- MUST validate the grant's explicit `typ` (per the grant profile in
  use; `oauth-id-jag+jwt` for the RECOMMENDED profile), signature,
  and expiry, and verify its `aud` is the Resource AS's own
  identifier: it rejects a grant minted for a different Resource AS,
  and rejects a JWT of any other type presented as this grant,
  whatever Mission facts it carries.
- MUST verify the grant's sender-constraint by the proof-of-possession
  mechanism the cross-domain grant profile defines (for the ID-JAG
  profile, as that specification defines), and MUST reject with
  `invalid_grant` a cross-domain grant that is not sender-constrained
  or whose proof-of-possession does not verify. When the grant profile
  defines no proof-of-possession and the grant carries a `cnf` claim
  per {{cross-domain-grant}}, the Resource AS MUST verify possession of
  that key at redemption: a DPoP proof ({{RFC9449}}) for its own token
  endpoint for a `jkt` binding, or the mTLS connection certificate
  ({{RFC8705}}) for an `x5t#S256` binding. Binding and verification
  MUST use the same mechanism. A bearer grant MUST
  NOT be accepted: it is the highest-authority credential crossing the
  trust boundary, so accepting one unbound would let any party that
  captured it mint a local token.
  - Because this document defines no cross-domain status query,
    freshness is the Resource AS's only check that the Mission was
    active at issuance; the short grant lifetime bounds the staleness.
- MUST reject a replayed cross-domain grant: it MUST track the grant's
  `jti` for the grant's validity window and refuse a second
  presentation with `invalid_grant` ({{RFC7523}} Section 3), so a grant
  cannot be replayed even by the party it is bound to.
- When issuing local access tokens for its resources, the Resource AS
  uses the subject-resolution rules of the underlying cross-domain
  grant and identity chaining specifications. The local token preserves
  the `mission` claim (`id`, `issuer`, and `authority_hash`) unchanged
  from the cross-domain grant. The issuing `iss` is the Resource AS;
  `mission.issuer` remains the originating AS. Such a local token:
  - has an `exp` that MUST NOT exceed the grant's `exp`. The Resource
    AS does not hold the Mission's `expires_at`; because the grant's
    own `exp` is bounded by it ({{cross-domain-grant}}), the local
    token is bounded transitively;
  - MUST be sender-constrained ({{RFC7800}}), like the grant it derives
    from, and MUST NOT be issued as a bearer token; and
  - if it preserves the issuer's `client_id`, does so only as an audit
    reference, not a local identity: that value is in the originating
    AS's namespace, and a partner Resource Server MUST NOT resolve or
    authorize on it as a local client, for the same portability reason
    that applies to a `sub` matcher in `allowed_delegates` (see
    below).
- MUST bound the issued `authorization_details` by what the
  cross-domain grant conveyed, and MUST apply its own local
  authorization policy in addition: honoring a Mission does not
  obligate it to authorize any particular request. Because the
  conveyed entries were derived under the originating AS's local policy,
  the Resource AS does not re-derive them; it interprets and enforces
  them by their structure and vocabulary. It MUST fail closed on a
  conveyed `actions` identifier or `constraints` key it does not
  recognize for the resource in question, exactly as a Resource Server
  does ({{I-D.draft-mcguinness-oauth-mission}}, Section "Resource
  Server Enforcement"), so authority it cannot interpret is never
  honored across the trust boundary rather than enforced by guess.
- MUST, when it issues delegated tokens of its own, enforce each
  entry's `delegation` policy as the base profile specifies
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Delegation
  Constraints"); the policy travels on the conveyed entries. The
  cross-domain grant carries no `act` chain ({{cross-domain-grant}}),
  so the Resource AS's own delegation depth begins at 0.
- SHOULD record, per minted local token, both sides of the
  derivation: the consumed grant's `jti` and conveyed
  `authorization_details`, and the local token's own identifier or
  digest (`jti`), `iss`, `aud`, `iat`, `exp`, and issued
  `authorization_details`. The issuer cannot observe local tokens
  ({{cross-domain-revocation}}), so this record is the only evidence
  tying a local token to the grant it was minted from and showing
  its authority did not widen; without it, cross-domain minting is
  unaccountable to both domains. Whether the Resource AS keeps this
  record is a pre-established trust input
  ({{pre-established-trust}}).

A grant that carries no `mission` claim is outside this profile: the
Resource AS processes it, or refuses it, under plain identity
chaining, and MUST NOT grant Mission-scoped resources on it. Where
the deployment's pre-established trust ({{pre-established-trust}})
requires Mission binding for the requested resources, the Resource AS
refuses such a grant with `invalid_grant`; a `mission` claim that is
present but malformed is always `invalid_grant`
({{error-responses}}).

A `{ "sub": ... }` matcher in a conveyed entry's
`delegation.allowed_delegates` is a client identifier in the
originating AS's namespace and is not portable across the trust
domain. When a Resource AS evaluates a conveyed entry, it MUST fail
closed, narrowing the entry out, for any `sub` matcher it cannot
resolve against the delegate it authenticated in its own namespace.
Portable cross-domain matching SHOULD therefore use a `sub_profile`
matcher, an actor-type class rather than a domain-relative identifier
({{I-D.draft-mcguinness-oauth-mission}}, Section "Delegation
Constraints").

This document does not define cross-domain subject mapping. A Resource
AS consuming a Mission-bound cross-domain grant resolves the subject
of any local token according to the cross-domain grant profile in use
(the Identity Assertion Authorization Grant profile in the recommended
case), the OAuth identity chaining architecture, and its local trust
and account-linking policy. This document only requires that the
Mission binding (`mission.id`, `mission.issuer`, and `authority_hash`)
and the audience-scoped `authorization_details` remain bounded as
described here.

Downstream, `authority_hash` is an immutable audit and correlation
anchor to the originating AS's consent commitment. A Resource AS and
its Resource Servers hold only the audience-scoped subset, never the
full Authority Set, so they cannot recompute `authority_hash`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Integrity Anchors");
its integrity rests on the signature chain (the originating AS signs
the ID-JAG; the Resource AS validates issuer trust and signs its local
token). It is verifiable only against the originating AS, which this
document does not require to be exposed. A Resource AS or auditor
that needs to verify the conveyed entries against the approved
commitment MAY obtain a Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}) and recompute
`authority_hash` per that profile.

# Error Responses {#error-responses}

This document defines no new error codes; it binds the standard codes
of {{RFC8693}}, {{RFC7523}}, and OAuth 2.0 to this profile's failure
conditions so both surfaces fail uniformly.

At issuance (the token exchange at the Mission Issuer,
{{cross-domain-grant}}):

| Condition | Error |
|---|---|
| `subject_token_type` is not `refresh_token`, or an access, delegated, or bare identity-assertion token is presented | `invalid_request` |
| The subject token does not resolve to a Mission, or the Mission is not `active` | `invalid_grant` |
| The target Resource AS is not authorized for the requested resources under the Authority Set | `invalid_target` |

At redemption (the JWT-bearer grant at the Resource AS,
{{validation-at-resource-as}}):

| Condition | Error |
|---|---|
| Client authentication fails | `invalid_client` |
| Untrusted issuer; wrong or missing `typ`; signature, audience, or expiry failure; a sender-constraint absent, unverifiable, or bound to a different client; a replayed `jti`; a malformed `mission` claim, or a grant carrying none where the deployment's pre-established trust requires Mission binding for the requested resources ({{validation-at-resource-as}}) | `invalid_grant` |
| The request names a resource outside the conveyed entries | `invalid_target` |

A Resource AS rejecting a grant reveals no Mission state it does not
hold: `invalid_grant` at redemption speaks to the presented grant,
not to the Mission's current lifecycle state, which the Resource AS
cannot know ({{introspection-at-resource-as}}).

# Introspection at a Resource AS {#introspection-at-resource-as}

The base profile's OPTIONAL token introspection ({{RFC7662}}) reports
a `mission` response member, and only the Mission `issuer` reports the
Mission's lifecycle `state` ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission State via Token Introspection"). This section
specifies the non-issuer half of that rule.

A Resource AS that supports introspection for a local token it minted
from a cross-domain grant returns the claim-shape members only: `id`,
`issuer`, and `authority_hash`. It holds the token, not the Mission:
it knows the Mission state only as of grant validation and has no
query to the issuer keyed by `mission_id` (neither this document nor
the base profile defines one). It MUST omit `mission.state` rather
than report a stale value as current. `authority_hash`, when included,
is the issuer's commitment carried through the grant, not a value the
Resource AS recomputes from its audience-scoped subset
({{I-D.draft-mcguinness-oauth-mission}}, Section "Consent Binding").

# Authorization Server Metadata {#as-metadata}

Discovery uses existing metadata; this document defines no new
parameters. A Mission Issuer supporting this capability advertises
the {{RFC8693}} token-exchange grant type in `grant_types_supported`,
the base profile's signal for cross-domain grant issuance
({{I-D.draft-mcguinness-oauth-mission}}, Section "Authorization
Server Metadata"). A Resource AS advertises the {{RFC7523}}
JWT-bearer grant type the grant is redeemed through; support for a
specific grant profile is discovered as that profile specifies, or
out of band. The bilateral inputs of {{pre-established-trust}} are
not discoverable and exist before first use.

# Security Considerations

The security considerations of the base profile
{{I-D.draft-mcguinness-oauth-mission}} and of the identity chaining
architecture {{I-D.draft-ietf-oauth-identity-chaining}} apply.

## Cross-Domain Revocation Latency {#cross-domain-revocation}

Single-domain revocation is prompt: the AS that issued a token also
honors its revocation ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Revocation"). The cross-domain case is strictly weaker. When a
Mission is revoked at the originating AS, that AS can stop issuing new
cross-domain grants, but it cannot revoke a token a Resource AS has
already minted in another domain: that token remains valid until its
own expiry. Cross-domain revocation latency is therefore the
downstream token lifetime. The grant lifetime is the state lease the
partner domain runs on: the longest a Resource AS may treat Mission
state established at issuance as current
({{I-D.draft-mcguinness-mission-runtime}}). For this reason, Resource
ASes MUST issue
short-lived local tokens for Mission-bound interactions; the
originating AS bounds grant lifetimes by the 300-second cap of
{{cross-domain-grant}}, so a revoked Mission cannot continue to seed
new downstream tokens for long.
The base profile's token introspection closes the revocation gap only
single-domain: it requires the introspecting AS to hold the Mission,
and a Resource AS has no query to the issuer keyed by `mission_id`
({{introspection-at-resource-as}}), so short downstream lifetimes
remain the only cross-domain control. Deployments needing a tighter
lease add the companion mechanisms this document does not require:
Mission Status {{I-D.draft-mcguinness-oauth-mission-status}} gives
any consumer holding the `mission_id`, including a Resource AS, a
state query against the issuer, and Mission Lifecycle Signals
{{I-D.draft-mcguinness-oauth-mission-signals}} pushes lifecycle
transitions to the partner domain.

## The Grant at the Trust Boundary

The cross-domain grant is the highest-authority credential in the
chain and the only one that crosses a trust boundary. The requirements
of {{cross-domain-grant}} and {{validation-at-resource-as}} follow
from that position: issuer trust is established by local policy or
metadata, never inferred from a signed assertion's own
`mission.issuer`; the grant is sender-constrained and one-time-use,
because the underlying grant profile provides no replay backstop of
its own; and everything the Resource AS honors is bounded by the
audience-scoped entries the grant conveyed, interpreted fail-closed.
Downstream of the issuer, `authority_hash` is an audit and correlation
anchor, not a recomputable proof: its integrity rests on the signature
chain ({{validation-at-resource-as}}).

One companion mechanism composes here beyond the trust publication
methods of {{pre-established-trust}}: a consumer that needs
independently verifiable provenance of the delegation hops upstream
of the re-mint, rather than trust in the minting domain's assertion
of them, MAY require issuer-signed hop receipts
({{I-D.draft-mcguinness-oauth-actor-receipts}}).

# Privacy Considerations

The cross-domain grant and every local token minted from it carry the
canonical `mission_id`, `mission.issuer`, and `authority_hash`
unchanged, so a Resource AS and its Resource Servers can correlate a
Mission's activity across domains, and `mission.issuer` identifies the
issuing AS to the partner domain. This is the deliberate correlation
property of the base profile
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Identifier
Correlation"), extended across the trust boundary. Audience scoping
({{audience-scope}}) is the minimization measure: a Resource AS never
sees Authority Set entries addressed to other audiences.

# Conformance {#conformance}

An implementation conforms in one of two roles and names the
capability as the base profile's conformance model directs (for
example, "Mission Issuer with Cross-Domain";
{{I-D.draft-mcguinness-oauth-mission}}, Section "Conformance").

An **Originating Mission Issuer with Cross-Domain** is a conforming
Mission Issuer of the base profile that additionally:

- issues the Mission-bound cross-domain grant per
  {{cross-domain-grant}}, gated and counted as a derivation;
- scopes every projection by audience ({{audience-scope}});
- fails issuance with the codes of {{error-responses}}; and
- advertises cross-domain grant issuance per {{as-metadata}}.

A **Resource AS**:

- honors the cross-domain grant per {{validation-at-resource-as}},
  including issuer trust by local policy, explicit typing,
  sender-constraint and one-time-use verification, and fail-closed
  interpretation of conveyed authority;
- bounds every local token by the grant that seeded it and issues it
  sender-constrained and short-lived ({{validation-at-resource-as}},
  {{cross-domain-revocation}});
- fails redemption with the codes of {{error-responses}};
- where it offers token introspection for its local tokens, follows
  {{introspection-at-resource-as}}; and
- never creates or alters a Mission ({{model}}).

A Resource AS is not required to implement the base profile's Mission
Issuer role.

# IANA Considerations

This document has no IANA actions. The `mission` JWT claim, the
`mission` introspection response member, and the
`mission_resource_access` authorization details type it carries are
registered by the base profile {{I-D.draft-mcguinness-oauth-mission}}.

--- back

# End-to-End Example (Non-Normative)

This appendix continues the end-to-end example of the base profile's
appendix across a trust boundary: from the home domain
(`as.example.com`) into a partner domain, and then into the partner's
internal microservice call chain. It is illustrative and adds no
normative requirements. The final intra-domain hop shows one
deployment-local way to carry Mission context in a Transaction Token
{{I-D.draft-ietf-oauth-transaction-tokens}}. Identifiers and hash
values are illustrative and are not computed from the displayed JSON.

The chain crosses boundaries in two distinct ways, and seeing why is
the point of the example:

- The **Identity Assertion Authorization Grant (ID-JAG)** crosses
  *between* trust domains: from the home domain (`as.example.com`)
  to the partner domain (`ras.partner.example.com`).
- **Transaction Tokens** propagate *within* the partner trust domain:
  from the partner's Resource Server through its internal services.

The Mission is the durable anchor across both: `mission.id`,
`mission.issuer`, and `authority_hash` ride unchanged through every
hop. OAuth authority is audience-scoped by the Mission Issuer and
Resource AS; deployment-local transaction context then narrows the
operation for internal services. In this baseline walkthrough no hop
calls back to `mission.issuer` for state; each enforces from the
credential it holds. The OPTIONAL companion profiles layer on this
baseline, and the stages note where: Stage 4 gains a runtime
point-of-use check, and Stage 3 gains prompt cross-domain revocation
from Status or Signals.

Scenario: agent `s6BhdRkqt3`, acting for `alice`
(`user_3p2q8mN1a0kV7tR`), reconciles Q3 invoices in a partner ERP
under Mission `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`. Stage 0 (agent
identity) and Stage 1 (Mission creation at the home AS) are the base
profile's single-domain walkthrough, extended here in one way: the
Mission Intent's `resources` also names the partner ERP
`https://erp.partner.example.com`, so the approved Authority Set
additionally carries, for that resource, an `invoices.read` entry
(delegable to `ai_agent` actors at depth 1) and a
`journal-entries.write` entry capped at a `max_amount` of 500.00
USD. The
Mission was recorded `active` with `authority_hash`
`sha-256:Gv2nD9bM7sX1cF8gH0pVl3KvZ4mP5x0wQrR6tY2jE5kQ` and
`intent_hash`
`sha-256:Zb8mR3nX5pV4lE6sQqYwQ7p4LHnX9Md0LqJ6sZJ2xT5f` (illustrative;
this Mission's Intent and Authority Set extend the single-domain
walkthrough's, so its anchors differ from that example's). The partner ERP
is behind the Resource AS `ras.partner.example.com`, so the agent's
next step is a cross-domain projection rather than a home-domain
access token.

## Stage 2: Cross-Domain Projection via ID-JAG (Between Domains)

The agent needs the partner ERP, behind the Resource AS
`ras.partner.example.com`. It presents its Mission refresh token as
the `subject_token` of a token exchange requesting an ID-JAG
({{cross-domain-grant}}); the home AS resolves the Mission from that
grant, gates on Mission `active`, and mints a Mission-bound ID-JAG
audienced to that Resource AS, carrying the `mission` claim and the
audience-scoped authority for the ERP:

~~~ json
{
  "iss": "https://as.example.com",
  "aud": "https://ras.partner.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "client_id": "s6BhdRkqt3",
  "iat": 1793606400,
  "exp": 1793606700,
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 1,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["journal-entries.write"],
      "constraints": { "max_amount":
        { "amount": "500.00", "currency": "USD" } } }
  ],
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:Gv2nD9bM7sX1cF8gH0pVl3KvZ4mP5x0wQrR6tY2jE5kQ"
  }
}
~~~

The ID-JAG is short-lived (300 s), explicitly typed
(`oauth-id-jag+jwt` in its JWT header), and sender-constrained to the
agent. Its `exp` does not exceed the Mission's `expires_at`
({{cross-domain-grant}}).

## Stage 3: The Resource AS Issues a Local Access Token

`ras.partner.example.com` validates the ID-JAG
({{validation-at-resource-as}}): it
establishes issuer trust in `as.example.com`, verifies the signature,
checks that `aud` is itself, checks the expiry, and verifies the
sender-constraint proof. It then issues its own access token for the
ERP, preserving the `mission` claim unchanged and capping `exp` at the
ID-JAG's `exp`:

~~~ json
{
  "iss": "https://ras.partner.example.com",
  "aud": "https://erp.partner.example.com",
  "sub": "partner-user_7Kp4QnZ2vR9s",
  "client_id": "s6BhdRkqt3",
  "iat": 1793606430,
  "exp": 1793606690,
  "jti": "at_7Kp4QnZ2vR9sT1mX8b3N",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 1,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.partner.example.com",
      "actions": ["journal-entries.write"],
      "constraints": { "max_amount":
        { "amount": "500.00", "currency": "USD" } } }
  ],
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:Gv2nD9bM7sX1cF8gH0pVl3KvZ4mP5x0wQrR6tY2jE5kQ"
  }
}
~~~

The issuing `iss` is now the Resource AS, but `mission.issuer` remains
the home AS. The token's `exp` (1793606690) is below the ID-JAG's
(1793606700) and far below the Mission's `expires_at`. The Resource
AS-local `sub` is illustrative; its value is determined by the
subject-resolution rules of the ID-JAG and identity chaining profiles,
not by this document.

Revoking the Mission now stops new ID-JAGs, but the local token the
Resource AS minted stays usable until its `exp` (260 seconds), bounded
by the 300-second ID-JAG cap ({{cross-domain-revocation}}). Tighter
cross-domain revocation is opt-in, and the two companions do different
things: a Mission Status freshness lease shortens how long the partner
relies on stale state by forcing a pull or per-request re-check, while a
Mission Lifecycle Signal notifies the partner on a Mission transition so
it can react without polling.

The Resource AS holds only this audience's subset and cannot recompute
`authority_hash`. It records both sides of the derivation, the
consumed ID-JAG and the minted token ({{validation-at-resource-as}}),
so an auditor can identify the exact local token, tie it to the grant
it was minted from, and check its authority is a subset of that
grant.

## Stage 4: The Resource Server Enforces

The agent calls the ERP Resource Server (`erp.partner.example.com`)
with that token. The Resource Server validates the JWT and the `cnf`
binding and enforces the `authorization_details` whose `resource` it
serves, permitting `invoices.read` and `journal-entries.write` up to
a `max_amount` of 500.00 USD
({{I-D.draft-mcguinness-oauth-mission}}, Section
"Resource Server Enforcement"). It treats the
`mission` claim as an audit anchor; holding only this audience's
subset of the Authority Set, it does not recompute `authority_hash`.

This is stateless enforcement from the token alone.
`journal-entries.write` is a consequential write, so where the partner
deploys the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}) it also obtains a
point-of-use PDP permit against current Mission state before executing.
The baseline bounds the write only by token lifetime and
`max_amount`.

## Stage 5: Internal Call Context via Transaction Tokens

To serve the request, the ERP Resource Server calls internal services
inside the partner trust domain. Here it calls a ledger service for one
invoice. The Resource Server is the entry edge of that domain: after
it has validated the Mission-bound access token, it obtains a
short-lived Transaction Token for the internal call.

The following shows one illustrative way the Mission context could
ride in that Transaction Token. This is not a Mission-derived OAuth
access token, and this document does not define the Transaction Token
claim names or issuance rules. The important point is that the local
context can keep the Mission anchor while narrowing the internal
operation:

~~~ json
{
  "iss": "https://txn.partner.example.com",
  "aud": "https://ledger.partner.example.com",
  "sub": "partner-user_7Kp4QnZ2vR9s",
  "tid": "txn_5kQ9pX2vN7sR1tY8mZ3",
  "iat": 1793606460,
  "exp": 1793606520,
  "txn_authorization": {
    "source_resource": "https://erp.partner.example.com",
    "source_actions": ["invoices.read"],
    "internal_operation": "ledger.lookup_invoice",
    "constraints": { "invoice_id": "inv_2026Q3_1042" }
  },
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:Gv2nD9bM7sX1cF8gH0pVl3KvZ4mP5x0wQrR6tY2jE5kQ"
  }
}
~~~

The Transaction Token is intra-domain and the shortest-lived
credential in the chain (60 s). The holder has changed: the Resource
Server's workload, not the agent, possesses it. The local context has
narrowed again, to one ledger lookup for one invoice, while the
`mission` anchor is unchanged.

## Stage 6: The Internal Service Enforces

The ledger service receives the Transaction Token, validates it under
partner-domain policy, reads the Mission context and local transaction
authorization, and enforces them for the internal operation. Like
every consumer downstream of the home AS, it treats `authority_hash`
as an audit and correlation anchor it cannot recompute, and it makes
no call to `mission.issuer`.

## What Rode Through, and What Narrowed

| Hop (mechanism) | Mission anchor | Authority or context | Expiry |
|---|---|---|---|
| ID-JAG (between domains) | unchanged | ERP: read + write | 1793606700 |
| Resource AS token | unchanged | ERP: read + write | 1793606690 |
| Txn Token (within domain) | unchanged | one ledger lookup | 1793606520 |

The Mission anchor (`id`, `issuer`, `authority_hash`) is constant end
to end. OAuth authority is preserved or narrowed at the cross-domain
boundary, and local transaction context narrows the internal operation
inside the partner domain. The lifetime shrinks at every hop and never
exceeds the Mission's `expires_at`. The ID-JAG carried identity
*between* trust domains; the Transaction Token carried context
*within* one. The Mission bound both.
