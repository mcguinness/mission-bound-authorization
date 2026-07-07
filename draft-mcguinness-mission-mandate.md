---
title: "Mission Mandate"
abbrev: "Mission Mandate"
category: std

docname: draft-mcguinness-mission-mandate-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - mandate
 - evidence
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6838:
  RFC7515:
  RFC7519:
  RFC9901:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
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
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
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
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission-Bound Authorization for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
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

--- abstract

A Mission's committed facts (the approved task, the consented
authority, the principals, and the expiry) live on the Mission record
at its issuer, and a party outside the issuing domain cannot verify
what was approved short of a token-exchange hop or trust in the
issuer's own records. This document defines the Mission Mandate: a
signed, portable, independently verifiable statement of a Mission's
committed facts, minted by the Mission Issuer. A Mandate is evidence,
not a credential; presenting one authorizes nothing. It lets a
cross-domain verifier, an external rail deriving its own vertical
mandate, or an auditor verify what was approved from the artifact plus
a current-state check. An optional selective-disclosure presentation
limits what a given verifier sees.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile")
commits a Mission's facts at the approval event:
the approved Mission Intent and consented Authority Set under their
integrity anchors, the Subject and Approver, the agent `client_id`,
the derivation `policy_version`, and the `mission_expiry`. Those facts
live on the Mission record, held by the Mission Issuer; a derived
token or cross-domain grant projects only the `mission` claim and an
audience-scoped subset of the authority. A verifier that needs the
committed facts themselves (a partner domain, a payments network
deriving its own vertical mandate, an auditor in another organization)
has today only a token-exchange hop it may have no standing to
perform, or trust in records it cannot check.

This document defines the **Mission Mandate**: a signed JWT in which
the Mission Issuer states a Mission's committed facts. Any holder can
verify it against the issuer's published keys, with no exchange and no
callback for the facts themselves. Only currency is external: a
Mandate proves what was committed as of its `iat`, and a verifier that
relies on the Mission being active checks current state separately
({{state-at-issuance}}).

The family distinguishes three artifacts: the Mission is the
governed task object; a Mandate is portable evidence about the
Mission and its committed authority; a Mission Receipt is portable
evidence about an action taken under it
({{I-D.draft-mcguinness-mission-runtime}}).

A Mandate is evidence, not a credential. The issuance profile makes
`mission_id` an informational reference: presenting it authorizes
nothing ({{I-D.draft-mcguinness-oauth-mission}}, Section "Binding the
Mission to the Grant"). A Mandate extends that rule from the
identifier to the full committed record: presenting a Mandate
authorizes nothing either. It lets a verifier know what was approved;
authority remains the substrate's job
({{cross-domain-verification}}).

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. A deployment that never mints Mandates is
fully conformant to the issuance profile and its companions and is
unaffected by this document; the Mandate defines no authority surface
and places no requirement on deployments that do not claim it.

The Mandate is among the newest artifacts in the family. Its normative
dependencies are ratified: JWS, JWT, and SD-JWT are published
standards, and the issuance profile's committed record is its only
Mission input. The artifact itself is not yet exercised in deployment,
so an implementer validates the verification steps and failure
taxonomy against real cross-domain use before relying on them.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

This document uses the terms Mission, Mission record, Mission Intent,
Authority Set, integrity anchor, `mission` claim, `mission_id`,
Subject, Approver, and audit horizon as the issuance profile
{{I-D.draft-mcguinness-oauth-mission}} defines them. It additionally
uses:

Mission Issuer:
: The component that approved and holds the Mission, identified by the
  Mission's `issuer`: the OAuth Authorization Server under the
  issuance profile, a Mission Authority Server
  ({{I-D.draft-mcguinness-mission-authority-server}}) under the
  standalone binding, or an AAuth Person Server
  ({{I-D.draft-mcguinness-mission-aauth}}) under the AAuth binding.

Mission Mandate (Mandate):
: A signed, portable statement of a Mission's committed facts, minted
  by the Mission Issuer ({{mandate}}).

Mandate Issuer, Mandate Verifier:
: The conformance roles of {{conformance}}: the Mission Issuer acting
  as the minter of Mandates (always the Mission `issuer`), and a party
  that validates a Mandate ({{verification}}) and relies on it as
  evidence.

# Mission Substrate {#mission-substrate}

This profile is defined against the Mission model rather than against
OAuth 2.0 mechanics. It consumes these substrate primitives: the
Mission record's committed members and their immutability; the
integrity-anchor envelope with its encoded digest form; the lifecycle
state space with its only-`active`-permits rule; and the Mission
Issuer's published key material, resolvable by `kid`. The issuance
profile {{I-D.draft-mcguinness-oauth-mission}} is this version's
normative substrate, publishing keys through its Authorization Server
metadata `jwks_uri`; the Mission Authority Server
({{I-D.draft-mcguinness-mission-authority-server}}) is a standalone
binding of the same primitives with its own metadata `jwks_uri`; and
the AAuth binding ({{I-D.draft-mcguinness-mission-aauth}}) hosts the
same primitives at the AAuth Person Server, whose existing `jwks_uri`
is the published key material for its signed artifacts. A Mandate
minted under any of the three bindings is verified identically.

# Mission Mandate {#mandate}

A Mission Mandate is a JWT {{RFC7519}} signed as a JWS {{RFC7515}} by
the Mission Issuer, stating the committed facts of exactly one Mission
as of the Mandate's `iat`. The JWS Compact Serialization is the
Mandate's wire and evidence form.

## JOSE Header {#header}

The protected header MUST carry:

`typ`:
: REQUIRED. `mission-mandate+jwt`. Per {{RFC7515}} Section 4.1.9 the
  value omits the `application/` prefix of the media type registered
  in {{iana}}.

`alg`:
: REQUIRED. An asymmetric JWS algorithm. `none` MUST NOT be used.

`kid`:
: REQUIRED. A key identifier that resolves in the Mission Issuer's
  published key material ({{mission-substrate}}).

## Mandate Claims {#claims}

`iss`:
: REQUIRED. A string. The Mission `issuer`.

`iat`:
: REQUIRED. A NumericDate {{RFC7519}}. When the Mandate was minted.

`jti`:
: REQUIRED. A string. A unique identifier for this Mandate. It MUST
  NOT be reused by the issuer.

`mission`:
: REQUIRED. An object in the `mission` claim shape of the issuance
  profile, extended per its extensibility rules: `id`, `issuer`, and
  `authority_hash`, plus `intent_hash` committing the approved Mission
  Intent. All four members are REQUIRED here. `mission.issuer` MUST
  equal `iss`.

`subject`:
: REQUIRED. An object with `iss` and `sub`, the Mission record's
  `subject`.

`approver`:
: REQUIRED. An object with `iss` and `sub`, the Mission record's
  `approver`.

`client_id`:
: REQUIRED. A string. The Mission record's `client_id`.

`mission_expiry`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}} date-time, mirroring the
  Mission record's `expires_at`.

`policy_version`:
: REQUIRED. A string. The Mission record's `policy_version`.

`state_at_issuance`:
: REQUIRED. A string. The Mission's lifecycle state at `iat`
  ({{state-at-issuance}}).

`authority_set`:
: OPTIONAL. An array. The full consented Authority Set, exactly as
  recorded on the Mission record, preserving array order (the order is
  part of the canonical form under the issuance profile's
  canonicalization rules). When present, a verifier MAY recompute
  `authority_hash` over it ({{verification}}).

`mandate_exp`:
: OPTIONAL. A NumericDate. An expiry of the Mandate artifact itself,
  distinct from `mission_expiry`: after it, the Mandate MUST NOT be
  relied on as evidence. When absent, the Mandate is valid as evidence
  for the Mission's audit horizon, the retention term the issuance
  profile defines. It is deliberately not the standard `exp` claim,
  whose validity window would read as a credential lifetime.

The claim set is open in the manner of the `mission` claim: a
companion profile of the issuance profile MAY add members with
coordinated short names, and any other extension member MUST use a
collision-resistant name. A consumer MUST ignore members it does not
understand and MUST NOT derive authority from any member.

## State at Issuance {#state-at-issuance}

`state_at_issuance` records history, not currency. A Mandate proves
the Mission's committed facts as of `iat`; it MUST NOT be treated as
proof of the Mission's current state. The Mission may have transitioned
since minting, and nothing in the artifact would show it.

Current state comes from a state surface, not from the Mandate: the
Mission Status operation, keyed by the `mission.id` the Mandate
carries ({{I-D.draft-mcguinness-oauth-mission-status}}); a lifecycle
Signals stream ({{I-D.draft-mcguinness-oauth-mission-signals}}); or
token introspection where the verifier holds a Mission-bound token
({{I-D.draft-mcguinness-oauth-mission}}). A verifier whose reliance
requires the Mission to be active MUST obtain current state from a
source its deployment trusts, within a freshness bound its policy
sets; where the issuer advertises a propagation bound, the freshness
bound SHOULD be no looser
({{I-D.draft-mcguinness-oauth-mission-status}}). Reliance that needs
no active Mission, such as auditing a completed one, needs no check.

## Minting {#minting}

The Mission Issuer MAY mint a Mandate at any time within the Mission's
audit horizon, including after the Mission reaches a terminal state.
Each claim MUST be populated from the Mission record's committed
members; `state_at_issuance` MUST equal the Mission's lifecycle state
at `iat`. The issuer MUST NOT mint a Mandate whose facts diverge from
the record.

To whom Mandates are issued, and through what request surface, is
deployment policy; this document defines the artifact, not a delivery
protocol. An issuer SHOULD mint narrowly for the recipient's need, in
particular omitting `authority_set` when the recipient does not
recompute the anchor ({{privacy-considerations}}).

## Example {#example}

A decoded Mandate for the issuance profile's worked-example Mission.
The signature value is illustrative; all other segments are computed
from the displayed JSON.

Protected header:

~~~ json
{
  "typ": "mission-mandate+jwt",
  "alg": "ES256",
  "kid": "as-key-2026-q3"
}
~~~

Payload:

~~~ json
{
  "iss": "https://as.example.com",
  "iat": 1793607400,
  "jti": "mnd_4Xq7vB2kR9sT1mZ6pL3n",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
    "intent_hash":
      "sha-256:wQ7p4LHnX9Md0LqJ6sZJ8b8mZ3rN2xT5pV4lE6sQqYY"
  },
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approver": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "client_id": "s6BhdRkqt3",
  "mission_expiry": "2026-12-31T23:59:59Z",
  "policy_version": "deploy-policy:v17",
  "state_at_issuance": "active",
  "mandate_exp": 1805617000,
  "authority_set": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints":
        { "max_amount": { "amount": "500.00", "currency": "USD" } } }
  ]
}
~~~

The JWS segments are computed over the header and payload above,
serialized with no whitespace and members in the order displayed.
Line breaks within encoded segments are for display only.

Protected header, base64url:

~~~ text
eyJ0eXAiOiJtaXNzaW9uLW1hbmRhdGUrand0IiwiYWxnIjoiRVMyNTYiLCJraWQiOi
Jhcy1rZXktMjAyNi1xMyJ9
~~~

Payload, base64url:

~~~ text
eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiaWF0IjoxNzkzNjA3NDAwLC
JqdGkiOiJtbmRfNFhxN3ZCMmtSOXNUMW1aNnBMM24iLCJtaXNzaW9uIjp7ImlkIjoi
bXNuXzhSZlgyTHF2OVRxTXY0ejdzQTJiTjFrMFlwRWRIYzktIiwiaXNzdWVyIjoiaH
R0cHM6Ly9hcy5leGFtcGxlLmNvbSIsImF1dGhvcml0eV9oYXNoIjoic2hhLTI1Njps
M0t2WjRtUDV4MHdRclI2dFkybkQ5Yk03c1gxY0Y4Z0gydko0a0U1cE5RIiwiaW50ZW
50X2hhc2giOiJzaGEtMjU2OndRN3A0TEhuWDlNZDBMcUo2c1pKOGI4bVozck4yeFQ1
cFY0bEU2c1FxWVkifSwic3ViamVjdCI6eyJpc3MiOiJodHRwczovL2lkcC5leGFtcG
xlLmNvbSIsInN1YiI6InVzZXJfM3AycThtTjFhMGtWN3RSIn0sImFwcHJvdmVyIjp7
ImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUuY29tIiwic3ViIjoidXNlcl8zcDJxOG
1OMWEwa1Y3dFIifSwiY2xpZW50X2lkIjoiczZCaGRSa3F0MyIsIm1pc3Npb25fZXhw
aXJ5IjoiMjAyNi0xMi0zMVQyMzo1OTo1OVoiLCJwb2xpY3lfdmVyc2lvbiI6ImRlcG
xveS1wb2xpY3k6djE3Iiwic3RhdGVfYXRfaXNzdWFuY2UiOiJhY3RpdmUiLCJtYW5k
YXRlX2V4cCI6MTgwNTYxNzAwMCwiYXV0aG9yaXR5X3NldCI6W3sidHlwZSI6Im1pc3
Npb25fcmVzb3VyY2VfYWNjZXNzIiwicmVzb3VyY2UiOiJodHRwczovL2VycC5leGFt
cGxlLmNvbSIsImFjdGlvbnMiOlsiaW52b2ljZXMucmVhZCJdLCJkZWxlZ2F0aW9uIj
p7Im1heF9kZXB0aCI6MiwiYWxsb3dlZF9kZWxlZ2F0ZXMiOlt7InN1Yl9wcm9maWxl
IjoiYWlfYWdlbnQifV19fSx7InR5cGUiOiJtaXNzaW9uX3Jlc291cmNlX2FjY2Vzcy
IsInJlc291cmNlIjoiaHR0cHM6Ly9lcnAuZXhhbXBsZS5jb20iLCJhY3Rpb25zIjpb
ImpvdXJuYWwtZW50cmllcy53cml0ZSJdLCJjb25zdHJhaW50cyI6eyJtYXhfYW1vdW
50Ijp7ImFtb3VudCI6IjUwMC4wMCIsImN1cnJlbmN5IjoiVVNEIn19fV19
~~~

JWS signing input, the two segments joined by `.`:

~~~ text
eyJ0eXAiOiJtaXNzaW9uLW1hbmRhdGUrand0IiwiYWxnIjoiRVMyNTYiLCJraWQiOi
Jhcy1rZXktMjAyNi1xMyJ9.eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiw
iaWF0IjoxNzkzNjA3NDAwLCJqdGkiOiJtbmRfNFhxN3ZCMmtSOXNUMW1aNnBMM24iL
CJtaXNzaW9uIjp7ImlkIjoibXNuXzhSZlgyTHF2OVRxTXY0ejdzQTJiTjFrMFlwRWR
IYzktIiwiaXNzdWVyIjoiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbSIsImF1dGhvcml0e
V9oYXNoIjoic2hhLTI1NjpsM0t2WjRtUDV4MHdRclI2dFkybkQ5Yk03c1gxY0Y4Z0g
ydko0a0U1cE5RIiwiaW50ZW50X2hhc2giOiJzaGEtMjU2OndRN3A0TEhuWDlNZDBMc
Uo2c1pKOGI4bVozck4yeFQ1cFY0bEU2c1FxWVkifSwic3ViamVjdCI6eyJpc3MiOiJ
odHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXJfM3AycThtTjFhMGtWN
3RSIn0sImFwcHJvdmVyIjp7ImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUuY29tIiw
ic3ViIjoidXNlcl8zcDJxOG1OMWEwa1Y3dFIifSwiY2xpZW50X2lkIjoiczZCaGRSa
3F0MyIsIm1pc3Npb25fZXhwaXJ5IjoiMjAyNi0xMi0zMVQyMzo1OTo1OVoiLCJwb2x
pY3lfdmVyc2lvbiI6ImRlcGxveS1wb2xpY3k6djE3Iiwic3RhdGVfYXRfaXNzdWFuY
2UiOiJhY3RpdmUiLCJtYW5kYXRlX2V4cCI6MTgwNTYxNzAwMCwiYXV0aG9yaXR5X3N
ldCI6W3sidHlwZSI6Im1pc3Npb25fcmVzb3VyY2VfYWNjZXNzIiwicmVzb3VyY2UiO
iJodHRwczovL2VycC5leGFtcGxlLmNvbSIsImFjdGlvbnMiOlsiaW52b2ljZXMucmV
hZCJdLCJkZWxlZ2F0aW9uIjp7Im1heF9kZXB0aCI6MiwiYWxsb3dlZF9kZWxlZ2F0Z
XMiOlt7InN1Yl9wcm9maWxlIjoiYWlfYWdlbnQifV19fSx7InR5cGUiOiJtaXNzaW9
uX3Jlc291cmNlX2FjY2VzcyIsInJlc291cmNlIjoiaHR0cHM6Ly9lcnAuZXhhbXBsZ
S5jb20iLCJhY3Rpb25zIjpbImpvdXJuYWwtZW50cmllcy53cml0ZSJdLCJjb25zdHJ
haW50cyI6eyJtYXhfYW1vdW50Ijp7ImFtb3VudCI6IjUwMC4wMCIsImN1cnJlbmN5I
joiVVNEIn19fV19
~~~

The Mandate's JWS Compact Serialization appends `.` and the signature
over the signing input; the signature value depends on the issuer's
key and is not reproduced here.

# Selective Disclosure {#selective-disclosure}

This section is OPTIONAL. The plain JWS form of {{mandate}} is the
mandatory-to-implement baseline. An issuer MAY additionally mint a
Mandate as an SD-JWT {{RFC9901}}, so a holder passing the Mandate
onward discloses to a given verifier only what it needs; this
addresses the payload-disclosure concern the issuance profile's
privacy considerations record.

The disclosable elements are exactly: the `authority_set` entries,
each an array-element disclosure per {{RFC9901}}, and any free-text
Intent-derived extension member added under {{claims}}. All other
claims, in particular `iss`, `mission`, `subject`, and
`state_at_issuance`, MUST remain plaintext, so every presentation
still identifies the Mission, its issuer, its Subject, and its state
as of minting.

A verifier MUST NOT recompute `authority_hash` from a partial
presentation: the anchor is defined only over the full Authority Set
({{I-D.draft-mcguinness-oauth-mission}}), and an undisclosed
array-element digest in `authority_set` means the set is partial.

The SD-JWT form carries the protected header `typ`
`mission-mandate+sd-jwt` and the SD-JWT serialization of {{RFC9901}},
with no Key Binding JWT ({{non-goals}}). This document registers a
media type only for the plain JWS form ({{iana}}); the SD-JWT form is
identified by its `typ`.

# Mandate Verification {#verification}

A Mandate Verifier MUST perform these steps before relying on a
Mandate:

1. **Type.** Confirm the protected header `typ` is
   `mission-mandate+jwt` (or `mission-mandate+sd-jwt` for the SD-JWT
   form, then applying {{RFC9901}} processing). Reject any other
   value.
2. **Signature.** Resolve the REQUIRED `kid` in the Mission Issuer's
   published key material ({{mission-substrate}}) and verify the JWS
   signature. Confirm `mission.issuer` equals `iss`.
3. **Issuer trust.** Decide by local policy or configured trust
   anchors whether the `iss` value names a trusted issuer. A verifier MUST NOT
   trust an issuer merely because it appears inside a signed artifact,
   mirroring the issuer-trust rule of the cross-domain projection
   profile ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). A
   Mandate from an untrusted issuer proves nothing.
4. **Anchor recomputation.** When `authority_set` is present in full,
   the verifier MAY recompute `authority_hash` over it per the
   issuance profile's integrity-anchor rules (the
   `mission-authority-set` envelope with `iss` set to `mission.issuer`) and
   MUST reject the Mandate on mismatch. It MAY likewise verify
   `intent_hash` against a Mission Intent it holds.
5. **Freshness.** When reliance requires an active Mission, obtain
   current state within the freshness bound of
   {{state-at-issuance}}. `state_at_issuance` never substitutes.
6. **Hash agility.** Reject any integrity anchor whose algorithm
   prefix the verifier does not recognize, and never treat an
   unrecognized prefix as `sha-256`, per the issuance profile.

A verifier MUST additionally reject a Mandate whose required claims
are absent or malformed, and MUST NOT rely on a Mandate whose
`mandate_exp` has passed.

## Failure Taxonomy {#failures}

Verification failures fall into three classes, and a verifier MUST
distinguish them:

Invalid:
: The artifact fails as an artifact: signature, `typ`, required-claim
  structure, `iss`/`issuer` mismatch, anchor mismatch under step 4, or
  an unrecognized hash prefix under step 6. The Mandate MUST be
  rejected and MUST NOT be relied on for anything.

Unverifiable:
: Verification cannot complete: the issuer's key material is
  unreachable, the `kid` does not resolve, or no trust anchor covers
  the Mission's issuer. This is not evidence of tampering, mirroring the audit
  profile's classification ({{I-D.draft-mcguinness-mission-audit}});
  the verifier MUST NOT treat the Mandate as verified and MUST NOT
  treat the failure as proof the artifact is false.

Stale:
: The artifact verifies, but reliance requires an active Mission and
  no current state was obtained within the freshness bound (step 5).
  The verifier MUST NOT proceed with that reliance until it obtains
  current state.

# Mandate Use {#use}

## Cross-Domain Verification {#cross-domain-verification}

Mission Cross-Domain Projection for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission-cross-domain}} projects
authority: the cross-domain grant carries the `mission` claim and the
audience-scoped Authority Set entries to one Resource AS, which mints
local tokens from it. That projection remains the only path to local tokens; a
Mandate replaces nothing in it, is not redeemable, is not audienced,
and authorizes nothing.

What a Mandate adds is knowledge. A verifier that needed to know what
a Mission approved previously had only the token-exchange projection,
available only in the grant flow and only audience-scoped. With a
Mandate plus a current-state check ({{state-at-issuance}}), any
authorized recipient verifies the committed facts without standing in
the token path at all.

## Vertical Derivation {#vertical-derivation}

This subsection is informative. An external rail with its own mandate
artifact, for example a payments network's payment mandate, can mint
its vertical artifact from a Mission Mandate, recording the Mandate's
`mission.id` and `authority_hash` in its own artifact. The two then
share an audit anchor: activity on the rail joins back to the approved
Mission that motivated it. The derivation itself, what the rail's
artifact authorizes and how it is consented and revoked, is governed
by that rail, not by this document; the Mission Mandate contributes
committed facts and audit continuity, never authority.

## Mission Evidence {#audit-evidence}

A Mandate is registrable Mission evidence. For deployments running the
audit transparency profile ({{I-D.draft-mcguinness-mission-audit}}),
the Mandate slots into its evidence-type pattern with these values:

- **Canonical bytes**: the JWS Compact Serialization as issued, hashed
  as-is (an already-signed object is not re-canonicalized).
- **`payload-preimage-content-type`**: `application/mission-mandate+jwt`
  ({{iana}}).
- **Authoritative producer**: the Mission `issuer`; the registering
  `iss` MUST equal it, which holds by construction since a Mandate's
  `iss` is `mission.issuer` ({{conformance}}).

Registration gives a Mandate an independent existence proof, which
bounds a later issuer key compromise ({{security-considerations}}).

# Non-Goals and Deferred Work {#non-goals}

- A Mandate is not a credential and is never authority-bearing;
  anything authority-bearing belongs to the substrate's issuance
  surfaces.
- No key binding. A Mandate binds no holder key, and its presentation
  proves nothing about the presenter. A holder-bound Mandate, a
  `cnf`-style confirmation with key-bound presentation, is named
  future work.
- No revocation of the Mandate artifact. State currency is the status
  surface's job ({{state-at-issuance}}); `mandate_exp` bounds the
  artifact's evidence lifetime, and no revocation list is defined.
- No multi-Mission bundling. A Mandate states exactly one Mission.

# Conformance {#conformance}

A **Mandate Issuer** MUST:

- be the Mission `issuer` and set `iss` to it;
- mint only over an existing Mission record, populating every claim
  from its committed members ({{minting}});
- set `state_at_issuance` to the Mission's lifecycle state at `iat`;
- when including `authority_set`, include the consented Authority Set
  exactly as recorded, in recorded order;
- sign with a key resolvable by `kid` in its published key material,
  with the protected `typ` of {{header}}; and
- issue `jti` values it never reuses.

A **Mandate Verifier** MUST:

- perform steps 1 through 6 of {{verification}} before reliance;
- classify failures per {{failures}} and treat only the invalid class
  as evidence against the artifact;
- obtain current state within its freshness bound whenever reliance
  requires an active Mission; and
- never grant access, mint credentials, or widen authority on
  presentation of a Mandate ({{security-considerations}}).

# Security Considerations {#security-considerations}

## Mandate-as-Credential Misuse

The central risk is the mandate-as-credential anti-pattern: granting
access because a presenter holds a well-signed Mandate. A Mandate
binds no presenter, proves no possession, and commits no current
state; accepting it as a credential turns a freely copyable audit
artifact into a bearer token. A verifier MUST NOT grant access, mint a
credential, or widen any authority on presentation of a Mandate.
Authority flows only through the substrate's issuance surfaces
({{I-D.draft-mcguinness-oauth-mission}}).

## Stale-State Reliance

A verified Mandate over a revoked Mission is still a verified Mandate:
treating `state_at_issuance` as current state extends reliance past
revocation with no artifact-level signal. The freshness rule of
{{state-at-issuance}} is the control; the stale class of {{failures}}
makes the omission a named failure rather than a silent acceptance.

## Issuer Key Compromise

A party holding the Mission Issuer's signing key can mint Mandates for
Missions that never existed, until the key is rotated out of the
published set. Verifiers bound this by resolving `kid` against live
key material; audit registration ({{audit-evidence}}) narrows it
further, since a genuine Mandate has an independent, timestamped
existence proof and a forged one either goes unregistered or leaves a
permanent, attributable trace. A deployment whose Mandates feed
high-consequence decisions SHOULD register them.

## Confusion with the Cross-Domain Grant

Both artifacts are issuer-signed JWTs carrying Mission facts. The
cross-domain grant
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}) is redeemable,
audienced, sender-constrained, and single-use; the Mandate is none of
these. The distinct protected `typ`
is the mechanical separator: a token endpoint MUST NOT accept a
`mission-mandate+jwt` as any grant or assertion, and a Mandate
Verifier rejects a grant presented as a Mandate at step 1 of
{{verification}}.

# Privacy Considerations {#privacy-considerations}

## Task-Data Propagation

A Mandate carries what the Mission record committed: principals, task
anchors, expiry, and optionally the full Authority Set with its
business bounds. It travels to parties that would otherwise never hold
Mission data, and unlike a token it has no audience to scope it. An
issuer SHOULD apply the restraint the issuance profile applies at a
domain boundary: omit `authority_set` unless the recipient needs
anchor recomputation, prefer the selective-disclosure form
({{selective-disclosure}}) where a holder re-presents the Mandate
onward, and avoid Intent-derived free-text extension members by
default.

The Mandate also extends the correlation surface the issuance
profile's privacy considerations describe: it carries `mission.id` and
`authority_hash` to parties outside the token path, and any two
holders can correlate on them. That is the artifact's purpose, an
auditable shared anchor; a deployment SHOULD weigh it before minting
Mandates for recipients that do not need durable correlation.

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register one media type per {{RFC6838}}.

### application/mission-mandate+jwt

- Type name: application
- Subtype name: mission-mandate+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  issuers, verifiers, and audit deployments
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

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work and
makes a Mission's committed facts portable, verifiable evidence.
