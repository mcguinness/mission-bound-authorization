---
title: "Mission Offline Attenuation for OAuth 2.0"
abbrev: "OAuth Mission Offline Attenuation"
category: std

docname: draft-mcguinness-oauth-mission-attenuation-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - delegation
 - attenuation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC8414:
  RFC8693:
  RFC9396:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-runtime-latest

informative:
  RFC7638:
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-cross-domain-latest
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-harness-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 derives delegated authority
through the Authorization Server: each narrowing is a derivation at
the issuer. For deep sub-agent fan-out, the common agent topology, that
puts the Authorization Server in the hot path as a latency and
availability dependency. This document defines an optional Mission
Offline Attenuation profile. It profiles Attenuating Agent Tokens so a
Mission-bound token holder can mint a narrower child token offline, with
no Authorization Server round-trip, carrying the same `mission` claim.
The Mission Issuer derives the attenuation root from the Mission's
approved Authority Set under a normative mapping; the narrowing is
verifiable from the carried token chain, and the Mission kill switch is
preserved because consumption is gated by the runtime enforcement
layer, which re-checks current Mission state on every presentation of a
token in the chain; a revoked Mission stops the whole chain even though
no issuer minted the children. Offline attenuation is offered
alongside, not instead of, Authorization-Server-mediated delegation.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") narrows
authority through the Authorization Server: a delegated or narrowed
token is derived at the issuer, and cross-domain projection is a Token
Exchange ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). For an
agent that fans out to many
sub-agents, each needing a slice of the Mission's authority, that makes
the Authorization Server a per-delegation latency and availability
dependency on the execution hot path.

This document removes the issuer from that path for narrowing. It
profiles Attenuating Agent Tokens
{{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}} (the "attenuation
substrate"), in which a token holder mints a narrower child token
offline by signing it with the key the parent token's `cnf` binds, and
the child commits to its parent by hash. A Mission-bound token can be an
attenuation-substrate root; its holder then derives narrower children
for sub-agents with no Authorization Server contact.

Three things make this safe within the Mission model, and this document
requires all three ({{mission-binding-check}}, {{kill-switch}}): the
child carries the parent chain, with audience and expiry bounded per
hop, so a consumer verifies the narrowing from the tokens it holds;
the Mission kill switch is preserved because consumption is gated by the
runtime enforcement layer re-checking current Mission state, not by the
issuer (the attenuation substrate defines no revocation of its own); and
`authority_hash` rides the chain as a lineage anchor, not as the child's
own authority commitment.

# Status: An EXPERIMENTAL Extension {#optional-status}

This document is OPTIONAL and **experimental**: adopt it for
evaluation, not as a stable interface. A deployment that narrows
authority only
through the Authorization Server is fully conformant to the issuance
profile and is unaffected by this document. It places no new requirement
on the issuance profile, and it does not replace
Authorization-Server-mediated delegation; a deployment offers offline
attenuation in addition, for the fan-out paths where issuer round-trips
are the bottleneck.

A deployment claims this profile only when it issues or accepts
Mission-bound attenuation-substrate tokens. Because the Mission kill
switch reaches offline-minted tokens only through per-presentation
runtime state checks ({{kill-switch}}), this profile is available only
to deployments running the runtime enforcement profile
({{I-D.draft-mcguinness-mission-runtime}}); on such a deployment the
offline mint saves issuer round-trips, not enforcement checks. Weigh
that saving against the chain-verification surface before adopting.

This profile also depends normatively on the Attenuating Agent Tokens
substrate ({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}), an
in-progress Internet-Draft whose details may change; an implementation
tracks that work as it evolves. Authorization-Server-mediated
delegation, which depends only on ratified OAuth, is the stable path;
a deployment uses offline attenuation where its substrate dependency is
acceptable and treats the interface as tracking the substrate.

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and the
attenuation substrate, and is not implementable alone. It reuses the
issuance profile's Mission, `mission` claim, Authority Set, subset rule,
and lifecycle, and the attenuation substrate's token format, offline
derivation, chain linkage, capability monotonicity, and proof-of-
possession. It uses Agent (Client), Mission Issuer, Mission, and derived
token as the issuance profile defines them, and root token, derived
token, `par_hash`, `del_depth`, and capability monotonicity as the
attenuation substrate defines them.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Mission-bound attenuation root:
: An attenuation-substrate root token, issued by the Mission Issuer,
  that carries the `mission` claim and whose authority is bounded by the
  Mission's Authority Set.

Offline attenuation:
: A token holder minting a narrower child of a Mission-bound attenuation
  token, signed with the parent's confirmation key, without contacting
  the Mission Issuer.

Attenuating Holder:
: The holder of a Mission-bound attenuation token, in its role of
  minting narrower children offline under this profile.

In this profile a child is a token: a narrower token minted under one
Mission, not a new Mission. The Mission Child Delegation profile
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) defines Child
Missions, which are new Missions with their own `mission_id`; the two
are distinct.

# Mission-Bound Attenuation Roots {#root}

A Mission-bound attenuation root is a Mission-bound token
({{I-D.draft-mcguinness-oauth-mission}}) whose carried authority is an
`attenuating_agent_token` authorization detail
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}, {{RFC9396}}).
The Mission Issuer derives that authority from the Mission's Authority
Set by the mapping of {{root-mapping}}. The root carries the `mission`
claim (`id`, `issuer`, `authority_hash`) and the holder's confirmation
key, as both profiles require. It MUST carry `aud` per the issuance
profile's token rules ({{I-D.draft-mcguinness-oauth-mission}}),
identifying the Resource Server(s) authorized to consume its authority.

A Mission-bound attenuation root is one shape of Mission-bound token. A
deployment MAY also issue ordinary `mission_resource_access` tokens for
the same Mission; the two are derived from the same Authority Set and
gated on the same Mission state.

## Deriving the Root from the Authority Set {#root-mapping}

The Mission Issuer derives the root's `attenuating_agent_token`
authority from `mission_resource_access` entries
({{I-D.draft-mcguinness-oauth-mission}}) by this mapping:

- each tool identifier in the root maps to an `actions` value at the
  entry's `resource`; the root's tool set MUST be a subset of that
  entry's `actions`;
- a tool's argument constraints map to the entry's `constraints`,
  compared under the specification-defined Common Constraint value-space rules
  ({{I-D.draft-mcguinness-oauth-mission}}) for specification-defined constraint
  names and under the deployment's rules otherwise; a root argument
  constraint MUST be no broader than the mapped entry `constraints`; and
- the root MUST derive only from entries whose `delegation` permits the
  intended holder ({{I-D.draft-mcguinness-oauth-mission}}).

The root's authority MUST be within the Mission's approved authority
under this mapping and the issuance profile's subset rule. An auditor
verifies that a root is within the Authority Set by applying this same
mapping in reverse: each root tool and argument constraint traces to a
permitted entry action and constraint.

# Requesting a Root and Discovery {#request-discovery}

A Mission Issuer that supports this profile advertises it in its
authorization server metadata {{RFC8414}}:

`mission_attenuation_supported`:
: OPTIONAL boolean. When `true`, the Mission Issuer issues Mission-bound
  attenuation roots ({{root}}) and derives their authority from the
  Mission's Authority Set ({{root-mapping}}).

A client requests a Mission-bound attenuation root at the token endpoint.
The attenuation substrate defines no OAuth Token Exchange {{RFC8693}}
requested-token-type identifier for asking for a root; a substrate root
is requested by carrying an `attenuating_agent_token` authorization
detail and the holder's confirmation key
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}). To ask the
Mission Issuer to bind such a root to the Mission and derive it from the
Authority Set, a client includes the token-request parameter:

`mission_attenuation_root`:
: OPTIONAL boolean. When `true` on a Mission-bound token request, the
  Mission Issuer issues the token as a Mission-bound attenuation root
  ({{root}}) rather than an ordinary `mission_resource_access` token.

# Offline Attenuation {#attenuation}

The holder of a Mission-bound attenuation token mints a narrower child
offline, by the attenuation substrate's derivation: it selects a
narrower tool and constraint set, increments `del_depth`, signs with the
key the parent's `cnf` binds, and sets `par_hash` to the parent's
commitment. No Mission Issuer contact occurs.

`par_hash` commits to the exact parent token bytes, per the attenuation
substrate's cryptographic linkage rule
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}): its value is
the base64url encoding, without padding, of the SHA-256 digest of the
parent token's JWS Signing Input.

The child's `aud` MUST equal its parent's `aud` or be a subset of it,
and the child's `exp` MUST NOT exceed its parent's `exp`. Because the
Mission Issuer caps the root's `exp` at the Mission's `expires_at`
({{I-D.draft-mcguinness-oauth-mission}}), the per-hop `exp` rule bounds
the whole chain transitively: no descendant outlives the root, hence
none outlives the Mission.

The `mission` claim rides the chain unchanged: every token in the chain
carries the same `id`, `issuer`, and `authority_hash` as the root. The
child's narrowing is governed entirely by the attenuation substrate's
capability monotonicity, which is the subset relation a consumer checks;
because the child carries the parent chain, a consumer holding only the
leaf and its chain can verify that the leaf is a subset of the root,
without holding the Mission's full Authority Set.

`authority_hash` on a derived token is a lineage anchor, not the child's
authority commitment. The child's authority is its own carried
constraints, narrower than the root's; `authority_hash` still commits
the root Mission's Authority Set, so it links the chain to the approved
Mission for audit and remains an audit anchor a consumer cannot recompute
from the narrowed leaf, exactly as for any narrowed Mission-bound token
({{I-D.draft-mcguinness-oauth-mission}}).

# Verifying the Mission Binding {#mission-binding-check}

A consumer verifies the chain linkage, capability monotonicity, depth,
and proof-of-possession under the attenuation substrate
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}). This profile
adds checks on the `mission` claim, which the substrate does not define
because it has no concept of the Mission binding. In addition to the
substrate's chain verification, a consumer MUST:

- reject the chain unless every token in it carries a `mission` claim
  and every claim carries the same `id`, `issuer`, and `authority_hash`
  as the root. A child cannot re-bind to a different Mission or change
  the lineage anchor; a link whose `mission` claim differs from the
  root's, or that omits it, MUST cause the whole chain to be refused,
  not treated as a narrower grant; and
- treat a chain whose root carries no `mission` claim as outside this
  profile: it is an ordinary attenuation chain with no Mission binding,
  and a consumer MUST NOT apply the Mission-state kill switch
  ({{kill-switch}}) to it or report it as Mission-bound;
- reject the chain if any child's `aud` is not equal to, or a subset of,
  its parent's `aud` ({{attenuation}}); and
- reject the chain if any child's `exp` exceeds its parent's `exp`
  ({{attenuation}}).

These checks fail safe: a chain that does not present a single, unchanged
Mission binding, an audience within its parent's, and an expiry within
its parent's is refused, not evaluated against a guessed Mission.

# The Kill Switch Requires Runtime Enforcement {#kill-switch}

The attenuation substrate defines no revocation: a child, once minted,
is valid by its signature chain until its `exp`, and no issuer can reach
it. The Mission kill switch is therefore not automatic for offline
children; it is delivered only by the runtime enforcement layer.

A consumer of a Mission-bound attenuation chain MUST evaluate it under
the runtime enforcement profile
({{I-D.draft-mcguinness-mission-runtime}}): on every presentation
of a token in the chain, regardless of action class, it MUST establish
that the chain's Mission is `active`, within the deployment's declared
freshness bound, from a Mission state source, in addition to verifying
the attenuation chain and the proof-of-possession. If the consumer
cannot establish the Mission as `active` within the bound, including when
the state source is unreachable, it MUST refuse, as the runtime profile
fails closed on unestablished state
({{I-D.draft-mcguinness-mission-runtime}}). A cached chain does
not bypass this: a chain held in a harness cache is still re-checked
against current Mission state on every presentation, since the cache is
never evidence of continuing authority
({{I-D.draft-mcguinness-mission-harness}}). A revoked or expired
Mission MUST cause refusal of every token in the chain, regardless of
the children's own `exp`. A deployment MUST NOT accept Mission-bound
attenuation tokens on a path that does not enforce current Mission
state: without that check the offline chain is ungoverned bearer
authority until it ages out, which defeats the purpose of binding it to
a Mission. Offline attenuation is thus a capability for deployments
running the runtime enforcement profile
({{I-D.draft-mcguinness-mission-runtime}}); it is not available to
a deployment that relies on token lifetime alone.

# Relationship to Other Delegation {#relationship-delegation}

Offline attenuation sits beside two other narrowing mechanisms:
Authorization-Server-mediated delegation (the issuance profile's `act`
chain and Token Exchange), which narrows at the issuer, online, so the
issuer observes each delegation; and Child Mission Delegation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), which creates
a separate Child Mission with its own `mission_id`, lifecycle, and
approval. The Mission Child Delegation profile sets out how the three
differ. Offline attenuation creates no new Mission: every child rides
the same `mission` claim and dies with the same Mission. Use offline
attenuation when a sub-agent needs a narrower token under the same
Mission, fast, at fan-out scale; use a Child Mission when it needs its
own durable, separately revocable Mission.

# Worked Example {#example}

An orchestrator agent (`s6BhdRkqt3`), acting for `alice` under Mission
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` to reconcile Q3 invoices, holds a
Mission-bound attenuation root. Its authority covers reading Q3 invoices
and posting journal entries under $500; `del_max_depth` allows two
levels of offline narrowing. Decoded root token:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "client_id": "s6BhdRkqt3",
  "aud": "https://erp.example.com",
  "iat": 1797840000,
  "exp": 1797840300,
  "jti": "aat_root_7M2R4kP9sT1x",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "del_depth": 0,
  "del_max_depth": 2,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "authorization_details": [
    { "type": "attenuating_agent_token",
      "tools": {
        "erp.invoices.read": {
          "period": { "constraint_type": "exact", "value": "2026-Q3" } },
        "erp.journal-entries.write": {
          "amount_usd": { "constraint_type": "range", "max": 500 } } } }
  ]
}
~~~

The root's `erp.invoices.read` and `erp.journal-entries.write` tools map
to the `invoices.read` and `journal-entries.write` actions on
`https://erp.example.com`, and the `amount_usd` argument maps to the
Mission Common Constraint `max_amount` ({{root-mapping}}); its `aud`
names that Resource Server.

The orchestrator spawns a read-only extraction sub-agent and, with no
Authorization Server contact, mints a child that drops the write tool
and keeps only the Q3 invoice read. It signs the child with the key the
root's `cnf` binds, sets `iss` to that key's thumbprint, increments
`del_depth`, and commits the parent by `par_hash`:

~~~ json
{
  "iss":
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
  "sub": "user_3p2q8mN1a0kV7tR",
  "aud": "https://erp.example.com",
  "iat": 1797840030,
  "exp": 1797840240,
  "jti": "aat_child_2Yt7Qv9Lq",
  "cnf": { "jkt": "kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t" },
  "par_hash": "9XbVt2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQ",
  "del_depth": 1,
  "del_max_depth": 2,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "authorization_details": [
    { "type": "attenuating_agent_token",
      "tools": {
        "erp.invoices.read": {
          "period": { "constraint_type": "exact", "value": "2026-Q3" } } } }
  ]
}
~~~

The `mission` claim is unchanged, the child's `aud` equals the root's,
its `exp` (1797840240) ends before the root's (1797840300), within the
per-hop bound, the write tool is gone, and the read constraint is
unchanged (a permitted narrowing). The child's `cnf.jkt` is the JWK
thumbprint {{RFC7638}} of the delegate extractor's own key, which its
per-invocation proof-of-possession must match. The child's `par_hash`
derives as {{attenuation}} states, the base64url SHA-256 digest, without
padding, of the root token's JWS Signing Input; the value shown is
illustrative, since the example gives the root's decoded claims rather
than its serialized bytes. To read an invoice
the extractor presents the chain `[root, child]` and a per-invocation
proof-of-possession to the gateway. The gateway verifies the chain (the
child's signature under the root's `cnf` key, `par_hash`, the depth,
capability monotonicity, and the `aud` and `exp` bounds), verifies the
proof-of-possession under the child's `cnf` key, and, because this is
Mission-bound, checks on this presentation that
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` is `active` within the
deployment's declared freshness bound ({{kill-switch}}). A write attempt
by the extractor fails on capability monotonicity:
`erp.journal-entries.write` is not in its tools. And when `alice` revokes
the Mission, the next presentation fails the state check and the whole
chain stops, even though no issuer ever saw the child and the child's
`exp` has not passed.

For contrast, suppose the extractor presents a chain whose child
carries `"exp": 1797840360`, sixty seconds past the root's. The
per-hop bound check ({{mission-binding-check}}) fails before any tool
or Mission-state evaluation: a child that outlives its parent breaks
the chain's transitive expiry bound, so the gateway refuses the whole
chain. A chain whose child carried a `mission` claim differing from the
root's is refused the same way, as a re-bound chain, not read as a
narrower grant.

# Conformance {#conformance}

A Mission Issuer conforming to this profile MUST bound a Mission-bound
attenuation root by the Mission's Authority Set ({{root-mapping}}) and
carry the `mission` claim, the confirmation key, and `aud` on it.

An Attenuating Holder conforming to this profile MUST carry the
`mission` claim unchanged into every child it mints, MUST only narrow
authority and never broaden it, MUST keep each child's `aud` within its
parent's and its `exp` within its parent's, and MUST increment the depth
member the attenuation substrate defines (`del_depth`,
{{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).

A consumer conforming to this profile MUST verify the attenuation chain
and proof-of-possession per the attenuation substrate, MUST verify that
the `mission` claim is unchanged across the chain and that each child's
`aud` and `exp` are within its parent's ({{mission-binding-check}}), and
MUST enforce current Mission state per {{kill-switch}}. A deployment MUST
NOT claim this profile on a path that does not enforce Mission state.

# Security Considerations {#security-considerations}

The security considerations of the issuance profile, the runtime
profile, and the attenuation substrate apply. This profile adds:

- No native revocation. Offline children cannot be recalled by the
  issuer; the kill switch is the runtime Mission-state check
  ({{kill-switch}}), which is mandatory for this profile. A deployment
  that cannot enforce Mission state MUST NOT accept these tokens.
- Stale authority. A child's `exp` bounds its life absent a state check;
  a deployment SHOULD keep child lifetimes short so that even a path
  with a coarse staleness bound limits exposure.
- Holder-key compromise. A compromised holder can mint any narrower
  child within its authority, offline and unobserved. The bound is that
  it can only narrow, never broaden (capability monotonicity), and that
  the runtime layer still gates every action against the Mission; the
  compromise does not widen authority or evade revocation.
- Depth and fan-out. `del_max_depth` bounds chain depth; a deployment
  SHOULD set it. Because offline minting is unobserved by the issuer,
  breadth is bounded at consumption, not at issuance: PEPs SHOULD meter
  the distinct leaf `jti` and `cnf` values they see per Mission and
  alert or refuse beyond a deployment-set bound, and issuers SHOULD keep
  root lifetimes short.
- Per-branch revocation. The only kill switch is whole-Mission: revoking
  the Mission stops the entire chain, but this profile provides no way to
  revoke a single branch or leaf without revoking the Mission. Per-branch
  revocation is deferred work. As a deployment mitigation, a PEP MAY
  maintain a denylist keyed by leaf `jti` or `cnf` to refuse specific
  leaves.
- Audit. Because the issuer does not observe offline derivations, the
  consuming enforcement points are the only place a derivation is seen;
  runtime enforcement evidence
  ({{I-D.draft-mcguinness-mission-runtime}}) is the audit record
  for offline-attenuated actions.

# Privacy Considerations {#privacy-considerations}

The `mission` claim (`id`, `issuer`, `authority_hash`) rides every token
in an attenuation chain unchanged ({{attenuation}}), so every consumer
of any child sees the same durable Mission correlator and lineage
anchor. The chain is therefore a correlation surface across the
sub-agents and resources it reaches: two consumers that compare the
Mission identifiers they were shown can tell the tokens belong to one
Mission. This profile does not narrow that correlation; the
single-canonical-`mission` cross-audience linkability the issuance
profile acknowledges ({{I-D.draft-mcguinness-oauth-mission}}) applies to
offline children as well, and unlinkable or per-audience presentation of
Mission-bound authority is out of scope and deferred.

Because the child carries the parent chain, every consumer of a leaf
sees each ancestor's full authority, not only the leaf's narrowed slice.
A leaf presented to one Resource Server therefore discloses the broader
authority of every token above it. To minimize that disclosure, a
deployment SHOULD mint narrowly scoped, per-subtree roots rather than one
broad root fanned out across unrelated subtrees, so a leaf reveals only
the ancestors of its own subtree.

Offline minting is unobserved by the Mission Issuer, so which children
were minted and to whom is visible only at the consuming enforcement
points, not in the issuer's records. A deployment SHOULD treat the
runtime enforcement evidence those points produce
({{I-D.draft-mcguinness-mission-runtime}}) as the privacy-relevant
record of offline derivations and protect it accordingly.

# IANA Considerations {#iana}

A Mission-bound attenuation root carries the `mission` claim, which the
issuance profile registers as an open object, and the
`attenuating_agent_token` authorization detail, which the attenuation
substrate registers; this profile combines them by reference and defines
no new claim or registry. It registers one metadata member and one
request parameter.

This document registers one member in the existing "OAuth Authorization
Server Metadata" registry {{RFC8414}}: Change Controller IETF; Reference
this document, {{request-discovery}}.

- `mission_attenuation_supported`

This document registers one parameter in the "OAuth Parameters" registry:
Parameter Usage Location token request; Change Controller IETF; Reference
this document, {{request-discovery}}.

- `mission_attenuation_root`

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles Attenuating Agent Tokens for offline, holder-derived
narrowing of Mission authority.
