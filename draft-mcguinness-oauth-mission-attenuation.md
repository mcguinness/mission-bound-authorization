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
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-attenuation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9396:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest

informative:
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Child Mission Delegation for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-child-delegation-latest
  I-D.draft-mcguinness-oauth-mission-harness:
    title: "Mission-Aware Agent Harnesses for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-harness-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 derives delegated authority
through the Authorization Server: each narrowing is a Token Exchange at
the issuer. For deep sub-agent fan-out, the common agent topology, that
puts the Authorization Server in the hot path as a latency and
availability dependency. This document defines an OPTIONAL Mission
Offline Attenuation profile. It profiles Attenuating Agent Tokens so a
Mission-bound token holder can mint a narrower child token offline, with
no Authorization Server round-trip, carrying the same `mission` claim.
The narrowing is verifiable from the carried token chain, and the
Mission kill switch is preserved because consumption is gated by the
runtime enforcement layer, which re-checks Mission state at use; a
revoked Mission stops the whole chain even though no issuer minted the
children. Offline attenuation is offered alongside, not instead of,
Authorization-Server-mediated delegation.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} (the
"issuance profile") narrows authority through the Authorization Server:
a delegated or narrowed token is derived at the issuer, and cross-domain
projection is a Token Exchange. For an agent that fans out to many
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
requires all three ({{kill-switch}}): the child carries the parent
chain, so a consumer verifies the narrowing from the tokens it holds;
the Mission kill switch is preserved because consumption is gated by the
runtime enforcement layer re-checking current Mission state, not by the
issuer (the attenuation substrate defines no revocation of its own); and
`authority_hash` rides the chain as a lineage anchor, not as the child's
own authority commitment.

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. A deployment that narrows authority only
through the Authorization Server is fully conformant to the issuance
profile and is unaffected by this document. It places no new requirement
on the issuance profile, and it does not replace
Authorization-Server-mediated delegation; a deployment offers offline
attenuation in addition, for the fan-out paths where issuer round-trips
are the bottleneck.

A deployment claims this profile only when it issues or accepts
Mission-bound attenuation-substrate tokens.

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

# Mission-Bound Attenuation Roots {#root}

A Mission-bound attenuation root is a Mission-bound token
({{I-D.draft-mcguinness-oauth-mission}}) whose carried authority is an
`attenuating_agent_token` authorization detail
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}, {{RFC9396}}).
The Mission Issuer derives that authority from the Mission's Authority
Set: the root's tool and argument constraints MUST be within the
Mission's approved authority under the issuance profile's subset rule.
The root carries the `mission` claim (`id`, `origin`, `authority_hash`)
and the holder's confirmation key, as both profiles require.

A Mission-bound attenuation root is one shape of Mission-bound token. A
deployment MAY also issue ordinary `mission_resource_access` tokens for
the same Mission; the two are derived from the same Authority Set and
gated on the same Mission state.

# Offline Attenuation {#attenuation}

The holder of a Mission-bound attenuation token mints a narrower child
offline, by the attenuation substrate's derivation: it selects a
narrower tool and constraint set, increments `del_depth`, signs with the
key the parent's `cnf` binds, and sets `par_hash` to the parent's
commitment. No Mission Issuer contact occurs.

The `mission` claim rides the chain unchanged: every token in the chain
carries the same `id`, `origin`, and `authority_hash` as the root. The
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
  and every claim carries the same `id`, `origin`, and `authority_hash`
  as the root. A child cannot re-bind to a different Mission or change
  the lineage anchor; a link whose `mission` claim differs from the
  root's, or that omits it, MUST cause the whole chain to be refused,
  not treated as a narrower grant; and
- treat a chain whose root carries no `mission` claim as outside this
  profile: it is an ordinary attenuation chain with no Mission binding,
  and a consumer MUST NOT apply the Mission-state kill switch
  ({{kill-switch}}) to it or report it as Mission-bound.

These checks fail safe: a chain that does not present a single, unchanged
Mission binding is refused, not evaluated against a guessed Mission.

# The Kill Switch Requires Runtime Enforcement {#kill-switch}

The attenuation substrate defines no revocation: a child, once minted,
is valid by its signature chain until its `exp`, and no issuer can reach
it. The Mission kill switch is therefore not automatic for offline
children; it is delivered only by the runtime enforcement layer.

A consumer of a Mission-bound attenuation chain MUST evaluate it under
the runtime enforcement profile
({{I-D.draft-mcguinness-oauth-mission-runtime}}): before each
consequential action it MUST establish that the chain's Mission is
`active`, within the deployment's staleness bound, from a Mission state
source, in addition to verifying the attenuation chain and the
proof-of-possession. If the consumer cannot establish the Mission as
`active` within the bound, including when the state source is
unreachable, it MUST refuse the action, as the runtime profile fails
closed on unestablished state
({{I-D.draft-mcguinness-oauth-mission-runtime}}). A cached chain does
not bypass this: a chain held in a harness cache is still re-checked
against current Mission state before each consequential action, since
the cache is never evidence of continuing authority
({{I-D.draft-mcguinness-oauth-mission-harness}}). A revoked or expired
Mission MUST cause refusal of every token in the chain, regardless of
the children's own `exp`. A
deployment MUST NOT accept Mission-bound attenuation tokens on a path
that does not enforce current Mission state: without that check the
offline chain is ungoverned bearer authority until it ages out, which
defeats the purpose of binding it to a Mission. Offline attenuation is
thus an enforced-tier capability; it is not available to a deployment
that relies on token lifetime alone.

# Relationship to Other Delegation {#relationship-delegation}

Offline attenuation sits beside two existing mechanisms and is distinct
from both:

- Authorization-Server-mediated delegation (the issuance profile's `act`
  chain and Token Exchange) narrows at the issuer, online, and is the
  right choice when an issuer round-trip is acceptable and a deployment
  wants the issuer to observe each delegation. Offline attenuation trades
  that observation for removing the issuer from the path.
- Child Mission Delegation
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) creates a
  separate Child Mission with its own `mission_id`, lifecycle, and
  approval. Offline attenuation creates no new Mission: every child rides
  the same `mission` claim and dies with the same Mission. Use a Child
  Mission when the sub-agent needs its own durable, separately revocable
  Mission; use offline attenuation when it needs a narrower token under
  the same Mission, fast, at fan-out scale.

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
  "iat": 1797840000,
  "exp": 1797840300,
  "jti": "aat_root_7M2R4kP9sT1x",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "del_depth": 0,
  "del_max_depth": 2,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
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
  "iat": 1797840030,
  "exp": 1797840300,
  "jti": "aat_child_2Yt7Qv9Lq",
  "cnf": { "jkt": "kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t" },
  "par_hash": "9XbVt2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQ",
  "del_depth": 1,
  "del_max_depth": 2,
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
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

The `mission` claim is unchanged, the write tool is gone, and the read
constraint is unchanged (a permitted narrowing). To read an invoice the
extractor presents the chain `[root, child]` and a per-invocation
proof-of-possession to the gateway. The gateway verifies the chain (the
child's signature under the root's `cnf` key, `par_hash`, the depth and
capability monotonicity), verifies the proof-of-possession under the
child's `cnf` key, and, because this is Mission-bound, checks that
`msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` is `active` within its staleness
bound ({{kill-switch}}). A write attempt by the extractor fails on
capability monotonicity: `erp.journal-entries.write` is not in its tools.
And when `alice` revokes the Mission, the next read fails the state
check and the whole chain stops, even though no issuer ever saw the
child and the child's `exp` has not passed.

# Conformance {#conformance}

A Mission Issuer conforming to this profile MUST bound a Mission-bound
attenuation root by the Mission's Authority Set and carry the `mission`
claim and confirmation key on it. A consumer conforming to this profile
MUST verify the attenuation chain and proof-of-possession per the
attenuation substrate, MUST carry the `mission` claim unchanged across
the chain, and MUST enforce current Mission state per {{kill-switch}}. A
deployment MUST NOT claim this profile on a path that does not enforce
Mission state.

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
  SHOULD set it, and SHOULD bound fan-out breadth by policy, since
  offline minting is unobserved by the issuer.
- Audit. Because the issuer does not observe offline derivations, the
  consuming enforcement points are the only place a derivation is seen;
  runtime enforcement evidence
  ({{I-D.draft-mcguinness-oauth-mission-runtime}}) is the audit record
  for offline-attenuated actions.

# IANA Considerations {#iana}

This document makes no IANA request. A Mission-bound attenuation root
carries the `mission` claim, which the issuance profile registers as an
open object, and the `attenuating_agent_token` authorization detail,
which the attenuation substrate registers; this profile combines them by
reference and defines no new claim, parameter, or registry.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles Attenuating Agent Tokens for offline, holder-derived
narrowing of Mission authority.
