---
title: "Mission Offline Attenuation for OAuth 2.0"
abbrev: "OAuth Mission Offline Attenuation"
category: exp

docname: draft-mcguinness-oauth-mission-attenuation-latest
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
    title: "Attenuating Authorization Tokens for Agentic Delegation Chains"
    author:
      -
        ins: N. A. Niyikiza
        name: Niki Aimable Niyikiza
    date: 2026-10-26
    seriesinfo:
      Internet-Draft: draft-niyikiza-oauth-attenuating-agent-tokens-02
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-mission-cross-org-delegation:
    title: "Mission Cross-Organizational Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-org-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC7638:
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 derives delegated authority
through the authorization server: each narrowing is a derivation at
the issuer. For deep sub-agent fan-out, the common agent topology, that
puts the authorization server in the hot path as a latency and
availability dependency. This document defines an optional Mission
Offline Attenuation profile. It profiles Attenuating Agent Tokens so a
Mission-bound token holder can mint a narrower child token offline, with
no authorization server round-trip, carrying the same `mission` claim.
The Mission Issuer derives the attenuation root from the Mission's
approved Authority Set under a normative mapping; the narrowing is
verifiable from the carried token chain, and the Mission kill switch is
preserved because consumption is gated by the runtime enforcement
layer, which re-checks current Mission state on every presentation of a
token in the chain; a revoked Mission stops the whole chain even though
no issuer minted the children. Offline attenuation is offered
alongside, not instead of, Authorization-Server-mediated delegation.

--- middle

# Introduction {#introduction}

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") narrows
authority through the authorization server: a delegated or narrowed
token is derived at the issuer, and cross-domain projection is a Token
Exchange ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}). For an
agent that fans out to many
sub-agents, each needing a slice of the Mission's authority, that makes
the authorization server a per-delegation latency and availability
dependency on the execution hot path. At machine speed that
dependency is the bottleneck: a swarm forking sub-agents per subtask
cannot afford an issuer round trip per fork, and localized, offline,
cryptographically verifiable narrowing is the shape that load
requires from day one.

This profile is the family's OAuth-lane answer to it;
its Experimental status reflects the maturity of the attenuation
substrate it profiles, not a judgment that the capability is
optional. The stable path meanwhile is issuer-mediated child
delegation ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

The saving is amortization, not elimination: because a root's lifetime
is kept short ({{security-considerations}}), the holder returns to the
issuer once per subtree per root-lifetime window to mint the root, and
every narrowing within that window is then offline. The issuer leaves
the per-fork hot path; it is not removed from the deployment.

This document removes the issuer from that per-fork path for narrowing
within a root's lifetime. It
profiles Attenuating Agent Tokens
{{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}} (the "attenuation
substrate"), in which a token holder mints a narrower child token
offline by signing it with the key the parent token's `cnf` binds, and
the child commits to its parent by hash. A Mission-bound token can be an
attenuation-substrate root; its holder then derives narrower children
for sub-agents with no authorization server contact.

Three things make this safe within the Mission model, and this document
requires all three ({{mission-binding-check}}, {{kill-switch}}):

- the child carries the parent chain, with audience and expiry bounded
  per hop, so a consumer verifies the narrowing from the tokens it
  holds;
- the Mission kill switch is preserved because consumption is gated by
  the runtime enforcement layer re-checking current Mission state, not
  by the issuer (the attenuation substrate defines no revocation of its
  own); and
- `authority_hash` rides the chain as a lineage anchor, not as the
  child's own authority commitment.

This document is optional and experimental: adopt it for
evaluation, not as a stable interface. A deployment that narrows
authority only
through the authorization server is fully conformant to the issuance
profile and is unaffected by this document. It places no new requirement
on the issuance profile, and it does not replace
Authorization-Server-mediated delegation; a deployment offers offline
attenuation in addition, for the fan-out paths described in
{{introduction}}.

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
attenuation substrate, and is not implementable alone. It reuses:

- from the issuance profile: the Mission, the `mission` claim, the
  Authority Set, the subset rule, and the lifecycle; and
- from the attenuation substrate: the token format, offline derivation,
  chain linkage, capability monotonicity, and proof-of-possession.

It uses Agent (Client), Mission Issuer, Mission, and derived token as
the issuance profile defines them, and root token, derived token,
`par_hash`, `del_depth`, and capability monotonicity as the attenuation
substrate defines them.

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
({{Section 3.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}},
{{RFC9396}}).
The Mission Issuer derives that authority from the Mission's Authority
Set by the mapping of {{root-mapping}}. The root carries the `mission`
claim ({{I-D.draft-mcguinness-oauth-mission}}) and the holder's
confirmation key, as both profiles require. This profile REQUIRES
`authority_hash` on that claim, reintroducing it as this profile's own
lineage anchor beyond the issuance profile's baseline `id`/`issuer`
({{I-D.draft-mcguinness-oauth-mission}}): the offline chain has no
other channel back to the approved Mission once the root leaves the
issuer.

The root's `iss` MUST equal its
`mission.issuer`: only the Mission Issuer mints a Mission-bound root,
and it signs the root with its own keys. It MUST carry `aud` per the
issuance profile's token rules ({{I-D.draft-mcguinness-oauth-mission}}),
identifying the resource server(s) authorized to consume its authority.

The root is an attenuation-substrate token, not a JWT access token: its
JWS header carries the substrate's `typ` value `aat+jwt`
({{Section 3.5 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}})
in place of the issuance profile's `at+jwt`, its `cnf` carries the
holder's public key as `jwk`
({{Section 3.2 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}),
and the token endpoint returns it with the substrate's `token_type`
value `aat`
({{Section 6.1.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).

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
- every operation a mapped tool can perform at each audience in the
  root's `aud` MUST have an operation target, as that resource
  server's operation contract establishes it, that matches the
  entry's `resource` under the entry's `resource_match`
  ({{I-D.draft-mcguinness-oauth-mission-resource-access}}, Section
  "Resource Matching"). This target restriction is part of the entry,
  and the mapping preserves all of it for every tool and every
  audience. The root carries no resource member, so an `aud` value
  equal to the entry's `resource` does not establish this by itself.
  Where the entry's `resource` is finer than the targets a tool can
  reach, the root carries argument constraints that confine every
  target within it. An issuer that cannot establish this for a tool
  at every audience MUST NOT map the entry to that tool, and never
  maps it with the restriction removed; a requested root that needs
  such a tool is rejected ({{request-discovery}});
- the entry's `constraints`, and its `resource_contract` when it
  carries one, become the tool's `mission_constraints` value unchanged
  ({{mission-constraints}}). A tool takes its restrictions from exactly
  one entry: where more than one entry maps to a tool identifier, the
  issuer carries one entry's restrictions for that tool or mints
  separate roots, and never merges them. The issuer MUST NOT map an
  entry to a tool unless the resource server establishes, for every
  operation the tool identifier names, each fact the entry's
  `constraints` restrict;
- a tool's argument constraints name every argument that the resource
  server's definitions of the operations the tool identifier names
  declare, each admitted explicitly, and carry no `"*"` entry
  ({{Section 3.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
  An argument that only some of those operations take is `optional` in
  the map, which leaves its requiredness to each operation's own
  definition. Argument constraints narrower than a wildcard come only
  from the target restriction above, never from the entry's
  `constraints`; and
- the root MUST derive only from entries whose `delegation` permits the
  intended holder ({{I-D.draft-mcguinness-oauth-mission}}).

Root issuance is the only moment the Mission Issuer is present in the
chain, so per-entry delegation policy is enforced by shaping the root:

- an entry whose `delegation` policy does not permit re-delegation,
  including the non-delegable default of an entry carrying no
  `delegation` member, MUST NOT be carried on a root whose
  `del_max_depth` exceeds 0; the issuer carries such entries only on
  roots with `del_max_depth` 0;
- a root's `del_max_depth` MUST NOT exceed the minimum `max_depth`
  across the `delegation` members of the entries it maps; and
- the issuer SHOULD mint separate roots per delegation class rather
  than mix entries of differing delegation policy on one root, which
  also serves the per-subtree disclosure minimization of
  {{privacy-considerations}}.

The root's authority MUST be within the Mission's approved authority
under this mapping and the issuance profile's subset rule. An auditor
verifies that a root is within the Authority Set by applying this same
mapping in reverse: each root tool, argument constraint, and
`mission_constraints` value traces to a permitted entry action, target
restriction, and `constraints`.

## Mission Constraints Member {#mission-constraints}

The attenuation substrate carries authority as tools and their
argument constraints, which constrain the arguments of an invocation
({{Section 3.4 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
A Mission entry's `constraints` are not arguments: a resource server
evaluates them against the facts it establishes for the operation it
executes, such as a record's amount, currency, or vendor
({{I-D.draft-mcguinness-oauth-mission-resource-access}}, Section
"Resource Server Enforcement"). This profile carries them in a member
of the `attenuating_agent_token` entry that the substrate gives no
authority and this profile defines
({{Section 3.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}):

`mission_constraints`:
: REQUIRED in the `attenuating_agent_token` entry of every token in a
  Mission-bound attenuation chain. A JSON object with exactly one member
  for each tool identifier in the entry's `tools`, and no other member.
  Each member's value is an object with:

  - `constraints`: REQUIRED. The `constraints` of the
    `mission_resource_access` entry the tool maps from
    ({{root-mapping}}), as a JSON object; an empty object means that
    entry carries none.
  - `resource_contract`: present exactly when that entry carries one,
    and then equal to it
    ({{I-D.draft-mcguinness-oauth-mission-resource-access}}).

Each hop narrows the member as the Resource Access profile's subset
rule narrows an entry
({{I-D.draft-mcguinness-oauth-mission-resource-access}}, Section
"Subset Rule"): for every tool a child keeps, the child's
`constraints` is a subset of the parent's under step 3 of that rule,
and its `resource_contract` is preserved under step 4. A child that
drops a tool drops that tool's member. Removing a restriction never
yields unrestricted authority: a missing `mission_constraints`, a
missing or extra member, a missing `constraints`, `constraints` that
are not a subset of the parent's under step 3, or a changed
`resource_contract` refuses the whole chain. A key the consumer does
not understand or cannot enforce also refuses the chain; it is never
ignored.

# Requesting a Root and Discovery {#request-discovery}

A Mission Issuer that supports this profile advertises it in its
authorization server metadata {{RFC8414}}:

`mission_attenuation_supported`:
: OPTIONAL boolean. When `true`, the Mission Issuer issues Mission-bound
  attenuation roots ({{root}}) and derives their authority from the
  Mission's Authority Set ({{root-mapping}}).

Such an issuer also lists `attenuating_agent_token` in
`authorization_details_types_supported`, the substrate's root issuer
discovery
({{Section 6.1.1 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).

A client requests a Mission-bound attenuation root at the token
endpoint with the substrate's root request
({{Section 6.1.2 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}),
on any grant the issuance profile uses to issue a Mission-bound token
(for example, the Mission's `refresh_token` grant). The request
carries an `attenuating_agent_token` authorization detail {{RFC9396}}
whose `tools` and `mission_constraints` are the requested root
authority; that detail on a Mission-bound token request selects root
issuance ({{root}}) rather than an ordinary `mission_resource_access`
token.

The client MUST carry the holder's public key in the substrate's
`req_cnf` parameter
({{Section 6.1.2 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
The Mission Issuer verifies that the client possesses the
corresponding private key and binds that key as the root's `cnf.jwk`
({{Section 6.1.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}},
{{root}}).

The Mission Issuer MUST validate the detail against the root mapping
({{root-mapping}}). It MUST refuse the request with
`invalid_authorization_details` when any tool, argument constraint, or
`mission_constraints` value is not within the mapped Authority Set,
rather than issue a root for
the rest, as the issuance profile refuses a requested subset beyond
the Mission's authority ({{I-D.draft-mcguinness-oauth-mission}}). A
client-requested root is therefore always at most the mapped Authority
Set, never broader.

# Offline Attenuation {#attenuation}

The holder of a Mission-bound attenuation token mints a narrower child
offline, by the attenuation substrate's derivation
({{Section 6.2 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
The holder:

- selects a narrower tool and constraint set;
- narrows `mission_constraints` with the tools it keeps
  ({{mission-constraints}});
- increments `del_depth`;
- signs with the key the parent's `cnf` binds; and
- sets `par_hash` to the parent's commitment.

No Mission Issuer contact occurs.

`par_hash` commits to the exact parent token bytes, per the attenuation
substrate's cryptographic linkage rule
({{Section 4.6 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}):
its value is the base64url encoding, without padding, of the SHA-256
digest of the parent token's JWS Signing Input.

The child's `aud` MUST equal its parent's `aud` or be a subset of it.
For this comparison the `aud` is treated as a set of audience values: a
string `aud` is the one-element set of that string, and an array `aud`
is the set of its members. Values are compared as case-sensitive,
byte-exact strings, with no URI normalization; a single-string `aud`
and a one-element array carrying the same value are therefore
equivalent.

The child's `exp` MUST NOT exceed its parent's `exp`, the substrate's
TTL monotonicity
({{Section 4.4 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
Because the Mission Issuer caps the root's `exp` at the Mission's
`expires_at`
({{I-D.draft-mcguinness-oauth-mission}}), the per-hop `exp` rule bounds
the whole chain transitively: no descendant outlives the root, hence
none outlives the Mission.

The `mission` claim rides the chain unchanged: every token in the chain
carries the same `id`, `issuer`, and `authority_hash` as the root. The
child's narrowing is governed by the attenuation substrate's
capability monotonicity
({{Section 4.5 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}})
and by the narrowing of `mission_constraints`
({{mission-constraints}}), the two subset relations a consumer checks;
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
and proof-of-possession under the attenuation substrate's chain
verification algorithm
({{Section 8 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
This profile
adds checks on the `mission` claim, which the substrate does not define
because it has no concept of the Mission binding. The substrate gives a
claim it does not define no authority in a derived token unless a
profile defines how it carries across derivation
({{Section 3.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}});
this profile defines that for `mission`, which is carried unchanged,
and for `mission_constraints` ({{mission-constraints}}). In
addition to the substrate's chain verification, a consumer MUST:

- reject the chain unless every token in it carries a `mission` claim
  and every claim carries the same `id`, `issuer`, and `authority_hash`
  as the root. A child cannot re-bind to a different Mission or change
  the lineage anchor; a link whose `mission` claim differs from the
  root's, or that omits it, MUST cause the whole chain to be refused,
  not treated as a narrower grant; and
- reject the chain unless the root's `iss` equals its `mission.issuer`,
  and verify the root's signature under the Mission Issuer's keys, the
  consumer's trust anchor for that `iss`
  ({{Section 8 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}},
  step 3). A root whose `iss` is not its
  `mission.issuer`, or whose signature does not verify under the Mission
  Issuer's keys, MUST cause the whole chain to be refused: only the
  Mission Issuer mints a Mission-bound root; and
- treat a chain whose root carries no `mission` claim as outside this
  profile: it is an ordinary attenuation chain with no Mission binding,
  and a consumer MUST NOT apply the Mission-state kill switch
  ({{kill-switch}}) to it or report it as Mission-bound;
- reject the chain if any child's `aud` is not equal to, or a subset of,
  its parent's `aud` ({{attenuation}}); and
- reject the chain if any child's `exp` exceeds its parent's `exp`
  ({{attenuation}}); and
- reject the chain unless every token carries `mission_constraints`
  as {{mission-constraints}} defines it, each child's narrowing its
  parent's.

These checks fail safe: a chain that does not present a single, unchanged
Mission binding, an audience within its parent's, an expiry within
its parent's, and Mission constraints within its parent's is refused,
not evaluated against a guessed Mission.

A substrate verification that permits a presentation does not by
itself authorize the invocation. The consumer MUST also enforce the
leaf's `mission_constraints` value for the invoked tool against the
facts of the operation it executes, and refuse the invocation where
they do not hold. It establishes those facts as it does when it
enforces an entry's `constraints`
({{I-D.draft-mcguinness-oauth-mission-resource-access}}, Section
"Resource Server Enforcement"): from its own records where the
operation acts on one, never from an argument's claim about such a
record.

Verification cost scales with the chain: a consumer performs one
signature verification per link, the proof-of-possession check, and
the Mission-state check ({{kill-switch}}) on every presentation. The
substrate's implementation depth limit bounds the chain length a
consumer accepts independently of the `del_max_depth` the chain
carries
({{Section 4.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}),
so an adversarially deep chain is refused rather than verified.

## Edge Validation {#edge-validation}

This is the deployment pattern this profile exists for
({{introduction}}). At Mission start the issuer mints the attenuation
root alongside issuance and hands it to the orchestrating agent; from
there, narrowing never touches the issuer. The agent mints children
for its sub-agents offline ({{attenuation}}), and the PEP fronting
each tool or resource (an agent harness, an edge API gateway, a
service-mesh sidecar) validates offline too. All of the following are
facts of the presented chain ({{mission-binding-check}}), checkable
locally at memory speed:

- the signature chain to the root;
- capability monotonicity and the narrowing of `mission_constraints`;
- audience and expiry nesting; and
- the holder's proof of possession.

Where the root's `mission` claim carries the `expires_at` member
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), the Mission
ceiling is offline-checkable too.

The kill switch is the one non-local fact. For ordinary
consequential classes the validating PEP relies on cached Mission
state within the published staleness bound, so the state cost is
paid once per freshness window rather than per call; the
high-consequence classes and Mission state transitions still reach
the state source synchronously, under the runtime profile's
active-freshness requirement ({{kill-switch}}). The result is local
validation on the hot path, with synchronous authority only for the
actions whose consequences warrant it.

# The Kill Switch Requires Runtime Enforcement {#kill-switch}

The attenuation substrate defines no revocation
({{Section 9.8 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}):
a child, once minted,
is valid by its signature chain until its `exp`, and no issuer can reach
it. The Mission kill switch is therefore not automatic for offline
children; it is delivered only by the runtime enforcement layer.

A consumer of a Mission-bound attenuation chain MUST evaluate it under
the runtime enforcement profile
({{I-D.draft-mcguinness-mission-runtime}}). On every presentation of a
token in the chain, regardless of action class, in addition to
verifying the attenuation chain and the proof-of-possession, the
consumer:

1. MUST establish that the chain's Mission is `active`, within the
   deployment's declared freshness bound, from a Mission state source;
   and
2. MUST refuse if it cannot establish the Mission as `active` within
   the bound, including when the state source is unreachable, as the
   runtime profile fails closed on unestablished state
   ({{I-D.draft-mcguinness-mission-runtime}}).

Where a deployment also runs the Mission Containment profile
({{I-D.draft-mcguinness-oauth-mission-containment}}), `active` is not
the same question as uncontained: a contained Mission stays `active`,
so this check alone does not stop a root minted before the contain
transition, or the offline children it keeps minting under it.
Containment gates derivation at the issuer and propagates to Child
Missions; it defines no consumer-side check that this profile's
per-presentation state evaluation picks up, so an attenuation root
already in a holder's possession keeps minting against the Mission's
pre-containment authority until the root's own `exp` or
`del_max_depth` ends it, or the Mission itself is revoked or expires
({{security-considerations}}).

A cached chain does not bypass this: a chain held in a harness cache is
still re-checked against current Mission state on every presentation,
since the cache is never evidence of continuing authority
({{I-D.draft-mcguinness-mission-harness}}). A revoked or expired
Mission MUST cause refusal of every token in the chain, regardless of
the children's own `exp`.

A deployment MUST NOT accept Mission-bound attenuation tokens on a path
that does not enforce current Mission state: without that check the
offline chain is ungoverned bearer authority until it ages out, which
defeats the purpose of binding it to a Mission. Offline attenuation is
thus a capability for deployments running the runtime enforcement
profile ({{I-D.draft-mcguinness-mission-runtime}}); it is not available
to a deployment that relies on token lifetime alone.

# Mission-Binding Profile {#binding-profile}

Every token in a Mission-bound attenuation chain carries the `mission`
claim under this profile, which states the elements the issuance
profile's Claim Reservation names for a path whose minter is not the
Mission's issuer, here the holder that derives a child
({{I-D.draft-mcguinness-oauth-mission}}, Section "Claim Reservation"):

1. **Parent chain.** The root, minted and signed by the Mission Issuer
   with `iss` equal to `mission.issuer` ({{root}}), and each child's
   `par_hash` link to its parent and signature under the key its
   parent's `cnf` binds ({{attenuation}}).
2. **Authority bound.** The root is bounded by the Mission's Authority
   Set ({{root-mapping}}); each child is no broader than its parent
   under the attenuation substrate's capability monotonicity and the
   narrowing of `mission_constraints` ({{mission-constraints}}), with
   its `aud` and `exp` within its parent's ({{attenuation}}).
3. **Mission state.** The Mission Issuer gates the root on Mission
   state as it gates any Mission-bound token ({{root}}). A holder
   mints a child with no state check; the consumer establishes that
   the Mission is `active`, within the deployment's declared freshness
   bound, on every presentation ({{kill-switch}}).
4. **Consumer checks.** The chain verification of
   {{mission-binding-check}} and the state check of {{kill-switch}}.
   Chain verification alone does not satisfy this profile
   ({{conformance}}).

# Relationship to Other Delegation {#relationship-delegation}

Offline attenuation sits beside two other narrowing mechanisms:
Authorization-Server-mediated delegation (the issuance profile's `act`
chain and Token Exchange), which narrows at the issuer, online, so the
issuer observes each delegation; and Mission Child Delegation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), which creates
a separate Child Mission with its own `mission_id`, lifecycle, and
approval. Offline attenuation creates no new Mission: every child rides
the same `mission` claim and dies with the same Mission.

Mission Child Delegation's own comparison section
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
"Relationship to Delegated Tokens") is the family's decision guide for
choosing among the three narrowing mechanisms; this document does not
restate it.

# Actor Attribution on the Chain {#actor-attribution}

The chain identifies holders by key possession: each token binds its
holder through `cnf`, and possession is proven at use. This document
defines no actor-identity member on chain tokens. A profile that adds
named-actor attribution to chain artifacts is bound by the following
model; the cross-organizational delegation companion
({{I-D.draft-mcguinness-oauth-mission-cross-org-delegation}}) defines
the member and its verification semantics.

Each artifact names only its own hop's actor. The complete actor
history is reconstructed from the validated root-to-leaf chain; it is
never duplicated as a nested history inside each artifact, and a
consumer MUST reject a chain that presents conflicting or duplicated
actor representations. A materialized nested `act` projection
({{RFC8693}}, shaped per the Actor Profile,
{{I-D.draft-mcguinness-oauth-actor-profile}}) is constructed from the
validated chain at a consuming boundary, a PDP, an introspection
responder, or a destination authorization server; it is not carried
on the artifacts.

The root actor is asserted by the Mission Issuer and bound to the
root presenter key: the root names the originally approved agent, so
the approved-agent identity travels with the chain instead of resting
on a Mission Record the verifier may not hold. A parent signature on
a later hop proves only that the parent delegated to the child key;
it does not authenticate the identity values the parent asserts. A
named actor on a holder-created hop therefore counts only when the
issuer-qualified actor identifier is independently bound to that
hop's `cnf` key through a validated workload credential or
attestation. Absent that binding the hop is key-only: its asserted
identity is informational provenance at most and MUST NOT satisfy an
eligibility matcher (the issuance profile's `allowed_delegates` or a
`sub_profile` selector, {{I-D.draft-mcguinness-oauth-mission}}) or
otherwise influence authorization; where policy requires a named
actor and the binding is absent or invalid, verification fails
closed.

# Worked Example {#example}

An orchestrator agent (`s6BhdRkqt3`), acting for `alice` under Mission
`msn_wJDMty6vSvxrbyZ2F5B_qqWbtovA6Sns` to reconcile Q3 invoices, holds a
Mission-bound attenuation root. Its authority covers reading invoices
and posting journal entries of at most USD 500; `del_max_depth` allows
two levels of offline narrowing (illustrative; this Mission's Authority
Set extends the single-domain walkthrough's, its write entry also
carrying a `delegation` member with `max_depth` 2, so both mapped
entries are delegable to depth 2 under the root-shaping rules of
{{root-mapping}} and its `authority_hash` differs from that example's).
The Mission Issuer signs the root with protected header
`{"alg":"ES256","kid":"as-2026-10","typ":"aat+jwt"}`. Decoded root
claims:

~~~ json
{
  "iss": "https://as.example.com",
  "sub": "user_3p2q8mN1a0kV7tR",
  "client_id": "s6BhdRkqt3",
  "aud": "https://erp.example.com",
  "iat": 1793609400,
  "exp": 1793609700,
  "jti": "01a19b73-7ec0-7404-b47d-da1f4f13688c",
  "cnf": { "jwk": {
    "kty": "OKP", "crv": "Ed25519",
    "x": "13PnaI27qUjjjxZ7rW0Ls-iTo5F_c_hMNN3K4aLGv2g" } },
  "del_depth": 0,
  "del_max_depth": 2,
  "mission": {
    "id": "msn_wJDMty6vSvxrbyZ2F5B_qqWbtovA6Sns",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:RWSQPa3ifNhS35OyuUXMW3c3lduo-DkQ68-itStel6I"
  },
  "authorization_details": [
    { "type": "attenuating_agent_token",
      "tools": {
        "erp.invoices.read": {
          "period": { "constraint_type": "wildcard" } },
        "erp.journal-entries.write": {
          "account": { "constraint_type": "wildcard" },
          "amount": { "constraint_type": "wildcard" } } },
      "mission_constraints": {
        "erp.invoices.read": { "constraints": {} },
        "erp.journal-entries.write": {
          "constraints": {
            "max_amount": { "amount": "500.00", "currency": "USD" }
          } } } }
  ]
}
~~~

The root's `erp.invoices.read` and `erp.journal-entries.write` tools map
to the `invoices.read` and `journal-entries.write` actions on
`https://erp.example.com`. Their argument constraints admit each
argument the ERP's operation definitions declare, and the write entry's
`max_amount` rides `mission_constraints`, which the ERP enforces
against the amount of the journal entry it posts
({{mission-constraints}}). The root's `aud`
names that resource server. The ERP's operation contract identifies
`https://erp.example.com` as the operation target of both tools
({{I-D.draft-mcguinness-oauth-mission-resource-access}}), so the
`aud` value and the tool set bound the mapped entries completely.

The orchestrator spawns a read-only extraction sub-agent and, with no
authorization server contact, mints a child that drops the write tool
and keeps only the Q3 invoice read. It signs the child with the key the
root's `cnf.jwk` carries (protected header
`{"alg":"Ed25519","typ":"aat+jwt"}`), sets `iss` to the JWK Thumbprint
({{RFC7638}}) URI of that key, increments `del_depth`, and commits the
parent by `par_hash` (the `iss` value is one line, wrapped here for
display):

~~~
{
  "iss":
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:gmukbzuLQoEbUSbOF
     xbiOyvNwWCaCXdeii24v-xRahg",
  "aud": "https://erp.example.com",
  "iat": 1793609430,
  "exp": 1793609640,
  "jti": "01a19b73-f3f0-76a5-bdf3-fe39a8c43247",
  "cnf": { "jwk": {
    "kty": "OKP", "crv": "Ed25519",
    "x": "l3TlQp7m4AFPndPII7gkG2jxttodVKaGrm58SEi2AF4" } },
  "par_hash": "9XbVt2nD9bM7sX1cF8gH2vJ4kE5pNQl3KvZ4mP5x0wQ",
  "del_depth": 1,
  "del_max_depth": 2,
  "mission": {
    "id": "msn_wJDMty6vSvxrbyZ2F5B_qqWbtovA6Sns",
    "issuer": "https://as.example.com",
    "authority_hash":
      "sha-256:RWSQPa3ifNhS35OyuUXMW3c3lduo-DkQ68-itStel6I"
  },
  "authorization_details": [
    { "type": "attenuating_agent_token",
      "tools": {
        "erp.invoices.read": {
          "period":
            { "constraint_type": "exact", "value": "2026-Q3" } } },
      "mission_constraints": {
        "erp.invoices.read": { "constraints": {} } } }
  ]
}
~~~

The `mission` claim is unchanged, the child's `aud` equals the root's,
its `exp` (1793609640) ends before the root's (1793609700), within the
per-hop bound, the write tool and its `mission_constraints` member are
gone, and the read tool's `period` argument narrows from any value to
`2026-Q3` (a permitted narrowing). The child's `cnf.jwk` is the
extractor's own public key, not the orchestrator's, as the substrate
requires for a child handed across a process boundary
({{Section 6.2 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
The child's `par_hash`
derives as {{attenuation}} states, the base64url SHA-256 digest, without
padding, of the root token's JWS Signing Input; the value shown is
illustrative, since the example gives the root's decoded claims rather
than its serialized bytes. To read an invoice
the extractor sends the gateway a presentation, the chain
`[root, child]` and a PoP JWT for that invocation
({{Section 7.4 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).
The gateway verifies the chain (the child's signature under the root's
`cnf.jwk`, `par_hash`, the depth, capability monotonicity, and the
`aud` and `exp` bounds), verifies the PoP JWT under the child's
`cnf.jwk`, and, because this is
Mission-bound, checks on this presentation that
`msn_wJDMty6vSvxrbyZ2F5B_qqWbtovA6Sns` is `active` within the
deployment's declared freshness bound ({{kill-switch}}). A write attempt
by the extractor fails on capability monotonicity:
`erp.journal-entries.write` is not in its tools. And when the Mission is
revoked, the next presentation fails the state check and the whole
chain stops, even though no issuer ever saw the child and the child's
`exp` has not passed.

For contrast, suppose the extractor presents a chain whose child
carries `"exp": 1793609760`, sixty seconds past the root's. The
per-hop bound check ({{mission-binding-check}}) fails before any tool
or Mission-state evaluation: a child that outlives its parent breaks
the chain's transitive expiry bound, so the gateway refuses the whole
chain. A chain whose child carried a `mission` claim differing from the
root's is refused the same way, as a re-bound chain, not read as a
narrower grant. So is a chain whose child keeps the write tool but
drops its `max_amount`, or omits `mission_constraints`: removing a
restriction never reads as unrestricted authority
({{mission-constraints}}).

# Conformance {#conformance}

A Mission Issuer conforming to this profile MUST bound a Mission-bound
attenuation root by the Mission's Authority Set ({{root-mapping}}) and
carry the `mission` claim, the confirmation key, `aud`, and
`mission_constraints` ({{mission-constraints}}) on it.

An Attenuating Holder conforming to this profile:

- MUST carry the `mission` claim unchanged into every child it mints;
- MUST only narrow authority and never broaden it, including
  `mission_constraints` ({{mission-constraints}});
- MUST keep each child's `aud` within its parent's and its `exp`
  within its parent's; and
- MUST increment the depth member the attenuation substrate defines
  (`del_depth`,
  {{Section 4.3 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).

A consumer conforming to this profile:

- MUST verify the attenuation chain and proof-of-possession per the
  attenuation substrate
  ({{Section 8 of I-D.draft-niyikiza-oauth-attenuating-agent-tokens}});
- MUST verify that the `mission` claim is unchanged across the chain,
  that each child's `aud` and `exp` are within its parent's, and that
  each child's `mission_constraints` narrows its parent's
  ({{mission-binding-check}});
- MUST enforce the leaf's `mission_constraints` against the facts of
  the operation it executes ({{mission-binding-check}}); and
- MUST enforce current Mission state per {{kill-switch}}.

A deployment MUST NOT claim this profile on a path that does not
enforce Mission state.

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
  compromise does not widen authority or evade revocation. The `cnf`
  key of an attenuation root is nonetheless two things at once: the
  presentation key for one token and the offline minting key for its
  whole subtree, and a key whose theft mints credentials warrants a
  higher custody class than one whose theft replays a credential. A
  deployment SHOULD hold attenuation-root keys under the mediating
  component's custody (the runtime profile's mediated custody,
  {{I-D.draft-mcguinness-mission-runtime}}), hardware-backed where
  available, rather than loose in the agent process.
- Depth and fan-out. `del_max_depth` bounds chain depth; a deployment
  SHOULD set it. Because offline minting is unobserved by the issuer,
  breadth is bounded at consumption, not at issuance: PEPs SHOULD meter
  the distinct leaf `jti` and `cnf` values they see per Mission and
  alert or refuse beyond a deployment-set bound. Issuers SHOULD keep
  root lifetimes short. This metering bound is per-PEP: each enforcement
  point counts only the leaves it sees, so the effective breadth limit
  is per-PEP unless the deployment aggregates leaf counters across its
  PEPs into a shared count. An issuer-side breadth control like Child
  Delegation's `max_children`
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) is
  structurally unavailable here, because the issuer never observes an
  offline mint and so cannot count children at issuance.
- Per-branch revocation. The only kill switch is whole-Mission: revoking
  the Mission stops the entire chain, but this profile provides no way to
  revoke a single branch or leaf without revoking the Mission. Per-branch
  revocation is deferred work. As a deployment mitigation, a PEP MAY
  maintain a denylist keyed by leaf `jti` or `cnf` to refuse specific
  leaves.
- Containment does not reach an already-minted root. The Mission
  Containment profile narrows a live Mission's effective authority
  while keeping the Mission `active`
  ({{I-D.draft-mcguinness-oauth-mission-containment}}). Because the
  kill switch of {{kill-switch}} checks only `active`, a root minted
  before the contain transition, and the subtree of offline children
  under it, keep minting against the pre-containment authority for the
  root's own lifetime: containment narrows what a fresh root can carry,
  but it is not a way to stop an outstanding one early. A deployment
  that relies on containment to bound offline attenuation SHOULD keep
  root lifetimes short and `del_max_depth` conservative for this
  reason, and MAY apply the per-branch denylist mitigation above to a
  specific root or subtree it learns is contained.
- Generic substrate consumers. A consumer that verifies only the
  attenuation substrate gives `mission_constraints` no authority and
  so enforces none of the Mission's constraints. A Mission-bound chain
  is accepted only by a consumer conforming to this profile
  ({{conformance}}), which enforces both the argument constraints and
  `mission_constraints`.
- Audit. Because the issuer does not observe offline derivations, the
  consuming enforcement points are the only place a derivation is seen;
  runtime enforcement evidence
  ({{I-D.draft-mcguinness-mission-runtime}}) is the audit record
  for offline-attenuated actions. PEP evidence for an action under an
  attenuated token SHOULD carry the chain linkage, the leaf's `jti`,
  its `del_depth`, and its `par_hash`, so offline derivations are
  reconstructable in audit.

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
A leaf presented to one resource server therefore discloses the broader
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
substrate defines ({{RFC9396}} establishes no registry of types); this
profile combines them by reference and defines no new claim or
registry. Its one addition to that detail, the `mission_constraints`
member ({{mission-constraints}}), needs no registration, since
{{RFC9396}} keeps no registry of detail members. It registers one
metadata member.

This document registers one member in the existing "OAuth Authorization
Server Metadata" registry {{RFC8414}}: Change Controller IETF; Reference
this document, {{request-discovery}}.

- `mission_attenuation_supported`

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Mission Constraints Member: a Mission entry's `constraints` and
  `resource_contract` ride the profile-defined `mission_constraints`
  member of the `attenuating_agent_token` entry, required in every
  token and narrowed per hop under the Resource Access subset rule,
  instead of argument constraints; argument constraints admit each
  declared argument explicitly; a consumer enforces both layers
  (#1756).

- Worked Example: the tokens carry `typ` `aat+jwt` and `cnf.jwk`, the
  child binds the extractor's own key, and the extractor presents a
  PoP JWT.

- Verifying the Mission Binding: the chain-length bound is the
  substrate's `MAX_DELEGATION_DEPTH`, a requirement there, in place of
  this profile's own recommendation.

- Requesting a Root and Discovery: the substrate's root request, which
  always carries an `attenuating_agent_token` detail, selects root
  issuance; the `mission_attenuation_root` parameter and the full
  mapped root for a request without a detail are withdrawn.

- Requesting a Root and Discovery: the holder key travels in the
  substrate's `req_cnf`, and the Mission Issuer verifies possession
  before binding it as `cnf.jwk`; a Mission Issuer that advertises this
  profile also lists `attenuating_agent_token` in
  `authorization_details_types_supported`.

- Requesting a Root and Discovery: a requested tool or argument
  constraint beyond the mapped Authority Set refuses the request with
  `invalid_authorization_details` (was `invalid_request`), as in the
  issuance profile and the substrate.

- Mission-Bound Attenuation Roots: the root carries the substrate's
  `typ` (`aat+jwt`, not `at+jwt`) and a `cnf.jwk`, and is returned
  with `token_type` `aat`.

- Profiles revision -02 of Attenuating Agent Tokens and cites it by
  section.

- Mission-Binding Profile states the root, chain, authority bound,
  state check, and consumer checks under which every token in a chain
  carries the `mission` claim, as the issuance profile's Claim
  Reservation requires. No requirement changed (#1531).

- Deriving the Root from the Authority Set: every operation a mapped
  tool can perform at each root audience has an operation target
  within the entry's `resource`; equal `resource` and `aud` values do
  not establish this alone, and an entry finer than the reachable
  targets is confined by argument constraints or not mapped (#1276).

- Deriving the Root from the Authority Set: the preserved target
  restriction includes the entry's `resource_match` and holds for every
  tool and every audience; an issuer that cannot establish it for a
  tool does not map the entry to that tool, and the reverse mapping
  traces each tool to the entry's target restriction (#1276).

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles Attenuating Agent Tokens for offline, holder-derived
narrowing of Mission authority.
