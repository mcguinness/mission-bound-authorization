---
title: "Mission Cross-Organizational Delegation for OAuth 2.0"
abbrev: "OAuth Mission Cross-Org Delegation"
category: exp

docname: draft-mcguinness-oauth-mission-cross-org-delegation-latest
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
 - cross-domain
 - attenuation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-org-delegation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC8693:
  RFC9396:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.ietf-wimse-arch:
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit"
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
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

An agent in one organization sometimes delegates a narrower part of
its approved authority to an agent in another organization, which can
delegate again, while the relying party verifies the complete
narrowing chain without calling the originating issuer on the request
path.  This document profiles Mission Offline Attenuation across
organizational trust domains: the attenuation chain is the portable
authority proof, each hop carries its own actor under an explicit
identity-binding rule, the originally approved agent and the
on-behalf-of principal travel with the chain, and Cross-Domain
Projection remains the adapter by which a destination Authorization
Server validates the chain, applies local policy, and issues a local
token.  Projection and delegation stay distinct verbs; the profile
composes them and never merges them.

--- middle

# Introduction

The Mission family separates two verbs that cross-organizational
deployments need together.  **Project** makes Mission authority
consumable in a resource domain: single-hop, issuer-mediated,
audience-scoped ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).
**Delegate** gives a different actor a narrowed slice it may exercise
or further narrow.  Within one domain, delegation is
Authorization-Server-mediated Token Exchange or holder-mediated
offline attenuation
({{I-D.draft-mcguinness-oauth-mission-attenuation}}).  What no family
document previously covered is the recursive cross-organizational
case identified by workload-identity delegation work
({{I-D.ietf-wimse-arch}}): agent A in organization 1 delegates a
narrowed slice to agent B in organization 2, B delegates further, and
the final relying party verifies every narrowing without a callback.

This document defines that case as a profile of Mission Offline
Attenuation.  The attenuation chain already carries the complete
parent chain and verifies signature, capability monotonicity,
audience, expiry, depth, proof of possession, and an unchanged
Mission binding; this profile carries it across organizational trust
boundaries, adds the actor-identity and origin-principal rules those
boundaries require, and defines how a destination consumes the
verified chain.

# Status: An Experimental Extension {#status}

This profile is experimental, and it profiles an experimental
substrate: it inherits the maturity of Mission Offline Attenuation
and the attenuating-agent-token substrate that document profiles
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}).  The
issuer-mediated alternative, a chain of Token Exchange re-issuances
whose evidence layer is the actor-suite companions (issuer-signed hop
receipts, actor-signed hop proofs, and recorded authority bounds), is
documented as related work and is not defined here; maintaining two
wire formats in a first revision would make interoperability worse.
A family profiling of Actor Chain Authority Bounds is constrained
ahead of time: every in-Mission basis-reset or widening mechanism,
including a domain-transition reset, is prohibited; a new authority
basis is an Expansion successor or another fresh approval
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses the Mission family's terms from the issuance
profile ({{I-D.draft-mcguinness-oauth-mission}}) and the chain terms
of Mission Offline Attenuation
({{I-D.draft-mcguinness-oauth-mission-attenuation}}).

Cross-Organizational Mission Delegation Chain (the Chain):
: a Mission-bound attenuation root plus zero or more attenuation
  children, presented in root-to-leaf order using the attenuation
  substrate's chain serialization and token-type identifier.

Chain-verifying consumer:
: a relying party that receives and verifies the complete Chain.

AS-mediated consumer:
: a Resource Server that trusts a local token its Resource
  Authorization Server minted after verifying a Chain, and does not
  claim to have independently verified the Chain.

# The Delegation Chain {#chain}

A Chain is presented as one typed `subject_token` or one typed
credential; its signed hops carry the semantics.  No free-form
envelope, no additions to `mission_intent`, and no new PAR or Token
Exchange parameter collection are introduced.  `authority_hash`
remains a commitment to the complete approved Authority Set and an
audit correlator: it does not prove that a narrowed entry was a
member of that set.  The signed root and the verified per-hop subset
relations provide that proof.

## Hop Members {#hop-members}

Each hop carries the substrate's members and this profile's:

* the signed hop envelope: `iss`, `iat`, `exp`, `jti`, and the
  substrate's explicit `typ`;
* `authorization_details` ({{RFC9396}}): the authority at that hop;
* `aud`;
* `cnf`: the next presenter's key;
* the substrate's parent commitment and depth members (`par_hash`,
  `del_depth`, `del_max_depth`);
* `act`: exactly ONE profile-conformant actor object
  ({{I-D.draft-mcguinness-oauth-actor-profile}}: `iss` REQUIRED,
  `sub`, and `sub_profile`) naming this hop's actor only, REQUIRED on
  every hop of a conforming Chain ({{actor-identity}}); and
* the `mission` claim, value-invariant across every hop: `id`,
  `issuer`, `authority_hash`, and `subject`, the origin principal of
  the Origin Principal profile
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}), REQUIRED on
  a conforming Chain.

A hop never carries a nested actor history: the complete actor
history is the validated root-to-leaf Chain itself, reconstructed at
verification ({{verification}}), and a consumer MUST reject a Chain
presenting conflicting or duplicated actor representations.  A
materialized nested `act` projection ({{RFC8693}}) is constructed
from the validated Chain at a consuming boundary, a PDP, an
introspection responder, or a destination Authorization Server; it is
not carried on the artifacts
({{I-D.draft-mcguinness-oauth-mission-attenuation}}, Section "Actor
Attribution on the Chain").

## Actor Identity {#actor-identity}

Each surface has one attestation authority.  The root's `act` is
asserted by the Mission Issuer and bound to the root presenter key:
the root names the originally approved agent, so the approved-agent
identity travels with the Chain instead of resting on a Mission
Record the verifier may not hold.

A parent signature on a later hop proves only that the parent
delegated to the child key; it does not authenticate the identity
values the parent asserts.  A named actor on a holder-created hop
therefore counts only when the issuer-qualified pair (`act.iss`,
`act.sub`) is independently bound to that hop's `cnf` key through a
validated workload credential or attestation resolved through the
trust model ({{trust-model}}).  Absent that binding the hop is
key-only: its asserted identity is informational provenance at most,
MUST NOT satisfy an eligibility matcher (the issuance profile's
`allowed_delegates` or a `sub_profile` selector), and MUST NOT
otherwise influence authorization.  Where policy requires a named
actor and the binding is absent or invalid, verification fails
closed.

The `act` member never carries authority.  Delegation history follows
authorization continuity, not organizational topology
({{I-D.draft-mcguinness-oauth-mission}}): an attenuation hop is
in-Mission delegation, so an organizational boundary neither starts a
new root nor resets depth.

# Root Issuance {#root-issuance}

The originating Mission Issuer MAY issue a cross-organizational
attenuation root only when all of the following hold:

1. the Mission is `active`;
2. every carried `authorization_details` entry is within the Mission
   Authority Set;
3. every carried authorization-details type and constraint has
   registered, deterministic subset semantics usable by downstream
   verifiers (the family's Common Constraints registry; no local
   comparison rules);
4. every entry is delegable and the root depth does not exceed its
   approved `delegation.max_depth`;
5. the root `aud` is an approved destination or audience set;
6. the root is sender-constrained to the approved agent's workload
   key;
7. deployment policy permits the named authority and subject class to
   cross the named trust boundary; and
8. the root carries the issuer-asserted `act` naming the approved
   agent ({{actor-identity}}) and the `mission` claim including
   `subject`.

An entry with a deployment-private action, constraint, matcher, or
resource identifier whose meaning the destination cannot resolve MUST
be omitted.  It MUST NOT cross under a promise that the destination
will interpret prose or issuer-local policy.

# Per-Hop Derivation {#derivation}

A holder creates a child exactly as Mission Offline Attenuation
specifies, with these profile rules:

1. sign the child with the key bound by the parent's `cnf`;
2. bind the child to the exact parent through `par_hash`;
3. narrow or preserve every `authorization_details` entry under the
   registered subset semantics;
4. keep `aud` equal to or narrower than the parent's;
5. set `exp` no later than the parent's and no later than the
   destination trust policy permits;
6. increment `del_depth` without resetting it at any organizational
   boundary, and preserve `del_max_depth`;
7. keep the `mission` claim value-invariant, including `subject`;
8. set this hop's `act` to the actor receiving the delegation; and
9. bind the child to the recipient workload's own proof-of-possession
   key.

The recipient proves possession of the leaf key at redemption or
direct resource access.

# Trust Model {#trust-model}

"No interaction-specific bilateral agreement" does not mean "trust
any issuer."  A conforming deployment MUST hold a federation or
administrative policy that maps:

* trust-domain identifiers to accepted workload-identity trust
  anchors;
* Mission Issuers to accepted signing keys and key-status sources;
* actor-identity attestation sources: the anchors that bind an
  issuer-qualified (`act.iss`, `act.sub`) to a workload key
  ({{actor-identity}});
* resource identifiers to the Resource AS or RS authorized to consume
  them;
* authorization-details types and constraint registries to supported
  versions; and
* freshness ceilings for issuer metadata, key status, and Mission
  state.

The secure mapping from a trust-domain name to anchors is an explicit
deployment dependency the workload-identity architecture leaves out
of scope ({{I-D.ietf-wimse-arch}}).  Cached issuer metadata, key
status, and Mission state follow the substrate's Bounded Reliance
floor ({{I-D.draft-mcguinness-mission-substrate}}): maximum age
declared, missing or stale required state failing closed.  This meets
"no callback to the origin on the request path"; it does not claim
instantaneous revocation.

# Destination Verification {#verification}

A Resource AS or chain-verifying Resource Server MUST perform the
following, in order:

1. resolve the origin Mission Issuer to an accepted trust domain and
   verification keys through the trust model, never because the
   Chain names it;
2. validate the root: substrate type, signature, time bounds,
   Mission-Issuer equality, the issuer-asserted root `act`, and the
   `mission` claim including `subject`;
3. validate every `par_hash` link and child signature through the
   leaf;
4. verify the `mission` invariants unchanged across all hops: value
   equality of `id`, `issuer`, `authority_hash`, and `subject`;
5. verify monotonic `del_depth`, the preserved `del_max_depth`,
   nested `aud` and `exp`, and every `authorization_details` subset
   relation, rejecting any unknown type, action, constraint,
   comparison rule, or actor-binding profile;
6. classify each hop's actor as named (its identity binding
   validated) or key-only (its asserted identity inert,
   {{actor-identity}}), failing closed where policy requires a named
   actor;
7. reconstruct the ordered actor history from the validated
   artifacts, rejecting conflicting or duplicated representations;
8. verify the leaf presenter's proof of possession; identity
   verification never substitutes for the authority-chain checks;
9. establish that the Mission is `active` from a locally available
   state source within the deployment's declared freshness bound
   ({{I-D.draft-mcguinness-oauth-mission-status}}; Bounded Reliance,
   {{trust-model}}); and
10. authorize dual-axis under the Origin Principal profile
    ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}): the
    verified delegated authority, the current entitlement of the
    mapped origin principal, and local resource policy are
    independent requirements, each within its declared freshness.

In the substrate's transition classification
({{I-D.draft-mcguinness-mission-substrate}}), every verified hop is
`attenuate`; the destination's own decisions under local policy are
`decide_anew`.

# Local Projection {#projection}

When a Resource AS mints a conventional local token from a verified
Chain, it MUST:

* carry only the locally permitted subset;
* preserve the `mission` claim invariants, including `subject`;
* restart the local `act` chain at the local delegate (the
  cross-domain rule;
  {{I-D.draft-mcguinness-oauth-mission-cross-domain}});
* bind the token to the local presenter;
* cap its expiry by the leaf and local policy; and
* record in derivation evidence: the Chain digest, the leaf `jti`,
  the input and output authority, the reconstructed actor lineage,
  the policy version, and the `principal_mapping` object
  ({{I-D.draft-mcguinness-mission-runtime-evidence}}).

A local access token is not a new portable delegation root.
Recursive cross-organizational delegation continues from the verified
attenuation Chain, never from a locally projected token that has lost
the parent proof.

# Provenance for AS-Mediated Consumption {#provenance-bridge}

An AS-mediated consumer needing provenance of the upstream hops uses
one of:

* the validated Chain carried alongside the local token;
* the destination AS's introspection or evidence resolution over its
  recorded derivation evidence; or
* a chain-verification attestation ({{chain-verification-attestation}}).

Issuer-signed hop receipts belong to the issuer-mediated lane: a
destination AS MUST NOT manufacture receipts for holder-created hops.

## Chain-Verification Attestation {#chain-verification-attestation}

A destination AS MAY issue a signed attestation that it verified a
Chain: a JWT with explicit `typ`
`mission-chain-verification+jwt` carrying `iss` (the verifying AS),
`iat`, `exp`, the Chain digest (the substrate's chain-serialization
bytes under the family anchor idiom), the leaf `jti`, the
verification result, and the verifying policy version.  It is an
attestation about verification, surviving local-token expiry; it
conveys no authority and creates no delegation root.

# Capability and Discovery {#capability}

This profile defines no new metadata members.  A deployment declares
the `cross_org_delegation` capability through this document's
conformance claim ({{conformance}}), advertises root issuance through
the attenuation substrate's existing discovery, and consumes the
capability under the family's declared-consumption rule.

# Conformance {#conformance}

A deployment claims one or both consumption classes:

* **Chain-verifying**: the relying party receives and verifies the
  complete Chain per {{verification}}.
* **AS-mediated**: an RS trusts its Resource AS's locally issued
  token and does not claim independent verification of the Chain;
  provenance uses {{provenance-bridge}}.

Positive and negative vectors cover, at minimum: a valid three-domain
A to B to C chain; action, resource, amount, audience, or expiry
widening at either hop; constraint removal, including
`requires_action_approval: true`; parent-hash substitution, a
reordered or missing hop, a changed Mission binding including
`subject`, and an untrusted root; a root missing the issuer-asserted
actor; a named-actor hop without a validated binding influencing
authorization (it must not); a duplicated or conflicting actor
representation (a nested history smuggled onto a hop); depth reset at
an organizational boundary and depth overflow; a wrong leaf
proof-of-possession key; an unknown authorization-details type,
action, constraint, or subset algorithm; a revoked or expired
Mission, a compromised signing key, and stale or unavailable state; a
locally projected token offered as the parent of a new hop; and valid
delegated authority denied by local entitlement or local policy.

# Security Considerations

The attenuation profile's security considerations apply in full,
including its kill-switch requirement that consumption re-checks
Mission state.  This profile adds the cross-organizational surface.

- **Compromised delegation keys.**  A compromised hop key mints
  narrower children offline.  Depth and lifetime ceilings, the
  audience funnel, conservative `del_max_depth`, and leaf or key deny
  lists bound the blast radius; whole-Mission revocation stops the
  Chain at every state-checking consumer but does not selectively
  revoke a branch.  No instantaneous branch revocation exists in this
  revision.
- **Holder-asserted identity.**  Without the binding rule of
  {{actor-identity}}, a holder could name any actor and have policy
  trust it.  The rule makes unverified names inert; the failure mode
  is attribution loss, never authority gain.
- **Origin non-observability.**  The origin cannot observe offline
  fan-out.  Deployments requiring fan-out observability use
  issuer-mediated delegation or the runtime profile's enforcement
  surfaces ({{I-D.draft-mcguinness-mission-runtime}}).
- **Chain-size exhaustion.**  Chains grow linearly with depth and
  verification cost is linear in hops.  A verifier declares and
  enforces maximum hops, maximum artifact size, and a
  verification-cost ceiling, refusing above them.
- **State staleness.**  Cached state substitutes bounded staleness
  for a synchronous origin dependency; the bound is declared and
  exceeded state fails closed ({{trust-model}}).

# Privacy Considerations

The Chain discloses issuer-qualified actor identifiers and the origin
principal along its path.  Actor identifiers are correlation handles:
the pairwise and pseudonym guidance the Origin Principal profile
states for `mission.subject` applies to actor identifiers alike, and
the origin principal's own disclosure, minimization, and evidence
rules apply unchanged
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).  A Chain is
audience-narrowed by construction; a hop's `aud` never widens, so
disclosure is bounded by the root's audience set.

# IANA Considerations {#iana}

## Media Type Registration

This document registers `application/mission-chain-verification+jwt`
in the "Media Types" registry, per {{chain-verification-attestation}}:
Type name: application; Subtype name:
mission-chain-verification+jwt; Required parameters: N/A; Optional
parameters: N/A; Encoding considerations: binary (JWT); Security
considerations: see this document; Interoperability considerations:
N/A; Published specification: this document; Applications that use
this media type: Mission-aware Authorization Servers and Resource
Servers; Change controller: IESG.

--- back

# Acknowledgments
{:numbered="false"}

The cross-organizational deployment class and its verification
requirements were articulated by the WIMSE cross-organization
delegation work, whose problem statement this profile answers with
the Mission family's existing attenuation substrate.
