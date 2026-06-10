<!-- regenerate: off (set to on to regenerate this file from drafts/Makefile) -->

# Mission-Bound Authorization

This is the working area for the **Mission-Bound Authorization** Internet-Drafts.

Mission-Bound Authorization defines the **Mission** as a durable,
integrity-anchored, lifecycle-governed governance object for an approved task.
A Mission is created by a state authority from a structured Mission Intent at
the approval event, carries a typed Authority Set bounded by the Intent, and
binds every derived credential through a stable identifier that audiences
verify via Mission Status. Profile specifications compose this framework with
OAuth, AAuth, and a substrate-neutral Mission Authority Server (MAS).

The architecture is described at
<https://mcguinness.io/category/mission-bound-authorization/>.

## Start Here

Read the **Mission Framework** first — every other draft references it.

| | Draft |
|---|---|
| **Start** | [Mission Framework](#mission-framework) |
| **For OAuth deployments** | [OAuth Profile](#mission-bound-oauth-profile), then [Runtime Profile](#mission-bound-runtime-enforcement-profile) |
| **For AAuth deployments** | [AAuth Composition Profile](#mission-bound-aauth-composition-profile) |
| **For cross-substrate (MAS) deployments** | [Mission Authority Server](#mission-authority-server) |
| **For migration planning** | [Migration Guide](#mission-bound-authorization-migration-guide) and [Capability Model](#mission-bound-authorization-capability-model) |

## Specifications

The eleven drafts are grouped by spec layer.

### Foundational

#### Mission Framework

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-framework.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-framework)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-framework)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-framework.diff)

Defines the Mission and Mission Proposal records, lifecycle state machines, the
Mission Intent JSON schema, the typed Authority Set entry shape, integrity
anchors with domain-separated authorization-domain-bound envelopes, the
canonical Mission identifier, the principal model (composing RFC 9493 Subject
Identifiers and Actor Profile `sub_profile`), the abstract Mission Status
interface, and the Common Constraints framework with initial entries
`max_derivations`, `acr`, and `amr`.

### Standards Track: Substrate Profiles

#### Mission-Bound OAuth Profile

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-oauth-profile.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-oauth-profile)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-oauth-profile)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-oauth-profile.diff)

Binds the Framework to OAuth 2.0/2.1. Defines the `mission_intent` PAR
parameter, the `mission_resource_access` RAR type with full JSON schema, the
`mission` JWT claim, the Mission Status and Mission Lifecycle endpoints
(OAuth idiom: POST form-urlencoded), four enforcement classes, and
DPoP/mTLS sender-constraint requirements.

#### Mission-Bound AAuth Composition Profile

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth-profile.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-aauth-profile)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-aauth-profile)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth-profile.diff)

Binds the Framework to AAuth (Hardt). Defines wire-preserving local mappings
(no AAuth-side changes) and a set of optional AAuth wire extensions. Uses
RFC 9421 HTTP Message Signatures for the Mission Status binding.

#### Mission Authority Server

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-authority-server)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-authority-server)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.diff)

Defines the substrate-neutral Mission Authority Server: a RESTful HTTP API
(action subresources for state transitions, GET on resource for reads, POST
collection for submission, RFC 6570 URI templates in discovery) that owns
Mission state for cross-substrate deployments where OAuth and AAuth consumers
share a Mission. Cross-substrate revocation propagates through OpenID Shared
Signals events.

#### Mission-Bound Runtime Enforcement Profile

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-profile.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-runtime-profile)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-runtime-profile)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-profile.diff)

Defines the PDP contract composing with OpenID AuthZEN. Mission-to-policy
materialization, the RS-D enforcement contract with an enforcement-scope
manifest, Decision Evidence Object, Execution Evidence Object,
`parameter_digest` TOCTOU protection, runtime denial classification, and the
`max_invocations` reserve-on-permit/finalize-on-outcome counter protocol.

### Standards Track: Feature Specifications

#### Mission Expansion

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-expansion.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-expansion)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-expansion)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-expansion.diff)

Defines substrate-neutral Mission Expansion semantics: eligibility signaling,
the AuthZEN Access Request workflow for re-approval, Replacement vs Branch
expansion modes, concurrent expansion reconciliation, and the
`mission.predecessor` and `mission.expansion_mode` lineage attributes.

#### Delegated Authority Validation

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-delegated-authority-validation.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-delegated-authority-validation)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-delegated-authority-validation)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-delegated-authority-validation.diff)

Defines the narrow AS-to-Resource-AS validation handoff at issuance/expansion
time, with three classification outcomes (`in_bounds`, `out_of_bounds`,
`out_of_bounds_eligible`) and disclosure minimization.

#### Mission-Bound Transaction Token Chaining Composition

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-txn-token-chaining.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-txn-token-chaining)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-txn-token-chaining)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-txn-token-chaining.diff)

Composes Mission carriage with Fletcher's Transaction Token Chaining profile
through the `txn_claims.mission` member, including cross-domain trust agreement
(CDTA) integration and the Mission Transcription Profile registry.

### Informational

#### Mission Shaper Profile

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaper-profile.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-shaper-profile)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-shaper-profile)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaper-profile.diff)

Guidance for Mission Shapers: agent-side libraries that translate natural-
language goals into structured Mission Intent before submission to a state
authority. No wire claims, no IANA actions.

#### Mission-Bound Authorization Migration Guide

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-migration.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-migration)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-migration)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-migration.diff)

Stage 0-5 incremental adoption guidance for OAuth deployments moving from
substrate-only (no Mission) to full runtime enforcement, with compatibility
hazards and rollback considerations at each stage.

#### Mission-Bound Authorization Capability Model

* [Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-capability-model.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-mission-capability-model)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-mission-capability-model)
* [Compare Editor's Copy to Individual Draft](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-capability-model.diff)

Descriptive vocabulary for deployment maturity: the Capability Ladder (Levels
0-5), Resource Server Tiers (RS-A through RS-D), and Authorization Domain Tiers
(AD-1 through AD-3), with three named Adoption Claims. Vocabulary only — not
a protocol-actionable advertisement.

## Author's Companion Drafts

The Mission-Bound Authorization series composes with several individual
Internet-Drafts maintained by the same author:

* [`draft-mcguinness-oauth-actor-profile`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/) — OAuth Actor Profile for Delegation (`act` claim + `sub_profile` entity-type classification).
* [`draft-mcguinness-oauth-client-instance-assertion`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-client-instance-assertion/) — Client Instance Assertion for Token Exchange `actor_token`.
* [`draft-mcguinness-oauth-id-continuation-assertion`](https://mcguinness.github.io/draft-mcguinness-oauth-id-continuation-assertion/draft-mcguinness-oauth-id-continuation-assertion.html) — Identity Continuation Assertion for same-IdP SaaS-to-SaaS chains.
* [`draft-mcguinness-authzen-access-request`](https://datatracker.ietf.org/doc/draft-mcguinness-authzen-access-request/) — composes with [Mission Expansion](#mission-expansion) for re-approval workflows.

## Contributing

See the
[guidelines for contributions](https://github.com/mcguinness/mission-bound-authorization/blob/main/CONTRIBUTING.md).

The contributing file also has tips on how to make contributions, if you
don't already know how to do that.

## Command Line Usage

Formatted text and HTML versions of the drafts can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).
