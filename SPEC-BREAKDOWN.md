# Mission-Bound Authorization: Draft Roadmap and Spec Breakdown

This document defines what becomes a standards-track Internet-Draft, what stays in the [blog series](https://notes.karlmcguinness.com/series/mission-bound-authorization/), and the dependency order for drafting.

## First Deliverable: Vertical Slice

Rather than writing the full 35-45 page Framework first, the first deliverable is a **vertical implementation slice** co-developed with a reference implementation:

1. **Core Model** (subset of Framework):
   - Mission **Proposal** (pre-approval) vs Mission (approved) lifecycle.
   - Principal model (subject, approving principal, requesting client, actor chain, tenant, state authority).
   - Typed Authority Set entries with explicit equality/subset/intersection rules.
   - Canonical internal Mission ID + audience-pairwise external reference.
   - Domain-separated integrity hashes (`{type, schema_version, value}` inputs).
   - Abstract Mission Status semantics (authentication/integrity/freshness/audience properties, not a specific signing format).

2. **OAuth Binding** (subset of OAuth Profile):
   - `mission_intent` PAR parameter encoding.
   - `mission_resource_access` RAR representation.
   - `mission` token claim.
   - Sender constraint.
   - Refresh and exchange gating.
   - Dedicated Mission Status operation + optional introspection projection.
   - AS metadata and error codes.

3. **Conformance package**:
   - JSON Schemas (Mission Intent, Authority Set, Mission Status response).
   - Positive and negative validation vectors.
   - State-transition tests (Proposal → Mission → lifecycle).
   - Authority-Set narrowing tests.
   - JCS canonicalization and hash vectors.
   - Two-AS same-IdP worked example end-to-end.

The eleven-spec map below is the **destination**, not a settled drafting backlog. The vertical slice produces the first publishable artifact and validates the architecture before expanding scope.

## Drafting Goal

**These specs exist to enable implementation. They are not being submitted to IETF in their current form. Submission is deferred until they have baked through implementation.**

The bar at each version:

- Concrete enough that someone can build a conforming implementation from the spec alone (JSON schemas, exact wire shapes, error codes, validation rules, worked examples, reference test vectors).
- Internally consistent across the set so an implementer can pick up Framework + OAuth Profile and have them compose without ambiguity.
- Iterating with implementer feedback. Each spec ships as `-00` when implementable; `-01`, `-02` follow based on what implementations expose.

**Implications:**

- IETF process concerns (workgroup targeting, IESG review, BCP 14 polish, IANA registry expert review) are deferred. Drafts use kramdown-rfc so they're ready when submission time comes, but submission is not imminent.
- Implementer ergonomics is the primary quality metric. Worked examples, reference test vectors, and conformance checklists take priority over normative language polish.
- A reference implementation alongside the drafts is part of the deliverable. Specs without a corresponding reference implementation are unverified.
- Drafting order leads with what builders need first, not with what's foundational architecturally.

## Architectural Principles

The split obeys three principles:

1. **Profiles bind Framework semantics to an existing substrate** and MAY define the minimum extension points required for that binding (new parameters, claims, error codes, response members). Profiles do not invent new architectural features; they realize Framework concepts on a specific wire.
2. **Features are separate composable specs.** Anything that adds capability beyond the Framework's baseline (Mission Expansion, Delegated Authority Validation, etc.) is its own spec that profiles can compose with.
3. **The Framework is substrate-neutral on semantics, not on protection mechanism.** The Framework defines abstract data models, integrity/authentication/freshness/audience requirements, and registry vocabularies. Profile specs pick the concrete protection mechanism (e.g., OAuth uses RFC 9701 signed introspection responses; AAuth uses its native signing; MAS picks its own). Substrate neutrality means the Framework doesn't pick a wire format, not that it has no requirements.

## Author and Organization

All drafts in this set use the following author block:

```yaml
author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com
```

## Spec Layers

The drafts are organized into four layers. Each layer has a specific role.

| Layer | Specs | Role |
| --- | --- | --- |
| **Framework** | Mission Framework | Defines abstract concepts every profile and feature spec references. Owns Mission Status interface and capability-advertisement metadata registry. |
| **Server / Topology** | Mission Authority Server | Defines a new server role and its endpoints. Cross-substrate consumers reference it. |
| **Profiles** | OAuth Profile, AAuth Profile, Shaper Profile, Runtime Enforcement Profile | Compose existing standards + Framework + Feature specs into deployable wire surfaces. |
| **Features** | Mission Expansion, Delegated Authority Validation, Mission-Bound Transaction Token Chaining Composition | Each adds capability that one or more profiles can compose with. |
| **Informational** | Migration Guide, Capability Model | Adoption guidance and reporting model. |

## Summary

| # | Short name | Title | Layer | Category | Approx pages |
| --- | --- | --- | --- | --- | --- |
| 1 | `draft-mcguinness-mission-framework` | Mission Framework | Framework | Standards Track | 35-45 |
| 2 | `draft-mcguinness-mission-oauth-profile` | Mission-Bound OAuth Profile | Profile | Standards Track | 35-45 |
| 3 | `draft-mcguinness-mission-expansion` | Mission Expansion | Feature | Standards Track | 20-30 |
| 4 | `draft-mcguinness-mission-delegated-authority-validation` | Delegated Authority Validation | Feature | Standards Track | 15-20 |
| 5 | `draft-mcguinness-mission-txn-token-chaining` | Mission-Bound Transaction Token Chaining Composition | Feature | Standards Track | 10-15 |
| 6 | `draft-mcguinness-mission-aauth-profile` | Mission-Bound AAuth Composition Profile | Profile | Standards Track | 25-35 |
| 7 | `draft-mcguinness-mission-authority-server` | Mission Authority Server | Server / Topology | Standards Track | 30-40 |
| 8 | `draft-mcguinness-mission-runtime-profile` | Mission-Bound Runtime Enforcement Profile | Profile | Standards Track | 35-45 |
| 9 | `draft-mcguinness-mission-shaper-profile` | Mission Shaper Profile | Profile | Informational | 20-30 |
| 10 | `draft-mcguinness-mission-migration` | Mission-Bound Authorization Migration Guide | Informational | Informational | 15-20 |
| 11 | `draft-mcguinness-mission-capability-model` | Mission-Bound Authorization Capability Model | Informational | Informational | 20-25 |

**Specs the Mission-Bound work composes with.** See the Composition Surface section below for the full list.

**Future drafts (separate as they mature; not part of initial set):**

- Tool Binding, Decision Receipt, Purpose Registry, Attestation, Policy Projection (each as a Runtime Enforcement composition extension, when implementation interest justifies).
- Resumable Suspension (currently sketched in the AAuth Profile; promote to its own feature spec if applicable beyond AAuth).

## Naming Convention

All drafts use `draft-mcguinness-mission-*` (no "bound" prefix). The architecture is named "Mission-Bound Authorization" but the drafts are about Missions. "Mission-Bound" remains the architecture name in titles and prose; short names use `mission-*`.

## Composition Surface

The Mission-Bound work composes with the following published RFCs, adopted IETF/OpenID work, and existing individual drafts. The principle that "profiles compose existing standards" is satisfied by treating each of these as Normative or Informative references in the relevant Mission-Bound draft.

### OAuth 2.0 substrate (published RFCs)

| RFC | Title | Used by |
| --- | --- | --- |
| RFC 6749 | OAuth 2.0 Authorization Framework | Drafts 2, 3 |
| RFC 6750 | OAuth 2.0 Bearer Token Usage | Draft 2 (baseline) |
| RFC 7009 | OAuth 2.0 Token Revocation | Draft 2 (Mission revocation), Draft 7 (MAS) |
| RFC 7519 | JSON Web Token (JWT) | Drafts 1, 2 (Mission claim format) |
| RFC 7591 | OAuth 2.0 Dynamic Client Registration | Draft 2 (client declaring Mission Intent capabilities) |
| RFC 7592 | OAuth 2.0 Dynamic Client Registration Management | Draft 2 (informative) |
| RFC 7662 | OAuth 2.0 Token Introspection | Draft 2 (Mission Status OAuth binding) |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata | Draft 2 (Mission capability advertisement) |
| RFC 8693 | OAuth 2.0 Token Exchange | Drafts 2, 6 (Mission-state-gated derivation) |
| RFC 8705 | OAuth 2.0 Mutual-TLS Client Authentication | Drafts 2, 6 (sender constraint) |
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens | Draft 2 (`mission` claim placement) |
| RFC 9126 | OAuth 2.0 Pushed Authorization Requests | Draft 2 (`mission_intent` submission) |
| RFC 9396 | OAuth 2.0 Rich Authorization Requests | Drafts 1, 2 (`mission_resource_access` RAR type) |
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | Drafts 2, 6 (sender constraint) |
| RFC 9700 | Best Current Practice for OAuth 2.0 Security | Draft 2 Security Considerations |
| RFC 9728 | OAuth 2.0 Protected Resource Metadata | Drafts 2, 8 (RS tier advertisement); also relates to `draft-mcguinness-oauth-rfc9728bis` |

### Step-up and identity chaining

| Spec | Title | Used by |
| --- | --- | --- |
| RFC 9470 | OAuth 2.0 Step-up Authentication Challenge | Drafts 2, 3 (AAL-driven Mission Expansion), Draft 1 (`aal` constraint) |
| `draft-ietf-oauth-identity-chaining` | Identity Chaining across Trust Domains | Drafts 2, 7 (cross-trust-domain Mission carriage) |
| `draft-ietf-oauth-identity-assertion-authz-grant` (ID-JAG) | Identity Assertion Authorization Grant | Draft 2 (cross-IdP identity assertion) |

### Cryptographic and serialization primitives

| RFC | Title | Used by |
| --- | --- | --- |
| RFC 6234 | US Secure Hash Algorithms (SHA-256) | Draft 1 (integrity anchor algorithm) |
| RFC 7515 | JSON Web Signature (JWS) | Drafts 1, 2 (signed Mission Status, signed evidence) |
| RFC 7517 | JSON Web Key (JWK) | Drafts 1, 2, 7 (key publication for state authorities and MAS) |
| RFC 8174 | Ambiguity of Uppercase vs Lowercase in BCP 14 | All Standards Track drafts |
| RFC 8785 | JSON Canonicalization Scheme (JCS) | Draft 1 (canonicalization for integrity anchors) |

### Continuous evaluation and event propagation

| Spec | Title | Used by |
| --- | --- | --- |
| OpenID Shared Signals Framework (SSF) | Shared Signals event delivery | Drafts 2, 7, 8 (Mission lifecycle event propagation) |
| OpenID Continuous Access Evaluation Profile (CAEP) | CAEP subject and event definitions | Drafts 2, 7, 8 (Mission state change events) |
| `draft-ietf-secevent-subject-identifiers` | Subject Identifiers for SETs | Drafts 1, 7 (pairwise identifier framework, MAS) |

### Authorization decision and policy

| Spec | Title | Used by |
| --- | --- | --- |
| AuthZEN Authorization API | Substrate-neutral PDP interface | Draft 8 (PDP composition) |
| AuthZEN Access Request | Requestable denial workflow | Drafts 3, 8 (Mission Expansion request submission) |

### Cross-substrate

| Spec | Title | Used by |
| --- | --- | --- |
| `draft-hardt-oauth-aauth-protocol` (AAuth `-01`) | AAuth Protocol | Draft 6 (composition substrate) |

### Adjacent emerging work (compose when each matures)

| Spec | Title | Used by |
| --- | --- | --- |
| `draft-ietf-oauth-transaction-tokens` | Transaction Tokens (intra-trust-domain call-chain context) | Drafts 2, 5 (Mission-bound access token seeds Transaction Token Service) |
| `draft-fletcher-transaction-token-chaining-profile` | Transaction Token Chaining Profile (cross-trust-domain) | Draft 5 (Mission-Bound Txn Token Chaining composition) |
| `draft-yakung-oauth-agent-attestation` (ACAP) | Agent Attestation Profile | Future Mission Attestation module |
| `draft-anandakrishnan-rats-ptv-agent-identity` | RATS Prove-Transform-Verify Agent Identity | Future Mission Attestation module (sender-key binding to attested identity) |
| WIMSE (IETF Workload Identity in Multi-System Environments WG) | Workload Identity Multi-System Environments | Future Mission Attestation module (alongside RATS PTV) |
| `draft-zehavi-oauth-rar-metadata` | OAuth RAR Metadata | Draft 2 (`authorization_details_types_metadata_endpoint` for RAR type discovery) |
| `draft-chen-oauth-rar-agent-extensions` | OAuth RAR Agent Extensions | Adjacent to `mission_resource_access`; may converge |
| `draft-cecchetti-oauth-rar-cedar` | Cedar-in-RAR | Draft 8 (AS-to-RS policy carriage for materialized policy view) |
| `draft-ietf-oauth-selective-disclosure-jwt` (SD-JWT) | Selective Disclosure for JWTs | Potential composition for privacy-preserving Mission Status |
| OpenID CIBA Core | Client-Initiated Backchannel Authentication | Drafts 2, 3 (out-of-band approval channel for Mission bootstrap or expansion; not a Mission state model) |
| `draft-ietf-gnap-core-protocol` (GNAP) | Grant Negotiation and Authorization Protocol | Future MAS consumer; the MAS role contract is substrate-agnostic and could be consumed by GNAP-based deployments |

### Karl's existing individual drafts

Drafts on the IETF Datatracker:

| Draft | Title | Composes with |
| --- | --- | --- |
| [`draft-mcguinness-oauth-actor-profile`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/) | OAuth Actor Profile for Delegation | Drafts 2, 8 (actor context). Covers Actor Provenance; no separate spec needed. |
| [`draft-mcguinness-oauth-client-instance-assertion`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-client-instance-assertion/) | Client Instance Assertion | Draft 2 (instance identity in Token Exchange `actor_token`) |
| [`draft-mcguinness-oauth-id-continuation-assertion`](https://mcguinness.github.io/draft-mcguinness-oauth-id-continuation-assertion/draft-mcguinness-oauth-id-continuation-assertion.html) | Identity Continuation Assertion | Draft 2 (same-IdP SaaS continuation). Covers Same-IdP Chain Continuation; no separate spec needed. |
| [`draft-mcguinness-oauth-rfc9728bis`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-rfc9728bis/) | RFC 9728bis (Protected Resource Metadata update) | Drafts 2, 8 (RS tier advertisement) |
| [`draft-mcguinness-oauth-insufficient-claims`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-insufficient-claims/) | Insufficient Claims Error | Drafts 2, 8 (runtime denial classification) |
| [`draft-mcguinness-oauth-resource-token-resp`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-resource-token-resp/) | Resource Token Response | Draft 6 (AAuth-aligned resource-token response) |
| [`draft-mcguinness-token-xchg-target-svc-disco`](https://datatracker.ietf.org/doc/draft-mcguinness-token-xchg-target-svc-disco/) | Token Exchange Target Service Discovery | Draft 2 (Multi-AS Token Exchange discovery) |

Drafts in development (GitHub repo, not yet on Datatracker):

| Draft | Title | Composes with |
| --- | --- | --- |
| [`draft-mcguinness-authzen-access-request`](https://github.com/mcguinness/draft-mcguinness-authzen-access-request) | AuthZEN Access Request | Drafts 3, 8 (Mission Expansion request and runtime escalation) |
| [`draft-mcguinness-oauth-deferred-code`](https://github.com/mcguinness/draft-mcguinness-oauth-deferred-code) | Deferred Code Flow | Drafts 2, 6 (deferred Mission approval; potentially Resumable Suspension) |
| [`draft-mcguinness-oauth-identity-assertion-trust-policy`](https://github.com/mcguinness/draft-mcguinness-oauth-identity-assertion-trust-policy) | Identity Assertion Trust Policy | Drafts 2, 7 (Resource AS validates MAS issuer; Resource AS validates assertion issuer) |

Referenced in the architecture but not yet published as drafts:

| Spec name | Role | Composes with |
| --- | --- | --- |
| `draft-mcguinness-oauth-domain-authorized-issuer-discovery` | Domain-Authorized Issuer Discovery | Drafts 2, 7 (pairs with Identity Assertion Trust Policy for issuer trust discovery) |
| `draft-mcguinness-oauth-actor-receipts` | Actor Receipts | Draft 8 (portable per-action evidence composition with Decision Evidence Object) |

### Specs intentionally not composed with

These are adjacent or speculative; not in scope for the initial set:

- W3C Verifiable Credentials Data Model 2.0 — adjacent (Decision Receipt may compose later).
- W3C DID Core — out of scope (per project memory: avoid VC/DID adjacency for agent identity).
- FAPI 2.0 Security Profile — a deployment may layer Mission-Bound work over FAPI 2.0, but the Mission-Bound drafts do not require FAPI 2.0.
- OpenID Connect Core — Mission-Bound work is OAuth 2.0-based; OIDC composition is deployment-level, not specification-level.
- OAuth 2.1 (`draft-ietf-oauth-v2-1`) — when this advances, references to RFC 6749 may be updated to OAuth 2.1; no behavioral change to Mission-Bound work.

---

## Draft 1: `draft-mcguinness-mission-framework`

**Mission Framework**

**Layer:** Framework. **Category:** Standards Track. **Target WG:** OAUTH or independent submission. **Status:** New.

### Abstract

This document defines the Mission as a durable, integrity-anchored, lifecycle-governed governance object for an approved task. It defines the abstract types, interfaces, and behaviors that profile specifications map onto specific substrates: the Mission Intent JSON schema, Authority Set, lifecycle state machine, integrity anchors, mission identifier model, common constraints vocabulary, Mission Status interface, pairwise identifier framework, evidence binding, and capability-advertisement metadata. The framework is substrate-neutral. Profile specifications for OAuth, AAuth, and the Mission Authority Server compose this framework with their respective wire substrates.

### What this spec defines

- **Mission Proposal vs Mission distinction.** A **Mission Proposal** is the pre-approval object created when a client submits Mission Intent. It has its own lifecycle: `pending_approval`, `rejected`, `withdrawn`, `expired_as_pending`. A **Mission** is created at the moment of approval and has its own lifecycle: `active`, `suspended`, `revoked`, `completed`, `expired`. The two are distinct records with distinct identifiers (a `proposal_id` and, only on activation, a `mission.id`). This resolves the prior contradiction where a "Mission" was claimed to exist before approval despite the litmus test requiring approval.
- **Mission Intent JSON schema**: structured task proposal carried by Mission Proposal. Fields: `goal`, `objects`, `constraints`, `success_criteria`, `mission_expiry`, optional `purpose`, optional `context`. Profiles define transport; the schema is owned here.
- **Principal model.** Mission and Mission Proposal records explicitly carry:
  - `subject` / `beneficiary`: the principal on whose behalf the task is approved.
  - `approving_principal`: the principal who approved the Mission (may differ from subject for delegated approval; covers headless approval anchors too).
  - `requesting_client`: the OAuth client or AAuth agent that submitted the Proposal.
  - `actor_chain`: the current delegation chain at any derived artifact (composes with `draft-mcguinness-oauth-actor-profile`).
  - `tenant` / `authorization_domain`: the tenant identifier the Mission lives in.
  - `state_authority`: the AS, PS, or MAS that owns the Mission record.

  Subject identifiers can differ at each hop; the state authority is the only party that can authoritatively map them. Pairwise resolution rules are defined below.

- **Typed Authority Set entries.** Each entry has explicit type metadata:
  ```json
  {
    "type": "mission_resource_access",
    "schema_uri": "https://example.com/schemas/mission_resource_access/v1",
    "schema_version": "1",
    "authority": { ... type-specific payload ... },
    "narrowing_profile": "default"
  }
  ```
  The Framework defines a type registry. Each registered type provides deterministic equality, subset, intersection, and unknown-field rules. Loose `resource/actions/constraints` is the payload shape of one type (`mission_resource_access`), not the universal shape.

- **Lifecycle state machines** (two, not one):
  - **Mission Proposal lifecycle**: `pending_approval` → (`approved` → transitions to Mission) | `rejected` | `withdrawn` | `expired_as_pending`.
  - **Mission lifecycle**: `active` → (`suspended` ⇄ `active`) | `revoked` | `completed` | `expired`. Mission begins at `active` on activation; there is no Mission record in any earlier state.

- **Integrity hashes with domain separation.** Hash inputs are wrapped to prevent collision across object types:
  ```
  SHA-256(JCS({
    "type": "mission-intent",
    "schema_version": 1,
    "value": <canonical content>
  }))
  ```
  - `proposal_hash`: over the approved Mission Intent (wrapped with `type=mission-intent`).
  - `authority_hash`: over the approved Authority Set (wrapped with `type=mission-authority-set`).
  - `consent_disclosure_hash`: over the structured consent disclosure object (wrapped with `type=mission-consent-disclosure`). **Renamed from `consent_rendering_hash`** because the hash covers the disclosure object, not rendered output.

  JCS (RFC 8785) is the canonicalization; SHA-256 is the digest; base64url is the encoding. JCS avoids XML C14N's wrapping, namespace, comment, and DTD pitfalls because JSON's data model is structurally simpler.

- **Identifier model: canonical + pairwise.**
  - **Canonical Mission ID** (`mission.id`): stable opaque identifier held by the state authority. Used internally and by authorized auditors.
  - **Pairwise Mission Reference**: audience-specific identifier surfaced to consumers (Resource ASes, Resource Servers, downstream domains). Each pairwise reference resolves to the canonical ID only at the state authority.
  - **Mapping authority**: the state authority owns the canonical → pairwise map. No other party can independently derive one from the other.
  - **Correlation authorization**: defines which parties are entitled to resolve pairwise references (typically: authorized auditors, the state authority itself, regulators in defined jurisdictions). Default-deny for everyone else.
  - **Audit export behavior**: when audit records are exported across organizational boundaries, the export controller selects either canonical or pairwise references per recipient policy.

  `mission.origin` identifies the state authority (and resolves to its metadata document). It is not a separate audience-pairwise quantity; it is the discovery anchor for resolving references.

- **Abstract Mission Status semantics** (not a specific signing format). The Framework defines:
  - **Operation**: by-mission-reference query (input: canonical or pairwise mission reference; output: state, integrity hashes, audience-filtered Authority Set projection, `policy_version`, `iat`, freshness indicator). Distinct from token introspection.
  - **Authentication property**: responses MUST carry an integrity signal whose source is the state authority. The Framework does not pick the wire format. Profiles bind to substrate-appropriate mechanisms.
  - **Freshness property**: responses MUST indicate when the state was current. Profiles bind to substrate-appropriate freshness semantics.
  - **Audience property**: responses MUST be addressable to the requesting consumer (so the response can't be replayed against a different audience).
  - **Integrity property**: the response payload and its hash chain back to the canonical Mission record MUST be verifiable.

  Profile bindings:
  - OAuth Profile composes with **RFC 9701 (signed introspection responses)** plus a dedicated by-mission-reference status operation. RFC 9701 already defines signed responses; no new signing envelope is invented.
  - AAuth Profile composes with AAuth's native signing.
  - MAS Profile defines its own signed Mission Status binding.

- **Common Constraints framework + initial entries.** The Framework defines a **constraint extension framework**: registry with `name`, `type`, `schema_uri`, `schema_version`, semantics document URI, equality/subset/intersection rules, narrowing rules, runtime enforcement contract. Initial fully specified entries:
  - **`max_calls`**: integer count of invocation events. Authoritative counter at the state authority. Increments on derivation; resets only on Mission Expansion to a successor Mission.
  - **`aal`**: required authentication assurance level (composes with RFC 9470's AAL signaling). Freshness window is required.

  Other constraint names sketched in the blog (`max_value`, `max_duration`, `geo`, `data_classification`) become **future-work entries** with explicit unresolved semantics noted (currency / aggregation period / authoritative counter for `max_value`; units and start event for `max_duration`; subject vs actor vs resource vs execution location for `geo`; auth context and freshness for `aal`-related). The Framework ships the extension mechanism, not six underspecified names.

- **Capability-advertisement metadata**: `mission_authorization_domain_tiers_supported`, `mission_ladder_levels_supported`, `mission_profiles_supported`, `mission_optional_modules_supported`. Registry creation lives here; Capability Model (Draft 11) adds entries.

- **Trust boundaries**: who is trusted for what (Shaper, state authority, credential issuer, PDP, evidence emitter). Profiles populate these roles for their substrate.

- **Reference test vectors** as a first-class spec deliverable. For each canonicalization and hash output: input JSON → expected JCS canonical bytes (hex) → expected hash (base64url). Plus state-transition vectors and narrowing-rule vectors. An implementation that does not reproduce the test vectors is non-conformant.

- **Normative vocabulary**: Mission Proposal, Mission, Mission Intent, Authority Set, Projection, Runtime Decision, Evidence.

### Key normative requirements (abstract)

- A Mission MUST satisfy the litmus test (durable, integrity-anchored, lifecycle-governed, identifier-stable, reference-bearing, derived-authority). A Mission record exists only after activation; pre-approval state is held in a Mission Proposal record.
- A Mission Proposal MUST be promoted to a Mission by an explicit state-authority approval event; rejected/withdrawn/expired Proposals MUST NOT become Missions.
- A state authority MUST compute `proposal_hash`, `authority_hash`, and `consent_disclosure_hash` over domain-separated JCS-canonicalized (RFC 8785) inputs (`{type, schema_version, value}`), SHA-256, base64url-encoded.
- A state authority MUST produce byte-identical JCS output to the reference test vectors published with this spec.
- A Mission record MUST carry binding evidence (signer identity, timestamp, policy version, schema version, disclosure template version, approving principal) alongside the integrity hashes.
- A Mission record MUST carry the principal-model fields (`subject`, `approving_principal`, `requesting_client`, `actor_chain`, `tenant`, `state_authority`).
- A Mission MUST be in `active` state to permit new derivation; every non-active state refuses.
- A state authority MUST expose a by-mission-reference Mission Status operation distinct from token introspection. Responses MUST satisfy the authentication, freshness, audience, and integrity properties defined in this spec. Profiles specify the wire format and protection mechanism.
- Authority Set entries MUST carry explicit `type`, `schema_uri`, `schema_version`, and `authority` fields. Equality, subset, intersection, and unknown-field rules MUST be those registered for the type.
- Constraint values that require precision MUST use string representation in JCS-canonical form (e.g., `"max_calls": "100"`), not JSON number representation.
- Pairwise Mission references MUST be resolvable to the canonical Mission ID only at the state authority. Other parties MUST NOT be able to derive the canonical ID from a pairwise reference.
- A profile MUST specify how each Framework element manifests on its substrate, including the chosen wire format for Mission Status protection.
- A profile MAY define minimum extension points required for that binding (new parameters, claims, error codes); a profile MUST NOT enlarge the Framework semantics.

### IANA Considerations

Registry-by-registry audit required. The previous draft of this section claimed registrations that don't track real registries; corrected here:

- **Mission Common Constraints registry**: new IANA registry to be created. Defines registry policy (Specification Required or similar), entry schema (`name`, `type`, `schema_uri`, `schema_version`, semantics document, narrowing rules, runtime contract), and initial entries (`max_calls`, `aal`).
- **Mission Authority Set Type registry**: new IANA registry. Defines registry policy, entry schema (`type`, `schema_uri`, `schema_version`, equality/subset/intersection/unknown-field rules), and initial entry (`mission_resource_access`).
- **Mission lifecycle state enumeration**: defined inline in this spec (closed set); reservation in a new "Mission Lifecycle States" registry if extensibility is needed.
- **Mission Proposal lifecycle state enumeration**: same pattern.
- **Mission Status response media types**: where new media types are needed (e.g., `application/mission-status-response+json`), registered via the IANA Media Types Registry per RFC 6838. The Framework does NOT register `typ` values for JWT; that is profile-level (e.g., OAuth Profile registers any new media types it needs for RFC 9701-signed responses, per IANA Media Types Registry).
- **Capability-advertisement metadata registry**: new IANA registry. Capability Model (Draft 11) adds entries.
- **Mission Model identifier vocabulary** (`mission.id`, `mission.origin`): if these become JWT claims (in profiles, not in Framework), profiles register them in the JWT Claims Registry per RFC 7519.

What this spec does NOT register here:
- RAR `type` values: RFC 9396 does not establish an IANA registry for every RAR `type`. The `mission_resource_access` RAR type is documented descriptively here; OAuth Profile may propose a RAR-type registry creation if that work emerges separately, or rely on convention until one exists.
- Generic JWT `typ` values: there is no IANA "JWT Media Type Registry" for arbitrary `typ` values. Where a profile needs a specific JWT `typ`, it registers a media type via IANA Media Types Registry per RFC 6838.

### Security Considerations themes

- Integrity anchor non-guarantees (faithful rendering, comprehension, real-time honesty, principal authenticity).
- State authority compromise.
- Trust-boundary violations (Shaper acting as authorization component).
- Pairwise identifier privacy and correlation risk.
- Mission Status interface privacy and freshness.
- **JCS implementation correctness as a deployment risk.** Implementations that produce byte-divergent canonical output produce divergent hashes and break the content-addressability that the rest of the architecture depends on. Mitigation: the spec's reference test vectors. An implementation that does not reproduce the test vectors byte-for-byte is non-conformant. Where possible, deployments SHOULD use known-good JCS libraries rather than rolling their own.
- **JWS key management for signed Mission evidence.** The state authority's JWKS publication, key rotation, and `kid` discipline are load-bearing for Mission Status authenticity. Key compromise produces forgeable Mission Status responses. Standard JWS key-management guidance applies; the spec adds Mission-specific considerations for key continuity across Mission lifetimes that may outlast individual key rotations.
- **Number precision under JCS.** IEEE 754 double precision applies to JSON numbers under JCS. Constraint values where precision matters MUST use string representation (e.g., `"max_value": "100.00"`), not number representation.

### Normative references

RFC 8785 (JCS), RFC 8174 (BCP 14 update), RFC 6234 (SHA-256). JWS, JWK, JWA, JWT are referenced informatively from the Framework; profiles make them normative where they're used for protection.

### Informative references

Series blog posts as background; profile drafts as consumers.

---

## Draft 2: `draft-mcguinness-mission-oauth-profile`

**Mission-Bound OAuth Profile**

**Layer:** Profile. **Category:** Standards Track. **Target WG:** OAUTH. **Status:** New. **Depends on:** Draft 1.

### Abstract

This profile defines how a deployment composes OAuth 2.0 (RFC 6749), Rich Authorization Requests (RFC 9396), Pushed Authorization Requests (RFC 9126), Token Exchange (RFC 8693), DPoP (RFC 9449), and mTLS (RFC 8705) with the Mission Framework. A client submits structured Mission Intent at PAR; the Authorization Server validates and renders it, records an Approved Mission per the Framework, derives `authorization_details`, and binds issuance, refresh, and Token Exchange to the Mission record. Tokens carry a `mission` claim referencing the governance record. Common Constraints from the Framework's vocabulary serialize into `mission_resource_access.constraints` entries.

### What this profile composes

- **OAuth 2.0 (RFC 6749)** as the credential substrate.
- **PAR (RFC 9126)** as the Mission Intent submission point.
- **RAR (RFC 9396)** as the Authority Set wire serialization. Defines the `mission_resource_access` RAR type.
- **Token Exchange (RFC 8693)** as the derivation path that gates on Mission state.
- **DPoP (RFC 9449)** or **mTLS (RFC 8705)** as the sender-constraint mechanism.
- **The Mission Framework (Draft 1)** for Mission record semantics, integrity anchors, lifecycle, constraints vocabulary, and Mission Status interface.

### What this profile defines on the OAuth wire

- **`mission_intent`** parameter at PAR (transport for the Framework's Mission Intent JSON schema).
- **`mission_resource_access`** RAR type as one Framework Authority Set type (with declared `schema_uri`, `schema_version`, and narrowing rules). RFC 9396 does not provide an IANA registry of RAR types; the profile documents this descriptively.
- **`mission`** claim on JWT access tokens (registered in the IANA JWT Claims Registry).
- **`mission_inactive`** error code for refresh/exchange denial.
- **Mission Expansion eligibility signaling on the OAuth wire**: the `expansion` block in OAuth error responses, carrying `eligible`, `access_request_uri`, `ticket`, and `requested_authority`. Substrate-neutral semantics live in Draft 3; this profile binds them on the OAuth wire.
- **Dedicated Mission Status operation** (by mission reference) plus an **optional introspection projection** (RFC 7662 extended to return a Mission snapshot for the queried token). These are different operations:
  - The dedicated operation takes a Mission reference (canonical or pairwise) and returns Mission state.
  - The introspection extension takes a token and returns its claims, including a Mission snapshot if the token references a Mission.
  - Mission Status responses use **RFC 9701 signed introspection responses** as the protection mechanism for the introspection projection, and a parallel signed-JSON encoding for the dedicated operation. No new signing envelope is invented here.
- **Mission lifecycle operations on OAuth endpoints**: revoke, suspend, resume, complete by mission reference. **Distinct from RFC 7009 token revocation.** RFC 7009 revokes a specific token; Mission revocation terminates the Mission and cascades to all derived credentials. The profile defines a dedicated Mission lifecycle endpoint.

### What this profile composes with (existing or separate drafts)

Identity-chaining decomposition (corrected):

- **`draft-ietf-oauth-identity-assertion-authz-grant` (ID-JAG)**: common-IdP case. The user is resolved by a single IdP; Resource ASes consume the ID-JAG. This profile defines how Mission claims thread through ID-JAGs in the common-IdP scenario.
- **[`draft-mcguinness-oauth-id-continuation-assertion`](https://mcguinness.github.io/draft-mcguinness-oauth-id-continuation-assertion/draft-mcguinness-oauth-id-continuation-assertion.html) (Identity Continuation Assertion)**: onward issuance in a common-IdP chain when SaaS1 calls SaaS2 calls SaaS3. Composes with ID-JAG.
- **`draft-ietf-oauth-identity-chaining` (OAuth Identity and Authorization Chaining Across Domains)**: cross-domain mapping where issuer and subject identifiers differ across trust domains. This is the cross-IdP case; the previous breakdown conflated it with ID-JAG.

This profile composes with all three, with explicit role assignment per scenario.

### RFC compositions clarified

- **RFC 7009** revokes OAuth tokens. **Mission revocation is a separate operation** defined by this profile's Mission lifecycle endpoint.
- **RFC 9470** performs authentication step-up. It may satisfy an `aal` constraint, but it does NOT perform Mission Expansion. Expansion is a governance operation requiring approval; step-up is an authentication operation. The profile may compose with RFC 9470 for the case where a denied request would be permitted by satisfying an `aal` constraint via fresh authentication.

### What this profile does NOT define

- Mission Expansion semantics → Mission Expansion (Draft 3). This profile only defines the OAuth-wire binding.
- Resource-AS authority validation for open-world tools → Delegated Authority Validation (Draft 4).
- Transaction Token Chaining composition → Draft 5.
- Multi-AS ID-JAG composition → composes with `draft-ietf-oauth-identity-assertion-authz-grant` directly; not a new spec.
- Same-IdP SaaS continuation → composes with `draft-mcguinness-oauth-id-continuation-assertion`; not a new spec.
- Runtime per-action enforcement → Mission-Bound Runtime Enforcement Profile (Draft 8).
- MAS topology → Mission Authority Server (Draft 7).
- Token Size at Depth → operational guidance in this profile's Security Considerations and in MAS audience-pairwise sections; not a separate spec.

### IANA Considerations

- `mission_intent` PAR parameter.
- `mission_resource_access` RAR type.
- `mission` JWT claim.
- `mission_inactive` error code.
- Mission Expansion `expansion` error-response block fields.
- Mission Status introspection extension.

---

## Draft 3: `draft-mcguinness-mission-expansion`

**Mission Expansion**

**Layer:** Feature. **Category:** Standards Track. **Target WG:** OAUTH (composes with OAuth Profile) or AUTHZEN (composes with AuthZEN Access Request). **Status:** New. **Depends on:** Draft 1, AuthZEN Access Request.

### Abstract

This document defines the governance expansion mechanism for Mission-Bound Authorization. When an action falls outside the Authority Set of an active Mission but is eligible for governed expansion, this spec defines (substrate-neutrally) the eligibility-signaling semantics, the expansion-request workflow, the binding of the successor Mission to the prior Mission, and the reconciliation rules for concurrent expansion. The substrate-specific wire bindings for eligibility signaling live in the substrate profiles (OAuth Profile defines the OAuth binding; AAuth Profile defines the AAuth binding).

### What this spec defines (substrate-neutral semantics)

- **Eligibility-signaling abstract contract**: the fields a substrate-specific denial MUST surface when expansion is eligible (`eligible`, `access_request_uri`, `ticket`, `requested_authority`). Profiles bind these to substrate-specific transport.
- **Expansion request workflow via AuthZEN Access Request**: how the orchestrator submits the access request with the ticket, how the state authority adjudicates, how the result is communicated.
- **Workflow outcomes**: synchronous approved, asynchronous approved, denied, expired.
- **Successor-Mission binding**: `mission.supersedes`, expiry inheritance rules, atomic transition between prior and successor Mission.
- **Concurrent expansion reconciliation**: rules for when more than one expansion request is in flight for the same Mission.

### What this spec does NOT define

- Substrate-specific wire bindings for eligibility signaling → OAuth Profile (Draft 2) and AAuth Profile (Draft 6) each define their binding.
- How Resource ASes detect out-of-bounds requests → Delegated Authority Validation (Draft 4).

### IANA Considerations

- `mission.supersedes` claim or attribute.
- Expansion ticket and access-request shapes (in coordination with AUTHZEN).
- Concurrent expansion reconciliation status codes.

---

## Draft 4: `draft-mcguinness-mission-delegated-authority-validation`

**Delegated Authority Validation (AS-to-Resource-AS handoff)**

**Layer:** Feature. **Category:** Standards Track. **Status:** New. **Depends on:** Drafts 1 and 3.

### Abstract

This document defines a narrow AS-to-Resource-AS protocol for delegating authority validation when the originating Authorization Server lacks the Resource AS's action ontology. The Resource AS validates the request against the Mission's Authority Set using its local ontology, and signals back to the originating AS whether expansion is eligible. **Scope is intentionally narrow**: this spec defines the wire protocol between two specific server roles for this specific handoff. General per-action authority validation (request classification, PDP evaluation) belongs in the Runtime Enforcement Profile (Draft 8).

### What this spec defines (narrowly)

- The AS-to-Resource-AS validation request and response.
- Resource AS responsibilities in the handoff: examine the Mission Intent against local ontology, determine eligibility classification, signal expansion eligibility per Mission Expansion contract (Draft 3).
- Trust establishment between Resource AS and originating AS (the originating AS trusts the Resource AS's classification because the Resource AS owns the ontology; the Resource AS trusts the originating AS's Mission record because the originating AS is the state authority).
- Failure modes: Resource AS unreachable, classification timeout, mismatched ontology versions.

### What this spec does NOT define

- General per-request authority validation at runtime → Runtime Enforcement Profile (Draft 8). Draft 4 is specifically about the AS-to-Resource-AS handoff at issuance or expansion time, not about every consequential action.
- The expansion workflow itself → Mission Expansion (Draft 3).
- Mission Intent shape → Mission Framework (Draft 1).

### Overlap with Runtime Enforcement

Draft 4 and Draft 8 both classify requests against Mission authority. The boundary:

- **Draft 4** is server-to-server, at issuance or expansion time, between the originating AS and a Resource AS that owns ontology the originating AS does not have. The output is a classification for the expansion eligibility decision.
- **Draft 8** is runtime, per consequential action, between a PEP and a PDP. The output is a permit/deny/expand decision for a specific request.

If implementer experience shows the boundary is unstable, this draft folds into Draft 8.

### IANA Considerations

- AS-to-Resource-AS validation request/response shapes (media types via IANA Media Types Registry).
- Classification result codes.

---

## Draft 5: `draft-mcguinness-mission-txn-token-chaining`

**Mission-Bound Transaction Token Chaining Composition**

**Layer:** Feature. **Category:** Standards Track. **Target WG:** OAUTH (coordinated with `draft-fletcher-transaction-token-chaining-profile`). **Status:** New. **Depends on:** Drafts 1 and 2, `draft-fletcher-transaction-token-chaining-profile`.

### Abstract

This document defines the composition between Mission-Bound Authorization and Transaction Token Chaining. Appendix B of `draft-fletcher-transaction-token-chaining-profile` notes that RAR transcription across trust domains is future work. This spec specifies how Mission handles and AS-derived `mission_resource_access` entries flow through the `txn_claims` object in JWT Authorization Grants, including which entries are audience-filtered for the downstream Authorization Server.

### What this spec defines

- How `mission.id` and `mission.origin` carry in `txn_claims`.
- How the Authority Set transcribes from `mission_resource_access` into the JWT Grant, with audience filtering.
- Validation rules at the receiving AS in the downstream trust domain.
- Trust-boundary considerations between transaction token issuers.

### IANA Considerations

- `txn_claims` Mission-bound members.
- Transcription rules registry entry.

---

## Draft 6: `draft-mcguinness-mission-aauth-profile`

**Mission-Bound AAuth Composition Profile**

**Layer:** Profile. **Category:** Standards Track. **Submission type:** Independent (since AAuth itself is independent). **Depends on:** Draft 1, `draft-hardt-oauth-aauth-protocol`.

### Abstract

This profile defines how a deployment composes AAuth `-01` with the Mission Framework. AAuth defines a native Mission model. This composition preserves AAuth's wire protocol and maps its native concepts onto the substrate-neutral Mission Framework: identifier mapping, hash domain separation, Authority Set projection into resource-token and auth-token issuance, lifecycle composition, and Mission Status binding to the AAuth Person Server.

### What this profile composes

- **AAuth `-01`** as the credential substrate.
- **The Mission Framework (Draft 1)** for governance semantics, Mission Status interface, and pairwise identifier framework.

### What this profile defines on the AAuth substrate

- Identifier mapping between AAuth's `(approver, s256)` native Mission reference and the Framework's `(mission.id, mission.origin)` governance reference.
- Hash domain separation between AAuth's exact-body Mission hash and the Framework's structured governance hashes.
- Authority Set projection rules into AAuth resource tokens and auth tokens.
- Lifecycle composition: how the Framework's seven states map onto AAuth's native two-state `(active, terminated)` lifecycle.
- **Mission Expansion eligibility signaling on the AAuth wire**: the AAuth-native binding for the contract defined in Draft 3.
- **Mission Status AAuth binding**: the AAuth PS endpoint for Mission Status.

### What this profile does NOT define

- New AAuth wire elements beyond the bindings above; the composition preserves AAuth.
- Resumable Suspension semantics → currently sketched here; may promote to its own feature spec if needed.
- Cross-substrate (OAuth + AAuth) consumption → Mission Authority Server (Draft 7).

### IANA Considerations

- AAuth-side governance-mapping fields, in coordination with AAuth's registry.

---

## Draft 7: `draft-mcguinness-mission-authority-server`

**Mission Authority Server**

**Layer:** Server / Topology. **Category:** Standards Track. **Target WG:** OAUTH or independent. **Depends on:** Drafts 1, 2, 6.

### Abstract

A Mission Authority Server (MAS) holds the canonical Mission record so multiple OAuth Authorization Servers, AAuth Person Servers, and future substrate-state-authorities can project from one governance object. This document defines the MAS role, its metadata and discovery, the Mission submission and lifecycle endpoints, the MAS-side Mission Status binding (the abstract interface is in Draft 1), the substrate-neutral Authority Set serialization, audience-pairwise Mission identifiers, and the cross-substrate revocation propagation contract.

### What this spec defines

- MAS role and topology.
- MAS metadata document and well-known discovery URL.
- Mission submission endpoint (consumer-mediated and direct flows).
- Mission lifecycle endpoint (revoke, suspend, resume, complete).
- MAS-side Mission Status binding (transport for the Framework's abstract Mission Status interface).
- Substrate-neutral Authority Set serialization.
- Audience-pairwise Mission identifier protocol (transport for the Framework's pairwise identifier framework).
- Cross-substrate revocation propagation via SSF/CAEP or polling.

### What this spec does NOT define

- Substrate-local Mission state (covered by OAuth Profile and AAuth Profile).
- Mission Status abstract interface (defined in Framework, Draft 1).
- Runtime enforcement (Draft 8).
- Cross-MAS federation (out of scope for v1).

### IANA Considerations

- MAS metadata document and well-known URL.
- Mission Status MAS binding shape.
- Cross-substrate Authority Set serialization.
- Audience-pairwise identifier protocol.
- MAS lifecycle event shapes for SSF/CAEP propagation.

---

## Draft 8: `draft-mcguinness-mission-runtime-profile`

**Mission-Bound Runtime Enforcement Profile**

**Layer:** Profile. **Category:** Standards Track. **Submission venue:** Independent IETF I-D composing with the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) (a final OpenID specification, not an IETF artifact). **Depends on:** Drafts 1, 2 and/or 6, OpenID AuthZEN Authorization API 1.0, OpenID AuthZEN Access Request.

### Abstract

This profile defines how a deployment composes the AuthZEN Authorization API with the Mission Framework to enforce Mission-bound authority at runtime. Every consequential action is evaluated against the Mission's versioned policy view, the audience-relevant Authority Set projection, authenticated actor context, and current Resource policy. The composition defines reproducible Mission-to-policy materialization, the Resource-Side Enforcement Contract (RS-D), PEP placement rules, parameter binding, authority-expandable denial handling, and the Runtime Evidence Object.

### What this profile composes

- **OpenID AuthZEN Authorization API 1.0** as the PDP interface (final OpenID spec, not IETF).
- **OpenID AuthZEN Access Request** for governed expansion of denied authority (per Mission Expansion, Draft 3).
- **The Mission Framework (Draft 1)** for Mission state, Authority Set, integrity hashes, and Mission Status interface.
- Either the OAuth Profile (Draft 2) or the AAuth Profile (Draft 6) as the credential substrate adapter (at least one substrate profile is required).

### What this profile defines

- The Mission-to-policy materialization contract (reproducible compilation of the approved Mission tuple into an evaluable policy view).
- The Resource-Side Enforcement Contract (RS-D requirements).
- PEP placement rules.
- Parameter binding (`parameter_digest`) to close the TOCTOU gap.
- Runtime denial classification and expansion eligibility.
- Mission Status and runtime context requirements.
- Local-Action Boundary requirements (non-OAuth/non-AAuth actions).
- The Runtime Evidence Object format and binding evidence.

### What this profile does NOT define

- Optional Modules (Tool Binding, Decision Receipt, Purpose Registry, Actor Provenance, Attestation, Policy Projection) → separate per-module specs as each matures.
- Policy compilation contract (how the materialized policy is represented in a specific policy language) → separate spec when needed.

### IANA Considerations

- Runtime Evidence Object media type and registry.
- Runtime decision evidence claim names.
- AuthZEN extension parameters for Mission inputs (in coordination with AUTHZEN WG).

---

## Draft 9: `draft-mcguinness-mission-shaper-profile`

**Mission Shaper Profile**

**Layer:** Profile. **Category:** Informational. **Submission type:** Independent. **Depends on:** Draft 1.

### Abstract

The Mission Shaper is a client-side component that turns user input into structured Mission Intent. This profile defines the Shaper's contract with the orchestrator, the versioned discovery snapshot it consumes, non-authoritative derivation hints, the ambiguity-surfacing protocol, refusals, and the Shaper Trace audit artifact. The Shaper does not issue authority; its output remains untrusted until the validating server admits it.

### What this profile composes

- **The Mission Framework (Draft 1)** for Mission Intent shape.
- Substrate-specific Mission Intent submission contract (defined by OAuth Profile, AAuth Profile, or MAS).

### What this profile defines

- Shaper role and trust boundary.
- Discovery snapshot versioning.
- Mission Intent construction rules.
- Ambiguity-surfacing protocol (when to ask clarifications vs. accept defaults).
- Non-authoritative derivation hints format.
- Refusal protocol.
- Shaper Trace audit artifact.

### IANA Considerations

- Shaper Trace media type.
- Ambiguity-surfacing response shape.
- Discovery snapshot version field.

---

## Draft 10: `draft-mcguinness-mission-migration`

**Mission-Bound Authorization Migration Guide**

**Layer:** Informational. **Category:** Informational. **Depends on:** Drafts 1, 2, 6.

### Abstract

This document defines a Stage 0 through Stage 5 incremental adoption path for an existing OAuth or AAuth deployment to reach Mission-Bound Authorization conformance. Each stage names what the deployment ships, what client and Resource Server changes are required, and what compatibility hazards apply. The migration guide is operational; it makes no normative wire requirements beyond what the underlying profiles already specify.

### Sections

- Stage 0: where you are today (existing OAuth or AAuth deployment).
- Stage 1: shadow Mission (record the Mission, do not enforce).
- Stage 2: gate refresh and exchange on Mission state.
- Stage 3: narrow authority from the approved Mission.
- Stage 4: Resource Server uptake.
- Stage 5: cross-AS continuity.
- Compatibility hazards.

---

## Draft 11: `draft-mcguinness-mission-capability-model`

**Mission-Bound Authorization Capability Model**

**Layer:** Informational. **Category:** Informational. **Depends on:** Drafts 1-9.

### Abstract

This document defines a substrate-neutral capability and adoption model for Mission-Bound Authorization. Capability is reported as a coordinate on three axes: the Capability Ladder (Levels 0-5), Resource Server Tiers (RS-A through RS-D), and Authorization Domain Tiers (AD-1 through AD-3). The document defines three named adoption claims (Mission-Bound Issuance, Mission-Bound Runtime Enforcement, Mission-Bound Cross-Domain Projection) and the mapping from OAuth-only, AAuth-only, and cross-substrate deployments onto the coordinate. The capability-advertisement metadata registry is defined in the Framework (Draft 1); this document adds entries.

### Why Informational

The capability model is a description, not a wire protocol. Conformance is claimed against the substrate or runtime profile. The capability coordinate is a reporting tool. IANA actions are confined to adding entries to the registry created by the Framework.

---

## Future Drafts (not in initial set)

These extensions are part of the architecture but defer to separate drafts as each matures.

| Short name | Title | Depends on |
| --- | --- | --- |
| `draft-mcguinness-mission-tool-binding` | Mission Tool Binding | Drafts 1, 8 |
| `draft-mcguinness-mission-decision-receipt` | Mission Decision Receipt | Drafts 1, 8 |
| `draft-mcguinness-mission-purpose-registry` | Mission Purpose Registry | Drafts 1, 8 |
| `draft-mcguinness-mission-attestation` | Mission Attestation Profile | Drafts 1, 8, ACAP |
| `draft-mcguinness-mission-policy-projection` | Mission Policy Projection | Drafts 1, 8 |
| `draft-mcguinness-mission-resumable-suspension` | Resumable Suspension | Drafts 1, 6 (if scope broadens beyond AAuth) |

Each gets its own draft when there is sufficient implementation interest and the design is stable.

**Actor Provenance** is not in this list because it is already covered by [`draft-mcguinness-oauth-actor-profile`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/) (the OAuth Actor Profile for Delegation). The Mission-Bound OAuth Profile and Runtime Enforcement Profile compose with that draft for actor context; no separate Mission-prefixed Actor Provenance spec is needed.

---

## What Stays in the Blog

The blog series carries the conceptual argument, worked examples, and applied analysis. The drafts carry the normative wire requirements.

| Blog post | Future role |
| --- | --- |
| Part 1: Missing Abstraction | Argument for why a Mission is needed. Links to Draft 1. Stays in the blog. |
| Part 2: Mission Model | Affirmative argument for the Mission primitive. Reader-friendly explainer for Draft 1. |
| Part 3: Mission Shaper | Reader-friendly explainer; links to Draft 9. |
| Part 4: Mission-Bound OAuth Profile | Reader-friendly explainer; links to Drafts 1 and 2. Worked example stays here. |
| Part 4 Extensions: OAuth Extensions companion | Reader-friendly explainer; links to Drafts 3, 4, 5 (the feature specs) and the existing Identity Continuation Assertion draft. |
| Part 5: AAuth Composition | Reader-friendly explainer; links to Draft 6. |
| Part 6: Mission Authority Server | Reader-friendly explainer; links to Draft 7. |
| Part 7: Runtime Enforcement | Reader-friendly explainer; links to Draft 8 and the future Optional Module drafts. |
| Part 8: MCP Application | Applied use case. Stays in the blog. Links to Drafts 1, 2, 8 for protocol detail. |
| Part 9: Capability Model | Reader-friendly explainer; links to Draft 11. |

The blog posts retain their arguments, diagrams, worked examples, TL;DR and spine framing. They drop normative MUST/SHOULD/MAY language; those move to the drafts.

## Dependency Graph

```
                       ┌──────────────────────────────────────┐
                       │ Draft 1: Mission Framework           │
                       │ (defines abstract model, Mission     │
                       │  Status interface, pairwise IDs,     │
                       │  capability metadata registry)       │
                       └────────────────────┬─────────────────┘
                                            │
        ┌──────────────────┬─────────────────┼──────────────────┬─────────────────┐
        ▼                  ▼                 ▼                  ▼                 ▼
┌───────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ ┌──────────────┐
│ Draft 2:      │  │ Draft 6:     │  │ Draft 9:     │  │ Draft 8:       │ │ Draft 7: MAS │
│ OAuth Profile │  │ AAuth        │  │ Shaper       │  │ Runtime        │ │              │
└───────┬───────┘  └──────┬───────┘  └──────────────┘  └────────────────┘ └──────┬───────┘
        │                 │                                                       │
        │   Composed by both OAuth and AAuth Profiles:                            │
        │     Draft 3: Mission Expansion (substrate-neutral semantics)            │
        │     Draft 4: Delegated Authority Validation                             │
        │     Draft 5: Mission-Bound Txn Token Chaining                           │
        │                                                                          │
        │   Also referenced from Draft 2:                                          │
        │     draft-mcguinness-oauth-id-continuation-assertion (existing)         │
        │     draft-ietf-oauth-identity-assertion-authz-grant (existing)          │
        │                                                                          │
        └──────────────────────────────────────────────────────────────────────────┘
                                  ▲
                                  │ MAS composes both OAuth and AAuth Profiles

                       ┌──────────────────────────────────────┐
                       │ Draft 10: Migration                  │
                       │ (references Drafts 1, 2, 6)          │
                       └──────────────────────────────────────┘

                       ┌──────────────────────────────────────┐
                       │ Draft 11: Capability Model           │
                       │ (references Drafts 1-9; adds         │
                       │  entries to Framework's registry)    │
                       └──────────────────────────────────────┘
```

Draft 1 (Framework) is foundational: every other draft references it.

Drafts 3-5 (Features) are composable extensions. The substrate profiles (Drafts 2, 6) bind them on their wires.

Drafts 10 and 11 are terminal.

## Drafting Order (phased by implementer need)

The order leads with what builders need first to ship a Mission-Bound deployment.

**Phase 1: the implementable pair.** What an OAuth AS implementer needs to ship Mission-Bound issuance.

1. **Draft 1: Mission Framework.** Concrete data model, JSON schemas, hash algorithms, lifecycle state machine, Mission Status interface, integrity-anchor algorithm. Includes reference test vectors so implementers can validate their canonicalization and hash output. Foundational.
2. **Draft 2: Mission-Bound OAuth Profile.** Concrete OAuth wire bindings: `mission_intent` PAR parameter, `mission_resource_access` RAR type, `mission` claim, Mission Status introspection extension. Composes Framework + RFCs 6749, 9126, 9396, 9068, 9449, 7662, 8693. Implementable by an OAuth AS builder.

A reference implementation of the Framework + OAuth Profile pair lives alongside, validating that the specs are concrete enough to build from.

**Phase 2: extending the implementable pair.** Builders running into denial or wanting runtime enforcement.

3. **Draft 3: Mission Expansion.** Most-referenced feature. Substrate-neutral semantics; OAuth wire binding lives in Draft 2.
4. **Draft 8: Mission-Bound Runtime Enforcement Profile.** Substrate-independent PDP contract. Builders integrating Mission state into AuthZEN decisions need this.

**Phase 3: substrate breadth.** Tests the substrate-neutrality of the Framework.

5. **Draft 6: Mission-Bound AAuth Composition Profile.** Second substrate composition. If the Framework's abstractions don't fit AAuth, this phase is where we discover it and revise the Framework.
6. **Draft 7: Mission Authority Server.** Drafted when cross-substrate demand exists. Until then, sketched as a -00 that the breakdown points to.

**Phase 4: features as deployment patterns emerge.**

7. **Draft 4: Delegated Authority Validation.** When open-world tool deployments emerge.
8. **Draft 5: Mission-Bound Txn Token Chaining.** When Fletcher's chaining draft and Transaction Tokens mature enough to compose with.

**Phase 5: adoption guidance.**

9. **Draft 9: Mission Shaper Profile.** When a reference Shaper implementation is ready to back the guidance.
10. **Draft 10: Migration Guide.** After at least one team has actually migrated.
11. **Draft 11: Capability Model.** After multiple deployments at different capability levels exist to categorize.

---

## Resolved Decisions

1. ✅ **Common Constraints Catalog**: lives in Framework (Draft 1) as the abstract vocabulary; substrate profiles define wire serialization. May split into its own draft later if the catalog grows beyond what fits in the Framework.
2. ✅ **OAuth Extensions catchall**: gone. Each former extension is its own feature spec (Drafts 3, 4, 5).
3. ✅ **Mission Expansion**: substrate-neutral semantics in Draft 3 + per-profile wire bindings in the substrate profiles (Drafts 2 and 6).
4. ✅ **Mission Status**: abstract interface in Framework (Draft 1); each substrate profile and MAS spec defines its transport binding. Not its own draft.
5. ✅ **Same-IdP Chain Continuation**: composes with the existing [`draft-mcguinness-oauth-id-continuation-assertion`](https://mcguinness.github.io/draft-mcguinness-oauth-id-continuation-assertion/draft-mcguinness-oauth-id-continuation-assertion.html). No new spec.
6. ✅ **Capability-advertisement metadata registry**: lives in Framework (Draft 1); Capability Model (Draft 11) adds entries and stays purely Informational.
7. ✅ **Framework split**: kept as one spec for now. Common Constraints can spin out later if it grows.
8. ✅ **AAuth Composition Profile**: Standards Track with declared normative dependency on AAuth `-01` stabilizing.
9. ✅ **MAS layer**: "Server / Topology" — kept distinct from "Profile" because MAS defines a genuinely new server role.
10. ✅ **Naming convention**: `draft-mcguinness-mission-*` (no "bound" prefix on short names). "Mission-Bound" remains the architecture name in titles.
11. ✅ **Token Size at Depth**: operational guidance in OAuth Profile and MAS specs; not its own draft.
12. ✅ **Author**: `Karl McGuinness / Independent / public@karlmcguinness.com`.
13. ✅ **Workgroup targeting**: deferred. These specs are not being submitted to IETF in their current form; the goal is to enable implementation first. Workgroup targeting becomes relevant when a spec has implementer support and a submission is being prepared.
14. ✅ **Shaper Profile category**: Informational. Client-side processing spec with loose conformance; Standards Track would overclaim. The trace artifact and refusal protocol are guidance, not enforceable wire contracts.
15. ✅ **Worked examples**: each draft carries a minimal illustrative example (~5-10 lines). The full worked board-packet example stays in the blog and is referenced by each draft.
16. ✅ **Resumable Suspension placement**: currently sketched inside the AAuth Profile (Draft 6). If it generalizes beyond AAuth during drafting, promote to its own feature spec; otherwise keep as an AAuth-specific section.

## Tradeoff: Runtime Optional Modules Deferred

The Runtime Enforcement Profile (Draft 8) describes a substrate-independent PDP contract that can be extended with six Optional Modules: Tool Binding, Decision Receipt, Purpose Registry, Actor Provenance, Attestation, Policy Projection. The initial 11-spec set ships without these modules. They become per-module drafts as each matures.

Four ways to handle the modules; I'm recommending option A. Tradeoffs:

**Option A: defer all six modules (current plan, 11 drafts).**

- *Pro:* Smallest initial set; faster path to first publication and implementer review.
- *Pro:* Each module advances independently as implementation interest emerges.
- *Pro:* Capability Level 5 ("verifiable governance") can describe the abstract requirement without committing to specific module specs that may not survive contact with implementers.
- *Con:* Implementers targeting Level 5 have no concrete module specs to point at.
- *Con:* Runtime Enforcement Profile (Draft 8) describes module-extensible enforcement but the extension points have no specs at submission time.
- *Con:* The "interoperable optional capability" language in the Capability Model (Draft 11) describes Level 5 with deferred concrete requirements.

**Option B: include all six modules in the initial set (17 drafts).**

- *Pro:* Complete picture from day one; Level 5 is implementable from the spec set.
- *Con:* 17 drafts from a single independent author is a lot. IESG and area directors typically prefer focused submissions.
- *Con:* Not all modules are equally ready:
  - **Tool Binding**: design is stable (binds tool invocation to actor identity via `tool_id`). Ready to spec.
  - **Purpose Registry**: small and well-defined (registry of purposes referenced by `purpose` URI in Mission Intent). Ready to spec.
  - **Decision Receipt**: overlaps with W3C verifiable-credential work and existing receipt formats. Design needs coordination with adjacent communities. Not yet ready.
  - **Attestation**: depends on ACAP (`draft-yakung-oauth-agent-attestation`) advancing. Can't ship faster than ACAP.
  - **Policy Projection**: most architecturally open (Cedar vs OpenFGA vs canonical input bundle vs engine-native artifact). Specifying before implementers have picked an approach picks a winner that may be wrong.
  - **Actor Provenance**: not in the Optional Modules list; already covered by `draft-mcguinness-oauth-actor-profile`. The Runtime Enforcement Profile composes with that existing draft.
- *Con:* Drafting modules before implementation interest produces mediocre specs that get rewritten.

**Option C: include the mature subset; defer the speculative ones (14 drafts).**

- *Pro:* Ships modules with stable designs (Tool Binding, Purpose Registry, Actor Provenance); defers the speculative ones (Decision Receipt, Attestation, Policy Projection).
- *Pro:* Level 5 has concrete spec targets for the three included modules.
- *Pro:* Initial set grows to 14, still manageable.
- *Con:* Picking the cutoff is a judgment call. "Mature enough" is subjective.
- *Con:* Three additional drafts to write before initial publication.

**Option D: bundle all six modules into one combined "Runtime Optional Modules" draft (12 drafts).**

- *Pro:* One additional draft instead of six.
- *Con:* Combined drafts get long and harder to review.
- *Con:* Each module advances at a different pace; bundling slows the fast ones.
- *Con:* IESG typically prefers focused drafts over omnibus.

**Recommendation: Option A.** The Optional Modules are an architectural extension point; specifying them before there are implementers using them produces specs that won't survive contact with reality. The Runtime Enforcement Profile (Draft 8) describes the extension contract; the Capability Model (Draft 11) describes Level 5 in terms of "interoperable specifications for each claimed optional capability." That's an honest description: when a module reaches enough maturity for interop claims, it gets its own spec.

If you have a specific module with near-term implementation interest (e.g., a Tool Binding deployment that wants a spec to align on), we can promote that module to the initial set without changing the rest of the plan.

## Next Step

All decisions are now resolved. The drafting plan starts with Phase 1: the implementable pair (Framework + OAuth Profile). Goal is implementation-readiness, not IETF submission.

Draft 1 (Mission Framework) ships when an implementer can read it and build:

- The Mission record with the three integrity hashes (correct JCS canonicalization, SHA-256 output).
- The Mission Intent JSON validator.
- The lifecycle state machine.
- The Common Constraints catalog entries.
- The abstract Mission Status interface.

The deliverable includes reference test vectors: a canonical Mission Intent input, the expected `proposal_hash` output, the expected canonical bytes, the expected state-machine transitions. Without test vectors, "implementable" is aspirational.

Draft 2 (OAuth Profile) ships when an implementer can read it and build a Mission-Bound OAuth AS that accepts `mission_intent` at PAR, issues `mission`-claim tokens, gates refresh and exchange on Mission state, and surfaces Mission Status via introspection. Both drafts use the worked board-packet scenario from the blog as the consistent example.

Reference implementation alongside: a thin OAuth AS + Framework library that passes the test vectors and demonstrates the wire shapes. The implementation is the test that the specs are concrete enough to build from. Specs without an implementation that exercises them are not yet baked.

I will start with Draft 1. First version produces a complete `-00` for review; subsequent versions iterate based on what implementation exposes.
