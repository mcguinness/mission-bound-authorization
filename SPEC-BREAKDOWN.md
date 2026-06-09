# Mission-Bound Authorization: Draft Roadmap and Spec Breakdown

This document defines what becomes a standards-track Internet-Draft, what stays in the [blog series](https://notes.karlmcguinness.com/series/mission-bound-authorization/), and the dependency order for drafting.

## First Deliverable: Vertical Slice

Rather than writing the full 35-45 page Framework first, the first deliverable is a **vertical implementation slice** co-developed with a reference implementation:

1. **Core Model** (subset of Framework):
   - Mission **Proposal** (pre-approval) vs Mission (approved) lifecycle.
   - Principal model (subject, approving principal, requesting client, tenant, state authority, delegation policy).
   - Typed Authority Set entries with explicit equality/subset/intersection rules.
   - Canonical Mission ID. Pairwise references are deferred to the second interoperability slice.
   - Semantic normalization followed by domain-separated integrity hashes.
   - Abstract Mission Status semantics (authentication/integrity/freshness/audience properties, not a specific signing format).

2. **OAuth Binding** (subset of OAuth Profile):
   - `mission_intent` authorization request parameter, required to be submitted through PAR in this profile.
   - `mission_resource_access` RAR representation.
   - `mission` token claim.
   - Sender constraint.
   - Refresh and exchange gating.
   - Dedicated Mission Status operation + optional introspection projection.
   - Revocation behavior for already-issued credentials.
   - AS metadata and error codes.

3. **Conformance package**:
   - JSON Schemas (Mission Intent, Authority Set, Mission Status response).
   - Positive and negative validation vectors.
   - State-transition tests (Proposal → Mission → lifecycle).
   - Authority-Set narrowing tests.
   - Semantic-normalization, JCS canonicalization, and hash vectors.
   - Race, replay, stale-state, unauthorized-status-lookup, malformed-JSON, and narrowing-failure tests.
   - One AS, one client, and two Resource Servers end-to-end.

The two-AS same-IdP scenario is the **second interoperability slice**. It adds ID-JAG, Identity Continuation Assertions, subject mapping, pairwise references, and cross-AS consistency only after the single-AS baseline is stable.

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
| RFC 7009 | OAuth 2.0 Token Revocation | Draft 2 (cascaded token revocation when a Mission is revoked); Mission revocation itself is a separate operation defined by Draft 2's Mission lifecycle endpoint, not by RFC 7009. |
| RFC 7519 | JSON Web Token (JWT) | Draft 2 (Mission claim format) |
| RFC 7591 | OAuth 2.0 Dynamic Client Registration | Draft 2 (client declaring Mission Intent capabilities) |
| RFC 7592 | OAuth 2.0 Dynamic Client Registration Management | Draft 2 (informative) |
| RFC 7662 | OAuth 2.0 Token Introspection | Draft 2 (optional Mission snapshot in token introspection; not the Mission Status operation) |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata | Draft 2 (Mission capability advertisement) |
| RFC 8693 | OAuth 2.0 Token Exchange | Drafts 2, 6 (Mission-state-gated derivation) |
| RFC 8705 | OAuth 2.0 Mutual-TLS Client Authentication | Drafts 2, 6 (sender constraint) |
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens | Draft 2 (`mission` claim placement) |
| RFC 9126 | OAuth 2.0 Pushed Authorization Requests | Draft 2 (`mission_intent` authorization request submission through PAR) |
| RFC 9396 | OAuth 2.0 Rich Authorization Requests | Draft 2 (`mission_resource_access` RAR type) |
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | Drafts 2, 6 (sender constraint) |
| RFC 9700 | Best Current Practice for OAuth 2.0 Security | Draft 2 Security Considerations |
| RFC 9728 | OAuth 2.0 Protected Resource Metadata | Drafts 2, 8 (RS tier advertisement); also relates to `draft-mcguinness-oauth-rfc9728bis` |

### Step-up and identity chaining

| Spec | Title | Used by |
| --- | --- | --- |
| RFC 9470 | OAuth 2.0 Step-up Authentication Challenge | Draft 2 (satisfying an `aal` constraint; not Mission Expansion), Draft 1 (`aal` constraint) |
| `draft-ietf-oauth-identity-chaining` | Identity Chaining across Trust Domains | Drafts 2, 7 (cross-trust-domain Mission carriage) |
| `draft-ietf-oauth-identity-assertion-authz-grant` (ID-JAG) | Identity Assertion Authorization Grant | Draft 2 (same-IdP identity assertion for Resource ASes) |

### Cryptographic and serialization primitives

| RFC | Title | Used by |
| --- | --- | --- |
| RFC 6234 | US Secure Hash Algorithms (SHA-256) | Draft 1 (integrity anchor algorithm) |
| RFC 7515 | JSON Web Signature (JWS) | Drafts 2, 7 (profile-level signed responses). OAuth Profile uses RFC 9701 only for the optional token-introspection projection; the dedicated Mission Status operation defines its own response media type and protection profile. MAS uses JWS-signed Mission Status. Framework defines abstract signing requirements only. |
| RFC 7517 | JSON Web Key (JWK) | Drafts 2, 7 (profile-level key publication) |
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

This document defines the Mission as a durable, integrity-anchored, lifecycle-governed governance object for an approved task. It defines the abstract types, interfaces, and behaviors that profile specifications map onto specific substrates: Mission Proposal and Mission lifecycles, the Mission Intent JSON schema, typed Authority Set, integrity anchors (with domain-separated hash inputs), canonical and pairwise identifier model, common constraints framework, Mission Status interface, principal model, evidence binding, and capability-advertisement metadata. The framework is substrate-neutral on semantics; profile specifications for OAuth, AAuth, and the Mission Authority Server compose this framework with their respective wire substrates and pick the concrete protection mechanism.

### What this spec defines

- **Mission Proposal vs Mission distinction.** A **Mission Proposal** is the pre-approval object created when a client submits Mission Intent. It has its own lifecycle: `pending_approval`, `rejected`, `withdrawn`, `expired_as_pending`. A **Mission** is created at the moment of approval and has its own lifecycle: `active`, `suspended`, `revoked`, `completed`, `expired`. The two are distinct records with distinct identifiers (a `proposal_id` and, only on activation, a `mission.id`). This resolves the prior contradiction where a "Mission" was claimed to exist before approval despite the litmus test requiring approval.
- **Mission Intent JSON schema**: structured task proposal carried by Mission Proposal. Fields: `goal`, `objects`, `constraints`, `success_criteria`, `mission_expiry`, optional `purpose`, optional `context`. Profiles define transport; the schema is owned here.
- **Principal model.** Mission and Mission Proposal records explicitly carry:
  - `subject` / `beneficiary`: the principal on whose behalf the task is approved.
  - `approving_principal`: the principal who approved the Mission (may differ from subject for delegated approval; covers headless approval anchors too).
  - `requesting_client`: the OAuth client or AAuth agent that submitted the Proposal.
  - `tenant` / `authorization_domain`: the tenant identifier the Mission lives in.
  - `state_authority`: the AS, PS, or MAS that owns the Mission record.
  - `delegation_policy`: the stable bounds under which actors may derive or exercise authority.

  The current `actor_chain` is dynamic execution context and therefore does **not** live in the canonical Mission record. It is carried by derived artifacts and runtime requests, composing with `draft-mcguinness-oauth-actor-profile`. Subject identifiers can differ at each hop; the applicable identity authority is authoritative for mapping them.

- **Typed Authority Set entries.** Each entry has explicit type metadata:
  ```json
  {
    "type": "mission_resource_access",
    "specification_uri": "https://example.com/specs/mission_resource_access/v1",
    "schema_digest": "sha-256:<base64url>",
    "schema_version": "1",
    "authority": { ... type-specific payload ... },
    "narrowing_profile": "default"
  }
  ```
  The Framework defines a type registry. Each registered type provides an immutable specification reference or schema digest plus deterministic normalization, equality, subset, intersection, and unknown-field rules. Loose `resource/actions/constraints` is the payload shape of one type (`mission_resource_access`), not the universal shape.

  **`schema_digest` format.** The value is `"sha-256:" || base64url(SHA-256(canonical schema bytes))`, parallel to the integrity-anchor hash format. The "canonical schema bytes" are the JCS-canonicalized representation of the JSON Schema document. Future digest algorithms register with prefixes like `sha-384:`; consumers MUST reject digests using unregistered prefixes.

- **Lifecycle state machines** (two, not one):
  - **Mission Proposal lifecycle**: `pending_approval` → (`approved` → transitions to Mission) | `rejected` | `withdrawn` | `expired_as_pending`.
  - **Mission lifecycle**: `active` → (`suspended` ⇄ `active`) | `revoked` | `completed` | `expired`. Mission begins at `active` on activation; there is no Mission record in any earlier state.

- **Semantic normalization and integrity hashes.** JCS canonicalizes JSON syntax but does not make semantically equivalent values identical. Before JCS, each committed object is normalized under its registered normalization profile. The profile defines:
  - array ordering and duplicate handling;
  - Unicode normalization policy;
  - URI normalization or exact-comparison rules;
  - absent-member versus empty-member semantics;
  - rejection of duplicate JSON object member names before parsing into the data model.

  After normalization, hash inputs are domain-separated and authorization-domain-bound:
  ```
  SHA-256(JCS({
    "type": "mission-intent",
    "schema_version": 1,
    "authorization_domain": "tenant-or-domain-id",
    "state_authority": "https://as.example.com",
    "value": <normalized content>
  }))
  ```
  - `proposal_hash`: over the approved Mission Intent (wrapped with `type=mission-intent`).
  - `authority_hash`: over the approved Authority Set (wrapped with `type=mission-authority-set`).
  - `consent_disclosure_hash`: over the structured consent disclosure object (wrapped with `type=mission-consent-disclosure`). **Renamed from `consent_rendering_hash`** because the hash covers the disclosure object, not rendered output.

  Binding hashes to the authorization domain and state authority prevents cross-tenant or cross-authority transplantation and avoids leaking equality across unrelated domains. JCS (RFC 8785) is the final syntactic canonicalization; SHA-256 is the digest; base64url is the encoding.

- **Identifier model: canonical + pairwise.**
  - **Canonical Mission ID** (`mission.id`): stable opaque identifier held by the state authority. Used internally and by authorized auditors.
  - **Pairwise Mission Reference** (`mission.ref`): audience-sector-specific identifier surfaced to consumers instead of the canonical ID. Each pairwise reference resolves to the canonical ID only at the state authority.
  - **Mapping authority**: the state authority owns the canonical → pairwise map. No other party can independently derive one from the other.
  - **Pairwise sector**: the state authority defines whether the sector is a Resource Server, Resource AS, tenant, or trust domain and advertises that choice in metadata. References are at least 128 bits of opaque entropy and contain no audience label or correlatable input.
  - **Rotation**: references are stable for the Mission lifetime within a sector. Rotation creates an alias period sufficient for outstanding credentials, then retires the old reference. Retired references are never reassigned.
  - **Correlation authorization**: defines which parties are entitled to resolve pairwise references (typically: authorized auditors, the state authority itself, regulators in defined jurisdictions). Default-deny for everyone else.
  - **Audit export behavior**: when audit records are exported across organizational boundaries, the export controller selects either canonical or pairwise references per recipient policy.

  `mission.origin` identifies the state authority (and resolves to its metadata document). It is not a separate audience-pairwise quantity; it is the discovery anchor for resolving references.

- **Abstract Mission Status semantics** (not a specific signing format). The Framework defines:
  - **Operation**: by-mission-reference query (input: canonical or pairwise mission reference; output: state, integrity hashes, audience-filtered Authority Set projection, `policy_version`, `iat`, freshness indicator). Distinct from token introspection.
  - **Authentication property**: responses MUST carry an integrity signal whose source is the state authority. The Framework does not pick the wire format. Profiles bind to substrate-appropriate mechanisms.
  - **Freshness property**: responses MUST indicate when the state was current. Profiles bind to substrate-appropriate freshness semantics.
  - **Audience property**: responses MUST be addressable to the requesting consumer (so the response can't be replayed against a different audience).
  - **Integrity property**: the response payload and its hash chain back to the canonical Mission record MUST be verifiable.
  - **Anti-oracle property**: possession of a Mission reference is not authorization. The caller is authenticated and authorized for the requested reference and audience. Unknown and unauthorized references produce indistinguishable responses.
  - **Request-binding property**: signed responses bind the caller, requested Mission reference, audience, and a caller-provided nonce or equivalent request identifier.
  - **Caching property**: every response declares `issued_at`, `expires_at`, and maximum tolerated staleness. Consumers fail closed after expiration unless a profile explicitly defines a bounded degraded mode.

  Profile bindings:
  - OAuth Profile composes with **RFC 9701** only for the optional token-introspection projection.
  - The dedicated by-mission-reference operation defines its own authenticated response representation and media type because RFC 9701 applies specifically to token introspection.
  - AAuth Profile composes with AAuth's native signing.
  - MAS Profile defines its own signed Mission Status binding.

- **Common Constraints framework + initial entries.** The Framework defines a **constraint extension framework**: registry with `name`, `type`, immutable specification reference, optional schema digest, schema version, normalization/equality/subset/intersection rules, narrowing rules, and enforcement contract. Initial fully specified entries:
  - **`max_derivations`**: nonnegative decimal-string count of credential derivation events. Enforced atomically by the credential issuer or state authority.
  - **`aal`**: required authentication assurance level (composes with RFC 9470's AAL signaling). Freshness window is required.

  Invocation budgets are runtime constraints, not issuance constraints. **`max_invocations`** is deferred to the Runtime Enforcement Profile, where an authoritative atomic counter can observe execution attempts. Other constraint names sketched in the blog (`max_value`, `max_duration`, `geo`, `data_classification`) remain future work. The Framework ships the extension mechanism, not underspecified names.

- **Trust boundaries**: who is trusted for what (Shaper, state authority, credential issuer, PDP, evidence emitter). Profiles populate these roles for their substrate.

- **Reference test vectors** as a first-class spec deliverable. For each canonicalization and hash output: input JSON → expected JCS canonical bytes (hex) → expected hash (base64url). Plus state-transition vectors and narrowing-rule vectors. An implementation that does not reproduce the test vectors is non-conformant.

- **Normative vocabulary**: Mission Proposal, Mission, Mission Intent, Authority Set, Projection, Runtime Decision, Evidence.

### Concrete shapes for the vertical slice

These shapes are pinned here so implementer ambiguity is resolved across the Framework + OAuth vertical slice. Ownership is explicit below: Framework-owned shapes become Draft 1 requirements; OAuth-owned shapes become Draft 2 requirements.

**Pairwise Mission Reference format**: `mission.ref` is an opaque URL-safe string containing at least 128 bits of entropy. It contains no audience label, tenant name, canonical-ID derivative, or other correlatable input. The state authority binds the opaque reference to an advertised pairwise sector type: Resource Server, Resource AS, tenant, or trust domain.

Resolution: a consumer presents a pairwise reference to `mission.origin` over an authenticated channel; the state authority returns Mission Status if the consumer is authorized for that audience.

**`narrowing_profile`**: a URI value referencing a named narrowing profile. Default value `urn:mbo:narrowing:default-v1` which mandates set-inclusion subset for arrays, key-set inclusion for objects, and refusal on unknown machine-enforceable constraints. Alternative profiles register their narrowing rules in the Authority Set Type registry.

**Approval event semantics**: an "approval event" is a state-authority-initiated atomic transition from Proposal to Mission upon receiving a binding consent signal. The consent signal is substrate-specific:
- OAuth: user approval at the authorization endpoint or admin approval through an out-of-band approval workflow.
- AAuth: native PS approval.
- MAS: MAS-mediated consent rendering.

At the approval event the state authority records the principal-model evidence (approving principal identity, AAL, timestamp, consent disclosure object) atomically with Mission record creation. The operation is idempotent on `proposal_id` and approval-event identifier. Exactly one Mission may be created from a Proposal. Concurrent approve, reject, withdraw, and expiry operations are serialized with compare-and-set semantics. If the state authority cannot complete the atomic commit, the Proposal remains `pending_approval`; no partial Mission record exists. The resulting Mission permanently records its source `proposal_id`.

The Proposal record is retained alongside its resulting Mission for the same audit retention window as the Mission (per the retention rule in Resolved Decisions). After retention, the Proposal record MAY be garbage-collected with the Mission record. `proposal_id` MUST NOT be reused after garbage collection. Terminal-state Proposals (rejected, withdrawn, expired_as_pending) follow a deployment-defined Proposal-only retention policy that is independent of Mission retention.

**`policy_version`**: a string in the Mission record indicating the version of the state authority's derivation policy that was applied at approval. Format: `{policy_namespace}:{policy_id}@{version}` (e.g., `as.example.com:standard@2026-06-01`). Distinct from Resource policy version (which lives at the Resource AS) and PDP policy materialization version (which lives at the PDP). The Mission record's `policy_version` is the derivation policy that produced the Authority Set.

**`mission.origin` resolution**: an HTTPS URL identifying the state authority's issuer. Resolution: the state authority publishes a metadata document at `{mission.origin}/.well-known/mission-authority` (per RFC 8615 well-known URI conventions). The metadata document follows an RFC 8414-shaped structure and includes:
- `issuer` (matches `mission.origin`)
- `jwks_uri` (state authority's public keys for response signing)
- `mission_status_endpoint`
- `mission_lifecycle_endpoint`
- `mission_intent_schema_uri`
- `authority_set_types_supported`
- `mission_pairwise_supported` (boolean)
- substrate-specific extensions

**Mission Expansion ticket**: an opaque, single-use, time-limited bearer token. Default eligibility window: 300 seconds. Holder presents the ticket at the expansion request endpoint (per Mission Expansion, Draft 3). Tickets MUST be cryptographically unpredictable, MUST NOT be reused, and MUST be invalidated on first use or expiry.

**Consent disclosure object schema**:
```json
{
  "mission_intent_canonical_hash": "<base64url SHA-256 of JCS-canonical Mission Intent>",
  "authority_set_canonical_hash": "<base64url SHA-256 of JCS-canonical derived Authority Set>",
  "locale": "en-US",
  "template_id": "urn:example:consent-template:standard",
  "template_version": "2026-06-01",
  "material_notices": [
    { "notice_id": "data-classification", "text": "This task accesses confidential records." }
  ],
  "presented_at": "2026-06-08T17:30:00Z",
  "principal_assurance": {
    "aal": "AAL2",
    "amr": ["pwd", "otp"],
    "auth_time": "2026-06-08T17:25:00Z"
  }
}
```

`consent_disclosure_hash` is computed after semantic normalization over the authorization-domain-bound envelope defined above.

**OAuth Profile-owned: `mission` JWT claim shape, canonical mode**:
```json
{
  "mission": {
    "id": "msn_01J9Z2P8BQ4Y3F0V0K9D6Z7M1",
    "origin": "https://as.example.com",
    "authority_hash": "sha-256:<base64url>",
    "version": 1
  }
}
```
- `id`: canonical Mission ID. URL-safe ASCII, max 256 bytes. Required in canonical mode.
- `origin`: state authority issuer URL. Required.
- `authority_hash`: integrity anchor for the Authority Set from which this credential was projected. Required.
- `version`: Mission record version used for issuance. Required.

**Pairwise mode** replaces `id` with `ref`; it never emits both:
```json
{
  "mission": {
    "ref": "opq_mW8Jx...128-bits-or-more",
    "origin": "https://as.example.com",
    "authority_hash": "sha-256:<base64url>",
    "version": 1
  }
}
```

The token audience determines which pairwise sector applies. Refresh preserves the reference when the audience and sector are unchanged. Token Exchange mints the reference appropriate to the target audience and MUST NOT copy an upstream pairwise reference into a different sector. Opaque tokens expose the same logical members through introspection.

**OAuth Profile-owned: `mission_resource_access` payload shape** (one instance of a typed Authority Set entry):
```json
  {
    "type": "mission_resource_access",
    "specification_uri": "https://mcguinness.github.io/mission-bound-authorization/specs/mission_resource_access-v1",
    "schema_digest": "sha-256:<base64url>",
    "schema_version": "1",
  "authority": {
    "resource": "https://docs.example.com",
    "actions": ["documents.read", "documents.write"],
    "constraints": {
      "folder": "board-materials",
      "data_classification": "confidential"
    }
  },
  "narrowing_profile": "urn:mbo:narrowing:default-v1"
}
```

Narrowing rules for `mission_resource_access` under the default profile:
- `resource`: exact-match equality (string).
- `actions`: subset = set-inclusion (every derived action is in the approved set).
- `constraints`: every key in the derived `constraints` MUST be present in the approved `constraints`; values narrow per constraint-key rules from the Common Constraints registry; unknown keys at derivation time are refused unless a registered constraint type defines pass-through semantics.

**Framework-owned floor with profile-owned bindings: Mission Status request authentication and authorization**:
- Request MUST be authenticated. The Framework does not pick the mechanism.
- The state authority MUST authorize the authenticated caller for the requested Mission reference and audience. A reference is never a bearer capability.
- A request carries a nonce or equivalent unique request identifier. The protected response binds the caller identity, requested reference, audience, and nonce.
- OAuth Profile MUST permit at minimum: (a) `client_credentials`-authenticated request with the state authority, OR (b) mTLS-authenticated request with the state authority, OR (c) DPoP-bound bearer token issued by the state authority for status queries.
- AAuth Profile: AAuth-native signed-request authentication.
- MAS Profile: explicit RP-style authentication using the MAS metadata document's registered client credentials.

**Framework-owned semantics with profile-owned transport: Mission Status error model**:

| Code | Symbol | Meaning |
|---|---|---|
| 200 | `ok` | Mission found and visible. Response carries state. |
| 401 | `unauthorized` | Request not authenticated. |
| 404 | `not_found` | Mission reference does not exist **or** is not visible to this consumer. These cases are intentionally indistinguishable. |
| 410 | `terminated` | Mission is in a terminal state. Response includes state. |
| 423 | `suspended` | Mission is suspended. Response includes state. |
| 429 | `rate_limited` | Consumer is rate-limited. |
| 503 | `unavailable` | State authority temporarily can't serve status. |

Consumers distinguish authentication failure (401) from Mission-state-based responses (410/423). They MUST NOT be able to distinguish an unknown Mission from a known but unauthorized Mission. A terminal Mission is "found" only for an authorized caller.

**Reference test vectors enumeration**: the Framework spec MUST publish, alongside the spec text:

1. **Semantic-normalization and JCS vectors**: ≥20 input JSON objects → expected normalized data model → expected JCS bytes. Covers array ordering, duplicate elements, duplicate object member rejection, absent versus empty members, URI comparison, number formatting, key ordering, escapes, Unicode policy, nested objects, arrays, and nulls.
2. **Domain-separated and authorization-domain-bound hash vectors**: input value → normalized wrapped input → expected SHA-256 hash. Includes negative cross-tenant and cross-authority transplantation cases.
3. **State-transition vectors**: full state-machine traversals for Mission Proposal and Mission lifecycles, including invalid transitions that MUST be refused.
4. **Authority Set narrowing vectors** per registered type. For `mission_resource_access`: approved entry + derived entry → expected accept/refuse classification.
5. **Mission Status vectors**: authenticated request → expected response shape for success, stale state, replayed nonce, wrong audience, unknown reference, and unauthorized reference. Unknown and unauthorized cases MUST be observationally equivalent.
6. **`mission` claim vectors**: Mission record → expected claim shape including canonical and pairwise variants.

Vectors are JSON files in a `vectors/` directory in the repo, named `{spec_short_name}-{class}-{n}.json`. Each vector includes `description`, `input`, `expected_output`, and `notes` fields. License: CC0 (public domain) so vectors can be embedded in any implementation.

**Spec revision and compatibility advertisement**:
- Each spec ships with a `spec_version` identifier (e.g., `draft-mcguinness-mission-framework-00`).
- Implementations advertise supported spec versions in the state authority's metadata document via `mission_framework_versions_supported`.
- Internet-Draft revision numbers do not imply semantic compatibility. Every revision declares compatibility with prior revisions explicitly.
- Incompatible revisions use distinct advertised identifiers and require explicit consumer agreement.

### Key normative requirements (abstract)

- A Mission MUST satisfy the litmus test (durable, integrity-anchored, lifecycle-governed, identifier-stable, reference-bearing, derived-authority). A Mission record exists only after activation; pre-approval state is held in a Mission Proposal record.
- A Mission Proposal MUST be promoted to a Mission by an explicit state-authority approval event; rejected/withdrawn/expired Proposals MUST NOT become Missions.
- A state authority MUST normalize committed objects according to their registered normalization profile, then compute `proposal_hash`, `authority_hash`, and `consent_disclosure_hash` over domain-separated, authorization-domain-bound JCS inputs, SHA-256, base64url-encoded.
- A state authority MUST produce byte-identical JCS output to the reference test vectors published with this spec.
- A Mission record MUST carry binding evidence (signer identity, timestamp, policy version, schema version, disclosure template version, approving principal) alongside the integrity hashes.
- A Mission record MUST carry the stable principal-model fields (`subject`, `approving_principal`, `requesting_client`, `tenant`, `state_authority`, `delegation_policy`). Dynamic actor chains MUST be carried by projections and runtime requests, not stored as mutable Mission state.
- A Mission MUST be in `active` state to permit new derivation; every non-active state refuses.
- A state authority MUST expose a by-mission-reference Mission Status operation distinct from token introspection. Responses MUST satisfy the authentication, freshness, audience, and integrity properties defined in this spec. Profiles specify the wire format and protection mechanism.
- Authority Set entries MUST carry explicit `type`, immutable `specification_uri` or `schema_digest`, `schema_version`, and `authority` fields. Normalization, equality, subset, intersection, and unknown-field rules MUST be those registered for the type.
- Constraint values that require precision MUST use string representation in JCS-canonical form, not JSON number representation.
- Pairwise Mission references MUST be resolvable to the canonical Mission ID only at the state authority. Other parties MUST NOT be able to derive the canonical ID from a pairwise reference.
- A profile MUST specify how each Framework element manifests on its substrate, including the chosen wire format for Mission Status protection.
- A profile MAY define minimum extension points required for that binding (new parameters, claims, error codes); a profile MUST NOT enlarge the Framework semantics.

### IANA Considerations

Registry-by-registry audit required. The previous draft of this section claimed registrations that don't track real registries; corrected here:

- **Mission Common Constraints registry**: new IANA registry to be created. Defines registry policy, immutable specification reference, schema digest where applicable, normalization and narrowing rules, and runtime contract. Initial entries: `max_derivations` and `aal`.
- **Mission Authority Set Type registry**: new IANA registry. Defines registry policy, immutable specification reference or schema digest, normalization/equality/subset/intersection/unknown-field rules, and initial entry (`mission_resource_access`).
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
- Mission Status enumeration and authorization-oracle resistance.
- Hash equality leakage and cross-tenant transplantation.
- **JCS implementation correctness as a deployment risk.** Implementations that produce byte-divergent canonical output produce divergent hashes and break the content-addressability that the rest of the architecture depends on. Mitigation: the spec's reference test vectors. An implementation that does not reproduce the test vectors byte-for-byte is non-conformant. Where possible, deployments SHOULD use known-good JCS libraries rather than rolling their own.
- **Protection-key management.** Profile-selected signing or authentication keys are load-bearing for Mission Status authenticity. Profiles define publication, rotation, identifier, and continuity rules appropriate to their protection mechanism.
- **Number precision under JCS.** IEEE 754 double precision applies to JSON numbers under JCS. Constraint values where precision matters MUST use string representation (e.g., `"max_derivations": "100"`), not number representation.

### Normative references

RFC 8785 (JCS), RFC 8174 (BCP 14 update), RFC 6234 (SHA-256). JWS, JWK, JWA, JWT are referenced informatively from the Framework; profiles make them normative where they're used for protection.

### Informative references

Series blog posts as background; profile drafts as consumers.

---

## Draft 2: `draft-mcguinness-mission-oauth-profile`

**Mission-Bound OAuth Profile**

**Layer:** Profile. **Category:** Standards Track. **Target WG:** OAUTH. **Status:** New. **Depends on:** Draft 1.

### Abstract

This profile defines how a deployment composes OAuth 2.0 (RFC 6749), Rich Authorization Requests (RFC 9396), Pushed Authorization Requests (RFC 9126), Token Exchange (RFC 8693), DPoP (RFC 9449), and mTLS (RFC 8705) with the Mission Framework. A client submits the `mission_intent` authorization request parameter through PAR; the Authorization Server validates and renders it, creates a Mission on approval, derives `authorization_details`, and binds issuance, refresh, and Token Exchange to Mission state. Tokens carry a complete `mission` claim referencing the governance record.

### What this profile composes

- **OAuth 2.0 (RFC 6749)** as the credential substrate.
- **PAR (RFC 9126)** as the Mission Intent submission point.
- **RAR (RFC 9396)** as the Authority Set wire serialization. Defines the `mission_resource_access` RAR type.
- **Token Exchange (RFC 8693)** as the derivation path that gates on Mission state.
- **DPoP (RFC 9449)** or **mTLS (RFC 8705)** as the sender-constraint mechanism.
- **The Mission Framework (Draft 1)** for Mission record semantics, integrity anchors, lifecycle, constraints vocabulary, and Mission Status interface.

### What this profile defines on the OAuth wire

- **`mission_intent` authorization request parameter.** The parameter is defined for authorization requests and this profile requires it to be submitted through PAR. The profile specifies UTF-8 JSON serialization inside `application/x-www-form-urlencoded`, percent-encoding, duplicate-parameter rejection, duplicate-JSON-member rejection, maximum supported size advertisement, Request Object behavior, and whether the authorization endpoint accepts it outside a PAR `request_uri` flow.
- **`mission_resource_access`** RAR type as one Framework Authority Set type, with immutable specification reference or schema digest, schema version, normalization, and narrowing rules. RFC 9396 does not provide an IANA registry of RAR types; the profile documents this descriptively.
- **`mission`** claim on JWT access tokens (registered in the IANA JWT Claims Registry).
- **`mission_inactive`** error code for refresh/exchange denial.
- **Mission Expansion eligibility signaling on the OAuth wire, after Draft 3 stabilizes**: a coordinated revision adds the OAuth binding. The baseline `-00` does not define expansion fields ahead of their owning feature specification.
- **Dedicated Mission Status operation** (by mission reference) plus an **optional introspection projection** (RFC 7662 extended to return a Mission snapshot for the queried token). These are different operations:
  - The dedicated operation takes a Mission reference (canonical or pairwise) and returns Mission state.
  - The introspection extension takes a token and returns its claims, including a Mission snapshot if the token references a Mission.
  - The introspection projection may use **RFC 9701 signed introspection responses**.
  - The dedicated operation defines a new Mission Status response media type and protection profile because RFC 9701 applies only to token introspection. The response binds the caller, Mission reference, audience, nonce, `issued_at`, and `expires_at`.
- **Mission lifecycle operations on OAuth endpoints**: revoke, suspend, resume, complete by mission reference. **Distinct from RFC 7009 token revocation.** The profile defines the lifecycle endpoint and four enforcement classes:
  - **Issuance gating**: blocks refresh, exchange, and new issuance.
  - **Introspection gating**: introspection reports tokens inactive when Mission state disallows use.
  - **Event-driven invalidation**: SSF/CAEP or equivalent pushes state changes to Resource Servers.
  - **Per-request status**: high-assurance Resource Servers query or validate sufficiently fresh Mission state for each consequential request.

  A deployment advertises its supported enforcement classes and maximum tolerated stale interval. Mission revocation does not claim to invalidate an offline self-contained token immediately unless event-driven or per-request enforcement is deployed.

  **Recommended access-token TTL.** For deployments where Mission revocation propagation matters but only issuance gating is deployed (i.e., no event-driven or per-request enforcement), Mission-Bound access tokens SHOULD use a TTL shorter than the deployment's maximum tolerated stale interval. Standard OAuth defaults (1 hour) may be too long; deployments that rely on revocation propagation through token expiry SHOULD use TTLs aligned with their stated stale-interval bound, typically minutes. Deployments with event-driven or per-request enforcement may use longer TTLs because revocation propagates out-of-band.

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

- `mission_intent` authorization request parameter in the OAuth Parameters registry, if that registry's applicable namespace and registration policy support it.
- `mission` JWT claim.
- `mission_inactive` error code.
- Mission Expansion error-response members are added only in the coordinated post-Draft-3 revision.
- Mission Status introspection extension.
- Dedicated Mission Status response media type and associated OAuth metadata members.

`mission_resource_access` is not listed as an IANA registration because RFC 9396 does not define a registry for RAR type values.

---

## Draft 3: `draft-mcguinness-mission-expansion`

**Mission Expansion**

**Layer:** Feature. **Category:** Standards Track. **Submission venue:** to be determined between IETF OAUTH, OpenID AuthZEN, or independent publication based on where the stable wire binding lands. **Status:** New. **Depends on:** Draft 1 and OpenID AuthZEN Access Request.

### Abstract

This document defines the governance expansion mechanism for Mission-Bound Authorization. When an action falls outside the Authority Set of an active Mission but is eligible for governed expansion, this spec defines (substrate-neutrally) the eligibility-signaling semantics, the expansion-request workflow, the binding of the successor Mission to the prior Mission, and the reconciliation rules for concurrent expansion. The substrate-specific wire bindings for eligibility signaling live in the substrate profiles (OAuth Profile defines the OAuth binding; AAuth Profile defines the AAuth binding).

### What this spec defines (substrate-neutral semantics)

- **Eligibility-signaling abstract contract**: the fields a substrate-specific denial MUST surface when expansion is eligible (`eligible`, `access_request_uri`, `ticket`, `requested_authority`). Profiles bind these to substrate-specific transport.
- **Expansion request workflow via AuthZEN Access Request**: how the orchestrator submits the access request with the ticket, how the state authority adjudicates, how the result is communicated.
- **Workflow outcomes**: synchronous approved, asynchronous approved, denied, expired.
- **Successor-Mission binding and mode**:
  - **Replacement expansion** creates a successor that carries explicitly approved unchanged authority plus the approved addition. On activation, the predecessor becomes `completed` and new derivation occurs only from the successor.
  - **Branch expansion** creates a separately scoped child Mission while the predecessor remains active. It is used when replacing the predecessor would unnecessarily invalidate unrelated authority.
  - The request declares the mode; state-authority policy may narrow or refuse it. `mission.predecessor` and `mission.expansion_mode` preserve lineage.
  - Replacement activation is atomic: failed activation leaves the predecessor active; successful activation completes it. Credentials bound to the completed predecessor follow the deployment's advertised stale-state enforcement class and are never silently rebound to the successor.
  - Branch credentials remain independent: predecessor credentials retain predecessor authority, and child credentials carry only authority explicitly approved for the child.
  - Rollback after activation is a new governed transition or expansion; implementations do not resurrect the predecessor implicitly.
- **Concurrent expansion reconciliation**: rules for when more than one expansion request is in flight for the same Mission.

### What this spec does NOT define

- Substrate-specific wire bindings for eligibility signaling → OAuth Profile (Draft 2) and AAuth Profile (Draft 6) each define their binding.
- How Resource ASes detect out-of-bounds requests → Delegated Authority Validation (Draft 4).

### IANA Considerations

- `mission.predecessor` and `mission.expansion_mode` attributes.
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
- Resource AS responsibilities in the handoff: examine only the minimized requested authority and audience-filtered Mission projection needed for local ontology validation, determine eligibility classification, and signal expansion eligibility per Mission Expansion contract (Draft 3).
- Trust establishment between Resource AS and originating AS (the originating AS trusts the Resource AS's classification because the Resource AS owns the ontology; the Resource AS trusts the originating AS's Mission record because the originating AS is the state authority).
- Failure modes: Resource AS unreachable, classification timeout, mismatched ontology versions.

### What this spec does NOT define

- General per-request authority validation at runtime → Runtime Enforcement Profile (Draft 8). Draft 4 is specifically about the AS-to-Resource-AS handoff at issuance or expansion time, not about every consequential action.
- Disclosure of the full Mission Intent to a Resource AS. Business purpose, unrelated objects, and authority for other resources are excluded unless the Resource AS can demonstrate a policy need for a specific field.
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

**Layer:** Profile. **Category:** Standards Track. **Submission type:** Independent (since AAuth itself is independent). **Depends on:** Drafts 1 and 3, `draft-hardt-oauth-aauth-protocol`.

### Abstract

This profile defines how a deployment composes AAuth `-01` with the Mission Framework. AAuth defines a native Mission model. The profile distinguishes **local governance mappings**, which preserve the AAuth wire, from **optional AAuth extension fields or endpoints**, which change the interoperable wire and require coordination with AAuth.

### What this profile composes

- **AAuth `-01`** as the credential substrate.
- **The Mission Framework (Draft 1)** for governance semantics, Mission Status interface, and pairwise identifier framework.

### What this profile defines on the AAuth substrate

- **Wire-preserving local mappings**: identifier mapping between AAuth's `(approver, s256)` and the Framework Mission reference; hash-domain separation; governance-record linkage; and local lifecycle projection.
- **Native-token projection rules**: rules that use existing AAuth extension points without changing required base fields.
- **Optional AAuth wire extensions**: Mission Expansion signaling and Mission Status fields or endpoints. Each extension is explicitly marked, versioned, advertised in AAuth metadata, and coordinated with the AAuth specification rather than described as preserving the base wire.

### What this profile does NOT define

- Unadvertised changes to AAuth wire behavior.
- Resumable Suspension semantics → currently sketched here; may promote to its own feature spec if needed.
- Cross-substrate (OAuth + AAuth) consumption → Mission Authority Server (Draft 7).

### IANA Considerations

- AAuth-side governance-mapping fields, in coordination with AAuth's registry.

---

## Draft 7: `draft-mcguinness-mission-authority-server`

**Mission Authority Server**

**Layer:** Server / Topology. **Category:** Standards Track. **Target WG:** OAUTH or independent. **Depends on:** Draft 1. OAuth and AAuth consumer bindings are separate sections that additionally depend on Drafts 2 and 6 respectively.

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

**Layer:** Profile. **Category:** Standards Track. **Submission venue:** Independent IETF I-D composing with the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) (a final OpenID specification, not an IETF artifact). **Depends on:** Drafts 1 and 3, Draft 2 and/or 6, OpenID AuthZEN Authorization API 1.0, OpenID AuthZEN Access Request.

### Abstract

This profile defines how a deployment composes the AuthZEN Authorization API with the Mission Framework to enforce Mission-bound authority at runtime. Every action class listed in the deployment's enforcement-scope manifest is evaluated against the Mission's versioned policy view, the audience-relevant Authority Set projection, authenticated actor context, and current Resource policy. The composition defines reproducible Mission-to-policy materialization, the Resource-Side Enforcement Contract (RS-D), PEP placement rules, parameter binding, authority-expandable denial handling, Decision Evidence, and Execution Evidence.

### What this profile composes

- **OpenID AuthZEN Authorization API 1.0** as the PDP interface (final OpenID spec, not IETF).
- **OpenID AuthZEN Access Request** for governed expansion of denied authority (per Mission Expansion, Draft 3).
- **The Mission Framework (Draft 1)** for Mission state, Authority Set, integrity hashes, and Mission Status interface.
- Either the OAuth Profile (Draft 2) or the AAuth Profile (Draft 6) as the credential substrate adapter (at least one substrate profile is required).

### What this profile defines

- The Mission-to-policy materialization contract (reproducible compilation of the approved Mission tuple into an evaluable policy view).
- The Resource-Side Enforcement Contract (RS-D requirements), including a deployment-published enforcement-scope manifest that identifies every action class and execution boundary covered by a conformance claim.
- PEP placement rules.
- Parameter binding (`parameter_digest`) to close the TOCTOU gap.
- Runtime denial classification and expansion eligibility.
- Mission Status and runtime context requirements.
- Local-Action Boundary requirements (non-OAuth/non-AAuth actions).
- A **Decision Evidence Object** emitted by the PDP, proving what was evaluated and decided.
- An **Execution Evidence Object** emitted by the PEP or executor, proving whether the authorized action was attempted, completed, failed, or was suppressed. It links to the decision through `decision_id` and `parameter_digest`.
- Runtime `max_invocations` semantics using an authoritative atomic counter at the enforcement boundary. The PEP reserves capacity before permit, records the reservation in Decision Evidence, and finalizes it in Execution Evidence as attempted, completed, failed, or released according to the registered constraint semantics.

### What this profile does NOT define

- Optional Modules (Tool Binding, Decision Receipt, Purpose Registry, Actor Provenance, Attestation, Policy Projection) → separate per-module specs as each matures.
- Policy compilation contract (how the materialized policy is represented in a specific policy language) → separate spec when needed.

### IANA Considerations

- Decision Evidence and Execution Evidence media types.
- Runtime decision evidence claim names.
- AuthZEN extension parameters for Mission inputs (in coordination with the OpenID AuthZEN working group; AuthZEN is an OpenID Foundation effort, not an IETF WG).

---

## Draft 9: `draft-mcguinness-mission-shaper-profile`

**Mission Shaper Profile**

**Layer:** Profile. **Category:** Informational. **Submission type:** Independent. **Depends on:** Draft 1.

### Abstract

The Mission Shaper is a client-side component that turns user input into structured Mission Intent. This Informational profile defines role boundaries and recommended behavior. It does not define a portable wire protocol or claim cross-vendor conformance.

### What this profile composes

- **The Mission Framework (Draft 1)** for Mission Intent shape.
- Substrate-specific Mission Intent submission contract (defined by OAuth Profile, AAuth Profile, or MAS).

### What this profile defines

- Shaper role and trust boundary.
- Discovery snapshot versioning.
- Mission Intent construction rules.
- Recommended ambiguity-surfacing behavior.
- Recommended non-authoritative derivation-hint content.
- Recommended refusal behavior.
- A non-normative Shaper Trace example.

### IANA Considerations

None. A future portable Shaper protocol would be a separate Standards Track specification with its own media types, discovery fields, and conformance requirements.

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

- **Draft 1: Framework** is foundational.
- **Draft 2: OAuth Profile baseline** depends on Draft 1. Its initial `-00` excludes Mission Expansion.
- **Draft 3: Mission Expansion** depends on Draft 1 and AuthZEN Access Request. After Draft 3 stabilizes, Draft 2 is revised to add the OAuth binding.
- **Draft 4: Delegated Authority Validation** depends on Drafts 1 and 3.
- **Draft 5: Transaction Token Chaining Composition** depends on Drafts 1 and 2 plus the transaction-token chaining profile.
- **Draft 6: AAuth Profile** depends on Drafts 1 and 3 plus AAuth. Wire-preserving baseline mappings may be implemented without the optional expansion binding.
- **Draft 7: MAS core** depends on Draft 1. Its OAuth consumer binding depends on Draft 2; its AAuth consumer binding depends on Draft 6.
- **Draft 8: Runtime Enforcement** depends on Drafts 1 and 3, at least one substrate profile (Draft 2 or 6), and the OpenID AuthZEN specifications.
- **Draft 9: Shaper Profile** depends on Draft 1.
- **Draft 10: Migration Guide** depends on the profiles it describes.
- **Draft 11: Capability Model** is terminal and references implemented capabilities rather than assuming all Drafts 1-9 are complete.

## Drafting Order (phased by implementer need)

The order leads with what builders need first to ship a Mission-Bound deployment.

**Phase 1: the implementable pair.** What an OAuth AS implementer needs to ship Mission-Bound issuance.

1. **Draft 1: Mission Framework.** Concrete data model, JSON schemas, hash algorithms, lifecycle state machine, Mission Status interface, integrity-anchor algorithm. Includes reference test vectors so implementers can validate their canonicalization and hash output. Foundational.
2. **Draft 2: Mission-Bound OAuth Profile baseline.** Concrete OAuth wire bindings: `mission_intent` authorization request parameter submitted through PAR, `mission_resource_access` RAR type, complete `mission` claim, dedicated Mission Status operation, optional Mission-snapshot introspection projection, lifecycle endpoint, and advertised stale-state enforcement classes. The initial `-00` does not include Mission Expansion.

A reference implementation of the Framework + OAuth Profile pair lives alongside, validating that the specs are concrete enough to build from.

**Phase 2: extending the implementable pair.** Builders running into denial or wanting runtime enforcement.

3. **Draft 3: Mission Expansion.** Defines replacement and branch semantics. Once stable, Draft 2 and Draft 6 add their substrate bindings in coordinated revisions.
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

1. ✅ **Common Constraints**: a constraint extension framework lives in Framework (Draft 1), with initial fully specified entries `max_derivations` and `aal`. Runtime `max_invocations` belongs in Draft 8. Other constraint names remain future work.
2. ✅ **OAuth Extensions catchall**: gone. Each former extension is its own feature spec (Drafts 3, 4, 5).
3. ✅ **Mission Expansion**: substrate-neutral replacement and branch semantics in Draft 3. Drafts 2 and 6 add bindings only after Draft 3 stabilizes.
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
17. ✅ **AAuth pairwise identifier conflict**: the Framework's pairwise identifier framework is **OPTIONAL with substrate-declared support**. Substrates advertise which identifier modes they support; AAuth ships canonical-only initially and the AAuth Profile documents the privacy trade-off. OAuth supports both canonical and pairwise.
18. ✅ **AAuth lifecycle mapping with Proposal/Mission split**: AAuth wire preserves its native two states (`active`, `terminated`). The substrate-neutral Mission Status carries the fine-grained Framework state for governance consumers. AAuth `terminated` covers `revoked / completed / expired`. Suspension projects to AAuth `terminated` for the suspension duration; resumption requires a new Mission Proposal flow at the AAuth substrate.
19. ✅ **Approving principal AAL**: Framework requires the AAL to be **recorded** in binding evidence; the Framework does NOT mandate an AAL floor. Deployment policy declares the minimum AAL per Mission class. Runtime Enforcement composes with RFC 9470 step-up when an `aal` constraint requires higher AAL than the approving principal's session carries.
20. ✅ **Mission record retention**: Mission records MUST be retained at least until (a) all derived credentials have expired, AND (b) the deployment's audit retention period for that Mission class has elapsed. After retention the state authority MAY garbage-collect; the canonical `mission.id` MUST NOT be reused. Cross-substrate Mission records under MAS follow the MAS's retention policy advertised in MAS metadata.
21. ✅ **Mission Intent schema evolution**: extension fields with `x_*` prefix are permitted; non-prefixed unknown properties are reserved for future Framework revisions. Extension fields are included in semantic normalization and `proposal_hash`. An unrecognized extension MUST NOT grant or enlarge authority; if it claims authority-relevant semantics, the state authority rejects it unless a registered extension defines validation and narrowing behavior.
22. ✅ **Approval atomicity contract**: approval, rejection, withdrawal, and expiry are serialized. Approval is idempotent, creates at most one Mission, and permanently links that Mission to its `proposal_id`. Partial activation is forbidden.
23. ✅ **MAS scope**: a committed MAS implementer is assumed. MAS spec (Draft 7) proceeds at Phase 3 as planned. Cross-MAS federation is OUT of scope for v1. MAS-to-MAS Mission migration is OUT of scope. MAS-supporting both pairwise and canonical identifier modes simultaneously per consumer IS in scope. MAS retention policy is advertised in MAS metadata.
24. ✅ **Dynamic actor context**: the Mission stores delegation policy, not a mutable actor chain. Actual actor chains travel on projections and runtime requests.
25. ✅ **Integrity normalization**: registered normalization runs before JCS; hash envelopes bind authorization domain and state authority.
26. ✅ **Pairwise identifiers**: `mission.ref` is distinct from canonical `mission.id`, opaque, sector-specific, and deferred from the first vertical slice.
27. ✅ **Mission Status privacy**: references are not bearer capabilities; unknown and unauthorized lookups are indistinguishable; protected responses bind caller, reference, audience, nonce, and freshness.
28. ✅ **Revocation semantics**: profiles advertise issuance, introspection, event-driven, and per-request enforcement classes plus maximum tolerated staleness. Immediate invalidation is not claimed without an applicable enforcement path.
29. ✅ **Runtime evidence**: PDP Decision Evidence and PEP Execution Evidence are separate linked artifacts.
30. ✅ **Runtime conformance scope**: every runtime claim includes an enforcement-scope manifest identifying covered action classes and execution boundaries.
31. ✅ **Shaper category**: the Informational Shaper Profile defines guidance only. A portable Shaper protocol would be a separate Standards Track specification.

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
- The normalization profiles and typed Authority Set registry.
- The `max_derivations` and `aal` constraint entries.
- The abstract Mission Status interface.

The deliverable includes positive and negative vectors for normalization, canonicalization, hashes, state transitions, races, replay, stale state, unauthorized status lookup, malformed JSON, and narrowing failure.

Draft 2 ships when an implementer can build one Mission-Bound OAuth AS serving one client and two Resource Servers. It defines the authorization request parameter, complete token claim, dedicated authenticated Mission Status operation, optional introspection projection, refresh/exchange gating, and behavior for already-issued credentials under each advertised enforcement class.

Reference implementation alongside: a thin OAuth AS + Framework library that passes the test vectors and demonstrates the wire shapes. The implementation is the test that the specs are concrete enough to build from. Specs without an implementation that exercises them are not yet baked.

The second interoperability slice adds two ASes under one IdP, ID-JAG, Identity Continuation Assertions, pairwise references, subject mapping, and cross-AS consistency.

## Glossary

These definitions are the canonical terminology for the specs. They build on the blog's [Terminology key](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key) (Part 1) and [Normative vocabulary](https://notes.karlmcguinness.com/notes/the-mission-model/#normative-vocabulary) (Part 2), with the following improvements:

- Distinguish **Submitted** from **Validated** Mission Intent (the blog's "Mission Intent" was dual-referent).
- Introduce **Mission Proposal** as a first-class term (the blog had no name for the pre-approval record; using "Mission" both pre- and post-approval was contradictory).
- Drop **Approved Mission** as redundant: after the Proposal/Mission split, a Mission only exists post-approval, so "Mission" alone is unambiguous.
- Rename **`consent_rendering_hash` → `consent_disclosure_hash`** (the hash covers the disclosure object, not rendered output).
- Add terms the blog lacked: **Pairwise Mission Reference**, **Resource AS**, **Tenant / Authorization domain**, principal-model roles.

Blog updates required to align with these terms are listed in the Operational Plan's Blog synchronization section.

**Intent step:**

- **Mission Shaper.** Client-side component that turns a prompt or trigger into Submitted Mission Intent. Does not issue authority and never crosses the trust boundary on its own. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **Submitted Mission Intent.** The structured proposal the Shaper produces and the client submits. **Untrusted** until the state authority validates it. Carries `goal`, `objects`, `constraints`, `success_criteria`, `mission_expiry`, optional `purpose`, optional `context`.
- **Validated Mission Intent.** The post-validation, post-narrowing form recorded on the Mission Proposal. The state authority's authoritative version. `proposal_hash` is computed over this form. When unqualified, "Mission Intent" in spec text means the **validated** form.

**Mission step:**

- **Mission Proposal.** Pre-approval record carrying Validated Mission Intent. Has its own lifecycle: `pending_approval`, `rejected`, `withdrawn`, `expired_as_pending`. Created at submission; either promoted to Mission at the approval event, or terminated. Carries a `proposal_id` distinct from `mission.id`.
- **Mission.** The durable, integrity-anchored, lifecycle-governed governance object that records an approved task. Created at the approval event from a Mission Proposal. Lifecycle: `active`, `suspended`, `revoked`, `completed`, `expired`. Carries Validated Mission Intent, Authority Set, integrity anchors, principal-model fields, lifecycle state, consent disclosure reference, and a stable identifier. ([Part 2](https://notes.karlmcguinness.com/notes/the-mission-model/#normative-vocabulary))
- **Approval event.** The atomic state-authority transition from Mission Proposal to Mission upon a binding consent signal. Records principal-model evidence (approving principal identity, AAL, timestamp, consent disclosure object) atomically with Mission record creation. Idempotent on `proposal_id`; concurrent approve/reject/withdraw/expiry operations are serialized with compare-and-set semantics; exactly one Mission per Proposal. Full semantics in [Framework Concrete shapes / Approval event semantics](#concrete-shapes-for-the-vertical-slice) above.
- **Mission record.** The server-side record holding a Mission. Lives at the OAuth AS, AAuth PS, or MAS depending on topology. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **State authority.** The server that holds the Mission record: AS, PS, or MAS. Authoritative for Mission state and the only party that can resolve Pairwise Mission References to the canonical `mission.id`. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **`mission` claim.** Object claim carried on credentials. Canonical mode uses `id`; pairwise mode uses `ref`; the two are mutually exclusive. Both modes carry `origin`, `authority_hash`, and `version`.
- **`mission.id`.** Canonical Mission identifier held by the state authority. Stable for the Mission's lifetime; MUST NOT be reused after Mission record garbage collection.
- **`mission.origin`.** State authority issuer URL. Resolves via `/.well-known/mission-authority` metadata document.
- **Pairwise Mission Reference (`mission.ref`).** Sector-specific opaque identifier for a Mission, resolvable to canonical `mission.id` only at the state authority. It contains no audience label or derivable identifier.
- **Integrity anchors.** Collective term for `proposal_hash`, `authority_hash`, `consent_disclosure_hash`. Each is computed after registered semantic normalization over a domain-separated envelope bound to the authorization domain and state authority.
- **`proposal_hash`.** Integrity anchor over Validated Mission Intent.
- **`authority_hash`.** Integrity anchor over the Authority Set.
- **`consent_disclosure_hash`** (renamed from `consent_rendering_hash`). Integrity anchor over the structured consent disclosure object presented to the approving principal. Renamed because the hash covers the disclosure object, not rendered output.

**Authority step:**

- **Authority Set.** Substrate-neutral canonical container for the maximum authority the state authority approved. Composed of **typed entries**; each entry declares its type, schema, schema version, and narrowing rules. On OAuth substrates serializes as `authorization_details` with `mission_resource_access` entries (or ecosystem-specific RAR types). ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key); [Part 2](https://notes.karlmcguinness.com/notes/the-mission-model/#normative-vocabulary); breakdown adds typed-entry structure.)
- **Authority Set entry.** A typed payload in the Authority Set: `{type, specification_uri, schema_digest, schema_version, authority, narrowing_profile}`. The Framework maintains a type registry; each type provides deterministic normalization, equality, subset, intersection, and unknown-field rules.
- **`mission_resource_access`.** One Authority Set entry type. Payload (`authority` field) carries `resource`, `actions`, `constraints` per the blog's original shape. The OAuth Profile defines this type's schema and narrowing rules.
- **`authorization_details`.** OAuth wire shape for derived authority (RFC 9396). The OAuth Profile uses `mission_resource_access` as one entry in this array. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **`narrowing_profile`.** URI identifying the narrowing rules applied to an Authority Set entry. Default `urn:mbo:narrowing:default-v1`.
- **Projection.** Substrate-specific, audience-bounded credential or assertion derived from the Mission's Authority Set: OAuth access token, ID-JAG, AAuth resource token, AAuth auth token, downstream JWT Authorization Grant. Each carries the Mission reference and is bounded by the Authority Set. ([Part 2](https://notes.karlmcguinness.com/notes/the-mission-model/#normative-vocabulary))
- **Mission Expansion.** Governance mechanism that either replaces a Mission with a broader successor or creates a separately scoped branch. `mission.predecessor` and `mission.expansion_mode` preserve lineage and semantics.

**Enforcement step:**

- **PDP (Policy Decision Point).** Component that evaluates per-action requests against the Mission's versioned policy view, the audience-relevant Authority Set projection, authenticated actor context, and current Resource policy. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **PEP (Policy Enforcement Point).** The in-line component that calls the PDP before allowing a consequential action and enforces the decision.
- **Mission Status.** Authenticated state-authority view returning Mission state, integrity anchors, audience-filtered Authority Set projection, `policy_version`, freshness indicator. By-mission-reference operation, **distinct from token introspection**. The blog conflated these; the breakdown separates them.
- **Runtime Decision.** Per-action evaluation result from a PDP. Produces Decision Evidence.
- **Execution Evidence.** PEP or executor record indicating whether the authorized action was attempted, completed, failed, or suppressed. Linked to Decision Evidence by `decision_id` and `parameter_digest`.
- **Evidence.** Durable record of a state-authority decision, runtime decision, or execution outcome. Decision and execution records are linked but distinct so authorization is not mistaken for proof that an action occurred.

**Principal model:**

- **Subject** (also **Beneficiary**). The principal on whose behalf the task is approved. The user the Mission serves.
- **Approving principal.** The principal who actually approved the Mission. Usually the Subject; may differ for delegated approval (e.g., admin approval, headless approval anchors).
- **Requesting client.** The OAuth client or AAuth agent that submitted the Mission Proposal.
- **Delegation policy.** Stable Mission-level bounds governing which actors may derive or exercise authority.
- **Actor chain.** Dynamic delegation context carried on derived artifacts and runtime requests. It is not mutable state in the canonical Mission record.
- **Tenant / Authorization domain.** Logical partitioning at the state authority. Missions in one tenant are not visible to consumers of another tenant unless explicit cross-tenant policy declares it.

**Deployment roles (cross-cutting):**

- **AS (Authorization Server).** OAuth server. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **PS (Person Server).** AAuth server. Defines a native Mission ([AAuth `-01`](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/01/)). ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **MAS (Mission Authority Server).** Dedicated governance server holding the Mission record when OAuth and AAuth share one governance object, or when governance lives outside any one credential issuer. ([Part 1](https://notes.karlmcguinness.com/notes/the-mission-is-the-missing-abstraction/#terminology-key))
- **Resource Server.** The server hosting a protected resource and accepting Mission-bound credentials. Per RFC 6749 and RFC 9728. Resource Server tiers (RS-A through RS-D) describe what the RS does with the credential.
- **Resource AS.** Authorization Server adjacent to a Resource Server in cross-AS topology (RFC 8693). Validates audience-bound credentials, may host a PDP or projection issuer.

**Trust boundaries.** See [Part 2 Trust boundaries and roles](https://notes.karlmcguinness.com/notes/the-mission-model/#trust-boundaries-and-roles) for the canonical role map (who is trusted for what).

## Conformance

Each Standards Track spec in this set includes a conformance section that enumerates the MUST/SHOULD/MAY surface for that spec. A claim of conformance MUST identify:

- The spec's short name and version (e.g., `draft-mcguinness-mission-framework-00`).
- The role(s) the implementation plays (state authority, credential issuer, Resource AS, PDP, etc.).
- Which optional features the implementation supports (e.g., pairwise identifiers, specific Authority Set types, specific constraint types).
- Which test vector classes the implementation has been validated against.
- For Runtime Enforcement, the enforcement-scope manifest: covered action classes, PEP locations, excluded execution boundaries, Mission-state freshness mode, and maximum tolerated stale interval.

Test vector reproduction is the conformance floor for the Framework: an implementation that does not reproduce the published test vectors byte-for-byte is not conformant to that vector class.

**Conformance shape for Informational drafts.** Migration Guide (Draft 10), Shaper Profile (Draft 9), and Capability Model (Draft 11) are Informational and do not carry testable conformance. An implementation claiming alignment with an Informational draft describes how its implementation maps to the draft's guidance; conformance is descriptive, not testable. Implementations of Standards Track drafts that incidentally reflect Informational-draft guidance MAY note that alignment in their conformance claim but MUST NOT claim "conformance to" an Informational draft.

## License

- **Spec text** (kramdown-rfc sources, rendered HTML/text drafts): IETF Trust License Provisions, per standard Internet-Draft submission norms.
- **Test vectors**: CC0 (public domain). Vectors are intended to be embedded in any implementation regardless of license.
- **Reference implementation**: Apache License 2.0.
- **Schemas** (JSON Schema files for Mission Intent, Authority Set, Mission Status response, etc.): CC0.

A `LICENSE` file at the repo root carries the IETF Trust License Provisions for spec text. Other licenses are declared in their respective files or subdirectory READMEs.

## Reference Implementation

A reference implementation lives alongside the drafts and is part of the deliverable. Without it, "implementer-ready" is aspirational.

- **Language**: TypeScript. Broad JOSE library ecosystem, broad OAuth stack ecosystem, accessible to web-platform implementers, runs in Node and Deno.
- **Repository**: `mcguinness/mission-bound-authorization-reference` (sibling to the spec repo). Created when Draft 1 reaches `-00`.
- **Scope at Phase 1**:
  - Framework: Mission Intent JSON validator, normalization profiles, Authority Set type registry, integrity-anchor computation, Mission Proposal and Mission state machines.
  - OAuth Profile: `mission_intent` authorization request parsing through PAR, `mission_resource_access` derivation, complete `mission` claim emission, Mission Status endpoint, Mission lifecycle endpoint, enforcement-class advertisement, and optional RFC 9701-signed introspection projection.
  - Topology: one AS, one client, and two Resource Servers. Pairwise references and identity chaining are deferred to the second slice.
- **Validation**: the reference implementation MUST reproduce every published test vector. CI runs the vector suite on every commit.
- **Out of scope**: production-grade hardening, persistence at scale, production key management. The reference implementation is a conformance reference and interop partner, not a production deployment.

## Cross-spec versioning

When the Framework spec advances (e.g., `-00` → `-01`) with changes that affect dependent profiles, the dependent profiles MUST track. Rules:

- Each profile declares the Framework version range it supports in its frontmatter.
- Backward-incompatible Framework changes require dependent profiles to revise; the changelog records the cascade.
- Implementations advertise their supported version sets in state-authority metadata; consumers select compatible versions during composition.
- During the implementation-readiness phase (before IETF submission), backward incompatibility is acceptable; once submitted, backward compatibility within a major version is required.

**Test vector versioning.** Test vectors ship with each spec revision in the `vectors/` directory, tagged with the spec revision they validate (e.g., `vectors/draft-mcguinness-mission-framework-00/`). When a spec revision changes vector outputs, the new revision ships a new vector directory; older vector directories are retained as historical reference. Implementations declare which spec revision (and therefore which vector directory) they validate against in their conformance claim. The reference implementation tracks the current spec revision; CI runs against the matching vector directory.

## Operational Plan

### Maturity stages

Each draft progresses through three stages before being submitted to IETF:

1. **Sketch (this breakdown).** Scope, structure, and key normative items documented. No spec text yet.
2. **Implementable `-00`.** Full spec text published in the repo. Test vectors included. Reference implementation validates the vectors. Implementer review is open.
3. **Baked (`-01` and beyond).** Implementation feedback incorporated. At least one external implementation exists. Submission to IETF (or the relevant venue) is then considered.

Phase 1 (Framework + OAuth Profile) target: `-00` publication when both specs are implementable and reference implementation passes test vectors. Quality over speed.

### Contributor pathway

- **Spec text**: PRs to the repo on individual draft files. Editorial PRs accepted with minimal review; substantive PRs require an issue first.
- **Test vectors**: PRs to `vectors/` directory. Each vector PR includes the input, expected output, and a `notes` field explaining what it tests.
- **Reference implementation**: PRs to the sibling repo. Required: vector suite passes.
- **Co-authorship**: implementers who contribute substantive design or text may be added as co-authors on the relevant spec.

### Feedback channel

- **GitHub Issues** on the spec repo: structural feedback, draft text issues, breakdown revisions.
- **Discussion thread on the blog**: conceptual feedback, architecture-level questions.
- **Direct email** to the author: confidential review, embargoed implementer-interest signals.

### Blog synchronization

The blog series carries the conceptual argument and the canonical terminology; the breakdown and drafts carry the wire and normative requirements. As decisions change in the breakdown, blog posts SHOULD be updated within the same week as the breakdown commit.

Current breakdown/blog deltas requiring blog updates:

- Blog refers to "seven-state lifecycle"; breakdown splits into Mission Proposal (4 states) and Mission (5 states). **Blog needs Mission Proposal vs Mission distinction.**
- Blog uses `consent_rendering_hash`; breakdown uses `consent_disclosure_hash`. **Blog rename pending.**
- Blog uses "Approved Mission"; breakdown drops this term as redundant (Mission only exists post-approval). **Blog should align.**
- Blog defines Mission Intent without distinguishing submitted vs validated forms; breakdown distinguishes them. **Blog should adopt distinction.**
- Blog `mission` claim shape has `{id, origin}`; breakdown uses mutually exclusive canonical `id` or pairwise `ref`, plus `authority_hash` and `version`. **Blog should update the complete claim shape.**
- Blog uses `additionalProperties: true` for Mission Intent; breakdown specifies `x_*` prefix extension policy. **Blog needs extension policy update.**
- Blog references `draft-mcguinness-oauth-identity-assertion-trust-framework`; correct draft name is `draft-mcguinness-oauth-identity-assertion-trust-policy`. **Blog link fix needed.**

## Changelog

| Date | Change |
|---|---|
| 2026-06-08 | Fresh-read polish: clarified Composition Surface RFC 7515 two-mode usage; updated `max_value` example to `max_derivations` (`max_value` is future work); pinned `proposal_id` lifecycle (Proposal retained alongside Mission for the same retention window; no reuse after garbage collection); added test-vector versioning rule (per-revision vector directories); added conformance shape for Informational drafts (descriptive, not testable); added recommended access-token TTL guidance (shorter for issuance-gating-only deployments); cross-referenced Approval event glossary entry to Framework body semantics; pinned `schema_digest` format (`sha-256:` prefix + base64url, canonical schema bytes via JCS). |
| 2026-06-08 | Second stress-test resolution: reduced Phase 1 to one AS/one client/two Resource Servers; moved actor chains out of Mission state; added semantic normalization and authorization-domain-bound hashes; split derivation and invocation budgets; hardened Mission Status against enumeration and replay; defined a distinct status response profile; completed the `mission` claim; added revocation enforcement classes; made Authority Set type references immutable; defined replacement vs branch expansion; minimized Resource-AS disclosure; corrected dependencies; split runtime decision and execution evidence; required runtime enforcement-scope manifests; and removed wire/IANA claims from the Informational Shaper Profile. |
| 2026-06-08 | Stress-test resolution: stale references fixed; concrete shapes pinned for pairwise reference, `narrowing_profile`, approval event, `policy_version`, `mission.origin` resolution, Mission Expansion ticket, consent disclosure schema, `mission` claim, `mission_resource_access` payload, Mission Status request auth + error model, spec versioning, test vector enumeration. Decisions 17-23 closed (AAuth pairwise, AAuth lifecycle, approving AAL, retention, schema evolution, atomicity, MAS scope). Added Glossary (with improved terms over blog), Conformance, License, Reference Implementation, Cross-spec versioning, Operational Plan, Changelog sections. |
| 2026-06-08 | Reviewer's 14-item stress test addressed (Proposal/Mission split, JWS pulled to profile level, Mission Status distinct from introspection, ID-JAG roles corrected, principal model added, canonical+pairwise identifier scheme, typed Authority Set, constraint extension framework + 2 worked entries, domain-separated hashes, IANA audit, RFC 7009/9470 claims tightened, profile principle rewritten, Draft 4 narrowed, AuthZEN OpenID attribution). |
| 2026-06-08 | Reframed for implementation-readiness, not IETF submission. Added vertical-slice first-deliverable approach. |
| 2026-06-08 | Composition Surface section added with full audit of RFCs, drafts, and Karl's individual drafts. |
| 2026-06-08 | OAuth Extensions catchall split into Mission Expansion, Delegated Authority Validation, Same-IdP Chain Continuation (referenced from existing `draft-mcguinness-oauth-id-continuation-assertion`), Mission-Bound Txn Token Chaining. |
| 2026-06-08 | Layered structure introduced: Framework / Server-Topology / Profiles / Features / Informational. Mission Framework added as Draft 1. |
| 2026-06-08 | Initial spec breakdown published. |
