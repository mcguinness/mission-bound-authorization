# Mission-Bound Authorization: Draft Roadmap and Spec Breakdown

This document defines what becomes a standards-track Internet-Draft, what stays in the [blog series](https://notes.karlmcguinness.com/series/mission-bound-authorization/), and the dependency order for drafting.

The breakdown is open for revision before drafting begins. Comments inline; see the open questions at the end.

## Architectural Principles

The split obeys three principles:

1. **Profiles compose existing standards.** A profile spec defines how existing standards (RFC 6749, RFC 9396, RFC 9126, AAuth, AuthZEN, etc.) plus the Mission Model framework are deployed together. Profiles do not invent new features or wire formats; they specify deployment requirements over what already exists.
2. **Features are separate composable specs.** Anything not already in an existing standard (Mission Model, Mission Expansion, Delegated Authority Validation, Same-IdP Chain Continuation, etc.) gets its own spec. Profiles reference these features and require them to compose with the substrate.
3. **The framework is substrate-neutral.** The Mission Model and Framework spec defines abstract concepts (Mission, Authority Set, lifecycle, integrity anchors, constraints vocabulary). Profile specs map those abstract concepts onto specific wire substrates (OAuth, AAuth) and topologies (MAS).

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
| **Framework** | Mission Model and Framework | Defines abstract concepts every profile and feature spec references. |
| **Server / Topology** | Mission Authority Server | Defines a new server role and its endpoints. Cross-substrate consumers reference it. |
| **Profiles** | OAuth Profile, AAuth Profile, Shaper Profile, Runtime Enforcement Profile | Compose existing standards + Framework + Feature specs into deployable wire surfaces. |
| **Features (Extensions)** | OAuth Extensions, plus Runtime Optional Modules as they mature | Each adds capability that one or more profiles can compose. |
| **Informational** | Capability Model, Migration | Adoption guidance and reporting model. |

## Summary

| # | Short name | Title | Layer | Category | Approx pages |
| --- | --- | --- | --- | --- | --- |
| 1 | `draft-mcguinness-mission-bound-framework` | Mission Model and Framework | Framework | Standards Track | 30-40 |
| 2 | `draft-mcguinness-mission-bound-oauth` | Mission-Bound OAuth Profile | Profile | Standards Track | 35-45 |
| 3 | `draft-mcguinness-mission-expansion` | Mission Expansion | Feature | Standards Track | 20-30 |
| 4 | `draft-mcguinness-mission-delegated-authority-validation` | Delegated Authority Validation | Feature | Standards Track | 15-20 |
| 5 | `draft-mcguinness-mission-same-idp-chain-continuation` | Same-IdP Chain Continuation Assertion | Feature | Standards Track | 15-20 |
| 6 | `draft-mcguinness-mission-txn-token-chaining` | Mission-Bound Transaction Token Chaining Composition | Feature | Standards Track | 10-15 |
| 7 | `draft-mcguinness-mission-bound-aauth` | Mission-Bound AAuth Composition Profile | Profile | Standards Track | 25-35 |
| 8 | `draft-mcguinness-mission-authority-server` | Mission Authority Server | Server/Topology | Standards Track | 30-40 |
| 9 | `draft-mcguinness-mission-bound-runtime` | Mission-Bound Runtime Enforcement Profile | Profile | Standards Track | 35-45 |
| 10 | `draft-mcguinness-mission-shaper-profile` | Mission Shaper Profile | Profile | Standards Track | 20-30 |
| 11 | `draft-mcguinness-mission-bound-migration` | Mission-Bound Authorization Migration Guide | Informational | Informational | 15-20 |
| 12 | `draft-mcguinness-mission-bound-capability-model` | Mission-Bound Authorization Capability Model | Informational | Informational | 20-25 |

The OAuth Extensions catchall is gone. Each feature is its own spec that profiles compose:

- **Mission Expansion** (Draft 3): the governance expansion mechanism. Includes Concurrent Expansion reconciliation as a section.
- **Delegated Authority Validation** (Draft 4): the Resource-AS authority validation pattern for open-world tools.
- **Same-IdP Chain Continuation Assertion** (Draft 5): the JWT assertion type for cross-resource SaaS continuation.
- **Mission-Bound Transaction Token Chaining Composition** (Draft 6): the composition between Mission-Bound OAuth and `draft-fletcher-transaction-token-chaining-profile`.

Token Size at Depth (mitigations like audience-filtered Authority Set projection) is operational guidance, not a new wire feature. It folds into the OAuth Profile Security Considerations and the MAS audience-pairwise-identifier section.

Future drafts (separate as they mature; not part of initial set):

- Tool Binding Profile, Decision Receipt Profile, Purpose Registry Profile, Actor Provenance Profile, Attestation Profile, Policy Projection Profile (each as a Runtime Enforcement composition extension).

---

## Draft 1: `draft-mcguinness-mission-bound-framework`

**Mission Model and Framework**

**Layer:** Framework. **Category:** Standards Track. **Target WG:** OAUTH or independent submission. **Status:** New.

### Abstract

This document defines the Mission as a durable, integrity-anchored, lifecycle-governed governance object for an approved task. It defines the abstract types and behaviors that profile specifications map onto specific substrates: the Mission Intent, Authority Set, lifecycle state machine, integrity anchors, mission identifier model, common constraints vocabulary, and evidence binding. The framework is substrate-neutral. Profile specifications for OAuth, AAuth, and the Mission Authority Server compose this framework with their respective wire substrates.

### What this spec defines

- **Mission object structure**: Intent, Authority Set, integrity anchors, lifecycle state, consent reference, identifier, delegation context.
- **Mission Intent**: structured task proposal admitted by the state authority. Fields: `goal`, `objects`, `constraints`, `success_criteria`, `mission_expiry`, optional `purpose`, optional `context`.
- **Authority Set**: substrate-neutral container for approved authority bounded by Mission Intent. Carries per-resource entries with `resource`, `actions`, and `constraints`.
- **Lifecycle state machine**: seven states (`pending_approval`, `active`, `suspended`, `revoked`, `completed`, `expired`, `rejected`) and the permitted transitions.
- **Integrity anchors**: `proposal_hash`, `authority_hash`, `consent_rendering_hash`. Canonical form (JCS, RFC 8785), digest algorithm (SHA-256), and what each commits.
- **Mission identifier model**: `mission.id` (stable opaque), `mission.origin` (state-authority issuer URI), audience-pairwise identifier framework.
- **Common Constraints vocabulary**: standardized constraint key names with stable semantics (`max_calls`, `max_value`, `max_duration`, `aal`, `geo`, `data_classification`). Each defines what it constrains; substrate profiles define wire serialization.
- **Evidence binding**: signer, timestamp, policy version, schema version, rendering template version, approving principal. The minimum metadata each integrity anchor MUST be paired with for audit.
- **Trust boundaries**: who is trusted for what (Shaper, state authority, credential issuer, PDP, evidence emitter). The Shaper Profile, OAuth Profile, AAuth Profile, MAS Profile, and Runtime Profile populate these roles for their substrate.
- **Normative vocabulary**: Mission Intent, Mission, Authority Set, Projection, Runtime Decision, Evidence.

### Key normative requirements (abstract)

- A Mission MUST satisfy the litmus test (durable, integrity-anchored, lifecycle-governed, identifier-stable, reference-bearing, derived-authority).
- A state authority MUST compute `proposal_hash`, `authority_hash`, and `consent_rendering_hash` over JCS-canonicalized objects and SHA-256.
- A Mission record MUST carry binding evidence (signer, timestamp, policy version, schema version, rendering template version, approver) alongside the integrity anchors.
- A Mission MUST be in `active` state to permit new derivation; every non-active state refuses.
- A profile MUST specify how each Mission Model element manifests on its substrate.
- A profile MUST NOT enlarge the Mission Model semantics; profile mappings are subset-faithful representations.

### IANA Considerations

- Mission Common Constraints registry (new): key, semantics, commitment shape, narrowing rules.
- Mission lifecycle state registry (or fixed enumeration).
- Mission Model identifier vocabulary (`mission.id`, `mission.origin`) for cross-reference by substrate profiles.

### Security Considerations themes

- Integrity anchor non-guarantees (faithful rendering, comprehension, real-time honesty, principal authenticity).
- State authority compromise.
- Trust-boundary violations (Shaper acting as authorization component).
- Pairwise identifier privacy.

### Normative references

RFC 8785 (JCS), RFC 8174 (BCP 14 update), RFC 6234 (SHA-256).

### Informative references

Series blog posts as background.

---

## Draft 2: `draft-mcguinness-mission-bound-oauth`

**Mission-Bound OAuth Profile**

**Layer:** Profile. **Category:** Standards Track. **Target WG:** OAUTH. **Status:** New. **Depends on:** Draft 1.

### Abstract

This profile defines how a deployment composes OAuth 2.0 (RFC 6749), Rich Authorization Requests (RFC 9396), Pushed Authorization Requests (RFC 9126), Token Exchange (RFC 8693), DPoP (RFC 9449), and mTLS (RFC 8705) with the Mission Model and Framework. A client submits structured Mission Intent at PAR; the Authorization Server validates and renders it, records an Approved Mission per the Framework, derives `authorization_details`, and binds issuance, refresh, and Token Exchange to the Mission record. Tokens carry a `mission` claim referencing the governance record. Common Constraints from the Framework's vocabulary serialize into `mission_resource_access.constraints` entries.

### What this profile composes

- **OAuth 2.0 (RFC 6749)** as the credential substrate.
- **Pushed Authorization Requests (RFC 9126)** as the Mission Intent submission point.
- **Rich Authorization Requests (RFC 9396)** as the Authority Set wire serialization. Defines the `mission_resource_access` RAR type as the OAuth representation of an Authority Set entry.
- **Token Exchange (RFC 8693)** as the derivation path that gates on Mission state.
- **DPoP (RFC 9449)** or **mTLS (RFC 8705)** as the sender-constraint mechanism.
- **The Mission Model and Framework (Draft 1)** for Mission record semantics, integrity anchors, lifecycle, and constraints vocabulary.

### What this profile defines on the OAuth wire (registered with IANA)

- **`mission_intent`** parameter at PAR.
- **`mission_resource_access`** RAR type.
- **`mission`** claim on JWT access tokens.
- **`mission_inactive`** error code for refresh/exchange denial.
- Mission Status introspection extension (optional at this profile, required at AD-3).

### What this profile does NOT define

- Mission Expansion → Mission Expansion (Draft 3).
- Delegated Authority Validation → Delegated Authority Validation (Draft 4).
- Same-IdP Chain Continuation → Same-IdP Chain Continuation Assertion (Draft 5).
- Transaction Token Chaining composition → Mission-Bound Transaction Token Chaining (Draft 6).
- Multi-AS ID-JAG composition → composes with `draft-ietf-oauth-identity-assertion-authz-grant` directly.
- Runtime per-action enforcement → Mission-Bound Runtime Enforcement Profile (Draft 9).
- MAS topology → Mission Authority Server (Draft 8).
- Token Size at Depth mitigations → covered as Security and Operational Considerations in this profile and in the MAS spec.

### IANA Considerations

- `mission_intent` PAR parameter.
- `mission_resource_access` RAR type.
- `mission` JWT claim.
- `mission_inactive` error code.

### Security Considerations themes

- OAuth-specific replay, redirect, token theft.
- Sender-constraint downgrade.
- Cross-audience derivation hardening.
- Mission identifier privacy on the OAuth wire.

---

## Draft 3: `draft-mcguinness-mission-expansion`

**Mission Expansion**

**Layer:** Feature. **Category:** Standards Track. **Target WG:** OAUTH (composes with OAuth Profile) or AUTHZEN (composes with AuthZEN Access Request). **Status:** New. **Depends on:** Draft 1, AuthZEN Access Request.

### Abstract

This document defines the governance expansion mechanism for Mission-Bound Authorization. When an action falls outside the Authority Set of an active Mission but is eligible for governed expansion, this spec defines the eligibility signaling, the expansion request workflow, the binding of the successor Mission to the prior Mission, and the reconciliation rules for concurrent expansion requests. The expansion mechanism is substrate-neutral; substrate profiles (OAuth, AAuth) compose with this spec to surface expansion eligibility on their wires.

### What this spec defines

- Expansion eligibility signaling on denial: the `expansion` block with `eligible`, `access_request_uri`, `ticket`, and `requested_authority`.
- Expansion request workflow via AuthZEN Access Request: how the orchestrator submits the access request with the ticket, how the state authority adjudicates, how the result is communicated.
- Workflow outcomes: synchronous approved, asynchronous approved, denied, expired.
- Successor-Mission binding: `mission.supersedes`, expiry inheritance rules, atomic transition between prior and successor Mission.
- Concurrent expansion reconciliation: rules for when more than one expansion request is in flight for the same Mission.

### What this spec does NOT define

- Substrate-specific wire formats for the denial signal → covered by the OAuth Profile (Draft 2) and AAuth Profile (Draft 7) as composition rules.
- How Resource ASes detect out-of-bounds requests → covered by Delegated Authority Validation (Draft 4).

### IANA Considerations

- Mission Expansion error fields and response shape.
- `mission.supersedes` claim or attribute.
- Expansion ticket and access-request shapes (in coordination with AUTHZEN).
- Concurrent expansion reconciliation status codes.

---

## Draft 4: `draft-mcguinness-mission-delegated-authority-validation`

**Delegated Authority Validation**

**Layer:** Feature. **Category:** Standards Track. **Target WG:** OAUTH or independent. **Status:** New. **Depends on:** Drafts 1 and 3 (Mission Expansion for the eligibility-signaling contract).

### Abstract

This document defines the authority validation pattern for open-world tool semantics. When an agent attempts an action at a Resource AS whose ontology the originating AS does not know, the Resource AS validates the request against the Mission's Authority Set and returns either a permit, a hard denial, or an expansion-eligible denial. This spec defines the protocol between the Resource AS and the originating state authority, the eligibility-discovery rules, and how the validation result composes with Mission Expansion.

### What this spec defines

- The Resource-AS-as-validator pattern: when an originating AS issues a credential whose Authority Set the Resource AS can interpret beyond the AS's own ontology.
- Resource AS responsibilities: examine the Mission Intent's `objects` field, determine action eligibility against local ontology, distinguish in-bounds / out-of-bounds / out-of-bounds-but-eligible.
- The expansion-eligibility signaling protocol: how a Resource AS marks a denial as expandable in coordination with Mission Expansion (Draft 3).
- Trust boundaries: what the Resource AS is trusted to determine vs. what requires the originating AS's confirmation.

### What this spec does NOT define

- The expansion workflow itself → Mission Expansion (Draft 3).
- Mission Intent shape → Mission Model and Framework (Draft 1).

### IANA Considerations

- Delegated Authority Validation request and response shapes.
- Eligibility-discovery error codes.

---

## Draft 5: `draft-mcguinness-mission-same-idp-chain-continuation`

**Same-IdP Chain Continuation Assertion**

**Layer:** Feature. **Category:** Standards Track. **Target WG:** OAUTH. **Status:** New. **Depends on:** Drafts 1 and 2, RFC 7519 (JWT), Identity Chaining drafts.

### Abstract

This document defines a JWT-based Continuation Assertion that carries Mission-bound governance context across SaaS authorization boundaries inside one identity provider's trust domain. The Continuation Assertion is consumed by downstream Authorization Servers to validate that an exchanged credential is part of the same Mission-governed task. It composes with `draft-ietf-oauth-identity-assertion-authz-grant` (ID-JAG) and is similar in structure but specialized for same-IdP continuation rather than cross-domain identity assertion.

### What this spec defines

- The Continuation Assertion JWT type.
- Required claims: `mission.id`, `mission.origin`, root delegation context, chain authority trust statement, IdP validation reference.
- Validation rules at the receiving AS.
- Discovery and error handling.
- Composition with ID-JAG: when to use Continuation Assertion vs ID-JAG.

### IANA Considerations

- Continuation Assertion JWT type and `typ` value.
- Claim names if not already in the JWT Claim Registry.
- Error codes for invalid or expired continuation.

---

## Draft 6: `draft-mcguinness-mission-txn-token-chaining`

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

## Draft 7: `draft-mcguinness-mission-bound-aauth`

**Mission-Bound AAuth Composition Profile**

**Layer:** Profile. **Category:** Standards Track. **Submission type:** Independent (since AAuth itself is independent). **Depends on:** Draft 1, `draft-hardt-oauth-aauth-protocol`.

### Abstract

This profile defines how a deployment composes AAuth `-01` with the Mission Model and Framework. AAuth defines a native Mission model. This composition preserves AAuth's wire protocol and maps its native concepts onto the substrate-neutral Mission Model: identifier mapping, hash domain separation, Authority Set projection into resource-token and auth-token issuance, lifecycle composition, and Mission Status surface.

### What this profile composes

- **AAuth `-01`** as the credential substrate.
- **The Mission Model and Framework (Draft 1)** for governance semantics.

### What this profile defines on the AAuth substrate

- Identifier mapping between AAuth's `(approver, s256)` native Mission reference and the Framework's `(mission.id, mission.origin)` governance reference.
- Hash domain separation between AAuth's exact-body Mission hash and the Framework's structured governance hashes.
- Authority Set projection rules into AAuth resource tokens and auth tokens.
- Lifecycle composition: how the Framework's seven states map onto AAuth's native two-state `(active, terminated)` lifecycle.
- Mission Status surface on the AAuth Person Server.

### What this profile does NOT define

- New AAuth wire elements; the composition preserves AAuth.
- Resumable Suspension semantics → separate extension if/when needed.
- Cross-substrate (OAuth + AAuth) consumption → Mission Authority Server (Draft 5).

### IANA Considerations

- AAuth-side governance-mapping fields, in coordination with AAuth's registry.

---

## Draft 8: `draft-mcguinness-mission-authority-server`

**Mission Authority Server**

**Layer:** Server / Topology. **Category:** Standards Track. **Target WG:** OAUTH or independent. **Depends on:** Drafts 1, 2, 7.

### Abstract

A Mission Authority Server (MAS) holds the canonical Mission record so multiple OAuth Authorization Servers, AAuth Person Servers, and future substrate-state-authorities can project from one governance object. This document defines the MAS role, its metadata and discovery, the Mission submission and lifecycle endpoints, the authenticated Mission Status surface, the substrate-neutral Authority Set serialization, audience-pairwise Mission identifiers, and the cross-substrate revocation propagation contract.

### What this spec defines

- MAS role and topology.
- MAS metadata document and well-known discovery URL.
- Mission submission endpoint (consumer-mediated and direct flows).
- Mission lifecycle endpoint (revoke, suspend, resume, complete).
- Mission Status endpoint with authenticated responses.
- Substrate-neutral Authority Set serialization (the wire form of the abstract Framework Authority Set).
- Audience-pairwise Mission identifier protocol.
- Cross-substrate revocation propagation via SSF/CAEP or polling.

### What this spec does NOT define

- Substrate-local Mission state (covered by OAuth Profile and AAuth Profile).
- Runtime enforcement (Mission-Bound Runtime Enforcement Profile, Draft 6).
- Cross-MAS federation (out of scope for v1).

### IANA Considerations

- MAS metadata document and well-known URL.
- Mission Status response shape.
- Cross-substrate Authority Set serialization.
- Audience-pairwise identifier protocol.
- MAS lifecycle event shapes for SSF/CAEP propagation.

---

## Draft 9: `draft-mcguinness-mission-bound-runtime`

**Mission-Bound Runtime Enforcement Profile**

**Layer:** Profile. **Category:** Standards Track. **Target WG:** AUTHZEN. **Depends on:** Drafts 1, 2 and/or 7, AuthZEN Authorization API.

### Abstract

This profile defines how a deployment composes the AuthZEN Authorization API with the Mission Model and Framework to enforce Mission-bound authority at runtime. Every consequential action is evaluated against the Mission's versioned policy view, the audience-relevant Authority Set projection, authenticated actor context, and current Resource policy. The composition defines reproducible Mission-to-policy materialization, the Resource-Side Enforcement Contract (RS-D), PEP placement rules, parameter binding, authority-expandable denial handling, and the Runtime Evidence Object.

### What this profile composes

- **AuthZEN Authorization API** as the PDP interface.
- **AuthZEN Access Request** for governed expansion of denied authority.
- **The Mission Model and Framework (Draft 1)** for Mission state, Authority Set, and integrity anchors.
- Either the OAuth Profile (Draft 2) or the AAuth Profile (Draft 4) as the credential substrate adapter.

### What this profile defines

- The Mission-to-policy materialization contract (reproducible compilation of the approved Mission tuple into an evaluable policy view).
- The Resource-Side Enforcement Contract (RS-D requirements: every consequential action goes through the PDP).
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
- Mission expansion ticket and access-request shapes (in coordination with AuthZEN Access Request).

---

## Draft 10: `draft-mcguinness-mission-shaper-profile`

**Mission Shaper Profile**

**Layer:** Profile. **Category:** Standards Track. **Target WG:** OAUTH or independent. **Depends on:** Draft 1.

### Abstract

The Mission Shaper is a client-side component that turns user input into structured Mission Intent. This profile defines the Shaper's contract with the orchestrator, the versioned discovery snapshot it consumes, non-authoritative derivation hints, the ambiguity-surfacing protocol, refusals, and the Shaper Trace audit artifact. The Shaper does not issue authority; its output remains untrusted until the validating server admits it.

### What this profile composes

- **The Mission Model and Framework (Draft 1)** for Mission Intent shape.
- Substrate-specific Mission Intent submission contract (defined by OAuth Profile, AAuth Profile, or MAS).

### What this profile defines (client-side processing contract)

- Shaper role and trust boundary.
- Discovery snapshot versioning.
- Mission Intent construction rules.
- Ambiguity surfacing protocol (when to ask clarifications vs. accept defaults).
- Non-authoritative derivation hints format.
- Refusal protocol.
- Shaper Trace audit artifact.

### IANA Considerations

- Shaper Trace media type.
- Ambiguity-surfacing response shape.
- Discovery snapshot version field.

### Open question

Is "Profile" the right word for a client-side processing spec that doesn't compose wire-level standards in the same way? Alternative: call it a "Role" or "Implementation Guide." Recommendation: keep "Profile" for naming consistency.

---

## Draft 11: `draft-mcguinness-mission-bound-migration`

**Mission-Bound Authorization Migration Guide**

**Layer:** Informational. **Category:** Informational. **Depends on:** Drafts 1, 2, 7.

### Abstract

This document defines a Stage 0 through Stage 5 incremental adoption path for an existing OAuth or AAuth deployment to reach Mission-Bound Authorization conformance. Each stage names what the deployment ships, what client and Resource Server changes are required, and what compatibility hazards apply. The migration guide is operational; it makes no normative wire requirements beyond what the underlying profiles already specify.

### Why a separate spec

The migration path is operational guidance. It does not introduce new wire elements. Putting it in the OAuth Profile, OAuth Extensions, or Mission Model bloats those documents with adoption material that audiences don't need. A separate Informational draft is the right home.

### Sections

- Stage 0: where you are today (existing OAuth or AAuth deployment).
- Stage 1: shadow Mission (record the Mission, do not enforce).
- Stage 2: gate refresh and exchange on Mission state.
- Stage 3: narrow authority from the approved Mission.
- Stage 4: Resource Server uptake.
- Stage 5: cross-AS continuity.
- Compatibility hazards (back-compat for legacy clients, RS-A tier, audience-pairwise rollout, etc.).

---

## Draft 12: `draft-mcguinness-mission-bound-capability-model`

**Mission-Bound Authorization Capability Model**

**Layer:** Informational. **Category:** Informational. **Depends on:** Drafts 1-10 for capability mapping.

### Abstract

This document defines a substrate-neutral capability and adoption model for Mission-Bound Authorization. Capability is reported as a coordinate on three axes: the Capability Ladder (Levels 0-5), Resource Server Tiers (RS-A through RS-D), and Authorization Domain Tiers (AD-1 through AD-3). The document defines three named adoption claims (Mission-Bound Issuance, Mission-Bound Runtime Enforcement, Mission-Bound Cross-Domain Projection), capability advertisement metadata, and the mapping from OAuth-only, AAuth-only, and cross-substrate deployments onto the coordinate.

### Why Informational

The capability model is a description, not a wire protocol. Conformance is claimed against the substrate or runtime profile. The capability coordinate is a reporting tool.

### IANA Considerations

- Capability advertisement metadata: `mission_authorization_domain_tiers_supported`, `mission_ladder_levels_supported`, `mission_profiles_supported`, `mission_optional_modules_supported`.

---

## Future Drafts (not in initial set)

These extensions are part of the architecture but defer to separate drafts as each matures.

| Short name | Title | Depends on |
| --- | --- | --- |
| `draft-mcguinness-mission-tool-binding` | Tool Binding Profile | Drafts 1, 6 |
| `draft-mcguinness-mission-decision-receipt` | Mission Decision Receipt Profile | Drafts 1, 6 |
| `draft-mcguinness-mission-purpose-registry` | Mission Purpose Registry | Drafts 1, 6 |
| `draft-mcguinness-mission-actor-provenance` | Actor Provenance Profile | Drafts 1, 6 |
| `draft-mcguinness-mission-attestation` | Mission Attestation Profile | Drafts 1, 6, ACAP |
| `draft-mcguinness-mission-policy-projection` | Mission Policy Projection | Drafts 1, 6 |

Each gets its own draft when there is sufficient implementation interest and the design is stable. Until then they are sketched in the blog (Part 7 Optional Modules) and the Runtime Enforcement Profile (Draft 6) references them as composable extensions.

---

## What Stays in the Blog

The blog series carries the conceptual argument, worked examples, and applied analysis. The drafts carry the normative wire requirements.

| Blog post | Future role |
| --- | --- |
| Part 1: Missing Abstraction | Argument for why a Mission is needed. Links to Draft 1 (Framework). Stays in the blog. |
| Part 2: Mission Model | Affirmative argument for the Mission primitive. Reader-friendly explainer for Draft 1. |
| Part 3: Mission Shaper | Reader-friendly explainer; links to Draft 10. |
| Part 4: Mission-Bound OAuth Profile | Reader-friendly explainer; links to Drafts 1 and 2. Worked example stays here. |
| Part 4 Extensions: OAuth Extensions companion | Reader-friendly explainer; links to Drafts 3, 4, 5, 6 (the former-extension specs). |
| Part 5: AAuth Composition | Reader-friendly explainer; links to Draft 7. |
| Part 6: Mission Authority Server | Reader-friendly explainer; links to Draft 8. |
| Part 7: Runtime Enforcement | Reader-friendly explainer; links to Draft 9 and the future Optional Module drafts. |
| Part 8: MCP Application | Applied use case. Stays in the blog. Links to Drafts 1, 2, 9 for protocol detail. |
| Part 9: Capability Model | Reader-friendly explainer; links to Draft 12. |

The blog posts retain their arguments, diagrams, worked examples, TL;DR and spine framing. They drop normative MUST/SHOULD/MAY language; those move to the drafts.

## Dependency Graph

```
                          ┌──────────────────────────────────────┐
                          │ Draft 1: Mission Model & Framework   │
                          └──────────────────┬───────────────────┘
                                             │
        ┌────────────────────┬───────────────┼────────────────────┬───────────────────┐
        │                    │               │                    │                   │
        ▼                    ▼               ▼                    ▼                   ▼
┌───────────────┐  ┌─────────────────┐  ┌──────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Draft 2:      │  │ Draft 7: AAuth  │  │ Draft 10:│  │ Draft 9:        │  │ Draft 8: MAS    │
│ OAuth Profile │  │ Profile         │  │ Shaper   │  │ Runtime         │  │                 │
└───────┬───────┘  └────────┬────────┘  └──────────┘  └─────────────────┘  └─────────────────┘
        │                   │
        │     ┌─────────────┴──────────────────────────────────┐
        │     │ Features composed by OAuth and AAuth Profiles: │
        │     │   Draft 3: Mission Expansion                   │
        │     │   Draft 4: Delegated Authority Validation      │
        │     │   Draft 5: Same-IdP Chain Continuation         │
        │     │   Draft 6: Transaction Token Chaining          │
        │     └────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────┐
│ Draft 8 (MAS) composes both OAuth and AAuth Profiles  │
└───────────────────────────────────────────────────────┘

                          ┌──────────────────────────────────────┐
                          │ Draft 11: Migration                  │
                          │ (references Drafts 1, 2, 7)          │
                          └──────────────────────────────────────┘

                          ┌──────────────────────────────────────┐
                          │ Draft 12: Capability Model           │
                          │ (references Drafts 1-10)             │
                          └──────────────────────────────────────┘
```

Draft 1 (Framework) is foundational: every other draft references it for the Mission Model.

Drafts 3-6 (Features) are composable extensions. Each profile (OAuth, AAuth) chooses which features to compose with at each capability level.

Drafts 11 and 12 are terminal: Migration is operational guidance; Capability Model categorizes deployments by which other drafts they implement.

## Recommended Drafting Order

1. **Draft 1: Mission Model and Framework.** Foundational. Establishes the abstract model every profile and feature references. Highest priority.
2. **Draft 2: Mission-Bound OAuth Profile.** First substrate composition. Sets the pattern for how profiles compose existing standards with the Framework.
3. **Draft 3: Mission Expansion.** Substrate-neutral feature; the most-referenced extension; profiles will compose with it at Level 2+.
4. **Draft 9: Mission-Bound Runtime Enforcement Profile.** Substrate-independent; can advance in parallel with Drafts 2 and 3 once the Framework's runtime contracts are stable.
5. **Draft 7: Mission-Bound AAuth Composition Profile.** Second substrate composition. Depends on the Framework for governance vocabulary and on AAuth `-01`.
6. **Draft 8: Mission Authority Server.** Depends on Drafts 2 and 7 for substrate-local baseline.
7. **Draft 4: Delegated Authority Validation.** Builds on Mission Expansion (Draft 3) and the OAuth Profile (Draft 2).
8. **Draft 5: Same-IdP Chain Continuation Assertion.** OAuth substrate extension; lower priority unless SaaS continuation is a near-term deployment need.
9. **Draft 6: Mission-Bound Transaction Token Chaining.** Composes with Fletcher's chaining draft; lowest priority until that work matures.
10. **Draft 10: Mission Shaper Profile.** Client-side; lower priority for standardization.
11. **Draft 11: Migration Guide.** After substrate profiles stabilize.
12. **Draft 12: Capability Model.** Last; categorizes the others.

---

## Open Questions for Karl

Before I start writing Draft 1, please confirm or redirect on each:

1. **Common Constraints Catalog: Mission Model (Draft 1) or OAuth Profile Core (Draft 2)?** The catalog defines abstract bounds on Missions (`max_calls`, `geo`, `data_classification`, etc.) that apply across substrates. My recommendation: in Draft 1 (Framework), with substrate profiles defining wire serialization. You said "constraints belong in core" — confirm core means Framework (Draft 1), not OAuth Profile Core.

2. ~~**OAuth Extensions: one spec or each extension its own spec?**~~ Resolved: each feature is its own spec. The former OAuth Extensions catchall is split into Mission Expansion (Draft 3, substrate-neutral, includes Concurrent Expansion), Delegated Authority Validation (Draft 4), Same-IdP Chain Continuation Assertion (Draft 5), and Mission-Bound Transaction Token Chaining Composition (Draft 6). Token Size at Depth becomes operational guidance inside the OAuth Profile and MAS specs rather than its own draft.

3. **Runtime Optional Modules: deferred to separate per-module drafts.** Each becomes its own Standards Track draft when it reaches enough maturity. Confirm? The initial set ships without them.

4. **AAuth Composition Profile category: Standards Track confirmed?** The substrate is itself a draft, so we declare a normative dependency on AAuth -01 stabilizing.

5. **Shaper Profile: Standards Track or Informational?** Client-side processing spec. My recommendation: Standards Track with explicit conformance for the trace artifact and refusal protocol; everything else is guidance.

6. **Workgroup targeting.**
   - Draft 1 (Framework): OAUTH WG or independent submission? It's foundational and substrate-neutral; could go to either.
   - Draft 2 (OAuth Profile): OAUTH WG.
   - Draft 3 (Mission Expansion): OAUTH WG or AUTHZEN (since it composes AuthZEN Access Request).
   - Draft 4 (Delegated Authority Validation): OAUTH WG or independent.
   - Draft 5 (Same-IdP Chain Continuation Assertion): OAUTH WG.
   - Draft 6 (Transaction Token Chaining Composition): OAUTH WG, coordinated with Fletcher's draft.
   - Draft 7 (AAuth Composition): independent submission (since AAuth itself is independent).
   - Draft 8 (MAS): OAUTH WG or independent. Cross-substrate; lean independent because OAUTH WG may not want to charter cross-substrate work.
   - Draft 9 (Runtime Enforcement): AUTHZEN WG.
   - Draft 10 (Shaper): OAUTH WG or independent. Lean independent.
   - Drafts 11, 12 (Migration, Capability Model): independent submission.

7. **Mission Authority Server as "Server / Topology" layer.** The MAS defines a new server role, which is more than just composing existing standards. I put it in its own layer. Alternative: call it a profile too. Recommendation: keep "Server / Topology" since the MAS role is genuinely new architecture.

8. **Capability advertisement metadata registry.** Lives in Draft 12 (Capability Model), since the model defines the vocabulary. Confirm.

## Recommended Next Step

Confirm or revise the layered breakdown above, and answer the open questions (especially #1, #2, and #6). Once you sign off, I will start with Draft 1 (Mission Model and Framework) as the foundational spec and quality bar.

A fully fleshed-out, IETF-reviewable Standards Track draft for the Framework is roughly a week of focused work (30-40 pages, complete IANA Considerations, substantive Security Considerations, normative throughout). I will not try to compress that into one session at the cost of quality. Plan: produce a first complete draft for review, iterate based on your feedback, then move to Draft 2.
