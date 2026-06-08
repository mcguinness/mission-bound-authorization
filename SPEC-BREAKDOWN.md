# Mission-Bound Authorization: Draft Roadmap and Spec Breakdown

This document defines what becomes a standards-track Internet-Draft, what stays in the [blog series](https://notes.karlmcguinness.com/series/mission-bound-authorization/), and the dependency order for drafting.

The breakdown is open for revision before drafting begins. Comments inline; see the open questions at the end.

## Summary

Seven candidate I-Ds, split along substrate boundaries and architectural layers. Six Standards Track, one Informational.

| # | Short name | Title | Category | Approx pages | Source post |
| --- | --- | --- | --- | --- | --- |
| 1 | `draft-mcguinness-oauth-mission-bound` | Mission-Bound OAuth Profile | Standards Track | 40-50 | Part 4 OAuth Profile |
| 2 | `draft-mcguinness-oauth-mission-bound-extensions` | Mission-Bound OAuth Composition Extensions | Standards Track | 30-40 | Part 4 Extensions |
| 3 | `draft-mcguinness-aauth-mission-bound` | Mission-Bound Composition Profile for AAuth | Standards Track | 25-35 | Part 5 AAuth |
| 4 | `draft-mcguinness-mission-authority-server` | Mission Authority Server Profile | Standards Track | 30-40 | Part 6 MAS |
| 5 | `draft-mcguinness-mission-runtime-enforcement` | Mission-Bound Runtime Enforcement Profile | Standards Track | 35-50 | Part 7 Runtime |
| 6 | `draft-mcguinness-mission-shaper-profile` | Mission Shaper Profile | Standards Track | 20-30 | Part 3 Shaper |
| 7 | `draft-mcguinness-mission-capability-model` | Mission-Bound Authorization Capability Model | Informational | 20-25 | Part 9 Capability |

Total: roughly 200-270 pages of normative content. This is a multi-session drafting effort; the recommended order is below.

---

## Draft 1: `draft-mcguinness-oauth-mission-bound`

**Mission-Bound OAuth Profile**

**Category:** Standards Track. **Target WG:** OAUTH. **Status:** New.

### Abstract

This profile adds a durable, integrity-anchored Mission record to OAuth 2.0 as a first-class artifact distinct from authority. A client submits structured Mission Intent; the Authorization Server validates and renders it, records the Approved Mission, derives `authorization_details`, and binds issuance, refresh, and Token Exchange to that record. Tokens carry a `mission` claim that references the governance record. The profile composes with RFC 9396, RFC 9126, RFC 8693, RFC 9449, RFC 8705, and Identity Chaining.

### Key normative requirements

- AS MUST accept the `mission_intent` parameter at the Pushed Authorization Request endpoint (RFC 9126). Submission outside PAR is NOT permitted.
- AS MUST validate the Mission Intent against client registration and deployment policy before consent.
- AS MUST render the validated Mission Intent and derived authority for the approving principal. The presented disclosure MUST be canonicalized (JCS, RFC 8785) and committed via `consent_rendering_hash`.
- AS MUST compute `proposal_hash`, `authority_hash`, and `consent_rendering_hash` as defined and store all three on the Mission record.
- AS MUST issue a stable, opaque `mission.id` for each approved Mission and set `mission.origin` to the AS issuer URI.
- AS MUST issue access tokens carrying the `mission` claim with `id` and `origin`.
- AS MUST sender-constrain Mission-bound credentials (DPoP per RFC 9449 or mTLS per RFC 8705).
- AS MUST gate refresh, Token Exchange (RFC 8693), and any other credential-derivation path on Mission state. Derivation against a non-active Mission MUST be refused with the inactive-Mission signal defined in this profile.
- AS MUST expose a Mission inventory and lifecycle operations (revoke, complete; suspend and resume OPTIONAL at this level).
- AS MUST key audit records on `mission.id` and `mission.origin`.
- AS MUST derive `authorization_details` from the Approved Mission. Every derived entry MUST be a subset of an approved entry of the same `type`.

### IANA Considerations

This document registers:

1. **`mission_intent`** in the IANA Pushed Authorization Request Parameters Registry (created by this document or one of its dependencies if not already established).
2. **`mission_resource_access`** in the IANA OAuth Authorization Request `authorization_details` Type Registry.
3. **`mission`** in the IANA JSON Web Token Claims Registry.
4. **`evidence_id`** in the IANA JWT Claims Registry (or scoped to Mission claim).
5. **OAuth Inactive Mission error code** in the appropriate error registry (e.g., `mission_inactive`).
6. Mission lifecycle state values: `pending_approval`, `active`, `suspended`, `revoked`, `completed`, `expired`, `rejected`.

### Security Considerations themes

- Compromised AS, compromised Shaper, compromised Resource AS.
- Replay of `mission.id` across audiences (mitigated by audience-pairwise identifiers, deferred to Extensions or MAS profile).
- Integrity-anchor non-guarantees (faithful rendering, comprehension, real-time honesty, principal authenticity).
- Mission identifier privacy and correlation risk.
- Sender-constraint downgrade.
- Mission expiry as a hard ceiling.

### Normative references

RFC 6749 (OAuth 2.0), RFC 9126 (PAR), RFC 9396 (RAR), RFC 8693 (Token Exchange), RFC 9068 (JWT Access Tokens), RFC 7662 (Introspection), RFC 7009 (Revocation), RFC 9449 (DPoP), RFC 8705 (mTLS), RFC 7519 (JWT), RFC 8785 (JCS), RFC 8174 (BCP 14 update).

### Informative references

Identity Chaining (`draft-ietf-oauth-identity-chaining`), ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`), AAuth (`draft-hardt-oauth-aauth-protocol`), AuthZEN Authorization API, AuthZEN Access Request, ACAP (`draft-yakung-oauth-agent-attestation`).

### Out of scope (deferred to other drafts)

- Mission Expansion wire mechanics → Extensions
- Common Constraints Catalog → Extensions
- Delegated Authority Validation → Extensions
- Concurrent Expansion reconciliation → Extensions
- Same-IdP Chain Continuation → Extensions
- Transaction Token Chaining composition → Extensions
- Multi-AS ID-JAG → references existing OAuth identity-chaining work
- Runtime enforcement at the RS → separate runtime profile
- MAS topology → separate MAS profile

---

## Draft 2: `draft-mcguinness-oauth-mission-bound-extensions`

**Mission-Bound OAuth Composition Extensions**

**Category:** Standards Track. **Target WG:** OAUTH. **Status:** New. **Depends on:** Draft 1.

### Abstract

This document defines composition extensions to the Mission-Bound OAuth Profile. Each extension is independently adoptable and addresses a surface that the Core profile deliberately leaves open: machine-enforceable budget and constraint bounds, open-world tool semantics, concurrent Mission Expansion, deep delegation chains, same-IdP SaaS continuation, and cross-trust-domain Transaction Token chaining.

### Sections (each is a standalone extension)

1. **Common Constraints Catalog**: standardized `context` keys with stable semantics (`max_calls`, `max_value`, `max_duration`, `aal`, `geo`, `data_classification`, etc.), each with Mission commitment semantics and runtime enforcement contract.
2. **Mission Expansion Wire Mechanics**: eligibility signaling on denial, initiator authentication, workflow outcomes (synchronous approved, async approved, denied, expired), and binding the successor Mission to the prior Mission via `mission.supersedes`.
3. **Delegated Authority Validation for Open-World Tools**: how Resource ASes validate authority for tools discovered at runtime when the originating AS lacks the resource's ontology.
4. **Concurrent Mission Expansion Reconciliation**: when multiple expansion requests are in flight, how successor Missions reconcile.
5. **Token Size at Depth**: mitigations for credential growth in deep delegation chains (audience-filtered Authority Set projection, reference dereferencing).
6. **Same-IdP Chain Continuation Assertions**: how a long-running task continues across resource access boundaries inside one IdP.
7. **Transaction Token Chaining Composition**: how the Mission handle and Authority Set transcribe through the `txn_claims` object in JWT Authorization Grants per `draft-fletcher-transaction-token-chaining-profile`.
8. **Stage 0-5 Migration Story** (Informational, possibly its own draft): incremental adoption path for an existing OAuth AS.

### IANA Considerations

- Common Constraints Catalog registry (new): catalog key registry with name, semantics, commitment shape, enforcement reference.
- Mission Expansion error codes and response shapes.
- Successor-Mission claim if separate from `mission.supersedes`.

### Open question

Does the Migration Story belong in this draft or a separate Informational draft? My recommendation: separate Informational draft (`draft-mcguinness-oauth-mission-bound-migration`), since it is operational guidance rather than wire protocol.

---

## Draft 3: `draft-mcguinness-aauth-mission-bound`

**Mission-Bound Composition Profile for AAuth**

**Category:** Standards Track. **Status:** New. **Submission type:** Independent or via the same group that handles AAuth. **Depends on:** Draft 1 (governance vocabulary), `draft-hardt-oauth-aauth-protocol`.

### Abstract

AAuth defines a native Mission. This profile composes that native model with the Mission-Bound governance vocabulary: identifier mapping, hash domain separation, Authority Set projection, lifecycle composition, and an optional resumable suspension extension. The composition preserves AAuth's wire protocol and adds the contracts needed for AAuth credentials to participate in Mission-Bound governance.

### Key normative requirements

- AAuth Person Server MUST preserve the native `(approver, s256)` Mission reference unchanged.
- Composition MUST establish a stable `(mission.id, mission.origin)` governance reference and bind it to `(approver, s256)`.
- Composition MUST compute `proposal_hash`, `authority_hash`, `consent_rendering_hash` separately from AAuth's exact-body Mission hash. The hash domains are disjoint by construction.
- Composition MUST project an Authority Set into AAuth resource-token and auth-token issuance.
- Composition MUST map AAuth's two-state lifecycle (`active`, `terminated`) onto the governance lifecycle states.
- Composition MUST gate AAuth resource-token and auth-token issuance on governance Mission state.
- Optional: Resumable Suspension extension with `mission_suspended` error format and resume probe semantics.

### IANA Considerations

- AAuth-side governance-mapping fields, if separate from AAuth's native registry.
- `mission_suspended` error code.

### Open question

Should the AAuth composition profile be a Standards Track IETF I-D, or carried as an extension within the AAuth draft itself? Recommendation: separate profile, since governance composition is a distinct contract layered above AAuth.

---

## Draft 4: `draft-mcguinness-mission-authority-server`

**Mission Authority Server Profile**

**Category:** Standards Track. **Target WG:** OAUTH or independent. **Status:** New. **Depends on:** Drafts 1 and 3.

### Abstract

A Mission Authority Server (MAS) holds the canonical Mission record so OAuth Authorization Servers and AAuth Person Servers can project from one governance object. This profile defines MAS metadata and discovery, the substrate-neutral Authority Set serialization, audience-pairwise Mission identifiers, request flows for consumer-mediated and direct submission, an authenticated Mission Status surface, and the cross-substrate revocation propagation contract.

### Key normative requirements

- MAS MUST publish discovery metadata at a well-known URL.
- MAS MUST issue stable `mission.id` and set `mission.origin` to its issuer URI.
- MAS MUST commit a canonical Authority Set distinct from any substrate's wire serialization.
- MAS MUST authenticate Mission Status responses (signed metadata or signed responses).
- MAS MUST support audience-pairwise Mission identifiers if requested by an OAuth AS or AAuth PS.
- Consuming OAuth AS or AAuth PS MUST validate the Mission projection before issuing local credentials.
- Revocation at the MAS MUST propagate to consuming domains (event-driven via SSF or polled via Mission Status).

### IANA Considerations

- MAS metadata registry (new, well-known URL suffix).
- Mission Status response shape.
- Cross-substrate Authority Set serialization.
- Pairwise identifier protocol.

---

## Draft 5: `draft-mcguinness-mission-runtime-enforcement`

**Mission-Bound Runtime Enforcement Profile**

**Category:** Standards Track. **Target WG:** AUTHZEN (composes with AuthZEN Authorization API). **Status:** New. **Depends on:** Drafts 1 and/or 3 for governance vocabulary; AuthZEN Authorization API.

### Abstract

This profile specifies a substrate-independent contract for evaluating each consequential action against the Mission's versioned policy view, the audience-relevant Authority Set projection, authenticated actor context, and current Resource policy. It defines reproducible Mission-to-policy materialization, the Resource-Side Enforcement Contract (RS-D), PEP placement rules, Capability Source Binding, parameter binding, runtime failure handling, AuthZEN evaluation with Mission inputs, authority-expandable denial handling, and the Runtime Evidence Object.

### Key normative requirements

- PEP MUST evaluate every consequential action against a versioned Mission policy view.
- State authority or trusted compiler MUST reproducibly materialize the approved Mission tuple as an evaluable policy view; the materialization MUST be deterministic for a given (Authority Set, policy version, schema version) tuple.
- PDP request MUST carry the Mission projection, Mission state, applicable Authority Set entries, authenticated subject and actor context, resource, action, parameters, and tenant context.
- Resource Server claiming RS-D MUST consult the PDP before any consequential action; bypass MUST NOT be possible within the claimed enforcement scope.
- Decision evidence MUST be recorded for every consequential decision; the Runtime Evidence Object format is defined in this profile.
- Denials caused specifically by missing-but-eligible Mission authority MUST be returned as requestable expansions (AuthZEN Access Request).
- Parameter binding MUST close the time-of-check-time-of-use gap via `parameter_digest` or equivalent.

### IANA Considerations

- Runtime Evidence Object media type and registry.
- Mission policy materialization profile.
- Decision evidence claim names.
- AuthZEN PDP extension parameters (in coordination with AuthZEN).

### Open question

Are the Optional Modules (Tool Binding, Decision Receipt, Purpose Registry, Actor Provenance, Attestation, Policy Projection) part of this draft as appendices, or separate per-module drafts? Recommendation: separate drafts for each that reaches enough maturity for interoperability claims; Runtime Enforcement Core stays standalone.

---

## Draft 6: `draft-mcguinness-mission-shaper-profile`

**Mission Shaper Profile**

**Category:** Standards Track (alternatively Informational). **Target WG:** OAUTH or independent. **Status:** New. **Depends on:** Drafts 1 and 3.

### Abstract

The Mission Shaper is the client-side component that transforms user input into structured Mission Intent. This profile defines the Shaper's contract with the orchestrator, the versioned discovery snapshot it consumes, non-authoritative derivation hints, the ambiguity-surfacing protocol, refusals, and the Shaper Trace audit artifact. The Shaper never issues authority; its output is untrusted until the validating server admits it.

### Key normative requirements

- A conforming Shaper MUST NOT issue authority, derive scopes, or mint tokens.
- A conforming Shaper MUST surface material ambiguity to the user rather than silently resolving.
- A conforming Shaper MUST emit a Shaper Trace bound to the discovery snapshot version.
- Derivation hints, where emitted, MUST be tagged as non-authoritative and the validating server MUST treat them as such.

### IANA Considerations

- Shaper Trace media type.
- Ambiguity-surfacing response schema.
- Discovery snapshot versioning.

### Open question

Standards Track or Informational? The Shaper is client-side and its output is untrusted, so a conforming Shaper is loosely defined. A reasonable case for Informational. Recommendation: Standards Track with explicit conformance for the trace artifact and refusal protocol; everything else is guidance.

---

## Draft 7: `draft-mcguinness-mission-capability-model`

**Mission-Bound Authorization Capability Model**

**Category:** Informational. **Status:** New. **Depends on:** Drafts 1, 3, 4, 5 (for capability mapping).

### Abstract

This document defines a substrate-neutral capability and adoption model for Mission-Bound Authorization. Capability is reported as a coordinate on three axes: the Capability Ladder (Levels 0-5), Resource Server Tiers (RS-A through RS-D), and Authorization Domain Tiers (AD-1 through AD-3). The document defines three named adoption claims (Mission-Bound Issuance, Mission-Bound Runtime Enforcement, Mission-Bound Cross-Domain Projection), capability advertisement metadata, and the mapping from OAuth-only, AAuth-only, and cross-substrate deployments onto the coordinate.

### Why Informational

The capability model is a description, not a wire protocol. Conformance is claimed against the substrate or runtime profile. The capability coordinate is a reporting and adoption tool.

### IANA Considerations

- Capability advertisement metadata: `mission_authorization_domain_tiers_supported`, `mission_ladder_levels_supported`, `mission_profiles_supported`, `mission_optional_modules_supported`. Registry creation if not already.

---

## What Stays in the Blog

The blog series carries the conceptual argument, worked examples, and applied analysis. The drafts carry the wire.

| Blog post | Future role |
| --- | --- |
| Part 1: Missing Abstraction | Conceptual argument. Links to all drafts for normative detail. Stays in the blog. |
| Part 2: Mission Model | Affirmative argument for the Mission primitive. Vocabulary table, trust map, name defense. Stays in the blog. |
| Part 3: Mission Shaper Profile | Reader-friendly explainer that links to Draft 6 for normative detail. Stays in the blog. |
| Part 4: Mission-Bound OAuth Profile | Reader-friendly explainer that links to Draft 1. Worked example stays here. |
| Part 4 Extensions: OAuth Extensions companion | Reader-friendly explainer that links to Draft 2. |
| Part 5: Mission-Bound AAuth | Reader-friendly explainer that links to Draft 3. |
| Part 6: Mission Authority Server | Reader-friendly explainer that links to Draft 4. |
| Part 7: Runtime Enforcement Profile | Reader-friendly explainer that links to Draft 5. |
| Part 8: MCP Application | Applied use case. Stays in the blog. Links to Drafts 1 and 5 for protocol detail. |
| Part 9: Capability Model | Reader-friendly explainer that links to Draft 7. |

The blog posts retain their arguments, diagrams, worked examples, and TL;DR/spine framing. They drop MUST/SHOULD/MAY normative requirements; those move to the drafts.

## What Moves to the Specs

- All MUST/SHOULD/MAY/REQUIRED/RECOMMENDED/OPTIONAL normative statements.
- Wire formats: JSON shapes, parameter names, claim values, error codes.
- IANA registry actions: new registries and new entries in existing registries.
- Security Considerations sections (formal, complete, addressing each named threat).
- Conformance checklists (in the form expected by IESG review).
- Cross-references between drafts (formal, with section numbers).

The blog explains *why* a MUST exists. The draft says *what* MUST happen.

## Dependency Graph

```
                                  ┌─────────────────────────────────┐
                                  │ Draft 1: OAuth Mission-Bound    │
                                  └─────────────┬───────────────────┘
                                                │
                ┌───────────────────────────────┼──────────────────────────────────┐
                │                               │                                  │
                ▼                               ▼                                  ▼
   ┌────────────────────────┐    ┌──────────────────────────┐    ┌────────────────────────┐
   │ Draft 2: OAuth Ext     │    │ Draft 6: Shaper Profile  │    │ Draft 5: Runtime Enf   │
   └────────────────────────┘    └──────────────────────────┘    └────────────────────────┘
                                                                              ▲
                ┌─────────────────────────────────────────────────────────────┘
                │
                ▼
   ┌────────────────────────┐
   │ Draft 3: AAuth Mission │ ───┐
   └────────────────────────┘    │
                                 ▼
                  ┌──────────────────────────┐
                  │ Draft 4: MAS Profile     │
                  └──────────────┬───────────┘
                                 │
                                 ▼
                  ┌──────────────────────────┐
                  │ Draft 7: Capability Model│
                  └──────────────────────────┘
```

Draft 1 is foundational: every other draft references it for governance vocabulary, Mission record semantics, integrity anchors, and lifecycle states.

Draft 7 (Capability Model) is terminal: it categorizes deployments by which of the other drafts they implement.

## Recommended Drafting Order

1. **Draft 1: OAuth Profile (Core).** Foundational. Establishes the governance vocabulary every other draft references. Highest priority.
2. **Draft 5: Runtime Enforcement Profile.** Substrate-independent; can advance in parallel once Draft 1 has stable governance vocabulary.
3. **Draft 3: AAuth Composition.** Depends on Draft 1 for governance vocabulary. Composes with AAuth `-01`.
4. **Draft 4: MAS Profile.** Depends on Drafts 1 and 3 for substrate-local baseline.
5. **Draft 2: OAuth Extensions.** Each extension is independently adoptable; can advance after Draft 1 stabilizes.
6. **Draft 6: Shaper Profile.** Lower priority for standardization; the contract is loose and the threat surface is contained.
7. **Draft 7: Capability Model.** Last, since it categorizes the others.

## Open Questions for Karl

Before I start writing Draft 1, please confirm or redirect on each:

1. **Split into 7 drafts vs single umbrella I-D?** I recommend the split. OAuth WG chairs typically prefer smaller, focused drafts that can advance independently. The umbrella would be ~250 pages and review-burdensome.

2. **Workgroup targeting.** OAUTH for Drafts 1, 2, 6; AUTHZEN for Draft 5; independent submission for Drafts 3, 4, 7; or different targeting?

3. **Author and organization fields.** Confirm `Karl McGuinness / ConductorOne` as author. Co-authors?

4. **AAuth composition (Draft 3): Standards Track or Informational?** The substrate is itself a draft; standardizing a composition profile against a draft creates dependency risk. Recommendation: Standards Track, with a normative dependency declared on AAuth -01 stabilizing.

5. **Mission Expansion: Core or Extensions?** Currently in the blog OAuth Profile (Part 4). Recommendation: move to Extensions (Draft 2), because expansion is a Level 2+ behavior and the minimum profile can ship without it.

6. **Runtime Enforcement Optional Modules.** Six modules (Tool Binding, Decision Receipt, Purpose Registry, Actor Provenance, Attestation, Policy Projection). One draft, multiple drafts, or appendix? Recommendation: Each gets its own draft when it reaches enough maturity for interoperability claims. Runtime Enforcement Core stays standalone.

7. **Migration Story Stages 0-5.** Currently in Part 4 Extensions companion. Recommendation: separate Informational draft (`draft-mcguinness-oauth-mission-bound-migration`), or keep in the blog. I lean toward the blog since it's operational rather than wire protocol.

8. **Capability advertisement metadata registry.** Does it belong in Draft 7 (Capability Model) or as part of Draft 1 (OAuth Profile)? Recommendation: Draft 7, since the model defines the vocabulary.

## Recommended Next Step

Confirm or revise the breakdown above. Once you sign off, I will start with Draft 1 (OAuth Profile) as the quality bar, then propose to continue with the others one at a time.

A fully fleshed-out, IETF-reviewable Standards Track draft for OAuth Profile is roughly a week of focused work (40-50 pages, normative throughout, complete IANA Considerations, substantive Security Considerations). I will not try to compress that into one session at the cost of quality. Plan: produce a first complete draft for review, iterate based on your feedback, then move to Draft 2.
