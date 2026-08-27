# The Mission-Bound Authorization draft catalog

This file is the exhaustive catalog: every draft in the family, with
the generated index first and the full prose entry for each document
below it. [README.md](README.md) is the curated explanation and links
here instead of restating the inventory.

Each document carries five independent axes, never collapsed into one
word. **Role** is architectural: **core** (the substrate kernel),
**adapter-binding** (a binding of the Mission model to a wire
protocol), **companion** (a profile or extension built on a binding or
on the substrate kernel), or **guide** (an informational document that
explains rather than defines, with no protocol interface to mature).
**Spec
maturity** is a design-maturity gate on the document's own claimed
interface, resolved against structured evidence in
[`candidate-gate.json`](candidate-gate.json), never a raw coverage
percentage or an inference from a "# Conformance" heading:
**candidate** requires an attested, commit-verified requirement
inventory (not merely a recorded audit, but one the checker confirms
exists), no `decide` issue scoped to the interface without a recorded
resolved_in_tree resolution, a named interoperability floor, examples
or a recorded waiver, and disclosed unstable external dependencies.
**Experimental** is design work still settling, gated on an unstable
external dependency, or lacking one of the above with no waiver;
**sketch** is an early exploration; **not applicable** is guide
documents, with no protocol interface to rate. Neither axis is
standards status or deployment history: no production Mission
deployment is known today on any binding. **Intended standards
category** is the document's own IETF front-matter category (`std`,
`exp`, or `info`): a statement of requested RFC category, not of WG
adoption, approval, or publication state; external dependency status
lives in [DEPENDENCIES.md](DEPENDENCIES.md). **Implementation/conformance**
is derived per document from the audited requirement rows in
`conformance-manifest.json` and shown beside spec maturity, never
folded into it: an empty ledger states that plainly rather than
reading as failure, since the ledger tracks what the reference
implementation has undertaken, not specification quality.
**Maintenance class** (active, frozen pending an upstream release, and
so on) is unchanged by this axis split.

The index table, this summary, and every draft's own family-status
block are generated from `family-manifest.json` and
`conformance-manifest.json` by `scripts/generate-drafts-index.mjs`;
everything outside their markers is hand-authored.

<!-- generated:family-counts:start -->

44 documents: 1 core, 5 adapter-binding, 35 companion, 3 guide.
Spec maturity: 1 candidate, 36 experimental, 4 sketch, 3 not applicable (guide documents; protocol maturity does not apply).
Conformance ledger (`conformance-manifest.json`): 612 requirement rows across 19 audited specs (149 tested, 55 partial, 405 todo, 3 blocked); 25 documents carry no rows in the audited set yet.

<!-- generated:family-counts:end -->

<!-- generated:drafts-index:start -->

| Document | Role | Spec maturity | Verbs | Group | Summary | Pull this in when |
|---|---|---|---|---|---|---|
| [AAuth Mission Expiry](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-aauth-mission-expiry.html) | companion | experimental | govern | Lifecycle | Profiles AAuth's `expires_at` mission-blob member: an immutable, consent-bound lifetime the base protocol enforces on every Person Server decision path, with lifetime caps on every token carrying `mission_s256`. | A citable profile of AAuth's native `expires_at` is needed (base AAuth enforces it regardless; the profile's own conformance line is OPTIONAL). |
| [Mission-Bound Authorization for the Agent Access Model](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aam.html) | companion | sketch | analyze | Architecture | Maps Cloudflare's Agent Access Model onto the family, realizing each of its six components with an existing mechanism and declining the grant review loop because Missions are not standing grants. | Adopting Cloudflare's AAM vocabulary and mapping it onto existing mechanisms. |
| [Mission Context Binding for AAuth](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html) | adapter-binding | experimental | approve | The substrate and the bindings | The thin AAuth-native binding: it uses AAuth's existing mission blob, `{approver, s256}` reference, propose/clarify/approve flow, and active and terminated states unchanged, and defines no new wire members. | The substrate is AAuth: Mission context on its native propose/approve flow. |
| [AAuth Mission Management](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth-management.html) | companion | experimental | govern | Lifecycle | The AAuth-native companion promised by the AAuth protocol: authenticated status, permanent termination, optional immutable expiry, and delegation-tree queries at the existing Person Server `mission_endpoint`. | Alongside the AAuth binding: status, termination, delegation-tree queries. |
| [Mission Approval Governance](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-approval-governance.html) | companion | experimental | approve | Approval time | Extracts approval-authority provenance into the Approval Governance Record: an issuer-retained, issuer-signed record of who approved, under which authority, and why the decision satisfied governance. | Approval authority itself needs authenticated, policy-backed provenance. |
| [An Architecture for Mission-Bound Authorization](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html) | guide | not applicable | analyze | Architecture | The single structural view: the delegated-authority-layer thesis, a Mission's life end to end, the seven invariants, the substrate interface, the verb spine, the Mission Assurance Levels, and the Deployment Profile. | Before adopting anything: the Mission model, invariants, and assurance levels the rest cite. |
| [Mission Audit Transparency](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-audit.html) | companion | experimental | prove | Proof and portability | Makes the suite's evidence tamper-evident and independently verifiable by registering it into a SCITT Transparency Service as Signed Statements. | A cross-domain party must verify evidence integrity without trusting issuer logs. |
| [Mission Authority Server](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html) | adapter-binding | experimental | approve | The substrate and the bindings | A peer binding, the AS-optional deployment mode, and the estate control plane of the delegated-authority layer. | The AS cannot change: run Mission governance as a standalone control plane. |
| [Mission-Bound Runtime Enforcement: AuthZEN Profile](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html) | companion | experimental | enforce | Runtime enforcement | The concrete OpenID AuthZEN binding of the runtime decision contract. | The PDP speaks AuthZEN and needs the decision-contract wire mapping. |
| [Mission Capability Binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-capability-binding.html) | companion | experimental | enforce | Agent runtime | Binds a Mission's approved catalog-sourced entry (an MCP tool, an OpenAPI operation, or an equivalent) to the capability source it was derived from: `tool_id`, source, and a content digest recorded at derivation and verified at decision time. | Actions come from a discovered catalog where invoked identity can drift from approval. |
| [Mission Open-World Discovery](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-discovery.html) | companion | experimental | govern | Lifecycle | Makes discovery a governed operation for agents that meet resources their approval could not name, defining the Encounter, resource identity pinning, two-mode Discovery Adjudication, and Discovery Evidence. | An open-world agent meets resources its approval never named. |
| [Mission Evidence Envelope](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-evidence-envelope.html) | companion | sketch | prove | Proof and portability | A generic, binding-neutral evidence envelope and payload-type registry a future evidence kind MAY register into instead of minting a one-off object and media type, seeded with Intent Admission Evidence as its first payload type; migrates none of the family's existing evidence kinds. | A new evidence kind is being designed and a deployment wants to avoid minting another bespoke media type, or Intent Admission Evidence's inbound assertion and emitted attestation are needed. |
| [Mission-Bound Authorization for GNAP](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-gnap.html) | adapter-binding | sketch | approve | The substrate and the bindings | Experimental sketch: the fifth binding, to the Grant Negotiation and Authorization Protocol (RFC 9635) authorization server, and the second authored against the Mission Substrate Requirements contract. | Evaluating a GNAP deployment only. |
| [Mission-Aware Agent Harnesses](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html) | companion | experimental | run | Agent runtime | How an agent harness binds sessions, task graphs, queues, and sub-agent handles to Mission state, and how it must pause, suppress, or terminate work once the Mission is no longer active. | A harness holds session state across restarts and must stop work when the Mission dies. |
| [Mission Mandate](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-mandate.html) | companion | experimental | prove | Proof and portability | A signed, portable, independently verifiable statement of a Mission's committed facts (its identifiers, integrity anchors, Subject, Approver, and optionally its Authority Set), minted by the Mission Issuer. | An outside party must verify what was approved without a token-exchange hop. |
| [Mission Consumption Metering](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-metering.html) | companion | experimental | govern | Runtime enforcement | Defines the cumulative consumption bounds a Mission Intent may carry (`max_budget`, `max_calls`, `max_duration`, `max_egress_volume`), the `exclusive` latch, and the runtime metering and AuthZEN wire binding that enforce them. | A Mission needs cumulative caps (budget, calls, duration, egress), not just scope. |
| [Mission Orchestration and Unwinding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-orchestration.html) | companion | experimental | run | Agent runtime | How a multi-step or multi-Mission workflow assigns a reversibility class to each step, records an unwind plan before dispatch, and unwinds in-flight work safely when a Mission stops. | In-flight work must unwind safely if the Mission ends mid-workflow. |
| [Mission Runtime Evidence](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-evidence.html) | companion | experimental | enforce, prove | Runtime enforcement | The binding-neutral Decision Evidence, Execution Evidence, and Refusal Record objects a decision-API binding's PDP and PEP emit: their members, canonicalization, integrity envelope, media types, and retention. | Runtime enforcement is deployed and decisions need durable, verifiable records. |
| [Mission Runtime OAuth Adapter](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-oauth.html) | companion | experimental | enforce | Runtime enforcement | The OAuth 2.0 realization of the runtime core's binding-neutral contract: token presentation and validation, the `mission`/`act`/`cnf`/`aud` claim mapping, the `authorization_details` and `mission_resource_access` authority-entry mapping, and Resource-Owner Class Floors through OAuth protected resource metadata. | The Mission-bound credential is an OAuth access token and the runtime core's abstract roles need their concrete OAuth realization. |
| [Mission-Bound Runtime Enforcement](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html) | companion | experimental | enforce | Runtime enforcement | A binding-neutral decision contract for enforcing a Mission-bound credential at the point of use: within a declared enforcement scope, before each consequential action a Policy Enforcement Point obtains a permit from a Policy Decision Point that evaluates the action against the Mission. | Actions need a point-of-use check, not just issuance-time gating. |
| [Mission Transaction Authorization Profile for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-transaction-authorization.html) | companion | experimental | enforce | Runtime enforcement | Profiles the OAuth transaction authorization challenge for the Mission cross-domain case: a Transaction Authorization Server runs a fresh decision with a governed approval as input and issues a sender-constrained, single-use transaction token the resource verifies offline. | One action needs a fresh, portable, cross-org authorization with no live callback. |
| [Mission Security Model](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html) | guide | not applicable | analyze | Security model | A cross-cutting, Informational consolidation of the suite's trusted base. | Reviewing or auditing: the one consolidated trust and blast-radius view. |
| [Mission Intent Shaping](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.html) | guide | not applicable | propose | Approval time | How a client-side "shaper" turns a user's request into a candidate Mission Intent before it is submitted. | You need a defined client-side path from user prompt to candidate Mission Intent. |
| [Mission Substrate Requirements](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html) | core | candidate | approve | The substrate and the bindings | For authors of new bindings: a small, normative contextual-governance kernel (native Mission reference, identified Controller, authenticated Actor binding, immutable Approved Context, approval event, active/non-active gate, context propagation, ordered governance record), with stronger properties declared separately as capabilities. | Runtime implementers consume its commitment construction and kernel contract; binding authors profile it. |
| [Mission-Bound Authorization for UMA 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-uma.html) | adapter-binding | sketch | approve | The substrate and the bindings | Experimental sketch: the fourth binding, and the first authored against the Mission Substrate Requirements contract rather than extracted into it. | Evaluating a UMA 2.0 deployment only. |
| [Mission Approval Revision for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval-revision.html) | companion | experimental | approve | Approval time | Adds a `revisable` mode to Deferred Approval: the Authorization Server signals which dimensions it refused and invites the client to push a narrowing revision, continuing the same deferred approval instead of starting over. | Reviewers routinely narrow a proposed Mission rather than approve or deny. |
| [Mission Deferred Approval for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html) | companion | experimental | approve | Approval time | Makes the approval event asynchronous, profiling OAuth Deferred Token Response so a Mission approval can be deferred and polled. | Approval is asynchronous: a human review queue, not an immediate decision. |
| [Mission Offline Attenuation for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-attenuation.html) | companion | experimental | delegate | Sub-agents | Removes the Authorization Server from the sub-agent fan-out hot path, profiling Attenuating Agent Tokens so a Mission-bound token holder mints a narrower child token offline. | Deep fan-out makes an AS round-trip per narrowing too costly; mint offline. |
| [Mission Child Delegation for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-child-delegation.html) | companion | experimental | delegate | Sub-agents | Lets a parent Mission authorize a Child Mission for a sub-agent, with explicit parent lineage, strict-subset authority, expiry no later than the parent, fan-out controls, and cascade revocation when the parent reaches a terminal state. | A sub-agent needs its own Mission outliving a call frame, with cascade termination. |
| [Mission Consent Evidence for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-consent-evidence.html) | companion | experimental | approve, prove | Approval time | Commits the structured consent disclosure shown to the Approver at the approval event, through a `consent_rendering_hash` and a signed Consent Evidence object, so an auditor can reconstruct the recorded approval surface. | You must prove what the Approver actually saw, not only what was approved. |
| [Mission Containment for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-containment.html) | companion | experimental | govern | Lifecycle | Narrows a live Mission without ending it: on a declared protected event the Mission Issuer commits a contain transition whose issuer-held, monotonic, removal-only overlay gates every derivation while the approved anchors stay immutable. | A live Mission must be narrowed, not ended, on a protected event. |
| [Mission Continuation: Authorization Continuity for Mission-Bound Authorization](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-continuation.html) | companion | experimental | continue | Cross-domain projection | Profiles authorization continuity: how a Mission's work continues across hops and over time without re-presenting the original credential and without widening authority. | Authorized work continues across hops or time without re-presented credentials. |
| [Mission Cross-Domain Projection for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-domain.html) | companion | experimental | project | Cross-domain projection | Lets a single Mission be honored by Authorization Servers in other trust domains: the originating issuer projects audience-scoped authority through a short-lived, sender-constrained cross-domain grant, and the Resource AS mints its own local Mission-bound tokens preserving the `mission` claim. | A Mission from one trust domain must be honored by an AS in another (also the floor's conditional dependency). |
| [Mission Cross-Organizational Delegation for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-org-delegation.html) | companion | experimental | delegate, project | Cross-domain projection | Profiles Mission Offline Attenuation across organizational trust domains: an agent in one organization delegates a narrowed slice to an agent in another, and the relying party verifies the complete narrowing chain without calling the origin on the request path. | An attenuation chain crosses organizational trust domains. |
| [Mission Expansion for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-expansion.html) | companion | experimental | govern | Lifecycle | How to widen a Mission's authority: because authority can only narrow within a Mission, widening requires a fresh approval that creates a successor Mission superseding its predecessor. | Approved authority will predictably need to widen mid-task via fresh approval. |
| [Mission Issuance Grant for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-issuance-grant.html) | companion | experimental | approve | The substrate and the bindings | The issuance join: the middle integration between the standalone binding and a natively Mission-aware AS. | A MAS-governed estate wants Mission-bound gated tokens without full intake at each AS. |
| [Mission Management for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-management.html) | companion | experimental | govern | Lifecycle | The fleet-management surface the status profile defers: authenticated Mission enumeration and bulk lifecycle operations, dry-run first, with a per-Mission outcome manifest. | An operator needs fleet enumeration and bulk lifecycle across many Missions. |
| [Mission Progressive Authorization for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-progressive.html) | companion | experimental | govern | Lifecycle | At the initial approval the Approver also consents to an authority ceiling and a drawdown policy, letting the Mission Issuer adjudicate an in-ceiling expansion by policy instead of a fresh human approval. | Authority cannot be enumerated up front; policy-bounded drawdown beats over-provisioning. |
| [Mission Resource Access Profile for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-resource-access.html) | companion | experimental | approve | The substrate and the bindings | Defines mission_resource_access, split from the OAuth binding: resource exact/prefix matching, the action namespace and wildcard families, Common Constraints, per-entry delegation policy, and the subset/intersection algebra, plus this type's scope-projection safety conditions and machine-readable transformation-capability declaration. | The OAuth binding's supported authorization_details types include mission_resource_access, or you need its concrete subset/delegation/projection semantics. |
| [Mission Lifecycle Signals for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.html) | companion | experimental | govern | Lifecycle | A profile of the OpenID Shared Signals Framework: the Mission Issuer emits a signed Security Event Token on each Mission lifecycle transition, delivered by push or poll, so a consumer learns of a transition promptly without polling. | Consumers need push notice of state changes instead of polling per Mission. |
| [Mission Status and Lifecycle for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html) | companion | experimental | govern | Lifecycle | A `mission_id`-keyed status surface with signed responses, plus a lifecycle endpoint for explicit `revoke`, `suspend`, `resume`, and `complete` transitions and the `suspended` and `completed` states. | You must observe or change Mission state beyond token expiry (revoke, suspend, complete). |
| [Mission Template for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-template.html) | companion | experimental | approve | Approval time | An Approver consents once to a task template (a ceiling of resources, actions, and constraints plus a dispatch policy), and each dispatch then instantiates an ordinary, independently gated Mission from it at machine speed. | Machine-speed dispatch makes per-run approval infeasible; consent once to a ceiling. |
| [Mission Work Products](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-work-products.html) | companion | experimental | prove | Security model | Keeps information from carrying authority: a policy-free work-product provenance object attributes an artifact to the approved work that produced it, and a non-transitive handoff rule makes the receiving Mission re-evaluate any proposed action under its own Authority Set. | Artifacts cross into another Mission and must carry provenance, never authority. |
| [Mission-Bound Authorization for OAuth 2.0](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) | adapter-binding | experimental | approve | The substrate and the bindings | The OAuth 2.0 binding of the Mission model, the issuance profile to its OAuth companions: defines the OAuth realization of the Mission, the Mission Intent and Authority Set, the approval event and its `intent_hash` / `authority_hash` anchors, the `mission` token claim, the subset rule, and state-gated issuance. | Start here for OAuth issuance: any agent's approval must bind durably to the tokens it later uses. |

<!-- generated:drafts-index:end -->

## Reference stacks

The Architecture's four cumulative reference stacks (its Mission
Assurance Levels, realized on the OAuth binding), each level's
document set generated from `family-manifest.json`'s
`reference_stacks` object so this table cannot drift from the
manifest that also drives `check-family-manifest.mjs`'s check (g).
The Architecture's own [assurance levels
section](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
states each level's proof obligations; this table states only what
document set gets a reader there. The Architecture's five *packages*,
its own orthogonal decomposition, are deliberately not restated here
or anywhere in this repository (see README.md's Repository use
section).

<!-- generated:reference-stacks:start -->

| Level | Cumulative documents | Summary |
|---|---|---|
| Baseline Issuance | 1 document: Mission-Bound Authorization for OAuth 2.0 | The OAuth issuance profile alone: approved, anchored, state-gated Missions with no per-action control. |
| Runtime-Enforced | 4 documents: Mission-Bound Authorization for OAuth 2.0 + Mission-Bound Runtime Enforcement + Mission-Bound Runtime Enforcement: AuthZEN Profile + Mission Runtime Evidence | The default evaluation shape: point-of-use permits with durable decision and execution evidence, plus a freshness source. |
| Governed Agent | 6 documents: Mission-Bound Authorization for OAuth 2.0 + Mission-Bound Runtime Enforcement + Mission-Bound Runtime Enforcement: AuthZEN Profile + Mission Runtime Evidence + Mission-Aware Agent Harnesses + Mission Consent Evidence for OAuth 2.0 | What a deployment running autonomous AI agents should build: session-continuity stop and proof of what the Approver saw. |
| High-Assurance Agent | 6 documents: Mission-Bound Authorization for OAuth 2.0 + Mission-Bound Runtime Enforcement + Mission-Bound Runtime Enforcement: AuthZEN Profile + Mission Runtime Evidence + Mission-Aware Agent Harnesses + Mission Consent Evidence for OAuth 2.0 | The recommended architecture plus the named per-path claims; a claims level, not an additional document list. |

<!-- generated:reference-stacks:end -->

## The documents

Together these drafts form the **Mission-Bound Authorization suite**.
The suite takes its name from the model; the OAuth binding's title,
"Mission-Bound Authorization for OAuth 2.0", names what it is: one
binding of the model. Its OAuth companions refer to it as the
**"issuance profile"** (it governs issuance and derivation on that
substrate).

The naming encodes a boundary, by category rather than an exhaustive
list. `oauth-mission-*` extends the Authorization Server's own
surfaces: issuance, approval, lifecycle, evidence of consent.
`mission-*` (no leading `oauth-` or `aauth-`) specifies a component
outside the Authorization Server. Where that component is defined
against the Mission model's substrate primitives rather than one
binding, it names those primitives in a Mission Substrate section, and
the OAuth binding is that model's OAuth 2.0 realization, so another mission-based
protocol that supplies the same primitives can host the component
unchanged. Runtime enforcement and its AuthZEN binding, the agent
harness, orchestration, and the security model are examples, not the
complete set.

A third pattern distinguishes direction at the AAuth binding.
`aauth-mission-*` names an AAuth-native extension, a profile of a
member already inside AAuth's own approved mission blob (as
`draft-mcguinness-aauth-mission-expiry` profiles `expires_at`),
consistent with the sibling `draft-mcguinness-aauth-budget`
repository's own AAuth-native extensions. `mission-aauth-*` names the
Mission family's binding to AAuth and its companions
(`draft-mcguinness-mission-aauth`,
`draft-mcguinness-mission-aauth-management`), specified the same way
as the family's other non-OAuth components.

### Architecture

#### An Architecture for Mission-Bound Authorization

The single structural view: the delegated-authority-layer thesis, the
capability envelope, a Mission's life end to end, the seven
invariants, roles and components, the substrate interface (the
primitives a binding provides and the profiles consume), the verb
spine, deployment patterns, the Mission Assurance Levels, the
Deployment Profile, and the requirements the family answers.
Informational; it defines no mechanism, and the profiles remain
authoritative. The recommended first read.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)

#### Mission-Bound Authorization for the Agent Access Model

Experimental sketch. Maps Cloudflare's Agent Access Model onto the
family: each of AAM's six components is realized by an existing
mechanism (approval-gated issuance on two paths, the stateless PDP,
the mediated harness plus egress gate, Containment as the trust
ratchet, Mission Templates as the task template and capability
ceiling, and the Activity Log as a read-model join over family
evidence), and the grant review loop is deliberately not adopted
because Missions are not standing grants. The honesty boundaries are
stated plainly: an in-process egress gate claims no containment, and
authenticated protected events are never assumed honest. It defines
no binding and no new mechanism.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aam.html)

### Approval time

#### Mission Intent Shaping

How a client-side "shaper" turns a user's request into a candidate
Mission Intent before it is submitted. The shaper only proposes: its
output is untrusted input until the Mission Issuer validates, narrows,
and derives authority from it. Optional Shaping Evidence records how
the proposal was produced. (Informational.)

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.html)

#### Mission Consent Evidence for OAuth 2.0

Commits the structured consent disclosure shown to the Approver at the
approval event, through a `consent_rendering_hash` and a signed Consent
Evidence object, so an auditor can reconstruct the recorded approval
surface. A translation floor requires the disclosure to render
authority as natural language rather than serialized structure, and
Disclosure Interrogation lets the Approver ask why an entry is needed
before deciding, answered from recorded shaping and provenance
material. It commits what the Authorization Server recorded, not the
pixels presented or the Approver's comprehension.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-consent-evidence.html)

#### Mission Deferred Approval for OAuth 2.0

Makes the approval event asynchronous. Profiles OAuth
Deferred Token Response so a Mission approval can be deferred and
polled; the Mission record is created atomically with the asynchronous
decision. A proposal the reviewer will grant only in narrowed form
resolves to a denial, and the client resubmits a narrower Intent.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html)

#### Mission Approval Governance

Extracts approval-authority provenance into the Approval Governance
Record: an issuer-retained, issuer-signed record of who approved,
under which authority, and why the decision satisfied governance.
Assertions are authenticated, event-bound, and policy-authorized
before the evaluation contributes to Mission activation; the
committed record is immutable and never appears on tokens, protocol
messages, or enforcement projections. Required by the Enterprise
Mission Authority Profile under its recording triggers.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-approval-governance.html)

#### Mission Approval Revision for OAuth 2.0

Experimental companion to Deferred Approval. Adds a `revisable` mode:
when the Authorization Server can grant only a narrowed version of the
proposed Mission, it signals which dimensions it refused and invites
the client to push a narrowing revision, continuing the same deferred
approval instead of starting over. Narrowing only; deny-and-resubmit
under Deferred Approval alone is the stable path.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval-revision.html)

#### Mission Template for OAuth 2.0

Experimental. An Approver consents once to a task template: a ceiling of
resources, actions, and constraints, plus a dispatch policy and bounds.
Each dispatch then instantiates an ordinary Mission from the template by
policy, at machine speed, with no fresh approval per run. Every instance
is a full Mission, bounded by its own derived Authority Set,
independently gated and revocable, and never exceeding the ceiling.
High-consequence authority classes are never dispatched by policy; they
stay on a fresh human decision.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-template.html)

### Lifecycle

#### Mission Status and Lifecycle for OAuth 2.0

A `mission_id`-keyed status surface with signed responses, plus a
lifecycle endpoint for explicit `revoke`, `suspend`, `resume`, and
`complete` transitions and the `suspended` and `completed` states. It
lets a consumer holding only a `mission_id` ask the issuer for current
Mission state, and an authorized party change it. It also defines
Mission Completion, the narrowing counterpart of Expansion:
`terminal_when`, a Common Constraint that discharges a
`mission_resource_access` entry when its completion condition fires,
monotonic (only retires authority) and so safe against an injected
agent.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html)

#### Mission Lifecycle Signals for OAuth 2.0

A profile of the OpenID Shared Signals Framework: the
Mission Issuer
emits a signed Security Event Token on each Mission lifecycle
transition, delivered by push or poll, so a consumer learns of a
revocation, expiry, or other transition promptly without polling. It is
the push complement to the pull-based Status surface, a latency
optimization for deployments where per-Mission polling does not scale.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.html)

#### Mission Expansion for OAuth 2.0

How to widen a Mission's authority. Because authority can only narrow
within a Mission, widening requires a fresh approval that creates a
successor Mission, which supersedes its predecessor. Expansion is a
governance operation and is deliberately distinct from authentication
step-up.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-expansion.html)

#### Mission Progressive Authorization for OAuth 2.0

Experimental companion to Expansion. At the initial approval the
Approver additionally consents to an authority ceiling and a drawdown
policy; the Mission Issuer may then adjudicate an expansion that stays
within the ceiling by policy instead of a fresh human approval.
High-consequence and cross-domain authority always require the human.
Under Expansion alone, every widening is human-approved.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-progressive.html)

#### Mission Open-World Discovery

Experimental. Makes discovery a governed operation for agents that
meet resources their approval could not name. Defines the Encounter,
resource identity pinning (origin, the RFC 9728 resource-to-AS
metadata chain, self-declaration digests), Discovery Adjudication in
two modes (against a pre-consented ceiling, or contextually by the
binding's Controller as the AAuth Person Server does; bind, route to
a human, or refuse; default-closed in both), and Discovery Evidence
for the transparency log.
Two floors hold regardless of policy: a resource's self-declaration
never classifies its own consequences, and a tainted session never
binds egress-capable authority without a human.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-discovery.html)

#### Mission Management for OAuth 2.0

The fleet-management surface the status profile defers: authenticated
Mission enumeration (by subject, client, state, or expiry window, with
purpose-recorded audit) and bulk lifecycle operations (dry-run first,
then execute against the evaluated set, with a per-Mission outcome
manifest). Operator- and incident-response-facing; each bulk
transition applies the status profile's per-Mission semantics and
emits its per-Mission events. The highest-blast-radius surface in the
family, and documented as such.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-management.html)

#### AAuth Mission Management

The AAuth-native companion promised by the AAuth protocol: authenticated
status, permanent termination, optional immutable expiry, and
delegation-tree queries at the existing Person Server
`mission_endpoint`. Operations use only AAuth's native
`{approver, s256}` mission reference and preserve its two protocol states,
`active` and `terminated`; completion, revocation, expiry, supersession,
and administrative action are separate termination reasons. The Person
Server closes its local decision and issuance paths atomically, attempts
revocation of tracked Auth Tokens by `(iss, jti)`, and reports honestly
where already-issued, opaque, identity-based, or off-path access leaves a
bounded or unknown residual.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth-management.html)

#### AAuth Mission Expiry

Profiles AAuth's `expires_at` mission-blob member: an immutable,
consent-bound lifetime the base protocol enforces on every Person
Server decision path, with lifetime caps on every token carrying
`mission_s256`. This profile adds RFC 3339 date-time precision,
clock-skew documentation duties, and prompt termination at the
deadline. The Mission Context Binding for AAuth requires the member
on every mission.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-aauth-mission-expiry.html)

#### Mission Containment for OAuth 2.0

Optional. Narrows a live Mission without ending it. When a declared
protected event fires (a tainted read, an anomaly signal, a discovery
tainted-session event), the Mission Issuer commits a contain transition:
an issuer-held, versioned overlay removes capability from the Mission's
effective authority while the Mission stays active and the approved
anchors stay immutable. Containment is monotonic and removal-only, and
every derivation (token, child, cross-domain, offline) is gated on the
effective authority. Removed authority returns only through a successor
Mission under the expansion profile, with the predecessor's containment
history disclosed to the Approver.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-containment.html)

### Runtime enforcement

#### Mission-Bound Runtime Enforcement

A decision contract for enforcing a Mission-bound token at the point of
use: within a declared enforcement scope, before each consequential
action a Policy Enforcement Point obtains a permit from a Policy
Decision Point that evaluates the action against the Mission. Covers
action classification, where the enforcement point sits, the binding of
a permit to concrete request parameters to close the time-of-check to
time-of-use gap, the fail-closed posture for consumption bounds, and
fail-closed behavior generally. For the
high-consequence classes it adds credential custody and mediated
execution (the enforcement point, not the agent, holds the token's
sender-constraint key, so a compromised agent cannot act off-path) and
an action-bound approval for the highest-consequence classes. The
decision-API wire format is a deployment choice, so the contract does
not mandate one. Its two named claims, agent-compromise-resistant
enforcement and trifecta containment, set the High-Assurance Agent
bar, and the Mission Receipt makes a single action's evidence
portable.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html)

#### Mission Runtime OAuth Adapter

The OAuth 2.0 realization of the runtime core's binding-neutral
contract: token presentation and validation, the `mission`/`act`/`cnf`/
`aud` claim mapping onto the runtime core's abstract subject, actor,
sender-constraint, and audience roles, the `authorization_details` and
`mission_resource_access` mapping onto the runtime core's
effective-authority-set input, and Resource-Owner Class Floors carried
through OAuth protected resource metadata. Adds no enforcement
invariant of its own; every requirement it mentions is the runtime
core's, cited and mapped.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-oauth.html)

#### Mission Runtime Evidence

The binding-neutral Decision Evidence, Execution Evidence, and
Refusal Record objects a decision-API binding's PDP and PEP emit:
their members, canonicalization, integrity envelope, media types,
and retention. Defined against the runtime profile's abstract
decision output and failure classification, so any decision-API
binding produces the same records; the AuthZEN binding is one such
producer and emits them unchanged. Correlation across records and
wire artifacts of one evaluation is by `evaluation_id`; each record
additionally carries its own record identifier.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-evidence.html)

#### Mission-Bound Runtime Enforcement: AuthZEN Profile

The concrete OpenID AuthZEN binding of the runtime decision contract. It
maps the runtime profile's abstract decision inputs onto the AuthZEN
Authorization API request and response, emits the Decision Evidence,
Execution Evidence, and Refusal Record of the runtime evidence
companion, and maps every runtime failure condition onto a
wire-visible identifier. It binds the contract; it does not restate
the enforcement semantics the runtime profile owns or the record
formats the runtime evidence companion owns.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html)

#### Mission Consumption Metering

Experimental. Defines the cumulative consumption bounds a Mission
Intent may carry (`max_budget`, `max_calls`, `max_duration`,
`max_egress_volume`), the `exclusive` control that latches
conflicting action classes apart under a single approval, the
runtime metering that enforces them (atomic check-and-decrement,
reserve/commit postures, duration leases, settlement), and the AuthZEN
wire binding for lease renewal and settlement. Without it, Missions
carry no cumulative bounds; the runtime profile's fail-closed rule
covers any bound a deployment cannot meter.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-metering.html)

#### Mission Transaction Authorization Profile for OAuth 2.0

Profiles the OAuth transaction authorization challenge for the
Mission cross-domain case: a protected resource signs a challenge for
one normalized operation, a trusted Transaction Authorization Server
validates the challenge, the Mission or delegation chain, the
presenter, and a governed approval, runs a fresh decision with the
approval as input, and issues a sender-constrained, single-use
transaction token the resource verifies offline. The approval is
input, never a bearer bypass; the token carries no approval or
evidence bag. Experimental; profiles an unratified individual draft.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-transaction-authorization.html)

### The substrate and the bindings

The kernel contract first, then its five peer bindings. No
production Mission deployment is known today; OAuth brings the most
deployed substrate infrastructure, and Missions on it still require
the changes its binding defines.

#### Mission Substrate Requirements

For authors of new bindings. Defines a small, normative
contextual-governance kernel: a native Mission reference, identified
Controller, authenticated Actor binding, immutable Approved Context or
verifiable commitment, approval event, active/non-active gate with
bounded reliance, context propagation, and ordered governance record. Stronger properties are
declared separately as lifecycle-gated, state-observable,
structured-authority, monotonic-derivation, credential-bound,
independently-verifiable, and portable-evidence capabilities. Each
binding publishes a Mission Substrate Statement identifying the scope
and limitations of every claim; the kernel does not require OAuth
identifiers, RAR, JWT claims, a universal Authority Set, or common
integrity anchors. The kernel is adoptable outside the family; the
family vocabulary bridge, scoped precedence, and change-ownership
rule live in an appendix.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html)

#### Mission-Bound Authorization for OAuth 2.0

The OAuth 2.0 binding of the Mission model, the **issuance profile**
to its OAuth companions, and the published Internet-Draft. Defines
the OAuth realization of the Mission, the Mission Intent and
Authority Set, the approval event and its `intent_hash` /
`authority_hash` integrity anchors, the `mission` token claim, the
subset rule, and state-gated issuance. The `oauth-mission-*`
companions build on this binding; the binding-neutral documents
anchor on the substrate contract.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) · [Datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission) · [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mcguinness-oauth-mission) · [Diff](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.diff)

#### Mission Resource Access Profile for OAuth 2.0

The general-purpose `authorization_details` type the issuance profile's
own examples use throughout: `mission_resource_access`. Defines the
type's resource (exact or prefix) and action (with wildcard families)
matching, its generic per-entry constraints and the registered Common
Constraints vocabulary, a per-entry delegation policy, the subset and
intersection algebra a deployment uses to compare and narrow two
entries, this type's Scope Projection safety conditions, and its
declaration under the issuance profile's transformation-capability map.
A deployment MAY support this type, another AS-supported type, or
both; the issuance profile is type-agnostic and complete without it.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-resource-access.html)

#### Mission Authority Server

A peer binding, the AS-optional deployment mode, and the estate
control plane of the delegated-authority layer. A Mission Authority
Server (MAS) implements the Mission Issuer role (intent submission, the
approval event, the record, lifecycle, and state) without being an
OAuth Authorization Server and without deriving tokens. Enforcement
joins ordinary OAuth tokens to Missions at the Policy Decision Point,
so a deployment gets Mission governance with an unmodified AS. Joined
credentials are not Mission-bound, so runtime enforcement covers
every consequential path, and a path claiming the Enterprise
profile's high-consequence credential property MUST use Mission-bound
issuance (the Issuance Grant, or a natively Mission-aware AS). Above
the conformance floor,
the Enterprise Mission Authority Profile is the estate operating
mode: Join Assertions, instance-bound joins, a mapping contract,
policy-view distribution, and documented PEP coverage, with a
deployment topology, connector patterns, and a progressive adoption
path. Where an AS later becomes Mission-aware, the issuance profile
adds Mission-bound tokens for its resources while the MAS continues
to govern the estate.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html)

#### Mission Issuance Grant for OAuth 2.0

The issuance join: the middle integration between the standalone
binding and a natively Mission-aware AS. A short-lived, one-time,
audience-bound assertion minted by the Mission Authority Server for
an active Mission; an estate Authorization Server redeems it at its
token endpoint (RFC 7523 JWT authorization grant) and mints
Mission-bound tokens bounded by the grant's authority subset, capped
at Mission expiry, with refresh gated on Mission state. Restores
Mission-bound credentials and the issuance-gate kill switch without
the AS implementing the OAuth binding's intake, approval, or derivation
surfaces.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-issuance-grant.html)

#### Mission Context Binding for AAuth

The thin AAuth-native binding. AAuth already defines an immutable
mission blob, exact-byte `s256` commitment, `{approver, s256}` reference,
propose/clarify/approve flow, native `expires_at`, `active` and
`terminated` states, and an ordered mission log. The binding uses those
elements unchanged and defines no new wire members. It treats the
Person Server as the controlling authority for contextual governance,
while scopes, resource tokens, Resource and Access Server policy, and
optionally R3 carry deterministic resource authorization.
`approved_tools` are tool invocations exempt from per-call permission
at the Person Server; they are not remote resource authority. A
mission travels as `mission_s256` in PS-issued person tokens; resources
must copy it into the resource tokens they issue. Active-state
issuance gating is structural in PS-asserted and federated access, and
person-token issuance is itself a PS control point; identity-based and
resource-managed decisions are not Person-Server-gated. Its Mission
Substrate Statement declares the kernel mapping and per-mode
capability claims, including the capabilities it does not supply.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html)

#### Mission-Bound Authorization for UMA 2.0

Experimental sketch: the fourth binding, and the first authored
against the Mission Substrate Requirements contract rather than
extracted into it. UMA 2.0 standardized the plumbing of asynchronous,
party-asymmetric authorization (the rotating permission ticket,
`request_submitted`, claims pushing, per-use introspection, and a
continuity token that grants nothing) and deliberately left the
authorization assessment unspecified; this binding fills that
interior with the Mission. The pushed Mission Intent rides claims
pushing at the token endpoint, the resource owner's decision is the
approval event, the lifecycle gates every RPT (requesting party
token) issuance and upgrade,
the RPT is the Mission-bound credential (token-carried or
introspection-carried via the OAuth binding's registered `mission` member),
and the PCT (persistent claims token) is Mission continuity that is
never authority. It claims
the contextual-governance kernel plus lifecycle-gated, state-observable,
structured-authority, monotonic-derivation, and credential-bound
capabilities on ratified substrate machinery; independent verification
and portable evidence depend on the selected carriage and companion
profiles. The trades are UMA's thin deployed base and its scope-coarse
authority grain, which leaves runtime enforcement's role unchanged.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-uma.html)

#### Mission-Bound Authorization for GNAP

Experimental sketch: the fifth binding, to the Grant Negotiation and
Authorization Protocol (RFC 9635) authorization server, and the
second authored against the Mission Substrate Requirements contract.
GNAP standardized the negotiation the OAuth binding assembles from
parts (a grant request that is pushed by construction,
key-bound client instances, the native `pending` grant with
continuation, structured access rights, and token management) and
left the object of that negotiation unspecified: no durable record
governs what the resource owner approved, in what bounds, under what
lifecycle. This binding fills that interior with the Mission. The
Mission Intent rides a registered grant request member, the
interaction ceremony, or a companion-supplied standing basis, is the
approval event, the
lifecycle gates every access token issuance and rotation, grant
modification splits into in-Mission drawdown and Approver-routed
expansion, and the continuation access token is Mission continuity
that is never authority. The trades are GNAP's thin deployed base
and the mutability discipline the binding must impose on grant
updates.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-gnap.html)

### Agent runtime

#### Mission-Aware Agent Harnesses

How an agent harness binds sessions, task graphs, queues, cached tool
connections, and sub-agent handles to Mission state, when it must
re-check status, and how it must pause, suppress, or terminate work when
the Mission is no longer active. It also establishes the mediated
execution environment the runtime profile relies on: for mediated action
classes, governed work runs with no unmediated path to the resource. The
core principle: session continuity is not authority.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html)

#### Mission Capability Binding

Binds a Mission's approved catalog-sourced entry, an MCP tool, an
OpenAPI operation, or an equivalent capability source, to the
capability source it was derived from: `tool_id`, source, and a
content digest recorded at derivation and verified at decision time.
Defines the per-capability extraction rule that computes the digest,
the `capability_drift` denial reason as a coordinated extension of
the AuthZEN binding's runtime denial classification, and the mapping
onto the OpenID AuthZEN Profile for Model Context Protocol Tool
Authorization (COAZ) for MCP deployments. It rides the AuthZEN
binding's request and consumes an already established action
identity.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-capability-binding.html)

#### Mission Orchestration and Unwinding

How a multi-step or multi-Mission workflow assigns a reversibility class
to each step, records an unwind plan before dispatch, and unwinds
in-flight work safely when a Mission stops, including compensation after
termination. It governs how workflow state is unwound once continuation
is stopped.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-orchestration.html)

### Sub-agents

#### Mission Child Delegation for OAuth 2.0

Lets a parent Mission authorize a Child Mission for a sub-agent, with
explicit parent lineage, strict-subset authority, expiry no later than
the parent, fan-out controls, and cascade revocation when the parent
reaches a terminal state (suspension pauses, not terminates). A child
is never created by session ancestry alone.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-child-delegation.html)

#### Mission Offline Attenuation for OAuth 2.0

Removes the Authorization Server from the sub-agent fan-out hot path.
Profiles Attenuating Agent Tokens so a Mission-bound token holder mints a
narrower child token offline, carrying the same `mission` claim; the
narrowing is verifiable from the carried token chain. The kill switch is
preserved because consumption is gated by the runtime layer re-checking
Mission state, so a revoked Mission stops the whole chain. A capability
for deployments running the runtime enforcement profile, offered
alongside Authorization-Server-mediated delegation.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-attenuation.html)

### Cross-domain projection

#### Mission Cross-Domain Projection for OAuth 2.0

Lets a single Mission be honored by Authorization Servers in other
trust domains: the originating Mission Issuer projects audience-scoped
authority through a short-lived, sender-constrained cross-domain grant
(ID-JAG recommended), and the Resource AS mints its own local
Mission-bound tokens from it, preserving the `mission` claim unchanged.
One hop; the single-domain OAuth binding is complete without it. Extracted from
the OAuth binding so that binding carries no cross-domain dependencies.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-domain.html)

#### Mission Cross-Organizational Delegation for OAuth 2.0

Profiles Mission Offline Attenuation across organizational trust
domains: an agent in one organization delegates a narrowed slice to an
agent in another, which can delegate again, and the relying party
verifies the complete narrowing chain without calling the origin on
the request path. Each hop names its own actor under an explicit
identity-binding rule, the approved agent and origin principal travel
with the chain, and Cross-Domain Projection remains the adapter that
turns a verified chain into a local token. Experimental, like the
attenuation substrate it profiles.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-org-delegation.html)

#### Mission Continuation: Authorization Continuity for Mission-Bound Authorization

Profiles authorization continuity: how a Mission's work continues across
hops and over time without re-presenting the original credential and
without widening authority. The Identity Continuation Assertion, async
delegation, and cross-domain projection are the transports; the Mission
binds all of them under one invariant, a continuation handle grants
nothing. Identity continuity re-establishes who is acting; the Mission
remains the record of what work stays authorized.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-continuation.html)

### Proof and portability

Three layers of proof, from the approval surface outward: Consent
Evidence commits what the Approver was shown (listed under Approval
time above); the Mandate makes a Mission's committed facts portable and
independently verifiable; Audit Transparency makes all Mission evidence
tamper-evident in an append-only log.

#### Mission Mandate

A signed, portable, independently verifiable statement of a Mission's
committed facts (its identifiers, integrity anchors, Subject, Approver,
and optionally its Authority Set), minted by the Mission Issuer. It is
evidence, not a credential: presenting it authorizes nothing. It lets a
cross-domain verifier, an external rail deriving its own vertical
mandate, or an auditor know what was approved without a token exchange;
current state still comes from Status or Signals. Optional selective
disclosure via SD-JWT.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-mandate.html)

#### Mission Audit Transparency

Makes the suite's evidence tamper-evident and independently verifiable.
Registers Mission evidence (the approval event, lifecycle transitions,
runtime and consent evidence) into a SCITT Transparency Service as
Signed Statements, with the Mission as the statement subject so a
Mission's records form one append-only feed, and binds the Receipt back
so any party, in any domain, can verify inclusion offline. Statements
commit to evidence by hash, so sensitive task data stays out of the log.
Layers onto any level.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-audit.html)

#### Mission Evidence Envelope

An Experimental, binding-neutral evidence envelope (type, id, mission,
emitter, occurred_at, sequence, related, payload, integrity envelope)
and a Mission Evidence Payload Type Registry a future evidence kind
MAY register into instead of minting its own bespoke media type,
without weakening per-kind schema and verification separation.
Migrates none of the family's existing evidence kinds; ships one
pilot payload type, Intent Admission Evidence, the first consumer of
the OAuth binding's Intent Submission Evidence dispatch.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-evidence-envelope.html)

### Security model

#### Mission Security Model

A cross-cutting, Informational consolidation of the suite's trusted base.
Enforcement is spread across components (Authorization Server or Mission
Authority Server, PEP, PDP, harness, consent rendering, and optional
state, access-request, transparency, and event-source services); each
profile states its own security considerations, but this document gives
the single view: what each component must achieve, what it assumes of
the others, and how its compromise degrades the guarantees. It defines
no new mechanism and points to the profiles' normative security
considerations.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html)

#### Mission Work Products

Experimental. Keeps information from carrying authority: an artifact can
cross a boundary with knowledge, but not with the producing Mission's
authority. Defines a policy-free work-product provenance object that
attributes an artifact to the approved work under which it came into
existence, and a non-transitive Mission-to-Mission handoff rule: an
artifact crossing into a receiving Mission is input, and the receiving
Mission re-evaluates any proposed action under its own Authority Set.
One invariant holds throughout: no authority is acquired by information
propagation alone. Provenance records where an artifact came from; it
never says what the reader may do.

[Editor's Copy](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-work-products.html)
