# Proposal: Mission substrate composition and MVP

Status: design proposal, not an Internet-Draft and not yet normative.
Reviewed 2026-08-11; disposition in the Review Disposition section below:
harvest the adopted items as targeted PRs, keep the composition framework
as a design record, run the validator as an implementation experiment,
do not run the migration plan as written.

Purpose: define the recommended refactor of the Mission Substrate Requirements,
including a minimum viable substrate, scoped capability claims, consumer requirements,
deterministic composition, binding examples, migration sequencing, and the boundary
between the substrate contract and higher-assurance profiles such as AgentCorp,
runtime enforcement, least exposure, and cross-domain continuity.

This proposal does not directly change any protocol wire format. It is intended to be
reviewed before normative requirements move among the substrate, architecture, OAuth,
AAuth, MAS, UMA, runtime, AuthZEN, evidence, or exposure documents.

## Executive summary

The existing substrate refactor made the right first move: it separated a small
contextual-governance kernel from optional capabilities so AAuth, OAuth, UMA, and a
standalone Mission Authority Server do not have to pretend they provide the same
authorization model. The refactor is incomplete in four ways:

1. The kernel mixes the identity of approved work with stronger governance,
   propagation, reliance, and audit properties.
2. Capability claims are prose tables that cannot be reliably compared with the
   requirements of a consuming profile.
3. `conditional` conflates specification support, deployment configuration, extension
   availability, and scope.
4. The OAuth core does not publish a Mission Substrate Statement, while runtime and
   other nominally substrate-neutral companions still consume OAuth-specific
   primitives without declaring their capability requirements.

The recommended target has four layers:

1. **Mission Record Kernel**: the lifecycle-aware, substrate-neutral record of approved
   work.
2. **Capability Provider Statements**: scoped claims made by bindings, extensions, and
   cooperating components.
3. **Capability Requirement Statements**: properties required by runtime, evidence,
   delegation, exposure, and other consumer profiles.
4. **Composition and Deployment Profiles**: deterministic matching of requirements to
   providers for a declared deployment scope.

The minimum viable deployment is **Issuance-Bound Mission**:

- a durable Mission Record whose lifecycle is independent of credentials;
- an authenticated approval bound to an eligible Actor;
- an active/non-active predicate and bounded validity;
- a Mission-bound authorization artifact;
- issuance and refresh gated on current Mission state; and
- an explicit maximum residual interval after the Mission becomes non-active.

This MVP is useful but deliberately does not claim action-time containment. A second
profile, **Action-Enforced Mission**, composes State Observation, Structured Authority,
Action-Time Enforcement, and Evidence Continuity. A third profile, **Least-Exposure
Runtime**, composes Mission-scoped context admission and working-set controls. These
profiles can be adopted independently and can be supplied by more than one component.

The core rule is:

> The kernel defines what approved work is. Capabilities define which security
> properties a provider supplies. Consumer profiles define which properties they need.
> A deployment claim is valid only when every requirement is matched to a compatible,
> scoped provider claim.

## Review disposition (2026-08-11)

This section records the review outcome and governs which parts of the
proposal proceed. The document below is preserved as the design record;
where a section conflicts with this disposition, the disposition wins.

### Adopted — proceed as targeted, PR-sized changes to the current substrate

1. **Authority role map** (5.1): enumerate the distinct authority roles in
   the kernel's Controller element, with the rule that colocation MUST NOT
   imply one role's assertion establishes another role's fact. A kernel
   refinement, not a demotion.
2. **Activation conditions replace `conditional`** (6.1): a capability row
   either supplies the property in a named scope when stated activation
   conditions hold, or does not supply it. Adopted inside the existing
   Statement format; the surrounding claim schema is not adopted (see
   deferred).
3. **Mission-Bound Artifact fact-semantics split** (7.2): a claim selects
   which of correlation / issued-under / authority-derived /
   lifecycle-gated-issuance / state-as-of it establishes. Folded into the
   existing Credential-Bound capability's requirements.
4. **Authorized Context Correlation** (7.2) as a named capability: joining
   authority, association policy, proof inputs, substitution protection.
   Formalizes the MAS join and Join Assertion machinery; the
   context-splicing consideration (16.2) travels with it.
5. **`preserve` / `attenuate` / `decide_anew`** (7.3): adopted as the
   transition classification for Monotonic Derivation and the cross-domain
   profile, with incomparability routing to refusal or `decide_anew`,
   never silent attenuation.
6. **MVP conformance tests** (13.3): adopted, attached to the existing
   **Baseline Issuance** assurance level. "Issuance-Bound Mission" is
   Baseline Issuance restated; no second ladder is created (see rejected).
7. **The OAuth-core Statement gap** (1.4, 14.1): the finding is accepted;
   the fix is reshaped. The core stands alone and takes no companion
   normative dependencies, so the normative OAuth-native Statement is
   hosted on the substrate's side (its family appendix machinery), with a
   core issue recording the pointer for the core's next revision — the
   #440 pattern.
8. **Temporal and failure fields**: the statement checklist gains required
   temporal (freshness, decision lifetime, residual) and failure-behavior
   elements per claim — adopted additively; the kernel floors they were
   intended to replace stay where they are.
9. **Worked composition** (14.3): adopted as an architecture-document
   example candidate.

### Deferred — revisit only with implementation experience

- The 16-field provider-claim schema, consumer requirement schema, and the
  10-step composition procedure as normative text. The **reference
  composition evaluator** (19.1) with the fixtures of 19.2 is adopted as
  an implementation-repo experiment (`src/`, zero normative surface); its
  results decide whether the full model earns normative status.
- Machine-readable statements, discovery carriage, registries (as the
  proposal itself defers in Phase 5).
- The exposure capability catalog (7.4) as substrate content: exposure,
  working-set, provenance, and custody claims belong to the harness,
  containment, and runtime documents publishing their own claims against
  the substrate's extension point, not to the substrate catalog.

### Rejected — relitigates ratified decisions or conflicts with recorded rules

- **Kernel demotions** (17 Phase 1, items 3-6): moving Bounded Reliance out
  of the kernel (ratified in, and defended against this exact argument,
  twice); reducing the kernel record to approval + lifecycle history
  (decision attributability is constitutive — the substrate's own
  definition of a Mission — and for AAuth the decision log is the
  governance mechanism itself; coverage honesty is already handled by
  scope declarations); moving propagation out of the kernel (the current
  element is already "propagation or decision correlation"). Note these
  demotions appear in Phase 1 but not in the proposal's own section 20
  accept list; section 20 governs.
- **A parallel profile ladder**: Issuance-Bound / Action-Enforced /
  Least-Exposure re-derive Baseline Issuance / Runtime-Enforced / the
  Governed Agent territory without engaging the existing assurance levels,
  named claims, and Deployment Profile. The deltas (tests, requirement
  precision) strengthen the existing rungs instead.
- A Statement **inside** the published OAuth core (see adopted item 7 for
  the reshaped fix).

### Corrected premises

- The architecture's eight-primitive section already presents the
  binding-neutral contract first, with the primitives labeled as the
  issuance profile's instantiation; the section-18 row describes work that
  is done.
- The README already presents the assurance ladder and adoption order, not
  an undifferentiated family claim.
- The consumer-profile substrate sections already declare consumed
  capabilities in the contract's vocabulary; the accepted delta is
  precision (temporal/failure elements), not the requirement-statement
  schema.

### Sequencing

The adopted items are five or six PRs in the established pattern, after
the current stabilization commitments (substrate publishes before or with
its bindings; migrate-by-touch). No five-phase migration; no
fourteen-document sweep.

## 1. Problem statement

The Mission family currently carries three architectural concerns:

- a durable record of approved work and its lifecycle;
- one OAuth realization using authorization details, tokens, and issuer gating; and
- a runtime and evidence architecture that evaluates concrete actions.

Those concerns compose, but they are not the same abstraction. Treating the OAuth
realization as the common substrate forces other bindings to emulate:

- OAuth issuer identifiers;
- Rich Authorization Requests;
- one universal Authority Set;
- one subset algebra;
- JWT claims and integrity anchors; and
- access-token issuance and refresh semantics.

The current Mission Substrate Requirements correctly rejects those as kernel
requirements. It nevertheless makes other strong properties mandatory, including an
ordered governance record and propagation rules, while leaving the provider/consumer
composition contract informal.

This creates four practical failures.

### 1.1 Capability confusion

A statement that a binding “supports Missions” can be misread as proving any of the
following:

- the work has an independently governed lifecycle;
- a credential was issued under that work;
- current state is observable;
- authority is structured and machine-evaluable;
- delegation is non-amplifying;
- a resource checked the Mission at action time;
- an artifact can be verified independently; or
- evidence joins approval to effect.

None follows from the others.

### 1.2 False substrate neutrality

A companion can say it is substrate-neutral while requiring:

- OAuth `authorization_details`;
- the core's Common Constraints;
- the core's exact subset relation;
- the `mission` JWT claim; or
- the core's integrity-anchor envelope.

Such a profile may be valuable, but it is a structured-authority or OAuth-binding
profile, not a consumer of the neutral kernel alone.

### 1.3 Uncheckable composition

The current provider table has `supported`, `not supported`, and `conditional` rows.
It does not give a consumer a deterministic way to answer:

- Is the capability supported for this operation?
- Does it cover this artifact or access mode?
- Is its freshness bound strong enough?
- Is its residual lifetime short enough?
- Who asserted and who decides the fact?
- Does it prove correlation, issuance, authority, or current state?
- Which extension or deployment property activates it?
- Are separately valid identity, authority, and work facts authorized to be joined?

### 1.4 No small deployment target

The family describes a strong reference security architecture, but implementers need a
small first rung that earns a precise claim without pretending to provide action-time
containment. The substrate should make that rung explicit and allow stronger profiles
to compose without redefining the kernel.

## 2. Goals

The refactor should:

1. define one lifecycle-aware, protocol-neutral record of approved work;
2. preserve OAuth, AAuth, UMA, MAS, workflow-native, and future bindings as native
   realizations rather than weaker imitations of OAuth;
3. distinguish specification support from deployment activation;
4. allow multiple components to jointly supply one consumer profile;
5. make compatibility mechanically or procedurally checkable;
6. support token-side and resource-side authorization without forcing one wire model;
7. preserve separate authorities for approval, lifecycle, identity, projection,
   resource policy, correlation, and evidence;
8. treat exposure governance as parallel to action authority, not as an overloaded read
   permission;
9. support an MVP that can be implemented on deployed authorization rails; and
10. let higher-assurance profiles state exactly what additional guarantees they add.

## 3. Non-goals

This proposal does not:

- define a universal authority language;
- define a universal Mission wire object;
- require JSON, JWT, OAuth, RAR, AuthZEN, AAuth, UMA, MCP, or SCITT;
- make a Mission Reference a credential;
- standardize workflow engines or business completion semantics;
- make context correlation equivalent to authorization;
- make evidence complete merely because records share a Mission identifier;
- require every binding to provide action-time enforcement;
- require every deployment to disclose approved context to resources;
- claim that the capability list is permanently closed; or
- directly standardize the AgentCorp enterprise architecture.

## 4. Design principles

### 4.0 Relationship to the architecture essays

This proposal treats AgentCorp, least-exposure analysis, the MCP Mission application,
and the continuity taxonomy as design inputs rather than authorities that the substrate
must reproduce wholesale.

It accepts:

- independently governed work lifecycle as a fact credentials do not supply;
- task-level continuity across token-side and resource-side decisions;
- separation of request, identity, authorization, and work continuity;
- authorized correlation rather than matching identifiers;
- exposure admission as distinct from read authorization; and
- scoped assurance claims with explicit residuals.

It does not adopt:

- one universal Authority Set across every binding and resource vocabulary;
- the Authorization Server as the necessary home of the Mission;
- a Mission as the sole authority over data disclosure into context;
- four continuity questions as a permanently closed taxonomy;
- a fresh target-local decision as attenuation merely because it is narrower;
- a Mission identifier as sufficient evidence continuity; or
- AgentCorp's action-enforced architecture as the minimum substrate or MVP.

This separation is deliberate. The essays provide demanding profiles that exercise the
substrate contract. They do not define the substrate's minimum.

### 4.1 Work continuity is the substrate's center

The substrate owns the fourth continuity question: does approved work still justify
reliance now? Request provenance, subject identity, Actor identity, and target-local
permission remain independently governed facts. A binding can consume evidence for
them without making them kernel fields asserted by one omniscient Controller.

### 4.2 Mission is not a credential

A credential can be bound to a Mission, and a Mission can govern its issuance, but the
Mission Record remains independent of credential lifetime and representation.

### 4.3 Correlation is not governance

A bare Mission identifier proves neither that an artifact was issued under the
Mission nor that independently valid facts belong to the same decision. Correlation
must be established by a party authorized to associate the named facts for the target
context.

### 4.4 Resource semantics remain resource-owned

The Mission can commit a ceiling or a set of typed projections. It does not make one
Authorization Server authoritative for every resource's operation vocabulary. When
authority values are incomparable, the safe result is a target-local decision, not an
invented subset relation.

### 4.5 Authority and exposure are parallel envelopes

The authority envelope bounds what effects the agent may cause. The exposure envelope
bounds what may enter the agent's reasoning context. Permission to retrieve an item is
not permission to disclose it into an untrusted model context.

### 4.6 Capabilities are scoped facts

A capability claim is never a product-wide adjective. It applies to named operations,
artifacts, modes, consumers, trust boundaries, or consequence classes and carries its
own temporal and failure semantics.

### 4.7 No silent strengthening through composition

Combining two claims does not produce a stronger fact unless a profile defines the
join and a named authority is entitled to make it. State observation plus an artifact
identifier does not automatically prove lifecycle-gated issuance. A signed artifact
plus a Mission Reference does not automatically prove approved authority.

### 4.8 Higher assurance is a profile, not a larger kernel

AgentCorp, Action-Enforced Mission, governed runtime, mediated effects, portable
evidence, and least exposure are compositions over the kernel. Making them kernel
requirements would exclude valid bindings and obscure which component supplies each
property.

## 5. Target architecture

~~~
                    +------------------------------+
                    |   Deployment/Profile Claim   |
                    | scope + enabled components   |
                    +---------------+--------------+
                                    |
                       composition result
                                    |
             +----------------------+----------------------+
             |                                             |
+------------v-------------+                 +-------------v------------+
| Consumer Requirement     |                 | Provider Capability       |
| Statements               |                 | Statements                |
| runtime, delegation,     |                 | OAuth, AAuth, UMA, MAS,   |
| evidence, exposure       |                 | adapters, status, runtime |
+------------+-------------+                 +-------------+------------+
             |                                             |
             +----------------------+----------------------+
                                    |
                    +---------------v--------------+
                    |     Mission Record Kernel     |
                    | approved work + lifecycle     |
                    +-------------------------------+
~~~

### 5.1 Mission Record Kernel

Every conforming binding maps the following functions. The mapping can use native
records, references, protocol fields, or protected joins; these are semantic
requirements, not a common wire schema.

#### Mission Reference

The binding defines:

- a stable reference;
- its Controller or authority namespace;
- exact comparison rules;
- non-reassignment during the retention period;
- disclosure and guessability controls; and
- any pairwise or aliasing behavior across domains.

#### Authority role map

The binding identifies the authorities responsible for the functions it uses. Roles
may be co-located, but their semantics remain distinct:

- approval authority;
- lifecycle authority;
- accountable owner;
- approved-context commitment authority;
- Actor identity authority;
- Deployment or workload identity authority, where applicable;
- authority-source authority, where structured authority is composed;
- artifact projection or credential issuer;
- resource decision authority;
- correlation or joining authority; and
- evidence authority.

The kernel requires approval and lifecycle authorities. Other roles appear when the
corresponding capability is claimed. One implementation can fill multiple roles, but a
provider statement MUST NOT use that colocation to imply that one role's assertion
establishes another role's fact.

#### Actor eligibility binding

At approval, the Mission is bound to an authenticated Actor handle or an eligibility
rule whose resolution is controlled by a named authority. The binding states:

- what the handle identifies;
- how it was established;
- how a later actor or delegate is related to it; and
- how identifier mappings are authorized.

Bindings supporting agent governance SHOULD distinguish:

- logical Agent;
- approved Agent Deployment or behavioral version; and
- executing instance or workload.

The kernel does not require all three, but a binding MUST NOT claim a Deployment or
instance guarantee from a logical Agent identifier alone.

#### Approved-undertaking commitment

The binding retains an immutable approved undertaking or a verifiable commitment to
it. It defines:

- the exact immutable boundary;
- the approver-visible representation;
- untrusted proposer material;
- commitment construction where used;
- completion or termination rule reference where one exists; and
- how material changes obtain a new approval and unambiguous version or successor.

The approved undertaking can be prose, a native workflow record, structured context,
or a reference. It is not necessarily machine-evaluable authority.

#### Approval event

The binding defines a native ceremony that:

1. authenticates the Approver;
2. establishes the Actor eligibility binding;
3. faithfully presents the undertaking and material risk information;
4. records the Approver, Actor binding, authority roles, approved undertaking, Mission
   Reference, and validity; and
5. makes the Mission active only after successful approval.

#### Independent lifecycle

The Mission has lifecycle state independent of credentials and sessions. The binding
defines:

- its state vocabulary;
- the exact active predicate;
- state and record versioning;
- authenticated transition mechanisms;
- which authority can cause each transition;
- expiry or maximum validity; and
- fail-closed treatment of unknown state where state is relied upon.

Only the active predicate permits positive Mission reliance. This does not imply that
every downstream resource checks state; that is supplied by lifecycle-gated and
action-enforcement capabilities.

#### Kernel record

The kernel requires a durable record of approval and lifecycle transitions sufficient
to establish the Mission's current and historical state. It does not require a full
ordered log of every positive and negative authorization decision. Decision records,
approval-to-effect joins, independent verification, and portable evidence are separate
capabilities.

### 5.2 Why lifecycle remains in the kernel

A record with a reference, Actor, and approved context but no independent lifecycle is
an approved-context record. It does not answer whether the work remains approved after
its credentials, sessions, or executions diverge. The independent active predicate is
therefore constitutive of a Mission, while the enforcement points that consume it are
capabilities.

### 5.3 Why structured authority stays outside the kernel

AgentCorp and the OAuth binding require machine-evaluable authority for their stronger
claims. AAuth's native Mission description, a workflow-native record, or a MAS acting
only as a lifecycle authority may not. Such records can still supply work continuity
and later compose with resource-owned authority through a scoped adapter or joining
authority.

## 6. Capability claim model

### 6.1 Claim states

The capability table no longer uses `conditional` as a claim state. A provider either:

- supplies a capability in a named scope when stated activation conditions hold; or
- does not supply it.

An extension can itself publish a provider claim. A deployment profile declares which
extensions and conditions are active. This separates:

- what a specification defines;
- what an implementation supports;
- what a deployment enables; and
- where the resulting property applies.

### 6.2 Required fields for every provider claim

Every capability provider claim includes:

| Field | Meaning |
|---|---|
| `capability` | Collision-resistant capability identifier and version |
| `provider` | Component or binding supplying the property |
| `scope` | Operations, artifacts, modes, routes, consumers, or consequence classes covered |
| `fact_semantics` | Exact property established; nearby properties explicitly excluded |
| `authoritative_source` | Authority entitled to assert the fact |
| `decider` | Party entitled to use or decide from the fact for the target |
| `mechanism` | Native protocol, protected join, decision procedure, or artifact |
| `presentation` | Authorized presenter and proof required |
| `correlation` | How the fact is associated with the Mission and other inputs |
| `applicability` | Audience, resource, action, transaction, or context restriction |
| `temporal` | Fact state, evidence freshness, decision lifetime, expiry, and residual interval |
| `failure` | Behavior for absent, stale, unknown, incomparable, invalid, or unavailable input |
| `audit` | Record created, authoritative fields, integrity, and retention |
| `disclosure` | Information exposed by the mechanism and minimization requirements |
| `activation` | Extension, mode, configuration, or cooperating component required |
| `limitations` | Material properties the claim does not supply |

These fields instantiate the reusable boundary contract. A profile can use prose or a
machine-readable representation, but every answer must be present.

### 6.3 Required fields for every consumer requirement

A consumer requirement identifies:

- the capability and acceptable versions;
- the consuming operation and scope;
- required fact semantics;
- acceptable providers or trust anchors;
- required correlation strength;
- maximum evidence staleness;
- maximum decision or artifact lifetime;
- maximum post-transition residual;
- mandatory failure behavior;
- evidence requirements;
- disclosure ceiling; and
- whether an adapter is permitted.

### 6.4 Capability identifiers

The MVP uses collision-resistant identifiers and does not require an IANA registry.
Examples use the namespace `https://example.org/mission-capabilities/` only as
illustration. Family drafts should use stable identifiers under the family's published
namespace if machine-readable statements are adopted.

Capability versions identify semantic compatibility, not document revisions. An
incompatible change creates a new version. A requirement can accept an exact version
or a declared compatible range.

## 7. Recommended capability catalog

### 7.1 Work and state capabilities

#### State Observation

Supplies authenticated, integrity-protected observation of Mission state to named
consumers. The claim defines:

- state vocabulary and active predicate;
- authoritative source;
- request and response authentication;
- observation timestamp and freshness bound;
- cache behavior;
- anti-enumeration behavior; and
- fail-closed handling.

State Observation does not assert that a consumer performs the check.

#### Lifecycle-Gated Operation

Supplies an active-state check before a named positive operation, such as:

- credential issuance;
- refresh;
- delegation;
- child creation;
- permission decision;
- action execution; or
- continued runtime reliance.

The claim enumerates operations and states the maximum interval during which an
earlier positive result remains usable after the Mission becomes non-active.

### 7.2 Artifact and correlation capabilities

#### Mission-Bound Artifact

Supplies an integrity-protected association between exactly one artifact and exactly
one Mission Reference and namespace. It states whether the mechanism proves:

- correlation only;
- artifact issuance under the Mission;
- authority derivation under the Mission;
- lifecycle-gated issuance; or
- current state as of an observation.

These are separate semantics. A claim MUST NOT use “Mission-bound” without selecting
which are established.

Actor or presenter proof is described separately in `presentation`; bearer artifacts
can be Mission-bound even though they offer a weaker holder guarantee.

#### Authorized Context Correlation

Supplies an authorized association among independently established facts, such as:

- Mission;
- Subject;
- Actor, Deployment, and instance;
- authority artifact;
- request or transaction; and
- target resource.

The claim identifies the joining authority, association policy, proof inputs, conflict
handling, lifetime, revocation, audience, and substitution protection. Matching strings
or timestamps do not satisfy this capability.

### 7.3 Authority capabilities

#### Authority Provenance

Supplies the source and autonomous-use basis of authority associated with a Mission.
It identifies:

- the root authority or policy source;
- its version and current-state semantics;
- the portion eligible for autonomous exercise;
- the portion eligible for onward delegation;
- the component that derives a projection; and
- how later source narrowing affects effective authority.

#### Structured Authority

Supplies a machine-evaluable authority representation for a named decision boundary.
It defines:

- type and version identification;
- resource, operation, object, parameter, quantity, time, and constraint semantics;
- semantic owner;
- decision points that consume it;
- comparison domain; and
- handling of unknown or incomparable values.

It does not imply a subset relation or portability across vocabularies.

#### Monotonic Authority Transition

Supplies a no-broader-than relation for a declared authority vocabulary and transition.
Every covered derivation, delegation, or attenuation verifies all authority-bearing
dimensions. The claim explicitly classifies the transition as one of:

- `preserve`: the same authoritative fact remains applicable;
- `attenuate`: validity derives from a provable no-broader-than relationship; or
- `decide_anew`: a target-recognized authority makes a fresh decision.

Incomparability routes to refusal or `decide_anew`; translation is not silently treated
as attenuation.

#### Action-Time Enforcement

Supplies evaluation of a concrete action at the last declared boundary where its
effect can still be prevented. The claim states:

- action and resource identity;
- concrete parameter binding;
- current Mission-state input;
- applicable structured authority or resource-local policy;
- freshness and decision-lifetime bounds;
- denied and degraded behavior;
- uncovered routes; and
- evidence emitted.

It does not imply final-effect binding when the request and resulting effect can diverge.

#### Final-Effect Binding

Supplies a permit or handler invocation bound to the final effect, including relevant
parameters, recipient, amount, object version, idempotency identity, executor, use
limit, expiry, and commitment point. It identifies custody of the credential and the
atomicity of permit redemption with effect execution.

### 7.4 Exposure capabilities

#### Mission-Scoped Exposure

Supplies an admission decision for material entering an agent's reasoning context. The
claim covers named exposure points, such as:

- retrieval;
- prompt assembly;
- tool or schema discovery;
- memory recall;
- policy or business-rule disclosure;
- downstream response inclusion; and
- secret release.

It identifies the Mission exposure ceiling and the independent authorities whose data
policy remains applicable. Permission to retrieve does not by itself satisfy this
capability.

#### Working-Set Governance

Supplies lifecycle and isolation semantics for admitted context:

- Mission and step scope;
- checkpoint and resume behavior;
- Child Mission and delegate propagation;
- cache and memory retention;
- terminal cleanup or sealing; and
- shared-store composition controls.

#### Content Provenance and Flow Restriction

Supplies protected classification and provenance for admitted context and defines how
sensitive or untrusted material restricts later exposure or effects. It states whether
and how labels survive summarization, copying, branching, or format conversion and who
may remove or weaken a restriction.

#### Secret Custody

Supplies use of a secret or credential without disclosure into agent context. It
identifies the broker or handler, permitted operation, effect binding, isolation
boundary, and evidence. Delivery of a usable secret into the agent environment does
not satisfy mediated custody.

### 7.5 Record and evidence capabilities

#### Local Governance Record

Supplies an integrity-protected Controller-local record beyond the kernel approval and
lifecycle history. The claim enumerates covered decisions and events, ordering,
authorized readers, integrity mechanism, retention, and deletion behavior.

#### Evidence Continuity

Supplies a defined join across some or all of:

~~~
approval -> authority projection -> decision -> execution -> effect
~~~

The claim defines event coverage, producer independence, authoritative fields,
correlation proof, ordering, gap detection, duplicate handling, reconciliation, and
retention. A shared Mission identifier is necessary correlation but is not sufficient
evidence continuity.

#### Independent Verification

Supplies offline verification of named properties without querying the property's
Controller. It identifies artifact, canonical input, keys, algorithm agility, validity,
revocation, freshness, and the exact property established.

#### Portable Evidence

Supplies evidence transferable across the declared administrative boundary. It adds
cross-boundary trust, disclosure minimization, pairwise identifiers where appropriate,
key availability, retention, and verifier processing. Portable Evidence normally
depends on Independent Verification for the exported property.

## 8. Capability dependencies

The initial dependency graph is:

~~~
Lifecycle-Gated Operation -----> Mission Record Kernel lifecycle
State Observation -------------> Mission Record Kernel lifecycle

Monotonic Authority Transition -> Structured Authority
Action-Time Enforcement --------> State Observation OR an equivalent fresh local read
Action-Time Enforcement --------> Structured Authority OR named resource-local policy
Final-Effect Binding -----------> Action-Time Enforcement

Working-Set Governance ---------> Mission-Scoped Exposure
Content Provenance -------------> Mission-Scoped Exposure
Secret Custody -----------------> Final-Effect Binding for mediated effects

Evidence Continuity -----------> Authorized Context Correlation
Portable Evidence -------------> Independent Verification of each exported property
~~~

Dependencies are semantic prerequisites, not mandatory document references. A single
provider can satisfy several, or a deployment can compose multiple providers.

## 9. Provider statement format

The normative drafts can initially use prose tables. A machine-readable form is
recommended after the semantics stabilize. The following YAML is illustrative, not a
wire format:

~~~ yaml
statement_version: mission-substrate-statement-v1
binding:
  id: https://example.com/bindings/oauth-mission
  version: "1"

kernel:
  reference:
    form: [mission.issuer, mission.id]
    comparison: byte-equal after issuer normalization defined by binding
    non_reassignment: permanent within issuer retention horizon
  authorities:
    approval: https://as.example.com
    lifecycle: https://as.example.com
    artifact_projection: https://as.example.com
  actor_binding:
    logical_actor: oauth-client-id
    authenticated_by: registered client authentication and sender constraint
  approved_undertaking:
    form: mission-record intent commitment
    immutable_boundary: intent_hash input
  approval:
    mechanism: authorization-code approval event
  lifecycle:
    active_predicate: state == active
    validity_ceiling: mission.expires_at
    unknown_state: non-active

provides:
  - capability: https://example.org/mission-capabilities/mission-bound-artifact/v1
    provider: oauth-authorization-server
    scope:
      artifacts: [mission-bound-access-token, mission-bound-refresh-binding]
    fact_semantics:
      proves: [issued-under-mission, authority-derived-under-mission]
      excludes: [current-state-at-resource]
    authoritative_source: mission-issuer
    decider: resource-server
    mechanism: protected mission claim plus server-side refresh binding
    presentation:
      holder: dpop-or-mtls
    correlation:
      authority: artifact-issuer
      inputs: [mission.id, mission.issuer, authority_hash]
    applicability:
      audience: token.aud
    temporal:
      fact_state: active checked at issuance
      decision_lifetime: token lifetime
      residual_after_non_active: token lifetime unless introspected
    failure:
      invalid_or_missing_binding: reject
    activation:
      required: []
    limitations:
      - does not prove current Mission state after issuance
~~~

## 10. Consumer requirement format

Illustrative runtime requirement:

~~~ yaml
requirement_statement_version: mission-capability-requirements-v1
profile:
  id: https://example.com/profiles/action-enforced-mission
  version: "1"

scope_parameters:
  - consequence_class
  - resource
  - route

requires:
  - capability: https://example.org/mission-capabilities/state-observation/v1
    for: action-decision
    constraints:
      maximum_staleness: profile.consequence_class.max_state_staleness
      unknown_state: deny
      unavailable: deny-or-declared-degraded-mode

  - capability: https://example.org/mission-capabilities/action-time-enforcement/v1
    for: consequential-action
    constraints:
      boundary: last-preventable-effect-boundary
      authority_source: structured-or-resource-local
      maximum_decision_lifetime: profile.consequence_class.max_permit_lifetime
      uncovered_routes: must-be-declared

  - capability: https://example.org/mission-capabilities/evidence-continuity/v1
    for: approval-to-effect
    constraints:
      agent_self_report_only: false
      reconciliation_required: true
~~~

## 11. Composition procedure

A composition evaluator processes a deployment claim in this order.

### Step 1: Validate the kernel mapping

Every selected binding must map the kernel completely for the mode in use. If more than
one component jointly supplies the kernel, the deployment names the authoritative
record and the authorized joins among components. Two unrelated Mission records with
matching identifiers do not compose.

### Step 2: Activate provider claims

Evaluate each provider claim's activation conditions against the deployment:

- enabled extensions;
- access mode;
- configured status source;
- artifact type;
- route;
- resource;
- consequence class; and
- cooperating components.

An unmet activation condition means the claim is absent, not partially supported.

### Step 3: Match capability identifiers and versions

For each consumer requirement, locate one provider claim or an explicitly defined
multi-provider composition with compatible capability semantics and version.

### Step 4: Check scope containment

The provider's scope must contain the consumer's required scope. Examples:

- a claim for PS-brokered token issuance does not cover independently issued resource
  tokens;
- a claim for one MCP server does not cover browser egress;
- a claim for reversible writes does not cover irreversible payments; and
- a claim for one authority language does not cover another language merely because
  action names are similar.

### Step 5: Check authority and correlation

The provider's authoritative source and decider must be acceptable under the consumer
profile and deployment trust policy. If facts come from different authorities, a
provider must supply Authorized Context Correlation. A Mission identifier copied by an
Actor cannot satisfy this step.

### Step 6: Check temporal strength

Provider bounds must be at least as strong as consumer requirements:

- provider maximum staleness <= consumer maximum staleness;
- provider decision lifetime <= consumer maximum decision lifetime;
- provider residual after non-active <= consumer maximum residual; and
- artifact expiry <= Mission validity ceiling.

Unbounded or deployment-undefined values do not satisfy a finite requirement.

### Step 7: Check failure behavior

Provider failure behavior must be no weaker than the consumer requirement. A consumer
requiring denial on stale state cannot compose with a provider that continues on cached
state without a declared bound.

### Step 8: Resolve dependencies

Every semantic prerequisite of the selected capability must itself be satisfied in the
relevant scope. Dependency resolution does not allow a stronger claim from one route to
leak onto another route.

### Step 9: Check disclosure constraints

The provider's required disclosure must not exceed the consumer or deployment privacy
ceiling. If it does, the deployment needs a minimizing adapter or cannot compose.

### Step 10: Produce a composition result

The result records:

- binding and component versions;
- activated claims;
- requirement-to-provider mappings;
- scopes;
- trust anchors and joining authorities;
- temporal bounds;
- uncovered routes;
- accepted residuals;
- evidence locations; and
- unresolved optional requirements.

A deployment MUST NOT claim the profile if any mandatory requirement is unresolved.

## 12. Conformance model

### 12.1 Binding-specification conformance

A binding specification conforms when it:

1. maps every kernel function;
2. publishes provider claims for every capability it asserts;
3. states activation, scope, boundaries, temporal behavior, failure behavior, and
   limitations; and
4. makes no unqualified property claim outside those scopes.

### 12.2 Consumer-profile conformance

A substrate-neutral consumer profile conforms when it:

1. publishes a requirement statement;
2. depends only on kernel functions and declared capabilities;
3. identifies every concrete representation it additionally requires;
4. defines adapter behavior where a binding does not natively supply a capability; and
5. fails closed when a mandatory requirement is absent.

### 12.3 Composition conformance

A composition conforms when every mandatory requirement maps to one or more compatible
provider claims and the mapping passes the procedure in Section 11.

### 12.4 Deployment conformance

A deployment claims a named profile only for its declared:

- resources;
- routes;
- operations;
- consequence classes;
- access modes;
- artifact types;
- trust boundaries; and
- validity period.

Deployment conformance is evidence-backed. A configuration that could compose but is
not enabled does not earn the claim.

## 13. Minimum viable substrate

### 13.1 Standards MVP

The first normative revision should include only:

1. Mission Record Kernel;
2. provider and consumer statement requirements;
3. the composition procedure;
4. five initial capabilities:
   - State Observation;
   - Lifecycle-Gated Operation;
   - Mission-Bound Artifact;
   - Structured Authority; and
   - Authorized Context Correlation;
5. conformance rules; and
6. OAuth and AAuth example statements.

The remaining capabilities can be specified in the same revision if stable, but the
five above are sufficient to prove cross-binding composition and support the deployment
MVP.

### 13.2 Deployment MVP: Issuance-Bound Mission

The smallest useful deployment requires:

| Requirement | Required property |
|---|---|
| Mission record | Durable approved work independent of credential lifetime |
| Approval | Authenticated Approver and eligible Actor binding |
| Lifecycle | Only active permits new projection; unknown is non-active |
| Validity | Mission expiry and explicit renewal or new approval |
| Artifact | Integrity-protected association to exactly one Mission |
| Issuance gate | Issuance and refresh check current Mission state |
| Authority | Artifact authority remains within the deployment's ordinary outer entitlement and approved Mission projection |
| Residual | Maximum token or decision lifetime after Mission becomes non-active is declared |
| Evidence | Approval, issuance, refresh refusal, and terminal transition are recorded |

This profile does not require a resource to query Mission state per action. Its claim is:

> New Mission-derived authority stops being issued when the work stops, and previously
> issued authority expires within the declared residual bound.

It MUST NOT claim:

- immediate revocation at resources;
- action-time Mission enforcement;
- final-effect binding;
- complete approval-to-effect evidence; or
- least-exposure working-set governance.

### 13.3 MVP test cases

A deployment demonstrates at least:

1. approval creates an active Mission and a Mission-bound artifact;
2. an artifact cannot outlive Mission expiry;
3. refresh while active succeeds within policy;
4. terminal transition prevents new issuance and refresh;
5. unknown state prevents issuance;
6. a token or artifact from another Mission cannot be substituted;
7. a bare client-supplied Mission identifier cannot create the binding;
8. a lost state dependency follows declared failure behavior; and
9. the actual residual after transition does not exceed the published bound.

### 13.4 Second rung: Action-Enforced Mission

Adds:

- State Observation or an equivalent fresh local read;
- Structured Authority or named resource-local policy;
- Action-Time Enforcement;
- explicit parameter and permit lifetime rules;
- declared uncovered routes; and
- Evidence Continuity through the action decision.

The claim is scoped per route and consequence class.

### 13.5 Third independent rung: Least-Exposure Runtime

Adds:

- Mission-Scoped Exposure;
- Working-Set Governance;
- Content Provenance and Flow Restriction;
- Secret Custody where secrets are used; and
- exposure admission and cleanup evidence.

This profile can compose with Issuance-Bound or Action-Enforced Mission. It is not
implied by either.

## 14. Binding examples

### 14.1 OAuth Mission binding

The OAuth binding maps:

- Mission Reference: `(mission.issuer, mission.id)`;
- approval/lifecycle authority: Authorization Server in the base profile;
- Actor: authenticated OAuth client, with Subject and Approver kept as separate
  principal facts;
- approved undertaking: Mission Intent commitment;
- lifecycle: Mission Record state and `expires_at`;
- Mission-Bound Artifact: protected `mission` claim plus server-side refresh binding;
- Lifecycle-Gated Operation: issuance, refresh, and covered derivations;
- Structured Authority: authorization details within supported type semantics;
- Monotonic Authority Transition: only for types defining a no-broader-than relation;
- State Observation: supplied when status, introspection, or another declared
  extension activates the provider claim; and
- Evidence capabilities: supplied only by the relevant evidence profiles.

The OAuth core should publish this Statement normatively. It should not claim current
resource state from a self-contained access token, nor portability of arbitrary RAR
types.

### 14.2 AAuth Mission binding

The AAuth binding maps:

- Mission Reference: its native approver and mission digest tuple;
- approval/lifecycle authority: Person Server;
- Actor: AAuth agent authenticated through native signed requests;
- approved undertaking: private approved Mission blob;
- lifecycle: native active/terminated behavior plus the declared validity extension;
- Mission-Bound Artifact: supplied only for access modes carrying a protected native
  Mission reference established by the PS or a cooperating issuer;
- Lifecycle-Gated Operation: PS-controlled permission and issuance paths;
- State Observation: supplied by the management extension when deployed;
- Structured Authority: not supplied by the Mission blob itself;
- Monotonic Authority Transition: not supplied across resource boundaries by the base;
  and
- Local Governance Record: PS Mission log, within its declared coverage.

AAuth remains native. It does not acquire OAuth authorization details merely to claim
Mission support.

### 14.3 AAuth plus resource-policy adapter

An Action-Enforced composition can use:

1. AAuth for the Mission kernel and lifecycle;
2. AAuth Management for State Observation;
3. a resource-owned R3 or other policy adapter for Structured Authority;
4. a scoped joining authority associating the AAuth Mission, Actor, and resource
   decision;
5. a resource PEP/PDP for Action-Time Enforcement; and
6. a decision/effect store for Evidence Continuity.

The structured authority claim applies only inside the resource vocabulary. A fresh
resource decision is `decide_anew`, not cross-substrate attenuation.

#### Worked composition

Assume an AAuth agent acts under Mission `{approver, s256}` and calls a payment API.
Four specifications or components publish provider claims:

| Provider | Capability supplied | Scope |
|---|---|---|
| AAuth PS | Mission Record Kernel; Lifecycle-Gated Operation | PS permission decisions and PS-brokered issuance |
| AAuth Mission Management | State Observation | Payment PDP, maximum staleness 5 seconds |
| Payment policy adapter | Structured Authority; Authority Provenance | Payment API actions and constraints under payment-policy-v3 |
| Payment gateway PEP/PDP | Authorized Context Correlation; Action-Time Enforcement; Evidence Continuity | `schedule_payment` and `release_payment` routes |

The Action-Enforced consumer profile requires current state, target-applicable
authority, an authorized join, an effect-boundary decision, and decision evidence.
The deployment declaration names all four providers and the payment routes:

~~~ yaml
deployment_profile_version: mission-deployment-profile-v1
deployment: acme-aauth-payments
binding:
  id: aauth-mission
  mode: ps-asserted

enabled_providers:
  - aauth-person-server
  - aauth-mission-management
  - payment-policy-adapter-v3
  - payment-gateway-runtime

claim:
  profile: action-enforced-mission-v1
  scope:
    resources: [https://payments.example.com]
    routes: [schedule_payment, release_payment]
    consequence_classes: [external-commitment]
~~~

The composition result is:

| Requirement | Provider | Result and important limit |
|---|---|---|
| Kernel | AAuth PS | satisfied; native private Mission blob and lifecycle |
| State Observation | AAuth Management | satisfied; 5-second staleness is within the profile's 10-second maximum |
| Structured Authority | Payment adapter | satisfied only for payment-policy-v3; no cross-resource authority claim |
| Authorized Context Correlation | Payment gateway | satisfied; gateway validates PS evidence, Actor proof, resource request, and policy-adapter output before joining them |
| Action-Time Enforcement | Payment gateway | satisfied for two named routes; direct payment-API routes remain prohibited or explicitly uncovered |
| Evidence Continuity | Payment gateway | satisfied through decision; effect completion requires an execution receipt if the deployment wants approval-to-effect completeness |

This composition succeeds without making the AAuth Mission blob a RAR object and
without claiming that the resource policy is an attenuation of AAuth authority. AAuth
supplies work continuity; the payment authority decides permission in its own
vocabulary; the gateway is the scoped joining and enforcement authority.

The same composition fails when any of the following is true:

- AAuth Management is disabled and no equivalent fresh local state source exists;
- the payment adapter publishes only descriptive strings rather than machine-evaluable
  semantics;
- the gateway accepts `mission_s256` directly from the agent without validating PS
  provenance;
- the status source's maximum staleness exceeds the profile requirement;
- a direct route lets the agent bypass the gateway; or
- the deployment generalizes the payment-policy claim to another resource vocabulary.

### 14.4 Standalone MAS binding

The MAS supplies the kernel, state, and optionally structured authority. It does not by
itself prove an unchanged OAuth AS issued a token under the Mission. An Action-Enforced
deployment therefore needs:

- Authorized Context Correlation at the joining PDP;
- ordinary token validation;
- fresh MAS state;
- target-applicable authority; and
- a resource decision.

A Join Assertion can strengthen correlation but must state whether it proves only the
join or also a decision made by the MAS. It cannot retroactively turn unchanged AS
issuance into lifecycle-gated issuance.

### 14.5 UMA binding

UMA can supply:

- native approval and assessment state;
- Mission-bound RPT correlation;
- lifecycle-gated RPT issuance and upgrade;
- State Observation through introspection; and
- Structured Authority within the UMA permission projection.

Its capability Statement must preserve the limits of UMA scope granularity and avoid
claiming parameter-level or cross-language monotonicity unless an extension defines it.

### 14.6 MCP token-side profile

The MCP server consumes a Mission-bound access token whose authority applies to the
tool. The token provider supplies Mission-Bound Artifact and possibly Structured
Authority. The server still supplies Action-Time Enforcement for `tools/call` and owns
the concrete tool and parameter semantics.

### 14.7 MCP resource-side profile

The access token may carry only ordinary resource authority plus a verified Mission
binding. A resource PDP supplies the target-local decision. The joining authority must
associate token, Actor, Mission, tool, and request. No requirement says the resource
must import the issuer's entire Authority Set.

### 14.8 MCP discovery and least exposure

`tools/list` filtering consumes Mission-Scoped Exposure. `tools/call` consumes
Action-Time Enforcement. The visible set and invocable set can differ:

- visible but not authorized tools support safe planning and requestable denial;
- authorized but unnecessary tools can remain hidden to reduce attack surface; and
- capability definitions can be admitted only after provenance and digest validation.

### 14.9 Cross-domain profile

The profile names separately:

- identity evidence and its authority;
- Actor and presenter evidence;
- Mission work-continuity evidence;
- authority transition (`preserve`, `attenuate`, or `decide_anew`);
- joining authority at the target;
- target-local authorization authority; and
- local lifecycle and residual behavior.

An upstream Mission and authority digest can cross as evidence without becoming
target-local permission. When vocabularies are incomparable, the target decides anew.

## 15. Profile definitions

### 15.1 Issuance-Bound Mission Profile

Requires:

- kernel;
- Mission-Bound Artifact proving issuance under Mission;
- Lifecycle-Gated Operation for issuance and refresh; and
- declared residual bound.

Optional:

- Structured Authority;
- State Observation for consumers;
- Local Governance Record beyond the required approval/lifecycle/issuance events.

### 15.2 Action-Enforced Mission Profile

Requires:

- kernel;
- State Observation or equivalent fresh local state;
- target-applicable Structured Authority or named resource-local policy;
- Authorized Context Correlation when facts have different authorities;
- Action-Time Enforcement; and
- Evidence Continuity through decision and declared effect boundary.

### 15.3 Monotonic Delegation Profile

Requires:

- Structured Authority;
- Authority Provenance;
- Monotonic Authority Transition;
- Mission-bound parent and child/delegate artifacts;
- explicit Actor transition;
- lifecycle gate at derivation; and
- idempotent creation where a durable child is created.

### 15.4 Least-Exposure Runtime Profile

Requires:

- Mission-Scoped Exposure at every claimed context source;
- Working-Set Governance;
- Content Provenance and Flow Restriction for sensitive or untrusted input;
- no unmediated context source in the claimed scope;
- terminal cleanup or sealing behavior; and
- exposure evidence with minimized content.

### 15.5 AgentCorp scoped profile

AgentCorp is not the kernel. A scoped AgentCorp claim composes:

- Action-Enforced Mission;
- Authority Provenance;
- bounded and non-amplifying projections or independent rejection of excess;
- explicit delegation;
- graph-to-Mission binding where execution graphs exist;
- Evidence Continuity through effect and recovery; and
- declared ungoverned routes and consequence classes.

Governed runtime, mediated effect, preventive independence, evidentiary independence,
and least exposure remain separately named assurance profiles.

## 16. Security considerations

### 16.1 Capability downgrade

A deployment must not fall back from a required capability to correlation-only
semantics. If Action-Time Enforcement requires fresh state, a self-contained token with
a Mission identifier is not an acceptable substitute.

### 16.2 Context splicing

An attacker can combine valid identity evidence, a valid token, and a valid Mission
from different transactions. Authorized Context Correlation is required whenever one
authority did not bind all required facts in the applicable context.

### 16.3 Authority-role collapse

One product implementing approval, lifecycle, projection, decision, and evidence does
not make those facts identical. Provider statements preserve the roles even when they
share an operator or key hierarchy. Higher-assurance profiles can require preventive or
evidentiary independence.

### 16.4 Temporal confusion

Profiles distinguish:

- the current state of a fact;
- freshness of evidence about that fact; and
- lifetime of a decision based on that evidence.

An unexpired signature does not prove current state. An active Mission does not make a
cached permit current. A fresh state response does not authorize an action.

### 16.5 False monotonicity

Narrowing one field while extending lifetime, audience, delegation depth, resource
membership, or constraint interpretation can amplify authority. Monotonic claims cover
every authority-bearing dimension and return incomparable when no proof exists.

### 16.6 Exposure is not read authorization

An authorized read can still be an unauthorized disclosure to model context. Exposure
claims preserve independent data-owner, tenant, subject, regulatory, and runtime
restrictions. A Mission exposure ceiling cannot widen any of them.

### 16.7 Evidence overclaim

A Mission identifier supports correlation. A signature supports integrity and
attribution for the signed content. Neither proves completeness, ordering, current
state, effect occurrence, or independence unless the corresponding capability says so.

### 16.8 Privacy and correlation

Mission, Actor, purpose, authority, exposure, and evidence records form a sensitive
who-did-what-for-whom graph. Statements define disclosure, pairwise or aliased
references, access, retention, deletion, and cross-domain minimization. Composition is
not permission to disclose every input to every provider.

### 16.9 Availability and break glass

Every live provider is an enforcement dependency. Profiles state cache, staleness,
degraded-mode, and failure behavior. High-consequence profiles normally fail closed and
require a separately governed emergency path rather than an implicit fail-open.

## 17. Migration plan

Superseded by the Review Disposition: the adopted items proceed as
targeted PRs in the established pattern; this plan is retained as the
design record. Phase 1 items 3-6 are rejected (kernel demotions); the
Phase 5 deferrals stand.

### Phase 0: accept the model

Review and resolve:

- kernel boundary;
- initial capability identifiers;
- claim and requirement fields;
- MVP profile;
- role map;
- treatment of exposure; and
- compatibility procedure.

No normative text moves before these decisions are recorded.

### Phase 1: revise Mission Substrate Requirements

Recommended changes:

1. Rename the kernel concept to **Mission Record Kernel** while retaining Mission
   Context as the relationship it records.
2. Keep independent lifecycle in the kernel.
3. Reduce the kernel governance record to approval and lifecycle history.
4. Move generic bounded reliance into the temporal fields of lifecycle-gated and
   artifact capabilities.
5. Move propagation into Mission-Bound Artifact and Authorized Context Correlation.
6. Move the full ordered decision record into Local Governance Record.
7. Replace the fixed capability table with provider-claim requirements.
8. Replace `conditional` with activation conditions and deployment selection.
9. Add consumer requirements and the composition procedure.
10. Add the MVP and its conformance tests.

### Phase 2: publish binding statements

Add or update statements in:

- OAuth core;
- AAuth binding;
- standalone MAS;
- UMA binding; and
- any future native workflow or GNAP binding.

The OAuth core is the priority because it is the primary binding and currently lacks
the Statement required of other bindings.

### Phase 3: migrate consumer profiles

Each nominally substrate-neutral profile publishes requirements.

Priority order:

1. runtime;
2. runtime evidence;
3. AuthZEN binding;
4. audit;
5. harness;
6. orchestration;
7. mandate;
8. discovery and shaping; and
9. exposure/containment profiles.

Runtime should explicitly declare that its generic action evaluation consumes
target-applicable Structured Authority or resource-local policy, State Observation,
Action-Time Enforcement, and Authorized Context Correlation where needed. OAuth
authorization details remain one binding, not the neutral requirement.

### Phase 4: define named composition profiles

Publish requirement statements for:

- Issuance-Bound Mission;
- Action-Enforced Mission;
- Monotonic Delegation;
- Least-Exposure Runtime;
- AgentCorp Scoped; and
- Cross-Domain Mission Continuity.

These can initially be appendices or architecture sections. Separate drafts are
justified only when they define independent wire mechanisms or substantial conformance
tests.

### Phase 5: machine-readable statements and discovery

Only after prose statements interoperate:

- define a JSON or CBOR statement schema;
- define canonicalization and signing if statements cross trust boundaries;
- define discovery or deployment-manifest carriage;
- define capability version compatibility; and
- consider registration policy.

Do not make dynamic discovery an MVP dependency. Static deployment profiles and
published specifications are sufficient to validate the model first.

## 18. Document-by-document impact

Read against the Review Disposition: the architecture and README rows
describe work that is already done, the OAuth-core row is reshaped to the
substrate-side Statement, and only the rows implied by the adopted items
proceed.

| Document | Recommended change |
|---|---|
| Mission Substrate Requirements | Adopt kernel, claims, requirements, composition, and MVP defined here |
| Mission Architecture | Replace the eight OAuth-derived “substrate primitives” as the neutral model with kernel plus capability graph; retain OAuth primitives only in the OAuth mapping |
| OAuth core | Add normative provider statement; consider describing Mission as a task-bound OAuth grant profile while keeping substrate semantics independent |
| AAuth binding | Convert table to provider claims; retain native Mission semantics and per-mode scope |
| MAS | Identify correlation versus issuance proof explicitly; publish join capability claims |
| UMA | Scope structured and monotonic authority claims to UMA permission semantics |
| Runtime | Publish consumer requirements; stop claiming unchanged portability from an undeclared bundle of OAuth primitives |
| AuthZEN | Bind the runtime requirements to AuthZEN wire fields; do not become the home of substrate semantics |
| Runtime Evidence | Supply Evidence Continuity claims and exact coverage |
| Audit | Supply Independent Verification and Portable Evidence where applicable |
| Harness/containment | Supply Working-Set Governance, Content Provenance, and runtime restriction claims |
| Capability Binding | Remain the concrete catalog/source-digest binding; map it to Content Provenance and Structured Authority inputs without overloading the generic capability contract |
| Cross-domain | Use the boundary contract and explicit preserve/attenuate/decide_anew classification |
| README | Present the MVP and named profiles rather than one undifferentiated family conformance claim |

## 19. Implementation and validation strategy

### 19.1 Reference composition evaluator

Add a small validator that consumes checked-in provider, requirement, and deployment
fixtures. It need not be a network service. It should:

- validate required fields;
- activate claims from deployment conditions;
- match requirements;
- compare scope and temporal bounds;
- resolve dependencies;
- produce a human-readable result; and
- fail on unresolved mandatory requirements.

### 19.2 Initial fixtures

Recommended fixtures:

1. OAuth Issuance-Bound success;
2. OAuth Action-Enforced success with Status plus runtime;
3. AAuth kernel-only success;
4. AAuth Action-Enforced success with management, resource adapter, and runtime;
5. AAuth Action-Enforced failure without Structured Authority or resource-local policy;
6. MAS Action-Enforced success with authorized join;
7. MAS failure where a bare Mission identifier is the only correlation;
8. cross-domain `decide_anew` success;
9. false attenuation failure across incomparable vocabularies;
10. least-exposure failure where retrieval is authorized but context admission is not;
11. temporal failure where status staleness exceeds the consequence-class bound; and
12. scope failure where one route's enforcement claim is generalized to another route.

### 19.3 Normative test vectors

The substrate revision should include statement fragments showing:

- exact compatible composition;
- maximum-bound comparison;
- inactive extension causing a missing capability;
- provider scope narrower than requirement;
- unauthorized correlation;
- unknown capability version;
- incomparable authority transition; and
- disclosure ceiling conflict.

## 20. Decisions recommended now

The Review Disposition records the ratified outcome of these lists:
accepted 2, 5, 8, 9; 6 and 10 remapped (Baseline Issuance carries the MVP
tests; the OAuth Statement is substrate-hosted); 3 and 4 deferred pending
the validator experiment; the kernel rename in 1 and the separate profile
ladder in 7 are not adopted. The defer and reject lists stand as written.

Accept:

1. lifecycle-aware Mission Record Kernel;
2. authority role map rather than one semantically omnipotent Controller;
3. provider and consumer statements;
4. deterministic composition;
5. no `conditional` claim state;
6. Issuance-Bound Mission as the MVP;
7. Action-Enforced and Least-Exposure as separate profiles;
8. Authorized Context Correlation as a first-class capability;
9. explicit `preserve`/`attenuate`/`decide_anew` transitions; and
10. OAuth core, AAuth, MAS, and UMA statements as the first interoperability proof.

Defer:

1. dynamic capability discovery;
2. a capability registry;
3. signed machine-readable statements;
4. universal exposure-policy syntax;
5. universal authority syntax;
6. automatic composition across arbitrary vocabularies; and
7. AgentCorp estate-level certification.

Reject:

1. making OAuth authorization details a kernel requirement;
2. making one universal Authority Set a kernel requirement;
3. treating a Mission identifier as authorized correlation;
4. treating identity continuity as authorization continuity;
5. treating every narrow fresh decision as attenuation;
6. treating tool visibility as tool invocation authority;
7. treating retrieval permission as model-context admission; and
8. treating signed or correlated evidence as complete evidence.

## 21. Acceptance criteria

The refactor is successful when:

1. the OAuth, AAuth, UMA, and MAS bindings can all map the same kernel without importing
   another binding's native wire constructs;
2. each binding can state capabilities it does not supply without losing kernel
   conformance;
3. runtime can state requirements without saying “same primitives” or assuming OAuth
   authorization details;
4. a deployment can determine whether AAuth plus a resource adapter plus a PDP satisfies
   Action-Enforced Mission;
5. a bare Mission identifier cannot satisfy artifact-binding or correlation
   requirements;
6. temporal and scope mismatches cause composition failure;
7. Issuance-Bound Mission can be implemented without action-time runtime integration;
8. Action-Enforced Mission cannot be claimed from issuance gating alone;
9. Least-Exposure Runtime cannot be claimed from narrow read authority alone;
10. cross-domain profiles distinguish identity evidence, work evidence, and target-local
    permission;
11. the capability-source binding remains a concrete mechanism rather than becoming the
    generic capability model; and
12. every named assurance claim identifies the components, routes, bounds, residuals,
    and evidence that earn it.

## 22. Recommended publication posture

The substrate document should be the narrow normative contract for binding and
composition authors. It should not attempt to standardize the entire Mission family.

The initial standards story becomes:

1. **Mission Substrate Requirements**: approved-work kernel and composition contract.
2. **OAuth Mission binding**: one interoperable realization and the first MVP.
3. **AAuth Mission binding**: native alternative proving the abstraction is real.
4. **Action-Enforced Mission profile**: runtime requirements independent of one decision
   wire format.
5. **AuthZEN binding**: interoperable wire realization of action enforcement.

AgentCorp, least exposure, continuity, and the larger family remain architecture and
profile work that exercise the contract. They should inform the substrate but should
not all become prerequisites for its adoption.

## One-line recommendation

Refactor the substrate around a lifecycle-aware Mission Record Kernel, scoped provider
and consumer capability statements, and deterministic composition; ship an
Issuance-Bound MVP first, then let action enforcement, exposure governance, delegation,
cross-domain continuity, and evidence compose as independently earned profiles.

**As disposed (2026-08-11):** keep the current kernel and floors; adopt
the role map, activation conditions, artifact fact-semantics,
Authorized Context Correlation, the transition classification, the
temporal/failure statement elements, the Baseline Issuance conformance
tests, and the substrate-hosted OAuth-native Statement as targeted PRs;
prove the composition machinery with the implementation-repo evaluator
before any of it becomes normative.
