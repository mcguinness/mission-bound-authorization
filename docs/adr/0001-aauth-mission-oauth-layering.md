# ADR 0001: Reposition the family around a protocol-independent Mission Governance Model

Status: Proposed (exploration branch; no normative draft rewrite proceeds
until this ADR is accepted)

Date: 2026-07-17

## Context

The repository defines a coherent architecture for governing long-running
agent work: the Mission as a durable approval-backed record, the Authority
Set, integrity anchors, lifecycle and delegation, credential binding,
runtime enforcement, evidence, management, cross-domain projection, and
enterprise deployment. Its weakness is not the model but the hierarchy of
presentation:

- The OAuth 2.0 issuance profile is the mandatory core and the
  definitional home for transport-neutral concepts.
- The AAuth binding is framed as the first non-OAuth alternate binding,
  understating its role as a native agent-authorization protocol.
- The Mission Substrate Requirements document captures the binding
  contract but remains subordinate to the OAuth core (ownership migrates
  by touch).
- The public surface leads with a flat list of ~29 drafts.
- Without an ownership matrix, approval, clarification, continuation,
  lifecycle, delegation, challenge, and status concepts risk definition
  in more than one place.

The strategic reading this ADR adopts: execution providers naturally own
runtime state; enterprises naturally own durable authority records;
heterogeneous agent environments need a standard seam between the two.
AAuth standardizes how an agent requests, acquires, presents, and
continues authority. Mission-Bound Authorization standardizes the durable
enterprise record of the approved work that authority serves. OAuth is the
installed-base deployment path. Runtime enforcement decides whether each
consequential action remains within the approved Mission.

## Decision

1. The Mission Governance Model becomes the definitional home. The
   Mission Substrate Requirements document is promoted and renamed; it
   defines Mission, Mission Intent, Authority Set, approval event and
   fidelity, integrity anchors, lifecycle and the only-active rule, the
   subset rule, successor and parent/child semantics, expiry, status
   requirements, audit horizon, credential-or-join, versioning and
   extension rules, and binding conformance.
2. The AAuth Mission profile is the primary native agent-protocol
   profile. It maps AAuth actors and operations onto Mission semantics
   and does not duplicate AAuth wire mechanics.
3. The OAuth profile remains first-class, implementation-ready, and
   independently deployable. It is a deployment profile of the
   governance model, not the semantic definition of the Mission. OAuth
   deployments never require AAuth.
4. The standalone Mission Authority Server remains a peer enterprise
   deployment architecture, not a migration workaround.
5. Runtime enforcement remains transport-independent and consumes
   Mission semantics identically from the OAuth path, the AAuth path,
   and the standalone-MAS join.
6. Every common semantic concept has exactly one normative owner, per
   the ownership matrix below.
7. The repository retains the Mission-Bound Authorization name.
8. No generic Authority header and no second protocol competing with
   AAuth is introduced.
9. Existing document URLs remain stable where practical; renames ship
   with aliases and migration notes, phased separately from semantic
   moves.
10. The suite is publicly presented as a five-document standards kernel
    (architecture, governance model, AAuth profile, OAuth profile,
    runtime enforcement, with the AuthZEN binding beside runtime) plus
    grouped companion profiles.

The dependency shape is deliberately not a linear stack: the Governance
Model is the common semantic dependency; AAuth, OAuth, and the standalone
MAS are sibling realization paths; runtime consumes their common output.

## Normative ownership matrix

| Concept | Normative owner | Profile responsibility |
|---|---|---|
| Mission definition | Governance Model | Bindings serialize or reference it |
| Mission Intent | Governance Model | Bindings define submission mechanics |
| Authority Set | Governance Model | Bindings map authority representation |
| Approval-event semantics | Governance Model | AAuth/OAuth define interaction mechanics |
| intent_hash / authority_hash | Governance Model | Bindings define canonical projection and carriage |
| Only-active rule | Governance Model | Bindings apply it to issuance and reliance |
| Lifecycle semantics | Governance Model | Status/Signals define protocol surfaces |
| Approval request interaction | AAuth or OAuth profile | Must produce governance-compliant approval |
| Clarification | AAuth; OAuth approval extensions where required | Must not silently alter approved authority |
| Pending response | AAuth or OAuth profile | Retains correlation, conveys no authority |
| Continuation | AAuth or transport profile | Bound to an active Mission, never widens |
| Access-token issuance | OAuth profile | Bounded by Mission authority |
| AAuth auth-token issuance | AAuth profile | Bounded by Mission authority |
| Token introspection | OAuth profile | Exposes Mission binding and state |
| Mission Status | Status profile | Common state-query semantics |
| Mission Signals | Signals profile | Push complement to Status |
| Parent/child semantics | Governance Model or Child Delegation profile | Bindings map wire behavior |
| Cross-hop call chaining | AAuth | Mission profile defines the governance boundary |
| Successor Mission | Governance Model / Expansion | Transport profile defines the request flow |
| Requestable denial | Native protocol mechanism or resource profile | Mission defines the resulting invariant |
| Per-action permit | Runtime Enforcement | AuthZEN maps it to an API |
| Action parameter binding | Runtime Enforcement | Binding defines the input format |
| Consumption limits | Metering profile | Runtime enforces atomically |
| Consent evidence | Consent Evidence profile | Bindings record profile-specific evidence |
| Mission Mandate | Mandate profile | Evidence only |
| Fleet operations | Management profile | Applies lifecycle semantics |
| Enterprise join | Mission Authority Server | Runtime/PDP consumes the join |
| Assurance claims | Architecture / Deployment Profile | Deployments publish actual properties |

## Non-goals

The refactor does not: replace Mission with a generic Authority object;
invent new Authority HTTP headers; create a second protocol competing
with AAuth; remove the OAuth profile; make AAuth mandatory for OAuth
deployments; collapse the suite into one document; rewrite established
normative behavior without a documented reason; move runtime semantics
into AAuth; treat a Mission Mandate as a credential; remove the
standalone MAS; make the AAuth profile normative before its external
dependencies can be cited; or promise uniform assurance without a
Deployment Profile.

## Design principles preserved

Mission is an approved task, not a credential. Authority may narrow
without new approval; widening requires a new approval, a successor, or
an explicitly approved ceiling with drawdown policy. Only active permits
reliance; unknown states fail closed. Governance and execution stay
separate; Mission approval never commands a resource. Session continuity
is not authority. Evidence is not authority. Bindings do not redefine the
model. Incremental adoption is preserved: Mission plus OAuth without
AAuth; Mission plus AAuth without OAuth; standalone governance over
unmodified Authorization Servers; runtime enforcement only on
high-consequence paths.

## Alternatives considered

- A. Keep OAuth as the mandatory core: minimal disruption, but a
  transport-specific definitional home that understates AAuth and makes
  future bindings derivative. Rejected as the end state; retained as the
  migration starting point.
- B. Replace Mission with generic Portable Authority: loses the
  approved-task insight, collides with existing meanings, duplicates
  AAuth, risks a vague meta-standard. Rejected.
- C. Make AAuth the sole mandatory protocol: abandons the installed
  base, depends on immature work, blocks incremental adoption. Rejected.
- D. Fold all Mission semantics into AAuth: makes OAuth and standalone
  deployments second-class and protocol-owns enterprise governance.
  Rejected.
- E. Peer bindings with no definitional model: semantic divergence,
  duplicated lifecycle and approval behavior, no stable system-of-record
  contract. Rejected.

## Unresolved dependencies on the external AAuth draft

The AAuth Mission profile depends on an individual draft that changes.
Known open questions to track as needs-upstream issues rather than
silently invent: native seams for tool constraints, a lifecycle
companion (revocation and expiry as mission-log events with an
authenticated revocation operation), blob extension-member conventions,
and expires_at as a native blob member (repo issue #256); the stability
of the s256 projection the binding's anchors derive from; and the
maturity of AAuth's continuation and call-chain mechanics. The OAuth
path and the Governance Model must not block on any of these.

## Migration rules

Stage 1 changes narrative only (README, diagrams, architecture
positioning, grouping, standardization ask); no file renames, no
normative moves. Stage 2 introduces the Governance Model, keeping
duplicated definitions temporarily and marking them for removal. Stage 3
refactors the AAuth and OAuth profiles onto Governance references,
preserving all wire behavior. Stage 4 updates runtime and companions.
Stage 5 renames and redirects only after builds and references are
stable. Stage 6 demonstrates cross-binding equivalence with
interoperability fixtures. Semantic changes and mass renames never share
a commit.

## Rollback strategy

Each phase lands as a separate commit (and, if adopted beyond
exploration, a separate pull request). A failed phase is reverted alone;
the inventory and this ADR persist; generated drafts are not deleted
until replacements build. The suggested sequence: inventory and ADR;
README and architecture narrative; Governance Model introduction; AAuth
profile refactor; OAuth profile refactor; runtime alignment; companion
migration; interoperability tests; final naming cleanup.

## Consequences

Positive: one source of truth for Mission invariants; correct separation
of semantics, transport, and enforcement; a smaller public coordination
ask; easier future bindings; a stronger multi-vendor standards story.
Costs: one more document in the implementer's reference chain (kept
compact); rename and reference churn (mitigated by aliases and phasing);
dependence of one profile on immature AAuth work (isolated; OAuth stays
first-class); risk of an over-abstract governance document (every
requirement must derive from at least one existing binding); possible
reader perception that OAuth is deprecated (countered explicitly and
repeatedly).

## Open issues

- Whether Child Delegation's common parent/child semantics move into the
  Governance Model or stay in a protocol-neutral companion.
- Whether Deferred Approval is presented as OAuth-only compatibility once
  AAuth's native asynchronous interaction is cited.
- How the Status and Signals surfaces bind to AAuth state without
  duplicating the AAuth profile's state mapping.
- The concrete alias/redirect mechanism for renamed documents on the
  datatracker and the editor's-copy site.
