---
title: "Mission Control-Plane Consistency"
abbrev: "Mission Control-Plane Consistency"
category: std
docname: draft-mcguinness-mission-control-plane-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - authorization
 - consistency
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-control-plane.html"
author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com
normative:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
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

informative:

--- abstract

This optional profile specifies topology-neutral consistency and recovery
invariants for Mission issuers and state-observation consumers. It separates
serialized authority changes from asynchronous publication, prevents freshness
from being manufactured after lag or recovery, and keeps emergency authority
outside the Mission enforcement claim. It defines no endpoint or wire member.

--- middle

# Introduction {#introduction}

Mission approval anchors, mutable lifecycle state, and runtime policy views
solve different problems. A correctly signed artifact is insufficient if its
issuer lost a committed revocation, double-spent a creation budget, or
re-stamped a stale observation. This profile gives those failure modes a
testable consistency contract without prescribing a database, leader topology,
or replication product.

The OAuth binding's existing atomic issuance and identifier-nonreuse duties
({{I-D.draft-mcguinness-oauth-mission}}) remain unconditional for adopters of that
binding. Declining this optional profile cannot waive them. Status owns state
versions and freshness ({{I-D.draft-mcguinness-oauth-mission-status}}), Signals
owns its delivery protocol ({{I-D.draft-mcguinness-oauth-mission-signals}}), and
Runtime owns point-of-use bounded reliance
({{I-D.draft-mcguinness-mission-runtime}}).

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: lab-best-effort.
Implementation: 12 conformance rows in conformance-manifest.json (12 todo).
Adopt when: A deployment claims testable control-plane consistency across replication, partition, and recovery.
Requires: Mission-Bound Runtime Enforcement; Mission-Bound Authorization for OAuth 2.0; Mission Lifecycle Signals for OAuth 2.0; Mission Status and Lifecycle for OAuth 2.0.
<!-- family-status: END -->

This document has no implemented conformance coverage. Its fault cases
and requirement rows are unimplemented, and its maintenance class reflects
that absence of implementation evidence.

# Conventions {#conventions}

{::boilerplate bcp14-tagged}

"Mission Issuer" identifies the authority owning the Mission record, not
necessarily an OAuth Authorization Server. "Canonical tuple" means the
binding-established issuer identity and Mission identifier, not caller-chosen
aliases. State versions and PDP policy-view identifiers inhabit different
identifier spaces and are not compared for raw equality.

# Shared Consistency and Availability Rule {#consistency-availability}

A deployment may trade availability inside a declared freshness window, but
it cannot manufacture freshness, lose a serialized narrowing transition, or
relabel emergency authority as Mission authority. Operational availability
guidance composes with this anchor; it does not define a second set of issuer
invariants. Recovery objectives guide selecting bounds within the security
ceiling, never extending them during an incident.

# Issuer Consistency Invariants {#issuer-consistency}

The following requirements apply when the deployment claims this profile,
in addition to the unconditional requirements of each adopted binding.
Each subsection identifies its enforcing subject.

## 1. Serialization domains {#serialization}

The Mission Issuer MUST provide one serialization order per Mission and per multi-object invariant.

Atomic domains include lifecycle state, state version, and durable fan-out work; predecessor supersession and successor creation; parent fan-out accounting and child creation; counter checks/increments and artifact issuance; and an idempotency claim and its side effect. These members commit together or none does. A region label is not a serialization mechanism. This tightens the binding's existing atomic-issuance obligations and adds explicit durable fan-out coupling.

## 2. Fresh observations, not fresh signatures {#fresh-observation}

A signer of a state observation MUST NOT manufacture freshness by assigning a new `iat` or `fresh_until` to an older observation without establishing that its value reflects the authoritative committed state at the new observation point.

The issuer establishes an authenticated observation/commit watermark justified by its consistency mechanism. An authoritative transactional read, quorum/read-index, or correctly defined lease mechanism can provide that guarantee; a lease alone does not prove inclusion of a committed transition. Without it, the signer may replay an original authenticated snapshot only within that snapshot's original validity and audience binding, or refuse. Signature validity proves producer and integrity, not recency. The Status freshness ceiling is unchanged.

## 3. One state-observation model {#state-surfaces}

A binding claiming this profile MUST map its state observations onto the existing Status, introspection, Mission Status List, or Signals semantics, rather than define a parallel signed state-snapshot protocol.

A binding-native realization can map those semantics without adopting another binding's endpoint or claim. Push delivery supplies invalidation and ordered-transition information; it is not the sole evidence of active state after freshness confidence is lost. Conflicting observations are reconciled under the version and freshness rules, never by selecting the more permissive surface.

## 4. Rollback resistance {#rollback}

After restore or failover, the Mission Issuer MUST NOT issue a lower state `version` for an existing Mission, and MUST refuse state-dependent service while its durable version or commit metadata is uncertain.

A retaining consumer MUST key its high-water mark by the canonical (issuer, mission_id) tuple, reject a lower version, and retain the high-water mark across its own recovery. A legitimate higher-version resume to active is accepted under the other validity checks; state names are not ordered by severity. Issuer durability is required even when a consumer has never seen the pre-restore version.

## 5. Terminal-state tombstones {#tombstones}

The Mission Issuer MUST retain terminal-state tombstones for the maximum applicable credential/artifact lifetime, state-staleness plus skew, idempotency/retry horizon, child-cascade horizon, and audit-retention horizon.

A tombstone identifies the canonical issuer/Mission tuple, terminal state, final version, and transition time or commit reference. After detailed retention expires, the issuer MUST retain enough namespace state to prevent identifier reuse or a return to active. This composes retention horizons; it does not weaken the binding's existing identifier-nonreuse requirement.

## 6. Authoritative mutation under partition {#partitions}

The Mission Issuer MUST perform issuance, refresh, expansion, child creation, and lifecycle mutation against authoritative current state within the operation's serialization domain, and MUST refuse when it cannot establish that condition.

A read from a node called a replica is not inherently forbidden if the consistency mechanism establishes its authority and currency for this operation. A stale or non-authoritative read is forbidden regardless of node name. The data plane may rely on already-valid observations only within its separate Runtime bounds; that does not authorize a stale control-plane write.

## 7. Emergency narrowing {#emergency-deny}

An issuer or deny cache MUST NOT use emergency deny information to create authority or extend the freshness of an active observation.

A separately authenticated suspend, revoke, or containment operation may narrow immediately under its own governed authorization, idempotency, versioning, and evidence. A non-terminal deny entry MUST carry version, authenticated source, and expiry or a reconciliation rule. Expiration of such an entry only removes that additional denial; ordinary positive checks still apply. A terminal tombstone MUST NOT expire into active behavior.

## 8. Positive emergency authority is separate {#emergency-authority}

A deployment MUST NOT represent positive emergency permission as a Mission permit, active Mission state, or Authority Set authorization, and MUST exclude actions relying on that permission from its Mission enforcement claim.

The ordinary Mission path still fails closed. Operator-facing emergency-mode activation and truthful evidence belong to the operational profile; narrowing emergency control is described in {{emergency-deny}}. No emergency flag turns a failed Mission check into a successful one.

## 9. Isolation at mutable seams {#isolation}

Issuers and retaining consumers MUST isolate mutable Mission state by the canonical (issuer, mission_id) tuple, or a tenant-qualified equivalent that unambiguously preserves both identities.

This applies to version high-water marks, idempotency records, deny caches, counters, queues, signing authorization, quotas, and replication authority. Tenant-wide services such as signing keys or queues bind each operation to that qualified identity; this does not require one key or queue per Mission. Shared infrastructure declares its tenant separation and resource isolation so one tenant cannot silently consume another's state-propagation guarantee.

## 10. Repairable fan-out {#fanout}

The Mission Issuer MUST atomically retain durable publication or repair work with each committed transition and publish only after that commit, with idempotent recovery that prevents loss of the committed transition.

An outbox or equivalent satisfies this only when it shares the state transaction. A second Signals database does not join that transaction merely because its API is called inside it. Publication can duplicate, reorder, or stop after commit: event identity and Mission/version correlation make redelivery idempotent and gaps detectable, and consumers resynchronize from an authoritative state surface. Non-active transitions receive priority. The profile does not promise global delivery order or require a particular worker/claiming topology.

# Deployment Declaration {#deployment-declaration}

A claiming deployment MUST document its serialization domains, authoritative
observation mechanism, replication and recovery model, applicable recovery
objectives, tenant isolation, and residual risks. The declaration may use the
Deployment Profile's illustrative `state_sources` entries, for example
`serialization_domain`, `replication`, and `recovery_objective_seconds`; those
illustrative names define no standardized metadata member or endpoint.

The existing `mission_max_stale_seconds` ceiling retains its meaning.
A residual risk is a disclosed limitation, not an exemption from a requirement
the deployment claims.

# Fault Conformance Cases {#fault-conformance}

| Fault or race | Required outcome | Invariant |
|---|---|---|
| Two writers race a transition or counter | One serialized result; no double budget spend | {{serialization}} |
| Child creation races the fan-out cap | Child record and counter commit together | {{serialization}} |
| Expansion fails between predecessor and successor writes | Neither half survives alone | {{serialization}} |
| Crash after state commit, before publication | Durable repair publishes without losing the transition | {{fanout}} |
| Lagging node signs a newly fresh active value | Refusal unless an authoritative observation establishes that value | {{fresh-observation}} |
| Restore exposes a lower version | Issuer refuses until reconciled; retaining consumer rejects rollback | {{rollback}} |
| Legitimate higher-version resume | State is not rejected merely because active seems less severe | {{rollback}} |
| Partition outlasts the existing freshness horizon | No new control-plane mutation; stale reliance stops | {{partitions}} |
| Terminal record is absent after backup restore | Identifier does not regain active authority | {{tombstones}} |
| Same Mission ID under two issuers | No shared high-water mark, budget, or idempotency result | {{isolation}} |
| Key rotation during replication lag | A new signing key does not create freshness | {{fresh-observation}} |
| Duplicate or out-of-order transition events | Idempotent handling, gap detection, authoritative resynchronization | {{fanout}} |
| Positive emergency permission | Truthfully separate authority; affected actions excluded from the claim | {{emergency-authority}} |

# Conformance {#conformance}

A deployment claiming Mission Control-Plane Consistency MUST satisfy every
applicable requirement for the issuer, binding, and consumer roles it runs.
The conformance ledger separates the ten invariant groups from implementation
coverage; an unimplemented test is not evidence of compliance. Existing
binding-level conformance remains independent of this optional claim.

# Security Considerations {#security-considerations}

A valid signature can authenticate a stale or rolled-back assertion.
Consumer high-water marks complement, but do not replace, issuer durability:
a new consumer has no history against which to detect rollback. Failure
between the authoritative transaction and an external publisher requires
repair work in the former, not a best-effort call to the latter.

Emergency denial is not positive authorization. Expiring an emergency deny
never skips ordinary state, authority, identity, or point-of-use checks.
Shared infrastructure needs both identity isolation and bounded propagation
capacity; correct cache keys alone do not establish tenant availability.

# Privacy Considerations {#privacy-considerations}

Durable tombstones, idempotency records, and qualified Mission identifiers
can correlate activity. Retain the minimum facts needed for the stated
security horizons, restrict disclosure, and avoid putting human identity
or action content into replication and queue keys.

# IANA Considerations {#iana}

This document requests no IANA actions.

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Initial topology-neutral consistency foundation (#250): ten issuer
  invariant groups, the shared consistency and availability rule, the
  deployment declaration riding existing surfaces, and the fault
  conformance table. Implementation, multi-process claiming, and operator
  performance measurement are separate work.

# Acknowledgments
{:numbered="false"}

The author thanks the Mission-Bound Authorization implementer community.
