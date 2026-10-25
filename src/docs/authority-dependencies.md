# Authority dependencies and identity changes

How the reference responds when a principal's standing changes after a
Mission is approved, by principal role (#830, D798; Runtime "Authority
Dependencies" and "Mission State and Freshness"). Paths are relative to
`src/`.

## The declared dependency

`config/authority-dependencies.json` declares one dependency,
`subject-delegation`: reliance on a user-delegated Mission depends on the
Mission Subject's account being active and on the Subject not having
withdrawn its delegation from the Mission's client. The source is
`config/identity.json` (each principal's `status`, `withdrawn_delegations`
and `changed_at`), read by the identity-state resolver
(`packages/mission-core/src/authority-dependency.ts`) and re-read without a
restart. An observation stays acceptable for `max_staleness_seconds` (300 s)
from when its read was issued, not when the read completed, so a slow read
never renews old state. Overlapping reads (a scheduled refresh and a
reconciliation pass) publish in the order they were issued, so an older read
never replaces a newer one. A Subject the source answers without is
unresolved: an uncertainty that refuses dependent actions and is recorded
as `unresolved`, never as a withdrawal and never as deprovisioning.

It is enforced by both routes:

- **Direct evaluation.** The authorization server's issuance gates evaluate
  it beside the `active` check: an approval is refused `access_denied`, and a
  code redemption, refresh, token exchange, child or expansion derivation is
  refused `invalid_grant`. The PDP evaluates it in its Resource-policy step
  and refuses `resource_policy`. A deployment can route this step to the PEP
  instead (`enforcement.direct: "pep"`).
- **At release.** A PEP holding the dependency rechecks it at every use of a
  permit, release included, on every dispatch path: reads, unkeyed and keyed
  reversible writes, and the transaction tier. Routed to the PEP, its
  composed step's ceiling (the admission observation's validity) travels
  with the permit, and no effect is released once it is reached. Either way,
  a known withdrawal, an observed invalidation or a lost observation that
  reaches the PEP after the decision stops the release (`resource_policy`).
- **Lifecycle-mediated enforcement.** The authorization server's reconciler
  (`services/authorization-server/src/adapters/authority-reconciler.ts`)
  commits `suspend` for a disabled Subject or a withdrawn delegation and
  `revoke` for a deprovisioned Subject, through the existing lifecycle
  operations. Mission Status, the Status List and Mission Signals carry
  each commit.

The enforcers split the failure cases:

- The PDP applies the lag refusal. It refuses a governed Mission's
  actions once the reconciler's last complete pass rests on an observation
  older than `reconciliation_max_lag_seconds` (60 s), even while the
  Mission's state reads `active`. It does so only where the composition
  binds the PDP to the dependency. A composition that routes direct
  evaluation to the PEP under lifecycle-mediated enforcement must still
  bind the PDP, because the PEP's composed step evaluates the observation
  and not the reconciler's progress.
- Lifecycle-only enforcement (no direct route) keeps the declaration's
  observation limits. The observation relied on is the one the last
  complete reconciliation acted on, dated from the time it represents. Once
  it is older than `max_staleness_seconds` the PDP refuses `stale`, and
  where an online check is declared a failed latest read refuses
  `unavailable`. A permit expires at the earlier of the staleness and lag
  deadlines. A PEP holding a lifecycle-only dependency applies the same
  checks at release: the reconciliation's currency, an unresolved Subject,
  the staleness bound and any online check.
- A Mission the reconciler restricted carries no cause on its record. The
  reconciler's last outcome (`AuthorityReconciler.last()`) and the
  lifecycle commit stream show which Missions it suspended or revoked.
- In the reference composition, the PDP reads the reconciler's progress in
  process (`BuiltAs.authorityDependency.reconciliation`). A PDP without that
  progress refuses every governed action, so a lost or never-started
  reconciler fails closed.
- Fresh progress does not authorize reliance on a dependency the
  reconciliation could not resolve. A pass records the governed Missions
  whose Subject the source holds no record of, and the PDP refuses their
  actions as `unresolved`. The reconciler does not suspend or revoke them.
- The issuance gates do not rely on reconciled state. They evaluate the
  observation itself and fail closed once it passes `max_staleness_seconds`.

The dependency is opt-in per composition: the authorization server's
`authorityDependency` option, the decision point's `authorityDependency`
binding, or the PEP's `authorityDependency` dependency. No shipped
composition (the demo stack, the MAS pilot, the as-native stack) wires it.
The declaration governs `user_delegated` Missions only. To govern a
workload Subject's Missions, add `service_owned` to
`governs.authority_sources`.

## The external-change bound

The declaration's `external_change_bound` states the claim:

- **Start:** the identity source records the change (`changed_at`).
- **End:** no action under a governed Mission can begin an effect. Every
  issuance gate and every PDP decision under it refuses, a PEP holding the
  dependency releases no effect under a permit issued before the change,
  and the reconciler has suspended or revoked the Mission.
- **Bound:** 60 s, covering one detection period (30 s) and one
  reconciliation period (30 s) in sequence. The reader refuses a bound that
  does not cover them. The authorization server refuses to start with a
  scheduled source read or reconciliation pass slower than the declared
  period.
- **Measured** (`services/authorization-server/test/authority-dependency-bound.test.ts`):
  the reference composition, run at the declared periods from every phase
  of the two schedules against the change in 5 s steps, with the payments
  PEP holding a permit issued just before the change. The worst case is 30 s
  for the first gate refusal, the first PDP refusal, the held permit's
  refusal at release and the suspension, which is a read and a pass that
  both land just before the change. The held permit is refused while its
  own `valid_until` still runs.
- **Already-started work:** work whose effect began before the change
  completes within that request. Permit issuance is not already-started
  work: a permit issued before the change and not yet used is rechecked at
  release and releases no effect after the cutoff. A permit relied on beyond
  its request expires no later than its `valid_until`: at most
  `max_staleness_seconds` after the observation it relied on, and at most
  `reconciliation_max_lag_seconds` after the observation the last complete
  reconciliation acted on. Access tokens already issued run to their expiry,
  but every issuance and every decision they reach refuses.

The bound holds for a successful observation path. Under failure:

| Failure | What catches it | Bound |
|---|---|---|
| Lost event (the change reaches the source, the next reconciliation pass does not run) | The next issuance gate and the PDP, from the resolver's read | One detection period |
| Disconnected feed (the source cannot be read) | The PDP's lag refusal. The issuance gates keep serving a cached observation still within its validity, then fail closed. | PDP: `reconciliation_max_lag_seconds` after the last good read. Gates: `max_staleness_seconds`. |
| Failed reconciliation (a transition does not commit) | The pass does not advance its progress, so the PDP's lag refusal applies. The next pass commits the remainder. | `reconciliation_max_lag_seconds` |
| Reconciler restart | Its progress starts absent, so the PDP refuses until the first complete pass. That pass commits nothing it already committed. | Until the first pass |
| Overlapping or slow read | An older read completing late is not published over a newer one; a slow read is dated from when it was issued, so it renews neither the observation's validity nor the reconciler's progress. | No extension |
| Subject unresolved (the source answers without the Subject) | The gates and direct evaluation refuse `unresolved`; under lifecycle-only enforcement the PDP refuses the Missions the last pass could not resolve. Nothing is suspended or revoked. | One detection period |

A source outage commits no lifecycle change. If a deprovisioning's
transition fails and an outage follows, the Mission stays unrevoked until
the source answers. Meanwhile the PDP refuses its actions once the lag
passes its bound, and the gates refuse once the observation passes its
staleness bound.

## Recovery

Re-enablement is a basis for future issuance only. The reconciler never
resumes a Mission and never revives a terminated one. A suspended Mission
resumes only through an authorized Lifecycle request (the
`mission_lifecycle` grant, `status#lifecycle-authorization`), and every
remaining check still applies afterwards. If the Subject is still disabled,
the gates and the PDP refuse, and the next pass suspends the Mission again.
Authority removed through Containment stays removed across suspension and
resumption. Work that must continue without the Subject is a new Mission
under an authority source that names its successor. The original approval's
attribution is unchanged.

## Matrix by principal role

Identifiers may coincide in a deployment; lifecycle consequences follow the
role, not the identifier. Only the recorded Subject's standing triggers the
declared dependency. For each change, the table names the effect, its
owner, its source and its staleness bound for new issuance, for the existing
Mission and for credentials already issued.

### Subject disabled

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | Gates refuse: approval `access_denied`, derivations `invalid_grant` | Identity owner | `identity.json` `status`, through the resolver | One detection period (30 s); fails closed once the observation is 300 s old |
| Existing Mission | `suspend` by the reconciler; the PDP refuses `resource_policy` until then | Security owner (the declaration's `lifecycle_operations`) | Same | 60 s declared, 30 s measured |
| Already-issued credentials | Run to expiry; every decision and derivation they reach refuses | Security owner | Same | As the existing Mission |

### Subject deprovisioned

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | Gates refuse | Identity owner | `identity.json` `status` | One detection period |
| Existing Mission | `revoke` by the reconciler, for any non-terminal Mission, a suspended one included. A source with no record of the principal, an outage and a disabled Subject never revoke; an unresolved Subject's actions are refused as `unresolved`. | Security owner | Same | 60 s declared, 30 s measured |
| Already-issued credentials | Unusable at every enforcing PEP once the Mission is terminated | Security owner | Same | As the existing Mission |

The core's Subject-deprovisioning SHOULD (#830 Q-e, open as #1683) is not
yet in the binding; its ledger row is mapped once that PR lands.

### Delegation withdrawn by the Subject

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | Gates refuse for that client | Identity owner (on the Subject's request) | `identity.json` `withdrawn_delegations` | One detection period |
| Existing Mission | `suspend` by the reconciler | Security owner | Same | 60 s declared |
| Already-issued credentials | As for a disabled Subject | Security owner | Same | As the existing Mission |

### Source principal's entitlement removed

Here the source principal is the principal whose authority the source
carries, who may differ from the Subject.

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | A derivation beyond the current ceiling refuses (the per-principal source resolver, #827). Under organizational authority, a changed governed policy fails the digest check at approval and at drawdown. | Authority-source owner | `authority-sources.json`, `governed-policy.json` | Read at each derivation from the loaded configuration; a change takes effect on restart |
| Existing Mission | None by default. Narrowing through Containment where it runs, or a declared dependency. | Security owner | `containment.json` | Containment: on the protected event |
| Already-issued credentials | Run to expiry | n/a | n/a | Token lifetime |

### Approving principal departs or loses the role

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | New approvals need a current activator | Identity owner | `identity.json` `roles` and `approves_for`, `authority-sources.json` `activators` | Loaded at startup; a change takes effect on restart |
| Existing Mission | None. No approver dependency is declared, and the reconciler evaluates only the recorded Subject. | n/a | n/a | n/a |
| Already-issued credentials | Unaffected | n/a | n/a | Token lifetime |

### Accountable owner departs

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | n/a | n/a | n/a | n/a |
| Existing Mission | None. The reference records no accountable owner apart from the Subject and approver, and declares no sponsorship dependency. | n/a | n/a | n/a |
| Already-issued credentials | Unaffected | n/a | n/a | Token lifetime |

### Client disabled

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | Client authentication fails at every gate | Client registry owner | `clients.json` | Loaded at startup; removal takes effect on restart |
| Existing Mission | None; no transition. A principal record for the client's identifier in the identity source changes nothing. | n/a | n/a | n/a |
| Already-issued credentials | Not stopped by the disablement; a declared dependency or a resource-side check must stop them where required | Security owner | n/a | Token lifetime |

### Immediate actor (delegate) disabled

| Consequence | Effect | Owner | Source | Bound |
|---|---|---|---|---|
| New issuance | That actor's delegated exchange and redemption refuse | Client registry owner | `clients.json`, `delegation.json` | Loaded at startup |
| Existing Mission | None | n/a | n/a | n/a |
| Already-issued credentials | Its delegated tokens run to expiry unless restricted | Security owner | n/a | Token lifetime |
