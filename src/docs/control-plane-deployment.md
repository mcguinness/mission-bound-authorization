# Control-plane implementation boundary

The reference deployment declares one process and one writer. Each service uses
an in-memory database by default; the Mission kernel also accepts a file-backed
single-writer store as an opt-in, and the restart-recovery test exercises that
path. The posture stays single-process: a file authorizes no second writer. A
Mission kernel owns exactly one issuer namespace; `insertRecord` rejects another
issuer. Equal local IDs can exist in independent issuer kernels, not as two rows
in one kernel's `missions` table.

Local transactions couple lifecycle state/version with descendant state,
child fanout admission with insertion, and expansion deferral retirement with
successor activation, predecessor supersession and durable publication work.
Each of those writes is admitted from the stored row, not from the caller's
snapshot: a lifecycle transition compares and sets on `(version, state)`, and
a transition whose expiry clock materialized `expired` first is refused rather
than overwritten.

Every committed transition writes one immutable event row on the kernel handle
in the same transaction as the state write, with its event identity assigned
inside that transaction. Publication runs after the commit. Managed
transactions defer synchronous publication until the outermost commit and
discard callbacks on rollback, including rolled-back savepoints, so no
subscriber observes a transition that rolled back; and a process lost between
the commit and its publication replays the persisted payload, with the same
identity and the same commit timestamp, at startup or on the next request path.
Subscribers are classified rather than each given retry state. The Signals
subscriber's synchronous journal insert is its durable acceptance and its
unique event key makes a redelivery a no-op. The Status List republisher, the
continuation store and the delegation-family store are projections rebuilt at
boot and are idempotent per Mission. A subscriber whose effect leaves the
process gets a durable delivery row with attempts and a next-retry time,
drained by an awaited call from startup and from request paths, never from a
commit callback. Delivery is at least once with idempotent acceptance; a crash
after a downstream accepted but before the local acknowledgement may redeliver.
Exactly-once external delivery is not offered. A pending delivery whose
subscriber is no longer registered is marked at startup with a terminal
`subscriber_removed` disposition and its removal time, retained for the same
horizon as a completed delivery, blocking no other subscriber's rows, and not
resurrected by re-registering that subscriber.

Derivation admission uses a conditional counter update, so a caller holding a
snapshot taken before another writer consumed the last derivation is refused
rather than allowed to overshoot the cap. A synchronous caller can include the
reservation in the same managed transaction as its local side effect, as the
fault tests demonstrate. Existing asynchronous provider, continuation and
signed-grant issuance paths do not yet share that atomic domain; no completed
serialization conformance claim is made. In particular, an expansion's
`completion_released` marker records release to the token adapter, not proof
of token delivery. It preserves recovery before that release but does not
provide cross-store exactly-once issuance.

The Mission Status List publisher answers only from a token still inside the
validity that token was signed with. Past its own `exp`, and on any lifecycle
commit, the list is rebuilt from the authoritative record set rather than
re-signed from cached bits; a failed rebuild leaves no superseded token
published; and a fetch arriving mid-build joins that build, so an older
snapshot never lands after a newer commit. The authenticated
observation/commit watermark and the Status conditional-request surface remain
follow-on work, so the fresh-observation claim stays partial.

A terminal transition writes its tombstone in that same transaction: canonical
issuer and Mission identity, terminal state, final version, transition time and
the commit event reference. The table carries no foreign key to `missions`, so
pruning a terminal record cannot take the marker with it. Detailed retention is
the composed maximum of the declared credential and artifact lifetime, the
state-staleness ceiling plus clock skew, the idempotency and retry horizon, the
child-cascade horizon and the audit-retention horizon. This deployment declares
300 seconds of access-token lifetime, a 300-second staleness ceiling with
30 seconds of skew, 86400 seconds of creation and discharge idempotency
retention, no separate child-cascade horizon because the cascade commits inside
the terminal transition, and 7776000 seconds of audit retention; the audit
horizon therefore governs. A horizon that is not a non-negative number is
refused at construction. Past the composed horizon the detail columns are
pruned and the identity row remains as the permanent nonreuse marker. Two
consumers rest on it: record creation refuses a terminal identifier inside its
own transaction, which is what keeps nonreuse true after the terminal row is
purged; and the creation-idempotency purge window is one of the composed
inputs, so a reservation admitted after that purge still cannot name a terminal
identifier.

Namespace inventory for the changed seams:

| Mutable seam | Namespace boundary |
|---|---|
| Mission state/version, counters, child accounting and expansion deferrals | One issuer owns the kernel database |
| Durable lifecycle events and per-subscriber delivery rows | One issuer owns the kernel database; each event row records the issuer it committed under |
| Terminal tombstones | Keyed on the canonical issuer and Mission identity pair |
| Actor-depth records | Existing structured issuer/Mission/client tuple |
| Signals receiver state, replay and gap tracking | Structured issuer/local-ID tuple in each registered issuer receiver |
| Shared Signals delivery outbox | Structured issuer/event-ID storage key plus audience; wire event IDs remain unchanged |

The Signals outbox migrates legacy raw event keys transactionally, preserving
stored SET bytes and retry state. The kernel migrates the retired
expansion-specific outbox the same way, carrying each pending job's original
event identity and commit timestamp onto the generalized table. Invalid or
conflicting identities stop startup rather than dropping deliveries. A receiver
treats the SET `iss` and the event's `mission.issuer` as one identity and
refuses a SET that separates them. Its tests prove equal Mission and event IDs
at distinct issuers remain independent, not an exhaustive audit of all
cross-issuer services, quotas or replication authority.

Rollback resistance is partial. A restart on the file-backed store keeps the
state version and the terminal tombstone, so no lower version is served after
recovery. Refusing state-dependent service while a durable version is uncertain
after an out-of-band restore, and the fenced reconciliation policy that would
decide when it is certain again, remain follow-on work. Multi-process
serialization and claiming remain under #641's explicit deployment trigger;
this slice adds no such claim.
