# Control-plane implementation boundary

The reference deployment retains D27: one process and one in-memory database
per service by default. A Mission kernel owns exactly one issuer namespace;
`insertRecord` rejects another issuer. Equal local IDs can exist in independent
issuer kernels, not as two rows in one kernel's `missions` table.

Local transactions now couple lifecycle state/version with descendant state,
child fanout admission with insertion, and expansion deferral retirement with
successor activation, predecessor supersession and expansion-finalize work.
Managed transactions defer synchronous publication until the outermost commit
and discard callbacks on rollback, including rolled-back savepoints. Such a
callback is not a durable delivery record: a subscriber failure after commit
cannot roll back the database, and process loss can still lose ordinary
lifecycle publication. Generalized durable fan-out is the next slice of #250.

Derivation admission uses a conditional counter update. A synchronous caller
can include it in the same managed transaction as its local side effect, as
the fault test demonstrates. Existing asynchronous provider, continuation and
signed-grant issuance paths do not yet share that atomic domain; no completed
serialization conformance claim is made. In particular, an expansion's
`completion_released` marker records release to the token adapter, not proof
of token delivery. It preserves recovery before that release but does not
provide cross-store exactly-once issuance.

Namespace inventory for the changed seams:

| Mutable seam | Namespace boundary |
|---|---|
| Mission state/version, counters, child accounting and expansion deferrals | One issuer owns the kernel database |
| Actor-depth records | Existing structured issuer/Mission/client tuple |
| Signals receiver state, replay and gap tracking | Structured issuer/local-ID tuple in each registered issuer receiver |
| Shared Signals delivery outbox | Structured issuer/event-ID storage key plus audience; wire event IDs remain unchanged |

The Signals outbox migrates legacy raw event keys transactionally, preserving
stored SET bytes and retry state. Invalid or conflicting identities stop
startup rather than dropping deliveries. Its tests prove equal Mission and
event IDs at distinct issuers remain independent, not an exhaustive audit of
all cross-issuer services, quotas or replication authority.

Persistent deployment, recovery horizons and permanent nonreuse tombstones
remain follow-on work. Multi-process serialization and claiming remain under
#641's explicit deployment trigger; this slice adds no such claim.
