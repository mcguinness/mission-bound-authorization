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
identity and the same commit timestamp, at startup or on the next request
path. Subscribers are classified rather than each given retry state. The
Signals subscriber's synchronous journal insert is its durable acceptance and
its unique event key makes a redelivery a no-op. The Status List republisher
rebuilds from the authoritative record set. The continuation store and the
delegation-family store are in-memory projections that start empty at each
boot, and recovery replays only committed-but-unpublished events, so an
activation event that was already published does not repopulate them. Both are
idempotent per Mission and both fail closed on a row they do not hold: after a
restart an unknown continuation handle and an unknown family grant resolve to
nothing, so continuation resolution and family refresh refuse rather than
serve authority the process cannot account for. Rebuilding those two
projections from a durable source is follow-on work and no restart-recovery
claim is made for them. A subscriber whose effect leaves the process gets a
durable delivery row with attempts and a next-retry time, drained by an
awaited call from startup and from request paths, never from a commit
callback. Those drains are serialized on the kernel's outbox: one pass runs at
a time, and a caller arriving while a pass runs joins one follow-up pass that
starts after it, so two passes cannot dispose of the same delivery row. Each
disposition write is guarded on the pending row and on the attempt that
produced it, so a terminal disposition never moves and a stale attempt never
rewrites the attempt count, the error or the backoff. Delivery is at least
once with idempotent acceptance; a crash after a downstream accepted but
before the local acknowledgement may redeliver. Exactly-once external delivery
is not offered. A pending delivery whose subscriber is no longer registered is
marked at startup with a terminal `subscriber_removed` disposition and its
removal time, retained for the same horizon as a completed delivery, blocking
no other subscriber's rows, and not resurrected by re-registering that
subscriber.

Derivation admission uses a conditional counter update, so a caller holding a
snapshot taken before another writer consumed the last derivation is refused
rather than allowed to overshoot the cap. A synchronous caller can include the
reservation in the same managed transaction as its local side effect, as the
fault tests demonstrate.

Each counted derivation also carries a durable reservation naming the operation
and the artifact it paid for. The increment and the reservation commit in one
transaction; the reservation is released when the artifact is accepted; and a
repeat of a recorded operation identity replays the recorded artifact rather
than counting a second derivation. An unreleased reservation is AMBIGUOUS: the
artifact may never have been minted, or it may have been accepted with the
acknowledgement lost. Startup recovery therefore records the ambiguity as
`unacknowledged` and keeps the count consumed. A count is returned only on an
authoritative observation that no artifact was accepted, recorded with the
source that asserted it. Operators reconciling a fleet should read
`unacknowledged` as work owed an authoritative answer, never as a refund.

The ID-JAG and attenuation-root paths use that reservation. The provider
access-token hook does not: it is synchronous, runs inside the provider's own
token save, and offers neither an operation identity nor an acceptance
callback, so its count stays uncoupled from the token it pays for. Recording
authoritative issuance state and artifact material transactionally before
delivery is a possible future architecture; this deployment does not implement
it, and no completed serialization conformance claim is made. In particular, an
expansion's `completion_released` marker records release to the token adapter,
not proof of token delivery. It preserves recovery before that release but does
not provide cross-store exactly-once issuance, and it is not evidence of any
broader guarantee.

The lifecycle endpoint's retry key has an explicit signing boundary. The nonce
claim, the committed operation outcome and enough immutable response material
commit with the transition; the exact bytes are retained before they are
delivered. A retransmission that finds a committed outcome whose bytes were
lost finalizes the response from that material instead of re-executing the
operation, so a `resume` that in fact succeeded replays its success rather than
answering a conflict. For a signed envelope the recorded observation is signed
again with its original `iat` and `exp`, so recovery re-dates nothing, and a
retained envelope past its own validity is not replayed at all. Replay lookup
runs before any state-dependent check, which is where a future
`expected_version` precondition must stay behind it.

The Mission Status List publisher answers only from a token still inside the
validity that token was signed with. Past its own `exp`, and on any lifecycle
commit, the list is rebuilt from the authoritative record set rather than
re-signed from cached bits; a failed rebuild leaves no superseded token
published; and a fetch arriving mid-build joins that build, so an older
snapshot never lands after a newer commit.

A signed Mission Status observation is taken in one authoritative transactional
read of the stored record, with the expiry clock materialized in that same
transaction, and it carries the `(version, commit)` watermark it was taken at.
Its `iat`, `exp` and `fresh_until` belong to that observation point and are
never restamped, so a commit landing while the signature is in flight leaves
the delivered snapshot older without making it fresher. Refusing to deliver an
observation whose commit point advanced is available as an optional declared
policy (`strictObservationWatermark`), off by default: the governing rule
permits delivering an authenticated authoritative observation inside its own
validity, and refusal costs churn on a busy Mission and reader starvation under
sustained writes. The Status conditional-request surface remains follow-on
work, so the fresh-observation claim stays partial.

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
