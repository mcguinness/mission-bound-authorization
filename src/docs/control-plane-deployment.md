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
a transition whose expiry clock materialized the expiry (`terminated`, reason
`expired`) first is refused rather than overwritten.

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
rebuilds from the authoritative record set. The continuation anchors and
handles and the delegation families are not subscribers: they are tables on
the kernel database, and the kernel writes them in its committing
transactions. The activating commit roots a Mission's anchor and initial handle
with the record, and the terminal commit marks every anchor, handle and family
of the Mission terminal beside the tombstone, so a commit that is never
published still leaves the projections right, and nothing is rebuilt from the
outbox. A subscriber whose effect leaves the process gets a
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
answering a conflict. That crash case is the only one that re-signs, and it
signs the recorded observation with its original `iat` and `exp`, so recovery
re-dates nothing; a response whose bytes were retained replays those exact
bytes. Replay lookup runs before any state-dependent check, which is where a
future `expected_version` precondition must stay behind it.

One clock governs the retry key: the ten-minute nonce window. For its whole
length, reusing a nonce with a different request stays `invalid_request`, and a
byte-identical retransmit replays the original response. That holds for a signed
`discharge` envelope too, whose own validity is sixty seconds: the profile
requires the window to be at least the response's validity span and permits it
to be longer, so a retransmit at two minutes replays rather than re-executes.
Replaying a retained acknowledgement of a completed operation is not a fresh
observation, and the envelope's own `exp` tells its consumer so. A deployment
that configures a window shorter than the response validity is raised to that
floor rather than allowed to free the nonce early.

The divergent-retry refusal is delivered and retained nowhere. It is refused
precisely because a row claimed under a different request digest holds that
nonce, so it is not that nonce's response; and finalization is guarded on the
request digest the claim was made under, so only the exchange that claimed a
nonce can fill in its bytes.

The expiry clock runs in its own transaction, before the transaction a
requested transition commits in. The clock materializes a narrowing transition
wherever a lifecycle request reads the record, and the operation then requested
may be illegal from the state that commit left; a refusal must never roll that
expiry back, leaving an expired Mission `active` without its transition or its
publication. The derivation gate follows the same rule.

Suspension schedules (`suspend_until` and `on_expiry`) are off unless a
deployment adopts them (`suspensionSchedules`). Where adopted, the schedule is
persisted, not the timer. Each schedule lives in its Mission's row, written in
the same compare-and-set statement as the `suspend` that arms it or the
metadata-only commit that replaces it, together with its committing party and
its generation (the state version of that commit); every transition out of
`suspended` clears it in the same statement. The schedule is therefore exactly
as durable as the Mission Record: it survives a restart on the file-backed
store and, like everything else, not on the in-memory default. Timers are
in-process and unreferenced. Startup re-arms one per persisted schedule and
delivers any whose deadline passed while the process was down before the
assembly serves a request. A delivery claims its generation inside one kernel
transaction and acts only on that exact schedule of a `suspended` Mission, so a
stale or replaced timer, a duplicate delivery and a delivery racing a manual
transition change nothing; nothing depends on cancelling a timer. The expiry
clock applies a due schedule after expiry, on any read of the record as well as
at the timer, so a Mission past its `expires_at` is `expired` and never resumed:
one first observed past `expires_at`, by a late resume or revoke delivery
included, ends `expired`, while a revocation committed before `expires_at` keeps
`revoked`. The transition and its durable lifecycle event commit together, as
for every other transition, and every effect outside the kernel follows that
commit: the commit names the schedule it applied, and a scheduled revocation's
destruction of the Mission's OAuth grant is a durable delivery of it, owed
whether a read, a request or the timer committed the transition, and retried
after a failure. This deployment refuses a `suspend_until` at or before the
current time with `invalid_request`; that refusal is its own choice, not a
requirement of the profile. Delivery is single-process: a second process would run its
own timers, each still claiming the generation under the version
compare-and-set, but no multi-process scheduling claim is made. Authorization
is decided at commit; a delivery never re-checks the committing party's grant.

A reservation replay is the one ungated path, and only when an artifact was
actually retained: returning a recorded artifact produces nothing new. A
recorded operation identity with no retained artifact is gated like any fresh
request, so a Mission revoked, expired or fully contained since the first
attempt refuses rather than signing off an unvalidated record. An identity an
authoritative non-acceptance refunded is terminal and refuses outright: its
count was returned, so admitting a retry would issue against a derivation
nobody is paying for. A new attempt needs a new operation identity.

A pending reservation is exclusive. Signing is asynchronous, so at most one
caller per (mission, operation) runs at a time on this instance; a caller
arriving mid-flight receives that owner's artifact, and one arriving afterwards
recovers the recorded one. Instance-level serialization for the declared
one-process topology, like the outbox drain, not a distributed lease.

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

A Template Dispatch or policy-adjudicated child creation retains, in its
record's own transaction, each activation policy snapshot its gate verified:
the exact bytes and media type, keyed by issuer, policy id, version and digest.
A retention failure commits no Mission. A write recomputes the digest and
refuses bytes that do not reproduce it, and never rewrites retained bytes, so
a policy edited under an unchanged version is a new row and never replaces the
evidence behind an earlier commitment. Each row is retained until the latest
expiry of a Mission activated under it plus the declared 7776000 seconds of
audit retention, the same declaration the tombstones compose. Boot recovery
deletes only rows past that horizon; replacing, editing or retiring a policy
in the current registry deletes nothing. Storage is not indefinite: past its
horizon a snapshot is gone and an audit check reports it unavailable. The
retained rows are audit evidence only. Activation eligibility reads the current
registry alone, so a retained snapshot never admits a replaced or retired
policy. The rows are on the kernel database and survive a restart only on the
file-backed store.

Namespace inventory for the changed seams:

| Mutable seam | Namespace boundary |
|---|---|
| Mission state/version, counters, child accounting and expansion deferrals | One issuer owns the kernel database |
| Suspension schedules and their generations | The Mission's own row in the kernel database |
| Durable lifecycle events and per-subscriber delivery rows | One issuer owns the kernel database; each event row records the issuer it committed under |
| Terminal tombstones | Keyed on the canonical issuer and Mission identity pair |
| Retained activation policy snapshots | Keyed on issuer, policy id, version and digest |
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

## Restart inventory

What a process restart keeps, for the AS's state and the state it depends on.
"File-backed" means the kernel opened with `kernelStore: { file }`. The shipped
launchers (`server.ts`, `pnpm as-native` and `pnpm issuance-only`) run the
kernel in memory unless `MISSION_KERNEL_STORE=<absolute path>` names its file,
which requires a key ring (`MISSION_KEY_RING`), so that what the kept kernel
issued or signed still verifies after a restart. That is restart recovery for
one process on one host: the file takes no lock, so a second process on the same
file is not refused, and a restore from an older backup is not detected, which
remain #250's restore and fencing step.

| State | Where it lives | Across a restart |
|---|---|---|
| Mission records, lifecycle events and deliveries, tombstones, creation idempotency, lifecycle responses | Kernel database | Durable on the file-backed kernel |
| Continuation anchors and handles, delegation families | Kernel database | Durable on the file-backed kernel; a lineage terminated before the restart stays terminal |
| Provider Grants, refresh tokens, authorization codes, sessions, interactions | oidc-provider's memory adapter (no adapter is configured) | Lost, and not reconstructible from the kernel: refresh continuity is not established. A recovered family whose grant is gone is refused `invalid_grant` |
| `missions.grant_id` (the approval binding) | Kernel database | Durable, but names a provider Grant that is gone |
| Mission-bound grant index | Its own in-memory database, deliberately off the kernel's | Lost with the grants it classifies |
| Token issuance index, which is also the delegation accounting (#869): each designation's and delegated token's kind, depth, actor chain, designee and designator key | Its own in-memory database, also when the kernel is file-backed | Deliberately invalidated: introspection of an earlier token answers inactive, an earlier designation is not redeemable (`invalid_request`), and no earlier token can be designated (`invalid_target`) |
| Dispatch Handoff consumption records | Its own in-memory database | Lost, so every earlier handoff grant is deliberately invalidated: each grant's `jti` names the process that issued it, and redemption refuses a grant another process issued (`invalid_grant`), even within the same second (PR #1299) |
| AS signing keys (`as-token`, `as-status`, `as-txn`, `as-continuation`) | A key ring file (`signingKeys: { ring }`; `MISSION_KEY_RING` in the launchers), or generated at boot (the library default; `MISSION_EPHEMERAL_KEYS=1` in the launchers, which refuse neither or both) | Durable with a key ring: each key keeps its `kid`, so an earlier token or signed record still verifies. Generated keys are deliberately invalidated: nothing earlier verifies |
| Access tokens | Self-contained JWTs | Verify only while their signing key survives |
| Durable grant revocations still pending | Kernel database | Attempted at boot; a revocation whose grant was lost with the provider is acknowledged with nothing left to revoke |
| Signals receiver state: the version high-water, the cached observation, the gap and rematerialization markers, the retained SET and the seen `jti` values | The receiver's store (`ReceiverOptions.store`): in memory by default, or a file the consumer gives it. No shipped service constructs a receiver | Durable when the consumer gives the receiver a file |

oidc-provider's memory adapter is process-global, so an AS rebuilt in the
same process still holds the previous provider's grants. A restart test that
rebuilds in-process witnesses the kernel side only, and the provider's loss is
emulated by destroying the grant.

The delegation accounting's loss is witnessed on the file-backed kernel with a
key ring, where every earlier token still verifies
(`delegation-accounting-restart.test.ts`). Each refusal precedes the grant
check, so it is the accounting's, not the provider's. A refusal counts
nothing, and nothing counted before the restart is returned. Introspection's
designation check loses its record too: an earlier designation answers
inactive through its missing issuance record while its Mission is active, and
through audience separation alone once it is not. A resource server that
accepts the designated client's identifier, which audience separation
forbids, is therefore shown that Mission's state, a residual that stays
until the accounting is kept with the provider's tokens.

The derivation counter and artifact issuance stay outside one transaction
(the provider access-token hook has no acceptance boundary), and the kernel's
file mode adds no owner, lock or schema version; both remain open.

Rollback resistance is partial. A restart on the file-backed store keeps the
state version and the terminal tombstone, so no lower version is served after
recovery. Refusing state-dependent service while a durable version is uncertain
after an out-of-band restore, and the fenced reconciliation policy that would
decide when it is certain again, remain follow-on work. Multi-process
serialization and claiming remain under #641's explicit deployment trigger;
this slice adds no such claim.

## Upgrading a kernel written before #1340

Before #1340 (`fccc1fe1`), the expansion and child-creation exchanges and the
deferred expansion poll did not check that the acting client is the
predecessor's or parent's own client (#1326). A file-backed kernel written by
such a build can hold Missions another client created. An in-memory kernel
keeps nothing across a restart, so only a deployment that kept its kernel file
is affected.

Building the AS revokes each such Mission that retained provenance identifies,
through the ordinary `revoke` transition, then drains the lifecycle outbox
before it serves a request:

- A Child Mission whose completed `creation_idempotency` row
  (`op = 'child-creation'`) names a client other than the parent's
  `client_id`. The child record names no creating client, so this row is the
  only link.
- An expansion successor created through another client's deferral. Its
  `expansion_deferrals` row records the client that opened it and the
  approval event it completed under, and its `redeemed = 1` marker is set in
  the transaction that created the successor. A later `deny` rewrites the
  row's `state` but not the marker, and deferral rows are never deleted. The
  successor carries the predecessor's client, so its own record cannot show
  the defect. The AS acts only when the predecessor and the successor both
  name this AS's issuer, exactly one Mission carries the deferral's
  predecessor and approval event, the predecessor's `superseded` termination
  names it, it carries the predecessor's client, and no deferral the
  predecessor's own client opened claims the same approval event. Each check
  runs before the expiry clock.
- A Progressive ceiling-drawdown successor another client requested. With
  Progressive drawdown on (`progressive`, off in every shipped launcher), the
  in-ceiling path creates a successor without a deferral. Its
  `approval_basis.activation_actor` records the requesting client, while its
  `client_id` is copied from the predecessor, so the successor's own record is
  the link and is never purged. The AS acts only when the activation actor
  names both an issuer and a client; the actor, the successor and the
  predecessor all name this AS's issuer; the actor's client differs from the
  successor's; the successor carries the predecessor's client; and the
  predecessor's `superseded` termination names it. Two stored issuers that
  agree with each other but not with this AS do not qualify, and a missing
  client identifies no one. Each check runs before the expiry clock.

Revocation runs after the expiry clock, so an expired Mission records
`expired`, and a terminal one keeps its recorded termination. The predecessor
stays superseded: nothing is resurrected and no replacement approval is
created. The cascade terminates the revoked Mission's children
(`parent_terminated`), and the delegation-family grant revocations are
attempted before the AS serves; a failed delivery stays pending for the next
drain. A successor that its own client later approved from a
revoked one is not a target, since the defect belongs to one creation
operation. A later boot finds nothing left to revoke and commits nothing. A
revocation that fails stops the build, so the AS never serves with an
identified live Mission. `BuiltAs.startupRemediation` lists what was revoked,
each committed deferral from another client whose successor could not be
identified, and each drawdown successor whose provenance disagrees, and each
shipped launcher (`server.ts`, `pnpm as-native` and `pnpm issuance-only`) logs
them. A reported deferral or successor is left alone.

Residuals:

- **Purged child-creation rows.** A child-creation row is retained for the
  creation idempotency horizon (86400 seconds by default) and can be lost
  after it in two ways: `CreationIdempotencyStore.find` deletes an expired row
  when its `(client_id, creation_request_id)` key is looked up, and an insert
  that reuses the key deletes the expired row first. Neither needs a
  replacement creation to succeed. A child whose row was gone before the first
  boot of a build with #1340 cannot be identified, and the AS revokes no child
  whose provenance is missing.
- **Credentials already issued.** Revocation is enforced wherever the AS or a
  resource consults the Mission's state: issuance gating, refresh, Token
  Exchange, introspection and Mission Status. A self-contained access token
  issued before the boot still verifies at a token-only resource until its
  `exp`, at most the declared 300-second access-token lifetime, and only while
  its signing key survives: a key ring keeps it, keys generated at each boot do
  not. A resource that reads Mission state sees the revocation within the
  staleness bound it declares.

An operator with authoritative backups or audit records of creation requests
can identify a specific affected Mission and revoke it through the Lifecycle
endpoint. Without them, an empty report does not prove the deployment clean.
