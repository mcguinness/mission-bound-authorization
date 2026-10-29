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

Child Mission Carryover (`child-delegation.carryover`; `child_mission_carryover`
in `policy.json`, on in the reference deployment) widens that expansion
transaction rather than adding a second one. The plan is rendered, its
identifiers reserved and its manifest committed on the deferral row at
approval. Completion runs the whole batch in the expansion completion
transaction, between successor activation and predecessor supersession:
- the descendant-set membership pass;
- one compare-and-set per carried row against its rendered snapshot;
- every replacement record, in generation order, each keeping the old child's
  `derivation_limit` and `derivation_count`;
- the cascade of the whole old subtree;
- the complete final map and the signed Carryover Evidence;
- the terminal tombstones and the durable outbox payloads.

A failure anywhere rolls all of it back, so no partial successor, replacement or
cascade survives, and publication runs after the commit, as for every other
transition. The consistency domain is therefore the predecessor, its whole live
subtree and the successor, together with their budget state and their durable
publication, in one issuer's kernel database with its single writer. A
deployment that shards Mission state per Mission cannot offer carryover without
a transaction spanning that domain. No external meter or latch participates:
the deployment declares none (`noApplicableExternalState`), so a carried budget
is the kernel's own counters. The domain is bounded at intake by
`carryover_max_rows` (8 in `policy.json`): a larger plan is refused
`carryover_plan_too_large` before any approval names it. A deployment that
omits carryover keeps the ordinary cascade, and the specification is unchanged.

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
callback, so its count stays uncoupled from the token it pays for. A failure
the request itself observes before the token leaves returns that count
(#935, D772): the request notes each count the hook spends and settles it
when it answers anything but a 200, or fails by an exception after its
response was prepared. A crash or a lost response is never
observed, so it stays counted. The ID-JAG path settles a reservation it
admitted itself as not accepted, with authority `as:in-process-failure`,
when the grant fails before it is returned. Recording
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
sustained writes. That optional policy blocks Lifecycle response recovery and
its `commit` member falls after boot pruning (#1865); neither re-dates an
observation.

Signed-artifact inventory: every signed artifact the reference produces,
classified against the fresh-observation rule. Only a state observation states
Mission state at a time for a verifier to rely on as current, so only its
timestamps must belong to its observation point.

| Artifact | Signer | Class | Observation point and timestamps | Replay | Witness |
|---|---|---|---|---|---|
| Mission Status response (`mission-status-response+jwt`) | AS, Status key | State observation | One transactional read of the record, its `(version, commit)` watermark captured there; `iat` is that read's clock, and `exp` and `fresh_until` derive from it | Not cached; never re-signed | `control-plane-faults.test.ts` ("stamps an observation with its own observation point, not the clock at signature time"; "leaves a snapshot older when state commits during the signature, and re-dates nothing") |
| Lifecycle endpoint response (the same type, the discharge envelope included) | AS, Status key | State observation | Observed inside the transition or latch transaction | Final bytes replay for the 600-second nonce window, past the 60-second `exp`, solely as confirmation of the correlated original operation with every other check passing: the replay refreshes no state and authorizes nothing; a committed row re-signs the retained observation with its original `iat`, `exp` and `fresh_until` | `control-plane-responses.test.ts` ("signs a recovered response over the original observation, never re-dating it"; "replays the retained bytes of a signed envelope past its own validity, for the whole nonce window"); `lifecycle-endpoint.test.ts` ("recovers a committed response whose bytes were lost at its original observation: the same iat, exp and fresh_until") |
| Mission Status List token (`statuslist+jwt`) | AS, Status key | State observation | `iat` is read immediately before the record set, in one synchronous step with no await between them; that ordering is load-bearing | Cached only inside its own `exp` and while no commit is pending; past `exp` it is rebuilt from the records, never re-signed | `status-list.test.ts` (the three "Status List republication" cases) |
| Mission Signals lifecycle-change SET (`secevent+jwt`) | AS-side transmitter, Status key | Transition record (D993) | Its observation point is `committed_at`, recorded at commit; `iat` is RFC 8417 issuance at the first dispatch, which a crash can delay well past the commit. The receiver orders by `version`, never `iat` | Signed bytes persisted before the first hand-off; every redelivery is byte-identical | `durable-delivery.test.ts` ("signs a job journaled before a crash, hours later, with its commit's own committed_at, and a receiver orders it by version ...") |
| Join Assertion (`mission-join+jwt`) | AS, Status key | Attestation that a credential joins a Mission: no state, version or `fresh_until` | `iat` is read in the same step as a synchronous re-read of the Mission, which is re-read again after signing | The cache serves the original bytes only inside their `exp`, keyed on the Mission, the token digest and the audience | `join-assertion-endpoint.test.ts` (the cache key and re-read cases) |
| Discharge Receipt (`mission-discharge-receipt+jwt`) | AS, Status key | Record of a forwarded discharge; no Mission state | `iat` inside the discharge transaction | Retained and recovered like a Lifecycle response | `discharge-carryover.test.ts` (the signed receipt replay case) |
| Credentials: OAuth JWT access tokens and ID Tokens, ID-JAGs, AAT roots and children, transaction tokens, child grants, Dispatch Handoff grants, cross-org and RAS access tokens, AAuth person, auth and resource tokens, ARAP approvals | AS, RAS, AAuth PS and resource, Access Request Service, holders | Credential | `iat` is issuance time, not a statement of current Mission state. The AS's Mission-bound OAuth access tokens, ID-JAGs and AAT roots gate on Mission state at mint and bound `exp` by the Mission's expiry. A holder mints an offline AAT child with no Mission-state check, under its parent's bounds; an ARAP approval states `approved_until`, carries no JWT `exp`, and checks no Mission state. This inventory makes no mint-time state claim for the other credentials | New per mint; a recorded operation replays its stored bytes | The issuance suites |
| Records: Approval Governance Records, governed-policy consent attestations, Carryover Evidence, Decision Evidence, Refusal Records, Execution Evidence, Mission Receipts, PDP denial bindings, work-product bindings, transparency statements and receipts | AS, PDP, PEP, mediators, the transparency service | Historical record | Dated by the recorded event time; the AS records are signed inside the transaction that commits the event | Retained byte for byte | Their own suites |
| Proofs and metadata: DPoP proofs, client assertions, transaction challenges, AAT proofs of possession, AAuth HTTP signatures, the Historical Key Set, the harness scope statement | Clients, holders, resources, the AS | Other | Not a statement of Mission state | n/a | n/a |

Two observations are unsigned: the RFC 7662 introspection response and the
AAuth Person Server's status response stamp `fresh_until` from the same read,
with no await between the read and the stamp.

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

Namespace inventory: every mutable seam in the reference, its key, and what
keeps one issuer's Mission state apart from another's (the key itself or a
declared separation), with the test that witnesses it. "Per AS" is a store each
`buildAuthorizationServer` constructs for itself, and an AS serves one issuer.
"Per composition" is one PEP composition: an `McpPaymentsServer` with its
Mission loader.

| Mutable seam | Key | Isolation | Witness |
|---|---|---|---|
| **AS kernel database:** every table in the [transaction inventory](#transaction-inventory) (Mission state and version, counters, child accounting, deferrals, approval records, lifecycle events and deliveries, carryover, schedules, standing payments) | Each table's own key, several the bare Mission identifier | One issuer owns the database, recorded in `kernel_issuer`: an open under another issuer is refused, and so is another issuer's record. A store written before the record binds only to the one issuer its state names ([upgrade](#upgrading-a-kernel-written-before-1748)) | `kernel-issuer-binding.test.ts`, its upgrade cases included; `control-plane-faults.test.ts` ("one-issuer stores refuse foreign records and independent issuers can retain the same local id") |
| Terminal tombstones | (issuer, Mission) | Key, in the one-issuer database | `control-plane-fanout.test.ts` ("isolates tombstones per issuer, so one issuer's terminal id does not refuse another's") |
| Carryover reservations and replacement evidence, derivation reservations, activation policy snapshots, approval rule records | (issuer, Mission); (issuer, replacement); unique (issuer, Mission, operation); (issuer, policy id, version, digest) | Key, in the one-issuer database | The kernel database's witnesses |
| **AS, per AS:** token issuance index (actor depth) | (`iss`, `jti`) | Key, per AS | None |
| Dispatch Handoff consumption records | `jti` | Per AS; a grant from another issuer is refused before it is consumed | `dispatch-handoff.test.ts` ("an expired grant, or one from another issuer, is refused") |
| Mission-bound grant index, token deferrals, transaction-authorization workflows, templates and their dispatch events, issuer evidence, in-flight derivations, suspension timers, the expansion, Join Assertion and Mission Status rate limiters, DPoP replay, the Join Assertion cache, approval and login sessions, the published Status List | Grant, deferral code, workflow, template, Mission, client, proof or minted handle | Per AS | None |
| Signing key ring | Role keys under one named issuer | One ring per AS; a ring for another issuer is refused | `signing-key-ring.test.ts` (its "another issuer" case); `as-native-stack.test.ts` ("signs with a configured key ring and says so; a ring for another issuer refuses before anything connects (#831)") |
| **AS, process-global:** oidc-provider's memory adapter (Grants, sessions, authorization codes, refresh tokens, device user codes) | Model and identifier | Declared: one AS per process. The adapter is a module-level LRU of 1000 entries shared by every AS in a process, and every launcher runs one AS per process (`stack.ts`, `issuance-only.ts`, `mas-as.ts`) | None |
| Device authorization decisions in progress | Provider-minted session identifier | Declared: one AS per process, as above | None |
| **PDP** (one per deployment, shared by every PEP and issuer it serves): idempotency claims | (scope digest, idempotency key); the scope carries the Mission issuer | Key | `idempotency-claim.test.ts` ("gives the same key and operation under the same local Mission identifier at another issuer its own claim, never the first issuer's") |
| Decision Evidence sequences | (issuer, Mission, emitter, role) | Key | `decision-evidence-sequence.test.ts` ("keeps a distinct counter for each Mission and each emitter, across a restart") |
| `mission` budget counters | (issuer, root Mission) | Key | `budget-reservations.test.ts` ("keeps each issuer's instance counter apart for one local Mission identifier, while both draw on the standing consent their accounting domain declares") |
| `standing_consent` budget counters | (owner, budget id) | The budget's accounting domain, not the issuer: one standing consent spans every Mission whose committed policy commits that budget, under any issuer whose policy the PDP's budget declaration lists. It is charged only through the trusted budget source (the kernel's committed policy snapshot, never the request) and the declared policy references, so a matching owner and budget id alone charge nothing | The same `budget-reservations.test.ts` case; `budget-reservations.test.ts` ("currency mismatch, an undeclared budget, another owner, and a limit or a Dispatch Policy id, version or digest that disagrees with the declaration each deny constraint_unsupported ..."; "createDecisionPoint over a claim domain that meters budgets refuses construction without a budget source, and a decision point over one that meters none denies constraint_unsupported a caller's view that carries a binding ...") |
| Claim and budget transitions, budget reservations, settlement conflicts, claims in flight, duration leases | Evaluation identifier, counter or activity; a renewal's scope digest carries the Mission issuer | PDP-minted identifiers, or key | None |
| Mission Status resolver cache | Mission identifier | One resolver per issuer and scope; a reference or response naming another issuer is refused, and a cached read answers nothing for one | `mission-status-resolver.test.ts` ("never reads a reference naming another issuer"; "returns what an earlier resolve established, never reads the source, and returns nothing once a bound has passed") |
| **PEP, per composition:** operations, permit redemptions, the connector ledger, reversals and outbox, outcome alerts | `op:<Mission>:...`, the bare Mission identifier | Declared: one Mission issuer per composition (below) | `kernel-mission-view-issuer.test.ts`; `token-profile.test.ts` ("answers an at+jwt from the trusted issuer whose mission.issuer names another issuer 401 invalid_token ...") |
| Execution Evidence sequences, durable and in memory | (Mission, emitter, role) | Declared: one Mission issuer per composition | As above |
| Write reservations, payment schedules | (scope digest, key), the scope carrying the Mission issuer; unique (Mission issuer, Mission, invoice) | Key | None |
| Actor-depth records | (issuer, Mission, client) | Key | `actor-records.test.ts` ("ignores a same-id record from another issuer: records are keyed on the canonical (issuer, id) pair") |
| Consumed permits, execution attempts, transaction challenges and their consumption, permit redeemers, retained evidence and published keys | Evaluation, execution, `txn`, permit or record identifier | The minter's namespace | None |
| Introspection cache | Token digest | One introspection issuer; an answer naming another issuer is refused | `token-introspection.test.ts` ("refuses an answer naming another issuer") |
| **Replay caches:** DPoP and channel replay (AS, PEP, PDP, plain resource server), AAuth request replay and JWKS caches | Presenter-chosen proof identifier, key thumbprint, URL or issuer | One verifier each; a collision fails closed | None |
| **Signals:** receiver state, replay, gap, recovery and resynchronization nonces | (issuer, audience, Mission, `jti` or nonce) | Key | `receiver-durability.test.ts` ("keeps receivers for different issuers and audiences apart in one shared file") |
| Shared Signals delivery outbox | (issuer, event identifier) plus audience; wire event IDs remain unchanged | Key | `durable-delivery.test.ts` ("equal Mission ids and event ids from distinct issuers keep separate delivery jobs and state") |
| **Other services:** RAS grant redemptions | (issuer, `jti`) | Key | `durable-redemptions.test.ts` ("scopes a claim to its issuer: one jti from two issuers is two claims, and each is claimed once") |
| AAuth Person Server Missions, issued tokens and log | (agent, digest); (`iss`, `jti`); sequence | One Person Server | None |
| Access-request tasks | Task identifier | One per instance | None |

The MCP SaaS resource accepts several Mission issuers but keeps no mutable
per-Mission state; the console BFF, the plain and AAuth resources, the
transparency service and the agent keep none either.

One Mission issuer per PEP composition: every Mission the PEP acts on is
resolved through the composition's loader, on the credential, propagated and
Join paths alike, and each shipped loader answers only its own issuer
(`kernelMissionViewFor` in the stack and the MAS pilot, a Mission Status
resolver bound to one issuer in the separated pilot). A Mission-bound
credential's `iss` is the PEP's configured issuer, and its `mission.issuer`
must equal it. The MAS pilot's gateway and resource routes share one engine,
connectors, write reservations and evidence store, and one loader for the
Mission Issuer; the gateway's estate issuer mints only ordinary credentials.
The operation keys and Execution Evidence sequences therefore key on the bare
Mission identifier inside that one namespace. Qualifying them would restart
every Execution Evidence sequence and orphan an operation in flight, so they
are declared instead. The separation holds for a persistent store's whole
lifetime, restarts included: a PEP's durable stores are never reopened by a
composition serving another Mission issuer, and nothing in the PEP refuses
such a reopen.

The Signals outbox migrates legacy raw event keys transactionally, preserving
stored SET bytes and retry state. The kernel migrates the retired
expansion-specific outbox the same way, carrying each pending job's original
event identity and commit timestamp onto the generalized table. Invalid or
conflicting identities stop startup rather than dropping deliveries. A receiver
treats the SET `iss` and the event's `mission.issuer` as one identity and
refuses a SET that separates them.

## Carryover compositions

How an expansion composes with the predecessor's children here, with the
reference configuration: carryover on, `all_or_nothing`, at most 8 rows, no
external state. These rows declare the reference deployment's behavior; a
deployment that omits carryover or selects other exclusions changes them
without changing the specification. Unless its row says otherwise, a refusal
comes at completion, rolls the whole transaction back (no successor, no
replacement, no cascade, the predecessor still active) and answers the client
`access_denied`, so a fresh expansion request is needed. Each witness names a test file under
`src/services/authorization-server/test/` and the test's title, unique in its
file. "Not supported" marks a composition the reference deployment does not
offer.

| Composition | Outcome | Mechanism | Witness | Ledger row |
|---|---|---|---|---|
| Expansion with no live descendant | No plan; an ordinary expansion supersedes the predecessor | `prepareCarryover` prepares no plan | `carryover.test.ts`: "prepares no plan for a predecessor with no live descendant and completes an ordinary expansion" | None |
| Live children, carryover off when the expansion opens | No plan; supersession cascades the whole subtree `parent_terminated`, each naming its immediate parent, and carries nothing | The supersession's own cascade (`supersedeInCallerTx`) | `carryover.test.ts`: "with the switch off when the expansion opens, prepares no plan and cascades the live subtree ordinarily, carrying nothing" | None |
| Live children under carryover, `all_or_nothing` | Each active child is replaced under the successor, or under its parent's replacement, and terminated `parent_terminated` with `carried_to`; the signed map lists every old child | Rendering, then at completion the membership pass, one compare-and-set per carried row, and inserts in generation order, in one transaction | `carryover.test.ts`: "carries an active leaf child under the successor with a fresh direct approval basis, the preserved budget and bare same-issuer correlation"; "carries a grandchild under its replacement parent, never the root successor" | `child-delegation.carryover.fresh-direct-records`, `.generation-order`, `.atomic-records-map-outbox` |
| Live children under carryover, `disclosed_exclusions` | Not supported by `policy.json`, which fixes `all_or_nothing`; through the `childMissionCarryover` option, a change of a committed class excludes that child and its dependents and carries the rest, and any other class refuses | Adjudication against the plan's committed change classes | `carryover.test.ts`: "excludes only a committed change class under disclosed exclusions and carries the rest"; "refuses a change class the plan did not commit, even under disclosed exclusions" | `child-delegation.carryover.completion-cas`, `.expansion-disclosure` |
| Child suspended at rendering | Rendered as a cascade (`suspended_not_resumed`) and terminated `parent_terminated`, never resumed; its dependents are excluded | Rendering reads each child's effective state | `carryover.test.ts`: "excludes a suspended child and never resumes it" | `child-delegation.carryover.effective-set-basis` |
| Child suspended and resumed before rendering | Carried as an active child | Rendering reads the current state | `carryover.test.ts`: "carries a child suspended and resumed before rendering; one suspended at rendering and resumed before completion refuses the batch" | `child-delegation.carryover.completion-cas` |
| Child suspended, or resumed, after rendering | Refused | Membership pass (`state_changed`); for a carried row, also the compare-and-set on state and version | `carryover.test.ts`: "refuses a batch when a rendered child was suspended after approval", and the resume test above | `child-delegation.carryover.completion-cas` |
| Child contained before rendering | Carried without the contained authority; no containment is restored or carried | The replacement is derived from the old child's effective set, under an independent ceiling of that set | `carryover.test.ts`: "does not restore containment removed from the old child's effective set" | `child-delegation.carryover.effective-set-basis` |
| Child contained after rendering | Refused | Membership pass (`containment_version`, effective authority) | `carryover.test.ts`: "refuses a batch when a rendered child was contained after approval" | `child-delegation.carryover.completion-cas` |
| Child entry discharged before rendering | Carried without the discharged entry, though the successor holds it; the replacement has no latch of its own | The old child's effective set drops discharged entries | `discharge-carryover.test.ts`: "does not restore an entry discharged on the old child: the replacement carries only the remaining entry, though its new parent holds both" | `child-delegation.carryover.effective-set-basis` |
| Child entry discharged after rendering | Refused, even by a plan that excludes the discharge's state change, and even where the entry was already contained | Membership pass (the committed discharge state, effective authority, `state_changed`) | `discharge-carryover.test.ts`: "refuses a batch whose child entry was discharged after rendering, creating nothing"; "refuses it even where the plan commits a state change as an exclusion: the child's effective authority moved, which the plan did not commit"; "refuses a discharge after rendering that leaves the effective authority unchanged, under a plan that excludes only state changes" | `child-delegation.carryover.completion-cas` |
| Derivation consumed after rendering | Refused | Membership pass (`derivation_consumed`); compare-and-set on `derivation_count`, which moves with no version change | `carryover.test.ts`: "refuses a batch whose derivation counter moved after rendering with no lifecycle version bump" | `child-delegation.carryover.completion-cas` |
| Child created after rendering | Refused | Membership pass (`unrendered_descendant`; the parent's fan-out occupancy moved) | `carryover.test.ts`: "refuses a batch when a grandchild was inserted after approval, so no unrendered descendant is silently carried" | `child-delegation.carryover.completion-cas` |
| Rendered child terminated, or its record gone, after rendering | Refused; a terminated row is not an acceptable exclusion. Where a plan commits `record_missing`, a gone row is recorded from its tombstone's committed termination, or refused without one | Membership pass (`state_changed`, `record_missing`); the final map records every rendered row | `carryover.test.ts`: "refuses a batch when a rendered child was terminated after approval rather than treating it as an acceptable exclusion"; "refuses a batch when a rendered child's record is gone at completion" | `child-delegation.carryover.completion-cas` |
| Carried child's own expiry arriving before completion | Refused, with nothing carried; a plan that commits `state_changed` instead excludes the child and records it `expired` while the rest carries | The membership pass compares a carried row through the expiry clock (`state_changed`); creation's expiry check is a backstop | `carryover.test.ts`: "refuses a batch when a carried child's own expiry arrives before completion: no replacement can outlive it"; "is excluded and recorded expired under a plan committing state changes, while its sibling carries" | `child-delegation.carryover.completion-cas`, `child-delegation.child-state.own-expiry-precedence` |
| Successor expiry extension | Completes; each replacement keeps the old child's expiry. The deferred expansion route offers no extension; the kernel accepts one | The old child's expiry is an independent bound beside the new parent's | `carryover.test.ts`: "refuses to extend a carried child under a successor whose approved extension outlives the predecessor" (the batch completes) | `child-delegation.carryover.no-expiry-extension`, `.expansion-expiry` |
| Carryover switched off after the plan was approved | Completion refused `server_error` (HTTP 500), a deployment fault rather than a decision; nothing is cascaded and the approval stays unredeemed; restoring the switch completes the same plan | Completion refuses a committed plan while the switch is off | `carryover.test.ts`: "refuses completion when a committed manifest meets a disabled switch, and cascades nothing"; "executes the same committed manifest intact once the switch is restored" | None |
| Plan above `carryover_max_rows` | Refused at intake, before any approval names it: `invalid_request` with `mission_denial_reason` `carryover_plan_too_large`; nothing reserved | The cap counts every non-terminal descendant | `carryover.test.ts`: "refuses an oversized plan at intake, before any approval event names it" | `child-delegation.carryover.manifest-committed` |
| Policy-adjudicated (Progressive) drawdown with live children | Not supported: the request falls back to a fresh direct approval (`live_children`), which prepares carryover; the policy path never carries | The drawdown's live-children fallback; the carryover funnel refuses a non-direct basis | `progressive-drawdown-endpoint.test.ts`: "a predecessor with a non-terminal Child Mission falls back; once the child is terminal it is adjudicated" | `progressive.in-ceiling.live-children-fall-back`; `child-delegation.carryover.no-progressive-drawdown` stays `todo` |
| External meter or latch | Not supported: the deployment declares none, so a carried budget is the kernel's own counters | `noApplicableExternalState` | `carryover.test.ts`: "renders a child ineligible when no external meter or latch can participate and the deployment declares none absent"; "rolls the whole batch back when a transaction-participating external transfer fails" | `child-delegation.carryover.budget-transfer` stays `partial` |

## Restart inventory

What a process restart keeps, for the AS's state and the state it depends on.
"File-backed" means the kernel opened with `kernelStore: { file }`. The shipped
launchers (`server.ts`, `pnpm as-native` and `pnpm issuance-only`) run the
kernel in memory unless `MISSION_KERNEL_STORE=<absolute path>` names its file,
which requires a key ring (`MISSION_KEY_RING`), so that what the kept kernel
issued or signed still verifies after a restart, and a recovery witness
(`MISSION_KERNEL_WITNESS`), so that a restored older store is refused rather than
resumed ([Restore admission](#restore-admission)). That is recovery for one
process on one host.

| State | Where it lives | Across a restart |
|---|---|---|
| Mission records, lifecycle events and deliveries, tombstones, creation idempotency, lifecycle responses | Kernel database | Durable on the file-backed kernel |
| Continuation anchors and handles, delegation families | Kernel database | Durable on the file-backed kernel; a lineage terminated before the restart stays terminal |
| Join evidence events, one per Join Assertion minted (#1560) | Kernel database, written before the assertion is returned | Durable on the file-backed kernel; each is kept until the `retain_until` written when it was recorded (its Mission's expiry plus the declared audit retention: `auditRetentionSeconds`, else 7776000 seconds), which a reboot never recomputes, and boot recovery deletes only events past it |
| Provider Grants, refresh tokens, authorization codes, sessions, interactions | oidc-provider's memory adapter (no adapter is configured) | Lost, and not reconstructible from the kernel: refresh continuity is not established. A recovered family whose grant is gone is refused `invalid_grant` |
| `missions.grant_id` (the approval binding) | Kernel database | Durable, but names a provider Grant that is gone |
| Mission-bound grant index | Its own in-memory database, deliberately off the kernel's | Lost with the grants it classifies |
| Token issuance index, which is also the delegation accounting (#869): each designation's and delegated token's kind, depth, actor chain, designee and designator key | Its own in-memory database, also when the kernel is file-backed | Deliberately invalidated: introspection of an earlier token answers inactive, an earlier designation is not redeemable (`invalid_request`), and no earlier token can be designated (`invalid_target`) |
| Dispatch Handoff consumption records | Its own in-memory database | Lost, so every earlier handoff grant is deliberately invalidated: each grant's `jti` names the process that issued it, and redemption refuses a grant another process issued (`invalid_grant`), even within the same second (PR #1299) |
| AS signing keys (`as-token`, `as-status`, `as-txn`, `as-continuation`) | A key ring file (`signingKeys: { ring }`; `MISSION_KEY_RING` in the launchers), or generated at boot (the library default; `MISSION_EPHEMERAL_KEYS=1` in the launchers, which refuse neither or both) | Durable with a key ring: each key keeps its `kid`, so an earlier token or signed record still verifies, through an `overlap` generation after a rotation, until that generation is retired or withdrawn as compromised. A ring change takes effect only through stop, edit, start, `pnpm keys verify` (see `channel-key-matrix.md`). Generated keys are deliberately invalidated: nothing earlier verifies |
| Access tokens | Self-contained JWTs | Verify only while their signing key survives |
| Durable grant revocations still pending | Kernel database | Attempted at boot; a revocation whose grant was lost with the provider is acknowledged with nothing left to revoke |
| Signals receiver state: the version high-water, the cached observation, the gap and rematerialization markers, the retained SET and the seen `jti` values | The receiver's store (`ReceiverOptions.store`): in memory by default, or a file the consumer gives it. No shipped service constructs a receiver | Durable when the consumer gives the receiver a file. With a recovery witness (`ReceiverOptions.witness`, a file outside the store's directory tree), a restore of that file from an older backup, or its replacement by an empty one, is detected when the receiver opens, and every Mission is held until a fresh Mission Status read resynchronizes it (#1749). A witnessed store opens only with its witness, and a witness admits one writer (D910) |

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
(the provider access-token hook has no acceptance boundary), which remains
open. Without a recovery witness the kernel's file takes no lock; with one it
is held exclusively ([Restore admission](#restore-admission)). The file carries
no schema version.

Rollback resistance is partial. A restart on the file-backed store keeps the
state version and the terminal tombstone, so no lower version is served after
recovery. With a recovery witness, a restored older store is refused and
state-dependent service is refused while the durable version is uncertain
([Restore admission](#restore-admission)), for one writer on one host.
Multi-process serialization and claiming remain under #641's explicit
deployment trigger.

## Restore admission

With a recovery witness (#250 step 3; `KernelOptions.recoveryWitness`, or
`kernelStore: { file, witness }`, or `MISSION_KERNEL_WITNESS` for the shipped
launchers), the file-backed kernel answers Control Plane's rollback resistance for
one writer on one host.

- **The witness.** A small file at an absolute path outside the store's directory
  tree, with the store outside the witness's (both compared canonically), so
  restoring either tree cannot restore the other with it. It holds the store's
  identity, the writer generation, the last committed recovery sequence, the
  sequence of a commit in flight, and any uncertainty a run recorded. The store
  holds the matching `recovery_marker` row. `pnpm kernel-recovery init --store
  <path> --witness <path>` creates both, once, for a new store or one that
  predates the witness; nothing initializes them automatically.
- **One writer, one witness.** The kernel holds its store with an exclusive lock,
  and the witness's own lock (`<witness>.lock`, a SQLite handle the operating
  system releases with the process), taken before the witness is read. A second
  kernel, on the same store or on a copy of it, and an offline reconciliation are
  refused while one holds either.
- **Every write is witnessed.** Each outermost write transaction on the kernel
  database reads the witness back (it must be the record this writer last wrote),
  writes the intent durably before its commit, advances the marker inside it, and
  finalizes the witness after it, before any lifecycle publication. Every
  statement that can write runs inside such a transaction: `run`, `get`, `all`
  and `iterate` on a statement that is not read-only, the same through a chained
  builder, and `exec`.
- **A closed boot.** The kernel opens only when the store's marker matches the
  witness exactly, with nothing recorded. A store older than the witness (a
  restored backup), a lost, unreadable or foreign witness, a store ahead of its
  witness, a commit left in flight, a recorded uncertainty, and a witnessed store
  opened without its witness all refuse, and the AS does not start: `pnpm
  as-native`, for one, exits 1 with the refusal as its startup-failure line.
- **Offline reconciliation.** With the AS stopped, `pnpm kernel-recovery
  acknowledge` records a commit the store holds, `abandon` clears one it does
  not, and `accept` takes the store as it is, under a new generation, once a run
  recorded an uncertainty (an escaped write, a witness that moved) with no commit
  in flight. Each refuses when the store says otherwise. Nothing lowers the
  witness: an older store is refused until the witnessed one is restored.
- **Uncertain while running.** A witness write that fails, a commit that fails
  after its intent, a witness that changed underneath the writer, or a write that
  bypassed the guard leaves the kernel uncertain: every later write refuses, the
  uncertainty is recorded in the witness where it can be written (a pending
  intent is the trace when it cannot), and the AS answers every request but
  discovery metadata and the key set with 503 `temporarily_unavailable`, a
  request already in flight included: the release fence checks again after
  every await. A commit whose witness could not be finalized publishes nothing;
  boot recovery publishes it after `acknowledge`. The demo stack's and the
  in-process MAS pilot's PEP, RS and PDP load Missions through
  `kernelMissionView`, which loads none while the kernel is uncertain, so their
  decisions refuse too. Other in-process readers that only display state (the
  console BFF's fleet view, the agent console, the catalog) are not gated.

### Transaction inventory

Every table in the kernel database, the module that writes it, and how its
writes are witnessed. "Managed" is a `withTransaction` (or an `...InCallerTx`
step inside one); "statement" is a bare statement the guard runs as a
one-statement transaction; "boot" writes run at construction or `recoverAtBoot`.
`recovery-witness-as.test.ts` fails when the database holds a table this list
does not name. A write the list misses is still caught by the guard's backstop,
a check at the next guarded transaction, after that write committed.

| Table | Module | Writes |
|---|---|---|
| `missions` | `kernel.ts` | managed (insert, transitions, containment, discharge latch, schedule, status-list slot, supersession, carryover's version check); statement (`bindGrant`, `bindFirstGrant`, the derivation count and its refund) |
| `approval_reservations` | `kernel.ts` | statement (`reserveApproval`) |
| `authority_source_bindings` | `source-binding-store.ts` | managed (with the Mission insert; boot reconciliation) |
| `continuation_anchors`, `continuation_handles` | `continuation-store.ts` | managed (rooting, termination); statement (a continuation hop's `mint`) |
| `delegation_families` | `delegation-family-store.ts` | managed (termination); statement (`record`, `invalidate`) |
| `mission_tombstones` | `tombstones.ts` | managed (with the terminal transition); boot (detail pruning) |
| `lifecycle_events`, `lifecycle_deliveries` | `lifecycle-outbox.ts` | managed (enqueue with the transition); statement (delivery outcomes, after the commit); boot (pruning, migration) |
| `lifecycle_responses`, `discharge_events` | `lifecycle-idempotency.ts` | managed (claims, discharge records); statement (`record`, expiry purges) |
| `derivation_reservations` | `derivation-reservations.ts` | managed (reserve, release, reconcile); boot (`recoverAtBoot`) |
| `activation_policy_snapshots` | `activation-policy-snapshots.ts` | managed (upsert); boot (pruning) |
| `join_assertion_events` | `join-evidence-store.ts` | statement (`record`); boot (pruning) |
| `discharge_mapping_pins` | `discharge-pin-store.ts` | managed (with the Mission insert) |
| `discharge_selectors` | `discharge-selector-store.ts` | managed (`selectorFor`) |
| `approval_governance_records` | `approval-governance.ts` | managed |
| `direct_approval_rules`, `direct_approval_inputs` | `direct-approval-record.ts` | managed |
| `drawdown_recording_rules`, `drawdown_record_inputs` | `drawdown-approval-record.ts` | managed |
| `template_recording_rules`, `template_record_inputs` | `template-approval-record.ts` | managed (with the standing-payment instance insert) |
| `standing_payment_budget_bindings` | `standing-payment.ts` | managed (`bindBudget`, at template consent) |
| `standing_payment_admissions`, `standing_payment_dispatches` | `standing-payment.ts` | managed (with the standing-payment instance insert) |
| `governed_policy_roots`, `governed_policy_consents`, `governed_policy_activations` | `governed-policy-approval.ts` | managed (consent, activation); statement (`withdraw`) |
| `creation_idempotency` | `creation-idempotency.ts` | managed (reserve, complete, advance); statement (`failReserved`, `completeDelivered`, `recordDelivery`, expiry purge) |
| `expansion_deferrals`, `progressive_refusals` | `deferred.ts` (`ExpansionDeferralStore`) | managed (redemption); statement (open, approve, deny, cancel, polls, refusals) |
| `carryover_reservations`, `carryover_results`, `carryover_replacements` | `carryover.ts` | managed (reserve, consume, retain); statement (`cancel`) |
| `mission_approval_deferrals` | `mission-approval-deferral.ts` | managed (open, completion, direct approval); statement (resolve, cancel, polls, delivery claims) |
| `mission_deferred_authorization_codes` | `adapters/deferred-mission-approval.ts` | managed (`openOnce`); statement (`stage`) |
| `recovery_marker` | `recovery-witness.ts` | managed (every guarded transaction; reconciliation) |
| `kernel_issuer` | `kernel.ts` | boot (a store with no record records the issuer its state allows: an empty store's opener, or the one issuer a populated store names; on a witnessed store that write is a guarded transaction, advancing the marker and the witness once) |

Not supported: a way back from an older store by invalidating its authority under
a new generation (deferred, D820), more than one writer, and more than one host
(#641).

## Deployment declaration

Control Plane's Deployment Declaration for the reference deployment, one item
per heading. The reference does not claim Mission Control-Plane Consistency: a
claiming deployment satisfies every applicable requirement for the roles it
runs, and the rows under [Residual risks](#residual-risks) are not yet
satisfied. Each item states demonstrated behavior and points to the section
that details it.

### Serialization domains

One issuer's kernel database, with one writer in one process, serializes every
Mission of that issuer. Each of these commits as one transaction or not at all:

- a lifecycle transition, its state version and its durable lifecycle event and
  delivery rows, and on a terminal transition the tombstone and the termination
  of the Mission's continuation lineages and delegation families;
- a containment, as a metadata-only commit at a new version;
- a Child Mission and its parent's fan-out accounting;
- an expansion's successor activation and the predecessor's supersession, and
  with carryover every replacement, the cascade of the old subtree and the final
  map ([Carryover compositions](#carryover-compositions));
- a counted derivation and its reservation;
- a lifecycle nonce claim and its committed outcome, and a creation idempotency
  claim and its Mission.

Outside any one transaction: the provider access-token hook's count and the
token it pays for (#935), and the provider's Grants and refresh tokens, which
oidc-provider keeps in memory ([Restart inventory](#restart-inventory)).

### Authoritative observation mechanism

The kernel database is the only copy of Mission state, so every read of it is
authoritative. A signed Mission Status observation is one transactional read of
the record, with the expiry clock materialized in that read, and it carries its
`(version, commit)` watermark. Its `iat`, `exp` and `fresh_until` belong to that
read and are never restamped; its freshness is 60 seconds, within
`mission_max_stale_seconds` (300). Introspection reads the same record, the
Mission Status List is rebuilt from the record set, and the Signals event is
the committed lifecycle event, published after its commit. These four are the
deployment's whole set of state-observation surfaces: it defines no parallel
signed state-snapshot protocol (a deployment-inventory conclusion, D874). The
Signals surface's signed artifact, the SET, is a transition record dated by its
`committed_at`, not a signed state observation (D993); the signed-artifact
inventory under
[Control-plane implementation boundary](#control-plane-implementation-boundary)
classifies every signed artifact. Refusing an observation whose commit point
advanced is an optional policy (`strictObservationWatermark`), off. There is no
lease and no replica read.

### Replication and recovery model

- **Replication:** none. The Enforcement Scope Statement declares
  `replication: "none"`, and the PEP and PDP refuse another value at load.
- **Topology:** one writer on one host. With a recovery witness, a second
  kernel on the same store, or on a copy of it, is refused while one runs. More
  than one writer or host is not supported (#641).
- **Recovery:** a restart on the file-backed kernel with its recovery witness
  ([Restore admission](#restore-admission)). The [Restart
  inventory](#restart-inventory) lists what survives a restart and what is
  deliberately invalidated. The in-memory default keeps nothing.
- **Admission:** boot is closed. A store that does not match its witness exactly
  does not open, and the AS does not start. A running kernel that loses
  certainty refuses every write, and the AS answers 503
  `temporarily_unavailable` to every request but discovery metadata and the key
  set. Reconciliation is offline (`pnpm kernel-recovery`) and never lowers the
  witness. Taking an older store by invalidating its authority under a new
  generation is not offered (D820).
- **Partitions:** with no replica there is no partitioned copy to read. An
  operation that cannot establish current state, because the kernel is
  uncertain, is refused rather than served from what the process last knew.

### Recovery objectives

- **Recovery point:** two cases, kept apart.
  - *Crash:* on the witnessed file-backed kernel, under the declared storage
    assumptions (the store opened with `synchronous=FULL`, on storage that
    honors its flushes), a committed transaction survives a crash. The witness
    records an intent before every commit, so a crash between the intent and
    its finalization leaves a pending intent that refuses the restart until
    `acknowledge` records the commit the store holds or `abandon` clears one it
    does not.
  - *Backup or media loss:* no zero-loss guarantee is made. The witness detects
    a store restored from an older backup and refuses it, but it cannot
    reconstruct the transactions the backup lacks; the way back is restoring
    the witnessed store.
  - On the in-memory default a restart loses the whole store. The provider's
    Grants, refresh tokens, sessions and interactions have no recovery point: a
    restart loses them.
- **Recovery time:** no bound is declared. A restart on a matching store and
  witness serves once boot recovery has published unpublished commits and
  drained the outbox. A restored older store, a lost witness, a commit in flight
  or a recorded uncertainty waits for an operator's offline reconciliation, and
  the AS does not start until then.
- The Enforcement Scope Statement's per-class `recovery_objective_seconds` (60)
  belongs to the runtime state source. It extends no staleness bound: stale
  state is refused even when recovery takes longer.

### Tenant isolation

Each kernel database belongs to one issuer, recorded in the database: it
refuses an open under another issuer and another issuer's record, and a store
written before the record binds only to the one issuer its state names
([Upgrading a kernel written before #1748](#upgrading-a-kernel-written-before-1748)).
Every mutable seam is keyed on the canonical issuer and Mission identity, owned
by one issuer's store, or under a declared separation (the namespace inventory
under
[Control-plane implementation boundary](#control-plane-implementation-boundary)).
The declared separations are one AS per process, for the provider's memory
adapter and the device decisions in progress, and one Mission issuer per PEP
composition for each persistent store's whole lifetime, for its operation keys
and Execution Evidence sequences. A standing consent's shared counter keys on
the budget's accounting domain (owner and budget id), not on the issuer, and
is charged only through the trusted budget source and the declared policy
references. A Lifecycle client's grant can be scoped to a tenant's Subjects, or
to Subjects and requesting clients, and any other Mission answers that client
as unknown.
Shared services bind each operation to its issuer: the PDP's idempotency
claims, Decision Evidence sequences and Mission budget counters, the Signals
receiver and outbox, and the RAS's redemptions key on the issuer, and each AS
signs with its own keys.

### Emergency narrowing and emergency authority

- **Narrowing:** `suspend`, `revoke` and `contain` on the Lifecycle endpoint (a
  client authenticated with the lifecycle grant, a nonce retry key, the optional
  `expected_version`), and containment from a protected event: a JWS from a
  source the trusted-source registry trusts for that event type, applied through
  the issuer's own ContainmentPolicy, so the caller supplies only the event. A
  containment commits the narrower effective set at a new state version and
  containment version, with the event's source and the policy rule in its
  Containment Evidence. It moves no state, expiry or derivation limit, and its
  answer carries no observation. It has no expiry: authority it removed returns
  only through a new approval, an expansion successor, which is another Mission
  and not a reconciliation of this one. The AS keeps no deny cache.
- **Positive emergency authority:** absent. The Enforcement Scope Statement
  declares `break_glass: "absent"`, and the PEP does not start under a statement
  declaring another mode.

### Residual risks

The control-plane ledger rows not yet `tested`, which are why the reference
makes no claim:

- `control-plane.consistency.serialization`: a counted derivation and the
  provider token it pays for are not one transaction (#935); no multi-process
  serialization (#641).
- `control-plane.consistency.state-surfaces`: the surfaces are read in the
  kernel, not over HTTP; the absence of a parallel snapshot protocol is a
  documented inventory conclusion (D874).
- `control-plane.consistency.state-surfaces-consumer`: the Signals receiver
  anchors freshness to each observation, the issuer's time plus
  `mission_max_stale_seconds`, a stricter stand-in for stream liveness, which
  it does not read (#1747).
- `control-plane.consistency.rollback`: one writer on one host only, and no way
  back from an older store but restoring the witnessed one (D820).
- `control-plane.consistency.rollback-retaining-consumer`: a restore of the
  Signals receiver's store is detected, and each Mission held until Mission
  Status resynchronizes it, only for a receiver configured with its recovery
  witness, which is optional (#1749, D898).
- `control-plane.consistency.partitions`: the refusal is witnessed in the
  single-writer topology; the multi-node cases cannot be constructed here, an
  accepted declared limitation (D874).
- `control-plane.consistency.emergency-deny`: the deny-entry clauses have no
  subject, since the AS keeps no deny cache, an accepted declared limitation
  (D874).
- `control-plane.consistency.emergency-authority`: the refusal of positive
  emergency configuration is witnessed; excluding actions that rely on it has no
  subject, an accepted declared limitation (D874).
- `control-plane.consistency.isolation`: one AS per process is declared, not
  enforced: the provider's memory adapter and the device decisions in progress
  are process-global.
- `control-plane.consistency.isolation-retaining-consumer`: the Signals
  receiver's seen jti values are issuer-keyed but not witnessed across issuers.
- `control-plane.consistency.isolation-retaining-consumer-pdp`: the Decision
  Evidence key's binding to the qualified identity is stated, not witnessed
  across issuers.
- `control-plane.consistency.isolation-retaining-consumer-pep`: one Mission
  issuer per PEP composition is declared, not enforced, for each persistent
  store's whole lifetime: the operation keys and Execution Evidence sequences
  key on the bare Mission identifier.
- `control-plane.consistency.claim`: the reference makes no claim.

Outside those rows: the provider's Grants and refresh tokens do not survive a
restart; the delegation accounting and the Dispatch Handoff consumption records
are invalidated by one; an ambiguous delivery after a crash stays counted
(#935); and the #914 refresh pre-check window is an accepted single-process
residual (D772). On the file-backed kernel, a crash after the approval commit
leaves the Mission `active` until `expires_at` or a revocation, and its
authorization code is lost with provider memory: the same end state as the
delivery gap (#1863, D1001).

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

## Upgrading a kernel written before #1748

A kernel database written before #1748 has no `kernel_issuer` record. Its
first open under a later build records one only as the store's own state
allows:

- A store with no state, empty or opened but never written, is bound to the
  issuer that opens it.
- A populated store is bound only to the one issuer its state names: every
  `issuer` column and the `deployment` of its authority source bindings.
  Opened under that issuer, it is recorded and serves as before.
- State naming another issuer, several issuers or none refuses the open with
  `KernelIssuerMismatchError` and leaves the store unchanged, with no record
  written; on a witnessed store the witness does not advance.

A store refused for naming another issuer opens under that issuer. No offline
action records an owner for a store whose state names several issuers or none,
so such a store stays refused.
