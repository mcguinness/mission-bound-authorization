# AAuth three-party route

The reference AAuth Person Server and Resource for issue #836 slices 2 and
3 (D303), with the test kit's agent and management client. Slice 2 builds
the three-party route; slice 3 adds the PS's mission control plane (AAuth
Mission Management: `status` and `terminate`), local gating, revocation
of issued tokens at the Resource, and restart recovery. This note records
what the slices build and which paths their tests demonstrate. It makes no
conformance or interoperability claim: the results below name
demonstrated paths only, between components of this repository, on
loopback.

## Pins

- AAuth: `draft-hardt-oauth-aauth-protocol-11` (2026-09-25).
- Signature-Key: `draft-hardt-httpbis-signature-key-09` (2026-09-13).
- The AAuth binding: `draft-mcguinness-mission-aauth.md` at `59720df0`, as
  `conformance-manifest.json` pins it in `source.specs`.
- AAuth Mission Management: `draft-mcguinness-mission-aauth-management.md`
  at `940972b9`, pinned the same way.
- RFC 9421, Signature-Key, key discovery and token verification come from
  `@mission/aauth-wire` (slice 1) at the same pins; nothing here
  re-implements them. `src/SPEC_VERSIONS.md` maps each pin to code and tests.

## Components

| Package | Path | Configuration |
|---|---|---|
| `@mission/aauth-ps` | `src/services/aauth-ps` | `src/config/aauth-ps.json` (its `management` member is the control plane's policy) |
| `@mission/aauth-resource` | `src/services/aauth-resource` | `src/config/aauth-resource.json` (its `revocation_limits` bound each PS at the revocation endpoint) |
| `@mission/aauth-testkit` (test only) | `src/packages/aauth-testkit` | none: the agent-provider stub, the agent client, the management client, the endpoint switch and the loopback network |

## Governance mode

Deterministic, from static configuration; no model and no person in the
loop. `agents` in `aauth-ps.json` is both the agent allowlist and the
agent-person binding, and `mission_governed` places an agent under mission
governance. A proposal is decided at once: the first `description_rules`
entry whose text the description contains (case-insensitive) decides,
else `default_decision`. The shipped file governs `aauth:assistant@ap.test`
and `aauth:planner@ap.test` (alice) and admits `aauth:helper@ap.test` (bob)
missionless.

## Access mode covered

Three-party access with PS-issued auth tokens: agent, PS and Resource,
with no access server. The Resource accepts an auth token only when its
`iss` equals its `ps`. Termination covers this mode only: agent identity
access and resource-managed access (an opaque `AAuth-Access` token) are
not built, and termination claims nothing about them.

## Endpoints

| Party | Endpoint | Behavior |
|---|---|---|
| PS | `GET /.well-known/aauth-person.json`, `GET /.well-known/jwks.json` | metadata and JWKS, `cache-control: max-age=300`; the metadata names `mission_control_endpoint` and `mission_control_actions_supported` `["status", "terminate"]` when the control plane is served |
| PS | `POST /mission` (`mission_endpoint`) | propose and decide; an approval returns `s256`, the exact blob bytes as `mission`, and a person token per proposed resource; the agent client accepts it only when the blob's `agent` is its own identifier |
| PS | `GET /mission/{mission_s256}` | the owner's read of the persisted bytes; a local surface (AAuth defines only POST at this URL, which answers 405 here) |
| PS | `POST /person` (`person_token_endpoint`) | person tokens, with or without `mission_s256` |
| PS | `POST /token` (`auth_token_endpoint`) | Section 6.7.2 steps 1 to 4, then a direct auth token; a resource token carrying `interaction` is refused |
| PS | `POST /mission-control/{mission_s256}` (`mission_control_endpoint`) | the control plane: `status` and `terminate` for the owning agent and configured administrators; any other method is 405, the bare URL 404 |
| Resource | `GET /.well-known/aauth-resource.json`, `GET /.well-known/jwks.json` | metadata (with `revocation_endpoint`) and JWKS |
| Resource | `POST /authorize` (`authorization_endpoint`) | a resource token for a person token and a defined scope |
| Resource | `POST /revoke` (`revocation_endpoint`) | AAuth -11 Section 11.12: a PS revokes `{jti, exp}` of a token it issued |
| Resource | `GET /api/documents`, `POST /api/documents` | protected operations (`documents.read`, `documents.write`), challenged with `AAuth-Requirement` |

Every PS answer except the metadata and JWKS carries `cache-control:
no-store`.

## The mission control plane

**Callers.** Two caller classes are built; the Person and the management
service are not.

- **The owning agent**, when `management.admit_owning_agent` is true:
  it signs with its agent token under Signature-Key `jwt`, as at the other
  PS endpoints. It must be a top-level agent (no `parent_agent`) on the
  allowlist, and the `sub` of its agent token must be the mission blob's
  `agent`. It may read `status` and terminate with `revoked` only.
- **Configured administrators** (`management.administrators`): each is an
  `id`, a deployment-chosen metadata document name (`dwk`) and an enrolled
  public key with its `kid`. An administrator signs under Signature-Key
  `jwks_uri` with that `id`, `dwk` and `kid`; the PS takes the key from its
  configuration and never fetches it, and refuses an AAuth document name as
  an administrator's `dwk`. Each administrator is scoped by persons (their
  agents' missions) and by actions. It may terminate with `revoked`,
  `superseded` (with `replacement_s256`, another mission in its scope) or
  `administrative`, and must give a `purpose`. The shipped administrator
  (`https://admin.ps.test`, `mission-admin.json`) is enrolled under a key
  no one in this repository holds; a deployment enrolls its own. The
  pinned key is the whole of an administrator's authentication: it does
  not satisfy the companion's step-up authentication or dual control for
  high-blast-radius automation, which is not built.

**Check order.** Every request is a signed JSON POST covering
Content-Digest and Content-Type. The PS checks the signature (401 with
Signature-Error), then the path segment, Content-Type, strict JSON (no
duplicate members, nesting at most 32), a body without `mission_s256`, and
`action` (`invalid_request`), then the terminate members, which depend
only on the caller's class (`invalid_request`, `invalid_termination_reason`),
then one lookup keyed by the caller's authorization and `s256` together.
An absent mission and one outside the caller's authorization are both
`mission_not_found` (404), with the same body bytes and headers, within
each caller class (P2). Each miss goes to the security-event list under a
keyed digest, never the reference. The action then runs under one
transaction.

**The same-second limitation.** The control plane keeps the library's
default replay key, (signing-key thumbprint, `created`, method, authority,
path), so two requests from the same caller to the same mission URL signed
in the same second collide: the second is 401 `invalid_signature`
("duplicate signed request"), even when its body differs. A caller spaces
its requests to one mission URL into distinct seconds, as the testkit's
management client does. Widening the key is a separate decision.

**`status`** applies expiry first, then answers `mission_s256`,
`mission_status`, `approved_at`, `expires_at`, `observed_at`, `fresh_until`
(`observed_at` plus `status_fresh_seconds`, 30) and `accepted_updates` (0:
this PS accepts no update), and for a terminated mission `terminated_at`,
`termination_reason` and `token_residual`. The blob is never returned.
Each read is logged.

**`terminate`** applies expiry, then looks up a retained outcome under
(caller, `request_id`): an equivalent request (the same body as canonical
JSON, to the same mission) is a replay, answered with the retained receipt
and a fresh observation, logging `terminate_replayed`; a different one is
409 `idempotency_conflict`. Otherwise the one active-to-terminated
transition is a conditional update: of concurrent requests exactly one
transitions, and a later request receives the first committed outcome,
logged `termination_request_after_terminal`. The transition's log entry
carries the actor, role, decision, policy, `request_id`, reason, purpose,
replacement and token impact. In the same transaction the PS records
revocation work for every unexpired Tracked Credential and the request's
receipt. Receipts are durable and never purged. Revocation starts after the
commit, and the answer waits at most `immediate_wait_ms` (2000) for it.

**Local gating.** From the commit on, the person token endpoint, the auth
token endpoint (a resource token or presented token carrying the
reference) and the owner's read refuse the mission with
`mission_terminated`. Slice 2's issuance commit applies unchanged: a
request in flight when termination commits reads the terminated state at
its mission gate and issues nothing. A token is recorded before it is
minted, and signing awaits, so the mission is read again after signing,
immediately before the response, with no await between that check and the
send: at the person token endpoint, the auth token endpoint and an
approval that returns person tokens, a mission that terminated or reached
`expires_at` while the token was signed is refused `mission_terminated`
and no token is released. The token's record stays, so it remains a
Tracked Credential and the termination's revocation covers it.

## Revocation and residuals

**The PS's attempts.** After termination the PS revokes each unexpired
Person Token and Auth Token it issued under the mission at the Resource
in the token's `aud`; there is no AS in this route, so no Person Token is
presented to one. For each attempt it reads `{aud}/.well-known/aauth-resource.json`
(whose `issuer` must be `aud`) for an https `revocation_endpoint`, then
POSTs `{jti, exp}` with `exp` from its own record, signed under
Signature-Key `jwks_uri` with its issuer as `id`, `aauth-person.json` as
`dwk` and its signing key's `kid`, covering Content-Digest and
Content-Type. Each attempt is counted, recorded and logged before it is
sent, its result after, with the token named by (`iss`, `jti`); the
attempt budget is checked before anything is counted or sent. Requests to
one endpoint go one at a time, in distinct seconds. Discovery and that
wait take time, so the clock is read again immediately before signing: a
credential at or past its `exp` is not sent and is recorded `expired`, and
an attempt whose time limit already ended sends nothing.

| Outcome | State | Next |
|---|---|---|
| `200`, empty or a JSON object | confirmed | none |
| `403 unsupported_iss`; no `revocation_endpoint` | unsupported | none; honored by the Resource until `exp` |
| `400` | rejected | none |
| `429` | pending | after Retry-After |
| `401`, `5xx`, `202`, a malformed `200`, a dropped or refused connection, a timeout | pending | backoff |
| the credential reached its `exp` before the request was sent | expired | none; no longer needed |
| the attempts already reached the bound when the attempt came due (the last one was cut short) | exhausted | none; unconfirmed until `exp` |

The shipped retry policy (`management.revocation`): at most 6 attempts,
spaced 30 seconds and doubling to a 900-second cap, each attempt limited
to 5000 ms, and none sent at or after the token's `exp`. A `202` is not
polled.

**Two same-second protections.** AAuth's optional replay key has no
request body in it, so two revocations at one endpoint signed in the same
second would collide. The PS spaces its revocations to one endpoint into
distinct seconds, which protects it at any recipient that keeps the base
key; the Resource also keys its revocation replay cache on the covered
Content-Digest, which protects it against any PS that does not space. Each
alone keeps two revocations of different tokens apart (the integration
tests fail only with both removed); both are kept, since neither side can
assume the other.

**The Resource's endpoint.** `POST /revoke` accepts only a request signed
under `jwks_uri` covering Content-Digest and Content-Type, from a signer
whose `dwk` is `aauth-person.json`; any other signer is 403
`unsupported_iss`. The issuer is the verified signer, never a request
member. Each issuer is bounded at 600 requests a minute and 10000
unexpired entries (`rate_limited` with Retry-After). `{jti, exp}` is
committed to the revoked set before the answer, `200` with no body; a
repeat records nothing new. A revoked person token presented afterwards is
401 with `Signature-Error: error=revoked_jwt`; a revoked auth token also
carries `AAuth-Requirement: requirement=person-token`. No resource token is
issued naming a revoked token.

**Residuals.** `token_residual` counts Tracked Credentials, a Person Token
as an Auth Token: `tracked`, `revocation_attempted` (credentials with at
least one recorded attempt), `revocation_confirmed`, `complete`, and
`residual_until`, the latest `exp` among unexpired unconfirmed credentials,
omitted when there is none. `complete` is false while any credential is
live and unconfirmed, so an outstanding Person Token keeps it false
whatever the Auth Tokens did (D299), and it is never true when
`management.untracked_access` says an untracked access mode may serve the
mission. Natural expiry closes a credential's residual.

**The worst-case residual under partition.** The PS's own gating takes
effect at the commit, whatever the network. A Resource the PS cannot reach
honors a token it already accepted until that token's `exp`: at most one
hour after issuance, the shipped person and auth token lifetimes (AAuth's
ceiling), and never past the mission's `expires_at`. A resource token
lives 300 seconds and is redeemable only at the PS, which refuses it.

## Restart

- **PS.** Missions, the issued-token records, the mission log, terminate
  receipts and revocation work are in SQLite. A restarted PS on the same
  file keeps every terminal state and reason, refuses the mission at every
  issuance path, replays a retained receipt, and, when it listens, runs the
  revocation work that is due and then runs it on its poll interval, so an
  attempt interrupted by the restart is retried, unless it was the last
  the budget allows: its outcome is unknown, so the credential is
  exhausted, unconfirmed until its `exp`, and nothing more is sent. The PS
  generates its signing key at boot unless one is given; the integration
  tests restart it with the same key, and a restart with a new key is not
  exercised.
- **Resource.** A restarted Resource on the same file keeps its revoked set
  and refuses each revoked token until its `exp`.

## State

| Party | State | Durability |
|---|---|---|
| PS | missions with their exact blob bytes, issued-token records (`iss`, `jti`, kind, `aud`, `exp`, `sub`, agent and `mission_s256`), the mission log, the pairwise-`sub` key, terminate receipts, revocation work (recipient, endpoint once discovered, state, attempts, next attempt, last outcome) | durable SQLite through `@mission/store`'s `openDurableStore`, at a file the caller names |
| PS | the replay cache, the security-event list (bounded at 1000), the probe-digest key, the signing key | in memory |
| Resource | the revoked set, (`iss`, `jti`) until each `exp` | durable SQLite (`SqliteRevocationStore`, one writer), at a file the caller names |
| Resource | the effect log, person records, issued resource tokens, the replay cache, the per-issuer revocation rate, the operations' data, the signing key | in memory |

## Issuance commit

Key resolution and token verification await, and time passes while they
do. Each issuance therefore reads the clock again and checks, with no
await before its record is written:

- at the auth token endpoint, after step 4: the resource token's `exp`
  (`expired_resource_token`), the presented token's `exp`
  (`expired_presented_token`), the mission's state and `expires_at`
  (`mission_terminated`), and the issued token's `exp` cap;
- at the person token endpoint (the mission gate and the `exp` cap) and the
  approval (the requested `expires_at` and each person token's `exp` cap),
  which read the time after authentication.

The record is written first and the token is minted after, from claims
already fixed, so no token is issued already expired; after the token is
minted, the mission is read again immediately before release (Local
gating). When the cap fails because the agent token that authenticated the
request expired meanwhile, the answer is 401 with `Signature-Error:
error=expired_jwt`, as for any failure of the Signature-Key token. Tests
drive these paths by advancing the clock while a key is resolved or a
token is signed, and terminate a mission at those points.

## Exclusions

- No access server: four-party access, V6 and V15 are out, and so are AS
  recipients of revocation.
- No call chaining (V13): `upstream_token` is refused `invalid_request`.
- No sub-agents: a sub-agent calling the PS directly is refused, and one
  calling the control plane is `mission_not_found`.
- No 202 deferral and no interaction: the approver decides at once, the
  agent client reports a 202 as unsupported, and the PS refuses a resource
  token carrying `interaction` (AAuth -11 Section 7.2.3) with 403
  `user_unreachable`, issuing and recording nothing.
- No mission `update` or `completion`, and no delegation tree.
- No launcher.

## Named gaps against the management companion

Obligations of AAuth Mission Management that slice 3 does not build. Each
is a `todo` or `partial` ledger row.

- The Person path and the management-service path (Sections Person and
  Management Service), so no completion and no Person-initiated
  termination.
- `delegation_tree`.
- Rate limiting: repeated control-plane failures and administrative
  credentials are not rate limited, and the control plane never answers
  `rate_limited`.
- P2 timing: the single authorization-keyed lookup avoids the lookup-then-
  check arrangement, but timing is not measured.
- The mission log carries no PS-local sequence value in an event.
- The security log is the in-memory, bounded security-event list, and it
  does not capture an administrative request refused at authentication.
- Step-up authentication or dual control for administrators (a SHOULD).
- Polling a `202` revocation answer.
- Local gating at `{mission_endpoint}/{mission_s256}` for `update` and
  `completion`: the PS answers 405 there for any mission.
- A default production outbound transport: the PS takes its transport for
  metadata fetches and revocations from its caller; the tests use the
  loopback network.
- Publishing the deployment documentation the companion requires
  (Sections Honest Residual Bounds and Conformance). This note states the
  covered access mode, the token lifetimes, Resource revocation, the retry
  policy and the worst-case residual, but it is not a conformance claim.

## Test topology

- Identifiers carry no port: `https://ap.test`, `https://ps.test`,
  `https://resource.test`.
- Each party is real HTTP on an ephemeral port of 127.0.0.1. An
  `https://host/path` URL travels as plain HTTP to that port, with `Host`
  the identifier's host. There is no TLS.
- The agent signs `@method`, `@authority`, `@path` and `signature-key`, plus
  `content-digest` and `content-type` on a body; `@target-uri` is not
  covered. Each verifier builds the signature base from its own identifier
  and the raw request target, never from the Host field.
- Key discovery uses the library's egress admission and pinned fetch,
  admitting only the hosts the test registers. One clock drives every party.
- The PS's control plane gets the same durable store, the loopback network
  as its outbound transport, and the shared clock's sleep. Revocation work
  runs when a termination commits and when a test asks; the restart test
  restarts the PS with a 20 ms poll interval.
- The integration world enrolls two administrators of its own under the
  shipped policy: `https://admin.ps.test` (alice's missions) and
  `https://admin-bob.ps.test` (bob's). Each caller has one management
  client on the shared clock.
- The Resource's revocation endpoint sits behind the testkit's
  `EndpointSwitch` (a 5xx, a dropped connection or a malformed 200), and
  `LoopbackNetwork.refuse` refuses the whole Resource host.

## Demonstrated paths

`src/services/aauth-resource/test/integration/three-party.test.ts` runs the
vectors of `notes/aauth-propagation-vectors.md` through the real agent
client, the PS on a temporary SQLite file, and the Resource, all on the
shipped configuration. Every negative vector asserts its exact refusal,
unchanged PS records (issued tokens and mission logs), no token in the
response, and an unchanged effect log.

| Vector | Demonstrated |
|---|---|
| V1 | `mission_s256` exact from approval through the person token, resource token and auth token to the run; each token recorded under the mission; the agent's bytes equal the persisted blob |
| V2, V3 | a stripped or substituted resource-token reference: refused by the agent, and by the PS (`invalid_resource_token`) when the agent skips its check; V3 is surfaced to operators |
| V4 | another person token forwarded: `invalid_resource_token` |
| V5 | an honest step-up carries the mission; a stripped step-up is refused by the agent and by the PS |
| V7, V8 | malformed, unknown and foreign references at the person token endpoint: `invalid_request` |
| V9 | a governed agent's missionless request: `denied` at the person token endpoint, and at both endpoints after a restart that places a missionless agent under governance |
| V10 | a mission terminated after issuance: `mission_terminated` at both endpoints |
| V11 | a person token capped at `expires_at`, presented after it: `expired_presented_token` |
| V12 | mission state unreadable: `server_error` at both endpoints |
| V14 | missionless access by policy; the same agent's failing reference is refused, not served missionless |
| P1 | identical status, body bytes and headers (`Date` aside) for an absent and another agent's mission, active or terminated, at the person token endpoint, `GET /mission/{mission_s256}` and the auth token endpoint's mission check |

The P1 probe at the auth token endpoint re-signs the agent's real person
token with the PS's key, changing only `mission_s256`, because no honest PS
issues one naming a mission the agent does not own. P1 timing is not
measured. A further test shows the PS refuses a resource token naming
another PS in `ps` before reading any mission state.

`src/services/aauth-resource/test/integration/termination.test.ts` runs
slice 3 through the same parties, with callers on the testkit's management
client. Every refusal asserts its exact status and code, unchanged PS
records, and no effect.

| Path | Demonstrated |
|---|---|
| Termination with live tokens | the owning agent terminates; the answer is the full status representation; the PS revokes the person token and the auth token at the Resource, which holds each `{jti, exp}` under the PS until its `exp` and then refuses them (`revoked_jwt`, the auth token with `requirement=person-token`); the agent's next request is refused at the PS (`mission_terminated`); `status` reports the reason and a `complete` residual |
| Expiry | past `expires_at`, the agent's request commits the transition at the `expires_at` instant, attributed to the PS scheduler, and is refused `mission_terminated`; `status` reports it |
| Unavailable revocation | while the endpoint answers 5xx, drops the connection or answers a malformed 200, or the host refuses connections, nothing is confirmed, `complete` stays false and `residual_until` is the latest unconfirmed `exp`, a person token's; the Resource still honors the unrevoked person token while the PS refuses the mission; once reachable, the retry confirms what is unexpired |
| No revocation endpoint (D299) | a person token for a Resource that advertises none keeps `complete` false until its `exp` though every other token is confirmed; `status` still reports the termination afterwards |
| Restart mid-revocation | terminated while the endpoint is down; a PS restarted on the same file keeps terminal state, gating and receipts; its own loop revokes both tokens once the endpoint returns; a restarted Resource keeps its revoked set; past every token's `exp`, `status` still reports the termination |
| Local gating | after the commit, and for a person token or auth token request in flight when it lands: `mission_terminated`, nothing issued; the administrator's request is logged with its principal, role, decision, policy and purpose |
| P2 | a non-owner agent (alice's other agent, and bob's) and an administrator outside the mission's scope get the absent mission's answer, byte for byte, for `status` and `terminate` on an active and a terminated mission |
| Authentication | an unsigned request and one signed by an unenrolled key are 401, with nothing disclosed or changed, the same for an absent mission |
| Idempotency | a replay 5 seconds and 24 hours later repeats the receipt with a fresh observation and no new event or revocation; a reused `request_id` with changed content or for another mission is 409 `idempotency_conflict`; concurrent terminates by the owning agent and an administrator make one transition |

## Readings a second implementer could make differently

1. An agent the allowlist does not name is refused `user_unreachable`
   (403) at every endpoint: the PS reads an agent with no bound person as
   one with no person to reach.
2. An unknown or foreign `mission_s256` is `invalid_request` at the person
   token endpoint, where -11 says only "MUST reject the request
   otherwise", and `invalid_resource_token` at the auth token endpoint's
   mission check, where the reference rides in the resource token.
3. A governed agent's missionless request is `denied` (403); the binding
   names no error.
4. A denied proposal is 403 `denied` at once, never a 202.
5. A sub-agent calling the PS directly is `denied`, even when the allowlist
   names it.
6. "`expired_presented_token` when only `exp` fails": the PS verifies the
   token again at one second before its `exp`, and reports
   `expired_presented_token` only if that passes.
7. The check that the resource token's `ps` names this PS runs after step 3
   and before the mission check, and fails `invalid_resource_token`.
8. `GET {mission_endpoint}/{mission_s256}` is a local owner's read; -11
   defines only POST there.
9. Neither server signs responses; both sign tokens only, as -11 defines no
   signed response.
10. The signature base comes from the verifier's own identifier and the raw
    target, never from the Host field.
11. Time is whole seconds with no tolerance on `exp` ("no tolerance for
    clock skew on exp") or on `expires_at`: a mission is past `expires_at`
    once the clock reaches it.
12. Every issued-token record under a mission is a Tracked Credential; a
    missionless token is never revoked by a termination.
13. The mission log records approvals and issuance, not refusals; a
    presented-token mismatch and a missed reference become security events.
14. The PS verifies its own person and auth tokens, when presented back to
    it, through its own `jwks_uri`.
15. P1 equivalence rests on one lookup keyed by owning agent and `s256`
    together, not a lookup followed by an ownership check; timing is not
    measured.
16. A step-up resource token's `aud` is the presented auth token's `ps`;
    -11 states three-party `aud` only for "the iss of the person token".
17. The Resource accepts only PS-issued auth tokens (`iss` equal to `ps`).
18. An unsigned request is challenged `requirement=person-token`, as an
    agent-token request is, not answered with Signature-Error.
19. The optional replay cache keys on "(signing-key-thumbprint, created,
    @method, @authority, @path)", so an honest second request to one URL in
    the same second collides. The agent, the management client and the
    PS's revocation sender each wait for the next second. The control plane
    keeps that key for this pilot, so the same caller, the same mission URL
    and the same second give 401; the Resource's revocation endpoint also
    keys on the covered Content-Digest. A possible upstream note, the
    owner's call.
20. Content-Digest and Content-Type are required on requests with a body
    only, and the Resource publishes no `additional_signature_components`;
    the control plane and the revocation endpoint require them on every
    request, a bodiless one included.
21. An auth token whose scope lacks the operation's is challenged for a
    step-up, not refused.
22. An `account` parameter at the authorization endpoint is
    `invalid_account`: the Resource holds no accounts.
23. The Resource establishes a person record on first sight of an
    (`iss`, `sub`) pair.
24. The agent checks a resource token's `aud` against its own PS.
25. An agent with no mission refuses a resource token that carries a
    `mission_s256`.
26. The Resource copies `mission_s256` unchanged even when it is malformed;
    validating it is the PS's job.
27. A resource token carrying `interaction` is refused 403
    `user_unreachable`, after the mission check. -11 defines no code for a
    PS that cannot conduct the resource's flow; Table 16 gives
    `user_unreachable` for "The PS has no channel to reach the user and the
    agent did not declare the interaction capability". This PS has no
    interaction surface at all, so the agent's capability cannot help, and
    the reference reads the first condition alone as sufficient.
28. An agent token that expires after authentication but before an
    issuance commits is 401 `expired_jwt` with Signature-Error, since the
    Signature-Key token "has no codes in this table".
29. An administrator authenticates with a key pinned in the PS's
    configuration, under Signature-Key `jwks_uri` with a deployment-chosen
    `dwk`. The companion leaves the mechanism to "the PS's own
    administrative channel ... appropriate to the deployment".
30. A sub-agent, an agent off the allowlist, and an owning agent the PS
    does not admit get `mission_not_found` at the control plane, not slice
    2's `denied` or `user_unreachable`: such an agent "is an authenticated
    caller without authorization for the mission", and "A sub-agent MUST
    NOT call this endpoint".
31. An administrator lacking the action is unauthorized for the mission:
    `mission_not_found`.
32. The body and reason checks, which depend only on the caller's class,
    run before the lookup; the companion requires authorization "before
    existence is disclosed".
33. Idempotency is checked after the authorization lookup: a reused
    `request_id` against an absent or unauthorized mission is
    `mission_not_found`, not `idempotency_conflict`, although a reuse
    "addressed to another mission, fails with `idempotency_conflict`".
34. `request_id` must be 22 to 255 visible ASCII characters, a necessary
    condition for "at least 128 bits of ... entropy".
35. `replacement_s256` with a reason other than `superseded` is refused,
    not ignored.
36. A replacement may be in any state, must not be the target, and must
    lie in the administrator's person scope ("an already approved mission
    that the caller is authorized to reference").
37. A replay is logged as `terminate_replayed`, not as a lifecycle event.
    This reconciles "creates no second lifecycle event" with logging
    "every authorized termination request received after termination".
38. Duplicate member names are compared after decoding escapes.
39. `approved_at` and `expires_at` echo the blob's own strings
    (`approved_at` to the millisecond); `terminated_at` and `observed_at`
    are whole seconds.
40. Expiry is committed at `expires_at`, not at the moment it is detected,
    and attributed to `ps-scheduler`.
41. `tracked` includes credentials that expired before termination, and
    those get no revocation row: the companion says "SHOULD revoke every
    unexpired Tracked Credential".
42. `revocation_attempted` counts a credential whose discovery found no
    endpoint.
43. `residual_until` covers only live unconfirmed credentials; under
    `untracked_access` it can be present beside `complete: false`.
44. `complete` is true for a mission with no Tracked Credentials.
45. `untracked_access` is a deployment declaration in the configuration,
    shipped false: this Resource serves only auth-token access.
46. The revocation endpoint is retained at the first attempt, not at
    issuance (the companion: "retain ... the revocation endpoint of the
    Resource in `aud`, when advertised"). A metadata document without a
    usable https endpoint is terminal and never read again.
47. A `401` is retried and a `400` is not; a `202` is retried by POSTing
    again, never polled, since "A recipient with nothing downstream MUST
    NOT answer 202".
48. "Rate limited" retries are realized as sequential passes, backoff and
    spacing; there is no per-recipient limiter.
49. The restart tests reuse the signing key, since keys are generated per
    boot; a new key under the same `kid` fails once at the recipient's key
    cache, until it refreshes.
50. Three-party only: there are no presented-to-AS recipients, and every
    credential is PS-issued, none federated.
51. Any PS whose signature verifies under `jwks_uri` with `dwk`
    `aauth-person.json` may revoke at the Resource, bounded per issuer in
    rate and in entries; there is no PS allowlist, since the revoked set is
    keyed by the verified issuer and a PS can revoke only its own tokens.
52. The Resource checks the revoked set after the request's signature
    verifies, so a revoked token in a request that fails verification gets
    that failure first. An agent token is never looked up: agent tokens
    are revoked at the PS only.
53. `requirement=person-token` accompanies `revoked_jwt` for a revoked auth
    token only; a revoked person token gets no requirement.
54. A repeat revocation keeps the first `exp`; a far-future `exp` is not
    capped beyond the entries bound; an entry applies while the current
    second is before its `exp`; a revocation whose `exp` has passed is
    answered `200` and holds nothing.
55. A failure to read or write the revoked set fails closed: 500, and
    nothing runs or is recorded.
56. The Resource's check order at `/revoke`: the signature (with the
    `jwks_uri` scheme and both body components), the signer's document
    (`unsupported_iss`), the issuer's rate, the body (`invalid_request` for
    a body that is not a JSON object, a missing or empty `jti`, or an `exp`
    that is not a positive integer), then the entries bound.
57. The testkit's switch reads -11's "did not respond, timed out, or
    returned a 5xx or a malformed response" as three modes: a 503 with a
    problem body, a closed connection, and a 200 whose body is not JSON.
58. The management client's `request_id` is `t-` and 32 hex characters
    (128 random bits), and it refuses to send an administrator's terminate
    without a `purpose` or an action the PS does not list.
59. A token whose mission terminates or reaches `expires_at` while it
    is signed is refused at release, and its record is kept: the PS tracks
    conservatively, so a termination revokes a token the agent never
    received.
60. A final attempt cut short before its outcome (a crash, a restart)
    is not sent again: the credential is exhausted, last outcome
    `interrupted`, unconfirmed until its `exp`, though the recipient may
    have recorded it.
61. A credential that reaches its `exp` before its revocation could
    be sent is recorded `expired`, a state of its own, not a failure.
