# Issuance-only reference deployment

A proposed reference deployment of the issuance-only floor (#873): the
reference Mission-aware Authorization Server and the `plain-rs` Resource
Server, which has no Mission-specific code, in two configurations: JWT
validation alone, and JWT validation plus per-request introspection. There is
no separate Mission runtime PEP or PDP; ordinary Resource Server credential
validation and authorization still apply. Every behavioral statement below is
true of the reference implementation at this revision and cites the function
or the exact test (`describe > it`) that shows it. A path with no witnessing
test says "no test yet". This document is the documentation foundation for
#873; §10 lists what that issue still requires. §7 shows how to run both
configurations.

## 1. Scope and claims

What the deployment is:

- **The AS changes; Resource Servers need not.** The Authorization Server
  takes Mission intake, derivation, approval, the Mission Record, and
  state-gated issuance. A Resource Server either consumes
  `authorization_details` or authorizes on `scope` alone.
- **Scope-only Resource Servers get a safe projection or no token.** A
  `scope`-only Resource Server receives only a `scope` projection the AS proved
  safe, or no token.
- **Revocation cutoff.** Revocation stops at the issuance gate. Outstanding
  tokens run to their own `exp`, or to the next request at a Resource Server
  that introspects.

What it is not:

- It is not a runtime profile: there is no per-action check within a token
  lifetime.
- It claims nothing for the high-consequence classes.
- It has no parameter binding and emits no per-action evidence. Its evidence
  is the AS's issuance records.

Where it sits in the drafts:

- `draft-mcguinness-mission-architecture.md`:
  - § Entry Ramps by Estate (`{#entry-ramps}`), the "issuance-only
    deployment" paragraph under the table's last row;
  - the adoption ladder's Baseline Issuance row (§ Mission Assurance Levels,
    `{#assurance-levels}`);
  - § Assurance Claims (`{#assurance-claims-axis}`);
  - § The Mission Deployment Profile (`{#deployment-profile}`).
- `draft-mcguinness-oauth-mission.md`:
  - § Issuance Scope, Not Runtime Enforcement (`{#runtime-boundary}`), what
    the OAuth binding does not do;
  - § Scope Projection (`{#scope-projection}`), how a `scope`-only target is
    served.
- #253: the AS-native reference deployment is this floor plus the runtime
  overlay (`draft-mcguinness-mission-runtime.md`) on the high-consequence
  classes.

## 2. Topology and trust assumptions

**One issuer, one trust domain.** The reference AS
(`services/authorization-server`, `src/server.ts`) listens on `AS_PORT`
(default 4400) with issuer `AS_ISSUER` (default `http://localhost:4400`). The
demo stack with the auth server uses the same `http://localhost:{asPort}`
issuer (`demo/src/stack.ts`); `config/topology.json` `issuers.as`
(`https://as.demo`) names only the in-process surfaces that run without it. It
signs every Mission-bound access token as an RFC 9068 `at+jwt` with the
`as-token` key (`RS256`, `config/topology.json` `keys.asToken`) and publishes
its keys at `{issuer}/jwks`.

**The deployment's Resource Server.** `plain-rs` (`http://localhost:4410/api`;
mapping mode `scope_only`, `mission_aware: false`, version `2026-09-29.2` in
`config/scope-projection.json`) has zero Mission code. It performs RFC 9068
validation, verifies DPoP when `cnf.jkt` is present, refuses a `cnf` other
than a well-formed `jkt`, and authorizes on `scope` alone
(`services/plain-rs/src/index.ts`;
`` plain-rs carries zero Mission code > no source file under src/ contains `mission` or `authorization_details` (case-insensitive) ``).

**Related compositions, not part of this deployment.**

- `mcp-payments` (`http://localhost:4403/mcp`; `authorization_details`,
  `mission_aware: true`) is the runtime composition. Every tool call, reads
  included, runs `pep.enforce`, obtains a PDP decision, and verifies the
  permit before it proceeds (`services/mcp-payments/src/server.ts`). It
  belongs to #253's AS-native deployment: this floor plus the runtime overlay.
  The AS-side tests below use its audience to exercise the AS's behavior
  toward an `authorization_details` target. They claim nothing about payments
  as an issuance-only Resource Server.
- `mcp-saas` (`http://localhost:4406/mcp`; `authorization_details`,
  `mission_aware: false`) enforces from the token alone. As shipped, it
  accepts tokens from the RAS issuer (`deps.rasIssuer`), not from this AS;
  running it against this AS is a configuration change with no test yet.
- The mapping also classifies `http://localhost:4499/mcp` (hrFiles) as
  `authorization_details`, `mission_aware: false`. No Resource Server for it
  exists in this repository.

No token-only `authorization_details`-consuming Resource Server is part of
this deployment.

The `plain-rs` operations are `GET /api/reports` (needs `reports.read`) and
`POST /api/reports` (needs `reports.write`) (`OPERATIONS`). Its mapping values
stand for `reports:report.read` and `reports:report.write`, exact match, with
no mandatory controls. The shipped ceiling gives the plain RS one
constraints-free entry with those two actions and no delegation policy
(`config/policy.json`).

**Introspection (optional).** RFC 7662 at `{issuer}/introspect`, with HTTP
Basic principals from `config/introspection.json`; the plain RS's is
`rs-plain`, authorized for its audience. `plain-rs` in introspection mode calls
it on every request and honors only `active` (`introspectActive`). The call
authenticates with client_secret_basic. Each request makes a fresh POST, and
no result is cached. Each call is bounded by `introspection.timeoutMs`
(default 2000 ms, `DEFAULT_INTROSPECTION_TIMEOUT_MS`;
`PLAIN_RS_INTROSPECTION_TIMEOUT_MS` in the launcher), response body included.
Outcomes by response, each refusing before the operation runs, and none a 500:

- **503 `temporarily_unavailable`** for:
  - a non-200 status;
  - a network failure;
  - a response slower than the timeout;
  - a body that is not JSON;
  - JSON that is not an object (`null`, an array, a number, a string).
- **401 `invalid_token`** for a JSON object whose `active` is not the boolean
  `true` (missing, `false`, or `"true"`).
- **The operation runs** only when `active` is `true`.

Tests:

- `` plain-rs introspection mode > honors only `active`: an inactive token is refused even when its JWT is valid, and an introspected scope grants nothing ``
- `plain-rs introspection failure contract (#873) > a 500 from the introspection endpoint refuses 503 temporarily_unavailable before the operation`
- `plain-rs introspection failure contract (#873) > an unreachable introspection endpoint (connection refused) refuses 503 temporarily_unavailable before the operation`
- `plain-rs introspection failure contract (#873) > a body that is not JSON refuses 503 temporarily_unavailable before the operation`
- `plain-rs introspection failure contract (#873) > a JSON null body refuses 503 temporarily_unavailable, never 500`
- `plain-rs introspection failure contract (#873) > a JSON array, number or string body refuses 503 temporarily_unavailable`
- `plain-rs introspection failure contract (#873) > an object with no active member refuses 401 invalid_token before the operation`
- `` plain-rs introspection failure contract (#873) > an object whose active is the string "true" refuses 401 invalid_token before the operation ``
- `plain-rs introspection failure contract (#873) > a response slower than the introspection timeout refuses 503 temporarily_unavailable within about the timeout`
- `plain-rs introspection failure contract (#873) > active true admits the operation`
- `plain-rs introspection failure contract (#873) > introspects every request: two requests make two calls, and a positive first result does not admit the second once the endpoint says active false`

A
non-active Mission yields `active: false` with `mission.state`
(`composite non-active: active:false WITH mission.state (@spec mission#composite-active) > revoked Mission + valid token: only { active, mission }, state revoked, NO top-level or mission authorization_details`).

**The scope-projection mapping is trusted operator configuration.** Its
ownership, integrity and update procedure are in `src/config/README.md`.
`loadScopeProjection` (`packages/demo-data`) parses it strictly: duplicate
members, unknown members, and a missing or non-boolean `mission_aware` refuse
at load. The AS loads it at startup (or on a reload) and evaluates every
issuance against the loaded mapping; it never fetches it at runtime.
`mission_aware` is the delegated-routing classification: `true` only for a
target that processes the `act` chain and the `mission` claim.

**Lifetimes.**

- **No credential outlives the Mission.** Every credential issued under a
  Mission-bound grant has its configured lifetime or the Mission's remaining
  whole seconds, whichever is shorter (`clampToMission` and the `ttl`
  configuration in `buildProvider`). A Mission with under one second left is
  refused `invalid_grant` `mission_expired` at the token endpoint, never given
  a token:
  `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > code exchange: the access token, refresh token and authorization code all expire no later than a Mission ending inside their lifetimes`,
  `> a credential minted with under one second of Mission left is refused, never given a 0 s or overrunning lifetime`.
- **Access tokens:** 300 seconds (`config/topology.json`
  `ttls.accessTokenSeconds`), clamped as above. A deferred token is also
  clamped to its approval expiry.
- **Refresh tokens:** oidc-provider's 14-day default, clamped as above. A
  refresh presented after `expires_at` is refused because the refresh token
  itself has expired, so the refusal is `invalid_grant` with no
  `mission_error`:
  `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > a refresh after expires_at is refused invalid_grant by the expired refresh token itself, before the state gate (no mission_error)`.
- **Authorization codes and ID Tokens:** oidc-provider's 60 seconds and 1
  hour, clamped as above. The code is minted at the authorization endpoint's
  resume, so a code the clamp refuses there redirects `access_denied`, never
  `invalid_grant`, and no code is issued:
  `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > an authorization resumed with under one second of Mission left redirects access_denied, never invalid_grant, and issues no code`.
- **Refresh gating:** refresh is gated on Mission state.

**Clocks and keys.**

- **Keys:** signing keys are generated at every boot
  (`buildAuthorizationServer`, D25), under the static `kid` `as-token`. Losing
  the previous signing key is not revocation.
  - A consumer that cached the old key keeps accepting tokens issued before
    the restart until their `exp`.
  - `plain-rs` uses jose's `createRemoteJWKSet`, which reloads only when no
    cached key matches the `kid` or the cache is older than 10 minutes. It
    therefore also rejects tokens issued after the restart until its cache
    refreshes.
  - A consumer that refetches the JWKS after the restart can no longer verify
    pre-restart tokens.

  A restart is not a revocation mechanism.
- **Clocks:** oidc-provider applies its default 15-second `clockTolerance`.
  `plain-rs`'s access-token time tolerance is `clockToleranceSeconds` (default
  0, `PLAIN_RS_CLOCK_TOLERANCE_SECONDS` in the launcher). It is passed to jose
  with the injectable `now()` clock. A token is refused once
  `exp <= now - tolerance`, so an issued token stays usable until its `exp`
  plus the declared tolerance. A tolerance that is not a finite number >= 0, or
  a timeout that is not a positive integer, stops `plain-rs` at construction
  (`plain-rs configuration validation > refuses at construction a clock tolerance that is not a finite non-negative number, and an introspection timeout that is not a positive integer`).
  `plain-rs` accepts DPoP proofs whose `iat` is
  within ±60 seconds of now, inclusive (`dpopWindowSeconds`). With the shipped
  values, the JWT-only configuration states a 300-second maximum access-token
  lifetime and a 0-second accepted skew. One synchronized clock is assumed
  across the AS and the Resource Servers. Tests:
  - `` plain-rs access-token time boundaries (injected clock) > with clock tolerance 0, a token whose exp is 1 s before now is refused and one whose exp is 1 s after now is accepted ``
  - `` plain-rs access-token time boundaries (injected clock) > with clock tolerance 5 s, a token 3 s past exp is accepted and one 6 s past exp is refused ``
  - `` plain-rs access-token time boundaries (injected clock) > a DPoP proof whose iat is exactly 60 s either side of now is accepted, and 61 s is refused ``
- **Stores:** the Mission kernel, grants, the token issuance index
  (`TokenIssuanceStore`) and the delegation-family store are in memory by
  default (`src/docs/control-plane-deployment.md`).

## 3. Behavior by path

The rows describe the reference AS. Rows that need a capability §8 turns off
at the launcher (OIDC values, the delegated and async-delegation exchanges)
describe the full assembly. At the launcher those requests get §8's refusal.

| Path | Outcome | Evidence |
|---|---|---|
| AS toward an `authorization_details` audience (tests use the payments audience) | Token carries the entries and the `mission` claim, no `scope`; response has no `scope` member unless OIDC values were granted | `projectMissionBoundScope`/`decideMissionScope` (`provider.ts`); `scope projection at the token endpoint (@spec mission#scope-projection) > omits scope on a Mission-bound token to an authorization_details audience` |
| Issuance to the `scope_only` plain RS | Token carries exactly the projected values; plain RS allows the in-scope call, 403 `insufficient_scope` otherwise | `scope projection at the token endpoint (@spec mission#scope-projection) > a safe projection carries exactly the projected scope, and the plain RS allows the in-scope operation and refuses the other with 403 insufficient_scope` |
| Issuance with a requested subset (`scope=reports.read`) | Exactly the requested safe values, reported in the response | `requested scope and the token response (@spec mission#scope-projection) > a requested scope narrows the projection to exactly the requested values, and the response reports them` |
| OIDC values (`openid`) | id_token issued; response `scope` reports OIDC plus projected values; JWT `scope` carries projected values only | `requested scope and the token response (@spec mission#scope-projection) > OIDC values combine with authorization_details: openid yields an id_token, and the response scope reports the granted OIDC and projected values` |
| Refresh | Re-projected against the current mapping; a version bump alone still projects | `scope projection on derived tokens (@spec mission#scope-projection) > refresh re-projects against the current mapping: a version bump alone still projects, a mapping that no longer proves the value refuses invalid_target, and an audience removed from the mapping fails closed` |
| Revocation | Refresh `invalid_grant`; introspection `active: false`; the introspecting plain RS denies the next call; the JWT-only plain RS keeps accepting until `exp` | `revocation with a scope-only Resource Server (@spec mission#scope-projection) > after the Mission is revoked, refresh refuses invalid_grant, introspection returns active false, and the plain RS in introspection mode denies the next call` |
| Mapping failure (no current entry for the audience, or a mapping failing the strict load) | `invalid_target`; a mapping that fails the strict load stops the AS at boot | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses invalid_target for an audience the mapping does not know`; the refresh test above; `config/scope-projection.json loader (@spec mission#scope-projection) > refuses an ambiguous mapping (a duplicated member name) and an unknown member at load` |
| No safe projection (unenforced constraint, union, aggregation, prefix) | `invalid_target` | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses invalid_target when an entry constraint is not independently enforced by the target, and projects once the mapping declares a control at least as tight`, `> refuses a scope only the union of two entries covers`, `> refuses a scope that aggregates an action the entry does not carry`, `> refuses a prefix scope for an exact entry` |
| Ungrantable requested scope | `invalid_scope` at PAR (resource value for an `authorization_details` target, or a value the mapping does not name), at the decision (a mapped value no entry makes safe, before any Mission exists), and at the token endpoint | `ungrantable requested scope (@spec mission#scope-projection, mission#error-mapping) > refuses invalid_scope at PAR a resource scope for an authorization_details target, and a value the scope-only target's mapping does not name`, `> refuses invalid_scope at the authorization decision a mapped value no carried entry makes safe, before any Mission exists`, `> refuses invalid_scope at the token endpoint when an authorized requested value is no longer safe, and invalid_target when the target's mapping is unknown even though scope was requested` |
| Precedence | Unknown mapping refuses `invalid_target` even when `scope` is requested | the last test above; `projectScope (@spec mission#scope-projection) > an unknown mapping refuses invalid_target even when the request names a scope value` |
| Refresh preservation | A projection-only refusal consumes nothing; after the mapping is repaired the same token succeeds once, then reuse is replay-detected | `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refused rotating refresh leaves the same refresh token valid: once the trusted mapping is repaired it succeeds once, and its reuse gets the ordinary replay treatment` |
| Refresh probing | An unauthenticated or wrong-client refresh gets the client error, not the projection error | `refresh preserved on a projection refusal (@spec mission#scope-projection) > an unauthenticated or wrong-client refresh of a projection-failing token gets the ordinary client error, never a projection error` |
| Narrower refresh | Granted exactly the requested values; a value never granted is `invalid_scope` without consuming the token | `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refresh naming a narrower scope is granted exactly it; a value never granted refuses invalid_scope without consuming the token (#871)` |
| Explicit OIDC-only refresh (`scope=openid`) | At the plain RS: `invalid_scope`, token kept. At an `authorization_details` audience: 200, response `scope` `openid`, no JWT `scope` | `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refresh naming only OIDC values explicitly asks for no resource value: refused invalid_scope at a scope-only target without consuming the token, which then inherits its full granted scope`, `> a refresh naming only OIDC values at an authorization_details target is granted exactly them, with no scope on the token` |
| Inherited grant after a mapping change | Narrowed and reported while a value remains; `invalid_scope` before rotation when none would | `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refresh omitting scope whose inherited grant the current mapping no longer grants, leaving no scope value to report, is refused invalid_scope before rotation; the restored mapping lets the same token succeed`, `> a refresh omitting scope narrows an inherited grant the response can still report: a mode change keeps the OIDC values, an unsafe value drops out, and nothing widens` |
| Delegated routing (`act`-bearing tokens) | Minted only when every audience is `mission_aware: true`, else `invalid_target` before any side effect | `delegated routing on the cross-org exchange (@spec mission#rs-enforcement) > refuses invalid_target, recording no derivation evidence, when the act-bearing token's audience is not classified Mission-aware, even with a safe scope projection`, `> mints the act-bearing token for an audience classified Mission-aware`; `delegated routing of transaction tokens (@spec mission#rs-enforcement) > refuses invalid_target, opening no approval, an act-bearing transaction token for a Challenge-Issuing Resource not classified Mission-aware, and admits it once the resource is`; JWT-customizer backstop (`formats.customizers.jwt`): no test yet |
| Delegate calling the plain RS | Not supported: a delegated (`act`-bearing) token is refused for it, and the refusal never creates a Child Mission. Child Missions are a separately enabled capability, off at the launcher (§8). In the full assembly the plain RS ceiling entry has no `delegation.children` either (`kernel/child-delegation.ts`) | Refusal: the delegated-routing row above; Child Mission path: §8's child rows |
| Token expiry | `plain-rs` refuses a token once `exp <= now - clockToleranceSeconds` (default tolerance 0), with no operation performed; the DPoP `iat` window is ±60 s inclusive | `plain-rs RFC 9068 / RFC 9449 validation > refuses a wrong typ, a wrong audience or issuer, and an expired token`; `plain-rs access-token time boundaries (injected clock) > with clock tolerance 0, a token whose exp is 1 s before now is refused and one whose exp is 1 s after now is accepted`; `plain-rs access-token time boundaries (injected clock) > with clock tolerance 5 s, a token 3 s past exp is accepted and one 6 s past exp is refused`; `plain-rs access-token time boundaries (injected clock) > a DPoP proof whose iat is exactly 60 s either side of now is accepted, and 61 s is refused` |
| Introspection failure (introspection configuration) | No operation performed, and never a 500. A non-200 status, a network failure, a response slower than the timeout (default 2000 ms), a body that is not JSON, or JSON that is not an object gives 503 `temporarily_unavailable`; an object whose `active` is not the boolean `true` gives 401 `invalid_token` | `plain-rs introspection failure contract (#873) > a 500 from the introspection endpoint refuses 503 temporarily_unavailable before the operation`; `plain-rs introspection failure contract (#873) > an unreachable introspection endpoint (connection refused) refuses 503 temporarily_unavailable before the operation`; `plain-rs introspection failure contract (#873) > a body that is not JSON refuses 503 temporarily_unavailable before the operation`; `plain-rs introspection failure contract (#873) > a JSON null body refuses 503 temporarily_unavailable, never 500`; `plain-rs introspection failure contract (#873) > a JSON array, number or string body refuses 503 temporarily_unavailable`; `plain-rs introspection failure contract (#873) > an object with no active member refuses 401 invalid_token before the operation`; `` plain-rs introspection failure contract (#873) > an object whose active is the string "true" refuses 401 invalid_token before the operation ``; `plain-rs introspection failure contract (#873) > a response slower than the introspection timeout refuses 503 temporarily_unavailable within about the timeout` |
| No introspection caching | Every request makes its own call; a positive result never admits a later request | `plain-rs introspection failure contract (#873) > introspects every request: two requests make two calls, and a positive first result does not admit the second once the endpoint says active false` |
| Async-delegation with `actor_token` | `invalid_request` for any target before any side effect; an `act`-bearing subject token is refused too | `unsupported actor context on the async-delegation exchange (@spec continuation#transport-async) > refuses invalid_request any exchange presenting an actor_token, to a scope-only or a Mission-aware target, spending no derivation; the same exchange with no actor succeeds with the projected scope`, `> refuses invalid_request a subject_token that already carries act, rather than stripping it` |

## 4. Provider integration port

These are the hooks an AS implementer builds for this deployment, and where the
reference builds each one. "Transactional" means the hook must commit
atomically with the state it depends on. "Async" means it may run after the
commit without weakening a claim. "In-request" hooks run synchronously inside
the issuing request and must complete before the response; none of them may be
deferred.

| Hook | Reference implementation | Consistency |
|---|---|---|
| Trusted approval input | `decide()` (`provider.ts`); the resolving principal comes from the surface (`ApprovalSessionStore.resolve`, or a scoped service principal behind `allowHeadlessAdjudication`), and a `decide` body naming `approver`/`subject` is refused | In-request; no separate commit |
| Principal resolution | Client: oidc-provider `private_key_jwt` (`config/clients.json`). Subject: `login_hint` checked against `knownSubjects` and `approverApprovesFor`. Authority source gates inside `kernel.approve` | In-request, before derivation |
| Derive-and-commit issuance | `kernel.derive` at the decision, then `kernel.approve` (anchors and record through `insertRecord`, deduplicated on `approval_event_id`), then `grant.save()` and `kernel.bindGrant` | MUST be transactional for the record and its anchors. In the reference, `bindGrant` is a separate write after the grant save, not in the record's transaction. Provider token acceptance and derivation counting are not coupled atomically: the provider access-token hook counts inside the provider's own token save, with no reservation, operation identity, or acceptance callback (`src/docs/control-plane-deployment.md`; #250) |
| Grant-to-Mission lookup | `kernel.findByGrant`, the delegation-family store, and the durable append-only `MissionBoundGrantStore`; `missionForBoundGrant` fails closed when the index names a grant whose Mission is gone | Read at every issuance |
| Refresh and revocation gating | `extraTokenClaims` runs `gateDerivation` (conditional counter update) or `gateActive`; `rarThroughEffectiveSet` re-projects through the effective set; `kernel.transition` compare-and-sets state. Family grants are destroyed by the durable subscriber `delegation-family-grant-revoke` (`index.ts`) | The state gate and the counter update are one conditional update, but the count is not coupled to the provider's token acceptance (see derive-and-commit). Family-grant destruction MAY be async, because the gate refuses first |
| Scope projection | `decideMissionScope`, shared by the save-time `projectMissionBoundScope` (in `extraTokenClaims`, before the state gates) and the refresh pre-check `preCheckRefreshProjection` (in `rotateRefreshToken`, after client authentication and the token's own checks, before consumption). Also: `earlyScopeRefusal` at PAR, the decision-time check, the async-delegation and cross-org pre-checks, and the response-`scope` middleware | In-request, before any side effect of the issuing request; the refresh pre-check MUST precede consumption |
| Introspection composite `active` | `/introspect` in `makeRoutes`: signature, `at+jwt`, the RFC 9068 claim set, the issuance index (`TokenIssuanceStore`) and `isGrantLive`, then Mission state; audience-minimized through `resourcesForAudiences` | Reads current state per request |
| JWT customizer backstop | `formats.customizers.jwt`: applies the projection's decision and refuses a Mission-bound JWT the projection did not decide, or an `act`-bearing one to a non-Mission-aware audience | In-request |

**Provider-specific notes (oidc-provider 9.10 workarounds).** These are
honest workarounds, not protocol requirements.

- **Intent-only requests get a synthesized `authorization_details`.**
  oidc-provider completes an authorization only when a scope was granted or
  `authorization_details` was requested. For an Intent-only request, `decide()`
  therefore writes the derived authority into the stored interaction as
  `authorization_details`, beside the reserved marker
  `DERIVED_AUTHORIZATION_DETAILS_MARKER`. The approval render and `decide()`
  read the proposal through `clientProposalParam`, which treats a marked value
  as absent. A client cannot send the marker, because oidc-provider's parameter
  allow-list drops it. Tests:
  - `requested scope and the token response (@spec mission#scope-projection) > a Mission created from the Intent alone (no authorization_details, no scope) completes and projects`;
  - `the Intent-only completion workaround is never a client proposal (@spec mission#authority-proposal) > an Intent-only Mission commits no proposal_hash, and re-rendering or re-deciding the same interaction still reads no proposal`;
  - `> a client-sent marker key is dropped: a pushed proposal is still the client's proposal, and an Intent-only request stays Intent-only`.
- **The refresh-token scope is recorded through the code's scope.**
  `issueRefreshToken` sets the authorization code's `scope` to its OIDC values
  plus the projected values, so the refresh token records what was granted,
  and oidc-provider's own RFC 6749 §6 check refuses a refresh naming more.

## 5. Deployment Profile instance

This uses the architecture's issuance-only example shape, filled with this
deployment's values: the reference AS and `plain-rs`.

- `authorization_details_enforcing` is empty, because no token-only
  `authorization_details`-consuming Resource Server is part of this
  deployment.
- `state_sources` applies to the introspection configuration. The JWT-only
  configuration has none and relies on token lifetime.
- "approved-record integrity" is claimed only in its defined sense: the
  anchors reproduce from the retained record. It is not independent proof
  against an issuer that substitutes both the record and its hashes.

~~~ json
{
  "profile": "mission-issuance-only",
  "assurance_claims": [
    "approved-record integrity", "bounded revocation latency"
  ],
  "mission_issuer": "http://localhost:4400",
  "state_sources": [
    { "type": "introspection", "max_staleness_seconds": 0 }
  ],
  "issuance": {
    "binding": "oauth-core",
    "refresh_gated_on_active_state": true,
    "max_access_token_lifetime_seconds": 300
  },
  "resource_servers": {
    "authorization_details_enforcing": [],
    "scope_projection_only": ["http://localhost:4410/api"],
    "constraint_enforcement_for_scope_only": "refuse_issuance"
  },
  "residual_risks": [
    "no per-action check within a token lifetime",
    "high-consequence classes excluded; no parameter binding",
    "revocation up to 300 seconds at a Resource Server that does not introspect",
    "scope-only constraints not projectable are refused",
    "delegated (act-bearing) tokens are refused for plain-rs, with no automatic Child Mission fallback; Child Missions are off",
    "no cancellation of admitted work: a check completed before revocation does not stop an admitted request",
    "no token-only authorization_details-consuming Resource Server is part of this deployment: payments is the runtime composition, and mcp-saas accepts RAS-issued tokens",
    "evidence is the AS's issuance records only: the Mission Record, its lifecycle events, and the per-token issuance index",
    "plain-rs logs nothing Mission-linked",
    "a restart is not revocation: consumers holding the old key keep accepting pre-restart tokens until exp, and plain-rs rejects post-restart tokens until its JWKS cache refreshes (up to 10 minutes)",
    "an introspection call that exceeds its timeout (default 2000 ms) or fails refuses service with 503; the plain RS never falls back to the JWT alone",
    "provider token acceptance and derivation counting are not coupled atomically (#250)",
    "grants, the issuance index and the delegation-family store are in memory",
    "the scope-projection mapping's integrity is repository review; it is not fetched or signed",
    "Intent-only requests depend on an oidc-provider workaround (a marked, AS-written authorization_details)",
    "the decision-time scope check projects the derived set without capability_sources, so a catalog-sourced scope_only entry can pass at the decision and refuse at the token endpoint",
    "a repeated decision on one interaction binds a second grant to the committed record",
    "the JWT-customizer backstop has no test yet"
  ]
}
~~~

This is an instance, not a schema. The parked Deployment Profile schema (#424)
is not revived here.

## 6. Negative vector pack

Each vector maps to its ledger rows (`conformance-manifest.json`) and to
existing tests only. "No test yet" marks a vector nothing witnesses.

| Vector | Expected outcome | Ledger row(s) | Existing test (`describe > it`) |
|---|---|---|---|
| Entry constraint the scope-only target does not enforce | `invalid_target` | `core.tokens.scope-ceiling`, `core.scope-projection.semantic-subset-condition`, `resource-access.scope-projection.constraints-independently-enforced` | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses invalid_target when an entry constraint is not independently enforced by the target, and projects once the mapping declares a control at least as tight` |
| Scope only a union of entries covers | `invalid_target` | `core.scope-projection.union-widening-fails`, `resource-access.scope-projection.actions-no-aggregation` | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses a scope only the union of two entries covers` |
| Scope aggregating an action the entry lacks | `invalid_target` | `core.scope-projection.action-aggregation-fails`, `resource-access.scope-projection.actions-no-aggregation`, `resource-access.scope-projection.actions-subset` | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses a scope that aggregates an action the entry does not carry` |
| Prefix scope for an exact entry | `invalid_target` | `core.scope-projection.resource-path-aggregation-fails`, `resource-access.scope-projection.prefix-resource-match-exact` (partial) | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses a prefix scope for an exact entry` |
| No current mapping entry for the audience, no `scope` requested | `invalid_target` | `core.scope-projection.unknown-stale-mapping-fail-closed`, `core.tokens.scope-ceiling` | `scope projection at the token endpoint (@spec mission#scope-projection) > refuses invalid_target for an audience the mapping does not know`; on refresh, `scope projection on derived tokens (@spec mission#scope-projection) > refresh re-projects against the current mapping: a version bump alone still projects, a mapping that no longer proves the value refuses invalid_target, and an audience removed from the mapping fails closed` |
| No current mapping entry for the audience, `scope` requested | `invalid_target` (precedence over `invalid_scope`) | `core.scope-projection.unknown-stale-mapping-fail-closed` | `ungrantable requested scope (@spec mission#scope-projection, mission#error-mapping) > refuses invalid_scope at the token endpoint when an authorized requested value is no longer safe, and invalid_target when the target's mapping is unknown even though scope was requested` |
| A mapping the AS cannot establish as current (fails the strict load) | The AS does not start; no issuance under it | `core.scope-projection.unknown-stale-mapping-fail-closed` | `config/scope-projection.json loader (@spec mission#scope-projection) > refuses an ambiguous mapping (a duplicated member name) and an unknown member at load`; `> refuses an audience whose mission_aware is missing or not a boolean (@spec mission#rs-enforcement)` |
| A changed mapping version (not by itself stale) | Re-projects | `core.scope-projection.unknown-stale-mapping-fail-closed` | the refresh test above; `projectScope (@spec mission#scope-projection) > evaluates the mapping current at each issuance: a changed version still projects` |
| Ungrantable requested value | `invalid_scope` | `core.scope-projection.ungrantable-requested-scope-refused` | `ungrantable requested scope (@spec mission#scope-projection, mission#error-mapping) > refuses invalid_scope at PAR a resource scope for an authorization_details target, and a value the scope-only target's mapping does not name`; `> refuses invalid_scope at the authorization decision a mapped value no carried entry makes safe, before any Mission exists`; `> refuses invalid_scope a Token Exchange naming a value no carried entry makes safe, or an OIDC value where no id_token is issued, and grants a safe requested value` |
| Refresh after a projection-only refusal | Token and grant still valid | `core.scope-projection.refresh-preserved-on-projection-refusal` | `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refused rotating refresh leaves the same refresh token valid: once the trusted mapping is repaired it succeeds once, and its reuse gets the ordinary replay treatment` |
| Delegated token for a Resource Server that is not Mission-aware | `invalid_target`, no side effect, no automatic Child Mission | No ledger row covers the delegated-routing rule | `delegated routing on the cross-org exchange (@spec mission#rs-enforcement) > refuses invalid_target, recording no derivation evidence, when the act-bearing token's audience is not classified Mission-aware, even with a safe scope projection`; `delegated routing of transaction tokens (@spec mission#rs-enforcement) > refuses invalid_target, opening no approval, an act-bearing transaction token for a Challenge-Issuing Resource not classified Mission-aware, and admits it once the resource is` |
| Token past `exp` at the plain RS | 401 `invalid_token`, no operation | No ledger row covers `plain-rs` | `plain-rs RFC 9068 / RFC 9449 validation > refuses a wrong typ, a wrong audience or issuer, and an expired token`; `plain-rs access-token time boundaries (injected clock) > with clock tolerance 0, a token whose exp is 1 s before now is refused and one whose exp is 1 s after now is accepted` |
| Token within the declared clock tolerance past `exp` | Accepted inside the tolerance, refused beyond it | No ledger row covers `plain-rs` | `plain-rs access-token time boundaries (injected clock) > with clock tolerance 5 s, a token 3 s past exp is accepted and one 6 s past exp is refused` |
| DPoP proof at the `iat` window edge | ±60 s accepted, ±61 s refused `invalid_dpop_proof` | No ledger row covers `plain-rs` | `plain-rs access-token time boundaries (injected clock) > a DPoP proof whose iat is exactly 60 s either side of now is accepted, and 61 s is refused` |
| Introspection outage (non-200, connection refused) | 503 `temporarily_unavailable`, no operation | No ledger row covers `plain-rs` | `plain-rs introspection failure contract (#873) > a 500 from the introspection endpoint refuses 503 temporarily_unavailable before the operation`; `plain-rs introspection failure contract (#873) > an unreachable introspection endpoint (connection refused) refuses 503 temporarily_unavailable before the operation` |
| Introspection body not JSON, or JSON that is not an object (`null`, array, number, string) | 503 `temporarily_unavailable`, no operation, never 500 | No ledger row covers `plain-rs` | `plain-rs introspection failure contract (#873) > a body that is not JSON refuses 503 temporarily_unavailable before the operation`; `plain-rs introspection failure contract (#873) > a JSON null body refuses 503 temporarily_unavailable, never 500`; `plain-rs introspection failure contract (#873) > a JSON array, number or string body refuses 503 temporarily_unavailable` |
| Introspection body `{}`, or `active` not the boolean `true` | 401 `invalid_token`, no operation | No ledger row covers `plain-rs` | `plain-rs introspection failure contract (#873) > an object with no active member refuses 401 invalid_token before the operation`; `` plain-rs introspection failure contract (#873) > an object whose active is the string "true" refuses 401 invalid_token before the operation ``; `` plain-rs introspection mode > honors only `active`: an inactive token is refused even when its JWT is valid, and an introspected scope grants nothing `` |
| Introspection endpoint slower than the timeout | 503 `temporarily_unavailable` within about the timeout, no operation | No ledger row covers `plain-rs` | `plain-rs introspection failure contract (#873) > a response slower than the introspection timeout refuses 503 temporarily_unavailable within about the timeout` |
| A positive introspection result reused for a later request | Never: the next request introspects again and is refused when the endpoint says `active: false` | No ledger row covers `plain-rs` | `plain-rs introspection failure contract (#873) > introspects every request: two requests make two calls, and a positive first result does not admit the second once the endpoint says active false` |
| Revocation cutting off an introspecting plain RS | Next call denied (401 `invalid_token`) | `core.introspection.composite-active`; `core.grant-binding.termination-gates-every-binding` is still todo and does not cite this test | `revocation with a scope-only Resource Server (@spec mission#scope-projection) > after the Mission is revoked, refresh refuses invalid_grant, introspection returns active false, and the plain RS in introspection mode denies the next call` |

The reference cannot tell an audience that was never mapped from one removed
from the mapping: both have no current entry and refuse the same way. The
endpoint tests remove the entry between approval and issuance. The strict
loader runs when `packages/demo-data` is imported (`SCOPE_PROJECTION`), so a
mapping that fails it stops the AS before any issuance.

## 7. Run it

Both configurations run from `src/` with no OpenFGA, PDP or PEP. Install once
with `pnpm install --frozen-lockfile`.

| Configuration | Start | Walkthrough (second shell) |
|---|---|---|
| JWT validation alone | `pnpm issuance-only` | `pnpm issuance-only:walkthrough` |
| JWT plus per-request introspection | `pnpm issuance-only --introspection` | `pnpm issuance-only:walkthrough` |

**What the launcher starts.** `pnpm issuance-only` (`scripts/issuance-only.mjs`
→ `demo/src/issuance-only-serve.ts` → `startIssuanceOnly` in
`demo/src/issuance-only.ts`) starts two servers in one server process:

- **The reference AS**, at `http://localhost:4400`. This is the
  `buildAuthorizationServer` assembly restricted to the capability set of §8
  (`ISSUANCE_ONLY_CAPABILITIES`). `src/server.ts` runs the same assembly with
  every capability on. It is the issuer, and its JWKS is at `/jwks`.
- **`plain-rs`**, at `http://localhost:4410`, audience
  `http://localhost:4410/api`.

It reads the shipped config:

- `config/topology.json`: ports, resources, the 300 s access-token lifetime,
  and the `as-token` key id.
- `config/scope-projection.json`: the plain RS's `scope_only` entry.
- `config/policy.json`: the plain RS ceiling entry.
- `config/clients.json`: the `ap-agent` client.
- `config/introspection.json`: the `rs-plain` principal, used with
  `--introspection`.

The environment can override the ports with `AS_PORT` and `PLAIN_RS_PORT`.
The audience stays the mapped one. The launcher adds one input that
`src/server.ts` lacks: the demo's trusted approval input (below).

It writes the per-boot dev credentials, mode 0600, to
`$TMPDIR/mission-issuance-only.credentials.json` (override with
`ISSUANCE_ONLY_CREDENTIALS`): the `ap-agent` private key, which is generated
per boot (D25), the approver console's token, and the lifecycle console's
token. In a real deployment three different parties hold these three
credentials. Here the walkthrough plays all three, each step under its own
credential.

**Stopping.** The wrapper (`scripts/run-demo-ts.mjs`) runs the server process
as its only child (`node --import tsx`), forwards SIGINT, SIGTERM and SIGHUP
to it, and exits with its status. The server process closes both servers on
the first of those signals and exits 0. A SIGTERM or SIGHUP sent to the
wrapper's pid alone, or a Ctrl-C (SIGINT to the whole process group), frees
both ports:

- `the issuance-only commands under signals (#873) > SIGTERM to the launcher wrapper's pid alone stops both servers: exit 0 within 10 s and both ports free`
- `> SIGHUP to the launcher wrapper's pid alone stops both servers the same way`
- `> SIGINT to the launcher's whole process group (a terminal Ctrl-C, which reaches the server twice) stops both servers: exit 0 and both ports free`

The walkthrough wrapper works the same way and exits with the walkthrough's
status:
`the issuance-only commands under signals (#873) > the walkthrough wrapper exits with the walkthrough's status: 1 when no deployment's credentials exist`.

**Approval input, not end-user consent.** Step 2 is the demo's trusted
approval input. It is the `svc:approver-console` service principal (approver
`bob`, achieved `acr` `mfa`) behind `allowHeadlessAdjudication`, the same input
the demo stack uses (`demo/src/stack.ts`). The approver identity comes from
that registration, never from the `decide` body. It is not a browser login
and not end-user consent. A deployment replaces it with its own approver
authentication (`ApprovalSessionStore`).

**The walkthrough** (`runWalkthrough`), over real HTTP. The `mission_intent`
targets the plain RS, the `authorization_details` proposal is
`reports:report.read`, the request names no `scope`, and the Subject is
`alice`. Each step prints its request and result. Expected output, abridged:

```
1. PAR                     <- 201 {"request_uri":"urn:ietf:params:oauth:request_uri:..."}
2. Approval                <- 200 {"code":"(redacted)"}             (as svc:approver-console)
3. Code exchange           <- 200 {"token_type":"DPoP","scope":"reports.read","expires_in":300,
                                   "access_token_claims":{"aud":"http://localhost:4410/api","scope":"reports.read",
                                   "mission":{"id":"msn_...","issuer":"http://localhost:4400"},"cnf":{"jkt":"..."}}}
4. GET /api/reports        <- 200 {"reports":[]}
5. POST /api/reports       <- 403 {"error":"insufficient_scope", ... scope="reports.write" ...}
6. Revoke                  <- 200 {"id":"msn_...","state":"revoked","version":2}   (as svc:console)
6a. Refresh after revoke   <- 400 {"error":"invalid_grant"}
6b. GET after revoke       <- 200 {"reports":[]}                                    JWT only: honored until exp
6b. GET after revoke       <- 401 {"error":"invalid_token","error_description":"the access token is not active"}
                                                                                    with --introspection
```

Step 6a's refusal has two independent causes:

- the lifecycle endpoint destroys the Mission's grant on a terminal
  transition;
- the issuance gate refuses a non-active Mission.

Either alone refuses the refresh.

CI runs the same two walkthroughs in process:
- `the issuance-only walkthrough (#873) > JWT only: reports.read is issued and served, reports.write is refused insufficient_scope, and after revocation refresh is refused while the access token is still honored until exp`
- `the issuance-only walkthrough (#873) > JWT plus introspection: the same path, and after revocation the next call is refused invalid_token`

## 8. Enabled capabilities

The launcher passes `ISSUANCE_ONLY_CAPABILITIES` (`demo/src/issuance-only.ts`)
as `buildAuthorizationServer`'s `capabilities` option
(`services/authorization-server/src/adapters/capabilities.ts`). The issuance
profile is always on. Of the optional capabilities, only the lifecycle
endpoint's `revoke` is enabled. Every other one is off, and a request for it
gets the standard refusal its path already uses. With no `capabilities` set,
the assembly is the full reference provider.

How a capability is turned off:

- A custom grant that is off is not registered, so `/token` answers
  `unsupported_grant_type`. It is also removed from every client's
  `grant_types`, and the child client is not registered.
- An exchange profile that is off while the exchange grant is registered for
  another profile answers `invalid_request`.
- A lifecycle operation that is off answers `invalid_request` before any
  Mission lookup.
- An endpoint that is off answers 501 `temporarily_unavailable`, its
  unconfigured response.
- A route that is off is not served (404).
- A metadata member that is off is not advertised.

Each row with a test names it in
`demo/test/issuance-only-capabilities.test.ts`, under `the issuance-only
launcher refuses every excluded path (#873)` unless the row says otherwise.

| Capability | Status | Refusal | Test |
|---|---|---|---|
| PAR, authorization code with PKCE, DPoP-bound JWT access tokens | On | | `the issuance-only walkthrough (#873)`, both tests |
| Refresh, scope projection | On | | the same |
| Introspection (`/introspect`) | On | plain-rs calls it only with `--introspection` | `the issuance-only walkthrough (#873) > JWT plus introspection: the same path, and after revocation the next call is refused invalid_token` |
| Lifecycle `revoke` | On | | the same two walkthrough tests, step 6 |
| Lifecycle `suspend`, `resume`, `complete` | Off | 400 `invalid_request`; the Mission stays `active` | `the lifecycle suspend, resume and complete operations are refused invalid_request and the Mission stays active` |
| Async-delegation exchange (`request_refresh_token`) | Off | 400 `unsupported_grant_type` | `async-delegation token exchange (request_refresh_token) is refused unsupported_grant_type` |
| In-Mission delegation (`act` from an `actor_token`) | Off | Not implemented in the provider; it rides the async exchange, which is off | the same |
| Child Missions: creation exchange | Off | 400 `unsupported_grant_type` | `child creation token exchange (requested_token_type jwt) is refused unsupported_grant_type` |
| Child Missions: jwt-bearer redemption | Off | 400 `unsupported_grant_type`; the child client is not registered (401 `invalid_client`) | `the child jwt-bearer grant is refused unsupported_grant_type, and the child client is not registered` |
| Cross-domain projection (ICA to an ID-JAG) | Off | 400 `unsupported_grant_type` | `cross-domain continuation (ICA subject token to an ID-JAG) is refused unsupported_grant_type` |
| Cross-organization delegation chains | Off | 400 `unsupported_grant_type` | `the cross-organization chain exchange is refused unsupported_grant_type` |
| Expansion exchange | Off | 400 `unsupported_grant_type` | `the expansion exchange (requested_token_type access_token) is refused unsupported_grant_type` |
| AROP deferred grant (DTR) | Off | 400 `unsupported_grant_type` | `the AROP deferred grant is refused unsupported_grant_type` |
| Templates: dispatch grant and the admin routes | Off | 400 `unsupported_grant_type`; `/templates` and `/templates/{id}/lifecycle` answer 501 `temporarily_unavailable` | `template dispatch is refused unsupported_grant_type, and the template admin routes answer 501` |
| Containment: lifecycle `contain` | Off | 400 `invalid_request`; the Mission stays `active` at version 1 | `the lifecycle contain operation is refused invalid_request and the Mission stays active` |
| Containment: protected-event ingestion | Off | 501 `temporarily_unavailable` | `protected-event ingestion answers 501 temporarily_unavailable` |
| Entry discharge (lifecycle `discharge`) | Off | 400 `invalid_request` | `the lifecycle discharge operation is refused invalid_request` |
| Mission Status (`/missions/{id}/status`) | Off | 404, not served | `the Mission Status operation is not served (404)` |
| Mission Status List (`/statuslist/{id}`) | Off | 404 `not_found` | `the Mission Status List is not served (404 not_found)` |
| Transaction authorization (`/transaction`) | Off | 501 `temporarily_unavailable` | `transaction authorization answers 501 temporarily_unavailable`. The launcher also passes no `transactionAuthorization`, so the capability gate is shown on an assembly that wires it: `capability gates the launcher's wiring shadows, and the default assembly (#873) > an assembly that wires transaction authorization and dev issuance but leaves both capabilities off answers 501 and advertises neither` |
| Dev ordinary-token route | Off | 501 `temporarily_unavailable` | `the dev ordinary-token route answers 501 temporarily_unavailable`, and the same wired-assembly test |
| OIDC (`openid`, `profile`, `email`, `offline_access`; userinfo; RP-initiated logout) | Off | 400 `invalid_scope` at PAR, with or without a Mission Intent; `/me` and `/session/end` are not served (404). No grant can carry `openid`, so no ID Token is issued | `OIDC is off: openid is refused invalid_scope at PAR, and userinfo and RP-initiated logout are not served` |
| RFC 7009 token revocation (`/token/revocation`) | Off | 404, not served. Mission revocation is the lifecycle `revoke` | `RFC 7009 token revocation is not served (404)` |
| `mission_attenuation_supported` | Off | Not advertised. The provider parses no `mission_attenuation_root`, even with the member on | `the metadata advertises only the enabled surface` |
| `service_catalog_endpoint` | Off | Not advertised. No HTTP route serves `/service-catalog` in any assembly | the same |
| Runtime profiles (PEP, PDP, enforcement scope) | Off | Not started: no PDP, PEP or `mcp-payments` runs | |
| Mission Signals | Off | No lifecycle subscriber is injected | |

The metadata test also checks that `grant_types_supported` is `implicit`,
`authorization_code` and `refresh_token`. oidc-provider always lists
`implicit`, its token endpoint refuses it, and no client registers a response
type that uses it. The test checks too that the discovery document has none
of the off members (`mission_child_delegation_supported`,
`identity_continuation_supported`, `delegated_refresh_token_profile_supported`,
`transaction_authorization_endpoint`, `userinfo_endpoint`,
`end_session_endpoint`, `revocation_endpoint`).

**Exchange profiles behind one gate.** At the launcher every token-exchange
row is refused by the same gate, because the exchange grant is not
registered. Each profile also has its own gate inside the exchange handler,
for an assembly that registers the grant for some other profile. One such
gate is tested:
`capability gates the launcher's wiring shadows, and the default assembly (#873) > with the exchange grant registered for one profile, a disabled profile's exchange is refused invalid_request`.
The child-creation, continuation, cross-org and expansion branch gates have
no test of their own yet.

**The default stays the full provider.**
`capability gates the launcher's wiring shadows, and the default assembly (#873) > the default assembly (no capability set) is the full provider: every grant registered and every member advertised`.

A reader adopting this deployment depends only on the "On" rows.

## 9. Pinned adoption closure

**Implementation revision.** The implementation this document describes is
the commit that last changed it,
`git log -1 --format=%H -- src/docs/issuance-only-deployment.md`, or the merge
commit of the PR that published it. Check it out, then run
`pnpm install --frozen-lockfile` from `src/`.

**In-repo drafts, each at `git log -1 --format=%h -- <draft>.md`:**

| Draft | Revision | Role |
|---|---|---|
| `draft-mcguinness-oauth-mission.md` (the OAuth binding) | `5f5768e8` (the sections this deployment relies on are unchanged in substance since `4777b582`: later commits are editorial, or re-point the Intent Submission Evidence citations to its companion, which this deployment does not use) | Normative: Mission intake, derivation, approval, record, issuance, scope projection, introspection (`{#introspection}`), and the authenticated revocation means (§ Revocation, `{#revocation}`), which a deployment-defined surface satisfies |
| `draft-mcguinness-oauth-mission-resource-access.md` | `7fc9ef45` | Normative: the `mission_resource_access` type and its scope-projection conditions |
| `draft-mcguinness-mission-architecture.md` | `40d72534` (the sections relied on are unchanged since `e2dda50a`; later commits touch only the document map and the verb layers) | Informative: the entry ramp, assurance claims and the Deployment Profile shape |
| `draft-mcguinness-oauth-mission-status.md` | `4fe0d0b0` (the only change since the `9311ba74` that `SPEC_VERSIONS.md` records is the retired Status section) | Informative: the semantics the lifecycle `revoke` follows, and the revocation-propagation sizing. Section by section below |
| `draft-mcguinness-mission-control-plane.md` | `909a3ee7` | Informative: implementation discipline on the revoke path. The transition, its `nonce` claim and the response commit together (`{#serialization}`); a terminal Mission leaves a tombstone (`{#tombstones}`); lifecycle fan-out drains per request (`{#fanout}`). No claim here depends on it |
| `draft-mcguinness-oauth-mission-issuance-grant.md` | `e2dda50a` | Not relied on. The code-exchange and refresh projections (`rarThroughEffectiveSet`) cite its `{#effective-set-projection}`, which governs a consuming AS. This AS is the Mission's issuer, and with containment and discharge off the effective set is the Authority Set |

**The Mission Status companion, section by section.** The lifecycle endpoint
here is the OAuth binding's deployment-defined revocation surface
(`{#revocation}`). Its `revoke` follows these sections of the Status
companion at `4fe0d0b0`:

- § Mission Lifecycle Endpoint (`{#mission-lifecycle-endpoint}`), its
  Operations subsection: the `revoke` operation and the REQUIRED `nonce`.
  Walkthrough step 6.
- § Legal Transitions (`{#legal-transitions}`): `revoke` from `active` to
  `revoked`. Walkthrough step 6.
- § Idempotency and Conflicts (`{#idempotency}`): deduplication by
  principal, Mission and `nonce`; a byte-identical retransmit replays the
  original response; the same `nonce` on a different request is refused
  `invalid_request`; an illegal operation is 409 `conflict`.
  `control-plane lifecycle response boundary > replays a successful request before any state-dependent check, after the state moved on`,
  `> refuses a divergent retry without retaining it, leaving the committed success replayable`,
  `> conflicts on the same retry when no claim was retained, which is what the claim fixes`.
- The endpoint's Authorization subsection: a `mission_lifecycle` grant is
  required (here the `svc:console` service principal holds it), and a caller
  without it gets the not-found shape of § Error Responses
  (`{#mission-status-errors}`). No test yet for a state operation; the
  distinct discharge grant is
  `the discharge operation on the lifecycle endpoint > mission_lifecycle does not imply mission_discharge`.
- § Revocation Propagation (`{#revocation-enforcement-classes}`) and its
  Recommended Access-Token TTL subsection: the AS advertises
  `mission_max_stale_seconds` 300 (§ Authorization Server Metadata,
  `{#as-metadata}`) and issues 300 s access tokens. The JWT-only
  configuration's revocation bound is that lifetime; introspection is the
  upgrade. The value 300 at the launcher:
  `the issuance-only launcher refuses every excluded path (#873) > the metadata advertises only the enabled surface`;
  the 300 s lifetime is walkthrough step 3.

Of § Conformance's (`{#conformance}`) extensions, this deployment meets only
Revocation propagation: the advertisement and the token sizing above. It does
not claim Mission Lifecycle, because the reference endpoint's wire differs
from the companion's:

- it is `POST /missions/{id}/lifecycle` with a JSON body, not the
  `mission_lifecycle_endpoint` URL with a form-urlencoded body carrying
  `mission_id`;
- the caller authenticates with an `x-service-token` header, not mTLS, a
  sender-constrained access token or private-key JWT (the endpoint's
  Authentication subsection);
- a transition answers `{"id", "state", "version"}` JSON, not a signed
  Mission Status Response;
- `mission_lifecycle_endpoint` and its auth-methods member are not
  advertised.

Not used here: § Mission Status Operation (`{#mission-status}`), off (§8);
the Status List companion (`draft-mcguinness-oauth-mission-status-list.md`),
off (§8); `suspend`, `resume` and `complete`, off (§8); and § Token
Introspection Mission Projection (`{#introspection-projection}`). The
introspection response carries the OAuth binding's `mission` member
(`{#introspection}`), with no `fresh_until`, and is not RFC 9701-signed.

**RFCs used on this path:**

- RFC 6749 (OAuth 2.0)
- RFC 6750 (bearer tokens and the `WWW-Authenticate` challenge)
- RFC 7515 (JWS), RFC 7517 (JWK) and RFC 7519 (JWT)
- RFC 7523 (`private_key_jwt` client authentication)
- RFC 7636 (PKCE)
- RFC 7638 (JWK thumbprint, `cnf.jkt`)
- RFC 7662 (introspection)
- RFC 7800 (`cnf`)
- RFC 8707 (resource indicators)
- RFC 9068 (JWT access tokens)
- RFC 9126 (PAR)
- RFC 9396 (RAR, `authorization_details`)
- RFC 9449 (DPoP)
- RFC 3986 (URIs)

**Dependencies, from `src/pnpm-lock.yaml`:**

| Package | Version | Used by |
|---|---|---|
| `oidc-provider` | 9.10.0 | the AS |
| `jose` | 6.2.3 | the AS (`^6.1.3`), plain-rs (`^6.1.3`), and `oidc-provider` itself |
| `better-sqlite3` | 12.11.1 | the Mission kernel store (`@mission/store`) |
| `tsx` | 4.23.1 | the launcher and walkthrough |
| `pnpm` | 11.15.1 | `packageManager` |
| Node.js | `>=22` (`engines`) | oidc-provider supports the v22 LTS; the shell runs below used v23.10.0, for which oidc-provider prints an "Unsupported runtime" warning |

## 10. Status

A proposed reference deployment. It is not an owner-accepted conformance
class and makes no production-readiness claim.

This document is the documentation foundation for #873: the deployment
contract, the claim and residual matrix, a hook inventory, and an index of
existing evidence. #873 still requires the following before it closes:

- **`src/docs/provider-integration-port.md`:** the full obligation matrix,
  covering the transaction and acceptance boundary, permitted asynchronous
  work, crash and recovery behavior, public-surface test, and residual for
  each obligation.
- **The executable acceptance pack's missing cases:**
  - revoke-during-issuance and failure after reservation or artifact
    acceptance (tied to #250);
  - restart and uncertain-recovery behavior for any persistence claim.
