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
#873; §7 lists what that issue still requires.

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
it on every request and honors only `active` (`introspectActive`). Each
request makes a fresh POST, and no result is cached. A non-200 status, a
network failure, or a malformed body refuses 503 `temporarily_unavailable`
before the operation runs. A missing or non-`true` `active` refuses 401
`invalid_token`. No request timeout is configured, so an introspection
endpoint that hangs stalls the request. Only the `active: false` case has a
test (`` plain-rs introspection mode > honors only `active`: an inactive token is refused even when its JWT is valid, and an introspected scope grants nothing ``);
outage, malformed body, missing `active`, and timeout have no test yet. A
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

- **Access tokens:** 300 seconds (`config/topology.json`
  `ttls.accessTokenSeconds`). A deferred token is clamped to its approval
  expiry; child and dispatch tokens are clamped to the Mission's `expires_at`.
- **Refresh tokens:** oidc-provider's 14-day default (`ttl.RefreshToken` in
  `buildProvider`). A delegation-family refresh token is clamped to the
  Mission's `expires_at`.
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
  `plain-rs` applies none to `exp` and accepts DPoP proofs within ±60 seconds
  of `iat` (`dpopWindowSeconds`). One synchronized clock is assumed across the
  AS and the Resource Servers.
- **Stores:** the Mission kernel, grants, the token issuance index
  (`TokenIssuanceStore`) and the delegation-family store are in memory by
  default (`src/docs/control-plane-deployment.md`).

## 3. Behavior by path

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
| Delegate calling the plain RS | Not supported: a delegated (`act`-bearing) token is refused for it, and the refusal never creates a Child Mission. Child Missions are a separately enabled capability, not enabled here (the plain RS ceiling entry has no `delegation.children`, `kernel/child-delegation.ts`) | Refusal: the delegated-routing row above; Child Mission path: not enabled, no test |
| Token expiry | `plain-rs` refuses an expired token; it applies no `exp` tolerance | `plain-rs RFC 9068 / RFC 9449 validation > refuses a wrong typ, a wrong audience or issuer, and an expired token`; the exact clock-tolerance boundary: no test yet |
| Introspection unavailable or malformed (introspection configuration) | 503 `temporarily_unavailable` and no operation; missing or non-`true` `active` is 401 `invalid_token`; no timeout configured | `introspectActive`; `active: false`: the introspection-mode test above; outage, malformed body, missing `active`, and timeout: no test yet |
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
    "delegated (act-bearing) tokens are refused for plain-rs, with no automatic Child Mission fallback; Child Missions are not enabled",
    "no cancellation of admitted work: a check completed before revocation does not stop an admitted request",
    "no token-only authorization_details-consuming Resource Server is part of this deployment: payments is the runtime composition, and mcp-saas accepts RAS-issued tokens",
    "evidence is the AS's issuance records only: the Mission Record, its lifecycle events, and the per-token issuance index",
    "plain-rs logs nothing Mission-linked",
    "a projection refusal on a single-use path (deferred redemption, child jwt-bearer, dispatch, expansion poll) lands after that path's own consumption",
    "a restart is not revocation: consumers holding the old key keep accepting pre-restart tokens until exp, and plain-rs rejects post-restart tokens until its JWKS cache refreshes (up to 10 minutes)",
    "introspection has no configured timeout, so an unresponsive endpoint stalls requests",
    "provider token acceptance and derivation counting are not coupled atomically (#250)",
    "grants, the issuance index and the delegation-family store are in memory",
    "the scope-projection mapping's integrity is repository review; it is not fetched or signed",
    "Intent-only requests depend on an oidc-provider workaround (a marked, AS-written authorization_details)",
    "the decision-time scope check projects the derived set without capability_sources, so a catalog-sourced scope_only entry can pass at the decision and refuse at the token endpoint",
    "a repeated decision on one interaction binds a second grant to the committed record",
    "scope refusals on the ICA continuation, child creation and expansion initiation, explicit scope on the child, dispatch and expansion-poll mints, and the JWT-customizer backstop have no test yet"
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
| Token past `exp` at the plain RS | 401 `invalid_token` | No ledger row covers `plain-rs` | `plain-rs RFC 9068 / RFC 9449 validation > refuses a wrong typ, a wrong audience or issuer, and an expired token` |
| Introspection outage, timeout, malformed body, missing `active` | 503 `temporarily_unavailable` or 401 `invalid_token`, no operation | No ledger row covers `plain-rs` | No test yet |
| Revocation cutting off an introspecting plain RS | Next call denied (401 `invalid_token`) | `core.introspection.composite-active`; `core.grant-binding.termination-gates-every-binding` is still todo and does not cite this test | `revocation with a scope-only Resource Server (@spec mission#scope-projection) > after the Mission is revoked, refresh refuses invalid_grant, introspection returns active false, and the plain RS in introspection mode denies the next call` |

The reference cannot tell an audience that was never mapped from one removed
from the mapping: both have no current entry and refuse the same way. The
endpoint tests remove the entry between approval and issuance. The strict
loader runs when `packages/demo-data` is imported (`SCOPE_PROJECTION`), so a
mapping that fails it stops the AS before any issuance.

## 7. Status

A proposed reference deployment. It is not an owner-accepted conformance
class and makes no production-readiness claim.

This document is the documentation foundation for #873: the deployment
contract, the claim and residual matrix, a hook inventory, and an index of
existing evidence. #873 still requires the following before it closes:

- **Runnable configurations:** startup and configuration instructions for the
  JWT-only and introspection configurations, the approval and token requests,
  and a successful `reports.read` call. Also the enabled-capability list and
  the pinned adoption closure.
- **`src/docs/provider-integration-port.md`:** the full obligation matrix,
  covering the transaction and acceptance boundary, permitted asynchronous
  work, crash and recovery behavior, public-surface test, and residual for
  each obligation.
- **The executable acceptance pack's missing cases:**
  - expiration and clock-tolerance boundaries;
  - introspection outage, timeout, malformed body, and missing `active`;
  - revoke-during-issuance and failure after reservation or artifact
    acceptance (tied to #250);
  - restart and uncertain-recovery behavior for any persistence claim.
