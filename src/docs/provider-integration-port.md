# Provider integration port

The provider integration port is the set of obligations a Mission-aware
Authorization Server meets where its OAuth provider and its Mission store
meet. This document maps each obligation to the hook the reference AS uses on
the issuance-only path, and states for each one the transaction boundary, the
permitted asynchronous work, the crash and recovery behavior, the
public-surface test, and what is unsupported. Section 5 does the same for
the runtime overlay of the AS-native payments target: the obligations its PEP
and PDP meet when they consume what this AS issued and committed. It documents
the reference implementation at this revision. Each behavioral statement cites a function or
an exact test (`describe > it`). A statement with no witnessing test says
"no test yet". A statement taken from reading code alone says "code reading".

Paths are relative to `src/`. `provider.ts` is
`services/authorization-server/src/adapters/provider.ts`, `kernel.ts` is
`services/authorization-server/src/kernel/kernel.ts`, and `index.ts` is
`services/authorization-server/src/index.ts`. oidc-provider file and line
references are to version 9.10.0 under `lib/`. Tests are in
`services/authorization-server/test/` unless a path is given.

## 1. Purpose and scope

- **The port.** oidc-provider owns the OAuth objects: interactions, grants,
  authorization codes, refresh tokens, and access-token signing. The Mission
  kernel owns the Mission Record, its lifecycle, and its derivation counter.
  Each Mission obligation runs inside or beside a provider step. The port is
  that set of steps.
- **The path.** The issuance-only deployment: the reference AS and
  `plain-rs`, in the JWT-only and the JWT-plus-introspection configurations.
  Topology, claims and the evidence index are in
  [issuance-only-deployment.md](issuance-only-deployment.md). Its §4 hook
  inventory is the starting point here.
- **The runtime overlay.** The AS-native payments target (#253, D284) adds the
  `mcp-payments` PEP and the reference PDP to this path. Its deployment
  contract is [initial-runtime-deployment.md](initial-runtime-deployment.md);
  §5 maps its obligations.
- **Not covered.** Delegation families, Child Missions, expansion, deferred
  tokens, templates and cross-domain paths share some hooks. They are not part
  of this path and appear only where a shared hook behaves differently for
  them.

Five stores take part. No transaction spans two of them. The runtime overlay
adds its own stores (the deployment contract's §7).

| Store | Holds | Persistence |
|---|---|---|
| Kernel database (`MissionKernel.db`) | Mission Records, `derivation_count`, `grant_id`, lifecycle events and outbox, tombstones, derivation reservations, lifecycle and creation replay rows | In memory by default. A file-backed single writer is an opt-in (`kernelStore.file` on `buildAuthorizationServer`). `server.ts` uses the default. |
| oidc-provider adapter | Interactions, grants, authorization codes, refresh tokens | In memory. `buildProvider` configures no `adapter`, so oidc-provider's memory adapter applies. |
| `MissionBoundGrantStore` (`kernel.missionBoundGrants`) | Grant id to Mission, append-only | Its own in-memory handle, built per boot, also when the kernel is file-backed |
| `TokenIssuanceStore` | (`iss`, `jti`) to the grant id that minted the token | Its own in-memory handle, built per boot |
| `DelegationFamilyStore` | Family grant id to Mission | Its own in-memory handle, built per boot |

## 2. Desired contract

The spec family's contract is derive-and-commit: the AS derives the
authority, commits the Mission, and binds and gates every artifact against
that commit. In brief, with the anchors in `draft-mcguinness-oauth-mission.md`:

1. **Approval input.** The AS authenticates the Approver. It takes the
   Approver's identity and achieved authentication context only from the
   surface that resolved the approval, never from client input
   (`{#approval-event}` step 1; `{#approval-authentication}`).
2. **Subject.** The Subject is the Approver, or a principal the Approver is
   authorized under local policy to approve for. An external Subject maps
   injectively to a local `sub` (`{#approval-event}` step 2).
3. **Source and authority.** The authority source comes from trusted
   configuration. Activation and the source ceiling are separate checks. The
   derived Authority Set is rendered, and the anchors cover the context
   actually approved, recomputed when it changes before the decision
   (`{#approval-event}` steps 3, 5 and 6; `{#authority-sources}`;
   `{#integrity-anchors}`).
4. **Record and grant binding.** The Mission Record is created `active`
   atomically with issuance of the authorization code, with the expiry
   recheck in that commit. The code's grant lineage resolves to exactly one
   Mission, and a refresh-token family inherits the binding atomically with
   its issuance (`{#approval-event}` step 7; `{#grant-binding}`).
5. **Issuance.** Each derivation resolves the Mission from the presented
   grant, requires it `active`, emits only subsets, meets scope projection,
   and gives each token an `exp` no later than the Mission's `expires_at`. A
   derivation answered after the AS acknowledged a revocation is refused
   (`{#issuance-gating}`; `{#mission-bound-tokens}`).
6. **Refresh and revocation gating.** A refresh is a derivation, gated the
   same way. Revocation is an authenticated operation by `mission_id`. An
   issued token stays valid until it expires (`{#lifecycle}`;
   `{#revocation}`).
7. **Scope projection.** A `scope`-only target receives a projection proven
   safe against its current trusted mapping, or no token. A refusal caused only
   by the projection leaves the refresh token valid (`{#scope-projection}`).
8. **Protected introspection.** The caller is authenticated and an audience of
   the token. Each response is an observation for one decision, with no
   caching semantics. `active: true` requires a valid token and an `active`
   Mission (`{#introspection}`; `{#caller-authorization-and-minimization}`;
   `{#composite-active}`).

The control-plane companion (`draft-mcguinness-mission-control-plane.md`,
`{#serialization}`) names counter checks and artifact issuance as one atomic
domain. This deployment makes no completed serialization claim
([control-plane-deployment.md](control-plane-deployment.md)).

**A method name is not an atomicity claim.** `kernel.approve`,
`kernel.bindGrant` and `kernel.gateDerivation` each write kernel-local state
only. None of them includes a provider write, and the provider offers no
transaction the kernel can join. Where this document says "commit", it names
the store.

## 3. The matrix

| Obligation | Required for this path | Provider hook | Transaction or acceptance boundary | Permitted asynchronous work | Crash and recovery | Public-surface test | Unsupported or residual |
|---|---|---|---|---|---|---|---|
| Trusted approval input and achieved authentication context | Yes, both configurations | `/interaction/{uid}/decide` route, then `decide()` (§3.1) | In request, before any write; no commit of its own | None | Approval sessions and pending interactions are in memory and are lost; nothing to recover | Yes, HTTP (§3.1) | Achieved context checked, not retained; no render-to-decision binding (§3.1) |
| Canonical Subject resolution and approve-for authorization | Yes | `decide()`: the approval surface's Subject selection, `knownSubjects`, `approverApprovesFor`, `approverRoleSubs`; the Approver as provider account (§3.2) | In request, before `kernel.approve` | None | Configuration only; nothing to recover | Yes, HTTP (§3.2) | External Subject unsupported and refused (§3.2) |
| Source and authority derivation | Yes | `kernel.derive`; the source gates in `kernel.approve` (§3.3) | Computed before the record transaction | None | Nothing written before §4.1 | Yes, HTTP; gate detail is kernel-level (§3.3) | Decision-time `scope` check ignores `capability_sources` (§3.3) |
| Record and grant binding | Yes | `kernel.approve` and `insertRecord`; `grant.save()`; `kernel.bindGrant`; the code on the resume request (§3.4) | Only the record commit is transactional (§4.1); grant, binding and code are separate writes | Publication of the activating event | A crash before binding leaves an orphan `active` Mission; provider state is lost at restart (§4.5) | Partial (§3.4) | `{#approval-event}` step 7 atomicity not met; a repeated decision binds a second grant (§3.4) |
| Issuance | Yes | `at.save()`: `extraTokenClaims`, `formats.customizers.jwt`, `access_token.issued` (§3.5) | The counter `UPDATE` autocommits before signing; no acceptance callback (§4.2) | None before delivery | The count stays consumed; nothing reconciles it (§4.3) | Yes, HTTP (§3.5) | Uncoupled counter: a failure after the count stays counted (§4.3); revoke-versus-issue window (§3.5) |
| Refresh and revocation gating | Yes | `rotateRefreshToken`; the gates in `extraTokenClaims`; the lifecycle route (§3.6) | The lifecycle commit is one kernel transaction; grant destruction follows it | Grant destruction and publication | File-backed state survives; provider grants do not (§4.5) | Yes, HTTP (§3.6) | A state change between the refresh pre-check and the save-time gate is refused after rotation consumes the presented token (§3.6; #250); a fully contained family is refused after rotation, losing no recoverable issuance authority (§3.6) |
| Scope projection | Yes (`plain-rs` is `scope_only`) | `earlyScopeRefusal`; the decision check; `decideMissionScope`; `preCheckRefreshProjection`; the JWT customizer (§3.7) | In request, before the state gate and before refresh consumption; reads only | None | The mapping is configuration, strictly loaded at boot | Yes, HTTP (§3.7) | Code-exchange refusal after code consumption; JWT-customizer backstop has no test (§3.7) |
| Protected introspection | JWT-plus-introspection configuration only | `/introspect` route in `makeRoutes` (§3.8) | Per-request read of current kernel state; may commit an expiry | None | Index and keys are per boot; pre-restart tokens introspect `active: false` | Yes, HTTP (§3.8) | No test for a signed token with no issuance record (§3.8) |

### 3.1 Trusted approval input and achieved authentication context

- **Hook.** The `POST /interaction/{uid}/decide` route in `makeRoutes`
  refuses, with 400 `invalid_request`, a body naming `approver`, `subject`,
  `approver_acr` or `approver_auth_time`, and any `decision` other than
  `approve` or `deny`. The principal comes from `ApprovalSessionStore.resolve`
  (session cookie, CSRF token and interaction uid, on a request with no
  `Origin` or the issuer's origin). When
  `allowHeadlessAdjudication` is set, it may instead come from a registered
  service token holding the `mission_approval` scope (`validApprovalPrincipal`).
  No principal, or an `auth_time` in the future, is 401. `decide()` then checks
  the requested `acr_values` and `max_age`, and `prompt=login`, which
  oidc-provider substitutes for `max_age=0`, against the principal's `acr` and
  `auth_time` (`approverAuthenticationSatisfies`). A miss finishes the
  interaction `access_denied`.
- **Boundary.** In request. Nothing is written before these checks pass.
- **Asynchronous work.** None.
- **Crash and recovery.** `ApprovalSessionStore` is an in-process `Map`, and
  the pending interaction is in oidc-provider's memory adapter. Both are lost
  at restart. The client starts a new authorization request.
- **Tests (HTTP, `demo/test/approval-resolution-identity.test.ts`):**
  - `approval resolution establishes identity from the surface (#759, #761) > refuses every identity-bearing body member loudly, even with a valid approver credential`
  - `approval resolution establishes identity from the surface (#759, #761) > enabled headless mode refuses all agent-held credentials and cookies for both approve and deny, then the independent approver succeeds`
  - `approval resolution establishes identity from the surface (#759, #761) > independent browser login requires its own session, CSRF, origin, and interaction binding`
  - `approval resolution establishes identity from the surface (#759, #761) > a service token without the approval scope cannot resolve, even though it authenticates other console operations`
  - `approval resolution establishes identity from the surface (#759, #761) > headless mode defaults off and a service approver cannot bypass that default`
  - `approval resolution establishes identity from the surface (#759, #761) > requested authentication strength is checked against the surface context, including stale authentication`
- **Tests (HTTP, `rar-carriage.test.ts`):**
  - `Approver Authentication Strength (@spec mission#approval-authentication, issue #636) > same-principal: a self-approved Mission satisfies a requested acr_values`
  - `Approver Authentication Strength (@spec mission#approval-authentication, issue #636) > split-principal: the Approver's authentication never becomes the Subject's: openid refuses, and the token carries the Subject and none of the Approver's authentication`
  - `Approver Authentication Strength (@spec mission#approval-authentication, issue #636) > max_age=0 refuses a stale Approver authentication`
  - `Approver Authentication Strength (@spec mission#approval-authentication, issue #636) > an unsupported acr is refused`
- **Residual.**
  - The achieved `acr` and `auth_time` are checked and not retained. The
    record's `approver` is `{iss, sub}` (`kernel.approve`), so the issuance
    evidence does not show the achieved context.
  - The decision carries no digest of the rendered page. `decide()`
    re-derives from the interaction's immutable pushed parameters and current
    configuration, and `kernel.approve` computes the anchors over that. A
    configuration change between render and decision would commit the
    recomputed context without a fresh render. Whether any shipped
    configuration can change during an interaction: not verified. No test yet.
  - `renderApprovalPage` renders the Intent, including its requested
    `expires_at`, and no separately computed effective expiry. The shipped
    `max_mission_lifetime_s` is `null` (`config/policy.json`), so the two are
    equal here.

### 3.2 Canonical Subject resolution and approve-for authorization

- **Hook.** In `decide()`, the Subject is the selection the authenticated
  approval surface made (`ApprovalPrincipal.subject`: recorded by the trusted
  browser login, or named by a headless approval service on
  `x-approval-subject`), else the Approver. `login_hint` concerns the Approver
  and selects nothing. The Subject must be in `knownSubjects`, and an Approver
  other than the Subject must hold it in `approverApprovesFor`; otherwise 403
  `approval_forbidden`. `buildAuthorizationServer` builds `knownSubjects` from
  the configured users and the authority-source principals, and
  `approverApprovesFor` from each user's `approves_for`. A write-bearing
  Authority Set needs a distinct Approver with the approver role
  (`approverRoleSubs`, D37); otherwise 403. Inside `kernel.approve`,
  `establishAuthoritySource` applies the source's subject discipline (gate 4).
- **Boundary.** In request. The identity checks run before derivation and the
  write-bearing check after it. All run before `kernel.approve`.
- **Asynchronous work.** None.
- **Crash and recovery.** Configuration only; nothing to recover.
- **Tests (HTTP):**
  - `approval resolution establishes identity from the surface (#759, #761) > the Subject is the approval surface's selection, authorized for the Approver, never the client's login_hint` (`demo/test/approval-resolution-identity.test.ts`)
  - `approval resolution establishes identity from the surface (#759, #761) > write-bearing distinctness and role checks run over the resolved identities` (same file)
  - `authority source on the approval surface (@spec mission#authority-sources) > refuses access_denied at the decision when the subject discipline fails` (`rar-carriage.test.ts`)
- **Kernel principal namespace (#829).** The kernel accepts only canonical
  local principals: a Subject and an Approver whose `iss` is byte-equal to the
  kernel's principal namespace, `principalIssuer` in `KernelOptions` (default:
  the kernel's `issuer`). The authority-source catalog is bound to that
  namespace at kernel construction, and every source gate
  (`assertApproverMayActivate`, `assertSubjectDiscipline`) refuses a foreign,
  missing, or malformed tuple `access_denied` before comparing `sub`.
  `kernel.approve` refuses one before derivation. Template consent and
  dispatch refuse one before their idempotent returns, so a retry cannot
  reuse an event ID with a different namespace's principal. This holds for a
  direct kernel caller as well as this adapter, which always builds
  principals in the kernel's namespace.
- **Approver and Subject identities (#826).** The provider account and Grant
  are the Approver's: `interactionFinished` logs the Approver in with the
  achieved `acr` and authentication time, never the Subject. A browser
  approval keeps that session. A headless approval leaves none: its user
  agent is the client's, so the resume runs without the session cookie that
  user agent holds, the session the login created is destroyed before the
  response is flushed and its cookie removed, and the code is not
  session-bound (`expiresWithSession`). Every
  Mission-bound access token carries the Subject: `formats.customizers.jwt`
  sets `sub` from the Mission its grant resolves to, failing closed when it
  no longer resolves, and refresh-token introspection reports the Subject,
  not the token's account. `findAccount` (`accountFinder`) knows no account
  for an id outside the deployment. `openid` asks for an ID Token about the
  End-User this interaction authenticated: it is refused `invalid_scope`
  before `kernel.approve` when the Approver is not the Subject, and on a
  headless approval, where no End-User authenticated in this user agent.
  oidc-provider accepts `acr_values` and `max_age` only with `openid`, so a
  delegated request cannot name an Approver strength: PAR refuses it
  `invalid_request` before any interaction. That is the accepted limitation
  (D305): client-requested strength on a delegated approval, including a
  client registration's incompatible OIDC defaults, is unsupported and fails
  closed, never ignored or downgraded. The issuer's published approval floor
  governs the Approver's strength, and no other carrier is defined.
  Tests (HTTP, `approver-subject-separation.test.ts`):
  `Approver and Subject stay separate identities (@spec mission#approval-authentication, #826)`,
  every case.
- **Unsupported.** External Subjects. `decide()` always records `subject.iss`
  as this AS's issuer, and there is no injective external-to-local mapping. An
  unknown Subject selection is refused 403 `approval_forbidden`, so nothing is
  approved under an unrecognized identity. Matching is exact string equality
  on the configured `sub` values. A deployment that admits identities from
  another namespace maps each to a canonical local principal first, through
  its own separately trusted mapping. The kernel does not map by equal `sub`,
  and rewriting a request's `iss` does not establish a mapping.

### 3.3 Source and authority derivation

- **Hook.** `kernel.derive` runs at render (`GET /interaction/{uid}`) and again
  in `decide()`. `kernel.approve` derives once more, attaches and resolves
  capability sources (`attachCapabilitySources`, `resolveFreshCapabilities`),
  runs `establishAuthoritySource` (gates 1, 2, 4 and 5) and
  `assertAuthorityWithinSource` (gate 3) on one resolution, and computes
  `authority_hash`, `intent_hash` and, with a proposal, `proposal_hash`.
  `insertRecord` re-asserts the source ceiling against that resolution, or
  for a drawdown against its origin's committed root, records the Mission's
  binding in the record transaction, and re-asserts the discharge mappings
  (`assertDischargePoliciesResolvable`). Each refusal is an
  `IntentError`; `decide()` finishes the interaction with its code
  (`access_denied` for the source gates).
- **Per-principal resolution (#827).** Gate 1 selects one root for the
  authenticated client and the issuer-qualified Subject, through the
  `authoritySourceResolver` in `KernelOptions` (default: the resolver over the
  trusted catalog). Catalog entries may share a client when each declares
  disjoint `subjects`; a duplicate root id or an overlapping selection refuses
  construction. The kernel holds the Subject to its namespace before the
  resolver runs, and refuses `access_denied` when the resolver is unavailable
  or answers for a different Subject, client, deployment or source.
  `kernel.approve`, Expansion and template consent each resolve once per
  completion. The render consults the same resolver: for the Subject the
  approval session selected, or with none through `resolveForRendering`,
  which answers only a provenance every Subject of the client shares and
  otherwise refuses.
  Gate 4's human-principal list stays kernel configuration; it can only
  refuse.
- **Committed roots (#827).** Every Mission records the root it committed
  (`authority_source_bindings`: root id, deployment, root context and
  provenance), private and outside every anchor. Each path's root follows its
  approval basis. A child inherits its parent's root and that root's context,
  whatever client the child presents. Template consent records each
  recipient pair's root, the pairs sharing one provenance, and dispatch uses
  the dispatching Subject's own. A carryover replacement takes its rendered
  origin's root. Direct approval and Expansion resolve fresh. A drawdown
  resolves its origin's root through the resolver's `resolveCommittedRoot`,
  which never rebinds: a removed root, a changed provenance or policy digest,
  or a root whose client or Subject selector no longer selects its own
  context refuses.
- **Synchronous resolution.** The resolver is synchronous by contract: it runs
  inside an approval completion, whose record commit is one synchronous store
  transaction. A remote resolver answers from a snapshot and revalidates at
  commit, never awaiting network I/O inside the transaction. Source authority
  is consulted at each approval completion and drawdown; nothing monitors it
  in between (#830).
- **Boundary.** Computation over configuration and the pushed parameters,
  before the record transaction (§4.1). The two re-assertions in
  `insertRecord` run before its transaction opens.
- **Asynchronous work.** None.
- **Crash and recovery.** Nothing is written before §4.1.
- **Tests (HTTP, `rar-carriage.test.ts`):**
  - `authority source on the approval surface (@spec mission#authority-sources) > renders the user-delegated source and approves`
  - `authority source on the approval surface (@spec mission#authority-sources) > renders the organizational source with the governed policy it draws on`
  - `authority source on the approval surface (@spec mission#authority-sources) > refuses access_denied when the Approver may not activate the source`
  - `derivation refusal at the authorization decision (@spec mission#error-mapping) > configured-mapping mode (no proposal) that derives nothing is access_denied`
  - `derivation refusal at the authorization decision (@spec mission#error-mapping) > a submitted proposal that derives nothing is invalid_authorization_details`
  - `authority source rendering for a shared agent registration (@spec mission#approval-event, mission#authority-sources, #827) > renders the source of the Subject the approval session selected, never one login_hint names, and refuses to render one that depends on an unnamed Subject` (`authority-source-render.test.ts`)
- **Tests (kernel-level, not the public surface):**
  - `authority source establishment (@spec mission#authority-sources, mission#approval-event) > refuses access_denied when the derived Authority Set exceeds the source ceiling` (`authority-source.test.ts`)
  - `authority source establishment (@spec mission#authority-sources, mission#approval-event) > establishes the source from configuration alone: ApproveInput carries no source member` (same file)
  - `authority source drawdown (@spec mission#authority-sources, child-delegation#child-creation) > a drawdown refuses access_denied when the source narrowed since approval` (same file)
  - `principal-specific source resolution (@spec mission#authority-sources, mission#approval-event, #827)`, every case (same file)
- **Residual.** The decision-time `scope` check in `decide()` projects
  `kernel.derive`'s output, which has no `capability_sources`; `kernel.approve`
  attaches them afterwards. `scopeValueSafeForEntry`
  (`packages/mission-core/src/scope-projection.ts`) treats an entry carrying
  `capability_sources` as never safe. A catalog-sourced `scope_only` entry can
  therefore pass at the decision and refuse `invalid_target` at the token
  endpoint. Code reading; no test yet.

### 3.4 Record and grant binding

- **Hook.** In `decide()`, in order:
  1. `kernel.approve`, then `insertRecord`: the authoritative Mission commit
     (§4.1). The `approval_event_id` is `apev_{interaction uid}`, `UNIQUE` in
     the `missions` table. A repeat returns the stored record
     (`findByApprovalEvent`).
  2. `new provider.Grant(...)` with the request's OIDC and resource scopes
     and the effective Authority Set as its `rar`, then `grant.save()`: a
     provider adapter write.
  3. `kernel.bindGrant`: `UPDATE missions SET grant_id`, then
     `missionBoundGrants.record`. Two writes on two handles, in no shared
     transaction.
  4. For an Intent-only request, `details.save()` of the marked
     `authorization_details` (§7).
  5. `interactionFinished`: a 303 to the resume URL (`lib/provider.js`
     L229-233). oidc-provider issues the authorization code on that later
     request.

  The authorization code's lifetime is clamped to the Mission's `expires_at`
  like every other credential; a resume reached with under one second of
  Mission left, or after it, redirects `access_denied` and issues no code.

  The refresh token inherits the binding by construction: `createRefreshToken`
  copies the code's `grantId` (`lib/helpers/grant_common.js`).
- **Resolution.** `kernel.findByGrant`, then the delegation-family store, then
  the grant index through `missionForBoundGrant`, which refuses `invalid_grant`
  when the index names a grant whose Mission no longer resolves.
  `MissionBoundGrantStore.record` keeps the first Mission for a grant id
  (`ON CONFLICT DO NOTHING`).
- **Boundary.** Only step 1 is transactional. Steps 2 and 3 and the code are
  separate writes, in two stores and two requests.
- **Asynchronous work.** Publication of the activating lifecycle event after
  the step 1 commit (the outbox, [control-plane-deployment.md](control-plane-deployment.md)).
- **Crash and recovery.** On the file-backed kernel, a crash after step 1 and
  before step 3 leaves an `active` Mission with `grant_id` null and no index
  row. The interaction was in provider memory, so nothing can resume it.
  Nothing derives from that Mission and nothing reconciles it; it stays
  `active` until `expires_at` or a revocation. Code reading; no test yet. On
  the in-memory default the crash loses all of it.
- **Tests:**
  - `approval event and record (@spec mission#integrity-anchors) > creates an active record with both anchors and is idempotent by approval_event_id` (kernel-level, `kernel.test.ts`)
  - `unresolvable Mission fails closed (@spec issuance-grant#effective-set-projection) > the Mission's OWN code-flow grant fails closed the same way once its record is purged` (HTTP, `async-delegation.test.ts`)
  - `unresolvable Mission fails closed (@spec issuance-grant#effective-set-projection) > a LIVE Mission whose grant_id column has moved on still refreshes, gated and claimed through the index (never a false refusal, never a claimless token)` (HTTP, same file)
  - `unresolvable Mission fails closed (@spec issuance-grant#effective-set-projection) > the index is the discriminator: it survives the Mission's deletion, and an unknown grant resolves undefined (the pass-through case)` (same file)
  - `the Intent-only completion workaround is never a client proposal (@spec mission#authority-proposal) > an Intent-only Mission commits no proposal_hash, and re-rendering or re-deciding the same interaction still reads no proposal` (HTTP, `scope-projection.test.ts`): it decides twice on one interaction and asserts two `approve` calls and one proposal-free record. It does not assert the number of grants.
- **Unsupported or residual.**
  - `{#approval-event}` step 7 is not met. The record commits `active` before
    the grant exists, and one request before the code is issued. A client
    that never follows the redirect leaves an `active` Mission with a bound
    grant and no code. No test yet.
  - A repeated decision on one interaction binds a second grant to the
    committed record. `kernel.approve` returns the stored record, and
    `decide()` saves and binds a new grant each time. `missions.grant_id`
    names the latest grant; the index keeps both.
  - A lineage resolving to more than one Mission is not detected:
    `findByGrant` returns the first matching row. Each `bindGrant` call in
    `decide()` uses a grant id saved just before it, so this path does not
    reach that case. Code reading; no test yet.

### 3.5 Issuance

- **Hook.** oidc-provider's `authorization_code` grant consumes the code
  (`lib/actions/grants/authorization_code.js` L89) and then calls `at.save()`
  (L127). Inside `save()` (§7), `extraTokenClaims` runs
  `projectMissionBoundScope` and then `kernel.gateDerivation`, and returns the
  `mission` claim. `formats.customizers.jwt` applies the projected `scope`.
  oidc-provider signs the token and emits `access_token.issued`, whose
  listener `recordTokenIssuance` writes the `TokenIssuanceStore` row. After
  `save()` returns, `createRefreshToken` (L129, through `issueRefreshToken`)
  and `issueIdToken` (L133) run. Middleware in `buildProvider` then sets the
  response `scope` and, for `authorization_code`, `mission_id` and
  `mission_expires_at`.
- **`gateDerivation`.** The state half (`gateDerivable`: the expiry clock in
  its own write, `active`, the ancestor walk, a non-empty effective set) runs
  first. Then `countDerivationInCallerTx` runs one
  `UPDATE missions SET derivation_count = derivation_count + 1` whose
  condition is the cap alone. Both are synchronous better-sqlite3 calls with
  no `await` between them, so no other request runs between them in the one
  process. This path has no caller transaction, so the `UPDATE` autocommits.
- **Boundary.** §4.2. The count commits before the token is signed. No
  transaction spans the count, the signature and the index row.
- **Asynchronous work.** None before delivery, and none is used.
- **Crash and recovery.** §4.3 and §4.5.
- **Tests (HTTP):**
  - `M1 tracer slice > authorization redirects to the interaction; headless approval by Bob issues a code` (`tracer.test.ts`)
  - `M1 tracer slice > token exchange yields a DPoP-bound JWT AT with the mission claim and RAR echo` (`tracer.test.ts`; the `authorization_code` exchange)
  - `scope projection at the token endpoint (@spec mission#scope-projection) > a safe projection carries exactly the projected scope, and the plain RS allows the in-scope operation and refuses the other with 403 insufficient_scope` (`scope-projection.test.ts`)
  - `mission_error wire carriage: derivations_exhausted (@spec mission#error-mapping) > a Mission capped at requested_derivation_limit 1 refuses its second derivation with invalid_grant + mission_error=derivations_exhausted` (`tracer.test.ts`)
  - `async-delegation single count (@spec async-delegation) > regression: an ordinary code-flow refresh STILL increments derivation_count` (`async-delegation.test.ts`)
  - `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > code exchange: the access token, refresh token and authorization code all expire no later than a Mission ending inside their lifetimes` (`exp-clamp.test.ts`)
  - `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > a rotating refresh: the rotated refresh token and the new access token expire no later than the Mission` (`exp-clamp.test.ts`)
  - `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > a credential minted with under one second of Mission left is refused, never given a 0 s or overrunning lifetime` (`exp-clamp.test.ts`)
  - `credentials never outlive the Mission (@spec mission#mission-bound-tokens) > an authorization resumed with under one second of Mission left redirects access_denied, never invalid_grant, and issues no code` (`exp-clamp.test.ts`)
  - `async-delegation terminal paths (@spec async-delegation) > fractional-second boundary: a family refresh token lives exactly until expires_at, and a family refresh with 0.9 s left is refused mission_expired with no refresh token saved (@spec mission#mission-bound-tokens)` (`async-delegation.test.ts`)
- **Tests (kernel-level):** `single-process control-plane fault boundaries > a derivation admitted from a stale snapshot cannot overshoot the cap` (`control-plane-faults.test.ts`).
- **Unsupported or residual.**
  - The counter is not coupled to the token it pays for (§4.3; #250).
  - **`exp` is bounded by `expires_at` on every mint.** The `ttl` configuration
    in `buildProvider` sets `AccessToken`, `RefreshToken`, `AuthorizationCode`
    and `IdToken` through one clamp, `clampToMission`: oidc-provider's
    configured lifetime, or the Mission's remaining whole seconds, whichever is
    shorter. A delegation-family refresh token has no configured cap, so it
    lives exactly until `expires_at`. The Mission resolves from the token's
    grant as issuance resolves it (`kernel.findByGrant`, the family store, the
    bound-grant index), and a grant that was never Mission-bound keeps the
    configured lifetime unchanged. oidc-provider evaluates a lifetime before
    `extraTokenClaims` runs the gate (`lib/models/formats/opaque.js` L28 before
    L39), and saves a rotated refresh token before the access token is gated
    (L168 before L216), so the hook meets an expired Mission first. It never
    returns 0, a negative lifetime, or a 1 s floor: past `expires_at` it runs
    `gateActive`, which commits the expiry and refuses as the gate does, and
    with under one second left it refuses too. A token-endpoint mint refuses
    `invalid_grant` `mission_expired`; the authorization code, minted at the
    authorization endpoint's resume, refuses `access_denied`
    (`{#error-mapping}`, an authorization decision refused by AS policy),
    because RFC 6749 Section 4.1.2.1 defines no `invalid_grant` there. The
    deferred, child, dispatch, async-delegation and expansion mints keep their
    own clamps, whose 1 s floors the access-token clamp overrides; the hook
    also bounds the deferred token, which its own clamp bounded only by
    `approved_until`, and the family refresh's access token, which took a flat
    300 s.
  - **A refresh after `expires_at` is refused by the refresh token's own
    expiry,** before the gate: `invalid_grant` with no `mission_error`, and no
    lazy expiry commit. This holds for the approval grant and a delegation
    family alike.
  - **Revoke versus issue.** Between the gate and the signature, `save()`
    awaits the customizer and `JWT.sign`. A lifecycle request can commit and
    acknowledge a revocation in that window, and the gated token is still
    signed and returned. `{#issuance-gating}` refuses a derivation answered
    after an acknowledged revocation. Code reading; no test yet; #250 owns the
    race (§4.6).
  - No operation identity: a retry after a lost token response is a new,
    separately counted derivation (§4.4).

### 3.6 Refresh and revocation gating

- **Refresh hook.** oidc-provider's `refresh_token` grant checks the
  token's client, expiry and sender constraint, any requested `scope`, and
  the grant (`lib/actions/grants/refresh_token.js` L55-118). It then awaits
  `rotateRefreshToken` (L133-135), where `probeAuthoritySource`,
  `preCheckRefreshProjection` and `preCheckRefreshMissionState` run. When
  rotation applies, it consumes the
  presented token (L137) and saves the rotated one (L168). Then
  `rarForRefreshTokenResponse` re-projects the grant's `rar` through the
  effective set (`rarThroughEffectiveSet`, L212), and `at.save()` (L216) runs
  `extraTokenClaims`. That gate is `gateDerivation` for a Mission approval
  grant, and `gateActive` for a family grant or an index hit whose
  `grant_id` has moved. A `GateError` becomes `invalid_grant`
  (`MissionGrantError`). Where a value applies (`mission_revoked`,
  `mission_expired`, `derivations_exhausted`), the `grant.error` listener adds
  `mission_error`; a suspended Mission gets none.
  Both saves evaluate the token's lifetime (`clampToMission`) before any gate,
  so the rotated refresh token, a family token included, is never saved past
  the Mission's `expires_at`. The presented token is still consumed first
  (L137).
- **State pre-check (#914).** `preCheckRefreshMissionState` runs the save-time
  gate's checks in `rotateRefreshToken`, before consumption, with nothing
  counted. It resolves the grant's Mission the same way (`missionGateTarget`)
  and runs `kernel.checkDerivation` for an approval grant (the expiry clock,
  the lineage walk, the effective-set gate and the cap read, with no counter
  write) or the same `gateActive` for a family grant or an index hit. A family
  refresh is therefore never counted and never refused for the Mission's cap. A
  `GateError` maps through the same `missionGateRefusal`, so the wire refusal
  is unchanged. It is non-consuming, not read-only: an expiry it discovers
  commits, as the gate's does. The save-time gate still runs and stays
  authoritative.
- **Rotation rule.** `rotateRefreshToken` always rotates a family grant.
  Otherwise it inlines oidc-provider's default (`lib/helpers/defaults.js`
  L528-547): rotate a public client's token that is not sender-constrained,
  else rotate once 70 percent of the lifetime has passed.
- **Revocation hook.** `POST /missions/{id}/lifecycle` in `makeRoutes`,
  authenticated by a service token. `kernel.materializeExpiry` commits any
  expiry first, in its own transaction. One `withTransaction(kernel.db, ...)`
  then commits `kernel.transition` (state, version, event row and, for a
  terminal state, the tombstone) with the nonce-keyed outcome. After that
  commit, outside it, the handler awaits `provider.Grant.find(record.grant_id)`
  and `destroy()` for a state other than `active` or `suspended`. Family grants are revoked by the
  durable subscriber `delegation-family-grant-revoke` (`index.ts`).
- **Boundary.** The lifecycle commit is one kernel transaction. The
  approval-grant destruction is a separate provider write with no retry row.
  The refresh gate is the read-then-count of §3.5.
- **Asynchronous work.** Grant destruction and lifecycle publication may lag
  the commit. The gate refuses first, so the lag widens no authority at the
  AS.
- **Crash and recovery.** On the file-backed kernel the transition, its
  version and its tombstone survive a restart, and an unpublished event is
  replayed ([control-plane-deployment.md](control-plane-deployment.md)). A
  crash between the commit and the approval-grant destruction loses that grant
  anyway, because the provider store is in memory. A family revocation has a
  durable delivery row that `recoverAtBoot` drains. No assembly-level restart
  test (§4.5).
- **Tests (HTTP):**
  - `M1 tracer slice > suspend gates refresh with invalid_grant; resume restores issuance` (`tracer.test.ts`)
  - `M1 tracer slice > revocation destroys the grant: refresh fails and introspection reports the state` (`tracer.test.ts`)
  - `revocation with a scope-only Resource Server (@spec mission#scope-projection) > after the Mission is revoked, refresh refuses invalid_grant, introspection returns active false, and the plain RS in introspection mode denies the next call` (`scope-projection.test.ts`). It revokes through `kernel.transition`, not the lifecycle route, so the gate alone refuses.
  - `refresh pre-check: a refused refresh consumes nothing (@spec mission#issuance-gating, #914) > rotating approval grant: a refresh refused while suspended saves no refresh token, the same token refreshes after resume, and its replay is still reuse` (`refresh-precheck.test.ts`)
  - `refresh pre-check: a refused refresh consumes nothing (@spec mission#issuance-gating, #914) > delegation-family grant: a family refresh refused while suspended saves no refresh token, the same token refreshes after resume, and its replay is still reuse` (`refresh-precheck.test.ts`)
  - `refresh pre-check: a refused refresh consumes nothing (@spec mission#issuance-gating, #914) > approval grant with an exhausted derivation cap: refused derivations_exhausted without counting or consuming, so the same token is refused by the gate again, never as reuse` (`refresh-precheck.test.ts`)
  - `refresh pre-check: a refused refresh consumes nothing (@spec mission#issuance-gating, #914) > delegation-family grant over an exhausted cap: the family refresh is not refused for the Mission's cap and counts nothing` (`refresh-precheck.test.ts`)
  - `refresh pre-check: a refused refresh consumes nothing (@spec mission#issuance-gating, #914) > residual: a suspension landing between the pre-check and the save-time gate is still refused by that gate, after rotation (#250)` (`refresh-precheck.test.ts`)
  - `a fully contained family is refused after rotation, within the owner's boundary (#914 ruling 3) > (a) and (b): a family whose ENTIRE confined subset is contained is refused, while a sibling family and the approval grant with surviving authority still refresh` (`async-delegation.test.ts`)
  - `a fully contained family is refused after rotation, within the owner's boundary (#914 ruling 3) > boundary: a family whose confined subset is only PARTLY contained narrows and is not refused` (`async-delegation.test.ts`)
  - `a fully contained family is refused after rotation, within the owner's boundary (#914 ruling 3) > (c): an Expansion successor is authorized from a Mission access token, never from the contained family's consumed refresh token` (`async-delegation.test.ts`)
- **Tests (kernel-level):**
  - `lifecycle (@spec status#legal-transitions) > gates derivation on state and derivation cap (@spec mission#lifecycle)` (`kernel.test.ts`)
  - `kernel.gateActive (@spec mission#lifecycle) > a non-active (suspended) mission throws GateError` (`gate-active.test.ts`)
  - `basic governance gate: state-gated issuance and derivation (@spec mission-substrate#basic-gate) > a persisted state value outside the recognized lifecycle set fails closed, never treated as active` (`kernel.test.ts`)
- **Unsupported or residual.**
  - **The state pre-check is a partial fix.** A refresh refused for Mission
    state, lineage, effective set or cap is refused before rotation when the
    pre-check detects it, so the presented token stays valid and works after a
    `resume`. A suspension, or another derivation, landing between the
    pre-check and the save-time gate is still refused there, after the
    presented token is consumed and a rotated one saved: after a `resume` the
    client's token is reuse, and oidc-provider revokes the grant
    (`refresh_token.js` L121-127). Only refusals detected before rotation
    consume nothing. Closing that window is #250's cross-step atomic domain.
  - **A fully contained family is refused after rotation.** A delegation family
    whose effective authority is entirely contained is refused at the `rar`
    hook (L212), after the presented token is consumed and a rotated one saved,
    because the family's gate checks live state only. No recoverable issuance
    authority is lost, because three conditions hold: (a) the family's ENTIRE
    authority is contained, not merely what this refresh requested, and a
    family that is only partly contained narrows instead, as the effective-set
    projection does; (b) the refusal invalidates no other family or grant that
    still has authority; (c) restoring the authority goes through an Expansion
    successor, authorized from a Mission access token, never by redeeming the
    consumed refresh token. These conditions permit the refusal after rotation;
    they do not require that ordering. Moving it before rotation would be an
    implementation improvement, not a change to family authorization semantics.
  - The JWT-only `plain-rs` keeps accepting an issued token until its `exp`
    plus the clock tolerance (the revocation test above;
    `issuance-only-deployment.md` §2).
  - Revocation destroys only `record.grant_id`. A grant bound by an earlier
    repeated decision (§3.4) remains in the provider store. A refresh against
    it is still refused, through `missionForBoundGrant` and then
    `gateActive`. Code reading; no test yet.
  - The approval-grant destruction has no durable retry. The gate is the
    backstop.

### 3.7 Scope projection

- **Hooks.** One decision, several call sites:
  - PAR: `earlyScopeRefusal` in the `mission_intent` `extraParams` handler
    refuses `invalid_scope` for a resource value at an
    `authorization_details` target, or one the mapping does not name.
  - Decision: `projectScope` in `decide()`, before any Mission exists. It
    refuses `invalid_scope` only; mapping and safety failures are left to the
    token endpoint.
  - Token endpoint: `projectMissionBoundScope`, then `decideMissionScope`,
    from `extraTokenClaims`, before the state gate.
  - Refresh: `preCheckRefreshProjection`, from `rotateRefreshToken`, before
    consumption.
  - Signing: `formats.customizers.jwt` writes the decided `scope`. It refuses
    `invalid_target` for a Mission-bound token the projection did not decide,
    and for an `act`-bearing token to an audience the mapping does not
    classify Mission-aware.
  - Recording: `issueRefreshToken` and the response-`scope` middleware (§7).
- **Boundary.** In request, read-only against the mapping loaded at boot
  (`SCOPE_PROJECTION`, `loadScopeProjection`). The token-endpoint call runs
  before `gateDerivation`, so a refusal there counts nothing. The refresh
  pre-check runs before consumption.
- **Asynchronous work.** None.
- **Crash and recovery.** The mapping is configuration. A mapping that fails
  the strict load stops the AS before any issuance
  (`issuance-only-deployment.md` §6).
- **Tests (HTTP, `scope-projection.test.ts`).** The scope-projection rows of
  `issuance-only-deployment.md` §3 and §6, among them:
  - `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refused rotating refresh leaves the same refresh token valid: once the trusted mapping is repaired it succeeds once, and its reuse gets the ordinary replay treatment`
  - `ungrantable requested scope (@spec mission#scope-projection, mission#error-mapping) > refuses invalid_scope at PAR a resource scope for an authorization_details target, and a value the scope-only target's mapping does not name`
  - `ungrantable requested scope (@spec mission#scope-projection, mission#error-mapping) > refuses invalid_scope at the authorization decision a mapped value no carried entry makes safe, before any Mission exists`
  - `scope projection at the token endpoint (@spec mission#scope-projection) > refuses invalid_target for an audience the mapping does not know`
  - `scope projection on derived tokens (@spec mission#scope-projection) > Token Exchange projects the family token's scope from its confined subset, keeps it on the family refresh, and refuses an unenforced constraint before creating a family`: asserts `derivation_count` is unchanged after the refusal.
- **Tests (unit, `packages/mission-core/test/scope-projection.test.ts`):**
  `projectScope (@spec mission#scope-projection) > an unknown mapping refuses invalid_target even when the request names a scope value`.
- **Unsupported or residual.**
  - At the code exchange the projection runs after the code is consumed
    (`authorization_code.js` L89, then L127). A refusal there spends the
    code. `issuance-only-deployment.md` §5 states the same for the
    single-use deferred, child, dispatch and expansion mints; not re-verified
    here.
  - No test asserts `derivation_count` after a projection refusal on the code
    or refresh path. The Token Exchange tests above assert it on their path.
  - The JWT-customizer backstop has no test.
  - The decision-time check ignores `capability_sources` (§3.3).

### 3.8 Protected introspection

- **Hook.** `POST /introspect` in `makeRoutes`. oidc-provider's own
  introspection feature stays at its disabled default (`features` in
  `buildProvider`). The steps, in order:
  1. `authenticateIntrospection`: HTTP Basic against `config/introspection.json`,
     compared in constant time; 401 `invalid_client` otherwise.
  2. A `token` parameter; 400 `invalid_request` otherwise.
  3. `jwtVerify` against the AS's keys, with the expected issuer and
     `typ: at+jwt`.
  4. The RFC 9068 claim set, a well-formed `mission` claim, and well-formed
     `authorization_details`.
  5. `kernel.get(mission.id)`, with `mission.issuer` equal to the record's
     issuer.
  6. An audience the caller is registered for.
  7. `kernel.introspectionProjection`, which applies the expiry clock. A
     non-active Mission answers `active: false` with `mission.state`.
  8. `TokenIssuanceStore.resolve` and `isGrantLive`.
  9. The token's own `authorization_details`, intersected with the current
     effective set and audience-minimized (`projectThroughEffective`,
     `resourcesForAudiences`).

  A failure in steps 3 to 6, or in step 8, is a bare `active: false`. A
  refresh token takes a parallel branch through `provider.RefreshToken.find`.
- **Boundary.** Each call reads current kernel state. `applyExpiry` can commit
  an `expired` transition during the read. The AS caches nothing. The route
  itself sets no `Cache-Control` header (code reading). `plain-rs` makes a
  fresh call for every request and caches nothing (`introspectActive`;
  `plain-rs introspection failure contract (#873) > introspects every request: two requests make two calls, and a positive first result does not admit the second once the endpoint says active false`).
- **Asynchronous work.** None.
- **Crash and recovery.** The issuance index, the provider grants and the
  signing keys are per boot. A pre-restart token fails verification against
  the new keys, and would miss the index if it verified. Both answer
  `active: false`. Fail closed; no assembly-level restart test.
- **Tests (HTTP):**
  - `composite non-active: active:false WITH mission.state (@spec mission#composite-active) > revoked Mission + valid token: only { active, mission }, state revoked, NO top-level or mission authorization_details` (`introspection-endpoint.test.ts`)
  - `caller authentication (@spec mission#caller-authorization-and-minimization) > refuses an unauthenticated call with 401 + WWW-Authenticate` (`introspection-endpoint.test.ts`)
  - `strict token resolution: bare active:false, no Mission or token detail > wrong-audience caller: the ENTIRE response is minimized` (`introspection-endpoint.test.ts`)
  - `Mission-bound refresh tokens (@spec mission#introspection) > Mission revocation reports the composite even though it destroys the grant` (`introspection-endpoint.test.ts`)
  - The revocation test of §3.6 runs `plain-rs` against the reference AS. The `plain-rs introspection failure contract (#873) > ...` tests (`services/plain-rs/test/plain-rs.test.ts`) run it against a stub endpoint (`issuance-only-deployment.md` §2).
- **Residual.**
  - No test presents a correctly signed token whose `jti` has no issuance
    record. The crafted tokens in `introspection-endpoint.test.ts` reuse a
    real `jti`. No test yet.
  - A check completed before a revocation does not cancel a request it
    admitted (`issuance-only-deployment.md` §1).

## 4. Commit and acceptance points

### 4.1 The authoritative commit for a Mission

`insertRecord`'s `withTransaction` on the kernel database is the one
authoritative commit. It holds the expiry invariant
(`created_at < expires_at <= intent.expires_at`), the tombstone nonreuse
check, the `missions` row with its anchors, the discharge pins, and the
activating lifecycle event with its outbox row (`emitCommit`). Publication
runs after the commit. The provider grant, the binding and the code follow in
other stores (§3.4). On the file-backed kernel this commit survives a restart;
on the in-memory default it does not.

### 4.2 The token acceptance point

The reference has no acceptance point in the sense of
[control-plane-deployment.md](control-plane-deployment.md)'s reservations: the
provider access-token hook offers neither an operation identity nor an
acceptance callback. The observable points inside `AccessToken#save()`, in
order:

1. `extraTokenClaims`: projection, state gate, counter `UPDATE`
   (autocommitted in the kernel database).
2. `formats.customizers.jwt`.
3. `JWT.sign`.
4. `emit('issued')`, then `recordTokenIssuance` writes the `TokenIssuanceStore`
   row (in-memory handle). From here introspection can answer `active: true`
   for the token.
5. `save()` returns; then refresh-token creation, the ID token, and the
   response.

A JWT-only Resource Server accepts the token from step 3 on, without the AS
knowing it was delivered. No authoritative issuance commit exists across the
provider and Mission stores. Defining one is #250's first acceptance item
(§4.6).

### 4.3 Failed-issuance counting

- **Counts nothing:** a projection refusal (it runs before the gate); a gate
  refusal (the `UPDATE` does not run, or changes no row at the cap); any
  client, code or grant refusal before `at.save()`.
- **Counts, and never returns the count:** any failure after the `UPDATE`.
  That covers a customizer refusal, a signing failure, a throw from the index
  listener, on the code path a refresh-token or ID-token failure, a response
  lost in transit, and a process exit. No reservation row exists for these, so
  `recoverAtBoot` has nothing to mark `unacknowledged` and nothing refunds. The
  count is the only record that a derivation was spent:
  `a derivation that fails after admission (@spec mission#issuance-gating, #914 ruling 1) > residual: the provider access-token hook counts before signing, so a code exchange that fails after the count leaves the failed derivation counted (#250)`
  (`derivation-counting.test.ts`).
- **Where reservations apply.** The ID-JAG and attenuation-root paths use
  `reserveDerivation` and its recovery
  ([control-plane-deployment.md](control-plane-deployment.md); the
  `control-plane derivation reservations > ...` tests in
  `control-plane-faults.test.ts`). They are not on this path.
  At the token endpoint, the ID-JAG continuation's deterministic refusals
  run before admission and count nothing (the audience-scoped authority
  check). A continuation grant that fails after admission, which a state
  change between that check and the gate can cause, leaves its reservation
  `reserved` and the count spent until an authoritative non-acceptance
  returns it; the reservation is keyed by the grant's own `jti`, so no retry
  replays it. The test drives that failure at `issueCrossDomainGrant`, not
  through the endpoint:
  `a continuation ID-JAG that fails after admission (@spec mission#issuance-gating, #914 ruling 1) > residual: a continuation grant that fails after admission leaves the derivation counted under an unreleased reservation, until an authoritative non-acceptance returns it`
  (`continuation-grant.test.ts`).
- **Rolled back:** the async-delegation creating exchange counts inside the
  transaction that commits the family, so a failure before that commit
  returns the count:
  `a derivation that fails after admission (@spec mission#issuance-gating, #914 ruling 1) > async-delegation creating exchange: a failure after the cap check, inside the commit, rolls the count back`
  (`derivation-counting.test.ts`).

### 4.4 Replay and idempotency

- **Approval.** `approval_event_id` (`apev_{uid}`) is `UNIQUE`. A repeat
  decision returns the stored record and emits no second activating event
  (`kernel.approve`). The grant is not idempotent: each decision saves and
  binds a new one (§3.4).
- **Authorization code.** Single use. oidc-provider refuses a consumed code
  and revokes its grant (`authorization_code.js` L84-87). No test in this
  repository.
- **Refresh token.** Reuse of a consumed refresh token is refused and revokes
  the grant (`refresh_token.js` L121-127), witnessed by
  `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refused rotating refresh leaves the same refresh token valid: once the trusted mapping is repaired it succeeds once, and its reuse gets the ordinary replay treatment`.
  A non-rotating refresh token can be presented again, and each use is a new
  derivation.
- **Access-token issuance.** No operation identity. A retry after a lost
  response is a fresh derivation, counted again. An earlier token, if it was
  signed, stays valid until `exp`. No recorded artifact is replayed.
- **Lifecycle operations.** Nonce-keyed replay of the committed outcome
  ([control-plane-deployment.md](control-plane-deployment.md)).

### 4.5 Reconciliation and startup recovery

`buildAuthorizationServer` awaits `kernel.recoverAtBoot()` after the provider
exists. It marks deliveries owed to removed subscribers, drains the outbox,
prunes settled rows and tombstone detail, and marks unreleased reservations
`unacknowledged` (`kernel.ts`). For this path, a restart on the file-backed
kernel leaves:

- **Retained:** Mission Records, their committed authority-source roots,
  `derivation_count`, `grant_id`, lifecycle events and tombstones.
- **Lost:** provider interactions, grants, codes and refresh tokens. Every
  outstanding refresh token is unknown, and oidc-provider refuses it
  `invalid_grant` (`refresh token not found`).
- **Empty:** `TokenIssuanceStore`, `MissionBoundGrantStore` and
  `DelegationFamilyStore`.
- **Regenerated:** the signing keys (D25). A pre-restart access token fails
  introspection. A Resource Server with a cached JWKS keeps accepting it until
  `exp` (`issuance-only-deployment.md` §2).
- **Stranded:** an `active` Mission whose grant is gone. Nothing can derive
  from it, and it stays `active` until `expires_at` or a revocation.

Committed authority-source roots are the one thing reconciled at kernel
construction (#827). A row that predates them gains one only from trusted
evidence: an explicit mapping (`authoritySourceReconciliation.mappings`,
Mission ID to root ID), or a declared historical catalog in force at its
approval (`.history`) in which exactly one root selected its client, Subject
and provenance. The approval instant follows the approval basis: a template
instance's is its template's consent (`approval_basis.approved_at`), not its
dispatch. A match in the current catalog is never evidence. A derived
row takes its origin's root; a row without evidence stays unbound and every
drawdown from it refuses. Nothing else on this path is reconciled, because it
has no reservations to settle.
Each unsupported recovery refuses rather than serves. No test boots the
assembled AS on a file-backed kernel. The restart test,
`restart recovery on the declared file-backed store > recovers the unpublished commit, the version high-water and the tombstone across a restart`
(`control-plane-fanout.test.ts`), is kernel-level.

### 4.6 Where #250 owns the open work

Issue #250 owns control-plane consistency, including cross-store atomicity. Its
2026-09-16 acceptance items map onto this port:

| #250 acceptance item | Port points it would close |
|---|---|
| Define the authoritative issuance commit point and durable operation and artifact identity across the provider and kernel path | §4.2, §4.3 |
| Revoke versus issue, crash after reservation, an accepted artifact with a lost acknowledgement, and replay without refund or duplicate issuance | §3.5, §4.3, §4.4 |
| Assembly-level restart recovery for outstanding credentials and required indexes and projections, with explicit refusal where recovery is unsupported | §4.5 |
| Restore to an older snapshot under a recovery admission or fencing mechanism | Rollback resistance stays partial ([control-plane-deployment.md](control-plane-deployment.md)) |

The latest owner status on #250 also lists `expected_version` with 409, the
durable projections with a rollback witness, and the emergency rows and
closure. Multi-process serialization stays with #641. This document claims
none of that work.

These gaps are not named in #250's items, and their owner is not verified:

- the approval commit ordering against code issuance (§3.4);
- external Subjects (§3.2).

The state gate after rotation (§3.6) is partly fixed by the refresh pre-check
(#914). What remains, a state change between the pre-check and the save-time
gate, is the pre-check-to-commit window of #250's cross-step atomic domain.

## 5. Runtime overlay: the AS-native payments target

The AS-native payments target adds a runtime overlay to this path. The
`mcp-payments` PEP and the reference PDP decide each mediated action on a
token this AS issued. The deployment contract,
[initial-runtime-deployment.md](initial-runtime-deployment.md), holds the
operation allowlist, the per-class bounds and the fail-closed table (its §4),
the store and restart table (§7) and the acceptance vectors (§10). This
section maps each overlay obligation to its hook, read at origin/main
`01874fd5`; statements about the as-native target (#1105) are true at
`7ed2505b`, and every `file:line` citation is read there.

In this section `pep.ts` and `server.ts` are under `services/mcp-payments/src/`,
`evaluate.ts`, `fga.ts`, `policy.ts` and `idempotency-claims.ts` are under
`services/pdp/src/`, and `stack.ts` is `demo/src/stack.ts`. Everything runs in
one process. The PDP is a direct call by default, with no PEP
authentication (`services/pdp/src/decision-channel.ts:56-61`).
`MISSION_PDP_MODE=remote` adds a loopback HTTP hop keyed by a per-boot secret
that is never configured, so it cannot cross processes as shipped (`:64-66`).
Most tests cited here drive the PEP (`enforce`), the in-process
`mcp-payments` server methods or the PDP directly, not the MCP transport.
Tests marked
[FGA] are skipped without a live OpenFGA. The AS-native target and its
acceptance pack are HTTP MCP with verified DPoP (D315): they reach the PEP
only through the endpoint `composeStack({ target: "as-native" })` serves at
the declared resource audience, and exclude the in-process mediated channel.
The target's AS runs the issuance profile plus exactly `lifecycle-revoke`
and `transaction-authorization`, arms no dev ordinary issuance, and refuses
each of the other 15 optional capabilities with its standard error (D332;
the contract's §2 maps each to its witness). Ordinary-token minting is a
test-only composition option that the launcher refuses.
[FGA]
`the as-native target over HTTP MCP with DPoP against a live OpenFGA (D315) > carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read`
drives an AS-issued Mission-bound token through that assembled path.

| Obligation | Required for this path | Hook | Transaction or acceptance boundary | Permitted asynchronous work | Crash and recovery | Public-surface test | Unsupported or residual |
|---|---|---|---|---|---|---|---|
| Credential validation | Yes. Credential authority at the PDP is not met: acceptance gate (#825) | HTTP: `validateCredential` with a DPoP proof, then `verifyDpopBoundToken`. In-process mediated channel: `validateCredential` without one, then `validateMissionToken`. Both: `missionBoundFactsFrom`, `readMissionAccessClaims`, the PEP's credential-authority check (§5.1) | In request, before any claim is a decision input | None | DPoP replay cache and signing keys are per boot; a pre-restart token fails validation | HTTP transport and PEP-level (§5.1) | The PDP neither receives nor evaluates the credential authority (#825 PRs 2a, 2b; D312); the mediated channel proves no possession, so high-consequence claims hold on HTTP only (§5.1) |
| Independent Resource policy | Yes, not met: acceptance gate (#828) | The PDP's OpenFGA check and action-to-relation map (§5.2) | In the decision | None | Nothing durable; the tuple is injected per check | PDP-level, [FGA] (§5.2) | The shipped model cannot deny independently of Mission authority (§5.2) |
| Protected state and lifecycle | Yes | `loadView`, forwarded at `context.mission_state_observation`; the PDP's own view (§5.3) | Read per decision, inside the request; a fresh decision at each commit phase | None | Reads the floor's kernel (§4.5); no cache | PEP- and PDP-level (§5.3) | Local committed read only (D293); a separated source is #1101's; run to completion inside the permit (§5.3) |
| Target and parameter binding | Yes | `buildEffectiveParams`, `parameterDigest`; at use, `verifyPermitAtUse` (phase, expiry), `reverifyCapability`, and `reverify` or `reverifyList` (digest) (§5.4) | Read and write paths write nothing before the effect; the transaction tier redeems the permit, writing operation state, before the digest check (§5.4) | None | The payments store is reseeded per boot; a crash after redemption leaves a claim that closes `indeterminate` | Server-level, [FGA] (§5.4) | A single-record read re-derives no digest at use; the Operation Profile's intake rules are not implemented (#1106) (§5.4) |
| Permit redemption | Transaction tier and keyed writes | The PDP's Exact claim; `TransactionEngine.redeemPermit`; the PEP write reservation (§5.5) | Claim insert in one PDP transaction; then redemption, effect, evidence and settlement as separate writes. A keyed write is one local transaction | None; settlement is awaited | Claim and reservation files survive, but a restarted PEP cannot reconcile a prior claim (§5.7); engine redemption records are lost (§5.5) | Server- and PDP-level, [FGA] (§5.5) | `hold_transfer` has no permit control (#1080); one redemption per operation key per process (§5.5) |
| Evidence | Yes | The PDP's emitter; `recordRefusal`, `suppressExecution`; the executor's `completed` write (§5.6) | Synchronous in the request; Decision Evidence is verified before release | None | Retention is in memory and lost at restart | PEP-level (§5.6) | A failed `completed` write after a connector commit is silent (#1104); no Execution Evidence on a successful call outside the transaction tier (§5.6) |
| Recovery and reconciliation | Declared by the Enforcement Scope Statement | `reconcileClaims`, `reconcile`, the reservation `sweep()` (§5.7) | None runs | Reconciliation would be the overlay's only asynchronous work | A prior process's claim closes `indeterminate` and its key stays refused (§5.7) | PEP-level restart witness (§5.7); the PDP crash boundary (§5.5) | No production caller and no alert (#1103) |

### 5.1 Credential validation

- **Hook.** Two entry points reach the same claim checks, and only one proves
  possession.
  - **HTTP transport** (`services/mcp-payments/src/mcp-http-transport.ts:264`):
    `validateCredential` with the request's DPoP presentation calls
    `validateToken`, which runs `verifyDpopBoundToken` (`server.ts:495-512`):
    signature, issuer, audience, `cnf.jkt` and the DPoP proof over this
    request. The target serves this entry point at the declared resource
    audience. A MAS-governed route calls `validateGatewayCredential` instead;
    the target mounts none (D315). Each MCP session belongs to the holder
    whose credential opened it (`cnf.jkt`, subject and client): every request
    is authenticated before its session is resolved, and another holder's
    request on the session is answered 404 `Session not found`
    (`createHttpMcpChannel`).
  - **In-process mediated channel** (`services/mcp-payments/src/mcp-transport.ts:121`,
    `:147`): `validateCredential` with no proof calls `validateMissionToken`
    (`server.ts:657-670`): signature, issuer and audience. It carries
    `cnf.jkt` into the token facts but verifies no proof of possession,
    because the channel has no HTTP request to bind one to. It refuses a
    transaction token (`txn_pop_required`), so a challenged retry goes over
    HTTP. The demo agent (`pnpm agent`, through `createMediatedHarness`) uses
    this channel with AS-issued Mission-bound tokens. The AS-native target
    and its acceptance pack exclude it (D315).

  Both then apply `missionBoundFactsFrom` (`server.ts:523-556`) and
  `readMissionAccessClaims`
  (`services/mcp-payments/src/token-verifier.ts:108-120`): `typ` `at+jwt`, the
  RFC 9068 claims, a `mission` claim with `id` and `issuer`, and the token's
  own `authorization_details`, read as the credential's authority. A token
  that fails the profile is refused, never demoted to the ordinary class.
  Before the PDP is asked, the PEP refuses `out_of_authority` for an action
  outside that authority, one whole entry at a time (`pep.ts:1331-1365`).
- **Boundary.** In request, before any claim reaches a decision.
- **Asynchronous work.** None.
- **Crash and recovery.** The DPoP replay cache is in memory. Signing keys are
  generated per boot (D25), so a pre-restart token fails signature
  validation. The PEP fetches the AS JWKS once at assembly (`stack.ts:472`);
  refresh is #831's.
- **Tests:**
  - `HTTP mediated MCP channel (harness duty 2 + DPoP proof-of-possession over HTTP) > 4a: DISCRIMINATING token-without-a-DPoP-proof (valid token, no proof header; and the bearer scheme) is rejected at the gate BEFORE the PEP -- zero evidence/ledger; a valid DPoP client on the SAME server then permits` (HTTP transport)
  - `HTTP mediated MCP channel (harness duty 2 + DPoP proof-of-possession over HTTP) > 4b: DISCRIMINATING mismatched-key (DPoP proof signed by a DIFFERENT key than cnf.jkt) is rejected BEFORE the PEP -- zero evidence/ledger; a valid DPoP client on the SAME server then permits` (HTTP transport)
  - `the PEP establishes token validity before using any of its claims as decision inputs (@spec runtime#token-validation) > a token whose audience does not name this resource is refused, before any of its claims reach a decision (@spec runtime#token-validation, audience)` (PEP-level)
  - `the Mission access-token profile is met before any claim is trusted (@spec runtime-oauth#token-validation, #825) > admits a conforming at+jwt over HTTP and the mediated channel, carrying its own authority` (both entry points)
  - `the Mission access-token profile is met before any claim is trusted (@spec runtime-oauth#token-validation, #825) > never demotes a Mission-bound token that fails its profile to the ordinary class on a gateway route` (PEP-level)
  - `the credential authority bounds the action the PEP resolved (@spec runtime#input-authority, #825) > refuses vendor lookup under an invoice-only token, and lets a broad token reach the PDP, on the same broad Mission` (PEP-level)
  - [FGA] `M5 transaction-assurance tier > refuses a transaction credential on the transport that cannot prove possession (@spec txn-authorization#offline-verification)` (mediated channel)
  - `the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision`, `the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision` and `the as-native target with the test-only ordinary-token minting fixture, OpenFGA client stubbed (D315, D332) > refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it` (HTTP transport, assembled path)
  - `the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > binds a session to the holder that opened it: every request on it is authenticated, and another holder's credential carrying its id is answered 404 Session not found before the PEP` (HTTP transport, assembled path) and `MCP sessions on the HTTP channel (D315, #1105) > dispatches a request on a session only for its holder: another key, subject or client is answered 404 Session not found and reaches no handler, and a refused credential is answered 401` (HTTP transport, stubbed payments server)
- **Required, not met.** The PDP neither receives nor evaluates the
  credential authority: it matches the kernel's current Authority Set
  (`evaluate.ts:1110-1117`). D312 splits the rest of #825 into three PRs: 2a
  pins each signing key to its token role; 2b adds the
  `context.credential.authority` carrier, PDP enforcement independent of the
  PEP, the PEP pre-check redesign and `context.credential.expires_at`
  validation; 2c audits the issuance paths. Today credential expiry is checked
  at validation only, and the PDP records `context.credential.expires_at`
  without denying on it.
- **Residual.** On the in-process mediated channel every action, the
  high-consequence classes included, runs on a token whose possession is not
  proven. D240 requires a current proof of possession for a credential used
  on a high-consequence action (`runtime.custody.high-consequence-credential-sender-constrained`,
  `todo`). The AS-native target and its acceptance pack therefore exclude
  this channel (D315), and the gap stays documented here. #825 records the
  limitation; a shared verifier never claims a proof it did not receive.

### 5.2 Independent Resource policy

- **Hook.** After the Mission-authority gates, the PDP asks OpenFGA for the
  relation `policy.ts:19-31` maps the action to (`fga.ts:20-47`).
- **Boundary.** In the decision.
- **Asynchronous work.** None.
- **Crash and recovery.** Nothing durable. The tuple is injected per check.
- **Tests:**
  - [FGA] `PDP decisions against OpenFGA (@spec authzen) > out-of-authority action -> deny out_of_authority` (PDP-level)
  - `finding 3: a multi-vendor list_invoices names every returned vendor to Resource policy, not just one representative (@spec read-binding) > Mission authority includes two vendors; Resource policy denies one: the whole read refuses out_of_authority, never a narrowed result` (PEP-level, stubbed policy)
  - `runtime decision gates are independently necessary (@spec runtime#decision) > a stale freshness failure denies even though authority and the Resource-policy/FGA check both permit` (PDP-level)
- **Required, not met.** The relations admit only `mission` subjects, and the
  injected tuple mirrors the triple being checked, so the shipped model cannot
  deny independently. A stubbed denial is `out_of_authority`,
  indistinguishable from a Mission-authority denial. #828.

### 5.3 Protected state and lifecycle

- **Hook.** `loadView` (`stack.ts:781-788`) reads the kernel's committed state
  and version for each decision, with `mode: "fresh"` and `freshness_at` set
  to now. Under PEP placement the PEP forwards that observation at
  `context.mission_state_observation`, and the PDP's own view wins on
  disagreement. D293 accepts this read as the co-located target's declared
  local source; it is not a Mission Status wire call.
- **Boundary.** Per decision, inside the request. A commit phase takes a fresh
  decision. An admitted high-consequence action is not re-checked after
  `enforce`: it runs to completion inside its permit and lease (the contract's
  §4).
- **Asynchronous work.** None.
- **Crash and recovery.** The read goes to the floor's kernel (§4.5); there is
  no cache to recover.
- **Tests:**
  - `the PEP sends the AuthZEN profile's members (@spec authzen#context-audience-freshness, #1004) > under PEP placement, carries the loader's observation at context.mission_state_observation, with state, mode and freshness_at, and no context.freshness` (PEP-level)
  - `AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004) > the PEP-supplied state is exactly active, and the PDP's own view wins on disagreement (@spec authzen#pdp-request rule 1) > the PDP's own revoked view against a PEP-supplied active state denies mission_inactive: the PDP's view wins` (PDP-level)
  - `compound-action phases (@spec runtime#compound-actions) > denies the fresh commit Decision when the Mission deactivates after prepare` (server-level)
- **Residual.** A PEP or PDP separated from the AS has no demonstrated source;
  #1101 owns the authenticated Status or introspection adapter. A Mission the
  loader does not find has no test on the Mission-bound path. The
  run-to-completion interval has no test.

### 5.4 Target and parameter binding

- **Hook.** `buildEffectiveParams`
  (`services/mcp-payments/src/effective-params.ts:27-44`) builds the effective
  parameters from the payments store, never from tool arguments, and
  `parameterDigest` (`:83`) commits them into the decision request. Three
  separate PEP checks run at use:
  - `verifyPermitAtUse` (`pep.ts:1980`) runs the permit-use table
    (`pep.ts:418-458`): the permit's bound phase against the crossing's phase
    (`phase_mismatch`), then `valid_until` (`permit_expired`). It compares no
    digest.
  - `reverifyCapability` (`pep.ts:2101`) re-checks the capability snapshot
    (`capability_source_unresolvable`).
  - `reverify` (`pep.ts:2012`, a single-record operation) and `reverifyList`
    (`pep.ts:2052`, a list read) re-derive the effective parameters and
    compare the digest (`parameter_mismatch`; a target that no longer resolves
    is also `parameter_mismatch`).
- **Order and boundary, by dispatch path** (`dispatchPathFor`, called from
  both transports):
  - Read (`callReadTool`, `server.ts:970`): the permit-use table, the
    capability check, `reverifyList` for a list read, the permit-use table
    again, then the read. A single-record read re-derives no digest at use.
    Nothing is written.
  - Write (`callWriteTool`, `server.ts:1059`): the permit-use table, the
    capability check, `reverify`, the permit-use table again, then the
    effect. For a keyed reversible write, the effect is the reservation
    transaction (§5.5). Nothing is written before it.
  - Transaction tier (`callTransactionTool`, `server.ts:1316`): the
    permit-use table at admission (`:1384`); single-use redemption (`:1426`),
    which writes the engine's operation state; then the capability check
    (`:1457`), the execution lease (`:1475`), `reverify` (`:1481`) and the
    permit-use table again (`:1493`); then the `txn` consumption, where a
    transaction token is presented, and the connector commit (`:1546-1557`).
    A refusal after redemption marks the operation `abandoned` and records
    suppressed Execution Evidence, which settles the PDP claim `failed`
    because the attempt is redeemed (`pep.ts:1908-1911`). The permit is spent;
    a retry needs a fresh decision (code reading).
- **Asynchronous work.** None.
- **Crash and recovery.** The payments store is in memory and reseeded per
  boot. A crash after redemption and before the connector commit leaves a
  `permit_issued` claim, which closes `indeterminate` (§5.7).
- **Tests (server-level):**
  - [FGA] `M4 core enforcement tier > scenario 3: TOCTOU -- invoice mutated between decision and execute -> parameter_mismatch refusal` (write path, digest)
  - [FGA] `M5 transaction-assurance tier > TOCTOU in the decision->commit window refuses before the connector commits` (transaction tier, digest after redemption, zero connector effects)
  - `GAP 1: list_invoices binds its result set to the Mission's Authority Set (@spec read-binding) > a Mission-authority change landing in the decision->execute window is caught by reverification, never executed on the stale normalized scope (TOCTOU)` (list read)
  - `compound-action phases (@spec runtime#compound-actions) > compares the bound phase before any effect on all three dispatch paths` (phase)
  - `compound-action phases (@spec runtime#compound-actions) > refuses a commit presenting prepare's permit, zero connector effects` (phase)
- **Residual.** A single-record read re-derives no digest at use; its fresh
  decision is the binding. A transaction-tier refusal after redemption spends
  the permit, and no test asserts the spent state. The payments Operation
  Profile promises NFC normalization and refusal of unknown or authoritative
  members at intake; neither is implemented, and its schema list differs from
  the served catalog (#1106, pending a ruling).

### 5.5 Permit redemption

- **Hook.**
  - Transaction tier: the PDP claims (idempotency scope, `idempotency_key`)
    with the operation identity before issuing the permit
    (`idempotency-claims.ts`). `callTransactionTool` (`server.ts:1316`)
    redeems the permit once (`TransactionEngine.redeemPermit`,
    `server.ts:1426`) under an execution lease, commits the connector effect,
    emits Execution Evidence and settles the claim (`settleClaim`,
    `server.ts:1616`).
  - Keyed reversible writes: the PEP reserves the key in its own SQLite store
    and commits the effect, the reservation and the result in one local
    transaction (`server.ts:1279`;
    `services/mcp-payments/src/write-reservations.ts:228`).
  - Other paths redeem nothing; each crossing takes a fresh decision.
- **Boundary.** The claim insert is one transaction in the PDP's store.
  Redemption, effect, evidence and settlement follow as separate writes, in
  that order. A keyed write is one local transaction.
- **Asynchronous work.** None. `settleClaim` is awaited.
- **Crash and recovery.** The claim and reservation files survive a restart.
  The engine's redemption records do not, and every process reuses the epoch
  `demo-epoch` (`stack.ts:820`), so single use across a restart rests on the
  persisted claim and reservations (the contract's §7). Surviving is not
recovery: a restarted PEP cannot reconcile a prior process's claim (§5.7).
- **Tests:**
  - [FGA] `M5 transaction-assurance tier > the SAME evaluation identifier presented again is refused as permit_consumed, and the completed record stands` (server-level)
  - [FGA] `M5 transaction-assurance tier > a FRESH permit for an already-claimed operation is refused as operation_already_claimed and does not double-execute` (server-level)
  - `PDP idempotency claim (@spec runtime#idempotency, #917) > crash boundaries and restart > a persisted permit is unknown after restart: suppressed, never returned, never fresh` (PDP-level)
  - `the PEP's reservation and retention for keyed reversible writes (@spec runtime#idempotency, #918) > the persisted store reopens with the record > a key scheduled before the store closed resolves against its record from a new server on the same file` (server-level)
- **Residual.** `hold_transfer`, the prepare phase, carries no permit-lifetime
  or idempotency control (#1080). The operation key omits `idempotency_key`:
  one redemption is allowed per Mission, action, phase and digest per process,
  so a repeat is refused, never executed twice (a stated bound).

### 5.6 Evidence

- **Hook.** The PDP emits Decision Evidence for every decision. The PEP
  verifies it (byte equality, signature, emitter-bound key, role, audience)
  before release, refusing `decision_evidence_unverifiable` otherwise
  (`pep.ts:1565-1577`). The PEP emits Refusal Records (`pep.ts:2116-2177`) and
  suppressed Execution Evidence (`suppressExecution`, `pep.ts:1876-1919`). The
  executor emits `completed` Execution Evidence after a connector commit
  (`server.ts:1586-1617`). The record table is the contract's §6.
- **Boundary.** Synchronous, inside the request.
- **Asynchronous work.** None.
- **Crash and recovery.** `EvidenceRetentionStore` is in memory as shipped
  (`stack.ts:682-684`). Retained records are lost at restart.
- **Tests (PEP-level):**
  - `a permit the PDP did not evidence is refused, never executed (#741) > refuses the action when the decision carries no Decision Evidence`
  - `retention honors the declared audit window (@spec runtime-evidence#receipt-retention) > recovers the retained records, the emitter sequences and the key retirement metadata after a restart` (on a file-backed store, not the shipped one)
- **Residual.** The `completed` write after a connector commit has no error
  handling: if it fails, the effect stands, no Execution Evidence exists and
  the claim is not settled. The other three emission failures fail closed
  with no test. Both are #1104's. A successful call outside the transaction
  tier emits no Execution Evidence.

### 5.7 Recovery and reconciliation

- **Hook.** The Enforcement Scope Statement declares `outcome_reconciliation`
  (`config/enforcement-scope.json:81-85`): a PT15M window, `mcp-payments-pep`
  as the responsible component, and an operator alert for every claim that
  closes `indeterminate`. `reconcileClaims`
  (`services/mcp-payments/src/claim-reconciliation.ts:47`) and `reconcile`
  (`services/mcp-payments/src/reconcile.ts:21`) implement it, and the
  reservation store has `sweep()` (`write-reservations.ts:364`).
- **Boundary.** None of them runs: no production code calls them.
- **Asynchronous work.** Reconciliation would be the overlay's only
  asynchronous work.
- **Crash and recovery.** A restarted PEP draws a new claim-requester epoch
  (`services/mcp-payments/src/redemption-status.ts:67`), so it cannot list or
  reconcile a prior process's claim (`idempotency-claims.ts:647`, `:682`). A
  retry against that claim is suppressed (`:444-455`). The claim moves to
  `unresolved` once its lease elapses and closes `indeterminate` when the
  window closes (`:723-735`); its key stays refused.
- **Tests:**
  - `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > refuses the retry when the redemption store cannot answer, or answers for another epoch` (PEP-level)
- **Residual.** No production caller and no alert (#1103). Recovery tests must
  distinguish a refusal before any effect from missing evidence after an
  effect, and show that no retry or reconciliation repeats the effect (#1103,
  #1104).

## 6. Unsupported and residual

**Required, not met (runtime overlay).** These block the AS-native payments
target's acceptance. Neither is unsupported, and neither can become an
exclusion.

- The credential authority at the PDP: key-role pinning, carriage, PDP
  evaluation and PDP-side witnesses (#825 PRs 2a and 2b, D312). §5.1.
- Independently administered Resource policy (#828). §5.2.

**Unsupported.** Each is refused or visibly absent; none is partial support.

1. Creating the Mission Record atomically with issuance of the authorization
   code (`{#approval-event}` step 7). §3.4.
2. An authoritative issuance commit that couples the derivation count to the
   access token (#250). §4.2, §4.3.
3. Refusing a derivation answered after an acknowledged revocation when its
   gate ran before the revocation commit (`{#issuance-gating}`). §3.5.
4. External Subjects (`{#approval-event}` step 2), refused
   `approval_forbidden`. §3.2.
5. An operation identity and artifact replay for provider mints. §4.4.
6. Durable provider state. Grants, codes, refresh tokens, the issuance index
   and the grant index do not survive a restart, so every refresh after a
   restart is refused. A file-backed kernel alone establishes no durability
   for them. §4.5.

Runtime overlay:

7. A state source for a PEP or PDP separated from the AS (#1101). This target
   uses the declared local read (D293). §5.3.
8. A permit-lifetime or idempotency control for `hold_transfer` (#1080). §5.5.
9. Running the declared outcome reconciliation, its alert, and recovery of a
   prior process's claims (#1103). §5.7.
10. An assembled deployment of exactly the contract's components:
    `pnpm as-native` runs the D332 AS capability set (the issuance profile
    plus exactly `lifecycle-revoke` and `transaction-authorization`, with
    `dev-token` and dev ordinary issuance off) and mounts no MAS join route,
    but it builds the cross-domain RAS and SaaS objects in process, with no
    listener (#1105).

**Residual.**

- A repeated decision binds a second grant to the committed record (§3.4).
- An abandoned redirect leaves an `active` Mission with no code (§3.4).
- A crash after the record commit leaves an `active` Mission with no grant on
  the file-backed kernel (§3.4).
- A state change between the refresh pre-check and the save-time gate is
  refused after rotation consumes the presented refresh token (§3.6; #250).
- A fully contained delegation family is refused after rotation consumes its
  refresh token; no recoverable issuance authority is lost under the three
  conditions of §3.6.
- A failure after the provider hook's counter `UPDATE` leaves that derivation
  counted, and an ID-JAG refused after admission stays counted until an
  authoritative non-acceptance returns it (§4.3).
- A projection refusal at the code exchange lands after code consumption
  (§3.7).
- The decision-time `scope` check ignores `capability_sources` (§3.3).
- The decision carries no render digest, and the page shows no separately
  computed effective expiry (§3.1).
- The achieved authentication context is not retained (§3.1).
- The approval-grant destruction is not durable, and an earlier grant from a
  repeated decision is not destroyed; the gate refuses both (§3.6).
- A refresh presented after `expires_at` is refused by the refresh token's
  own expiry, with no `mission_error` (§3.5).
- The JWT-only `plain-rs` accepts a token until `exp` plus its clock
  tolerance (§3.6).
- Runtime overlay: the in-process mediated channel verifies no proof of
  possession, so high-consequence claims hold on the HTTP entry point only
  (§5.1); a single-record read re-derives no digest at use, and a
  transaction-tier refusal after redemption spends the permit (§5.4); an
  admitted high-consequence action runs to completion inside its permit and
  lease after a revocation (§5.3); the operation key
  omits `idempotency_key`, so a repeat for an unchanged invoice is refused
  (§5.5); a failed `completed` write after a connector commit leaves the
  effect without Execution Evidence (§5.6; #1104); a successful call outside
  the transaction tier has no Execution Evidence (§5.6); the Operation
  Profile's intake rules are not implemented (§5.4; #1106).

**No test yet.**

- Approval: a configuration change between render and decision (§3.1).
- Derivation: a catalog-sourced `scope_only` entry that passes the decision
  and refuses at the token endpoint (§3.3).
- Binding: record and code atomicity; an abandoned redirect; a crash between
  the record commit and the binding; the grant count after a repeated
  decision; a lineage resolving to more than one Mission (§3.4).
- Issuance: revoke versus issue (§3.5).
- Gating: refresh against an earlier grant after revocation (§3.6).
- Scope projection: `derivation_count` after a code or refresh projection
  refusal; the JWT-customizer backstop (§3.7).
- Introspection: a signed token with no issuance record (§3.8).
- Replay: authorization-code reuse (§4.4).
- Recovery: an assembled AS restarted on a file-backed kernel (§4.5).
- Runtime overlay: a Mission the loader does not find on the Mission-bound
  path, and the run-to-completion interval (§5.3); the PDP emitter throwing,
  a Refusal Record emission throwing, both `suppressExecution` gaps and the
  failed `completed` write, each distinguishing a refusal before any effect
  from missing evidence after one (§5.6; #1104); reconciliation across a
  restart (§5.7; #1103); the assembled-path test against a live OpenFGA runs
  only in CI (§5).

## 7. Provider-specific notes (oidc-provider 9.10)

These are honest workarounds and ordering facts, not protocol requirements.

- **Intent-only requests get a synthesized `authorization_details`.**
  oidc-provider completes an authorization only when a scope was granted or
  `authorization_details` was requested. For an Intent-only request, `decide()`
  writes the effective Authority Set into the stored interaction as
  `authorization_details`, beside the marker
  `DERIVED_AUTHORIZATION_DETAILS_MARKER`, and saves the interaction. The
  render and `decide()` read the proposal through `clientProposalParam`,
  which treats a marked value as absent, so no anchor commits a proposal the
  client did not send. A client cannot send the marker: oidc-provider's
  parameter allow-list drops it. Tests (`scope-projection.test.ts`):
  - `requested scope and the token response (@spec mission#scope-projection) > a Mission created from the Intent alone (no authorization_details, no scope) completes and projects`
  - `the Intent-only completion workaround is never a client proposal (@spec mission#authority-proposal) > an Intent-only Mission commits no proposal_hash, and re-rendering or re-deciding the same interaction still reads no proposal`
  - `the Intent-only completion workaround is never a client proposal (@spec mission#authority-proposal) > a client-sent marker key is dropped: a pushed proposal is still the client's proposal, and an Intent-only request stays Intent-only`
- **The refresh-token scope is recorded through the code's scope.**
  `issueRefreshToken` rewrites the authorization code's in-memory `scope` to
  its kept OIDC values plus the projected values. `createRefreshToken` copies
  `source.scope` into the new refresh token (`lib/helpers/grant_common.js`).
  oidc-provider's own check (`refresh_token.js` L86-92) then refuses a refresh
  naming a value the token never recorded, before any consumption. Test:
  `refresh preserved on a projection refusal (@spec mission#scope-projection) > a refresh naming a narrower scope is granted exactly it; a value never granted refuses invalid_scope without consuming the token (#871)`.
  The override also issues a refresh token to any client allowed the
  `refresh_token` grant, without the default's `offline_access` condition
  (`lib/helpers/defaults.js` L308-313).
- **Inside `AccessToken#save()`.** `models/formats/opaque.js` L39 calls
  `extraTokenClaims`. `models/formats/jwt.js` L140-143 calls the JWT
  customizer, and signing follows (L151-155). `models/base_model.js` L62-69
  emits `issued` for a format that stores no payload, which is the JWT access
  token.
- **Grant ordering.** Code exchange: consume (L89), `at.save()` (L127),
  refresh token (L129), ID token (L133). Refresh: `rotateRefreshToken`
  (L133-135), consume (L137), rotated save (L168), `rar` hook (L212),
  `at.save()` (L216), ID token (L218).
- **`rotateRefreshToken` replaces the default.** Supplying it removes
  oidc-provider's own rule, so the reference inlines that rule for every
  non-family grant (`lib/helpers/defaults.js` L528-547).
- **Credential lifetimes.** `ttl` sets `AccessToken` (the resource server's
  `accessTokenTTL`, or 1 hour), `RefreshToken` (14 days; a delegation-family
  token is uncapped), `AuthorizationCode` (60 seconds) and `IdToken` (1 hour),
  each clamped to the Mission's `expires_at` by `clampToMission`. Each
  configured value is oidc-provider 9.10.0's own default
  (`lib/helpers/defaults.js`), so a token under a grant that is not
  Mission-bound is unchanged.
- **Introspection.** The adapter owns `/introspect` (§3.8). Its comment
  records that JWT access tokens cannot use oidc-provider's endpoint, a spike
  finding not re-verified here.
- **Storage.** No `adapter` is configured, so every provider object is in
  oidc-provider's memory adapter.
- **`mission_error`.** oidc-provider copies only `error`,
  `error_description`, `scope` and `state` into an error body. The
  `grant.error` listener in `buildProvider` adds `mission_error` to the
  rendered `invalid_grant` body.

## 8. Status

Documentation of the current reference implementation. It is not an
owner-accepted conformance class, makes no production-readiness claim, and
adds no normative text. An unsupported obligation listed here constrains what
the issuance-only deployment, or for §5 the AS-native payments target, may
claim; it is not partial support. A required obligation that is not met (§6)
blocks that target's acceptance and is never an exclusion.
