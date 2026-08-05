# Spec Traceability Matrix

The record of every spec this implementation implements, the exact version
implemented against, where it lands in the code, and the tests that prove
it. This is how a spec update becomes a change list: diff the spec from its
pinned version to the new one, then follow the touched sections through
this matrix and the `@spec` tags to the affected code and tests.

## Conventions

- **Pins.** In-repo drafts pin the last commit that touched the draft file
  (`git log -1 -- <draft>.md`). External specs pin a revision, tag, PR head
  SHA, or dated snapshot. Dependencies that embody a spec surface pin an
  exact version.
- **`@spec` tags.** Source code implementing spec-derived behavior carries
  a greppable comment tag: `@spec <doc>#<section>` (e.g.
  `@spec mission#integrity-anchors`). One tag per behavior, at the
  narrowest enclosing scope. `grep -rn "@spec mission#"` answers "where
  does the core land in the code."
- **Updating a pin.** Deliberate, never implicit (D25/D41): diff the spec
  old→new, grep the changed section anchors against `@spec` tags, list the
  affected modules and tests in the bump commit message, review against the
  Spec Feedback Log (a bump may resolve an S-entry), then update the row.
- One row per (spec, implementing component); a spec spanning components
  gets multiple rows.

## Implemented (updated per milestone)

| Spec | Pinned version | Component | Surfaces (`@spec` doc key) | Tests |
|---|---|---|---|---|
| `draft-mcguinness-oauth-mission` | `c2053e5` (2026-07-17) | `packages/mission-core` | `mission#integrity-anchors`, `mission#canonicalization`, `mission#test-vectors` | `packages/mission-core/test/anchors.test.ts` |
| `draft-mcguinness-oauth-mission` | `c2053e5` (2026-07-17) | `services/authorization-server` (kernel + adapters) | `mission#submission-via-par`, `mission#mission-intent`, `mission#authorization-derivation`, `mission#subset`, `mission#integrity-anchors`, `mission#the-mission-claim`, `mission#lifecycle`, `mission#introspection`, `mission#as-metadata` | `services/authorization-server/test/{kernel,tracer}.test.ts` |
| `draft-mcguinness-oauth-mission-status` | `89ba0b4` (2026-07-16) | `services/authorization-server` (kernel + adapters) | `status#legal-transitions`, `status#state-machine`, `status#mission-status-response`, `status#status-list`, `status#mission-status-anti-oracle` | `services/authorization-server/test/{kernel,tracer,status-list}.test.ts` |
| `draft-ietf-oauth-status-list` | `-21` (2026-06) | `services/authorization-server/src/kernel/status-list.ts` | `statuslist+jwt`, 2-bit `lst`, DEFLATE/ZLIB, `idx`/`uri` | `services/authorization-server/test/status-list.test.ts` |
| `draft-mcguinness-oauth-mission-signals` | `4cc71d7` (2026-07-13) | `packages/mission-signals` + `services/authorization-server` (kernel commit hook subscriber) | `signals#lifecycle-event`, `signals#set-protection`, `signals#consumer-behavior` | `packages/mission-signals/test/signals.test.ts` |
| `oidc-provider` | `9.10.0` (RAR ack `experimental-01`) | `services/authorization-server/src/adapters` | PAR, RAR (issuer-derived via `rarFor*`), DPoP, resource indicators, custom routes | `services/authorization-server/test/tracer.test.ts` |
| `draft-mcguinness-oauth-actor-profile` | local @ 2026-07-21 | `packages/actor-chain` | `actor-profile#actor-object-structure`, `actor-profile#delegation-chains` (flatten, validate, depth, presenter transitions) | `packages/actor-chain/test/actor-chain.test.ts` |
| `draft-mcguinness-mission-authzen` (context.actor) | `02d53dd` | `packages/actor-chain` | `authzen#context-actor` (root-to-leaf projection, PEP build / PDP validate, D31) | `packages/actor-chain/test/actor-chain.test.ts` |
| CIA-CORE (`client-instance-assertion`) | local `-latest` @ 2026-06-23 | `services/authorization-server/src/kernel/instance-assertion.ts` | carrier validation (typ, 12-step processing, cnf, replay, chain merge) | `services/authorization-server/test/delegation.test.ts` |
| `draft-mcguinness-oauth-ai-agent-instance` | rev 00 | `services/authorization-server/src/kernel` (instance-assertion, delegation) | instance claims, sub_profile `ai_agent client_instance`, delegated act population | `services/authorization-server/test/delegation.test.ts` |
| `draft-mora-oauth-entity-profiles` | rev 01 (local 2026-04-12) | `packages/actor-chain` | position-keyed `sub_profile` allowlists + pass-through | `packages/actor-chain/test/actor-chain.test.ts` |
| `draft-mcguinness-mission-authzen` (PDP request/decision) | `02d53dd` | `services/pdp` | `authzen#pdp-request` (envelope, context.audience rule), `authzen#denial-response`, `authzen#runtime-denial-classification`, `authzen#materialization` | `services/pdp/test/evaluate.test.ts` |
| `draft-mcguinness-mission-runtime` (decision contract) | `02d53dd` | `services/pdp` | abstract decision inputs, staleness bound, permit properties | `services/pdp/test/evaluate.test.ts` |
| OpenFGA | `v1.18.1` (by digest) | `services/pdp/src/fga.ts` | domain model, contextual-tuple check, explicit model id (D26/fga-hygiene) | `services/pdp/test/evaluate.test.ts` (live) |
| `draft-mcguinness-oauth-mission` (RS enforcement) | `c2053e5` | `services/mcp-payments` | `mission#rs-enforcement` (token + mission claim + DPoP cnf validation, mission-scoped tools/list) | `services/mcp-payments/test/enforcement.test.ts` |
| `draft-mcguinness-mission-authzen` (PEP envelope + evidence) | `02d53dd` | `services/mcp-payments/src/pep.ts` | envelope build (context.actor, parameter_digest, capability_source), Decision Evidence, Refusal Records | `services/mcp-payments/test/enforcement.test.ts` |
| RFC 9728 (Protected Resource Metadata) | RFC 9728 | `services/mcp-payments/src/server.ts` | `mission_bound_authorization_required`, `mission_constraints_supported` | `services/mcp-payments/test/enforcement.test.ts` |
| `draft-mcguinness-mission-runtime` (transaction-assurance tier) | `02d53dd` | `services/mcp-payments` (transaction, connectors, reconcile) | single-use permits, execution leases, operation state machine (D36), Execution Evidence, outcome reconciliation | `services/mcp-payments/test/transaction.test.ts` |
| `draft-mcguinness-mission-authzen` (requestable denials, action approval) | `02d53dd` | `services/pdp`, `services/mcp-payments` | `authzen#requestable-denials`, `authzen#context-approval` (action_approval validation, PDP-signed binding_token) | `services/access-request/test/reevaluate.test.ts` |
| AuthZEN ARAP (external, OpenID) | openid/authzen PR #508 merged, blob `670f5831f6e786c70944887dec6ab14de26986f8` | `services/access-request` | access request submission, task lifecycle, adjudication, action-bound approval object (reevaluate mode; `approved_until` honored end-to-end, requestable `access_request.expires_at`, approval-state `iss`+`aud`) | `services/access-request/test/reevaluate.test.ts` |
| `draft-mcguinness-oauth-mission-expansion` | `dc7a897` | `services/authorization-server/src/kernel/expansion.ts` | successor Mission, `predecessor` member, supersede-on-redemption, approved_until bounding | `services/authorization-server/test/arop.test.ts` |
| `draft-mcguinness-oauth-mission-child-delegation` | `8427e9b` (kernel, 2026-07-15) + AS wire (branch `feat/child-delegation-wire`, 2026-08-05) | `services/authorization-server/src/kernel/child-delegation.ts` (+ kernel `cascadeChildren`/`findChildren`/suspend-projection, `parent`/`ParentRef`); AS wire in `services/authorization-server/src/adapters/provider.ts` (`extraParams` `parent`/`parent_token`/`child_actor`, back-channel `POST /child-missions`, discovery flag) and `services/authorization-server/src/adapters/child-grant.ts` (child-bound grant) | `child-delegation#child-creation`, `#child-client-identity`, `#request-processing`, `#parent-member`, `#strict-subset`, `#cascade`, `#discovery` (kernel flow, terminal cascade, suspend-projection, fan-out accounting; PAR wire params, parent resolve-only, child-bound RFC 7523 grant issuance, discovery metadata all realized; child redeeming AS ITSELF at `/token` deferred to PR4b) | `services/authorization-server/test/child-delegation.test.ts`, `services/authorization-server/test/child-delegation-endpoint.test.ts` |
| AuthZEN AROP (openid/authzen#531) | PR #531 @ 2026-07-20 | `services/authorization-server/src/kernel` (deferred, txn-challenge) | DTR deferred grant + Transaction Challenge, token-issuance completion; subset-of-Mission with the active Mission carried unchanged (Expansion is a separate flow — D42/D46) | `services/authorization-server/test/arop.test.ts` |
| DTR (`draft-gerber-oauth-deferred-token-response`) | [`-00`](https://datatracker.ietf.org/doc/draft-gerber-oauth-deferred-token-response/00/) | `services/authorization-server/src/kernel/deferred.ts`, `services/authorization-server/src/adapters/provider.ts` (deferred grant on the real `/token`) | deferred grant (`urn:ietf:params:oauth:grant-type:deferred`) on the real `/token` endpoint: initiation (folded — see Notes) + poll/redeem, `deferral_code`, `authorization_pending`/`slow_down`/`expired_token` (RFC 8628 backoff), idempotent submission, redeem error codes (`invalid_grant`/`access_denied`, §5.6); redemption mints a resource-bound JWT mission token carrying the active Mission unchanged (D42) | `services/authorization-server/test/dtr-endpoint.test.ts` (real HTTP), `services/authorization-server/test/arop.test.ts` (kernel) |
| Txn Challenge (`draft-rosomakho-oauth-txn-challenge`) | [`-00`](https://datatracker.ietf.org/doc/draft-rosomakho-oauth-txn-challenge/00/) | `services/authorization-server/src/kernel/txn-challenge.ts` | signed challenge (`txn-authz-challenge+jwt`, txn/jti/authorization_details/iss/aud/reason, §4.2), txn-bound single-use audience-restricted token, §6.2 token-vs-challenge binding | `services/authorization-server/test/arop.test.ts` |
| `draft-mcguinness-svc-connectivity-disco` | repo main @ 2026-07-20 | `services/authorization-server/src/kernel/catalog.ts` | per-user catalog, filtering, mission-derived status (D9), request-access link (D10), service_catalog_endpoint metadata | `services/authorization-server/test/catalog.test.ts` |
| `draft-mcguinness-oauth-mission-cross-domain` | `dc7a897` | `services/authorization-server/src/kernel/cross-domain.ts`, `services/ras` | ID-JAG grant issuance (audience-scoped, PoP, one-time, mission-preserving), RAS validation | `services/mcp-saas/test/cross-domain.test.ts` |
| ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`) | [`-04`](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/04/) (2026-05-21) | `services/authorization-server`, `services/ras` | `oauth-id-jag+jwt` grant (incl. `client_id` claim, §3.1), RFC 7523 JWT-bearer redemption | `services/mcp-saas/test/cross-domain.test.ts` |
| MCP EMA | 2025-11-25 track | `services/ras`, `services/mcp-saas` | enterprise-managed-authorization declaration; token-only SaaS enforcement | `services/mcp-saas/test/cross-domain.test.ts` |
| `draft-mcguinness-oauth-mission-attenuation` | `eb568f5` (2026-07-15) | `services/authorization-server/src/kernel/attenuation.ts` + `packages/mission-core` + `services/mcp-payments` | `attenuation#root-mapping`, `attenuation#attenuation`, `attenuation#mission-binding-check`, `attenuation#kill-switch` | `packages/mission-core/test/attenuation-chain.test.ts`, `services/mcp-payments/test/attenuation.test.ts` |
| `draft-mcguinness-mission-audit` (SCITT profile) | `dc7a897` | `services/transparency` | append-only Merkle log, hash-committed Signed Statements, Receipts + signed tree heads, per-mission feeds, five-step offline verification | `services/transparency/test/transparency.test.ts` |
| RFC 9162 (Merkle tree) | RFC 9162 | `services/transparency/src/merkle.ts` | leaf/node domain separation, inclusion proofs | `services/transparency/test/transparency.test.ts` |
| `draft-mcguinness-oauth-mission-management` (partial) | `dc7a897` | `services/console-bff`, `authorization-server` (allMissions) | fleet enumeration + operator lifecycle surfaces | `services/console-bff/test/console.test.ts` |
| `draft-mcguinness-mission-harness` (partial) | `dc7a897` | `packages/mission-core/src/binding.ts`, `services/agent/src/{harness,mediated-harness,harness-scope}.ts`, `services/mcp-payments/src/mcp-transport.ts` | duty 1 fail-closed resume + duty 2 mediated execution environment (real MCP channel, no PEP bypass); `harness#mission-binding` (shared `state_source`/`MissionStatusLease`/`MissionBinding`/`StopPolicy` types, `suppress` realized); `harness#mediated-egress` (execution-environment scope statement, claim-gated channel-class enumeration, sign/verify); `harness#resume-algorithm` (status-continuity: fail closed once `now > status_expires_at`, freshness re-checked at each submission) | `services/agent/test/{harness,mediated-harness,harness-scope}.test.ts`, `services/mcp-payments/test/mcp-channel.test.ts` |
| `@modelcontextprotocol/sdk` | 1.29.0 | `services/mcp-payments/src/mcp-transport.ts` (in-memory transport), `services/mcp-payments/src/mcp-http-transport.ts` (StreamableHTTP transport) | `tools/list`/`tools/call` delegating to the same PEP over two transports. In-memory: mission credential in `_meta` (advances/closes the O-33 transport swap). Real StreamableHTTP (server+client): a DPoP-auth middleware enforces proof-of-possession over HTTP via `validateToken` (canonical `htu`/`htm`; `cnf.jkt` equals the proof thumbprint) before dispatch, with the credential carried in the `Authorization: DPoP`/`DPoP` headers instead of `_meta` | `services/mcp-payments/test/mcp-channel.test.ts`, `services/mcp-payments/test/mcp-http-channel.test.ts` |
| `draft-mcguinness-mission-shaping` | `dc7a897` | `services/agent/src/index.ts` (shapeIntent) | untrusted intent proposal; derivation still bounds | `services/agent/test/harness.test.ts` |
| (eval harness, goal 2) | n/a | `evals` | adversarial + legitimate suites, containment scorecard, CI gate (D24) | `evals/test/evals.test.ts` |
| (vendor test, handbook) | n/a | `evals/src/vendor-test.ts` | four-axis valid-token-but-denied demonstration | `evals/test/vendor-test.test.ts` |
| `draft-mcguinness-mission-orchestration` | `3ce193c` (2026-07-15) | `packages/orchestration` + `packages/mission-core` (anchors `UNWIND_PLAN_TYP`) | `orchestration#reversibility`, `orchestration#unwind-plan`, `orchestration#unwind-plan-integrity`, `orchestration#state-change-behavior`, `orchestration#compensation`, `orchestration#orchestration-evidence` | `packages/orchestration/test/orchestration.test.ts` |

## Adopted for planning, not yet implemented (pins from the pre-flight spike)

| Spec | Pinned version | Lands in |
|---|---|---|
| `draft-mcguinness-mission-authzen` (PEP evidence, requestable denials) | `02d53dd` | M4/M6 PEP |
| `draft-mcguinness-mission-audit` + SCITT (RFC 9943) | in-repo current | M10 |
| MCP authorization profile | 2025-11-25 (stable) | M4/M8/M9 |
| OpenFGA | `v1.18.1@sha256:efde89d2...6688` | M0 compose (done) |
| `draft-niyikiza-oauth-attenuating-agent-tokens` (AAT substrate) | I-D in progress (no published revision) | attenuation substrate profiled by `services/authorization-server/src/kernel/attenuation.ts` + `packages/mission-core/src/attenuation-chain.ts` (JWS chain, `par_hash` linkage, capability monotonicity, `del_depth`/`del_max_depth`) |

## Notes

- DTR (`-00`) initiation is folded into the deferred grant type rather than
  carried as `completion_mode=deferred` on the originating grant:
  node-oidc-provider offers no pre-issuance defer hook for built-in grants. A
  deferred-grant request with `deferred_authorization` (and no `deferral_code`)
  opens the deferral and returns the DTR initiation body; a request with
  `deferral_code` polls/redeems it. Responses remain DTR-shaped
  (`authorization_pending` + `deferral_code`/`expires_in`/`interval`; RFC
  8628-shaped poll errors `slow_down`/`expired_token`/`access_denied`).
- `oidc-provider@9.10.0` ships no first-party TypeScript types; the build
  depends on `@types/oidc-provider@9.5.0` (behind the runtime). Gaps handled
  with narrow local aliases (e.g. `InvalidAuthorizationDetails`, present at
  runtime in 9.10, absent from the 9.5 types). Re-check on any provider bump.
- Harness scope statement: the draft (§ mission-mediation) says a harness MUST
  *publish* the execution-environment scope statement, not sign it.
  `signScopeStatement`/`verifyScopeStatement` add an ES256 JWS over the JCS
  digest (mirroring the `@mission/transparency` evidence convention) so a
  relying party can *verify* a published statement; this is a beyond-the-draft
  assurance, not a conformance requirement. Deferred (named, not built): signed
  Harness Evidence + transparency registration + harness key publication;
  session-taint / egress-downgrade (the taint policy is an opaque pass-through);
  discovery-bound channels entering the enumeration at binding; multi-entry
  per-mediated-action-class statements; queue-item/expiry; sub-agent stop
  propagation; the harness execution-state machine. Only the `suppress` stop
  policy is realized (the harness's no-dispatch behavior); `pause`/`terminate`/
  `handoff` are declared in `StopPolicy` but unimplemented.
- The `AuthorityEntry.delegation` core extension (the S-15 gap) is realized in
  `services/authorization-server/src/kernel/types.ts`: `intersect` carries and
  narrows it as an inherit-by-default GRANT (ceiling-absent means non-delegable,
  the deliberate opposite of the `constraints` ceiling-absent branch), and
  `isSubsetEntry` treats it as a narrowing dimension (a candidate omitting
  delegation the grantor has PASSES; introducing it FAILS). Consequently
  `deriveAttenuationRoot` DERIVES `del_max_depth` (min `max_depth` across the
  delegable entries; non-delegable entries drop from a root with
  `del_max_depth > 0`) instead of requiring the caller to supply it. The
  child-delegation companion `children` object rides under the delegation open
  index, gated as a grant one level down; kernel fan-out, PAR wire params, and
  the offline holder-side chain verifier
  (`packages/mission-core/src/attenuation-chain.ts`, a separate `del_max_depth`
  surface) are unchanged.
  (`services/authorization-server/test/derivation-delegation.test.ts`.)
- Mission Child-Delegation fan-out accounting and Child Evidence are realized in
  `services/authorization-server/src/kernel/child-delegation.ts`:
  `createChildMission` derives the delegation decision from the parent Authority
  Set's per-entry `delegation.children` (PR1's S-15 on-switch) instead of an
  explicit `delegationAllowed` flag. Each child entry is attributed to the FIRST
  parent entry (Authority Set order) it is a subset of (`isSubsetEntry`), and
  that justifying entry is the accounting basis: absence of `children` refuses
  `delegation_not_permitted` (kept distinct from `policy_denied`);
  `allowed_child_actors` gates the child actor (`child_actor_not_allowed`);
  `max_child_depth` (default 1) is a per-entry, decrementing child-generation
  ceiling and `max_children` a per-entry non-terminal fan-out cap (counted over
  `kernel.findChildren` filtered by `TERMINAL_STATES`), both refusing
  `fanout_exceeded`; the count-then-insert is atomic on the single-threaded,
  synchronous kernel. A Child Evidence record
  (`application/mission-child-evidence+json`, JCS canonical bytes, `decision`
  `created` / `denied`, note the draft's field values, not permit/deny) is
  returned on permit and attached to the thrown `ChildDelegationError` on
  refusal. `children` is read through a typed `ChildFanoutControls` reader so the
  `delegation` open index derivation relies on stays byte-identical (derive.ts
  and kernel.ts unchanged); kernel lifecycle / suspend and the PAR wire remain
  deferred.
  (`services/authorization-server/test/child-delegation.test.ts`.)
- Mission Child-Delegation suspend-projection and restore-on-resume are realized
  in `services/authorization-server/src/kernel/kernel.ts`: a parent SUSPEND
  projects its transitive `active` descendants to the REVERSIBLE `suspended` hold
  (the counterpart to the terminal `cascaded` cascade), and a parent RESUME
  restores them. Projection (`projectSuspendedChildren`) and restore
  (`restoreProjectedChildren`) are gated off the non-terminal `suspended`/`active`
  commits in `setState`, so transitivity and generation order ride the same
  re-entry as `cascadeChildren` (no self-recursion) and every commit flows through
  `setState -> emitCommit` (Status List + Signals fan-out; version increments). A
  nullable `projected_from` column records a child's pre-suspension state: it is
  set only when a projection changes an `active` child, so an independently
  `suspended` descendant carries NO marker and is NOT restored on parent resume.
  Restore applies the expiry clock FIRST (`applyExpiry`), so a child whose
  `expires_at` passed during suspension ends `expired`, not `active`; a parent
  driven terminal while suspended still cascades descendants to `cascaded`
  (terminal wins). `gateDerivation` additionally refuses (`mission_not_active`)
  while ANY ancestor is non-active (the explicit `parent`-lineage walk, expiry
  applied per hop). The Mission Signals anti-revive guard accepts the
  `suspended` -> `active` restore lift because acceptance is version-based (strict
  forward progress), not state-based.
  (`services/authorization-server/test/suspend-projection.test.ts`,
  `packages/mission-signals/test/suspend-lift.test.ts`.)
- Mission Child-Delegation PAR wire, parent resolution, child-grant issuance, and
  discovery are realized in `services/authorization-server/src/adapters/provider.ts`
  and `services/authorization-server/src/adapters/child-grant.ts`. The parent pushes
  the child-creation params (`mission_intent` + `parent` + `parent_token` +
  `child_actor`) via PAR (registered `extraParams`, mirroring `mission_intent`); the
  back-channel `POST /child-missions` route reads the pushed request (bound to the
  PAR-authenticated client), resolves the Parent Mission from `parent_token`
  RESOLVE-ONLY (`RefreshToken.find`: non-consuming, `ignoreSessionBinding`, so no
  rotation and no replay registration), cross-checks the `parent` param
  (`parent_mismatch` under `invalid_grant`), and runs `createChildMission` end-to-end.
  Denial reasons map to layered OAuth errors carried in `mission_denial_reason`, set
  on `ctx` directly so `err_out` does not strip the member. A front-channel
  presentation of `parent_token` (route `authorization`, e.g. a `request_uri` resolved
  at `/auth`) is refused `invalid_request`. On success the AS mints the child-bound
  RFC 7523 JWT authorization grant (`adapters/child-grant.ts`, ID-JAG-shaped: `aud` is
  the token endpoint, `sub` the Mission subject, `client_id` the child actor, and the
  `mission` claim carries the `parent` lineage and the CHILD `authority_hash`) as the
  grant reference the parent conveys; the pushed request is destroyed after read so
  `parent_token` never sits at rest. `mission_child_delegation_supported` is advertised
  in AS metadata. Deferred to PR4b: the child redeeming that assertion AS ITSELF at
  `/token` (RFC 7523 JWT-bearer), which needs the child actor registered as an OAuth
  client (a `config/clients.json` + demo-data change outside this PR's surface).
  (`services/authorization-server/test/child-delegation-endpoint.test.ts`.)
