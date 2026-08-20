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
| `draft-mcguinness-oauth-mission` | `c2053e5` (2026-07-17) | `services/authorization-server` (kernel + adapters) | `mission#submission-via-par`, `mission#mission-intent`, `mission#authorization-derivation`, `mission#subset`, `mission#integrity-anchors`, `mission#the-mission-claim`, `mission#lifecycle`, `mission#introspection`, `mission#as-metadata` | `services/authorization-server/test/{kernel,tracer,authorization-endpoint}.test.ts` |
| `draft-mcguinness-oauth-mission-status` | `89ba0b4` (2026-07-16) | `services/authorization-server` (kernel + adapters) | `status#legal-transitions`, `status#state-machine`, `status#mission-status-response`, `status#status-list`, `status#mission-status-anti-oracle` | `services/authorization-server/test/{kernel,tracer,status-list}.test.ts` |
| `draft-ietf-oauth-status-list` | `-21` (2026-06) | `services/authorization-server/src/kernel/status-list.ts` | `statuslist+jwt`, 2-bit `lst`, DEFLATE/ZLIB, `idx`/`uri` | `services/authorization-server/test/status-list.test.ts` |
| `draft-mcguinness-oauth-mission-signals` | `4cc71d7` (2026-07-13) | `packages/mission-signals` + `services/authorization-server` (kernel commit hook subscriber) | `signals#lifecycle-event`, `signals#set-protection`, `signals#consumer-behavior` | `packages/mission-signals/test/signals.test.ts` |
| `oidc-provider` | `9.10.0` (RAR ack `experimental-01`) | `services/authorization-server/src/adapters` | PAR, RAR (issuer-derived via `rarFor*`), DPoP, resource indicators, custom routes | `services/authorization-server/test/tracer.test.ts` |
| `draft-mcguinness-oauth-actor-profile` | local @ 2026-07-21 | `packages/actor-chain` | `actor-profile#actor-object-structure`, `actor-profile#delegation-chains` (flatten, validate, depth, presenter transitions) | `packages/actor-chain/test/actor-chain.test.ts` |
| `draft-mcguinness-mission-authzen` (context.actor) | `02d53dd` | `packages/actor-chain` | `authzen#context-actor` (root-to-leaf projection, PEP build / PDP validate, D31) | `packages/actor-chain/test/actor-chain.test.ts` |
| CIA-CORE (`client-instance-assertion`) | local `-latest` @ 2026-06-23 | `services/authorization-server/src/kernel/instance-assertion.ts` | carrier validation (typ, 12-step processing, cnf, replay, chain merge) | `services/authorization-server/test/delegation.test.ts` |
| `draft-mcguinness-oauth-ai-agent-instance` | rev 00 | `services/authorization-server/src/kernel` (instance-assertion, delegation) | instance claims, sub_profile `ai_agent client_instance`, delegated act population | `services/authorization-server/test/delegation.test.ts` |
| `draft-mora-oauth-entity-profiles` | rev 01 (local 2026-04-12) | `packages/actor-chain` | position-keyed `sub_profile` allowlists + pass-through | `packages/actor-chain/test/actor-chain.test.ts` |
<<<<<<< HEAD
| `draft-mcguinness-mission-authzen` (PDP request/decision) | `f5977e0` (2026-08-16) | `services/pdp` | `authzen#pdp-request` (envelope, context.audience rule), `authzen#denial-response`, `authzen#runtime-denial-classification`, `authzen#materialization`, `authzen#response-context` (`evaluation_id`/`reason` additive alongside `decision_id`/`denial_reason`; permit `conditions` object with `parameter_digest`/`valid_until`/`use_limit`, replacing the flat `permit_expires_at`/`single_use` members; `use_limit: 1` now set for both high-consequence classes present in this deployment, not only `irreversible_action`) | `services/pdp/test/{evaluate,evaluate-decision}.test.ts` |
=======
| `draft-mcguinness-mission-authzen` (PDP request/decision) | `02d53dd` | `services/pdp` | `authzen#pdp-request` (envelope, context.audience rule), `authzen#denial-response`, `authzen#runtime-denial-classification`, `authzen#materialization`, `authzen#failure-condition-coverage` (out_of_authority vs unsupported_authorization_type mapping, author review finding 3) | `services/pdp/test/{evaluate,evaluate-fail-closed}.test.ts` |
>>>>>>> main
| `draft-mcguinness-mission-runtime` (decision contract) | `b5e35e2` (2026-08-18) | `services/pdp` | abstract decision inputs, staleness bound, permit properties | `services/pdp/test/{evaluate,evaluate-decision-inputs,evaluate-classification,evaluate-decision,evaluate-compromise-resistant}.test.ts` |
| OpenFGA | `v1.18.1` (by digest) | `services/pdp/src/fga.ts` | domain model, contextual-tuple check, explicit model id (D26/fga-hygiene) | `services/pdp/test/evaluate.test.ts` (live) |
| `draft-mcguinness-oauth-mission` (RS enforcement) | `c2053e5` | `services/mcp-payments` | `mission#rs-enforcement` (token + mission claim + DPoP cnf validation, mission-scoped tools/list) | `services/mcp-payments/test/enforcement.test.ts` |
| `draft-mcguinness-mission-authzen` (PEP envelope + evidence) | `f5977e0` (2026-08-16) | `services/mcp-payments/src/pep.ts` | envelope build (context.actor, parameter_digest, capability_source), Decision Evidence, Refusal Records; response-context conditions parsing (`decision.context.conditions` recognized-member check scoped to `conditions` only, never the whole top-level context; `decision.context.obligations` presence is an effective deny, `unfulfillable_obligation`) | `services/mcp-payments/test/{enforcement,pep-fail-closed}.test.ts` |
| RFC 9728 (Protected Resource Metadata) | RFC 9728 | `services/mcp-payments/src/server.ts` | `mission_bound_authorization_required`, `mission_constraints_supported` | `services/mcp-payments/test/enforcement.test.ts` |
| `draft-mcguinness-mission-runtime` (transaction-assurance tier) | `02d53dd` | `services/mcp-payments` (transaction, connectors, reconcile) | single-use permits, execution leases, operation state machine (D36), Execution Evidence, outcome reconciliation | `services/mcp-payments/test/transaction.test.ts` |
| `draft-mcguinness-mission-runtime` (PEP/RS boundary conformance) | `b5e35e2` (2026-08-18) | `services/mcp-payments` (pep, server) | `runtime#pep-placement` (last controllable boundary, catalog filter is not a substitute), `runtime#rs-runtime-profile` (a PEP that can refuse precedes execution), `runtime#classification` (high-consequence actions always reach a PDP decision), `runtime#token-validation` (validity, audience, and missing-mission-claim refusal before decision inputs are used), `runtime#action-approval` (reparameterization invalidates an approval), `runtime#decision` (a permit is never reused once authority is withdrawn), `runtime#security-considerations` (a permit bound to one resource is refused at another) | `services/mcp-payments/test/runtime-refusal-backlog.test.ts` (unconditional); `services/mcp-payments/test/{mcp-channel,mcp-http-channel}.test.ts` (reused, live-OpenFGA/CI-only, for the proof-of-possession and bad-signature arms) |
| `draft-mcguinness-mission-runtime` (read binding + decision-output polarity) | `b5e35e2` (2026-08-18) | `services/mcp-payments/src/pep.ts`, `services/mcp-payments/src/server.ts`, `services/mcp-payments/src/effective-params.ts`, `services/pdp/src/evaluate.ts` | `runtime#read-binding` (list_invoices binds a requested vendor_id through the ordinary vendor-constraint check, and binds its absence to a normalized {vendor_scope, vendor_scope_source} Operation Profile whose parameter_digest is reverified immediately before execution; a multi-vendor collection is checked member-by-member against Resource policy via `resource.properties.vendor_ids`, evaluateInner step 6a, not just one representative object), `runtime#decision-output` (a permit's `decision.context.conditions` member outside {parameter_digest, valid_until, use_limit} refuses with zero effect; an obligation's mere presence is an effective deny) | `services/mcp-payments/test/pep-fail-closed.test.ts`, `services/pdp/test/evaluate-decision.test.ts` |
| `draft-mcguinness-mission-authzen` (requestable denials, action approval) | `f5977e0` (2026-08-16) | `services/pdp`, `services/mcp-payments` | `authzen#requestable-denials`, `authzen#context-approval` (action_approval validation, PDP-signed binding_token), `authzen#response-context` (reevaluate mode's fresh permit carries `conditions.valid_until`) | `services/access-request/test/reevaluate.test.ts` |
| AuthZEN ARAP (external, OpenID) | openid/authzen #515 (OIDF WG stream) @ `7327cb1bcea8cfc223e7b6816535f60149845468`, blob `670f5831f6e786c70944887dec6ab14de26986f8` (corrected at PR #595 review from a "PR #508 merged" label: PR #508's own merge commit carries a different blob and digest, so the prior label named the wrong commit for this content; #515 is the later WG-stream commit the reference implementation was verified against) | `services/access-request` | access request submission, task lifecycle, adjudication, action-bound approval object (reevaluate mode; `approved_until` honored end-to-end, requestable `access_request.expires_at`, approval-state `iss`+`aud`) | `services/access-request/test/reevaluate.test.ts` |
| `draft-mcguinness-oauth-mission-expansion` | `dc7a897` | `services/authorization-server/src/kernel/expansion.ts` | successor Mission, `predecessor` member, supersede-on-redemption, approved_until bounding | `services/authorization-server/test/arop.test.ts` |
| `draft-mcguinness-oauth-mission-child-delegation` | `8427e9b` (kernel, 2026-07-15) + AS wire (branch `feat/child-delegation-wire`, 2026-08-05) | `services/authorization-server/src/kernel/child-delegation.ts` (+ kernel `cascadeChildren`/`findChildren`/suspend-projection, `parent`/`ParentRef`); AS wire in `services/authorization-server/src/adapters/provider.ts` (`extraParams` `parent`/`parent_token`/`child_actor`, creation + child-redemption grants on `/token`, discovery flag) and `services/authorization-server/src/adapters/child-grant.ts` (child-bound grant) | `child-delegation#child-creation`, `#child-client-identity`, `#request-processing`, `#parent-member`, `#strict-subset`, `#cascade`, `#discovery` (kernel flow, terminal cascade, suspend-projection, fan-out accounting; PAR wire params, parent resolve-only, child-bound RFC 7523 grant issuance, discovery metadata all realized; child redeeming AS ITSELF at `/token` (PR4b) and creation relocated onto `/token` as an impl-local grant retiring `POST /child-missions` (PR4c); fully wired, single-issuer) | `services/authorization-server/test/child-delegation.test.ts`, `services/authorization-server/test/child-delegation-endpoint.test.ts` |
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
| `draft-mcguinness-mission-harness` (partial) | `dc7a897` | `packages/mission-core/src/binding.ts`, `services/agent/src/{harness,mediated-harness,harness-scope,egress-gate}.ts`, `services/mcp-payments/src/mcp-transport.ts` | duty 1 fail-closed resume + duty 2 mediated execution environment (real MCP channel, no PEP bypass); `harness#mission-binding` (shared `state_source`/`MissionStatusLease`/`MissionBinding`/`StopPolicy` types, `suppress` realized); `harness#mediated-egress` (execution-environment scope statement, claim-gated channel-class enumeration, sign/verify; default-deny egress gate keyed to the published statement: per-mediated-channel destination sets, state guard first, every request recorded as `EgressEvidence` with emitter role `egress`); `harness#resume-algorithm` (status-continuity: fail closed once `now > status_expires_at`, freshness re-checked at each submission) | `services/agent/test/{harness,mediated-harness,harness-scope,egress-gate}.test.ts`, `services/mcp-payments/test/mcp-channel.test.ts` |
| `@modelcontextprotocol/sdk` | 1.29.0 | `services/mcp-payments/src/mcp-transport.ts` (in-memory transport), `services/mcp-payments/src/mcp-http-transport.ts` (StreamableHTTP transport) | `tools/list`/`tools/call` delegating to the same PEP over two transports. In-memory: mission credential in `_meta` (advances/closes the O-33 transport swap). Real StreamableHTTP (server+client): a DPoP-auth middleware enforces proof-of-possession over HTTP via `validateToken` (canonical `htu`/`htm`; `cnf.jkt` equals the proof thumbprint) before dispatch, with the credential carried in the `Authorization: DPoP`/`DPoP` headers instead of `_meta` | `services/mcp-payments/test/mcp-channel.test.ts`, `services/mcp-payments/test/mcp-http-channel.test.ts` |
| `draft-mcguinness-mission-shaping` | `dc7a897` | `services/agent/src/index.ts` (shapeIntent) | untrusted intent proposal; derivation still bounds | `services/agent/test/harness.test.ts` |
| (eval harness, goal 2) | n/a | `evals` | adversarial + legitimate suites, containment scorecard, CI gate (D24) | `evals/test/evals.test.ts` |
| (vendor test, handbook) | n/a | `evals/src/vendor-test.ts` | four-axis valid-token-but-denied demonstration | `evals/test/vendor-test.test.ts` |
| `draft-mcguinness-mission-orchestration` | `3ce193c` (2026-07-15) | `packages/orchestration` + `packages/mission-core` (anchors `UNWIND_PLAN_TYP`) | `orchestration#reversibility`, `orchestration#unwind-plan`, `orchestration#unwind-plan-integrity`, `orchestration#state-change-behavior`, `orchestration#compensation`, `orchestration#orchestration-evidence` | `packages/orchestration/test/orchestration.test.ts` |
| `draft-mcguinness-oauth-id-continuation-assertion` | [`-00`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-id-continuation-assertion/) | `services/authorization-server/src/kernel/{continuation-assertion,continuation-store}.ts`, `adapters/continuation-grant.ts`, `kernel/cross-domain.ts` (ext), `packages/actor-chain` (collapse), `config/topology.json` (`as-continuation` key), `services/ras` | RFC 8693 token-exchange grant (`identity-continuation` subject token, typ `oauth-identity-continuation+jwt`) yielding a Mission-rooted continuation ID-JAG (the intra-domain ICA transport of the authorization-continuity profile `oauth-mission-continuation`, whose full normative I-D landed in #383); four-signal actor agreement; sender-constrained assertion (`exp-iat` <= 300) + `jti` replay; `identity_continuation_handle` store with grant/session anchors + lifecycle-commit termination; approval-time rooting; dedicated `as-continuation` ES256 signing key on `jwks_uri`; `identity_continuation_supported` discovery + RAS `id-jag-continuation` grant profile (PRs #378-#382) | `services/authorization-server/test/{continuation-grant,continuation-assertion,continuation-store}.test.ts` |
| `draft-zhu-oauth-async-delegation` | `-05` | `services/authorization-server/src/kernel/delegation-family-store.ts` + `kernel.gateActive`, `adapters/continuation-grant.ts` (`request_refresh_token` path), `adapters/provider.ts` (extraTokenClaims family fallback, `rotateRefreshToken`/`ttl.RefreshToken`, terminal revoke) | async-delegation continuation transport: `request_refresh_token` on token-exchange yields a Mission-rooted refresh-token family on a per-delegation oidc Grant (blast-radius isolation), absolute lifetime = Mission `expires_at`, family-revoke on Mission terminal, a single `gateDerivation` count with `gateActive` re-gates, base `subject_token` bound to the acting client; `delegated_refresh_token_profile_supported` discovery. Execution-time evidence carries the continuation hop reference (`jti` + Mission lineage) into the Mission Receipt (`services/mcp-payments`, #386). (PRs #384/#385/#386) | `services/authorization-server/test/async-delegation.test.ts`, `services/mcp-payments/test/{transaction,mcp-channel}.test.ts` |
| `draft-mcguinness-oauth-mission-work-products` | `-latest` (exp) | `services/authorization-server/src/kernel/work-products.ts`, `services/mcp-payments/src/evidence.ts` (`kind:"artifact"` provenance + `buildArtifactEvidence`), `services/console-bff/src/activity-log.ts` (distinct `artifact_producer`) | `work-products#invariant` (no authority by information propagation alone); `work-products#provenance` (policy-free attribution object: exactly `mission_id`/`deployment_id`/`producer`/`created_at`/`parent_artifact?`, `producer` = producing Mission, carried with the product, kept off the evidence store); `work-products#handoff` (non-transitive Mission-to-Mission ingest: `gateActive` never `gateDerivation`, the artifact never contributes to the receiver's effective authority; authority only via a bounded Child Mission). Core axiom filed as issue #402 (PRs #403/#404) | `services/authorization-server/test/work-products-incident-e2e.test.ts` |
| `draft-mcguinness-oauth-mission-cross-org-delegation` | `942d2b0` (2026-08-15) | `packages/mission-core/src/cross-org-presentation.ts` | `cross-org-delegation#chain-presentation` | `packages/mission-core/test/cross-org-presentation.test.ts` |
| `draft-mcguinness-oauth-mission-cross-org-delegation` | `942d2b0` (2026-08-15) | `services/authorization-server/src/kernel/cross-org-chain.ts` + `services/authorization-server/src/kernel/attenuation.ts` (root mapping) + `services/authorization-server/src/adapters/cross-org-grant.ts` + `services/authorization-server/src/adapters/continuation-grant.ts` (`subject_token_type` dispatch) + `services/authorization-server/src/adapters/provider.ts` (crossOrg config) + `services/authorization-server/src/index.ts` (crossOrg config) | `cross-org-delegation#actor-identity`, `#actor-evidence`, `#verification`, `#hop-members`, `#root-issuance`, `#derivation`, `#projection`, `#projection-exchange` | `services/authorization-server/test/{cross-org-delegation,cross-org-grant-endpoint}.test.ts` |
| `draft-mcguinness-oauth-mission-transaction-authorization` | `700499b` (2026-08-17) | `packages/mission-core/src/txn-authorization.ts` | `txn-authorization#resource-challenge`, `#challenge-redemption`, `#transaction-token`, `#offline-verification`, `#two-phase-expiry`, `#failure-semantics` | `packages/mission-core/test/txn-authorization.test.ts` |
| `draft-mcguinness-oauth-mission-transaction-authorization` | `700499b` (2026-08-17) | `services/authorization-server/src/adapters/transaction-authorization.ts` + `services/authorization-server/src/kernel/txn-workflow-store.ts` + `services/authorization-server/src/kernel/transaction-token.ts` (the transaction-token mint) + `services/authorization-server/src/kernel/txn-challenge.ts` (the challenge verifier) + `services/authorization-server/src/kernel/operation-profile.ts` + `services/authorization-server/src/kernel/derive.ts` + `services/authorization-server/src/kernel/child-delegation.ts` + `services/authorization-server/src/kernel/types.ts` + `services/authorization-server/src/adapters/provider.ts` + `services/authorization-server/src/index.ts` | `txn-authorization#applicability`, `#resource-challenge`, `#challenge-redemption`, `#two-phase-expiry`, `#transaction-token`, `#offline-verification`, `#failure-semantics` | `services/authorization-server/test/{txn-endpoint,txn-authorization-e2e,child-delegation}.test.ts` |
| `draft-mcguinness-oauth-mission-transaction-authorization` | `700499b` (2026-08-17) | `services/mcp-payments/src/{txn-challenge,txn-store,pep,server,mcp-transport,mcp-http-transport,resource-metadata}.ts` | `txn-authorization#resource-challenge`, `#transaction-token`, `#two-phase-expiry`, `#offline-verification`, `#challenge-redemption` | `services/mcp-payments/test/transaction.test.ts` |
| `draft-mcguinness-oauth-mission-transaction-authorization` | `700499b` (2026-08-17) | `services/pdp/src/evaluate.ts` + `services/pdp/src/policy-view.ts` | `txn-authorization#applicability` | `services/pdp/test/evaluate.test.ts` |
| `draft-mcguinness-oauth-mission-transaction-authorization` | `700499b` (2026-08-17) | `services/access-request/src/index.ts` | `txn-authorization#challenge-redemption`, `#offline-verification` | `services/access-request/test/txn.test.ts` |
| `draft-mcguinness-mission-substrate` | `b5e35e2` (2026-08-18) | `services/authorization-server/src/kernel/{kernel,mission-id}.ts` | `mission-substrate#basic-gate`, `mission-substrate#approved-context`, `mission-substrate#actor-binding`, `mission-substrate#reference` | `services/authorization-server/test/kernel.test.ts` |
| `draft-mcguinness-mission-runtime-evidence` | `3694449` (2026-08-14) | `services/mcp-payments/src/evidence.ts` | `runtime-evidence#decision-evidence-object`, `runtime-evidence#pre-decision-refusal` | `services/mcp-payments/test/{refusal-evidence,enforcement}.test.ts` |

## Adopted for planning, not yet implemented (pins from the pre-flight spike)

| Spec | Pinned version | Lands in |
|---|---|---|
| `draft-mcguinness-mission-authzen` (PEP evidence, requestable denials) | `02d53dd` | M4/M6 PEP |
| `draft-mcguinness-mission-audit` + SCITT (RFC 9943) | in-repo current | M10 |
| MCP authorization profile | 2025-11-25 (stable) | M4/M8/M9 |
| OpenFGA | `v1.18.1@sha256:efde89d2...6688` | M0 compose (done) |
| `draft-niyikiza-oauth-attenuating-agent-tokens` (AAT substrate) | I-D in progress (no published revision) | attenuation substrate profiled by `services/authorization-server/src/kernel/attenuation.ts` + `packages/mission-core/src/attenuation-chain.ts` (JWS chain, `par_hash` linkage, capability monotonicity, `del_depth`/`del_max_depth`) |

## Notes

- SUPERSESSION (2026-08-12, issue #475 / D67, PRs #477/#479/#478): the core's
  authority-proposal carriage changed. `proposed_authority`-inside-`mission_intent`
  is retired; the proposal rides the standard top-level `authorization_details`
  parameter (PAR); `intent_hash` input is now the task-only Intent (BREAKING for
  any vector whose intent carried a proposal; the repo's four existing vectors
  were unaffected and a fifth `proposal_hash` vector was added); new anchor
  `proposal_hash` (`typ: mission-proposed-authority`, present iff submitted,
  record + introspection, not the claim). The core rows above pin `c2053e5`,
  which predates this; the `@spec` surfaces `mission#submission-via-par` /
  `mission#authorization-derivation` now realize the new carriage in code
  (PR #478). The core pin bump remains deliberate-deferred per D25/D41.
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
  assurance, not a conformance requirement. The draft's second mediation
  boundary is realized as `services/agent/src/egress-gate.ts`: a default-deny
  egress gate whose authoritative input is the published statement (a
  `mediated` channel MAY name its destination set; the claim and the enforced
  allowlist are the same object), applying the fail-closed Mission-state rule
  before any allowlist check and recording every request (permitted and
  refused) as producer-retained `EgressEvidence`. The demo agent's inference
  API egresses only through `gate.guardedFetch()` (`createAnthropic` custom
  fetch), so the live agent has no unmediated egress path; an in-process gate
  supports no containment claim (the `in_memory` -> `"none"` downgrade encodes
  this). Deferred (named, not built): signed
  Harness Evidence + transparency registration + harness key publication;
  session-taint / egress-downgrade (the taint policy is an opaque pass-through;
  the gate is a channel/destination check, not the taint rule);
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
  in AS metadata. (SUPERSEDED 2026-08-11 by D62 / PR #451: child creation is now an
  RFC 8693 token exchange at `/token` (`grant_type=token-exchange`,
  `requested_token_type=urn:ietf:params:oauth:token-type:jwt`, `subject_token` = the
  parent Mission-bound access token, `subject_token_type=access_token`, possession
  proven against the token's OWN cnf, refresh token rejected); the dedicated
  `mission-child-creation` grant and the `parent_token`/PAR carrier are removed,
  dispatched by `handleChildCreationExchange` in `adapters/continuation-grant.ts`. The
  response stays RFC 8693-shaped and the two-grant flow is kept. Expansion likewise
  gains a token-exchange wire (`requested_token_type=access_token`) where it had no
  wire code before.) Deferred to PR4b: the child redeeming that assertion AS ITSELF at
  `/token` (RFC 7523 JWT-bearer), which needs the child actor registered as an OAuth
  client (a `config/clients.json` + demo-data change outside this PR's surface).
  (`services/authorization-server/test/child-delegation-endpoint.test.ts`.)
- PR4b + PR4c close the child-delegation wiring (single-issuer). PR4b registered the
  RFC 7523 JWT-bearer redemption grant on `/token` (`handleChildJwtBearerGrant`) so
  the child actor (`subagent-invoice-extractor`, now a registered client) redeems the
  child-bound assertion AS ITSELF for a DPoP-bound child token. PR4c then relocated
  child CREATION off the bespoke dev-guarded `POST /child-missions` route onto `/token`
  as an impl-local grant (`urn:ietf:params:oauth:grant-type:mission-child-creation`,
  distinct from the child jwt-bearer URN), authenticated by the parent's real
  `private_key_jwt`, satisfying `#request-processing` step 1 with genuine client auth
  in place of the `x-service-token` stand-in, and the house rule "no new endpoints when
  an existing surface carries it". The creation LOGIC (PAR resolve, parent resolve-only,
  `parent`/`parent_mismatch` cross-check, `createChildMission`, `mintChildGrant`,
  `mission_denial_reason` mapping) is unchanged; the `POST /child-missions` route is
  removed (the shared `x-service-token` dev guard remains for the other admin routes).
  The whole `child-delegation-endpoint.test.ts` suite now exercises the full lifecycle
  end-to-end on the OAuth surface with no bespoke route.
  (`services/authorization-server/test/child-delegation-endpoint.test.ts`.)
- Unified cross-enforcement evidence base (`authzen#decision-evidence-object`):
  `EvidenceBase` gains the optional `emitter` (`id` + `role`, roles `pdp`/`pep`/
  `executor` plus the coordinated companion roles `harness`/`egress`) and a
  `scope_statement_digest` slot; Decision Evidence gains the `entry_digest`
  resolved-scope anchor (PDP computes it over the matched Authority Set entry
  under the new `AUTHORITY_ENTRY_TYP` domain separator and carries it in the
  decision context; the PEP copies it onto the retained record), and an
  `EgressEvidence` kind joins the union for the egress enforcement point. All
  fields additive and optional, so existing records stay valid. The evidence
  base deliberately stays in `@mission/mcp-payments`; lifting it to
  `@mission/core` is a named deferral.
  (`services/mcp-payments/test/{enforcement,transaction}.test.ts`,
  `services/pdp/test/evaluate.test.ts`, `services/transparency/test/transparency.test.ts`.)
- Mission Containment kernel (`services/authorization-server/src/kernel/kernel.ts` +
  `kernel/containment.ts`): an issuer-held, versioned, MONOTONIC narrowing overlay on
  an active Mission's effective authority. The approved `authority_set`/`authority_hash`
  stay immutable; `contain()` (legal from `active`/`suspended`, idempotent by
  `event_id`, removal-only union) commits `containment_json` + `version + 1` atomically
  and fires the existing lifecycle-commit fan-out as the fourth commit funnel, a
  metadata-only commit (`prior_state === state`), so the Status List and Mission
  Signals propagate with no new channels. `effectiveAuthoritySet()` (approved minus
  contained; fast path returns the approved set as-is) now feeds every token-mint and
  delegation funnel (decide grant rar, child grant/redemption, deferred, txn, async
  continuation, cross-domain audience scoping, child strict-subset ceiling, attenuation
  root mapping); a fully contained Mission refuses derivation with `GateError`
  `authority_contained`. Containment Evidence (JCS bytes,
  `application/mission-containment-evidence+json`) mirrors the Child Evidence
  conventions; the lifecycle endpoint gains `operation: "contain"`. The PDP join:
  `MissionView` carries the containment DELTA (version + contained entries, not a
  filtered set) so the decision function distinguishes never-approved
  (`out_of_authority`, step 5) from approved-then-contained (`authority_contained`,
  inserted between the entry match and the FGA check, `containment_version` in the
  decision context); `policyViewId` is unchanged (it commits `mission_version`,
  which contain() bumps, so pre-containment pins deny `view_inconsistent`). The
  refresh-path rar conformance fix: `rarForCodeResponse`/`rarForRefreshTokenResponse`
  re-project the stored grant's issuance-time rar copy through
  `effectiveAuthoritySet` (mission via `findByGrant`, else the delegation family
  store), so a derivation never echoes a contained capability; no-containment
  grants pass through byte-identical. Demo: the exhibit gains a containment
  sequence (SIEM tainted-read event over the lifecycle wire, `authority_contained`
  denial beside a permitted uncontained action, Expansion successor restore with
  no containment) and a live AS+PDP+OpenFGA e2e test proves the same sequence.
  (`services/authorization-server/test/{containment,containment-pdp-e2e,async-delegation}.test.ts`,
  `services/pdp/test/evaluate.test.ts`,
  `packages/mission-signals/test/containment-commit.test.ts`.)
- Unified cross-enforcement evidence base (`authzen#decision-evidence-object`):
  `EvidenceBase` gains the optional `emitter` (`id` + `role`, roles `pdp`/`pep`/
  `executor` plus the coordinated companion roles `harness`/`egress`) and a
  `scope_statement_digest` slot; Decision Evidence gains the `entry_digest`
  resolved-scope anchor (PDP computes it over the matched Authority Set entry
  under the new `AUTHORITY_ENTRY_TYP` domain separator and carries it in the
  decision context; the PEP copies it onto the retained record), and an
  `EgressEvidence` kind joins the union for the egress enforcement point. All
  fields additive and optional, so existing records stay valid. The evidence
  base deliberately stays in `@mission/mcp-payments`; lifting it to
  `@mission/core` is a named deferral.
  (`services/mcp-payments/test/{enforcement,transaction}.test.ts`,
  `services/pdp/test/evaluate.test.ts`, `services/transparency/test/transparency.test.ts`.)
