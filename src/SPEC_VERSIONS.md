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
| `draft-mcguinness-oauth-mission-status` | `89ba0b4` (2026-07-16) | `services/authorization-server` (kernel + adapters) | `status#legal-transitions`, `status#state-machine`, `status#mission-status-response` | `services/authorization-server/test/{kernel,tracer}.test.ts` |
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
| AuthZEN ARAP (external, OpenID) | consumed | `services/access-request` | access request submission, task lifecycle, adjudication, action-bound approval object (reevaluate mode) | `services/access-request/test/reevaluate.test.ts` |
| `draft-mcguinness-oauth-mission-expansion` | `dc7a897` | `services/authorization-server/src/kernel/expansion.ts` | successor Mission, `predecessor` member, supersede-on-redemption, approved_until bounding | `services/authorization-server/test/arop.test.ts` |
| AuthZEN AROP (openid/authzen#531) | PR #531 @ 2026-07-20 | `services/authorization-server/src/kernel` (deferred, txn-challenge) | DTR deferred grant + Transaction Challenge, token-issuance completion via Expansion | `services/authorization-server/test/arop.test.ts` |
| DTR (`draft-gerber-oauth-deferred-token-response`) | via AROP #531 | `services/authorization-server/src/kernel/deferred.ts` | `completion_mode=deferred`, `deferral_code`, `authorization_pending`, deferred grant, idempotent submission | `services/authorization-server/test/arop.test.ts` |
| Txn Challenge (`draft-rosomakho-oauth-txn-challenge`) | via AROP #531 | `services/authorization-server/src/kernel/txn-challenge.ts` | signed challenge (txn/authorization_details/iss/aud/reason), txn-bound single-use audience-restricted token | `services/authorization-server/test/arop.test.ts` |

## Adopted for planning, not yet implemented (pins from the pre-flight spike)

| Spec | Pinned version | Lands in |
|---|---|---|
| `draft-mcguinness-mission-authzen` (PEP evidence, requestable denials) | `02d53dd` | M4/M6 PEP |
| `draft-mcguinness-oauth-mission-status` (Status List, introspection projection) | `89ba0b4` | M3 freshness |
| `draft-mcguinness-svc-connectivity-disco` | repo main @ 2026-07-20 | M8 |
| `draft-mcguinness-oauth-mission-cross-domain` + ID-JAG | in-repo / datatracker current | M9 |
| `draft-mcguinness-mission-audit` + SCITT (RFC 9943) | in-repo current | M10 |
| MCP authorization profile | 2025-11-25 (stable) | M4/M8/M9 |
| `@modelcontextprotocol/sdk` | 1.29.0 | M4 |
| OpenFGA | `v1.18.1@sha256:efde89d2...6688` | M0 compose (done) |

## Notes

- `oidc-provider@9.10.0` ships no first-party TypeScript types; the build
  depends on `@types/oidc-provider@9.5.0` (behind the runtime). Gaps handled
  with narrow local aliases (e.g. `InvalidAuthorizationDetails`, present at
  runtime in 9.10, absent from the 9.5 types). Re-check on any provider bump.
