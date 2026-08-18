# Mission Reference Implementation Plan

Living document. Tracks the plan, the decisions made with their rationale, and the
open/resolved issue log for an end-to-end reference implementation of the Mission
family at the **Runtime-Enforced** assurance level.

- Location: all implementation code lives under `src/` in this repo.
- Language: TypeScript (Node 22+), pnpm workspaces.
- Maintenance: this document is updated by direct commits to `main` (no PRs),
  per the 2026-07-20 workflow decision. Implementation milestones still land
  as their own PRs (see § Milestones).
- License: implementation code under `src/` is BSD-2-Clause (own LICENSE
  file + `license` fields, D40), harmonizing with the TLP's code-component
  terms; the drafts remain under the repo's IETF terms.
- Last updated: 2026-07-21.

How to use this document in an implementation session: read § 1 (goals),
then only the decision rows (D-n) and open issues (O-n) referenced by the
milestone you are working, then that milestone's entry. Do not re-read the
whole document. Implementation bugs go to GitHub issues on this repo; the
O-log records design questions only.

## 1. Goal and Conformance Target

Two goals, equal in rank:

1. **Reach the level.** Build a complete, running system that reaches
   **Runtime-Enforced Mission conformance** as defined by the six invariants
   in `draft-mcguinness-mission-architecture.md` (§ Runtime-Enforced Mission
   conformance): the four Baseline invariants plus per-action runtime
   enforcement and evidence that joins.
2. **Validate the architecture and the specs.** The implementation is a
   validation instrument for the draft family: every architecture decision
   and normative requirement it touches gets tested by being built. Friction
   is a deliverable, not a nuisance: spec defects, ambiguities, requirements
   that are disproportionately hard to implement, complexity worth
   simplifying, and interop issues are captured in the Spec Feedback Log
   (§ 8) with a disposition, and the final milestone (M14) consolidates them
   into a spec-feedback report. The eval harness (M13) is the empirical arm:
   it measures the containment claims against adversarial agent behavior
   rather than assuming them.

Documents implemented (the required set for the level, per README § Assurance Levels):

| Draft | Role in this build |
|---|---|
| `draft-mcguinness-oauth-mission` | Core issuance profile: PAR intent, approval event, Mission Record, anchors, `mission` claim, subset rule, state-gated issuance, introspection |
| `draft-mcguinness-mission-runtime` | Abstract PEP/PDP contract, Enforcement Scope Statement, core + transaction-assurance tiers |
| `draft-mcguinness-mission-authzen` | Concrete AuthZEN binding: decision envelope, evidence objects, requestable denials, capability source binding |
| `draft-mcguinness-oauth-mission-status` | Freshness source: signed, `mission_id`-keyed Status |
| `draft-mcguinness-oauth-mission-expansion` | Successor-mission widening (backs AROP token issuance) |
| `draft-mcguinness-mission-shaping` | Client-side Intent Shaping: the untrusted proposal arm (shaper proposes, issuer derives, approver decides) |
| `draft-mcguinness-mission-harness` (partial) | Only the minimal harness duty: agent-side stop on non-active mission state at resume; session/task-graph binding stays out |
| `draft-mcguinness-svc-connectivity-disco` (external repo) | Resource discovery: the per-user service connectivity catalog the agent bootstraps from |
| `draft-mcguinness-mission-audit` | SCITT transparency for Mission evidence: Signed Statements, Receipts, per-mission feeds, offline verification |
| `draft-mcguinness-oauth-mission-cross-domain` | One Mission honored in the SaaS trust domain: cross-domain grant (ID-JAG profile), audience-scoped projection, Resource AS validation |
| ID-JAG (external, IETF OAuth WG) | `draft-ietf-oauth-identity-assertion-authz-grant`, the recommended cross-domain grant profile |
| MCP EMA (external, MCP auth extension) | Enterprise-Managed Authorization: capability + metadata declarations and the ID-JAG redemption flow for the SaaS MCP server |
| `draft-mcguinness-oauth-actor-profile` (external repo, local checkout) | Base actor profile: normalized RFC 8693 `act` chains (`act.iss`, `act.sub`, `sub_profile`), presenter transitions, metadata, introspection, errors |
| `draft-mcguinness-oauth-ai-agent-instance` (external, datatracker) | AI agent instance identity: `agent_instance_id` / `agent_platform` / `agent_model` presented via Client Instance Assertion carriers and surfaced into `act` |
| CIA-CORE (external) | `draft-mcguinness-oauth-client-instance-assertion`, the carrier and token-endpoint processing base the instance profile builds on |
| `draft-mcguinness-oauth-mission-management` (partial) | Fleet enumeration and per-mission lifecycle operations backing the operator app; scope subset pinned in O-32 |
| AuthZEN ARAP (external, OpenID) | Access request / approval lifecycle behind requestable denials |
| AuthZEN AROP (external, openid/authzen PR #531) | Token-issuance completion: DTR and Transaction Challenge bindings |

Out of scope for the first pass: signals (SSF push), harness session binding
(only the minimal stop-on-non-active duty is in scope),
child delegation (Child Missions; token-level actor chains ARE in scope),
metering (cumulative caps land there; D28), mandate, CIBA binding, and the
actor suite companions (receipts, proofs, authority bounds).
Implementation non-goals: persistence, high availability, horizontal scale,
and production hardening. In-memory stores and dev keys are deliberate;
nothing here is production code.

Each is a candidate follow-on once the level is reached. Naming note: resource
discovery in this plan means `svc-connectivity-disco` (the service catalog);
the family's own `draft-mcguinness-mission-discovery` (open-world Encounter
adjudication) is a different concern and is also out of scope.

## 2. Decision Log (captured answers)

Decisions confirmed with Karl on 2026-07-20:

| # | Question | Decision |
|---|---|---|
| D1 | What is AROP? | The AuthZEN Access Request OAuth Profile, openid/authzen PR #531: ARAP's token-issuance completion mode for OAuth, with DTR / CIBA / Transaction Challenge transport bindings |
| D2 | Demo domain for the MCP tool estate | Accounts payable: list/read invoices, vendor lookup, schedule payment, execute wire transfer (high-consequence), send remittance email (external communication) |
| D3 | AS construction | panva `node-oidc-provider` (PAR, RAR, DPoP, introspection built in); token exchange and the DTR deferred grant added as custom grants; mission gating via provider hooks |
| D4 | Agent client | Scripted scenario runner (deterministic, no API key) plus an optional LLM chat mode via the Anthropic API when a key is present |
| D5 | AROP binding scope | DTR + Transaction Challenge. CIBA out of scope |
| D6 | AROP x Mission composition | SUPERSEDED by D42. (Original: AROP token issuance backed by a Mission Expansion. Corrected: AROP issues subset-of-Mission grants only and never expands; Expansion is its own flow.) |
| D7 | UX shape | Separate apps per persona: approver app, operator app, agent console |
| D8 | Resource discovery | Adopt `draft-mcguinness-svc-connectivity-disco` (github.com/mcguinness/draft-mcguinness-svc-connectivity-disco); the Mission AS co-hosts the Catalog Provider role and serves the Service Catalog Endpoint, advertised as `service_catalog_endpoint` in its RFC 8414 metadata |
| D9 | Catalog status semantics | Per-connection `status` is mission-derived: an active covering mission renders `connected`, approvable issuance renders `consent_required`, revoked/suspended renders `unavailable` |
| D10 | request-access linkage | Catalog `request-access` links deep-link into the ARS intake, joining discovery of unreachable services to the approval flow |
| D11 | Audit depth | Full `mission-audit` SCITT profile: in-memory Transparency Service (append-only Merkle log, COSE Signed Statements via hash envelope, Receipts, signed tree heads), evidence registered by the AS, PDP, and MCP server, five-step offline verification |
| D12 | Observability | OpenTelemetry in every service with W3C trace context propagated across OAuth requests, PDP evaluations, and MCP tool calls; Jaeger (docker-compose) for traces; pino structured logs carrying `trace_id` and `mission_id` |
| D13 | Trace-evidence correlation | Evidence and audit records carry the producing span's `trace_id` as a non-normative extension member (consumers ignore unknown members); the operator timeline links evidence to its trace |
| D14 | Cross-domain SaaS leg | Add a second trust domain per the cross-domain companion: internal MCP server plus a SaaS MCP server fronted by a Resource AS (RAS), reached via ID-JAG with MCP Enterprise-Managed Authorization (EMA) |
| D15 | SaaS app | The SaaS MCP server represents "LedgerCloud", an accounting/books SaaS: vendor bank details, payment journal entry posting |
| D16 | SaaS estate assurance | The SaaS estate runs at lifetime-bounded reliance: the SaaS MCP server enforces from the token alone (mission claim + audience-scoped authorization_details, short lifetimes sized to the cross-domain lease); no PDP in that domain, contrasting the levels in one demo |
| D17 | RAS construction | The RAS is a second node-oidc-provider instance with a custom RFC 7523 JWT-bearer grant for ID-JAG redemption (uniform AS codebase preferred over a slim custom RAS) |
| D18 | Actor suite depth | Base actor-profile only: conformant nested `act` chains with required `act.iss`, presenter continuation/rebind, local max depth, `actor_unauthorized`, AS + protected-resource metadata, introspection surfaces. Receipts, proofs, and bounds are follow-ons |
| D19 | Agent instance | Full ai-agent-instance profile: every agent and sub-agent holds a per-instance key and presents Client Instance Assertion evidence (`agent_instance_id`, `agent_platform`, `agent_model`) at token requests; AS validates carriers and publishes `ai_agent_instance_profile_supported`; surfaced `sub_profile` carries `ai_agent client_instance`; PEPs get per-instance controls |
| D20 | Sub-agent delegation demo | Orchestrator to sub-agent token exchange is a first-class scenario (13) and milestone (M2, demoed end to end in M12): authority narrows by subset, the chain grows a hop, the PDP sees the root-to-leaf `context.actor.act` |
| D21 | act.cnf stance | The `act.cnf` conflict is filed upstream (actor-profile issue #4); this implementation validates proof of possession against the top-level `cnf` only and treats `act.cnf` as informative |
| D22 | Handbook alignment | From the handbook-cover review: Shaper (shaping draft) in scope with the compromised-shaper test; minimal harness stop-on-non-active with the 02:00-resume scenario; five-laws mapping table; vendor-test demonstration + Field Reference checklist in M14; mission-scoped `tools/list`; wire-exhibit mode; control-plane framing. Declined: consent evidence remains undecided (O-11 stays open) |
| D23 | Spec validation goal | Validating the architecture decisions and the specs is a co-equal goal of the implementation; spec friction (defects, ambiguities, hard-to-implement requirements, simplification candidates, interop issues) is tracked in the Spec Feedback Log with per-entry dispositions, and every milestone exit includes a spec-feedback pass |
| D24 | Evals | An eval harness (milestone M13) mirrors the D4 split: a deterministic adversarial suite (CI-runnable, no API key) plus an optional LLM red-team mode; runs are scored on containment (zero unauthorized side effects), denial correctness, evidence completeness, over-blocking rate on legitimate flows, and freshness-bound compliance, emitting a scorecard artifact |
| D25 | Pre-implementation readiness | Adopted: the pre-flight spike (O-1/O-2/O-25/O-26/O-27 before M1 design hardens), the testing-and-delivery conventions (vitest, in-process scenario composition, `src/**`-filtered CI separate from draft-build CI, toolchain pinning, `SPEC_VERSIONS.md`), the headless adjudication path + side-effect oracle, O-33, and the non-goals statement. Declined for now: the determinism-by-design bundle (injectable clock/RNG, checked-in deterministic dev keys); revisit if golden files, exhibits, or evals prove flaky or unstable |
| D26 | Mission authority in FGA (debate #1) | Hybrid contextual: OpenFGA stores only the durable domain substrate (invoice ownership, vendor approval, roles); mission authority is derived from the Mission Record as **contextual tuples** per check, computed by the PDP alongside the state/freshness check. No dual-write, revocation is instant via the record, `policy_view_id` = content hash of (Mission Record version + FGA model version). Companion feedback logged as S-5 |
| D27 | Store architecture | Record-shaped stores (missions, approval events, ARAP tasks, permits/leases, ledger/outbox/journal oracles, catalog entries, evidence index) live in SQLite `:memory:` (better-sqlite3) behind repository interfaces: UNIQUE constraints and transactions where the spec implies them, SQL for management/catalog/timeline queries. No ORM; optional non-default `--persist` flag; pure in-process structures where SQL adds nothing (keys, Merkle nodes); OpenFGA keeps its own memory storage; node-oidc-provider artifacts stay on its default adapter |
| D28 | Stateless PDP (debate #2) | The PDP is a pure decision function (envelope, FGA check with contextual tuples, fresh record read, clock, keys). It **declares** permit properties in the decision response (single-use decision identifier, `permit_expires_at`, lease requirement, PEP/channel binding); the PEP **owns** redemption and lease state (atomic redeem-on-execute in its store; replay refused as `permit_consumed` in Execution Evidence). ARAP linkage stays stateless via the signed `binding_token`; the Status freshness cache is a soft optimization only; evidence is emitted outward, never read back as decision input. Cumulative caps are deferred to the metering follow-on: this build enforces per-payment caps only. Companion feedback logged as S-6 |
| D29 | Two-tier freshness (debate #3) | One mechanism, two consumption modes, both spec branches exercised: signed Status is the single freshness surface. Core tier consumes it through the polled cache under the published staleness bound. `execute_wire_transfer` (irreversible) takes the **immediate-check** branch: a cache-bypassed Status read at decision time plus the execution lease, so revocation denies instantly. `send_remittance_email` (external commitment) takes the **single-use-permit-within-bound** branch plus the egress PEP. Fail-closed when Status is unreachable: high-consequence actions deny immediately; the core tier rides the cache until the bound expires, then fails closed. Introspection stays implemented as an AS capability; the bound, fail-closed posture, and skew assumptions are published in the Enforcement Scope Statement. Branches revised by D33 |
| D30 | Single AS, mission-kernel (debate #4) | One AS service, validating the core profile's co-location claim (Mission Issuer = the OAuth AS; the split shape is the MAS binding declined in R-8, and one AS keeps one issuer/one `jwks_uri`/one metadata document). Internally, a **mission-kernel** module (mission records, approval events, derivation, status, expansion, catalog computation, management ops, cross-domain projection policy) behind a typed interface; node-oidc-provider hooks and the custom HTTP routes are thin adapters over it. Boundary enforced: hooks call the kernel only through its interface, the kernel never imports provider types. The O-2 go/fallback decision is scoped to the adapter layer; a future MAS follow-on lifts the kernel |
| D31 | Act-chain transform ownership (debate #5) | The PEP flattens the token's nested `act` chain into the root-to-leaf `context.actor.act` array via `packages/actor-chain` (it already validated the token, and only the PEP can verify proof-of-possession); the PDP performs shape and consistency validation on the supplied chain (non-empty, `iss`/`sub` per entry, root consistent with `subject`, leaf consistent with `client_instance_id`) without becoming credential-aware. Golden transform vectors live in the shared package and are the candidate contribution behind S-2 (normative spec vectors) |
| D32 | Evidence retention (debate #6) | Feed-driven distributed: producers (AS, PDP, MCP server) retain their own evidence and Receipts in their own stores; the Transparency Service holds hash commitments only. The operator timeline is assembled by walking the mission's transparency feed, retrieving evidence from producers under access control, and verifying digests on render, so the timeline is a continuous run of the audit draft's five-step verification; tampering renders as a failed row. Direct producer queries remain for pre-M10 development and tests |
| D33 | Freshness plane, production form | Revises D29's branches; both recognized freshness sources, each in its production role. Polled plane: the **Mission Status List** (the companion's optional IETF Token Status List profile: signed compressed 2-bit array, `status_list` refs on the Status response/introspection projection, list `ttl` as the published bound, anti-oracle indices) backs the PDP's core-tier cache with one fetch per window. Immediate check on irreversible actions: **introspection with the mission projection** (one authenticated call validates credential standing AND mission state); the PDP's signed Decision Evidence records the observation. External commitment keeps the permit-within-bound branch. The per-mission signed Status operation remains the authoritative surface |
| D34 | Operation Profile + business state | `payments-runtime-profile-v1` is an M0 architecture artifact: exact action/resource URIs, JSON schemas and normalization per tool, money as integer minor units in decimal strings + ISO 4217 (never a JS `number`), authoritative vs caller-supplied fields, parameter-digest membership + resource-version binding, idempotency-key construction, permit lifetime/commit point/evidence fields. The payments service is authoritative for business state: the PEP loads invoice/vendor records, builds effective parameters carrying their versions for the PDP, and conditionally re-verifies those versions at commit; agent-supplied amounts/payees are never authoritative. Resource policy (invoice payable, vendor active, not already paid, remittance only after successful payment) is defined independently of Mission authority |
| D35 | BFF topology | The agent service is the Agent Console's BFF and exclusively owns the OAuth/DPoP/client keys; a dedicated `services/console-bff` owns approver/operator browser sessions (HttpOnly SameSite cookies) and hosts the feed-driven audit read model (joins, orphan detection, sequence-gap checks per `(Mission, emitter)` per the companion). Browsers never hold service credentials or call service-only endpoints |
| D36 | Irreversible operation state machine | `reserved -> permit_consumed -> connector_committed -> evidence_emitted -> reconciled`, owned by the payments service; the ledger/outbox connectors take an operation idempotency key; the execution lease covers validation and pre-commit, and after connector commit cancellation is meaningless (the commit point is defined in the Operation Profile). No PDP outcome callback: duplicate suppression is PEP-side (operation state + idempotency key), preserving D28's stateless PDP |
| D37 | Approval ownership + governance | The AS owns Mission/Expansion interactions and OAuth pending artifacts (deferral codes, transaction ids); the ARS owns ARAP/AROP tasks and approvals; the AS stores the task handle and validated terminal approval and is the only credential issuer; approval completion never directly executes an action. An AROP approval never satisfies `action_approval_required` implicitly: the parameter-bound approval is explicitly passed as `context.approval` for PDP validation. Governance: missions containing writes or irreversible actions require Bob (subject != approver); Alice self-approves read-only missions only |
| D38 | Token, client, and interop profile | JWT access tokens validated locally (issuer, audience, expiry, `mission`, `cnf.jkt`); the agent is a confidential client using `private_key_jwt` with a separate DPoP key, both owned by the agent service; DPoP checks (replay cache, nonce policy, `ath`, `htu`, `htm`, `iat`, `jti`) are explicit tests; one canonical MCP resource URI is used byte-for-byte in PRM, OAuth `resource`, token audience, DPoP, AuthZEN context, and evidence; MCP pinned to the stable 2025-11-25 authorization profile (draft changes tracked via O-20/O-33) |
| D39 | Hardening bundle | Per-edge channel/auth/key matrix as an M0 artifact (browser->BFF, agent->AS, agent->MCP, PEP->PDP, AS<->ARS, PDP->OpenFGA, producers->transparency), OpenFGA with pre-shared auth + TLS from setup; separated key purposes (AS tokens/status, PDP evidence + `binding_token`, PEP evidence, transaction challenges, transparency). FGA hygiene: explicit `authorization_model_id` on every check, higher-consistency mode on checks after domain-substrate writes, 100-tuple write limit respected in seeds. Restart semantics without persistence: per-boot instance epochs bound into permits (a restarted PEP rejects prior-epoch permits), no deterministic ID reuse after reseeding, pending ARAP/AROP work terminally unavailable after its owner restarts, unknown state fails closed. Dependency policy: pin at the pre-flight spike (first oidc-provider version that passes), OpenFGA image by digest, MCP SDK + spec revision |
| D40 | Final readiness sweep | `src/` code is BSD-2-Clause (own LICENSE, landed in M0). Execution conventions: a live milestone status table in § 5, a per-milestone definition of done (tests green, spec-feedback pass done, status + logs updated, PR merged), implementation bugs tracked as GitHub issues (the O-log stays design-only), and a how-to-use note for implementation sessions. The M0 channel/key matrix artifact includes a trusted-base statement (shaper, agent, and tool outputs untrusted; AS/PDP/ARS/PEPs/transparency trusted; the headless adjudication path trusted-but-test-only). Each scenario is one named spec file with a stable ID referenced from milestone exits; M12 ships `DEMO.md`, the guided walkthrough matching the runner |
| D41 | Spec traceability | `SPEC_VERSIONS.md` is a per-spec traceability matrix (spec, pinned version, implementing components, conformance tests) and spec-derived code carries greppable `@spec <doc>#<section>` tags, so a spec update resolves to a concrete implementation change list; every version bump is deliberate and names its affected modules and tests |
| D42 | AROP never expands (supersedes D6) | Reconciliation of Karl's plan revision. AROP issues **only a grant that is a subset of both the originating request and the active Mission's Authority Set**; it never creates or widens a Mission. Widening is a separate **Mission Expansion** flow (standard PAR submission with `predecessor` + sender-constrained `predecessor_token`, fresh approval, authorization-code redemption, atomic successor activation / predecessor supersession). Every AROP-issued token carries the active Mission reference unchanged and stays subject to per-action runtime enforcement. M7's inline `createExpansion`-in-the-DTR-flow is a defect against this and is realigned |
| D43 | Explicit freshness table (refines D29/O-8) | Published per-class bounds: `consequential_read` = signed Status cached, 60 s; `consequential_write` = signed Status cached, 15 s; `irreversible_action` = introspection or signed Status on every action, 5 s, single-use permit with an execution lease <= 5 s. Max clock skew 1 s, never extending a bound; missing/expired/unverifiable/unrefreshable state fails closed. Action classes are named `consequential_read` / `consequential_write` / `irreversible_action` (external communication is an `irreversible_action` with an external-communication predicate) |
| D44 | Conformance + trust-boundary rigor (folds Karl's revision) | Adopt as first-class: a living conformance matrix from M0 (every normative requirement in a claimed role -> component + test + evidence artifact), all service-to-service traffic HTTPS with mutual TLS on PEP<->PDP, ES256-signed JCS-canonical Decision/Execution/Refusal evidence with an audit verifier (signature, typ, emitter/scope binding, per-Mission sequence continuity, decision/execution joins, parameter-digest continuity), and the Enforcement Scope Statement as a separate structured artifact (the runtime profile defines no metadata member for it) |
| D45 | Materialization stays contextual (D26 wins over the revision) | Karl's plan revision described a signed, versioned "trusted-compiler" materialization artifact; this session's debate #1 (D26) chose contextual tuples derived per check, and that stands. Ported from the revision: the precise `policy_view_id` commitment (content hash over a canonical `mission-policy-view` envelope of mission version + authority_hash + policy_version + FGA model id). The stored-artifact vs contextual-tuple divergence from the spec's materialization language remains logged as S-5 |
| D46 | AROP completion via Transaction Challenge, hybrid (settles S-3) | JIT approval completes by AROP **token issuance** over the Transaction Challenge binding, never as an agent-supplied tool input. The RS signs a `transaction_challenge` (binds the operation + `parameter_digest`); the **client** presents it once to the AS `transaction_authorization_endpoint`, which mints a `transaction_authorization_id` continuation handle bound to the validated challenge + client `cnf` and polled by the client (client-driven; polling is native to the txn binding, not a DTR handoff, which is a separate alternative binding). On approval the AS issues a single-use DPoP-bound `txn-token` carrying the **active Mission unchanged** (D42) plus the approval; the RS validates that AS-signed token and derives `context.approval`, and the **unchanged PDP step 8** validates it (parameter_digest + age). Hybrid: the approval's source is the AS signature and its carrier the trusted RS, so the reevaluate primitive is preserved and nothing rides the client wire. Changes M6's completion mechanism from ARAP reevaluate-with-agent-context to AROP token issuance; the ARAP `requestable`/`access_request` path is retained as a dormant capability. Resolves S-3; realigns the txn path to D42 (scenario 7 carries the active Mission, no Expansion) |
| D47 | Mission harness: the mediated MCP channel is the product (increment 1) | The harness realizes the mission-harness profile's two duties as consume-and-gate checks at boundaries the execution engine already has (the draft's two-ledger separation: never copy Mission state into engine state). Increment 1 (PR #357): duty 2 is a real `@modelcontextprotocol/sdk` channel (in-memory transport) whose `tools/list`/`tools/call` delegate to the **unchanged** PEP, with the mission access token crossing IN the request under a namespaced `_meta` key and validated server-side into `TokenFacts` (a bare `TokenFacts` is never accepted over the wire); duty 1 is `resumeGuard` composing the existing `checkOnResume` (fail-closed). A no-bypass test proves the mediated path enforces IDENTICALLY to the direct PEP (parity + zero side effects) and that a credential-less client gets an empty `tools/list` + `invalid_credential`. Because the PEP is now a real MCP server, the agent framework is a swappable MCP client: increment 2 (PR #358) shipped the **Vercel AI SDK** loop as the reference binding (in-process, widest reach, only the LLM call needs a key): the planner's tools delegate to `MediatedHarness.callTool` (the only tool path), a key-free `MockLanguageModelV3` test proves it cannot escape the channel (adversarial denied + ledger unchanged, in-authority permit, fail-closed resume, mission-scoped toolset), and the live loop is opt-in via `pnpm agent`; `ai@7.0.41` / `@ai-sdk/anthropic@4.0.23` pinned, with the **Claude Agent SDK** noted as the MCP/EMA-native alternative (its loop runs in a spawned `claude` CLI subprocess, which fights this repo's in-process/deterministic-CI composition). LangGraph rejected: its checkpointer persists execution state, but resume is a consume-and-gate check, not persistence, so adopting it would copy Mission state into engine state (draft-forbidden). Carry-forward (resolved): increment 1's `validateMissionToken` skips live DPoP proof-of-possession (no HTTP request over the in-process transport); the full `validateToken` (with PoP) now applies at the real HTTP transport, shipped in **harness increment 3** (PR #364: a StreamableHTTP transport + a DPoP-auth middleware enforcing PoP per request; a token with no/mismatched proof is rejected before the PEP). The in-memory channel keeps the no-PoP path by design |
| D48 | Companion suite: five drafts implemented in parallel | Research-first then parallel worktree-isolated builds, one verified PR each. **Status List** (PR #366): `statuslist+jwt`, 2-bit `lst` (ZLIB), anti-oracle random index allocation, `GET /statuslist/:id`; it introduced the shared kernel `onLifecycleCommit(commit)` hook (synchronous, built from the re-read post-UPDATE row) and fixed two latent bugs (`allMissions` skipping `applyExpiry`; `supersedeOnRedemption` bypassing `setState`). **Signals** (PR #368): `secevent+jwt` lifecycle SET — the push complement to the list's pull — with a version-idempotent/anti-revive receiver, composed onto the SAME hook at the AS construction site (no funnel re-hook). **Harness completion** (PR #365): execution-environment scope statement + channel-class enumeration (completeness required only under an agent-compromise-resistant claim) + status-continuity fail-closed past `status_expires_at`; landed the shared `@mission/core` `StateSource`/`MissionStatusLease`/`MissionBinding` that Signals + Orchestration reuse; fully additive. **Attenuation** (PR #367): holder-side offline AAT JWS chain (macaroon-caveat narrowing) — root ⊆ Authority via `isSubsetSet`, child ⊆ parent via a `tools`-map comparator in `@mission/core`, leaf enforcement reusing `out_of_authority`; `derive.ts`/`actor-chain` untouched. **Orchestration** (PR #369) is the saga/**unwinding+compensation** profile (NOT parent→child): reversibility floor, unwind-plan integrity hash (reproduces the draft's published vector under `computeAnchor`), the 5-step state-change with the staleness asymmetry, compensation-authority basis (never the terminated Mission's authority). Final combined gate: 230 tests / 0 skipped, evals 100%. Reframe: `mission-orchestration` ≠ parent→child sub-agents (that is the separate, unimplemented `oauth-mission-child-delegation`, O-38). Deferrals logged: S-15, O-37, O-39 |
| D49 | Child-delegation deferrals resolved as a verified stacked 4-PR set | The `oauth-mission-child-delegation` boundary left by O-38 (PR #370) was closed in dependency order, one verified worktree PR each, gate green at every link. **PR #371** (`AuthorityEntry.delegation` core extension): `intersect()` carries and narrows a per-entry `delegation` member (inherit-by-default from the ceiling; ceiling-absent yields non-delegable, the compromised-shaper property), `isSubsetEntry()` treats it as narrowing (a candidate omitting delegation passes; introducing it on a non-delegable grantor fails), and `deriveAttenuationRoot` derives `del_max_depth` from it. This closes S-15. **PR #375** (fan-out accounting + child evidence): per-entry justifying selection, `max_children`/`max_child_depth`/`allowed_child_actors` caps, on-switch `delegation_not_permitted`, and a JCS `application/mission-child-evidence+json` record with a `created`/`denied` decision. **PR #373** (suspend-projection + restore-on-resume): the one reversible cascade trigger, with expiry precedence, independent-suspend safety, the ancestor-active derivation gate, and a Signals lift-acceptance test. **PR #374** (PAR wire + child grant + discovery): `parent`/`parent_token`/`child_actor` params (front-channel guard, resolve-only parent lookup, `parent_mismatch`), the RFC-7523-shaped child grant assertion, and `mission_child_delegation_supported`. Merged to main 2026-08-05; final gate 273 passed / 1 skipped. Remaining deferrals: cross-issuer (the draft defers it; `child.issuer = parent.issuer` holds), PR4b (the child redeems the assertion as itself at `/token`), and relocating child creation from the dev-guarded `POST /child-missions` route to `/token` via `registerGrantType` (PR4b and the route move both need child-actor client registration). Both later closed by D50; only cross-issuer remains. |
| D50 | Child redemption at `/token` + creation relocated to a `/token` grant (PR4b/PR4c) | The two follow-on deferrals from D49 landed as stacked PRs on 2026-08-05. **PR #376 (PR4b):** registered the `subagent-invoice-extractor` OAuth client and added the RFC 7523 JWT-bearer redemption grant so a child actor redeems its AS-minted assertion as itself at `/token`, receiving a DPoP-bound access token whose `cnf` is the child's own key, `authorization_details` the child Authority Set, and `mission` claim the parent lineage; the security gate requires the assertion's named redeemer to equal the authenticated client, and `gateDerivation` runs exactly once via `extraTokenClaims`. **PR #377 (PR4c):** relocated child creation from the dev-guarded `POST /child-missions` route to a `/token` grant (`urn:ietf:params:oauth:grant-type:mission-child-creation`, impl-local) under real `ap-agent` `private_key_jwt` auth, and retired the bespoke route; the full child lifecycle now runs on the OAuth surface. Final gate 278 passed / 0 skipped. Only cross-issuer remains deferred. |
| D51 | Authorization continuity: the `oauth-mission-continuation` profile + transports | Separated three axes the first-cut design conflated: identity continuity (who is acting), authorization continuity (what work remains authorized, under which constraints, on whose approval), and execution-time evidence. New OAuth-wire profile `oauth-mission-continuation` (NOT a substrate row: the substrate doc restates no definition, and the continuity semantics are applications of existing requirements): a Mission is the durable, grant-anchored root; identity-continuity transports carry the acting identity; the load-bearing invariant is that a continuation handle grants nothing and every continued grant re-passes the `active` gate (continuity is never authority). Transports coded: **ICA** (`draft-mcguinness-oauth-id-continuation-assertion`, intra-domain short-lived ID-JAG; PRs #378-#382) and **async delegation** (`draft-zhu-oauth-async-delegation`, intra-domain long-running Mission-rooted refresh-token family on a per-delegation oidc Grant for blast-radius isolation, absolute lifetime = Mission `expires_at`, family-revoke on Mission terminal, a single `gateDerivation` count with a non-incrementing `gateActive` re-gate on every refresh, base `subject_token` bound to the acting client; PRs #384/#385); cross-domain projection is the cross-boundary transport (existing). Execution-time evidence records the continuation hop reference (`jti` + Mission lineage) in the Mission Receipt digest (#386). Non-OAuth bindings dispositioned by composition bullets: AAuth over-time continuation is native (the `(approver, s256)` reference + PS state-gated issuance), cross-workload declined by design; UMA's PCT already realizes the invariant. Docs (#383): the full normative `draft-mcguinness-oauth-mission-continuation` I-D + architecture Continue verb + README + cross-domain relationship + AAuth bullet + SPEC_VERSIONS. Merged to main 2026-08-06; final gate 359 passed / 0 skipped. Deferred: async cross-issuer, a cross-client-substitution negative test (needs a second async-capable client), evidence mirroring onto Decision/Refusal Evidence and the attenuation path, and full draft conformance (scheduled-continuation rooting, disclosed-depth) beyond the chosen slice-plus-lifecycle-plus-RAS scope. |
| D52 | Agent Access Model deltas adopted: Mission Containment, egress gate, unified evidence | Reviewed Cloudflare's Agent Access Model against the family: it maps near-1:1 onto existing profiles (task template/ceiling = Mission + derivation, per-request engine = PDP/PEP, activity log = evidence/receipts), validating the architecture; four genuine deltas were adopted (2026-08-06, PRs #387-#391). **Mission Containment** (new companion `draft-mcguinness-oauth-mission-containment`, #388 + kernel #389 + PDP/demo #391), the family's rendering of the "trust ratchet" in family vocabulary: an issuer-held, versioned, MONOTONIC narrowing overlay on a live Mission's effective authority. `authority_hash` stays immutable (containment is evaluated state, mirroring Status discharge: completion retires an entry because work is done, containment because trust was lost); `contain()` is union-only and idempotent per event_id, a metadata-only commit that bumps the state `version` and rides the existing lifecycle fan-out (Signals `state == prior_state`; the Status List bit deliberately unchanged, corrected during authoring against the Status draft's normative text); `effectiveAuthoritySet()` feeds every mint/delegation funnel including a refresh-path rar conformance fix; PDP denies `authority_contained` (approved-then-contained, distinct from `out_of_authority`, expansion-eligible); restore only via an Expansion successor whose approval MUST surface the predecessor's containment history (anti-laundering). Removal-only v1; issuer-held policy with the `controls.containment` seam named. **Egress gate** (#390): the harness draft's second mediation boundary realized as a default-deny in-process gate keyed to the published scope statement (`destinations` on mediated channels; `egress_undeclared`/`egress_destination_unlisted`; fail-closed state guard first; no containment claim); demo agent inference calls routed through `guardedFetch`. **Unified evidence contract** (#387): `emitter` (roles incl. `harness`/`egress`), `entry_digest` resolved-scope anchor via `AUTHORITY_ENTRY_TYP`, `scope_statement_digest`, and the `EgressEvidence` kind, all additive; receipts commit the new fields automatically. **Ceiling composition** framing added to the architecture's derivation boundary. Also: a signals delivery-order test race fixed (drain between transitions), the dev cert dropped from history tips and `/certs/` gitignored. Merged main gate 390 passed / 0 skipped, all five drafts build clean. Skipped by design: the Grant Review Loop (ops feedback, out of protocol scope). |
| D53 | AAM-on-Missions reference architecture: Mission Templates + the end-to-end demo | Built the reference architecture that runs Cloudflare's Agent Access Model end-to-end on the Mission layer (2026-08-07, PRs #393-#399), closing the two capabilities the D52 review found missing. **Mission Templates** (new experimental companion `draft-mcguinness-oauth-mission-template` #393; kernel #394; `/token` dispatch grant + `/templates` admin #395): a human consents once to a task template (a ceiling + dispatch policy + bounds); each DISPATCH instantiates an ordinary Mission at machine speed with NO fresh human approval, its Authority Set a subset of BOTH the derivation-policy ceiling AND the template ceiling (double intersection), `approver` of record = the template's human, idempotent per dispatch event; template revocation stops dispatch only (instances live their clamped lifetimes); prohibited high-consequence classes still require a human; Subject is issuer-established, never client-named (core-consistency). **Issuer-held containment policy + protected-event ingestion** (#396 kernel `ContainmentPolicy` + `containOnEvent`; #397 `POST /missions/:id/protected-events` JWS event-source ingestion) closing the containment draft-vs-impl gap: events now drive containment deterministically instead of hand-picked `remove[]`; ingestion uses the Status JWS event-source profile (verified by source identity, trusted per event_type), unknown-type -> 422 reject-and-record, ingestion + the previously-discarded ContainmentEvidence are first-class in the unified evidence contract (new `ingestion` kind, `issuer` role); the egress gate reports advisory (never signs; `containment_claim: none` preserved); `evidence.policy` corrected to the containment rule_id (or `manual`). **Agent Activity Log** (#398): a read-only console-bff join over the producer-retained unified evidence (PDP-via-PEP/PEP/harness/egress/issuer/containment) into the per-task-run graph, keyed on `mission_id`/`event_id`/`hop_reference`/`entry_digest`; no write path moved. **Capstone** (#399): `aam-nightly-reconciliation.test.ts` drives all seven AAM steps against the live stack (consent -> machine-speed dispatch -> async-delegation disconnected run -> PEP/PDP + egress mediation -> signed tainted-read -> `authority_contained` -> restore only via a new dispatch -> joined activity log), nothing simulated, plus `AAM.md` mapping every AAM component to its Mission realization with the honesty boundaries stated. Merged main gate 453 passed / 0 skipped; the template draft builds + `make lint` clean. AAM maps near-1:1 onto Missions; the Grant Review Loop stays out of scope (D52). |
| D54 | Mission Work Products: information may propagate, authority may not (provenance + non-transitive handoff) | Extended the family's possession-independence from the credential plane to the artifact plane, in response to a documented multi-agent incident (independently-bounded agents used shared state, Artifactory then reconstructed via WebDAV directory names, as a coordination/memory plane, composing knowledge and credentials across runtimes to act as one persistent actor) (2026-08-08). The invariant, stated verbatim in the drafts: no authority may be acquired by information propagation alone; an agent may inherit another agent's knowledge, never its authority; information may cross a boundary without authority crossing with it. This is the artifact-plane generalization of an existing credential-plane claim (continuation's grants-nothing, possession-independent revocation, Active-Mission-is-not-ambient-authority), NOT a new axiom. **Core axiom filed as issue #402** (the published core is read-only; the axiom plus a new threat category "emergent authority through coordination" proposed for Security Considerations, mechanism kept in a companion so the core takes no companion normative dependency). **Spec (#403):** new experimental companion `draft-mcguinness-oauth-mission-work-products` carrying (A) a policy-free work-product provenance object (exactly mission_id, deployment_id, producer, created_at, optional parent_artifact; producer = the producing Mission; framed after reconciliation as attribution metadata carried WITH the work product, NOT one of the suite's evidence objects, grounded in the audit draft's producer-of-Mission-evidence) and (B) the non-transitive Mission-to-Mission handoff rule (a crossing artifact is input, the receiving Mission re-evaluates under its own Authority Set, producing-Mission authority never transfers, the legitimate path to act is a Child Mission bounded by the parent); it promotes the architecture's existing quarantine pattern from a deployment pattern to a normative rule (added as a reading of the invariants, NOT an eighth invariant, so the Seven stay intact) and adds the threat category to `mission-security-model` (distinguished from one-swarm-instance-compromised, which is legitimate multiplication under one Mission). **Reference impl (#404):** evidence `kind:"artifact"` (five policy-free fields, kept OFF `EvidenceStore.record` and mapped to a distinct `artifact_producer` in the activity-log join, never conflated with the component `emitter`); kernel `work-products.ts` (`produceWorkProduct`/`ingestWorkProduct` use `gateActive`, NEVER `gateDerivation`, and never read or write any authority set, so an ingested artifact structurally cannot confer authority); an incident-reconstruction e2e proving a read changes what the receiving Mission KNOWS but not what it may DO (identical PDP denial before/after, version + authority_hash + effective-set byte-identical, a child claiming the action refused `not_strict_subset`, and the bounded child-mission grant as the only authority path). Two premise corrections verified against the drafts and applied: the family's three continuities are identity / authorization / execution-time evidence (NOT "mission continuity"), so work provenance sits BESIDE the evidence continuity; and the three objects (agent identity, Agent Deployment, Mission) compose conjunctively and do not nest, so work-product ingestion is an added conjunctive gate. Merged main gate 454 passed / 0 skipped; the new draft builds and `make lint` clean. Deferred as future work named in the companion (managed-channel-only defense-in-depth and narrowings, awaiting go-ahead): shared-state effect-classification resource class, communications/audience envelope, lineage-keyed aggregate bounds (a narrowing of the metering aggregate-bounds hook), and artifact quarantine plus consumer-blocking on compromise (a containment extension). **Follow-through (2026-08-08):** Karl clarified the core is the editor's draft (docname `-latest`), not a frozen numbered revision, so it may be edited on his go-ahead without cutting a `-01`; the #402 resolution was folded into the core editor's draft as new Security Considerations section "Authority Does Not Propagate With Information" (rendered 16.5, inserted verbatim, docname preserved, informative-only reference to the work-products companion; a proposed-resolution comment is recorded on the issue), PR #405. README catalog brought to 32 drafts (the four missing recent companions added), and the Datatracker/Individual Draft/Diff links removed from every non-core document since the core is the only draft submitted to the datatracker, PR #406. |
| D55 | External architecture review commissioned and resolved | Ran an external adversarial review of the family (four independent lenses: IETF standards-fit, red-team security, prior-art/novelty, adoptability/coherence, plus a composition-focused security pass) reading the actual drafts (2026-08-08). Verdict: rigorous, self-aware individual submission, research-stage as a family; defects concentrated in COMPOSITION and process/venue, not the core mechanisms in isolation; genuine strengths confirmed (JCS integrity-anchor test vectors reproduced byte-for-byte, 32/32 drafts build clean, threat self-awareness). The highest-severity finding (containment does not survive the derive-then-contain composition order) was verified against primary sources before any action. All findings resolved in spec across four conflict-free, additive, capability-preserving draft PRs, all merged to main. **#408 composition/containment:** Finding 1 hybrid fix, child-delegation gains a normative MUST that the issuer propagates containment entry-wise to existing child Missions (mirroring discharge-propagation), containment's absolute claim narrowed with a new Materialized-Capability Residual section for already-redeemed cross-domain grants and already-minted offline attenuation roots (lifetime-bounded like revocation), plus per-domain-depth and max_derivations-not-inherited disclosure, Mission-vs-trifecta terminology disambiguation, and an anti-laundering consent-anchor recommendation. **#409 core (editor's draft, docname preserved):** Relationship to GNAP and capability-system prior-art (macaroons/Biscuit/UCAN/SPKI-SDSI); the `mission` claim named as the client_id actor-freezing wire signal with an RS-misattribution note; a real Mission Common Constraints IANA registry (Specification Required) replacing the future-revision deferral; actor-profile reference normative to informative (unblocks the RFC path); RFC 6750/9700 informative to normative; Composition-and-the-Effective-Ceiling and materialized-residual Security Considerations. **#410 profiles/docs:** work-products gains RFC 2119 keywords, a Conformance section, and a trusted-mediator provenance custody rule with the aggregate emergent-authority case stated out of scope honestly; template recommends anchoring the dispatch-policy body and marks the dispatch approver-of-record policy-adjudicated (parallel to child-delegation); mandate acknowledges zcap/VC prior-art; architecture gains an effective-ceiling-under-composition reading and a containment-residual matrix note; README adoption-order tiers updated (template/containment/work-products) and approval/aauth get dependency-stability notes; also corrected a prior mislabel of Containment as experimental in the verb diagram (it is category std, An Optional Extension). **#411 enforcement/honesty:** self-graded-enforcement stated plainly in the security model with execution-environment attestation upgraded MAY to MUST scoped to High-Assurance/trifecta claims only; the PDP now evaluates the EFFECTIVE Authority Set where Containment is deployed, with an extension seam parallel to the denial-reason pattern and contained denials routed to authority_contained; trifecta-vs-Mission-containment disambiguation; materialized-capability-escape and effective-ceiling-composition added as named threats; XACML named as the PDP/PEP lineage. All four disjoint-file, build and make lint clean, 0 em-dashes, merged with branches deleted; each stream ran its own advisor pass and self-corrected before commit. TWO reference-impl follow-ups OPEN (the spec now asserts behavior the kernel does not yet implement): kernel child-containment propagation to match #408's new MUST (issue #412), and work-products conformance code to match #410 (issue #413). |
| D56 | Implementation review resolved (PRs #414-#417) | Ran an implementation review (three read-only miners: spec/impl divergence, underspecification and impl-local decisions, impl-ahead and contract mismatch) to surface what the reference build teaches the drafts (2026-08-09). Verified the sharpest findings against the code before acting. Resolved across four conflict-free PRs, all merged to main. **#414 core:** A2 derivation MUST fail closed on a registered Common Constraint it cannot narrow (never silent-drop-widen; refuse the derivation or omit the entry), and A3 pin decimal-value comparison for `max_amount` and decimal constraints (`^[0-9]+(\.[0-9]{1,18})?$`, exact decimal arithmetic, never IEEE-754). **#415 grant-type:** A5 fix the IANA-arc squatting by DEFINING and REGISTERING, adding a Grant Type section plus an IANA OAuth-URI registration request for `mission-child-creation` (child-delegation) and `mission-dispatch` (template), no wire churn. **#416 evidence model:** A1 a shared Mission Evidence base in audit/authzen WITH per-kind `typ` retained so a signature over one kind cannot be cross-used, `hop_reference` and `scope_statement_digest` formalized, a registrable Protected Event Receipt (applied and rejected) in containment, and a flat PEP-style Egress Evidence blessed in harness distinct from the Harness Evidence Object; A4 an informative cross-producer correlation section (join keys plus lineage tree) in audit; A6 egress destination-set matching defined in harness (destination = URI, origin-equality default, refuse on no match). **#417 code:** B1 child `max_derivations` reads its own Intent not the parent's (fixing a violation of #408's now-normative rule), B2 expansion surfaces predecessor containment history (the unimplemented anti-laundering MUST, distinct from #412/#413), B3 `intersect()` fails closed on an unimplemented registered constraint instead of silently dropping it, B4 a BigInt-exact decimal money comparison helper at all four authority-path sites (derive, PDP, attenuation) with amount-format validation; gate 58 files / 479 tests / 0 skipped. Each stream ran its own advisor pass and self-corrected. All disjoint-file, build+lint / gate clean, docname preserved, merged with branches deleted. Follow-on: a subsequent external review recommended an architecture-convergence cycle (approval-basis constitution, AAM prohibited-class conformance, substrate two-capability, containment cutoff, plus family-manifest/CI and a Deployment Profile schema); being applied next. |
| D57 | Architecture-convergence cycle, Phase 1 (constitution + four contradictions) | A second external review judged the family "a strong core surrounded by rapidly evolving extensions" and recommended pausing new profiles for an architecture-convergence cycle (2026-08-09). Karl chose: fix the AAM conformance bug by keeping Template dispatch low-consequence (not by weakening the draft), adopt the approval-basis constitution, and run the full cycle sequenced. Verified the two sharpest findings against the code before acting (the AAM capstone dispatched an external_commitment action the Template draft prohibits; containment's cutoff overclaim survived at containment.md, a line #408's residual had not reconciled). Phase 1 resolved and merged as six PRs. **Constitution (#418 spec across core/architecture/template/child-delegation + #419 code):** reframed the invariant from "every Mission is created by an explicit approval event" to "every Mission is rooted in an approved authorization basis"; `approval_basis { type: direct|template|policy_drawdown, consent_principal, activation, activation_actor, root_commitment }` is Mission Record metadata fixed at creation, NOT folded into intent_hash/authority_hash (domain separation preserved: task / authority / provenance); `approver` == `consent_principal`; direct is the default so existing Missions are unchanged; policy_drawdown root_commitment is the child_creation_policy ref or, absent one, parent.authority_hash (a committed root, reconciled spec-and-code). **#420 substrate two-capability:** lifecycle-gated (MUST floor, satisfied by the TTL/stateless core) vs state-observable (the overlay runtime enforcement requires when a staleness bound is tighter than credential lifetime), resolving the core/substrate/architecture disagreement about state sources. **#421 containment cutoff:** a full-draft sweep giving containment two labeled properties, Baseline new-derivation kill (old-token exposure bounded by lifetime) and Runtime-Enforced action-time kill, with the "RS needs no new behavior" claim made conditional; plus the architecture TTL/state-source reconcile and the containment matrix labeling. **#422 AAM conformance:** Template dispatch stays low-consequence; the exhibit/e2e route `remittance.send` (external_commitment) through a human-approved Mission and a template dispatch of it is refused `dispatch_prohibited_class`; `policy.json` covers the prohibited classes; template.md gains a normative "a deployment's configured prohibited set MUST cover the prohibited classes" rule (the root cause); gate 487 / 0 skipped, exhibit clean. Each stream ran its own advisor pass and self-corrected (a policy_drawdown root fallback, a runtime-vs-freshness contradiction, an over-broad client_id rule earlier). Note: the no-em-dash rule is a DRAFTS rule; it does not govern the demo `exhibit.ts`, which uses em-dashes as its established output style (an over-application cost one wasted agent round-trip). Phase 2 (Deployment Profile schema + claim IDs, a machine-readable family manifest + CI drift guardrails, and relabeling still-maturing profiles experimental) is next. |
| D58 | Architecture-convergence cycle, Phase 2 (governance infra + maturity) | Completed the convergence cycle's second phase (2026-08-09/10), keeping to the review's "consolidate, do not expand" posture. **2a Deployment Profile schema (deferred by design):** filed as issue #424 rather than drafted inline, because a normative Deployment Profile serialization + stable claim identifiers + validation rules is new normative content and a placement decision (recommended: a normative section in mission-substrate.md, not a new companion) better settled deliberately; the issue records the three-axis claim taxonomy (binding capabilities / enforcement assurance / named claims) and the "publish before adding more assurance vocabulary" sequencing. **2b family manifest + CI drift guardrails (#423, merged):** `family-manifest.json` (one entry per all 32 drafts: file, category, maturity, group, adoption_rung, deps, is_published_core), a dependency-free validator `scripts/check-family-manifest.mjs` checking inventory / category / README-catalog / architecture-document-map / adoption-order coverage, and a `.github/workflows/family-manifest.yml` running it on push and PR; it also fixed the drift it was built to catch (the architecture document map was missing Mission Template). This is the systemic fix for the governance lag that recurred this session (README count, doc-map omissions, adoption-order gaps). **2c relabel + downref cleanup (#425, merged):** Containment and Continuation moved category std to exp (Karl's call; Progressive/Template/Discovery were already exp), with manifest and README adoption-order updated to match and the validator kept green; and the std-to-exp normative downref this created (child-delegation.md normatively referenced now-experimental Containment) was closed by moving that reference to informative (the dependency is conditional on the optional Containment profile). Convergence cycle complete: the four normative contradictions resolved (Phase 1), governance guardrails in place, maturity labels honest; issues #402 (axiom folded into core 16.5), #412/#413 (impl follow-ups), and #424 (Deployment Profile) remain the tracked open threads. |
| D59 | Standards review P0 interop batch (JAR, client_id, RFC 8693 child response) | A second, standards-focused external review (2026-08-10) withdrew nine earlier objections (validating several convergence calls: continuation-grants-nothing, custom grants OK, signed status OK, RFC 7523 issuance-grant OK) and left three P0 interop blockers, verified against current main before action. Resolved as three conflict-free PRs, all merged. **P0-1 JAR/PAR (#431 core):** replaced the blanket "MUST NOT unwrap a request object" with a JAR-compatible rule, `mission_intent` MAY ride a signed Request Object pushed through PAR (RFC 9101) with a precedence rule, keeping Intent off the plaintext front channel. **P0-2 client_id (#431 core + #427 cross-domain + #432 code):** `client_id` = the client requesting THIS token (RFC 8693 sec 4.3 / RFC 9068 sec 2.2), reversing the draft's freeze to the approved agent; the code was already conformant (the freeze was prose-only, from #409), so the code change was a no-op there. **P0-3 child-creation response (#427 child-delegation + #432 code):** reshaped the nonconforming response to RFC 8693 form (`access_token` = the child assertion, `issued_token_type` = `urn:ietf:params:oauth:token-type:jwt`, `token_type` = `N_A`, plus `mission_id`/`parent`, response `grant_type` removed), keeping the `/token` endpoint and the #415-registered grant. Two design corrections from Karl during the batch: (1) `mission.approved_client` is NOT needed on every token (a base token IS issued to the approved client, so it is just `client_id`); (2) the proper delegation-identity model is the RFC 8693 act chain whose ROOT is the approved agent, which subsumes `approved_client` and travels cross-domain (unlike an introspection-only field). So `approved_client` was dropped entirely from the P0 PRs (leaving them smaller: just the client_id/JAR/child-response fixes), the approved agent is recovered from the Mission Record for now, and the full act-chain model was filed as issue #433 (`foundation`, P1; only the continuation flow builds a chain today). Gate 501/0 on the code PR; drafts build + `make lint` clean; core docname preserved. Remaining from this review: P1 (proposed_authority types, refresh-token-in-PAR to a scoped assertion, aggregate-bounds normative statement, containment/Signals change-event, plus #433 act chain) and P2 (provenance-to-artifact binding, wire reduction incl. dropping mission_derivation, the earned "stable" label). |
| D60 | Adopt draft-zehavi RAR type metadata; resolve proposed_authority types (P1-4) | Karl directed adopting `draft-zehavi-oauth-rar-metadata` FIRST, then resolving the proposed_authority-types gap on it (2026-08-10). Verified the two-part model against the least-privilege-MCP series (notes.karlmcguinness.com): draft-zehavi's `insufficient_authorization` is a GRAIN of the family's graduated-challenge family ("the no and how to ask"), not a separate layer; ARAP is another grain. Key realization while exploring: the reviewer's Option A (restrict proposed_authority to `mission_resource_access`) would CONTRADICT the core's existing `#other-types` design (other AS-supported RFC 9396 types are allowed, with type-defined subset or carry-as-approved when none), so Option A was rejected as capability-removing; the real gap was the underspecified same-type derivation relationship + unsupported-type handling. draft-zehavi is WG-bound, so referenced NORMATIVE (Karl OK'd the dependency). Bundled, merged as three PRs. **#436 core:** adopt `authorization_details_types_metadata_endpoint` (per-type JSON Schema discovery), publish the `mission_resource_access` schema through it, point `#other-types` at it as the source of truth for supported types; proposed_authority resolved (an entry MUST be an advertised, schema-valid type; derivation is SAME-TYPE, `mission_resource_access` -> family subset, other supported types -> their subset or carry-as-approved; unadvertised/invalid -> refused `invalid_authorization_details` or omitted with `mission_derivation: partial`, never silently kept; extensibility preserved, NOT restricted); new Remediation Grains section adopting `insufficient_authorization` + `authorization_remediation` as the RAR-details grain composing with `mission_denial` and ARAP. **#434 authzen:** composed the RAR-details grain with the ARAP grain as one graduated-challenge family (additive). **#437 code:** `GET /authorization-details-types` + the `mission_resource_access` JSON Schema artifact + discovery advertisement, proposed_authority type/schema validation at the intake gate, and the `insufficient_authorization`+`authorization_remediation` grain on the PEP path (fires only on genuine `out_of_authority` absence, not `constraint_exceeded`/`authority_contained`; empirically confirmed the endpoint key set equals oidc-provider's `authorization_details_types_supported`); gate 59 files / 507 tests / 0 skipped. docname preserved; drafts build + `make lint` clean; disjoint files. This closes P1-4 and the draft-zehavi adoption. Remaining P1: refresh-token-in-PAR -> scoped relationship assertion (P1-5), aggregate-bounds normative statement (P1-6), containment/Signals change-event (P1-7), the RFC 8693 act-chain model (#433). Then P2. |
| D61 | Standards review P1-6 (aggregate bounds) + P1-7 (containment/Signals change-event) | Continued P1 with the two lowest-design-risk, disjoint items (2026-08-10), merged as three PRs. **P1-6 aggregate bounds (#446):** child-delegation now states NORMATIVELY that `max_derivations` is per-Mission and independent of the parent, and MUST NOT be treated at any single Mission as an aggregate/concurrency/spend/subtree bound; composed-bound disclosure upgraded to a MUST where an approval interface displays such a control. Metering gains a lineage-keyed budget identifier + shared counter as the ONLY mechanism defined for a lineage-wide aggregate CONSUMPTION bound, with a deployment MUST NOT against rendering such a bound as in force without one deployed (scoped to consumption, distinct from security-model's anticipated authority-composition aggregate note). cross-domain (per-domain depth reset -> max_depth x domains) and architecture (composed-effective-ceiling reading) were already normative from the convergence and left untouched. **P1-7 containment/Signals (#444 spec + #442 code):** the composition gap where an active-to-active containment event (state == prior_state, only version bumps) neither told a Signals consumer what changed nor forced a refresh. Fix (augment the existing event, not a new type): `mission.lifecycle-change` now carries the Mission's `containment_version` (and MAY reference `authority_hash`); a containment-aware consumer that sees `containment_version` advance past what it last materialized MUST rematerialize the effective authority view before further consequential reliance (version-gap refetch stays for the coarse case). Code: `emitCommit()` spreads `containment_version` and `signLifecycleEvent()` copies it onto the signed SET body (verified by decoding the JWT); tests prove a contained-then-still-active sequence surfaces the changed version; gate 59 files / 509 tests / 0 skipped. Each cluster ran its own advisor pass (caught a dangling member reference + antecedent drift in the signals spec, and an unscoped "only mechanism" claim in metering). docname/scope clean, disjoint files. Remaining from this review: P1-5 (refresh-token-in-PAR -> scoped relationship assertion) and #433 (the RFC 8693 act-chain model), then P2. Small follow-up noted: security-model.md's "lineage-keyed aggregate bounds" (authority-composition) vs metering's consumption budget deserve a one-line cross-reference so they are not conflated. |
| D62 | P1-5 resolved by reframing expansion + child-creation as RFC 8693 token exchanges (not a bespoke assertion); DTR-gated approval (PRs #452/#451) | Karl asked whether the refresh-token-in-PAR fix (P1-5) should extend the Identity Continuation Assertion or add a new Work/Mission Continuity Assertion (2026-08-10/11), citing his "continuity is not one thing" note. The note names FOUR continuities with distinct artifacts: request (delegation chain), identity (ICA), authorization (Token Exchange / Transaction Tokens), work (the Mission itself). Proving "I hold this predecessor/parent and may continue the work" is AUTHORIZATION continuity, whose artifact is Token Exchange, NOT identity (so not ICA) and NOT a new assertion (the Mission IS the work-continuity record; succession is governance carried by its own lifecycle). So the bespoke "Mission relationship assertion" of #448 was the wrong shape and was CLOSED/superseded. **Design:** expansion and child-creation become proper RFC 8693 token exchanges at `/token`. `subject_token` = the predecessor/parent's sender-constrained Mission-bound ACCESS token; possession is proven against the `subject_token`'s OWN cnf (RFC 9449 DPoP `jkt` / RFC 8705 mTLS `x5t`), NOT a Mission-record cnf field (none invented); `subject_token_type` MUST be access_token, a refresh token MUST NOT be the carrier (retires refresh-token-in-PAR by construction: no PAR request holds a credential). `actor_token` carries the acting agent (Phase 1 carries it; it does NOT restructure the act chain, still #433). `requested_token_type` is the operation selector: jwt = child creation, access_token = expansion. Child creation was FOLDED from its dedicated `mission-child-creation` grant into the generic token-exchange grant (dedicated-grant IANA registration request removed; the child gate lives in `delegation.children`, not client `grant_types`, and every other family flow already uses generic token-exchange). Completion MODES, DTR is a mode not a replacement: synchronous (pure subset derivation) / Deferred Token Response (`draft-gerber`, the family's Mission Deferred Approval substrate; D5 already chose DTR over CIBA) for async fresh approval / the deployment's interactive approval RETAINED. **Deferred-window checks (spec + code):** predecessor/parent STATE re-verified AT ISSUANCE, a Mission terminated OR contained during the window fails completion (a deferred approval MUST NOT bypass the containment Baseline new-derivation kill); `subject_token` expiry MUST NOT gate completion (possession evaluated + recorded at request time). The successor's issued access-token `mission` claim now carries the `predecessor` member (a pre-existing normative requirement that expansion's first real wire path had to honor; C2 fix via the `extraTokenClaims` three-way selection). **PRs (merged):** #452 spec (expansion/child-delegation/authority-server; the MAS binding kept token-less in lock-step as the peer of the AS token-exchange binding), #451 code (expansion given a real back-channel wire path where it had NONE, child-creation request migrated, both on the `continuation-grant.ts` template; gate 60 files / 520 tests / 0 skipped). A merge conflict with #428 (substrate Mission-Substrate-Statement) in authority-server.md was resolved keeping the token-exchange bullet, #428 content preserved (verified). Advisor passes caught and corrected: a "DTR replaces the interactive leg" overreach (kept three modes), the impulse to FUSE P1-5 with #433 (edit surfaces near-disjoint, kept separate), the two deferred-window checks, and the possession-is-the-token's-own-cnf clarification. Three pre-existing emitters bypass `extraTokenClaims` and would omit predecessor/parent (D42 txn-token, async-delegation family-fallback, introspection): pre-existing, distinct token types, noted for a possible follow-up. **Remaining:** #433 (the RFC 8693 act-chain model) narrows under the continuity lens to unifying the two actor-gating vocabularies (`allowed_delegates` core ~ `allowed_child_actors` child) onto one matcher plus correct WITHIN-mission `act` nesting; a child/successor act chain correctly RESTARTS at a mission-lineage boundary (a new work-continuity unit), so #433 is NOT chain-extension across missions. Then P2 (provenance-to-artifact binding, wire reduction incl. dropping `mission_derivation`, the earned stable label). |
| D63 | #433 explored, split into two concerns; Concern 1 (actor-gating ENFORCEMENT unification) resolved (PR #457), Concern 2 deferred | Explored #433 (the RFC 8693 act-chain model, last P1 item) with Karl (2026-08-11). Karl agreed the issue conflated TWO things: (1) delegation IDENTITY (the `act` chain) and (2) approved-agent / lineage-root RECOVERY (the thing that actually motivated retiring `mission.approved_client`). A precise current-state map showed the issue's original "plumbing" list (make child creation / template dispatch / cross-domain projection all nest ONE continuous chain, innermost = approved agent) is REJECTED by the family's own invariants: a Child Mission has its own approval basis and "authority may not propagate", so a child/successor acts under its OWN approval, not the parent actor's delegated authority. The drafts ALREADY encode this as restart-at-lineage (child-delegation.md {#child-vs-act} + `actor_token` def "a new work-continuity unit whose own act chain restarts at the child actor"; expansion "begins its own act chain afresh"; cross-domain restarts at depth 0); in-mission delegation nests (`act.act`). So the act-chain lifecycle needed NO change; a re-scoping comment was posted on #433. **Concern 1 (resolved, PR #457) is ENFORCEMENT, not modeling.** The map found the real gap: core `allowed_delegates` (the may_act gate) was SPEC'D BUT UNENFORCED (no runtime matcher; `delegation.ts` did depth/structural only), and the child `actorAllowed` (the only runtime matcher) was NON-CONFORMANT to both drafts, matching `sub_profile` by raw string equality instead of space-separated membership and defaulting an absent list to blanket-allow (contradicting the core's "never a blanket grant"). Fix: one shared helper `kernel/delegate-matcher.ts` `delegatePermitted()` conforming to the drafts, `sub` exact, `sub_profile` MEMBERSHIP via the existing `parseSubProfile`, absent list => fail-closed DENY, empty `{}` matcher => no match, and a `sub_profile` matched ONLY against the AS-asserted `assertedProfile` (sourced from new `config/actor-profiles.json`) so a self-asserted profile can never satisfy it. Wired into BOTH the child path (`child-delegation.ts`, LIVE via the child-creation exchange) and the core path (`delegation.ts` `gateDelegableAuthority` in `constructDelegatedIssuance`, adding the previously-missing per-entry `max_depth` bound). `allowed_child_actors` added to the published RAR metadata schema. `invalid_target` (RFC 8693 2.2.2) added for zero-narrowing. "Deferred to policy" realized as fail-closed in the reference impl; three demo Authority-Set policies (containment, child-delegation basis, mission-signals) that carried a `children` on-switch with no `allowed_child_actors` were made EXPLICIT to survive the fail-closed flip; test child actors are AS-asserted via a per-suite helper; `config/actor-profiles.json` is load-bearing (pinned by a test). Gate 63 files / 553 tests / 0 skipped; typecheck + lint clean. Advisor calibration during the exploration: downgraded my "security-relevant" framing to a CONFORMANCE defect (it governs WHO may act; derived authority stays strict-subset-bounded, so no escalation), and settled fail-closed as the "deferred to policy" default. **Known follow-up (flagged, not a defect):** the core matcher is implemented + unit-tested + wired into `constructDelegatedIssuance`, but NO live HTTP path supplies an `authoritySet` today (there is no live in-mission delegation exchange endpoint in the reference impl), so the core gate is "ready but unreached" pending such a flow; the CHILD gate is live and end-to-end. **Concern 2 (DEFERRED):** approved-agent recovery is already served within a domain by the Mission record `client_id` (introspection) and across lineage by the `parent`/`predecessor` record links; only cross-domain (partner cannot introspect) would need it on-token, and cross-domain projection carries no actor today with delegate-crossing out of scope, so there is likely no consumer yet. When built it MUST be a distinguished attribution claim, NOT the `act` chain (`act` is authorization-bearing and cross-domain narrows out non-portable `sub` client identifiers; putting the approved agent in `act` would re-conflate the two concerns). #433 stays OPEN for Concern 2. |
| D64 | P2-1 wire reduction: dropped the `mission_derivation` token-response parameter (PR #461, merged) | First P2 item (2026-08-11). A read-only map returned a RECOVERABLE verdict: `mission_derivation` (values `partial`/`full`) was a convenience signal that a client's `proposed_authority` was not fully granted, but the client already holds both diff operands, its `proposed_authority` (committed by `intent_hash`) and the authoritative granted `authorization_details` echo, and derivation is same-type subset, so an omitted proposal has no same-type echo counterpart and a narrowed one is a strict subset. The parameter carried strictly less (one bit, never WHICH entries or HOW), and the reference impl neither emitted nor consumed it (zero code/test churn). Kept it capability-preserving per the advisor: the "MUST NOT keep the entry silently" guarantee was a disjunction whose second limb WAS this parameter, so rather than let it degrade to "refuse or omit", the guarantee was re-anchored to the echo with an explicit MUST (the granted `authorization_details` echo MUST reflect every omission and narrowing; no entry is ever represented as granted when it was not) at both edited sites ({{authorization-derivation}} and the Common Constraints fail-closed rule). Honest caveat stated in the PR (not clean equivalence): on a per-RS single-audience token the echo is also audience-narrowed, so an omission affecting resource R surfaces when the client requests R's token rather than at first issuance, a recovery-timing deferral not an information loss (immediate against the full-Authority-Set primary token). Scope: core-only (confirmed no companion references it); removed the definition, the IANA registration request, and the `-01` "new wire surface" mention (the `-01` list corrected to net content since docname is `-latest` and that history block is marked to-be-removed; append-form offered to Karl); the redundant `full` value went with it. NOT folded in: `derivations_remaining` (genuine server state, not client-recoverable) or the rest of the `-01` wire-surface batch. Build clean / `make lint` 0 / docname preserved / no code or test change. Remaining P2: provenance-to-artifact binding (in-toto, on the experimental work-products companion) and the earned "stable" label (selective per-profile promotion, gated on the hardening landing). Housekeeping still open: SPEC_VERSIONS core pin bump (deliberate D25/D41; the core pin has intentionally not tracked every editor's-draft edit) and the security-model vs metering aggregate-bounds cross-reference (D61). |
| D65 | P2-2 provenance -> artifact binding shipped (PRs #464 spec + #466 code, merged) | Second P2 item, explored with Karl (2026-08-11). Split the concept: today the Work Product Provenance object is ATTRIBUTION metadata carried with an artifact, with NO digest of the artifact bytes, so it is re-attachable/forgeable. The binding adds a tamper-evident proof that a provenance object describes a SPECIFIC artifact and was attached by a trusted mediator, WITHOUT making provenance authority-bearing. **Envelope fork = B (Karl's call):** the family's OWN JWS Compact idiom (as signed SETs / the Mandate use), NOT native in-toto DSSE. Native DSSE was rejected on a real invariant clash: it signs bytes-as-received with a hex `sha256` digest, contradicting the family's reproduce-the-digest-from-the-record (JCS) rule and its reject-any-prefix-that-is-not-`sha-256:` rule. in-toto (CNCF) + SLSA (OpenSSF) cited INFORMATIVELY as the conceptual model (subject/digest/predicate), not a normative MUST; a byte-compatible in-toto/DSSE translation shim is deferred. **Shape = (ii) (my recommendation, Karl did not override):** a SEPARATE signed binding object; the sealed 5-member provenance object and its three normative sites ("these members and only these" / "carry no member beyond the five" / the privacy analysis) left BYTE-UNTOUCHED (verified both in spec counts and the code `ArtifactEvidence` diff). **Factual finding that resized the work:** no signed carrier covers the provenance on egress today (it is plain metadata on opaque content), so binding needed BOTH a digest AND a signature (a signed carrier), not a one-field add. **Signer/iss reconciliation (the divergence the two clusters hit, resolved via advisor + a family grounding grep):** the TRUSTED MEDIATOR (harness or issuer, the #410 custody party) signs with ITS OWN key from its own record; `iss` = the Mission Issuer / deployment URL under which the deployment publishes its key set (NOT the mediator id, dropping the code's initial `mediator.id === iss` overload and the non-URL-`iss` smell); `kid` selects the mediator's key WITHIN that published key set by `mediator.role` (Issuer key via AS `jwks_uri` for `issuer`; the harness signing key, already required family-wide to be "resolvable in the published key set", for `harness`); `mediator {id, role}` names the signer, `id` != `producer`. The binding payload: `artifact_digest` (`sha-256:`+base64url over the artifact's octets AS EXCHANGED, opaque, no serialization mandated) and `provenance_digest` (integrity-anchor `computeAnchor("mission-work-product-provenance", iss, <sealed 5-member object>)`, JCS+SHA-256). The `provenance_digest` pinned vector was INDEPENDENTLY RECOMPUTED (JCS+SHA-256+base64url) and matched the code byte-for-byte, confirming spec and code describe the same object. **Guardrail (unchanged invariant):** a valid binding proves ATTRIBUTION INTEGRITY only, never authority; it is never a PDP permit input; the Receiving Mission still re-evaluates under its own Authority Set. Aggregate emergent-authority + quarantine remain out of scope. Gate 64 files / 568 tests / 0 skipped; drafts build + `make lint` clean; sealed object byte-identical. Honesty notes at handoff: biome does not lint `services/**` so the code coverage is typecheck + tests (not lint); the code's `workProductBytes` JSON helper is a documented reference-impl convenience, not normative. Follow-ups filed (not bundled, one normative change at a time): `parent_artifact` -> digest-valued for a verifiable artifact-lineage chain (reuse the #194 Mission-Receipt chaining precedent); an optional one-line spec reword giving the verification steps unordered-independent-predicate framing (spec lists the signer!=producer check earlier than the code enforces it; same rejected-input set, cosmetic). Remaining P2: the earned "stable" label (P2-3). |
| D66 | Fresh external OAuth architecture review (2 rounds) triaged and the uncontested findings resolved (PRs #468/#469/#470/#471 merged) | A fresh external review of all 34 drafts (2026-08-11): 9 findings (2 "blocking", 4 high-priority, 3 gaps) plus a strategic thesis (the family standardizes three things at once: an OAuth grant profile / a runtime architecture / a substrate-neutral abstraction, the third overstated). Triaged with three read-only verifier agents (findings cross-checked against current main + the D-log for prior-decision conflicts) AND primary-source datatracker checks, which CORRECTED the reviewer BOTH rounds: draft-zehavi is NOT expired (active -06, 9 Aug 2026, "OAuth 2.0 RAR Metadata and Error Remediation") but IS still an individual non-WG draft; identity-chaining is in the RFC Editor queue (IESG "Submitted for Publication", RFC-Editor "In Progress"), NOT Last Call as the reviewer claimed; but ID-JAG -04 IS DPoP/jkt-only (mTLS is the unmerged WG issue #117 / PR #118, per Karl) and DOES define the refresh-token subject mode (the reviewer was right on both ID-JAG points). Karl chose "resolve Uncontested" then, after a sharper second-round review, "apply recommendation". **Merged as four disjoint draft PRs (round-1 + round-2 second pass):** #470 core (finding 1 subject-namespace: the RFC 9068 concern is a PROSE contradiction not a runtime bug since `subject.iss` is audit-only with no runtime lookup, so resolved by a clarifying REWORD, the record's `(subject.iss,subject.sub)` is the EXTERNAL subject identity carried as provenance, the derived token's principal is the AS-LOCAL `(AS,sub)`, both denote one Subject in two namespaces, byte-equality compares WITHIN a namespace, plus a MUST that an adopted foreign `sub` is unique in the AS namespace, NOT the reviewer's full remodel to `{iss:AS,sub:local}`+`subject_source`; finding 9 prefix-match: carried the existing {#subset} RFC 3986 canonicalization to RS enforcement + `%2f`==`%2F` hex-case + 7 allow/deny adversarial vectors); #471 status (finding 2 sub-semantics: `sub`=resource owner, caller=`client_id`+`act`, DPoP/mTLS binds presenter not `sub` meaning, plus a new `mission_status` scope and RFC 9728 per-endpoint discovery, while REJECTING the reviewer's "remove direct client auth" which would break the token-less MAS binding (D62), all three mechanisms retained; finding 3 new IANA-registered `mission_status/lifecycle_endpoint_auth_methods_supported`+`_signing_alg_values_supported` metadata, exact `client_assertion_type`, endpoint-`aud` processing; finding 4 token MUST be audience-restricted to the endpoint's RFC 9728 `resource`, distinct from the request-body `audience` param, mTLS cert-bound token added, three-arm mechanism-disambiguation rule; finding 5 the Status<->Child-Delegation normative dependency CYCLE broken by moving Status's expansion/child-delegation refs normative->informative, the D58-2c move, core stays normative and child-delegation.md untouched); #469 cross-domain (finding 6a: identity-chaining statement LEFT as-is, verified current; finding 6b: profile ID-JAG's NATIVE DPoP/jkt PoP as REQUIRED and reframe the stale "ID-JAG defines no PoP" + dead custom fallback, with mTLS via `cnf`/`x5t#S256` (RFC 8705) as a Mission-profile MAY "aligning with the mTLS support ID-JAG is expected to add" (NOT claimed as currently ID-JAG-native) plus its issuance/redemption/downgrade mechanics; refresh-token mode reframed from "deviation" to "requires ID-JAG's mode exclusively"); #468 README (finding 3 README: correct the "core's one informative I-D reference" claim, the core has a SECOND normative dep on the individual draft-zehavi, plus three "entirely ratified dependencies" summary claims reconciled, non-enumerated for durability; the reviewer's "-03/Error Signaling" title nit was itself stale, title kept). All four file-disjoint, draft/doc-only, build+`make lint` clean, docname preserved, MERGEABLE, verified (the `provenance_digest`-style spot-check here was re-deriving that the subject reword did NOT remodel `subject` and that direct client auth stayed). **Filed, not fixed:** #467 (finding 7, child-creation business idempotency: DPoP `jti` stops same-proof replay only, a lost-response + fresh-proof retry duplicates a child, needs a `delegation_request_id`/`idempotency_key` across child-delegation/template/expansion) and a #433 corroboration comment (finding 8 = #433 Concern 2 resurfacing: the reviewer independently re-derived the D63 conclusion that approved-agent recovery wants a distinguished NON-authoritative attribution claim, not `act`; still deferred, no cross-domain consumer yet). **LEFT IN KARL'S COURT (not applied):** finding 3's dependency DEMOTION (D60 accepted the draft-zehavi normative dep on a "WG-bound, soon adopted" premise that a year on is unmet, still individual; demoting reopens P1-4's three coupled sites, so it is Karl's trade) and the STRATEGIC reshape (finding 4 substrate-neutrality naming + the task-bound-OAuth-grant framing + submit-two-documents-first, which is publication SEQUENCING, not merging drafts, so it does not trip the intentional-decomposition rule). Reference-impl follow-ups flagged (not coded): `resource_match` prefix enforcement with the shared RFC 3986 canonicalization; `mission_status` scope + the new metadata + RFC 9728 publication. Process note: I flagged the mTLS-drop capability-narrowing risk in #469 then wrongly dismissed it on the published -04 snapshot; Karl corrected it with the ID-JAG WG direction (issue #117), so mTLS was restored as a Mission-profile MAY. Lesson: do not dismiss a self-flagged capability-narrowing risk on a point-in-time spec read; check the WG direction. |
| D67 | RAR carriage: the authority proposal moves to the standard top-level `authorization_details` parameter (issue #475; PRs #477/#479/#478 merged) | The round-3 external review's "core hides RAR inside mission_intent" finding, explored with Karl (2026-08-11/12). Verification established that narrowing mode was ALREADY RFC 9396 request-narrow-grant semantics with nonstandard carriage; the family's own adopted remediation grain outputs `authorization_details` the client had to re-wrap; `scope`/`resource` were already accepted top-level while `authorization_details` alone was refused; and discovery advertised `mission_resource_access` while hard-refusing its submission (a conformant-client trap). Karl chose Option B (standard carriage) over status-quo-plus-patch; decision filed ISSUE-FIRST as #475 (decide) per the core protocol, with four Karl amendments locked: grep-derived family sweep (not a fixed list), explicit tri-anchor TOCTOU, an AS-side anti-downgrade hook, and honest breaking-change disclosure; naming settled `proposal_hash` / `typ: mission-proposed-authority`. **Design as merged:** `mission_intent` is task-only (`proposed_authority` member removed; closed top level refuses it); the proposal rides top-level `authorization_details` via PAR; proposal-never-authority preserved verbatim; narrowing mode re-pointed, template mode untouched; `proposal_hash` committed via the documented anchor extension point, present iff a proposal was submitted, record + introspection surfacing, NOT on the `mission` claim (approval_basis-style provenance); TOCTOU recomputes the recorded anchors on any context change between rendering and decision (substrate approval-event rule); AS-side hook: a `mission_governed` client registration causes bare-`authorization_details` requests to be refused (impl chose `invalid_request`; spec deliberately pins none, mirroring the AAuth #459 shape); discovery trap dissolved; remediation loop closes natively. **Capability-preserving carriage on five companion surfaces** (expansion, child-delegation, template dispatch, MAS submission member, UMA claim token): the old carriage traveled implicitly inside the intent there, so each gained one OPTIONAL parameter/member/claim, each EXPLICITLY REPLACING the core's PAR-only carriage rule while importing validation/derivation/recording/hashing semantics unchanged (token-request carriage is ordinary RFC 9396 Section 6 usage). **Pre-merge external review (5 findings + nit, all verified then applied):** RFC 9396 Section 5 forbids repairing a validation failure by omission, so unadvertised/schema-invalid entries are now refuse-only while policy narrowing of valid entries stays omit-able and echo-visible (this ALIGNED SPEC TO CODE - the impl was already refuse-only); the five carriage-override sentences (above); narrowed consent-evidence descriptors gained conditional `proposal_hash`; the subject-mapping rule generalized from verbatim-adoption to an INJECTIVE MAPPING external (iss,sub) -> AS-local sub with verbatim copy one permitted deployment choice (fixes the two-issuers-same-sub collision; still no remodel, record model byte-identical); README + src/docs/CONFORMANCE.md staleness; TOCTOU reworded to "the anchors the Mission records". Merged in the reviewer's order #477 core -> #479 companions (17 drafts + README + CONFORMANCE) -> #478 code. **Verification:** the new proposal_hash vector independently derived three ways (orchestrator Python, impl Node, spec text) byte-identical; the four existing vectors unchanged (no existing vector's input contained a proposal, narrowing the practical break below the disclosed worst case); claim surfaces asserted clean at unit + wire; rarFor* issued-details path proven unchanged by an over-ask e2e (900->500 cap; echo is the derived set, never the submission); gate 65 files / 583 tests / 0 skipped. Breaking change disclosed in the core Document History and the SPEC_VERSIONS Notes (anchor inputs changed; core pin bump deliberately deferred per D25/D41). Process notes: a Phase-3 agent stalled pre-gate and was resumed (work had been pushed incrementally, nothing lost); the batch cross-check caught a dispatch-carriage spec/code gap (code had it, template.md did not) closed before merge; my own verification grep initially fell into the line-wrapped-phrase trap Karl's amendment had warned about (whitespace-squeezed re-grep confirmed all sites present). Remaining from the round-3 review: F8 runtime capability-declaration alignment (accepted, not yet built), the #467 idempotency promotion decision, and the strategic bucket (grant-profile framing, mission_resource_access split, publication unit) plus the draft-zehavi demotion, all Karl's. |
| D68 | F8 resolved: runtime declares its substrate capability consumption (PR #483 merged); retro-log of the un-D-logged capability refactor `a394b4e`; follow-on issue #482 | The round-3 review's F8 finding, explored and applied on Karl's defaults (2026-08-12). Verified state: THREE documents disagreed about one fact. The substrate (refactored into a seven-capability model by commit `a394b4e`, 2026-08-09, WITHOUT a D-entry, the governance gap that caused this) mandates "a substrate-neutral profile MUST declare the kernel functions and optional capabilities it consumes" and names runtime its exemplar consumer; the architecture CLAIMED companions already declare consumption (false, no consumer did); runtime declared nothing, listed the pre-refactor "primitives" bundle, and claimed "another authorization substrate that provides the same primitives... can host this profile unchanged", the unqualified portability claim the substrate's own Capability Confusion consideration warns against. Only the SUPPLY side existed (UMA/AAuth/MAS Mission Substrate Statements; AAuth honestly declaring Structured Authority not supported). Runtime's text already half-spoke the language (lifecycle-gated/state-observable forms, D57 residue), so this completed what D57 started. **Fix (PR #483, three files, surgical):** runtime's {#mission-substrate} rewritten as a consumer-side declaration, kernel functions mapped onto the substrate's REAL kernel names (Native Reference and Controller, Basic Governance Gate, Ordered Governance Record; runtime's pre-existing "audit horizon" term kept and explicitly mapped) plus a capability table mirroring the supply-side Statement idiom: Structured Authority REQUIRED (the decision contract materializes/evaluates the effective Authority Set; a Mission reference alone is not structured authority), Lifecycle-Gated REQUIRED (only-`active` gating), State-Observable CONDITIONAL (staleness bound tighter than credential lifetime, the D57 condition kept verbatim, TTL-first preserved), Monotonic Derivation CONDITIONAL (delegation/attenuation/containment narrowing enforced at action time), Credential-Bound CONDITIONAL (else the externally established Mission reference of {{mission-binding}}, the defined external join), Independently Verifiable + Portable Evidence NOT CONSUMED (runtime-evidence's concern). Portability claim narrowed to the declared set citing Capability Confusion: a binding without Structured Authority does not host the decision contract and composes through its own native gate plus the external reference (the AAuth-stays-native honesty; AAuth cited informatively only). Architecture's false sentence corrected to reality (bindings declare provision; consumers declare consumption; runtime the exemplar; rest progressive). Runtime -> substrate reference NORMATIVE (substrate's runtime ref is informative, so no cycle, verified); manifest dep added (36 drafts, no drift). The reviewer's title rename ("Structured-Authority Mission Runtime") was DECLINED per Karl's default: the declaration does the honest work without churning the family naming. Surgical discipline held because parallel sessions were actively editing runtime elsewhere (round-5 review commits): exactly two runtime hunks (front-matter refs + the section), one architecture sentence area, one manifest line. Verified: vocabulary grep against substrate section heads (all terms real), wrap-tolerant table-row checks, docname preserved, builds 0 "Section ??", lint 0. **Follow-on filed as #482 (coordinated):** the remaining consumers (containment, metering, security-model, harness, orchestration, and runtime-evidence, which cites the substrate zero times today) get the same idiom, mostly mechanical now that the exemplar exists; each profile's required/conditional split should follow its own existing conditional language. |
| D69 | #467 resolved: `creation_request_id` REQUIRED idempotency for Mission-creating operations (PRs #488 spec + #487 code, merged); three verified impl gaps fixed in the same pass | Explored with Karl, then his advisor review REDESIGNED my proposal before build (2026-08-12): REQUIRED (not my OPTIONAL+SHOULD, which "does not close a High-severity issue" - the client cannot know the completion mode in advance, and an interactive retry starts a SECOND approval ceremony since single-use request_uri only prevents duplicate redemption of one); dedup the CREATION not the serialized response (the child grant is ~300s, so replaying a stored response returns expired artifacts); a durable reserved->completed|failed state machine with a datastore uniqueness constraint on (client, creation_request_id) and the reservation committed ATOMICALLY with Mission creation (closing the crash-before-response window); an EXACT typed fingerprint (family anchor idiom, typ `mission-creation-fingerprint`: op/iss/client/source/cnf/actor/intent/proposal/child_actor/requested_token_type/cross_check + an extension rule; `source` is the RESOLVED Mission from subject_token, never the raw token which legitimately rotates across retries, never the optional cross-check alone) with attempt-specific material excluded; security REVALIDATION on recovery (same client, recorded cnf possession, no key-rotation path defined) and the load-bearing LOOKUP-ORDER rule (after client auth + possession, BEFORE the predecessor lifecycle gate, because the retry worth recovering is exactly the one whose predecessor moved to `superseded` when the first attempt succeeded); recovery-as-delivery (pending -> same deferral_code/continuation; valid credential returned; EXPIRED credential -> a FRESH delivery credential for the already-created Mission under issuance-only accounting, never creation accounting); two-tier tombstone retention outliving the delivery artifact (>= published retry horizon; clients MUST NOT retry past it). Key exploration findings that resized the work: the family had ALREADY shipped the idiom in template dispatch (`dispatch_event_id`, "idempotent per dispatch event identifier"), both external reviews missed it, so #467 became extending the family's own pattern; and the IETF httpapi Idempotency-Key header draft is EXPIRED, so a family OAuth token-request parameter (expansion-owned per the mission_denial_reason shared-carrier precedent, child-delegation citing) won the carriage fork. FOUR advisor impl-assessment claims all VERIFIED TRUE against main and fixed in #487: (1) NO proof-jti replay cache existed for the manual DPoP blocks at the token endpoint (the code's own comment admitted it; captured-proof replay was open) - a bounded-TTL cache now covers all seven blocks; (2) the dispatch handler generated a crypto.randomUUID() fallback when dispatch_event_id was absent, silently defeating the retry safety template.md's REQUIRED promises - removed, missing now refused; (3) the generic deferral dedup key omitted client_id - both deferral keys now client-scoped (spec states the client-scoped rule; the unscoped behavior was NOT promoted); (4) the expansion `predecessor` cross-check was fingerprinted but not ENFORCED - refusal added, spec-pinned to plain `invalid_grant` because expansion.md explicitly EXCLUDES cross-check mismatch from its mission_denial_reason closed set (unlike child's `parent_mismatch`, which is in child-delegation's set - the build agent caught this distinction against my instruction's guess). Gate 66 files / 594 tests / 0 skipped. Filed alongside: #485 (async-delegation exchange retry safety, honestly framed as lower-consequence-but-not-retry-safe, a follow-on) and #486 (decide: the expansion SYNCHRONOUS mode spec/impl divergence - the spec issues a successor under a pre-consented ceiling, the code's sync branch is an ordinary confined derivation with NO successor; the idempotency code scoped itself to actual creation paths pending that call). #467 closed. |
| D70 | #486 resolved (option B-prime): expansion drops the synchronous completion mode; non-widening requests refused `nothing_to_expand`; drawdown machinery moves to its owner (PRs #490 spec + #491 code, merged) | Explored with Karl (2026-08-12). The fact base was decisive: the spec's synchronous ceiling-drawdown mode was TRIPLY unmoored (unreachable - no ceiling exists in any code, progressive has zero implementation; disowned by its own trigger - progressive.md completes policy-adjudicated drawdowns via the interactive path with the prompt skipped and never mentions the token exchange; basis-unspecified - zero approval_basis hits in expansion or progressive), while the code's sync branch fired on exactly the input class the spec excluded (a request NARROWING the predecessor's own effective set) and returned the opposite artifact (a confined token on the predecessor, no successor), with two warts: retries burned derivation_count and escaped the D69 idempotency reservation. ROOT CAUSE OWNED: my D62 lock said "pure subset derivation of already-approved authority" without disambiguating approved SET vs approved CEILING; the spec and code agents resolved it in opposite directions and the only test pinned the invented behavior. **Resolution (B-prime):** expansion.md now has TWO completion modes (deferred, interactive; "an expansion response is a successor or a refusal, never a token derived under the predecessor"); a non-widening request is refused with new closed-set denial reason `nothing_to_expand` under `invalid_request`, MANDATORY on the wire with an explicit carve-out from the privacy-omission rule (it reveals only what the requester's own token shows, so the policy-probing rationale does not apply); the code's sync branch replaced by the matching stateless refusal (pinning test rewritten: predecessor active, nothing created/reserved, derivation_count unchanged; gate 66/594/0-skipped). **Pre-merge review round (4 findings + 1 adjacent, all applied):** progressive now DEFINES its basis type `ceiling_drawdown` (activation = exactly policy_id + policy_version; consent_principal = the ceiling's Approver; root_commitment = ceiling_hash; child-delegation's policy_drawdown explicitly NOT reused); expansion DEFINES "effective Authority Set" (approved set reduced by the containment overlay and Status-profile discharged entries where deployed; the approved set otherwise) and states contained/discharged authority is NEVER nothing_to_expand but expansion-restorable only via a fresh-consent successor with disclosed containment history (matching the family containment-restore rule and the shipped code's effectiveAuthoritySet comparison); child-delegation's "mirrors expansion" replaced with shared-family-completion-pattern language (child KEEPS its synchronous mode - a Child Mission is always a creation and strict subset, unambiguous - with the expansion contrast stated); the worked example gained the D69-required creation_request_id. #486 closed. Progressive remains experimental and unimplemented; its interactive prompt-skipped completion is now the sole documented drawdown carriage until it matures. |
| D71 | draft-zehavi normative dependency KEPT (demotion declined) | Explored the thrice-raised reviewer objection to the core's normative dependency on the individual draft-zehavi-oauth-rar-metadata (D60; active -06 but not yet WG-adopted). Options: demote in place, relocate the schema-discovery + remediation-grain coupling to the discovery companion (my recommendation, restoring the all-ratified-RFC core posture), or keep. Karl decided: DON'T DEMOTE (2026-08-12). The dependency stays normative per D60's premise (WG adoption expected); the README's dependency-posture disclosure (D66) remains the honest statement of record. This is a deliberate reservation, not an oversight: do not re-propose demotion absent a material change (the draft expiring, or WG adoption resolving it naturally). |
| D72 | #482 resolved: consumer-side substrate capability declarations across six profiles (PR #494 merged) | The D68 runtime exemplar extended family-wide (2026-08-12). Containment, metering, harness, orchestration, and runtime-evidence now declare kernel functions + a required/conditional capability table in the runtime idiom; security-model (Informational) got a vocabulary-alignment sentence only, with the MUST-declare carve-out stated. Both unqualified "another substrate can host this unchanged" overclaims (harness, orchestration) replaced with capability-scoped claims. Key correction from the investigation: runtime-evidence PRODUCES deployment-key-anchored evidence and disclaims cross-boundary portability (routing it to audit), so the runtime exemplar's circular portability pointer was repointed to the audit profile. A five-finding external review round was applied before merge, the sharpest indicting my own D68 exemplar: the "integrity-anchor envelope" is NOT a substrate kernel primitive (the kernel requires immutable Approved Context; intent_hash/authority_hash are the OAuth binding's commitment mechanism) - corrected in containment/metering/orchestration AND runtime.md, with every portability claim now requiring capability compatibility plus a representation/commitment mapping; runtime-evidence's emitter streams are NOT the Controller's ordered governance record (joinable stream, audit may incorporate) and it does NOT consume Structured Authority (correlation, not evaluation); Independently Verifiable and Portable Evidence split into separate rows in all six tables; metering's Structured Authority condition extended to the `exclusive` control's selector semantics. Substrate refs normative in the five profiles (informative in security-model); manifest deps added (harness, orchestration, runtime-evidence). Gate: 7 drafts build 0 "Section ??", lint 0, manifest 36-drafts no-drift. #482 closed (auto-closed by the merge; completion comment posted). |
| D73 | #485 resolved: creation_request_id REQUIRED on the async-delegation exchange; single-lineage recovery (PR #497 merged) | The D69 follow-on (2026-08-12), one spec+code PR. continuation.md's async transport now REQUIRES creation_request_id by reference to expansion's D69 definitions, importing ONLY the common idempotency primitives (key uniqueness, fingerprint comparison, reservation ownership, tombstones, revalidation) and defining refresh-family delivery and recovery ITSELF; fingerprint op `async-delegation` (iss, client, resolved base Mission, the ACTING client's cnf since this exchange deliberately re-binds, the confined subset, target resource, request_refresh_token). A three-finding pre-merge review CORRECTED MY DESIGN: the D69 fresh-delivery-credential analogy is wrong for a stateful rotating refresh-token lineage - post-consumption re-minting creates parallel live RT branches, so the shipped model is CONSUMPTION-PROVES-DELIVERY (once the initial RT is consumed the operation is delivered and creation recovery is REFUSED invalid_grant; a rotating family is a single lineage per RFC 9700 and recovery MUST NOT mint a sibling); and the reservation now precedes ALL side effects via a reserved -> family-created -> completed state machine (family identity recorded on the reservation atomically with the single gateDerivation; crash between states resumes delivery of the SAME family; gate rejection invalidates the provisional family and records a replayable refusal). Tests cover the three previously-untested interleavings (post-rotation retry refused with the rotated head sole-live; concurrent first presentations -> exactly one family + one derivation count; crash rewind -> same-family resume). Gate 66 files / 600 tests / 0 skipped; drafts build 0 "Section ??", lint 0. D69's jti replay cache already covered this handler's captured-proof case, so #485 was purely the fresh-proof business-idempotency gap. #485 closed. Execution backlog now empty; remaining open thread: the strategic bucket (grant-profile framing, mission_resource_access split, publication unit) - Karl's. |
| D74 | #440 resolved: core's substrate description corrected to the post-refactor relationship (PR #504 merged); #499 blocked on PR #500 | Core hygiene batch explored (2026-08-12). #440: the published core still described the substrate companion as "a substrate-neutral statement of the Mission model, generalizing it" - inverted after the capability refactor (a394b4e/#438/#439): the substrate is the standalone binding-neutral contextual-governance kernel and the Mission model is its OAuth-NATIVE INSTANTIATION. Both informative sites fixed with the issue's proposed wording (the companion-profiles sentence verbatim; the GNAP paragraph now "the OAuth-native instantiation of a binding-neutral contextual-governance kernel that admits a candidate binding onto that substrate"), vocabulary matched to the substrate draft, the integrity-bound appositive kept on the Mission model (anchors are kernel non-goals, the D72 lesson), substrate ref stays informative, docname preserved, informative-only. #499 (Single Accountable Approver pointer -> Mission Approval Governance): BLOCKED - the target draft arrives only with the in-flight #240 extraction PR #500 (another session's work; not stacked onto); dependency comment posted, executes as a one-sentence follow-up when #500 merges. #440 closed. |
| D75 | #506 shipped: Mission Intent Submission envelope + Intent Submission Evidence hook (PRs #509 spec + #508 code, merged); Intent Admission profile deferred to #512 | Karl authored #506 (2026-08-12/13): the mission_intent value becomes a Submission envelope {intent, evidence} because an admission assertion committing to intent_hash cannot live inside the object intent_hash covers (circularity), controls would mis-model provenance as authority, and per-scheme OAuth parameters would proliferate. Two review rounds were folded into the ISSUE BODY before build (rev 2: shaping/revision invalidates evidence bound to a changed intent_hash; anti-downgrade with policy-required types resolved before derivation; presenter binding as a CONJUNCTION never alternative authentication; fingerprint rule scoped to surfaces that have D69 fingerprints; carriers vs re-admission vs consent-evidence sweep split; the provenance-commitment property left as the one open gate). Orchestrator decisions: BASELINE provenance (approval_basis-style record trust, honestly stated, provenance_hash extension point named), naming "Intent Submission Evidence" vs the family's emitted Evidence, the Intent Admission profile deferred (registry ships EMPTY, every presented type refused - the correct state). **As merged:** envelope closed to {intent (REQUIRED), evidence (OPTIONAL non-empty, [] refused)}; intent_hash commits exactly the inner intent (carriage-breaking, ANCHOR-STABLE, Document History entry); hook rules in core {#intent-submission-evidence} (reject-never-ignore; type-owns-members; policy-input-never-authority; anti-downgrade; shaping/revision invalidation; presenter conjunction; bounds incl. verification cost; 8-step order); NEW error `invalid_mission_intent_evidence` (IANA) split from structural invalid_request; record member submission_evidence pinned as {type, artifact_hash (typ mission-intent-evidence), verified_at, facts nested}; D69 fingerprints gain `evidence`; 9 drafts swept (5 carriers adopt, shaping+approval-revision get re-admission, consent-evidence non-ingestion). **Pre-merge review (6 findings) applied:** the sync schema-callback registry replaced by a TWO-STAGE interface (sync structural + async contextual verifier receiving intentHash/issuer/presenter/now, returning normalized facts) with a required-types policy hook; wire evidence was being DISCARDED before approval - now propagated end-to-end (PAR interaction state, approval renderer "Verified intent provenance" section, deferral-row persistence across the window, kernel.approve on every creation path: interactive/dispatch/child/expansion) with the fabricated-facts test replaced by a true wire-to-record e2e using a test-only type; rendering commitment now COVERS provenance via the consent-disclosure `submission_provenance_hash` (typ mission-submission-provenance over the submission_evidence array, covered by consent_rendering_hash; raw artifacts stay out) - conditional on a deployment implementing the companion commitment (the reference impl does not compute consent_rendering_hash, verified); recovery-precedes-freshness ordering (an expired artifact never breaks recovery of a completed operation, both sides); [] refused; MAS examples enveloped. Gate 67 files / 632 tests / 0 skipped; 9 drafts build 0 "Section ??", lint 0. Process notes: a stale-fetch false alarm (SSH identity drop made local origin/* refs stale; the "missing" final commit was on the remote all along - lesson: with SSH broken, verify remote state via gh api, push via the gh HTTPS credential helper); follow-on filed as #512 (Intent Admission evidence type, the hook's first consumer). #506 closed. |
| D76 | #499 resolved: the core's Single Accountable Approver pointer follows the Approval Governance Record extraction (PR #513 merged) | Unblocked when PR #500 (the #240 AGR extraction, another session) merged. One-sentence core fix plus the informative reference: the closing sentence repoints from the deferred-approval profile's Approval Decision Set to the Approval Governance Record; per the approving review's wording correction, Consent Evidence "may carry a deliberately partial presentation of that record through `co_approvals` and its approval-governance members" (the co-approval-members phrasing was too narrow: co_approvals presents human assertions only, while approval_authority/approval_policy_version/approval_governance_digest are the other presentation members). Deferred Approval stays referenced for its ceremony; reference informative (no cycle); the core's single-accountable-Approver model and its deferral unchanged; informative-only, docname preserved. #499 closed. |
| D77 | Issue-analysis sweep executed: 17 issues carry appended architect analyses; #291/#256 closed with records; #501 resolved (PR #517); #344/#316/#313 landed via Karl's parallel PRs (#514/#511) | Karl directed per-issue exploration with recommendations written INTO the issue bodies (2026-08-12/13, append-only, verified). Batch 1: #313 (free-text constraints disclosure-only, two structured doors), #316 (three authority sources + subject discipline), #290 (10 of 12 hygiene bullets survive as one batch), #291 (all four calls settled - CLOSED with record), #344 (third-party data-subject boundary), #501 (RS-local verification a documented non-goal), #343 (Evidence Properties citable table). Batch 2: #170 (three-tier IANA strategy), #284 (Commitment Mechanisms statement: I-JSON zero hits tree-wide, agility binds 4/24 drafts, three digest species), #283 (Mission-Reference carriage; #248 owns J0-J3), #286 (4 of 6 seams built; residue = OAuth-list notes), #256 (duplicate of #445 - CLOSED), #282 (envelope substance delivered; completion pass = 6 missing table rows + one typ-derivation rule, 4 divergent spellings found), #245 (14 MUST clusters lack negative tests), #194 (Mission Receipt homed in runtime-evidence, blocked by #282), #287 (1a superseded; discharge operation adopted reduced), #289 (all single-homed; remainder owned by #237/#248). **Executed so far:** #291 + #256 closed with disposition records; #501 shipped as PR #517 (the deliberate-omission text corrected by review from "impossible" to "undefined": the flat commitment defines no selective inclusion-proof mechanism, a future profile can compose generic Merkle inclusion with the type-owned subset test; the worked two-party contrast example ends at "containment verified relative to the authenticated committed set" with the four-item provenance provisioning list and the replacement-set attack; threat models split, the pinning is what makes the difference). **Parallel-session collisions handled cleanly:** #316 (PR #511, with the authority_source record member beyond the analysis), #344 (PR #514), #313 landed via Karl's own PRs while my builders were dispatched - agents detected the merged state, verified the merger identity per the guardrail, and stood down without duplicating; dispatch protocol now checks issue state first. Also this arc: #506 shipped (D75), #499 (D76). Remaining lock-ready: #290, #343, #170, #284, #282->#194, #245, #283, #287, #286, #512, the strategic bucket. |
| D78 | #282 resolved: committed-evidence completion pass (PR #520 merged); #194 unblocked | The bounded completion pass per the on-issue analysis AS REFINED by Karl's 2026-08-13 fresh-review comment (per-kind explicit typ mappings as a table column, NOT a universal derivation rule; eligible rows only; the as-issued canonical-bytes fix prioritized). As merged: four rows added to the audit evidence-types table (work-product binding as +jwt JWS bytes; egress; containment evidence; protected event receipt) with a new Operational typ column across all 17 rows; shaping cataloged via its shaping_evidence_hash commitment and orchestration kept local-use, both in prose by design; four existing rows' ambiguous "as issued" bytes corrected to the complete retained object, evidence_envelope included (JCS). A six-finding pre-merge review then applied: Harness/Egress operational typ = `none fixed` full stop (the invented "its media type when signed" deleted - the defining profile fixes raw JCS bytes under a named mechanism, not a JWS envelope); the JOSE-vs-COSE "two tiers" passage rewritten as COMPOSITIONAL LAYERS by function (operational signature = producer origin/integrity to any key-resolving verifier; Signed Statement = typed hash commitment, still a producer assertion; the Transparency Service Receipt under a separately trusted key is what makes verification independent, and it proves neither record truth nor feed completeness), with anti-cross-use re-anchored to identifier ROLES AND CHECKS not string values; the Work Product Binding producer projection defined exactly (producer = the signing mediator principal; binding iss = key-set authority not mediator identity; inner JWS verified first; Signed Statement iss MUST equal the binding iss and its key MUST be authorized for the same mediator principal/role; the Issuer does not register a harness-mediated binding as its own); RFC 7515 + six row-defining companion refs moved to normative with conditional-downref framing; the extension rule extended to five values (canonical bytes, preimage content type, operational typ + carrier or explicit none, producer); and a COMPUTED nested-envelope Decision Evidence vector added (retained object incl. envelope, one-line JCS 2570 bytes, digest sha-256:0qiDkwVoXwySxY32mS1NF_arp20x28leBo65z5PE5CQ) - independently re-derived byte-for-byte by the orchestrator, catching the two divergent-implementation classes (hashing received octets; stripping the nested envelope). Three files (audit + one-line notes in consent-evidence and work-products); builds 0 "Section ??", lint 0. Mid-task the build agent proactively surfaced the owner's fresh comment before editing and asked; the refined plan was confirmed over the literal dispatch prompt - the issue thread is the authoritative spec. #282 closed; #194 (Mission Receipt, homed in runtime-evidence as the first payload profile of this envelope convention) is now unblocked. |
| D79 | #251 resolved: metering promotion criteria (PR #529 merged); #117 now gated on evidence, not blocked | The quick item from the 2026-08-13 fresh triage, grown by review into a draft-mechanics repair. First pass authored the Promotion Criteria section (exercised machinery not elapsed time; eligibility for a deliberate decision, never an automatic flip; selective promotion allowed; the #117 linkage in the PR body not spec prose). A seven-finding chat-relayed review (never on GitHub; provenance recorded - the build agent detected the absent review, proceeded on the relayed findings, independently verified the evaluation_id premise, and requested the verbatim body, which reconciled cleanly) then exposed that the criteria assumed settlement/assurance mechanics the draft had not specified: FIXED as (1) the topology claims split into named Exact and Bounded-consistency enforcement profiles, only Exact qualifying a baseline hard-cap promotion and `exclusive` requiring it; (2) settlement standardized on `evaluation_id` (the `decision_id` references were a pre-existing bug vs runtime-evidence) plus a Settlement Submission Contract profiling the runtime-evidence delivery path (durable-apply-before-ack, idempotent on evaluation_id, conflicting redelivery fails closed, committed quantity per bound class); (3) the flat list replaced by a GATE MATRIX (gate x applies-to) making selective promotion well-defined; (4) settlement BY EVIDENCE STATE (suppressed = affirmative non-execution releases and is the exclusivity-latch release state; completed commits actual-or-reserved; attempted-but-failed needs a class-defined rule else holds; unknown holds and reconciles, timeout alone never releases a non-idempotent class; conflicting fails closed), reconciling the retry-release vs hold-until-affirmative contradiction; (5) a coordinated `metering` evidence member on Decision/Execution Evidence (bound, counter_scope, committed/pseudonymous counter_id, requested/reserved/remaining/consumed, decision-time settlement_state) so lineage-refusal artifacts prove the accounting invariant; (6) interoperation split into operational experience vs independently-implemented PEP/PDP interoperability (RFC 7942); (7) maturity language corrected - evidence for a deliberate decision through the applicable IETF process, catalog labels distinct from IETF stream decisions. One file; builds 0 "Section ??"; lint 0. #251 closed; #117 (exclusive-control core promotion) now waits on the Exact-profile latch gate being exercised rather than on an undefined bar. |
| D80 | #433 ruled: delegation identity follows authorization continuity; the holder-mediated actor-attribution model recorded (PR #544 merged); wire changes ride #538 | The deferred issue reopened when three consumers arrived (#538 cross-org delegation, #539 origin principal, #540 transaction authorization), all citing #433 for one actor-chain convention - and what they need is new (the attenuation chain carries no act member; parties are key-identified via cnf), not the deferred Concern 2. Exploration surfaced the two-lane structure: the sibling actor suite (Actor Profile for Delegation with REQUIRED act.iss; Actor Receipts, issuer-signed hop provenance; Actor Proofs, actor-signed participation + target binding; Authority Bounds) is the evidence layer of ISSUER-mediated chaining, while the attenuation chain is HOLDER-mediated and self-proving (delegator-signed hops + structural subset + leaf PoP), needing neither receipts nor bounds; the family already cites the suite at the two right seams (runtime consumes proofs/receipts as token-derived facts; cross-domain MAY-requires receipts upstream of a re-mint). Karl's architecture review (2026-08-14, on-issue) revised the first proposal with three P1s, all adopted: (1) the root must carry an ISSUER-ATTESTED actor bound to the root presenter key - client_id names a client not an actor, cnf names a key not a controller, and a Mission Record the verifier may not hold is not portable identity; (2) holder-minted act values are NOT authenticated identities - a parent signature proves delegation to a key, never the asserted identity values, so a named actor counts only with an independent workload-credential/attestation binding of (act.iss, act.sub) to that hop's cnf, else the hop is key-only, its asserted identity informational at most, never satisfying allowed_delegates/sub_profile or influencing authorization, failing closed where a named actor is required; (3) NO nested-history duplication - each artifact names only its own hop's actor, the complete history is reconstructed from the validated root-to-leaf chain, and the RFC 8693 nested projection is materialized once at a consuming boundary (PDP/introspection/destination AS), never carried per artifact (quadratic growth, consistency and DoS surface). Also ruled: Actor Receipts stay in the issuer-mediated lane (a destination AS cannot retroactively manufacture issuer receipts for holder-created hops; the AAT-to-local bridge is chain-alongside, introspection/evidence resolution, or a destination-AS chain-verification ATTESTATION); the Authority Bounds caution extends beyond reauthorized/bounds_events to every basis-reset/widening mechanism including domain_transition (detailed profile = separate issue); Concern 1 (eligibility matcher, D63) complete and out of active scope; Concern 2's eventual shape named; AAuth act/agent cleanup stays #445. AS MERGED (PR #544, the ruling-recording slice per the review's sequencing): core delegation section gains the authorization-continuity corollary (nest while authority continues under the same approved Mission; a new approval basis - child, successor - begins its own delegation basis; no organizational/topological boundary restarts or extends a chain) plus chain-is-attribution-never-authority (subset relations prove narrowing) - the piece #539 needs, unblocked without the wire change; attenuation gains {#actor-attribution} recording the model as binding constraints on the profile that adds the field while defining no member itself. The actor field, its shape, and the five-step verification algorithm are specified through #538 first, then generalized into the substrate. Two drafts build 0 "Section ??"; lint 0. #433 stays open tracking the #538-borne wire work; order #539 -> #538 parallel #540. |
| D81 | #526 resolved: authenticated introspection state machine (PR #541 merged) | Karl's corrected issue body implemented as a two-commit fail-first sequence (23 conformance rows, then the fix). Registered introspection principals (config/introspection.json + typed loader): per-caller authorized audiences and disclosure privileges, HTTP Basic with timing-safe compare, 401 + WWW-Authenticate, audience decisions never from the request; the shared x-service-token is retired for /introspect. Strict resolution: signature over published keys, expected issuer, at+jwt token class (jose typ check), time validity, Mission-reference resolution; INDIVIDUAL REVOCATION IS GRANT-SCOPED for stateless JWT ATs (oidc-provider never stores jwt-format tokens, the spike finding one layer deeper), with the non-active branch PRECEDING the grant arm so Mission-level revocation (which destroys the grant as a side effect) still reports the core-REQUIRED mission.state, while an active Mission with a destroyed grant (RFC 7009) is bare active:false. Response matrix as specced: unresolvable or caller-invisible tokens return bare {active:false} with no Mission or token detail; valid+visible+active returns the audience-minimized projection with COMPLETE pinned key sets (no cross-audience privacy oracle via sub/aud/client_id/jti/cnf); valid+visible+non-active returns ONLY {active:false, mission} with mission.state. kernel.introspectionProjection: audience-filtered EFFECTIVE authorization_details, derivations_remaining under controls.max_derivations, containment_version, privilege-gated proposal_hash (provenance) and status_list - issuer-only is authority to assert, not authorization to disclose. Mission-bound refresh tokens introspect under the same composite (found, unexpired, not consumed/destroyed, grant intact when active; visibility = effective authority intersect caller audiences). BuiltAs.tokenSigningJwk exposed as the adversarial-token test seam. Gate: typecheck clean, lint clean, 655/655 tests 0 skipped (68 files) with OpenFGA live; tracer + rar-carriage suites moved to the authenticated contract. #526 closed. |
| D82 | #539 spec surface shipped: the Origin Principal profile (PR #545 merged, after its declared dependency PR #541); chain carriage + implementation ride #538 | Cross-Domain Projection hosts the profile (where Subject conveyance already lived: the grant populates the record subject; both defines-no-mapping disclaimers RECAST, not contradicted - still no universal account-linking protocol, but the mapping INPUT, continuity INVARIANT, and authorization rule are standardized). mission.subject: closed {iss,sub}, VALUE equality (not bytes) surviving re-signing/re-serialization; identity provenance and constraint input, never authority; opaque pseudonymous sub REQUIRED and stated as sensitive correlation data even when opaque; multi-tenant bar (globally unambiguous pair or the profile cannot be claimed). Trust class per surface mirrors D80: root-attested + invariance-verified on chains (no per-hop binding needed for this member), destination-AS-signature-attested on projections, responder-asserted on introspection under the new origin_principal disclosure privilege (composes with D81's principal model - the declared reason PR #541 merged first). The pairwise/invariance contradiction resolved: linkability fixed at record creation; default = origin-sector pseudonym with cross-destination Mission correlation (named honestly per review); RECOMMENDED per-Mission pseudonym where mapping infrastructure supports it; destination-pairwise not constructible. ID-JAG composition (review P1): both issuer-qualified subjects MUST identify one principal (issuance attests under the recorded injective mapping; redemption requires one destination-local resolution or invalid_grant; neither value independently selects an account). AuthZEN: context.mission.subject via the companion-extension rule + consistency check 10 with the mapped_subject algorithm (map -> require equality with the authenticated request subject -> entitlement lookup; direct namespace comparison wrong by construction; PDP-authoritative default, PEP placement needs a structured integrity-protected mapping observation; denies principal_mapping_failed). Evidence: principal_mapping coordinated extension (Decision + Refusal; Execution joins via evaluation_id; derivation record carries the mapping decision) with PROTECTED subject references (keyed pseudonym w/ method+key id+rotation, opaque auditor reference, or the public mission-origin-subject digest ONLY where correlation is intended, dictionary limitation disclosed - the without-disclosing claim was false and removed). Dual-axis authorization = delegated authority INTERSECT current principal entitlement INTERSECT local policy, separate freshness declarations, fail closed, scoped as the profile's conformance bar (TTL-first baseline undisturbed). Mandate.subject pinned as the same value by construction. Refs classified normative where load-bearing (authzen/runtime-evidence -> cross-domain) with cross-domain's evidence paragraph an informative composition pointer (no cycle). Eight-item conformance inventory enumerated; manifest rows + vectors + implementation blocked on #538. Nine-finding review (5 P1 / 4 P2) applied in full. Four drafts build 0 "Section ??"; lint 0. #539 stays open for chain carriage + impl. |
| D83 | #523 resolved: binary compromise-boundary verification rule (PR #531 merged) | Karl's corrected issue body replaced the earlier vague per-draft "compromise exception" and this analyst's rejected "suspect"-state idea (plus the false claim that registration cadence bounds adversarial backdating: it bounds honest-evidence anchoring lag only; no registration_cadence ESS member). The rule, stated ONCE in runtime-evidence {#evidence-integrity-signing-keys} and referenced everywhere else: a verifier MUST NOT use timestamps carried by an artifact to place its signature before a compromise boundary; once the key is identified as compromised, only an independently trusted proof committing to the complete signed artifact (or its unambiguous typed digest) and establishing existence BEFORE the boundary restores verification, and such a proof proves byte-existence by proof time, never truth, actual signing time, or earlier non-compromise. Applies whether or not the audit profile is adopted (audit registration or a trusted timestamp is the optional recovery mechanism); a Receipt-based proof requires FULL audit Receipt verification (TS signature, authenticated registration time, inclusion proof, type binding, digest linkage; a bare inclusion path or payload timestamp is insufficient). Applied in the record verification paths (Decision/Execution/Refusal), Receipt Verification, and the harness key lifecycle (carried-over exception replaced by a cross-reference); the Session-independent evidence-property row points at the rule. Refusal under the rule is an AUDIT failure, never an integrity finding: absence of an independent proof is not evidence of tampering. Conformance outcomes added ({#compromise-vectors}): self-asserted timestamps never rescue; verified pre-boundary proof permits continuation; at/after-boundary proof does not; missing/failed proof = not-verified; same outcomes for Mission Receipts and harness evidence. No new parameters, states, objects, or key-status protocol. Both drafts build 0 "Section ??"; lint 0. #523 closed. |
| D84 | #525 resolved: family-wide requested-versus-effective Mission expiry + mission_expires_at (PR #542 merged after a five-finding review round) | intent.expires_at = the client's requested not-after ceiling (recorded verbatim; malformed/already-past = invalid_request, replacing the invalid_authorization_details refusal: the member rides mission_intent and the request may carry no RAR); Mission Record expires_at = the AS-established effective lifetime, never later than the request; shortening under policy or an already-approved bound is ordinary narrowing, never Authority Set derivation; extension always requires a new submitted value. Per-surface ceilings: direct (AS policy only), Template Dispatch (three-way clamp min(requested, committed created_at + instance_lifetime, template.expires_at), the addend measured from the COMMITTED created_at so audit recomputation is exact; the earlier "deployment policy" third input was wrong), Expansion (submitted request + predecessor bound with the disclosed-extension carve-out), Child (submitted request + parent bound). One common mission_expires_at success-response member for EVERY Mission-creating flow (expires_in describes only the access token) with IANA registration; consent-evidence renders effective + requested-when-different. REVIEW ROUND (five findings, applied by the peer session in 87bfbe9): (1) explicit approval sequencing: establish the effective expiry BEFORE rendering, render exactly that value, commit exactly the rendered value, re-establish + re-render on any pre-commit ceiling change (render-one-commit-another foreclosed); (2) audit formulas corrected to INEQUALITY verification, not recomputed-minimum matching (child: effective <= both bounds, further shortening justified by recorded policy; expansion: <= requested always, <= predecessor absent an approved extension, predecessor < effective <= requested with one, rendered and approved at the consent event; Template stays exact); (3) deferred race closed: the creation commit atomically verifies effective expiry strictly later than the creation instant, a ceiling passing while approval pends creates no Mission; (4) mission_expires_at defined first as the common member of every creation-completing surface (the OAuth token-response registration is additional; the MAS approved submission-status response carries it REQUIRED, closing the no-credential creation surface; expansion carriage an explicit MUST); (5) the stale core.intent.expires-at-refusal manifest row replaced by six rows describing the new contract (manifest 55 rows, 0 blocked; executable tests ride #245, now unblocked for the expiry rows). Six drafts build; family manifest + whitespace checks pass. #525 closed. |
| D85 | Composition-proposal disposition executed, bundles 1-3 (PRs #548/#549/#550 merged as a stacked chain; core pointer filed as #551) | The 2026-08-11 review disposition on notes/mission-substrate-composition-proposal.md had been recorded but never executed: an audit found ZERO of its adopted items in the substrate draft (no role map, activation conditions, fact-semantics split, Authorized Context Correlation, transition classification, temporal/failure elements; no composition evaluator in src; the crosswalk explicitly disclaims being the Statement) and the OAuth issuance core remained the one binding without a Mission Substrate Statement - an asymmetry D72 sharpened (every consumer MUST-declares consumption; the largest provider declared nothing). Karl directed bundles 1-3 (bundle 4, Baseline Issuance tests + worked composition example, rides #245/architecture later). BUNDLE 1 (#548, disposition items 2+8): the Statement capability table retires `conditional` - a row is `supplied` in a named scope when stated ACTIVATION CONDITIONS hold, or `not supplied`, separating what the spec defines / the implementation supports / the deployment enables / where the property applies; every supplied row states TEMPORAL elements (freshness at use, decision/artifact lifetime, post-non-active residual, stated or expressly inherited from the Bounded Reliance floor - kernel floors unchanged) and FAILURE behavior (absent/stale/unknown/incomparable/invalid/unavailable); extensions publish Statement extensions a deployment profile activates; skeleton, crosswalk, and capability-confusion consideration swept. BUNDLE 2 (#549, items 1+3+4+5): Authority Roles {#authority-roles} (eleven roles; colocation MUST NOT let one role's assertion establish another role's fact; kernel requires approval + lifecycle; family appendix aligns the authority-source role to the core's authority_source vocabulary, user-delegated/service-owned/organizational + source ceiling, rather than inventing a parallel one); Credential-Bound selects its FACT SEMANTICS (correlation-only / issued-under / authority-derived / lifecycle-gated-issuance / state-as-of; no unqualified "Mission-bound"; presenter proof separate, bearer compatible); Authorized Context Correlation as a named capability (the MAS join / Join Assertion machinery formalized: joining authority, association policy, proof inputs, conflicts, lifetime, revocation, audience, substitution protection; matching strings or timestamps never satisfy) with the Context Splicing consideration; Monotonic Derivation transitions classify preserve/attenuate/decide_anew with incomparability routing to refusal or decide_anew (never silent attenuation) - cross-domain cites it (audience-scoped projection = attenuate, local re-mint = decide_anew), giving #538's chain rules a citable classification. BUNDLE 3 (#550, item 7 as reshaped): the normative OAUTH MISSION BINDING STATEMENT hosted in the substrate's family appendix {#oauth-statement} so the core stays self-contained: nine kernel mappings (mission_id; issuer Controller; client Actor + injective Subject mapping + act-chain delegates + lineage members; Intent/proposal/derived-set Approved Context under the typed anchors; the approval ceremony incl. distinct-approver + effective-expiry rendering; the exact active predicate; the effective-expires_at reliance bound with declared-TTL residual; five propagation/join surfaces WITH per-surface fact semantics; record + audit horizon) plus the eight-capability table in the upgraded format (companions are the activation conditions for State-Observable / Independently Verifiable / Portable Evidence; ACC scoped to the issuer's own grant binding, cross-authority joins stay MAS machinery). Issue #551 records the core-side pointer for the core's next revision (the #440 pattern) - the previously dangling "revisit oauth issuance" action, now tracked. Deferred (per disposition, unchanged): the 16-field schema and composition procedure, gated on the implementation-repo evaluator, whose first real fixture now exists (#550's Statement). Stacked-chain merge executed with retarget-before-merge (no mid-chain branch deletion). Substrate + cross-domain build 0 "Section ??"; lint 0. |
| D86 | Delegation-continuity duplicate resolved (#546 collision; PR #553 merged with two review fixes) | A parallel-session collision: PR #544 (05:02Z) and PR #546 (20:17Z, another session) both recorded the #433 ruling in core on 2026-08-14, leaving two adjacent, subtly different statements of the invariant (core lines ~3599 and ~3630). PR #553 (Karl) removed #546's paraphrase, keeping the D80-ruled #544 wording verbatim, and rewrote architecture invariant R19 to the three-lane representation (issuer-mediated nests act; holder-mediated attenuation reconstructs history from per-hop actors; cross-domain projection carries no upstream chain, destination chains begin locally; "topology alone neither restarts nor extends one"), adding cross-domain to the invariant's document refs. Review (this session) verified the right paragraph survives, R19 is faithful to D80, and builds/lint/both manifests pass (55 requirements 0 blocked; 38 drafts no drift), and applied two fixes pre-merge: (1) the removed #546 paragraph UNIQUELY carried the act-as-policy-input clause; migrated into the surviving core paragraph ("an act entry names who acted, for audit and as policy input to the eligibility matching of {{delegation-constraints}}") so attribution-never-authority cannot be misread as never-consult-act, contradicting the D63 eligibility matcher and the D82 dual-axis model, and core now matches R19's precise phrasing (consolidate-structure-not-content: every normative clause preserved when merging redundant sections); (2) R19's new-basis enumeration regained "any fresh approval" beside Child Mission and Expansion successor. Process note: the collision class is the known parallel-session risk; the issue-state-check-at-dispatch discipline applies to ruling-recording PRs too - #544 was pushed and merged before #546 branched, so #546's session missed a fetch-fresh check against main. |
| D87 | Composition-proposal bundle 4 shipped: Baseline Issuance test set + worked composition (PR #552 merged after a five-finding review; #554 filed) | Architecture gains the disposition's last two adopted items (6 + 9). The Baseline Issuance minimum test set landed CAPABILITY-SCOPED after review finding 1 (the flat nine-case draft was OAuth-centric and contradicted the section's own standalone-MAS case): kernel rows for every Baseline deployment (approval creates an active Mission; an authenticated terminal transition takes effect in the Controller's own decisions; observed residual <= the published reliance bound), Credential-Bound rows where claimed (nothing outlives effective expiry; no cross-Mission substitution), Lifecycle-Gated Authorization rows where claimed and limited to the claim's named operations (positive-on-active; terminal prevents; and, per finding 2 replacing the arbitrary declared-failure-behavior escape hatch, unavailable/invalid/stale/unknown state prevents a positive result - lost state never fails open, matching the substrate's LGA fail-closed rule), and OAuth-binding rows (refresh both directions; the grant, never a client-supplied identifier, determines the Mission). Executable rows stated plainly as planned in the conformance suite (#245 lane; the manifest models normative MUST-statements, so architecture demonstrations get traceability when the suite lands them). The Worked Composition ({#worked-composition}, note 14.3 adapted to the landed substrate vocabulary): an Action-Enforced deployment from four non-OAuth providers (AAuth PS kernel + Lifecycle-Gated Authorization; AAuth Mission Management as State-Observable; a resource-owned payment policy adapter as Structured Authority in its own vocabulary; the gateway as Authorized Context Correlation) with runtime/evidence supplying enforcement; the resource's fresh decision classified decide_anew (never cross-vocabulary attenuation); per findings 3 + 4 the example assumes a DEPLOYMENT-LOCAL Statement extension in the current claim format (the AAuth draft's table still uses the retired states) and pins PS-asserted access: the signed mission_s256 reference is the protected propagation path (identity-based/resource-managed access explicitly out of scope: not PS-gated, may ignore the reference), the join validates issuer/audience/actor-key/request binding, is scoped to the two routes with a freshness-bounded lifetime, and fails closed on missing or conflicting inputs; the failure list gains the identity-based/resource-managed acceptance condition; the declaration stays prose/tables (machine-readable statements deferred; the Deployment Profile schema #424 stays parked and is explicitly reserved in the text). FOLLOW-UP FILED: #554, the family sweep migrating the EIGHT drafts still publishing retired-format capability tables (aauth, harness, authority-server, orchestration, metering, runtime, uma, containment) to the supplied/activation format, incl. the per-binding decision whether AAuth Mission Management publishes its own Statement extension. With this, all nine adopted items of the 2026-08-11 disposition are executed (D85 + D87); the deferred schema/procedure items stay gated on the composition evaluator, whose first fixture (the OAuth Binding Statement) exists. Architecture builds 0 "Section ??"; lint 0. |
| D88 | #538 spec shipped: Mission Cross-Organizational Delegation, the 39th draft (PR #555 merged after a nine-finding review; PR B implementation pending) | The companion (draft-mcguinness-oauth-mission-cross-org-delegation, experimental, profiling Offline Attenuation) implements the issue's protocol under the D80/D82 rulings: per-hop single actor objects with history reconstructed from the validated chain (never nested); the issuer-asserted approved agent on the root; mission claim value-invariant incl. subject; org boundaries never reset del_depth; ten-step destination verification ending in the dual-axis rule; projection restarts act and never yields a new delegation root; hop transitions attenuate, local decisions decide_anew. Karl's nine-finding review (6 P1 / 3 P2) then forced the load-bearing seams from prose into protocol objects, all applied: (1) the CHAIN PRESENTATION, a closed JSON envelope {chain: ordered compact-JWS root-to-leaf, actor_credentials: typed hop-aligned}, base64url subject_token under the new urn:ietf:params:oauth:token-type:mission-delegation-chain + application/mission-delegation-chain+json (both IANA-registered), declared hop/size/cost bounds refused BEFORE any signature verification, chain digest pinned to JCS canonical bytes of the chain array (typ mission-delegation-chain), direct RS presentation deferred; (2) portable chains MUST carry full public cnf.jwk per hop (thumbprint-only non-conforming: a disconnected verifier verifies each child under the parent's carried key); (3) actor evidence TRANSPORTED, not assumed: named hops require an aligned actor-binding credential validated five ways (registered type refuse-never-ignore, trusted issuer per the federation mapping's attestation anchors, validity/status, subject = both-REQUIRED act.iss+act.sub, bound key = cnf.jwk by thumbprint); key-only hops OMIT act entirely (eliminating the inert-names ambiguity); the Mission Issuer resolves the approved client to a canonical actor and records mapping+version in issuance evidence (client_id is not an actor identity); (4) authority scoped to exactly the mapped AAT capability entry via the attenuation root mapping (mapping profile+version recorded; unknown/unmapped entries never confer and their presence refuses; other RAR types need a registered per-type mapping+subset algorithm), fixing the silent-ignore risk against the AAT processing model; (5) the chain-verification attestation DEFERRED to a companion until a consumer shows the two remaining AS-mediated provenance modes (chain-alongside; introspection/evidence resolution) insufficient; (6) the PROJECTION EXCHANGE defined as the executable RFC 8693 seam (parameters, leaf-cnf.jwk PoP matching the issued token's binding, invalid_request/invalid_grant/invalid_target mapping, no partial-verification disclosure) plus a non-normative A-to-B-to-C end-to-end example with a key-only hop; (7) explicitly NO runtime discovery (aat_issuer advertises root issuance only; capability + consumption class + trust domains are deployment-profile/federation declarations); (8) NINE conformance-manifest rows added with coverage blocked on #538 (manifest 64 requirements; PR B turns them green); (9) Status normative (step 9's state source), runtime inheritance stated precisely, RFC 7515/7519/8725 + a JWT-BCP compliance statement. Wiring: cross-domain delegate-crossing repointed to the companion + local-depth/chain-depth split; attenuation {#actor-attribution} names the companion as the member's defining profile; family manifest 39 drafts, README catalog + adoption order, architecture document map. Open-question answers adopted as recommended: the companion name; attestation deferred (superseding the v1-minimal recommendation, per review); capability via deployment declaration. #538 stays open for PR B (root mint + chain verifier + projection path + the nine blocked vectors). |
| D89 | #538 resolved: cross-org delegation IMPLEMENTATION shipped (PR #559 merged; #538 closed) | PR B, the reference implementation of the #555 companion. NEW mission-core/cross-org-presentation.ts (dependency-free): the closed Chain Presentation parser (top-level closure, hop/size bounds enforced BEFORE any signature verification, typed hop-aligned actor_credentials) + chainDigest over JCS canonical bytes of the chain array. NEW AS kernel/cross-org-chain.ts: the ten-step verifier (trust-model issuer resolution never from the chain; root incl. issuer-asserted act + mission.subject; every par_hash link and child signature under the PARENT's carried public cnf.jwk, thumbprint-only refused; mission value-invariants across hops; monotonic depth, nested aud/exp, mapped-capability subset; named-vs-key-only classification with five-point actor-credential validation; lineage reconstruction rejecting nested/duplicated act; fail-closed Mission-state gate within a freshness bound; step 10 dual-axis + leaf PoP are the caller's). kernel/attenuation.ts gains deriveCrossOrgRoot (issuer-asserted actor from a RECORDED canonical mapping, public cnf.jwk, subject) + mintCrossOrgChild (public cnf.jwk, optional per-hop act). NEW adapters/cross-org-grant.ts: the RFC 8693 projection exchange at the token endpoint (leaf-key DPoP PoP, origin-principal mapping refusing on missing, dual-axis intersection with the local ceiling, restarted local act, principal_mapping derivation evidence, invalid_request/invalid_grant/invalid_target mapping with no partial-verification disclosure), behind the chain subject_token_type and gated on a per-deployment crossOrg config (absent = refused). Tests +72: 12 unit (presentation parser + digest) + 14 integration (valid A-to-B-to-C across three synthetic trust domains with root named / hop1 named+credential-validated / hop2 key-only, then the negative matrix: widening, reorder, missing hop, untrusted root, missing/wrong-key/untrusted-source actor credential, depth overflow, nested-act duplication, unmapped authority, unavailable/stale/revoked state). The nine #538-blocked conformance rows flipped to tested. MERGE INCIDENT: main moved under the branch (a parallel session's #556/#283 appended manifest rows); merge conflict confined to conformance-manifest.json (my tested cross-org rows vs their blocked + their new mas.reference rows), resolved by keeping my tested versions and appending their new rows (71 requirements, 0 blocked); GitHub cached CONFLICTING after the resolution pushed, cleared on recompute; no force-push. Also dropped a .claude/settings.json git-add-all swept in. Full gate on the merged tree: typecheck clean, lint clean, 727/727 tests 0 skipped (71 files) with OpenFGA live; both manifests clean. The cross-org trio's delegation half (#433 ruling D80, #539 origin principal D82, #538 spec D88 + impl D89) is complete; #540 (transaction authorization) is the remaining roadmap piece. |
| D90 | #540 spec shipped: Mission Transaction Authorization profile, the 40th draft (PR #560 merged after a nine-finding review; PR B pending) | PR A. First pass authored draft-mcguinness-MISSION-transaction-authorization as an architecture sketch; a nine-finding review (7 P1) directed a rewrite into a THIN OAUTH DELTA over the upstream transaction authorization challenge (draft-rosomakho-oauth-txn-challenge), all applied. (1) Profiles the UPSTREAM WIRE PROTOCOL unchanged: Accept-Txn-Challenge, transaction_authorization_required (WWW-Authenticate), transaction_challenge, transaction_authorization_endpoint (AS metadata), transaction_authorization_id pending handle, polling, upstream errors, typ txn-authz-challenge+jwt, mandatory reason; TAS = the OAuth AS functional role; exact token response with token_type + refresh-token prohibition. (2) CROSS-ORG PROJECTS FIRST (the load-bearing simplification): the input is ONE local Mission-bound token; a delegation chain is verified + projected via the existing Resource AS exchange BEFORE this profile runs, so one credential class, one authority language, the chain surviving in derivation evidence not the transaction request; a TAS is not a chain-verifying endpoint (this also made the identity-projection finding clean). (3) ASYNC LIFETIMES separated: challenge exp (admission/replay) vs transaction_authorization_id expiry (pending workflow, may exceed challenge exp) vs token exp (step-9 fresh-revalidation inputs + pending-handle, NOT the consumed challenge exp); one accepted challenge -> one pending workflow, retries return the same handle, completion triggers fresh revalidation - fixing the impossible-async-lifetime bug. (4) AT-MOST-ONCE keyed by resource-scoped txn (not (iss,jti)): idempotent TAS issuance per workflow, atomic resource consumption per txn under the metering Exact enforcement profile, (iss,jti) for exact token replay; four identifier roles defined (challenge jti / transaction_authorization_id / txn / token jti + runtime idempotency); same-txn/different-jti vector added - fixing the two-tokens-one-txn double-execute bug. (5) IDENTITY PROJECTION + token restrictions explicit: sub (mapped local principal) / client_id (endpoint auth) / act (local token) / aud (single challenge issuer) / cnf (challenge key) sourced; approver never becomes an identity; mission-txn-token+jwt REQUIRED; no refresh/exchange/delegate/cross-org-root/ordinary-token, usable only for its txn. (6) PARAMETER TRANSPORT via reason_uri or the RAR detail bound to iss/txn/challenge-jti/parameter_digest, with a versioned operation_profile {id,version} pinned so a mid-flight profile update can't change normalization; no generic attributes bag. (7) EVIDENCE lifecycle corrected: ARAP + Approval Governance for the action-approval workflow, Decision/Execution Evidence for decision + execution, Mission Consent Evidence ONLY for the original Mission approval (it is scoped to approval-time rendering); runtime edit says the profile DEFINES the cross-domain wire workflow, not that it profiles Consent Evidence. (8) RENAMED draft-mcguinness-mission-transaction-authorization -> -oauth-mission- (OAuth-specific endpoint + JWT AT, no substrate section; the honest oauth-* name; family manifest/README/architecture-doc-map retargeted). (9) IANA/refs: full RFC 6838 template with 8bit encoding, only the token media type registered (challenge type is upstream's), RFC 6838/7519/7800 normative; EIGHT todo conformance rows added (upstream endpoint, async completion, one-workflow, same-txn/different-jti, token restrictions, identity projection, fresh-decision, versioned parameter profile) for PR B. Runtime's txn-challenge composition sentence retargeted. Incidental: .claude/settings.json git-add-all sweep caught and kept out of the commit (verified post-commit). 40 drafts no drift; all edited drafts build 0 "Section ??"; lint 0; conformance manifest 79 requirements 0 blocked. #540 stays open for PR B (remove the spike's approval/single_use members, wire the conforming challenge/token/verification path, turn the eight rows green). The full cross-org trio is now spec-complete: delegation (#538 D88/D89) + origin principal (#539 D82) + transaction authorization (#540 D90). |
| D91 | #540 spec convergence: a parallel session (#558) reworked the merged transaction-authorization draft; PR B implementation still pending, #540 OPEN | Correction/annotation to D90. Two sessions authored the #540 spec concurrently: mine (PR #560, merged first at 1e433b8) and another (#558, "39th draft" framing). #558 REBASED ONTO the identity my #560 established, reworked its text, and merged on top (03ddc0b, after my D90 push). The draft on main is now #558's blended version (757+/492- vs my #560 text): it preserves every nine-finding review outcome (upstream Accept-Txn-Challenge protocol run unchanged; TAS = OAuth AS role; mission-txn-token+jwt typ; single_use is a PROHIBITION not a member; Exact-enforcement consumption citing metering; Status-surface state source; ARAP + Approval Governance evidence with Consent Evidence scoped to Mission approval; oauth-* name) but differs in specifics from D90's description of MY version: it does NOT use the operation_profile {id,version} member, registers TWO media types (mission-txn-challenge+jwt + mission-txn+jwt) rather than my token-only registration, and carries a Mission Substrate capability-consumption section (honoring the naming rule's second half instead of my no-substrate-section approach). My 8 txn-authz.* todo rows were REPLACED by #558's fuller 20-row txn-authorization.* set (all coverage todo; 91 requirements total). NET: the #540 spec is a converged blend, review-hardened, on main. NOT merged: PR B (the conforming implementation). The transaction.ts on main is the separate M5 transaction-assurance permit/lease/reconciliation tier (commit b98b1c4), NOT the txn-authz wire profile; the src spike's private single_use/approval members remain on main, flagged by both #558 and the issue for removal at implementation time. #540 stays OPEN for PR B (remove the spike members, wire the conforming upstream-challenge/redemption/token/offline-verification path, turn the 20 todo rows green). Process note: this is the parallel-session collision class again - two sessions on one issue; convergence held because #558 rebased onto the first-merged identity rather than clobbering, but D90 was left describing a superseded draft shape until this annotation. |
| D92 | Architecture review cycle: issues #561-#565 filed + #424 question, rulings received, seven PRs opened (#566-#572), nothing merged | Fresh full-suite architecture review (six parallel reviewers over core/architecture, substrate kernel, bindings, lifecycle profiles, governance/evidence plane, family map; verified clean: manifest sync 40/40, substrate standalone posture, runtime/runtime-evidence field-level back-citation, approval-stack vocabulary, single evidence model, all designed seams). Findings filed as #561 (containment not threaded through harness/UMA/discovery), #562 (Effective Authority Set had no single home; discharge change-visibility), #563 (core-roles vs substrate-claims vocabularies unreconciled; lockstep passages unpinned; architecture nits), #564 (six convention stragglers), #565 (README/manifest hygiene), plus a course question on parked #424 (core approval-floor MUST naming the schema-free Deployment Profile as its home). Owner rulings (2026-08-17) revised every sketch; implemented as: PR #569 (spec: status.md owns the abstract cycle-safe Effective Authority Set definition + single-computation conformance invariant; containment/expansion/child-delegation cite it; template says committed Authority Set; NO counter broadening, containment_version stays containment-specific); PR #572 (impl: kernel computes authority_changed on metadata-only commits (documented as constraint, review point: inference vs per-funnel flag), signals builder relays it, receiver latches rematerialization on authority_changed or a containment_version advance past an observed baseline; 12 tests incl negatives, workspace 656 green; conformance row to partial honestly, producer rows stay todo, NO discharge funnel exists in src); PR #570 (UMA gating intersects the ENTIRE resulting RPT incl carried-forward permissions + introspection filtering of pre-transition RPTs, request_denied carrying authority_contained, active never flipped; harness gets INFORMATIVE containment-interaction subsection only, ruling rejected the sketched MUST; discovery gets reciprocal MAY-consume pointer, tainted/routed_to_approval never protected events themselves); PR #568 (crosswalk in the substrate-hosted OAuth Binding Statement relating roles to claims without equating them, Delegation row = LGA/SA/MD/CB with act = attribution, ACC excluded (Statement never scopes it to delegated exchange), Cross-Domain maps to no claim; sync pointers not tripwires; architecture: seven->eight claims + ACC, direct-only bases wording, Protocol core = the OAuth realization of Baseline Issuance); PR #571 (mandate consumption-only table, IV premise corrected: MAS/UMA supply IV via their own mechanisms not Mandate; expiry Conformance preserving SHOULD strength; txn-authz continuity paragraph per ruling (idempotency identity NOT on the token) + Continuation informative ref + missing substrate dep fixed; approval-revision/AGR Option A reciprocal notes, no interim AGR; authority-server heading -> Mission Authority Server Metadata, anchor kept; placement moves DROPPED per ruling); PR #567 (counts deleted from prose, conceptual-view diagram caption + five placements per ruling, durable naming rules incl aauth-mission-* vs mission-aauth-* direction rule; NO SPEC_VERSIONS row, ruling: DeferralStore is AROP/DTR narrowing not deferred initial Mission creation, an Implemented row would overclaim); PR #566 (core, authorized by #424 ruling course (a): floor MUST reworked, published statement = normative home with explicit deployment scope, conjunction with controls.acr, no global acr ordering, Deployment Profile named informatively, no new wire surface; #424 stays parked with the Substrate Statement as the future starting point, parked #281 would need redesign not rebase). Merge order: #569 before #570 (UMA cites the term's home; one-line retarget flagged in #570); others independent. All seven MERGEABLE, CI scheduled (the CONFLICTING-PR zero-runs gotcha checked). Follow-ups noted on issues, not fixed: authzen.md:488 + runtime.md:1418 restate the effective-set formula attributing solely to Containment (#562 comment); approval-governance.md missing substrate dep, txn-authz missing approval-governance dep, mandate three-hosting-bindings enumeration vs UMA Statement tension (#564 comment). Process: seven parallel worktree agents, commit-only (no agent push/merge per guardrail), diffs verified centrally before push; one silent git-push failure caught by remote-ref verification and retried (#567's branch). |
| D93 | Review round on the D92 PR set: #566 merged as written, six corrected per review, all seven MERGED; issues #561-#565 closed, #424 stays parked | Reviewer verdicts: only #566 clean; blocking interop/behavior defects in #572 and #570; targeted corrections required in #569/#568/#571/#567. Corrections applied and merged in the ruled order (#569 before #570; others independent): #572 (23a2784) authority_changed now keys on ACTUAL narrowing, an explicit authorityChanged argument into emitCommit computed as a strict-subset test reusing contain()'s priorEffective/newEffective (reverse-subset equality trick; contain() sole true-passer), covering the already-contained fresh-event_id defect at kernel and wire level with assertions empirically verified red against the old prior===state inference; the forever-latch gains markRematerialized(missionId, {version, containment_version?}) with high-water-marker semantics, fail-closed on omitted/stale baseline fields, post-ack narrowing re-raises; 6 new tests, workspace 662 green, conformance row honestly stays partial (Status refetch still unwired by any consumer). #570 (c3dcad3) UMA intersection reworked to SCOPE GRAIN (remove contained scopes per permission, omit only when no scope survives, refuse all-contained with error=request_denied + mission_denial_reason=authority_contained, the named registered carrier); RFC 7662 top-level active MUST stay true while the RPT is otherwise active even with zero surviving permissions; Discovery MAY lowercased informative + containment added to discovery deps; Effective Authority Set cited from Status per the relocation; deliberate binding-level tightening flagged in-PR: mission_denial_reason carriage MUST here vs containment.md token-endpoint MAY. #569 (f5977e0) runtime's Authority decision input consumes Status's Effective Authority Set directly (no-narrowing deployment = approved set; discharge and Containment each subtract when deployed), discharge exclusion scoped to establishability from the Mission state source so runtime's definitional MUST does not escalate status.md's SHOULD; authzen provenance corrected to Status + adjacent fail-open phrase scoped to the specific member's subtraction. #568 (77eb14b) ACC added to the Delegation row (Token Exchange issuing the delegated credential IS a grant binding at issuance: AS joins Mission+Subject from subject_token, delegate identity from actor_token/client auth, bound to the new credential; five claims exercised not created; act stays attribution never authority; knock-on: Cross-Domain's dangling same-four backref fixed); architecture artifact-plane pointer now names core as the invariant's normative home, Work Products as the carriage/handoff profile. #571 (82d2b2b) both evidence artifacts conditional (no AGR for interim revision_required; where an AGR/Consent Evidence is recorded, it owns its facts/history); mandate: UMA realizes the OAuth issuance host for Mandate purposes (same keys via same jwks_uri, no fourth host), Portable Evidence row cites all three Statements naming Mandate (OAuth/substrate-hosted, MAS, UMA; AAuth's not yet). #567 (0e40f88) README naming universal replaced with a positive conditional keyed on defined-against-substrate-primitives (spot-checked both sides; avoided a new false negative-universal the first draft introduced). Post-merge main verified: family-manifest OK 40/no drift; conformance-manifest OK 92 requirements (22 tested, 6 partial, 64 todo); issues #561-#565 CLOSED, #424 OPEN parked per ruling; zero feat/* branches left on remote. Ops notes: GitHub mergeability reads UNKNOWN transiently right after an upstream merge (hit on #570 and #572, resolved by re-poll); ssh-agent went empty mid-session, pull fell back to the HTTPS remote URL (known gotcha); watch-and-merge chains ran as background jobs gated on checks + the 569-before-570 order. |
| D94 | Critique cycle filed and sketched: issues #574-#579 opened with full solution sketches, input comments on #220/#288; awaiting rulings | The 2026-08-17 design critique (five adversarial lenses over merged main; six theses) converted to actionable form. New issues, each carrying a verified Sketch-and-tradeoffs comment with options, recommendation, blast radius, and open questions: #574 composed kill-switch reality (architecture rung x binding x what-stops table with the Baseline/Runtime-Enforced property-vs-level name-collision disambiguated; recommended containment-conditioned read-posture tightening in runtime, active only while the overlay is nonzero, honestly scoped as narrowing not closing the Baseline residual; README half-step footnote); #575 policy-authority approval bounds (discovery: AGR policy assertions carry NO human-approval timestamp, decided_at is the assertion instant, so recommend authority.approved_at + deployment-declared max age per consequence class, companion-only; consequence-class rule anchors core's four high-risk classes via consent-evidence's citation pattern, human-by-default with a declared staleness-bounded exception valve; split-honesty passage in architecture's Capability Envelope; surfaced companion gap: core approval_basis template/policy_drawdown have the same missing-timestamp shape); #576 widening with live children (steelmanned both rules: cascade protects child basis integrity, drawdown-block protects the disclosure event; re-parenting foreclosed by parent/lineage immutability + #547 precedent; recommended Child Mission Carryover, batched issuer-internal make-before-break re-derivation riding the expansion approval event, per-child strict-subset + justifying-entry + depth re-checks, new expansion_carryover approval_basis, related_to lineage reuse, atomic with successor activation; drawdown path stays blocked and priced, carryover composes with its full-approval fallback; residual stated: per-worker credential handoff remains); #577 cross-plane AND-join (three-conjunct rule, conjunct 3 keyed on core's own requires_action_approval Common Constraint so no optional-profile import; normative paragraph in runtime {{decision}} + scope note beside status's term + one-sentence echoes in architecture/metering/txn-authz; surfaced gap: runtime action-approval rule 1 does not trigger on the entry's own constraint despite core's self-executing wording); #578 issuer custody/isolation/forgery (premise NARROWED: custody obligations already exist in prose at oauth-mission:4567/authority-server:2225/security-model:1192, the gap is nothing reads them; claims-axis entry rejected on the axis's own proof-obligation invariant; recommend key_custody block in the Deployment Profile illustrative shape keyed by security-model's five key classes + one voids-the-model forward reference; external ai-agent-instance draft live-verified to define NO isolation vocabulary so the EAT MUST is re-pointed at runtime's own named conditions, compromise-resistant four + trifecta three; work-products gains a compromised-harness forgery residual paragraph, detect-not-prevent); #579 differentiation head-to-head (upgraded finding: core:344-385 already compares piecewise, the gap is the COMPOSED RAR+short-tokens+stateful-PDP stack; five crossover criteria each citing an existing architecture section; RAR leg generalized to structured-consent-input so the #220 tier is not insulted; home: architecture Deployment Patterns subsection + README two-sentence pointer; #238 convergence framing: past crossovers 1 and 4 the bespoke PDP grows this family's shape anyway). Input comments: #220 leading-indicator unpark trigger (periodic IdP RAR survey); #288 riskiest-untested-claims list (status 0/21, txn-authz 0/20 incl. linearizable + fail-closed rows; single-process impl cannot discharge them; unsummed per-action bill). Two agent-report deliveries needed recovery (one resumed via message for verbatim text, one read from its scratch file). All six sketches are companion-side except flagged optional core unifications in #575; #424 remains parked and un-argued-with throughout. Awaiting rulings before any PR. |
| D95 | Critique-cycle rulings applied: PRs #581-#586 opened for #574-#579; #580 filed; nothing merged | All six rulings (2026-08-18) implemented by parallel worktree agents, commit-only, pushed and PR'd centrally. #581 (#576, Refs not Closes per ruling): interaction + priced-limitation prose ONLY in expansion/progressive/child-delegation; Child Mission Carryover NOT greenlit, stays open on the issue under six acceptance criteria (subtree snapshot commitment, generation-by-generation re-derivation, no narrowing/state/expiry/budget resets, no standing-consent approval_basis (model as batched child-specific direct approvals), record-atomicity vs worker-continuity separation, partial-result + evidence semantics). #583 (#574, Closes): architecture Composed Kill-Switch Reality table at the 2418 seam (rung-vs-property disambiguation, Containment-scoped, ruling-corrected residual cells: pre-transition projection grants + attenuation roots run to own bounds, issuance grant redeems once to 300s max where redemption-time check absent, MAS residual to native bounds if any, Runtime-Enforced property keyed on containment-AWARE source per class); runtime post-taint read posture MUST name a containment-aware source (Status/introspection w/ containment_version, Signals, fresh derivation; Status List bit does NOT move), affected-class trigger w/ any-overlay as labeled conservative default, duration = remainder of Mission, ESS-declared under-containment bound, containment-response-target NOT made normative; containment pointer + README half-step footnote; Baseline residual explicitly not closed. #585 (#575, Closes): approval-governance authority.approved_at (REQUIRED, exact policy version, verified from retained authenticated governance state) + Policy-Approval Recency section (strictest ceiling across whole derived set, age at evaluated_at, approved_at<=decided_at<=evaluated_at under committed skew allowance, future timestamps rejected, ceiling/exception committed in approval_policy snapshot for re-runnable evaluation, issuance-time only, human-by-default for core's four high-risk classes with committed class-named exception valve, optional-profile scope honesty); architecture split-honesty passage revised per ruling ('does not require re-rendering' not 'never', materialized credentials to own bound, 'this and only this' dropped); #580 FILED (core standing-consent approval_basis template/policy_drawdown human-approval instant, blocked-shaped on #575 semantics). #584 (#577, Closes): runtime composition paragraph in ruling's non-exhaustive shape ('in addition to every other required decision input'; applicable-bound framing preserving fail-closed; exclusivity latch = stateful operational gate); rule-1 trigger fixed to fire on the applicable entry's requires_action_approval:true, fail-closed absent mechanism; status one-line necessary-never-sufficient scope note; txn-authz offline step 5 requires CURRENT Effective Authority Set within freshness bound (active-before-narrowing insufficient; token transports bounded approval, substitutes for nothing) + new conformance row txn-authorization.verification.current-effective-authority-set todo (93 requirements); architecture one pointer; metering untouched. #586 (#578, Refs not Closes): key_custody as illustrative LIST keyed by key class + kid_selector (two issuer_signing entries under distinct kids per core segmentation; software/hsm_or_kms example values, no frozen enum; declaration-only stated); security-model locative pointer after 'voids the model'; runtime EAT MUST replaced by 8-row per-condition evidence map fully grounded (3 EAT rows, 5 non-EAT), unknown/stale/unverifiable => claim unavailable, EAT-alone misrepresentation prohibited; work-products compromised-mediator residual with conditional detection only (no missing-activity-exposes-forgery promise). #582 (#579, Closes): architecture Comparison to a Conventional Stack after Entry Ramps (accurate steelman: RFC9396 = structured data not fidelity; short lifetimes bound revocation only if every issuance path re-evaluates; AuthZEN = decision API), five crossovers as conventional-realization-vs-Mission-standardization pairs, 4-column table with added-Mission-cost column, ruling's convergence conclusion near-verbatim, impossibility phrasings verified absent; one README pointer link. All six PRs MERGEABLE; architecture.md is touched by five PRs at five distinct seams (~609/~1811/~2020/~2418/~2476) and runtime.md by three (~867+1370/~1758/~2542): merge sequentially with mergeability re-checks between (transient UNKNOWN after each upstream merge, seen in D93). Issues #574/#575/#577/#579 close on merge; #576/#578 stay open by ruling; #580 open. Nothing merged; awaiting review. |
| D96 | Review round on PRs #581-#586: all corrections applied and ALL SIX MERGED; #589 filed; issues settled per rulings | Reviewer requested changes on all six; corrections applied per-branch by parallel worktree agents and merged with per-PR watch-and-merge chains (mergeability re-polls handled the transient-UNKNOWN class from D93). #582/#579 (c829aa8): monotonic-subset enumeration corrected to issuance/delegation/attenuation/cross-domain projections (verbatim match to the Authority-only-narrows invariant; widening stays owned by the invariants section); cost column renamed Illustrative. #581/#576 (66df9f3): no guaranteed-human-witnessing claims (modal where-the-deployment-provides-the-notice form in all three docs; one deliberate out-of-diff hunk fixed the SAME pre-existing overclaim three lines above in progressive.md, flagged in-PR); stale-child bound corrected to Cascade Failure's exact earlier-of-exp-and-runtime-staleness-bound wording. #583/#574 (5aa052d): fresh derivation reclassified Baseline not Runtime-Enforced (containment's own definitions: Baseline cites Derivation Gating; RE lists only Status/introspection/PDP), stated identically in architecture + runtime; issuance-join row rebuilt around containment-aware derivation (Baseline attributed to Derivation Gating at minting; refresh removed from stops-at-commit as active-only; residual = outstanding grant redeems once to its 300s max at any AS whose redemption check is active-only); conclusion scoped to paths/classes no containment-aware action-time gate reaches, binding determines artifact+cutoff. #584/#577 (700499b): Status List demoted to lifecycle prefilter (MAY, MUST NOT alone satisfy step 5; two-bit state observes neither containment nor discharge, verified vs containment stays-active + status reliance-bits-only); sufficient sources = full audience-scoped Status response, containment/discharge-aware introspection, or equivalent authenticated versioned source reflecting every authority_changed update; conformance row + observation synced; Signals informative ref added. #585/#575 (6af169a): classifier widened to the whole committed Mission, derived Authority Set classes PLUS Mission Intent controls consumption bounds (metering cited informatively per core's own precedent; manifest dep added), applied at strictest-ceiling, human-by-default, and Recording Issuer bullets; Relying Auditor bullet flagged observed-not-touched. #586/#578 (35984ce): least_exposure row added (context-scoping half of the trifecta private-data leg; signed configuration + negative tests producer; credential half already evidenced by custody/isolation rows) + negative-conformance row; EAT rows made a proof contract (ESS MUST select claim/profile ids, reference values, appraisal policy, attester identity, nonce/timestamp/session freshness per row; absent selection the token is declaration not proof, claim unavailable); harness dep added to work-products. NEW ISSUE #589 (from #583 verification, out of scope there): issuance-grant refresh gate is active-only and never re-derives against the current Effective Authority Set, so a refresh chain on a contained-but-active Mission renews ORIGINAL uncontained authority to Mission expires_at, far exceeding the 300s grant-window residual; candidate fix mirrors #584's source discipline at refresh, or explicit residual disclosure. End state: #574/#575/#577/#579 CLOSED by merges; #576 (Carryover design, six acceptance criteria) and #578 (custody until a normative verifier reads the declaration) OPEN by ruling; #580, #589 OPEN. Post-merge main: both manifest validators pass at 41 drafts (a 41st draft, draft-mcguinness-mission-gnap, landed from a PARALLEL SESSION mid-cycle, the D91 collision class again, absorbed cleanly by the manifest); zero feat/* branches left; per-PR builds + pre-merge CI green, main editor's-copy CI run in progress at close. Ops note: local make of the hot drafts fails post-pull on a Bundler-4 lockfile requirement in the UNTRACKED lib/Gemfile.lock (local env only, not content; worktree builds and CI were green); if it persists, refresh the local-build-toolchain note. |
| D97 | #540 PR B shipped: Mission Transaction Authorization implementation merged (PR #573) after two review rounds; #588 filed; #540 closed | The implementation PR carried the 20-row txn-authorization block from spike replacement to merge through two request-changes rounds, all corrections applied on the PR before merge. Round 1 (six findings + two hardenings): the transaction token became the SOLE OAuth credential for the challenged request (Authorization: DPoP per upstream 6.1; the RS branches on header typ, derives TokenFacts from the token's own claims against the RETAINED pending operation, refuses it on read/write tools; both MCP transports route the branching validator; e2e over real HTTP MCP), admission reserved before the ARS opens an approval (idempotent issuer-scoped task id), upstream wire members (authorization_details response parameter, Accept-Txn-Challenge gate, metadata gated on configuration), subject_token class pinned to at+jwt + DPoP iat window + client-assertion exp, resource-scoped txn keys across TAS/ARS/RS, mint-before-atomic-reserve-and-record (no wedged slot), operation-profile-drift honestly partial. Round 2 (six P1 + two P2): approval bound to the COMPLETE transaction via TxnApprovalBinding + binding digest recomputed at completion (bundled ARS fails closed on same-(resource,txn) different-binding opens; CLOCK_SKEW_S=30, future approved_at and inverted validity refused); ONE RFC 9449 verifier for both RS token classes (public-only jwk, alg allowlist, htu/htm, iat both directions, ath over the presented credential, jti replay consumed last; PoP REQUIRED for transaction credentials, in-process transport structurally excluded, exhibit walk moved to HTTP MCP with ath); authoritative subject-credential liveness at admission AND completion (tokenIssuanceStore.resolve -> isGrantLive, jti pinned on the workflow) with completionChecks factored into one helper run twice, the second pass a post-decision fence immediately before mint with exp recomputed; transaction sub = the DESTINATION-LOCAL subject with the issuer-qualified origin principal alongside in mission.subject and both identities in the binding + FreshDecisionInput (principalOf deleted; paired spec correction FILED as #588 including the identity-projection row text); Operation Profile registry per (issuer, type) with forAdmission/forPinned/supersede (mission_resource_access requires exactly one concrete action; unknown type refuses; reason never authorization input; superseded versions resolve for pinned workflows only); mission-claim wire shape conformed to core (RFC 3339 OPTIONAL expires_at, optional approval_basis; MissionKernel.missionClaim projection fixed from epoch seconds; deliberate widening: invariants-only claims, exactly what cross-org mints, now parse and can reach the challenge path, the intended pair to the sub fix); RFC 8941 Boolean-item parse (?1 with parameters accepts, ?0/malformed refuse) + form-encoding required + duplicate security-parameter rejection + 64 KiB body cap; expiry checked BEFORE serving stored issuance (expired_token, clamp removed) + durable consumption state {resource, txn, op_key, consumed|effect_committed} on the shared store with crash-window RESUME via the idempotent connector under the same op_key (different op_key or effect_committed refuse; exactly-once inside the resume window rests on connector idempotency by op_key, stated premise). Manifest end state: 14 of 20 rows tested, 6 partial (five held partial by reviewer instruction pending confirmation of the landed negative vectors + drift), the 21st row born on main via #584 (verification.current-effective-authority-set) stays todo and is adjacent to #589. Gate at merge: 816/816 tests 0 skipped (74 files) with OpenFGA live, both manifest validators OK (93 requirements: 36 tested/12 partial/45 todo), exhibit green, all CI checks green; branch merged with main twice mid-flight (through D93 then D96) conflict-free. Open after merge: #588; the five held-partial rows; flagged not changed: validateAttenuationChain keeps its own inline proof discipline (third token class, no ath) and mcp-saas keeps its own validator. Ops note: three subagent infra failures (529/stream stalls) were resumed mid-stream without losing commits; one fix (poll-race on the issuing workflow) was authored directly after review of the store contract. |
| D98 | Adoption optimization: plan of record shipped as PR #590 (notes/adoption-plan.md, v3) after two review rounds; artifact plan mirrors it | Cycle: adoption critique question -> detailed exploration (4 parallel agents: shelf/zone map for all 41 drafts, reader-edition build prototype (nav injection into xml2rfc's empty external-metadata div; true inlining disqualified: 242 colliding ids between two docs; kramdown merge = semantic surgery over 18,771 lines), baseline scope vs #220/#238/#253, consolidation measurement) -> v1 plan -> author review 1 (floor not dependency-closed; RAR-free = protocol design not packaging; bundle-level conformance; zones not shelves) -> v2 + independent fidelity/executability verification (13 findings fixed incl. presentation_zone forced by counterexamples, GHPAGES_EXTRA cannot carry versioned bundles on default branch, Bundler failure is contributor-machine-only) -> author review 2 (five execution details) -> v3 plan of record. Key rulings encoded: OAuth Implementation Floor = 6 normative docs (substrate included; it is a normative dep of runtime/runtime-evidence/authzen) + architecture preface; bundle named OAuth Mission Runtime Baseline v0 with OAuth Mission Issuance Baseline / Runtime-Enforced Baseline levels (tier numbering retired); RAR-free excluded behind #220 as oauth-rar/oauth-scope-reference alternate modes; single-snapshot pinning (one source_repository_commit; external pins repo+commit+path+digest; publisher refuses byte-different overwrite, serializes publications, verifies against manifest); conformance gate = all six floor docs inventoried (today 13 tested/5 partial/35 todo + runtime/authzen/substrate uninventoried) + coverage threshold (zero uninventoried, zero todo on authorization invariants/fail-closed, positive+negative per surface, composition tests over the bundle); freeze policy machine-enumerated human-enforced (five classes incl. active-experimental earned by implementation evidence: txn-authz 14/6/1, cross-org 9/9 via PR #573; required frozen-change check, label-AND-CODEOWNER bypass, branch protection with the PLAN.md direct-commit tension FLAGGED for ruling); reader editions per-edition copies + explicit make reader-editions step on PR and push; no consolidation before WG adoption; aauth-mission-expiry upstream-first. Dispositions: items 1/2/3/4/10 approved, 5/9 hold-lifted on confirmation, 6 expanded, 7 held, 8 deferred. PR #590 adds the note only; execution follows as separate PRs. NOTE: this D98 entry itself is a direct-to-main commit of the exact kind item 9's branch-protection ruling would end; the tension is recorded in the plan. |
| D99 | Adoption plan of record MERGED (PR #590, notes/adoption-plan.md v5) after four author review rounds and two fresh-eyes critique cycles | Version arc on the PR branch: v3 (initial note) -> v3.1 (verb spine preserved as the semantic signature; zones = adoption-map overlay, catalog untouched) -> v3.2 (AAuth Mission Context Bundle from derived closure: coherence-not-composition, upstream pin as the substance of frozen-until-upstream) -> v3.3 (composition-axis tracks) -> v3.4 (third review: Mission-components portability conditional + checkable, presentation_track, Architectural-group column, substrate in the AAuth gate) -> v4 (fresh-eyes rewrite: plan-as-fact, ship-first waves, success measure) -> v4.1 (self-critique applied: third resequencing flagged, table-prose contradictions repaired, Ship 3 made startable, Ship 1 split, trigger tripwires) -> v5 (fourth review: PROFILE MATRIX separating bundle contents from the two conformance slices, product renamed OAuth Mission Baseline Bundle, Issuance slice = core alone; v0 RESERVED for the gated publication with v0-preview.1 shipping in Ship 3 TOGETHER with the machine-readable bundle manifest; Ship-1 metadata reversal: presentation_zone/presentation_track land in wave 1b with exact-membership validation; the LEDGER wave restored (inventory runtime/authzen/substrate, prove runtime-evidence complete, missing pos/neg/composition tests, per-requirement profiles field); AAuth gate split (core bundle = substrate+binding+management; expiry gates only the add-on edition); operational triggers (freeze fires before merging the first externally-authored PR or granting write/triage access, extends CODEOWNERS; AAuth fires on src code); pinned bundles expose pinned-dependency URLs beside live copies; three-scenario scored success rubric; the guide replaces discovering/ordering/reconciling, never reading). All three resequencing flags settled (flag 3 by ruling, flags 1-2 accepted as refined). 'Zone' naming re-examined on request and kept: corpus grep shows zone appears once in 41 drafts (a time-zone mention) while level/tier/stage/group/area/track/path all collide; the container noun is near-invisible reader-facing (Start/Compose/Lab headings do the work). NEXT: execution waves per the merged plan: Ship 1a (notes/external-pins.md + policy record), 1b (vocabulary + adoption map + presentation fields + membership validation), 1c (expiry-framing fix + dep reconciliation, override window closes + maintenance enum), then reader editions, then v0-preview.1 + bundle manifest, then the Ledger issues. |

Defaults adopted (not separately asked; flag if wrong):

- pnpm workspace monorepo under `src/`; TypeScript everywhere; Node 22+.
- OpenFGA runs via docker compose in its in-memory storage mode; our PDP fronts it.
- Freshness per D29/D33: the Mission Status List backs the core-tier polled
  plane; introspection (mission projection) is the immediate check on
  irreversible actions; permit-within-bound covers external commitment; the
  per-mission signed Status operation remains the authoritative surface.
  Signals push is a stretch goal.
- All state is in-memory and reseeded on boot. Record-shaped stores use
  SQLite `:memory:` behind repository interfaces (decision D27); pure
  in-process structures elsewhere; OpenFGA memory storage.
- Web apps: React + Vite SPAs.

## 3. Architecture

Operationally the stack follows the handbook's control-plane reading: the
Mission AS is the control plane for delegated authority, holding desired
state (the approved task, its authority, its lifecycle); tokens, PEPs, and
the PDP are the data plane acting within it.

```
                 +-----------------+       +-----------------+
                 |  Approver App   |       |  Operator App   |
                 |  (React SPA)    |       |  (React SPA)    |
                 +---+--------+----+       +----+------------+
                     |        |                 |
        approvals,   |        | ARAP tasks      | fleet, status,
        consent UI   |        |                 | evidence timeline
                     v        v                 v
+----------+    +---------------+    +---------------+    +----------------+
|  Agent   |    |  Mission AS   |    |     ARS       |    |      PDP       |
| Console  |    | node-oidc-    |<-->| ARAP Access   |<-->| AuthZEN API    |
| (SPA) +  |    | provider +    |    | Request Svc   |    | + contextual   |
| scenario |    | mission layer |    +---------------+    | policy view    |
| runner / |    +-------+-------+                         +-------+--------+
| LLM loop |            ^                                         |
+----+-----+            | catalog, PAR intent, code+DPoP,          v
     |                  | token exchange, DTR, txn-authz    +-------------+
     v                  |                                   |   OpenFGA   |
+---------+   MCP tools |  401 + signed txn challenge       | (in-memory) |
|  Agent  +-------------+--------------------------+        +-------------+
| (openid-|                                        |
| client, |    +-----------------------------------v-+
|  DPoP)  +--->|  MCP Payments Server (RS + PEP)      |
+---------+    |  tools, token validation, per-action |
               |  PDP calls, permits/leases, evidence |
               +--------------------------------------+
```

Not shown above: the **Transparency Service** every trusted-base component
registers evidence with; the telemetry plane (OTel collector view in Jaeger);
and the **SaaS trust domain** (RAS + LedgerCloud MCP server) the agent reaches
by redeeming a Mission-AS-issued ID-JAG at the RAS.

Trusted-base components and their spec roles:

- **Mission AS** (`services/authorization-server`): Mission Issuer. Owns intent intake
  (PAR), derivation to `mission_resource_access` authorization_details, the approval
  event, Mission Records with integrity anchors, mission-bound token issuance (DPoP),
  the subset rule, state-gated issuance/refresh, revocation by `mission_id`,
  introspection with the `mission` member, the signed Status endpoint (and
  the Mission Status List token, republished on each lifecycle transition
  per D33), the DTR
  deferred grant, and the `transaction_authorization_endpoint`. Also hosts the
  Catalog Provider role of `svc-connectivity-disco`: the Service Catalog
  Endpoint, advertised as `service_catalog_endpoint` in its own metadata,
  serving the per-user catalog with mission-derived per-connection `status`
  and `request-access` links into the ARS. As the enterprise IdP of the
  cross-domain companion, it also issues the cross-domain grant: an RFC 8693
  token exchange mints the PoP-bound, single-use ID-JAG audienced to the RAS,
  projecting only the audience-scoped Authority Set entries. Implements the
  base actor profile at issuance (nested `act` with required `act.iss`, chain
  construction/validation, local max depth, presenter continuation/rebind,
  rejection of any `actor_token` carrying `act`, `actor_unauthorized`) and
  the agent-instance profile (Client Instance Assertion carrier validation,
  `agent_instance_id` requirements, `sub_profile` of `ai_agent
  client_instance`, `ai_agent_instance_profile_supported` metadata). The
  operator app's fleet surfaces (enumeration, per-mission lifecycle
  operations) are served per the management companion (partial; O-32).
  Structured per D30: a mission-kernel module behind a typed interface,
  with node-oidc-provider hooks and the custom HTTP routes as thin
  adapters over it.
- **PDP** (`services/pdp`): AuthZEN Access Evaluation (and bulk Evaluations) API.
  Checks mission authority by deriving **contextual tuples** from the Mission
  Record per evaluation (decision D26; stored FGA tuples hold only the durable
  domain substrate), correlated by a content-addressed `policy_view_id`;
  layers the mission overlay checks
  that FGA does not model (state freshness against the staleness bound,
  parameter binding, permit property declaration, expiry), and emits
  requestable denials with
  `context.access_request` and a PDP-signed `binding_token`. Stateless by
  design (decision D28): a pure function of its inputs; permit redemption
  and lease state live at the PEP, and the freshness cache is a soft
  optimization that never changes decision semantics. Validates the shape
  and consistency of the `context.actor` chain the PEP supplies (root vs
  `subject`, leaf vs `client_instance_id`) via `packages/actor-chain`; the
  flattening itself is PEP-side (decision D31).
- **ARS** (`services/access-request`): ARAP Access Request Service. Verifies
  `binding_token` denial bindings, runs the approval task lifecycle, exposes the
  adjudication queue the approver app consumes.
- **MCP Payments Server** (`services/mcp-payments`): the resource server and PEP.
  Streamable-HTTP MCP server exposing the AP tools; validates DPoP-bound access
  tokens and the `mission` claim; constructs the AuthZEN envelope, including
  flattening the token's nested `act` chain into the root-to-leaf
  `context.actor.act` array via `packages/actor-chain` (decision D31);
  obtains a PDP permit for every consequential
  action with parameter binding and capability source context; runs the
  transaction-assurance tier for the wire transfer (single-use permit, execution
  lease, Execution Evidence, outcome reconciliation), owning permit
  redemption, lease state, and the irreversible-operation state machine per
  D28/D36 (atomic redeem-on-execute; replay refused as `permit_consumed`;
  connector idempotency keys; per-boot instance epoch bound into permits per
  D39). Authoritative for business state per D34: loads invoice/vendor
  records, builds effective parameters carrying resource versions for the
  PDP, and conditionally re-verifies them at commit; signs Transaction
  Authorization Challenges; publishes its MCP Server Card (the catalog
  references it via `server_card_uri`) and RFC 9728 protected resource
  metadata with `mission_bound_authorization_required`, plus its Enforcement
  Scope Statement. Validates proof of possession against the top-level `cnf`
  only (decision D21) and applies per-instance controls keyed on
  `(act.iss, act.sub)`. Returns a mission-scoped `tools/list` (least exposure
  at the tool boundary: the agent only sees tools within the mission's
  authority).
- **RAS + SaaS MCP Server** (`services/ras`, `services/mcp-saas`): the SaaS
  trust domain, "LedgerCloud" (accounting SaaS). The RAS is a second
  node-oidc-provider instance whose custom RFC 7523 JWT-bearer grant redeems
  ID-JAGs per the cross-domain companion: signature against the Mission AS
  JWKS, audience, proof-of-possession, and a single-use replay check, then
  mints short-lived local access tokens preserving `mission.id`,
  `mission.issuer`, and `authority_hash`. The SaaS MCP server (vendor bank
  details, journal entry posting) declares the MCP EMA extension in its
  authorization metadata and enforces from the token alone (including a
  `tools/list` filtered to the token's granted authority): the estate runs
  at lifetime-bounded reliance, in deliberate contrast with the
  Runtime-Enforced internal estate.
- **Transparency Service** (`services/transparency`): the audit draft's SCITT
  Transparency Service, in memory: append-only Merkle log, COSE Signed
  Statements committed by hash envelope, Receipts and signed tree heads,
  per-mission feeds (`sub` is the Mission). The log holds commitments only;
  producers retain their own evidence and Receipts (decision D32). The AS,
  PDP, and MCP server register their evidence; a CLI verifier and the
  operator app run the draft's five-step verification, and from M11 the
  operator timeline's normal read path is the verified feed itself.
- **Agent** (`services/agent`): OAuth client built on panva `openid-client`
  (PAR + DPoP + token exchange), MCP client, scripted scenario runner, optional
  LLM loop. Declares the MCP EMA extension capability
  (`io.modelcontextprotocol/enterprise-managed-authorization`) at `initialize`
  and drives the ID-JAG acquisition/redemption for the SaaS domain. Each
  agent instance holds a per-instance key and presents Client Instance
  Assertion evidence (`agent_instance_id`, `agent_platform`, `agent_model`);
  sub-agent spawn is a further token exchange presenting the sub-agent's own
  evidence as the `actor_token`. Hosts the shaper module (intent proposals
  are untrusted input per the shaping draft) and the minimal harness duty:
  on resume it checks mission Status and stops on a non-active state before
  attempting any action. Acts as the Agent Console's BFF and exclusively
  owns the OAuth, DPoP, and client keys (decision D35).
- **Console BFF** (`services/console-bff`): owns approver/operator browser
  sessions (HttpOnly SameSite cookies), fronts the AS management surfaces
  and the ARS queue, and hosts the feed-driven audit read model behind the
  operator timeline: joins across producers, orphan detection, and
  sequence-gap checks per `(Mission, emitter)` (decisions D32/D35).
- **Apps** (`apps/approver`, `apps/operator`, `apps/agent-console`): persona UIs.
  Browsers never hold service credentials.

Cross-cutting: every service adopts `packages/telemetry` (OpenTelemetry with
W3C trace context propagated across OAuth requests, PDP evaluations, MCP tool
calls, and evidence registrations, exported to Jaeger; pino structured logs
carrying `trace_id` and `mission_id`). Evidence objects carry the producing
span's `trace_id` as an extension member (decision D13).

Two demo-correctness facilities: (1) a **headless adjudication path**, a
test-only API to approve or deny as a seeded approver, drives approvals in
scenario and eval runs; it is clearly marked test-only, disabled outside
dev, and its use is visible in the evidence so evals cannot be fooled by
it. (2) The **side-effect oracle**: the payments ledger, the email outbox,
and the SaaS journal record every mutation together with the authorizing
permit or token identity, giving evals ground truth for "zero unauthorized
side effects".

### Demo domain model (accounts payable)

Seeded entities: principals `alice` (mission owner) and `bob` (approver / AP manager);
OAuth client `ap-agent` (DPoP-bound); vendors `acme` (approved) and `globex`
(not yet approved); invoices in several amounts, at least one above the mission's
payment cap; a payments ledger for reconciliation. The catalog seeds three
services: the internal payments MCP server, the LedgerCloud SaaS MCP server
(an `id_jag` connection naming the RAS as `authorization_server`), and an
out-of-reach `hr-files` service (no authority path for `alice`) whose entry
carries a `request-access` link into the ARS.

Tools on the MCP server (action classification per runtime § action classification floor):

| Tool | Class | Enforcement tier |
|---|---|---|
| `list_invoices`, `get_invoice`, `lookup_vendor` | read | core tier |
| `schedule_payment` | consequential, reversible | core tier |
| `execute_wire_transfer` | high-consequence, irreversible | transaction-assurance tier |
| `send_remittance_email` | external communication | transaction-assurance tier |
| `get_vendor_bank_details` (SaaS) | read | token-only (lifetime-bounded estate) |
| `post_journal_entry` (SaaS) | consequential, reversible | token-only (lifetime-bounded estate) |

### OpenFGA model sketch

Types: `user`, `client`, `mission`, `vendor`, `invoice`, `payment_batch`.
Stored tuples hold only the durable domain substrate (invoice ownership,
vendor approval state, roles such as Bob's AP manager). Mission authority is
injected per check as **contextual tuples** derived from the Mission
Record's `authority_set` (for example `mission:m1#payer@invoice:inv-42`),
computed by the PDP alongside the state/freshness check it already performs
(decision D26). There is no tuple writer keyed to mission lifecycle and no
dual-write: revocation and completion take effect through the record itself
(state check precedes FGA). `policy_view_id` is the content hash of the
Mission Record version plus the FGA model version. Numeric constraints
(per-payment cap, cumulative caps) are evaluated with FGA conditions where
they fit and in the PDP overlay where they do not; see issue O-6.

### End-to-end scenarios (the demo script)

0. **Discovery bootstrap**: agent signs in, reads `service_catalog_endpoint`
   from the AS metadata, makes a scoped catalog request (`type=mcp` plus a
   category/tag filter), selects the payments server, re-anchors trust via the
   server's protected resource metadata, and reads its Server Card before
   shaping intent. With no mission yet, the connection reports
   `consent_required`.
1. **Issuance**: the shaper proposes intent (untrusted input per the shaping
   draft), the agent submits it via PAR, the issuer derives the authority,
   and Bob, the AP manager, approves in the approver app (intent + authority
   set + anchors rendered): the mission carries writes, so subject and
   approver must differ per D37, with Alice as the mission's subject.
   Mission-bound DPoP token issued; operator app shows the new Mission.
   Includes the compromised-shaper test: an over-broad proposal never widens
   the derived authority.
2. **Happy path**: agent pays an in-authority invoice under the cap; per-action
   PDP permits; Decision + Execution Evidence visible in the operator timeline.
3. **Parameter binding / TOCTOU**: scenario mutates payment params between
   decision and execution; digest mismatch, PEP refuses, Refusal Record logged.
4. **Wire transfer**: transaction-assurance tier end to end: single-use permit,
   execution lease, execution, outcome reconciliation against the ledger.
5. **ARAP reevaluate**: `action_approval_required` denial at the PEP; access
   request to ARS; Bob adjudicates; PEP re-evaluates with `context.approval`;
   action proceeds. No new token issued.
6. **AROP / DTR**: agent requests authority for vendor `globex` at the token
   endpoint with `completion_mode=deferred`; requestable denial; `deferral_code`;
   Bob approves; AS records a Mission Expansion (successor mission) and issues
   the token carrying the successor's `mission` claim; PDP view updates.
7. **AROP / Transaction Challenge**: MCP server returns 401 with a signed
   `transaction_challenge` for an over-cap wire; agent presents it at the AS
   `transaction_authorization_endpoint`; approval; txn-bound audience-restricted
   single-use token; re-presented and honored exactly once.
8. **Revocation freshness**: operator revokes mid-mission; a wire transfer
   is denied instantly (immediate-check branch), while a read is denied
   within the published staleness bound (polled-cache branch); issuance and
   refresh are also gated. The two-tier contrast is the demo.
9. **Completion**: mission completes; residual tokens no longer authorize.
10. **Catalog reflection**: per-connection `status` tracks the fleet
    (`connected` while the mission is active, `unavailable` after revocation),
    and the out-of-reach service's `request-access` link opens an ARS intake
    that, once adjudicated, flips its status.
11. **Transparent audit**: evidence from the scenarios above is registered as
    Signed Statements; the operator assembles the mission's feed, runs the
    five-step offline verification, and follows a Decision Evidence record's
    `trace_id` into Jaeger; tampering with stored evidence or dropping a
    registered record is detected.
12. **Cross-domain via EMA/ID-JAG**: the catalog lists LedgerCloud with an
    `id_jag` connection; the agent declares the EMA extension at `initialize`,
    obtains a PoP-bound single-use ID-JAG from the Mission AS by token
    exchange (audience-scoped authority only), redeems it at the RAS for a
    short-lived local token preserving the mission anchors, and posts the
    journal entry for the executed wire. A replayed grant is rejected; after
    mission revocation the next grant request is refused at the issuer, and
    the residual local token dies with its lease (lifetime-bounded estate).
13. **Sub-agent delegation**: the orchestrator agent spawns a sub-agent for
    invoice triage; the token exchange presents the sub-agent's instance
    assertion as the `actor_token`, authority narrows to a subset, the
    token's nested `act` grows a hop while `sub` is preserved, the PDP
    evaluates the root-to-leaf chain, and revoking the sub-agent's instance
    at the PEP kills only the sub-agent (the orchestrator continues).
14. **The 02:00 resume**: while the agent idles, the mission completes (or is
    cancelled); on wake the agent's harness check reads Status, sees the
    non-active state, and stops before attempting any action; if the check
    is bypassed, the PEP denies and the Refusal Record is written (the
    handbook's running example, both fears closed).

### The five laws, enforced

The handbook's five laws map onto the build as follows; the M14
self-assessment walks this table.

| Law | Enforced by | Scenarios |
|---|---|---|
| Durability | the Mission Record outlives sessions and tokens; signed Status is the authoritative state | 1, 8, 9, 14 |
| Attribution | subject/approver on the record; `act` chains + instance identity; evidence that joins | 1, 11, 13 |
| Narrowing | subset rule, audience-scoped projection, caps, delegation narrows | 6, 7, 12, 13 |
| Termination | state-gated issuance, revocation, completion, freshness bounds, cross-domain lease expiry | 8, 9, 12, 14 |
| Containment | per-action PEP/PDP, parameter binding, single-use permits, per-instance revocation | 2, 3, 4, 13 |

## 4. Repo Layout

```
src/
  PLAN.md                     this document
  package.json                workspace root (scripts: dev, seed, test, demo)
  pnpm-workspace.yaml
  docker-compose.yml          OpenFGA (in-memory storage mode) + Jaeger
  .env.example                ports, issuer URL, optional ANTHROPIC_API_KEY
  packages/
    mission-core/             shared types (Mission Record, mission claim, AuthZEN
                              envelope, evidence objects), canonicalization +
                              intent_hash / authority_hash, core test vectors
    authzen-client/           PEP-side AuthZEN client (evaluation, bulk, retries)
    demo-data/                seed loaders: users, clients, vendors, invoices,
                              FGA store + model + tuples
    store/                    SQLite :memory: repositories (missions, approvals,
                              tasks, permits, oracles, catalog, evidence index)
    telemetry/                shared OTel + pino setup (trace context, ids)
    actor-chain/              act-chain validation + nested-to-root-to-leaf
                              flattening, shared by AS, PDP, and PEPs
  services/
    authorization-server/     mission-kernel module + thin adapters
                              (node-oidc-provider hooks, custom routes)
    pdp/                      AuthZEN PDP + OpenFGA integration
    access-request/           ARAP ARS
    mcp-payments/             MCP server + RS/PEP + payments API + ledger
    ras/                      SaaS-domain Resource AS (node-oidc-provider,
                              JWT-bearer ID-JAG redemption)
    mcp-saas/                 LedgerCloud SaaS MCP server (token-only
                              enforcement, EMA declared)
    transparency/             SCITT Transparency Service (audit draft)
    console-bff/              approver/operator sessions + audit read model
    agent/                    OAuth+MCP client, scenario runner, LLM loop
  apps/
    approver/                 approvals inbox (missions, ARAP tasks, deferred queue)
    operator/                 fleet dashboard, evidence timeline, status controls
    agent-console/            chat + scenario runner UI, live token/mission state
  evals/
    suites/                   adversarial + legitimate-flow eval cases
    runner/                   drives agent modes, scores runs, emits scorecards
```

Port map (defaults, overridable via `.env`): AS 4400, PDP 4401, ARS 4402,
MCP/payments 4403, transparency 4404, RAS 4405, SaaS MCP 4406, console-bff
4407, approver 5173, operator 5174, agent-console 5175, OpenFGA 8080 (http,
pre-shared auth + TLS) / 8081 (grpc), playground disabled, Jaeger 16686
(UI) / 4317 (OTLP).

### Testing and delivery

- Traceability: each scenario (0-14) is one named spec file with a stable
  ID, referenced from milestone exits (D40).
- Tests: vitest across the workspace. Unit tests per package (anchor vectors
  in `mission-core`); scenario tests compose all services **in-process**
  (everything is in-memory, so one Node process can host the full stack),
  with real HTTP reserved for wire-shape assertions (PAR, token endpoint,
  AuthZEN, MCP transport); golden files for PDP decisions and exhibits.
- CI: a dedicated GitHub Actions workflow gated on `src/**` path filters so
  the draft-build/publish CI and the implementation CI never interfere.
  Jobs: lint, typecheck, unit, scenario integration (OpenFGA service
  container), evals (from M13).
- Toolchain: Node and pnpm pinned via `engines` + corepack; lockfile
  committed. Dependency policy per D39: `oidc-provider` pinned to the first
  version that passes the pre-flight spike; the OpenFGA image pinned by
  digest; the MCP SDK and spec revision pinned (D38: stable 2025-11-25
  authorization profile).
- Spec traceability (D41): `src/SPEC_VERSIONS.md` is a matrix mapping every
  implemented spec to its pinned version, its implementing components, and
  its conformance tests; spec-derived code carries greppable
  `@spec <doc>#<section>` tags. A spec update becomes a change list by
  diffing the spec from its pinned version and following the touched
  sections through the matrix and tags. Goal 2 means companions will change
  during implementation; version bumps are deliberate, reviewed against the
  Spec Feedback Log, never implicit, and each bump commit names the
  affected modules and tests.

## 5. Milestones

Status (update this table as work lands):

| Milestone | Status |
|---|---|
| Pre-flight spike | **done** 2026-07-21 (PR #317, `src/spikes/SPIKE-REPORT.md`) |
| M0 Scaffolding + artifacts | **done** 2026-07-21 (PR #318) |
| M1 Baseline AS | **done** 2026-07-22 (PR #319) |
| M2 Actor + instance | **done** 2026-07-22 (PR #321) |
| M3 PDP + OpenFGA | **done** 2026-07-22 (PR #322) |
| M4 MCP core tier | **done** 2026-07-22 (PR #323) |
| M5 Transaction tier | **done** 2026-07-22 (PR #324) |
| M6 ARAP | **done** 2026-07-22 (PR #325) |
| M7 AROP | **done** 2026-07-22 (PR #326) |
| M8 Discovery | **done** 2026-07-22 (PR #327) |
| M9 Cross-domain | **done** 2026-07-22 (PR #328) |
| M10 Audit (SCITT) | **done** 2026-07-22 (PR #330) |
| M11 Full UX | **done** 2026-07-23 (PR #331) |
| M12 Agent + demos | **done** 2026-07-23 (PR #332) |
| M13 Evals | **done** 2026-07-23 (PR #333) |
| M14 Conformance + reports | **done** 2026-07-23 (PR #334) |

Definition of done, every milestone: tests green, the spec-feedback pass
done, this status table and the logs updated, the PR merged.

Each milestone lands as its own PR with tests; acceptance criteria are the exit
bar. Every milestone's exit also includes a **spec-feedback pass**: anything
found during the milestone that is ambiguous, disproportionately hard to
implement, over-complex, or non-interoperable lands in the Spec Feedback Log
(§ 8) with a category and disposition before the milestone closes.

Before M1 design hardens, a **pre-flight spike** burns down the pin-type
issues gating the early milestones: O-1 (PAR intent carriage), O-25
(CIA-CORE carriers), O-26 (entity-profile values), and O-27 (chain
depth/rebind) by reading; and O-2 (node-oidc-provider fit) as a timeboxed
coding spike with an explicit go/fallback decision (fallback: thin custom
endpoints beside the provider). Per D30, the go/fallback decision is scoped
to the AS's adapter layer only; the mission-kernel is unaffected either
way. Results land in the issue log and, where they expose spec friction,
in the Spec Feedback Log.

- **M0. Scaffolding.** Workspace, tsconfig, lint, docker-compose (OpenFGA +
  Jaeger), `packages/telemetry` (the OTel + pino baseline every service
  adopts), `packages/store` (the SQLite `:memory:` repository baseline,
  decision D27), `mission-core` with canonicalization + anchors passing the
  core test vectors (`draft-mcguinness-oauth-mission` § test vectors), and
  four architecture artifacts: `payments-runtime-profile-v1` (the Operation
  Profile, D34), the channel/auth/key matrix with the trusted-base
  statement (D39/D40), the approval and irreversible-operation state
  machines (D36/D37), and the FGA hygiene policy (D39). Also lands
  `src/LICENSE` (BSD-2-Clause) and the `license` fields (D40).
  *Exit: `pnpm test` green on anchor vectors; `docker compose up` serves
  OpenFGA (pre-shared auth + TLS) and Jaeger; a sample service's span is
  visible in Jaeger; the four artifacts reviewed and committed.*
- **M1. Baseline Issuance AS.** PAR intent intake, derivation, approval event
  (minimal approver page), Mission Record store, `mission` claim + DPoP binding,
  subset rule, state-gated issuance/refresh, revocation by `mission_id`,
  introspection `mission` member, signed Status endpoint, AS metadata flags.
  *Exit: core conformance checklist items 1-6 (core § Conformance) demonstrably met;
  scenario 1 runs headless, including the compromised-shaper test; a thin
  tracer slice (PAR intent -> approval -> token -> minimal PDP evaluation ->
  `get_invoice` through an MCP skeleton, wire-real but throwaway-grade) runs
  end to end before M2 begins, surfacing URI/token/evidence mismatches
  early.*
- **M2. Actor profile + agent instance.** Base actor-profile conformance at
  the AS (chain construction/validation, presenter transitions, local max
  depth, errors, metadata, introspection) with `packages/actor-chain` shared
  by AS, PDP, and PEPs; full ai-agent-instance profile (per-instance keys,
  Client Instance Assertion carrier validation, instance claims, metadata
  flags). Foundational: the PDP envelope, PEP controls, and agent identity
  in every later milestone consume these surfaces.
  *Exit: delegated issuance produces conformant chains in token-level
  integration tests, including rejection of an `actor_token` that itself
  carries `act` and the actor-chain flattening vectors; the end-to-end
  sub-agent demo (scenario 13) lands with M12.*
- **M3. PDP + OpenFGA.** AuthZEN evaluation + evaluations endpoints, envelope
  parsing (note: approved-entry `resource` matches `context.audience`, not the
  AuthZEN `resource` member), `context.actor` shape/consistency validation
  via `packages/actor-chain` (flattening is PEP-side per D31),
  FGA model for the domain substrate with mission authority
  injected as contextual tuples derived from the Mission Record per check
  (decision D26), content-addressed `policy_view_id`, freshness per D33
  (Mission Status List fetch per window backs the core-tier polled plane;
  introspection with the mission projection is the immediate check for the
  irreversible class).
  *Exit: golden-file decision tests: in-authority allow, out-of-authority deny,
  revoked-mission deny within bound.*
- **M4. MCP server + core enforcement tier.** AP tools, streamable HTTP, RFC 9728
  PRM, token + `mission` claim validation, per-action PDP calls with
  `context.mission` / `context.actor` / `context.audience` / `parameter_digest` /
  `context.capability_source` (tool_id `mcp://` URI, source_uri, source_digest,
  operation_ref), mission-scoped `tools/list` filtering (least exposure),
  per-instance controls keyed on `(act.iss, act.sub)`, Decision Evidence and
  Refusal Records, Enforcement Scope Statement published.
  *Exit: scenarios 2 and 3 pass as integration tests.*
- **M5. Transaction-assurance tier.** Single-use permits and execution
  leases (properties declared by the PDP in the decision; redemption and
  lease state owned by the PEP per D28), Execution Evidence, outcome
  reconciliation for `execute_wire_transfer` and `send_remittance_email`.
  *Exit: scenario 4; a replayed permit is refused as `permit_consumed`;
  reconciliation report joins evidence to ledger entries.*
- **M6. ARAP reevaluate mode.** Requestable denials from the PDP
  (`context.access_request` + PDP-signed `binding_token`), ARS task lifecycle,
  approver adjudication UI, PEP re-evaluation with `context.approval`.
  *Exit: scenario 5; approval is provably input context (no token change).*
- **M7. AROP.** DTR custom grant (`completion_mode=deferred`, `deferral_code`,
  deferred grant polling, idempotent submission, approval-bounded lifetime) and
  Transaction Challenge (RS challenge signing + `txn_challenge_jwks_uri`, AS
  `transaction_authorization_endpoint`, txn-bound audience-restricted single-use
  token, re-presentation checks), both completing through Mission Expansion.
  *Exit: scenarios 6 and 7; issued tokens never broaden the originating request
  and never outlive `approved_until`.*
- **M8. Service connectivity discovery.** Catalog Provider co-located in the
  AS: Service Catalog Endpoint with filtering (`category`, `type`, `status`,
  `profile`, `tag`), `service_catalog_endpoint` in AS metadata, entries seeded
  from demo-data, mission-derived per-connection `status`, `request-access`
  links into the ARS, and the payments server's Server Card published and
  referenced via `server_card_uri`. The LedgerCloud `id_jag` entry is seeded
  here and becomes actionable with M9.
  *Exit: scenarios 0 and 10 pass headless; catalog status flips on approval,
  revocation, and expansion without restart.*
- **M9. Cross-domain SaaS leg (EMA + ID-JAG).** Second trust domain per the
  cross-domain companion: Mission AS token-exchange issuance of the
  cross-domain grant with audience-scoped projection; RAS (second
  node-oidc-provider) with the JWT-bearer redemption grant, PoP and
  single-use validation, mission-preserving local tokens; LedgerCloud SaaS
  MCP server with EMA declared, enforcing from the token alone; catalog
  entry with the `id_jag` connection; agent EMA capability and flow.
  *Exit: scenario 12 passes as integration tests, including grant replay
  rejection and the revocation-lease demonstration.*
- **M10. Transparent audit (SCITT).** Transparency Service per the audit
  draft: in-memory append-only Merkle log, COSE Signed Statements with
  hash-envelope commitments, Receipts and signed tree heads; registration
  hooks in the AS, PDP, and MCP server for every evidence type the draft
  fixes; per-mission feed retrieval; CLI verifier plus an operator app audit
  view running the five-step offline check; `trace_id` extension member on
  evidence.
  *Exit: scenario 11 passes headless, including the tamper demo (mutated
  evidence fails digest verification, a dropped record fails inclusion).*
- **M11 scope note.** The three SPAs (`apps/approver`, `apps/operator`,
  `apps/agent-console`) are thin views over `services/console-bff` (D35);
  interactive UI is not headlessly verifiable, so M11's testable substance is
  the BFF persona layer (sessions, role/CSRF, approver queue + adjudication,
  operator fleet + lifecycle, the D32 feed-driven evidence timeline), covered
  by `console-bff/test`. The scenarios are "runnable from the UIs" at the BFF
  API the SPAs consume; a manual UI pass is a follow-on, not a gate.

- **M11. Full UX.** The three persona apps complete: approvals inbox with intent
  rendering, fleet dashboard on the management companion's surfaces
  (enumeration, revoke/expand, status transitions), the evidence timeline
  assembled feed-first per D32 (walk the mission's transparency feed,
  retrieve from producers, verify digests on render) joining decisions,
  executions, refusals, and reconciliation, and the agent console's
  discovery/catalog view.
  *Exit: scenarios 0-12 all runnable from the UIs alone (13 and 14 join in
  M12).*
- **M12. Agent + demos.** Scenario runner covering scenarios 0-14; the
  minimal harness duty in the agent (Status check on resume, stop on
  non-active); orchestrator/sub-agent support (scenario 13); optional LLM
  chat mode; seed polish; a `pnpm demo` one-command boot; `DEMO.md`, the
  guided walkthrough matching the runner (D40); and the exhibit
  mode emitting annotated wire captures shaped like the handbook's
  Appendix B.
  *Exit: fresh clone to full demo in under five minutes; scenarios 0-14 pass
  headless via the runner, including per-instance revocation (13) and the
  02:00 resume (14).*
- **M13. Evals.** The eval harness (`evals/`): a deterministic adversarial
  suite driving misbehaving agents at the running stack (prompt-injected
  tool output steering the agent off-mission, over-broad shaper proposals,
  parameter mutation between decision and execution, out-of-authority tool
  calls, sub-agent escalation attempts, replayed permits and cross-domain
  grants, confused-deputy attempts against the RAS, resumed work on a dead
  mission) and a legitimate-flow suite (scenarios 0-14 as the baseline);
  optional LLM red-team mode (Anthropic API) generating adversarial agent
  behavior against the same scoring. Each run is scored on: containment
  (unauthorized side effects MUST be zero), denial correctness (right
  `denial_reason` for the right cause), evidence completeness (every
  consequential attempt joins decision, execution or refusal, and audit
  records), over-blocking rate on the legitimate suite, and freshness-bound
  compliance. Emits a scorecard artifact; regressions gate CI.
  *Exit: `pnpm evals` runs headless in CI with 100% containment and zero
  evidence gaps on the adversarial suite; over-blocking on the legitimate
  suite is at or below the threshold set in O-30; red-team mode produces a
  reproducible transcript + scorecard when an API key is present.*
- **M14. Conformance + reports.** The written self-assessment against the
  six Runtime-Enforced invariants, the handbook vendor test's six questions,
  and the Field Reference implementation checklist; the five-laws table
  walked with links into recorded evidence; the consolidated spec-feedback
  report drawn from the Spec Feedback Log (goal 2's deliverable).
  `pnpm demo:vendor-test` runs the four valid-token-but-denied cases back to
  back (state: scenario 8, bounds: 7, parameters: 3, delegation chain: 13).
  *Exit: all assessments published in-repo; the vendor-test demo passes on
  the eval-gated build.*

## 6. Spec Anchor Index

Working references into the drafts (line numbers as of commit `dc7a897`):

- Assurance levels: `draft-mcguinness-mission-architecture.md:1805-1899`;
  Runtime-Enforced invariants: `architecture.md:2148-2161`.
- Enforcement Scope Statement: `draft-mcguinness-mission-runtime.md:540-546`;
  tiers: `runtime.md:596-613`; action classification floor: `runtime.md:635-642`.
- Mission Record: `draft-mcguinness-oauth-mission.md:1677-1772`; anchors:
  `mission.md:1600,1651`; `mission` claim: `mission.md:2012-2094`; PAR intake:
  `mission.md:797`; subset rule: `mission.md:1079`; state-gated issuance:
  `mission.md:2202-2326`; introspection: `mission.md:2327-2494`; RS enforcement:
  `mission.md:2097-2201`; AS conformance: `mission.md:2871-2938`.
- AuthZEN envelope: `draft-mcguinness-mission-authzen.md:338-372` (audience rule
  `authzen.md:362-372`); context sub-objects: `authzen.md:391-745`; permit/denial
  shapes: `authzen.md:1173,1199,1233`; requestable denials + ARAP:
  `authzen.md:1339-1409`; evidence objects: `authzen.md:1520,2013,1719`;
  capability source binding: `authzen.md:2163-2333`; materialization:
  `authzen.md:311`.
- Status: `draft-mcguinness-oauth-mission-status.md` (signed responses: `:335`).
- Expansion: `draft-mcguinness-oauth-mission-expansion.md`.
- AROP: openid/authzen PR #531,
  `profiles/authzen-access-request-oauth/authzen-access-request-oauth-profile-1_0.md`.
- Cross-domain: `draft-mcguinness-oauth-mission-cross-domain.md`: projection
  model `:213`, what crosses `:260`, grant requirements `:380`, validation at
  the Resource AS `:524`, AS metadata `:714`, worked stages `:857`.
- ID-JAG: `draft-ietf-oauth-identity-assertion-authz-grant` (IETF OAuth WG).
- MCP EMA: modelcontextprotocol repo,
  `docs/extensions/auth/enterprise-managed-authorization.mdx` (capability id
  `io.modelcontextprotocol/enterprise-managed-authorization`).
- Handbook: `~/src/mcguinness-blog/content/mission-handbook/_index.md` (the
  cover: five laws, canonical picture, running example, vendor test); the
  wire appendix (`/notes/mission-bound-authorization-on-the-wire/`) is the
  exhibit-mode reference (O-28).
- Actor profile: local repo `~/src/draft-mcguinness-oauth-actor-profile/`,
  `draft-mcguinness-oauth-actor-profile.md`: actor object + chain
  `:245-320`, presenter binding `:422-433`, errors `:1237`, introspection
  `:1201`, metadata `:1264-1340`, AS/RS conformance `:1508-1537`.
- Agent instance: `draft-mcguinness-oauth-ai-agent-instance-00`
  (datatracker): instance claims § 4, carriers § 5, DCR/AS metadata flags,
  access-token surfacing § 8; base is CIA-CORE
  (`draft-mcguinness-oauth-client-instance-assertion`, local checkout at
  `~/src/`).
- Mission joins: delegation via the actor profile `mission.md:2502-2543`
  (actor token type `client-instance-jwt` `:2513`); `context.actor` as a
  root-to-leaf array `authzen.md:441-457`.
- Audit: `draft-mcguinness-mission-audit.md`: registration `:267`, hash
  commitment `:279`, evidence types `:307`, mission-as-subject feed `:687`,
  receipts + offline verification `:756`, conformance `:935`.
- Management: `draft-mcguinness-oauth-mission-management.md` (fleet
  enumeration + lifecycle operations; subset pinned in O-32).
- Discovery: `draft-mcguinness-svc-connectivity-disco.md` (repo
  mcguinness/draft-mcguinness-svc-connectivity-disco): endpoint discovery
  § endpoint-discovery, request/filtering § catalog-request, `mcp` service
  type § type-mcp, connection object/status § connection-object, OAuth
  profile § profile-oauth, `request-access` link rel § link-object,
  intent-based use § intent.

## 7. Issue Log

Conventions: `O-n` open, `R-n` resolved. Move entries down to Resolved with the
resolution and date; never delete them.

### Open

- **O-3. DTR draft fidelity.** Fetch `draft-gerber-oauth-deferred-token-response`
  and pin parameter names, error codes (`authorization_pending`, `slow_down`,
  `expired_token`), and the deferred grant URN before M7.
  Disposition (2026-07-26): pinned to `-00` (PR #350) — parameter names, the
  deferred grant URN, and the error vocabulary verified/aligned (`invalid_grant`
  routing for unknown/already-redeemed fixed).
  Resolved (2026-07-28, PR #353): the residual is closed — `slow_down` /
  `expired_token` backoff added to `deferred.ts` (RFC 8628: advertises
  `interval+5`, 600s lifetime), and the deferred grant is wired onto the real
  `/token` endpoint via `registerGrantType`. Redemption mints a resource-bound
  JWT mission token (not opaque), DPoP-bound (`cnf.jkt` from the request proof),
  TTL clamped by `approved_until`, carrying the active Mission unchanged (D42).
  Initiation is folded into the grant type (deviation S-14). SPEC_VERSIONS row
  51 updated; real-HTTP coverage in `dtr-endpoint.test.ts`.
- **O-4. Transaction challenge draft fidelity.** Fetch
  `draft-rosomakho-oauth-txn-challenge` and pin the challenge JWS claims
  (`txn`, `authorization_details`, `iss`, `aud`, `reason`), the
  `Accept-Txn-Challenge` header, endpoint request/response shapes, and
  `txn_challenge_jwks_uri` metadata before M7.
  Disposition (2026-07-26): resolved against `-00` (PR #350) — challenge JWS
  typ (`txn-authz-challenge+jwt`)/`jti`/`txn` claims, endpoint request/response,
  §6.2 token-vs-challenge binding, and poll error codes aligned. The
  `parameter_digest` gap is logged as S-10; the in-process/transport
  simplifications (401→`access_challenge`, `Accept-Txn-Challenge`, form-vs-JSON,
  `txn_challenge_jwks_uri` served) as S-11.
- **O-5. Expansion lifecycle detail.** Read the expansion draft closely: successor
  mission state transitions, predecessor disposition, and how the AROP-issued
  token's `mission` claim references the successor. Needed for M7.
- **O-6. Per-payment cap placement.** FGA condition vs PDP overlay for the
  per-payment cap. (Cumulative caps are deferred to the metering follow-on
  per D28.) Decide during M3 with a spike; record the rationale here.
- **O-8. Freshness numbers.** The authoritative-source question is resolved
  by D29/D33; what remains is picking values: the Status List fetch window
  and token `ttl`, the published staleness bound per action class (floor
  target: under 300 s for high-consequence), and lease durations. Decide in
  M3/M4.
- **O-9. COAZ alignment.** mission-authzen composes with COAZ for MCP tool
  mapping. Decide whether to fetch COAZ and mirror its subject/action/resource
  mapping or keep the profile's own `context.capability_source` members only.
- **O-10. ARAP draft fidelity.** Fetch the ARAP profile itself (access request
  submission shape, task states, `approval` object, `approved_until`,
  `binding_token` verification rules) before M6.
  Resolved (2026-07-27) against ARAP (openid/authzen PR #508, blob
  `670f5831`). The fidelity pass confirmed the submission / task / approval
  shapes; the companion was reconciled (`approved_until`, `access_request`
  `expires_at` + `binding_token`, an ARAP mapping note; PR #351) and the impl
  aligned (PDP emits `access_request.expires_at` + honors `approved_until`,
  ARS approval-state JWS carries `iss`+`aud`; PR #352). SPEC_VERSIONS row 48
  pinned. Watch PR #532 (`evaluation_id` denial binding).
- **O-11. Consent Evidence scope.** The approver app renders intent at approval;
  decide whether to include `consent_rendering_hash` + signed Consent Evidence
  (companion draft) in M11 or defer.
- **O-12. Mission-derived status mapping.** Exact mapping from mission
  lifecycle states (and issuance feasibility) to `connected` / `available` /
  `consent_required` / `unavailable`, and how the catalog decides a mission
  "covers" a service. Decide in M8.
- **O-13. MCP Server Card shape.** Which Server Card format/location the
  payments server publishes for `server_card_uri`, and whether the capability
  source `source_digest` (mission-authzen § capability source) is computed
  over the same card. Decide in M4, revisit in M8.
- **O-14. Catalog vocabulary for the AP domain.** The category registry seeds
  email/calendar/files/etc.; payments is not seeded. Namespaced category vs
  `tags` for the demo services. Decide in M8.
- **O-15. request-access intake shape.** What the `request-access` href
  carries (service id, requested capability, return URI) and whether an
  adjudicated request materializes as a first mission issuance or as an
  Expansion. Decide alongside M6, wire in M8.
- **O-16. COSE and Merkle tooling.** Pick the TS COSE_Sign1 library (or
  hand-roll over WebCrypto) and the Merkle tree approach (RFC 9162-style)
  for the Transparency Service, including the hash-envelope headers
  (payload-hash-alg 258, payload-preimage-content-type 259). Decide in M10.
- **O-17. Evidence-type registration map.** Map the audit draft's
  § evidence-types table onto our producers (AS: lifecycle transitions,
  derivation records; PDP: Decision Evidence, Refusal Records; MCP server:
  Execution Evidence, reconciliation) and pin the exact hashed bytes for
  each. Pin in M10.
- **O-18. trace_id extension member.** Name and placement of the trace
  correlation member on evidence objects (it is part of the signed and
  hashed evidence bytes once included, so it must be set before signing).
  Decide in M4.
- **O-19. ID-JAG draft fidelity.** Fetch
  `draft-ietf-oauth-identity-assertion-authz-grant` and pin the token
  exchange request parameters, the grant JWT claims, and how the
  cross-domain companion's proof-of-possession and single-use floors attach
  to it. Before M9.
  Resolved (2026-07-27) against draft-04. Redemption is RFC 7523 JWT-bearer
  (confirmed conformant; RFC 8693 token-exchange is only the IdP mint step);
  the `oauth-id-jag+jwt` typ and `urn:ietf:params:oauth:token-type:id-jag`
  URN match; the grant now carries the REQUIRED `client_id` (§3.1, PR #352).
  Single-use is conformant-to-companion (S-13); the RAS client-match gap is
  logged as an accepted deviation (S-12). SPEC_VERSIONS row 55 pinned `-04`.
- **O-20. EMA metadata surface.** Pin exactly how the SaaS MCP server
  "declares the extension in its authorization metadata" (member name and
  shape); the extension is young, so track the MCP spec revision we
  implement against. Before M9.
- **O-21. Catalog status for id_jag connections.** The mission-derived
  `status` mapping (O-12) assumed the internal domain; for the SaaS service
  it also depends on issuer-side projection policy. Extend the mapping.
  Decide in M9.
- **O-22. Audience-scoped projection derivation.** How the Mission AS
  decides which Authority Set entries a given RAS is authoritative for
  (the resource-to-AS mapping seed), per cross-domain § audience-scope.
  Decide in M9.
- **O-23. SaaS-side audit registration.** Whether the RAS registers grant
  redemptions in our Transparency Service (cross-domain producers) or the
  audit feed stays internal-side only, with the revocation lease documented
  in the demo. Decide in M9/M10.
- **O-24. act.cnf semantics.** Filed upstream as actor-profile issue #4
  (github.com/mcguinness/draft-mcguinness-oauth-actor-profile/issues/4):
  base profile leaves `act.cnf` semantics undefined, receipts prohibit it in
  receipt hops, agent-instance examples duplicate the top-level `cnf.jkt`
  inside `act`. Our stance until resolved: PoP against top-level `cnf` only,
  `act.cnf` informative (D21). Revisit when the upstream issue closes.
- **O-28. Appendix B exhibit fidelity.** Fetch the handbook's wire appendix
  and pin the exhibit format the scenario runner's exhibit mode emits, so
  captures are comparable to the published exhibits. Before M12.
- **O-29. Resume-check semantics.** Which non-active states stop vs pause
  the agent's harness check, and the check cadence on wake, consistent with
  the published staleness bounds (O-8). Decide in M12.
- **O-30. Eval taxonomy and pass bars. (addressed in M13: taxonomy = out-of-authority tool, vendor-constraint, over-cap, TOCTOU, unknown-mission, view-tamper; over-block threshold 0%; CI-gating metrics = containment/evidence-gaps/over-block/denial-correctness.)** Pin the misbehavior-class taxonomy
  (drawing on the handbook's Testing chapter framings, including the lethal
  trifecta), the over-blocking threshold for the legitimate suite, and
  which scorecard metrics gate CI vs merely report. Decide in M13.
- **O-31. Red-team eval methodology. (resolved: deterministic suite shipped in M13; LLM red-team mode shipped PR #355.)** How the LLM adversary is prompted
  and seeded, how nondeterministic runs stay comparable (persisted
  transcripts as replayable fixtures), and how red-team findings feed new
  deterministic cases. Decide in M13.
  Resolved (2026-07-28, PR #355): opt-in LLM red-team mode added to `evals/`
  (`pnpm evals:redteam`). An attacker generates `{tool,args}` attacks against a
  fixed in-bounds token; each runs through the existing `runCase` and is graded
  by a PDP-independent bounds oracle (`redteam.ts`), scored on a separate
  scorecard whose bar is zero breaches (oracle-deny attack that caused a side
  effect). Comparability = persisted transcripts replayed from a committed seed
  fixture (key-free); findings distil into new deterministic `suites.ts` cases.
  Per D24 the mode is opt-in and does NOT gate CI — the deterministic `pnpm
  evals` suite stays the gate (untouched). Two documented, benign limitations
  (ledger-only breach detection; an uncounted oracle-deny+permit+no-side-effect
  bucket) can't occur under the current authority.
- **O-32. Management companion subset.** Pin which of the management
  draft's surfaces the operator app consumes (fleet enumeration,
  per-mission lifecycle operations; bulk operations if needed) and how the
  operator app authenticates to them. Decide in M11.
- **O-33. MCP TS SDK gaps.** Pin the `@modelcontextprotocol/sdk` version;
  Server Card publication and EMA declarations are not SDK-supported and
  are hand-rolled. Track SDK evolution and replace hand-rolled pieces when
  the SDK catches up. SDK pinned at 1.29.0 by the spike; gap tracking
  remains. Revisit in M4.
  Disposition (2026-07-29, PR #357): the SDK is now wired as a REAL transport
  (`services/mcp-payments/src/mcp-transport.ts`, in-memory) delegating
  `tools/list`/`tools/call` to the PEP (SPEC_VERSIONS row moved planning ->
  implemented; the harness's mediated channel, D47) — the transport swap this
  entry tracked. Still open: Server Card publication + EMA declarations stay
  hand-rolled (not SDK-supported), and DPoP proof-of-possession over the MCP
  transport is deferred to the real HTTP transport. Gap tracking continues.
  Update (2026-08-02, PR #364): the PoP-over-transport caveat is now CLOSED for
  the HTTP path — harness increment 3 adds a real StreamableHTTP transport
  (`services/mcp-payments/src/mcp-http-transport.ts`) whose DPoP-auth middleware
  enforces proof-of-possession per request via `validateToken` (proof `jkt` =
  token `cnf.jkt`, canonical `htu`/`htm` bound); a token with no proof (or the
  bearer scheme), or a mismatched-key proof, is rejected before the PEP (zero
  evidence/ledger). The in-memory transport keeps the no-PoP
  `validateMissionToken` by design (no HTTP request to bind). Server Card + EMA
  declarations remain hand-rolled.
- **O-34. Status List mechanics.** Pin the Mission Status List
  implementation details per the companion § status-list and
  `draft-ietf-oauth-status-list`: 2-bit entries, compression, list token
  shape and `ttl`, anti-oracle index allocation, republication on
  transition, and library vs hand-roll. Decide in M3.
- **O-35. Introspection projection details.** Pin the introspection mission
  projection (status draft § introspection-projection): the `mission`
  member's contents, how the PDP authenticates as a caller, and how the
  observation is recorded in Decision Evidence. Before M3.
- **O-36. AROP DTR derivation double-count.** On a deferred-grant redemption the
  kernel gates twice — `DeferralStore.redeem()` calls `gateDerivation` (to
  refuse a mission revoked between approval and redemption) and the token
  formatter's `extraTokenClaims` gates again via `grantId` — so
  `derivation_count` increments twice per issuance. Latent: no `max_derivations`
  is configured in `config/`/`demo/`/`evals/`, so nothing observes it today; a
  capped mission would spend two derivations per AROP redemption and could hit
  `derivation_cap_exhausted` a redemption early. Fix (deferred): have `redeem()`
  read the mission via `kernel.get()` for the subset re-check and let
  `extraTokenClaims` be the single authoritative gate — a kernel-contract change
  asserted against by `arop.test.ts`, out of scope for PR #353 (which wired DTR
  onto `/token`). Surfaced 2026-07-28.
  Resolved (2026-07-28, PR #354): `redeem()` now does a read-only active check
  (`kernel.get` + `applyExpiry`, the pattern `open()` uses) and refuses a
  non-active Mission with `access_denied`; `extraTokenClaims` is the single
  authoritative gate + increment at mint. `dtr-endpoint.test.ts` case 10 asserts
  exactly one increment per redemption (verified failing `expected 2 to be 1`
  against the pre-fix code); no `arop.test.ts` assertion depended on the removed
  gate.
- **O-37. Orchestration `privileged_administration` action class.** The
  orchestration reversibility floor (PR #369) maps runtime action classes to a
  minimum reversibility, but `privileged_administration` has no corresponding
  runtime class in `services/pdp/src/policy.ts` (only `irreversible_action` /
  `external_commitment` exist). Mapped in the package with a documented gap; a
  real runtime class is deferred. Surfaced 2026-08-02.
- **O-38. Child-delegation (parent→child sub-missions) not implemented.** The
  `draft-mcguinness-mission-orchestration` shipped in PR #369 is the
  saga/unwinding+compensation profile. Parent→child sub-agent delegation — a
  child Mission with its own `mission_id`/lifecycle/approval, authority ⊆ parent,
  cascade termination via the existing `cascaded` state, a separate child actor
  hop — is a DISTINCT draft (`oauth-mission-child-delegation`), still
  unimplemented, and is what "orchestrator agent" colloquially means (D20 /
  scenario 13). A future AS-kernel increment. Surfaced 2026-08-02.
  Resolved (2026-08-03, PR #370): implemented as `kernel/child-delegation.ts`
  (`createChildMission`): a child Mission with its own `mission_id`/actor/`act`
  chain, `parent` lineage (`ParentRef` + `depth` cap), authority proven ⊆ parent
  (derive-then-`isSubsetSet`, refusing over-broad with `not_strict_subset` per
  §strict-subset — NOT silent narrowing), `expires_at` clamped ≤ parent, the
  delegation event as the child's approval. Parent TERMINAL transitions cascade
  active descendants to `cascaded` via `cascadeChildren` fired on the `setState`
  terminal path (+ `supersedeOnRedemption`), so the Status List + Signals
  propagate for free. Suspend is deliberately NOT cascaded (§cascade makes it the
  one reversible trigger — suspend-projection/restore deferred). Deferred: PAR
  wire params + child grant issuance, fan-out accounting + the
  `AuthorityEntry.delegation` core extension (S-15), child evidence, discovery
  metadata, cross-issuer. 240 tests green.
  Deferrals closed (2026-08-05, stacked PRs, see D49): fan-out accounting + the
  `delegation` extension/S-15 (#371, #375), child evidence (#375),
  suspend-projection/restore + ancestor-active gate (#373), and PAR wire params +
  child grant issuance + discovery (#374). Child redemption at `/token` (RFC 7523
  JWT-bearer, #376) and creation relocated to a `/token` grant retiring `POST
  /child-missions` (#377) then closed the wiring (see D50). Remaining deferred:
  cross-issuer only (the draft defers it; `child.issuer = parent.issuer` holds).
  Final gate 278 passed / 0 skipped.
- **O-39. Attenuation leaf-constraint enforcement is action-level.** The PEP leaf
  guard (PR #367) denies an in-Mission action outside the leaf's tool set
  (`out_of_authority`), but a leaf that TIGHTENS a constraint (e.g. lowers the
  amount cap below the Mission's) is enforced only by the chain verifier's
  constraint-monotonicity check, not yet by the PEP amount gate. Deferred.
  Surfaced 2026-08-02.

### Resolved

- **R-1 (2026-07-20). AROP identified.** AROP is the AuthZEN Access Request OAuth
  Profile, openid/authzen PR #531 (decision D1).
- **R-2 (2026-07-20). Demo domain.** Accounts payable (decision D2).
- **R-3 (2026-07-20). AS stack.** node-oidc-provider (decision D3).
- **R-4 (2026-07-20). Agent drive.** Scripted runner + optional LLM mode (D4).
- **R-5 (2026-07-20). AROP bindings.** DTR + Transaction Challenge; CIBA cut (D5).
- **R-6 (2026-07-20). Completion-mode composition.** Both ARAP `reevaluate` and
  AROP token issuance, demoed separately; AROP issuance is Expansion-backed so
  the PDP stays authoritative per action (D6).
- **R-7 (2026-07-20). UX shape.** Separate persona apps (D7).
- **R-8 (2026-07-20). MAS binding not used.** The build implements the core
  Mission-aware AS, not the standalone Mission Authority Server binding; the MAS
  join (issuance-grant draft) is a candidate follow-on.
- **R-9 (2026-07-20). Resource discovery adopted.** svc-connectivity-disco
  integrated as the discovery layer: Catalog Provider co-located with the AS,
  mission-derived `status`, `request-access` wired to the ARS (decisions
  D8-D10). New milestone M7; UX and agent milestones renumbered to M8/M9.
- **R-10 (2026-07-20). Audit and observability adopted.** Full mission-audit
  SCITT profile as milestone M10 with a dedicated Transparency Service;
  OTel + Jaeger + pino as the M0 telemetry baseline; evidence carries
  `trace_id` correlation (decisions D11-D13). Audit removed from the
  out-of-scope list.
- **R-11 (2026-07-20). Cross-domain SaaS leg adopted.** Internal + SaaS MCP
  topology per the cross-domain companion, ID-JAG grant, MCP EMA; LedgerCloud
  accounting SaaS at lifetime-bounded reliance; RAS as a second
  node-oidc-provider (decisions D14-D17, milestone M11, scenario 12).
  Cross-domain removed from the out-of-scope list.
- **R-12 (2026-07-20). Actor profile + agent instance adopted.** Base
  actor-profile (companions deferred) plus the full ai-agent-instance
  profile, with an orchestrator/sub-agent delegation scenario (decisions
  D18-D21, milestone M12, scenario 13). The act.cnf conflict was filed
  upstream as actor-profile issue #4.
- **R-13 (2026-07-20). Handbook review applied.** Against the handbook
  cover: Shaper + compromised-shaper test, minimal harness stop with the
  02:00-resume scenario (14), five-laws mapping, vendor-test demonstration
  and Field Reference checklist in M9, mission-scoped `tools/list`,
  wire-exhibit mode, control-plane framing (decision D22). Consent evidence
  was reviewed and left undecided: O-11 remains open.
- **R-14 (2026-07-20). Spec validation goal added.** Validating the
  architecture and specs is goal 2, co-equal with reaching the level; the
  Spec Feedback Log (§ 8) tracks findings with routing conventions and
  seeds S-1..S-4; every milestone exit gains a spec-feedback pass; M9
  produces the consolidated report (decision D23).
- **R-15 (2026-07-20). Evals adopted.** Milestone M13: deterministic
  adversarial + legitimate-flow suites with an optional LLM red-team mode,
  scored on containment, denial correctness, evidence completeness,
  over-blocking, and freshness compliance; scorecard gates CI
  (decision D24, issues O-30/O-31).
- **R-16 (2026-07-20). Review pass: milestones reordered into dependency
  order.** Actor profile + agent instance moved up to M2 (its surfaces are
  consumed by the PDP, PEPs, and agent from the start); cross-domain to M9;
  UX to M11; agent + demos to M12; conformance + reports split out as the
  final M14 (audit stays M10, evals stays M13). The management companion
  was adopted partially for the operator app's fleet surfaces (O-32), the
  LedgerCloud catalog-entry sequencing was noted in M8, a stray empty
  diagram fence was removed, and the runbook service list was corrected.
  R-entries above reference the pre-reorder numbering.
- **R-17 (2026-07-20). Pre-implementation readiness pass.** Pre-flight spike
  defined ahead of M1; testing-and-delivery conventions added (vitest,
  in-process scenario composition, separate `src/**` CI, toolchain pinning,
  SPEC_VERSIONS); headless adjudication path and side-effect oracle
  specified; O-33 opened for MCP SDK gaps; non-goals stated. The
  determinism-by-design bundle (injectable clock/RNG, deterministic dev
  keys) was reviewed and declined for now, with flaky golden files,
  exhibits, or evals as the revisit trigger (decision D25).
- **R-18 (2026-07-21). Debate #1 and store architecture resolved.** Mission
  authority reaches OpenFGA as contextual tuples derived from the Mission
  Record per check; stored tuples carry only the domain substrate (D26,
  feedback logged as S-5). Record-shaped stores move to SQLite `:memory:`
  behind repository interfaces in `packages/store` (D27). O-7 resolved by
  D26: `policy_view_id` is the content hash of the Mission Record version
  plus the FGA model version.
- **R-19 (2026-07-21). Debate #2 resolved: stateless PDP.** The PDP is a
  pure decision function; permit properties are declared in the decision
  and redemption/lease state is owned by the PEP, matching the companion's
  own duty assignment (`permit_expires_at` at the PEP, `permit_consumed`
  under Execution Evidence). Cumulative caps deferred to the metering
  follow-on; O-6 narrowed to per-payment cap placement; S-6 logged
  (decision D28).
- **R-20 (2026-07-21). Debate #3 resolved: two-tier freshness, both spec
  branches.** Signed Status is the single freshness surface consumed two
  ways: polled cache under the published bound (core tier), cache-bypassed
  immediate check for the irreversible class, and permit-within-bound plus
  egress PEP for external commitment; fail-closed on Status unavailability.
  Both branches of the runtime floor table are exercised; scenario 8 now
  demonstrates the contrast; O-8 narrowed to picking values (decision D29).
- **R-21 (2026-07-21). Debate #4 resolved: single AS with a mission-kernel
  module.** The core profile's co-location claim is validated as written;
  the kernel boundary (typed interface, no provider types in the kernel)
  contains the O-2 risk to the adapter layer and makes a future MAS
  follow-on a mechanical lift (decision D30).
- **R-22 (2026-07-21). Debate #5 resolved: PEP flattens, PDP shape-checks.**
  The act-chain transform is PEP-side (only the PEP can verify PoP; the PDP
  stays credential-agnostic); the PDP validates chain shape and
  consistency; golden vectors in `packages/actor-chain` back S-2's proposal
  for normative spec vectors (decision D31).
- **R-23 (2026-07-21). Debate #6 resolved: feed-driven distributed evidence.**
  Producers retain evidence + Receipts, the log holds commitments only, and
  the operator timeline is the verified per-mission feed rendered
  continuously (decision D32). This closes the architecture-debate series:
  all six debates resolved as D26-D32.
- **R-24 (2026-07-21). External critique answered item by item.** Adopted:
  the Operation Profile artifact and authoritative business state (D34),
  the BFF topology with a dedicated console-bff hosting the audit read
  model (D35), the irreversible-operation state machine minus the PDP
  outcome callback, which was rejected to preserve D28 (D36), approval
  ownership/reuse rules and write-approval governance, changing scenario 1
  to Bob as approver (D37), the token/client/interop profile with the
  canonical resource URI rule and the pinned MCP authorization profile
  (D38), and the hardening bundle: channel/key matrix, FGA hygiene, restart
  epochs, pin-at-spike policy (D39). Freshness revised on production
  realism (D33): Mission Status List backs the polled plane, introspection
  is the irreversible-action immediate check. Superseded by earlier
  decisions: the policy-view staging protocol (no tuple publication exists
  under D26) and central evidence collection (D32). Corrected premises: the
  plan never claimed all-HTTPS transport nor pinned oidc-provider 9.10.0.
  M0 gains four architecture artifacts; M1 gains the tracer slice; O-34 and
  O-35 opened.
- **R-25 (2026-07-21). Final readiness sweep.** `src/` code licensed
  BSD-2-Clause (harmonizing with the TLP's code-component terms);
  execution conventions added (milestone status table, definition of done,
  bugs-to-GitHub convention, how-to-use note); trusted-base statement
  folded into the M0 matrix artifact; scenario-spec traceability and
  `DEMO.md` adopted (decision D40). The plan is declared
  implementation-ready; next action is the pre-flight spike.
- **R-26 (2026-07-21). Pre-flight spike complete (PR #317).** O-2: GO on
  `oidc-provider@9.10.0`, 10/11 empirical checks (issuer-derived RAR via
  `Grant.addRar`; `mission_intent` as a validated PAR extra param flowing
  to the interaction; custom token-exchange and DTR grants; `mission`
  claim via `extraTokenClaims`). One scoped D30 fallback: JWT ATs cannot
  use the built-in introspection endpoint, so the mission-kernel adapter
  implements the introspection route (RFC 7662 + mission projection,
  mirroring the JWT claim set per CIA-CORE). RAR is experimental
  (`ack: 'experimental-01'`), reinforcing exact pins; Node 22 LTS
  required. O-1: `mission_intent` carriage pinned and wire-verified.
  O-25: CIA-CORE carriers pinned (`client-instance+jwt` typ vs the
  actor-token URN, 12-step processing, chain merge, cnf rules); CIA-CORE
  § security-binding answers half of actor-profile#4 (commented
  upstream). O-26: position-keyed `sub_profile` allowlists pinned; S-7
  logged. O-27: local max depth 4; sub-agent spawn = presenter rebind,
  self-exchange = continuation. Pins: MCP SDK 1.29.0, OpenFGA v1.18.1 by
  digest. Full detail: `src/spikes/SPIKE-REPORT.md`.
- **R-27 (2026-07-21). Spec traceability adopted.** `SPEC_VERSIONS.md`
  upgraded from a pin list to a traceability matrix with `@spec` code
  tags, seeded in the M0 PR with the mission-core row and the spike pins
  (decision D41).

## 8. Spec Feedback Log

The record backing goal 2. Implementation-driven findings about the specs
themselves, distinct from the implementation issues in § 7.

Entry format: `S-n (status)` — category, affected spec + section, one-line
finding, disposition. Categories: **defect**, **ambiguity**,
**hard-to-implement**, **simplification-candidate**, **interop**. Statuses:
`open` → `filed` (upstream issue opened), `fixed-in-spec`, `accepted`
(complexity acknowledged and kept, with the rationale recorded), or `resolved`
(settled by an implementation decision, cross-referenced to the Decision Log).
Entries are never deleted.

Routing: findings against the **published core** are filed as GitHub issues
on the mission repo (the core is never edited directly). Findings against
**companions** may be fixed directly in their drafts in this repo. Findings
against **external specs** (the actor suite, AuthZEN ARAP/AROP,
svc-connectivity-disco, MCP EMA, ID-JAG, CIA-CORE) are filed upstream on
their repositories or working groups.

- **S-1 (filed).** Interop/defect — actor-profile x actor-receipts x
  ai-agent-instance: `act.cnf` placement. The base profile leaves its
  semantics undefined, receipts prohibit it in receipt hops, and the
  agent-instance examples duplicate the top-level `cnf.jkt` inside `act`.
  Filed as actor-profile issue #4; implementation stance in D21
  (cross-ref O-24).
- **S-2 (open).** Simplification-candidate — mission-authzen § context.actor:
  the transform from the token's nested `act` (outermost-first) to the flat
  root-to-leaf `context.actor.act` array is left entirely to implementers.
  A normative transform example or test vector in the companion would
  prevent divergent orderings; per D31 the shared package's golden vectors
  are the candidate contribution. Candidate: direct companion edit.
- **S-3 (resolved).** Ambiguity — mission-authzen x AROP: the companion says an
  ARAP approval is input context, never a bearer grant, while AROP completes
  by token issuance; the composition only closes through Expansion (our D6),
  and neither document names it. Resolved by D46: the implementation completes
  JIT approval via AROP token issuance (Transaction Challenge binding,
  `transaction_authorization_id` handle), using the ARAP `approval` only as an
  internal AS<->PDP `context.approval`; AROP never expands (D42), so the old
  "closes through Expansion" framing is dropped. Remaining candidate: upstream
  AROP feedback confirming the shape.
- **S-4 (open).** Interop — MCP EMA: the extension is young and the exact
  authorization-metadata member for the server-side declaration is not yet
  pinned (cross-ref O-20). Track the extension revision implemented against;
  feed friction upstream to the MCP auth interest group.
- **S-8 (open).** Deviation — mission-audit mandates COSE hash-envelope
  Signed Statements (payload-hash-alg 258, payload-preimage-content-type
  259); this reference commits by hash under JWS to stay in the JOSE stack
  (O-16). SCITT semantics are faithful (commit-by-hash, Merkle inclusion,
  receipts, offline verification, tamper detection). Swap to COSE for
  wire-fidelity; feed back whether a JOSE profile is worth an option.
- **S-5 (open).** Simplification-candidate — mission-authzen
  § Mission-to-Policy Materialization: the text reads as write-on-approval
  (stored-tuple sync), which is the less typical strategy for ephemeral,
  task-scoped authority; the engine surfaces built for that case (OpenFGA
  contextual tuples, Cedar entities-in-request, OPA input) support
  per-decision derivation from the record with no dual-write. Propose the
  companion name both materialization strategies and define what
  `policy_view_id` commits to under each (see D26). Candidate: direct
  companion edit.
- **S-6 (open).** Ambiguity — mission-authzen: the draft implies PEP-side
  consumption tracking (`permit_expires_at` is checked "at the PEP",
  § clock-skew; a consumed single-use identifier re-presented is refused
  under Execution Evidence as `permit_consumed`, refusal taxonomy) but
  never states in one place where single-use consumption state lives. One
  sentence ("the PDP remains stateless; consumption tracking is a PEP
  duty") would settle it for implementers. Candidate: direct companion
  edit (see D28).
- **S-7 (open).** Ambiguity — draft-mora-oauth-entity-profiles rev 01: the
  "OAuth Entity Profiles Registry" describes Designated Expert review
  guidance but states no formal IANA registration policy keyword
  (Specification Required / Expert Review / etc.). One sentence would fix
  it. Candidate: upstream issue on the entity-profiles repo.
- **S-9 (open).** Ambiguity — mission core x OIDC: the core profile is silent
  on OpenID Connect id_tokens. Authority and the mission binding travel in the
  mission-bound access token (`aud` = resource, `cnf.jkt`, `mission`,
  `authorization_details`); whether the AS also issues a standard id_token
  (`aud` = client_id, identifying the user to the client) is undefined. This
  reference enables the `openid` scope so `/token` returns a real id_token
  alongside the access token (exercised end to end in the exhibit); the
  id_token is non-authoritative. Disposition: no spec change needed; the
  access token, not an id_token, is the authority carrier. Candidate: a
  one-sentence core clarification, filed as a mission core issue (the core is
  never edited directly).
- **S-10 (open).** Gap — draft-rosomakho-oauth-txn-challenge § 4.2.2: the
  challenge claim set has no member binding the *effective operation
  parameters* to the challenge, so an approval cannot be scoped to the exact
  parameters the RS gated on. This reference adds a `parameter_digest` claim and
  the AS requires it (`provider.ts` rejects a challenge without one), so a
  spec-conformant third-party challenge lacking it is refused (inbound-interop
  deviation). Candidate: file upstream proposing a parameter-binding claim;
  until then it is a documented local extension. (Found in the O-4 fidelity pass.)
- **S-11 (accepted).** Deviation — draft-rosomakho-oauth-txn-challenge (txn
  binding) x this demo: the MCP RS is in-process (O-33), so the signed challenge
  is surfaced as an `access_challenge` result field rather than a `401` +
  `WWW-Authenticate` response; the `Accept-Txn-Challenge` capability gate is not
  implemented; the transaction endpoint takes JSON `{challenge}` rather than
  form-encoded `transaction_challenge`; and `txn_challenge_jwks_uri` is
  config-injected rather than served. The wire-format + liveness bugs (typ, jti,
  txn-vs-sub, poll error codes) were fixed (PR #350); these transport
  simplifications are acknowledged and kept for the in-process demo.
- **S-12 (accepted).** Deviation — draft-ietf-oauth-identity-assertion-authz-grant-04
  § 3.1 / § 4.4.1 x this demo: ID-JAG mandates a `client_id` claim and the
  Resource AS MUST match it against the redeeming client's authentication. The
  grant now carries `client_id` (PR #352), but the demo RAS has no
  registered-client model, so it does not enforce the match; the DPoP `cnf.jkt`
  presenter check binds the client instead. Acknowledged for the in-process
  demo; a full fix needs a client-registration model at the RAS.
- **S-13 (accepted).** Layering — draft-ietf-oauth-identity-assertion-authz-grant-04
  § 4.4.3 permits a client to re-submit the grant after access-token expiry
  (`MAY`); the cross-domain companion deliberately tightens this to one-time use
  (a `jti` the RAS `MUST reject` on replay), noting ID-JAG has no replay
  backstop of its own. Our RAS is conformant to the governing companion; a
  draft-only client that re-submits after expiry gets `invalid_grant`. Kept as
  the intended layering.
- **S-14 (accepted).** Deviation — draft-gerber-oauth-deferred-token-response-00
  § 5 x node-oidc-provider: DTR initiates by sending `completion_mode=deferred`
  on the ORIGINATING grant's token request, leaving the AS discretion to defer.
  node-oidc-provider exposes no pre-issuance defer hook for its built-in grants
  (a middleware short-circuit of `/token` would bypass client-auth + DPoP), so
  initiation is folded into the deferred grant type itself: a request carrying
  `deferred_authorization` (no `deferral_code`) opens the deferral and returns
  the DTR 400 initiation body; a request with `deferral_code` polls/redeems.
  Wire responses stay DTR-shaped. Kept for the in-process demo (PR #353); a
  faithful `completion_mode` interception needs a grant-handler override the
  library does not offer.
- **S-15 (resolved 2026-08-05, PR #371).** Gap — draft-mcguinness-oauth-mission-attenuation § root-mapping
  x the substrate: the draft derives a root's `del_max_depth` from a per-entry
  `delegation` policy, but the core `AuthorityEntry` (`types.ts`) has no
  `delegation` member, so it cannot be derived. Attenuation (PR #367) takes
  `del_max_depth` as an explicit input to `deriveAttenuationRoot` and leaves
  `types.ts`/`derive.ts` untouched. Closing it needs an additive optional
  `delegation?: { max_depth }` on `AuthorityEntry` plus a derivation rule — not a
  one-line change, because the shared `intersect()` in `derive.ts` builds fresh
  entries and would drop the member. Surfaced 2026-08-02.
  Resolved (2026-08-05, PR #371): added the additive optional `delegation` member
  to `AuthorityEntry`, taught `intersect()` to carry and narrow it (so the
  fresh-entry rebuild no longer drops it: inherit-by-default from the ceiling,
  ceiling-absent yields non-delegable), and made `deriveAttenuationRoot` derive
  `del_max_depth = min(max_depth)` across the delegable entries, keeping the
  explicit input as an optional override for the existing call sites. 255 tests green.

## 9. Runbook (target state)

```
cp src/.env.example src/.env        # optionally add ANTHROPIC_API_KEY
docker compose -f src/docker-compose.yml up -d   # OpenFGA (in-memory) + Jaeger
pnpm -C src install
pnpm -C src seed                    # load users/clients/vendors/invoices + FGA model
pnpm -C src dev                     # AS, PDP, ARS, 2 MCP servers, RAS,
                                    # transparency, three SPAs
pnpm -C src demo                    # scripted scenarios 0-14 against the running stack
pnpm -C src demo:vendor-test        # the four valid-token-but-denied cases
pnpm -C src evals                   # adversarial + legitimate suites, scorecard
pnpm -C src evals:redteam           # LLM red-team mode (needs ANTHROPIC_API_KEY)
```

All state is in memory: restarting a service reseeds it. The seed scripts are the
single source of demo data; UIs and scenarios must not depend on hand-entered state.
