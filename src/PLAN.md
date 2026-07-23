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
| M13 Evals | **in progress** |
| M14 Conformance + reports | not started |

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
- **O-4. Transaction challenge draft fidelity.** Fetch
  `draft-rosomakho-oauth-txn-challenge` and pin the challenge JWS claims
  (`txn`, `authorization_details`, `iss`, `aud`, `reason`), the
  `Accept-Txn-Challenge` header, endpoint request/response shapes, and
  `txn_challenge_jwks_uri` metadata before M7.
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
- **O-30. Eval taxonomy and pass bars.** Pin the misbehavior-class taxonomy
  (drawing on the handbook's Testing chapter framings, including the lethal
  trifecta), the over-blocking threshold for the legitimate suite, and
  which scorecard metrics gate CI vs merely report. Decide in M13.
- **O-31. Red-team eval methodology.** How the LLM adversary is prompted
  and seeded, how nondeterministic runs stay comparable (persisted
  transcripts as replayable fixtures), and how red-team findings feed new
  deterministic cases. Decide in M13.
- **O-32. Management companion subset.** Pin which of the management
  draft's surfaces the operator app consumes (fleet enumeration,
  per-mission lifecycle operations; bulk operations if needed) and how the
  operator app authenticates to them. Decide in M11.
- **O-33. MCP TS SDK gaps.** Pin the `@modelcontextprotocol/sdk` version;
  Server Card publication and EMA declarations are not SDK-supported and
  are hand-rolled. Track SDK evolution and replace hand-rolled pieces when
  the SDK catches up. SDK pinned at 1.29.0 by the spike; gap tracking
  remains. Revisit in M4.
- **O-34. Status List mechanics.** Pin the Mission Status List
  implementation details per the companion § status-list and
  `draft-ietf-oauth-status-list`: 2-bit entries, compression, list token
  shape and `ttl`, anti-oracle index allocation, republication on
  transition, and library vs hand-roll. Decide in M3.
- **O-35. Introspection projection details.** Pin the introspection mission
  projection (status draft § introspection-projection): the `mission`
  member's contents, how the PDP authenticates as a caller, and how the
  observation is recorded in Decision Evidence. Before M3.

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
`open` → `filed` (upstream issue opened), `fixed-in-spec`, or `accepted`
(complexity acknowledged and kept, with the rationale recorded). Entries are
never deleted.

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
- **S-3 (open).** Ambiguity — mission-authzen x AROP: the companion says an
  ARAP approval is input context, never a bearer grant, while AROP completes
  by token issuance; the composition only closes through Expansion (our D6),
  and neither document names it. Candidate: companion note plus upstream
  AROP feedback once the implementation confirms the shape.
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
