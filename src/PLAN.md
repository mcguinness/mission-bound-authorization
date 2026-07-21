# Mission Reference Implementation Plan

Living document. Tracks the plan, the decisions made with their rationale, and the
open/resolved issue log for an end-to-end reference implementation of the Mission
family at the **Runtime-Enforced** assurance level.

- Location: all implementation code lives under `src/` in this repo.
- Language: TypeScript (Node 22+), pnpm workspaces.
- Maintenance: this document is updated by direct commits to `main` (no PRs),
  per the 2026-07-20 workflow decision. Implementation milestones still land
  as their own PRs (see § Milestones).
- Last updated: 2026-07-20.

## 1. Goal and Conformance Target

Build a complete, running system that reaches **Runtime-Enforced Mission conformance**
as defined by the six invariants in `draft-mcguinness-mission-architecture.md`
(§ Runtime-Enforced Mission conformance): the four Baseline invariants plus
per-action runtime enforcement and evidence that joins.

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
| AuthZEN ARAP (external, OpenID) | Access request / approval lifecycle behind requestable denials |
| AuthZEN AROP (external, openid/authzen PR #531) | Token-issuance completion: DTR and Transaction Challenge bindings |

Out of scope for the first pass: signals (SSF push), harness session binding
(only the minimal stop-on-non-active duty is in scope),
child delegation (Child Missions; token-level actor chains ARE in scope),
metering, mandate, CIBA binding, and the actor suite companions (receipts,
proofs, authority bounds).
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
| D6 | AROP x Mission composition | Both completion modes, demoed separately: runtime PEP denials resolve via ARAP `reevaluate` (approval is input context, PDP stays authoritative); token-endpoint and challenge denials resolve via AROP token issuance backed by a Mission Expansion (successor mission), so issuance never bypasses per-action enforcement |
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
| D20 | Sub-agent delegation demo | Orchestrator to sub-agent token exchange is a first-class scenario (13) and milestone (M12): authority narrows by subset, the chain grows a hop, the PDP sees the root-to-leaf `context.actor.act` |
| D21 | act.cnf stance | The `act.cnf` conflict is filed upstream (actor-profile issue #4); this implementation validates proof of possession against the top-level `cnf` only and treats `act.cnf` as informative |
| D22 | Handbook alignment | From the handbook-cover review: Shaper (shaping draft) in scope with the compromised-shaper test; minimal harness stop-on-non-active with the 02:00-resume scenario; five-laws mapping table; vendor-test demonstration + Field Reference checklist in M9; mission-scoped `tools/list`; wire-exhibit mode; control-plane framing. Declined: consent evidence remains undecided (O-11 stays open) |

Defaults adopted (not separately asked; flag if wrong):

- pnpm workspace monorepo under `src/`; TypeScript everywhere; Node 22+.
- OpenFGA runs via docker compose in its in-memory storage mode; our PDP fronts it.
- Freshness sources: Status polling + issuer introspection. Signals push is a stretch goal.
- All service state in in-memory stores (Maps); seed scripts load data on boot.
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
| (SPA) +  |    | provider +    |    | Request Svc   |    | + materialized |
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

```
```

Trust-base components and their spec roles:

- **Mission AS** (`services/authorization-server`): Mission Issuer. Owns intent intake
  (PAR), derivation to `mission_resource_access` authorization_details, the approval
  event, Mission Records with integrity anchors, mission-bound token issuance (DPoP),
  the subset rule, state-gated issuance/refresh, revocation by `mission_id`,
  introspection with the `mission` member, the signed Status endpoint, the DTR
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
  client_instance`, `ai_agent_instance_profile_supported` metadata).
- **PDP** (`services/pdp`): AuthZEN Access Evaluation (and bulk Evaluations) API.
  Materializes each approved Mission into an OpenFGA tuple set (the materialized
  policy view, correlated by `policy_view_id`), layers the mission overlay checks
  that FGA does not model (state freshness against the staleness bound, parameter
  binding, permit/lease issuance, expiry), and emits requestable denials with
  `context.access_request` and a PDP-signed `binding_token`. Builds
  `context.actor` by flattening the token's nested `act` chain into the
  root-to-leaf array via `packages/actor-chain`.
- **ARS** (`services/access-request`): ARAP Access Request Service. Verifies
  `binding_token` denial bindings, runs the approval task lifecycle, exposes the
  adjudication queue the approver app consumes.
- **MCP Payments Server** (`services/mcp-payments`): the resource server and PEP.
  Streamable-HTTP MCP server exposing the AP tools; validates DPoP-bound access
  tokens and the `mission` claim; obtains a PDP permit for every consequential
  action with parameter binding and capability source context; runs the
  transaction-assurance tier for the wire transfer (single-use permit, execution
  lease, Execution Evidence, outcome reconciliation); signs Transaction
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
  per-mission feeds (`sub` is the Mission). The AS, PDP, and MCP server
  register their evidence; a CLI verifier and the operator app's audit view
  run the draft's five-step offline verification.
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
  attempting any action.
- **Apps** (`apps/approver`, `apps/operator`, `apps/agent-console`): persona UIs.

Cross-cutting: every service adopts `packages/telemetry` (OpenTelemetry with
W3C trace context propagated across OAuth requests, PDP evaluations, MCP tool
calls, and evidence registrations, exported to Jaeger; pino structured logs
carrying `trace_id` and `mission_id`). Evidence objects carry the producing
span's `trace_id` as an extension member (decision D13).

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
On mission approval the PDP writes tuples deriving from the `authority_set`
(for example `mission:m1#payer@invoice:inv-42`, `mission:m1#reader@vendor:acme`).
Numeric constraints (per-payment cap, cumulative caps) are evaluated with FGA
conditions where they fit and in the PDP overlay where they do not; see issue O-6.
Revocation and completion delete or bypass the view (state check precedes FGA).

### End-to-end scenarios (the demo script)

0. **Discovery bootstrap**: agent signs in, reads `service_catalog_endpoint`
   from the AS metadata, makes a scoped catalog request (`type=mcp` plus a
   category/tag filter), selects the payments server, re-anchors trust via the
   server's protected resource metadata, and reads its Server Card before
   shaping intent. With no mission yet, the connection reports
   `consent_required`.
1. **Issuance**: the shaper proposes intent (untrusted input per the shaping
   draft), the agent submits it via PAR, the issuer derives the authority,
   Alice approves in the approver app (intent + authority set + anchors
   rendered), mission-bound DPoP token issued; operator app shows the new
   Mission. Includes the compromised-shaper test: an over-broad proposal
   never widens the derived authority.
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
8. **Revocation freshness**: operator revokes mid-mission; next action denied
   within the published staleness bound; issuance/refresh also gated.
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

The handbook's five laws map onto the build as follows; the M9
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
    telemetry/                shared OTel + pino setup (trace context, ids)
    actor-chain/              act-chain validation + nested-to-root-to-leaf
                              flattening, shared by AS, PDP, and PEPs
  services/
    authorization-server/     node-oidc-provider + mission layer
    pdp/                      AuthZEN PDP + OpenFGA integration
    access-request/           ARAP ARS
    mcp-payments/             MCP server + RS/PEP + payments API + ledger
    ras/                      SaaS-domain Resource AS (node-oidc-provider,
                              JWT-bearer ID-JAG redemption)
    mcp-saas/                 LedgerCloud SaaS MCP server (token-only
                              enforcement, EMA declared)
    transparency/             SCITT Transparency Service (audit draft)
    agent/                    OAuth+MCP client, scenario runner, LLM loop
  apps/
    approver/                 approvals inbox (missions, ARAP tasks, deferred queue)
    operator/                 fleet dashboard, evidence timeline, status controls
    agent-console/            chat + scenario runner UI, live token/mission state
```

Port map (defaults, overridable via `.env`): AS 4400, PDP 4401, ARS 4402,
MCP/payments 4403, transparency 4404, RAS 4405, SaaS MCP 4406, approver 5173,
operator 5174, agent-console 5175, OpenFGA 8080 (http) / 8081 (grpc),
playground disabled, Jaeger 16686 (UI) / 4317 (OTLP).

## 5. Milestones

Each milestone lands as its own PR with tests; acceptance criteria are the exit bar.

- **M0. Scaffolding.** Workspace, tsconfig, lint, docker-compose (OpenFGA +
  Jaeger), `packages/telemetry` (the OTel + pino baseline every service
  adopts), `mission-core` with canonicalization + anchors passing the core
  test vectors (`draft-mcguinness-oauth-mission` § test vectors).
  *Exit: `pnpm test` green on anchor vectors; `docker compose up` serves
  OpenFGA and Jaeger; a sample service's span is visible in Jaeger.*
- **M1. Baseline Issuance AS.** PAR intent intake, derivation, approval event
  (minimal approver page), Mission Record store, `mission` claim + DPoP binding,
  subset rule, state-gated issuance/refresh, revocation by `mission_id`,
  introspection `mission` member, signed Status endpoint, AS metadata flags.
  *Exit: core conformance checklist items 1-6 (core § Conformance) demonstrably met;
  scenario 1 runs headless, including the compromised-shaper test.*
- **M2. PDP + OpenFGA.** AuthZEN evaluation + evaluations endpoints, envelope
  parsing (note: approved-entry `resource` matches `context.audience`, not the
  AuthZEN `resource` member), materialized policy view with `policy_view_id`,
  FGA model + tuple writer keyed to mission lifecycle, freshness via Status
  polling + introspection with a published staleness bound.
  *Exit: golden-file decision tests: in-authority allow, out-of-authority deny,
  revoked-mission deny within bound.*
- **M3. MCP server + core enforcement tier.** AP tools, streamable HTTP, RFC 9728
  PRM, token + `mission` claim validation, per-action PDP calls with
  `context.mission` / `context.actor` / `context.audience` / `parameter_digest` /
  `context.capability_source` (tool_id `mcp://` URI, source_uri, source_digest,
  operation_ref), mission-scoped `tools/list` filtering (least exposure),
  Decision Evidence and Refusal Records, Enforcement Scope Statement
  published.
  *Exit: scenarios 2 and 3 pass as integration tests.*
- **M4. Transaction-assurance tier.** Single-use permits, execution leases,
  Execution Evidence, outcome reconciliation for `execute_wire_transfer` and
  `send_remittance_email`.
  *Exit: scenario 4; replayed permit is refused; reconciliation report joins
  evidence to ledger entries.*
- **M5. ARAP reevaluate mode.** Requestable denials from the PDP
  (`context.access_request` + PDP-signed `binding_token`), ARS task lifecycle,
  approver adjudication UI, PEP re-evaluation with `context.approval`.
  *Exit: scenario 5; approval is provably input context (no token change).*
- **M6. AROP.** DTR custom grant (`completion_mode=deferred`, `deferral_code`,
  deferred grant polling, idempotent submission, approval-bounded lifetime) and
  Transaction Challenge (RS challenge signing + `txn_challenge_jwks_uri`, AS
  `transaction_authorization_endpoint`, txn-bound audience-restricted single-use
  token, re-presentation checks), both completing through Mission Expansion.
  *Exit: scenarios 6 and 7; issued tokens never broaden the originating request
  and never outlive `approved_until`.*
- **M7. Service connectivity discovery.** Catalog Provider co-located in the
  AS: Service Catalog Endpoint with filtering (`category`, `type`, `status`,
  `profile`, `tag`), `service_catalog_endpoint` in AS metadata, entries seeded
  from demo-data, mission-derived per-connection `status`, `request-access`
  links into the ARS, and the payments server's Server Card published and
  referenced via `server_card_uri`.
  *Exit: scenarios 0 and 10 pass headless; catalog status flips on approval,
  revocation, and expansion without restart.*
- **M8. Full UX.** The three persona apps complete: approvals inbox with intent
  rendering, fleet dashboard with revoke/expand and status transitions, evidence
  timeline joining decisions, executions, refusals, and reconciliation, and the
  agent console's discovery/catalog view.
  *Exit: scenarios 0-10 all runnable from the UIs alone.*
- **M9. Agent + demos + conformance.** Scenario runner covering scenarios 0-10
  and 14 (the 02:00 resume), the minimal harness duty in the agent (Status
  check on resume, stop on non-active), optional LLM chat mode, seed polish,
  a `pnpm demo` one-command boot, an exhibit mode emitting annotated wire
  captures shaped like the handbook's Appendix B, and a written
  self-assessment against the six Runtime-Enforced invariants, the handbook
  vendor test's six questions, and the Field Reference implementation
  checklist. `pnpm demo:vendor-test` runs the four valid-token-but-denied
  cases back to back (state: scenario 8, bounds: 7, parameters: 3,
  delegation chain: 13).
  *Exit: fresh clone to full demo in under five minutes; self-assessments
  complete; the vendor-test demo passes.*
- **M10. Transparent audit (SCITT).** Transparency Service per the audit
  draft: in-memory append-only Merkle log, COSE Signed Statements with
  hash-envelope commitments, Receipts and signed tree heads; registration
  hooks in the AS, PDP, and MCP server for every evidence type the draft
  fixes; per-mission feed retrieval; CLI verifier plus an operator app audit
  view running the five-step offline check; `trace_id` extension member on
  evidence.
  *Exit: scenario 11 passes headless, including the tamper demo (mutated
  evidence fails digest verification, a dropped record fails inclusion);
  scenario runner adds scenario 11.*
- **M11. Cross-domain SaaS leg (EMA + ID-JAG).** Second trust domain per the
  cross-domain companion: Mission AS token-exchange issuance of the
  cross-domain grant with audience-scoped projection; RAS (second
  node-oidc-provider) with the JWT-bearer redemption grant, PoP and
  single-use validation, mission-preserving local tokens; LedgerCloud SaaS
  MCP server with EMA declared, enforcing from the token alone; catalog
  entry with the `id_jag` connection; agent EMA capability and flow.
  *Exit: scenario 12 passes headless, including grant replay rejection and
  the revocation-lease demonstration; scenario runner adds scenario 12.*
- **M12. Actor profile + agent instance (delegation).** Base actor-profile
  conformance at the AS (chain construction/validation, presenter
  transitions, local max depth, errors, metadata, introspection) with
  `packages/actor-chain` shared by AS, PDP, and PEPs; full ai-agent-instance
  profile (per-instance keys, Client Instance Assertion carrier validation,
  instance claims, metadata flags); PDP `context.actor` flattening;
  per-instance PEP controls; orchestrator/sub-agent support in the agent
  service.
  *Exit: scenario 13 passes headless, including per-instance revocation and
  a rejection test for an `actor_token` that itself carries `act`; scenario
  runner adds scenario 13.*

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

- **O-1. Mission Intent PAR carriage.** Pin the exact request shape from core
  § submission-via-PAR (parameter name, JSON shape, interaction with RAR
  `authorization_details`) before M1 endpoint work.
- **O-2. node-oidc-provider feature fit.** Verify the installed major supports
  RAR (`features.richAuthorizationRequests`) with custom type validation strong
  enough for `mission_resource_access` derivation, and confirm the extension
  points for a token-exchange custom grant and the DTR deferred grant alongside
  DPoP. Fallback: thin custom endpoints beside the provider for the gaps.
- **O-3. DTR draft fidelity.** Fetch `draft-gerber-oauth-deferred-token-response`
  and pin parameter names, error codes (`authorization_pending`, `slow_down`,
  `expired_token`), and the deferred grant URN before M6.
- **O-4. Transaction challenge draft fidelity.** Fetch
  `draft-rosomakho-oauth-txn-challenge` and pin the challenge JWS claims
  (`txn`, `authorization_details`, `iss`, `aud`, `reason`), the
  `Accept-Txn-Challenge` header, endpoint request/response shapes, and
  `txn_challenge_jwks_uri` metadata before M6.
- **O-5. Expansion lifecycle detail.** Read the expansion draft closely: successor
  mission state transitions, predecessor disposition, and how the AROP-issued
  token's `mission` claim references the successor. Needed for M6.
- **O-6. Where numeric constraints live.** Per-payment cap and cumulative caps:
  FGA conditions vs PDP overlay. Decide during M2 with a spike; record the
  rationale here.
- **O-7. `policy_view_id` scheme.** Content-addressing recipe (what exactly is
  hashed: model version + tuple set + mission version?). Decide in M2.
- **O-8. Staleness bounds for the demo.** Concrete published bounds per action
  class, and which freshness source is authoritative for the high-consequence
  class (Status poll interval vs introspection-on-action). Decide in M2/M3.
- **O-9. COAZ alignment.** mission-authzen composes with COAZ for MCP tool
  mapping. Decide whether to fetch COAZ and mirror its subject/action/resource
  mapping or keep the profile's own `context.capability_source` members only.
- **O-10. ARAP draft fidelity.** Fetch the ARAP profile itself (access request
  submission shape, task states, `approval` object, `approved_until`,
  `binding_token` verification rules) before M5.
- **O-11. Consent Evidence scope.** The approver app renders intent at approval;
  decide whether to include `consent_rendering_hash` + signed Consent Evidence
  (companion draft) in M8 or defer.
- **O-12. Mission-derived status mapping.** Exact mapping from mission
  lifecycle states (and issuance feasibility) to `connected` / `available` /
  `consent_required` / `unavailable`, and how the catalog decides a mission
  "covers" a service. Decide in M7.
- **O-13. MCP Server Card shape.** Which Server Card format/location the
  payments server publishes for `server_card_uri`, and whether the capability
  source `source_digest` (mission-authzen § capability source) is computed
  over the same card. Decide in M3, revisit in M7.
- **O-14. Catalog vocabulary for the AP domain.** The category registry seeds
  email/calendar/files/etc.; payments is not seeded. Namespaced category vs
  `tags` for the demo services. Decide in M7.
- **O-15. request-access intake shape.** What the `request-access` href
  carries (service id, requested capability, return URI) and whether an
  adjudicated request materializes as a first mission issuance or as an
  Expansion. Decide alongside M5, wire in M7.
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
  Decide in M3.
- **O-19. ID-JAG draft fidelity.** Fetch
  `draft-ietf-oauth-identity-assertion-authz-grant` and pin the token
  exchange request parameters, the grant JWT claims, and how the
  cross-domain companion's proof-of-possession and single-use floors attach
  to it. Before M11.
- **O-20. EMA metadata surface.** Pin exactly how the SaaS MCP server
  "declares the extension in its authorization metadata" (member name and
  shape); the extension is young, so track the MCP spec revision we
  implement against. Before M11.
- **O-21. Catalog status for id_jag connections.** The mission-derived
  `status` mapping (O-12) assumed the internal domain; for the SaaS service
  it also depends on issuer-side projection policy. Extend the mapping.
  Decide in M11.
- **O-22. Audience-scoped projection derivation.** How the Mission AS
  decides which Authority Set entries a given RAS is authoritative for
  (the resource-to-AS mapping seed), per cross-domain § audience-scope.
  Decide in M11.
- **O-23. SaaS-side audit registration.** Whether the RAS registers grant
  redemptions in our Transparency Service (cross-domain producers) or the
  audit feed stays internal-side only, with the revocation lease documented
  in the demo. Decide in M10/M11.
- **O-24. act.cnf semantics.** Filed upstream as actor-profile issue #4
  (github.com/mcguinness/draft-mcguinness-oauth-actor-profile/issues/4):
  base profile leaves `act.cnf` semantics undefined, receipts prohibit it in
  receipt hops, agent-instance examples duplicate the top-level `cnf.jkt`
  inside `act`. Our stance until resolved: PoP against top-level `cnf` only,
  `act.cnf` informative (D21). Revisit when the upstream issue closes.
- **O-25. CIA-CORE fidelity.** Read the local
  `draft-mcguinness-oauth-client-instance-assertion` checkout and pin the
  carrier header/`typ` values, token endpoint processing, chain merging, and
  introspection members the instance profile inherits. Before M12.
- **O-26. Entity-profile vocabulary.** Pin the `sub_profile` values
  (`ai_agent`, `client_instance`) against the referenced
  `draft-mora-oauth-entity-profiles` revision. Before M12.
- **O-27. Chain depth and rebind policy.** The demo's local max chain depth
  (the profile says SHOULD support >= 4) and which hops use presenter
  continuation vs rebind. Decide in M12.
- **O-28. Appendix B exhibit fidelity.** Fetch the handbook's wire appendix
  and pin the exhibit format the scenario runner's exhibit mode emits, so
  captures are comparable to the published exhibits. Before M9.
- **O-29. Resume-check semantics.** Which non-active states stop vs pause
  the agent's harness check, and the check cadence on wake, consistent with
  the published staleness bounds (O-8). Decide in M9.

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

## 8. Runbook (target state)

```
cp src/.env.example src/.env        # optionally add ANTHROPIC_API_KEY
docker compose -f src/docker-compose.yml up -d   # OpenFGA, in-memory
pnpm -C src install
pnpm -C src seed                    # load users/clients/vendors/invoices + FGA model
pnpm -C src dev                     # AS, PDP, ARS, MCP server, three SPAs
pnpm -C src demo                    # scripted scenarios 0-14 against the running stack
pnpm -C src demo:vendor-test        # the four valid-token-but-denied cases
```

All state is in memory: restarting a service reseeds it. The seed scripts are the
single source of demo data; UIs and scenarios must not depend on hand-entered state.
