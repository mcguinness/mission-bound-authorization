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
| `draft-mcguinness-svc-connectivity-disco` (external repo) | Resource discovery: the per-user service connectivity catalog the agent bootstraps from |
| `draft-mcguinness-mission-audit` | SCITT transparency for Mission evidence: Signed Statements, Receipts, per-mission feeds, offline verification |
| AuthZEN ARAP (external, OpenID) | Access request / approval lifecycle behind requestable denials |
| AuthZEN AROP (external, openid/authzen PR #531) | Token-issuance completion: DTR and Transaction Challenge bindings |

Out of scope for the first pass: signals (SSF push), harness session binding,
child delegation, metering, cross-domain, mandate, CIBA binding.
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

Defaults adopted (not separately asked; flag if wrong):

- pnpm workspace monorepo under `src/`; TypeScript everywhere; Node 22+.
- OpenFGA runs via docker compose in its in-memory storage mode; our PDP fronts it.
- Freshness sources: Status polling + issuer introspection. Signals push is a stretch goal.
- All service state in in-memory stores (Maps); seed scripts load data on boot.
- Web apps: React + Vite SPAs.

## 3. Architecture

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
registers evidence with, and the telemetry plane (OTel collector view in
Jaeger).

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
  and `request-access` links into the ARS.
- **PDP** (`services/pdp`): AuthZEN Access Evaluation (and bulk Evaluations) API.
  Materializes each approved Mission into an OpenFGA tuple set (the materialized
  policy view, correlated by `policy_view_id`), layers the mission overlay checks
  that FGA does not model (state freshness against the staleness bound, parameter
  binding, permit/lease issuance, expiry), and emits requestable denials with
  `context.access_request` and a PDP-signed `binding_token`.
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
  Scope Statement.
- **Transparency Service** (`services/transparency`): the audit draft's SCITT
  Transparency Service, in memory: append-only Merkle log, COSE Signed
  Statements committed by hash envelope, Receipts and signed tree heads,
  per-mission feeds (`sub` is the Mission). The AS, PDP, and MCP server
  register their evidence; a CLI verifier and the operator app's audit view
  run the draft's five-step offline verification.
- **Agent** (`services/agent`): OAuth client built on panva `openid-client`
  (PAR + DPoP + token exchange), MCP client, scripted scenario runner, optional
  LLM loop.
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
payment cap; a payments ledger for reconciliation. The catalog seeds two
services: the payments MCP server and an out-of-reach `hr-files` service (no
authority path for `alice`) whose entry carries a `request-access` link into
the ARS.

Tools on the MCP server (action classification per runtime § action classification floor):

| Tool | Class | Enforcement tier |
|---|---|---|
| `list_invoices`, `get_invoice`, `lookup_vendor` | read | core tier |
| `schedule_payment` | consequential, reversible | core tier |
| `execute_wire_transfer` | high-consequence, irreversible | transaction-assurance tier |
| `send_remittance_email` | external communication | transaction-assurance tier |

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
1. **Issuance**: agent shapes intent, submits via PAR, Alice approves in the
   approver app (intent + authority set + anchors rendered), mission-bound
   DPoP token issued; operator app shows the new Mission.
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
  services/
    authorization-server/     node-oidc-provider + mission layer
    pdp/                      AuthZEN PDP + OpenFGA integration
    access-request/           ARAP ARS
    mcp-payments/             MCP server + RS/PEP + payments API + ledger
    transparency/             SCITT Transparency Service (audit draft)
    agent/                    OAuth+MCP client, scenario runner, LLM loop
  apps/
    approver/                 approvals inbox (missions, ARAP tasks, deferred queue)
    operator/                 fleet dashboard, evidence timeline, status controls
    agent-console/            chat + scenario runner UI, live token/mission state
```

Port map (defaults, overridable via `.env`): AS 4400, PDP 4401, ARS 4402,
MCP/payments 4403, transparency 4404, approver 5173, operator 5174,
agent-console 5175, OpenFGA 8080 (http) / 8081 (grpc), playground disabled,
Jaeger 16686 (UI) / 4317 (OTLP).

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
  scenario 1 runs headless.*
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
  operation_ref), Decision Evidence and Refusal Records, Enforcement Scope
  Statement published.
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
- **M9. Agent + demos + conformance.** Scenario runner covering scenarios 0-10,
  optional LLM chat mode, seed polish, a `pnpm demo` one-command boot, and a
  written self-assessment against the six Runtime-Enforced invariants.
  *Exit: fresh clone to full demo in under five minutes; self-assessment complete.*
- **M10. Transparent audit (SCITT).** Transparency Service per the audit
  draft: in-memory append-only Merkle log, COSE Signed Statements with
  hash-envelope commitments, Receipts and signed tree heads; registration
  hooks in the AS, PDP, and MCP server for every evidence type the draft
  fixes; per-mission feed retrieval; CLI verifier plus an operator app audit
  view running the five-step offline check; `trace_id` extension member on
  evidence.
  *Exit: scenario 11 passes headless, including the tamper demo (mutated
  evidence fails digest verification, a dropped record fails inclusion);
  scenario runner extended to 0-11.*

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

## 8. Runbook (target state)

```
cp src/.env.example src/.env        # optionally add ANTHROPIC_API_KEY
docker compose -f src/docker-compose.yml up -d   # OpenFGA, in-memory
pnpm -C src install
pnpm -C src seed                    # load users/clients/vendors/invoices + FGA model
pnpm -C src dev                     # AS, PDP, ARS, MCP server, three SPAs
pnpm -C src demo                    # scripted scenarios 0-11 against the running stack
```

All state is in memory: restarting a service reseeds it. The seed scripts are the
single source of demo data; UIs and scenarios must not depend on hand-entered state.
