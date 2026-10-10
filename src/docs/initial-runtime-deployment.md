# Initial runtime reference deployment

The deployment contract for the first runtime reference target that #253
adopted (D284, 2026-10-03): the **AS-native payments composition**. It is the
issuance-only floor of [issuance-only-deployment.md](issuance-only-deployment.md)
(#873) plus a runtime overlay: the `mcp-payments` Policy Enforcement Point
(PEP) and the reference Policy Decision Point (PDP) deciding each mediated
action, and the AS's `transaction-authorization` capability for the
remittance approval (D332, §2). This document records the runtime delta only; every floor fact is
stated once, in the floor's document.

The selection is adopted. The evidence is not yet established: this contract
states what D284 requires, what the reference does at this revision, and
which open issue owns each gap. Selection is not a conformance,
production-readiness or interoperability claim (D284 ruling 1).

Every behavioral statement is true of the reference implementation read at
origin/main `e9001b2f`, and each statement about the as-native target and its
launcher (#1105), or naming a later merged issue (such as #1103 or #1104), at
`583e3806`. Each cites the function (`file:line`, read at
`583e3806`, paths relative to `src/`) or the exact test (`describe > it`)
that shows it. A path with no
witnessing test says "no test yet". Tests marked [FGA] are skipped without a
live OpenFGA, so a local run can pass where CI with OpenFGA fails, or the
reverse. The claim-to-evidence detail for this composition is
[runtime-enforced-assessment.md](runtime-enforced-assessment.md). It is
commit-bound at `a90a25c8` and partly superseded (its §9 lists which
statements); where the two differ, this document is current.

The abstract Mission substrate supplies no common token format and no
authority vocabulary. Everything below is the OAuth binding's realization:
Mission-bound OAuth access tokens and `mission_resource_access` entries.

## 1. Selection and claims

What is adopted (D284):

- **First target:** AS-native payments on #873's issuance floor, one issuer
  and one trust domain.
- **Second target:** the legacy-estate/MAS route, owned by #818, with its own
  independently pinned evidence. Nothing here validates it, and passing this
  target's acceptance proves nothing about it.
- **Limits:** per-action limits only, including `max_amount`. No Mission-wide,
  lineage-wide or other aggregate cap. #816 is parked until a named deployment
  adopts a total-cap promise.
- **Not waiting on #249 or #210:** the payments Operation Profile
  ([operation-profile-payments-v1.md](operation-profile-payments-v1.md)) is
  this target's resource contract.
- **State source (D293):** the declared local committed read is accepted for
  this co-located target (§4). #1101 owns a separated realization.

What the reference asserts: nothing named. The published Enforcement Scope
Statement (`config/enforcement-scope.json`) has no `claims` member, so it
declares scope and claims no named extension (`EnforcementScopeStatement.claims`,
`services/pdp/src/enforcement-scope.ts`). It declares, without claiming,
`transaction_assurance` for `irreversible_action` and `external_commitment`,
`reversible_write_idempotency` (the key control for `payments:payment.schedule`
and `payments:payment.schedule.cancel`, and the single-use default for the
`consequential_write` class), and `outcome_reconciliation` (PT15M).
`custody`, `evidence` and `high_assurance_agent` are absent.

Excluded from this target (D284 ruling 5): aggregate-budget enforcement,
compromise containment, and any unattended prohibited-class exception. #813
keeps its own ruling; #820 and #424 stay parked.

Required, not excluded: token authority (#825) and independently
administered Resource policy (#828) belong to the adopted policy conjunction.
Neither is met (§5): token authority is enforced at the PEP but not yet at
the PDP, and Resource policy is not implemented. Under D284 ruling 4 they are acceptance prerequisites,
so this target cannot pass acceptance while either is missing.

## 2. Dimension contract

| Dimension | Adopted (D284, D293) | Reference at `e9001b2f` (citations read at `583e3806`) | Status | Gap owner |
|---|---|---|---|---|
| Topology | One configured issuer and trust domain; trusted Approver resolver, PEP, PDP and Resource; no implied federation | One process. `pnpm as-native` (§11) runs `composeStack({ target: "as-native" })` (`demo/src/stack.ts:248`): the AS on 4400 (issuer `http://localhost:4400`, `stack.ts:374-376`) with the D332 capability set below, the PEP `mcp-payments-pep` (`stack.ts:869-871`) served over HTTP MCP at the resource audience `http://localhost:4403/mcp` (`services/mcp-payments/src/pep.ts:77`), the PDP (`stack.ts:695`), OpenFGA, and the in-process approval service: `the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > mounts no MAS join route and serves the HTTP MCP endpoint at exactly the declared resource audience`. The AS JWKS is fetched once at assembly (`stack.ts:497`) | Partial | JWKS reload: #831 |
| Binding | OAuth Mission-bound issuance, Runtime OAuth and AuthZEN; MAS join only in its separately declared path | Runtime OAuth credential validation over HTTP MCP, with a DPoP proof verified on every request, and the AuthZEN request (§4, §5). The in-process mediated channel is outside this target (D315). The PDP is a direct call by default with no PEP authentication (`services/pdp/src/decision-channel.ts:56-61`); `MISSION_PDP_MODE=remote` adds a loopback HTTP hop keyed by a per-boot secret that is never configured, so it cannot cross processes as shipped (`decision-channel.ts:64-66`). `config/mas-join.json` names the payments resource governed, and the shared demo mounts a MAS join route there; the target mounts none, and a configuration that would mount one fails startup: `the as-native target excludes the MAS join route at startup (D315) > fails startup, before connecting to anything, when the payments resource is configured governed` | HTTP entry point only (D315) | #818 owns MAS; #956 Q2 its declaration in the shared demo |
| Operations | Enumerated payments operations, authority types, classes, phases and parameter binding; refuse outside the allowlist | Nine tools, all classed (§3). An unknown tool is refused `unknown_tool` before any PDP call (`pep.ts:1186`). Arguments outside a tool's served schema are refused `invalid_request` before any PDP call (§3) | Partial | None open: `hold_transfer`'s control is implemented (§3); #1106 is closed |
| State | For this co-located target, the declared local committed read (D293 narrows D284's "authoritative Status"); per-class staleness, skew, permit and execution bounds; source ownership and unavailable behavior | The PEP and PDP read the AS kernel's committed record in process (`loadView`, `stack.ts:828-835`; the statement's state source is `kernel-committed load_view`, placement `pep`). That is the authoritative record behind Status, but it is not the Mission Status operation, introspection or Signals. Bounds and fail-closed behavior: §4 | Source accepted (D293); one unavailable-state witness missing (§4) | Separated PEP or PDP: #1101, which gates only a separated-deployment claim |
| Policy | Conjunction of token authority, current effective Mission authority and independently administered Resource policy | Current effective Mission authority is enforced and tested. Token authority is enforced at the PEP only: an action outside the verified token's own `authorization_details` is refused before the PDP, which does not evaluate it. Independent Resource policy is not implemented (§5) | Required, not met: blocks acceptance | Token authority: #825 (PR 1 merged as #1062; PRs 2a to 2c remain, D312). Resource policy: #828 |
| Evidence | Runtime/Decision Base and explicitly enabled evidence capabilities; emitters, verifiers, retention, failure carriers; missing telemetry is `indeterminate` | Decision Evidence, Refusal Records and Execution Evidence (§6). The `evidence` extension is not enabled, so there is no receipt issuer | Partial | none: the running reconciler settles a reported emission gap from the ledger (§7) |
| Persistence | Every store, its transaction or acceptance boundary, and restart and reconciliation behavior | Only the PDP claim domain and the PEP write reservations are durable files; every other store is in memory (§7). The declared reconciler runs in the launched PEP process; a restarted process cannot reconcile a prior one's claims, a stated bound (§7) | Partial | #250, #831 |
| Claims | Per-action limits only; execution and transaction handling for applicable operations; no aggregate cap, compromise containment or unattended prohibited-class exception | §8 | Partial | §8 |

**AS capability set (D332).** The target extends the issuance-only floor
for the remittance approval flow. Its AS runs the always-on issuance profile
plus exactly `lifecycle-revoke`, the floor's one capability, and
`transaction-authorization`, where the remittance action-bound approval is
redeemed (`AS_NATIVE_CAPABILITIES`, `demo/src/stack.ts:97-100`). The AS
reports the set it was built with and whether it armed dev ordinary issuance
(`BuiltAs.devOrdinaryIssuance` and `BuiltAs.capabilities`,
`services/authorization-server/src/index.ts:1231-1232`), and neither
`dev-token` nor dev ordinary issuance is on:
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > runs exactly the D332 AS capability set, the issuance profile plus lifecycle-revoke and transaction-authorization, and advertises only that surface`,
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > refuses a disabled optional surface with its standard error (token exchange, lifecycle suspend) while lifecycle revoke is served`
and
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > serves no dev ordinary-token route: the AS arms no dev ordinary issuance, and the route answers 501 temporarily_unavailable and mints nothing`.
Ordinary-token minting is test-only: `composeStack`'s
`testOrdinaryTokenMinting` option (`stack.ts:290`), which `pnpm as-native`
never sets and its launcher refuses (§11), turns on `dev-token` and dev
ordinary issuance for the baseline-Join refusal, and that composition proves
nothing about the target's enabled capabilities.

Every other optional capability is off and refuses with its standard error.
One probe per excluded capability, checked against `ALL_PROVIDER_CAPABILITIES`,
asserts each refusal and the absence of the metadata it would advertise:
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > refuses every optional AS capability outside the D332 set with its standard error: one probe for each of the 15, and no Mission touched`.

| Excluded capability | Refusal on the target |
|---|---|
| `async-delegation` | exchange with `request_refresh_token`: `unsupported_grant_type` (shared exchange-grant gate); no `delegated_refresh_token_profile_supported` |
| `child-delegation` | child-creation exchange: `unsupported_grant_type` (shared gate); the jwt-bearer grant is unregistered and refused; no `mission_child_delegation_supported` |
| `continuation` | ICA-to-ID-JAG exchange: `unsupported_grant_type` (shared gate); no `identity_continuation_supported` or `identity_chaining_requested_token_types_supported` |
| `cross-org` | Chain Presentation exchange: `unsupported_grant_type` (shared gate) |
| `expansion` | access-token exchange: `unsupported_grant_type` (shared gate); the exchange grant is unregistered |
| `deferred` | deferred grant: unregistered, `unsupported_grant_type` |
| `templates` | dispatch grant: unregistered, `unsupported_grant_type`; both template admin routes: 501 `temporarily_unavailable` |
| `containment` | lifecycle `contain`: `invalid_request`, not enabled; protected-event ingestion: 501 `temporarily_unavailable` |
| `discharge` | lifecycle `discharge`: `invalid_request`, not enabled; no `mission_status_signing_alg_values_supported` |
| `lifecycle-extended` | lifecycle `suspend`, `resume` and `complete`: `invalid_request`, not enabled |
| `status` | the Mission Status operation: 404, not served; no `mission_status_signing_alg_values_supported` |
| `status-list` | the Status List fetch: 404 `not_found` |
| `dev-token` | the dev ordinary-token route: 501 `temporarily_unavailable`, no token |
| `oidc` | `openid` at PAR: `invalid_scope`; userinfo and RP-initiated logout: 404; no `userinfo_endpoint` or `end_session_endpoint` |
| `token-revocation` | RFC 7009 revocation: 404; no `revocation_endpoint` |

The five token-exchange profiles share one gate: with none enabled the
exchange grant is not registered, so enabling any one of them changes all
five refusals. `status` and `discharge` share the signing-algorithm metadata
member, and each keeps its own refused surface. The dev route also needs dev
ordinary issuance, which is off, so the reported set and the dev-route test
above witness `dev-token` as well.

## 3. Operation allowlist

The operations are `TOOL_ACTIONS` (`services/mcp-payments/src/pep.ts:305-315`),
served from `config/tool-catalogs/payments.json`, with compound phases in
`config/catalog.json`. Every action carries a class the Enforcement Scope
Statement declares:
`every mediated crossing carries the class the deployment assigns it (@spec runtime#classification) > every Operation Profile entry carries an action class the Enforcement Scope Statement declares, and only the high-consequence classes take the transaction tier`.

| Tool | Action | Class | Phase | Path | Idempotency | Parameter binding |
|---|---|---|---|---|---|---|
| `list_invoices` | `payments:invoice.list` | `consequential_read` | | read | | list form |
| `get_invoice` | `payments:invoice.read` | `consequential_read` | | read | | invoice form |
| `lookup_vendor` | `payments:vendor.read` | `consequential_read` | | read | | none |
| `schedule_payment` | `payments:payment.schedule` | `consequential_write` | | keyed write | PEP reservation (#918) | invoice form |
| `cancel_scheduled_payment` | `payments:payment.schedule.cancel` | `consequential_write` | | keyed write | PEP reservation | invoice form |
| `check_transfer` | `payments:payment.execute` | `consequential_read` | preflight | read | | invoice form |
| `hold_transfer` | `payments:payment.execute` | `consequential_write` | prepare | unkeyed write | single-use permit, PEP-redeemed (#1080) | invoice form |
| `execute_wire_transfer` | `payments:payment.execute` | `irreversible_action` | commit | transaction | PDP claim (#917) | invoice form |
| `send_remittance_email` | `payments:remittance.send` | `external_commitment` | | transaction | PDP claim | invoice form |

- **Invoice form** (`buildEffectiveParams`, `services/mcp-payments/src/effective-params.ts:27-44`): `action`, `invoice_id`, `invoice_version`, `vendor_id`, `vendor_version`, `amount`, `payee_account` and `resource`, read from the payments store, not from arguments. **List form** (`:69-81`): `action`, `resource`, `vendor_scope`, `vendor_scope_source`.
- **Compound action:** one action and one digest serve three tools; the phase rides `context.action_phase` and is checked at every use: `compound-action phases (@spec runtime#compound-actions) > refuses a commit presenting prepare's permit, zero connector effects`.
- **Per-action limits** (`config/policy.json`): the read entry allows vendor `acme`; the write entry allows `max_amount` 500.00 USD and vendor `acme`. The PDP compares `max_amount` by exact decimal (`services/pdp/src/evaluate.ts:1426-1441`, refusal `parameter_violation`): `PDP per-action max_amount cap compares by exact decimal value (@spec mission#max-amount) > an amount exactly at the cap permits (the comparison is <=, not <)`, and [FGA] `M4 core enforcement tier > over-cap invoice denied parameter_violation`.
- **Action-bound approval:** `send_remittance_email` also requires an approval (`stack.ts:857-864`), refused `action_approval_required` otherwise: [FGA] `PDP decisions against OpenFGA (@spec authzen) > an approval past approved_until -> deny action_approval_required (ARAP)`. On this target the approval is redeemed at the AS transaction endpoint and the retry runs once under the transaction token over the HTTP endpoint: `the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > denies send_remittance_email with a transaction challenge, redeems the approval at the AS transaction endpoint, and executes the retry under the transaction token exactly once`. The challenge carries the Mission's committed entry narrowed to the gated action (`committedEntry`, D335; `services/mcp-payments/src/pep.ts:1703`), so no PDP-local member such as the loader's `join_delegation` rides it.
- **Outside the allowlist:** an unknown tool name is refused `unknown_tool` before any PDP call, with a Refusal Record carrying `request_unsupported` (`pep.ts:951-987`, `:1186`): `approval resolution is outside the mediated tool boundary (#759) > approval-resolution tool names refuse unknown_tool and retain one PEP Refusal Record`. That test calls the PEP directly; over the MCP channel, the signed `request_unsupported` is asserted beside intake's values, with no PDP call and no effect (added after `e9001b2f`): `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > the signed Refusal Record names request_invalid for arguments outside the schema, request_unsupported for an unknown tool and capability_source_unresolvable for an unreadable schema, each with no PDP call and no effect`. An ungranted known tool is hidden from `tools/list` and still refused if called: `a tool-catalog filter is not a substitute for the runtime gate (@spec runtime#pep-placement) > a tool absent from tools/list because it is ungranted is still refused by the runtime gate when called directly, never executed`.
- **Intake** (`Pep.intake` in `services/mcp-payments/src/pep.ts` and `admitArguments`, `services/mcp-payments/src/intake.ts:80-96`, both added after `e9001b2f`): `callReadTool`, `callWriteTool` and `callTransactionTool` NFC-normalize the arguments and validate them against the tool's served input schema, which is closed, before any decision work, then use the normalized object for target lookup, effective parameters and execution. An unknown or authoritative member, a missing required member, a non-string value or a pattern miss is refused `invalid_request` with no PDP call and one Refusal Record carrying `request_invalid` (D334), never `request_unsupported`, which names an unknown tool: `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > an argument member the served schema does not declare is refused invalid_request with no PDP call and one Refusal Record`, `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > an authoritative member (D34) is refused invalid_request with no PDP call and one Refusal Record` and `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > a missing required member, a non-string value and a pattern miss are refused invalid_request with no PDP call and one Refusal Record`. An intake refusal changes nothing on a read or either write path: no invoice, vendor or schedule, and no reservation or permit-consumption row: `an intake refusal leaves the business stores untouched on reads and both write paths (@spec operation-profile-payments-v1, #1148, D379) > get_invoice refused at intake changes no invoice, vendor or schedule, writes no reservation and consumes no permit, with no PDP call and one Refusal Record`, `an intake refusal leaves the business stores untouched on reads and both write paths (@spec operation-profile-payments-v1, #1148, D379) > hold_transfer refused at intake changes no invoice, vendor or schedule, writes no reservation and consumes no permit, with no PDP call and one Refusal Record` and `an intake refusal leaves the business stores untouched on reads and both write paths (@spec operation-profile-payments-v1, #1148, D379) > schedule_payment refused at intake changes no invoice, vendor or schedule, writes no reservation and consumes no permit, with no PDP call and one Refusal Record`. Two encodings of one invoice id resolve one target and one digest: `intake NFC-normalizes strings before target lookup, effective parameters and execution (@spec operation-profile-payments-v1, D316) > NFC and NFD forms of one invoice_id resolve the same target, yield the same effective parameters, and execute with the normalized value`. A schema intake cannot read is refused `capability_source_unresolvable`, and the signed values stay distinct: `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > the signed Refusal Record names request_invalid for arguments outside the schema, request_unsupported for an unknown tool and capability_source_unresolvable for an unreadable schema, each with no PDP call and no effect`. The PDP keeps its own key check (`evaluate.ts:1578`, `:1596`) for a key that reaches it directly: `the Operation Profile defines an idempotency key for every non-idempotent high-consequence operation (@spec runtime#idempotency) > a malformed key handed to the PEP past intake is still refused parameter_violation by the PDP`.
- **The statement publishes the single-use default (D333).** `reversible_write_idempotency` is discriminated on `permit_lifetime_control`. Its `consequential_write` class entry is `single_use_decision_identifier`, with `consumed_identifier_owner` `mcp-payments-pep`, a consumed-identifier domain and `retention_posture` `permit_acceptance_window`; the two keyed writes' own entries keep the key control, and an operation entry is selected before the class entry (`reversibleWriteControlFor`, `services/pdp/src/enforcement-scope.ts`): `the statement's permit-lifetime controls, discriminated on permit_lifetime_control (@spec runtime#permit-binding, runtime#single-use-identifiers, #1080, D333) > selects the most specific declaration before the class default, and returns a key declaration only when that selection is the key control: a less-specific key default never covers an operation that elects single use`. The server does not start unless every served `consequential_write` is covered by a control its write path enforces, with the enforcing store configured and owned by the declared owner (`assertPermitLifetimeCoverage`, `services/mcp-payments/src/server.ts`): `runtime posture publication on the resource metadata surface > publishes single_use_decision_identifier as the consequential_write class default the unkeyed hold resolves to, and refuses to start unless every served consequential_write has a supported control, a configured enforcing store and that store's declared owner`.
- **A `use_limit` on a keyed write is metered.** The PDP issues none there, but a keyed write's permit that carries `use_limit: 1` is redeemed inside the reservation's transaction, before the effect, and a consumed identifier is refused `permit_consumed` under any key; any other `use_limit` is refused `condition_unrecognized` (`McpPaymentsServer.admitReversibleWrite`): `a use_limit a keyed write's permit carries is metered, never ignored (@spec runtime#single-use-identifiers, #1136 review, D317) > the review's probe: scheduled under a use_limit: 1 permit, cancelled under a fresh Decision, the original permit replayed under another key is refused permit_consumed and schedules nothing`.
- **Releasing a retained result is a use of a single-use permit (D342).** Retrieval consumes `use_limit: 1` in the same store after the permit-use check and before anything is disclosed, on the initial lookup and on the concurrent-existing fallback (`McpPaymentsServer.releaseRetained`). A consumed identifier is refused `permit_consumed` on retrieval or admission under any key, and a store that cannot be written discloses nothing: `retrieval is a use of a single-use permit (@spec runtime#single-use-identifiers, #1080, D342) > two retrievals under one identifier: the first releases the retained result and consumes the permit, the second is refused permit_consumed and discloses nothing`, `retrieval is a use of a single-use permit (@spec runtime#single-use-identifiers, #1080, D342) > a retrieval followed by admission under another key: the permit the retrieval consumed is refused permit_consumed and schedules nothing, even after a separately authorized cancellation` and `retrieval is a use of a single-use permit (@spec runtime#single-use-identifiers, #1080, D342) > a consumed-identifier store that cannot be written refuses the retrieval consumption_unavailable and discloses nothing: no retained result and no retained-record disposition`. A fresh Decision still retrieves the original result with no new effect, and a permit with no use limit keeps the key control: `retrieval is a use of a single-use permit (@spec runtime#single-use-identifiers, #1080, D342) > a fresh Decision still retrieves the original result and repeats no effect: a fresh single-use one after the first is consumed, and one with no use limit keeps the key control and consumes nothing`.

Residuals:

- **`hold_transfer`** takes the single-use permit control. The PDP sets `use_limit: 1` on every `consequential_write` permit that no key control covers (`evaluate`, `services/pdp/src/evaluate.ts`), and the unkeyed write path redeems the permit's `evaluation_id` once, after the last permit-use check and immediately before the effect, in the PEP's durable store (`McpPaymentsServer.takeSingleUse`, `services/mcp-payments/src/server.ts`). A second presentation is suppressed `permit_consumed` with no effect: `single-use permits on the unkeyed write path (@spec runtime#single-use-identifiers, #1080) > a second presentation of one hold_transfer Decision is refused permit_consumed, releases no second hold, and records the suppression against the same evaluation_id`. Two concurrent presentations release one hold: `single-use permits on the unkeyed write path (@spec runtime#single-use-identifiers, #1080) > a presentation refused before redemption burns nothing, and two concurrent presentations of that Decision release at most one hold`. A store that cannot be written refuses `consumption_unavailable`: `single-use permits on the unkeyed write path (@spec runtime#single-use-identifiers, #1080) > a consumed-identifier store that cannot be written refuses consumption_unavailable with no hold, and a server with no store configured does not start`. Two separately authorized holds each place a hold; the control bounds one permit, not the action. The hold itself stores nothing: `execute()` returns `{held: true}`.

## 4. State and freshness

- **Decision (D293).** The synchronous committed read below is this
  co-located target's declared local source; it is not a Mission Status wire
  call. A PEP or PDP separated from the AS would use authenticated Mission
  Status or per-decision introspection at the AS holding the Mission, with no
  silent fallback or re-stamped observation (#1101). State alone supplies
  neither current effective authority nor independent Resource policy.
- **Source.** `loadView` (`stack.ts:828-835`) returns the kernel's committed state and version with `mode: "fresh"` and `freshness_at` set to now. Each read happens inside the request, so the bounds below bind only injected observations in tests: `the PEP sends the AuthZEN profile's members (@spec authzen#context-audience-freshness, #1004) > under PEP placement, carries the loader's observation at context.mission_state_observation, with state, mode and freshness_at, and no context.freshness`.
- **Per-class bounds** (`config/enforcement-scope.json:15-26`): 300 s for `consequential_read`, `consequential_write` and `non_consequential`; 30 s for `irreversible_action` and `privileged_administration`; 60 s for `external_commitment`; none for `audit_only`; beyond the bound, deny; issuer ceiling 300 s. The loader refuses any other mode: `published runtime posture (@spec runtime#runtime-operational, status#status-operational) > refuses unsupported modes, malformed or missing bounds, and bounds exceeding the issuer ceiling`.
- **Clock skew.** An observation up to 5 s in the future is accepted (`evaluate.ts:104`), and clamped to the decision instant for the permit cap: `permit deadline (@spec runtime#state-freshness) > clamps a skew-tolerated future observation to the decision instant, so skew cannot lengthen a permit`.
- **Permit lifetime.** 120 s for `irreversible_action`, 300 s otherwise (`evaluate.ts:1513`), capped by the observation plus the class bound, a reported expiry, a signed `fresh_until`, and 300 s for the two keyed writes (`evaluate.ts:1531-1551`). The high-consequence classes get `use_limit` 1: `a permit expires no later than the state view it was decided against (@spec runtime#state-freshness) > caps valid_until at the state observation plus the class staleness bound`.
- **Execution lease.** 30 s for both high-consequence classes, capped by `valid_until`; validity and phase are checked at admission and again just before commit (`server.ts:1596`, `:1705`): [FGA] `M5 transaction-assurance tier > derives the execution lease from the published transaction_assurance maximum, capped by the permit's validity`.

Unavailable or stale state fails closed:

| Condition | Refusal | Witness |
|---|---|---|
| Mission not found by the loader | `unknown_mission`, signed `state_unavailable` (`pep.ts:1228`) | no test yet on the Mission-bound path |
| Malformed observation | `state_unavailable`, the PDP is not asked (`pep.ts:1311-1313`) | `the PEP sends the AuthZEN profile's members (@spec authzen#context-audience-freshness, #1004) > under PEP placement, refuses state_unavailable without asking the PDP when the loader's observation lacks a member its mode requires or carries a malformed one` |
| Observation absent, stale or past the skew; version mismatch | `stale_state` | `AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004) > under PEP placement the PDP reads context.mission_state_observation > a missing observation denies stale_state for every high-consequence class` |
| Mission not `active` (the PDP's view wins) | `mission_inactive` | `AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004) > the PEP-supplied state is exactly active, and the PDP's own view wins on disagreement (@spec authzen#pdp-request rule 1) > the PDP's own revoked view against a PEP-supplied active state denies mission_inactive: the PDP's view wins` |
| PDP throws, times out, is unreachable or answers non-2xx | `pdp_unreachable` | `configured PDP unavailability (@spec runtime#ride-through, authzen#failure-condition-coverage) > refuses a decision function that throws synchronously as pdp_unreachable, with one Refusal Record and no effect` |
| Unsigned, malformed or oversized PDP response | `channel_failure` | `configured PDP unavailability (@spec runtime#ride-through, authzen#failure-condition-coverage) > refuses an unsigned 200 response as channel_failure, with no PDP decision retained` |

Revocation after a decision is a stated bound, not a defect, and no
instantaneous revocation is claimed: an admitted high-consequence action runs
to completion inside its permit window (about 30 s or 60 s) under the runtime
profile's run-to-completion rule;
`callTransactionTool` does not re-read Mission state after `enforce`
(`server.ts:1521-1852`). No test yet. The next call decides afresh:
`compound-action phases (@spec runtime#compound-actions) > denies the fresh commit Decision when the Mission deactivates after prepare`.

## 5. Policy conjunction

All three parts are required. Token authority and independent Resource
policy are not met; §10 makes each an acceptance gate.

**Current effective Mission authority** (PDP, `evaluate.ts`): view consistency
(`view_inconsistent`), state (`mission_inactive`), the entry matching
`resource.properties.audience` and the action (`out_of_authority`),
containment (`authority_contained`), discharge (`authority_discharged`),
capability binding (`capability_drift`), and the `vendors` and `max_amount`
constraints (`parameter_violation`). Witnesses include [FGA]
`PDP decisions against OpenFGA (@spec authzen) > out-of-authority action -> deny out_of_authority`
and
`discharged entries are excluded from the PDP's authority input > denies authority_discharged for the discharged entry while the Mission stays active`. The composed stack's canonical loader (`viewFor`) supplies the discharge delta, so the refusal holds end to end, a credential deriving only from a discharged entry included (step 5c), wherever a composition registers a discharge authority; the as-native target enables no discharge (D332): `the composed stack refuses a discharged entry at the point of use (@spec discharge#runtime, #1144) > after a discharge commit, the next decision for that entry is authority_discharged, and a credential deriving only from it is refused at step 5c while a live entry's credential still permits (co-resident)`.
The gates are independently necessary:
`runtime decision gates are independently necessary (@spec runtime#decision) > a stale freshness failure denies even though authority and the Resource-policy/FGA check both permit`.

**Token authority:** partial; #825 PR 1 merged as #1062 (D302). The PEP
validates the token's signature, issuer, audience, `cnf` and DPoP
(`verifyDpopBoundToken`, `server.ts:571-588`):
`the PEP establishes token validity before using any of its claims as decision inputs (@spec runtime#token-validation) > a token whose audience does not name this resource is refused, before any of its claims reach a decision (@spec runtime#token-validation, audience)`.
It then checks the Mission access-token profile: `typ` `at+jwt`, the RFC 9068
claims with their types, a `mission` claim with `id` and `issuer`, and the
token's own `authorization_details`, read in full as the credential's
authority. A token that fails the profile is refused, never demoted to the
ordinary class (`missionBoundFactsFrom`, `server.ts:599-632`;
`readMissionAccessClaims`, `services/mcp-payments/src/token-verifier.ts:108-120`):
`the Mission access-token profile is met before any claim is trusted (@spec runtime-oauth#token-validation, #825) > never demotes a Mission-bound token that fails its profile to the ordinary class on a gateway route`.
Before the PDP is asked, the PEP refuses `out_of_authority` for an action the
credential's own authority does not cover, one whole entry at a time, on the
resource, action, vendors and amount it resolved; an approval requirement is
honored only with a verified transaction credential's approval
(`pep.ts:1420-1454`):
`the credential authority bounds the action the PEP resolved (@spec runtime#input-authority, #825) > refuses vendor lookup under an invoice-only token, and lets a broad token reach the PDP, on the same broad Mission`.
A narrowed token is therefore honored as narrower at the PEP. The Mission-bound
path does not read `scope`. Credential expiry is checked only at validation;
the PDP records `context.credential.expires_at` in evidence but does not deny
on it. Remaining under #825: the PDP neither receives nor evaluates the
credential authority (no `context.credential.authority` carrier; it matches
the kernel's current Authority Set, `evaluate.ts:1127-1134`), so there is no
PDP-side witness. D312 adopts that carrier and splits the work: 2a key-role
pinning, 2b the carrier with PDP enforcement and the PEP pre-check redesign,
2c the issuance audit.

**Independently administered Resource policy:** not implemented. The OpenFGA
relations admit only `mission` subjects (`services/pdp/src/fga.ts:20-47`) and
the tuple injected per check mirrors the triple being checked, so the shipped
model cannot deny independently. A denial, when a stub produces one, is
`out_of_authority`, indistinguishable from a Mission-authority denial. Owner:
#828.

Deployment-administered gates that do exist: the action-bound approval for
`payments:remittance.send` (§3), the action-to-relation map (`out_of_authority`,
`services/pdp/src/policy.ts:19-31`), and the idempotency claim
(`duplicate_suppressed`, `idempotency_conflict`).

## 6. Evidence

| Record | Emitter | When |
|---|---|---|
| Decision Evidence | PDP, role `pdp`, kid `pdp-decision-evidence`, key generated per boot (`stack.ts:670`) | every decision, permit or deny; a retransmission returns the stored record (`evaluate.ts:575-579`) |
| Refusal Record | PEP, role `pep` | every refusal before a PDP decision (`pep.ts:2205-2266`) |
| Execution Evidence, `suppressed` | PEP, role `pep` | every post-permit failure (`suppressExecution`, `pep.ts:1965-2008`), and a keyed write whose retry returns the stored result (`operation_already_claimed`) |
| Execution Evidence, `completed` | role `executor` | the transaction tier after the connector commits (`server.ts:1799-1832`), and reconciliation from the connector ledger |

- **Verification.** The PEP verifies Decision Evidence (byte equality, signature, emitter-bound kid, role, audience) and retains it verbatim; a permit whose record fails is refused `decision_evidence_unverifiable` (`pep.ts:1654-1666`): `a permit the PDP did not evidence is refused, never executed (#741) > refuses the action when the decision carries no Decision Evidence`.
- **Outcomes** are `completed`, `failed` and `suppressed` (`services/mcp-payments/src/evidence.ts:213`). Nothing emits `failed`. An unknown outcome is not an Execution Evidence outcome; it is the PDP claim state `indeterminate`.
- **Coverage gap.** A successful call outside the transaction tier emits no Execution Evidence (`server.ts:1125`, `:1199`, `:1511`); only its Decision Evidence exists. No test asserts the absence.
- **Retention.** `EvidenceRetentionStore` is built without a file, so it is in memory (`stack.ts:722-724`), with a 31,536,000 s window from the `policy.json` audit horizon and no capacity limit. Restart recovery is shown only on a test file: `retention honors the declared audit window (@spec runtime-evidence#receipt-retention) > recovers the retained records, the emitter sequences and the key retirement metadata after a restart`.
- **Refusal reasons.** A Refusal Record's `denial_reason` comes from the closed set for its emitter's role. The PEP maps each diagnostic on its refusal path through `PRE_DECISION_DENIAL_REASON` (`pep.ts:951-987`), which is exhaustive over them, and `signedDenialReason` throws for anything else before the evidence store is called. The store also refuses a value outside the role's set before signing (`REFUSAL_DENIAL_REASONS`, `services/mcp-payments/src/evidence.ts`). An unmapped diagnostic therefore rejects enforcement with nothing signed or retained and no effect: `an unmapped refusal diagnostic is rejected before signing (@spec runtime-evidence#pre-decision-refusal, #1148, D379) > an unmapped diagnostic on the enforcement path rejects enforcement, with no signing call, no retained Refusal Record and no business effect`; the mapping's coverage and the store's refusal: `the PEP maps every Refusal Record diagnostic into the closed set (@spec runtime-evidence#pre-decision-refusal, #1148, D379) > the mapping covers exactly the Refusal Record path's diagnostics, and each maps to a value in the closed PEP set` and `the evidence store refuses a denial_reason outside the emitting role's closed set before signing (@spec runtime-evidence#pre-decision-refusal, #1148, D379) > a PEP record carrying a diagnostic or another role's value is refused unsigned, while every closed PEP value signs`.
- **Emission failure.** Each failure is either a refusal before any effect, which leaves no effect, or missing evidence after an effect, which is reported and never settled as if nothing happened. A PDP whose emitter throws releases the claim, and the PEP refuses `pdp_unreachable`: `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > the PDP's Decision Evidence emitter throws: the claim is released, the PEP refuses pdp_unreachable, and nothing executes`. A Refusal Record emission that throws rejects `enforce`, and nothing is recorded or executed: `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > a Refusal Record emission throws: the call rejects, nothing is recorded, and nothing executes`. `suppressExecution` returns `gap: "effective_parameter_digest_unobservable"` without emitting when the permit's target no longer resolves, and `gap: "emission_failed"` after one retry on the same execution identity: `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > suppressExecution returns effective_parameter_digest_unobservable when the permit's target no longer resolves, and retains nothing` and `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > suppressExecution retries once on the same execution identity, returns emission_failed after a second failure, and never retains a disposition twice`. The `completed` write after a connector commit (`callTransactionTool`) retries once on the same execution identity. A second failure returns `ok: false` with `gap: "emission_failed"` and the committed `result`, never a `refusal_reason`, and leaves the operation `connector_committed` and the claim unsettled; the effect stands once, and neither a retry nor reconciliation repeats it: `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > a completed write that fails once is retried on the same execution identity: one record, the claim settles completed, one effect` and `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > a completed write that fails twice reports the gap: the effect stands once, the claim is not settled completed, and neither a retry nor reconciliation repeats the effect`. The running reconciler later settles that claim `completed` from the connector ledger, with no second effect (§7).

## 7. Persistence and restart

No transaction spans two stores. The transaction tier writes redemption, then
the connector effect, then evidence, then claim settlement.

| Store | Backing as shipped | Atomic unit | Restart |
|---|---|---|---|
| PDP idempotency claims | SQLite file `var/pdp-idempotency-claims.sqlite`, exclusive lock, WAL, `synchronous=FULL` (`stack.ts:671-678`) | lookup and insert in one transaction; the decision is persisted before the response | a prior boot's `permit_issued` becomes `unresolved`; an unpersisted `claimed` is adoptable; `unresolved` closes `indeterminate` at `valid_until` plus 30 s plus PT15M, raises the declared operator alert and is never purged |
| PEP write reservations | SQLite file `var/pep-write-reservations.sqlite` (`stack.ts:693-698`) | reservation, effect and completion in one transaction; a single-use permit's consumed identifier is one insert on the unkeyed path and on a keyed retrieval, and joins that transaction on keyed admission | survives; completed rows read absent after P7D; a consumed identifier is kept until its permit's `valid_until` plus 30 s (`CONSUMED_PERMIT_RETENTION_MARGIN_MS`), which realizes the published `permit_acceptance_window` posture: the PEP accepts a permit only until `valid_until` on its own clock, with no skew; the declared reconciler runs `sweep()` and `sweepConsumedPermits()` on every run |
| `TransactionEngine` | in memory (`services/mcp-payments/src/transaction.ts:41`) | redemption is three statements, not one transaction | lost, with every redemption record. Every process reuses the constant epoch `demo-epoch` (`demo/src/stack.ts:867`), so D39's prior-epoch rejection (`transaction.ts:60-61`) never fires: a restarted engine has no record of earlier redemptions. The PEP's `instanceEpoch` is also `demo-epoch` (`stack.ts:904`) and is never read |
| Connectors, txn stores, evidence retention | in memory | one insert per operation key; atomic first use of a `txn` | lost |
| Payments store, DPoP replay cache, actor records | in memory, seeded per boot | none | lost or reseeded |
| Kernel and provider stores | the floor's (`provider-integration-port.md`) | the floor's | the floor's (`control-plane-deployment.md`) |
| Keys | generated per boot under fixed kids | none | rotated (#831) |

Witnesses for the durable stores:
`PDP idempotency claim (@spec runtime#idempotency, #917) > crash boundaries and restart > a persisted permit is unknown after restart: suppressed, never returned, never fresh`
and
`the PEP's reservation and retention for keyed reversible writes (@spec runtime#idempotency, #918) > the persisted store reopens with the record > a key scheduled before the store closed resolves against its record from a new server on the same file`,
and
`single-use permits on the unkeyed write path (@spec runtime#single-use-identifiers, #1080) > the consumed record survives a store reopen: a new server on the same file refuses the replay permit_consumed with no hold`.

Residuals:

- **The declared reconciler runs in the PEP process.** `OutcomeReconciler` (`services/mcp-payments/src/outcome-reconciler.ts`) is built from `outcome_reconciliation` and refuses a declaration naming another component. `composeStack` returns it stopped; `pnpm as-native` and `pnpm demo:serve` start it, once at boot and then every 300 s (a third of PT15M), and every close path stops it first. Each run settles this epoch's unresolved claims over the claim channel (`reconcileClaims`), alerts `completed` Execution Evidence with no committed connector effect and a committed effect still without evidence after the window, runs both reservation sweeps, and escalates a `reserved` row without executing it. A step that throws raises `reconciliation_failed`; the others still run. A claim whose reconciliation throws raises it naming that claim and stays unresolved for the next run, and the claims after it still settle. Evidence alone decides an outcome: a claim nothing establishes closes `indeterminate`, and the claim domain's `onIndeterminate` hook raises the declared alert once that transition commits. Each alert is one JSON line on stderr. Witnesses: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > missing evidence after an effect, over the remote channel: the wire stands once, and a run inside the window settles the claim completed from the ledger, with exactly one ledger entry`, `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > a refusal before any effect: a permit proven unredeemed in this epoch settles failed, and a retry under its key executes nothing`, `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > one claim's failed reconciliation is isolated: a later claim proven unredeemed still settles failed in the same run, the failed claim stays unresolved and is escalated, and a later run settles it with no second effect (#1161 review)`, `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > an outcome nothing establishes stays open, closes indeterminate when its window closes, and raises the declared alert exactly once, never from a run's open list` and `the as-native launcher in process, OpenFGA client stubbed (D332) > starts the declared outcome reconciler at launch, a third of the PT15M window apart, and its first run raises no alert; close stops it before the claim domain closes, in co-resident and remote PDP mode`.
- **Restart is a stated bound.** The claim channel's requester epoch is `demo-epoch` plus a UUID drawn per process (`services/mcp-payments/src/redemption-status.ts:67`), not the engine's constant. Claim listing and reconciliation match that epoch exactly (`services/pdp/src/idempotency-claims.ts:647`, `:682`), so a restarted PEP cannot list or reconcile a prior process's claim, and a retry against its `permit_issued` claim is suppressed (`idempotency-claims.ts:444-455`): `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > refuses the retry when the redemption store cannot answer, or answers for another epoch`. The claim moves to `unresolved` once its lease elapses and closes `indeterminate` when the window closes (`idempotency-claims.ts:723-735`); its key stays refused. Single use across a restart rests on this persisted claim and the PEP's write reservations, not on the engine, whose redemption records are lost. Redemption records, connectors and retained evidence are in memory, so no restarted process reconciles a prior process's claim, and the statement says so: `prior_process_outcomes: indeterminate_at_window_close` (`config/enforcement-scope.json`). The claim closes `indeterminate` at its window's end, swept by the restarted reconciler's own listing, and raises the declared alert: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > missing evidence after an effect across a restart: the prior epoch's claim is never listed, closes indeterminate when its window closes with the declared alert, and the retry executes nothing` and, composed, `the composed stack's declared outcome reconciler (@spec runtime#evidence outcome reconciliation, #1103) > a prior process's unsettled claim raises one operator_alert JSON line on stderr when the restarted stack's reconciler runs past its window`.
- **The operation key omits `idempotency_key`.** One redemption is allowed per Mission, action, phase and digest per process, so a new key for an unchanged invoice is refused `permit_consumed`: [FGA] `M5 transaction-assurance tier > a FRESH permit for an already-claimed operation is refused as operation_already_claimed and does not double-execute`. This target states it as a bound: a repeat is refused, never executed twice.
- **No assembled restart test.** Restart is tested at the unit level for the two durable stores and the transaction-token crash window, and for the claim bound on a stack composed again on the same claim file (above); no test restarts the assembled target. #873, #250.

## 8. Claims, exclusions and residuals by action path

Claims apply per action path, never as a product-wide maximum. An
unsupported obligation is refused or its claim excluded.

| Action path | Claimed | Not claimed | Residuals and owners |
|---|---|---|---|
| Reads (`list_invoices`, `get_invoice`, `lookup_vendor`, `check_transfer`) | per-call decision on current Mission authority and state; per-action `vendors` | Execution Evidence on success | #825 and #828 (required, §1) |
| Keyed writes (`schedule_payment`, `cancel_scheduled_payment`) | per-action `max_amount` and `vendors`; PEP-reserved idempotency with a durable record, swept by the declared reconciler | resolving a `reserved` row: no tool produces one, and the reconciler escalates one without executing it | none |
| Prepare (`hold_transfer`) | per-call decision; phase binding; single-use permit redeemed once in the PEP's durable store | idempotency across separately authorized holds; any stored effect (the hold is a stub) | none: single-use enforcement, not a durable business hold (D317) |
| Transaction tier (`execute_wire_transfer`, `send_remittance_email`) | single-use permit, execution lease, PDP-held Exact claim, digest and phase binding, Execution Evidence; action-bound approval for remittance | restart recovery beyond the claim store, a stated bound (§7); transaction-grade resource witnesses; a failed commit predicate that retains the permit | #250, #817 |
| Every path | per-action limits only | any aggregate cap; compromise containment; unattended prohibited-class exception | excluded by D284; #825 and #828 are required, not excluded (§1) |

**High-consequence claims hold on the HTTP entry point only.** The HTTP
transport verifies a DPoP proof of possession; the in-process mediated
channel, which the demo agent uses, validates the token without one
([provider-integration-port.md](provider-integration-port.md) §5.1). A
high-consequence action on that channel runs on an unproven token.

**The aggregate-cap exclusion is enforced by refusal.** The issuer refuses an
Intent carrying a member it does not implement, such as `max_budget`, under
the closed-top-level rule (`validateMissionIntent`,
`services/authorization-server/src/kernel/intent.ts`):
`intent validation (@spec mission#submission-via-par) > rejects unknown top-level members (closed top level)`.
That test uses another member; no test names `max_budget`.

**Unmet obligations by owner:**

- Blocking acceptance: #825 (token authority; PR 1 merged as #1062, PRs 2a to 2c remain per D312) and #828 (Resource policy).
- Acceptance-pack prerequisites: #1105 (`pnpm as-native` still builds the cross-domain objects in process; its AS capability set is D332's, §2).
- Separated deployment only: #1101 (state source under D293).
- Also open: #826 (Approver versus Subject; implemented by #1074, D306, awaiting acceptance), #831 (keys and verifier refresh), #250 (control-plane atomicity; revoke versus issue), #916 (approval commits before grant binding), #830 (identity changes apply at restart), #817 (resource-side execution capabilities), #773 (context-drift vectors, conditional), #873 (inherited floor obligations).
- #917 and #918 are closed as implemented (D245, D247); their leftovers are resolved by #1103 and #1080.

## 9. Pinned adoption closure

Computed from `family-manifest.json` at `e9001b2f`: the start set, its
`adoption_requires` transitively, and each `requires_when` evaluated for this
deployment. Each hash is `git log -1 --format=%h -- <draft>.md` at that
commit. Each pinned draft's bytes there equal its `conformance-manifest.json`
pin (Substrate and Signals are pinned at the byte-identical `19fa5a0e`, Runtime Evidence at `40705c1d`, Status at `60552344` and the MAS draft at `98445ffc`);
containment, Status List, attenuation, Architecture and Security Model carry
no pin.

**Protocol core, relied on normatively:**

| Draft | Hash | Why |
|---|---|---|
| `draft-mcguinness-oauth-mission.md` (the OAuth binding) | `73859449` | the floor; Mission-bound issuance |
| `draft-mcguinness-oauth-mission-resource-access.md` | `19fa5a0e` | `mission_resource_access`, the statement's only entry type |
| `draft-mcguinness-mission-substrate.md` | `eb59a919` | `adoption_requires` of runtime, runtime-oauth, authzen and runtime-evidence |
| `draft-mcguinness-mission-runtime.md` | `0c7ba9c3` | the runtime overlay |
| `draft-mcguinness-mission-runtime-oauth.md` | `2b422bf1` | Runtime OAuth credential validation |
| `draft-mcguinness-mission-authzen.md` | `6f10361e` | the decision wire: Decision Base, Transaction Assurance, Runtime Evidence and ARAP; not Obligations, History or Batch |
| `draft-mcguinness-mission-runtime-evidence.md` | `c8a4d8b8` | the portable Decision, Execution and Refusal objects |
| `draft-mcguinness-mission-capability-binding.md` | `2dc6ca1d` | `config/catalog.json` sources every payments action, and the PDP refuses `capability_drift` |
| `draft-mcguinness-oauth-mission-transaction-authorization.md` | `091f1ffd` | the AS `transaction-authorization` capability is on (D332): the remittance approval's resource challenge, its redemption at the transaction endpoint and the transaction token |

**Relied on for terms, not as the wire source:**
`draft-mcguinness-oauth-mission-status.md` `48521467` defines the Effective
Authority Set, the lifecycle states, `mission_max_stale_seconds` and the
floor's `revoke`. Its Mission Status operation is not this co-located
target's state source (D293, §4); a separated realization uses it or core
introspection (#1101).

**Conditional, not triggered:**

| Draft | Hash | Why not |
|---|---|---|
| `draft-mcguinness-oauth-mission-containment.md` | `5421debe` | `containment` off; the PDP sees an empty delta |
| `draft-mcguinness-oauth-mission-discharge.md` | `5421debe` | `discharge` off |
| `draft-mcguinness-oauth-mission-signals.md` | `eb59a919` | no lifecycle subscriber; not the state source |
| `draft-mcguinness-oauth-mission-status-list.md` | `4fe0d0b0` | off |
| `draft-mcguinness-oauth-mission-cross-domain.md` | `02014aa3` | no projected credentials or decisions on this path |
| `draft-mcguinness-oauth-mission-attenuation.md` | `4fe0d0b0` | the AS does not advertise `mission_attenuation_supported` |
| `draft-mcguinness-mission-authority-server.md` | `30933b36` | the MAS join route is excluded from this target (#1105) |

**Reader bundle, informative:** `draft-mcguinness-mission-architecture.md`
`106d552f`, `draft-mcguinness-mission-control-plane.md` `909a3ee7` (kept
informative as on the floor; adopting it would pull in Signals and Status),
and `draft-mcguinness-mission-security-model.md` `20706d3b`.

**Deployed components beyond the drafts:** OpenFGA; the AuthZEN ARAP access
request profile through the in-process `AccessRequestService`; the floor's
RFC list (`issuance-only-deployment.md` §9), plus RFC 9728 for the resource
metadata that publishes the Enforcement Scope Statement.

## 10. Acceptance prerequisites

The assembled acceptance pack (#253 Sketch step 3) pins the assembled path's
revision and exercises each vector below. It runs on the `pnpm as-native`
composition (§11) and reaches the PEP only through the HTTP MCP endpoint at
the declared audience, never the in-process mediated channel (D315). One test
drives an AS-issued Mission-bound token with a DPoP proof over that endpoint
through `mcp-payments` and the real PDP: [FGA]
`the as-native target over HTTP MCP with DPoP against a live OpenFGA (D315) > carries the AS-issued Mission-bound token with a valid DPoP proof through mcp-payments and the PDP to one permitted read`.

The pack cannot pass while #825 or #828 is unmet (§1).

| Vector | Existing witness | Gap |
|---|---|---|
| Valid request | [FGA] `M4 core enforcement tier > scenario 2: happy path -- in-authority read permitted, Decision Evidence recorded` | not on the assembled path |
| Narrowed token | at the PEP only: `the credential authority bounds the action the PEP resolved (@spec runtime#input-authority, #825) > narrows by vendor independently of the Mission` | no PDP-side witness and not on the assembled path; #825 PR 2b; required, blocks acceptance |
| Independent policy revocation | a stubbed policy only: `finding 3: a multi-vendor list_invoices names every returned vendor to Resource policy, not just one representative (@spec read-binding) > Mission authority includes two vendors; Resource policy denies one: the whole read refuses out_of_authority, never a narrowed result` | #828; required, blocks acceptance |
| Stale or non-active Mission at admission and at each fresh commit-phase decision | the §4 refusal table; `compound-action phases (@spec runtime#compound-actions) > denies the fresh commit Decision when the Mission deactivates after prepare` | not on the assembled path |
| Run to completion after an earlier valid permit | none | no test yet that an admitted action completes only inside its permit and lease bounds and that the next decision refuses; no instantaneous revocation is implied (§4) |
| Parameter digest mismatch | [FGA] `M4 core enforcement tier > scenario 3: TOCTOU -- invoice mutated between decision and execute -> parameter_mismatch refusal` | |
| Permit replay | [FGA] `M5 transaction-assurance tier > the SAME evaluation identifier presented again is refused as permit_consumed, and the completed record stands` | |
| Phase mismatch | `compound-action phases (@spec runtime#compound-actions) > refuses a commit presenting check_transfer's preflight permit` | |
| Failed commit predicate with the permit retained | none | applies only to a connector that claims a commit-point predicate; none does at this revision (#817), so the guarantee stays excluded (§8) |
| Bob for Alice, with and without `openid` | `Approver and Subject stay separate identities (@spec mission#approval-authentication, #826) > refuses openid invalid_scope when the Approver is not the Subject, leaving no Mission, grant, code or session for the Subject` and `Approver and Subject stay separate identities (@spec mission#approval-authentication, #826) > approves for another principal without openid: the token and introspection carry the Subject, the record the Approver, and the provider account and session the Approver` | not on the assembled path; #826 awaits implementation acceptance |
| Revoke during issuance | none on this surface | #250, #873 |
| Restart and uncertain recovery | the unit-level witnesses in §7 | no assembled restart test; a prior process's unsettled claims close indeterminate with an operator alert, a stated bound (§7) |
| Emission failure | the six #1104 tests in §6 | not on the assembled path |
| Unknown or authoritative argument member | `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > an argument member the served schema does not declare is refused invalid_request with no PDP call and one Refusal Record` and `intake refuses a request outside the tool's served schema before any PDP call (@spec operation-profile-payments-v1, D316) > an authoritative member (D34) is refused invalid_request with no PDP call and one Refusal Record` (§3) | not on the assembled path |

Each new test in the pack must fail when its guard is disabled, and a ledger
row reaches `tested` only with an exact `describe > it` citation at the
correct surface and role.

## 11. Run it

`pnpm as-native` (`scripts/as-native.mjs`, `demo/src/as-native-serve.ts`)
assembles this target with `launchAsNative` (`demo/src/as-native.ts:67`): the
AS on 4400 with the issuance profile plus exactly `lifecycle-revoke` and
`transaction-authorization` (D332, §2), the `mcp-payments` PEP over HTTP MCP
at `http://localhost:4403/mcp`, the PDP, OpenFGA and the in-process approval
service, with no MAS join route. It mints no ordinary token. It prints the
issuer, the AS capability set, the resource audience and the PDP mode, and
needs only `pnpm setup` and `docker compose up -d` (OpenFGA).

Its configuration is the OpenFGA connection and the PDP mode from the
environment, and nothing else (`asNativeLaunchOptions`, `demo/src/as-native.ts:19`).
A value that is set but unusable, an unreachable OpenFGA or a port already in
use fails startup with one `as-native: startup failed:` line and exit status
1, and a failed startup releases what it opened. SIGINT, SIGTERM or SIGHUP
closes every listener and both store files and exits 0. The launcher refuses
any composition but the target, the minting fixture included:
`the as-native launcher in process, OpenFGA client stubbed (D332) > composes exactly the target from its own configuration: the D332 capability set, no dev ordinary issuance, no MAS join route and no test fixture`,
`the as-native launcher in process, OpenFGA client stubbed (D332) > refuses an unusable configuration by name, before anything connects`,
`the as-native launcher in process, OpenFGA client stubbed (D332) > refuses startup when the AS port or the declared audience's port is taken, and keeps no port or store file`
and
`the as-native launcher in process, OpenFGA client stubbed (D332) > closes every listener it published and releases both store files on shutdown, in co-resident and remote PDP mode`.
The server entry also runs as its own process against a stand-in OpenFGA:
`the as-native launcher process, the entry pnpm as-native runs, against a stand-in OpenFGA (D332) > starts exactly the target and prints it, then on SIGTERM closes every listener and exits 0`,
`the as-native launcher process, the entry pnpm as-native runs, against a stand-in OpenFGA (D332) > exits 1 with one startup-failure line, before anything listens, when its configuration is unusable or OpenFGA is unreachable`
and
`the as-native launcher process, the entry pnpm as-native runs, against a stand-in OpenFGA (D332) > exits 1 with one startup-failure line, and releases the AS port, when the declared audience's port is taken`.
The wrapper's dev-CA check and signal forwarding (`scripts/as-native.mjs`)
have no test yet.

The target is HTTP MCP with verified DPoP only (D315). A request without a
proof, or with a proof under a key other than the token's `cnf.jkt`, is
refused before the PEP, and so is a baseline-Join credential:
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > refuses the AS-issued token with no DPoP proof at the HTTP gate, before the PEP: no evidence and no decision`,
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > refuses a DPoP proof under a key other than the token's cnf.jkt at the HTTP gate, before the PEP: no evidence and no decision`
and
`the as-native target with the test-only ordinary-token minting fixture, OpenFGA client stubbed (D315, D332) > refuses a baseline-Join credential (an AS-issued ordinary token with no mission claim) with a valid proof: no join route admits it`.
That last test mints its ordinary credential through the test-only
`testOrdinaryTokenMinting` composition (§2), never through the launcher's.
The in-process mediated channel, which the demo agent uses, is outside the
target's claims; its possession gap stays documented (§8).

Each MCP client's `initialize` opens its own session on the endpoint
(`createHttpMcpChannel`), and the client's DELETE ends it. A session belongs
to the holder whose credential opened it: the DPoP key (`cnf.jkt`), the
subject and the client. Every request on a session is authenticated first,
and another holder's credential carrying its id is answered 404
`Session not found`, as for an unknown session, before the PEP:
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > gives each successive and each concurrent client its own MCP session, each with a permitted read`
and
`the as-native target over HTTP MCP with DPoP, OpenFGA client stubbed (D315) > binds a session to the holder that opened it: every request on it is authenticated, and another holder's credential carrying its id is answered 404 Session not found before the PEP`.
Sessions a client never ends stay open until the process stops.

`pnpm demo:serve`, `pnpm exhibit`, `pnpm agent` and `pnpm demo` assemble the
shared demo composition (`src/DEMO.md`), which also starts the MAS join route
and other surfaces.

## 12. Status

Adopted (D284) as the first runtime reference target; not a conformance
class, and no production-readiness or interoperability claim. This document
is #253 Sketch step 1. The runtime integration port (step 2) is
[provider-integration-port.md](provider-integration-port.md) §5, which maps
the overlay's obligations to their hooks in the port's eight columns. Next:

1. **Acceptance pack (step 3):** `pnpm as-native` (#1105) and the vectors of
   §10, after the required enforcement gaps (#825, #828) are resolved.
2. **Second route (step 4):** #818's legacy-estate/MAS route, demonstrated
   independently and separately pinned.

A later commit invalidates any statement here until it is re-checked against
that commit. #253 closes only when both reference routes are demonstrated,
unless a later owner ruling changes that requirement.
