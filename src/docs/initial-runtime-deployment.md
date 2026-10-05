# Initial runtime reference deployment

The deployment contract for the first runtime reference target that #253
adopted (D284, 2026-10-03): the **AS-native payments composition**. It is the
issuance-only floor of [issuance-only-deployment.md](issuance-only-deployment.md)
(#873) plus a runtime overlay: the `mcp-payments` Policy Enforcement Point
(PEP) and the reference Policy Decision Point (PDP) deciding each mediated
action. This document records the runtime delta only; every floor fact is
stated once, in the floor's document.

The selection is adopted. The evidence is not yet established: this contract
states what D284 requires, what the reference does at this revision, and
which open issue owns each gap. Selection is not a conformance,
production-readiness or interoperability claim (D284 ruling 1).

Every behavioral statement is true of the reference implementation read at
origin/main `538d0d61` and cites the function (`file:line`, paths relative to
`src/`) or the exact test (`describe > it`) that shows it. A path with no
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
`reversible_write_idempotency` for `payments:payment.schedule` and
`payments:payment.schedule.cancel`, and `outcome_reconciliation` (PT15M).
`custody`, `evidence` and `high_assurance_agent` are absent.

Excluded from this target (D284 ruling 5): aggregate-budget enforcement,
compromise containment, and any unattended prohibited-class exception. #813
keeps its own ruling; #820 and #424 stay parked.

Required, not excluded: token authority (#825) and independently
administered Resource policy (#828) belong to the adopted policy conjunction.
Both are unmet (§5). Under D284 ruling 4 they are acceptance prerequisites,
so this target cannot pass acceptance while either is missing.

## 2. Dimension contract

| Dimension | Adopted (D284, D293) | Reference at `538d0d61` | Status | Gap owner |
|---|---|---|---|---|
| Topology | One configured issuer and trust domain; trusted Approver resolver, PEP, PDP and Resource; no implied federation | One process. `composeStack({ withAuthServer: true })` (`demo/src/stack.ts:191`) runs the AS on 4400 (issuer `http://localhost:4400`, `stack.ts:273-275`), the PEP `mcp-payments-pep` (`stack.ts:706-708`), the PDP (`stack.ts:539`), OpenFGA, and the in-process approval service. The resource audience is `http://localhost:4403/mcp` (`services/mcp-payments/src/pep.ts:69`); nothing listens there. The AS JWKS is fetched once at assembly (`stack.ts:373`) | Partial | Launcher for exactly this topology: #1105. JWKS reload: #831 |
| Binding | OAuth Mission-bound issuance, Runtime OAuth and AuthZEN; MAS join only in its separately declared path | Runtime OAuth credential validation and the AuthZEN request (§4, §5). The PDP is a direct call by default with no PEP authentication (`services/pdp/src/decision-channel.ts:56-61`); `MISSION_PDP_MODE=remote` adds a loopback HTTP hop keyed by a per-boot secret that is never configured, so it cannot cross processes as shipped (`decision-channel.ts:64-66`). `config/mas-join.json` names the payments resource governed, so `composeStack` also starts a MAS join route (`stack.ts:792-794`) the statement does not declare | Partial | Exclude the MAS route on this target: #1105 (#818 owns MAS; #956 Q2 its declaration in the shared demo) |
| Operations | Enumerated payments operations, authority types, classes, phases and parameter binding; refuse outside the allowlist | Nine tools, all classed (§3). An unknown tool is refused `unknown_tool` before any PDP call (`pep.ts:1095`) | Partial | `hold_transfer` permit control: #1080. Profile drift (§3): #1106 |
| State | For this co-located target, the declared local committed read (D293 narrows D284's "authoritative Status"); per-class staleness, skew, permit and execution bounds; source ownership and unavailable behavior | The PEP and PDP read the AS kernel's committed record in process (`loadView`, `stack.ts:665-672`; the statement's state source is `kernel-committed load_view`, placement `pep`). That is the authoritative record behind Status, but it is not the Mission Status operation, introspection or Signals. Bounds and fail-closed behavior: §4 | Source accepted (D293); one unavailable-state witness missing (§4) | Separated PEP or PDP: #1101, which gates only a separated-deployment claim |
| Policy | Conjunction of token authority, current effective Mission authority and independently administered Resource policy | Current effective Mission authority is enforced and tested. Token authority is read only for validity, audience, `cnf` and the `mission` reference. Independent Resource policy is not implemented (§5) | Required, not met: blocks acceptance | Token authority: #825 (PR #1062). Resource policy: #828 |
| Evidence | Runtime/Decision Base and explicitly enabled evidence capabilities; emitters, verifiers, retention, failure carriers; missing telemetry is `indeterminate` | Decision Evidence, Refusal Records and Execution Evidence (§6). The `evidence` extension is not enabled, so there is no receipt issuer | Partial | Emission failures: #1104 |
| Persistence | Every store, its transaction or acceptance boundary, and restart and reconciliation behavior | Only the PDP claim domain and the PEP write reservations are durable files; every other store is in memory (§7). The declared reconciler is not run | Partial | Reconciliation never runs: #1103. #250, #831 |
| Claims | Per-action limits only; execution and transaction handling for applicable operations; no aggregate cap, compromise containment or unattended prohibited-class exception | §8 | Partial | §8 |

## 3. Operation allowlist

The operations are `TOOL_ACTIONS` (`services/mcp-payments/src/pep.ts:297-307`),
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
| `hold_transfer` | `payments:payment.execute` | `consequential_write` | prepare | unkeyed write | none | invoice form |
| `execute_wire_transfer` | `payments:payment.execute` | `irreversible_action` | commit | transaction | PDP claim (#917) | invoice form |
| `send_remittance_email` | `payments:remittance.send` | `external_commitment` | | transaction | PDP claim | invoice form |

- **Invoice form** (`buildEffectiveParams`, `services/mcp-payments/src/effective-params.ts:27-44`): `action`, `invoice_id`, `invoice_version`, `vendor_id`, `vendor_version`, `amount`, `payee_account` and `resource`, read from the payments store, not from arguments. **List form** (`:69-80`): `action`, `resource`, `vendor_scope`, `vendor_scope_source`.
- **Compound action:** one action and one digest serve three tools; the phase rides `context.action_phase` and is checked at every use: `compound-action phases (@spec runtime#compound-actions) > refuses a commit presenting prepare's permit, zero connector effects`.
- **Per-action limits** (`config/policy.json`): the read entry allows vendor `acme`; the write entry allows `max_amount` 500.00 USD and vendor `acme`. The PDP compares `max_amount` by exact decimal (`services/pdp/src/evaluate.ts:1261-1276`, refusal `parameter_violation`): `PDP per-action max_amount cap compares by exact decimal value (@spec mission#max-amount) > an amount exactly at the cap permits (the comparison is <=, not <)`, and [FGA] `M4 core enforcement tier > over-cap invoice denied parameter_violation`.
- **Action-bound approval:** `send_remittance_email` also requires an approval (`stack.ts:694-701`), refused `action_approval_required` otherwise: [FGA] `PDP decisions against OpenFGA (@spec authzen) > an approval past approved_until -> deny action_approval_required (ARAP)`.
- **Outside the allowlist:** an unknown tool name is refused `unknown_tool` before any PDP call, with a Refusal Record carrying `request_unsupported` (`pep.ts:926-949`, `:1095`): `approval resolution is outside the mediated tool boundary (#759) > approval-resolution tool names refuse unknown_tool and retain one PEP Refusal Record`. That test calls the PEP directly and does not assert the `request_unsupported` value; no transport-level test yet. An ungranted known tool is hidden from `tools/list` and still refused if called: `a tool-catalog filter is not a substitute for the runtime gate (@spec runtime#pep-placement) > a tool absent from tools/list because it is ungranted is still refused by the runtime gate when called directly, never executed`.

Residuals:

- **`hold_transfer`** has no permit-lifetime or idempotency control and stores nothing: `execute()` returns `{held: true}` (`services/mcp-payments/src/server.ts:1705-1706`). It is in the allowlist as the prepare phase. #1080 owns the permit control. No test yet.
- **Operation Profile drift.** The profile says arguments are NFC-normalized and unknown members are refused `invalid_request`; neither is implemented in `services/mcp-payments/src`. Its `note` and `execute_after` members are neither served nor read. The key format is checked by the PDP (`evaluate.ts:1396`, `:1414`), not a schema. The schema list also omits `idempotency_key` on the two transaction-tier tools and lists an unserved `list_invoices` `status` filter. #1106 (owner ruling pending).

## 4. State and freshness

- **Decision (D293).** The synchronous committed read below is this
  co-located target's declared local source; it is not a Mission Status wire
  call. A PEP or PDP separated from the AS would use authenticated Mission
  Status or per-decision introspection at the AS holding the Mission, with no
  silent fallback or re-stamped observation (#1101). State alone supplies
  neither current effective authority nor independent Resource policy.
- **Source.** `loadView` (`stack.ts:665-672`) returns the kernel's committed state and version with `mode: "fresh"` and `freshness_at` set to now. Each read happens inside the request, so the bounds below bind only injected observations in tests: `the PEP sends the AuthZEN profile's members (@spec authzen#context-audience-freshness, #1004) > under PEP placement, carries the loader's observation at context.mission_state_observation, with state, mode and freshness_at, and no context.freshness`.
- **Per-class bounds** (`config/enforcement-scope.json:15-26`): 300 s for `consequential_read`, `consequential_write` and `non_consequential`; 30 s for `irreversible_action` and `privileged_administration`; 60 s for `external_commitment`; none for `audit_only`; beyond the bound, deny; issuer ceiling 300 s. The loader refuses any other mode: `published runtime posture (@spec runtime#runtime-operational, status#status-operational) > refuses unsupported modes, malformed or missing bounds, and bounds exceeding the issuer ceiling`.
- **Clock skew.** An observation up to 5 s in the future is accepted (`evaluate.ts:94`), and clamped to the decision instant for the permit cap: `permit deadline (@spec runtime#state-freshness) > clamps a skew-tolerated future observation to the decision instant, so skew cannot lengthen a permit`.
- **Permit lifetime.** 120 s for `irreversible_action`, 300 s otherwise (`evaluate.ts:1339`), capped by the observation plus the class bound, a reported expiry, a signed `fresh_until`, and 300 s for the two keyed writes (`evaluate.ts:1357-1377`). The high-consequence classes get `use_limit` 1: `a permit expires no later than the state view it was decided against (@spec runtime#state-freshness) > caps valid_until at the state observation plus the class staleness bound`.
- **Execution lease.** 30 s for both high-consequence classes, capped by `valid_until`; validity and phase are checked at admission and again just before commit (`server.ts:1366`, `:1475`): [FGA] `M5 transaction-assurance tier > derives the execution lease from the published transaction_assurance maximum, capped by the permit's validity`.

Unavailable or stale state fails closed:

| Condition | Refusal | Witness |
|---|---|---|
| Mission not found by the loader | `unknown_mission`, signed `state_unavailable` (`pep.ts:1132`) | no test yet on the Mission-bound path |
| Malformed observation | `state_unavailable`, the PDP is not asked (`pep.ts:1207-1209`) | `the PEP sends the AuthZEN profile's members (@spec authzen#context-audience-freshness, #1004) > under PEP placement, refuses state_unavailable without asking the PDP when the loader's observation lacks a member its mode requires or carries a malformed one` |
| Observation absent, stale or past the skew; version mismatch | `stale_state` | `AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004) > under PEP placement the PDP reads context.mission_state_observation > a missing observation denies stale_state for every high-consequence class` |
| Mission not `active` (the PDP's view wins) | `mission_inactive` | `AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004) > the PEP-supplied state is exactly active, and the PDP's own view wins on disagreement (@spec authzen#pdp-request rule 1) > the PDP's own revoked view against a PEP-supplied active state denies mission_inactive: the PDP's view wins` |
| PDP throws, times out, is unreachable or answers non-2xx | `pdp_unreachable` | `configured PDP unavailability (@spec runtime#ride-through, authzen#failure-condition-coverage) > refuses a decision function that throws synchronously as pdp_unreachable, with one Refusal Record and no effect` |
| Unsigned, malformed or oversized PDP response | `channel_failure` | `configured PDP unavailability (@spec runtime#ride-through, authzen#failure-condition-coverage) > refuses an unsigned 200 response as channel_failure, with no PDP decision retained` |

Revocation after a decision is a stated bound, not a defect, and no
instantaneous revocation is claimed: an admitted high-consequence action runs
to completion inside its permit window (about 30 s or 60 s) under the runtime
profile's run-to-completion rule;
`callTransactionTool` does not re-read Mission state after `enforce`
(`server.ts:1323-1482`). No test yet. The next call decides afresh:
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
`discharged entries are excluded from the PDP's authority input > denies authority_discharged for the discharged entry while the Mission stays active`.
The gates are independently necessary:
`runtime decision gates are independently necessary (@spec runtime#decision) > a stale freshness failure denies even though authority and the Resource-policy/FGA check both permit`.

**Token authority:** partial. The PEP validates the token's signature,
issuer, audience, `cnf` and DPoP, and requires the `mission` claim
(`verifyDpopBoundToken`, `server.ts:478-495`):
`the PEP establishes token validity before using any of its claims as decision inputs (@spec runtime#token-validation) > a token whose audience does not name this resource is refused, before any of its claims reach a decision (@spec runtime#token-validation, audience)`.
It does not read the Mission-bound token's `authorization_details` or `scope`;
the PDP matches the kernel's current Authority Set (`evaluate.ts:1070-1077`).
A narrowed token is therefore not honored as narrower. Credential expiry is
checked only at validation; the PDP records `context.credential.expires_at`
in evidence but does not deny on it. Owner: #825 (PR 1 is #1062).

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
| Decision Evidence | PDP, role `pdp`, kid `pdp-decision-evidence`, key generated per boot (`stack.ts:520`) | every decision, permit or deny; a retransmission returns the stored record (`evaluate.ts:541-545`) |
| Refusal Record | PEP, role `pep` | every refusal before a PDP decision (`pep.ts:2079-2140`) |
| Execution Evidence, `suppressed` | PEP, role `pep` | every post-permit failure (`suppressExecution`, `pep.ts:1839-1882`), and a keyed write whose retry returns the stored result (`operation_already_claimed`) |
| Execution Evidence, `completed` | role `executor` | the transaction tier after the connector commits (`server.ts:1568-1599`), and reconciliation from the connector ledger |

- **Verification.** The PEP verifies Decision Evidence (byte equality, signature, emitter-bound kid, role, audience) and retains it verbatim; a permit whose record fails is refused `decision_evidence_unverifiable` (`pep.ts:1534-1546`): `a permit the PDP did not evidence is refused, never executed (#741) > refuses the action when the decision carries no Decision Evidence`.
- **Outcomes** are `completed`, `failed` and `suppressed` (`services/mcp-payments/src/evidence.ts:213`). Nothing emits `failed`. An unknown outcome is not an Execution Evidence outcome; it is the PDP claim state `indeterminate`.
- **Coverage gap.** A successful call outside the transaction tier emits no Execution Evidence (`server.ts:1021`, `:1084`, `:1288`); only its Decision Evidence exists. No test asserts the absence.
- **Retention.** `EvidenceRetentionStore` is built without a file, so it is in memory (`stack.ts:566-568`), with a 31,536,000 s window from the `policy.json` audit horizon and no capacity limit. Restart recovery is shown only on a test file: `retention honors the declared audit window (@spec runtime-evidence#receipt-retention) > recovers the retained records, the emitter sequences and the key retirement metadata after a restart`.
- **Emission failure.** A PDP whose emitter throws releases the claim, and the PEP refuses `pdp_unreachable`; a Refusal Record emission that throws rejects `enforce`; `suppressExecution` retries once and then records `gap: "emission_failed"`; the `completed` write after a connector commit has no error handling and leaves the operation `connector_committed`. No test yet for the emitter throw, the Refusal Record throw, either `suppressExecution` gap, or the `completed` write failure. #1104.

## 7. Persistence and restart

No transaction spans two stores. The transaction tier writes redemption, then
the connector effect, then evidence, then claim settlement.

| Store | Backing as shipped | Atomic unit | Restart |
|---|---|---|---|
| PDP idempotency claims | SQLite file `var/pdp-idempotency-claims.sqlite`, exclusive lock, WAL, `synchronous=FULL` (`stack.ts:531-538`) | lookup and insert in one transaction; the decision is persisted before the response | a prior boot's `permit_issued` becomes `unresolved`; an unpersisted `claimed` is adoptable; `unresolved` closes `indeterminate` at `valid_until` plus 30 s plus PT15M and is never purged |
| PEP write reservations | SQLite file `var/pep-write-reservations.sqlite` (`stack.ts:553-559`) | reservation, effect and completion in one transaction | survives; completed rows read absent after P7D; its `sweep()` has no production caller |
| `TransactionEngine` | in memory (`services/mcp-payments/src/transaction.ts:41`) | redemption is three statements, not one transaction | lost, with every redemption record. Every process reuses the constant epoch `demo-epoch` (`demo/src/stack.ts:704`), so D39's prior-epoch rejection (`transaction.ts:60-61`) never fires: a restarted engine has no record of earlier redemptions. The PEP's `instanceEpoch` is also `demo-epoch` (`stack.ts:740`) and is never read |
| Connectors, txn stores, evidence retention | in memory | one insert per operation key; atomic first use of a `txn` | lost |
| Payments store, DPoP replay cache, actor records | in memory, seeded per boot | none | lost or reseeded |
| Kernel and provider stores | the floor's (`provider-integration-port.md`) | the floor's | the floor's (`control-plane-deployment.md`) |
| Keys | generated per boot under fixed kids | none | rotated (#831) |

Witnesses for the durable stores:
`PDP idempotency claim (@spec runtime#idempotency, #917) > crash boundaries and restart > a persisted permit is unknown after restart: suppressed, never returned, never fresh`
and
`the PEP's reservation and retention for keyed reversible writes (@spec runtime#idempotency, #918) > the persisted store reopens with the record > a key scheduled before the store closed resolves against its record from a new server on the same file`.

Residuals:

- **The declared reconciler does not run.** `outcome_reconciliation` names `mcp-payments-pep`, a PT15M window and an operator alert, but `reconcileClaims` and `reconcile` have no non-test caller and no alert exists. #1103.
- **Restart.** The claim channel's requester epoch is `demo-epoch` plus a UUID drawn per process (`services/mcp-payments/src/redemption-status.ts:67`), not the engine's constant. Claim listing and reconciliation match that epoch exactly (`services/pdp/src/idempotency-claims.ts:647`, `:682`), so a restarted PEP cannot list or reconcile a prior process's claim, and a retry against its `permit_issued` claim is suppressed (`idempotency-claims.ts:444-455`): `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > refuses the retry when the redemption store cannot answer, or answers for another epoch`. The claim closes `indeterminate` and its key stays refused. Single use across a restart rests on this persisted claim and the PEP's write reservations, not on the engine, whose redemption records are lost; no restarted process can prove a prior permit unredeemed. Safe restart recovery is #1103's.
- **The operation key omits `idempotency_key`.** One redemption is allowed per Mission, action, phase and digest per process, so a new key for an unchanged invoice is refused `permit_consumed`: [FGA] `M5 transaction-assurance tier > a FRESH permit for an already-claimed operation is refused as operation_already_claimed and does not double-execute`. This target states it as a bound: a repeat is refused, never executed twice.
- **No assembled restart test.** Restart is tested only at the unit level for the two durable stores and the transaction-token crash window. #873, #250, #1103.

## 8. Claims, exclusions and residuals by action path

Claims apply per action path, never as a product-wide maximum. An
unsupported obligation is refused or its claim excluded.

| Action path | Claimed | Not claimed | Residuals and owners |
|---|---|---|---|
| Reads (`list_invoices`, `get_invoice`, `lookup_vendor`, `check_transfer`) | per-call decision on current Mission authority and state; per-action `vendors` | Execution Evidence on success | #825 and #828 (required, §1) |
| Keyed writes (`schedule_payment`, `cancel_scheduled_payment`) | per-action `max_amount` and `vendors`; PEP-reserved idempotency with a durable record | reservation sweep; reconciliation of a `reserved` row | #1103 |
| Prepare (`hold_transfer`) | per-call decision; phase binding | idempotency or permit-lifetime control; any stored effect | #1080 |
| Transaction tier (`execute_wire_transfer`, `send_remittance_email`) | single-use permit, execution lease, PDP-held Exact claim, digest and phase binding, Execution Evidence; action-bound approval for remittance | restart recovery beyond the claim store; reconciliation run; transaction-grade resource witnesses; a failed commit predicate that retains the permit | #1103, #1104, #250, #817 |
| Every path | per-action limits only | any aggregate cap; compromise containment; unattended prohibited-class exception | excluded by D284; #825 and #828 are required, not excluded (§1) |

**The aggregate-cap exclusion is enforced by refusal.** The issuer refuses an
Intent carrying a member it does not implement, such as `max_budget`, under
the closed-top-level rule (`validateMissionIntent`,
`services/authorization-server/src/kernel/intent.ts`):
`intent validation (@spec mission#submission-via-par) > rejects unknown top-level members (closed top level)`.
That test uses another member; no test names `max_budget`.

**Unmet obligations by owner:**

- Blocking acceptance: #825 (token authority; PR #1062) and #828 (Resource policy).
- Acceptance-pack prerequisites: #1105 (launcher, MAS route excluded), #1103 (reconciliation never runs), #1104 (emission failures), #1106 (Operation Profile drift), #1080 (`hold_transfer` permit control).
- Separated deployment only: #1101 (state source under D293).
- Also open: #826 (Approver versus Subject; PR #1074), #831 (keys and verifier refresh), #250 (control-plane atomicity; revoke versus issue), #916 (approval commits before grant binding), #830 (identity changes apply at restart), #817 (resource-side execution capabilities), #773 (context-drift vectors, conditional), #873 (inherited floor obligations).
- #917 and #918 are closed as implemented (D245, D247); their leftovers are owned by #1103 and #1080.

## 9. Pinned adoption closure

Computed from `family-manifest.json` at `538d0d61`: the start set, its
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
| `draft-mcguinness-mission-runtime.md` | `84822ae9` | the runtime overlay |
| `draft-mcguinness-mission-runtime-oauth.md` | `2b422bf1` | Runtime OAuth credential validation |
| `draft-mcguinness-mission-authzen.md` | `6f10361e` | the decision wire: Decision Base, Transaction Assurance, Runtime Evidence and ARAP; not Obligations, History or Batch |
| `draft-mcguinness-mission-runtime-evidence.md` | `c8a4d8b8` | the portable Decision, Execution and Refusal objects |
| `draft-mcguinness-mission-capability-binding.md` | `2dc6ca1d` | `config/catalog.json` sources every payments action, and the PDP refuses `capability_drift` |

**Relied on for terms, not as the wire source:**
`draft-mcguinness-oauth-mission-status.md` `48521467` defines the Effective
Authority Set, the lifecycle states, `mission_max_stale_seconds` and the
floor's `revoke`. Its Mission Status operation is not this co-located
target's state source (D293, §4); a separated realization uses it or core
introspection (#1101).

**Conditional, not triggered:**

| Draft | Hash | Why not |
|---|---|---|
| `draft-mcguinness-oauth-mission-transaction-authorization.md` | `091f1ffd` | the AS `transaction-authorization` capability is off on the floor |
| `draft-mcguinness-oauth-mission-containment.md` | `5421debe` | `containment` off; the PDP sees an empty delta |
| `draft-mcguinness-oauth-mission-discharge.md` | `5421debe` | `discharge` off |
| `draft-mcguinness-oauth-mission-signals.md` | `eb59a919` | no lifecycle subscriber; not the state source |
| `draft-mcguinness-oauth-mission-status-list.md` | `4fe0d0b0` | off |
| `draft-mcguinness-oauth-mission-cross-domain.md` | `02014aa3` | no projected credentials or decisions on this path |
| `draft-mcguinness-oauth-mission-attenuation.md` | `4fe0d0b0` | the AS does not advertise `mission_attenuation_supported` |
| `draft-mcguinness-mission-authority-server.md` | `30933b36` | the MAS join route is excluded from this target (#1105) |

**Reader bundle, informative:** `draft-mcguinness-mission-architecture.md`
`3f95ce1c`, `draft-mcguinness-mission-control-plane.md` `909a3ee7` (kept
informative as on the floor; adopting it would pull in Signals and Status),
and `draft-mcguinness-mission-security-model.md` `20706d3b`.

**Deployed components beyond the drafts:** OpenFGA; the AuthZEN ARAP access
request profile through the in-process `AccessRequestService`; the floor's
RFC list (`issuance-only-deployment.md` §9), plus RFC 9728 for the resource
metadata that publishes the Enforcement Scope Statement.

## 10. Acceptance prerequisites

The assembled acceptance pack (#253 Sketch step 3) pins the assembled path's
revision and exercises each vector below. Only the `src/demo/test` files
`remote-pdp-stack`, `mas-join-stack` and `pep-emission-boundary` run
`composeStack`; no test yet drives an AS-issued Mission-bound token through
`mcp-payments` and the real PDP (#1105).

The pack cannot pass while #825 or #828 is unmet (§1).

| Vector | Existing witness | Gap |
|---|---|---|
| Valid request | [FGA] `M4 core enforcement tier > scenario 2: happy path -- in-authority read permitted, Decision Evidence recorded` | not on the assembled path |
| Narrowed token | none | #825 (PR #1062); required, blocks acceptance |
| Independent policy revocation | a stubbed policy only: `finding 3: a multi-vendor list_invoices names every returned vendor to Resource policy, not just one representative (@spec read-binding) > Mission authority includes two vendors; Resource policy denies one: the whole read refuses out_of_authority, never a narrowed result` | #828; required, blocks acceptance |
| Stale or non-active Mission at admission and at each fresh commit-phase decision | the §4 refusal table; `compound-action phases (@spec runtime#compound-actions) > denies the fresh commit Decision when the Mission deactivates after prepare` | not on the assembled path |
| Run to completion after an earlier valid permit | none | no test yet that an admitted action completes only inside its permit and lease bounds and that the next decision refuses; no instantaneous revocation is implied (§4) |
| Parameter digest mismatch | [FGA] `M4 core enforcement tier > scenario 3: TOCTOU -- invoice mutated between decision and execute -> parameter_mismatch refusal` | |
| Permit replay | [FGA] `M5 transaction-assurance tier > the SAME evaluation identifier presented again is refused as permit_consumed, and the completed record stands` | |
| Phase mismatch | `compound-action phases (@spec runtime#compound-actions) > refuses a commit presenting check_transfer's preflight permit` | |
| Failed commit predicate with the permit retained | none | applies only to a connector that claims a commit-point predicate; none does at this revision (#817), so the guarantee stays excluded (§8) |
| Bob for Alice, with and without `openid` | Subject selection only: `approval resolution establishes identity from the surface (#759, #761) > the pushed login_hint is resolved and authorized, never accepted as an arbitrary Subject` | #826 (PR #1074) |
| Revoke during issuance | none on this surface | #250, #873 |
| Restart and uncertain recovery | the unit-level witnesses in §7 | no assembled restart test; reconciliation never runs (#1103) |
| Emission failure | none (§6) | #1104 |
| Unknown or authoritative argument member | none; unknown tools only (§3) | #1106 |

Each new test in the pack must fail when its guard is disabled, and a ledger
row reaches `tested` only with an exact `describe > it` citation at the
correct surface and role.

## 11. Run it

No launcher assembles exactly this topology yet. `pnpm demo:serve`,
`pnpm exhibit`, `pnpm agent` and `pnpm demo` assemble `composeStack` and need
`docker compose up -d` (OpenFGA) and `pnpm setup` (`src/DEMO.md`); they also
start the excluded MAS route and other surfaces. #1105 owns a dedicated
launcher with that route excluded.

## 12. Status

Adopted (D284) as the first runtime reference target; not a conformance
class, and no production-readiness or interoperability claim. This document
is #253 Sketch step 1. Next:

1. **Runtime integration port (step 2):** extend
   [provider-integration-port.md](provider-integration-port.md) with protected
   state and lifecycle and resource composition rows, in its eight columns.
2. **Acceptance pack (step 3):** the launcher (#1105) and the vectors of
   §10, after the required enforcement gaps (#825, #828) and the recovery
   gaps (#1103, #1104) are resolved.
3. **Second route (step 4):** #818's legacy-estate/MAS route, demonstrated
   independently and separately pinned.

A later commit invalidates any statement here until it is re-checked against
that commit. #253 closes only when both reference routes are demonstrated,
unless a later owner ruling changes that requirement.
