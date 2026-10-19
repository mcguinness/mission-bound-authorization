# Settle one invoice once

This walkthrough follows one wire for one invoice through the reference
payments resource, from admission to settlement, and names the test that
witnesses each failure case. It describes `payments-runtime-profile-v8`
([operation-profile-payments-v1.md](operation-profile-payments-v1.md)) as
built and adds no requirement. Paths are relative to `src/`.

## The operation

`execute_wire_transfer` with `{"invoice_id": "inv-1", "idempotency_key":
"<caller key>"}`: the commit phase of the compound action
`payments:payment.execute`, class `irreversible_action`, tier
`transaction-assurance`. The worked values are the transaction tier's
fixture (`services/mcp-payments/test/transaction.test.ts`): Mission
(`https://as.test`, `msn_m5`), subject `alice`, client `ap-agent`, one
`mission_resource_access` entry for `payments:payment.execute` with
`max_amount` 500.00 USD and `vendors: ["acme"]`, and invoice `inv-1`
(vendor `acme`, 125.00 USD, payee `acct-acme`, `payable`).

## Steps

`McpPaymentsServer.callTransactionTool` (`services/mcp-payments/src/server.ts`)
runs every step in one request.

1. **Intake.** `Pep.intake` (`services/mcp-payments/src/pep.ts`)
   NFC-normalizes the arguments and checks them against the served schema.
   A missing or malformed key is refused `invalid_request` before any
   decision request.
2. **Parameters.** The PEP establishes the operation target from the
   Operation Profile (`Pep.operationTargetFor`), loads the invoice and
   vendor from the payments store, and builds the effective parameters,
   including `invoice_version`, `vendor_version` and the target as
   `resource` (`buildEffectiveParams`,
   `services/mcp-payments/src/effective-params.ts`). `parameterDigest`
   commits them.
3. **Decision.** `Pep.enforce` reads Mission state live and sends one
   evaluation request with the digest, the operation target, the phase
   `commit` and the key. The
   PDP (`evaluate`, `services/pdp/src/evaluate.ts`) checks Mission state,
   both authority bounds, Resource policy and parameters, then claims
   (idempotency scope, key) with the operation identity
   (`IdempotencyClaimDomain.claim`, `services/pdp/src/idempotency-claims.ts`).
   The permit carries `evaluation_id`, `valid_until`, `use_limit: 1`,
   `parameter_digest` and `action_phase`.
4. **Admission.** `Pep.verifyPermitAtUse` compares the phase, the
   operation target and the permit's validity before anything is stored. The execution lease is the
   published 30 s maximum capped by `valid_until` (`executionLeaseMs`,
   `services/pdp/src/permit-deadline.ts`).
5. **Redemption.** `TransactionEngine.redeemPermit`
   (`services/mcp-payments/src/transaction.ts`) takes the single use, keyed
   on the operation key, and `recordRedeemingAttempt`
   (`services/mcp-payments/src/redemption-status.ts`) records which attempt
   took it.
6. **Reverification.** `Pep.reverifyCapability`,
   `TransactionEngine.leaseValid`, then `Pep.reverify`, which recomputes the
   digest from the store, and `Pep.verifyPermitAtUse` once more. A failure
   suppresses the attempt and records Execution Evidence `suppressed`.
7. **Commit point.** `Connectors.postWire`
   (`services/mcp-payments/src/connectors.ts`) returns the original result
   for a known operation key (`deduped`), refuses a wire for a settled
   invoice (`already_settled`), or inserts the ledger row with its
   `permit_id` and `op_key`. The unique index `ledger_settlement` on
   `invoice_id` holds settle-once.
8. **Execution Evidence.** `EvidenceStore.recordExecution`
   (`services/mcp-payments/src/evidence.ts`) signs the record:
   `execution_id`, `evaluation_id`, both parameter digests and `outcome`
   `completed`. A retry reuses the same `execution_id`.
9. **Claim settlement.** `Pep.settleClaim` sends the signed record to the
   PDP. The claim becomes `completed`, and the key stays refused for the
   published horizon (604800 s).
10. **Reconciliation.** `OutcomeReconciler.runOnce`
    (`services/mcp-payments/src/outcome-reconciler.ts`) runs every third of
    the PT15M window. `reconcileClaims` (`claim-reconciliation.ts`) settles
    each unresolved claim from the attempt's retained record, from the
    ledger entry recorded against its permit (`Connectors.committedFor`), or
    as never redeemed once its lease has elapsed. Anything else stays open,
    and the PDP closes it `indeterminate` at the window's end with the
    declared operator alert. The reconciler also alerts what `reconcile`
    (`reconcile.ts`) leaves unmatched: evidence with no effect, and an
    effect with no evidence once older than the window.

## Identifiers

| Identifier | Value | Minted by | Recorded in | Code |
|---|---|---|---|---|
| Mission reference | (`https://as.test`, `msn_m5`) | the AS | the token's `mission` claim, every record's `mission_id`, the idempotency scope, the operation key | `TokenFacts.mission`; `resolvedMission` in `callTransactionTool` |
| Settlement identity | `inv-1` (`invoice_id`) | the payments store | the ledger's `invoice_id`, unique (`ledger_settlement`) | `Connectors.postWire`, `Connectors.settled` |
| Idempotency scope | mission, subject, actor, audience, action, resource, phase | the PDP, from validated request members | the claim row | `idempotencyScopeOf` (`services/pdp/src/projections.ts`); `idempotency_scope` in `config/enforcement-scope.json` |
| Idempotency key | the caller's `idempotency_key`: 16 to 128 of `[A-Za-z0-9_-]`, one per intended execution | the caller | `action.properties.idempotency_key` and the claim row; never `parameter_digest` | `IDEMPOTENCY_KEY_PATTERN` (`packages/mission-core/src/idempotency.ts`) |
| Operation target | `http://localhost:4403/mcp`, the canonical resource URI | the Operation Profile (`TOOL_ACTIONS`) | `resource.properties.operation_target`; the effective parameters' `resource` | `Pep.operationTargetFor` |
| Operation identity | digest over the action, the resource object, the operation target and `parameter_digest` | the PDP | the claim row; another identity under the same key is `idempotency_conflict` | `operationIdentity` (`projections.ts`) |
| `parameter_digest` | `sha-256:` and 43 base64url characters over the effective parameters | the PEP | the permit's conditions, Decision and Execution Evidence | `parameterDigest` (`effective-params.ts`) |
| Operation key | `op:msn_m5:payments:payment.execute:commit:<parameter_digest>` | the PEP | the redemption store, the operation state machine, the ledger's `op_key`, the Execution Evidence join | `operationKey` (`transaction.ts`) |
| `evaluation_id` | `dec_<uuid>`; `decision_id` carries the same value | the PDP | the permit, the claim row, Decision and Execution Evidence, the ledger's `permit_id` | `newDecisionId` and `base` in `evaluate.ts` |
| `execution_id` | `exe_<base64url>`, one per disposition attempt | the PEP | Execution Evidence and the redeeming-attempt link | `newRecordId("exe")` in `Pep.enforce`; `recordRedeemingAttempt` |
| Resource correlation identifier | the ledger row's `permit_id` (the `evaluation_id`) and `op_key` | the resource, at the commit point | the ledger | `Connectors.committedFor`, `Connectors.committedEffects` |

The profile's Idempotency keys section shows the operation key without its
phase; for a phase of a compound action, `operationKey` appends it. The
ledger records the permit with each effect, and reconciliation attributes an
effect to an action only through that record (W19). The family defines no
provider operation identifier member, and the simulated ledger returns none.

## Outcome classes

Orchestration defines `committed` and `unknown` by evidence (`#in-flight`),
and its `unknown` is Runtime's undetermined outcome.

| The evidence establishes | Execution Evidence | PDP claim | Orchestration | Runtime | AEB, through Runtime Evidence |
|---|---|---|---|---|---|
| The effect occurred: a `completed` record, or a ledger entry under this permit | `completed` | `completed` | `committed` | final outcome | EXECUTED |
| No effect: refused under the permit, before or at the commit point | `suppressed`, with `error` | `failed`, from the redeeming attempt only | not `committed` | final outcome | refusal before provider entry |
| No effect: the permit was never redeemed, proven in its epoch after the lease | none | `failed` | not `committed` | final outcome | not invoked |
| Neither | none | unresolved, then `indeterminate` at the window's end | `unknown` | undetermined outcome | INDETERMINATE |

`classifyOutcome` (`packages/orchestration/src/in-flight.ts`) reads the
operation state alone: `connector_committed`, `evidence_emitted` and
`reconciled` are `committed`; `abandoned`, which a refusal after redemption
sets, and any unrecognized state are `unknown`. The classifier fails closed:
a refused attempt goes to human review although its `suppressed` record
establishes no effect, and post-completion behavior never runs on it (W27,
W28).

## Failure cases

| Case | Reference behavior | Guarantee | Witness |
|---|---|---|---|
| Two workers | Same key: the claim is one linearizable operation. One request gets the permit; every other gets `duplicate_suppressed` with `next_action: retry`, also while the first holds its redeemed permit. Distinct keys, one Mission, unchanged record: each key gets a permit, and redemption, keyed on the operation key, admits one; the other is suppressed `operation_already_claimed`. Distinct keys are witnessed in sequence; redemption is one synchronous statement (`redeemOnce`). | One permit per key, one redemption per operation, one wire | W1, W13, W2, W10 |
| Lost PDP response | A retry under the same key gets the same decision back while the permit is unexpired and the PEP answers `unconsumed`. Once the permit is redeemed, or when the PEP cannot answer, the retry is refused `duplicate_suppressed`. An unreachable claim domain yields no decision: `pdp_unreachable`, and nothing executes. | A lost response does not lock the action out, and no second permit issues | W3, W4, W5 |
| Crash before dispatch | Before redemption: once the permit and its lease elapse, reconciliation proves the permit unredeemed in its epoch and settles the claim `failed`. The key stays refused, and a new key executes. After redemption, before the commit point: nothing establishes the outcome, so the claim stays open, closes `indeterminate` at the window's end with the declared alert, and the key stays refused. | No effect is assumed, and time never resolves an outcome | W6, W7, W8 |
| Lost provider acknowledgement | The commit point is a synchronous in-process insert, so the reference cannot lose an acknowledgement between the PEP and the ledger; it witnesses recovery when what follows the commit is lost: the evidence write, the rest of the attempt, or the settlement message to the PDP. Reconciliation settles `completed` from the ledger entry recorded against the permit, or from the attempt's retained record. A retry under the key is refused, a new key is refused at redemption, and a re-drive under the operation key is `deduped` at the ledger. | The effect stands once, and its outcome comes from attributable evidence | W9, W10, W11, W12, W20 |
| A replacement worker, with the original resuming | The original holds the redeemed permit: the replacement's same-key request is refused `duplicate_suppressed` with `next_action: retry`; the original resumes and commits; the replacement's retry is then refused as completed. The original holds an unredeemed permit: the PDP returns that permit to the replacement, which executes; the original, resuming with it, is refused `permit_consumed`. | One wire, under one `evaluation_id` | W13, W14 |
| Mission termination while unresolved | Reconciliation reads no Mission state: after termination it still settles the claim from the ledger entry recorded against the permit. A new effect under the terminated Mission is refused `mission_inactive`: the PDP refuses a non-active state in its own view and in the state the PEP reads live and sends (`evaluate.ts`). The PEP reads Mission state for the decision only, so an attempt already holding its permit runs to its commit point within the permit's validity and the lease (by code reading; no test isolates it). | No new effect under a non-active Mission, and the outcome of initiated work is still recorded | W15 |
| Duplicate settlement evidence | The same completed record sent twice settles the claim once (`duplicate: true`); a second, distinct completed record for the evaluation is refused `already_settled`. A record retried after it was retained, or emitted twice at once, is kept once under its `execution_id`. Reconciliation records nothing new where the attempt's record exists. A completed record with no committed effect is alerted `orphaned_evidence` and never matched. | One settlement per evaluation; evidence never creates or doubles an effect | W16, W17, W18, W12, W26 |
| A different request key for the same invoice | Same Mission, unchanged record: the operation key is unchanged, and redemption refuses it (`operation_already_claimed`; the caller sees `permit_consumed`). Same Mission after the record changes, or another Mission: the operation key differs, and the ledger refuses `already_settled`, recorded `suppressed` with `https://payments.demo/execution-errors/already_settled`. `check_transfer` then reports the invoice not feasible. | The invoice settles once under any Mission, operation key or caller key | W2, W10, W21, W22, W23, W24 |
| A target fact changing before commit | A change between the decision and the reread moves `parameter_digest`, and the attempt is suppressed `parameter_mismatch` with no wire. By code reading, the reread and the ledger insert are separate steps, and the ledger compares no record version, so a change after the reread is not refused; the wire still pays the amount and payee the permit bound. The reference claims no Evaluation-Context Binding, and Runtime keeps this residual (`#security-considerations`, TOCTOU and Replay). | The executed parameters equal the authorized ones, checked up to the reread | W25, W29 |

### Witnesses

Each entry is a file and its `describe > it` path. "(OpenFGA)" marks a test
that runs only against a live OpenFGA; "(new)" marks a test this walkthrough
added.

- W1. `services/pdp/test/idempotency-claim.test.ts`: `PDP idempotency claim (@spec runtime#idempotency, #917) > the claim is one linearizable operation > eight concurrent identical evaluations on one file store yield one permit, one row, and seven transient duplicate_suppressed`
- W2. `services/mcp-payments/test/transaction.test.ts` (OpenFGA): `M5 transaction-assurance tier > a FRESH permit for an already-claimed operation is refused as operation_already_claimed and does not double-execute`
- W3. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > returns the prior permit while the redemption store answers unconsumed, and refuses it once the permit is redeemed and its settlement is held`
- W4. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > refuses the retry when the redemption store cannot answer, or answers for another epoch`
- W5. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > an unreachable claim domain over the co-resident channel: the PEP records pdp_unreachable and nothing executes`
- W6. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > a refusal before any effect: a permit proven unredeemed in this epoch settles failed, and a retry under its key executes nothing`
- W7. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > reconciliation proves a permit that was never redeemed failed, within its epoch`
- W8. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > an outcome nothing establishes stays open, closes indeterminate when its window closes, and raises the declared alert exactly once, never from a run's open list`
- W9. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > missing evidence after an effect, over the remote channel: the wire stands once, and a run inside the window settles the claim completed from the ledger, with exactly one ledger entry`
- W10. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > a completed write that fails twice reports the gap: the effect stands once, the claim is not settled completed, and neither a retry nor reconciliation repeats the effect`
- W11. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > reconciliation settles a committed effect whose evidence never arrived, from the connector ledger`
- W12. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `the PDP idempotency claim through the executing PEP (@spec runtime#idempotency, #917) > reconciliation settles a claim whose settlement never arrived, from the attempt's retained evidence`
- W13. `services/mcp-payments/test/idempotency-claim-pep.test.ts` (new): `a replacement worker while the original's request is in flight (@spec runtime#idempotency, #1176) > the original holds the redeemed permit: the replacement is refused as unresolved and retryable, the original resumes and commits once, and the replacement's retry is refused as completed`
- W14. `services/mcp-payments/test/idempotency-claim-pep.test.ts` (new): `a replacement worker while the original's request is in flight (@spec runtime#idempotency, #1176) > the original holds an unredeemed permit: the replacement receives that permit again and executes once, and the original, resuming with it, is refused permit_consumed with no second effect`
- W15. `services/mcp-payments/test/outcome-reconciler.test.ts` (new): `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > a Mission terminated while an outcome is unresolved admits no new effect under it, and reconciliation still records the outcome of the wire already initiated (@spec runtime#evidence, #1176)`
- W16. `services/pdp/test/idempotency-claim.test.ts`: `PDP idempotency claim (@spec runtime#idempotency, #917) > crash boundaries and restart > a lost settlement acknowledgement is resent and applied once`
- W17. `services/mcp-payments/test/idempotency-claim-pep.test.ts`: `evidence emission failures: a refusal before any effect, or a reported gap after one (#1104) > a completed write that fails once is retried on the same execution identity: one record, the claim settles completed, one effect`
- W18. `services/mcp-payments/test/execution-identity-concurrency.test.ts`: `one execution identity survives concurrent emission > collapses two concurrent emissions of one disposition to one record when the first signature returns first`
- W19. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > resource state alone settles nothing: another operation's wire for the same invoice leaves a redeemed permit's outcome open, with no evidence recorded for it (@spec runtime#evidence, #1271)`
- W20. `services/mcp-payments/test/settlement-identity.test.ts`: `settlement identity (@spec runtime#security-considerations, operation-profile-payments-v1) > dedupes a retry under the same operation key instead of refusing it`
- W21. `services/mcp-payments/test/transaction.test.ts` (OpenFGA): `M5 transaction-assurance tier > the same Mission cannot settle an invoice twice after the record changes: a new key and digest are refused already_settled (#1270)`
- W22. `services/mcp-payments/test/transaction.test.ts` (OpenFGA): `M5 transaction-assurance tier > a second Mission cannot settle an invoice another Mission settled: refused already_settled with no effect (@spec runtime#security-considerations, #1270)`
- W23. `services/mcp-payments/test/settlement-identity.test.ts`: `settlement identity (@spec runtime#security-considerations, operation-profile-payments-v1) > refuses a second wire for a settled invoice under another operation key and Mission, with no effect`
- W24. `services/mcp-payments/test/transaction.test.ts` (OpenFGA): `M5 transaction-assurance tier > check_transfer reports a settled invoice as not feasible (#1270)`
- W25. `services/mcp-payments/test/transaction.test.ts` (OpenFGA): `M5 transaction-assurance tier > TOCTOU in the decision->commit window refuses before the connector commits`
- W26. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > alerts what stays unmatched after claim settlement: evidence of an effect that never committed at once, an effect without evidence once older than the window, and never a suppressed record or an email's effect`
- W27. `packages/orchestration/test/orchestration.test.ts`: `in-flight classification (@spec orchestration#state-change-behavior) > 6: maps D36 OpState fixtures onto the correct outcome class`
- W28. `packages/orchestration/test/orchestration.test.ts`: `state-change behavior (@spec orchestration#state-change-behavior) > an unknown step never runs its post-completion behavior: a compensate plan routes to human review (§ in-flight)`
- W29. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > a refusal before any effect: the redeeming attempt's own suppressed Execution Evidence settles failed when its settlement never arrived, and nothing executes`
- W30. `services/mcp-payments/test/outcome-reconciler.test.ts`: `the declared outcome reconciler runs the reconciliation (@spec runtime#evidence outcome reconciliation, #1103) > missing evidence after an effect across a restart: the prior epoch's claim is never listed, closes indeterminate when its window closes with the declared alert, and the retry executes nothing`

## The Action Evidence Boundary

Runtime Evidence's Relationship to the Action Evidence Boundary
(`#aeb-relationship`) aligns the two layers. The reference reads no AEB
artifact and depends on nothing AEB defines. Through that section:

- **Exact-action binding.** `parameter_digest` covers the whole effective
  parameter object, including the record versions the store resolved. The
  reference claims no Evaluation-Context Binding and carries no
  `evaluation_context_digest`.
- **Consumption.** `TransactionEngine.redeemPermit` takes the single use
  per operation key before provider entry.
- **Provider entry.** `Connectors.postWire` is the commit point.
- **Outcomes.** EXECUTED is `completed`. Runtime Evidence maps a refusal
  under a permit before provider entry to `suppressed`; the profile also
  records the ledger's own `already_settled` refusal as `suppressed`,
  because no money moved.
- **Reconciliation.** An unresolved claim is AEB's INDETERMINATE: its
  Decision Evidence stays orphaned, which a consumer classifies as
  undetermined-outcome. Reconciliation resolves it only from an identifier
  the ledger recorded with the effect.

## Topology

- One enforcement identity requests and executes the permit: the `Pep`
  inside `McpPaymentsServer` (`mcp-payments-pep`), in one process and one
  call. AuthZEN's split-topology rule (`#permit-binding-split`) requires
  this: the requesting component and the executing PEP are one enforcement
  identity, and a requester/executor split is reserved for a future
  split-execution profile. The permit never leaves that identity.
- One PDP serializes the claim: the Exact enforcement profile with a local
  single writer (`idempotency_claim_topology` in
  `config/enforcement-scope.json`).
- A worker is a caller of the resource, so two workers, or a replacement
  and the original, are two calls into the same PEP.
- Transaction Authorization applies only where action-bound approval
  applies. The composed stack requires action-bound approval for
  `payments:remittance.send` alone (`requiresActionApproval` in
  `demo/src/stack.ts`), so the wire carries no transaction token, and its
  single use rests on the permit, the claim and the ledger.

## Limits of the reference

- The ledger, the redemption store and the operation state machine are
  in-memory SQLite (`openStore` with no file); the PDP's claim domain is a
  durable file. After a restart the claim still refuses the original key
  (W30), but the simulated ledger's settlement index is gone, so by code
  reading a new key could settle the invoice again in the new process. A
  real provider keeps its settlement record durable; the simulation does
  not.
- The reread-to-commit window above is not coupled to the ledger insert.
- The settlement identity covers `execute_wire_transfer` only.
  `send_remittance_email` dedupes on its operation key (the profile's
  residual).
- The ledger returns no provider operation identifier, so the reference
  cannot show reconciliation on one.
