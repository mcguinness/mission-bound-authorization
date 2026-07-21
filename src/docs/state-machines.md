# Approval Ownership and Irreversible-Operation State Machines

Decisions D36/D37. Two machines: who owns approval state, and how an
irreversible operation moves from decision to reconciliation.

## Approval ownership (D37)

| Object | Owner | States |
|---|---|---|
| Mission approval interaction | AS | `proposed -> rendered -> approved / refused` |
| Expansion approval interaction | AS | same, over the successor record |
| OAuth pending artifacts (`deferral_code`, `transaction_authorization_id`) | AS | `pending -> redeemable -> redeemed / expired / denied` (single redemption) |
| ARAP/AROP task + approval objects | ARS | ARAP task lifecycle; terminal approval carries `approved_until` |

Rules:

- The AS stores the ARS task handle and the validated terminal approval;
  only the AS issues credentials. Approval completion never directly
  executes an action.
- An AROP approval never satisfies `action_approval_required` implicitly:
  the parameter-bound approval is passed explicitly as `context.approval`
  and the PDP validates it.
- Governance: a mission whose authority contains writes or irreversible
  actions requires an approver distinct from the subject (Bob for the
  demo); read-only missions may be self-approved (Alice).
- Restart (D39): pending AS artifacts and ARS tasks are terminally
  unavailable after their owner restarts; redemption attempts fail closed.

## Irreversible operation machine (D36)

Owned by the payments service (the PEP), persisted in its store:

```
reserved -> permit_consumed -> connector_committed -> evidence_emitted -> reconciled
```

- `reserved`: effective parameters built (authoritative fields + record
  versions), PDP decision obtained, permit properties recorded, lease
  started. Crash here: nothing executed; permit expires; safe.
- `permit_consumed`: atomic redemption (`redeemOnce`, keyed by the permit's
  single-use identifier + instance epoch) and the conditional re-read of
  record versions succeed, inside the lease. Crash here: connector has the
  idempotency key `op:<mission>:<action>:<parameter_digest>`; recovery
  re-drives the connector call, which deduplicates. Replay of the permit
  refuses with `permit_consumed`.
- `connector_committed`: the ledger/outbox accepted the operation. This is
  the commit point: cancellation is meaningless past it; the lease no
  longer applies.
- `evidence_emitted`: Execution Evidence signed and registered.
- `reconciled`: the reconciliation pass joined evidence to the connector's
  record (amount, idempotency key, outcome).

Failure/refusal at any pre-commit stage writes a Refusal Record with the
runtime `denial_reason` taxonomy (`permit_consumed`, `parameter_mismatch`,
lease expiry, freshness failure). No PDP outcome callback exists: duplicate
suppression is entirely PEP-side (D28); a duplicate decision is harmless
because the connector idempotency key and the redemption table make
double-execution impossible.

Epoch rule (D39): the machine's rows are keyed by instance epoch; a
restarted PEP starts a new epoch, rejects permits minted for a prior
epoch, and marks in-flight pre-commit operations of prior epochs
`abandoned` (fail closed). Post-commit recovery re-drives evidence
emission and reconciliation only.
