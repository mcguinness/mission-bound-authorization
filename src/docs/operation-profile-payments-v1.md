# payments-runtime-profile-v1

The Operation Profile (runtime § operation-profile; decision D34) for the
internal payments estate. Every component that produces or verifies bytes
(AS derivation, PDP, PEP, evidence verifier, evals) implements this
document. Version: `payments-runtime-profile-v1`; changes bump the suffix.

## Canonical identifiers

- Canonical MCP resource URI (byte-for-byte everywhere per D38):
  `http://localhost:4403/mcp` (overridable via `.env`; whatever the value,
  it is used identically in PRM, OAuth `resource`, token `aud`, AuthZEN
  `resource.properties.audience`, and evidence).
- Tool ids (capability source `tool_id`): `mcp://payments.demo/tools/<name>`.
- AuthZEN action ids: `payments:<operation>` as listed below.

## Operations

| Tool | Action id | Resource type | Class | Tier |
|---|---|---|---|---|
| `list_invoices` | `payments:invoice.list` | `invoice` (collection) | `consequential_read` | core |
| `get_invoice` | `payments:invoice.read` | `invoice` | `consequential_read` | core |
| `lookup_vendor` | `payments:vendor.read` | `vendor` | `consequential_read` | core |
| `schedule_payment` | `payments:payment.schedule` | `invoice` | `consequential_write` (reversible) | core |
| `cancel_scheduled_payment` | `payments:payment.schedule.cancel` | `invoice` | `consequential_write` (reversible) | core |
| `check_transfer` | `payments:payment.execute`, phase `preflight` | `invoice` | `consequential_read` (no state, no effect) | core |
| `hold_transfer` | `payments:payment.execute`, phase `prepare` | `invoice` | `consequential_write` (a reversible hold) | core |
| `execute_wire_transfer` | `payments:payment.execute`, phase `commit` | `invoice` | `irreversible_action` | transaction-assurance |
| `send_remittance_email` | `payments:remittance.send` | `invoice` | `external_commitment` | transaction-assurance |

The Class column is the `action_class` the PEP sends on every decision
request (`TOOL_ACTIONS` in `services/mcp-payments/src/pep.ts`), recorded
in Decision Evidence with `class_source: "deployment"`. Every class is one
the Enforcement Scope Statement declares. The Tier column is the execution
path (`tier` in the same table): only `transaction-assurance` takes the
single-use permit, execution lease, and connector path. The three
`payments:payment.execute` rows are the phases of one compound action
(runtime compound actions); each phase is classified by what that
crossing does.

## Money

`{"amount": "<decimal string>", "currency": "<ISO 4217>"}` — the OAuth binding's. `amount` is a decimal string at the currency's minor
scale (USD: exactly two fraction digits), never a JSON number. Comparison
is numeric over the decimal string; serialization is byte-preserved.

## Constraint enforcement: max_amount

The matched Authority Set entry's `max_amount`, when bound, is checked
against the authoritative invoice `{amount, currency}` mapping (Money,
above), read from the payments store, never from a caller-supplied value.
Comparison is exact decimal, per Money above; no currency conversion is
performed anywhere in the chain.

Enforcement is keyed on `max_amount` being present on the matched entry,
never on which action it is bound to: a cap the PDP cannot supply an
amount input for (a request with no `amount`, or one it cannot parse)
refuses the same as an out-of-bound or currency-mismatched one (@spec
runtime#input-parameters, "cannot supply the declared inputs for ... MUST
cause refusal"). An entry with no `max_amount` never requires an amount
merely because the mapped action's own schema declares one.

| Case | Outcome |
|---|---|
| amount exactly at the cap | permits |
| amount over the cap | refuses (`parameter_violation`) |
| amount absent from the request context | refuses (`parameter_violation`) |
| amount not a valid decimal string | refuses (`parameter_violation`) |
| cap denominated in a different currency than the invoice's | refuses (`parameter_violation`), never converted |

## Parameter schemas and normalization

All request parameters are JSON objects validated against the schemas
below before any authorization work; strings are NFC-normalized at intake;
unknown members are rejected (`invalid_request` at the tool boundary).

- `get_invoice`: `{ invoice_id: string }`
- `schedule_payment`: `{ invoice_id: string, idempotency_key: string, execute_after?: RFC3339 }`
- `cancel_scheduled_payment`: `{ invoice_id: string, idempotency_key: string }`
- `execute_wire_transfer`: `{ invoice_id: string }`
- `send_remittance_email`: `{ invoice_id: string, note?: string (<= 500 chars) }`
- `list_invoices`: `{ vendor_id?: string, status?: enum }`
- `lookup_vendor`: `{ vendor_id: string }`

## Authoritative vs caller-supplied fields (D34)

Caller-supplied: `invoice_id`, `vendor_id`, `note`, `execute_after`,
filters. Authoritative (loaded by the PEP from the payments store, never
from the caller): invoice `amount`, `currency`, `payee_account`,
`vendor_id`-of-invoice, invoice `status`, vendor `status`, and the record
versions. Agent-supplied values for authoritative fields are ignored;
their presence in a request is a schema violation.

## Effective parameters and the parameter digest

For consequential operations the PEP constructs the **effective
parameters** object: caller-supplied fields (post-normalization) merged
with the authoritative fields and the record versions:

```json
{
  "action": "payments:payment.execute",
  "invoice_id": "inv-42",
  "invoice_version": 7,
  "vendor_id": "acme",
  "vendor_version": 3,
  "amount": { "amount": "1250.00", "currency": "USD" },
  "payee_account": "acct-acme-001",
  "resource": "http://localhost:4403/mcp"
}
```

`parameter_digest` = `sha-256:` + base64url(no pad) of SHA-256 over the
JCS canonicalization of that object (the anchor encoding family; computed
with `@mission/core`). The digest binds decision to execution: the PEP
recomputes it immediately before commit after conditionally re-reading the
same record versions; any mismatch (record changed, parameter mutated) is
a refusal with reason `parameter_mismatch`.

## Idempotency keys

`op:<mission_id>:<action id>:<parameter_digest>` — passed to the ledger
and outbox connectors, which reject duplicates. Retries of the same
effective operation are therefore safe at the connector even if upstream
state machines fail mid-flight.

`execute_wire_transfer` and `send_remittance_email`, the two
high-consequence operations, also require a caller-supplied
`idempotency_key`: 16 to 128 characters of `ALPHA / DIGIT / "-" / "_"`,
one key per intended execution. The PEP forwards it as
`action.properties.idempotency_key`; it never enters `parameter_digest`.
The PDP claims (idempotency scope, key) with the operation identity before
it issues a permit, and refuses a missing or malformed key with
`parameter_violation` (#917).

`schedule_payment` and `cancel_scheduled_payment`, the two reversible
writes, take the "short validity window combined with an idempotency key"
permit-lifetime control (runtime permit binding; #918). They require the
same `idempotency_key`, forwarded the same way; the PDP refuses a missing
or malformed one with `parameter_violation` and makes no claim for it. Its
permit expires no later than the operation's published
`permit_validity_max_seconds` (300 s as shipped), which the statement holds
shorter than the retention, so no permit outlives its reservation. The
PEP reserves (idempotency scope, key) instead, in its own durable
single-writer store (`topology.json` `stores.pepWriteReservations.file`),
and commits the effect with its completed reservation and result in one
local transaction. A retry under the same key returns the original result
(`deduped`) for the published P7D horizon, authorized by the retry's own
fresh Decision; a different operation under the same key is refused
`operation_identity_conflict`.

- `schedule_payment` records one active schedule for the Mission and
  invoice and returns `{scheduled, schedule_id, invoice_id, amount}`. A new
  key on an invoice the Mission already scheduled is refused
  `schedule_exists`. A schedule moves no money and calls no connector;
  nothing reads it to pay, and `execute_wire_transfer` keeps its own
  Decision, single-use permit and redemption.
- `cancel_scheduled_payment` moves the calling Mission's active schedule
  for the invoice to `cancelled`, which stays for audit, and returns
  `{cancelled, schedule_id, invoice_id}`. No active schedule, or one
  another Mission holds, is refused `schedule_not_found`. Cancelling an
  uncommitted schedule is cleanup, not compensation.
- The two refusals change nothing and record no reservation. Their
  Execution Evidence `error` values are this deployment's
  collision-resistant names
  `https://payments.demo/execution-errors/schedule_exists` and
  `https://payments.demo/execution-errors/schedule_not_found`.
- A caller whose actor has no stable identity to scope the key on (an
  instance-profiled leaf with no client) is refused `actor_unkeyable`
  before any effect, recorded as
  `https://payments.demo/execution-errors/actor_unkeyable`.

## Permits, leases, commit point (D28/D36/D29/D39)

- Permit properties ride the PDP decision: single-use decision identifier,
  `permit_expires_at` (default 120 s), lease duration (default 30 s),
  audience = the canonical resource URI, PEP instance epoch.
- The PEP owns redemption: atomic redeem-on-execute
  (`@mission/store` `redeemOnce`); replay → refusal `permit_consumed`.
  Permits from an earlier instance epoch are rejected on restart.
- The execution lease covers validation and pre-commit only. The commit
  point is connector acceptance (ledger post / outbox accept); after it,
  cancellation is meaningless and the operation proceeds to
  `evidence_emitted -> reconciled` (see state machine artifact).
- Freshness at decision time (D33): `payments:payment.execute` requires
  the introspection immediate check; `payments:remittance.send` uses
  permit-within-bound; reads ride the Status List cache.

## Evidence fields

Every Decision Evidence, Execution Evidence, and Refusal Record for these
operations carries: the action id, `parameter_digest`, permit id (where
one exists), mission id + `authority_hash`, the freshness observation
(source, state, version, observed-at), the instance epoch, the connector
idempotency key (execution only), and the producing span's `trace_id`
(D13). Exact object shapes follow mission-authzen; this profile pins the
members that must be present for these six operations.
