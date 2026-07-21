# payments-runtime-profile-v1

The Operation Profile (runtime § operation-profile; decision D34) for the
internal payments estate. Every component that produces or verifies bytes
(AS derivation, PDP, PEP, evidence verifier, evals) implements this
document. Version: `payments-runtime-profile-v1`; changes bump the suffix.

## Canonical identifiers

- Canonical MCP resource URI (byte-for-byte everywhere per D38):
  `http://localhost:4403/mcp` (overridable via `.env`; whatever the value,
  it is used identically in PRM, OAuth `resource`, token `aud`, AuthZEN
  `context.audience`, and evidence).
- Tool ids (capability source `tool_id`): `mcp://payments.demo/tools/<name>`.
- AuthZEN action ids: `payments:<operation>` as listed below.

## Operations

| Tool | Action id | Resource type | Class | Tier |
|---|---|---|---|---|
| `list_invoices` | `payments:invoice.list` | `invoice` (collection) | read | core |
| `get_invoice` | `payments:invoice.read` | `invoice` | read | core |
| `lookup_vendor` | `payments:vendor.read` | `vendor` | read | core |
| `schedule_payment` | `payments:payment.schedule` | `invoice` | consequential, reversible | core |
| `execute_wire_transfer` | `payments:payment.execute` | `invoice` | irreversible | transaction-assurance |
| `send_remittance_email` | `payments:remittance.send` | `invoice` | external commitment | transaction-assurance |

## Money

`{"amount": "<decimal string>", "currency": "<ISO 4217>"}` — the core's
`max_amount` shape. `amount` is a decimal string at the currency's minor
scale (USD: exactly two fraction digits), never a JSON number. Comparison
is numeric over the decimal string; serialization is byte-preserved.

## Parameter schemas and normalization

All request parameters are JSON objects validated against the schemas
below before any authorization work; strings are NFC-normalized at intake;
unknown members are rejected (`invalid_request` at the tool boundary).

- `get_invoice`: `{ invoice_id: string }`
- `schedule_payment`: `{ invoice_id: string, execute_after?: RFC3339 }`
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
