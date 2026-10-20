# payments-runtime-profile-v11

The Operation Profile (runtime § operation-profile; decision D34) for the
internal payments estate. Every component that produces or verifies bytes
(AS derivation, PDP, PEP, evidence verifier, evals) implements this
document. Version: `payments-runtime-profile-v11`; changes bump the suffix.
The file name is the document's stable name and does not carry the version.

## Version history

- **v11** (#1276): the PDP and the PEP match a `prefix` entry, in the
  Mission and in the credential, with the Resource Access matcher: after
  the one URI normalization, at a path-segment boundary, the target's
  query excluded from the path comparison only. A v10 component refused
  every `prefix` entry. Decision bytes for `exact` entries are unchanged
  from v10.
- **v10** (#817): declares each operation's execution capabilities
  (below), published as the Enforcement Scope Statement's
  `extensions.execution_capabilities`. No operation asserts exactly-once
  execution or the enforced Evaluation-Context Binding property, and the
  loader refuses a statement that asserts either without the capability
  it rests on. Decision bytes are unchanged from v9.

- **v9** (#853, D487): the canonical resource URI is the enforcement
  boundary identifier the Enforcement Scope Statement declares for
  `mcp-payments-pep`. The PEP establishes it from that declaration, never
  from the token; a token's `aud` names it directly or through an alias
  the statement declares for the token's issuer and profile (the shipped
  statement declares none), and an array is read by membership. Decision
  requests, permits and all three evidence forms carry the boundary,
  never an `aud` value, and each signing key signs only for a boundary the
  statement authorizes it for. A permit decided under an earlier boundary
  is suppressed `kill_switch` at use. Decision bytes are unchanged from v8.

- **v8** (#1251, D484): a `lookup_vendor` naming a vendor the store does
  not hold is refused `unknown_vendor` (`target_unresolvable`) before any
  decision request or Resource-policy query, as an unknown invoice is.
  It no longer targets the server resource, so a vendor constraint or
  Resource policy never refuses a target that does not exist. A stored
  vendor's decision bytes are unchanged from v7.

- **v7** (#1266, D457): the resource enforces the Mission Resource Access
  Common Constraints listed under "Constraint enforcement: Common
  Constraints" below against facts it reads from its own records, carries
  those facts on the decision request, and advertises exactly the enforced
  keys in `mission_constraints_supported`. Decision requests gain the
  facts the table lists, where the store's records carry them.
  `send_remittance_email` resolves its recipients from the vendor's
  remittance routing; for a vendor whose record names its own routing the
  effective parameters gain `recipients`, so that operation's
  `parameter_digest` binds them. Every other digest is unchanged.

- **v6** (#1276, D457): declares the operation contract (below). Every
  payments operation's target is the service the canonical resource URI
  identifies, sent as `resource.properties.operation_target` beside
  `audience`, and the PEP rechecks it before every release. Parameter
  digests are unchanged from v5: the effective parameters' `resource` is
  that target.
- **v5** (#1270): names the settlement identity of `execute_wire_transfer`,
  the invoice. The ledger settles each invoice once and refuses a later
  wire for it, under any Mission, operation key or caller key, with no
  effect (`already_settled`); `check_transfer` reports a settled invoice
  as not feasible. Decision bytes are unchanged from v4.

- **v4** (#828, D429): the Resource policy also evaluates the
  authenticated client, which must hold `authorized_client` on every
  target, and the tenant: an entitlement counts only for a member of the
  vendor's tenant. A request with no authenticated client is refused.
- **v3** (#828): declares the Resource policy: its owner and
  provisioning, the principal it evaluates, its relations, its freshness
  (separate from Mission-state freshness) and its failure behavior.
  Decision bytes are unchanged from v2.
- **v2** (#828): the list form's `all` source enumerates every vendor the
  payments store holds invoices for, so an unconstrained `list_invoices`
  digest binds those vendors; a named `vendor_id` is the store-resolved
  vendor, and one the store does not hold is refused `unknown_vendor`. A
  `parameter_digest` over the list form is interpreted under the version in
  force when it was computed.
- **v1** (D34): the `all` source carries an empty `vendor_scope`, and a
  named `vendor_id` is used as supplied.

## Canonical identifiers

- Canonical MCP resource URI (byte-for-byte everywhere per D38):
  `http://localhost:4403/mcp` (overridable via `.env`; whatever the value,
  it is used identically in PRM, OAuth `resource`, the Enforcement Scope
  Statement's boundary declaration, AuthZEN
  `resource.properties.audience`, the operation target below, and
  evidence). It is the enforcement boundary identifier (#853): token
  `aud` names it directly or through a declared alias, and no `aud`
  value or alias is ever carried in its place
  (`docs/boundary-identifier-change.md`).
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

## Operation contract

The payments operation contract identifies the canonical resource URI as
the operation target for every operation above (Resource Access, Resource
Matching). Actions and constraints determine the permitted operations
within that service. Each `TOOL_ACTIONS` row declares the contract
(`target: { service: <canonical resource URI> }`); it is never assumed.

- The PEP establishes the target from that declaration, before any
  decision request: never from an entry, the token's audience, or an
  argument the contract does not name. Every shipped tool declares the
  service-level contract. A deployment's Operation Profile may instead
  declare the argument-derived invoice contract for an invoice-scoped tool
  (`PAYMENTS_INVOICE_CONTRACT`,
  `{ template: "<canonical resource URI>/invoices/{invoice_id}" }`), whose
  target is the invoice the validated `invoice_id` names, percent-encoded
  as one path segment; the PEP derives it again from the executing
  arguments before every release. A tool with no declaration, an
  unsupported contract form, a missing, list-valued or malformed argument,
  or declarations naming different targets is refused
  `operation_target_unresolvable` (`target_unresolvable`) before any
  decision request.
- The decision request carries the target as
  `resource.properties.operation_target`. The PDP matches the credential's
  and the Mission's entries against it with the Resource Access matcher:
  `exact` is literal; `prefix` normalizes both URIs (scheme and host case,
  default port, percent-encoding case, unreserved octets, dot-segments)
  and admits the base and each target beneath it at a path-segment
  boundary, so `<canonical resource URI>/invoices` covers
  `.../invoices/inv-1` but not `.../invoices-archive/inv-1`. An
  unrecognized `resource_match`, or a `prefix` entry whose `resource`
  carries a query or names no `//` authority, provides no authority, and a
  credential carrying one is refused. `audience` is the boundary identifier, the token-validation
  and decision-channel scope input, and an audience alias never rewrites
  an entry or the target; `resource.type` and `resource.id` stay
  Resource-policy object identity.
- The target is the effective parameters' `resource`, so the parameter
  digest and the operation key bind it, and it is part of operation
  identity and of the cache key.
- Before every release the PEP re-establishes the target from the live
  profile; a target that moved or can no longer be established suppresses
  the permit with `target_drift` and no effect.

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

## Constraint enforcement: Common Constraints

The resource enforces these Mission Resource Access Common Constraints
(#1266), and `mission_constraints_supported` names exactly them beside
`max_amount` and `vendors`. Each is evaluated through the shared
semantics in `packages/mission-core/src/common-constraints.ts`, on the
matched Mission entry (the PDP) and on the credential's own entries (the
PEP before any decision, and the PDP), against facts the PEP reads from
the payments store, never from tool arguments. A fact the store does not
hold refuses, as does a malformed constraint value. The Authorization
Server refuses every other constraints key (a Common Constraint registered
later, or an unknown key) at intake, configuration load and derivation,
and the PDP refuses a matched entry that carries one.

| Key | Authoritative fact | Decision request member | Targets without the fact |
|---|---|---|---|
| `resource_issued_after`, `resource_issued_before` | the invoice record's `issued_at` (RFC 3339), compared as a UTC instant, both bounds inclusive | `resource.properties.issued_at` | `list_invoices` and `lookup_vendor` (no single invoice), and an invoice with no `issued_at`: refused |
| `tenant` | the vendor record's `tenant` (an invoice belongs to its vendor's tenant), compared as an exact string | `resource.properties.tenant` | `list_invoices` (no single owner), and a vendor record naming no tenant: refused |
| `time_window` | the evaluating component's own clock at the point of use (the PEP's credential check and the PDP's decision), both bounds inclusive | none: the PDP reads its own clock | none: every operation has a time |
| `recipient_domain` | every final recipient `send_remittance_email` reaches: the vendor's remittance addresses with each distribution list expanded to its members, or the vendor's default address; each must be within the domain (case-insensitive, whole labels) | `action.properties.recipients` | every operation that addresses no recipient: refused |
| `data_classification` | the invoice record's `classification` label, compared as an exact string; every label the operation touches must be named | `resource.properties.data_classification` | `list_invoices` and `lookup_vendor` (no single labeled record), and an invoice with no label: refused |
| `allowed_tools` | the tool this PEP dispatched the operation to, from its Operation Profile (`TOOL_ACTIONS`), compared as an exact string; the phases of `payments:payment.execute` are distinct tools | `action.properties.tool` (on every decision request) | none: every operation has a dispatched tool |

`time_window` is also enforced after the decision: the PDP caps the
permit's `valid_until` at the matched entry's `not_after` (and, for the
credential bound, at the latest `not_after` among the covering credential
entries when each carries one), so every later use the PEP checks
(`PERMIT_USE_CHECKS`), a retransmitted permit and an execution lease
derived from the permit all end with the window. A window that closes at
the decision instant refuses `parameter_violation`.

A change to an invoice or vendor record between the decision and a
write's execution changes its version, which `parameter_digest` binds, so
the write refuses `parameter_mismatch`. Refusals are `parameter_violation`
on the Mission bound and `out_of_authority` at the PEP's credential
bound.

Recipients the routing cannot resolve (a list that contains itself,
nesting past eight levels, no final recipient) refuse
`unresolvable_recipients` before any decision, and the email connector
sends to exactly the recipients the decision evaluated.

## Parameter schemas and normalization

All request parameters are JSON objects. At the tool boundary the PEP
NFC-normalizes every string, then validates the object against the tool's
served input schema (`config/tool-catalogs/payments.json`), which is
closed (`additionalProperties: false`), before any authorization work. An
unknown member, an authoritative member (below), a missing required
member, a non-string value or a malformed `idempotency_key` is refused
`invalid_request`, with no decision request and a Refusal Record whose
`denial_reason` is `request_invalid`. An unknown tool is refused
`unknown_tool` (`request_unsupported`), and a schema intake cannot read is
refused `capability_source_unresolvable`. Target lookup, effective
parameters and execution use the normalized values.

- `list_invoices`: `{ vendor_id?: string }`
- `get_invoice`: `{ invoice_id: string }`
- `lookup_vendor`: `{ vendor_id: string }`
- `schedule_payment`: `{ invoice_id: string, idempotency_key: string }`
- `cancel_scheduled_payment`: `{ invoice_id: string, idempotency_key: string }`
- `check_transfer`: `{ invoice_id: string }`
- `hold_transfer`: `{ invoice_id: string }`
- `execute_wire_transfer`: `{ invoice_id: string, idempotency_key: string }`
- `send_remittance_email`: `{ invoice_id: string, idempotency_key: string }`

Every `idempotency_key` takes the format in Idempotency keys below.

## Authoritative vs caller-supplied fields (D34)

Caller-supplied: `invoice_id`, `vendor_id` (the `lookup_vendor` target and
the `list_invoices` filter) and `idempotency_key`. Authoritative (loaded by
the PEP from the payments store, never from the caller): invoice `amount`,
`currency`, `payee_account`, `vendor_id`-of-invoice, invoice `status`,
vendor `status`, the record versions, and the facts the Common
Constraints read (invoice `issued_at` and `classification`, vendor
`tenant`, and the remittance recipients). No served schema declares an
authoritative field, so its presence in a request is a schema violation,
refused at the tool boundary.

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

`resource` is the operation target the contract establishes.

`parameter_digest` = `sha-256:` + base64url(no pad) of SHA-256 over the
JCS canonicalization of that object (the anchor encoding family; computed
with `@mission/core`). The digest binds decision to execution: the PEP
recomputes it immediately before commit after conditionally re-reading the
same record versions; any mismatch (record changed, parameter mutated) is
a refusal with reason `parameter_mismatch`. For `send_remittance_email` to
a vendor whose record names its own remittance routing, the object also
carries `recipients`: the sorted final recipients, so a routing or list
change between decision and commit is a mismatch.

## Targets

Every target is resolved from the payments store, never taken from an
argument (#828). An invoice-scoped tool targets the invoice; an invoice the
store does not hold is refused `unknown_invoice` before any decision
request. `lookup_vendor` targets the vendor the store resolves (D324), and
the credential bound, the Mission and Resource policy each evaluate that
vendor. A vendor the store does not hold is refused `unknown_vendor`
(`target_unresolvable`) after intake and before the credential bound, any
decision request or any Resource-policy query, with no effect, whatever
vendors the credential or the Mission names (D484). `list_invoices`
targets the vendors of its list form, below.

## List form

`list_invoices` returns a collection, so its effective parameters are the
list form: `action`, `resource`, `vendor_scope` and `vendor_scope_source`,
digested as above.

| `vendor_scope_source` | When | `vendor_scope` |
|---|---|---|
| `requested` | `vendor_id` is supplied | the vendor the store resolves for it; empty when the matched entry's `vendors` excludes it |
| `entry` | no `vendor_id`; the matched entry carries `vendors` | that allowlist, sorted |
| `all` | no `vendor_id`; the matched entry carries no `vendors` | every vendor the store holds invoices for, sorted and deduplicated |

- A `vendor_id` the store does not hold is refused `unknown_vendor`
  (`target_unresolvable`) before any decision request.
- The decision request names the vendors as its targets: `resource.id`
  names the requested vendor or one representative member, and a bulk
  form's `resource.properties.vendor_ids` names every member of
  `vendor_scope`. The Mission's own check and Resource policy each evaluate
  every target, and a refusal of any one refuses the whole read; no response
  carries a narrowed subset.
- A bulk form with an empty `vendor_scope` names a placeholder vendor
  object instead. An entry's empty allowlist refuses it, and no stored
  entitlement names it, so the deployment's Resource policy refuses it.
- Before release the PEP recomputes the list form from the current Mission
  and store; a difference is `parameter_mismatch`. Execution returns only
  invoices whose vendor is in `vendor_scope`.

## Resource policy

Every decision also requires the deployment's independently
administered Resource policy (runtime § input-resource-policy). The PDP
evaluates it after the Mission's authority and the credential's, and
before the parameter, approval and claim steps, and composes it by
conjunction: an action proceeds only when both Mission authority and
Resource policy permit it. Nothing in the query is derived from the
Mission.

- **Owner and provisioning.** The deployment's OpenFGA administrator owns
  the policy and administers it with `pnpm resource-policy`
  (`FgaDomainAdmin`): subject and client entitlements, tenant membership
  and each vendor's tenant, never through a Mission approval or a token. The
  resource attaches to a configured store and model (`OPENFGA_STORE_ID`,
  `OPENFGA_MODEL_ID`), verifying the model and writing nothing.
  Bootstrapping a store seeded from `config/seed/resource-policy.json` is
  a development operation.
- **Principals.** The verified token subject under this resource's own
  issuer, `user:<enc(iss)>|<enc(sub)>`, and the authenticated client
  (`context.actor.client_id`) under the same issuer,
  `client:<enc(iss)>|<enc(client_id)>`. A subject or client under any
  other issuer, or a request with no client, maps to no principal and is
  refused.
- **Relations.** The read actions (`payments:invoice.read`,
  `payments:invoice.list`, `payments:vendor.read`) require
  `authorized_reader`; the payment and remittance actions require
  `authorized_payer`, and the client requires `authorized_client`,
  whatever the action. Each target is checked for both: a vendor
  directly, an invoice directly or through its owning vendor (a client's
  entitlement only through its vendor). Every target must be entitled.
- **Tenant.** Each vendor names its tenant, whose members are subjects
  and clients. A direct entitlement counts only for a member of the
  vendor's tenant, so a principal entitled on a vendor outside its tenant
  is refused.
- **Freshness.** Current as of the decision: every check is an
  authoritative OpenFGA read at `HIGHER_CONSISTENCY`, and the PDP caches
  nothing, so a revocation written before a decision is in force at it.
  This is separate from Mission-state freshness, whose per-class staleness
  bound the Enforcement Scope Statement declares (`state_source`). The
  check is not atomic with the effect: a revocation after a permit does
  not withdraw it, and the permit stays bounded by its own validity
  (Permits, below).
- **Failure.** A refusal denies `resource_policy` (`next_action: none`)
  with Decision Evidence. A policy that cannot answer yields no decision,
  and the PEP refuses `pdp_unreachable`. A store whose model does not
  match refuses startup.

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
it issues a permit. The tool boundary refuses a missing or malformed key
(above); the PDP also refuses one that reaches it with
`parameter_violation` (#917).

`schedule_payment` and `cancel_scheduled_payment`, the two reversible
writes, take the "short validity window combined with an idempotency key"
permit-lifetime control (runtime permit binding; #918). They require the
same `idempotency_key`, forwarded the same way; the tool boundary refuses
a missing or malformed one, and the PDP also refuses one that reaches it
with `parameter_violation` and makes no claim for it. Its
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

## Settlement identity

An idempotency key, and the operation key above, identifies one request,
not the business event it carries out (runtime § security
considerations). `execute_wire_transfer` settles an invoice, and the
invoice (`invoice_id`) is its settlement identity:

- The ledger connector settles each invoice at most once. A wire under the
  same operation key is a retry and returns the original result
  (`deduped`). A wire for an invoice another operation already settled is
  refused with no effect, whatever Mission, operation key, record version
  or caller `idempotency_key` it arrives under. The check and the ledger
  insert are one step at the commit point, and a unique settlement index
  holds the invariant.
- The refusal is affirmative non-execution: Execution Evidence `outcome`
  `suppressed` with the collision-resistant `error`
  `https://payments.demo/execution-errors/already_settled`, and the
  caller-visible diagnostic `already_settled`. No money moved, so nothing
  stays charged.
- `check_transfer` reports a settled invoice as not feasible.
- Outcome reconciliation attributes a ledger entry to an action only
  through the identifiers recorded with it, the permit (evaluation)
  identifier and the operation key. An entry for the same invoice under
  another permit is that operation's effect, never this action's outcome.

Residuals:

- `send_remittance_email` keeps operation-key deduplication only: a
  second remittance notice for one invoice is an external commitment but
  moves no money.
- An invoice amended after settlement (a larger amount) is refused as
  already settled; paying the difference is a new business event that
  needs its own identity and is left to operator handling.

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

## Execution capabilities (#817)

The Operation Profile's execution capabilities (runtime Execution
Capabilities) for each operation with an effect, stated even where the
answer is no. The Enforcement Scope Statement publishes them as
`extensions.execution_capabilities`, one entry per operation and phase
with its class. `loadRuntimePosture` refuses at load an entry that leaves
an item unstated, names an idempotency holder the statement does not
declare, or asserts a claim or a recovery no declared capability supports.
The reads (`list_invoices`, `get_invoice`, `lookup_vendor`,
`check_transfer`) release no effect and declare none.

| Tool | Idempotency held by | Outcome lookup | Commit point | Unknown outcome |
|---|---|---|---|---|
| `schedule_payment` | PEP reservation | reservation row | the local transaction | lookup |
| `cancel_scheduled_payment` | PEP reservation | reservation row | the local transaction | lookup |
| `hold_transfer` | none | none | the response | held |
| `execute_wire_transfer` | PDP claim | ledger entry | ledger acceptance | lookup |
| `send_remittance_email` | PDP claim | outbox entry | outbox acceptance | lookup |

- **Durable idempotency.** The wire and the notice rely on the PDP's
  claim over (idempotency scope, `idempotency_key`) under the horizon
  their `transaction_assurance` declaration publishes (604800 s); the
  schedule writes rely on the PEP's reservation under its P7D retention
  (Idempotency keys, above). A deliberately new operation carries a new
  `idempotency_key`. The connectors' operation key omits it, so a new
  identical wire or notice is refused `operation_already_claimed`, a new
  wire for a settled invoice `already_settled`, a second schedule
  `schedule_exists`, and a cancel with nothing left to cancel
  `schedule_not_found`. The connectors also deduplicate on the operation
  key, in memory only, so no resource holds durable idempotency of its
  own and no operation asserts exactly-once execution.
- **Conditional effect.** None. No operation carries a precondition to
  its resource, so none can assert the enforced Evaluation-Context Binding
  property; the reference claims that extension nowhere (#773).
- **Outcome lookup.** The connectors answer, by the permit's
  `evaluation_id`, whether a wire or a notice committed, and the declared
  reconciler reads that answer. They hold it in memory, so a prior
  process's effect is out of reach and its claim closes indeterminate
  (`prior_process_outcomes`). A schedule write resolves from its
  reservation row, committed with the schedule in one local transaction.
  The simulated hold records nothing, and its unknown outcome is held.
- **Cancellation.** Before the commit point, an expired execution lease or
  a failed reverification suppresses a wire or a notice; nothing stops
  either after it. `cancel_scheduled_payment` withdraws a schedule after
  its commit as its own operation under its own Decision.
- **Compensation.** None. A refund or a correcting notice would be a new
  operation under its own authority (runtime compound actions).
- **Claims.** Every entry asserts none. Recovery never executes an effect
  again: no operation declares `resource_retransmission`.

## Evidence fields

Every Decision Evidence, Execution Evidence, and Refusal Record for these
operations carries: the action id, `parameter_digest`, permit id (where
one exists), mission id + `authority_hash`, the freshness observation
(source, state, version, observed-at), the instance epoch, the connector
idempotency key (execution only), and the producing span's `trace_id`
(D13). Exact object shapes follow mission-authzen; this profile pins the
members that must be present for these six operations.
