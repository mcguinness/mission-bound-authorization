# The payments contract cutover

How the payments deployment moves from enforcing a carried
`resource_contract` reference to requiring one for its non-read
operations, and what happens to the work and credentials in flight (#249
C.3, D967, D1071; Resource Access "Resource Contracts", Runtime "Resource
Contract", Authority Server "Mapping Contract"). Paths are relative to
`src/`.

## What changes

`config/enforcement-scope.json` declares the payments contract's
`requires_reference` as the five non-read actions:
`payments:payment.schedule`, `payments:payment.schedule.cancel`,
`payments:payment.execute`, `payments:payment.reverse` and
`payments:remittance.send`. Every component reads that one declaration:

- the Authorization Server records the current contract's reference in
  every entry a fresh approval commits on the payments resource,
  read-only entries included (D989);
- the PEP refuses an entry without a reference for one of the five
  operations before any decision request, `resource_contract_unresolvable`,
  with a Refusal Record and no effect, and re-checks the permit's
  reference at use;
- the PDP denies `resource_contract_drift` where a contract applies and the
  request presents none, or another;
- the Transaction Authorization Server refuses an entry without a
  reference for one of the five at admission, and at completion for a
  workflow admitted before the requirement (#1935).

The requirement is per operation: `get_invoice`, `list_invoices` and
`lookup_vendor` need no reference. The contract versions, their documents
and digests are unchanged, so no Operation Profile version changes.

The MAS pilot's mapping contract (`config/mas-pilot.json`) moves to
version 2 and adds contract-stating scope values beside the legacy ones
(`invoices.read.2026-10-27`, `vendors.read.2026-10-27`,
`remit.send.2026-10-27`); the shared namespace (`config/mas-join.json`)
adds `payments.read.2026-10-27`. The scope binding ledger refuses a changed
document under a recorded version, so the version moves with the values.

## Order of the change

1. **Install the mapping contract's new version** and register the new
   scope values at the estate, for the resource and for each client that
   needs them. Adding values changes nothing for a credential already
   issued: a legacy value keeps its binding, no contract.
2. **Drain the transaction workflows** admitted without a reference for one
   of the five actions (below), or accept that they are refused at
   completion.
3. **Restart the Authorization Server, its Transaction Authorization
   Server, and the MAS where it issues Missions, first.** From then on every
   approval records the reference, and the Transaction Authorization Server
   refuses an entry without one for the five operations: at admission
   (`invalid_grant`), and at completion for a workflow admitted before
   (`access_denied`, the workflow left pending). Only the PEP and PDP
   instances not yet replaced keep their earlier behavior: they still
   accept an unpinned entry for the five, and already perform a pinned one
   under exactly its contract.
4. **Bring up the PDP and PEP instances on the new statement, then remove
   every earlier instance from routing.** No request may reach a PEP or a
   PDP that still reads the earlier declaration. Drain or cancel those
   instances' in-flight work: a call they admitted either completes or is
   cancelled before the instance is stopped, and a permit they decided is
   never released by a new instance without a matching reference (Work in
   flight, below). Then stop them.
5. **Declare the cutover complete only when every serving resource server
   and PDP enforces the requirement** (D875): every instance that can
   receive a request reads the new declaration, and no earlier, permissive
   instance remains an authorization path. Confirm it per instance: a PEP
   publishes its Enforcement Scope Statement in its protected resource
   metadata (`enforcement_scope_statement.extensions.resource_contracts`,
   whose payments `requires_reference` lists the five actions), and a PDP
   is checked from the declaration its deployment loads. Record the
   completion. Until then the cutover is in progress: an earlier instance
   still authorizes an unpinned entry for the five.

The reverse order, PEP before the Authorization Server, refuses every
write under a Mission approved in between, because those approvals still
carry no reference.

## Work in flight

- **Pending transaction workflows** admitted without a reference are
  refused at completion, `access_denied`, and stay pending until their
  lifetime ends; nothing is minted. Their operation needs a new approval
  that carries the reference.
- **Permits** decided before the requirement are re-resolved before
  release: one used against the new declaration without a matching
  reference is suppressed with Execution Evidence
  `resource_contract_unresolvable`, and nothing is released
  (`services/mcp-payments/test/resource-contract-pep.test.ts`, "the
  executing PEP re-resolves the permit's contract before release").

## Credentials and Missions approved before the cutover

- They carry no reference, and never gain one: refresh, Token Exchange and
  every derivation preserve the entry exactly. A Mission approved before
  the cutover keeps working for the three reads and is refused for the
  five operations.
- The remedy is a new approval: a new Mission, or an Expansion whose
  successor is approved with the reference.
- A child of a parent approved before the cutover carries none either, and
  is not carried by that Expansion. Carryover preserves the child's entries
  as they are and never assembles the current reference into them, so its
  replacement is not a strict subset of the successor's pinned entries: no
  replacement is created, the signed carryover result records the child
  `excluded` with `not_strict_subset`, and the old child terminates
  without `carried_to`. A child under the successor needs its own
  authorized creation.
- A supported older reference keeps working within its declared retention,
  under the Operation Profile its own contract version names
  (`2026-10-26`, `payments-runtime-profile-v15`, until 2027-10-27).

## Joined credentials

A legacy scope value states no contract and keeps that meaning: a
credential issued under it joins only a Mission approved before the
cutover. A Mission approved after it carries the reference, so a joined
credential needs a value whose mapping states the same contract; under a
legacy value it is denied `resource_contract_drift` at the PDP, or, for
one of the five operations, refused `resource_contract_unresolvable` at
the PEP. Clients request the new values, and the estate issues them only
where registered.

## Witnesses, and what is not witnessed

The cutover's tests run under the shipped configuration:
`demo/test/contract-cutover-stack.test.ts` (an unpinned credential issued
before the cutover and refreshed after it is refused for every tool of the
four actions the deployment issues, and still performs a read; a pinned
older reference through the TAS and the PEP),
`services/mcp-payments/test/resource-contract-pep.test.ts` (the per-tool
requirement, the reversal included), `demo/test/mas-pilot-contract.test.ts`
(joined reads and a joined write, legacy and contract-stating), and the two
MAS class-reservation cases in `demo/test/mas-pilot.test.ts` and
`demo/test/mas-pilot-introspection.test.ts`. The shipped policy ceiling
grants no `payments:payment.reverse`, so no credential this deployment
issues carries it; its refusal is witnessed at the PEP only.

No path gains a reference without an approval
(`resource-access.resource-contract.no-reference-without-approval`):
besides refresh and the Token Exchange through a handle, the designation
and its redemption (`services/authorization-server/test/delegation-exchange.test.ts`),
child creation and its redemption, and the refusal of a child proposal
restating the current reference
(`services/authorization-server/test/child-delegation-endpoint.test.ts`),
the Dispatch handoff (`services/authorization-server/test/dispatch-handoff.test.ts`),
a ceiling drawdown's minted token
(`services/authorization-server/test/progressive-drawdown-endpoint.test.ts`),
and the carryover cascade above
(`services/authorization-server/test/expansion-endpoint.test.ts`) are
witnessed under a configuration requiring the reference. The cascade's
witness asserts its committed result, not how the Expansion's approval
page renders it.

## Rolling back

Setting `requires_reference` back to `[]` and restarting restores the
earlier behavior for unpinned entries. Missions approved during the
cutover keep their references, which the PEP and the PDP still enforce,
and the pending workflows refused at completion may complete again within
their lifetime. The mapping contract's new values stay recorded: a
recorded binding is never changed or withdrawn while its contract is
supported.
