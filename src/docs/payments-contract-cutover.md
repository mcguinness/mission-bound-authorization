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
3. **Restart the Authorization Server, and its Transaction Authorization
   Server, first.** From then on every approval records the reference.
   Until the PEP and the PDP restart, they still accept an unpinned entry,
   and they already perform a pinned one under exactly its contract, so
   nothing new is refused yet.
4. **Restart the PDP and the PEP together** on the same statement. From
   then on an unpinned entry is refused for the five operations.

The reverse order, PEP before the Authorization Server, refuses every
write under a Mission approved in between, because those approvals still
carry no reference.

## Work in flight

- **Pending transaction workflows** admitted without a reference are
  refused at completion, `access_denied`, and stay pending until their
  lifetime ends; nothing is minted. Their operation needs a new approval
  that carries the reference.
- **Permits** decided before the PEP restart do not survive it: the PEP's
  in-memory permit state is rebuilt, and a permit used against the new
  declaration without a matching reference is suppressed with Execution
  Evidence `resource_contract_unresolvable`.

## Credentials and Missions approved before the cutover

- They carry no reference, and never gain one: refresh, Token Exchange and
  every derivation preserve the entry exactly. A Mission approved before
  the cutover keeps working for the three reads and is refused for the
  five operations.
- The remedy is a new approval: a new Mission, or an Expansion whose
  successor is approved with the reference.
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

Not witnessed: that no reference is gained at the delegated Token Exchange
without a handle, the designation exchange, the child-creation exchange,
`mintMissionAccessToken`, or the carryover of an unpinned grant
(`resource-access.resource-contract.no-reference-without-approval` stays
partial).

## Rolling back

Setting `requires_reference` back to `[]` and restarting restores the
earlier behavior for unpinned entries. Missions approved during the
cutover keep their references, which the PEP and the PDP still enforce,
and the pending workflows refused at completion may complete again within
their lifetime. The mapping contract's new values stay recorded: a
recorded binding is never changed or withdrawn while its contract is
supported.
