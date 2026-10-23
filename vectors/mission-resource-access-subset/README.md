# Mission Resource Access supported-subset fixture

This directory freezes the initial interoperable implementation subset of `mission_resource_access` (#819) against a concrete resource contract (#249, D553, D676). It is an implementation profile for consumers that implement less than the whole type, not a requirement on every conforming implementation. A consumer that runs the cases under it produces evidence for that consumer only. The reference implementation running them is not independent interoperability (D414).

## Files

| File | Format | Content |
|---|---|---|
| `payments-contract-2026-10-20.json` | `mission-resource-contract/1` | The payments resource contract, version `2026-10-20`: its reference (`id`, `version`, `digest`) and the contract document the digest commits |
| `supported-subset.json` | `mission-resource-access-subset/1` | The subset: resource matching, actions, entry members, constraint keys, and the capability set a consumer declares |

Both files are frozen. A changed contract is a new contract version with its own digest, and a changed subset is a new subset file with its own `id`; neither file is edited in place. The reference implementation's tests compare both files with the contract the payments resource declares and with the sets its engine supports (`src/services/authorization-server/test/resource-access-subset.test.ts`).

## The contract

`reference.digest` is `sha-256:` followed by the unpadded base64url SHA-256 of the JCS (RFC 8785) serialization of `document`, so a consumer can recompute it without this repository. The document assembles, for each operation, its action identifier and phase, action class, operation-target rule, parameter form, idempotency key and catalog capability, and it names the fact the resource reads for each constraint key (Resource Access, Resource Contracts; the payments Operation Profile `payments-runtime-profile-v13` it names). Resource policy, Mission state, entitlements, revocation and resolved resource facts are not contract material.

## The subset

| Member | Meaning |
|---|---|
| `contract` | The frozen contract the subset is defined against: its file and its reference |
| `resource_match` | The matching modes in the subset: `exact` only (an absent `resource_match` is `exact`) |
| `actions` | The explicit action identifiers the subset uses: the contract's own, and no action family |
| `members` | The entry members a subset consumer implements |
| `constraints` | The constraint keys a subset consumer implements, each with the specification that registers it in the Mission Common Constraints registry |
| `outside_subset` | What the contract or the reference implementation supports beyond the subset, with the reason |
| `capabilities` | The capability set, in the vocabulary of `vectors/mission-resource-access/README.md`, that a subset consumer declares |
| `excluded_capabilities` | Capabilities a subset consumer never declares (D414) |

Registry membership and implementation support are separate. All nine initial Common Constraints are in the subset. The reference implementation also supports `terminal_when`, which Discharge registers, and `vendors`, which the payments deployment defines without registering it. Both stay outside the subset, so subset evidence covers Resource Access semantics only.

Input outside the subset is unsupported input: a `prefix` entry, an action family, an entry member outside `members`, and a constraint key outside `constraints`. An authorization server refuses it before approval or transformation and never drops it to manufacture a subset (D152, D538), and a resource server treats an entry carrying it as providing no authority (Resource Access, Resource Server Enforcement). `locations` is refused by name. Since #1377 the reference implementation refuses an action-family value too, before approval or transformation; the sentence in `supported-subset.json`'s `outside_subset.action_families` that says it admits one predates that change, and the file is frozen. Cases ev-fam-01 and der-fam-01 witness a subset consumer's refusal (#819).

The constraint set and the action-family refusal are the owner's ruling (2026-10-22).

## Running the cases under the subset

A consumer declares `capabilities` and runs the files in `vectors/mission-resource-access/` as that README describes: a case runs when the consumer implements every capability in `requires` and none in `unless`. Under the subset that includes the refusals of `prefix` input, which the reference implementation skips because it implements `prefix`.

Input outside the subset appears in a case the subset selects only when the case expects it refused. A case expecting such input handled requires the capability for it (for example `member.delegation` or `resource-match.prefix`), so a subset consumer never runs it. The reference implementation's test checks this for every case the subset selects.

`member.resource_contract` selects the cases about the `resource_contract` member, sub-rc-01 to sub-rc-05: exact preservation of the frozen contract's reference under the subset rule, and a removed, added or substituted reference refused (#819).

Capabilities beyond the subset (delegate matching and eligibility, scope projection, transformation-capability declarations, the `rs.*` resource-server behaviors) are not part of it. A consumer may implement and declare them in addition; its runs of those cases are not subset evidence.
