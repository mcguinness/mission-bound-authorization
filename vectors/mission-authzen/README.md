# Mission AuthZEN profile expected-outcome cases

These files define, as data, the expected outcomes for the AuthZEN profile's carriage of the Mission Resource Access operation target settled in #1276 (D447, D457): the PEP-established `resource.properties.operation_target`, the PDP entry match against it, and its place in permit reuse and execution. They are specification cases. A case passing in one implementation is evidence for that implementation only; it is not a claim that every implementation conforms.

The files are independently consumable: a consumer needs only JSON, not this repository's implementation. The format follows `vectors/mission-resource-access/` (README there), with roles, checks and capabilities of its own, because the deciding parties here are an AuthZEN PDP and the PEP that requests and uses its permits.

## Format

Each file is one group (`format`: `mission-authzen-cases/1`) with a `cases` array. Each case carries:

| Member | Meaning |
|---|---|
| `id` | Stable identifier, unique across all files |
| `description` | What the case exercises |
| `role` | The deciding party: `pdp` or `pep` |
| `requires` | Capabilities a consumer must implement to run the case |
| `unless` | Optional. Capabilities whose implementation makes the case inapplicable |
| `check` | The decision being made (see below) |
| `input` | Explicit inputs for that decision |
| `expected` | `outcome`, `reason`, and any outcome detail (`carrier`, `error`, `authority_bound`, `target`) |
| `refs` | The issue, ruling or item the case comes from |

A consumer declares the capabilities it implements. It runs a case when it implements every capability in `requires` and none in `unless`. Otherwise it reports the case as skipped, naming the missing capability or the implemented one that makes the case inapplicable.

## Checks

| Check | Role | Input | Outcomes |
|---|---|---|---|
| `evaluate` | `pdp` | `request` (the AuthZEN `resource` and `action` members), `credential_authority` (`context.credential.authority`), `current_effective_authority`, and `pep_enforcement_scope` (the entries describing what the authenticated PEP is authorized to request) | `permit`; `deny` with `carrier` `pdp-denial`, `error` (the denial reason) and `authority_bound`; `refuse` with `carrier` `refusal-record` and `error` (the Refusal Record `denial_reason`) |
| `establish-target` | `pep` | `metadata_identifier`, `contract` (the operation's trusted operation contract, or `null` when none exists), `operation`, `arguments`, and any `presented_entries` | `established` with `target`; `refuse` with `carrier` `refusal-record` and `error` |
| `permit-reuse` | `pep` | `evaluated` (the request a permit was issued for), `permit`, `next` (a later request) and `now` | `reuse` or `re-evaluate` |
| `execute` | `pep` | `evaluated_target`, `target_at_use` (`null` when it cannot be established), `parameter_bound`, and whether a target-determining argument changed | `release`; `suppress` with `carrier` `execution-evidence` and `error` |

In every `evaluate` case, the inputs not shown (token validity, Mission state, actor and other credential facts) are valid, so the outcome turns on the operation target and the entries alone.

## Capabilities

- `pdp.operation-target`: the PDP validates `resource.properties.operation_target` and matches `exact` `mission_resource_access` entries of both authority bounds against it, never against `audience`, `type` or `id`.
- `pdp.resource-match.prefix`: the PDP also matches `prefix` entries against the target.
- `pdp.enforcement-scope`: the PDP refuses a target outside the enforcement scope of the authenticated PEP.
- `pep.operation-target`: the PEP establishes the target from its trusted operation contract and validated arguments, and refuses an operation for which it cannot.
- `pep.permit-target-binding`: the PEP keys permit reuse on a cache key that includes the target and releases an effect only on the evaluated target.

The reference implementation implements none of these yet, so its reader (`src/services/pdp/test/authzen-cases.test.ts`) validates the files and reports every case as skipped.
