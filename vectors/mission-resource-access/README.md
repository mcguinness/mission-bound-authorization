# Mission Resource Access expected-outcome cases

These files define, as data, the expected outcomes for `mission_resource_access` semantics settled in #1258 (D444, D446, D447, D452). They are specification cases. A case passing in one implementation is evidence for that implementation only; it is not a claim that every implementation conforms.

The files are independently consumable: a consumer needs only JSON, not this repository's implementation. #819's independent second consumer is expected to reuse them.

## Format

Each file is one group (`format`: `mission-resource-access-cases/1`) with a `cases` array. Each case carries:

| Member | Meaning |
|---|---|
| `id` | Stable identifier, unique across all files |
| `description` | What the case exercises |
| `role` | The deciding party: `authorization-server` or `resource-server` |
| `requires` | Capabilities a consumer must implement to run the case |
| `check` | The decision being made (for example `subset`, `derive`, `resource-match`) |
| `input` | Explicit inputs for that decision |
| `expected` | `outcome`, `reason`, and any outcome detail (`error`, `entries`, ...) |
| `refs` | The issue, ruling or item the case comes from |

A consumer runs a case when it implements every capability in `requires`. Otherwise it reports the case as skipped, naming the missing capability. A refusal of unsupported input is itself a case, with `refusal.unsupported-input`, and runs wherever refusal is implemented.

## Capabilities

- `operation-target`: resource-server establishment of an operation target.
- `resource-match.exact`, `resource-match.prefix`: resource-server matching of an entry against an operation target.
- `subset.exact-resource`: the subset relation over `exact` resources.
- `action-families`: `.*` action families.
- `constraint.<name>`: one Common Constraint (for example `constraint.max_amount`).
- `refusal.unsupported-input`: refusal of input the implementation does not support (prefix input, an unsupported constraint, an incomparable value).
- `refusal.locations`: refusal of an entry carrying `locations`.
- `rs.enforcement`, `rs.alternative-grants`, `rs.member-roles`: resource-server enforcement behaviors.
- `delegate-matcher`: `allowed_delegates` matching.
- `delegation.policy`, `delegation.inherited-eligibility`: policy-deferred and inherited delegate eligibility.
- `transformation-capabilities`, `scope-projection`: capability declarations and projection.
