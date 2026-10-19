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
| `unless` | Optional. Capabilities whose implementation makes the case inapplicable |
| `check` | The decision being made (for example `subset`, `derive`, `resource-match`) |
| `input` | Explicit inputs for that decision |
| `expected` | `outcome`, `reason`, and any outcome detail (`error`, `entries`, ...) |
| `refs` | The issue, ruling or item the case comes from |

A consumer declares the capabilities it implements. It runs a case when it implements every capability in `requires` and none in `unless`. Otherwise it reports the case as skipped, naming the missing capability or the implemented one that makes the case inapplicable.

A refusal of unsupported input is itself a case, with `refusal.unsupported-input`. Every such case names in `unless` the capability whose absence it tests, so a consumer that supports the input never runs a case expecting it to be refused. A case expecting the supported behavior requires that capability instead.

## Capabilities

- `operation-target`: resource-server establishment of an operation target.
- `resource-match.exact`, `resource-match.prefix`: resource-server matching of an entry against an operation target; `resource-match.prefix` also covers `prefix` entries in the authorization server's subset test.
- `subset.exact-resource`: the subset relation over `exact` resources.
- `action-families`: `.*` action families.
- `constraint.<name>`: one `constraints` key, a Common Constraint or a deployment-defined key (for example `constraint.max_amount`).
- `member.<name>`: one entry member another specification defines for this type.
- `refusal.unsupported-input`: refusal of input the implementation does not support (prefix input, an unsupported constraint, an incomparable value).
- `refusal.locations`: refusal of an entry carrying `locations`.
- `rs.enforcement`, `rs.alternative-grants`, `rs.member-roles`: resource-server enforcement behaviors.
- `rs.extension-members`: a resource server whose test configuration can declare an extension member's obligations fulfilled or unfulfilled (the `extension_members` input).
- `delegate-matcher`: `allowed_delegates` matching.
- `delegation.policy`, `delegation.inherited-eligibility`: policy-deferred and inherited delegate eligibility. A `delegate-eligibility` case gives the delegation member of the ceiling entry the approved entry was derived from, of the approved entry, and of the entry presented at the exchange (when it differs), with the policy decision per delegate.
- `transformation-capabilities`, `scope-projection`: capability declarations and projection.
