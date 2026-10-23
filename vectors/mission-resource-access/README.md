# Mission Resource Access expected-outcome cases

These files define, as data, the expected outcomes for `mission_resource_access` semantics settled in #1258 (D444, D446, D447, D452). They are specification cases. A case passing in one implementation is evidence for that implementation only; it is not a claim that every implementation conforms.

The files are independently consumable: a consumer needs only JSON, not this repository's implementation. #819's independent second consumer is expected to reuse them. The capability set of the initial interoperable subset, and the contract it is frozen against, are in `vectors/mission-resource-access-subset/` (#249, D676).

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

A consumer compares `outcome` always, and `error` and `entries` where a case gives them. `reason` is explanatory and never compared. Inputs are JSON values; an entry is a `mission_resource_access` object, given without its `type` member where the check does not read it.

## Checks

The five checks the initial interoperable subset runs (`vectors/mission-resource-access-subset/`):

| Check | Role | Input | Outcomes | Compared detail |
|---|---|---|---|---|
| `subset` | `authorization-server` | `candidate` and `reference`, one entry each | `subset` when the candidate is a subset of the reference under Resource Access's Subset Rule; otherwise `not-subset` | none |
| `derive` | `authorization-server` | `ceiling`, the policy ceiling's entries, and an optional `proposal`, the client's proposed entries | `derived`, or `refuse` | on `refuse`, `error`; on `derived`, `entries` when given |
| `entry-validation` | `authorization-server` | `entry`, one proposed entry | `valid` when the authorization server admits it at proposal intake; `refuse` when it refuses it | on `refuse`, `error` |
| `resource-match` | `resource-server` | `entry` (`resource`, `resource_match`), `target`, the operation target; optional `entry_resource_json_text`, `contract` and `operation` | `match` or `no-match` | none |
| `target-resolution` | `resource-server` | `contract`, the operation's contract, and the members named below | `refuse-resolution` or `no-match` | none |

- `subset`: the comparison of Resource Access's Subset Rule, steps 1 to 4. Step 4 compares `resource_contract` member for member (`id`, `version` and `digest` each equal), so a consumer recomputes no digest. The approval exception of step 4 belongs to `derive` against a policy ceiling, never to this check.
- `derive`: narrows each proposed entry to the ceiling as the OAuth binding's derivation does, and refuses what it cannot derive. `entries` is the derived Authority Set in canonical form: `resource_match` is present only when it is `prefix` (an `exact` entry omits it), member order is not significant, and arrays are compared in order. `derive` encodes the binding's derivation as well as Resource Access semantics, so a consumer of Resource Access semantics alone may scope it out.
- `entry-validation`: the intake of one proposed entry, before any approval. `error` is the OAuth error code of the refusal, `invalid_authorization_details` throughout.
- `resource-match`: `entry_resource_json_text`, where present, is the entry's `resource` as JSON text, decoded and compared without reserializing it. `contract` with `service_level: true` states that a service-level operation contract establishes `target`; `operation` describes the operation the target came from and is not compared.
- `target-resolution`: `contract: null` is an operation with no contract, and `contract.candidates` lists more than one target, an ambiguous contract; both are `refuse-resolution`. A `no-match` case gives `request`, the request URI, `resolved_target`, the target its contract resolves, and `entry`: the entry matches `request` but not `resolved_target`, and is matched against the latter.

The other checks, which the subset does not run:

| Check | Role | Input | Outcomes |
|---|---|---|---|
| `delegate-matcher` | `authorization-server` | `allowed_delegates`, `delegate` (`sub`, `sub_profile`), `policy` | `permitted`, `not-permitted` |
| `delegate-eligibility` | `authorization-server` | `ceiling_entry_delegation`, `approved_entry_delegation`, `entry_delegation`, `context`, `delegate`, `depth`, `policy` (see `delegation.inherited-eligibility` below) | `eligible`, `not-eligible`, `narrowed-out` |
| `rs-authorize` | `resource-server` | `entries`, `target`, `action`, and the operation's facts (`amount`, `tenant`, `recipients`), with `token_validation`, `resource_defines` and `extension_members` | `allow`, `deny`, `reject-token` |
| `capability-declaration` | `authorization-server` | `carriers`, `claim`, `implemented_constraints` | `declared`, `invalid-claim` (detail `projection`) |
| `issuance` | `authorization-server` | `entries`, `projection`, `requested_scope`, `target` | `issue`, `refuse`, `refuse-issuance` (detail `error`) |
| `projection` | `authorization-server` | `entry`, `mapping` | `safe`, `unsafe` |

## Capabilities

- `operation-target`: resource-server establishment of an operation target.
- `resource-match.exact`, `resource-match.prefix`: resource-server matching of an entry against an operation target; `resource-match.prefix` also covers `prefix` entries in the authorization server's subset test.
- `subset.exact-resource`: the subset relation over `exact` resources.
- `action-families`: `.*` action families.
- `constraint.<name>`: one `constraints` key, a Common Constraint or a deployment-defined key (for example `constraint.max_amount`).
- `member.<name>`: one optional entry member: `resource_contract` (Resource Contracts), `delegation` (Delegate Eligibility), or a member another specification defines for this type. A case expecting the member handled rather than refused requires it.
- `refusal.unsupported-input`: refusal of input the implementation does not support (prefix input, an unsupported constraint, an incomparable value).
- `refusal.locations`: refusal of an entry carrying `locations`.
- `rs.enforcement`, `rs.alternative-grants`, `rs.member-roles`: resource-server enforcement behaviors.
- `rs.extension-members`: a resource server whose test configuration can declare an extension member's obligations fulfilled or unfulfilled (the `extension_members` input).
- `delegate-matcher`: `allowed_delegates` matching.
- `delegation.policy`, `delegation.inherited-eligibility`: policy-deferred and inherited delegate eligibility. A `delegate-eligibility` case gives the delegation member of the ceiling entry the approved entry was derived from, of the approved entry, and of the entry presented at the exchange (when it differs), with the policy decision per delegate.
- `transformation-capabilities`, `scope-projection`: capability declarations and projection.
