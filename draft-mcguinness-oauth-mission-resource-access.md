---
title: "Mission Resource Access Profile for OAuth 2.0"
abbrev: "OAuth Mission Resource Access"
category: std

docname: draft-mcguinness-oauth-mission-resource-access-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - rar
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC3986:
  RFC6750:
  RFC8259:
  RFC8693:
  RFC8707:
  RFC8785:
  RFC9396:
  RFC9728:
  ISO4217:
    title: "ISO 4217:2015, Codes for the representation of currencies and funds"
    author:
      org: International Organization for Standardization
    date: 2015-08
    seriesinfo:
      ISO: "4217:2015"
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8126:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  MCP:
    title: "Model Context Protocol: Authorization"
    target: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
    author:
      - org: Model Context Protocol Project
    date: 2026
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

This document defines `mission_resource_access`, a general-purpose OAuth
2.0 Rich Authorization Requests (RAR) `authorization_details` type for
Mission-Bound Authorization for OAuth 2.0 (the "issuance profile"). An
entry names one protected resource, matched exactly or by path prefix;
the actions permitted there, including wildcard action families;
machine-actionable constraints, including a registered Common
Constraints vocabulary; and a per-entry delegation policy.

The document also defines how two entries compare and narrow, how a
resource server enforces an entry, when an entry can be projected to
OAuth `scope`, and how an authorization server declares its support for
these semantics. The issuance profile is type-agnostic: a deployment can
support `mission_resource_access`, another `authorization_details` type
its authorization server supports, or both.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} commits a
Mission's Authority Set as one or more {{RFC9396}}
`authorization_details` entries, of whatever type or types the
authorization server supports. It derives, commits, and gates entries of
every type the same way, and leaves each type's comparison and
transformation semantics to the specification that defines the type, as
{{Section 2 of RFC9396}} permits.

This document is that specification for one type,
`mission_resource_access`. It defines:

- the entry: a resource matched exactly or by path prefix, an action
  namespace with wildcard families, machine-actionable constraints, and
  a per-entry delegation policy ({{resource-access-type}}), and how a
  `resource` is matched ({{resource-matching}});
- the subset rule that compares two entries ({{subset}}), and the Common
  Constraints with their subset and intersection rules
  ({{common-constraints}});
- resource server enforcement ({{rs-enforcement}}) and delegate
  eligibility ({{delegate-eligibility}}); and
- the conditions under which an entry can be projected to `scope`
  ({{scope-projection}}), and the type's declaration under the issuance
  profile's transformation-capability map
  ({{transformation-capabilities}}).

The issuance profile keeps the type-agnostic machinery: the approved-set
commitment, derivation gating, and its own scope-projection rule and
issuance algorithm. This document defines the type-specific comparison,
delegation, and scope-projection rules for `mission_resource_access`.

This document defines one `authorization_details` type a deployment of
the issuance profile {{I-D.draft-mcguinness-oauth-mission}} MAY support;
the issuance profile is complete, and type-agnostic, without it. The
type is general-purpose: an authorization server with no reason to
define a narrower, audience-specific type can use it directly, and the
issuance profile's worked examples use it throughout.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

All JSON in this document is non-normative and illustrative; the member
definitions in the surrounding text are authoritative.

Terms such as Mission, Authority Set, Subject, and Approver are defined
by {{I-D.draft-mcguinness-oauth-mission}} and used here with the same
meaning.

A "consumer" of an entry is the authorization server or resource server
evaluating it in the context at hand: the authorization server when it
validates, compares, or narrows an entry, and the resource server when
it enforces one.

# The Mission Resource Access Type {#resource-access-type}

`mission_resource_access` is an `authorization_details` type
({{Section 2 of RFC9396}}): a general-purpose, cross-resource
authorization language. An entry is an `authorization_details` object
with these members:

`type`:
: REQUIRED. A string. `mission_resource_access`.

`resource`:
: REQUIRED. A string. The resource the entry applies to: an absolute URI
  compared with the target of an operation ({{resource-matching}}), the
  same kind of identifier as the {{RFC8707}} `resource` value.

  - Carrying `resource` per entry, which {{RFC9396}} permits, lets one
    token scope distinct authority to distinct resources. A
    Mission-bound token's `aud` is derived from the carried entries'
    `resource` values and is typically coarser
    ({{I-D.draft-mcguinness-oauth-mission}}).
  - Per {{Section 3.2 of RFC9396}}, the `resource` authorization request
    parameter does not affect how the authorization server processes
    `authorization_details`. This member is also distinct from the
    {{RFC9396}} common `locations` field.

`resource_match`:
: OPTIONAL. A string: `exact` (the default, and the behavior when the
  member is absent) or `prefix`.

  - Under `exact`, the entry applies to an operation target equal to
    `resource`.
  - Under `prefix`, the entry applies to the `resource` itself and to
    targets beneath it at a path-segment boundary. {{entry-validation}}
    limits the `resource` value a `prefix` entry may carry.
  - {{resource-matching}} defines the operation target and both
    comparisons.
  - These two values are the only ones defined; a consumer MUST treat an
    entry whose `resource_match` value it does not recognize as
    unenforceable and fail closed
    ({{I-D.draft-mcguinness-oauth-mission}}).

  Containment between effective resource sets is compared as defined in
  {{subset}}.

`actions`:
: REQUIRED. An array of strings. Each value is an action identifier
  whose whole value matches `[A-Za-z0-9_.:-]+`, or an action family: an
  identifier followed by `.*`. A family authorizes every action whose
  dot-separated identifier extends the family name at a segment
  boundary: `invoices.*` authorizes `invoices.read` and
  `invoices.q3.export`, not `invoicesx.read`.

  - Like an OAuth scope, an action value carries meaning only at the
    `resource` that defines it: a consumer enforces only the actions it
    recognizes for that resource and honors no others, so an
    unrecognized action fails closed.
  - An authorization server SHOULD draw action identifiers from a
    namespace the serving resource documents, so the set is
    interpretable cross-vendor rather than ad hoc.
  - The authorization server MUST ensure that a consent rendering
    presents a family as the breadth it is: all actions under the name,
    not one action.
  - An authorization server SHOULD treat deriving a family as high-risk
    breadth.

`constraints`:
: OPTIONAL. An object. Machine-actionable per-resource bounds (for
  example, `max_amount`). A member name defined as a Common Constraint
  ({{common-constraints}}) has shared semantics across deployments; any
  other name is deployment-defined.

  - Because a `constraints` member narrows authority, {{rs-enforcement}}
    requires a resource server that cannot enforce one to fail closed.
  - To avoid that failure mode, the authorization server SHOULD emit for
    a given `resource` only `constraints` keys that the resource server
    serving it is known to understand and enforce: by registration, by
    deployment policy, or by the resource's
    `mission_constraints_supported` metadata
    ({{protected-resource-metadata}}).

`delegation`:
: OPTIONAL. An object. The delegation policy for this entry
  ({{delegate-eligibility}}). When absent, this entry's authority is
  non-delegable: it MUST NOT appear in a delegated token. When present,
  it has these members:

  `max_depth`:
  : REQUIRED. An integer. The maximum delegation depth at which this
    entry's authority may be exercised ({{delegate-eligibility}}).

  `allowed_delegates`:
  : RECOMMENDED. An array of objects. The permitted delegates, each a
    `may_act`-style delegate matcher ({{matching-allowed-delegates}}):
    `{ "sub": "<client_id>" }` for a specific delegate, or
    `{ "sub_profile": "<actor-type>" }` for an actor-type class.

    When absent, eligibility falls to the authorization server's
    delegation-authorization policy, applied at every exchange
    ({{delegate-eligibility}}): absence defers the decision to policy
    and never grants blanket eligibility. The member is RECOMMENDED so
    that eligibility is committed and rendered with the entry rather
    than left wholly to policy.

  A companion profile MAY define additional `delegation` members. Such a
  member is policy, not authority ({{subset}}): a derived entry's value
  for it MUST NOT be broader than the parent entry's, and a member the
  authorization server does not understand is carried unchanged.

The following example shows an Authority Set with two entries for one
resource:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"],
    "constraints": {
      "resource_issued_after": "2026-07-01T00:00:00Z",
      "resource_issued_before": "2026-09-30T23:59:59Z"
    },
    "delegation": {
      "max_depth": 2,
      "allowed_delegates": [{ "sub_profile": "ai_agent" }]
    } },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } }
]
~~~

The read entry is delegable to depth 2 and bounded to a third-quarter
issuance window by the `resource_issued_after` and
`resource_issued_before` Common Constraints ({{common-constraints}}).
The write entry carries no `delegation`, so it is non-delegable:
`delegation` is per entry.

In the ERP example above, the operation contract identifies
`https://erp.example.com` as the operation target
({{resource-matching}}). Actions and constraints determine the
permitted operations within that service.

## Entry Validation {#entry-validation}

This section gathers the validity rules for an entry beyond each
member's type and presence requirements ({{resource-access-type}},
{{initial-common-constraints}}). The authorization server applies them
when it validates a proposed or carried entry ({{conformance}}); a
resource server applies them where a rule says so.

A `resource` value under `prefix` MUST NOT carry a query or fragment
component; the authorization server refuses such an entry with the
`invalid_authorization_details` error code ({{Section 5 of RFC9396}}).

This type does not use the {{RFC9396}} common `locations` field:
`resource` identifies where an entry applies. The authorization server
refuses an entry carrying `locations` with the
`invalid_authorization_details` error code.

The authorization server also refuses an entry with the
`invalid_authorization_details` error code when:

- its `resource` is not an `absolute-URI` ({{Section 4.3 of RFC3986}}),
  so no entry's `resource` carries a fragment component;
- its `resource` is an `http` or `https` URI without the `//` authority
  form naming a non-empty host;
- its `actions` array is empty, or one of its values is neither an
  action identifier nor an action family ({{resource-access-type}});
- its `delegation.max_depth` is not a non-negative integer, so a
  negative or fractional value is refused;
- an `allowed_delegates` matcher carries neither `sub` nor
  `sub_profile`, or carries any other member
  ({{matching-allowed-delegates}});
- its `time_window` Common Constraint has a `not_before` later than its
  `not_after`, a window that admits no instant; or
- its `recipient_domain` Common Constraint is not a DNS name in ASCII
  form, with each internationalized label in its A-label form, or ends
  in a dot.

Letter case does not make a `recipient_domain` invalid; values compare
case-insensitively ({{value-space-comparison}}).

The following values are valid and carry a defined meaning:

- A `max_depth` of 0 admits the entry into no delegated token, since a
  delegated token's delegation depth is 1 or more
  ({{delegate-eligibility}}): the entry supplies no in-Mission delegated
  authority. Any other `delegation` member stays intact; a member a
  companion profile defines there, such as a child-creation grant, keeps
  the bound that profile gives it.
- An empty `allowed_delegates` array permits no delegate. It differs
  from an absent member, which defers eligibility to the authorization
  server's delegation-authorization policy ({{delegate-eligibility}}).
- An action value that a consumer does not recognize for the entry's
  `resource` grants nothing. It does not make the entry unenforceable:
  the entry's other actions remain enforceable ({{rs-enforcement}}).

### Decimal Values {#decimal-values}

A decimal-string value in a Common Constraint (`max_amount`'s `amount`
member, and any future Common Constraint with a decimal-valued member)
MUST match `^[0-9]+(\.[0-9]{1,18})?$`: one or more decimal digits,
optionally followed by a single `.` and one to 18 further decimal
digits.

A value of any other form, including scientific notation (`"1e300"`), a
sign (a ceiling value is never negative), a thousands separator, or a
non-numeric token (`"NaN"`, `"Infinity"`), is malformed, and a consumer
MUST reject it rather than attempt to parse it:

- an authority proposal carrying one is refused at submission
  ({{I-D.draft-mcguinness-oauth-mission}}); and
- a resource server treats a malformed decimal value the same as a
  `constraints` key it cannot enforce ({{rs-enforcement}}).

Comparison and intersection over two such decimal-string values MUST be
computed as exact decimal arithmetic (for example, by scaling both
values to integers by their fractional digit count and comparing the
integers) and MUST NOT parse either value into an IEEE 754 binary
floating-point type: that representation does not hold every value the
grammar above admits exactly and can compare or combine two values
incorrectly.

A numeric constraint value MUST lie within the range that the JSON
Canonicalization Scheme (JCS) {{RFC8785}} serializes exactly. Monetary
amounts avoid that hazard: `max_amount` carries its `amount` as a string
containing a decimal number, paired with an ISO 4217 `currency` code,
and a future Common Constraint for a monetary value SHOULD reuse this
shape rather than a JSON number.

## Resource Matching {#resource-matching}

This section defines how an entry's `resource` is compared: with the
target of an operation when the resource server enforces the entry
({{rs-enforcement}}), and with another entry's `resource` when the
authorization server tests containment ({{subset}}).

**Operation target.** Before matching authority, the resource server
establishes the operation's target: an absolute URI identifying the
resource the operation acts on. The resource server:

- establishes the target from its documented, trusted operation
  contract: for an HTTP resource operation the target can be the
  effective request URI, and for an RPC or tool call the resource server
  derives it from the operation and its validated arguments;
- MUST establish the target independently of the entries the request
  presents, and MUST NOT choose a target because an entry would then
  match;
- MUST refuse the operation when it cannot establish one unambiguous
  target; and
- MUST execute the operation on the target it matched: matching a
  different target never authorizes the execution.

An operation contract preserves every resource distinction the
deployment's authorization constrains; it cannot collapse `/orders/123`
and `/admin` to the server's root identifier to obtain a match. There is
no fallback to the protected resource's metadata identifier: an
operation contract MAY define service-level authority and use that
identifier as its target, but an absent or ambiguous contract is not
such a definition. Validating the metadata identifier
({{Section 3.3 of RFC9728}}) and the token's audience remain separate
checks, and matching never rewrites a recorded entry or its integrity
commitments.

The following tables show one RPC operation and how entries match its
target:

| Role | Value |
| --- | --- |
| Protected resource metadata identifier | `https://api.example` |
| Transport endpoint | `https://api.example/rpc` |
| Validated operation | `orders.read` for order `123` |
| Operation target | `https://api.example/orders/123` |
{: title="An RPC operation and its target"}

| Entry `resource` | `resource_match` | Matches the target |
| --- | --- | --- |
| `https://api.example/orders/123` | `exact` | Yes |
| `https://api.example` | `exact` | No |
| `https://api.example/rpc` | `exact` | No |
| `https://api.example/orders` | `prefix` | Yes |
| `https://api.example/orders/` | `prefix` | Yes |
| `https://API.EXAMPLE:443/orders/123` | `exact` | No |
| `https://API.EXAMPLE:443/orders` | `prefix` | Yes |
{: title="Resource matches for the RPC operation"}

These are resource matches only; actions and constraints are checked
separately.

**Exact matching.** Under `exact`, the entry's `resource`, after JSON
decoding, and the operation target are compared character for character,
including any query component. The comparison applies no case folding,
default-port removal, percent-decoding, query removal, or trailing-slash
equivalence, and a matcher MUST NOT normalize either operand by parsing
and reserializing it. Equivalent URI spellings therefore do not match,
so an issuer SHOULD emit an `exact` `resource` in the resource server's
documented target spelling.

| `exact` entry `resource` | Operation target | Result |
| --- | --- | --- |
| `https://api.example/orders/123` | `https://api.example/orders/123` | Match |
| `https:\/\/api.example\/orders\/123` (JSON escapes) | `https://api.example/orders/123` | Match |
| `https://api.example/orders/123` | `https://API.EXAMPLE/orders/123` | No match |
| `https://api.example/orders/123` | `https://api.example:443/orders/123` | No match |
| `https://api.example/orders/123` | `https://api.example/orders/%31%32%33` | No match |
| `https://api.example/orders/123` | `https://api.example/orders/123/` | No match |
| `https://api.example/orders?id=1&view=full` | `https://api.example/orders?id=1&view=full` | Match |
| `https://api.example/orders?id=1&view=full` | `https://api.example/orders?view=full&id=1` | No match |
| `https://api.example/orders?` | `https://api.example/orders` | No match |
| `https://api.example` | `https://api.example/` | No match |
{: title="Exact matching"}

**Prefix matching.** For prefix purposes, a `resource` with an empty
path and one whose path is `/` denote the same base: `https://a.example`
and `https://a.example/` authorize the same set.

Resource containment under a `prefix` reference is compared after
normalizing both URIs with these steps from {{Section 6.2.2 of RFC3986}}
(syntax-based) and {{Section 6.2.3 of RFC3986}} (scheme-based):

1. lowercase the scheme and host;
2. remove a default port;
3. uppercase the hexadecimal digits of any percent-encoding
   ({{Section 2.1 of RFC3986}}), so `%2f` and `%2F` are equivalent;
4. decode percent-encoded octets of unreserved characters; and
5. remove dot-segments.

After normalization, a target is within a `prefix` entry when it has the
entry's scheme and authority and its path equals the base path or
extends it at a path-segment boundary. If the base path ends in `/`, a
descendant's path begins with the complete base path; otherwise it
begins with the base path followed by `/`. A `/orders/` base therefore
admits itself and `/orders/123`, but neither `/orders` nor `/ordersx`.
The target's query is excluded from this path comparison only: it still
participates in establishing the target and in action and constraint
enforcement, and a query that selects another resource is resolved to
that resource before matching.

This normalization applies to comparison only, never to hashing:
{{I-D.draft-mcguinness-oauth-mission}}'s anchor computation remains
byte-exact over the recorded values and is untouched by this rule.

The authorization server's containment test ({{subset}}) and the
resource server's request matching ({{rs-enforcement}}) MUST apply the
single URI normalization defined in this section, so issuance and
enforcement draw the same boundary.

The normalization MUST run before the prefix comparison, never after,
and the boundary MUST be evaluated on the same normalized form a
downstream component will act on.

An empty path and `/` denote the same base; beyond that equivalence, a
URI matcher MUST NOT coalesce `//` or trailing-slash differences of its
own, since the normalization does not.

The normalization lowercases the host but does not define Unicode to
A-label (IDNA) conversion, so a deployment that accepts non-ASCII hosts
MUST ensure both sides compare the same form.

The following table shows how operation targets match a `prefix` entry
whose `resource` is `https://api.example/orders`:

| Operation target | Result | Why |
| --- | --- | --- |
| `https://api.example/orders` | ALLOW | The base itself |
| `https://api.example/orders/123` | ALLOW | An extension at a path-segment boundary |
| `https://API.EXAMPLE/orders/123` | ALLOW | Scheme and host are case-folded |
| `https://api.example:443/orders/123` | ALLOW | The default port is removed |
| `https://api.example/Orders/123` | DENY | The path is case-sensitive: `Orders` is not `orders` |
| `https://api.example/orders%2F123` (equivalently `%2f`) | DENY | Hex digits normalize to `%2F`, which stays encoded and is not a separator: one segment `orders%2F123`, not an extension of `/orders` |
| `https://api.example/ordersX` | DENY | The match extends only at a path-segment boundary, not within a segment |
| `https://api.example/orders/%2e%2e/admin` | DENY | `%2e%2e` decodes to `..` and the dot-segment is removed, yielding `https://api.example/admin`, outside the prefix |
{: title="Prefix matching for https://api.example/orders"}

{{resource-boundary-canonicalization}} analyzes why each of these rules
matters.

## Subset Rule {#subset}

{{I-D.draft-mcguinness-oauth-mission}} derives, narrows, and delegates a
`mission_resource_access` entry only as a subset of a reference entry,
and refuses an entry that is not one. This section defines that
relation.

When the authorization server narrows the Authority Set for a derived
token, a derived `mission_resource_access` entry A is a subset of a
Mission entry B when all of the following hold:

1. **Resource.** A's resource set is contained in B's (`resource_match`,
   {{resource-access-type}}), under the matcher of
   {{resource-matching}}:
   - an `exact` A under an `exact` B: A.`resource` equals B.`resource`
     literally;
   - an `exact` A under a `prefix` B: B's prefix matcher admits
     A.`resource` as a target;
   - a `prefix` A under a `prefix` B: B's prefix matcher admits A's
     normalized base; and
   - a `prefix` A under an `exact` B: never contained.
2. **Actions.** Every A.`actions` value is within some B.`actions`
   value:
   - a value is within an equal value;
   - a literal action is within a family whose name it extends at a
     segment boundary (`invoices.read` is within `invoices.*`);
   - a family is within a reference family when its own name extends the
     reference's name at a segment boundary (`invoices.q3.*` is within
     `invoices.*`); and
   - a family is never within a literal action.
3. **Constraints.** For every key K in **B**.`constraints`:
   - K MUST also be present in A.`constraints`, unless B's value is one
     K's definition makes equivalent to omitting the member
     (`requires_action_approval: false`). Otherwise a key present in B
     but absent from A is treated as the broadest possible value and
     therefore fails this test.
   - A's value MUST be no broader than B's under K's subset rule: the
     specification-defined rule when K is a Common Constraint
     ({{common-constraints}}), the deployment-defined comparison
     otherwise.

The equivalence in step 3 holds for comparison only: recorded entries
and their integrity commitments are unchanged. A key present only in A
narrows A only when it has defined semantics and the resource server
serving A.`resource` can enforce it; an unknown key in A is never
treated as narrowing ({{common-constraints}}). A grant-enabling member
such as `delegation` follows the delegation rules below, not this one.

The authorization server MUST make this resource comparison with the
same matcher, over the same URI forms, that resource servers use to
enforce the entries ({{resource-matching}}), so that whenever A's
resource set is contained in B's, every target A admits is also admitted
by B. Resource containment alone never establishes authority
containment: actions, constraints, and delegation are checked as above.

Hierarchy is opt-in and closed to two forms: `resource_match: "prefix"`
for resource containment and `.*` action families for action containment
({{resource-access-type}}). Without them, comparison is flat: `resource`
matches by literal equality and a literal action by array membership.

The `delegation` member is policy, not authority, and is not part of
this comparison ({{delegate-eligibility}}). A derived entry's
`delegation`, when present, MUST NOT be broader than the parent entry's:

- its `max_depth` MUST be no greater than the parent entry's;
- its `allowed_delegates` MUST be no wider than the parent entry's, and
  where the parent entry's eligibility inherits the authorization
  server's policy decision ({{delegate-eligibility}}), a derived list
  only restricts that decision; and
- a derived entry MUST NOT introduce `delegation` where the parent entry
  has none.

## Common Constraints {#common-constraints}

A `constraints` member name ({{resource-access-type}}) is either a
specification-defined **Common Constraint** or a deployment-defined key.
Common Constraints give independently developed deployments one
vocabulary they interpret, narrow, and compare identically. Further
Common Constraints are defined by specification and registered
({{iana-common-constraints}}).

A Common Constraint definition fixes:

- **Value syntax**: the JSON value type ({{RFC8259}}) and any additional
  rules.
- **Subset rule**: how a candidate value is judged no broader than a
  reference value, used by the subset comparison of {{subset}}.
- **Intersection rule**: how two values for the same key combine; the
  result MUST be no broader than either operand.

{{subset}} applies a constraint's subset rule. Its intersection rule
applies where a derivation combines two bounds for the same key, as in
the proposal and policy-ceiling example of the Derivation Policy
appendix of {{I-D.draft-mcguinness-oauth-mission}}. This document does
not require a derivation to run a particular intersection algorithm, and
a ceiling whose specification defines a refusal rule is enforced by that
rule, not silently intersected.

A `constraints` member whose name is a specification-defined Common
Constraint is interpreted per its definition. Any other member name
remains deployment-defined and is interpreted only within the issuing
deployment; a consumer that does not recognize it MUST fail closed
({{I-D.draft-mcguinness-oauth-mission}}).

The same duty binds the authorization server when it narrows. The
authorization server derives a candidate entry from a ceiling entry when
it narrows:

- a client's authority proposal to the Authority Set
  ({{I-D.draft-mcguinness-oauth-mission}}); or
- an Authority Set entry to a derived or delegated token
  ({{delegate-eligibility}}).

In either case, a `constraints` key that the authorization server does
not implement narrowing for, whether a registered Common Constraint or a
deployment-defined key, and whether it appears in the ceiling entry or
in the candidate, MUST NOT be dropped while the entry survives. The
authorization server MUST instead refuse the derivation: an unsupported
constraint is unsupported input, so the entry is never omitted to repair
it ({{I-D.draft-mcguinness-oauth-mission}}). An entry whose constraints
the authorization server can compare but that policy declines to grant
is different: it is narrowed or omitted, and the granted
`authorization_details` echo reflects that
({{I-D.draft-mcguinness-oauth-mission}}). Carrying the entry forward
with the key dropped would widen effective authority past the ceiling,
as an unenforced key would at the resource server
({{I-D.draft-mcguinness-oauth-mission}}).

This type defines no interoperable cumulative use counter. A deployment
that adopts Mission Metering ({{I-D.draft-mcguinness-mission-metering}})
applies its accounting and settlement rules, and can embed the metering
policy decision point in the resource server.

### Initial Common Constraints {#initial-common-constraints}

This document defines the following Common Constraints.

`max_amount`:
: A per-action ceiling on a monetary amount.

  - Value: an object with two members, `amount` (REQUIRED, a string
    containing a decimal number, {{decimal-values}}) and `currency`
    (REQUIRED, a currency code as defined in {{ISO4217}}).
  - Subset: no broader when the `currency` values are equal and the
    candidate `amount` is less than or equal to the reference `amount`,
    compared in decimal value space; differing currencies fail the
    comparison (no conversion is defined).
  - Intersection: when the `currency` values are equal, the value with
    the smaller `amount`; differing currencies have no intersection and
    the combination fails.

`resource_issued_after`:
: The action applies only to resources issued at or after this instant.

  - Value: a date-time string as defined in {{RFC3339}}.
  - Subset: no broader when greater than or equal to the reference.
  - Intersection: the later instant.

`resource_issued_before`:
: The action applies only to resources issued at or before this instant.
  The `resource_` qualifier in both names marks that the window bounds
  resource issuance, not token issuance.

  - Value: a date-time string as defined in {{RFC3339}}.
  - Subset: no broader when less than or equal to the reference.
  - Intersection: the earlier instant.

`tenant`:
: The action applies only to resources of the named tenant.

  - Value: a string.
  - Subset: no broader when equal to the reference value.
  - Intersection: the common value when the two are equal; otherwise
    there is no intersection and the combination fails.

`recipient_domain`:
: The action applies only to recipients within the named domain. An
  action addressed to several recipients is within the bound only when
  every recipient is.

  - Value: a string containing a DNS name.
  - Subset: no broader when equal to the reference or a DNS subdomain of
    it.
  - Intersection: the narrower value when one is equal to or a subdomain
    of the other; otherwise there is no intersection and the combination
    fails.

`time_window`:
: The action may be exercised only within the window, evaluated at the
  point of use. This differs from `resource_issued_after` and
  `resource_issued_before`, which bound resource issuance, and from the
  token's `exp`, which bounds the credential.

  - Value: an object with two members, `not_before` and `not_after`,
    each a date-time string as defined in {{RFC3339}}; at least one MUST
    be present, and an absent member is unbounded on that side.
  - Subset: no broader when the candidate window lies within the
    reference window, an absent candidate bound counting as unbounded
    and therefore broader than any present reference bound.
  - Intersection: the overlap (the later `not_before`, the earlier
    `not_after`); an empty overlap has no intersection and the
    combination fails.

`data_classification`:
: The action applies only to data whose classification label is among
  the named values. Label semantics are deployment- or registry-defined;
  the comparison is not.

  - Value: an array of strings.
  - Subset: no broader when the candidate array's members are a subset
    of the reference array's, compared as exact strings.
  - Intersection: the common members; an empty result has no
    intersection and the combination fails.

`allowed_tools`:
: The action may be exercised only through a capability whose identifier
  is among the named values: a tool or function identity, asserted at
  the point of use by the resource server or a component that enforces
  on its behalf.

  - Value: an array of strings.
  - Subset: no broader when the candidate array's members are a subset
    of the reference array's, compared as exact strings.
  - Intersection: the common members; an empty result has no
    intersection and the combination fails.

`requires_action_approval`:
: When `true`, each exercise of the action requires a fresh,
  action-bound approval at the point of use; the resource server, or a
  component that enforces on its behalf, MUST NOT permit the action on
  Mission authority alone. A value of `false` is equivalent to omitting
  the member.

  - Value: a boolean.
  - Subset: no broader when the candidate is `true` or equals the
    reference (narrowing may add the requirement, never remove it).
  - Intersection: the logical OR of the two values.

### Value-Space Comparison {#value-space-comparison}

Common Constraint comparisons are in value space, not lexical:

- `max_amount` `amount` members are compared as the decimal numbers the
  strings contain, so `"500"`, `"500.0"`, and `"500.00"` are equal;
- `resource_issued_after` and `resource_issued_before` values are
  compared as the instants they denote after normalization to UTC, so
  two RFC 3339 representations of the same instant that differ only in
  timezone offset or trailing subsecond zeros are equal;
- `time_window` `not_before` and `not_after` values are compared as the
  instants they denote after normalization to UTC, as
  `resource_issued_after` and `resource_issued_before` values are; and
- `recipient_domain` values are compared as DNS names,
  case-insensitively and on whole labels, so `mail.example.com` is
  within `example.com` and `example.net` is not.

A Common Constraint definition MUST fix its subset and intersection in
value-space terms, so that independent deployments compute the same
result for the same values and the subset rule of {{subset}} is
reproducible.

## Resource Server Enforcement {#rs-enforcement}

{{I-D.draft-mcguinness-oauth-mission}} requires a resource server to
enforce each applicable `authorization_details` entry according to that
entry's own type specification, and to fail closed on an entry whose
type it does not implement or cannot fully evaluate. This section is
that specification for a `mission_resource_access` entry. A resource
server:

- MUST enforce an entry whose `resource` matches the operation target
  under the entry's `resource_match` ({{resource-matching}}), permitting
  only the listed `actions` subject to `constraints`. Where more than
  one applicable entry matches, entries are alternative grants of
  authority, not conjunctive filters.
- MUST treat an entry's `resource_match` value it does not recognize as
  unenforceable and fail closed ({{resource-access-type}}).
- MUST, when it matches an operation target against a `prefix` entry,
  apply the URI normalization {{resource-matching}} defines for
  containment, before the prefix comparison rather than after
  ({{resource-boundary-canonicalization}}).
- MUST fail closed on any `constraints` key it does not understand, or
  understands but cannot enforce, in an applicable entry, rather than
  grant access while ignoring the key.
- MUST NOT reduce a `constraints` key to disclosure-only: an unenforced
  key that narrows authority silently widens the grant if treated as
  absent or advisory.

**Failing closed.** An entry the resource server cannot fully enforce
provides no authority: one with an unrecognized `resource_match` value,
a member the resource server does not recognize or whose obligations it
cannot fulfill, or a `constraints` key the resource server does not
understand or cannot enforce. The resource server then authorizes the
request only through another applicable entry that it can fully enforce
and that covers the whole request on its own: the entry's `resource`
matches the target, the action is among its `actions`, and every key in
its `constraints` is satisfied. The resource server:

- MUST NOT combine parts of several entries to authorize one request, or
  borrow authority from an entry it cannot fully enforce; and
- MUST refuse the request when no such entry exists, for example with
  HTTP status code 403 and the `insufficient_scope` error code
  ({{Section 3.1 of RFC6750}}), or with the deployment's usual
  insufficient-authority error.

A failure of token-wide validation, such as of the token's signature,
audience, or sender constraint ({{I-D.draft-mcguinness-oauth-mission}}),
rejects the token whatever its entries carry.

**Entry members.** Each member of an entry has a resource-server role
or none:

- `type`, `resource`, `resource_match`, `actions`, and `constraints` are
  enforced as above;
- `delegation` has no resource-server enforcement role: the
  authorization server applies it at issuance
  ({{delegate-eligibility}}), so a resource server MAY disregard it,
  together with any member a companion profile adds to it;
- a member that another specification defines for this type is
  enforced as that specification requires, and leaves the entry fully
  enforceable when the resource server, or a runtime layer acting for
  it, implements that specification and fulfills every obligation it
  places on enforcement; and
- any other member, including one the resource server does not
  recognize, makes the entry one the resource server cannot fully
  enforce.

An entry carrying the {{RFC9396}} common `locations` field, which this
type does not use ({{entry-validation}}), is likewise one the resource
server cannot fully enforce.

## Protected Resource Metadata {#protected-resource-metadata}

A protected resource MAY advertise the following member in its protected
resource metadata ({{RFC9728}}):

`mission_constraints_supported`:
: OPTIONAL. A JSON array of strings: the `constraints` keys, Common
  Constraints and deployment-defined names, that the resource
  understands and enforces ({{rs-enforcement}}). It lets the
  authorization server discover which keys it can emit for the resource
  ({{resource-access-type}}), and lets a client predict a fail-closed
  constraint mismatch before making a request. When absent, that
  knowledge is established out of band.

## Delegate Eligibility {#delegate-eligibility}

{{I-D.draft-mcguinness-oauth-mission}} gates a delegated token's carried
entries on the entry type's own delegation policy, evaluated at the
delegation depth `d` of the token being issued. That document's
Delegation Constraints section defines `d` and how the authorization
server establishes it from its own accounting, including the
self-exchange and cross-domain rules; the `act` claim attributes the
chain and is not the authoritative count. For a
`mission_resource_access` entry, the authorization server includes it in
a delegated token issued at delegation depth `d` only if all of the
following hold:

1. the entry carries a `delegation` member (otherwise it is
   non-delegable, which is the default);
2. `d` is less than or equal to the entry's `delegation.max_depth`; and
3. the delegate is permitted by `delegation.allowed_delegates` or, when
   that member is absent, by the authorization server's
   delegation-authorization policy, which the authorization server MUST
   apply at every exchange: an absent list of delegate matchers is a
   decision deferred to policy, never a blanket grant of eligibility.

An entry failing any of these narrows out of the delegated token,
consistent with the subset rule ({{subset}}). Surviving entries are
carried with their `delegation` member intact, so the next hop is
evaluated the same way.

**Inherited eligibility.** A derived entry's `allowed_delegates`
restricts eligibility; it never replaces an obligation the derivation
inherits. An entry derived from a reference entry that has no
`allowed_delegates` inherits the authorization server's policy
decision, and so does every entry derived from it: a delegate is
permitted only when the policy permits it and, where the entry carries
a list, the list permits it too. When policy permits Bob and denies
Carol, an entry whose list names Carol still cannot admit Carol.

The obligation holds from the initial derivation. An approved entry
derived from a ceiling entry without `allowed_delegates` inherits the
policy decision even when the approved proposal added a list, so the
approved entry's own members do not reveal the obligation. The
authorization server therefore records, when it derives the Authority
Set, which approved entries inherit the policy decision, and retains
that provenance with the Mission. It evaluates every later exchange
against the approved entry in the Mission Record
({{I-D.draft-mcguinness-oauth-mission}}) and that provenance, never
against a presented token alone. Where it cannot resolve either, the
entry narrows out of the delegated token.

### Matching `allowed_delegates` {#matching-allowed-delegates}

Each `allowed_delegates` value is a delegate matcher: an object modeled
on the actor object of the `may_act` claim ({{Section 4.4 of RFC8693}}).
Where `may_act` names a single party eligible to act on a token,
`allowed_delegates` is a per-entry list of such matchers, generalized to
actor-type classes:

- A `{ "sub": ... }` matcher permits a specific delegate by client
  identifier.
- A `{ "sub_profile": ... }` matcher permits any actor of that type (for
  example, `ai_agent`), as given by the `sub_profile` member of the
  actor's object in the `act` claim
  ({{I-D.draft-mcguinness-oauth-mission}}). An actor's `sub_profile` MAY
  carry multiple space-separated values; a `{ "sub_profile": ... }`
  matcher is satisfied when its value is among the actor's values.

A delegate matcher that carries both `sub` and `sub_profile` is
satisfied only when the delegate satisfies both. A delegate is permitted
if it satisfies any of the entry's delegate matchers, so a deployment
can permit a specific client, a class of actors, or both.

The authorization server MUST authenticate the delegate at the Token
Exchange and assert the actor's `sub` and `sub_profile` itself. A
self-asserted `sub_profile` MUST NOT satisfy a delegate matcher;
otherwise a client could claim any actor type to bypass the constraint.

A `{ "sub": ... }` matcher is a client identifier in the issuing
authorization server's namespace and is not portable across a trust
domain. How an authorization server in another trust domain (a "Resource
AS") evaluates conveyed delegate matchers, failing closed and narrowing
out any `sub` matcher it cannot resolve, is specified by
{{I-D.draft-mcguinness-oauth-mission-cross-domain}}.

## Scope Projection {#scope-projection}

{{I-D.draft-mcguinness-oauth-mission}} states the semantic subset
condition and issuance algorithm an authorization server applies before
emitting `scope` for any `authorization_details` entry: the projected
scope's effective rights, together with every independently mandatory
control on the target's enforcement path, MUST be a subset of the rights
the applicable entries grant. This section states when that condition
holds for a `mission_resource_access` entry.

A scope-projection mapping's entry for this type names, for a target
resource server:

- the `scope` value or values it emits;
- the `resource` and `resource_match` the mapping covers;
- the `actions` value or values each `scope` value stands for; and
- for every `constraints` key an entry may carry, whether the target
  independently and identically enforces that key on the
  `scope`-authorized path.

Projecting a `mission_resource_access` entry's authority to `scope` is
safe only when all of the following hold:

1. **The mapping covers the same resource set.** The mapping's `scope`
   value is defined over the entry's `resource` and `resource_match`. A
   `prefix` entry projects safely only when the mapping scopes the value
   to that same prefix, or to a narrower resource within it whose
   complete effective rights remain a subset of the entry's; a `scope`
   value the target's own interpretation extends to a broader ancestor
   resource is not a safe projection of a narrower `prefix` entry.
2. **The actions match without aggregation.** Every action granted by
   the mapped `scope` value MUST be included in the applicable entry's
   `actions`; the value MAY grant a proper subset of them. A `scope`
   value that grants any additional action, including through an implied
   action family, an aggregate of unrelated actions, or the union of
   more than one entry's actions, fails this condition, because the
   target grants every action the union names, not only the entry's.
3. **Every carried `constraints` key is independently enforced.** For
   every key in the entry's `constraints`, the mapping states that the
   target enforces that key, under a comparison at least as tight as the
   entry's value, on the `scope`-authorized path. An entry with no
   `constraints` satisfies this condition. A key the mapping does not
   name as independently enforced fails the condition for that entry, as
   an unenforced key fails closed at a resource server that consumes
   `authorization_details` directly.

An entry failing any condition MUST NOT be projected to `scope`. Per
{{I-D.draft-mcguinness-oauth-mission}}'s issuance algorithm, the
authorization server then omits `scope` for that entry where the
target's enforcement path consumes `authorization_details`, and refuses
issuance to that target when it is `scope`-only (it consumes `scope` and
not `authorization_details`) and no other carried entry supplies a safe
projection.

## Transformation Capabilities {#transformation-capabilities}

{{I-D.draft-mcguinness-oauth-mission}} requires an authorization server
to declare, for every `authorization_details` type it supports, whether
it understands the type's narrowing, delegation, and scope-projection
semantics. The declaration is made through deployment documentation or,
where available, the machine-readable
`mission_transformation_capabilities` carrier that document defines.

For `mission_resource_access`, an authorization server that implements
this document in full declares:

`narrowing`: `true`
: The subset rule of {{subset}}, over every member this document
  specifies, and the Common Constraint intersection rules of
  {{common-constraints}} are fully defined. An authorization server MUST
  NOT declare `narrowing` as `true` unless it implements these rules for
  every Common Constraint of {{initial-common-constraints}}. A Common
  Constraint registered later is not required by the declaration, but an
  authorization server that meets one it does not support fails closed
  ({{common-constraints}}).

`delegation`: `true`
: The delegation policy of {{delegate-eligibility}} is fully defined; an
  entry's `delegation` member states its own depth and eligibility
  bounds.

`projection`: `true`
: A safe scope projection is defined, and decidable per entry, by
  {{scope-projection}}; it is not unconditionally available for every
  entry, and that section's conditions apply to each entry before
  `scope` is emitted.

An authorization server that implements only part of this document (for
example, `mission_resource_access` entries without ever emitting `scope`
for them) leaves `projection` undeclared rather than declaring it
`true`. {{I-D.draft-mcguinness-oauth-mission}}'s carried-as-approved
fallback then applies to `scope` projection for this type at that
deployment, as it would for an unsupported type. Omitting `projection`
from one carrier leaves it undeclared by that carrier only, so a
lower-priority carrier can still declare it
({{I-D.draft-mcguinness-oauth-mission}}). Where no carrier declares it,
the authorization server emits no projected resource `scope` for this
type: it carries `authorization_details` where the target consumes them,
refuses issuance to a `scope`-only target only when no other applicable
carried entry supplies a safe projection, and answers an explicitly
requested `scope` it cannot grant as
{{I-D.draft-mcguinness-oauth-mission}} specifies.

## Modeling Tools and Function Calls {#tools}

This section is non-normative. A tool an agent invokes, such as a Model
Context Protocol (MCP) tool or a function call, is modeled as a
`mission_resource_access` entry. No separate entry type is needed: the
subset and delegation rules apply unchanged, and derivation,
`authority_hash`, and the Authority Set itself remain
{{I-D.draft-mcguinness-oauth-mission}}'s.

The mapping is:

- `resource` names the operation target that the tool provider's
  operation contract establishes for a call ({{resource-matching}}).
  The MCP authorization model ({{MCP}}) makes an MCP server an
  OAuth 2.0 resource server, and a token is audience-bound to its
  URL; the server's contract can identify that URL or a finer target,
  such as a record a tool acts on.
- `actions` are the tool names the task needs at that provider.
  Authorizing a tool is authorizing its name as an action, which lines
  up with MCP filtering its tool list by the caller's granted authority
  and routing each tool call for authorization.
- `constraints` carry machine-actionable bounds on a tool's arguments,
  for example an amount ceiling or a recipient domain (the `max_amount`
  and `recipient_domain` Common Constraints, {{common-constraints}}).
  Like all `constraints`, they are committed by `authority_hash` and
  carried to the point of use, but the resource server, or a runtime
  enforcement layer acting for it, evaluates them against the concrete
  call arguments; the authorization server does not evaluate them at
  issuance ({{I-D.draft-mcguinness-oauth-mission}}).

In the examples in this section, each MCP server's operation contract
identifies the server's URL as the operation target. Tool names as
actions, and constraints on their arguments, determine the permitted
calls.

The following example shows the Authority Set of a Mission authorized to
read invoices and post small adjustments through a finance MCP server,
and to send messages through a messaging MCP server:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://finance.example.com/mcp",
    "actions": ["query_invoices", "post_adjustment"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } },
  { "type": "mission_resource_access",
    "resource": "https://mail.example.com/mcp",
    "actions": ["send_message"],
    "constraints": { "recipient_domain": "example.com" } }
]
~~~

Delegation to a sub-agent uses the same `delegation` member
({{delegate-eligibility}}). The following example shows an Authority Set
entry, approved with its `delegation` member, that a sub-agent of type
`ai_agent` may exercise at depth 1 for the read tool only:

~~~ json
{ "type": "mission_resource_access",
  "resource": "https://finance.example.com/mcp",
  "actions": ["query_invoices"],
  "delegation": {
    "max_depth": 1,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }]
  } }
~~~

This document does not define a typed, attenuable per-argument
constraint grammar for tools: one that narrows a tool's argument schema
(for example, `amount` in a `range`, or `recipient` in a `one_of` set)
as the grant is derived or delegated. Argument bounds here are the same
flat `constraints` used for any resource, evaluated at runtime.
Structured per-argument attenuation
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}, with
object-capability systems such as UCAN as prior art) would extend the
delegation and subset model of this document ({{delegate-eligibility}},
{{subset}}) rather than introduce a new entry type.

# Conformance {#conformance}

An implementation conforms to this document in one of two roles.

An **authorization server** conforms by supporting
`mission_resource_access` as one of the `authorization_details` types
{{I-D.draft-mcguinness-oauth-mission}} names in its approved set, and
implements:

- schema validation of a proposed or carried entry against the type
  definition ({{resource-access-type}}); and
- the Transformation Capabilities declaration
  ({{transformation-capabilities}}), stating which of narrowing,
  delegation, and projection it claims for this type.

For each capability it declares `true`, an authorization server also
implements:

- **narrowing**: the subset rule and the Common Constraint intersection
  rules ({{subset}}, {{common-constraints}});
- **delegation**: the delegate eligibility test
  ({{delegate-eligibility}}); and
- **projection**: the three per-entry, per-target safety conditions of
  {{scope-projection}} before emitting `scope`.

An authorization server that does not claim `projection` MUST NOT emit
`scope` for a `mission_resource_access` entry under
{{I-D.draft-mcguinness-oauth-mission}}'s issuance algorithm, and instead
omits `scope` or refuses issuance to a scope-only target, as that
document requires for any type without a declared projection.

A **resource server** conforms by implementing the enforcement duties of
{{rs-enforcement}}: exact or prefix resource matching, action and
action-family matching, and every carried `constraints` key, failing
closed on a member, matching mode, or key it does not implement. A
resource server does not implement narrowing, delegate eligibility, or
the Transformation Capabilities declaration; those are the authorization
server's, and their presence or absence does not bear on a resource
server's conformance.

# Security Considerations {#security-considerations}

This document defines a subset relation, a delegation policy, and a
scope-projection safety condition. The Security Considerations of
{{I-D.draft-mcguinness-oauth-mission}} apply to everything upstream of a
`mission_resource_access` entry: the approval event, the integrity
anchors, and issuance gating. Three risks are specific to this type:

- **Comparison, not meaning.** {{subset}} compares members, not effects:
  a candidate that compares as no broader can still permit an effect the
  parent's purpose never contemplated
  ({{I-D.draft-mcguinness-oauth-mission}}).
- **An unenforced constraint widens the grant.** A resource server or
  scope projection that treats an unrecognized `constraints` key as
  absent, or as disclosure-only, grants more than the entry authorizes;
  {{rs-enforcement}} and {{scope-projection}} require fail-closed
  handling instead.
- **A safe projection is per entry, not per type.** That
  `mission_resource_access` defines a projection relation
  ({{scope-projection}}) does not make every entry of the type safely
  projectable: {{scope-projection}}'s three conditions must hold for the
  specific entry and mapping in force, and the type's general capability
  does not extend to an entry by default.

## Resource Boundary Canonicalization {#resource-boundary-canonicalization}

A `prefix` entry ({{resource-access-type}}) draws an authority boundary
in URI space, and {{resource-matching}} requires the authorization
server and the resource server to draw it with one normalization. A URI
matcher that normalizes differently from the party that derived the
entry can admit a request the Approver never authorized, or deny one the
Approver did. An `exact` entry is compared literally, without
normalization, so these vectors concern `prefix` entries. Each of the
following vectors turns on such a difference:

- **Encoded slash (`%2F`).** A reserved octet, left encoded by the
  normalization (which decodes only unreserved octets) and never a
  path-segment separator when matching. An intermediary that decodes it
  before the resource server enforces shifts the boundary; a deployment
  MUST prevent that rewriting or account for it.
- **Encoded dot (`%2e`, `%2e%2e`).** The `.` octet is unreserved, so the
  normalization decodes it and then removes dot-segments. The hazard is
  order: normalizing before the comparison collapses a decoded `%2e%2e`
  out of the path and draws the boundary correctly, while matching the
  raw string first and letting a downstream component decode and
  collapse afterward can escape the prefix.
- **Double or empty path segments.** Beyond the empty-path equivalence,
  a URI matcher that coalesces `//` or trailing-slash differences of its
  own draws a boundary the normalization does not, which
  {{resource-matching}} forbids.
- **Default-port presence.** `https://a.example:443` and
  `https://a.example` are one authority only after the default-port
  removal of {{resource-matching}}; a URI matcher that skips it splits
  one boundary into two.
- **Unicode and IDNA host.** The normalization lowercases the host but
  defines no IDNA conversion, so two sides that convert differently draw
  different boundaries; {{resource-matching}} requires them to compare
  the same form.
- **Percent-decoding order.** The normalization decodes only unreserved
  octets and runs before comparison; decoding reserved octets, or
  decoding after the comparison, changes which characters count as
  separators and can move the boundary.

A deployment MAY agree out of band on the canonicalization profile its
authorization server and resource servers apply; this document defines
one rule ({{resource-matching}}), so no profile identifier is required
for interoperation.

# Privacy Considerations {#privacy-considerations}

This document defines no data element beyond what
{{I-D.draft-mcguinness-oauth-mission}} carries in
`authorization_details`, and that document's Privacy Considerations
apply unchanged. The `resource`, `actions`, and `constraints` values of
an entry are as privacy-sensitive as the Authority Set that carries
them.

# IANA Considerations {#iana}

## The Mission Resource Access Authorization Details Type {#type-registration}

`mission_resource_access` is an `authorization_details` type
({{Section 2 of RFC9396}}), defined in {{resource-access-type}}.
{{RFC9396}} establishes no IANA registry of authorization details types
(the authorization server interprets type identifiers), so this document
requests no IANA action for it. If a registry of authorization details
types is established in the future, this type SHOULD be registered in
it.

## OAuth Protected Resource Metadata Registration {#oauth-protected-resource-metadata-registration}

This document requests registration of the following value in the "OAuth
Protected Resource Metadata" registry ({{RFC9728}}):

- Metadata Name: `mission_constraints_supported`
- Metadata Description: JSON array of the `constraints` keys the
  protected resource understands and enforces
- Change Controller: IETF
- Specification Document(s): {{protected-resource-metadata}} of this
  document

## Common Constraints Registry {#iana-common-constraints}

This document establishes the "Mission Common Constraints" registry. The
registration policy is Specification Required ({{RFC8126}}). The
Designated Expert checks that a submission:

- uses a name matching `^[A-Za-z0-9_.:-]+$` that is not already
  registered;
- gives a JSON value syntax ({{RFC8259}}) precise enough for independent
  implementations to agree on; and
- states a subset rule and an intersection rule, both in value-space
  terms ({{value-space-comparison}}), with the intersection of any two
  valid values never broader than either operand.

A specification-defined name is coordinated through this registry. Any
other `constraints` member name is either collision-resistant or
deployment-defined, and stays outside the registry.

Each registration records:

- **Key Name**: the `constraints` member name.
- **Value Syntax**: the JSON value type and any additional syntax rules.
- **Subset Rule**: how a candidate value is judged no broader than a
  reference value.
- **Intersection Rule**: how two values for the key combine into a
  result no broader than either operand.
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the key.

The initial contents of the registry are the Common Constraints of
{{initial-common-constraints}}. For every entry, the Change Controller
is IETF and the Reference is {{initial-common-constraints}} of this
document, which holds the full Subset Rule and Intersection Rule text;
the table summarizes them.

| Key Name | Value Syntax | Subset Rule | Intersection Rule |
|---|---|---|---|
| `max_amount` | Object: `amount` (decimal string), `currency` (ISO 4217 code) | Same currency; candidate <= reference | Same currency; the smaller amount |
| `resource_issued_after` | String, RFC 3339 date-time | Candidate >= reference | The later instant |
| `resource_issued_before` | String, RFC 3339 date-time | Candidate <= reference | The earlier instant |
| `tenant` | String | Equal | The shared value |
| `recipient_domain` | String, DNS name | Equal or a subdomain | The narrower value |
| `time_window` | Object: `not_before` and `not_after` (RFC 3339 date-time) | Candidate window within reference window | The overlap |
| `data_classification` | Array of strings | Candidate a subset of reference | The common members |
| `allowed_tools` | Array of strings | Candidate a subset of reference | The common members |
| `requires_action_approval` | Boolean | Candidate `true` or equal to reference | The logical OR |
{: title="Initial Mission Common Constraints registry"}

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-00

- Initial version. Defines `mission_resource_access`, split from
  {{I-D.draft-mcguinness-oauth-mission}}: resource and action matching;
  constraints and the Mission Common Constraints registry; the
  delegation policy and delegate matching; the subset and intersection
  rules; resource server enforcement and the
  `mission_constraints_supported` metadata member; the Resource Boundary
  Canonicalization analysis; the type's scope-projection safety
  conditions; and its Transformation Capabilities declaration.

# Acknowledgments
{:numbered="false"}

This document was split from Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}}, where `mission_resource_access`
was originally defined.
