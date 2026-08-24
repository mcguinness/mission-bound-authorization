---
title: "Mission Resource Access Profile for OAuth 2.0"
abbrev: "OAuth Mission RAR"
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
  I-D.draft-zehavi-oauth-rar-metadata:
  I-D.draft-niyikiza-oauth-attenuating-agent-tokens:
  MCP:
    title: "Model Context Protocol: Authorization"
    target: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
    author:
      - org: Model Context Protocol Project
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

Mission-Bound Authorization for OAuth 2.0 (the "issuance profile") derives
a Mission's Authority Set as one or more Rich Authorization Requests
{{RFC9396}} `authorization_details` entries, of any Authorization
Server-supported type, and is type-agnostic toward that type's own
semantics. This document defines `mission_resource_access`: a
general-purpose, cross-resource `authorization_details` type carrying a
resource identifier matched exactly or by path prefix, an action
namespace with wildcard families, machine-actionable constraints
(including a registered Common Constraints vocabulary), and a per-entry
delegation policy, together with the subset and intersection algebra a
deployment uses to compare and narrow two entries. It also defines this
type's scope-projection safety conditions and its declaration under the
issuance profile's machine-readable transformation-capability map. This
document is a profile of the issuance profile; a deployment MAY support
`mission_resource_access`, another AS-supported `authorization_details`
type, or both.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}}
(the "issuance profile") commits a Mission's Authority Set as one or more
{{RFC9396}} `authorization_details` entries, of whatever `authorization_details`
type or types the Authorization Server supports. The issuance profile is
type-agnostic: it derives, commits, and gates entries of any AS-supported
type the same way, and leaves each type's own comparison and
transformation semantics to the specification that defines the type,
exactly as {{RFC9396}} Section 2 permits.

This document defines that specification for one type: `mission_resource_access`,
a cross-resource authorization language matching a resource exactly or by
prefix, an action namespace with wildcard families, machine-actionable
constraints drawn from a registered Common Constraints vocabulary or a
deployment's own names, and a per-entry delegation policy, together with
the subset and intersection algebra a deployment uses to compare and
narrow two entries. `mission_resource_access` is a general-purpose type:
an Authorization Server with no reason to define a narrower,
audience-specific `authorization_details` type can use it directly, and
the issuance profile's own worked examples use it throughout.

`mission_resource_access` was originally defined inline in the issuance
profile. This document relocates that definition without changing it:
every relocated rule keeps its member names and comparison semantics
unchanged. The issuance profile keeps the type-agnostic machinery: the
approved-set commitment, derivation gating, and its own type-agnostic
scope-projection rule and issuance algorithm. This document supplies
`mission_resource_access`'s concrete instance of each: its subset and
intersection algebra, its scope-projection safety conditions, and its
declaration under the issuance profile's transformation-capability map.

# Status: A General-Purpose Type {#status}

This document defines one `authorization_details` type a deployment of
the issuance profile {{I-D.draft-mcguinness-oauth-mission}} MAY
support; the issuance profile is complete, and type-agnostic, without
it. A deployment adopts this document when it has no reason to define
its own audience-specific type and wants `mission_resource_access`'s
resource, action, constraint, and delegation vocabulary instead.

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Maturity: stable. Maintenance: active.
Adopt when: The OAuth binding's supported authorization_details types include mission_resource_access, or you need its concrete subset/delegation/projection semantics.
Requires: Mission-Bound Authorization for OAuth 2.0.
<!-- family-status: END -->

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative. Terms such
as Mission, Authority Set, Subject, and Approver are defined by
{{I-D.draft-mcguinness-oauth-mission}} and used here with the same
meaning.

# The Mission Resource Access Type {#resource-access-type}

`mission_resource_access` is a {{RFC9396}} `authorization_details` type:
a general-purpose, cross-resource authorization language. An entry is a
{{RFC9396}} `authorization_details` object with these members:

`type`:
: REQUIRED. A string. `mission_resource_access`.

`resource`:
: REQUIRED. A string. The single protected resource the entry
  applies to: an absolute URI identifying an OAuth protected
  resource ({{RFC8707}}) or a Protected Resource ({{RFC9728}}), the
  same kind of identifier as the {{RFC8707}} `resource` value.
  Carrying it per entry, which {{RFC9396}} permits, lets one token
  scope distinct authority to distinct resources. A Mission-bound
  token's `aud` is derived from the carried entries' `resource`
  values and is typically coarser
  ({{I-D.draft-mcguinness-oauth-mission}}). Per {{RFC9396}}
  Section 3.2, the `resource` authorization request parameter does
  not affect how the AS processes `authorization_details`, and this
  member is distinct from the {{RFC9396}} common `locations` field.

`resource_match`:
: OPTIONAL. A string: `exact` (the default, and the behavior when the
  member is absent) or `prefix`. Under `exact` the entry applies to the
  `resource` URI alone. Under `prefix` the entry authorizes the
  `resource` itself and any URI beneath it at a path-segment boundary
  (the `resource` followed by `/` and further path). A `resource`
  value under `prefix` MUST NOT carry a query or fragment component;
  the AS refuses such an entry with `invalid_authorization_details`.
  For prefix purposes, a `resource` with an empty path and one whose
  path is `/` denote the same base: `https://a.example` and
  `https://a.example/` authorize the same set. These two values
  are the only ones defined; a consumer MUST treat an entry whose
  `resource_match` value it does not recognize as unenforceable and
  fail closed ({{I-D.draft-mcguinness-oauth-mission}}). Containment
  between effective resource sets is compared as defined in
  {{subset}}.

`actions`:
: REQUIRED. An array of strings. Permitted action values: each is an
  action identifier matching `[A-Za-z0-9_.:-]+`, or an action family
  (an identifier followed by `.*`). An action family authorizes
  every action whose dot-separated identifier extends the family
  name at a segment boundary (`invoices.*` authorizes
  `invoices.read` and `invoices.q3.export`, not `invoicesx.read`).

  - Like an OAuth scope, an action value carries meaning only at the
    `resource` that defines it: a consumer enforces only the actions
    it recognizes for that resource and honors no others, so an
    unrecognized action is fail-closed by construction.
  - An AS SHOULD draw action identifiers from a namespace the
    serving resource documents, so the set is interpretable
    cross-vendor rather than ad hoc.
  - A consent rendering MUST present a family as the breadth it is:
    all actions under the name, not one action.
  - An AS SHOULD treat deriving a family as high-risk breadth.

`constraints`:
: OPTIONAL. An object. Machine-actionable per-resource
  bounds (for example, `max_amount`). A member name defined as a
  Common Constraint ({{common-constraints}}) has shared semantics
  across deployments; any other name is deployment-defined.

  - Because a `constraints` member narrows authority, a Resource Server
    that cannot enforce one MUST fail closed
    ({{I-D.draft-mcguinness-oauth-mission}}).
  - To avoid that failure mode, the AS SHOULD emit for a given
    `resource` only `constraints` keys that the Resource Server serving
    it is known (by registration, deployment policy, or the resource's
    advertised `mission_constraints_supported`
    ({{I-D.draft-mcguinness-oauth-mission}})) to understand and enforce.

`delegation`:
: OPTIONAL. An object. The delegation policy for this
  entry ({{delegate-eligibility}}). When absent, this entry's
  authority is non-delegable: it MUST NOT appear in a delegated
  token. When present, it has these members:

  `max_depth`:
  : REQUIRED. An integer. The maximum delegation depth at
    which this entry's authority may be exercised
    ({{delegate-eligibility}}).

  `allowed_delegates`:
  : RECOMMENDED. An array of objects. The permitted
    delegates, each a `may_act`-style matcher
    ({{delegate-eligibility}}): `{ "sub": "<client_id>" }` for a
    specific delegate, or `{ "sub_profile": "<actor-type>" }` for an
    actor-type class. When absent, eligibility falls to the AS's
    delegation-authorization policy, which MUST be applied at every
    exchange ({{delegate-eligibility}}); absence delegates the
    decision to policy, it never grants blanket eligibility. The
    member is RECOMMENDED so that eligibility is committed and
    rendered with the entry rather than left wholly to policy.

  A companion profile MAY define additional `delegation` members.
  Such a member is policy, not authority ({{delegate-eligibility}}):
  a derived entry's value for it MUST NOT be broader than the parent
  entry's, and a member the AS does not understand is carried
  unchanged.

Example Authority Set (the read entry is delegable to depth 2 and
bounded to a Q3 issuance window by the `resource_issued_after` and
`resource_issued_before` Common Constraints ({{common-constraints}});
the write entry carries no `delegation` and so is non-delegable, because
`delegation` is per entry):

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

## Subset Rule {#subset}

{{I-D.draft-mcguinness-oauth-mission}} derives, narrows, and delegates a
`mission_resource_access` entry only as a subset of a reference entry,
and refuses an entry that is not one. This section defines that
relation.

When the AS narrows the Authority Set for a derived token, a derived
`mission_resource_access` entry A is a subset of a Mission entry B
when:

1. A's effective resource set is contained in B's
   (`resource_match`, {{resource-access-type}}): when neither
   entry sets `resource_match: "prefix"`, A.`resource` equals
   B.`resource`; when B is a `prefix` entry, A (whether `exact` or
   `prefix`) is contained when A.`resource` equals B.`resource` or
   extends its path at a path-segment boundary; a `prefix` A is never
   contained in an `exact` B.
2. Every A.`actions` value is within some B.`actions` value: a value
   is within an equal value; a literal action is within a family whose
   name it extends at a segment boundary (`invoices.read` is within
   `invoices.*`); a family is within a reference family when its own
   name extends the reference's name at a segment boundary
   (`invoices.q3.*` is within `invoices.*`). A family is never within
   a literal action.
3. For every key K in **B**.`constraints`:
   - K MUST also be present in A.`constraints`. A key present in B
     but absent from A is treated as the broadest possible value and
     therefore fails this test.
   - A's value MUST be no broader than B's under K's subset rule:
     the specification-defined rule when K is a Common Constraint
     ({{common-constraints}}), the deployment-defined comparison
     otherwise.

Resource containment under a `prefix` reference is compared after
RFC 3986 {{RFC3986}} syntax-based normalization of both URIs: lowercase
the scheme and host, remove a default port, uppercase the hexadecimal
digits of any percent-encoding ({{RFC3986}} Section 2.1, so `%2f` and
`%2F` are equivalent), decode percent-encoded octets of unreserved
characters, and remove dot-segments. This
normalization applies to comparison only, never to hashing:
{{I-D.draft-mcguinness-oauth-mission}}'s anchor computation remains
byte-exact over the recorded values and is untouched by this rule.

The default comparison is deliberately flat: `resource` matches by
exact equality and a literal action by array membership. Hierarchy is
opt-in and closed to the two forms above: `resource_match: "prefix"`
for resource containment and `.*` action families for action
containment ({{resource-access-type}}). A deployment that uses
neither retains the flat behavior unchanged.

The `delegation` member is policy, not authority, and is not part of
this comparison ({{delegate-eligibility}}). A derived entry's
`delegation`, when present, MUST NOT be broader than the parent
entry's:

- its `max_depth` MUST be no greater than the parent entry's;
- its `allowed_delegates` MUST be no wider than the parent entry's;
  and
- a derived entry MUST NOT introduce `delegation` where the parent
  entry has none.

## Common Constraints {#common-constraints}

A `constraints` member name ({{resource-access-type}}) is either a
specification-defined **Common Constraint** or a deployment-defined
key. Common
Constraints give independently developed deployments one vocabulary
they interpret, narrow, and compare identically; further Common
Constraints are defined by specification under the naming convention of
{{iana-common-constraints}}.

A Common Constraint definition fixes:

- **Value syntax**: the JSON {{RFC8259}} value type and any additional
  rules.
- **Subset rule**: how a candidate value is judged no broader than a
  reference value, used by the subset comparison of {{subset}}.
- **Intersection rule**: how two values for the same key combine; the
  result MUST be no broader than either operand.

A `constraints` member whose name is a specification-defined Common
Constraint is interpreted per its
definition. Any other member name remains
deployment-defined and is interpreted only within the issuing
deployment; a consumer that does not recognize it MUST fail closed
({{I-D.draft-mcguinness-oauth-mission}}).

The same duty binds the AS side of narrowing: whenever the AS derives
a candidate entry from a ceiling (a client's authority proposal
narrowed to the Authority Set, or an Authority Set entry narrowed to
a derived or delegated token, {{I-D.draft-mcguinness-oauth-mission}},
{{delegate-eligibility}}), a
registered Common Constraint key present in the ceiling entry that the
AS does not implement narrowing for MUST NOT be dropped while the
entry survives. The AS MUST instead fail closed: refuse the whole
derivation, or omit the entry from the result, exactly as an
unrecognized `resources` value already may be; the granted
`authorization_details` echo reflects any such omission
({{I-D.draft-mcguinness-oauth-mission}}). Carrying the entry forward with the
key dropped would widen effective authority past the ceiling exactly
as an unenforced key would at the Resource Server
({{I-D.draft-mcguinness-oauth-mission}}).

This document defines the initial Common Constraints:

- `max_amount` (object): a per-action ceiling on a monetary amount.
  The value is an object with two members: `amount` (REQUIRED, a
  string containing a decimal number) and `currency` (REQUIRED, an
  ISO 4217 {{ISO4217}} currency code). Subset: no broader when the `currency`
  values are equal and the candidate `amount` is less than or equal
  to the reference `amount`, compared in decimal value space;
  differing currencies fail the comparison (no conversion is
  defined). Intersection: when the `currency` values are equal, the
  value with the smaller `amount`; differing currencies have no
  intersection and the combination fails.
- `resource_issued_after` (string, an RFC 3339 {{RFC3339}} date-time):
  the action applies only to resources issued at or after this instant.
  Subset: no broader when greater than or equal to the reference.
  Intersection: the later instant.
- `resource_issued_before` (string, an RFC 3339 {{RFC3339}} date-time):
  the action applies only to resources issued at or before this
  instant. Subset: no broader when less than or equal to the reference.
  Intersection: the earlier instant. The `resource_` qualifier in both
  names marks that the window bounds resource issuance, not token
  issuance.
- `tenant` (string): the action applies only to resources of the named
  tenant. Subset: no broader when equal to the reference value.
  Intersection: the common value when the two are equal; otherwise
  there is no intersection and the combination fails.
- `recipient_domain` (string, a DNS name): the action applies only to
  recipients within the named domain. Subset: no broader when equal to
  the reference or a DNS subdomain of it. Intersection: the narrower
  value when one is equal to or a subdomain of the other; otherwise
  there is no intersection and the combination fails.
- `time_window` (object): the action may be exercised only within the
  window, evaluated at the point of use (unlike `resource_issued_after`
  and `resource_issued_before`, which bound resource issuance, and
  unlike token `exp`, which bounds the credential). The value has two
  members, `not_before` and `not_after` (each an RFC 3339 {{RFC3339}}
  date-time); at least one MUST be present, and an absent member is
  unbounded on that side. Subset: no broader when the candidate window
  lies within the reference window, an absent candidate bound counting
  as unbounded and therefore broader than any present reference bound.
  Intersection: the overlap (the later `not_before`, the earlier
  `not_after`); an empty overlap has no intersection and the
  combination fails.
- `data_classification` (array of strings): the action applies only to
  data whose classification label is among the named values. Label
  semantics are deployment- or registry-defined; the comparison is not.
  Subset: no broader when the candidate array's members are a subset of
  the reference array's, compared as exact strings. Intersection: the
  common members; an empty result has no intersection and the
  combination fails.
- `allowed_tools` (array of strings): the action may be exercised only
  through a capability whose identifier is among the named values (a
  tool or function identity, asserted at the point of use by the
  enforcing component). Subset: no broader when the candidate array's
  members are a subset of the reference array's, compared as exact
  strings. Intersection: the common members; an empty result has no
  intersection and the combination fails.
- `requires_action_approval` (boolean): when `true`, each exercise of
  the action requires a fresh, action-bound approval at the point of
  use; the enforcing component MUST NOT permit the action on Mission
  authority alone. A value of `false` is equivalent to omitting the
  member. Subset: no broader when the candidate is `true` or equals
  the reference (narrowing may add the requirement, never remove it).
  Intersection: the logical OR of the two values.

These comparisons are in value space, not lexical: `max_amount`
`amount` members are compared as the decimal numbers the strings
contain, so `"500"`, `"500.0"`, and `"500.00"` are equal;
`resource_issued_after` and `resource_issued_before` values are
compared as the
instants they denote after normalization to UTC, so two RFC 3339
representations of the same instant that differ only in timezone offset
or trailing subsecond zeros are equal; `recipient_domain` values are
compared as DNS names, case-insensitively and on whole labels, so
`mail.example.com` is within `example.com` and `example.net` is
not. A Common Constraint definition
MUST fix its subset and intersection in value-space terms, so that
independent deployments compute the same result for the same values and
the subset rule of {{subset}} is reproducible.

A decimal-string value in a Common Constraint (`max_amount`'s
`amount` member, and any future Common Constraint with a
decimal-valued member) MUST match `^[0-9]+(\.[0-9]{1,18})?$`: one or
more decimal digits, optionally followed by a single `.` and one to
18 further decimal digits. A leading `-` is out of scope for a
ceiling value and MUST be rejected.
A value of any other form, including scientific notation
(`"1e300"`), a sign, a thousands separator, or a non-numeric token
(`"NaN"`, `"Infinity"`), is malformed, and a consumer MUST reject it
rather than attempt to parse it: an authority proposal carrying
one is refused at submission ({{I-D.draft-mcguinness-oauth-mission}}), and a
Resource Server treats a malformed
decimal value the same as a `constraints` key it cannot enforce
({{I-D.draft-mcguinness-oauth-mission}}). Comparison and intersection over two such
decimal-string values MUST be computed as exact decimal arithmetic
(for example, by scaling both values to integers by their fractional
digit count and comparing the integers) and MUST NOT parse either
value into an IEEE 754 binary floating-point type: that
representation does not hold every value the grammar above admits
exactly and can compare or combine two values incorrectly.

A numeric constraint value MUST lie within the range JCS {{RFC8785}}
serializes exactly. Monetary amounts avoid that hazard by
construction: `max_amount` carries its `amount` as a string containing
a decimal number, paired with an ISO 4217 {{ISO4217}} `currency` code, and a
future Common Constraint for a monetary value SHOULD reuse this shape
rather than a JSON number.

## Delegate Eligibility {#delegate-eligibility}

{{I-D.draft-mcguinness-oauth-mission}} gates a delegated token's carried
entries on the entry type's own delegation policy, evaluated at the
delegate's delegation depth `d` (the nesting depth of the token's `act`
claim, as that document defines). For a `mission_resource_access`
entry, the Authorization Server includes it in a delegated token
issued at delegation depth `d` only if all of the following hold:

1. the entry carries a `delegation` member (otherwise it is
   non-delegable, which is the default);
2. `d` is less than or equal to the entry's `delegation.max_depth`;
   and
3. the delegate is permitted by `delegation.allowed_delegates` or,
   when that member is absent, by the AS's delegation-authorization
   policy, which the AS MUST apply at every exchange: an absent
   matcher list is a decision deferred to policy, never a blanket
   grant of eligibility.

An entry failing any of these narrows out of the delegated token,
consistent with the subset rule ({{subset}}). The `delegation`
member is policy, not authority, and is not part of the subset
comparison; surviving entries are carried with their `delegation`
member intact so the next hop is evaluated the same way.

**Matching `allowed_delegates`.** Each entry is a matcher object
modeled on the RFC 8693 `may_act` actor object ({{RFC8693}} Section
4.4): where `may_act` names a single party eligible to act on a token,
`allowed_delegates` is a per-Authority-Set-entry *list* of such
matchers, generalized to actor-type classes. A `{ "sub": ... }`
matcher permits a specific delegate by client identifier; a
`{ "sub_profile": ... }` matcher permits any actor of that type (for
example, `ai_agent`). An actor's `sub_profile` MAY carry multiple
space-separated values; a `{ "sub_profile": ... }` matcher is
satisfied when its value is among the actor's values. A deployment
can thus permit a specific client,
a class of actors, or both, and a delegate is permitted if it matches
any entry.

The AS MUST authenticate the delegate at the Token Exchange
and assert the actor's `sub` and `sub_profile` itself. A self-asserted
`sub_profile` MUST NOT satisfy a matcher; otherwise a client could
claim any actor type to bypass the constraint.

A `{ "sub": ... }` matcher is a client identifier in the issuing AS's
namespace and is not portable across a trust domain; how a Resource AS
evaluates conveyed matchers, failing closed and narrowing out any
`sub` matcher it cannot resolve, is specified by the companion
({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

## Scope Projection {#scope-projection}

{{I-D.draft-mcguinness-oauth-mission}} states the semantic subset
condition and issuance algorithm an Authorization Server applies
before emitting `scope` for any `authorization_details` entry: the
projected scope's effective rights, together with every independently
mandatory control on the target's enforcement path, MUST be a subset
of the rights the applicable entries grant. This section states when
that condition holds for a `mission_resource_access` entry.

A scope-projection mapping's entry for this type names, for a target
Resource Server: the `scope` value or values it emits, the `resource`
and `resource_match` the mapping covers, the `actions` value or values
each `scope` value stands for, and, for every `constraints` key an
entry may carry, whether the target independently and identically
enforces that key on the `scope`-authorized path.

Projecting a `mission_resource_access` entry's authority to `scope`
is safe only when all of the following hold:

1. **The resource match is exact under the mapping.** The mapping's
   `scope` value is defined over the entry's `resource` and
   `resource_match`. A `prefix` entry projects safely only when the
   mapping itself scopes the value to that same prefix; a `scope`
   value the target's own interpretation extends to a broader
   ancestor resource is not a safe projection of a narrower `prefix`
   entry.
2. **The actions match without aggregation.** The mapping's `scope`
   value stands for exactly the entry's `actions`, action for action.
   A `scope` value that stands for an action family, an aggregate of
   unrelated actions, or the union of more than one entry's actions
   fails this condition, because the target grants every action the
   union names, not only the entry's.
3. **Every carried `constraints` key is independently enforced.** For
   every key in the entry's `constraints`, the mapping states that
   the target enforces that key, under a comparison at least as tight
   as the entry's value, on the `scope`-authorized path. An entry
   with no `constraints` trivially satisfies this condition. A key
   the mapping does not name as independently enforced fails the
   condition for that entry, exactly as an unenforced key fails
   closed at a Resource Server that consumes `authorization_details`
   directly.

An entry failing any condition MUST NOT be projected to `scope`. Per
{{I-D.draft-mcguinness-oauth-mission}}'s issuance algorithm, the
Authorization Server then omits `scope` for that entry where the
target's enforcement path consumes `authorization_details`, and
refuses issuance to that target when it is `scope`-only and no other
carried entry supplies a safe projection.

## Transformation Capabilities {#transformation-capabilities}

{{I-D.draft-mcguinness-oauth-mission}} requires an Authorization
Server to declare, for every AS-supported `authorization_details`
type, whether it understands the type's narrowing, delegation, and
scope-projection semantics, through deployment documentation or,
where available, the machine-readable `mission_transformation_capabilities`
carrier that document defines.

For `mission_resource_access`, an Authorization Server that implements
this document in full declares:

`narrowing`: `true`
: The subset and intersection algebra of {{subset}} and
  {{common-constraints}} is fully defined, over every member this
  document specifies.

`delegation`: `true`
: The delegation policy of {{delegate-eligibility}} is fully
  defined; an entry's `delegation` member states its own depth and
  eligibility bounds.

`projection`: `true`
: A safe scope projection is defined, and decidable per entry, by
  {{scope-projection}}; it is not unconditionally available for
  every entry, and an Authorization Server MUST still apply that
  section's conditions per entry before emitting `scope`.

An Authorization Server that implements only part of this document
(for example, `mission_resource_access` entries without ever emitting
`scope` for them) declares `projection` as undeclared rather than
`true`, and {{I-D.draft-mcguinness-oauth-mission}}'s carried-as-approved
fallback then applies to `scope` projection for this type at that
deployment, exactly as it would for an unsupported type.

## Modeling Tools and Function Calls {#tools}

This section is non-normative guidance. A "tool" an agent invokes,
such as a Model Context Protocol (MCP) tool or a function call, is
modeled as a `mission_resource_access` entry. No separate entry type
is needed, and the rules above (subset, delegation) apply unchanged;
derivation, `authority_hash`, and the Authority Set itself remain
{{I-D.draft-mcguinness-oauth-mission}}'s.

The mapping is:

- `resource` is the tool provider. For an MCP tool it is the MCP
  server's URL. The MCP authorization model ({{MCP}}) makes the
  server an OAuth
  2.0 resource server, so this is the resource identifier a token is
  audience-bound to.
- `actions` are the tool names the task needs at that provider.
  Authorizing a tool is authorizing its name as an action, which
  lines up with MCP filtering its tool list by the caller's granted
  authority and routing each tool call for authorization.
- `constraints` carry machine-actionable bounds on a tool's
  arguments, for example an amount ceiling or a recipient domain (the
  `max_amount` and `recipient_domain` Common Constraints,
  {{common-constraints}}).
  Like all `constraints`, they are committed by `authority_hash` and
  carried to the point of use, but they are evaluated against the
  concrete call arguments by a runtime enforcement layer, not at
  issuance ({{I-D.draft-mcguinness-oauth-mission}}).

For example, a Mission authorized to read invoices and post small
adjustments through a finance MCP server, and to send messages
through a messaging MCP server, derives:

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

Delegation to a sub-agent works unchanged: add a `delegation` member
to a tool entry ({{delegate-eligibility}}). For example, an entry a
sub-agent of type `ai_agent` may invoke at depth 1, narrowed to the
read tool only:

~~~ json
{ "type": "mission_resource_access",
  "resource": "https://finance.example.com/mcp",
  "actions": ["query_invoices"],
  "delegation": {
    "max_depth": 1,
    "allowed_delegates": [{ "sub_profile": "ai_agent" }]
  } }
~~~

What this profile does not provide for tools is a typed, attenuable
per-argument constraint grammar: narrowing one tool's argument schema
against another (for example, `amount` in a `range`, `recipient` in a
`one_of` set) as the grant is derived or delegated. Argument bounds
here are the same flat, carried `constraints` used for any resource,
evaluated at runtime. Structured per-argument attenuation
({{I-D.draft-niyikiza-oauth-attenuating-agent-tokens}}, with object
capability systems such as UCAN as prior art) is a richer primitive
deferred to future work; it would extend the delegation and subset
model of this document ({{delegate-eligibility}}, {{subset}})
rather than introduce a new entry type.

# Conformance {#conformance}

An implementation conforms to this document by supporting
`mission_resource_access` as one of the `authorization_details` types
{{I-D.draft-mcguinness-oauth-mission}} names in its approved set. A
conforming Authorization Server or Resource Server implements:

- the type definition ({{resource-access-type}});
- the subset and intersection algebra ({{subset}}, {{common-constraints}});
- the delegate eligibility test ({{delegate-eligibility}}), where it
  claims the issuance profile's Delegation capability; and
- the Transformation Capabilities declaration
  ({{transformation-capabilities}}).

An Authorization Server MAY additionally claim the Scope Projection
capability: establishing, per entry and per target, the safety
conditions of {{scope-projection}} before emitting `scope`. An
implementation that does not claim it MUST NOT emit `scope` for a
`mission_resource_access` entry under
{{I-D.draft-mcguinness-oauth-mission}}'s issuance algorithm, and
instead omits `scope` or refuses issuance to a scope-only target,
exactly as that document requires for any type without a declared
projection.

# Security Considerations {#security-considerations}

This document defines a subset relation, a delegation policy, and a
scope-projection safety condition; it inherits
{{I-D.draft-mcguinness-oauth-mission}}'s Security Considerations for
everything upstream of a `mission_resource_access` entry (the approval
event, the integrity anchors, issuance gating). Three risks are
specific to this type:

- **Comparison, not meaning.** {{subset}} compares members, not
  effects: a candidate that compares as no broader can still permit
  an effect the parent's purpose never contemplated. This is a
  documented limit, not an omission
  ({{I-D.draft-mcguinness-oauth-mission}}).
- **Unenforceable constraints widen silently if not refused.** A
  Resource Server or scope projection that treats an unrecognized
  `constraints` key as absent, or as disclosure-only, grants more
  than the entry authorizes; {{I-D.draft-mcguinness-oauth-mission}}
  and {{scope-projection}} both require fail-closed handling instead.
- **A safe projection is per entry, not per type.** That
  `mission_resource_access` defines a projection relation
  ({{scope-projection}}) does not make every entry of the type
  safely projectable; an Authorization Server MUST evaluate the
  three conditions of {{scope-projection}} for the specific entry
  and mapping in force, not assume the type's general capability
  extends to it.

# Privacy Considerations {#privacy-considerations}

This document defines no data element beyond what
{{I-D.draft-mcguinness-oauth-mission}} already carries in
`authorization_details`; that document's Privacy Considerations apply
unchanged. The `resource`, `actions`, and `constraints` values chosen
for an entry are exactly as privacy-sensitive as the Authority Set
that carries them.

# IANA Considerations {#iana}

## The Mission Resource Access Authorization Details Type {#type-registration}

`mission_resource_access` is an `authorization_details` type per
{{RFC9396}} Section 2, defined by this document in
{{resource-access-type}}. RFC 9396 does not establish an IANA
registry of authorization details types (type identifiers are
interpreted by the Authorization Server), so this document creates no
registry entry for it and requires no IANA action here. If a registry
of authorization details types is established in the future, this type
SHOULD be registered in it.

## Common Constraints Registry {#iana-common-constraints}

This document establishes the "Mission Common Constraints" registry.
The registration policy is Specification Required {{RFC8126}}. A
Designated Expert reviews a submission for the discipline
{{common-constraints}} requires: a name matching
`^[A-Za-z0-9_.:-]+$` not already registered, a JSON {{RFC8259}} value
syntax precise enough for independent implementations to agree on,
and a subset rule and an intersection rule both stated in
value-space terms, with the intersection of any two valid values
never broader than either operand. Registration does not require IETF
review or a Standards Track document; a Specification Required
reference that a Designated Expert can review against these criteria
suffices.

Each registration records:

- **Key Name**: the `constraints` member name.
- **Value Space**: the JSON value type and any additional syntax
  rules.
- **Subset Rule**: how a candidate value is judged no broader than a
  reference value.
- **Intersection Rule**: how two values for the key combine into a
  result no broader than either operand.
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the key.

This document populates the registry with the Common Constraints it
defines ({{common-constraints}}); the "Ref" column below is this
document, at the section shown, for every row, and the full Subset
Rule and Intersection Rule text is there, not restated in the table:

| Key Name | Value Space | Subset / Intersection | Controller | Ref |
|---|---|---|---|---|
| `max_amount` | Object: `amount` (decimal string), `currency` (ISO 4217) | Same currency, candidate <= reference; intersection is the smaller amount | IETF | {{common-constraints}} |
| `resource_issued_after` | String, RFC 3339 date-time | Candidate >= reference; intersection is the later instant | IETF | {{common-constraints}} |
| `resource_issued_before` | String, RFC 3339 date-time | Candidate <= reference; intersection is the earlier instant | IETF | {{common-constraints}} |
| `tenant` | String | Equal; intersection is the shared value | IETF | {{common-constraints}} |
| `recipient_domain` | String, DNS name | Equal or a subdomain; intersection is the narrower value | IETF | {{common-constraints}} |
| `time_window` | Object: `not_before`, `not_after` (RFC 3339 date-time) | Candidate window within reference window; intersection is the overlap | IETF | {{common-constraints}} |
| `data_classification` | Array of strings | Candidate array a subset of reference array; intersection is the common members | IETF | {{common-constraints}} |
| `allowed_tools` | Array of strings | Candidate array a subset of reference array; intersection is the common members | IETF | {{common-constraints}} |
| `requires_action_approval` | Boolean | Candidate `true` or equal to reference; intersection is the logical OR | IETF | {{common-constraints}} |

Names are kept collision-free by the convention
{{common-constraints}} already uses: a specification-defined name is
coordinated through this registry, and any other name is either
collision-resistant or remains deployment-defined and outside the
registry.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-00

- Initial version: `mission_resource_access`, its resource and action
  matching, generic constraints, the Common Constraints registry, the
  delegation policy and delegate-matching rules, and the subset and
  intersection algebra, relocated without change from
  {{I-D.draft-mcguinness-oauth-mission}}, where they were previously
  defined inline (#637). Adds this type's concrete Scope Projection
  safety conditions and issuance-algorithm interlock (#698), and its
  Transformation Capabilities declaration for the issuance profile's
  machine-readable per-type capability map (#645).

# Acknowledgments
{:numbered="false"}

This document was split from Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}}, where `mission_resource_access`
was originally defined.
