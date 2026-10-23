# Deployment configuration

Each file here is static deployment configuration, read once at boot by the
typed, validating loaders in `packages/demo-data/src/index.ts`. A file that
fails validation stops the boot with a `ConfigError` naming the file.

## `approval-floor.json`

The published approval-authentication floor (`@spec
mission#approval-authentication`, #826, D425): its deployment scope, the
floors, and the AS-owned classification of every action the AS can admit,
keyed by authority type, resource and action. The shipped floor,
`high-risk-authority`, applies to `irreversible_action`,
`external_commitment` and `privileged_administration`. It accepts only a
browser Approver whose achieved `acr` is `mfa`, authenticated at most 300
seconds before the decision. Payment execution and remittance are its
high-risk actions, matching the payments Operation Profile. The approval
interaction and an Expansion deferral approval both apply it. On the
as-native target (`pnpm as-native`) the Approver logs in at each approval
through an upstream OpenID Provider that checks a password and a one-time
code (sent to an in-process stand-in for the Approver's device), and the floor evaluates the `acr` and `auth_time` of the ID Token the
AS validates (#1320). The shared demo's approval console presents a login
recorded once (simulated; that composition has no Approver identity
provider) and never at an approval, so it ages out of the floor until the
demo server's `POST /bff/approver/login` records a new one.

- **Owner.** The deployment's security owner owns the floors; each Resource
  Server's operator owns its actions' classes, which follow that server's
  operation definitions.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, duplicate member names, an unknown action class, an empty
  floor and a second classification for one type and resource. An admitted
  action the classification does not name refuses at the approval decision.
  Where the AS selects Progressive ceiling drawdown, an authority ceiling the
  Approver consents is classified with the derived set, and the AS does not
  start when its drawdown mapping (`progressive.actionClasses`) maps an
  action this classification places under a floor to a class a drawdown
  grants by policy (#1255).
- **Updating.** Edit, review, and restart the AS. A change applies to the
  next approval decision; Missions already approved are unaffected.

## `delegation.json`

The clients a same-Mission delegation may designate (`@spec
mission#designation`, #869, D449). A designation names its client in `aud`,
so the binding forbids designating a client whose identifier any resource
server accepts as an audience for this AS's tokens, aliases included, and
refuses a client for which the AS cannot establish that separation. Listing
a client in `designable_clients` is this deployment's statement that no
resource server accepts its identifier as an audience; the AS also refuses a
listed client whose identifier is a configured resource audience, a
registered resource server's accepted audience or alias, or one of the
Mission's own resources. The shipped list names the invoice-extraction
sub-agent. Delegation itself is opt-in and off in both baselines.

- **Owner.** The deployment's security owner, with each resource server's
  operator for the audiences it accepts.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, an empty identifier and a duplicate.
- **Updating.** Edit, review, and restart the AS. A change applies to the
  next designation.

## `mas-join.json`

The shared demo stack's MAS join (`@spec authority-server#mission-join`,
`authority-server#mapping-contract`, #557, #818): the resources whose route
admits an ordinary credential and joins it to a Mission
(`governed_resources`); the delegate policy (`delegates`, each client with
its depth ceiling); the scope mapping, which is the credential-authority
adapter (`scope_actions`, each `scope` value to the actions it carries at the
payments resource; a value it does not cover maps to nothing); and the
mapping contract the join applies (`mapping_contract`). The contract states,
in a closed vocabulary that names the one behavior this join implements:
the subject mapping (`identity`: the credential's issuer-qualified subject
compared with the Mission's by byte equality, the issuing authorization
server being the Mission Issuer); the client mapping (`identity`, or a
delegate in `delegates`); how an entry's `delegation` is evaluated
(`client_id_matchers`: an exact `sub` matcher in `allowed_delegates` names a
joining client, a profile matcher admits none, and `max_depth` is evaluated
against the deployment's actor records); client-instance identity (neither
supported nor required); the version identifier (`contract_id`, `version`);
the audit record (`decision_evidence`: the PDP's signed Decision Evidence of
each join decision, with the acting subject and client and either the
`join_view_id` commitment or the `mission_binding_failed` denial; a join
request refused before any decision is recorded in the PEP's signed Refusal
Record instead); and the
failure semantics (`mission_binding_failed`). Read by `@mission/demo-data`
(`parseMasJoinPolicy`).

- **Owner.** The deployment's identity owner for the mappings and delegate
  policy; the payments resource's operator for the governed resources and
  the scope mapping.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown and missing members, any mapping value this join does not
  implement, a client instance, and a non-positive version. A composition
  that would mount the join route refuses to start when no contract is
  declared, before it connects to anything.
- **Updating.** Edit, bump `mapping_contract.version` with any change to the
  mapping, review, and restart the stack.

## `mas-pilot.json`

The MAS pilot's deployment configuration (`@spec
authority-server#mapping-contract`, #818, D284, D508): the estate
authorization server's issuer, port, directory accounts, client
registrations (each with the access token format the estate issues it,
`jwt` or `opaque`) and resource vocabulary; the gateway's RFC 7662
introspection of opaque tokens (`introspection`: its registered
introspection client, call timeout and positive-cache bound); the separated
MAS (`separated_mas`, #818 slice 4b: its host and port, the PDP's client
identifier at its Mission Status endpoint (`pdp_client_id`, #1407), the
clients it enrolls by enforcement scope, each with its roles (`enrollment[]`:
`client_id`, `roles` of `pep`, `pdp` or both, `enforcement_scopes`; Join
Disclosure and a Join Assertion's `audience` take `pdp`, join-assertion
visibility either; #1591), and the state source's placement, which must be `pdp`,
read timeout and response-size cap); the mapping
cache's staleness bound;
the action classes the gateway reserves for Mission-bound credentials; the
grants a development bootstrap of the pilot's Resource-policy store writes
(`resource_policy`, #828: tenants with their vendors and members, and
entitlements, every principal under the estate issuer); the initial mapping
contract version; the route table; and the consequential-path inventory. Read by its own strict loader
(`demo/src/mas-pilot/config.ts`), not at boot by `@mission/demo-data`: only
the pilot composition reads it. [`docs/mas-pilot-deployment.md`](../docs/mas-pilot-deployment.md)
is the pilot's contract.

- **Owner.** The estate's identity owner for the accounts, clients and
  mapping rows; the payments resource's operator for the inventory and the
  reserved classes; the estate's OpenFGA administrator for the Resource-policy
  grants, which seed only a development store (an attached store is
  administered with `pnpm resource-policy --iss <estate issuer>`).
- **Integrity.** Repository review and the strict loaders: the configuration
  loader refuses unknown or missing members, a duplicate client, an estate
  issuer equal to the Mission Issuer, resource servers that omit the payments
  resource, a token format other than `jwt` or `opaque`, an introspection
  client that is also one of the estate's own clients, and a separated MAS
  whose state source is placed anywhere but the PDP; the contract loader refuses an ambiguous mapping (a second row
  for one issuer-qualified estate subject or client), a claimed
  client-instance mapping and any failure semantics but
  `mission_binding_failed`; the Resource-policy grants are refused unless each
  entry names exactly one of a subject or a client with a relation that kind
  may hold (a subject `authorized_reader` or `authorized_payer`, a client
  `authorized_client`). Client secrets and signing keys are generated at each
  boot and never configured.
- **Updating.** A new contract version is installed into the running cache
  (`MappingContractCache.install`), which refuses a version at or below the
  installed one. The file's version is the one installed at composition. The
  introspection bounds apply at composition; lowering
  `introspection.cache_max_seconds` shortens how long a token revoked at the
  estate can still be accepted.

## `progressive.json`

The Progressive section of the Mission Deployment Profile (`@spec
progressive#drawdown-bounds`, `progressive#fresh-approval`,
`progressive#ceiling-review`, #1017): the chain rate bound, the mapping from
action identifiers to the runtime profile's action classes, the
external-communication actions, the policy for a request beyond the
ceiling, and each drawdown policy's per-drawdown bound, ceiling review
cadence and optional `retire_undrawn_actions`. The AS's typed `progressive`
option and its drawdown policy snapshots are built from it
(`progressiveFromProfile`), so what is published is what is enforced.
`payments:remittance.send` is deliberately unmapped: its drawdown falls back
as unclassified.

- **Selection.** Like every file here, validated when `@mission/demo-data`
  loads, so a malformed file stops startup; only a deployment that selects
  Progressive ceiling drawdown uses it. The demo stack does not, so this
  declaration claims nothing for it.
- **Owner.** The deployment's security owner, who also owns the approval
  floor the mapping must agree with.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, an unknown action class, a non-positive bound or cadence,
  a duplicate policy identity and a malformed retirement list. The AS does
  not start when the mapping disagrees with the approval floor (#1255).
- **Updating.** Edit, review, and restart the AS. A changed drawdown policy
  needs a new `version`: a Mission commits the consented snapshot's digest,
  so a snapshot edited under the same version authorizes nothing.

## `scope-projection.json`

The trusted scope-projection mapping (`@spec mission#scope-projection`, step
2: authenticated out-of-band configuration). For each target audience it
records a `version`, the target's enforcement `mode` (`authorization_details`
or `scope_only`), the REQUIRED `mission_aware` classification used by the
delegated-routing rule (`@spec mission#rs-enforcement`), for an
`authorization_details` target the `mission_constraints_supported` keys it
enforces (`@spec resource-access#resource-access-type`, #1266), and, for a
`scope_only` target, the rights and independently enforced controls each
`scope` value stands for.

`mission_constraints_supported` mirrors the target's protected resource
metadata member of the same name. A Mission-bound token issued for an
`authorization_details` target carries an entry the target serves (one
naming the target, one for a finer resource within it, or a `prefix` entry
whose base contains it) only when every `constraints` key of the entry is
listed; otherwise the issuance is refused `invalid_target`, never narrowed by
dropping the key. A token with several such audiences meets each one's list.
An absent list names no key, so any constrained entry that target serves is
refused.

- **Owner.** The deployment operator responsible for each target Resource
  Server owns that audience's entry, because it describes how that server
  enforces.
- **Integrity.** The file is protected by repository review and by the strict
  loader, which refuses unknown members, duplicate member names, a missing or
  non-boolean `mission_aware`, and any control it has no comparison for. The
  AS never fetches it at runtime.
- **Updating.** Edit the entry, bump its `version`, land the change through
  review, and restart (or reload) the AS. Every issuance, refresh included,
  is evaluated against the mapping current at that issuance, so a bumped
  version does not by itself invalidate existing grants. An audience missing
  from the mapping fails closed.

The AS refuses a token whose audiences span both modes. That is an
implementation restriction (one `scope` claim is shared by every audience),
not a protocol rule.
