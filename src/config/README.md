# Deployment configuration

Each file here is static deployment configuration, read once at boot by the
typed, validating loaders in `packages/demo-data/src/index.ts`. A file that
fails validation stops the boot with a `ConfigError` naming the file.

## `aauth-ps.json`

The AAuth Person Server's deployment configuration (#836 slice 2, the
three-party route): its issuer, its signing key's `kid` and `alg`, token
and mission lifetimes, the persons it represents, and the deterministic
approver's inputs. `agents` is both the agent allowlist and the
agent-person binding (AAuth -11 Section 13.14): an agent it does not name
is refused at every endpoint, and `mission_governed` places an agent under
mission governance, so its missionless requests are refused.
`description_rules` are case-insensitive substrings evaluated in order
against a proposal's description, the first match deciding, else
`default_decision`. Read by its own strict loader (`loadPsConfig` in
`@mission/aauth-ps`), not by `@mission/demo-data`; it refuses with a
`PsConfigError`.

`management` (#836 slice 3) is the mission control plane's policy (AAuth
Mission Management): whether the owning agent is admitted for `status`
and `revoked` termination, the seconds `fresh_until` follows
`observed_at`, whether an untracked access mode may serve a mission (then
`complete` is never true), the revocation retry policy (attempts,
exponential spacing and its cap, one attempt's time limit, and how long a
terminate waits for immediate results), and the administrators. Each
administrator is an identifier, a deployment-chosen metadata document
name and an enrolled public key: it signs control-plane requests under
Signature-Key `jwks_uri` with that `id`, `dwk` and the key's `kid`, and
the PS takes the key from this file, never by fetching. Its privilege is
the listed persons' missions and the listed actions. The shipped
administrator's private key is held by no one in this repository; a
deployment enrolls its own.

- **Owner.** The PS operator.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, an issuer or agent that is not an AAuth identifier, an
  agent named twice or bound to an unconfigured person, and a person or
  auth token lifetime over AAuth's one-hour ceiling; under `management`,
  an administrator whose `dwk` is an AAuth document name, whose key
  carries a private member, lacks a `kid` or a usable fully-specified
  `alg`, whose `id` is the PS's own issuer or repeats, or that names an
  unconfigured person or an action the PS does not implement, and a retry
  base over its cap. The signing key is generated at each boot and never
  configured.
- **Updating.** Edit, review, and restart the PS. A change applies to the
  next request; approved missions keep the blob they were approved with.

## `aauth-resource.json`

The AAuth Resource of the three-party route (#836 slice 2,
`services/aauth-resource`, read by that package's own
`loadResourceConfig`): its server identifier, the `kid` and `alg` of its
resource-token signing key (the key is generated at boot), the
resource-token lifetime (at most 300 seconds, aauth -11 Section 6.7.1),
the signature window, the scope values it defines, and each protected
operation with the one scope an auth token must grant for it. The scope
check is the Resource's own policy on the PS-issued auth token (Section
13.7); the Resource never evaluates a mission.

- **Owner.** The Resource's operator.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, an issuer that is not a server identifier, a lifetime
  over 300 seconds, an unsupported algorithm, an operation at a reserved
  path, an operation scope the file does not define, and a duplicate
  operation.
- **Updating.** Edit, review, and restart the Resource. Resource tokens
  already issued keep their scope.

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

Each classification also states `cross_domain`: whether authority at that
resource is served by another trust domain's authorization server. The
ledger resource (`http://localhost:4406/mcp`) is cross-domain, since its path
goes through the RAS (`https://ras.ledgercloud.test`) with its own client
registration and policy, grant redemption and RAS-issued token. With
`progressive.json`'s external-communication actions, this classification is
the published mapping for Mission Template's prohibited classes (`@spec
mission-template#prohibited-classes`, #1710, D877). `policy.json`'s
`dispatch_prohibited_actions` covers every action the mapping makes
irreversible, external-commitment, privileged-administration,
external-communication or cross-domain, and a unit check
(`dispatch-prohibited-coverage.test.ts`) fails on a gap. An absent
`cross_domain` reads as `false`.

- **Owner.** The deployment's security owner owns the floors; each Resource
  Server's operator owns its actions' classes, which follow that server's
  operation definitions.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, duplicate member names, an unknown action class, an empty
  floor, a non-boolean `cross_domain` and a second classification for one
  type and resource. An admitted
  action the classification does not name refuses at the approval decision.
  Where the AS selects Progressive ceiling drawdown, an authority ceiling the
  Approver consents is classified with the derived set, and the AS does not
  start when its drawdown mapping (`progressive.actionClasses`) maps an
  action this classification places under a floor to a class a drawdown
  grants by policy (#1255).
- **Updating.** Edit, review, and restart the AS. A change applies to the
  next approval decision; Missions already approved are unaffected.

## `authority-dependencies.json`

The deployment's declared authority dependencies (`@spec
runtime#input-authority-dependency`, #830, D798). The one shipped
declaration, `subject-delegation`, makes reliance on a user-delegated
Mission depend on the Subject's continuing delegation to the client acting
under it: the Subject's account active in the identity source and the
delegation not withdrawn. Each declaration states every element the Runtime
requires: the dependency, its source and the state an observation
represents; what it governs (`governs.authority_sources`, the Missions'
recorded authority sources, and the scope in words); the invalidating
changes; `max_staleness_seconds`, separate from the Mission-state freshness
declaration; whether an online check is required; the enforcement route
(`enforcement.direct`, `pdp` or `pep`, and `enforcement.lifecycle`); and the
recovery and responsibility transfer. A composition that enforces it states
it in its Enforcement Scope Statement (`withAuthorityDependencies`, under
`extensions.authority_dependencies`), and gives the authorization server's
issuance gates, the PDP or the PEP's composed step the same declaration and
identity-state resolver. Read by `@mission/demo-data`
(`AUTHORITY_DEPENDENCIES`) through `@mission/core`'s strict reader.

Under lifecycle-mediated enforcement (`enforcement.lifecycle`), the
declaration also states `reconciliation_max_lag_seconds` and
`lifecycle_operations`, the operation the authorization server's reconciler
commits for each invalidating change: as shipped, `suspend` for a disabled
Subject or a withdrawn delegation and `revoke` for a deprovisioned Subject.
The PDP refuses the governed Missions' actions once the reconciler's last
complete pass rests on an observation older than the lag bound, and refuses
a Mission whose Subject that pass found no record of (`unresolved`, never a
revocation). Without a direct route, the declared observation limits still
hold: the pass's observation older than `max_staleness_seconds` refuses
`stale`, a declared online check refuses on a failed latest read, and a
permit expires at the earlier of the staleness and lag deadlines. Each
complete pass also records the Missions whose Subject shows an applicable
invalidation, mapped or not, and the PDP refuses them whatever their state
reads until a later complete pass observes the invalidation gone (an
unreachable source or an old observation never counts as that). A
lifecycle-only declaration must map every invalidating change; with a direct
route as well, a partial mapping is valid because direct evaluation refuses
an unmapped change.
`external_change_bound` is the deployment's claimed bound from an external
change (`@spec runtime#state-freshness`): its `seconds`, start, end, work
already started, the path, and the two periods the path names,
`detection_period_seconds` and `reconciliation_period_seconds`. The reader
requires the bound to cover one of each in sequence and the reconciliation
period to be shorter than the lag bound; the authorization server refuses
to start with a scheduled read or pass slower than declared. The matrix by
principal role is in `docs/authority-dependencies.md`.

The identity source is `identity.json`: each principal's optional `status`
(`active`, `disabled` or `deprovisioned`; absent, `active`),
`withdrawn_delegations` (the clients it no longer delegates to) and
`changed_at` (when the source recorded the change). The resolver re-reads
the file without a restart.

- **Owner.** The deployment's security owner for the declaration; the
  identity owner for `identity.json`'s status and delegations.
- **Integrity.** Repository review and the strict readers, which refuse a
  declaration missing any element, an unknown member, a non-positive
  staleness, an unknown invalidating change or authority source, a
  declaration with no enforcement route, a lifecycle route without its lag
  bound or operations, and a bound whose periods it does not cover; and, in
  the identity source, an
  unknown status, a malformed list or instant, and a principal listed twice.
- **Updating.** The declaration: edit, review, and restart. The identity
  source: edit it in place; the next resolver read observes the change, and
  an observation stays acceptable for `max_staleness_seconds` from when its
  read was issued. Overlapping reads publish in the order they were issued,
  so an older read never replaces a newer one. A PEP holding the dependency
  rechecks it at release, and a permit its composed step admitted releases
  no effect after the observation's validity ends.

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

## `governed-resources.json`

The resources this AS treats as Mission-governed (`@spec
mission#authority-proposal`, #1531, D741). `classification` is the
deployment's own classification of a resource, `governed` or
`not_governed`. `authenticated_metadata` holds the RFC 9728
`mission_bound_authorization_required` member of each resource's protected
resource metadata that the AS has authenticated; the reference fetches no
metadata, so these records are configured. A resource is governed when
either source says so, and neither source clears the other: metadata that
omits the member or sets it to `false` leaves a `governed` classification in
force, and a `not_governed` classification leaves metadata declaring the
requirement in force. The AS refuses a token request with no Mission binding
whose token would carry a governed audience, on every grant type and on the
dev ordinary-token route. The shipped file classifies the payments resource
governed, as its own metadata declares, in every composition, and classifies
the MAS Join route's own resource (`mas-join.json` `join_resource`)
`not_governed`: the dev ordinary-token route mints the join's ordinary
credential for that resource only.

- **Owner.** The deployment's security owner, with each resource server's
  operator for the requirement its metadata declares.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, a resource that is not an absolute URI, a classification
  other than `governed` or `not_governed`, and a metadata member that is not
  a boolean.
- **Updating.** Edit, review, and restart the AS. A change applies to the
  next token request.

## `mas-join.json`

The shared demo stack's MAS join (`@spec authority-server#mission-join`,
`authority-server#mapping-contract`, #557, #818): the resources whose route
admits an ordinary credential and joins it to a Mission
(`governed_resources`); the resource identifier the join route is served
under (`join_resource`, #1531, D741), distinct from every governed resource
and not Mission-governed, since a join acts under an ordinary credential:
the route's RFC 9728 metadata, served at its listener's well-known path,
names it and does not declare Mission-bound-only acceptance, the payments
enforcement boundary accepts it as an audience alias scoped to the
composition's authorization server and the `at+jwt` token profile, and the
dev ordinary-token route mints for it; the delegate policy (`delegates`, each client with
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
  implement, a client instance, a non-positive version, and a
  `join_resource` that is not an absolute URI or names a governed resource. A composition
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
