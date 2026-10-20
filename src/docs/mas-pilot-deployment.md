# MAS pilot deployment

The pilot contract for #253's second reference path: the **legacy-estate/MAS
route** that D284 adopted and D508 ruled executable, owned by #818 (Sketch
steps 3 and 4). A legacy estate keeps its own authorization server; its
ordinary tokens are joined to Missions at a gateway, under a versioned mapping
contract. This document records slices 1 to 3 of that evidence (slice 2:
the Resource policy, §4; slice 3: opaque tokens by introspection, §5), and
slice 4: the Mission Status surface and resolver a separated MAS needs
(§10), and the separated configuration that reads Missions through them
(§11). It is
not a
conformance, production-readiness or interoperability claim, and nothing in
the AS-native target's evidence ([initial-runtime-deployment.md](initial-runtime-deployment.md))
bears on it, or the reverse (D284).

Every statement here is true of the reference implementation at `e6a7d172`
(paths relative to `src/`). Each names the code that does it or the exact test
(`describe > it`) that shows it. A gap says so. The end-to-end files
(`demo/test/mas-pilot.test.ts`, `demo/test/mas-pilot-resource-policy.test.ts`,
`demo/test/mas-pilot-introspection.test.ts`, `demo/test/mas-pilot-separated.test.ts`) need a live OpenFGA, because the Resource policy is stored entitlements, and
are skipped without one; the mapping, estate-route, introspection and PDP
unit files always run.

## 1. Components

| Component | What it is | Trust |
|---|---|---|
| Estate AS | A stock `oidc-provider` instance (`demo/src/mas-pilot/estate-as.ts`) with no Mission code: its own issuer, a signing key generated at each boot, a directory of accounts and its own client registrations. Authorization code grant with PKCE, `client_secret_basic`, resource indicators, DPoP-bound access tokens: an RFC 9068 JWT, or an opaque reference for a client registered with `token_format: "opaque"`. RFC 7662 introspection open only to the gateway's registered introspection client; RFC 7009 revocation of a client's own tokens. | Issues ordinary tokens only. |
| MAS | The reference Mission kernel under its own issuer (`https://mas.pilot.invalid`), which issues no tokens in this mode. The PEP reads its committed records through the projection the shared demo stack also uses (`demo/src/kernel-mission-view.ts`), containment and discharge deltas included. | Holds the Missions the joins name. |
| Gateway route | A MAS-governed HTTP MCP route (`createHttpMcpChannel(…, { masGoverned: true })`) whose resource server sets `ordinaryOnly` (`services/mcp-payments/src/server.ts`) and trusts only the estate: a JWT under the keys the estate publishes at its `jwks_uri`, fetched over HTTP at boot, or an opaque token through introspection at the estate (§5). | Admits estate credentials, and only through the join. |
| Resource route | The payments resource's own Mission-bound route, trusting only the Mission Issuer's keys. Nothing signs with them in MAS mode. | Admits no estate credential. |
| PEP and PDP | The reference `Pep` and decision point over one payments store. Every crossing on either route goes through the PEP. | Apply the join, the credential bound and Resource policy. |
| Resource policy | Stored OpenFGA entitlements (`fgaResourcePolicy`, #828) for principals under the estate issuer, read by the decision point with no Mission input. The PEP's Mission-authority check reads the same store. | Independently administered (§4). |

The composition is `composeMasPilot` (`demo/src/mas-pilot/compose.ts`); its
configuration is `config/mas-pilot.json`, read by a strict loader
(`demo/src/mas-pilot/config.ts`). Client secrets and keys are generated at
each boot.

The estate's client identifiers (`estate-ap-bot-7f3`, `estate-extractor-2c1`,
`ap-agent`) are registered at the estate only; the Mission client they map to
is a separate identifier in the Mission Issuer's namespace. The estate
deliberately registers a client named `ap-agent`, the Mission's own
`client_id`, and an account named `alice`, the Mission subject's `sub`, so the
namespace tests in §7 run against real estate registrations.

## 2. The mapping contract

The contract is `config/mas-pilot.json` `mapping_contract`, version 1, with
the members MAS §mapping-contract lists:

- **Subject namespace mapping:** issuer-qualified estate subjects to Mission
  subjects, each `active` or `disabled`.
- **Client namespace mapping:** issuer-qualified estate clients to Mission
  clients, each `active` or `disabled`.
- **Scope mapping:** per estate issuer, each `scope` value to actions at the
  payments resource; a value it does not cover maps to nothing.
- **Delegate policy:** the Mission clients rule 4 admits as delegates, with a
  depth ceiling.
- **Client-instance identity:** not supported; the loader refuses a contract
  claiming it.
- **Version and provenance:** an integer `version`, `issued_at`, and the
  directory export it came from.
- **Failure semantics:** `mission_binding_failed`, the only value the loader
  accepts.

The loader (`parseMappingContract`, `demo/src/mas-pilot/mapping-contract.ts`)
refuses an unknown or missing member and an **ambiguous** mapping: a second
row for one issuer-qualified estate subject or client. Several estate
identities mapping to one Mission identity (**many-to-one**) is accepted and
disclosed: the shipped contract maps `u-1001` and `u-1002` to `alice`, and
every mapping decision records which estate identity it resolved.

Both configurations, in process and separated (§11), refuse to start without
a contract this loader accepts, before they build or connect to anything
(`requireDeclaredMappingContract`, `demo/src/mas-pilot/compose.ts`). The
shared demo stack's join declares its own contract
(`config/mas-join.json` `mapping_contract`) and refuses the same way
(`composeStack`):
`every join-enabling deployment declares the mapping contract its joins apply (@spec authority-server#mapping-contract, #818) > refuses to start a composition that would mount a join route with no declared contract, before it connects to anything`.

Where the mapping applies: the PDP maps the authenticated subject and client,
qualified by `context.credential.issuer`, before the join compares them with
the Mission's (`EvaluateOptions.joinMapping`, `services/pdp/src/evaluate.ts`
step 4b). An unresolved mapping, or a request naming no credential issuer,
denies `mission_binding_failed`; the bare presented strings never reach the
comparison. The PEP reads one contract snapshot per request
(`PepDeps.masJoin.mappingContract`) and uses it three ways: the scope mapping
as the credential's own authority (rule 8, bound 1), the mapped client as the
key for the actor-record depth (rule 5), and the snapshot it forwards to the
PDP, so one request applies one version.

## 3. Freshness, invalidation and failure

The pilot chose a **governed pre-materialized cache** over asynchronous
resolution (`MappingContractCache`):

- A snapshot is usable for `mapping_cache.max_stale_seconds` (300) after it is
  installed. After that, every resolution fails closed until a newer version
  is installed.
- Versions only move forward: an install at or below the installed version is
  refused, and the installed version stays until it goes stale.
- `invalidate()` drops the snapshot; every join then fails closed.
- An unusable snapshot (none installed, invalidated, or stale) is an
  unresolved mapping, so the join fails with `mission_binding_failed`, the
  contract's failure semantics. The PEP tells it apart
  (`JoinMappingContract.usable`), carries an empty credential authority to
  the PDP, and the PDP's join denies the request. A usable contract whose
  scope mapping does not cover the action is a credential without that
  authority: the PEP refuses it `out_of_authority` before any decision.
- The scope mapping is part of the contract, so the credential-authority
  mapping has the same freshness.
- The cache keeps an audit record of every identity decision (version, export
  identifier, the estate identities, the outcome), every install, refused
  install and invalidation. The record is in memory only (§9).

## 4. Resource policy

The decision point's Resource policy is the AS-native target's model (#828):
stored OpenFGA entitlements, `authorized_reader` and `authorized_payer` for a
subject and `authorized_client` for a client, each granted on a vendor (an
invoice inherits its owning vendor's) and counted only for a member of the
vendor's tenant. Every check is an authoritative read with no cache, so a
change applies to the next decision.

**Which identity it evaluates.** For a joined request the principals are the
subject and client the gateway authenticated, under the estate issuer:
`user:<enc(estate iss)>|<enc(sub)>` and `client:<enc(estate iss)>|<enc(client_id)>`
(`issuerLocalPrincipals` and `issuerLocalClients` over the estate issuer,
`demo/src/mas-pilot/compose.ts`). Never the Mission-side identities the
mapping contract resolves them to. Three reasons:

- MAS §mission-join rule 8 bounds a joined permit by three independently
  evaluated bounds. The mapping is part of the join, so a policy keyed on the
  mapped identity would inherit every mapping error: one wrong row would
  satisfy both the join and the policy.
- The policy query is "the verified token subject and the issuer this
  Resource authenticated it under" (`ResourcePolicyQuery.subject`,
  `services/pdp/src/resource-policy.ts`); the request carries exactly that
  (`subject.properties.iss` is the estate issuer, AuthZEN profile rule 10),
  and the PDP's step 6b reads it unchanged.
- A legacy estate administers its resources' entitlements against its own
  accounts and clients.

The two namespaces stay apart by construction: the Mission-side `alice`
(`user:<enc(https://mas.pilot.invalid)>|alice`) and the estate account named
`alice` are different principals, and neither entitlement satisfies the
other.

**The store.** `composeMasPilot` takes `resourcePolicyStore`: `attach` names a
configured store and model, which are verified and never written, so a
revocation made before a restart is what the next decision reads;
`bootstrap: "development"` creates a fresh store and seeds it from
`config/mas-pilot.json` `resource_policy` (estate subjects and clients, all
under the estate issuer) plus the payments store's invoice ownership. Nothing
in either is derived from a Mission or a token.

**Administration.** `pnpm resource-policy` (`demo/src/resource-policy-admin.ts`)
changes it, attached to `OPENFGA_STORE_ID` and `OPENFGA_MODEL_ID`, naming the
estate issuer:

```sh
pnpm resource-policy revoke --iss http://127.0.0.1:14818 --sub u-1001 --relation reader --vendor acme
pnpm resource-policy grant --iss http://127.0.0.1:14818 --client estate-ap-bot-7f3 --relation client --vendor acme
pnpm resource-policy grant --iss http://127.0.0.1:14818 --sub u-1001 --relation member --tenant estate-payments
```

The tests drive the same code path (`resourcePolicyAdmin`).

## 5. Opaque tokens and introspection

The estate issues an opaque, DPoP-bound access token to a client registered
with `token_format: "opaque"` (`estate-opaque-bot-4e2`). The gateway's estate
route validates it by RFC 7662 introspection at the estate
(`TokenIntrospector`, `services/mcp-payments/src/introspection.ts`); a compact
JWS still takes the JWT path. The facts are built exactly as the JWT path
builds them, so the same join, mapping contract, Resource policy and class
reservation apply.

- **The call.** An authenticated POST (`client_secret_basic`, as the gateway's
  registered introspection client `mas-gateway-introspector`, its secret
  generated at each boot) naming the token, bounded by
  `introspection.timeout_ms` (2000).
- **What it requires.** `active: true`; an `iss`, when present, that is the
  estate's; `token_type` `DPoP`; an `exp` still ahead; non-empty `sub` and
  `client_id`; an `aud`; and `cnf.jkt`. The audience rule is the JWT path's
  (`aud` must name this boundary, under the token profile
  `token-introspection`), and the request's DPoP proof must be bound to the
  introspected `cnf.jkt` and to the token (`ath`). The identity is qualified
  by the route's own issuer, the estate, never by a value the response
  supplies.
- **Expiry after the awaits.** The adapter reads its clock again once the
  answer arrives, checks `exp` against that reading and starts the cache
  entry from it; admission re-checks `exp` after its own awaits. A token that
  expires while it is being introspected is refused. The PDP's own
  credential-expiry check (`context.credential.expires_at`) was always a
  second line, so the earlier gap, found in review of #1400, concerned
  credential admission, not a demonstrated tool-execution bypass.
- **Fail closed.** No answer (a timeout, a network error, a non-200 status, a
  body that is not a JSON object) is refused 503 `temporarily_unavailable`;
  any other refusal is 401. Neither reaches the PEP, so no decision is made.
- **Cache and revocation latency.** A positive result is cached, keyed by the
  token's SHA-256, for at most `introspection.cache_max_seconds` (60) and
  never past the token's `exp`; a negative result is never cached. A token
  revoked at the estate is therefore refused within 60 seconds of its last
  successful introspection.
- **The estate's own controls,** as configured (`estate-as.ts`; no pilot test
  exercises either): introspection is allowed only to the registered
  introspection client, so any other caller reads `active: false`, and a
  client may revoke only its own tokens.

## 6. Routes and consequential-path inventory

`config/mas-pilot.json` `routes` names the two routes and `inventory` names
every payments tool, its action class and its disposition on the gateway:

| Tools | Class | Gateway |
|---|---|---|
| `list_invoices`, `get_invoice`, `lookup_vendor`, `check_transfer` | `consequential_read` | joined |
| `schedule_payment`, `cancel_scheduled_payment`, `hold_transfer` | `consequential_write` | joined |
| `execute_wire_transfer` | `irreversible_action` | Mission-bound only |
| `send_remittance_email` | `external_commitment` | Mission-bound only |

A joined request in a high-consequence class is denied before the join runs
(`EvaluateOptions.missionBoundOnlyClasses`; local reason
`mission_binding_failed`). A joined ordinary token is `credential-correlated`,
and the stronger posture needs Mission-bound issuance, which this pilot does
not include. The remittance test entitles the estate account to pay in the
Resource policy, so every other bound allows the action; without the
reservation it permits the remittance. The reservation is the control, not a
side effect of another check. This is the pilot's inventory choice; the
reference claims no `mas.enterprise` capability.

## 7. What the pilot witnesses

Against D284's evidence list (tests in `demo/test/mas-pilot.test.ts` unless
named):

| D284 requirement | Status | Witness |
|---|---|---|
| Gateway bypass refused | Covered for this composition | `MAS pilot: the gateway joins … > refuses the same estate credential on the resource's own route before any decision, though the gateway admits it (bypass)`: a whole attempt (the MCP handshake and a tool call) is refused, the handshake answered 401, with no decision request and no evidence record; the gateway permits the same credential. |
| Different issuer and client registrations | Covered | `MAS pilot: the estate is a separate issuer … > issues an ordinary RFC 9068 token under the estate issuer, with no mission claim and a client the MAS never registered`; `… > refuses to issue for a resource the client's estate registration does not name (invalid_target)`. |
| Credential-authority adapter | Covered for two formats | Scope to authority from an RFC 9068 JWT: `… > bounds a joined credential by its own scope as the contract maps it`; and from an RFC 7662 introspection response for an opaque token: `MAS pilot introspection: opaque estate tokens at the gateway … > bounds the opaque token by its introspected scope …` (slice 3, below). Other formats refused: `services/mcp-payments/test/estate-route.test.ts`, `estate route: ordinary credentials only … > refuses every other credential format`. |
| Mapping provenance and freshness | Covered | `demo/test/mas-pilot-mapping.test.ts`, `mapping contract cache: versions and freshness …` (reassignment, refused rollback, staleness bound, usability, invalidation) and `… > resolves two estate accounts mapped to one Mission subject, and audits which account each decision resolved`. At the gateway, `MAS pilot: an unavailable mapping fails the join, not the credential bound …`: an invalidated and a stale contract each deny `mission_binding_failed` at the PDP's join and permit again after a new install; a usable contract that does not map the action refuses `out_of_authority` before any decision. |
| Committed Mission state on the joined path | Covered for containment | `MAS pilot: a committed containment narrows a joined Mission … > denies authority_contained for the action a containment removed, while the uncontained read still permits`. The discharge delta rides the same shared projection; no pilot test discharges an entry. |
| Same `sub` or `client_id` in another namespace | Covered | `… > never conflates an estate client registered under the Mission's own client_id string`; `… > never conflates estate account "alice" with the Mission subject alice`; PDP: `services/pdp/test/evaluate-join-mapping.test.ts`. |
| Disabled accounts | Covered | `… > denies a disabled estate account whose row still names the Mission's subject`. |
| Reassigned accounts | Covered | `MAS pilot: a newer contract version moves a reassigned account … > an outstanding estate token for u-1001 stops joining alice's Mission once version 2 reassigns the account to dana`. |
| Many-to-one mappings | Covered | `… > joins two estate accounts mapped to one Mission subject (many-to-one), and the audit log keeps which account acted`. |
| Missing delegate records | Covered | `MAS pilot: delegates need a recorded actor edge … > denies a mapped delegate with no actor record, then joins it once the deployment records the edge`. |
| Joined token never takes the high-consequence posture | Covered for the pilot's reservation | `MAS pilot: a joined ordinary token never takes a high-consequence path … > denies a remittance under a joined credential whose scope, Mission and Resource policy all carry it, commits nothing, and still permits the joined read`; an estate token carrying a `mission` claim is refused: `estate-route.test.ts > … > refuses an estate token carrying a mission claim, which a Mission Issuer's route admits as Mission-bound`. |

Slice 2's Resource-policy witnesses (`demo/test/mas-pilot-resource-policy.test.ts`,
describe `MAS pilot Resource policy: estate entitlements, administered and
revoked (#818 slice 2)` unless named), all over the stored policy:

| Property | Witness |
|---|---|
| An entitled estate identity permits | `… > permits a joined read for an estate subject and client entitled in the store under the estate issuer` |
| Revoking only that entitlement denies, granting it back permits | `… > revoking only the estate subject's entitlement denies resource_policy with no result, and granting it back permits` (another estate account on the same Mission still reads) |
| The estate identity is evaluated, not the mapped one | `… > evaluates the estate subject, not the Mission-side identity it maps to: with alice and ap-agent fully entitled, the revoked estate account is still denied` |
| A colliding name in the other namespace is never satisfied | `… > keeps the two alices apart: the Mission-side alice's entitlement never satisfies the estate account named alice, and its own does` |
| The client dimension applies to estate clients | `… > applies the client dimension to the estate client: revoking its authorized_client denies, the Mission-side identity never stands in, and restoring permits` |
| A restart attached to the store keeps a revocation | `MAS pilot Resource policy: a restart attached to the same store keeps a revocation … > a pilot attached to the first pilot's store and model reads the revocation made before the restart, and the grant that follows` |
| The seed loads and refuses as the shipped seed does | `demo/test/mas-pilot-mapping.test.ts`, `pilot configuration: the estate's development Resource-policy grants …` |

Slice 3's introspection witnesses: end to end in
`demo/test/mas-pilot-introspection.test.ts` (describe `MAS pilot
introspection: opaque estate tokens at the gateway (#818 slice 3)`), with the
gateway's introspection calls through a forwarding proxy that can delay,
fail or rewrite them; the adapter in
`services/mcp-payments/test/token-introspection.test.ts`; the estate route in
`services/mcp-payments/test/estate-route-introspection.test.ts`.

| Property | Witness |
|---|---|
| An opaque token permits end to end, its identity from introspection | `… > permits a joined read with an opaque token, its identity read from the estate's introspection` |
| The introspected scope is the credential bound | `… > bounds the opaque token by its introspected scope: an action that scope does not carry is refused out_of_authority, and a scope that carries it permits` |
| An inactive token is refused with no decision | `… > refuses a token the estate reports inactive, with no decision` (401); adapter: `token introspection: fail-closed refusals … > refuses an inactive token, and does not cache the refusal` |
| A token expiring while its introspection is in flight is refused | adapter: `token introspection: expiry is checked after the answer arrives … > refuses a token that expires while its introspection is in flight, and keeps no cache entry for it`; admission: `estate route with introspection: expiry is re-checked at admission … > refuses a token whose exp passes after the adapter accepted it, before admission completes` |
| A revocation at the estate is refused within the cache bound | `… > stops admitting a token revoked at the estate once its positive cache entry ends, within cache_max_seconds`; adapter: `token introspection: the cache bounds …` (at most `cacheMaxSeconds`, never past `exp`) |
| A timeout and an error fail closed | `… > fails closed when introspection does not answer within its timeout, with no decision` and `… > fails closed when introspection answers with an error or a body that is not JSON, with no decision` (503) |
| A token for another resource is refused | `… > refuses an opaque token the estate issued for another of its resources, with no decision`; estate route: `… > refuses an opaque token introspected for another resource, under the same audience rule as a JWT` |
| The introspected `cnf` is enforced | `… > enforces the introspected cnf: the same opaque token with another DPoP key is refused` |
| Namespaces stay apart | `… > refuses an introspection answer that names another issuer, so an introspected identity is only ever the estate's`; `… > keeps namespaces apart on the opaque path: estate account alice joins dana's Mission and never alice's` |
| The same Resource policy and class reservation apply | `… > applies the same Resource policy to the introspected client: revoking its authorized_client denies resource_policy`; `… > applies the same class reservation: a remittance under an opaque token is denied though scope, Mission and Resource policy allow it` |

Each test was proved by introducing the defect it guards against and
confirming its assertion fails.

## 8. AS capabilities and adopter code for the baseline join

What the estate AS needed, all by configuration of an unmodified library:
RFC 9068 JWT access tokens carrying `scope`, `sub` and `client_id`;
DPoP-bound tokens (`cnf.jkt`); a published `jwks_uri`; per-client resource
and scope restrictions; and, for opaque tokens, a per-client access token
format, RFC 7662 introspection restricted to registered introspection clients
(its response carrying `active`, `iss`, `sub`, `client_id`, `scope`, `aud`,
`exp` and `cnf`), and RFC 7009 revocation.

What the adopter wrote: the gateway's resource-server configuration (trusted
estate keys, `ordinaryOnly`, the introspection client and its bounds), the
mapping contract and its cache, the estate's Resource-policy grants, and the
composition. The PEP and PDP changes are reference code
(`joinMapping`, `missionBoundOnlyClasses`, `mappingContract`).

Sender-bound Join Assertions (MAS §join-assertion) are not built; #1454
owns building them and the Enterprise tier. What they would additionally
need, by party:

- **The estate AS** (MAS §enterprise-prerequisites): sender-constrained
  access tokens carrying a `cnf` key, and introspection responses or
  validatable RFC 9068 claims that report it. The pilot's estate already
  provides all three as configured: DPoP-bound tokens with `cnf.jkt`, JWTs
  under its published keys, and RFC 7662 introspection reporting `cnf`
  (§5). Nothing changes there.
- **The MAS**: the join-assertion endpoint (MAS §join-assertion-request),
  advertised as `mission_join_assertion_endpoint`, with caller
  authentication, the visibility set and its anti-oracle split, and
  per-caller rate limiting; verifying the acting token centrally (by
  introspection at the estate, or RFC 9068 validation) and refusing one
  with no `cnf`; the subject and client joins under its own mapping
  contract, and a delegate's depth from actor records; and minting the
  artifact (MAS §join-assertion-artifact, `typ` `mission-join+jwt`): the
  `mission`, the `token` binding (`sha256` and `jkt` or `x5t#S256`), the
  `join` result, an `aud` naming an enrolled PDP, an `exp` within the
  token's own, and `mapping_version`, the contract version the joins were
  evaluated under. Each minting is a retained join evidence event. The
  reference MAS (`mas-serve.ts`) has none of this.
- **The PDP** (MAS §join-assertion-pdp): verifying the assertion
  (signature under the MAS's keys, `typ`, `alg`, `iss` and `mission`,
  `exp`, `aud`) and the token binding against
  `context.mission_join.token_sha256` and the reported thumbprint, then
  taking the joining client, disposition and depth from `join` in place of
  its own mapping checks; and the PEP carrying the token digest and
  thumbprint in `context.mission_join`. Neither is built.

The mapping version in join evidence belongs to that artifact's
`mapping_version` claim. Baseline Decision Evidence carries no mapping
version, and no draft requires one there.

## 9. Residuals and exclusions

- **The Resource policy administers estate principals only.** A request
  whose subject is not under the estate issuer has no principal and is
  refused `resource_policy`. In MAS mode nothing issues a Mission-bound token,
  so the Mission-side direction (an estate entitlement presented for a
  Mission-side subject) is not reachable end to end; the issuer-local mapping
  that refuses it is the PDP's (`issuerLocalPrincipals`).
- **The development seed is the pilot's own** (`config/mas-pilot.json`
  `resource_policy`); a production estate attaches to its administered store.
- **In the in-process configuration, Mission state is a kernel read**, as on
  the AS-native target (D293). The separated configuration (§11) reads it
  through the MAS's signed Mission Status instead.
- **The mapping audit log is in memory**, unsigned and not retained. Decision
  Evidence carries `join_view_id`, which commits the authenticated (estate)
  client, not the mapping version.
- **The pilot MAS's derivation ceiling names its delegates by client
  identifier** (`config/mas-pilot.json` `mas_delegates`), because the join
  compares a bare client identifier and drops profile matchers
  (`deriveJoinDelegation`). This is a deployment delta over the shipped
  policy.
- **The estate's login page is a stand-in:** its interaction logs in the
  account named by `login_hint`.
- **The gateway fetches the estate's keys once, at boot;** key rotation is
  not handled. The introspection endpoint is likewise read from the estate's
  metadata at boot.
- **Revocation latency on the opaque path is up to
  `introspection.cache_max_seconds` (60)**, never past the token's `exp`; the
  JWT path has no revocation check beyond the token's own lifetime, as for any
  RFC 9068 resource. Introspection answers are plain JSON (no RFC 9701 signed
  responses), over the estate's endpoint as configured.
- **No instance-bound join and no Join Assertion.**
- **Tool listing:** an ordinary credential is listed no tools
  (`McpPaymentsServer.toolsList`, an existing remainder); calls are enforced.
- **Co-resident decisions only.** `joinMapping` and
  `missionBoundOnlyClasses` reach the PDP in the PEP's decision options,
  which only the co-resident decision path carries. A remote decision
  channel's PDP would have to supply both in its own options: without them
  the subject join still fails closed on the issuer mismatch, but the class
  reservation would not apply.
- **No action-bound approval gate on the pilot PEP.** It configures no
  `requiresActionApproval`, unlike the AS-native PEP's remittance gate. The
  remittance class is reserved on the gateway and nothing issues a
  Mission-bound token for the resource route, so with a payer entitlement in
  the Resource policy the reservation is the only control on that path (the
  remittance mutation proof shows it).
- **No launcher:** the pilot runs in its tests only.
- The shared demo's MAS-governed channel (`config/mas-join.json`) is
  unchanged and keeps its shared-namespace join.

## 10. Toward a separated MAS: Join Disclosure and the Status resolver

Slice 4's first part: the two pieces a separated MAS needs, each tested on
its own against the reference authorization server over HTTP. The
separated configuration (§11) composes the pilot on them.

**Join Disclosure on Mission Status** (MAS §join-disclosure). The reference
authorization server's Status operation discloses `mission.subject` (`iss`,
`sub`) and `mission.client_id` only to a service principal that its
`enrolledJoinPdps` option enrolls for the requested `audience`
(`buildAuthorizationServer`; `joinDisclosureFor` in
`services/authorization-server/src/adapters/provider.ts`, `joinDisclosure` in
`MissionKernel.observeInCallerTx`). Audience-scoped entries carry their
recorded `delegation` for every caller, as before. Every other response is
unchanged:
`Join Disclosure on Mission Status (@spec authority-server#join-disclosure) > discloses subject, client_id and each entry's recorded delegation to a PDP enrolled for the requested enforcement scope`,
`Join Disclosure on Mission Status (@spec authority-server#join-disclosure) > includes neither member for any other caller: a principal enrolled for nothing, the enrolled PDP for another scope or for no scope, an inherited-name principal`,
`Join Disclosure on Mission Status (@spec authority-server#join-disclosure) > serves a caller not enrolled the response the kernel's default observation signs, byte for byte`.

**The PDP's remote Mission Status resolver** (MAS §join-rules rule 2):
`MissionStatusResolver` (`services/pdp/src/mission-status-resolver.ts`), one
per Mission issuer and enforcement scope, with no handle on the issuer's
store.

| Property | How |
|---|---|
| One verifier | `verifyMissionStatusResponse` (`services/pdp/src/state-observation.ts`), the function `verifyStateAssertion` also runs: the Status `typ`, a declared key, `iss`, `aud` equal to the enforcement scope, `exp` and `iat` both required (a response without either does not verify, on this path and the PEP-carried assertion's), not expired, the requested Mission under that issuer, a signed `fresh_until`. |
| Its own checks | The request's `nonce` echoed; `iat` not in the future; `state` one of `active`, `suspended`, `terminated`; `version`, `authority_hash`, `subject`, `client_id` and each entry (with its `delegation`) well formed. A reference naming another issuer is never read; the identifier travels as one percent-encoded path segment, and a dot segment is never requested. |
| Keys | The issuer's published JWKS, restricted to the declared status `kid`s (`declaredStatusKeys`): a key published for another purpose verifies nothing. |
| Authentication | This PDP's service credential holding `mission_status`, in `x-service-token`, as the reference Status route requires. |
| Bounds | One deadline covers connecting, the headers and the body; the body is counted against a byte cap as it arrives; a redirect is never followed. |
| Fail closed | A typed failure (`unavailable`, `unauthorized`, `not_found`, `unverifiable`, `stale`), never thrown and never cached. |
| Reliance bounds | Every observation the resolver returns, read now (a `fresh: true` read included) or reused from the cache, is before its signed `fresh_until`, within `iat` plus the issuer's `mission_max_stale_seconds`, and within the caller's `maxAgeSeconds`, with no skew allowance on the old side. One function holds the three bounds for both paths (`boundPassed`); an observation read now that has passed one verified but is refused `stale`, and is not cached. |
| Cache | Keyed on the Mission within one resolver; `fresh: true` reads the source whatever the cache holds; an older observation never replaces a newer one. |
| View | The audience-scoped effective set; each `delegation` mapped to `join_delegation` by `deriveJoinDelegation`; `subject` and `client_id` only where disclosed; no containment or discharge delta. |

Witnesses: `services/pdp/test/mission-status-resolver.test.ts` (a Status
server double: every answer that must establish nothing, a response without
`exp` or `iat`, an observation read now that is past a reliance bound, the
cache bounds, the configuration), the PEP-carried assertion signed without
`exp` or `iat` in `services/pdp/test/evaluate-authzen-members.test.ts`
(`AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004) > a present assertion is verified against the declared state source's key > an assertion signed without exp, or without iat, denies stale_state`), and `services/authorization-server/test/mission-status-resolver-as.test.ts`
(the reference authorization server over HTTP, configured from its published
metadata: the Join Disclosure an enrolled PDP reads and one it does not, a
revocation seen at once on a fresh read and after the signed bound on a
cached one, the server stopped and restarted, a source slower than the
deadline).

Gaps, both owned by #1407 (Status read conformance):

- **The envelope `sub`.** The reference signs the Mission's `client_id` (or
  a Lifecycle request's acting party) as `sub` for every caller. MAS
  §join-disclosure says the envelope `sub` identifies the requesting caller,
  and Status consumer check 6 has the consumer require that. A caller not
  enrolled therefore still learns the Mission's `client_id` from `sub`, so
  `mas.join-disclosure.not-to-others` stays `partial`. The resolver does not
  check `sub`.
- **The request shape.** The reference Status operation is
  `GET /missions/{id}/status` with `audience` and `nonce` as query
  parameters and the `x-service-token` stand-in, and its metadata advertises
  no `mission_status_endpoint`; the Status profile defines a form `POST` at
  that endpoint. The resolver takes the operation's URL as configuration
  (`statusUrl`).

## 11. The separated configuration

Slice 4's second part (D560). `composeSeparatedMasPilot`
(`demo/src/mas-pilot/separated.ts`) assembles everything §1 lists except the
Mission kernel. Both configurations share `assembleMasPilot`
(`demo/src/mas-pilot/compose.ts`), which never holds a Mission store; the
separated pilot's type (`SeparatedMasPilot`) has no kernel member, and it
knows the MAS only by URL and credential. The MAS is the reference
authorization server running as its own OS process
(`demo/src/mas-pilot/mas-serve.ts`, started by `mas-process.ts`) under the
pilot's derivation ceiling (`mas-policy.ts`, shared with the in-process
kernel), configured by `config/mas-pilot.json` `separated_mas`. Its URL is
the Mission issuer.

| Property | How |
|---|---|
| Source | The MAS's Mission Status, read by §10's `MissionStatusResolver` as `separated_mas.pdp_principal_id`, whose credential is generated at each boot and registered at the MAS with `mission_status` only. The resolver is configured from what the MAS publishes over HTTP: its metadata (`issuer`, `jwks_uri`, `mission_max_stale_seconds`) and its status-response key. |
| Disclosure | `separated_mas.enrolled_pdps` is the MAS-held enrollment (`enrolledJoinPdps`). A PDP it does not enroll reads no `subject` or `client_id`, and its join denies `mission_binding_failed` (`resolveBaselineJoin`; `MissionView.subject` and `client_id` are optional). |
| Placement | `pdp` (`separated_mas.state_source.placement`; the loader refuses any other). The PEP sends no `mission_state_observation`. |
| The PDP's read | Every decision reads its own (`ownReadDecide`): within the action class's staleness window (`maxAgeSeconds`), and from the MAS now (`fresh: true`) for a commit-phase decision. `stateObservedAt` is the response's signed `iat`, never the time of the fetch or of a cache hit; `stateFreshUntil` is its signed `fresh_until`, which caps the permit through the `signed_state_fresh_until` ceiling (`services/pdp/src/own-read-ceiling.ts`). A read that establishes nothing gives the decision no state, so it denies `stale_state` (authzen#pdp-request rule 1). The non-commit read answers from the resolver's cache the PEP's read filled, under its own window. |
| The PEP's read | One per enforcement, awaited at its start (`PepDeps.viewSource`, `statusViewSource`). A Mission the MAS does not hold or show refuses `unknown_mission`; every other failure, including the MAS refusing the PDP's credential, refuses `state_unavailable` (authzen#failure-condition-coverage, "Mission state not establishable at the PEP"); both on a signed Refusal Record before any decision. The PEP's synchronous reads (`loadView`) answer from the resolver's cache within its bounds (`peek`). With a remote source, a list read whose view lapses before re-verification is suppressed `target_drift`, recording no digest it could not observe; `toolsList` lists nothing for a credential with no view, as before (`McpPaymentsServer.toolsList` stays synchronous). |
| Bounds | The signed `fresh_until` (60 s on the reference MAS), `iat` plus `mission_max_stale_seconds` (300), the class window; nothing is cached from a failed read; the read's deadline (`timeout_ms`) and body cap (`max_response_bytes`). |
| Lifecycle | Revocation and containment go to the MAS's Lifecycle surface over HTTP. A test approves Missions and moves the MAS's clock through the process's operator channel (IPC), which is test harness, not a protocol surface. A key ring and a kernel store keep the MAS's keys and Missions across a restart. |

**Declared diagnostic.** The Authority Set is the Status response's
audience-scoped effective set (MAS rule 7), which carries no containment or
discharge delta. An action that a containment or a discharge removed at the
MAS is outside that set, so the decision denies `out_of_authority`; the
in-process configuration, which reads the deltas, denies
`authority_contained` or `authority_discharged`. Containment is witnessed;
discharge follows from the same projection and is not exercised here.

**No missing-authority remediation from a projection.** An effective-set view
gives no `insufficient_authorization` hint for an absent action unless it
proves it holds the committed set: its `authority_hash` recomputes over its
entries (`viewHoldsCommittedSet`, D335, the proof the PDP applies to the
credential bound; `absenceMeansNeverGranted` in
`services/mcp-payments/src/view-source.ts`). After a containment or a
discharge, or when the Mission has entries for another audience, the Status
view cannot prove it, so the refusal stands with no hint: a narrowed
capability is restored only through Expansion. A Status view whose effective
set is the committed set (one audience, nothing contained or discharged)
proves it, and a never-granted action there keeps its hint. A loader with no
remote source is read as the committed set, as before.

Witnesses: `demo/test/mas-pilot-separated.test.ts` (each refusal asserts no
committed effect and its carrier, the PDP's Decision Evidence or the PEP's
Refusal Record):

- `the separated MAS pilot: the PDP reads Missions through the MAS's signed Mission Status (#818 slice 4b) > permits a joined read on the Status view, with Join Disclosure, the MAS's own state version, and a permit capped by the signed fresh_until`
  (the Decision Evidence's `policy_view_id` commits the version and `authority_hash` a direct Status read returns);
- `… > denies the action a containment at the MAS removed out_of_authority, the Status view's declared diagnostic, while the uncontained read still permits` (and gives no `insufficient_authorization`);
- `… > proposes a never-granted action back on a Status view that proves it holds the committed set`;
- `… > observes a revocation at the MAS within the signed bound: relied on until its fresh_until, then mission_inactive`;
- `… > refuses the commit crossing of a Mission revoked after its prepare: the commit-phase decision reads the MAS now, and commits nothing`;
- `the separated MAS pilot: a PDP the MAS has not enrolled, a slow source, an answer that does not verify (#818 slice 4b) > an unenrolled PDP reads no Subject or client, so the join denies mission_binding_failed and nothing is permitted`;
- `… > a source slower than the deadline establishes no state: the PEP refuses state_unavailable before any decision`;
- `… > a Status answer that does not verify establishes no state: the PEP refuses state_unavailable before any decision`;
- `the separated MAS pilot: the MAS stops and starts (#818 slice 4b) > with the MAS down, a commit decision denies stale_state and an expired read refuses state_unavailable; restarted with its key ring and store, it reads again`.

Unit witnesses: `services/pdp/test/evaluate-own-read.test.ts` (the
signed-ceiling cap and a passed one, the join without a disclosed
`subject` or `client_id`), `services/mcp-payments/test/view-source.test.ts`
(the PEP's one read, its lapsed list re-verification, and the remediation
guard with a complete view, an effective projection, and no remote source), and
`demo/test/mas-pilot-separated-wiring.test.ts` (the class window, the
commit-phase fresh read, the signed `iat` and `fresh_until`, and the
refusal mapping).

Gaps:

- **The commit-phase witness uses a test scope.** The shipped scope mapping
  maps no estate scope to `payments:payment.execute`, so the gateway cannot
  prepare a transfer; the test's configuration adds one
  (`payments.execute`, for `estate-ap-bot-7f3`).
- **`maxAgeSeconds` binds before the MAS's 60 s `fresh_until`** only for a
  class whose window is shorter (`irreversible_action` and
  `privileged_administration`, 30 s). The gateway's one such crossing is the
  commit, which reads fresh, so the class window is witnessed at the adapter,
  not end to end.
- **Keys are read once, at composition.** A MAS restarted with new keys
  verifies nothing until the pilot is composed again: every read refuses
  `state_unavailable`. Key rotation is not handled.
- **#1407** still owns the Status envelope `sub` and the request shape (§10).

## 12. Remaining slices

1. Sender-bound Join Assertions and the Enterprise tier (Sketch step 5's
   second half), with the mapping version carried as the assertion's
   `mapping_version` claim: #1454 (§8 lists what they need). The
   introspection adapter here is what a MAS would use to inspect the estate
   token.
2. Done in slice 5B: operator launchers for both topologies
   (`pnpm mas-pilot`, `pnpm mas-pilot:separated`), attaching to an
   administered Resource-policy store, and the walkthrough
   (`docs/mas-pilot-walkthrough.md`; §13). MAS key rotation stays
   unsupported: the resolver reads the MAS's keys once, and restarting the
   pilot is the remedy.
3. Ledger: `mas.mapping-contract.floor-documented` is `tested` on
   `demo/test/mas-join-contract.test.ts`: every shipped deployment that
   mounts a join route declares its mapping contract (this pilot's in §2;
   the shared demo stack's in `config/mas-join.json` `mapping_contract`,
   described in `config/README.md`), and a composition that would mount
   one without it refuses to start. The
   `mas.enterprise`, `mas.join-assertion` and `mas.hc.mission-bound-instance-check`
   rows and `mas.mapping-contract.enterprise-publishes` stay `todo`, owned by
   #1454. `mas.join-disclosure.members` is `tested` and
   `mas.join-disclosure.not-to-others` `partial` (the envelope `sub`, #1407),
   both at the Controller role on §10's Join Disclosure tests. Join rule 2's
   two rows (`mas.baseline-join.resolve-at-mas`,
   `mas.baseline-join.mas-state-source`) are `tested` on §11's witnesses at
   the PDP role, and rule 7 (`mas.baseline-join.authority-from-mission`) cites
   two of them beside its earlier tests.

The component matrix in MAS §deployment-adoption (Sketch steps 1 and 2)
merged as #1352 (D523).

## 13. Run it

To run the pilot as an operator, `pnpm mas-pilot` starts the in-process
topology and `pnpm mas-pilot:separated` the separated one
(`demo/src/mas-pilot/launcher.ts`, #818 slice 5B). Each attaches to an
administered Resource-policy store, or bootstraps a development store only on
`MAS_PILOT_DEVELOPMENT_STORE=1`, and serves an operator console that
approves Missions on the MAS's approval surface and revokes and contains them
at its Lifecycle endpoint. [mas-pilot-walkthrough.md](mas-pilot-walkthrough.md)
starts each topology, makes joined calls with a JWT and an opaque estate
credential, revokes and contains at the MAS, reads the evidence, and states
what rotation of the estate's keys, the introspection client and the MAS's
keys takes.

To run the tests, from `src/`, with a live OpenFGA (`OPENFGA_HTTP_URL`,
`OPENFGA_PRESHARED_KEY`, and `OPENFGA_CA_CERT` where it serves TLS):

```sh
pnpm vitest run demo/test/mas-pilot.test.ts demo/test/mas-pilot-resource-policy.test.ts \
  demo/test/mas-pilot-introspection.test.ts demo/test/mas-pilot-mapping.test.ts \
  services/mcp-payments/test/estate-route.test.ts services/mcp-payments/test/estate-route-introspection.test.ts \
  services/mcp-payments/test/token-introspection.test.ts services/pdp/test/evaluate-join-mapping.test.ts \
  services/authorization-server/test/status-join-disclosure.test.ts \
  services/authorization-server/test/mission-status-resolver-as.test.ts services/pdp/test/mission-status-resolver.test.ts \
  services/pdp/test/evaluate-authzen-members.test.ts \
  demo/test/mas-pilot-separated.test.ts demo/test/mas-pilot-separated-wiring.test.ts \
  services/pdp/test/evaluate-own-read.test.ts services/mcp-payments/test/view-source.test.ts \
  demo/test/mas-pilot-launcher.test.ts
```

§10's four files and §11's three unit files need no OpenFGA. The reference authorization server binds
`localhost:14826` in `status-join-disclosure.test.ts` and `localhost:14827` in
`mission-status-resolver-as.test.ts`; the Status server double and the
forwarding proxy bind ephemeral ports.

Each end-to-end file bootstraps its own development store. The estate AS
binds `127.0.0.1:14818` in `mas-pilot.test.ts`, `127.0.0.1:14824` in
`mas-pilot-resource-policy.test.ts` and `127.0.0.1:14825` in
`mas-pilot-introspection.test.ts` (the configuration relocated, so the files
run in parallel); the gateway, the resource route and the introspection proxy
bind ephemeral ports. In `mas-pilot-separated.test.ts` the MAS process binds
`127.0.0.1:14835` (the shipped `separated_mas.port` is 14834), and the four
pilots it composes run their estates on `127.0.0.1:14843`, `14847`, `14850`
and `14852`; the slow proxy and the Status double bind ephemeral ports.
`mas-pilot-launcher.test.ts` binds `127.0.0.1:14858` to `14869`, except
`14866` (walkthrough §7); its startup refusals need no OpenFGA.
