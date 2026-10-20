# MAS pilot deployment

The pilot contract for #253's second reference path: the **legacy-estate/MAS
route** that D284 adopted and D508 ruled executable, owned by #818 (Sketch
steps 3 and 4). A legacy estate keeps its own authorization server; its
ordinary tokens are joined to Missions at a gateway, under a versioned mapping
contract. This document records slices 1 and 2 of that evidence (slice 2:
the Resource policy, §4). It is not a
conformance, production-readiness or interoperability claim, and nothing in
the AS-native target's evidence ([initial-runtime-deployment.md](initial-runtime-deployment.md))
bears on it, or the reverse (D284).

Every statement here is true of the reference implementation at `739a5c50`
(paths relative to `src/`). Each names the code that does it or the exact test
(`describe > it`) that shows it. A gap says so. The end-to-end files
(`demo/test/mas-pilot.test.ts`, `demo/test/mas-pilot-resource-policy.test.ts`)
need a live OpenFGA, because the Resource policy is stored entitlements, and
are skipped without one; the mapping, estate-route and PDP unit files always
run.

## 1. Components

| Component | What it is | Trust |
|---|---|---|
| Estate AS | A stock `oidc-provider` instance (`demo/src/mas-pilot/estate-as.ts`) with no Mission code: its own issuer, a signing key generated at each boot, a directory of accounts and its own client registrations. Authorization code grant with PKCE, `client_secret_basic`, resource indicators, DPoP-bound RFC 9068 JWT access tokens. | Issues ordinary tokens only. |
| MAS | The reference Mission kernel under its own issuer (`https://mas.pilot.invalid`), which issues no tokens in this mode. The PEP reads its committed records through the projection the shared demo stack also uses (`demo/src/kernel-mission-view.ts`), containment and discharge deltas included. | Holds the Missions the joins name. |
| Gateway route | A MAS-governed HTTP MCP route (`createHttpMcpChannel(…, { masGoverned: true })`) whose resource server trusts only the keys the estate publishes at its `jwks_uri`, fetched over HTTP at boot, and sets `ordinaryOnly` (`services/mcp-payments/src/server.ts`). | Admits estate credentials, and only through the join. |
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
namespace tests in §6 run against real estate registrations.

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
  install and invalidation. The record is in memory only (§8).

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

## 5. Routes and consequential-path inventory

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

## 6. What the pilot witnesses

Against D284's evidence list (tests in `demo/test/mas-pilot.test.ts` unless
named):

| D284 requirement | Status | Witness |
|---|---|---|
| Gateway bypass refused | Covered for this composition | `MAS pilot: the gateway joins … > refuses the same estate credential on the resource's own route before any decision, though the gateway admits it (bypass)`: a whole attempt (the MCP handshake and a tool call) is refused, the handshake answered 401, with no decision request and no evidence record; the gateway permits the same credential. |
| Different issuer and client registrations | Covered | `MAS pilot: the estate is a separate issuer … > issues an ordinary RFC 9068 token under the estate issuer, with no mission claim and a client the MAS never registered`; `… > refuses to issue for a resource the client's estate registration does not name (invalid_target)`. |
| Credential-authority adapter | Covered for one format | Scope to authority from an RFC 9068 JWT: `… > bounds a joined credential by its own scope as the contract maps it`. Other formats refused: `services/mcp-payments/test/estate-route.test.ts`, `estate route: ordinary credentials only … > refuses every other credential format`. Introspection to authority is not built. |
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

Each test was proved by introducing the defect it guards against and
confirming its assertion fails.

## 7. AS capabilities and adopter code for the baseline join

What the estate AS needed, all by configuration of an unmodified library:
RFC 9068 JWT access tokens carrying `scope`, `sub` and `client_id`;
DPoP-bound tokens (`cnf.jkt`); a published `jwks_uri`; and per-client
resource and scope restrictions. RFC 7662 introspection is enabled in its
configuration and not exercised by any test.

What the adopter wrote: the gateway's resource-server configuration (trusted
estate keys, `ordinaryOnly`), the mapping contract and its cache, the estate's
Resource-policy grants, and the composition. The PEP and PDP changes are reference code
(`joinMapping`, `missionBoundOnlyClasses`, `mappingContract`).

Sender-bound Join Assertions are not built. They would additionally need the
MAS to introspect or validate the estate token and report its `cnf`
(MAS §enterprise-prerequisites), and a Join Assertion endpoint, which the
reference does not implement.

## 8. Residuals and exclusions

- **The Resource policy administers estate principals only.** A request
  whose subject is not under the estate issuer has no principal and is
  refused `resource_policy`. In MAS mode nothing issues a Mission-bound token,
  so the Mission-side direction (an estate entitlement presented for a
  Mission-side subject) is not reachable end to end; the issuer-local mapping
  that refuses it is the PDP's (`issuerLocalPrincipals`).
- **The development seed is the pilot's own** (`config/mas-pilot.json`
  `resource_policy`); a production estate attaches to its administered store.
- **Mission state is an in-process kernel read**, as on the AS-native target
  (D293). Mission Status over HTTP from a separated MAS is not built (#1101's
  concern for a separated realization).
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
  not handled.
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

## 9. Remaining slices

1. Introspection to authority: an opaque-token estate route resolving `scope`
   and `cnf` through RFC 7662, with its timeout and cache bounds.
2. A separated MAS: Mission Status over HTTP as the state source, with the
   runtime profile's freshness bounds (#1101).
3. A retained, signed mapping audit record, or the mapping version in
   evidence, if the owner selects one.
4. Sender-bound Join Assertions, and the AS capabilities they need (Sketch
   step 5's second half).
5. A launcher and an operator walkthrough for the pilot topology, attaching
   to an administered Resource-policy store.
6. Ledger: `mas.mapping-contract.floor-documented` stays `todo` (the shared
   demo's join documents no contract); the `mas.enterprise` rows stay `todo`.

The component matrix in MAS §deployment-adoption (Sketch steps 1 and 2)
merged as #1352 (D523).

## 10. Run it

From `src/`, with a live OpenFGA (`OPENFGA_HTTP_URL`, `OPENFGA_PRESHARED_KEY`,
and `OPENFGA_CA_CERT` where it serves TLS):

```sh
pnpm vitest run demo/test/mas-pilot.test.ts demo/test/mas-pilot-resource-policy.test.ts \
  demo/test/mas-pilot-mapping.test.ts services/mcp-payments/test/estate-route.test.ts \
  services/pdp/test/evaluate-join-mapping.test.ts
```

Each end-to-end file bootstraps its own development store. The estate AS
binds `127.0.0.1:14818` in `mas-pilot.test.ts` and `127.0.0.1:14824` in
`mas-pilot-resource-policy.test.ts` (the configuration relocated, so the two
files run in parallel); the gateway and resource routes bind ephemeral ports.
