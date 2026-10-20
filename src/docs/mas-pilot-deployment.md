# MAS pilot deployment

The pilot contract for #253's second reference path: the **legacy-estate/MAS
route** that D284 adopted and D508 ruled executable, owned by #818 (Sketch
steps 3 and 4). A legacy estate keeps its own authorization server; its
ordinary tokens are joined to Missions at a gateway, under a versioned mapping
contract. This document records slice 1 of that evidence. It is not a
conformance, production-readiness or interoperability claim, and nothing in
the AS-native target's evidence ([initial-runtime-deployment.md](initial-runtime-deployment.md))
bears on it, or the reverse (D284).

Every statement here is true of the reference implementation at `43562b98`
(paths relative to `src/`). Each names the code that does it or the exact test
(`describe > it`) that shows it. A gap says so. No test here needs a live
OpenFGA: the decision point's Resource policy and FGA client are the
reference fixtures (§7).

## 1. Components

| Component | What it is | Trust |
|---|---|---|
| Estate AS | A stock `oidc-provider` instance (`demo/src/mas-pilot/estate-as.ts`) with no Mission code: its own issuer, a signing key generated at each boot, a directory of accounts and its own client registrations. Authorization code grant with PKCE, `client_secret_basic`, resource indicators, DPoP-bound RFC 9068 JWT access tokens. | Issues ordinary tokens only. |
| MAS | The reference Mission kernel under its own issuer (`https://mas.pilot.invalid`), which issues no tokens in this mode. | Holds the Missions the joins name. |
| Gateway route | A MAS-governed HTTP MCP route (`createHttpMcpChannel(…, { masGoverned: true })`) whose resource server trusts only the keys the estate publishes at its `jwks_uri`, fetched over HTTP at boot, and sets `ordinaryOnly` (`services/mcp-payments/src/server.ts`). | Admits estate credentials, and only through the join. |
| Resource route | The payments resource's own Mission-bound route, trusting only the Mission Issuer's keys. Nothing signs with them in MAS mode. | Admits no estate credential. |
| PEP and PDP | The reference `Pep` and decision point over one payments store. Every crossing on either route goes through the PEP. | Apply the join, the credential bound and Resource policy. |

The composition is `composeMasPilot` (`demo/src/mas-pilot/compose.ts`); its
configuration is `config/mas-pilot.json`, read by a strict loader
(`demo/src/mas-pilot/config.ts`). Client secrets and keys are generated at
each boot.

The estate's client identifiers (`estate-ap-bot-7f3`, `estate-extractor-2c1`,
`ap-agent`) are registered at the estate only; the Mission client they map to
is a separate identifier in the Mission Issuer's namespace. The estate
deliberately registers a client named `ap-agent`, the Mission's own
`client_id`, and an account named `alice`, the Mission subject's `sub`, so the
namespace tests in §5 run against real estate registrations.

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
- The scope mapping is part of the contract, so the credential-authority
  mapping has the same freshness. With no usable snapshot the PEP refuses
  `out_of_authority` before any decision, and the PDP would deny
  `mission_binding_failed`.
- The cache keeps an audit record of every identity decision (version, export
  identifier, the estate identities, the outcome), every install, refused
  install and invalidation. The record is in memory only (§7).

## 4. Routes and consequential-path inventory

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
not include. Without the reservation, the remittance test permits the
remittance: the reservation is the control, not a side effect of another
check. This is the pilot's inventory choice; the reference claims no
`mas.enterprise` capability.

## 5. What slice 1 witnesses

Against D284's evidence list (tests in `demo/test/mas-pilot.test.ts` unless
named):

| D284 requirement | Status | Witness |
|---|---|---|
| Gateway bypass refused | Covered for this composition | `MAS pilot: the gateway joins … > refuses the same estate credential on the resource's own route before any decision, though the gateway admits it (bypass)`: 401, no decision request, no evidence record; the gateway permits the same credential. |
| Different issuer and client registrations | Covered | `MAS pilot: the estate is a separate issuer … > issues an ordinary RFC 9068 token under the estate issuer, with no mission claim and a client the MAS never registered`; `… > refuses to issue for a resource the client's estate registration does not name (invalid_target)`. |
| Credential-authority adapter | Covered for one format | Scope to authority from an RFC 9068 JWT: `… > bounds a joined credential by its own scope as the contract maps it`. Other formats refused: `services/mcp-payments/test/estate-route.test.ts`, `estate route: ordinary credentials only … > refuses every other credential format`. Introspection to authority is not built. |
| Mapping provenance and freshness | Covered | `demo/test/mas-pilot-mapping.test.ts`, `mapping contract cache: versions and freshness …` (reassignment, refused rollback, staleness bound, invalidation) and `… > resolves two estate accounts mapped to one Mission subject, and audits which account each decision resolved`. |
| Same `sub` or `client_id` in another namespace | Covered | `… > never conflates an estate client registered under the Mission's own client_id string`; `… > never conflates estate account "alice" with the Mission subject alice`; PDP: `services/pdp/test/evaluate-join-mapping.test.ts`. |
| Disabled accounts | Covered | `… > denies a disabled estate account whose row still names the Mission's subject`. |
| Reassigned accounts | Covered | `MAS pilot: a newer contract version moves a reassigned account … > an outstanding estate token for u-1001 stops joining alice's Mission once version 2 reassigns the account to dana`. |
| Many-to-one mappings | Covered | `… > joins two estate accounts mapped to one Mission subject (many-to-one), and the audit log keeps which account acted`. |
| Missing delegate records | Covered | `MAS pilot: delegates need a recorded actor edge … > denies a mapped delegate with no actor record, then joins it once the deployment records the edge`. |
| Joined token never takes the high-consequence posture | Covered for the pilot's reservation | `MAS pilot: a joined ordinary token never takes a high-consequence path … > denies a remittance under a joined credential whose scope and Mission both carry it, commits nothing, and still permits the joined read`; an estate token carrying a `mission` claim is refused: `estate-route.test.ts > … > refuses an estate token carrying a mission claim, which a Mission Issuer's route admits as Mission-bound`. |

Each test was proved by introducing the defect it guards against and
confirming its assertion fails.

## 6. AS capabilities and adopter code for the baseline join

What the estate AS needed, all by configuration of an unmodified library:
RFC 9068 JWT access tokens carrying `scope`, `sub` and `client_id`;
DPoP-bound tokens (`cnf.jkt`); a published `jwks_uri`; and per-client
resource and scope restrictions. RFC 7662 introspection is enabled in its
configuration and not exercised by any test.

What the adopter wrote: the gateway's resource-server configuration (trusted
estate keys, `ordinaryOnly`), the mapping contract and its cache, and the
composition. The PEP and PDP changes are reference code
(`joinMapping`, `missionBoundOnlyClasses`, `mappingContract`).

Sender-bound Join Assertions are not built. They would additionally need the
MAS to introspect or validate the estate token and report its `cnf`
(MAS §enterprise-prerequisites), and a Join Assertion endpoint, which the
reference does not implement.

## 7. Residuals and exclusions

- **Resource policy and FGA are fixtures.** Independently administered
  Resource policy for estate identities is not witnessed; an
  OpenFGA-backed composition is a later slice.
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
- **No launcher:** the pilot runs in its tests only.
- The shared demo's MAS-governed channel (`config/mas-join.json`) is
  unchanged and keeps its shared-namespace join.

## 8. Remaining slices

1. An OpenFGA-backed composition: Resource policy entitlements for estate
   identities, administered independently of the mapping.
2. Introspection to authority: an opaque-token estate route resolving `scope`
   and `cnf` through RFC 7662, with its timeout and cache bounds.
3. A separated MAS: Mission Status over HTTP as the state source, with the
   runtime profile's freshness bounds (#1101).
4. A retained, signed mapping audit record, or the mapping version in
   evidence, if the owner selects one.
5. Sender-bound Join Assertions, and the AS capabilities they need (Sketch
   step 5's second half).
6. A launcher and an operator walkthrough for the pilot topology.
7. The component matrix and upgrade-path paragraph in MAS
   §deployment-adoption (Sketch steps 1 and 2), a draft change outside
   this slice.
8. Ledger: `mas.mapping-contract.floor-documented` stays `todo` (the shared
   demo's join documents no contract); the `mas.enterprise` rows stay `todo`.

## 9. Run it

From `src/`:

```sh
pnpm vitest run demo/test/mas-pilot.test.ts demo/test/mas-pilot-mapping.test.ts \
  services/mcp-payments/test/estate-route.test.ts services/pdp/test/evaluate-join-mapping.test.ts
```

The estate AS binds `127.0.0.1:14818`; the gateway and resource routes bind
ephemeral ports.
