# Pre-Flight Spike Report

Date: 2026-07-21. Resolves O-1, O-2, O-25, O-26, O-27; pins per D38/D39.
Spike code: `src/spikes/oidc-provider/` (throwaway-grade; `node spike.mjs`).

## O-2: node-oidc-provider fit — GO (with one adapter route)

`oidc-provider@9.10.0` (current latest) passes 10/11 empirical checks:

| Capability | Result |
|---|---|
| PAR + RAR (typed validators) + DPoP + introspection + resource indicators + extraParams together | PASS |
| `mission_intent` as a validated PAR extra param (JSON check, reject-both rule, malformed → `invalid_request`) | PASS |
| `mission_intent` flows to the interaction (`Interaction.find(uid).params`) for derivation/rendering | PASS |
| Issuer-derived RAR: `Grant.prototype.addRar` + `AccessToken.rar` exist | PASS |
| Custom grants register and are reachable (`...token-exchange`, `...deferred`); handler signature `async (ctx) => {}`, no `next()` | PASS |
| `extraTokenClaims` mints the `mission` claim into a JWT AT (verified by decode) | PASS |
| Built-in introspection of JWT-format ATs | **FAIL — by design**: `unsupported_token_type: Structured JWT Tokens cannot be introspected via the introspection_endpoint` |

**Decision: GO on node-oidc-provider.** The D30 fallback (custom endpoints
beside the provider) is invoked for exactly one surface: the
**introspection route is adapter-implemented** in the mission-kernel's
adapter layer (RFC 7662 semantics + the Status draft's mission projection;
parse JWT, check jti/revocation, load mission state). This also has to
satisfy CIA-CORE's rule that introspection responses mirror the JWT AT
claim set (`act`, `sub`, `sub_profile`, `client_id`, `cnf`).

Implementation notes captured for M1:
- RAR is an **experimental** feature: `features.richAuthorizationRequests`
  requires `ack: 'experimental-01'` and may break on minor updates —
  reinforces the exact-pin policy (D39).
- A client without `authorization_details_types` metadata cannot submit the
  `mission_resource_access` type at all: raw client submission of the
  issuer-derived type is rejected automatically (`invalid_authorization_details`).
- Node 22 LTS required (Node 23 triggers an unsupported-runtime warning).

## O-1: Mission Intent PAR carriage (core § submission-via-par)

- Parameter `mission_intent`: UTF-8 JSON serialization of the Intent,
  form-encoded in the PAR body. The ONLY carriage: front-channel
  `mission_intent` without a PAR `request_uri` → `invalid_request`; no
  request-object unwrapping.
- Closed top level (`invalid_request` on unknown members); extension data
  under `controls`. Bounded size (deployment limits).
- Well-formed but underivable Intent → `invalid_authorization_details`
  (distinguishes derivation failure from syntax).
- `mission_intent` + raw `authorization_details` → `invalid_request`
  (mutually exclusive); `scope`/`resource` allowed as a requested subset.
- On `request_uri` redemption, front-channel `mission_intent` /
  `authorization_details` / `scope` / `resource` are ignored; never widen.

## O-25: CIA-CORE carriers (pinned)

- JWS `typ`: `client-instance+jwt`; RFC 8693 `actor_token_type` URN:
  `urn:ietf:params:oauth:token-type:client-instance-jwt` (two different
  strings — do not conflate).
- Presentation: `client_instance_assertion` form param on
  authorization_code / client_credentials / refresh_token / jwt-bearer;
  as `actor_token` ONLY on token exchange (mutually exclusive rules).
- Claims: `iss`, `sub`, `aud`, `client_id` (octet-for-octet binding to the
  authenticated client), `exp`, `iat`, `jti`; `cnf` with exactly one of
  `jkt` / `x5t#S256`, minted from a **per-instance** key (client-wide keys
  insufficient); `sub_profile` RECOMMENDED; **MUST NOT contain `act`**.
- Algorithms: asymmetric only, ES256 MTI; reject `none`/HMAC.
- Token endpoint: 12-step processing; `(iss, jti)` replay cache ordered
  AFTER client_id binding and PoP; precise error taxonomy
  (`invalid_request` vs `invalid_grant` vs `unsupported_token_type`;
  re-coded to `invalid_client` when used as the client-auth method).
- Chain merge: assertion becomes the new outermost `act`
  (`{iss, sub, sub_profile, cnf?}`); inbound `subject_token` chain
  preserved verbatim beneath; self-acting omits `act`. Issued token's
  top-level `cnf` = assertion `cnf`; bearer issuance forbidden; refresh
  stays bound to the same instance key.
- Client Attestation carrier: headers `OAuth-Client-Attestation` (+ DPoP
  combined mode per ai-agent-instance); its `typ` is defined by the
  external attestation-based-client-auth spec, not locally — do not
  hardcode. Precedence: the Client Instance Assertion wins; key and
  `agent_instance_id` consistency across both artifacts or `invalid_grant`.
- **actor-profile#4 input**: CIA-CORE § security-binding already states
  PoP validates against top-level `cnf` ONLY and `act.cnf` is
  audit/correlation metadata (outermost `act.cnf` always equals top-level
  `cnf` by construction). Noted on the upstream issue.

## O-26: entity-profile vocabulary (pinned)

Pinned against draft-mora-oauth-entity-profiles rev 01 (local working copy
2026-04-12). Seven registered values; `sub_profile` is space-delimited,
**case-insensitive**, unordered, tokens `1*( ALPHA / DIGIT / "-" / "_" / "." )`.
Position-keyed validity (registry Usage Location):

- Top-level `sub_profile`: `user`, `device`, `service`, `ai_agent`.
- `act[].sub_profile`: `user`, `service`, `ai_agent`, plus
  `client_instance` (registered by CIA-CORE, Actor Profile usage only).
- `native_app` / `web_app` / `browser_app` are Client Profile only.
- Unknown-but-syntactically-valid values are preserved, not rejected.

Spec observation (S-7): rev 01 names Designated Experts but states no
formal IANA registration policy keyword.

## O-27: chain depth and presenter transitions (decided)

- Local max delegation depth: **4** (the profile's SHOULD), counted on the
  resulting chain; exceeding → `invalid_request`, never truncate.
- Sub-agent spawn = **presenter rebind** (validated `actor_token` — the
  sub-agent's instance assertion — identifies the new presenter; token's
  `cnf` becomes the sub-agent's key).
- Self-exchange down-scoping = **presenter continuation** (inbound
  presenter kept; requires PoP-capable inbound `cnf`).

## Version pins (D39)

| Dependency | Pin |
|---|---|
| `oidc-provider` | `9.10.0` (exact; RAR ack `experimental-01`) |
| Node | 22 LTS (`engines`) |
| `@modelcontextprotocol/sdk` | `1.29.0`; MCP authorization profile 2025-11-25 (D38) |
| OpenFGA image | `openfga/openfga:v1.18.1@sha256:efde89d24487da1a8bc37d85b61341f1fb7024943a1ded65f4b7d51a75666688` |
