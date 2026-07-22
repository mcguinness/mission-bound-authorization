# Spec Traceability Matrix

The record of every spec this implementation implements, the exact version
implemented against, where it lands in the code, and the tests that prove
it. This is how a spec update becomes a change list: diff the spec from its
pinned version to the new one, then follow the touched sections through
this matrix and the `@spec` tags to the affected code and tests.

## Conventions

- **Pins.** In-repo drafts pin the last commit that touched the draft file
  (`git log -1 -- <draft>.md`). External specs pin a revision, tag, PR head
  SHA, or dated snapshot. Dependencies that embody a spec surface pin an
  exact version.
- **`@spec` tags.** Source code implementing spec-derived behavior carries
  a greppable comment tag: `@spec <doc>#<section>` (e.g.
  `@spec mission#integrity-anchors`). One tag per behavior, at the
  narrowest enclosing scope. `grep -rn "@spec mission#"` answers "where
  does the core land in the code."
- **Updating a pin.** Deliberate, never implicit (D25/D41): diff the spec
  old→new, grep the changed section anchors against `@spec` tags, list the
  affected modules and tests in the bump commit message, review against the
  Spec Feedback Log (a bump may resolve an S-entry), then update the row.
- One row per (spec, implementing component); a spec spanning components
  gets multiple rows.

## Implemented (updated per milestone)

| Spec | Pinned version | Component | Surfaces (`@spec` doc key) | Tests |
|---|---|---|---|---|
| `draft-mcguinness-oauth-mission` | `c2053e5` (2026-07-17) | `packages/mission-core` | `mission#integrity-anchors`, `mission#canonicalization`, `mission#test-vectors` | `packages/mission-core/test/anchors.test.ts` |
| `draft-mcguinness-oauth-mission` | `c2053e5` (2026-07-17) | `services/authorization-server` (kernel + adapters) | `mission#submission-via-par`, `mission#mission-intent`, `mission#authorization-derivation`, `mission#subset`, `mission#integrity-anchors`, `mission#the-mission-claim`, `mission#lifecycle`, `mission#introspection`, `mission#as-metadata` | `services/authorization-server/test/{kernel,tracer}.test.ts` |
| `draft-mcguinness-oauth-mission-status` | `89ba0b4` (2026-07-16) | `services/authorization-server` (kernel + adapters) | `status#legal-transitions`, `status#state-machine`, `status#mission-status-response` | `services/authorization-server/test/{kernel,tracer}.test.ts` |
| `oidc-provider` | `9.10.0` (RAR ack `experimental-01`) | `services/authorization-server/src/adapters` | PAR, RAR (issuer-derived via `rarFor*`), DPoP, resource indicators, custom routes | `services/authorization-server/test/tracer.test.ts` |

## Adopted for planning, not yet implemented (pins from the pre-flight spike)

| Spec | Pinned version | Lands in |
|---|---|---|
| `draft-mcguinness-mission-runtime` | `02d53dd` | M4/M5 PEP + PDP |
| `draft-mcguinness-mission-authzen` | `02d53dd` | M3 PDP, M4 PEP |
| `draft-mcguinness-oauth-mission-status` (Status List, introspection projection) | `89ba0b4` | M3 freshness |
| `draft-mcguinness-oauth-actor-profile` | local repo @ spike date 2026-07-21 | M2 |
| CIA-CORE (`client-instance-assertion`) | local `-latest` @ 2026-06-23 | M2 |
| `draft-mcguinness-oauth-ai-agent-instance` | rev 00 | M2 |
| `draft-mora-oauth-entity-profiles` | rev 01 (local 2026-04-12) | M2 (`sub_profile` allowlists) |
| AuthZEN ARAP / AROP | openid/authzen PR #531 head @ 2026-07-20 | M6/M7 |
| `draft-mcguinness-svc-connectivity-disco` | repo main @ 2026-07-20 | M8 |
| `draft-mcguinness-oauth-mission-cross-domain` + ID-JAG | in-repo / datatracker current | M9 |
| `draft-mcguinness-mission-audit` + SCITT (RFC 9943) | in-repo current | M10 |
| MCP authorization profile | 2025-11-25 (stable) | M4/M8/M9 |
| `@modelcontextprotocol/sdk` | 1.29.0 | M4 |
| OpenFGA | `v1.18.1@sha256:efde89d2...6688` | M0 compose (done) |

## Notes

- `oidc-provider@9.10.0` ships no first-party TypeScript types; the build
  depends on `@types/oidc-provider@9.5.0` (behind the runtime). Gaps handled
  with narrow local aliases (e.g. `InvalidAuthorizationDetails`, present at
  runtime in 9.10, absent from the 9.5 types). Re-check on any provider bump.
