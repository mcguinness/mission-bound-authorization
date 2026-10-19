# Channel, Authentication, and Key Matrix

Decision D39/D40. Every edge in the deployment, its channel, and the
credential presented. Dev transport is HTTP on localhost except where
noted; the matrix is the contract, the transport hardening is deployment
detail.

## Edges

| Edge | Channel | Client credential | Audience/binding |
|---|---|---|---|
| Browser -> console-bff | HTTPS (dev: HTTP localhost) | HttpOnly SameSite session cookie | per-persona session |
| Browser -> agent-console (agent service BFF) | same | session cookie | agent service session |
| Agent service -> AS | HTTP localhost | `private_key_jwt` + DPoP proof (separate keys, D38) | AS issuer |
| Agent service -> MCP servers | HTTP localhost | DPoP-bound access token | canonical resource URI |
| MCP PEP -> PDP | in process (co-resident, the default), or a loopback HTTP hop (`MISSION_PDP_MODE=remote`) | remote: request and response MACs under a secret generated per channel (`services/pdp/src/decision-channel.ts:64`) | PDP audience |
| AS <-> ARS | HTTP localhost | mutual service tokens (seeded) | each other |
| PDP -> AS (Status List, introspection) | HTTP localhost | service token; introspection uses RFC 7662 caller auth | AS |
| PDP -> OpenFGA | **TLS** (self-signed dev CA) | pre-shared key | store id + explicit `authorization_model_id` |
| Producers -> Transparency Service | HTTP localhost | service tokens | transparency audience |
| console-bff -> AS management / ARS / producers | HTTP localhost | service token carrying the operator context | each surface |

Service tokens are seeded static bearer credentials (dev-grade), one per
edge direction, loaded from demo-data on boot; nothing shared between
edges.

## Key purposes (separate keys, per-purpose `kid`s)

The AS's four role keys come from a key ring or are generated at each boot
(#831): a key ring, created once by `pnpm keys init`, keeps them under the
same `kid` across restarts. Every other key below is generated at each boot.

| `kid` | Holder | Signs | Source |
|---|---|---|---|
| `as-token` | AS | access tokens and ID Tokens, child grants, Dispatch Handoff grants, cross-org access tokens, the dev ordinary token | key ring or per boot |
| `as-status` | AS kernel | Status responses, the Status List token, discharge receipts, and the records signed through the kernel's status signer (carryover evidence, governed-policy consents, approval-governance records) | key ring or per boot |
| `as-txn` | AS | transaction tokens | key ring or per boot |
| `as-continuation` | AS | the continuation ID-JAG | key ring or per boot |
| `as-crossdomain` | demo stack, not on the AS JWKS | the cross-domain ID-JAG (`demo/src/stack.ts:581`) | per boot |
| `rs-txn` | MCP payments PEP | Transaction Authorization Challenges, published at `txn_challenge_jwks_uri` (`stack.ts:432`) | per boot |
| `ras-token` | RAS | SaaS-domain local tokens (`stack.ts:583`) | per boot |
| `pdp-decision-evidence` | PDP | Decision Evidence (`stack.ts:731`) | per boot |
| `ephemeral-pep`, `ephemeral-executor`, `ephemeral-receipt_issuer` | MCP payments PEP | Execution Evidence and Refusal Records (`services/mcp-payments/src/ephemeral-signer.ts:124`) | per boot |
| `pdp-evidence` | PDP, as producer | Transparency Signed Statements (`stack.ts:1080`) | per boot |
| `transparency` | Transparency Service | receipts (`stack.ts:1078`) | per boot |
| `ars` | Access Request Service | ARAP approval JWS (`stack.ts:379`) | per boot |
| `*-auth` client keys | each client (the demo AS generates them) | `private_key_jwt` client assertions | per boot |
| per-instance | each agent instance | DPoP proofs and the instance assertion `cnf` | per instance |

The AS publishes `as-token`, `as-status`, `as-txn` and `as-continuation`
at `/jwks`. The payments resource takes its copy once, at assembly
(`stack.ts:555`), and accepts per role only the `kid`s it pins
(`services/mcp-payments/src/key-roles.ts`). With a key ring, an AS restart
changes nothing the resource holds. Rotation and resource-side refresh are
#831's next slice.

A per-boot key under a fixed `kid` breaks anything that outlives the
process. A file-backed evidence store refuses its second boot, because the
PEP republishes its `ephemeral-*` kids with new material
(`services/mcp-payments/src/evidence-retention.ts:460`). Records those keys
signed stop verifying after a restart. Both are #831's to close, role by
role.

Post-D26 note: there is no AS->PDP materialization artifact to
authenticate; `policy_view_id` is a content commitment, not a credential.

## Trusted-base statement (D40)

Untrusted: the shaper and its proposals, the agent (both modes), all tool
*outputs*, all browser input, everything crossing from the SaaS domain
except signatures we verify. Trusted: the AS (issuer + kernel), PDP, ARS,
the two PEPs within their own estates, the Transparency Service, and the
seeded connectors (ledger, outbox, journal) as side-effect oracles. The
headless adjudication path is trusted but test-only: disabled outside dev,
and its use is visible in evidence. Evals score containment against this
statement; a "compromise" of any untrusted component must produce zero
unauthorized side effects.
