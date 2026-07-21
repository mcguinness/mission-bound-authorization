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
| MCP PEP -> PDP | HTTP localhost | bearer service token (seeded, per-service) | PDP audience |
| AS <-> ARS | HTTP localhost | mutual service tokens (seeded) | each other |
| PDP -> AS (Status List, introspection) | HTTP localhost | service token; introspection uses RFC 7662 caller auth | AS |
| PDP -> OpenFGA | **TLS** (self-signed dev CA) | pre-shared key | store id + explicit `authorization_model_id` |
| Producers -> Transparency Service | HTTP localhost | service tokens | transparency audience |
| console-bff -> AS management / ARS / producers | HTTP localhost | service token carrying the operator context | each surface |

Service tokens are seeded static bearer credentials (dev-grade), one per
edge direction, loaded from demo-data on boot; nothing shared between
edges.

## Key purposes (separate keys, one `jwks_uri` with per-purpose `kid`s)

| Purpose | Holder | Surface |
|---|---|---|
| `as-token` | AS | access tokens, ID-JAGs |
| `as-status` | AS | signed Status responses + Status List tokens |
| `pdp-evidence` | PDP | Decision Evidence, Refusal Records, `binding_token` |
| `pep-evidence` | MCP payments PEP | Execution Evidence, reconciliation |
| `rs-txn` | MCP payments PEP | Transaction Authorization Challenges (`txn_challenge_jwks_uri`) |
| `ras-token` | RAS | SaaS-domain local tokens |
| `transparency` | Transparency Service | Receipts, signed tree heads |
| per-instance | each agent instance | DPoP + instance assertion `cnf` |

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
