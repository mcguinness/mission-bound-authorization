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
same `kid` across restarts. The PEP's and the PDP's evidence keys come from
evidence key files or are generated at each boot (#831): `pnpm evidence-keys
init` creates the files once, and the stack signs under the same keys at
every boot when it is given them. Every other key below is generated at each
boot.

A ring keeps each role's generations. Generation 1 is under the `kid` below,
generation `n` under `<kid>-<n>`, and a role signs under its one `active`
generation.

The AS reads the ring only at boot, so a successful edit is not a completed
change. Every change follows one procedure: stop the AS, edit the ring
(`pnpm keys`), start the AS, then `pnpm keys verify`. Each edit advances the
ring's `revision`, and the AS serves the revision it loaded as its `/jwks`
`ETag`. `verify` reads the running AS's metadata and `/jwks`, refuses unless
they carry this revision and exactly the ring's pending, active and overlap
generations, and records what that confirms: when a generation was first
published, when the AS stopped signing under it, and when it was withdrawn.
One operator edits a ring at a time; nothing locks it.

- `pnpm keys rotate` stages a `pending` generation, published once the AS
  restarts, not signing.
- `pnpm keys rotate --activate` makes it the signer once it has been
  confirmed published for the `/jwks` freshness lifetime
  (`Cache-Control: max-age`, 300 seconds). The previous generation moves to
  `overlap`: still published, accepted by the AS's verifiers (the
  provider's `id_token_hint` check included, as a verify-only key), and
  without its private key.
- `pnpm keys retire` removes an `overlap` generation after its retention
  deadline: the confirmed stop, plus the longer of the audit horizon
  (`policy.audit_horizon_s`) and the longest Mission lifetime
  (`policy.max_mission_lifetime_s`). With no Mission lifetime bound, which is
  the shipped policy, no deadline can be established and retirement is
  refused. A Status generation is also refused while a standing
  governed-policy consent is attested under it, counted from the kernel
  store (`--kernel-store`, or `MISSION_KERNEL_STORE`); `--in-memory-kernel`
  asserts there is none to count. A `pending` generation retires at once.
- `pnpm keys compromise` withdraws a generation, from `/jwks` and from every
  verifier the AS runs, recording its revocation time and any established
  compromise time. Compromising the active generation activates a fresh
  replacement in the same write, with no pre-publication; a consumer
  authorizes that replacement only through its own trusted rotation, since
  publication alone grants no trust.
- `pnpm keys migrate` converts a slice 1 ring, which still loads, before any
  of these.

| `kid` | Holder | Signs | Source |
|---|---|---|---|
| `as-token` | AS | access tokens and ID Tokens, child grants, Dispatch Handoff grants, cross-org access tokens, the dev ordinary token | key ring or per boot |
| `as-status` | AS kernel | Status responses, the Status List token, discharge receipts, and the records signed through the kernel's status signer (carryover evidence, governed-policy consents, approval-governance records) | key ring or per boot |
| `as-txn` | AS | transaction tokens | key ring or per boot |
| `as-continuation` | AS | the continuation ID-JAG | key ring or per boot |
| `as-crossdomain` | demo stack, not on the AS JWKS | the cross-domain ID-JAG (`demo/src/stack.ts`, `xdKeys`) | per boot: with the RAS's single-use claims in memory, this protects a coordinated restart of the whole stack only; a durable redemption store keeps them across an independent RAS restart too (#1767) |
| `rs-txn` | MCP payments PEP | Transaction Authorization Challenges, published at `txn_challenge_jwks_uri` (`stack.ts`, `rsTxnKeys`) | per boot: its challenges and the resource's pending store live in memory, so a restart fails closed |
| `ras-token` | RAS | SaaS-domain local tokens (`stack.ts`, `rasKeys`) | per boot: nothing it signs is persisted |
| `pdp-decision-evidence` | PDP | Decision Evidence and PDP Refusal Records (`stack.ts`, `decisionEvidenceKeys`) | evidence key file (`MISSION_PDP_EVIDENCE_KEYS`) or per boot |
| `ephemeral-pep`, `ephemeral-executor`, `ephemeral-receipt_issuer` | MCP payments PEP | Execution Evidence and Refusal Records (`demo/src/evidence-key-files.ts`; per boot, `services/mcp-payments/src/ephemeral-signer.ts`) | evidence key file (`MISSION_PEP_EVIDENCE_KEYS`) or per boot; the identifiers are retained, though "ephemeral" no longer describes every deployment |
| `pdp-evidence` | PDP, as producer | Transparency Signed Statements (`stack.ts`, `pdpProducerKeys`) | per boot: nothing it signs is persisted |
| `transparency` | Transparency Service | receipts (`stack.ts`) | per boot: its log is in memory |
| `ars` | Access Request Service | ARAP approval JWS (`stack.ts`) | per boot: pending tasks end with their owner (D39) |
| `*-auth` client keys | each client (the demo AS generates them) | `private_key_jwt` client assertions | per boot |
| per-instance | each agent instance | DPoP proofs and the instance assertion `cnf` | per instance |

The AS publishes every live generation of `as-token`, `as-status`,
`as-txn` and `as-continuation` at `/jwks`. The payments resource, the RAS
and the separated MAS pilot's PDP hold that set through `IssuerKeys`
(#831 C): per role, only the `kid`s their configuration trusts, refreshed
within the freshness `/jwks` declares, and refused when a stale set cannot
be revalidated. A rotation reaches them once their trusted `kid`s name the
new generation and they reload (`SIGUSR2`); publication alone grants no
trust.

A per-boot key under a fixed `kid` strands whatever it signed that
outlives the process. The evidence keys are the only keys outside the AS's
four whose signatures sit in a durable store. `pnpm evidence-keys init`
creates one file per holder (the PEP's three keys, the PDP's one; #741), and
with `MISSION_PEP_EVIDENCE_KEYS` and `MISSION_PDP_EVIDENCE_KEYS` the stack
signs under the same keys at every boot and publishes their key sets to a
durable file beside the retention file: each boot republishes the same keys,
a no-op, and a regenerated file is refused at publication
(`EvidenceRetentionStore.publishKey`) rather than stranding the records the
old key signed. Without them, the evidence keys stay per boot, their key
sets in memory, and a restart leaves the records an earlier boot signed
unverifiable. The other per-boot keys sign nothing that is persisted, or,
like `as-crossdomain`, stay per boot under D366. With the RAS's single-use
claims in memory, that protects only a coordinated restart of the whole
stack: an independent RAS restart lets a base or continuation ID-JAG it
already redeemed redeem again while its signing key still verifies. A
durable redemption store closes that (#1767): the RAS claims each grant's
issuer and `jti` atomically before it mints, and keeps the claim until the
grant's `exp` plus 300 s, so a grant redeemed before a restart is refused
after it, whichever key signed it. A restored older copy of the store loses
the claims made after it was taken, and nothing detects that (D901).

Post-D26 note: there is no AS->PDP materialization artifact to
authenticate; `policy_view_id` is a content commitment, not a credential.

### Durable or per boot: what the library supports and what each launcher chooses

The library supports both forms of each; the launchers differ in which they
require.

| Material | Library support | Launcher wiring |
|---|---|---|
| AS role keys (`as-token`, `as-status`, `as-txn`, `as-continuation`) | a key ring (`signingKeys: { ring }`, created by `pnpm keys init`), checked against a key binding record when given one (`signingKeys: { ring, bindings }`, #1815), or keys generated per boot | `pnpm as-native`, `pnpm issuance-only` and the MAS pilot's launchers require `MISSION_KEY_RING` with its key binding record `MISSION_KEY_BINDINGS`, or `MISSION_EPHEMERAL_KEYS=1`; `pnpm demo:serve` and the other demos run per boot |
| Evidence keys (`ephemeral-pep`, `ephemeral-executor`, `ephemeral-receipt_issuer`, `pdp-decision-evidence`) | evidence key files (`composeStack`'s `evidenceKeys`, created by `pnpm evidence-keys init`, loaded before anything listens), or keys generated per boot | `pnpm as-native` requires `MISSION_PEP_EVIDENCE_KEYS` and `MISSION_PDP_EVIDENCE_KEYS`, or `MISSION_EPHEMERAL_EVIDENCE_KEYS=1`; `pnpm demo:serve` takes the two files optionally, per boot without them; `pnpm measure:evidence` runs per boot |
| The RAS's single-use ID-JAG claims (not a key: what keeps a key that survives a restart from redeeming a grant twice) | a durable redemption store (`RasConfig.redemptions`, `composeStack`'s `rasRedemptions`, created by `pnpm ras-redemptions init`), or in memory | `pnpm as-native` requires `MISSION_RAS_REDEMPTIONS` whenever `MISSION_KEY_RING` is set, and refuses a missing or uninitialized store; every other composition that runs the RAS keeps its claims in memory, under per-boot keys |

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
