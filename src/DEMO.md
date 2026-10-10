# Mission Reference Implementation — Guided Demo

## Seeing it work — three surfaces

All three need OpenFGA up (`docker compose up -d`) and run from `src/`.

1. **Live browser console** — `pnpm demo:serve`, then open
   http://localhost:4407. A clickable dashboard driving the real stack: the
   agent panel (catalog + action buttons: read, in-cap wire, over-cap wire,
   out-of-vendor wire), the operator fleet with suspend/revoke/resume, and
   the verified evidence timeline. Watch the catalog status and timeline
   update as you act; a revoke flips `payments` from connected to
   consent_required.
2. **Terminal exhibit** — `pnpm exhibit`. A narrated end-to-end walk
   (discovery → issuance → read → wire → bounds deny → vendor deny → revoke →
   verified feed) printing the real wire artifacts at each step.
3. **Distributed traces** — `pnpm demo:trace`, then open
   http://localhost:16686 and select service `mission-demo`. Each action is
   one trace: `flow.wire → pep.enforce → pdp.evaluate → fga.check`.

The three SPAs under `apps/` are production-shaped thin views; the browser
console above is the runnable interactive surface.

## The headless scenario runner

`pnpm demo` runs scenarios 0–15 against the composed in-process stack. The
scenario bodies are the per-milestone integration tests (they compose the
services in one process; OpenFGA must be up). Boot:

```
docker compose up -d          # OpenFGA (TLS + preshared) + Jaeger
pnpm -C src setup             # dev certs + .env
pnpm -C src install
pnpm -C src demo              # scenarios 0-15 + scorecard
```

## Decision-channel mode

The default is co-resident. Set `MISSION_PDP_MODE=remote` (or pass
`pdpMode: "remote"` to `composeStack`) to route the same PEP through a real
loopback HTTP PDP listener. The PDP owns its policy/view resolver and its
Decision Evidence signer; the PEP receives only the client closure and public
evidence-verification material. Resource metadata declares the effective
boundary and its per-PEP authenticated request/response mechanism.

This is a network-hop fixture in the same process, not process/key isolation
or a production TLS deployment. Its only supported outage posture is `deny`:
timeouts, unavailable or unauthenticated responses produce a local PEP
Refusal Record, never a fabricated PDP Decision. The request deadline covers
headers, body, signature verification and parsing, and response size is capped.
No permit cache, bounded outage reuse, replica mode or break-glass is enabled.
Trusted test/operator code can stop the listener with
`await stack.decisionChannel.close()`; callers composing a stack must close it
alongside its other service listeners. The agent tool surface has no such hook.

## Scenarios

| # | Scenario | Milestone |
|---|---|---|
| 0 | Discovery bootstrap (catalog, consent_required) | M8 |
| 1 | Issuance (shaper -> PAR -> Bob approves -> DPoP token) | M1 |
| 2 | Happy path (in-authority read/schedule, Decision Evidence) | M4 |
| 3 | Parameter binding / TOCTOU refusal | M4 |
| 4 | Wire transfer (permit, lease, evidence, reconciliation) | M5 |
| 5 | ARAP reevaluate (approval as input context, no new token) | M6 |
| 6 | AROP / DTR (subset-of-Mission deferred token; never expands) | M7 |
| 7 | AROP / Transaction Challenge (txn-bound single-use token) | M7 |
| 8 | Revocation freshness (revoke -> denied within bound) | M1/M3 |
| 9 | Completion (residual tokens no longer authorize) | M1 |
| 10 | Catalog reflection (status flips on approval/revocation) | M8 |
| 11 | Transparent audit (feed, five-step verify, tamper demo) | M10 |
| 12 | Cross-domain via EMA/ID-JAG (LedgerCloud, lifetime-bounded) | M9 |
| 13 | Sub-agent delegation (two-hop chain, per-instance revocation) | M12 |
| 14 | The 02:00 resume (harness stop-on-non-active) | M12 |
| 15 | An agent acting for its own workload principal (headless PAR -> Dana approves -> `sub` is the workload) | #1194 |

### Scenario 15: an agent acting for its own workload principal

`services/authorization-server/test/workload-principal-agent.test.ts`
needs no OpenFGA:

```
pnpm -C src exec vitest run services/authorization-server/test/workload-principal-agent.test.ts
```

1. The `ledger-reconciler` agent pushes its own request (PAR) and runs the
   authorization request with no user present.
2. Dana, authorized to approve for the workload principal
   `agt_ledger_reconciler` and to activate its `service_owned` source,
   approves on the trusted approval service. Bob, who may not approve for
   that Subject, is refused, and a request beyond the source's read-only
   ceiling is refused `access_denied`.
3. The record names `agt_ledger_reconciler` as Subject, `ledger-reconciler`
   as client and Dana as consent principal. The access token's `sub` is the
   workload principal, its `client_id` is the agent, and it carries no
   `act`.
4. Refresh and the agent's own Token Exchange keep that Subject and client.
5. A caller without the lifecycle grant gets the not-found response. Dana's
   lifecycle credential revokes the Mission; refresh and the exchange are
   then refused.

Delegation to a sub-agent within the same Mission, with `act` naming the
sub-agent, waits on #869.

Exhibit mode (annotated wire captures, handbook Appendix B) is a follow-on
(O-28); the scenario runner is the reproducible path today.
