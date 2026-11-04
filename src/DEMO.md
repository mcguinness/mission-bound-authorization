# Mission Reference Implementation: Guided Demo

## The story: one Mission's life in seven steps

`pnpm demo:serve`, then open the operator link it prints. The console opens
in story mode: a bar at the bottom walks seven steps, each driven by real
calls against the composed stack. Press the right arrow key (or the bar's
main button) to run each step. A step that needs a person (Bob approving,
the operator revoking) waits for it with no time limit; the same button
performs that step, or click the highlighted button on the card.

The agent starts with two Missions: a payments task and a read-only
reconciliation task, both approved at boot. Every verdict on screen is the
PDP's or the authorization server's own answer; raw responses and token
claims sit one click away under each card.

| # | Step | Say | Click | Notice |
|---|---|---|---|---|
| 1 | The question | Agents hold delegated authority for hours, across many systems. When something looks wrong, someone has to ask what this task may still do, and how to end it. Identity cannot answer a question about a task. Only a record of the task can. | (nothing) | The two Missions at the top: who each is for, who approved it, what it may do, when it ends. The access token lasts 5 minutes; the Mission lasts 61 days. |
| 2 | The ask | Alice asks her agent to pay Acme and Globex invoices, up to $900. The agent's proposal is untrusted. | Check the proposal | Globex is struck out and the limit drops from $900 to $500. A compromised agent can propose more; it can never be granted more. |
| 3 | The approval | Bob approves a task, not a list of scopes. | Send to Bob, then Approve as Bob | Bob's card: the goal, what the agent may do, until when, what policy already removed, and the sign-in check. The new Mission joins the top row as Acting. |
| 4 | The work stays in bounds | Every tool call carries the Mission; the PDP checks it before anything moves. | Run the Mission | Decisions: $125 to Acme permitted; $900 refused `out_of_authority`, over the $500 limit; Globex refused, not a vendor the Mission names; the remittance waits for a person. |
| 5 | A person, just in time | This approval binds one action and its exact parameters, and grants nothing else. | Approve the remittance | The card shows the parameter digest. The agent retries on its own and the remittance is permitted. |
| 6 | Something looks wrong | It is 2 a.m. The operator asks the task's record what it may still do, then ends it. | Revoke the Mission | "What may this task still do? Nothing." The card is stamped Revoked. The same read is refused under the revoked Mission and permitted under the reconciliation Mission. Nobody went looking for tokens. |
| 7 | The receipt | The task is over; its record is not. Every decision was signed and logged, and the console checks each one. | Alter one record | Every row verifies; after the rewrite, one row fails at step 5 (the evidence digest no longer matches). Close: identity answers who is acting, entitlements what a principal may hold, and a Mission what work was approved and whether it is still in force. |

Presenter notes:

- The operator session ends 30 minutes after the server starts, and the
  console then says so; restart the server shortly before presenting.
- Restart the server to replay: inv-1 settles once per process, so step 4
  and the record rewrite in step 7 play differently on a second run in the
  same process.
- Approving a Mission that moves money needs Bob's login within 300 seconds
  (`config/approval-floor.json`). Bob's card shows the check; past the bound
  the card asks for a new login, and "Approve as Bob" logs in again first.
  The login is simulated: the shared demo has no Approver identity provider.
- The agent renews an access token about to lapse with its refresh token;
  the Decisions feed shows each renewal. After a revoke the authorization
  server refuses the renewal (`invalid_grant`), and a read under the revoked
  Mission is refused `mission_inactive` or, once its token has lapsed,
  `credential_invalid`.
- Large text enlarges the console for a projector. Story hides the bar for
  free exploration: the Request, Agent, Approvals and Operator views keep
  every action, including reads and wires under a chosen Mission.
- Two things are demo-only: the record rewrite in step 7
  (`POST /bff/operator/missions/:id/tamper`, which edits one retained
  execution record behind the transparency log) and the simulated login.
  Everything else is the composed stack.

## Seeing it work: three surfaces

All three need OpenFGA up (`docker compose up -d`) and run from `src/`.

1. **Live browser console**: `pnpm demo:serve`, then open the operator link
   it prints. The story above, plus free exploration: the agent's Missions,
   the catalog and action buttons (read, in-cap wire, over-cap wire,
   out-of-vendor wire, the remittance that needs approval), Bob's
   approvals, the operator fleet with suspend, revoke and resume, and the
   verified evidence timeline.
2. **Terminal exhibit**: `pnpm exhibit`. A narrated end-to-end walk
   (discovery, issuance, read, wire, bounds deny, vendor deny, revoke,
   verified feed) printing the real wire artifacts at each step.
3. **Distributed traces**: `pnpm demo:trace`, then open
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

## Standing payments

The composition behind
`pnpm demo:serve`, `pnpm exhibit` and `pnpm agent` enables standing-payment
dispatch and budget metering (#813, #816) from `config/standing-payment.json`
(see `config/README.md`); no other deployment enables either. Its one
Dispatch Policy, `ap-standing-payment` version 1, pays approved Acme
invoices to `acct-acme-001`, at most 500.00 USD per payment and per
instance, within the 1000.00 USD budget `payments-operator/ap-standing-payments`
shared by every instance. A human consents to a template under it on the
approval surface; the Dispatcher then dispatches instances unattended within
86400 seconds of that consent, with 60 seconds of clock skew allowed.
`demo/test/standing-payment-shipped.test.ts` runs this configuration.

Accepted limitations (D907, D1143):

- The idempotency scope keeps the Mission. An Expansion successor
  presenting its predecessor's key takes a new claim on the same budget
  counters. The payments ledger's one-settlement-per-invoice rule then
  refuses the wire within a process, but it is a separate guard, not
  lineage-wide idempotency, and the in-memory ledger does not survive a
  restart.
- Neither limitation lets a same-Mission claim lapse before the Mission's
  `expires_at`. The claim store is a file
  (`topology.json` `stores.pdpIdempotencyClaims`), and a composition
  restarted on the same claim, reservation and kernel files refuses a
  same-Mission duplicate `duplicate_suppressed` against the retained claim,
  past the published idempotency horizon too, and charges nothing.
- These launchers keep the kernel and the templates in memory and generate
  the AS's signing keys at each boot, so a restart ends their Missions and
  the credentials naming them. A composition given `kernelStore` keeps its
  Missions across a restart; that is the restart path the witness runs.

## Scenarios

| # | Scenario | Milestone |
|---|---|---|
| 0 | Discovery bootstrap (catalog, consent_required) | M8 |
| 1 | Issuance (shaper -> PAR -> Bob approves -> DPoP token) | M1 |
| 2 | Happy path (in-authority read/schedule, Decision Evidence) | M4 |
| 3 | Parameter binding / context drift refusal | M4 |
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
5. The agent designates the sub-agent `subagent-invoice-extractor` for its
   own token, and the sub-agent redeems the designation as itself. The
   delegated token keeps `agt_ledger_reconciler` as `sub`, names the
   sub-agent in `act`, is bound to the sub-agent's own key, and carries the
   sub-agent as `client_id`; the Mission's Agent stays `ledger-reconciler`.
6. A caller without the lifecycle grant gets the not-found response. Dana's
   lifecycle credential revokes the Mission; refresh and the exchange are
   then refused.

Exhibit mode (annotated wire captures, handbook Appendix B) is a follow-on
(O-28); the scenario runner is the reproducible path today.
