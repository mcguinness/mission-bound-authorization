# MAS pilot walkthrough

An operator's walk through the MAS pilot (#818) in its two topologies:
start it, approve a Mission, make a joined call with an estate credential,
see the permit, revoke or contain the Mission at the MAS, and see the
refusal with its evidence record. What the pilot is, and what each of its
properties rests on, is [mas-pilot-deployment.md](mas-pilot-deployment.md);
this document covers running it.

Every statement here is true of the reference implementation at `f1acfdfc`
(paths relative to `src/`). The launcher tests are
`demo/test/mas-pilot-launcher.test.ts` (§7); its smoke tests need a live
OpenFGA and are skipped without one, and its startup refusals always run.
The pilot is not a production deployment: the estate AS is the reference
stand-in, and the operator console holds per-boot credentials in memory.

## 1. What runs

| | `pnpm mas-pilot` (in process) | `pnpm mas-pilot:separated` |
|---|---|---|
| The MAS | The reference authorization server (`buildPilotMas`, `demo/src/mas-pilot/mas-as.ts`) in the launcher's process, around the kernel the pilot reads. | The same server as its own process (`demo/src/mas-pilot/mas-serve.ts`), which the launcher starts with no IPC channel, or one already running (`MAS_PILOT_MAS_URL`, §3.7). |
| How the pilot reads a Mission | The kernel's committed record (`composeMasPilot`). | The MAS's signed Mission Status over HTTP (`composeSeparatedMasPilot`, deployment §11). |
| Operator console | One listener with both halves. | The MAS half in the MAS's process, the pilot half in the launcher's. |
| A revocation is seen | At the next decision. | Once the signed `fresh_until` (60 s) of the last Status read of the Mission passes; at the next decision for a Mission not read since. |
| A contained action is refused | `authority_contained`. | `out_of_authority`, the Status view's declared diagnostic (deployment §11). |

In both, the MAS listens on `separated_mas.host:port` (shipped:
`http://127.0.0.1:14834`) and its URL is the Mission issuer: the launcher
moves the configuration's `mission_issuer` (`https://mas.pilot.invalid` in
`config/mas-pilot.json`), the mapping contract's included, to that URL
(`relocateMissionIssuer`, `demo/src/mas-pilot/config.ts`). The estate AS
(`127.0.0.1:14818`), the gateway, the resource route and the decision point
run in the launcher's process (`demo/src/mas-pilot/launcher.ts`).

## 2. Start it

From `src/`, after `pnpm setup` and `docker compose up -d` (OpenFGA):

```sh
MAS_PILOT_DEVELOPMENT_STORE=1 MISSION_EPHEMERAL_KEYS=1 pnpm mas-pilot
MAS_PILOT_DEVELOPMENT_STORE=1 MISSION_EPHEMERAL_KEYS=1 pnpm mas-pilot:separated
```

The launcher prints where everything is and the console's bearer:

```text
MAS pilot, separated (#818)
  MAS                http://127.0.0.1:14834  (process 50177, no IPC channel)
  MAS keys           ephemeral, generated at this boot; kernel in memory, lost at shutdown
  estate AS          http://127.0.0.1:14818
  gateway            http://127.0.0.1:53157/mcp  (estate credentials, joined under the mapping contract)
  resource route     http://127.0.0.1:53158/mcp  (Mission-bound credentials only)
  Resource policy    development store 01M5DT70SCAA7CVA5Q2X9P9W19 model 01M5DT70STYYQ9BZ17HBJFBS6H
  operator console   http://127.0.0.1:53147  (MAS)  http://127.0.0.1:53159  (pilot)
  console bearer     71b69dbc-b4c7-4228-a3ed-450bc6ede65e
  ready. Ctrl-C to stop.
```

The steps in §3 use these three values:

```sh
MAS_CONSOLE=http://127.0.0.1:53147 PILOT_CONSOLE=http://127.0.0.1:53159 BEARER=71b69dbc-b4c7-4228-a3ed-450bc6ede65e
```

In process, both consoles are the one printed URL.

**Environment** (`masPilotLaunchOptions`, `demo/src/mas-pilot/launcher.ts`):

| Variable | Meaning |
|---|---|
| `OPENFGA_STORE_ID`, `OPENFGA_MODEL_ID` | Attach to the administered Resource-policy store and model: verified, never written (deployment §4). |
| `MAS_PILOT_DEVELOPMENT_STORE=1` | Instead, bootstrap a fresh store seeded from `config/mas-pilot.json` `resource_policy`. Its store and model are printed, and a later start can attach to them. |
| `MISSION_KEY_RING=<absolute path>` or `MISSION_EPHEMERAL_KEYS=1` | Where the MAS's signing keys come from, as for the as-native target. A ring is created once with `pnpm keys init --ring <path> --issuer http://127.0.0.1:14834`. |
| `MISSION_KERNEL_STORE=<absolute path>` | Optional: keeps the MAS's Missions across a restart. |
| `MAS_PILOT_CONFIG` | The configuration file (default `config/mas-pilot.json`). |
| `OPENFGA_HTTP_URL`, `OPENFGA_PRESHARED_KEY`, `OPENFGA_CA_CERT` | The OpenFGA connection; the defaults reach the `docker compose` OpenFGA, and `scripts/mas-pilot.mjs` trusts `certs/openfga.crt` when it exists and no CA is set. |
| `MAS_PILOT_MAS_URL`, `MAS_PILOT_PDP_KEY` | Separated only: use a MAS already running, and the PDP's private key (a JWK with its `kid`) whose public half that MAS registered (§3.7). |
| `MAS_PILOT_JOIN_INTROSPECTION_SECRET` | With a running MAS whose configuration declares `join_assertion` only: the secret that MAS was given for its introspection client at the estate (§3.8). |

**Startup refusals.** Each prints one `mas-pilot: startup failed: <reason>`
line and exits 1:

- no Resource-policy store (neither an attached one nor
  `MAS_PILOT_DEVELOPMENT_STORE=1`), both, or only one of the two store
  identifiers;
- a `MAS_PILOT_CONFIG` that names no file, a configuration with no
  `mapping_contract` (the configuration loader), or one whose contract does
  not load (`requireDeclaredMappingContract`, the compositions' own guard,
  applied before the launcher starts anything: "the MAS pilot mounts a join
  route, but declares no usable mapping contract");
- `MAS_PILOT_MAS_URL` or `MAS_PILOT_PDP_KEY` in process, one of them
  without the other, or a `MAS_PILOT_PDP_KEY` that is not a private JWK with
  a `kid`;
- a MAS that is unreachable, a MAS whose metadata names another issuer
  ("answers as issuer ..., not the configured Mission issuer ..."), or a MAS
  process that fails its own startup (its reason, for example
  `http://127.0.0.1:14834 cannot listen`);
- a declared `join_assertion.pdp_algorithms` that shares no algorithm with
  the MAS's advertised list (§3.8);
- a configuration declaring `join_assertion` in process, a running MAS's
  declared path without `MAS_PILOT_JOIN_INTROSPECTION_SECRET`, and that
  variable where the configuration declares no path or the launcher starts
  the MAS (§3.8);
- an `OPENFGA_HTTP_URL` that is not an http or https URL, an
  `OPENFGA_CA_CERT` that names no file, and a signing-key environment that
  `signingKeysFromEnv` refuses.

None of them opens the Resource-policy store, and a failure part way
releases every listener and process already started (§7).

## 3. Walk through it

Every console request presents `authorization: Bearer $BEARER`; without
it, or with any other value, the console answers 401 before any route runs
(`startOperatorConsole`, `demo/src/mas-pilot/operator-console.ts`).

```sh
console() { curl -sS -H "authorization: Bearer $BEARER" -H "content-type: application/json" "$@"; }
```

### 3.1 Approve a Mission

```sh
console -X POST "$MAS_CONSOLE/missions" -d '{"subject":"alice","label":"walkthrough"}'
```

```json
{"mission_id":"msn_Z4izMoqnax3zOP_ZM1g0LZDx","issuer":"http://127.0.0.1:14834","subject":"alice","actions":["payments:invoice.read","payments:invoice.list","payments:vendor.read"]}
```

`subject` defaults to `alice`, `actions` to the three reads shown. The
console runs the MAS's own approval flow over HTTP (§4). The steps below
name this Mission `$MISSION`, and two more approved the same way
`$REVOKED` (§3.5) and `$CONTAINED` (§3.6).

### 3.2 Obtain an estate credential

```sh
console -X POST "$PILOT_CONSOLE/estate-tokens" -d '{"client_id":"estate-ap-bot-7f3","account":"u-1001","scope":"invoices.read"}'
console -X POST "$PILOT_CONSOLE/estate-tokens" -d '{"client_id":"estate-opaque-bot-4e2","account":"u-1001","scope":"invoices.read"}'
```

```json
{"credential_id":"cred-cd3b1b8c-340f-40d0-833f-ddbb26ffb073","client_id":"estate-ap-bot-7f3","token_format":"jwt"}
{"credential_id":"cred-85affc0d-bac3-4071-938a-745e94352ee0","client_id":"estate-opaque-bot-4e2","token_format":"opaque"}
```

The console runs the estate client's authorization code flow, DPoP-bound
(`obtainEstateToken`, `demo/src/mas-pilot/estate-client.ts`; `login_hint`
stands in for the estate's login), and keeps the token and its DPoP key in
memory under the returned `credential_id` (below, `$JWT_CREDENTIAL` and
`$OPAQUE_CREDENTIAL`). The first client receives an RFC
9068 JWT, the second an opaque token the gateway introspects (deployment
§5). Under the shipped mapping contract, `u-1001` and `u-1002` map to
`alice`, both clients to `ap-agent`, and `invoices.read` to
`payments:invoice.read` and `payments:invoice.list`.

### 3.3 Make a joined call

```sh
call() { console -X POST "$PILOT_CONSOLE/calls" -d "{\"credential_id\":\"$1\",\"mission_id\":\"$2\",\"tool\":\"get_invoice\",\"arguments\":{\"invoice_id\":\"inv-1\"}}"; }
call $JWT_CREDENTIAL $MISSION
```

```json
{"ok":true,"result":{"id":"inv-1","vendor_id":"acme","amount":"125.00","currency":"USD","payee_account":"acct-acme-001","status":"payable","issued_at":null,"classification":null,"version":1}}
```

The console calls the gateway over HTTP MCP as any client does: the estate
credential with a DPoP proof, and `Mission-Reference: id="msn_...",
issuer="http://127.0.0.1:14834"`. `call $OPAQUE_CREDENTIAL $MISSION`
permits the same way.

### 3.4 Read the evidence

```sh
console "$PILOT_CONSOLE/missions/$MISSION/evidence"
```

```json
{"mission_id":"msn_Z4izMoqnax3zOP_ZM1g0LZDx","records":[{"kind":"decision","at":"2026-10-20T23:26:49.390Z","decision":"permit","action":"payments:invoice.read"}]}
```

Each record summarizes one the PEP retained for the Mission: its kind
(`decision` is Decision Evidence, `refusal` a Refusal Record), time,
decision, denial reason and action.

### 3.5 Revoke at the MAS

**Separated timing.** The separated pilot relies on its last signed Status
read of a Mission until that read's `fresh_until` (60 s on the reference
MAS). A Mission read in the last 60 s keeps permitting after its revocation
until then, and then refuses `mission_inactive` (deployment §11, "observes a
revocation at the MAS within the signed bound"). To see the refusal at
once in either topology, revoke a Mission before its first call, as the
smoke tests do. In process, the next decision after a revocation refuses.

```sh
console -X POST "$MAS_CONSOLE/missions/$REVOKED/revoke" -d '{}'
```

```json
{"mission_id":"msn_QMpM7-P6qqWAAdYh2tvPUlho","state":"terminated","version":2}
```

The console sends `operation=revoke` to the MAS's advertised Mission
Lifecycle endpoint as its Lifecycle client (`private_key_jwt`,
`requestLifecycle`, `demo/src/lifecycle-client.ts`) and reports the state
from the signed Mission Status it answers with. `call $JWT_CREDENTIAL
$REVOKED` is refused, and the Mission's evidence ends with that refusal:

```json
{"ok":false,"denial_reason":"mission_inactive"}
{"mission_id":"msn_QMpM7-P6qqWAAdYh2tvPUlho","records":[{"kind":"decision","at":"2026-10-20T23:29:02.228Z","decision":"deny","denial_reason":"mission_inactive","action":"payments:invoice.read"}]}
```

### 3.6 Contain at the MAS

```sh
console -X POST "$MAS_CONSOLE/missions/$CONTAINED/contain" -d '{"actions":["payments:invoice.read"]}'
```

```json
{"mission_id":"msn_Enu1cDi2sGEc4j-S0tLyoLEE","state":"active","version":2,"containment_version":1}
```

The console sends `operation=contain` to the same endpoint, with an `event`
(`anomaly.detected` from `svc:mas-pilot-operator`) and a `remove` of the
named actions at the payments resource. The Mission stays active, and
`call $JWT_CREDENTIAL $CONTAINED` is refused: `authority_contained` in
process, `out_of_authority` separated, with the same `fresh_until` timing as
§3.5. An action not contained still permits (the containment tests in
`demo/test/mas-pilot.test.ts` and `demo/test/mas-pilot-separated.test.ts`).

### 3.7 Attach to a MAS already running

The PDP reads the MAS's Mission Status endpoint as the client
`separated_mas.pdp_client_id` (`mas-pilot-pdp`), authenticating by
private-key JWT (#1407). Generate its key where the PDP runs, from
`src/demo`: the private half for the launcher, the public half for the MAS.

```sh
umask 077
node --input-type=module -e "
import { exportJWK, generateKeyPair } from 'jose';
import { writeFileSync } from 'node:fs';
const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
const kid = 'mas-pilot-pdp-1';
writeFileSync('/tmp/mas-pilot-pdp-key.json', JSON.stringify({ ...(await exportJWK(privateKey)), kid, alg: 'ES256' }));
writeFileSync('/tmp/mas-pilot-status-clients.json', JSON.stringify([
  { client_id: 'mas-pilot-pdp', jwks: { keys: [{ ...(await exportJWK(publicKey)), kid, alg: 'ES256', use: 'sig' }] } },
]));
"
```

Start the MAS yourself, from `src/demo`, with that public key and its own
console bearer:

```sh
MISSION_EPHEMERAL_KEYS=1 MAS_PILOT_STATUS_CLIENTS="$(cat /tmp/mas-pilot-status-clients.json)" \
  MAS_PILOT_OPERATOR_TOKEN=<mas console bearer> MAS_PILOT_OPERATOR_CONSOLE_PORT=14856 \
  node --import tsx src/mas-pilot/mas-serve.ts
```

It prints `mas-pilot: operator console http://127.0.0.1:14856` and
`mas-pilot: ready http://127.0.0.1:14834`. Then, from `src/`:

```sh
MAS_PILOT_MAS_URL=http://127.0.0.1:14834 MAS_PILOT_PDP_KEY="$(cat /tmp/mas-pilot-pdp-key.json)" \
  MAS_PILOT_DEVELOPMENT_STORE=1 pnpm mas-pilot:separated
```

The launcher checks the MAS's metadata issuer before it composes anything,
and reads Mission Status at the endpoint the MAS advertises.
Approve, revoke and contain at the MAS's console with the MAS's bearer; the
launcher's printed bearer covers its pilot console only. Stopping the
launcher leaves the MAS running.

### 3.8 Run the Join Assertion path

The separated topology runs sender-bound Join Assertions (deployment §8)
where the configuration declares `join_assertion`; the shipped one does
not. Declare it in a copy, from `src/`:

```sh
node -e '
const c = require("./config/mas-pilot.json");
c.join_assertion = { introspection_client_id: "mas-join-introspector", required: false, required_classes: ["consequential_read"], pdp_algorithms: ["ES256"] };
require("node:fs").writeFileSync("/tmp/mas-pilot-join.json", JSON.stringify(c, null, 2));
'
MAS_PILOT_CONFIG=/tmp/mas-pilot-join.json MAS_PILOT_DEVELOPMENT_STORE=1 MISSION_EPHEMERAL_KEYS=1 pnpm mas-pilot:separated
```

The launcher generates the secret of the MAS's introspection client at the
estate, hands it to the MAS process (`MAS_PILOT_JOIN_INTROSPECTION_SECRET`)
and to the estate it starts, and prints one more line:

```text
  Join Assertions    requested by the PEP from the MAS; required for consequential_read
```

`pdp_algorithms` is the PDP's own algorithm allowlist: it accepts those of
the MAS's advertised `mission_status_signing_alg_values_supported` that the
list names, never `none`, and the launcher refuses to start when the two
share nothing. The reference MAS signs ES256.

§3.1 to §3.4 then run unchanged. For each joined call the PEP asks the
MAS's `mission_join_assertion_endpoint` for an assertion for the presented
credential, and the PDP joins on it. Every read is `consequential_read`, so
under this declaration a read the MAS mints no assertion for is denied
`mission_binding_failed`, with its Decision Evidence (§3.4), instead of
being joined under the mapping contract. With the class removed from
`required_classes`, such a read joins under the mapping contract, the
floor.

`pnpm mas-pilot` refuses this configuration ("join_assertion applies to the
separated topology only"). To attach to a MAS you started (§3.7), start it
with the same configuration and `MAS_PILOT_JOIN_INTROSPECTION_SECRET=<a
secret>`, and give the launcher the same variable.

The MAS installs the mapping contract once, when it starts, under the same
300 s bound as the gateway's (deployment §3); after that it mints nothing,
and a read that requires an assertion is denied. The launcher records no
delegate in either actor-record store, so no delegate joins here
(follow-up: #1561); the
tests show the delegate path (deployment §8).

### 3.9 Stop it

Ctrl-C (or SIGTERM or SIGHUP) closes the consoles, the gateway, the
resource route, the estate AS and the MAS's listener, stops the MAS process
the launcher started, and exits 0 (`demo/src/mas-pilot/launcher-serve.ts`).
Estate credentials do not survive a restart: the reference estate's key and
token store exist only for one boot.

Stopping the launcher at any point, startup included, stops the MAS process
and frees the ports. The launcher handles the three signals from its first
line. Everything a launch acquires is registered in its cleanup scope as it
is acquired (`StartupScope`, `demo/src/mas-pilot/startup.ts`): the MAS
process from the moment it is spawned, then each listener and store,
including those the composition opens. A signal during startup runs that
stack at once, whatever startup is waiting on (a Resource-policy store that
never answers, a MAS process not yet ready), prints
`mas-pilot: stopped the MAS process <pid>`, and exits with the signal's
status: 130, 143 or 129. A startup that fails releases the same stack before
it prints its `startup failed` line. The MAS process is stopped with SIGTERM,
then SIGKILL if it has not exited within 5 s.

The MAS process also shuts itself down when the launcher dies without
cleaning up, a SIGKILL for example: the launcher spawns it with a stdin
pipe it never writes and `MAS_PILOT_EXIT_WITH_PARENT=1`, and the MAS shuts
down when that pipe ends (`mas-serve.ts`). A MAS started by hand (§3.7)
does not set the variable and ignores stdin.

## 4. How approval runs

`POST /missions` on the MAS console runs the reference authorization
server's own approval flow over HTTP (`masConsoleRoutes`):

1. A pushed authorization request as the submitting agent `ap-agent`
   (`private_key_jwt` with the agent key the server generates at each boot),
   carrying the Mission intent and one `mission_resource_access` entry: the
   payments resource, the requested actions, vendor `acme`.
2. The decision, at the approval surface's
   `/interaction/{uid}/decide`, by the approval-service principal
   `svc:mas-pilot-approver`: a per-boot service token with the
   `mission_approval` scope and the Approver `bob` (`acr` `mfa`), naming the
   Subject. This composition admits headless adjudication
   (`allowHeadlessAdjudication`). Bob approves for `alice` and
   `acme-accounts-payable` only (`config/identity.json`).
3. The token request that redeems the code; the access token's `mission`
   claim names the new Mission.

The published approval-authentication floor (`config/approval-floor.json`,
D425) refuses a headless approval of floor-invoking authority
(`payments:payment.execute`, `payments:remittance.send`). A Mission with
that authority needs the browser approval surface and a fresh `mfa` login,
which the as-native launcher provides and this one does not. The default
reads invoke no floor.

The token from step 3 is Mission-bound to `ap-agent` and has no consumer
here: the pilot's resource route trusts a key nothing signs with
(deployment §1), so the console discards it. Estate credentials are what
reach the resource.

The MAS process's IPC messages `approve` and `clock` are test harness
(`demo/test/mas-process.ts`), registered only when the process has an IPC
channel. The launcher spawns it with `stdio: ["pipe", "pipe", "pipe"]`
and no `ipc`, so neither exists there; the stdin pipe only tells the MAS
that the launcher has gone (§3.9). The `actor` message (#1454), a delegate
recorded in the MAS's actor records, is test harness the same way.

## 5. Keys, clients and rotation

### Estate signing keys

The reference estate AS signs with one key it generates at each boot
(`estate-signing-1`, `demo/src/mas-pilot/estate-as.ts`) and runs in the
launcher's process, so its key changes only when the pilot restarts. The
gateway reads the estate's published JWKS once, at composition
(`demo/src/mas-pilot/compose.ts`), and never fetches it again.

A JWT signed under any key the gateway did not read at startup, such as the
key an estate rotates to while the pilot runs, is refused 401 at the MCP
handshake, before any decision, with no JWKS fetch. Opaque credentials are
unaffected: the gateway introspects them at the estate and holds no key for
them. The test signs the estate's own token again under a fresh key, because
the reference estate has no rotation operation of its own.

Operator step: after an estate rotates its signing key, restart the pilot so
the gateway reads the new JWKS. JWTs under the new key are refused until
then.

### Introspection endpoint or client

The gateway's introspection client is `introspection.client_id`
(`mas-gateway-introspector`); its secret is generated at each boot and
registered at the estate at that boot. The endpoint is the one the estate
publishes, read at composition; the launcher takes no override. Neither is
read again while the pilot runs.

Operator step: edit `introspection.client_id` in the configuration (the
loader refuses one that is also an estate client), or change the estate's
endpoint, then restart the pilot. Positive introspection results are cached
in memory for at most `introspection.cache_max_seconds` (60) and do not
carry across the restart.

### MAS signing keys: not supported

Rotating the MAS's signing keys is a gap. The separated pilot reads the
MAS's JWKS once, at composition, and accepts Status responses only under the
declared status key (`declaredStatusKeys`,
`demo/src/mas-pilot/separated.ts`). A MAS that starts signing under other
keys verifies nothing until the pilot is composed again: every read refuses
`state_unavailable` (deployment §11, Gaps). What the pilot supports is
keeping the same keys across a MAS restart, with `MISSION_KEY_RING` (and the
Missions, with `MISSION_KERNEL_STORE`): "the separated MAS pilot: the MAS
stops and starts". Do not rotate the MAS's keys while the pilot runs.

## 6. Gaps

- The operator console is a convenience for this walkthrough: loopback
  only, one bearer per boot printed on the terminal, credentials in memory.
- Headless approval only: floor-invoking authority cannot be approved here
  (§4).
- Separated, a revocation or containment is seen within the signed
  `fresh_until` of the last read (§3.5).
- MAS key rotation is not supported (§5).
- After startup, a signal's shutdown ran by hand for this walkthrough; the
  smoke tests call `close()` directly. During startup it is tested on the
  real entry points (§7). The OpenFGA connection and signing-key refusals
  are the launcher's checks, not exercised by its tests.
- A SIGKILL of the `scripts/mas-pilot.mjs` wrapper itself leaves the
  launcher process it started running, as for every `run-demo-ts`
  wrapper; a SIGKILL of the launcher process does not orphan the MAS
  process (§3.9).
- The Join Assertion path stops minting once the MAS's mapping contract is
  stale, and joins no delegate (§3.8; follow-up: #1561).

## 7. Witnesses

`demo/test/mas-pilot-launcher.test.ts` drives the functions the commands
run (`masPilotLaunchOptions`, `launchMasPilot`, `spawnMasProcess`) through
the operator console, as §3 does:

- `the MAS pilot launcher, in process (#818 slice 5B) > starts, approves through the MAS's approval surface, permits joined reads for a JWT and an opaque estate credential, refuses after a revocation and a containment at the MAS, and releases every port on shutdown`;
- `… > estate key rotation: a JWT under a key the gateway did not read at startup is refused before any decision, with no JWKS refetch; an opaque credential is unaffected`;
- `the MAS pilot launcher, separated (#818 slice 5B) > starts the MAS as its own process with no IPC channel, approves, permits, refuses after a revocation and a containment, and stops the process on shutdown`
  (the child has no `send` and is not `connected`);
- `… > attaches to a MAS already running (MAS_PILOT_MAS_URL), approves at its own console, permits, refuses after a revocation, and leaves the MAS running on shutdown`;
- `the MAS pilot launcher refuses to start, before anything connects (#818 slice 5B) > refuses with no Resource-policy store, or two, unless development is asked for by name; attach names the store`;
- `… > refuses a configuration file that is absent, or whose mapping contract is missing or does not load`;
- `… > refuses a running MAS that is unreachable or answers under another issuer, and a MAS process that fails to start, without opening the Resource-policy store`
  (with a control: a launch that reaches the store meets the stub, and its
  failure frees its ports);
- `… > refuses a running MAS's address in process, and one of the address and the PDP credential without the other`;
- `… > the separated composition refuses a MAS advertising no mission_status_endpoint, and a PDP key that is not a private JWK, before reaching OpenFGA (#1407)`;
- `… > the MAS process refuses a Status client registration it cannot use (#1407)`;
- `… > refuses a PDP key that is not a private JWK with a kid (#1407)`.

The smoke tests bind the MAS and estate on `127.0.0.1:14858` and `14859`
(in process), `14864` and `14865` (rotation), `14860` and `14861`
(separated) and `14868` and `14869` (attach); the refusals use `14862` and
`14863`. Consoles, gateways and resource routes bind ephemeral ports.

`demo/test/mas-pilot-launcher-shutdown.test.ts` runs the entry points as
processes, `scripts/mas-pilot.mjs` and `launcher-serve.ts`, with the
Resource-policy store pointed at a stub that accepts a connection and never
answers. It needs no OpenFGA:

- `` stopping the MAS pilot launcher during startup stops its MAS process and frees every port (#818 slice 5B review) > SIGTERM to `pnpm mas-pilot:separated` while startup waits on a Resource-policy store that never answers: the launcher stops its MAS process and exits 143; the MAS, its console and the estate refuse connections ``;
- `… > SIGINT to the launcher itself, blocked the same way: exit 130, its MAS process stopped and its port free`;
- `… > SIGTERM while the MAS process is still starting, before it is ready: the launcher stops it and exits 143`;
- `… > SIGHUP to the in-process launcher while it waits on the store: exit 129, the MAS and estate ports free`;
- `… > a startup that fails after the MAS process is up (the store refuses) stops the MAS process before the launch rejects, and leaves no port open`;
- `the MAS process outlives no launcher (#818 slice 5B review) > SIGKILL of the launcher, which runs no cleanup: the MAS process shuts down when its stdin pipe ends`;
- `… > a MAS process started without MAS_PILOT_EXIT_WITH_PARENT ignores the end of its stdin`;
- `… > stopChild escalates to SIGKILL for a MAS process that ignores SIGTERM`;
- `the launch's cleanup scope (#818 slice 5B review) > cancel releases everything registered, last first, at once, while a step waits on something that never answers; the step throws StartupCancelled`,
  and the cases for a resource that arrives after cancellation and a
  registration after release.

These bind `127.0.0.1:14876` to `14889`.

`demo/test/mas-pilot-join-assertion.test.ts` drives the same functions for
the Join Assertion path (§3.8):

- `the separated launcher runs the declared Join Assertion path (#1454) > generates the MAS's introspection client secret for the MAS process and the estate, and a joined read that requires an assertion permits, by JWT and by opaque credential`
  (on `127.0.0.1:14907` and `14908`; needs a live OpenFGA);
- `the launcher refuses a Join Assertion path it cannot run, before anything connects (#1454) > refuses the path in process, a running MAS's path without its secret, and a secret where none applies`.
