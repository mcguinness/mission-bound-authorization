/**
 * @spec runtime#state-freshness, status#mission-status (#1101, D1258)
 *
 * The separated AS-native configuration's authorization server, as its own
 * process (`as-server.ts`): the only holder of the Mission records. The
 * payments PEP and PDP reach it over HTTP alone: token verification under its
 * `jwks_uri`, Mission state over its signed Mission Status, revocation at its
 * Mission Lifecycle endpoint.
 *
 * Environment:
 * - `AS_NATIVE_SEPARATED_CONFIG`: the configuration file (default: the
 *   shipped `config/as-native-separated.json`).
 * - `AS_NATIVE_SEPARATED_STATUS_CLIENTS`: the Mission Status endpoint's
 *   clients, a JSON array of `{ "client_id", "jwks", "disclose"? }`, each the
 *   PUBLIC half of a key generated where that client runs; the PDP's
 *   (`pdp_client_id`) among them.
 * - `AS_NATIVE_SEPARATED_LIFECYCLE_CLIENT`: the Lifecycle console's
 *   registration, `{ "client_id", "client_name", "jwks", "grants" }`, its
 *   public half only.
 * - `AS_NATIVE_SEPARATED_APPROVER_LOGIN`: the upstream OpenID Provider the
 *   Approver logs in through: `{ "issuer", "clientId", "clientSecret",
 *   "idTokenSigningAlgs", "identities", "acrValues"? }`.
 * - `MISSION_KEY_RING` (with `MISSION_KEY_BINDINGS`) or
 *   `MISSION_EPHEMERAL_KEYS=1`, and optionally `MISSION_KERNEL_STORE` with
 *   `MISSION_KERNEL_WITNESS`, as for the standalone authorization server: a
 *   key ring and a kernel store keep the keys and the Missions across a
 *   restart.
 * - `AS_NATIVE_SEPARATED_EXIT_WITH_PARENT=1`: shut down when stdin ends.
 *
 * SIGINT, SIGTERM and SIGHUP close the listener and the kernel and exit 0.
 *
 * Started with an IPC channel (the tests' `as-process.ts`), it also takes
 * operator messages that are test harness, not a protocol surface: `clock`
 * (an offset on this process's clock, from `AS_NATIVE_SEPARATED_CLOCK_OFFSET_MS`
 * at start: the provider's token times and the kernel's both follow it, so
 * they agree with the test's controlled clock), `credentials` (the per-boot submitting
 * agent's private key, for its PAR and token requests), `adjudicate` (decide
 * the oldest pending action-bound approval on the ARS), `suspend` and
 * `contain` (a kernel suspension or containment: this capability set serves
 * neither operation at the Lifecycle endpoint). Started any other way, none
 * is registered.
 */

import { createServer, type Server } from "node:http";
import { kernelStoreFromEnv, type LifecycleClientRegistration, signingKeysFromEnv } from "@mission/authorization-server";
import type { StatusClientRegistration } from "../mas-pilot/mas-as.js";
import { type ApproverLoginConfig, buildSeparatedAs, type SeparatedAs } from "./as-server.js";
import { loadAsNativeSeparatedConfig } from "./config.js";

function fail(message: string): never {
  console.error(`as-native-separated: startup failed: ${message}`);
  process.exit(1);
}

function json<T>(name: string): T {
  const raw = process.env[name];
  if (raw === undefined || raw === "") fail(`${name} is not set`);
  try {
    return JSON.parse(raw) as T;
  } catch {
    fail(`${name} is not JSON`);
  }
}

const config = process.env.AS_NATIVE_SEPARATED_CONFIG
  ? loadAsNativeSeparatedConfig(process.env.AS_NATIVE_SEPARATED_CONFIG)
  : loadAsNativeSeparatedConfig();
const statusClients = json<StatusClientRegistration[]>("AS_NATIVE_SEPARATED_STATUS_CLIENTS");
if (!Array.isArray(statusClients) || statusClients.length === 0) fail("AS_NATIVE_SEPARATED_STATUS_CLIENTS registers no Status client");
if (!statusClients.some((c) => c.client_id === config.pdp_client_id)) {
  fail(`AS_NATIVE_SEPARATED_STATUS_CLIENTS does not register the PDP's client ${config.pdp_client_id}`);
}
const lifecycleClient = json<LifecycleClientRegistration>("AS_NATIVE_SEPARATED_LIFECYCLE_CLIENT");
const approverLogin = json<ApproverLoginConfig>("AS_NATIVE_SEPARATED_APPROVER_LOGIN");

// Test harness only: with an IPC channel, this process's clock is the real
// one offset by the operator's `clock` message, global `Date` included.
let offsetMs = 0;
if (process.send) {
  offsetMs = Number(process.env.AS_NATIVE_SEPARATED_CLOCK_OFFSET_MS ?? "0");
  const RealDate = globalThis.Date;
  class OffsetDate extends RealDate {
    constructor(...args: unknown[]) {
      if (args.length === 0) super(RealDate.now() + offsetMs);
      else super(...(args as [number]));
    }
    static override now(): number {
      return RealDate.now() + offsetMs;
    }
  }
  globalThis.Date = OffsetDate as DateConstructor;
}
let as: SeparatedAs | undefined;
let server: Server | undefined;

let closing = false;
const shutdown = (): void => {
  if (closing) return;
  closing = true;
  void (async () => {
    if (server?.listening) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server?.close(() => resolve()));
    }
    as?.built.kernel.close();
    process.exit(0);
  })();
};
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(signal, shutdown);
if (process.env.AS_NATIVE_SEPARATED_EXIT_WITH_PARENT === "1") {
  process.stdin.on("end", shutdown);
  process.stdin.on("close", shutdown);
  process.stdin.resume();
}

try {
  const kernelStore = kernelStoreFromEnv(process.env);
  as = await buildSeparatedAs({
    config,
    statusClients,
    lifecycleClient,
    approverLogin,
    signingKeys: signingKeysFromEnv(process.env),
    ...(kernelStore ? { kernelStore } : {}),
  });
} catch (e) {
  fail(e instanceof Error ? e.message : String(e));
}
const built = as;
const listening = createServer(built.built.provider.callback());
server = listening;
await new Promise<void>((resolve) => {
  listening.once("listening", () => resolve());
  listening.once("error", (e) => fail(`${built.issuer} cannot listen: ${e.message}`));
  listening.listen(config.authorization_server.port, config.authorization_server.host);
});
console.log(`as-native-separated: ready ${built.issuer}`);

interface OperatorMessage {
  id: number;
  op: "clock" | "credentials" | "adjudicate" | "suspend" | "contain";
  offsetMs?: number;
  decision?: "approve" | "deny";
  missionId?: string;
  remove?: { resource: string; actions?: string[] }[];
}

// Test harness only: registered where this process has an IPC channel.
if (process.send) {
  process.on("message", async (raw: unknown) => {
    const msg = raw as OperatorMessage;
    const reply = (body: Record<string, unknown>) => process.send?.({ id: msg.id, ...body });
    try {
      switch (msg.op) {
        case "clock":
          offsetMs = Number(msg.offsetMs ?? 0);
          return reply({ ok: true });
        case "credentials":
          return reply({ ok: true, agentClientJwk: built.built.agentClientJwk });
        case "adjudicate": {
          const task = built.ars.pending()[0];
          if (!task) return reply({ ok: false, error: "no pending approval" });
          await built.ars.adjudicate(task.id, msg.decision ?? "approve", "bob");
          return reply({ ok: true });
        }
        case "suspend":
          built.built.kernel.transition(String(msg.missionId), "suspend");
          return reply({ ok: true });
        case "contain":
          built.built.kernel.contain(String(msg.missionId), {
            event: { type: "anomaly.detected", source: "svc:soc", observed_at: new Date().toISOString(), event_id: `evt-${crypto.randomUUID()}` },
            remove: msg.remove ?? [],
          });
          return reply({ ok: true });
        default:
          return reply({ ok: false, error: `unknown operator message ${String((msg as { op?: unknown }).op)}` });
      }
    } catch (e) {
      reply({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  });
}
