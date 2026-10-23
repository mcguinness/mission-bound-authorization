/**
 * @spec authority-server#deployment-adoption, runtime#input-resource-policy (#818 slice 5B)
 *
 * The MAS pilot's operator launchers (`pnpm mas-pilot`,
 * `pnpm mas-pilot:separated`), after the as-native launcher's pattern
 * (`as-native.ts`): their configuration from the environment, their startup
 * and their shutdown. `launcher-serve.ts` is the process around these
 * functions (printing, signals, exit status), and the tests drive the same
 * functions, so what they show is what the launcher runs.
 *
 * - In process: the reference authorization server as the MAS on
 *   `separated_mas.host:port` (`mas-as.ts`), and the pilot composition
 *   (`composeMasPilot`) reading that server's kernel.
 * - Separated: the MAS as its own process (`mas-serve.ts`), started with no
 *   IPC channel, or an already running one (`MAS_PILOT_MAS_URL`), and the
 *   pilot composition reading it through its signed Mission Status
 *   (`composeSeparatedMasPilot`).
 *
 * Where the configuration declares `join_assertion` (#1454), the separated
 * launcher runs the Join Assertion path: it generates the MAS's introspection
 * client secret and hands it to the MAS process
 * (`MAS_PILOT_JOIN_INTROSPECTION_SECRET`) and to the estate it starts, or, for
 * a running MAS, takes the secret that MAS was given from the same variable.
 * The in-process topology refuses such a configuration.
 *
 * Either way the MAS's URL is the Mission issuer, approval runs on its
 * approval surface and revocation and containment on its Lifecycle
 * endpoint, through the operator console (`operator-console.ts`). The
 * Resource-policy store is attached (configured store and model, verified,
 * nothing written); a development store is bootstrapped only on the explicit
 * `MAS_PILOT_DEVELOPMENT_STORE=1`.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { kernelStoreFromEnv, type SigningKeySource, signingKeysFromEnv } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";
import type { JWK } from "jose";
import type { ResourcePolicyStore } from "../resource-policy-store.js";
import { composeMasPilot, type MasPilotParts, requireDeclaredMappingContract } from "./compose.js";
import { loadMasPilotConfig, type MasPilotConfig, relocateMissionIssuer } from "./config.js";
import { buildPilotMas, masIssuer, newStatusClientKey } from "./mas-as.js";
import { masConsoleRoutes, type OperatorConsole, pilotConsoleRoutes, startOperatorConsole } from "./operator-console.js";
import { composeSeparatedMasPilot } from "./separated.js";
import { StartupCancelled, StartupScope } from "./startup.js";

export type MasPilotTopology = "in-process" | "separated";

export interface MasPilotLaunchOptions {
  topology: MasPilotTopology;
  /** The configuration, its Mission issuer moved to the MAS's URL. */
  config: MasPilotConfig;
  /** The configuration file, when not the shipped one (the MAS process reads it too). */
  configPath?: string;
  openfga: { apiUrl: string; presharedKey: string; caCertPath?: string };
  resourcePolicyStore: ResourcePolicyStore;
  /** The MAS's signing keys and kernel file, where this launcher runs the MAS. */
  signingKeys?: SigningKeySource;
  kernelStore?: { file: string };
  /**
   * Separated only: an already running MAS, and the private key (a JWK with
   * its `kid`) the PDP authenticates with there as `separated_mas.pdp_client_id`,
   * whose public half that MAS registered, instead of starting one.
   */
  mas?: { url: string; pdpKey: JWK };
  /** The MAS process's key environment (`MISSION_KEY_RING`, `MISSION_EPHEMERAL_KEYS`, `MISSION_KERNEL_STORE`). */
  masKeyEnv?: Record<string, string>;
  /** A running MAS's introspection client secret at the estate, where the configuration declares `join_assertion` (#1454). */
  joinIntrospectionSecret?: string;
}

const KEY_ENV = ["MISSION_KEY_RING", "MISSION_EPHEMERAL_KEYS", "MISSION_KERNEL_STORE"] as const;

/**
 * The launcher's options, from its environment. Each value that is set but
 * unusable, a missing Resource-policy store, and a configuration whose
 * mapping contract does not load refuse startup with an error naming them,
 * before anything connects or listens.
 */
export function masPilotLaunchOptions(env: Readonly<Record<string, string | undefined>>, topology: MasPilotTopology): MasPilotLaunchOptions {
  const configPath = env.MAS_PILOT_CONFIG;
  if (configPath !== undefined && !existsSync(configPath)) throw new Error(`MAS_PILOT_CONFIG names ${configPath}, which does not exist`);
  const loaded = configPath ? loadMasPilotConfig(configPath) : loadMasPilotConfig();
  // @spec authority-server#mapping-contract: the compositions' own guard, here
  // before the launcher starts a MAS process or opens anything.
  requireDeclaredMappingContract(loaded);
  const config = relocateMissionIssuer(loaded, masIssuer(loaded));

  const apiUrl = env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url;
  let url: URL;
  try {
    url = new URL(apiUrl);
  } catch {
    throw new Error(`OPENFGA_HTTP_URL is not a URL: ${apiUrl}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`OPENFGA_HTTP_URL is not an http or https URL: ${apiUrl}`);
  const ca = env.OPENFGA_CA_CERT;
  if (ca && !existsSync(ca)) throw new Error(`OPENFGA_CA_CERT names ${ca}, which does not exist; run \`pnpm setup\` first`);

  // @spec runtime#input-resource-policy (#828): the administered store, or a
  // development one only when asked for by name.
  const storeId = env.OPENFGA_STORE_ID;
  const modelId = env.OPENFGA_MODEL_ID;
  const development = env.MAS_PILOT_DEVELOPMENT_STORE === "1";
  let resourcePolicyStore: ResourcePolicyStore;
  if (storeId || modelId) {
    if (!storeId || !modelId) throw new Error("set both OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach, or neither");
    if (development) throw new Error("set OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach, or MAS_PILOT_DEVELOPMENT_STORE=1, not both");
    resourcePolicyStore = { attach: { storeId, modelId } };
  } else if (development) {
    resourcePolicyStore = { bootstrap: "development" };
  } else {
    throw new Error(
      "no Resource-policy store: set OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach to the administered store, or MAS_PILOT_DEVELOPMENT_STORE=1 to bootstrap a development one",
    );
  }

  const masUrl = env.MAS_PILOT_MAS_URL;
  const pdpKeyRaw = env.MAS_PILOT_PDP_KEY;
  if (topology === "in-process" && (masUrl !== undefined || pdpKeyRaw !== undefined)) {
    throw new Error("MAS_PILOT_MAS_URL and MAS_PILOT_PDP_KEY apply to the separated topology only; in process, the launcher runs the MAS");
  }
  if ((masUrl === undefined) !== (pdpKeyRaw === undefined)) {
    throw new Error("set both MAS_PILOT_MAS_URL and MAS_PILOT_PDP_KEY to use a running MAS, or neither to start one");
  }
  let pdpKey: JWK | undefined;
  if (pdpKeyRaw !== undefined) {
    try {
      pdpKey = JSON.parse(pdpKeyRaw) as JWK;
    } catch {
      pdpKey = undefined;
    }
    if (pdpKey === null || typeof pdpKey !== "object" || typeof pdpKey.kid !== "string" || typeof pdpKey.d !== "string") {
      throw new Error("MAS_PILOT_PDP_KEY is not a private JWK with a kid");
    }
  }
  const base: MasPilotLaunchOptions = {
    topology,
    config,
    ...(configPath ? { configPath } : {}),
    openfga: { apiUrl, presharedKey: env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey, ...(ca ? { caCertPath: ca } : {}) },
    resourcePolicyStore,
  };
  // @spec authority-server#join-assertion (#1454): the path runs separated
  // only; a running MAS's introspection secret comes from the environment,
  // and only where the configuration declares the path.
  const joinSecret = env.MAS_PILOT_JOIN_INTROSPECTION_SECRET;
  if (config.join_assertion && topology === "in-process") throw new Error("join_assertion applies to the separated topology only");
  if (joinSecret !== undefined && (config.join_assertion === undefined || masUrl === undefined)) {
    throw new Error("MAS_PILOT_JOIN_INTROSPECTION_SECRET applies only to a running MAS whose configuration declares join_assertion");
  }
  if (masUrl !== undefined && pdpKey !== undefined) {
    if (config.join_assertion && joinSecret === undefined) {
      throw new Error("the configuration declares join_assertion: set MAS_PILOT_JOIN_INTROSPECTION_SECRET to the running MAS's introspection client secret");
    }
    return { ...base, mas: { url: masUrl, pdpKey }, ...(joinSecret !== undefined ? { joinIntrospectionSecret: joinSecret } : {}) };
  }
  // The launcher runs the MAS: it says where its keys come from (#831), and
  // where its kernel lives, if anywhere (#250).
  const signingKeys = signingKeysFromEnv(env);
  const kernelStore = kernelStoreFromEnv(env);
  const masKeyEnv = Object.fromEntries(KEY_ENV.flatMap((k) => (env[k] !== undefined ? [[k, env[k] as string]] : [])));
  return { ...base, signingKeys, ...(kernelStore ? { kernelStore } : {}), masKeyEnv };
}

/** A running pilot. */
export interface MasPilotLaunch {
  pilot: MasPilotParts;
  /** The MAS process, when this launcher started one. */
  masProcess?: ChildProcess;
  /** The operator consoles and the bearer every request to them presents. */
  consoles: { mas?: string; pilot: string; token: string };
  summary: string[];
  /** Close every listener and store this launcher opened, and stop the MAS process it started. Idempotent. */
  close: () => Promise<void>;
}

const SERVE_ENTRY = fileURLToPath(new URL("./mas-serve.ts", import.meta.url));
const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

/**
 * Start the MAS process with no IPC channel: it takes no operator messages,
 * so it approves only through its approval surface. Its stdout and stderr
 * are piped for its ready lines. Its stdin is a pipe this process never
 * writes, and `MAS_PILOT_EXIT_WITH_PARENT=1` has it shut down when that pipe
 * ends: when this process exits, however it exits, a SIGKILL included.
 */
export function spawnMasProcess(env: NodeJS.ProcessEnv): ChildProcess {
  return spawn(process.execPath, ["--import", TSX_LOADER, SERVE_ENTRY], {
    env: { ...env, MAS_PILOT_EXIT_WITH_PARENT: "1" },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

/**
 * Wait for the MAS process's ready line; its console line comes first when it
 * serves one. A cancelled startup stops waiting at once.
 */
function awaitMasReady(child: ChildProcess, signal: AbortSignal): Promise<{ consoleUrl?: string }> {
  let out = "";
  let err = "";
  return new Promise((resolve, reject) => {
    const settle = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      settle();
      reject(new StartupCancelled());
    };
    const timer = setTimeout(() => {
      settle();
      reject(new Error(`the MAS process did not start within 60 s${err ? `: ${err.trim()}` : ""}`));
    }, 60_000);
    signal.addEventListener("abort", onAbort, { once: true });
    child.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.includes("mas-pilot: ready ")) {
        settle();
        const consoleUrl = /mas-pilot: operator console (\S+)/.exec(out)?.[1];
        resolve(consoleUrl ? { consoleUrl } : {});
      }
    });
    child.stderr?.on("data", (d: Buffer) => {
      err += d.toString();
    });
    child.once("exit", () => {
      settle();
      const line = err.split("\n").find((l) => l.startsWith("mas-pilot: startup failed: "));
      reject(new Error(line ? line.slice("mas-pilot: ".length) : `the MAS process exited before it was ready${err ? `: ${err.trim()}` : ""}`));
    });
  });
}

/** The MAS answers at `url` under the configured Mission issuer, or startup refuses naming why. */
async function requireMasIssuer(url: string, expected: string, startup: StartupScope): Promise<void> {
  let metadata: { issuer?: unknown };
  try {
    const res = await fetch(`${url.replace(/\/$/, "")}/.well-known/openid-configuration`, {
      signal: AbortSignal.any([AbortSignal.timeout(5000), startup.signal]),
    });
    metadata = (await res.json()) as { issuer?: unknown };
  } catch (e) {
    startup.check();
    throw new Error(`the MAS at ${url} is unreachable: ${(e as Error).message}`);
  }
  if (metadata.issuer !== expected) {
    throw new Error(`the MAS at ${url} answers as issuer ${String(metadata.issuer)}, not the configured Mission issuer ${expected}`);
  }
}

/**
 * Stop a MAS process this launcher started: SIGTERM, then SIGKILL if it has
 * not exited within `graceMs`. Resolves once it has exited, and reports it.
 */
export async function stopChild(child: ChildProcess, report: (message: string) => void = () => {}, graceMs = 5000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  let forced = false;
  child.kill("SIGTERM");
  const timer = setTimeout(() => {
    forced = true;
    child.kill("SIGKILL");
  }, graceMs);
  await exited;
  clearTimeout(timer);
  report(`stopped the MAS process ${child.pid}${forced ? ` (SIGKILL after ${graceMs} ms)` : ""}`);
}

const listen = (server: Server, port: number, host: string, issuer: string): Promise<Server> =>
  new Promise<Server>((resolve, reject) => {
    server.once("listening", () => resolve(server));
    server.once("error", (e) => reject(new Error(`the MAS cannot listen at ${issuer}: ${e.message}`)));
    server.listen(port, host);
  });

const closeServer = (server: Server): Promise<void> =>
  new Promise<void>((resolve) => {
    if (!server.listening) return resolve();
    server.closeAllConnections();
    server.close(() => resolve());
  });

/** How a caller controls a launch. */
export interface MasPilotLaunchControl {
  /**
   * The launch's cleanup scope. A caller that holds it can cancel startup at
   * any point (`cancel()`), which releases everything acquired so far without
   * waiting for a blocked step; the launch then rejects with
   * `StartupCancelled`. Absent, the launch makes its own.
   */
  startup?: StartupScope;
  /** Progress lines: the MAS process started, ready, and stopped. */
  onProgress?: (message: string) => void;
}

/**
 * Start the pilot from `options`. Every resource is registered in the
 * launch's scope as it is acquired; a failure, or a cancellation, releases
 * them all, last first, the MAS process included.
 */
export async function launchMasPilot(options: MasPilotLaunchOptions, control: MasPilotLaunchControl = {}): Promise<MasPilotLaunch> {
  const { config } = options;
  const token = crypto.randomUUID();
  const issuer = masIssuer(config);
  const scope = control.startup ?? new StartupScope();
  const progress = control.onProgress ?? (() => {});
  try {
    let pilot: MasPilotParts;
    let masProcess: ChildProcess | undefined;
    let masConsole: string | undefined;
    let pilotConsole: OperatorConsole;
    const common = { openfga: options.openfga, resourcePolicyStore: options.resourcePolicyStore, config, startup: scope };
    if (options.topology === "in-process") {
      if (options.kernelStore) mkdirSync(dirname(options.kernelStore.file), { recursive: true });
      const mas = await scope.acquire(
        buildPilotMas(config, {
          ...(options.signingKeys ? { signingKeys: options.signingKeys } : {}),
          ...(options.kernelStore ? { kernelStore: options.kernelStore } : {}),
        }),
        (m) => m.built.kernel.close(),
      );
      await scope.acquire(listen(createServer(mas.built.provider.callback()), config.separated_mas.port, config.separated_mas.host, issuer), closeServer);
      pilot = await scope.step(composeMasPilot({ ...common, kernel: mas.built.kernel }));
      pilotConsole = await scope.acquire(startOperatorConsole([masConsoleRoutes(mas), pilotConsoleRoutes(pilot)], { port: 0, token }), (c) =>
        c.close(),
      );
    } else {
      let masUrl = issuer;
      let pdpKey: JWK;
      let joinIntrospectionSecret = options.joinIntrospectionSecret;
      if (options.mas) {
        masUrl = options.mas.url;
        pdpKey = options.mas.pdpKey;
      } else {
        // @spec status#mission-status-authentication (#1407): the PDP's key is
        // generated here, where the PDP runs; the MAS gets the public half.
        const pdp = await newStatusClientKey(config.separated_mas.pdp_client_id);
        pdpKey = pdp.privateJwk;
        const env: NodeJS.ProcessEnv = { ...process.env };
        for (const name of ["NODE_OPTIONS", ...KEY_ENV, "MAS_PILOT_CONFIG", "MAS_PILOT_JOIN_INTROSPECTION_SECRET"]) delete env[name];
        // @spec authority-server#join-assertion-request (#1454): the MAS's
        // introspection client secret, generated here for the MAS and the estate.
        if (config.join_assertion) joinIntrospectionSecret = crypto.randomUUID();
        Object.assign(env, options.masKeyEnv ?? {}, {
          ...(options.configPath ? { MAS_PILOT_CONFIG: options.configPath } : {}),
          MAS_PILOT_STATUS_CLIENTS: JSON.stringify([pdp.registration]),
          MAS_PILOT_OPERATOR_TOKEN: token,
          MAS_PILOT_OPERATOR_CONSOLE_PORT: "0",
          ...(joinIntrospectionSecret !== undefined ? { MAS_PILOT_JOIN_INTROSPECTION_SECRET: joinIntrospectionSecret } : {}),
        });
        scope.check();
        const child = spawnMasProcess(env);
        masProcess = child;
        // Registered as it is spawned: from here on, a failure or a signal stops it.
        scope.register(() => stopChild(child, progress));
        progress(`started the MAS process ${child.pid}`);
        masConsole = (await awaitMasReady(child, scope.signal)).consoleUrl;
        progress(`the MAS process ${child.pid} is ready at ${issuer}${masConsole ? `, its operator console at ${masConsole}` : ""}`);
      }
      await scope.step(requireMasIssuer(masUrl, config.mission_issuer, scope));
      pilot = await scope.step(
        composeSeparatedMasPilot({ ...common, mas: { url: masUrl, pdpKey }, ...(joinIntrospectionSecret !== undefined ? { joinIntrospectionSecret } : {}) }),
      );
      pilotConsole = await scope.acquire(startOperatorConsole([pilotConsoleRoutes(pilot)], { port: 0, token }), (c) => c.close());
    }
    const consoles = { ...(masConsole ? { mas: masConsole } : {}), pilot: pilotConsole.url, token };
    const keyEnv = options.masKeyEnv ?? {};
    const masKeys = options.mas
      ? "the running MAS's own"
      : `${keyEnv.MISSION_KEY_RING ? `key ring ${keyEnv.MISSION_KEY_RING}` : "ephemeral, generated at this boot"}; kernel ${
          keyEnv.MISSION_KERNEL_STORE ? `store ${keyEnv.MISSION_KERNEL_STORE}` : "in memory, lost at shutdown"
        }`;
    return {
      pilot,
      ...(masProcess ? { masProcess } : {}),
      consoles,
      summary: [
        `MAS pilot, ${options.topology === "in-process" ? "in process" : "separated"} (#818)`,
        `  MAS                ${config.mission_issuer}  (${options.topology === "in-process" ? "this process" : masProcess ? `process ${masProcess.pid}, no IPC channel` : "running elsewhere"})`,
        `  MAS keys           ${masKeys}`,
        `  estate AS          ${pilot.estate.issuer}`,
        `  gateway            ${pilot.gateway.url}  (estate credentials, joined under the mapping contract)`,
        `  resource route     ${pilot.resourceRoute.url}  (Mission-bound credentials only)`,
        `  Resource policy    ${pilot.resourcePolicy.development ? "development store" : "attached store"} ${pilot.resourcePolicy.storeId} model ${pilot.resourcePolicy.modelId}`,
        ...(config.join_assertion
          ? [
              `  Join Assertions    requested by the PEP from the MAS; required ${
                config.join_assertion.required ? "on every joined decision" : `for ${config.join_assertion.required_classes.join(", ") || "no class"}`
              }`,
            ]
          : []),
        options.topology === "in-process"
          ? `  operator console   ${pilotConsole.url}  (MAS and pilot)`
          : `  operator console   ${masConsole ?? "on the MAS's own process"}  (MAS)  ${pilotConsole.url}  (pilot)`,
        `  console bearer     ${token}`,
        "  ready. Ctrl-C to stop.",
      ],
      close: () => scope.release(),
    };
  } catch (e) {
    // A startup that fails releases what it acquired, the MAS process included.
    await scope.release().catch(() => {});
    throw e;
  }
}
