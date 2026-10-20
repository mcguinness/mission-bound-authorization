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
 * Either way the MAS's URL is the Mission issuer, approval runs on its
 * approval surface and revocation and containment on its Lifecycle
 * endpoint, through the operator console (`operator-console.ts`). The
 * Resource-policy store is attached (configured store and model, verified,
 * nothing written); a development store is bootstrapped only on the explicit
 * `MAS_PILOT_DEVELOPMENT_STORE=1`.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import type { Server } from "node:http";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { kernelStoreFromEnv, type SigningKeySource, signingKeysFromEnv } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";
import type { ResourcePolicyStore } from "../resource-policy-store.js";
import { composeMasPilot, type MasPilotParts } from "./compose.js";
import { loadMasPilotConfig, type MasPilotConfig, relocateMissionIssuer } from "./config.js";
import { parseMappingContract } from "./mapping-contract.js";
import { buildPilotMas, masIssuer } from "./mas-as.js";
import { masConsoleRoutes, type OperatorConsole, pilotConsoleRoutes, startOperatorConsole } from "./operator-console.js";
import { composeSeparatedMasPilot } from "./separated.js";

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
  /** Separated only: an already running MAS and the PDP credential it registered, instead of starting one. */
  mas?: { url: string; pdpToken: string };
  /** The MAS process's key environment (`MISSION_KEY_RING`, `MISSION_EPHEMERAL_KEYS`, `MISSION_KERNEL_STORE`). */
  masKeyEnv?: Record<string, string>;
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
  // @spec authority-server#mapping-contract: the gateway mounts a join route,
  // so the contract it applies is declared, and loads, before anything starts.
  try {
    parseMappingContract(loaded.mapping_contract);
  } catch (e) {
    throw new Error(`the configuration declares no usable mapping contract: ${(e as Error).message}`);
  }
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
  const pdpToken = env.MAS_PILOT_PDP_TOKEN;
  if (topology === "in-process" && (masUrl !== undefined || pdpToken !== undefined)) {
    throw new Error("MAS_PILOT_MAS_URL and MAS_PILOT_PDP_TOKEN apply to the separated topology only; in process, the launcher runs the MAS");
  }
  if ((masUrl === undefined) !== (pdpToken === undefined)) {
    throw new Error("set both MAS_PILOT_MAS_URL and MAS_PILOT_PDP_TOKEN to use a running MAS, or neither to start one");
  }
  const base: MasPilotLaunchOptions = {
    topology,
    config,
    ...(configPath ? { configPath } : {}),
    openfga: { apiUrl, presharedKey: env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey, ...(ca ? { caCertPath: ca } : {}) },
    resourcePolicyStore,
  };
  if (masUrl !== undefined && pdpToken !== undefined) return { ...base, mas: { url: masUrl, pdpToken } };
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
 * Start the MAS process with no IPC channel: its standard streams are piped
 * for its ready lines, and it takes no operator messages, so it approves
 * only through its approval surface.
 */
export function spawnMasProcess(env: NodeJS.ProcessEnv): ChildProcess {
  return spawn(process.execPath, ["--import", TSX_LOADER, SERVE_ENTRY], { env, stdio: ["ignore", "pipe", "pipe"] });
}

/** Wait for the MAS process's ready line; its console line comes first when it serves one. */
function awaitMasReady(child: ChildProcess): Promise<{ consoleUrl?: string }> {
  let out = "";
  let err = "";
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`the MAS process did not start within 60 s${err ? `: ${err.trim()}` : ""}`)), 60_000);
    child.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
      if (out.includes("mas-pilot: ready ")) {
        clearTimeout(timer);
        const consoleUrl = /mas-pilot: operator console (\S+)/.exec(out)?.[1];
        resolve(consoleUrl ? { consoleUrl } : {});
      }
    });
    child.stderr?.on("data", (d: Buffer) => {
      err += d.toString();
    });
    child.once("exit", () => {
      clearTimeout(timer);
      const line = err.split("\n").find((l) => l.startsWith("mas-pilot: startup failed: "));
      reject(new Error(line ? line.slice("mas-pilot: ".length) : `the MAS process exited before it was ready${err ? `: ${err.trim()}` : ""}`));
    });
  });
}

/** The MAS answers at `url` under the configured Mission issuer, or startup refuses naming why. */
async function requireMasIssuer(url: string, expected: string): Promise<void> {
  let metadata: { issuer?: unknown };
  try {
    const res = await fetch(`${url.replace(/\/$/, "")}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(5000) });
    metadata = (await res.json()) as { issuer?: unknown };
  } catch (e) {
    throw new Error(`the MAS at ${url} is unreachable: ${(e as Error).message}`);
  }
  if (metadata.issuer !== expected) {
    throw new Error(`the MAS at ${url} answers as issuer ${String(metadata.issuer)}, not the configured Mission issuer ${expected}`);
  }
}

const stopChild = async (child: ChildProcess | undefined): Promise<void> => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  await exited;
};

/** Start the pilot from `options`. A failure releases everything it opened. */
export async function launchMasPilot(options: MasPilotLaunchOptions): Promise<MasPilotLaunch> {
  const { config } = options;
  const token = crypto.randomUUID();
  const issuer = masIssuer(config);
  const opened: (() => Promise<void>)[] = [];
  const release = async () => {
    for (const close of opened.splice(0).reverse()) await close();
  };
  try {
    let pilot: MasPilotParts;
    let masProcess: ChildProcess | undefined;
    let masConsole: string | undefined;
    let pilotConsole: OperatorConsole;
    const common = { openfga: options.openfga, resourcePolicyStore: options.resourcePolicyStore, config };
    if (options.topology === "in-process") {
      if (options.kernelStore) mkdirSync(dirname(options.kernelStore.file), { recursive: true });
      const mas = await buildPilotMas(config, {
        ...(options.signingKeys ? { signingKeys: options.signingKeys } : {}),
        ...(options.kernelStore ? { kernelStore: options.kernelStore } : {}),
      });
      opened.push(async () => mas.built.kernel.close());
      const server: Server = mas.built.provider.listen(config.separated_mas.port, config.separated_mas.host);
      await new Promise<void>((resolve, reject) => {
        server.once("listening", () => resolve());
        server.once("error", (e) => reject(new Error(`the MAS cannot listen at ${issuer}: ${e.message}`)));
      });
      opened.push(
        () =>
          new Promise<void>((resolve) => {
            server.closeAllConnections();
            server.close(() => resolve());
          }),
      );
      const composed = await composeMasPilot({ ...common, kernel: mas.built.kernel });
      opened.push(composed.close);
      pilot = composed;
      pilotConsole = await startOperatorConsole([masConsoleRoutes(mas), pilotConsoleRoutes(pilot)], { port: 0, token });
    } else {
      let masUrl = issuer;
      let pdpToken: string;
      if (options.mas) {
        masUrl = options.mas.url;
        pdpToken = options.mas.pdpToken;
      } else {
        pdpToken = crypto.randomUUID();
        const env: NodeJS.ProcessEnv = { ...process.env };
        for (const name of ["NODE_OPTIONS", ...KEY_ENV, "MAS_PILOT_CONFIG"]) delete env[name];
        Object.assign(env, options.masKeyEnv ?? {}, {
          ...(options.configPath ? { MAS_PILOT_CONFIG: options.configPath } : {}),
          MAS_PILOT_PDP_TOKEN: pdpToken,
          MAS_PILOT_OPERATOR_TOKEN: token,
          MAS_PILOT_OPERATOR_CONSOLE_PORT: "0",
        });
        const child = spawnMasProcess(env);
        masProcess = child;
        opened.push(() => stopChild(child));
        masConsole = (await awaitMasReady(child)).consoleUrl;
      }
      await requireMasIssuer(masUrl, config.mission_issuer);
      const composed = await composeSeparatedMasPilot({ ...common, mas: { url: masUrl, pdpToken } });
      opened.push(composed.close);
      pilot = composed;
      pilotConsole = await startOperatorConsole([pilotConsoleRoutes(pilot)], { port: 0, token });
    }
    opened.push(pilotConsole.close);
    const consoles = { ...(masConsole ? { mas: masConsole } : {}), pilot: pilotConsole.url, token };
    const keyEnv = options.masKeyEnv ?? {};
    const masKeys = options.mas
      ? "the running MAS's own"
      : `${keyEnv.MISSION_KEY_RING ? `key ring ${keyEnv.MISSION_KEY_RING}` : "ephemeral, generated at this boot"}; kernel ${
          keyEnv.MISSION_KERNEL_STORE ? `store ${keyEnv.MISSION_KERNEL_STORE}` : "in memory, lost at shutdown"
        }`;
    let closing: Promise<void> | undefined;
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
        options.topology === "in-process"
          ? `  operator console   ${pilotConsole.url}  (MAS and pilot)`
          : `  operator console   ${masConsole ?? "on the MAS's own process"}  (MAS)  ${pilotConsole.url}  (pilot)`,
        `  console bearer     ${token}`,
        "  ready. Ctrl-C to stop.",
      ],
      close: () => (closing ??= release()),
    };
  } catch (e) {
    await release();
    throw e;
  }
}
