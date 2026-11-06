/**
 * @spec runtime#state-freshness (#1101)
 *
 * Start the separated AS-native configuration's authorization server
 * (`as-serve.ts`) as its own OS process, through the `tsx` loader, and drive
 * its operator channel. The handle holds a process, never a kernel.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { LifecycleClientRegistration } from "@mission/authorization-server";
import type { StatusClientRegistration } from "../mas-pilot/mas-as.js";
import type { ApproverLoginConfig } from "./as-server.js";

const SERVE_ENTRY = fileURLToPath(new URL("./as-serve.ts", import.meta.url));
const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

export interface SeparatedAsProcessOptions {
  /** The configuration file the process reads. */
  configPath: string;
  statusClients: readonly StatusClientRegistration[];
  lifecycleClient: LifecycleClientRegistration;
  approverLogin: ApproverLoginConfig;
  /** The signing keys: a key ring with its binding record (with `kernelStore`, Missions survive a restart), or ephemeral keys. */
  keyRing?: { ring: string; bindings: string };
  /** The kernel's file and its recovery witness, which require `keyRing`. */
  kernelStore?: { file: string; witness: string };
  /** The process clock's offset from real time at start (operator channel; `setClockOffset` moves it). */
  clockOffsetMs?: number;
}

export interface SeparatedAsProcess {
  child: ChildProcess;
  /** The submitting agent's private key at this boot (operator channel). */
  agentClientJwk: () => Promise<Record<string, unknown>>;
  /** Offset the AS process's clock from real time (operator channel). */
  setClockOffset: (offsetMs: number) => Promise<void>;
  /** Decide the oldest pending action-bound approval (operator channel). */
  adjudicate: (decision: "approve" | "deny") => Promise<void>;
  /** Suspend a Mission in the kernel (operator channel; no Lifecycle operation serves it here). */
  suspend: (missionId: string) => Promise<void>;
  /** Contain a Mission's authority in the kernel (operator channel; no Lifecycle operation serves it here). */
  contain: (missionId: string, remove: { resource: string; actions?: string[] }[]) => Promise<void>;
  /** SIGTERM, and resolve once the process has exited. */
  stop: () => Promise<void>;
  output: () => string;
}

export async function startSeparatedAsProcess(opts: SeparatedAsProcessOptions): Promise<SeparatedAsProcess> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of [
    "NODE_OPTIONS",
    "MISSION_KEY_RING",
    "MISSION_KEY_BINDINGS",
    "MISSION_EPHEMERAL_KEYS",
    "MISSION_KERNEL_STORE",
    "MISSION_KERNEL_WITNESS",
    "AS_NATIVE_SEPARATED_EXIT_WITH_PARENT",
    "AS_NATIVE_SEPARATED_CLOCK_OFFSET_MS",
  ]) {
    delete env[name];
  }
  Object.assign(env, {
    AS_NATIVE_SEPARATED_CONFIG: opts.configPath,
    AS_NATIVE_SEPARATED_STATUS_CLIENTS: JSON.stringify(opts.statusClients),
    AS_NATIVE_SEPARATED_LIFECYCLE_CLIENT: JSON.stringify(opts.lifecycleClient),
    AS_NATIVE_SEPARATED_APPROVER_LOGIN: JSON.stringify(opts.approverLogin),
    ...(opts.keyRing
      ? { MISSION_KEY_RING: opts.keyRing.ring, MISSION_KEY_BINDINGS: opts.keyRing.bindings }
      : { MISSION_EPHEMERAL_KEYS: "1" }),
    ...(opts.kernelStore ? { MISSION_KERNEL_STORE: opts.kernelStore.file, MISSION_KERNEL_WITNESS: opts.kernelStore.witness } : {}),
    ...(opts.clockOffsetMs !== undefined ? { AS_NATIVE_SEPARATED_CLOCK_OFFSET_MS: String(opts.clockOffsetMs) } : {}),
  });
  const child = spawn(process.execPath, ["--import", TSX_LOADER, SERVE_ENTRY], { env, stdio: ["ignore", "pipe", "pipe", "ipc"] });
  let out = "";
  child.stdout?.on("data", (d: Buffer) => {
    out += d.toString();
  });
  child.stderr?.on("data", (d: Buffer) => {
    out += d.toString();
  });
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`the AS process did not start within 60 s\n${out}`)), 60_000);
    const check = () => {
      if (out.includes("as-native-separated: ready")) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout?.on("data", check);
    void exited.then(() => {
      clearTimeout(timer);
      reject(new Error(`the AS process exited before it was ready\n${out}`));
    });
  });

  let next = 0;
  type Reply = { ok: boolean; error?: string; agentClientJwk?: Record<string, unknown> };
  const pending = new Map<number, (reply: Reply) => void>();
  child.on("message", (raw: unknown) => {
    const reply = raw as Reply & { id: number };
    pending.get(reply.id)?.(reply);
    pending.delete(reply.id);
  });
  const ask = async (msg: Record<string, unknown>): Promise<Reply> => {
    const reply = await new Promise<Reply>((resolve) => {
      const id = ++next;
      pending.set(id, resolve);
      child.send({ ...msg, id });
    });
    if (!reply.ok) throw new Error(`AS operator message ${String(msg.op)}: ${reply.error ?? "refused"}`);
    return reply;
  };

  return {
    child,
    agentClientJwk: async () => (await ask({ op: "credentials" })).agentClientJwk as Record<string, unknown>,
    setClockOffset: async (offsetMs) => {
      await ask({ op: "clock", offsetMs });
    },
    adjudicate: async (decision) => {
      await ask({ op: "adjudicate", decision });
    },
    suspend: async (missionId) => {
      await ask({ op: "suspend", missionId });
    },
    contain: async (missionId, remove) => {
      await ask({ op: "contain", missionId, remove });
    },
    stop: async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
      await exited;
    },
    output: () => out,
  };
}
