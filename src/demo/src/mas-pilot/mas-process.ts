/**
 * @spec authority-server#lifecycle-and-state (#818 slice 4b)
 *
 * Start the separated MAS (`mas-serve.ts`) as its own OS process, through
 * the same `tsx` loader the as-native launcher's tests use, and drive its
 * operator channel. The handle holds a process, never a kernel.
 */

import { type ChildProcess, spawn } from "node:child_process";
import type { StatusClientRegistration } from "./mas-as.js";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const SERVE_ENTRY = fileURLToPath(new URL("./mas-serve.ts", import.meta.url));
const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;

export interface MasProcessOptions {
  /** The pilot configuration file the process reads. */
  configPath: string;
  /** The Mission Status endpoint's clients the MAS registers (public keys), the PDP's among them (#1407). */
  statusClients: StatusClientRegistration[];
  /** The signing keys: a key ring path (with `kernelStore`, Missions survive a restart), or ephemeral keys. */
  keyRing?: string;
  kernelStore?: string;
  /** The MAS's introspection client secret at the estate, where the configuration declares `join_assertion` (#1454). */
  joinIntrospectionSecret?: string;
}

export interface MasProcess {
  child: ChildProcess;
  /** Approve a Mission through the MAS's kernel (operator channel). Resolves its identifier. */
  approve: (input: Record<string, unknown> & { intent: string }) => Promise<string>;
  /** Offset the MAS's kernel clock from real time (operator channel). */
  setClockOffset: (offsetMs: number) => Promise<void>;
  /** Record a delegate as acting under a Mission in the MAS's actor records (operator channel, #1454). */
  recordActor: (actor: { mission: { id: string; issuer: string }; clientId: string; delegatedBy: string }) => Promise<void>;
  /** SIGTERM, and resolve once the process has exited. */
  stop: () => Promise<void>;
  output: () => string;
}

export async function startMasProcess(opts: MasProcessOptions): Promise<MasProcess> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of ["NODE_OPTIONS", "MISSION_KEY_RING", "MISSION_EPHEMERAL_KEYS", "MISSION_KERNEL_STORE", "MAS_PILOT_JOIN_INTROSPECTION_SECRET"]) {
    delete env[name];
  }
  Object.assign(env, {
    MAS_PILOT_CONFIG: opts.configPath,
    MAS_PILOT_STATUS_CLIENTS: JSON.stringify(opts.statusClients),
    ...(opts.keyRing ? { MISSION_KEY_RING: opts.keyRing } : { MISSION_EPHEMERAL_KEYS: "1" }),
    ...(opts.kernelStore ? { MISSION_KERNEL_STORE: opts.kernelStore } : {}),
    ...(opts.joinIntrospectionSecret ? { MAS_PILOT_JOIN_INTROSPECTION_SECRET: opts.joinIntrospectionSecret } : {}),
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
    const timer = setTimeout(() => reject(new Error(`the MAS process did not start within 60 s\n${out}`)), 60_000);
    const check = () => {
      if (out.includes("mas-pilot: ready")) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout?.on("data", check);
    void exited.then(() => {
      clearTimeout(timer);
      reject(new Error(`the MAS process exited before it was ready\n${out}`));
    });
  });

  let next = 0;
  const pending = new Map<number, (reply: { ok: boolean; missionId?: string; error?: string }) => void>();
  child.on("message", (raw: unknown) => {
    const reply = raw as { id: number; ok: boolean; missionId?: string; error?: string };
    pending.get(reply.id)?.(reply);
    pending.delete(reply.id);
  });
  const ask = (msg: Record<string, unknown>) =>
    new Promise<{ ok: boolean; missionId?: string; error?: string }>((resolve) => {
      const id = ++next;
      pending.set(id, resolve);
      child.send({ ...msg, id });
    });

  return {
    child,
    approve: async (input) => {
      const reply = await ask({ op: "approve", input });
      if (!reply.ok || !reply.missionId) throw new Error(`MAS approve: ${reply.error ?? "no Mission"}`);
      return reply.missionId;
    },
    setClockOffset: async (offsetMs) => {
      await ask({ op: "clock", offsetMs });
    },
    recordActor: async (actor) => {
      const reply = await ask({ op: "actor", actor });
      if (!reply.ok) throw new Error(`MAS actor: ${reply.error ?? "refused"}`);
    },
    stop: async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
      await exited;
    },
    output: () => out,
  };
}
