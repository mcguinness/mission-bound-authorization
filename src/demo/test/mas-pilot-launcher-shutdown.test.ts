/**
 * @spec authority-server#deployment-adoption (#818 slice 5B review)
 *
 * Stopping the MAS pilot launcher at any point, startup included, stops the
 * MAS process it started and frees every port. These run the real entry
 * points as processes (`scripts/mas-pilot.mjs` and `launcher-serve.ts`), with
 * the Resource-policy store pointed at a stub that accepts a connection and
 * never answers, so startup is blocked there after the MAS process is up. A
 * startup that fails releases the same way, and the MAS process shuts itself
 * down when the launcher dies without cleaning up (SIGKILL). The cleanup
 * scope (`startup.ts`) and the MAS process stop are witnessed on their own.
 * None of this needs OpenFGA.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer, type Server, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { loadMasPilotConfig } from "../src/mas-pilot/config.js";
import { launchMasPilot, masPilotLaunchOptions, stopChild } from "../src/mas-pilot/launcher.js";
import { newStatusClientKey } from "../src/mas-pilot/mas-as.js";
import { StartupCancelled, StartupScope } from "../src/mas-pilot/startup.js";
import { relocateEstate } from "./mas-pilot-support.js";

const SRC = fileURLToPath(new URL("../../", import.meta.url));
const DEMO = fileURLToPath(new URL("../", import.meta.url));
const dirs: string[] = [];
const strays: number[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  for (const pid of strays) if (alive(pid)) process.kill(pid, "SIGKILL");
});

function configFile(estatePort: number, masPort: number): string {
  const dir = mkdtempSync(join(tmpdir(), "mas-pilot-shutdown-"));
  dirs.push(dir);
  const base = relocateEstate(loadMasPilotConfig(), estatePort);
  const path = join(dir, "mas-pilot.json");
  writeFileSync(path, JSON.stringify({ ...base, separated_mas: { ...base.separated_mas, port: masPort } }));
  return path;
}

/** A TCP server that accepts and never answers: a stalled OpenFGA. */
async function stalledStore(): Promise<{ url: string; connected: Promise<void>; close: () => Promise<void> }> {
  const sockets = new Set<Socket>();
  let connected!: () => void;
  const first = new Promise<void>((resolve) => {
    connected = resolve;
  });
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    connected();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    connected: first,
    close: async () => {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** An HTTP server that refuses every request 400: a store that refuses. */
async function refusingStore(): Promise<{ url: string; close: () => Promise<void> }> {
  const server: HttpServer = createHttpServer((_req, res) => {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ code: "validation_error", message: "the stub store refuses" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function launcherEnv(config: string, storeUrl: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, NODE_OPTIONS: "" };
  for (const name of ["OPENFGA_CA_CERT", "OPENFGA_STORE_ID", "OPENFGA_MODEL_ID", "MAS_PILOT_MAS_URL", "MAS_PILOT_PDP_KEY", "MISSION_KEY_RING"]) {
    delete env[name];
  }
  return {
    ...env,
    MAS_PILOT_CONFIG: config,
    MAS_PILOT_DEVELOPMENT_STORE: "1",
    MISSION_EPHEMERAL_KEYS: "1",
    OPENFGA_HTTP_URL: storeUrl,
    OPENFGA_PRESHARED_KEY: "stub",
  };
}

interface Running {
  proc: ChildProcess;
  output: () => string;
  waitFor: (pattern: RegExp, ms?: number) => Promise<RegExpExecArray>;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/** The launcher as an operator starts it: through the wrapper, or its entry directly. */
function startLauncher(via: "wrapper" | "entry", topology: "in-process" | "separated", env: NodeJS.ProcessEnv): Running {
  const proc =
    via === "wrapper"
      ? spawn(process.execPath, [join(SRC, "scripts/mas-pilot.mjs"), topology], { cwd: SRC, env, stdio: ["ignore", "pipe", "pipe"] })
      : spawn(process.execPath, ["--import", "tsx", "src/mas-pilot/launcher-serve.ts", topology], {
          cwd: DEMO,
          env,
          stdio: ["ignore", "pipe", "pipe"],
        });
  let out = "";
  const waiters: (() => void)[] = [];
  const onData = (d: Buffer) => {
    out += d.toString();
    for (const w of waiters.splice(0)) w();
  };
  proc.stdout?.on("data", onData);
  proc.stderr?.on("data", onData);
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
    proc.once("exit", (code, signal) => resolve({ code, signal })),
  );
  const waitFor = (pattern: RegExp, ms = 60_000) =>
    new Promise<RegExpExecArray>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no ${pattern} within ${ms} ms in:\n${out}`)), ms);
      const check = () => {
        const m = pattern.exec(out);
        if (m) {
          clearTimeout(timer);
          resolve(m);
        } else waiters.push(check);
      };
      void exited.then(() => {
        if (!pattern.exec(out)) {
          clearTimeout(timer);
          reject(new Error(`the launcher exited before ${pattern}:\n${out}`));
        }
      });
      check();
    });
  return { proc, output: () => out, waitFor, exited };
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function within<T>(p: Promise<T>, ms: number, what: string): Promise<T | string> {
  return Promise.race([p, new Promise<string>((resolve) => setTimeout(() => resolve(`${what}: not within ${ms} ms`), ms))]);
}

async function refuses(url: string): Promise<boolean> {
  try {
    await fetch(url, { signal: AbortSignal.timeout(2000) });
    return false;
  } catch {
    return true;
  }
}

const READY = /mas-pilot: the MAS process (\d+) is ready at (http:\/\/[^,\s]+)(?:, its operator console at (\S+))?/;

describe("stopping the MAS pilot launcher during startup stops its MAS process and frees every port (#818 slice 5B review)", () => {
  it("SIGTERM to `pnpm mas-pilot:separated` while startup waits on a Resource-policy store that never answers: the launcher stops its MAS process and exits 143; the MAS, its console and the estate refuse connections", async () => {
    const store = await stalledStore();
    const launcher = startLauncher("wrapper", "separated", launcherEnv(configFile(14877, 14876), store.url));
    try {
      const [, pid, masUrl, consoleUrl] = await launcher.waitFor(READY);
      strays.push(Number(pid));
      await store.connected;
      launcher.proc.kill("SIGTERM");
      expect(await within(launcher.exited, 20_000, "exit")).toEqual({ code: 143, signal: null });
      expect(launcher.output()).toContain(`mas-pilot: stopped the MAS process ${pid}`);
      expect(alive(Number(pid))).toBe(false);
      for (const url of [masUrl as string, consoleUrl as string, "http://127.0.0.1:14877"]) expect(await refuses(url), url).toBe(true);
    } finally {
      launcher.proc.kill("SIGKILL");
      await store.close();
    }
  }, 90_000);

  it("SIGINT to the launcher itself, blocked the same way: exit 130, its MAS process stopped and its port free", async () => {
    const store = await stalledStore();
    const launcher = startLauncher("entry", "separated", launcherEnv(configFile(14879, 14878), store.url));
    try {
      const [, pid, masUrl] = await launcher.waitFor(READY);
      strays.push(Number(pid));
      await store.connected;
      launcher.proc.kill("SIGINT");
      expect(await within(launcher.exited, 20_000, "exit")).toEqual({ code: 130, signal: null });
      expect(launcher.output()).toContain(`mas-pilot: stopped the MAS process ${pid}`);
      expect(alive(Number(pid))).toBe(false);
      expect(await refuses(masUrl as string)).toBe(true);
    } finally {
      launcher.proc.kill("SIGKILL");
      await store.close();
    }
  }, 90_000);

  it("SIGTERM while the MAS process is still starting, before it is ready: the launcher stops it and exits 143", async () => {
    const store = await stalledStore();
    const launcher = startLauncher("entry", "separated", launcherEnv(configFile(14881, 14880), store.url));
    try {
      const [, pid] = await launcher.waitFor(/mas-pilot: started the MAS process (\d+)/);
      strays.push(Number(pid));
      launcher.proc.kill("SIGTERM");
      expect(await within(launcher.exited, 20_000, "exit")).toEqual({ code: 143, signal: null });
      expect(launcher.output()).not.toMatch(READY);
      expect(launcher.output()).toContain(`mas-pilot: stopped the MAS process ${pid}`);
      expect(alive(Number(pid))).toBe(false);
      expect(await refuses("http://127.0.0.1:14880")).toBe(true);
    } finally {
      launcher.proc.kill("SIGKILL");
      await store.close();
    }
  }, 90_000);

  it("SIGHUP to the in-process launcher while it waits on the store: exit 129, the MAS and estate ports free", async () => {
    const store = await stalledStore();
    const launcher = startLauncher("entry", "in-process", launcherEnv(configFile(14883, 14882), store.url));
    try {
      await within(store.connected, 60_000, "the store connection");
      expect(await refuses("http://127.0.0.1:14882/.well-known/openid-configuration")).toBe(false);
      launcher.proc.kill("SIGHUP");
      expect(await within(launcher.exited, 20_000, "exit")).toEqual({ code: 129, signal: null });
      for (const url of ["http://127.0.0.1:14882", "http://127.0.0.1:14883"]) expect(await refuses(url), url).toBe(true);
    } finally {
      launcher.proc.kill("SIGKILL");
      await store.close();
    }
  }, 90_000);

  it("a startup that fails after the MAS process is up (the store refuses) stops the MAS process before the launch rejects, and leaves no port open", async () => {
    const store = await refusingStore();
    const progress: string[] = [];
    try {
      await expect(
        launchMasPilot(
          masPilotLaunchOptions(
            { MAS_PILOT_CONFIG: configFile(14885, 14884), MAS_PILOT_DEVELOPMENT_STORE: "1", MISSION_EPHEMERAL_KEYS: "1", OPENFGA_HTTP_URL: store.url },
            "separated",
          ),
          { onProgress: (m) => progress.push(m) },
        ),
      ).rejects.toThrow();
      const pid = Number(/started the MAS process (\d+)/.exec(progress.join("\n"))?.[1]);
      strays.push(pid);
      expect(progress.some((m) => m.startsWith(`the MAS process ${pid} is ready at `))).toBe(true);
      expect(alive(pid), "the MAS process is stopped before the launch rejects").toBe(false);
      expect(progress).toContain(`stopped the MAS process ${pid}`);
      for (const url of ["http://127.0.0.1:14884", "http://127.0.0.1:14885"]) expect(await refuses(url), url).toBe(true);
    } finally {
      await store.close();
    }
  }, 90_000);
});

describe("the MAS process outlives no launcher (#818 slice 5B review)", () => {
  it("SIGKILL of the launcher, which runs no cleanup: the MAS process shuts down when its stdin pipe ends", async () => {
    const store = await stalledStore();
    const launcher = startLauncher("entry", "separated", launcherEnv(configFile(14887, 14886), store.url));
    let pid = 0;
    try {
      const [, found, masUrl] = await launcher.waitFor(READY);
      pid = Number(found);
      strays.push(pid);
      await store.connected;
      launcher.proc.kill("SIGKILL");
      await launcher.exited;
      const deadline = Date.now() + 15_000;
      while (alive(pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      expect(alive(pid), "the MAS process is gone within 15 s").toBe(false);
      expect(await refuses(masUrl as string)).toBe(true);
    } finally {
      if (pid && alive(pid)) process.kill(pid, "SIGKILL");
      await store.close();
    }
  }, 90_000);

  it("a MAS process started without MAS_PILOT_EXIT_WITH_PARENT ignores the end of its stdin", async () => {
    const env: NodeJS.ProcessEnv = { ...process.env, NODE_OPTIONS: "" };
    delete env.MAS_PILOT_EXIT_WITH_PARENT;
    const pdp = await newStatusClientKey("mas-pilot-pdp");
    Object.assign(env, {
      MAS_PILOT_CONFIG: configFile(14889, 14888),
      MISSION_EPHEMERAL_KEYS: "1",
      MAS_PILOT_STATUS_CLIENTS: JSON.stringify([pdp.registration]),
    });
    const mas = spawn(process.execPath, ["--import", "tsx", "src/mas-pilot/mas-serve.ts"], { cwd: DEMO, env, stdio: ["pipe", "pipe", "pipe"] });
    try {
      await new Promise<void>((resolve, reject) => {
        let out = "";
        mas.stdout?.on("data", (d: Buffer) => {
          out += d.toString();
          if (out.includes("mas-pilot: ready ")) resolve();
        });
        mas.once("exit", (code) => reject(new Error(`the MAS exited ${code}`)));
      });
      mas.stdin?.end();
      await new Promise((r) => setTimeout(r, 1500));
      expect(mas.exitCode).toBeNull();
      expect((await fetch("http://127.0.0.1:14888/.well-known/openid-configuration")).status).toBe(200);
    } finally {
      if (mas.exitCode === null && mas.signalCode === null) {
        const exited = new Promise<void>((resolve) => mas.once("exit", () => resolve()));
        mas.kill("SIGTERM");
        await exited;
      }
    }
  }, 60_000);

  it("stopChild escalates to SIGKILL for a MAS process that ignores SIGTERM", async () => {
    const stubborn = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); console.log('up'); setInterval(() => {}, 1000);"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    try {
      await new Promise<void>((resolve) => stubborn.stdout?.once("data", () => resolve()));
      const reports: string[] = [];
      expect(await within(stopChild(stubborn, (m) => reports.push(m), 300).then(() => "stopped"), 3000, "stopChild")).toBe("stopped");
      expect(stubborn.signalCode).toBe("SIGKILL");
      expect(reports).toEqual([`stopped the MAS process ${stubborn.pid} (SIGKILL after 300 ms)`]);
    } finally {
      if (stubborn.exitCode === null && stubborn.signalCode === null) stubborn.kill("SIGKILL");
    }
  }, 15_000);
});

describe("the launch's cleanup scope (#818 slice 5B review)", () => {
  it("cancel releases everything registered, last first, at once, while a step waits on something that never answers; the step throws StartupCancelled", async () => {
    const scope = new StartupScope();
    const released: string[] = [];
    scope.register(() => {
      released.push("first");
    });
    const child = new StartupScope(scope);
    child.register(() => {
      released.push("child");
    });
    scope.register(() => {
      released.push("last");
    });
    const blocked = scope.step(new Promise<never>(() => {}));
    expect(await within(scope.cancel().then(() => "released"), 2000, "cancel")).toBe("released");
    expect(released).toEqual(["last", "child", "first"]);
    await expect(within(blocked, 2000, "the step")).rejects.toBeInstanceOf(StartupCancelled);
    expect(child.signal.aborted).toBe(true);
  });

  it("a resource that arrives after cancellation is disposed as it arrives, and its acquire throws", async () => {
    const scope = new StartupScope();
    let arrive!: (v: string) => void;
    const disposed: string[] = [];
    const acquiring = scope.acquire(
      new Promise<string>((resolve) => {
        arrive = resolve;
      }),
      (v) => {
        disposed.push(v);
      },
    );
    await scope.cancel();
    arrive("listener");
    await expect(acquiring).rejects.toBeInstanceOf(StartupCancelled);
    await new Promise((r) => setTimeout(r, 0));
    expect(disposed).toEqual(["listener"]);
  });

  it("registering after release disposes at once and throws; a failed release still disposes the rest", async () => {
    const scope = new StartupScope();
    const disposed: string[] = [];
    scope.register(() => {
      disposed.push("kept");
    });
    scope.register(() => {
      throw new Error("this one fails");
    });
    await expect(scope.release()).rejects.toThrow(/this one fails/);
    expect(disposed).toEqual(["kept"]);
    expect(() =>
      scope.register(() => {
        disposed.push("late");
      }),
    ).toThrow(StartupCancelled);
    await new Promise((r) => setTimeout(r, 0));
    expect(disposed).toEqual(["kept", "late"]);
  });
});
