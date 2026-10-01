/**
 * The issuance-only commands as a shell runs them (#873, PR #891 review): the
 * real `scripts/issuance-only.mjs` wrapper, spawned on test ports. A SIGTERM
 * sent to the wrapper's pid alone stops it promptly, the server process exits
 * through its own close handler (status 0), and both ports are free
 * afterwards. The walkthrough wrapper exits with the walkthrough's status.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../../", import.meta.url));
const AS_PORT = 14670;
const RS_PORT = 14671;

const spawned: ChildProcess[] = [];
const dirs: string[] = [];

afterEach(() => {
  // A failed run must not leave a server behind: each wrapper leads its own
  // process group, so the group is killed outright, even when the wrapper has
  // already exited (a server it failed to stop is still in the group).
  for (const p of spawned.splice(0)) {
    if (p.pid === undefined) continue;
    try {
      process.kill(-p.pid, "SIGKILL");
    } catch {
      // the group is gone
    }
  }
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function credentialsPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "issuance-only-signals-"));
  dirs.push(dir);
  return join(dir, "credentials.json");
}

function wrapper(script: string, env: Record<string, string>): ChildProcess {
  const child = spawn(process.execPath, [script], {
    cwd: SRC,
    env: { ...process.env, ...env },
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  spawned.push(child);
  return child;
}

function exited(child: ChildProcess, withinMs: number): Promise<{ code: number | null; signal: string | null }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no exit within ${withinMs} ms`)), withinMs);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

/** Resolve once the launcher prints its ready line (both servers listen by then). */
function ready(output: () => string, withinMs: number): Promise<void> {
  const deadline = Date.now() + withinMs;
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (output().includes("ready;")) resolve();
      else if (Date.now() > deadline) reject(new Error(`not ready within ${withinMs} ms:\n${output()}`));
      else setTimeout(poll, 100);
    };
    poll();
  });
}

/** The port can be bound again, so nothing is listening on it. */
function bindable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.once("error", () => resolve(false));
    probe.listen(port, () => probe.close(() => resolve(true)));
  });
}

/**
 * Boot the launcher wrapper on the test ports, deliver `signal` to its pid (or
 * to its whole process group, as a terminal does on Ctrl-C), and assert a
 * prompt exit 0 with both ports free.
 */
async function stopsCleanly(signal: NodeJS.Signals, target: "wrapper" | "group"): Promise<void> {
  const launcher = wrapper("scripts/issuance-only.mjs", {
    AS_PORT: String(AS_PORT),
    PLAIN_RS_PORT: String(RS_PORT),
    ISSUANCE_ONLY_CREDENTIALS: credentialsPath(),
  });
  let output = "";
  launcher.stdout?.on("data", (d) => {
    output += String(d);
  });
  launcher.stderr?.on("data", (d) => {
    output += String(d);
  });
  await ready(() => output, 30_000);
  expect((await fetch(`http://localhost:${AS_PORT}/jwks`)).status).toBe(200);
  expect(await bindable(AS_PORT)).toBe(false);
  expect(await bindable(RS_PORT)).toBe(false);

  const exit = exited(launcher, 10_000);
  const pid = launcher.pid as number;
  process.kill(target === "group" ? -pid : pid, signal);
  expect(await exit, output).toEqual({ code: 0, signal: null });
  expect(await bindable(AS_PORT)).toBe(true);
  expect(await bindable(RS_PORT)).toBe(true);
}

describe("the issuance-only commands under signals (#873)", () => {
  it("SIGTERM to the launcher wrapper's pid alone stops both servers: exit 0 within 10 s and both ports free", async () => {
    await stopsCleanly("SIGTERM", "wrapper");
  }, 60_000);

  it("SIGHUP to the launcher wrapper's pid alone stops both servers the same way", async () => {
    await stopsCleanly("SIGHUP", "wrapper");
  }, 60_000);

  it("SIGINT to the launcher's whole process group (a terminal Ctrl-C, which reaches the server twice) stops both servers: exit 0 and both ports free", async () => {
    await stopsCleanly("SIGINT", "group");
  }, 60_000);

  it("the walkthrough wrapper exits with the walkthrough's status: 1 when no deployment's credentials exist", async () => {
    const walkthrough = wrapper("scripts/issuance-only-walkthrough.mjs", {
      ISSUANCE_ONLY_CREDENTIALS: credentialsPath(),
    });
    expect(await exited(walkthrough, 30_000)).toEqual({ code: 1, signal: null });
  }, 60_000);
});
