/**
 * @spec mission-template#standing-payment-exception, metering#aggregate-bounds
 * (#813, #816, D1143 blocker 2, rulings 1 and 2): `config/standing-payment.json`
 * is read by the composition that enables standing-payment dispatch, the
 * shared demo composition with the AS, and by nothing else.
 *
 * Each case runs on a copy of the shipped `config/` named by
 * `MISSION_CONFIG_DIR`, with the module graph loaded afresh after it is set,
 * so nothing here edits the shared files. With the file absent, an ordinary
 * topology import loads and every disabled deployment starts with the
 * capability off: the issuance-only deployment, the as-native target, the MAS
 * pilot, the standalone authorization server and the shared composition
 * without the AS. The enabled composition refuses to start, before it
 * connects to anything or listens, on a missing file, invalid content, a
 * designating policy whose budget the declaration does not meter, and an
 * operator digest pin that does not match; a matching pin starts. Only the
 * OpenFGA client is stubbed, in each fresh graph.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SHIPPED_CONFIG = join(SRC, "config");
const TSX_LOADER = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const STANDALONE_AS = join(SRC, "services", "authorization-server", "src", "server.ts");
const POLICY_ID = "ap-standing-payment";
/** The shipped snapshot's digest at the shipped issuer http://localhost:4400: a pin for that issuer only. */
const SHIPPED_DIGEST_AT_4400 = "sha-256:oPOh2t72gnR7Z55KZMy34aaWVfmk7QFuQL52Fe51fPc";

type Json = Record<string, unknown>;
type Shipped = {
  dispatch_policies: Record<string, Json>;
  budget_metering: { budgets: Array<Json & { policies: Json[] }> } & Json;
};

const original = { dir: process.env.MISSION_CONFIG_DIR, resource: process.env.MCP_PAYMENTS_RESOURCE };
const dirs: string[] = [];

function restoreEnv(): void {
  if (original.dir === undefined) delete process.env.MISSION_CONFIG_DIR;
  else process.env.MISSION_CONFIG_DIR = original.dir;
  if (original.resource === undefined) delete process.env.MCP_PAYMENTS_RESOURCE;
  else process.env.MCP_PAYMENTS_RESOURCE = original.resource;
}

afterEach(() => {
  vi.restoreAllMocks();
  restoreEnv();
});
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/**
 * A copy of the shipped `config/` whose `standing-payment.json` is absent
 * (`undefined`), the given text, or the shipped file as `edit` returns it.
 */
function configDir(standingPayment: undefined | string | ((shipped: Shipped) => unknown)): string {
  const dir = mkdtempSync(join(tmpdir(), "sp-config-selection-"));
  dirs.push(dir);
  cpSync(SHIPPED_CONFIG, dir, { recursive: true });
  const file = join(dir, "standing-payment.json");
  if (standingPayment === undefined) {
    rmSync(file);
  } else if (typeof standingPayment === "string") {
    writeFileSync(file, standingPayment);
  } else {
    const shipped = JSON.parse(readFileSync(file, "utf8")) as Shipped;
    writeFileSync(file, JSON.stringify(standingPayment(shipped), null, 2));
  }
  return dir;
}

const STUB_BOOTSTRAP = {
  fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" },
  storeId: "test",
  modelId: "test",
};

/**
 * Load the module graph afresh over `dir` (and `resource` as the payments
 * resource, where given), with the OpenFGA client of this graph stubbed.
 */
async function freshGraph(dir: string, resource?: string) {
  process.env.MISSION_CONFIG_DIR = dir;
  if (resource !== undefined) process.env.MCP_PAYMENTS_RESOURCE = resource;
  vi.resetModules();
  const pdp = await import("@mission/pdp");
  const bootstrap = vi.spyOn(pdp.Fga, "bootstrap").mockResolvedValue(STUB_BOOTSTRAP as never);
  const stack = await import("../src/stack.js");
  return { pdp, bootstrap, stack };
}

type StackModule = typeof import("../src/stack.js");
type DemoStack = Awaited<ReturnType<StackModule["composeStack"]>>;

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

/** The shared composition, with the AS (the enabled path) or without it. */
function composeShared(stack: StackModule, withAuthServer: boolean, asPort: number): Promise<DemoStack> {
  return stack.composeStack({
    openfgaUrl: "http://unused.test",
    presharedKey: "unused",
    withAuthServer,
    asPort,
    claimsFile: tempFile("sp-selection-claims-", "claims.sqlite"),
    writeReservationsFile: tempFile("sp-selection-reservations-", "write-reservations.sqlite"),
    resourcePolicyStore: { bootstrap: "development" },
  });
}

async function closeStack(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.authServer?.closeAuthServer();
  await stack.resourceChannel?.close();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.evidenceRetention.close();
  stack.payments.db.close();
  stack.kernel.close();
}

/** The `claims` and `extensions` the composed resource publishes in its Enforcement Scope Statement. */
function published(stack: DemoStack): { claims: string[]; extensions: Json } {
  const statement = stack.server.protectedResourceMetadata().enforcement_scope_statement as { claims?: string[]; extensions?: Json };
  return { claims: statement.claims ?? [], extensions: statement.extensions ?? {} };
}

/** Whether anything accepts a connection at `url`. */
async function listening(url: string): Promise<boolean> {
  try {
    await fetch(url, { signal: AbortSignal.timeout(2000) });
    return true;
  } catch {
    return false;
  }
}

describe("config/standing-payment.json absent: every disabled deployment starts with the capability off, and the enabled composition refuses (@spec mission-template#standing-payment-exception, #813, #816, D1143 blocker 2, ruling 1)", () => {
  it("an ordinary topology import loads, and only the loader the enabled composition calls requires the file", async () => {
    process.env.MISSION_CONFIG_DIR = configDir(undefined);
    vi.resetModules();
    const data = await import("@mission/demo-data");
    expect(data.TOPOLOGY.ports.as).toBe(4400);
    expect(() => data.loadStandingPaymentDeployment()).toThrow(/^\[config:standing-payment\.json\] missing config file at /);
  });

  it("the issuance-only deployment starts with its own capability set, which names no standing-payment-dispatch", { timeout: 120_000 }, async () => {
    process.env.MISSION_CONFIG_DIR = configDir(undefined);
    vi.resetModules();
    const { startIssuanceOnly, ISSUANCE_ONLY_CAPABILITIES } = await import("../src/issuance-only.js");
    const deployment = await startIssuanceOnly({ introspection: false, asPort: 15151, rsPort: 15152 });
    try {
      expect(deployment.as.capabilities).toEqual(ISSUANCE_ONLY_CAPABILITIES);
      expect(deployment.as.capabilities?.has("standing-payment-dispatch")).toBe(false);
      expect(await listening("http://localhost:15151/.well-known/oauth-authorization-server")).toBe(true);
    } finally {
      await deployment.close();
    }
  });

  it("the as-native target composes with exactly its D332 capability set and publishes no budget_metering claim", { timeout: 120_000 }, async () => {
    const { stack } = await freshGraph(configDir(undefined), "http://localhost:15154/mcp");
    const composed = await stack.composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      target: "as-native",
      asPort: 15153,
      claimsFile: tempFile("sp-selection-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("sp-selection-reservations-", "write-reservations.sqlite"),
      resourcePolicyStore: { bootstrap: "development" },
    });
    try {
      expect(composed.authServer?.capabilities).toEqual(stack.AS_NATIVE_CAPABILITIES);
      expect(composed.authServer?.capabilities?.has("standing-payment-dispatch")).toBe(false);
      const { claims, extensions } = published(composed);
      expect(claims).not.toContain("budget_metering");
      expect(extensions).not.toHaveProperty("budget_metering");
    } finally {
      await closeStack(composed);
    }
  });

  it("the shared composition without the AS composes and publishes no budget_metering claim", { timeout: 120_000 }, async () => {
    const { stack } = await freshGraph(configDir(undefined));
    const composed = await composeShared(stack, false, 15158);
    try {
      expect(composed.authServer).toBeUndefined();
      const { claims, extensions } = published(composed);
      expect(claims).not.toContain("budget_metering");
      expect(extensions).not.toHaveProperty("budget_metering");
    } finally {
      await closeStack(composed);
    }
  });

  it("the MAS pilot launches in process with its MAS assembled with no capability set, so the opt-in standing-payment-dispatch is off", { timeout: 120_000 }, async () => {
    const dir = configDir(undefined);
    await freshGraph(dir);
    const { loadMasPilotConfig } = await import("../src/mas-pilot/config.js");
    const { relocateEstate } = await import("./mas-pilot-support.js");
    const { launchMasPilot, masPilotLaunchOptions } = await import("../src/mas-pilot/launcher.js");
    const { buildPilotMas } = await import("../src/mas-pilot/mas-as.js");
    const { capabilityEnabled } = await import("@mission/authorization-server");
    const base = relocateEstate(loadMasPilotConfig(), 15155);
    const config = { ...base, separated_mas: { ...base.separated_mas, port: 15156 } };
    const configPath = join(dir, "mas-pilot-selection.json");
    writeFileSync(configPath, JSON.stringify(config));
    const mas = await buildPilotMas(config);
    try {
      expect(mas.built.capabilities).toBeUndefined();
      expect(capabilityEnabled(mas.built, "standing-payment-dispatch")).toBe(false);
    } finally {
      mas.built.kernel.close();
    }
    const launch = await launchMasPilot(
      masPilotLaunchOptions({ MISSION_EPHEMERAL_KEYS: "1", MAS_PILOT_DEVELOPMENT_STORE: "1", MAS_PILOT_CONFIG: configPath }, "in-process"),
    );
    try {
      expect(await listening("http://127.0.0.1:15156/.well-known/oauth-authorization-server")).toBe(true);
    } finally {
      await launch.close();
    }
  });

  it("the standalone authorization server starts as its own process and serves its metadata, assembled with no capability set, so the opt-in standing-payment-dispatch is off", { timeout: 120_000 }, async () => {
    const dir = configDir(undefined);
    const inherited: NodeJS.ProcessEnv = { ...process.env };
    delete inherited.NODE_OPTIONS;
    const child: ChildProcess = spawn(process.execPath, ["--import", TSX_LOADER, STANDALONE_AS], {
      cwd: mkdtempSync(join(tmpdir(), "sp-selection-standalone-")),
      env: { ...inherited, MISSION_CONFIG_DIR: dir, AS_PORT: "15157", MISSION_EPHEMERAL_KEYS: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout?.on("data", (d: Buffer) => {
      output += d.toString();
    });
    child.stderr?.on("data", (d: Buffer) => {
      output += d.toString();
    });
    let exited = false;
    child.once("exit", () => {
      exited = true;
    });
    try {
      let metadata: Response | undefined;
      for (let i = 0; i < 300 && !exited && !metadata; i++) {
        metadata = await fetch("http://localhost:15157/.well-known/oauth-authorization-server").catch(() => undefined);
        if (!metadata) await new Promise((r) => setTimeout(r, 200));
      }
      expect(metadata?.status, output).toBe(200);
      expect(((await metadata?.json()) as Json).issuer).toBe("http://localhost:15157");
    } finally {
      child.kill("SIGKILL");
    }
    process.env.MISSION_CONFIG_DIR = dir;
    vi.resetModules();
    const { buildAuthorizationServer, capabilityEnabled } = await import("@mission/authorization-server");
    const built = await buildAuthorizationServer({ issuer: "http://localhost:15157", signingKeys: { ephemeral: true } });
    try {
      expect(built.capabilities).toBeUndefined();
      expect(capabilityEnabled(built, "standing-payment-dispatch")).toBe(false);
    } finally {
      built.kernel.close();
    }
  });

  it("the enabled composition refuses to start, naming the missing file, before it connects to anything or listens", async () => {
    const { bootstrap, stack } = await freshGraph(configDir(undefined));
    await expect(composeShared(stack, true, 15159)).rejects.toThrow(/^\[config:standing-payment\.json\] missing config file at /);
    expect(bootstrap).not.toHaveBeenCalled();
    expect(await listening("http://localhost:15159/")).toBe(false);
  });
});

describe("config/standing-payment.json invalid or pinned: the enabled composition refuses before it connects or listens, and a matching pin starts (@spec mission-template#standing-payment-exception, metering#aggregate-bounds, #813, #816, D1143 blocker 2, ruling 2)", () => {
  /** Compose the enabled composition over `dir` at `asPort` and return its refusal; nothing connected, nothing listens. */
  async function refusal(dir: string, asPort: number): Promise<string> {
    const { bootstrap, stack } = await freshGraph(dir);
    const outcome = await composeShared(stack, true, asPort).then(
      async (composed) => {
        await closeStack(composed);
        return undefined;
      },
      (e: unknown) => (e as Error).message,
    );
    expect(outcome, "the enabled composition started").toBeTypeOf("string");
    expect(bootstrap).not.toHaveBeenCalled();
    expect(await listening(`http://localhost:${asPort}/`)).toBe(false);
    return outcome as string;
  }

  it("refuses a file that is not JSON", async () => {
    expect(await refusal(configDir("{ not json"), 15160)).toMatch(/^\[config:standing-payment\.json\] invalid JSON: /);
  });

  it("refuses a file missing a required member: the budget_metering declaration, or a policy's version", async () => {
    const noDeclaration = configDir(({ budget_metering: _, ...rest }) => rest);
    expect(await refusal(noDeclaration, 15160)).toBe("[config:standing-payment.json] budget_metering must be an object");
    const noVersion = configDir((shipped) => {
      const { version: _, ...policy } = shipped.dispatch_policies[POLICY_ID] as Json;
      return { ...shipped, dispatch_policies: { [POLICY_ID]: policy } };
    });
    expect(await refusal(noVersion, 15160)).toBe(
      `[config:standing-payment.json] dispatch_policies.${POLICY_ID}.version must be a non-empty string`,
    );
  });

  it("refuses a designating policy whose budget the declaration does not meter, and a declared budget naming a policy version the file does not hold", async () => {
    const otherBudget = configDir((shipped) => {
      const [budget] = shipped.budget_metering.budgets;
      return { ...shipped, budget_metering: { ...shipped.budget_metering, budgets: [{ ...budget, budget_id: "another-budget" }] } };
    });
    expect(await refusal(otherBudget, 15160)).toBe(
      `Dispatch Policy ${POLICY_ID} designates a standing payment, but the Enforcement Scope Statement's budget_metering declares no budget payments-operator/ap-standing-payments: its budget is not metered under the Exact profile`,
    );
    const otherVersion = configDir((shipped) => {
      const [budget] = shipped.budget_metering.budgets;
      return {
        ...shipped,
        budget_metering: { ...shipped.budget_metering, budgets: [{ ...budget, policies: [{ id: POLICY_ID, version: "2" }] }] },
      };
    });
    expect(await refusal(otherVersion, 15160)).toBe(
      `config/standing-payment.json declares a budget under Dispatch Policy ${POLICY_ID} version 2, which it does not hold`,
    );
  });

  it("refuses a member the loader does not read, such as a digest beside a Dispatch Policy, rather than dropping it", async () => {
    const dir = configDir((shipped) => ({
      ...shipped,
      dispatch_policies: { [POLICY_ID]: { ...shipped.dispatch_policies[POLICY_ID], digest: SHIPPED_DIGEST_AT_4400 } },
    }));
    expect(await refusal(dir, 15160)).toBe(`[config:standing-payment.json] dispatch_policies.${POLICY_ID} has unknown member digest`);
  });

  it("refuses an operator digest pin that does not match the digest this issuer computes, the shipped issuer's own value pinned at another issuer included", async () => {
    const dir = configDir((shipped) => {
      const [budget] = shipped.budget_metering.budgets;
      return {
        ...shipped,
        budget_metering: {
          ...shipped.budget_metering,
          budgets: [{ ...budget, policies: [{ id: POLICY_ID, version: "1", digest: SHIPPED_DIGEST_AT_4400 }] }],
        },
      };
    });
    expect(await refusal(dir, 15161)).toMatch(
      new RegExp(
        `^config/standing-payment\\.json pins Dispatch Policy ${POLICY_ID} version 1 at digest ${SHIPPED_DIGEST_AT_4400}, but issuer http://localhost:15161 computes sha-256:[A-Za-z0-9_-]{43} over the snapshot the file holds$`,
      ),
    );
  });

  it("starts with an operator digest pin equal to the digest this issuer computes, and publishes that digest", { timeout: 120_000 }, async () => {
    const issuer = "http://localhost:15162";
    const shipped = JSON.parse(readFileSync(join(SHIPPED_CONFIG, "standing-payment.json"), "utf8")) as Shipped;
    const policy = shipped.dispatch_policies[POLICY_ID] as { version: string; content_type: string; content: Json };
    const { mintActivationPolicyRef } = await import("@mission/authorization-server");
    const pin = mintActivationPolicyRef(
      issuer,
      { [POLICY_ID]: { version: policy.version, content_type: policy.content_type, content: JSON.stringify(policy.content) } },
      POLICY_ID,
      "1",
    );
    expect(pin?.digest).toMatch(/^sha-256:/);
    const dir = configDir((s) => {
      const [budget] = s.budget_metering.budgets;
      return { ...s, budget_metering: { ...s.budget_metering, budgets: [{ ...budget, policies: [pin] }] } };
    });
    const { stack } = await freshGraph(dir);
    const composed = await composeShared(stack, true, 15162);
    try {
      expect(composed.authServer?.capabilities?.has("standing-payment-dispatch")).toBe(true);
      const { claims, extensions } = published(composed);
      expect(claims).toContain("budget_metering");
      const declared = extensions.budget_metering as { budgets: Array<{ policies: unknown[] }> };
      expect(declared.budgets[0]?.policies).toEqual([pin]);
    } finally {
      await closeStack(composed);
    }
  });
});
