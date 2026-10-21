/**
 * @spec authority-server#deployment-adoption, runtime#input-resource-policy (#818 slice 5B)
 *
 * The MAS pilot's operator launchers, driven through the same functions
 * `pnpm mas-pilot` and `pnpm mas-pilot:separated` run (`launcher.ts`): each
 * topology starts, approves a Mission through the MAS's approval surface,
 * permits a joined read for a JWT and an opaque estate credential, refuses
 * after a revocation at the MAS's Lifecycle endpoint with its evidence record,
 * and shuts down releasing every port. The separated MAS process is started
 * with no IPC channel. Each startup refusal fails before anything connects.
 * The smoke tests need a live OpenFGA and skip without one; the refusals never
 * skip.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Fga } from "@mission/pdp";
import { decodeJwt, decodeProtectedHeader, generateKeyPair, SignJWT } from "jose";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { launchMasPilot, type MasPilotLaunch, masPilotLaunchOptions, type MasPilotTopology, spawnMasProcess } from "../src/mas-pilot/launcher.js";
import { estateToken, handshakeStatus, OPENFGA, openfgaReachable, relocateEstate } from "./mas-pilot-support.js";

const d = (await openfgaReachable()) ? describe : describe.skip;
const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.restoreAllMocks();
});

/** A pilot configuration file with its estate and MAS on these ports. */
function configFile(estatePort: number, masPort: number, edit: (c: MasPilotConfig) => MasPilotConfig = (c) => c): string {
  const dir = mkdtempSync(join(tmpdir(), "mas-pilot-launcher-"));
  dirs.push(dir);
  const base = relocateEstate(loadMasPilotConfig(), estatePort);
  const config = edit({ ...base, separated_mas: { ...base.separated_mas, port: masPort } });
  const path = join(dir, "mas-pilot.json");
  writeFileSync(path, JSON.stringify(config));
  return path;
}

const fgaEnv = () => ({
  OPENFGA_HTTP_URL: OPENFGA.apiUrl,
  OPENFGA_PRESHARED_KEY: OPENFGA.presharedKey,
  ...(OPENFGA.caCertPath ? { OPENFGA_CA_CERT: OPENFGA.caCertPath } : {}),
});

type Json = Record<string, unknown>;
async function consoleRequest(launch: MasPilotLaunch, base: string, path: string, body?: Json, token = launch.consoles.token) {
  const res = await fetch(`${base}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

const refusesConnection = async (url: string): Promise<boolean> => {
  try {
    await fetch(url, { signal: AbortSignal.timeout(2000) });
    return false;
  } catch {
    return true;
  }
};

/**
 * One topology's operator walk: approve three Missions, a joined read with a
 * JWT and with an opaque estate credential on the first, a revocation of the
 * second before any read of it and the refusal with its Decision Evidence,
 * and a containment of the third before any read of it and its refusal
 * (`authority_contained` in process; `out_of_authority`, the Status view's
 * declared diagnostic, separated).
 */
async function walk(launch: MasPilotLaunch, masConsole: string, containedReason: string) {
  const pilotConsole = launch.consoles.pilot;
  // The console refuses a request without its bearer.
  for (const wrong of ["wrong", "x".repeat(launch.consoles.token.length)]) {
    expect((await consoleRequest(launch, pilotConsole, "/missions/x/evidence", undefined, wrong)).status).toBe(401);
    expect((await consoleRequest(launch, masConsole, "/missions", {}, wrong)).status).toBe(401);
  }

  const approved = await consoleRequest(launch, masConsole, "/missions", { subject: "alice", label: "launcher-read" });
  expect(approved, JSON.stringify(approved)).toMatchObject({ status: 201, body: { issuer: launch.pilot.missionIssuer } });
  const missionId = approved.body.mission_id as string;

  for (const [client, format] of [
    ["estate-ap-bot-7f3", "jwt"],
    ["estate-opaque-bot-4e2", "opaque"],
  ] as const) {
    const credential = await consoleRequest(launch, pilotConsole, "/estate-tokens", { client_id: client, account: "u-1001", scope: "invoices.read" });
    expect(credential, JSON.stringify(credential)).toMatchObject({ status: 201, body: { token_format: format } });
    const read = await consoleRequest(launch, pilotConsole, "/calls", {
      credential_id: credential.body.credential_id,
      mission_id: missionId,
      tool: "get_invoice",
      arguments: { invoice_id: "inv-1" },
    });
    expect(read.body.ok, `${format}: ${JSON.stringify(read.body)}`).toBe(true);
  }

  const revokedMission = (await consoleRequest(launch, masConsole, "/missions", { subject: "alice", label: "launcher-revoke" })).body
    .mission_id as string;
  const revoked = await consoleRequest(launch, masConsole, `/missions/${revokedMission}/revoke`, {});
  expect(revoked, JSON.stringify(revoked)).toMatchObject({ status: 200, body: { state: "terminated" } });
  const credential = await consoleRequest(launch, pilotConsole, "/estate-tokens", {
    client_id: "estate-ap-bot-7f3",
    account: "u-1001",
    scope: "invoices.read",
  });
  const refused = await consoleRequest(launch, pilotConsole, "/calls", {
    credential_id: credential.body.credential_id,
    mission_id: revokedMission,
    tool: "get_invoice",
    arguments: { invoice_id: "inv-1" },
  });
  expect(refused.body).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
  const evidence = await consoleRequest(launch, pilotConsole, `/missions/${revokedMission}/evidence`);
  expect((evidence.body.records as Json[]).at(-1)).toMatchObject({ kind: "decision", decision: "deny", denial_reason: "mission_inactive" });

  // A containment at the MAS's Lifecycle endpoint, before any read of the
  // Mission: the contained read is refused with the topology's diagnostic.
  const containedMission = (await consoleRequest(launch, masConsole, "/missions", { subject: "alice", label: "launcher-contain" })).body
    .mission_id as string;
  const contained = await consoleRequest(launch, masConsole, `/missions/${containedMission}/contain`, { actions: ["payments:invoice.read"] });
  expect(contained, JSON.stringify(contained)).toMatchObject({ status: 200, body: { state: "active", containment_version: 1 } });
  const containedRead = await consoleRequest(launch, pilotConsole, "/calls", {
    credential_id: credential.body.credential_id,
    mission_id: containedMission,
    tool: "get_invoice",
    arguments: { invoice_id: "inv-1" },
  });
  expect(containedRead.body).toMatchObject({ ok: false, denial_reason: containedReason });
}

async function launchFor(topology: MasPilotTopology, estatePort: number, masPort: number): Promise<MasPilotLaunch> {
  return launchMasPilot(
    masPilotLaunchOptions(
      { ...fgaEnv(), MAS_PILOT_CONFIG: configFile(estatePort, masPort), MAS_PILOT_DEVELOPMENT_STORE: "1", MISSION_EPHEMERAL_KEYS: "1" },
      topology,
    ),
  );
}

d("the MAS pilot launcher, in process (#818 slice 5B)", () => {
  it("starts, approves through the MAS's approval surface, permits joined reads for a JWT and an opaque estate credential, refuses after a revocation and a containment at the MAS, and releases every port on shutdown", async () => {
    const launch = await launchFor("in-process", 14859, 14858);
    try {
      expect(launch.masProcess).toBeUndefined();
      expect(launch.summary).toContain("  MAS keys           ephemeral, generated at this boot; kernel in memory, lost at shutdown");
      await walk(launch, launch.consoles.pilot, "authority_contained");
    } finally {
      await launch.close();
    }
    for (const url of ["http://127.0.0.1:14858", "http://127.0.0.1:14859", launch.pilot.gateway.url, launch.consoles.pilot]) {
      expect(await refusesConnection(url), url).toBe(true);
    }
  }, 120_000);

  it("estate key rotation: a JWT under a key the gateway did not read at startup is refused before any decision, with no JWKS refetch; an opaque credential is unaffected", async () => {
    const launch = await launchFor("in-process", 14865, 14864);
    try {
      const missionId = (await consoleRequest(launch, launch.consoles.pilot, "/missions", { subject: "alice", label: "launcher-rotation" })).body
        .mission_id as string;
      const issued = await estateToken(launch.pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
      expect(decodeProtectedHeader(issued.token).kid).toBe(launch.pilot.estate.kid);
      expect(await handshakeStatus(launch.pilot, issued, missionId)).toBe(200);

      // The same token, signed under the key an estate would rotate to.
      const next = await generateKeyPair("ES256");
      const rotated = {
        ...issued,
        token: await new SignJWT(decodeJwt(issued.token))
          .setProtectedHeader({ ...decodeProtectedHeader(issued.token), alg: "ES256", kid: "estate-signing-2" })
          .sign(next.privateKey),
      };
      const recorded = launch.pilot.evidence.forMission(missionId).length;
      const fetches = vi.spyOn(globalThis, "fetch");
      expect(await handshakeStatus(launch.pilot, rotated, missionId)).toBe(401);
      const jwksUri = launch.pilot.estate.jwksUri;
      expect(fetches.mock.calls.filter(([input]) => (input instanceof Request ? input.url : String(input)) === jwksUri)).toEqual([]);
      expect(launch.pilot.evidence.forMission(missionId)).toHaveLength(recorded);

      // Introspection asks the estate on each validation: no key is cached.
      const opaque = await estateToken(launch.pilot, "estate-opaque-bot-4e2", "u-1001", "invoices.read");
      expect(await handshakeStatus(launch.pilot, opaque, missionId)).toBe(200);
    } finally {
      await launch.close();
    }
  }, 120_000);
});

d("the MAS pilot launcher, separated (#818 slice 5B)", () => {
  it("starts the MAS as its own process with no IPC channel, approves, permits, refuses after a revocation and a containment, and stops the process on shutdown", async () => {
    const launch = await launchFor("separated", 14861, 14860);
    try {
      // No IPC channel: the MAS process takes no operator message.
      expect(launch.masProcess).toBeDefined();
      expect(launch.masProcess?.send).toBeUndefined();
      expect(launch.masProcess?.connected).toBe(false);
      expect(launch.consoles.mas).toBeDefined();
      await walk(launch, launch.consoles.mas as string, "out_of_authority");
    } finally {
      await launch.close();
    }
    expect(launch.masProcess?.exitCode === 0 || launch.masProcess?.signalCode !== null).toBe(true);
    for (const url of ["http://127.0.0.1:14860", "http://127.0.0.1:14861", launch.pilot.gateway.url, launch.consoles.pilot]) {
      expect(await refusesConnection(url), url).toBe(true);
    }
  }, 180_000);

  it("attaches to a MAS already running (MAS_PILOT_MAS_URL), approves at its own console, permits, refuses after a revocation, and leaves the MAS running on shutdown", async () => {
    const configPath = configFile(14869, 14868);
    const pdpToken = crypto.randomUUID();
    const masBearer = crypto.randomUUID();
    const env: NodeJS.ProcessEnv = { ...process.env, NODE_OPTIONS: "" };
    Object.assign(env, {
      MAS_PILOT_CONFIG: configPath,
      MISSION_EPHEMERAL_KEYS: "1",
      MAS_PILOT_PDP_TOKEN: pdpToken,
      MAS_PILOT_OPERATOR_TOKEN: masBearer,
      MAS_PILOT_OPERATOR_CONSOLE_PORT: "0",
    });
    const mas = spawnMasProcess(env);
    try {
      const masConsole = await new Promise<string>((resolve, reject) => {
        let out = "";
        mas.stdout?.on("data", (d: Buffer) => {
          out += d.toString();
          const url = /mas-pilot: operator console (\S+)/.exec(out)?.[1];
          if (url && out.includes("mas-pilot: ready ")) resolve(url);
        });
        mas.once("exit", (code) => reject(new Error(`the MAS exited ${code}`)));
      });
      const launched = await launchMasPilot(
        masPilotLaunchOptions(
          {
            ...fgaEnv(),
            MAS_PILOT_CONFIG: configPath,
            MAS_PILOT_DEVELOPMENT_STORE: "1",
            MAS_PILOT_MAS_URL: "http://127.0.0.1:14868",
            MAS_PILOT_PDP_TOKEN: pdpToken,
          },
          "separated",
        ),
      ).catch((e: unknown) => e);
      // It uses the running MAS: starting another on the MAS's address fails.
      expect(launched, String(launched)).not.toBeInstanceOf(Error);
      const launch = launched as MasPilotLaunch;
      try {
        expect(launch.masProcess).toBeUndefined();
        expect(launch.consoles.mas).toBeUndefined();
        const approve = async (label: string) =>
          (await consoleRequest(launch, masConsole, "/missions", { label }, masBearer)).body.mission_id as string;
        const permitted = await approve("attach-read");
        const revoked = await approve("attach-revoke");
        const credential = (
          await consoleRequest(launch, launch.consoles.pilot, "/estate-tokens", {
            client_id: "estate-opaque-bot-4e2",
            account: "u-1002",
            scope: "invoices.read",
          })
        ).body.credential_id;
        const read = (mission: string) =>
          consoleRequest(launch, launch.consoles.pilot, "/calls", {
            credential_id: credential,
            mission_id: mission,
            tool: "get_invoice",
            arguments: { invoice_id: "inv-1" },
          });
        expect((await read(permitted)).body.ok).toBe(true);
        expect(await consoleRequest(launch, masConsole, `/missions/${revoked}/revoke`, {}, masBearer)).toMatchObject({
          status: 200,
          body: { state: "terminated" },
        });
        expect((await read(revoked)).body).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
      } finally {
        await launch.close();
      }
      // The launcher did not start this MAS, so it leaves it running.
      expect(mas.exitCode).toBeNull();
      expect((await fetch("http://127.0.0.1:14868/.well-known/openid-configuration")).status).toBe(200);
    } finally {
      const exited = new Promise<void>((resolve) => mas.once("exit", () => resolve()));
      mas.kill("SIGTERM");
      await exited;
    }
  }, 180_000);
});

describe("the MAS pilot launcher refuses to start, before anything connects (#818 slice 5B)", () => {
  const keys = { MISSION_EPHEMERAL_KEYS: "1" };

  it("refuses with no Resource-policy store, or two, unless development is asked for by name; attach names the store", () => {
    const config = configFile(14862, 14863);
    expect(() => masPilotLaunchOptions({ ...keys, MAS_PILOT_CONFIG: config }, "in-process")).toThrow(/no Resource-policy store/);
    expect(() => masPilotLaunchOptions({ ...keys, MAS_PILOT_CONFIG: config, OPENFGA_STORE_ID: "s" }, "in-process")).toThrow(/set both OPENFGA_STORE_ID/);
    expect(() =>
      masPilotLaunchOptions({ ...keys, MAS_PILOT_CONFIG: config, OPENFGA_STORE_ID: "s", OPENFGA_MODEL_ID: "m", MAS_PILOT_DEVELOPMENT_STORE: "1" }, "in-process"),
    ).toThrow(/not both/);
    expect(masPilotLaunchOptions({ ...keys, MAS_PILOT_CONFIG: config, OPENFGA_STORE_ID: "s", OPENFGA_MODEL_ID: "m" }, "in-process").resourcePolicyStore).toEqual({
      attach: { storeId: "s", modelId: "m" },
    });
    expect(masPilotLaunchOptions({ ...keys, MAS_PILOT_CONFIG: config, MAS_PILOT_DEVELOPMENT_STORE: "1" }, "in-process").resourcePolicyStore).toEqual({
      bootstrap: "development",
    });
  });

  it("refuses a configuration file that is absent, or whose mapping contract is missing or does not load", () => {
    const store = { ...keys, MAS_PILOT_DEVELOPMENT_STORE: "1" };
    expect(() => masPilotLaunchOptions({ ...store, MAS_PILOT_CONFIG: "/nonexistent/mas-pilot.json" }, "in-process")).toThrow(
      /MAS_PILOT_CONFIG names \/nonexistent\/mas-pilot.json, which does not exist/,
    );
    const missing = configFile(14862, 14863, (c) => {
      const { mapping_contract: _, ...rest } = c;
      return rest as MasPilotConfig;
    });
    expect(() => masPilotLaunchOptions({ ...store, MAS_PILOT_CONFIG: missing }, "separated")).toThrow(/root is missing mapping_contract/);
    const invalid = configFile(14862, 14863, (c) => ({ ...c, mapping_contract: { ...(c.mapping_contract as Json), failure: "out_of_authority" } }));
    expect(() => masPilotLaunchOptions({ ...store, MAS_PILOT_CONFIG: invalid }, "separated")).toThrow(/declares no usable mapping contract/);
  });

  it("refuses a running MAS that is unreachable or answers under another issuer, and a MAS process that fails to start, without opening the Resource-policy store", async () => {
    const bootstrap = vi.spyOn(Fga, "bootstrap").mockRejectedValue(new Error("OpenFGA was reached"));
    const attach = vi.spyOn(Fga, "attach").mockRejectedValue(new Error("OpenFGA was reached"));
    const env = { MAS_PILOT_CONFIG: configFile(14862, 14863), MAS_PILOT_DEVELOPMENT_STORE: "1", MAS_PILOT_PDP_TOKEN: "pdp" };
    await expect(launchMasPilot(masPilotLaunchOptions({ ...env, MAS_PILOT_MAS_URL: "http://127.0.0.1:1" }, "separated"))).rejects.toThrow(
      /is unreachable/,
    );
    const impostor: Server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ issuer: "https://another-mas.example" }));
    });
    await new Promise<void>((resolve) => impostor.listen(0, "127.0.0.1", resolve));
    try {
      const url = `http://127.0.0.1:${(impostor.address() as AddressInfo).port}`;
      await expect(launchMasPilot(masPilotLaunchOptions({ ...env, MAS_PILOT_MAS_URL: url }, "separated"))).rejects.toThrow(
        /answers as issuer https:\/\/another-mas\.example, not the configured Mission issuer/,
      );
    } finally {
      impostor.closeAllConnections();
      await new Promise<void>((resolve) => impostor.close(() => resolve()));
    }
    // The MAS process this launcher starts cannot listen: its startup
    // failure is the launcher's.
    const local = { ...keys, MAS_PILOT_CONFIG: env.MAS_PILOT_CONFIG, MAS_PILOT_DEVELOPMENT_STORE: "1" };
    const blocker: Server = createServer();
    await new Promise<void>((resolve) => blocker.listen(14863, "127.0.0.1", resolve));
    try {
      await expect(launchMasPilot(masPilotLaunchOptions(local, "separated"))).rejects.toThrow(
        /^startup failed: http:\/\/127\.0\.0\.1:14863 cannot listen/,
      );
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => resolve()));
    }
    expect(bootstrap).not.toHaveBeenCalled();
    expect(attach).not.toHaveBeenCalled();

    // The control: a launch that gets as far as the store reaches the stub,
    // and its failure releases what it had opened.
    await expect(launchMasPilot(masPilotLaunchOptions(local, "in-process"))).rejects.toThrow(/OpenFGA was reached/);
    expect(bootstrap).toHaveBeenCalledTimes(1);
    for (const url of ["http://127.0.0.1:14862", "http://127.0.0.1:14863"]) expect(await refusesConnection(url), url).toBe(true);
  }, 60_000);

  it("refuses a running MAS's address in process, and one of the address and the PDP credential without the other", () => {
    const env = { ...keys, MAS_PILOT_CONFIG: configFile(14862, 14863), MAS_PILOT_DEVELOPMENT_STORE: "1" };
    expect(() => masPilotLaunchOptions({ ...env, MAS_PILOT_MAS_URL: "http://127.0.0.1:1", MAS_PILOT_PDP_TOKEN: "p" }, "in-process")).toThrow(
      /separated topology only/,
    );
    expect(() => masPilotLaunchOptions({ ...env, MAS_PILOT_MAS_URL: "http://127.0.0.1:1" }, "separated")).toThrow(/set both MAS_PILOT_MAS_URL/);
  });
});
