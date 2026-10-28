/**
 * @spec #831: `pnpm keys`, driven through `keysAdmin`: `init` (slice 1), and
 * `migrate`, `rotate`, `retire`, `compromise` and `verify` (B2).
 */
import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadSigningKeyRing,
  loadSigningKeyRingState,
  SIGNING_KEY_RING_FORMAT,
  SIGNING_KEY_RING_FORMAT_V1,
} from "@mission/authorization-server";
import { DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { keysAdmin } from "../src/keys-admin.js";

describe("pnpm keys init --bindings and pnpm keys bind (@spec #1815, D945)", () => {
  it("init records the new ring's kids in a key binding record outside the ring's directory; bind records an existing ring's once; rotate given the record skips its kids", async () => {
    const started = mkdtempSync(join(tmpdir(), "keys-admin-"));
    const ring = join(started, "keys", "ring.json");
    const bindings = join(started, "bindings", "key-bindings.json");
    const out = await keysAdmin(["init", "--ring", ring, "--bindings", "bindings/key-bindings.json"], { INIT_CWD: started });
    expect(out).toContain(`recorded its kids in the key binding record ${bindings}`);
    const recorded = (JSON.parse(readFileSync(bindings, "utf8")) as { bindings: { kid: string }[] }).bindings.map((b) => b.kid);
    expect(recorded).toEqual(["as-token", "as-status", "as-txn", "as-continuation"]);
    await loadSigningKeyRing(ring, `http://localhost:${TOPOLOGY.ports.as}`, ROLES, { bindings });

    const other = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "keys", "ring.json");
    await keysAdmin(["init", "--ring", other], {});
    const otherBindings = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "key-bindings.json");
    expect(await keysAdmin(["bind", "--ring", other, "--bindings", otherBindings], {})).toContain(
      `recorded the 4 kids of ${other} in the key binding record ${otherBindings}`,
    );
    await expect(keysAdmin(["bind", "--ring", other, "--bindings", otherBindings], {})).rejects.toThrow(/created once/);
    await expect(keysAdmin(["bind", "--ring", other], {})).rejects.toThrow(/usage: pnpm keys/);

    const staged = await keysAdmin(["rotate", "--ring", ring, "--role", "asToken", "--bindings", bindings], {});
    expect(staged).toContain("staged as-token-2 for asToken");
  });
});

describe("pnpm keys init (@spec #831 slice 1)", () => {
  it("creates the ring once at a path resolved against the directory pnpm started in, for the configured AS issuer, and names it for MISSION_KEY_RING", async () => {
    const started = mkdtempSync(join(tmpdir(), "keys-admin-"));
    const out = await keysAdmin(["init", "--ring", "var/keys/as-signing-keys.json"], { INIT_CWD: started }, "/elsewhere");
    const ring = join(started, "var/keys/as-signing-keys.json");
    expect(out).toBe(
      [
        `initialized ${ring} for http://localhost:${TOPOLOGY.ports.as}: 4 keys (as-token, as-status, as-txn, as-continuation)`,
        `record its kids once with \`pnpm keys bind --ring ${ring} --bindings <path>\` (outside the ring's directory), then start the AS with MISSION_KEY_RING=${ring} MISSION_KEY_BINDINGS=<path>`,
      ].join("\n"),
    );
    expect(statSync(ring).mode & 0o777).toBe(0o600);
    expect((JSON.parse(readFileSync(ring, "utf8")) as { issuer: string }).issuer).toBe(`http://localhost:${TOPOLOGY.ports.as}`);
    await expect(keysAdmin(["init", "--ring", ring], {})).rejects.toThrow(/already exists; a ring is initialized once/);
  });

  it("takes an explicit issuer", async () => {
    const ring = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "keys", "ring.json");
    await keysAdmin(["init", "--ring", ring, "--issuer", "https://as.example.com"], {});
    expect((JSON.parse(readFileSync(ring, "utf8")) as { issuer: string }).issuer).toBe("https://as.example.com");
  });

  it("refuses an unknown command, a missing or unknown flag, and an issuer that is not an http or https URL", async () => {
    const usage = /^usage: pnpm keys init --ring <path> \[--bindings <path>\] \[--issuer <url>\]\n {7}pnpm keys bind --ring <path> --bindings <path>/;
    for (const argv of [
      [],
      ["revoke", "--ring", "x"],
      ["init"],
      ["init", "--ring"],
      ["init", "--path", "x"],
      ["init", "--ring", "--issuer"],
      ["init", "--ring", "x", "--activate"],
      ["rotate", "--ring", "x"],
      ["retire", "--ring", "x", "--role", "asToken"],
      ["compromise", "--ring", "x", "--kid", "as-token"],
      ["verify"],
      ["verify", "--ring", "x", "--role", "asToken"],
      ["retire", "--ring", "x", "--role", "asStatus", "--kid", "as-status", "--in-memory-kernel", "--activate"],
    ]) {
      await expect(keysAdmin(argv, {}), JSON.stringify(argv)).rejects.toThrow(usage);
    }
    await expect(keysAdmin(["init", "--ring", "/tmp/x.json", "--issuer", "ftp://as"], {})).rejects.toThrow(
      /--issuer is not an http or https URL: ftp:\/\/as/,
    );
  });
});

/** The ring's AS issuer: the configured default `pnpm keys` uses. */
const ISSUER = `http://localhost:${TOPOLOGY.ports.as}`;
const ROLES = (({ asToken, asStatus, asTxn, asContinuation }) => ({ asToken, asStatus, asTxn, asContinuation }))(TOPOLOGY.keys);
type Generation = { kid: string; state: string; created_at: string; published_at?: string; compromised_at?: string };
const generations = (ring: string, role: string): Generation[] =>
  (JSON.parse(readFileSync(ring, "utf8")) as { roles: Record<string, { generations: Generation[] }> }).roles[role]!.generations;
/** Move every recorded time `seconds` into the past, as if the ring had been written then. */
function age(ring: string, seconds: number): void {
  const shift = (v: unknown): unknown =>
    typeof v === "string" && /^\d{4}-\d\d-\d\dT/.test(v) ? new Date(Date.parse(v) - seconds * 1000).toISOString() : v;
  const walk = (o: unknown): unknown =>
    Array.isArray(o) ? o.map(walk) : o && typeof o === "object" ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, walk(shift(v))])) : o;
  writeFileSync(ring, JSON.stringify(walk(JSON.parse(readFileSync(ring, "utf8")))), { mode: 0o600 });
}

/**
 * A ring and a stand-in for the AS running it: its metadata, and a `/jwks`
 * serving the ring's live set under its revision as `ETag`, as an AS started
 * after each edit serves it.
 */
async function servedRing(): Promise<{ ring: string; issuer: string; close: () => Promise<void> }> {
  const ring = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "keys", "ring.json");
  let issuer = "";
  const server = createServer(async (req, res) => {
    if (req.url === "/.well-known/openid-configuration") {
      res.end(JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks` }));
    } else if (req.url === "/jwks") {
      const { keys, revision } = await loadSigningKeyRingState(ring, issuer, ROLES);
      res.setHeader("etag", `"${revision}"`);
      res.end(JSON.stringify({ keys: Object.values(keys).flatMap((r) => r.published) }));
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, () => r()));
  issuer = `http://localhost:${(server.address() as AddressInfo).port}`;
  await keysAdmin(["init", "--ring", ring, "--issuer", issuer], {});
  return { ring, issuer, close: () => new Promise<void>((r) => server.close(() => r())) };
}

describe("pnpm keys migrate, rotate, retire, compromise and verify (@spec #831 B2)", () => {
  it("migrate converts a slice 1 ring, keeping its keys", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "keys");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const ring = join(dir, "ring.json");
    const roles: Record<string, unknown> = {};
    for (const [name, role] of Object.entries(ROLES)) {
      const { privateKey } = await generateKeyPair(role.alg, { extractable: true });
      roles[name] = { kid: role.kid, alg: role.alg, created_at: new Date().toISOString(), private_jwk: await exportJWK(privateKey) };
    }
    writeFileSync(ring, JSON.stringify({ format: SIGNING_KEY_RING_FORMAT_V1, issuer: ISSUER, created_at: new Date().toISOString(), roles }), { mode: 0o600 });
    await expect(keysAdmin(["rotate", "--ring", ring, "--role", "asToken"], {})).rejects.toThrow(/convert it first with `pnpm keys migrate/);
    expect(await keysAdmin(["migrate", "--ring", ring], {})).toBe(
      `converted ${ring} to ${SIGNING_KEY_RING_FORMAT}: the same 4 keys (as-token, as-status, as-txn, as-continuation), each its role's active generation`,
    );
    expect((await loadSigningKeyRing(ring, ISSUER, ROLES)).asToken.kid).toBe("as-token");
  });

  it("rotate stages; verify confirms the running AS publishes it; rotate --activate waits the /jwks freshness lifetime from that confirmation", async () => {
    const { ring, issuer, close } = await servedRing();
    try {
      const staged = await keysAdmin(["rotate", "--ring", ring, "--role", "asStatus", "--issuer", issuer], {});
      expect(staged.split("\n")).toEqual([
        "staged as-status-2 for asStatus: to be published, not signing",
        `next: start the AS with this ring, then \`pnpm keys verify --ring ${ring} --issuer ${issuer}\`; the edit is not in effect until then. Activation waits 300s from the publication that verification confirms`,
        "before activating, add as-status-2 to each consumer's trusted kids for asStatus (this deployment: config/topology.json keys.asStatus.trusted) and reload each consumer (SIGUSR2 to the demo's processes); publication alone grants no trust",
      ]);
      // Neither the staging's age nor any wait stands in for a confirmed publication.
      age(ring, 3600);
      await expect(keysAdmin(["rotate", "--ring", ring, "--role", "asStatus", "--activate", "--issuer", issuer], {})).rejects.toThrow(
        /as-status-2 is not confirmed published/,
      );
      expect((await keysAdmin(["verify", "--ring", ring, "--issuer", issuer], {})).split("\n")).toEqual([
        `the AS at ${issuer} runs revision 2 of ${ring}`,
        "confirmed published: as-token, as-status, as-status-2, as-txn, as-continuation; stopped signing: none new; withdrawn: none new",
      ]);
      await expect(keysAdmin(["rotate", "--ring", ring, "--role", "asStatus", "--activate", "--issuer", issuer], {})).rejects.toThrow(
        /as-status-2 has been confirmed published for \d+s; activation needs 300s/,
      );
      age(ring, 301);
      expect((await keysAdmin(["rotate", "--ring", ring, "--role", "asStatus", "--activate", "--issuer", issuer], {})).split("\n")[0]).toBe(
        "activated as-status-2 for asStatus; as-status stops signing and stays published in overlap",
      );
      expect((await loadSigningKeyRing(ring, issuer, ROLES)).asStatus.kid).toBe("as-status-2");
      expect((await keysAdmin(["verify", "--ring", ring, "--issuer", issuer], {})).split("\n")[1]).toBe(
        "confirmed published: none new; stopped signing: as-status; withdrawn: none new",
      );
    } finally {
      await close();
    }
  });

  it("retire refuses with the shipped policy, which bounds no Mission lifetime, so no retention deadline can be established", async () => {
    expect(DERIVATION_POLICY.max_mission_lifetime_s).toBeNull();
    const { ring, issuer, close } = await servedRing();
    try {
      await keysAdmin(["rotate", "--ring", ring, "--role", "asTxn", "--issuer", issuer], {});
      await keysAdmin(["verify", "--ring", ring, "--issuer", issuer], {});
      age(ring, 301);
      await keysAdmin(["rotate", "--ring", ring, "--role", "asTxn", "--activate", "--issuer", issuer], {});
      await expect(keysAdmin(["retire", "--ring", ring, "--role", "asTxn", "--kid", "as-txn", "--issuer", issuer], {})).rejects.toThrow(
        /as-txn is not confirmed to have stopped signing/,
      );
      await keysAdmin(["verify", "--ring", ring, "--issuer", issuer], {});
      age(ring, 10 * 365 * 86400);
      await expect(keysAdmin(["retire", "--ring", ring, "--role", "asTxn", "--kid", "as-txn", "--issuer", issuer], {})).rejects.toThrow(
        /no retention deadline can be established for as-txn: the Mission lifetime is unbounded/,
      );
      await expect(
        keysAdmin(["retire", "--ring", ring, "--role", "asStatus", "--kid", "as-status", "--kernel-store", "/k.db", "--in-memory-kernel", "--issuer", issuer], {}),
      ).rejects.toThrow(/name a --kernel-store or --in-memory-kernel, not both/);
      // A pending generation never signed: retiring it abandons a staged rotation, with no deadline.
      await keysAdmin(["rotate", "--ring", ring, "--role", "asTxn", "--issuer", issuer], {});
      expect((await keysAdmin(["retire", "--ring", ring, "--role", "asTxn", "--kid", "as-txn-3", "--issuer", issuer], {})).split("\n")[0]).toBe(
        "retired as-txn-3 for asTxn: it leaves the AS's key set",
      );
    } finally {
      await close();
    }
  });

  it("compromise withdraws at once, replaces an active signer, and records an established compromise time; verify confirms the withdrawal", async () => {
    const { ring, issuer, close } = await servedRing();
    try {
      await expect(
        keysAdmin(["compromise", "--ring", ring, "--role", "asToken", "--kid", "as-token", "--compromised-at", "last week", "--issuer", issuer], {}),
      ).rejects.toThrow(/--compromised-at is not a time: last week/);
      const out = await keysAdmin(
        ["compromise", "--ring", ring, "--role", "asToken", "--kid", "as-token", "--compromised-at", "2026-10-01T00:00:00Z", "--issuer", issuer],
        {},
      );
      expect(out.split("\n")[0]).toBe("withdrew as-token for asToken as compromised; as-token-2 replaces it as the signer");
      expect(out.split("\n")[1]).toContain(
        "accepts as-token-2 only once its trusted kids for asToken list it (this deployment: config/topology.json keys.asToken.trusted, then SIGUSR2 to the demo's processes)",
      );
      expect(generations(ring, "asToken").map((g) => [g.kid, g.state, g.compromised_at])).toEqual([
        ["as-token", "compromised", "2026-10-01T00:00:00.000Z"],
        ["as-token-2", "active", undefined],
      ]);
      expect((await keysAdmin(["verify", "--ring", ring, "--issuer", issuer], {})).split("\n")[1]).toBe(
        "confirmed published: as-token-2, as-status, as-txn, as-continuation; stopped signing: as-token; withdrawn: as-token",
      );
    } finally {
      await close();
    }
  });
});
