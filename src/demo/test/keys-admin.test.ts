/**
 * @spec #831: `pnpm keys`, driven through `keysAdmin`: `init` (slice 1), and
 * `migrate`, `rotate`, `retire` and `compromise` (B2).
 */
import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSigningKeyRing, SIGNING_KEY_RING_FORMAT, SIGNING_KEY_RING_FORMAT_V1 } from "@mission/authorization-server";
import { AUDIT_HORIZON_SECONDS, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { keysAdmin } from "../src/keys-admin.js";

describe("pnpm keys init (@spec #831 slice 1)", () => {
  it("creates the ring once at a path resolved against the directory pnpm started in, for the configured AS issuer, and names it for MISSION_KEY_RING", async () => {
    const started = mkdtempSync(join(tmpdir(), "keys-admin-"));
    const out = await keysAdmin(["init", "--ring", "var/keys/as-signing-keys.json"], { INIT_CWD: started }, "/elsewhere");
    const ring = join(started, "var/keys/as-signing-keys.json");
    expect(out).toBe(
      [
        `initialized ${ring} for http://localhost:${TOPOLOGY.ports.as}: 4 keys (as-token, as-status, as-txn, as-continuation)`,
        `start the AS with MISSION_KEY_RING=${ring}`,
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
    const usage = /^usage: pnpm keys init --ring <path> \[--issuer <url>\]\n {7}pnpm keys migrate/;
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
const freshRing = async (): Promise<string> => {
  const ring = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "keys", "ring.json");
  await keysAdmin(["init", "--ring", ring], {});
  return ring;
};
type Generation = { kid: string; state: string; created_at: string; stopped_at?: string; compromised_at?: string };
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

describe("pnpm keys migrate, rotate, retire and compromise (@spec #831 B2)", () => {
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

  it("rotate stages, and rotate --activate activates only after the /jwks freshness lifetime", async () => {
    const ring = await freshRing();
    const staged = await keysAdmin(["rotate", "--ring", ring, "--role", "asStatus"], {});
    expect(staged.split("\n")[0]).toBe("staged as-status-2 for asStatus: published, not signing");
    await expect(keysAdmin(["rotate", "--ring", ring, "--role", "asStatus", "--activate"], {})).rejects.toThrow(
      /as-status-2 has been published for \d+s; activation needs 300s/,
    );
    age(ring, 301);
    expect((await keysAdmin(["rotate", "--ring", ring, "--role", "asStatus", "--activate"], {})).split("\n")[0]).toBe(
      "activated as-status-2 for asStatus; as-status stops signing and stays published in overlap",
    );
    expect((await loadSigningKeyRing(ring, ISSUER, ROLES)).asStatus.kid).toBe("as-status-2");
  });

  it("retire waits out the deployment's audit horizon since the generation stopped signing", async () => {
    const ring = await freshRing();
    await keysAdmin(["rotate", "--ring", ring, "--role", "asTxn"], {});
    age(ring, 301);
    await keysAdmin(["rotate", "--ring", ring, "--role", "asTxn", "--activate"], {});
    await expect(keysAdmin(["retire", "--ring", ring, "--role", "asTxn", "--kid", "as-txn"], {})).rejects.toThrow(
      new RegExp(`it stays published for the audit horizon \\(${AUDIT_HORIZON_SECONDS}s\\)`),
    );
    age(ring, AUDIT_HORIZON_SECONDS);
    expect((await keysAdmin(["retire", "--ring", ring, "--role", "asTxn", "--kid", "as-txn"], {})).split("\n")[0]).toBe(
      "retired as-txn for asTxn: it leaves the AS's key set",
    );
    expect(generations(ring, "asTxn").map((g) => g.state)).toEqual(["retired", "active"]);
  });

  it("compromise withdraws at once, replaces an active signer, and records an established compromise time", async () => {
    const ring = await freshRing();
    await expect(
      keysAdmin(["compromise", "--ring", ring, "--role", "asToken", "--kid", "as-token", "--compromised-at", "last week"], {}),
    ).rejects.toThrow(/--compromised-at is not a time: last week/);
    const out = await keysAdmin(
      ["compromise", "--ring", ring, "--role", "asToken", "--kid", "as-token", "--compromised-at", "2026-10-01T00:00:00Z"],
      {},
    );
    expect(out.split("\n")[0]).toBe("withdrew as-token for asToken as compromised; as-token-2 replaces it as the signer");
    expect(generations(ring, "asToken").map((g) => [g.kid, g.state, g.compromised_at])).toEqual([
      ["as-token", "compromised", "2026-10-01T00:00:00.000Z"],
      ["as-token-2", "active", undefined],
    ]);
  });
});
