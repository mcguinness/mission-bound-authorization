/**
 * @spec mission#mission-bound-tokens (verification keys), #831 slice 1: the
 * AS's signing keys, durable across restarts.
 *
 * The AS signs with four role keys, each under its configured `kid`
 * (`TOPOLOGY.keys`): `asToken` (access tokens, ID Tokens, child grants and
 * the other `as-token` artifacts), `asStatus` (Status responses, the Status
 * List, discharge receipts and the records signed through the kernel's
 * status signer), `asTxn` (transaction tokens) and `asContinuation` (the
 * continuation ID-JAG). Two sources exist:
 *
 * - **A key ring file**: the private keys persisted once by an explicit
 *   initialization ({@link initSigningKeyRing}) and loaded at every boot
 *   ({@link loadSigningKeyRing}), so a restart keeps the same key material
 *   under the same `kid` and a consumer's JWKS snapshot stays valid.
 * - **Ephemeral keys** ({@link generateEphemeralSigningKeys}): generated at
 *   each boot, for tests and demos. A restart changes the material under the
 *   same `kid`.
 *
 * The ring holds one generation per role, under the configured `kid`.
 * Rotation (a next generation published before activation, an overlap,
 * retirement and compromise) is #831's next slice. Loading never falls back
 * to generation: a missing, unreadable, malformed or mismatched ring refuses
 * startup ({@link SigningKeyRingError}).
 */

import { closeSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { exportJWK, generateKeyPair, importJWK, type JWK } from "jose";

/** The AS signing roles, in `TOPOLOGY.keys` names. */
export const AS_SIGNING_ROLES = ["asToken", "asStatus", "asTxn", "asContinuation"] as const;
export type AsSigningRole = (typeof AS_SIGNING_ROLES)[number];

/** A role's configured identity: its `kid` and algorithm. */
export interface SigningRoleConfig {
  kid: string;
  alg: string;
}

/** One role's resolved key: the signer and its private and public JWKs (with `kid`, `alg`, `use`). */
export interface ResolvedSigningKey {
  privateKey: CryptoKey;
  privateJwk: Record<string, unknown>;
  publicJwk: Record<string, unknown>;
}

export type AsSigningKeys = Record<AsSigningRole, ResolvedSigningKey>;

/** The ring file's format marker; a file without it is not a ring. */
export const SIGNING_KEY_RING_FORMAT = "mission-as-signing-key-ring/1";

/** A ring that could not be created or loaded safely. Fatal at startup; nothing falls back. */
export class SigningKeyRingError extends Error {
  constructor(why: string) {
    super(`signing key ring refused: ${why}`);
    this.name = "SigningKeyRingError";
  }
}

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/** A JWK's public half: every private member removed. */
export function publicHalf(jwk: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...jwk };
  for (const m of PRIVATE_MEMBERS) delete out[m];
  return out;
}

async function resolve(privateJwk: Record<string, unknown>, role: SigningRoleConfig): Promise<ResolvedSigningKey> {
  const stamped = { ...privateJwk, kid: role.kid, alg: role.alg, use: "sig" };
  const privateKey = (await importJWK(stamped as JWK, role.alg)) as CryptoKey;
  return { privateKey, privateJwk: stamped, publicJwk: publicHalf(stamped) };
}

async function generate(role: SigningRoleConfig): Promise<Record<string, unknown>> {
  const { privateKey } = await generateKeyPair(role.alg, { extractable: true });
  return { ...(await exportJWK(privateKey)) } as Record<string, unknown>;
}

/** Keys generated at this boot, for tests and demos; a restart changes them. */
export async function generateEphemeralSigningKeys(roles: Record<AsSigningRole, SigningRoleConfig>): Promise<AsSigningKeys> {
  const out = {} as AsSigningKeys;
  for (const name of AS_SIGNING_ROLES) out[name] = await resolve(await generate(roles[name]), roles[name]);
  return out;
}

/** Group or other access to `path`, as mode bits (0 when private). */
const openToOthers = (path: string): number => statSync(path).mode & 0o077;

/**
 * Create the ring at `file` for `issuer`, once. The directory is created
 * 0700 when missing and must otherwise grant no group or other access; the
 * file is written 0600 to a temporary name in that directory, flushed, and
 * linked into place, which fails if a ring already exists, so an existing
 * ring is never replaced. Returns the public JWKs it published.
 */
export async function initSigningKeyRing(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  now: () => Date = () => new Date(),
): Promise<Record<string, unknown>[]> {
  if (!file) throw new SigningKeyRingError("no ring file is named");
  if (!issuer) throw new SigningKeyRingError("no issuer is named");
  const dir = dirname(file);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (openToOthers(dir) !== 0) {
    throw new SigningKeyRingError(`${dir} grants group or other access; use a directory with mode 0700`);
  }
  let exists = false;
  try {
    statSync(file);
    exists = true;
  } catch {
    exists = false;
  }
  if (exists) throw new SigningKeyRingError(`${file} already exists; a ring is initialized once`);

  const created = now().toISOString();
  const ring = {
    format: SIGNING_KEY_RING_FORMAT,
    issuer,
    created_at: created,
    roles: {} as Record<string, unknown>,
  };
  const published: Record<string, unknown>[] = [];
  for (const name of AS_SIGNING_ROLES) {
    const role = roles[name];
    const privateJwk = await generate(role);
    ring.roles[name] = { kid: role.kid, alg: role.alg, created_at: created, private_jwk: privateJwk };
    published.push(publicHalf({ ...privateJwk, kid: role.kid, alg: role.alg, use: "sig" }));
  }

  const tmp = join(dir, `.ring-${process.pid}-${Date.now()}.tmp`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, `${JSON.stringify(ring, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    linkSync(tmp, file);
  } catch (e) {
    unlinkSync(tmp);
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new SigningKeyRingError(`${file} already exists; a ring is initialized once`);
    }
    throw new SigningKeyRingError(`cannot write ${file}: ${(e as Error).message}`);
  }
  unlinkSync(tmp);
  try {
    const dfd = openSync(dir, "r");
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  } catch {
    // Directory fsync is not supported on every platform; the file itself is flushed.
  }
  return published;
}

/**
 * Load the ring at `file` for `issuer`. Refuses, never generating a
 * replacement, when the file is missing, grants group or other access, is
 * not a ring, names another issuer, lacks a role or carries an extra one,
 * records a `kid` or algorithm other than the configured one, or holds a key
 * that does not import.
 */
export async function loadSigningKeyRing(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
): Promise<AsSigningKeys> {
  if (!file) throw new SigningKeyRingError("no ring file is named");
  let raw: string;
  try {
    if (openToOthers(file) !== 0) {
      throw new SigningKeyRingError(`${file} grants group or other access; it must be mode 0600`);
    }
    raw = readFileSync(file, "utf8");
  } catch (e) {
    if (e instanceof SigningKeyRingError) throw e;
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new SigningKeyRingError(
        `no ring at ${file}; initialize one with \`pnpm keys init --ring ${file} --issuer ${issuer}\``,
      );
    }
    throw new SigningKeyRingError(`cannot read ${file}: ${(e as Error).message}`);
  }
  let ring: Record<string, unknown>;
  try {
    ring = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new SigningKeyRingError(`${file} is not valid JSON`);
  }
  if (ring === null || typeof ring !== "object" || ring.format !== SIGNING_KEY_RING_FORMAT) {
    throw new SigningKeyRingError(`${file} is not a ${SIGNING_KEY_RING_FORMAT} ring`);
  }
  if (ring.issuer !== issuer) {
    throw new SigningKeyRingError(`${file} is for issuer ${String(ring.issuer)}, not ${issuer}`);
  }
  const stored = ring.roles as Record<string, Record<string, unknown>> | undefined;
  if (stored === null || typeof stored !== "object") throw new SigningKeyRingError(`${file} has no roles`);
  const extra = Object.keys(stored).filter((k) => !(AS_SIGNING_ROLES as readonly string[]).includes(k));
  if (extra.length > 0) throw new SigningKeyRingError(`${file} carries unknown roles: ${extra.join(", ")}`);
  const out = {} as AsSigningKeys;
  for (const name of AS_SIGNING_ROLES) {
    const entry = stored[name];
    const role = roles[name];
    if (!entry || typeof entry !== "object") throw new SigningKeyRingError(`${file} has no ${name} key`);
    if (entry.kid !== role.kid) {
      throw new SigningKeyRingError(`${name} is recorded under kid ${String(entry.kid)}, not the configured ${role.kid}`);
    }
    if (entry.alg !== role.alg) {
      throw new SigningKeyRingError(`${name} is recorded with alg ${String(entry.alg)}, not the configured ${role.alg}`);
    }
    const privateJwk = entry.private_jwk as Record<string, unknown> | undefined;
    if (!privateJwk || typeof privateJwk !== "object" || typeof privateJwk.d !== "string") {
      throw new SigningKeyRingError(`${name} holds no private key`);
    }
    try {
      out[name] = await resolve(privateJwk, role);
    } catch (e) {
      throw new SigningKeyRingError(`${name}'s key does not import as ${role.alg}: ${(e as Error).message}`);
    }
  }
  return out;
}

/** How the AS obtains its signing keys. */
export type SigningKeySource = { ring: string } | { ephemeral: true };

/**
 * A deployment entry point's key source, from its environment: a ring at
 * `MISSION_KEY_RING`, or ephemeral keys when `MISSION_EPHEMERAL_KEYS=1`.
 * Neither, or both, refuses: a deployment says which it runs.
 */
export function signingKeysFromEnv(env: Record<string, string | undefined>): SigningKeySource {
  const ring = env.MISSION_KEY_RING?.trim();
  const ephemeral = env.MISSION_EPHEMERAL_KEYS === "1";
  if (ring && ephemeral) {
    throw new SigningKeyRingError("set MISSION_KEY_RING or MISSION_EPHEMERAL_KEYS=1, not both");
  }
  if (ring) return { ring };
  if (ephemeral) return { ephemeral: true };
  throw new SigningKeyRingError(
    "choose the signing keys: MISSION_KEY_RING=<path> (initialize it once with `pnpm keys init`), or MISSION_EPHEMERAL_KEYS=1 for keys that change at every restart",
  );
}
