/**
 * @spec mission#mission-bound-tokens (verification keys), #831: the AS's
 * signing keys, durable across restarts, rotated by role.
 *
 * The AS signs with four role keys (`TOPOLOGY.keys`): `asToken` (access
 * tokens, ID Tokens, child grants and the other `as-token` artifacts),
 * `asStatus` (Status responses, the Status List, discharge receipts and the
 * records signed through the kernel's status signer), `asTxn` (transaction
 * tokens) and `asContinuation` (the continuation ID-JAG). Two sources exist:
 *
 * - **A key ring file**: the private keys persisted once by an explicit
 *   initialization ({@link initSigningKeyRing}) and loaded at every boot
 *   ({@link loadSigningKeyRing}), so a restart keeps the same key material
 *   under the same `kid` and a consumer's JWKS snapshot stays valid.
 * - **Ephemeral keys** ({@link generateEphemeralSigningKeys}): generated at
 *   each boot, for tests and demos. A restart changes the material under the
 *   same `kid`.
 *
 * A ring keeps each role's generations (format `/2`). Generation 1 is under
 * the configured `kid`, generation `n` under `<kid>-<n>`, so no `kid` is
 * ever reused for other material. A generation is in one state:
 *
 * - `pending`: published at `/jwks`, not yet signing ({@link stageSigningKeyGeneration});
 * - `active`: the role's one signer, published;
 * - `overlap`: no longer signing, still published and accepted, so what it
 *   signed keeps verifying ({@link activateSigningKeyGeneration});
 * - `retired`: removed from `/jwks` after the audit horizon
 *   ({@link retireSigningKeyGeneration});
 * - `compromised`: removed from `/jwks` at once and never accepted again,
 *   kept with its revocation time and any established compromise time for
 *   the historical key set ({@link compromiseSigningKeyGeneration}).
 *
 * Only `pending` and `active` generations keep a private key. A ring of the
 * slice 1 format (`/1`) still loads, as one active generation per role, and
 * {@link migrateSigningKeyRing} converts it explicitly before any operation.
 * Loading never falls back to generation: a missing, unreadable, malformed
 * or mismatched ring refuses startup ({@link SigningKeyRingError}).
 *
 * The operations edit the file; a running AS reads it only at boot, so an
 * operation takes effect at the AS's next start, and a consumer that
 * fetched the key set once sees the change only when it fetches again. A
 * successful edit is therefore not a completed change. Each change follows
 * one procedure: stop the AS, edit the ring, start the AS, and verify
 * ({@link verifySigningKeyRing}). Every edit advances the ring's
 * `revision`, the AS serves the revision it loaded as its `/jwks` `ETag`,
 * and verification records, from the running AS's own `/jwks`, when a
 * generation was first published (`published_at`), when the AS was
 * confirmed to have stopped signing under it (`stop_confirmed_at`), and when
 * it was confirmed withdrawn (`withdrawal_confirmed_at`). The floors read
 * only those confirmed times. One operator edits a ring at a time: the
 * operations take no lock.
 */

import { randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from "jose";
import { witnessSharesStoreTree } from "./recovery-witness.js";

/** The AS signing roles, in `TOPOLOGY.keys` names. */
export const AS_SIGNING_ROLES = ["asToken", "asStatus", "asTxn", "asContinuation"] as const;
export type AsSigningRole = (typeof AS_SIGNING_ROLES)[number];

/** A role's configured identity: its base `kid` and algorithm. */
export interface SigningRoleConfig {
  kid: string;
  alg: string;
}

/** One key resolved for signing: the signer and its private and public JWKs (with `kid`, `alg`, `use`). */
export interface ResolvedSigningKey {
  privateKey: CryptoKey;
  privateJwk: Record<string, unknown>;
  publicJwk: Record<string, unknown>;
}

/** A generation withdrawn as compromised: its public JWK and times, for the historical key set. */
export interface WithdrawnSigningKey {
  publicJwk: Record<string, unknown>;
  revoked_at: string;
  compromised_at?: string;
}

/**
 * One role's keys as the AS uses them: the active generation's signer and
 * its `kid`; the live set the AS publishes at `/jwks` (pending, active and
 * overlap generations); the set its own verifiers accept (active and
 * overlap, the generations that may have signed a current artifact); and the
 * generations withdrawn as compromised, which neither set includes.
 */
export interface RoleSigningKeys extends ResolvedSigningKey {
  kid: string;
  published: Record<string, unknown>[];
  verification: Record<string, unknown>[];
  withdrawn: WithdrawnSigningKey[];
}

export type AsSigningKeys = Record<AsSigningRole, RoleSigningKeys>;

/** The ring file's format marker; a file without one of the two markers is not a ring. */
export const SIGNING_KEY_RING_FORMAT = "mission-as-signing-key-ring/2";
/** The slice 1 format: one key per role under its configured `kid`. Loaded, never written. */
export const SIGNING_KEY_RING_FORMAT_V1 = "mission-as-signing-key-ring/1";

export const SIGNING_KEY_STATES = ["pending", "active", "overlap", "retired", "compromised"] as const;
export type SigningKeyState = (typeof SIGNING_KEY_STATES)[number];

/**
 * The freshness lifetime, in seconds, the AS declares on its `/jwks`
 * response (`Cache-Control: max-age`). A pending generation is published at
 * least this long before it activates, so a consumer honoring the declared
 * lifetime holds it before anything is signed under it.
 */
export const JWKS_MAX_AGE_SECONDS = 300;

/** A ring that could not be created, loaded or updated safely. Fatal at startup; nothing falls back. */
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

/** The `kid` of a role's generation `n`: the configured `kid` for the first, `<kid>-<n>` after. */
export function generationKid(baseKid: string, n: number): string {
  return n === 1 ? baseKid : `${baseKid}-${n}`;
}

const stamp = (jwk: Record<string, unknown>, kid: string, alg: string): Record<string, unknown> => ({
  ...jwk,
  kid,
  alg,
  use: "sig",
});

async function resolve(privateJwk: Record<string, unknown>, kid: string, alg: string): Promise<ResolvedSigningKey> {
  const stamped = stamp(privateJwk, kid, alg);
  const privateKey = (await importJWK(stamped as JWK, alg)) as CryptoKey;
  return { privateKey, privateJwk: stamped, publicJwk: publicHalf(stamped) };
}

/** A single generation's keys: what slice 1 rings and ephemeral keys carry. */
function single(signer: ResolvedSigningKey, kid: string): RoleSigningKeys {
  return { ...signer, kid, published: [signer.publicJwk], verification: [signer.publicJwk], withdrawn: [] };
}

async function generate(role: SigningRoleConfig): Promise<Record<string, unknown>> {
  const { privateKey } = await generateKeyPair(role.alg, { extractable: true });
  return { ...(await exportJWK(privateKey)) } as Record<string, unknown>;
}

/** Keys generated at this boot, for tests and demos; a restart changes them. */
export async function generateEphemeralSigningKeys(roles: Record<AsSigningRole, SigningRoleConfig>): Promise<AsSigningKeys> {
  const out = {} as AsSigningKeys;
  for (const name of AS_SIGNING_ROLES) {
    const role = roles[name];
    out[name] = single(await resolve(await generate(role), role.kid, role.alg), role.kid);
  }
  return out;
}

/** Group or other access to `path`, as mode bits (0 when private). */
const openToOthers = (path: string): number => statSync(path).mode & 0o077;

/** Flush `dir`'s entries where the platform supports it; the file itself is flushed regardless. */
function fsyncDir(dir: string): void {
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
}

/**
 * Write `content` 0600 to a fresh temporary file in `dir`, flushed; returns its
 * path. A write or flush that fails removes the temporary file (#1815): it
 * would otherwise hold a partial copy of the ring, private keys included.
 */
function writeTemp(dir: string, content: string): string {
  const tmp = join(dir, `.ring-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, "wx", 0o600);
  let flushed = false;
  try {
    writeSync(fd, content);
    fsyncSync(fd);
    flushed = true;
  } catch (e) {
    throw new SigningKeyRingError(`cannot write a ring in ${dir}: ${(e as Error).message}`);
  } finally {
    closeSync(fd);
    if (!flushed) {
      try {
        unlinkSync(tmp);
      } catch {
        // Already gone.
      }
    }
  }
  return tmp;
}

const serialize = (ring: unknown): string => `${JSON.stringify(ring, null, 2)}\n`;

/** One stored generation of a `/2` ring. */
interface StoredGeneration {
  generation: number;
  kid: string;
  state: SigningKeyState;
  created_at: string;
  activated_at?: string;
  stopped_at?: string;
  retired_at?: string;
  revoked_at?: string;
  compromised_at?: string;
  published_at?: string;
  stop_confirmed_at?: string;
  withdrawal_confirmed_at?: string;
  public_jwk: Record<string, unknown>;
  private_jwk?: Record<string, unknown>;
}

interface StoredRing {
  format: typeof SIGNING_KEY_RING_FORMAT;
  issuer: string;
  revision: number;
  created_at: string;
  updated_at: string;
  roles: Record<AsSigningRole, { alg: string; generations: StoredGeneration[] }>;
}

/**
 * Create the ring at `file` for `issuer`, once, with generation 1 of every
 * role active under its configured `kid`. The directory is created 0700 when
 * missing and must otherwise grant no group or other access; the file is
 * written 0600 to a temporary name in that directory, flushed, and linked
 * into place, which fails if a ring already exists, so an existing ring is
 * never replaced. Returns the public JWKs it published.
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
  const ring: StoredRing = {
    format: SIGNING_KEY_RING_FORMAT,
    issuer,
    revision: 1,
    created_at: created,
    updated_at: created,
    roles: {} as StoredRing["roles"],
  };
  const published: Record<string, unknown>[] = [];
  for (const name of AS_SIGNING_ROLES) {
    const role = roles[name];
    const privateJwk = await generate(role);
    ring.roles[name] = {
      alg: role.alg,
      generations: [
        {
          generation: 1,
          kid: role.kid,
          state: "active",
          created_at: created,
          activated_at: created,
          public_jwk: publicHalf(privateJwk),
          private_jwk: privateJwk,
        },
      ],
    };
    published.push(publicHalf(stamp(privateJwk, role.kid, role.alg)));
  }

  const tmp = writeTemp(dir, serialize(ring));
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
  fsyncDir(dir);
  return published;
}

/** The ring file's bytes and parsed content, after the permission check. */
function readRing(file: string, issuer: string): { raw: string; ring: Record<string, unknown> } {
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
  if (ring === null || typeof ring !== "object") {
    throw new SigningKeyRingError(`${file} is not a ${SIGNING_KEY_RING_FORMAT_V1} or ${SIGNING_KEY_RING_FORMAT} ring`);
  }
  return { raw, ring };
}

/** The format, issuer and role set every ring must carry. */
function checkHeader(file: string, ring: Record<string, unknown>, issuer: string): Record<string, Record<string, unknown>> {
  if (ring.format !== SIGNING_KEY_RING_FORMAT_V1 && ring.format !== SIGNING_KEY_RING_FORMAT) {
    throw new SigningKeyRingError(`${file} is not a ${SIGNING_KEY_RING_FORMAT_V1} or ${SIGNING_KEY_RING_FORMAT} ring`);
  }
  if (ring.issuer !== issuer) {
    throw new SigningKeyRingError(`${file} is for issuer ${String(ring.issuer)}, not ${issuer}`);
  }
  const stored = ring.roles as Record<string, Record<string, unknown>> | undefined;
  if (stored === null || typeof stored !== "object") throw new SigningKeyRingError(`${file} has no roles`);
  const extra = Object.keys(stored).filter((k) => !(AS_SIGNING_ROLES as readonly string[]).includes(k));
  if (extra.length > 0) throw new SigningKeyRingError(`${file} carries unknown roles: ${extra.join(", ")}`);
  for (const name of AS_SIGNING_ROLES) {
    if (!stored[name] || typeof stored[name] !== "object") throw new SigningKeyRingError(`${file} has no ${name} key`);
  }
  return stored;
}

/** A slice 1 ring: one key per role under its configured `kid`, as one active generation. */
async function resolveV1(
  file: string,
  stored: Record<string, Record<string, unknown>>,
  roles: Record<AsSigningRole, SigningRoleConfig>,
): Promise<AsSigningKeys> {
  const out = {} as AsSigningKeys;
  for (const name of AS_SIGNING_ROLES) {
    const entry = stored[name] as Record<string, unknown>;
    const role = roles[name];
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
      out[name] = single(await resolve(privateJwk, role.kid, role.alg), role.kid);
    } catch (e) {
      throw new SigningKeyRingError(`${name}'s key does not import as ${role.alg}: ${(e as Error).message}`);
    }
  }
  return out;
}

const isTime = (v: unknown): v is string => typeof v === "string" && !Number.isNaN(Date.parse(v));

/** The times each state carries (required) and may carry (optional); every other time is refused. */
const STATE_TIMES: Record<SigningKeyState, { required: readonly string[]; optional: readonly string[] }> = {
  pending: { required: [], optional: ["published_at"] },
  active: { required: ["activated_at"], optional: ["published_at"] },
  overlap: { required: ["activated_at", "stopped_at"], optional: ["published_at", "stop_confirmed_at"] },
  retired: {
    required: ["retired_at"],
    optional: ["activated_at", "stopped_at", "published_at", "stop_confirmed_at", "withdrawal_confirmed_at"],
  },
  compromised: {
    required: ["revoked_at"],
    optional: [
      "activated_at",
      "stopped_at",
      "retired_at",
      "compromised_at",
      "published_at",
      "stop_confirmed_at",
      "withdrawal_confirmed_at",
    ],
  },
};
const LIFECYCLE_TIMES = [
  "activated_at",
  "stopped_at",
  "retired_at",
  "revoked_at",
  "compromised_at",
  "published_at",
  "stop_confirmed_at",
  "withdrawal_confirmed_at",
] as const;

/**
 * A `/2` ring, checked whole before anything is used: every role at its
 * configured algorithm; generations numbered once each, each under the `kid`
 * its number gives; one `active` and at most one `pending` generation per
 * role; a private key on exactly the `pending` and `active` generations,
 * matching the stored public key; and each state's times, no others.
 */
async function resolveV2(
  file: string,
  stored: Record<string, Record<string, unknown>>,
  roles: Record<AsSigningRole, SigningRoleConfig>,
): Promise<AsSigningKeys> {
  const out = {} as AsSigningKeys;
  const seenKids = new Set<string>();
  for (const name of AS_SIGNING_ROLES) {
    const entry = stored[name] as { alg?: unknown; generations?: unknown };
    const role = roles[name];
    if (entry.alg !== role.alg) {
      throw new SigningKeyRingError(`${name} is recorded with alg ${String(entry.alg)}, not the configured ${role.alg}`);
    }
    const generations = entry.generations;
    if (!Array.isArray(generations) || generations.length === 0) {
      throw new SigningKeyRingError(`${name} has no generations`);
    }
    const numbers = new Set<number>();
    let signer: { kid: string; key: ResolvedSigningKey } | undefined;
    let pending = 0;
    const published: Record<string, unknown>[] = [];
    const verification: Record<string, unknown>[] = [];
    const withdrawn: WithdrawnSigningKey[] = [];
    for (const raw of generations as Record<string, unknown>[]) {
      const g = raw as Partial<StoredGeneration> & Record<string, unknown>;
      const n = g.generation;
      if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1) {
        throw new SigningKeyRingError(`${name} has a generation numbered ${String(n)}`);
      }
      if (numbers.has(n)) throw new SigningKeyRingError(`${name} records generation ${n} twice`);
      numbers.add(n);
      const kid = generationKid(role.kid, n);
      if (g.kid !== kid) {
        throw new SigningKeyRingError(
          `${name} generation ${n} is recorded under kid ${String(g.kid)}, not ${kid} from the configured ${role.kid}`,
        );
      }
      if (seenKids.has(kid)) throw new SigningKeyRingError(`kid ${kid} is recorded twice`);
      seenKids.add(kid);
      const state = g.state as SigningKeyState;
      if (!(SIGNING_KEY_STATES as readonly string[]).includes(state)) {
        throw new SigningKeyRingError(`${kid} has an unknown state ${String(g.state)}`);
      }
      if (!isTime(g.created_at)) throw new SigningKeyRingError(`${kid} has no creation time`);
      const times = STATE_TIMES[state];
      for (const t of times.required) {
        if (!isTime(g[t])) throw new SigningKeyRingError(`${kid} is ${state} without ${t}`);
      }
      for (const t of LIFECYCLE_TIMES) {
        if (g[t] !== undefined && !times.required.includes(t) && !times.optional.includes(t)) {
          throw new SigningKeyRingError(`${kid} is ${state} but records ${t}`);
        }
        if (g[t] !== undefined && !isTime(g[t])) throw new SigningKeyRingError(`${kid} records ${t} that is not a time`);
      }
      const publicJwk = g.public_jwk;
      if (!publicJwk || typeof publicJwk !== "object" || PRIVATE_MEMBERS.some((m) => m in publicJwk)) {
        throw new SigningKeyRingError(`${kid} holds no public key, or a public key with private members`);
      }
      const stamped = publicHalf(stamp(publicJwk, kid, role.alg));
      try {
        await importJWK(stamped as JWK, role.alg);
      } catch (e) {
        throw new SigningKeyRingError(`${kid}'s public key does not import as ${role.alg}: ${(e as Error).message}`);
      }
      const holdsPrivate = state === "pending" || state === "active";
      const privateJwk = g.private_jwk;
      if (!holdsPrivate) {
        if (privateJwk !== undefined) throw new SigningKeyRingError(`${kid} is ${state} but still holds a private key`);
      } else {
        if (!privateJwk || typeof privateJwk !== "object" || typeof privateJwk.d !== "string") {
          throw new SigningKeyRingError(`${kid} holds no private key`);
        }
        let key: ResolvedSigningKey;
        try {
          key = await resolve(privateJwk, kid, role.alg);
        } catch (e) {
          throw new SigningKeyRingError(`${kid}'s key does not import as ${role.alg}: ${(e as Error).message}`);
        }
        if ((await calculateJwkThumbprint(key.publicJwk as JWK)) !== (await calculateJwkThumbprint(stamped as JWK))) {
          throw new SigningKeyRingError(`${kid}'s private key does not match its public key`);
        }
        if (state === "active") {
          if (signer) throw new SigningKeyRingError(`${name} has more than one active generation`);
          signer = { kid, key };
        } else {
          pending += 1;
        }
      }
      if (state === "pending" || state === "active" || state === "overlap") published.push(stamped);
      if (state === "active" || state === "overlap") verification.push(stamped);
      if (state === "compromised") {
        withdrawn.push({
          publicJwk: stamped,
          revoked_at: g.revoked_at as string,
          ...(g.compromised_at !== undefined ? { compromised_at: g.compromised_at as string } : {}),
        });
      }
    }
    if (!numbers.has(1)) throw new SigningKeyRingError(`${name} has no generation 1`);
    if (!signer) throw new SigningKeyRingError(`${name} has no active generation`);
    if (pending > 1) throw new SigningKeyRingError(`${name} has more than one pending generation`);
    out[name] = { ...signer.key, kid: signer.kid, published, verification, withdrawn };
  }
  return out;
}

/**
 * Load the ring at `file` for `issuer`. Refuses, never generating a
 * replacement, when the file is missing, grants group or other access, is
 * not a ring, names another issuer, lacks a role or carries an extra one,
 * records a `kid` or algorithm other than the configured one, or holds a key
 * that does not import; a `/2` ring is also refused when any of its
 * generations breaks the invariants above.
 */
export async function loadSigningKeyRing(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
): Promise<AsSigningKeys> {
  return (await loadSigningKeyRingState(file, issuer, roles)).keys;
}

/** A `/2` ring's revision: a positive integer every key-state operation advances. */
function revisionOf(file: string, ring: Record<string, unknown>): number {
  const revision = ring.revision;
  if (typeof revision !== "number" || !Number.isSafeInteger(revision) || revision < 1) {
    throw new SigningKeyRingError(`${file} has no revision`);
  }
  return revision;
}

/**
 * {@link loadSigningKeyRing}, with the ring's revision: what the AS serves
 * as its `/jwks` `ETag`, so verification can tell which revision a running
 * AS loaded. A slice 1 ring has none.
 */
export async function loadSigningKeyRingState(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
): Promise<{ keys: AsSigningKeys; revision?: number }> {
  const { ring } = readRing(file, issuer);
  const stored = checkHeader(file, ring, issuer);
  if (ring.format === SIGNING_KEY_RING_FORMAT_V1) return { keys: await resolveV1(file, stored, roles) };
  const revision = revisionOf(file, ring);
  return { keys: await resolveV2(file, stored, roles), revision };
}

/**
 * Replace the ring at `file` with `next`, unless it changed since `before`
 * was read: written 0600 to a temporary name in the same directory, flushed,
 * and renamed over the ring. The check narrows, but does not close, the
 * window for a concurrent writer; the operations take no lock, and an
 * operator runs one at a time.
 */
function replaceRing(file: string, before: string, next: unknown): void {
  const dir = dirname(file);
  if (openToOthers(dir) !== 0) {
    throw new SigningKeyRingError(`${dir} grants group or other access; use a directory with mode 0700`);
  }
  const tmp = writeTemp(dir, serialize(next));
  try {
    if (readFileSync(file, "utf8") !== before) {
      throw new SigningKeyRingError(`${file} changed while it was being updated; nothing was written`);
    }
    renameSync(tmp, file);
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {
      // Already renamed into place, or never created.
    }
    if (e instanceof SigningKeyRingError) throw e;
    throw new SigningKeyRingError(`cannot write ${file}: ${(e as Error).message}`);
  }
  fsyncDir(dir);
}

/**
 * Convert a slice 1 (`/1`) ring at `file` into a `/2` ring, explicitly: each
 * role's key becomes its active generation 1 under the same `kid`, with the
 * same material. Nothing is generated. Refuses a `/2` ring and any `/1` ring
 * that would not load. Returns the public JWKs, unchanged.
 */
export async function migrateSigningKeyRing(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  now: () => Date = () => new Date(),
): Promise<Record<string, unknown>[]> {
  const { raw, ring } = readRing(file, issuer);
  const stored = checkHeader(file, ring, issuer);
  if (ring.format === SIGNING_KEY_RING_FORMAT) throw new SigningKeyRingError(`${file} is already a ${SIGNING_KEY_RING_FORMAT} ring`);
  const before = await resolveV1(file, stored, roles);
  const created = isTime(ring.created_at) ? (ring.created_at as string) : now().toISOString();
  const next: StoredRing = {
    format: SIGNING_KEY_RING_FORMAT,
    issuer,
    revision: 1,
    created_at: created,
    updated_at: now().toISOString(),
    roles: {} as StoredRing["roles"],
  };
  for (const name of AS_SIGNING_ROLES) {
    const entry = stored[name] as Record<string, unknown>;
    const privateJwk = entry.private_jwk as Record<string, unknown>;
    const since = isTime(entry.created_at) ? (entry.created_at as string) : created;
    next.roles[name] = {
      alg: roles[name].alg,
      generations: [
        {
          generation: 1,
          kid: roles[name].kid,
          state: "active",
          created_at: since,
          activated_at: since,
          public_jwk: publicHalf(privateJwk),
          private_jwk: privateJwk,
        },
      ],
    };
  }
  await resolveV2(file, next.roles as unknown as Record<string, Record<string, unknown>>, roles);
  replaceRing(file, raw, next);
  return AS_SIGNING_ROLES.map((r) => before[r].publicJwk);
}

/**
 * Apply `change` to the `/2` ring at `file`, checking the ring whole before
 * and after, and replace the file only when both checks pass. A key-state
 * change advances the revision; a verification only records confirmations,
 * so the running AS still serves the ring's revision. A `/1` ring is refused
 * with the migration step to run first.
 */
async function updateRing<R>(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  now: () => Date,
  change: (ring: StoredRing, at: string) => Promise<R>,
  advance = true,
): Promise<R> {
  const { raw, ring } = readRing(file, issuer);
  const stored = checkHeader(file, ring, issuer);
  if (ring.format === SIGNING_KEY_RING_FORMAT_V1) {
    throw new SigningKeyRingError(
      `${file} is a ${SIGNING_KEY_RING_FORMAT_V1} ring; convert it first with \`pnpm keys migrate --ring ${file} --issuer ${issuer}\``,
    );
  }
  const revision = revisionOf(file, ring);
  await resolveV2(file, stored, roles);
  const next = structuredClone(ring) as unknown as StoredRing;
  const at = now().toISOString();
  const result = await change(next, at);
  next.updated_at = at;
  if (advance) next.revision = revision + 1;
  await resolveV2(file, next.roles as unknown as Record<string, Record<string, unknown>>, roles);
  replaceRing(file, raw, next);
  return result;
}

function roleOf(role: string): AsSigningRole {
  if (!(AS_SIGNING_ROLES as readonly string[]).includes(role)) {
    throw new SigningKeyRingError(`unknown role ${role}; one of ${AS_SIGNING_ROLES.join(", ")}`);
  }
  return role as AsSigningRole;
}

/** A new generation of `role` in the given state, numbered after every existing one. */
async function newGeneration(
  ring: StoredRing,
  role: AsSigningRole,
  config: SigningRoleConfig,
  state: "pending" | "active",
  at: string,
): Promise<StoredGeneration> {
  const n = Math.max(...ring.roles[role].generations.map((g) => g.generation)) + 1;
  const privateJwk = await generate(config);
  return {
    generation: n,
    kid: generationKid(config.kid, n),
    state,
    created_at: at,
    ...(state === "active" ? { activated_at: at } : {}),
    public_jwk: publicHalf(privateJwk),
    private_jwk: privateJwk,
  };
}

const secondsBetween = (from: string, to: string): number => Math.floor((Date.parse(to) - Date.parse(from)) / 1000);

/**
 * Rotation, first step: stage a new `pending` generation of `role`, published
 * at `/jwks` from the AS's next start but not yet signing. Refuses when the
 * role already has a pending generation.
 */
export async function stageSigningKeyGeneration(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  role: string,
  now: () => Date = () => new Date(),
): Promise<{ kid: string }> {
  const name = roleOf(role);
  return updateRing(file, issuer, roles, now, async (ring, at) => {
    const pending = ring.roles[name].generations.find((g) => g.state === "pending");
    if (pending) {
      throw new SigningKeyRingError(`${name} already has a pending generation, ${pending.kid}; activate or retire it first`);
    }
    const g = await newGeneration(ring, name, roles[name], "pending", at);
    ring.roles[name].generations.push(g);
    return { kid: g.kid };
  });
}

/**
 * Rotation, second step: the pending generation of `role` becomes `active`,
 * and the active one moves to `overlap`, where it signs nothing, loses its
 * private key, and stays published and accepted. Refuses until the pending
 * generation has been confirmed published by the running AS
 * ({@link verifySigningKeyRing}) for `minPublishedS` seconds, so a consumer
 * honoring the `/jwks` freshness lifetime ({@link JWKS_MAX_AGE_SECONDS})
 * holds it before anything is signed under it. Staging alone publishes
 * nothing.
 */
export async function activateSigningKeyGeneration(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  role: string,
  opts: { minPublishedS: number; now?: () => Date },
): Promise<{ kid: string; previous: string }> {
  const name = roleOf(role);
  return updateRing(file, issuer, roles, opts.now ?? (() => new Date()), async (ring, at) => {
    const generations = ring.roles[name].generations;
    const pending = generations.find((g) => g.state === "pending");
    if (!pending) {
      throw new SigningKeyRingError(`${name} has no pending generation; stage one with \`pnpm keys rotate --role ${name}\``);
    }
    if (!pending.published_at) {
      throw new SigningKeyRingError(
        `${pending.kid} is not confirmed published: start the AS with this ring, then run \`pnpm keys verify\``,
      );
    }
    const published = secondsBetween(pending.published_at, at);
    if (published < opts.minPublishedS) {
      throw new SigningKeyRingError(
        `${pending.kid} has been confirmed published for ${published}s; activation needs ${opts.minPublishedS}s, ${opts.minPublishedS - published}s more`,
      );
    }
    const active = generations.find((g) => g.state === "active") as StoredGeneration;
    active.state = "overlap";
    active.stopped_at = at;
    delete active.private_jwk;
    pending.state = "active";
    pending.activated_at = at;
    return { kid: pending.kid, previous: active.kid };
  });
}

/** What retiring a generation must outlast: the deployment's horizons, and the standing consents attested under it. */
export interface SigningKeyRetention {
  /** The deployment's audit horizon (`policy.audit_horizon_s`), in seconds. */
  auditHorizonS: number;
  /** The longest Mission lifetime (`policy.max_mission_lifetime_s`), or null when unbounded. */
  maxMissionLifetimeS: number | null;
  /**
   * For an `asStatus` generation: the governed-policy consents not withdrawn
   * whose attestation names its `kid`. Undefined when unknown.
   */
  standingConsents?: number;
}

/**
 * Remove generation `kid` of `role` from the live set: it leaves `/jwks` and
 * the AS's own verifiers, keeping only its public key in the ring's record.
 *
 * An `overlap` generation retires only after its retention deadline: the
 * time the running AS was confirmed to have stopped signing under it
 * (`stop_confirmed_at`), plus the longer of the audit horizon and the
 * longest Mission lifetime. A Mission whose artifacts it signed was created
 * no later than that, and its record is retained for its audit horizon,
 * which covers its lifetime. With no Mission lifetime bound, or no confirmed
 * stop, no deadline can be established, and retirement is refused. An
 * `asStatus` generation is also refused while any standing governed-policy
 * consent is attested under it: retirement does not expire a consent. After
 * the AS stopped signing under a generation, that count only falls.
 *
 * A `pending` generation never signed, so retiring it needs no wait; that is
 * how a staged rotation is abandoned. The active generation is refused:
 * activate a successor first.
 */
export async function retireSigningKeyGeneration(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  role: string,
  kid: string,
  opts: { retention: SigningKeyRetention; now?: () => Date },
): Promise<{ kid: string }> {
  const name = roleOf(role);
  return updateRing(file, issuer, roles, opts.now ?? (() => new Date()), async (ring, at) => {
    const g = ring.roles[name].generations.find((x) => x.kid === kid);
    if (!g) throw new SigningKeyRingError(`${name} has no generation ${kid}`);
    if (g.state === "active") {
      throw new SigningKeyRingError(`${kid} is ${name}'s active generation; activate a successor before retiring it`);
    }
    if (g.state === "retired" || g.state === "compromised") throw new SigningKeyRingError(`${kid} is already ${g.state}`);
    if (g.state === "overlap") {
      const { auditHorizonS, maxMissionLifetimeS, standingConsents } = opts.retention;
      if (!g.stop_confirmed_at) {
        throw new SigningKeyRingError(
          `${kid} is not confirmed to have stopped signing: start the AS with this ring, then run \`pnpm keys verify\``,
        );
      }
      if (maxMissionLifetimeS === null) {
        throw new SigningKeyRingError(
          `no retention deadline can be established for ${kid}: the Mission lifetime is unbounded (policy.max_mission_lifetime_s is null)`,
        );
      }
      const retainS = Math.max(auditHorizonS, maxMissionLifetimeS);
      const since = secondsBetween(g.stop_confirmed_at, at);
      if (since < retainS) {
        throw new SigningKeyRingError(
          `${kid} was confirmed to have stopped signing at ${g.stop_confirmed_at}; it stays published for ${retainS}s (the audit horizon, covering the longest Mission lifetime), ${retainS - since}s more`,
        );
      }
      if (name === "asStatus") {
        if (standingConsents === undefined) {
          throw new SigningKeyRingError(`the standing governed-policy consents attested under ${kid} are unknown; name the kernel store`);
        }
        if (standingConsents > 0) {
          throw new SigningKeyRingError(
            `${standingConsents} standing governed-policy consent(s) are attested under ${kid}; retirement does not expire a consent`,
          );
        }
      }
    }
    g.state = "retired";
    g.retired_at = at;
    delete g.private_jwk;
    return { kid };
  });
}

/**
 * Withdraw generation `kid` of `role` as compromised, at once: it leaves
 * `/jwks` and every verifier the AS runs, loses any private key, and is kept
 * only with its revocation time (`revoked_at`, now) and, when one is
 * established, its compromise time (`compromised_at`). Compromising the
 * active generation creates its replacement in the same write: a fresh
 * generation, active immediately. That replacement is not pre-published, a
 * deliberate departure from {@link stageSigningKeyGeneration}'s two steps for
 * an emergency; a pending generation is not promoted, since it may be exposed
 * with the same file.
 */
export async function compromiseSigningKeyGeneration(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  role: string,
  kid: string,
  opts: { compromisedAt?: Date; now?: () => Date } = {},
): Promise<{ kid: string; replacement?: string }> {
  const name = roleOf(role);
  const now = opts.now ?? (() => new Date());
  return updateRing(file, issuer, roles, now, async (ring, at) => {
    const g = ring.roles[name].generations.find((x) => x.kid === kid);
    if (!g) throw new SigningKeyRingError(`${name} has no generation ${kid}`);
    if (g.state === "compromised") throw new SigningKeyRingError(`${kid} is already compromised`);
    if (opts.compromisedAt) {
      if (Number.isNaN(opts.compromisedAt.getTime())) throw new SigningKeyRingError("the compromise time is not a time");
      if (opts.compromisedAt.getTime() > Date.parse(at)) {
        throw new SigningKeyRingError(`the compromise time ${opts.compromisedAt.toISOString()} is in the future`);
      }
    }
    let replacement: StoredGeneration | undefined;
    if (g.state === "active") {
      replacement = await newGeneration(ring, name, roles[name], "active", at);
      g.stopped_at = at;
    }
    g.state = "compromised";
    g.revoked_at = at;
    if (opts.compromisedAt) g.compromised_at = opts.compromisedAt.toISOString();
    delete g.private_jwk;
    if (replacement) ring.roles[name].generations.push(replacement);
    return { kid, ...(replacement ? { replacement: replacement.kid } : {}) };
  });
}

/** What a verification of the running AS confirmed. */
export interface SigningKeyRingVerification {
  revision: number;
  /** Generations first confirmed published by this verification. */
  published: string[];
  /** Generations first confirmed no longer signing. */
  stopped: string[];
  /** Generations first confirmed withdrawn from `/jwks`. */
  withdrawn: string[];
}

/**
 * The procedure's last step: confirm, from the running AS's own published
 * key set, that it loaded this ring, and record what that confirms. The
 * `jwks_uri` comes from the issuer's metadata. Refuses, recording nothing,
 * unless that `/jwks` carries this ring's revision as its `ETag` and
 * publishes exactly the ring's pending, active and overlap generations. Then
 * it records, where not yet recorded: `published_at` for each generation
 * published; `stop_confirmed_at` for each that has signed and is no longer
 * active; and `withdrawal_confirmed_at` for each retired or compromised one.
 * It does not advance the revision.
 */
export async function verifySigningKeyRing(
  file: string,
  issuer: string,
  roles: Record<AsSigningRole, SigningRoleConfig>,
  opts: { fetch?: (url: string) => Promise<Response>; now?: () => Date } = {},
): Promise<SigningKeyRingVerification> {
  const get = opts.fetch ?? ((url: string) => fetch(url));
  const metadataUrl = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  let metadata: Record<string, unknown>;
  try {
    const res = await get(metadataUrl);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    metadata = (await res.json()) as Record<string, unknown>;
  } catch (e) {
    throw new SigningKeyRingError(`cannot read the AS's metadata at ${metadataUrl}: ${(e as Error).message}`);
  }
  if (metadata.issuer !== issuer || typeof metadata.jwks_uri !== "string") {
    throw new SigningKeyRingError(`${metadataUrl} is not ${issuer}'s metadata with a jwks_uri`);
  }
  const jwksUri = metadata.jwks_uri;
  let etag: string | null;
  let liveKids: string[];
  try {
    const res = await get(jwksUri);
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    etag = res.headers.get("etag");
    const body = (await res.json()) as { keys?: Record<string, unknown>[] };
    liveKids = (body.keys ?? []).map((k) => String(k.kid)).sort();
  } catch (e) {
    throw new SigningKeyRingError(`cannot read ${jwksUri}: ${(e as Error).message}`);
  }
  return updateRing(
    file,
    issuer,
    roles,
    opts.now ?? (() => new Date()),
    async (ring, at) => {
      if (etag !== `"${ring.revision}"`) {
        throw new SigningKeyRingError(
          `the running AS serves revision ${etag ?? "(none)"}, not this ring's "${ring.revision}": restart it with this ring, then verify again`,
        );
      }
      const generations = AS_SIGNING_ROLES.flatMap((r) => ring.roles[r].generations);
      const expected = generations
        .filter((g) => g.state === "pending" || g.state === "active" || g.state === "overlap")
        .map((g) => g.kid)
        .sort();
      if (JSON.stringify(liveKids) !== JSON.stringify(expected)) {
        throw new SigningKeyRingError(
          `${jwksUri} publishes ${liveKids.join(", ")}, not this ring's live set ${expected.join(", ")}`,
        );
      }
      const confirmed: SigningKeyRingVerification = { revision: ring.revision, published: [], stopped: [], withdrawn: [] };
      for (const g of generations) {
        const live = g.state === "pending" || g.state === "active" || g.state === "overlap";
        if (live && !g.published_at) {
          g.published_at = at;
          confirmed.published.push(g.kid);
        }
        if (g.state !== "active" && g.activated_at && !g.stop_confirmed_at) {
          g.stop_confirmed_at = at;
          confirmed.stopped.push(g.kid);
        }
        if ((g.state === "retired" || g.state === "compromised") && !g.withdrawal_confirmed_at) {
          g.withdrawal_confirmed_at = at;
          confirmed.withdrawn.push(g.kid);
        }
      }
      return confirmed;
    },
    false,
  );
}

/** How the AS obtains its signing keys. */
export type SigningKeySource = { ring: string } | { ephemeral: true };

/**
 * A deployment entry point's key source, from its environment: a ring at
 * `MISSION_KEY_RING` (an absolute path, since launchers do not run in the
 * directory they were started from), or ephemeral keys when
 * `MISSION_EPHEMERAL_KEYS=1`. Neither, or both, refuses: a deployment says
 * which it runs.
 */
export function signingKeysFromEnv(env: Readonly<Record<string, string | undefined>>): SigningKeySource {
  const ring = env.MISSION_KEY_RING?.trim();
  const ephemeral = env.MISSION_EPHEMERAL_KEYS === "1";
  if (ring && ephemeral) {
    throw new SigningKeyRingError("set MISSION_KEY_RING or MISSION_EPHEMERAL_KEYS=1, not both");
  }
  if (ring && !isAbsolute(ring)) {
    throw new SigningKeyRingError(`MISSION_KEY_RING must be an absolute path, not ${ring}`);
  }
  if (ring) return { ring };
  if (ephemeral) return { ephemeral: true };
  throw new SigningKeyRingError(
    "choose the signing keys: MISSION_KEY_RING=<path> (initialize it once with `pnpm keys init`), or MISSION_EPHEMERAL_KEYS=1 for keys that change at every restart",
  );
}

/** A file-backed kernel store and its recovery witness (#250 step 3). */
export interface KernelStoreConfig {
  file: string;
  /** The recovery witness, outside the store's restore unit; absent, a restored older store is not detected. */
  witness?: string;
}

/**
 * @spec #250, #831: a deployment entry point's kernel store, from its
 * environment. `MISSION_KERNEL_STORE` absent: the kernel is in memory and a
 * restart loses it. Present: the absolute path of the kernel's file, kept
 * across restarts. It requires a key ring (`MISSION_KEY_RING`): with keys that
 * change at every restart, nothing the kept kernel issued or signed verifies
 * after one.
 *
 * It also requires a recovery witness (`MISSION_KERNEL_WITNESS`, #250 step 3):
 * an absolute path in another directory than the store, outside the store's
 * restore unit, created once with `pnpm kernel-recovery init`. The kernel then
 * holds its file exclusively, so a second process on it is refused, and opens
 * only when the store matches the witness, so a restored older store is
 * refused rather than resumed. One process on one host.
 */
export function kernelStoreFromEnv(env: Readonly<Record<string, string | undefined>>): KernelStoreConfig | undefined {
  const file = env.MISSION_KERNEL_STORE?.trim();
  if (!file) return undefined;
  if (!isAbsolute(file)) {
    throw new Error(`MISSION_KERNEL_STORE must be an absolute path, not ${file}`);
  }
  if (!env.MISSION_KEY_RING?.trim()) {
    throw new Error(
      "MISSION_KERNEL_STORE requires MISSION_KEY_RING: with signing keys that change at every restart, nothing the kept kernel issued or signed verifies after one",
    );
  }
  const witness = env.MISSION_KERNEL_WITNESS?.trim();
  if (!witness) {
    throw new Error(
      "MISSION_KERNEL_STORE requires MISSION_KERNEL_WITNESS: without a recovery witness outside the store, a restored older store would be resumed (create it once with `pnpm kernel-recovery init`)",
    );
  }
  if (!isAbsolute(witness)) {
    throw new Error(`MISSION_KERNEL_WITNESS must be an absolute path, not ${witness}`);
  }
  if (witnessSharesStoreTree(file, witness)) {
    throw new Error(
      "MISSION_KERNEL_WITNESS must be outside the store's directory, and the store outside the witness's, so restoring one cannot restore the other with it",
    );
  }
  return { file, witness };
}
