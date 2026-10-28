/**
 * @spec #1815 gap 5 (D945): the AS's key binding record. A durable file, kept
 * apart from the key ring, that binds each `kid` the ring has held for an
 * issuer to its public key's RFC 7638 thumbprint. Loading a ring against it:
 *
 * - **Refuses a recorded `kid` under other material.** A lost ring recreated
 *   with `pnpm keys init` reuses the configured `kid`s with new keys; every
 *   token, Status response and consent signed under the old keys would stop
 *   verifying while consumers still trust those `kid`s. Recovery restores the
 *   original ring, or replaces it under new identifiers (new configured base
 *   `kid`s), which the record accepts as new and notes as a replacement.
 * - **Appends a `kid` it has not seen** (a rotation's new generation), so the
 *   next recreated ring cannot reuse it either. A failed append refuses, since
 *   an unrecorded `kid` is the hole the record exists to close.
 * - **Never creates itself.** A missing record refuses; `pnpm keys init
 *   --bindings` or `pnpm keys bind` creates it once, by linking a flushed
 *   temporary file into place, so of two creators one is refused.
 *
 * Appends are serialized (#1833). A recorded binding never changes, so a check
 * that finds nothing to append is complete without a lock. One that finds a
 * `kid` to append takes an exclusive lock on `<record>.lock`, then re-reads,
 * re-checks and writes the record without yielding, so two loads, in one
 * process or two, never each replace the record with their own append. A load
 * that finds another process holding the lock is refused.
 *
 * The record and the ring are separate restore units: a record inside the
 * ring's directory tree, or the ring inside the record's, is refused, so
 * losing or restoring one does not take the other with it. Losing both is
 * not detected.
 */

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  createDurableFile,
  type Database,
  holdFileLock,
  witnessSharesStoreTree,
  writeDurableFile,
} from "@mission/store";
import { calculateJwkThumbprint, type JWK } from "jose";

export const KEY_BINDINGS_FORMAT = "mission-as-key-bindings/1";

/** One recorded `kid`: its role, its key's thumbprint, and when it was first recorded. */
export interface KeyBinding {
  role: string;
  kid: string;
  jkt: string;
  recorded_at: string;
}

/** A role's base `kid` changing for an issuer that already had recorded ones: a deliberate replacement. */
export interface KeyBindingReplacement {
  at: string;
  role: string;
  from: string[];
  to: string;
}

export interface KeyBindingRecord {
  format: typeof KEY_BINDINGS_FORMAT;
  issuer: string;
  bindings: KeyBinding[];
  replacements: KeyBindingReplacement[];
}

/** A key the ring holds, in any state: its role, its role's configured base `kid`, its `kid` and public JWK. */
export interface RingKey {
  role: string;
  baseKid: string;
  kid: string;
  publicJwk: Record<string, unknown>;
}

export class KeyBindingError extends Error {}

const serialize = (r: KeyBindingRecord): string => `${JSON.stringify(r, null, 2)}\n`;

/** The base of a generation `kid`: `<base>-<n>` for n >= 2, else the `kid` itself. */
function baseOf(kid: string, baseKid: string): boolean {
  return kid === baseKid || new RegExp(`^${baseKid.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-[0-9]+$`).test(kid);
}

function placement(ring: string, file: string): void {
  if (witnessSharesStoreTree(ring, file)) {
    throw new KeyBindingError(
      `the key binding record ${file} must be outside the ring's directory, and the ring outside the record's, so losing or restoring one does not take the other with it`,
    );
  }
}

function read(file: string, issuer: string): KeyBindingRecord {
  if (!existsSync(file)) {
    throw new KeyBindingError(
      `no key binding record at ${file}; create it once with \`pnpm keys bind --ring <ring> --bindings ${file}\` (never created at startup)`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new KeyBindingError(`${file} is not a readable key binding record`);
  }
  const r = parsed as Partial<KeyBindingRecord>;
  if (r.format !== KEY_BINDINGS_FORMAT || !Array.isArray(r.bindings) || !Array.isArray(r.replacements)) {
    throw new KeyBindingError(`${file} is not a ${KEY_BINDINGS_FORMAT} record`);
  }
  if (r.issuer !== issuer) throw new KeyBindingError(`${file} binds keys for issuer ${String(r.issuer)}, not ${issuer}`);
  return r as KeyBindingRecord;
}

const createdOnce = (file: string) => new KeyBindingError(`${file} already exists; a key binding record is created once`);

/** Create the record at `file` from the keys a ring holds now; an existing file is refused. */
export async function initKeyBindings(
  file: string,
  ring: string,
  issuer: string,
  keys: readonly RingKey[],
  now: () => Date = () => new Date(),
): Promise<KeyBindingRecord> {
  placement(ring, file);
  if (existsSync(file)) throw createdOnce(file);
  const at = now().toISOString();
  const record: KeyBindingRecord = {
    format: KEY_BINDINGS_FORMAT,
    issuer,
    bindings: await Promise.all(
      keys.map(async (k) => ({ role: k.role, kid: k.kid, jkt: await calculateJwkThumbprint(k.publicJwk as JWK), recorded_at: at })),
    ),
    replacements: [],
  };
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  try {
    createDurableFile(file, serialize(record));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw createdOnce(file);
    throw new KeyBindingError(`cannot write ${file}: ${(e as Error).message}`);
  }
  return record;
}

/** The `kid`s the record at `file` holds, for numbering new generations past them; empty when there is none. */
export function recordedKids(file: string, issuer: string): Set<string> {
  return new Set(read(file, issuer).bindings.map((b) => b.kid));
}

const kidsOf = (added: readonly KeyBinding[]) => added.map((a) => a.kid).join(", ");

/**
 * The record with the ring's unrecorded keys appended, and the bindings
 * added; undefined when every key is recorded. Refuses a recorded `kid` under
 * other material. `jkts` holds each key's thumbprint, in order.
 */
function appended(
  record: KeyBindingRecord,
  file: string,
  keys: readonly RingKey[],
  jkts: readonly string[],
  at: string,
): { next: KeyBindingRecord; added: KeyBinding[] } | undefined {
  const known = new Map(record.bindings.map((b) => [b.kid, b]));
  const added: KeyBinding[] = [];
  keys.forEach((k, i) => {
    const jkt = jkts[i] as string;
    const prior = known.get(k.kid);
    if (prior) {
      if (prior.jkt !== jkt) {
        throw new KeyBindingError(
          `the ring holds ${k.kid} with key material other than ${file} records for it: a recreated ring under recorded identifiers. Restore the original ring, or replace it under new configured kids (initial-runtime-deployment.md, §12); recorded kids are never reused`,
        );
      }
      return;
    }
    if (!added.some((a) => a.kid === k.kid)) added.push({ role: k.role, kid: k.kid, jkt, recorded_at: at });
  });
  if (added.length === 0) return undefined;
  const replacements: KeyBindingReplacement[] = [];
  for (const role of [...new Set(added.map((a) => a.role))]) {
    const baseKid = keys.find((k) => k.role === role)?.baseKid as string;
    const recordedForRole = record.bindings.filter((b) => b.role === role);
    if (recordedForRole.length > 0 && !recordedForRole.some((b) => baseOf(b.kid, baseKid))) {
      const from = [...new Set(recordedForRole.map((b) => b.kid))];
      replacements.push({ at, role, from, to: baseKid });
    }
  }
  return {
    next: {
      ...record,
      bindings: [...record.bindings, ...added],
      replacements: [...record.replacements, ...replacements],
    },
    added,
  };
}

/** The record's append lock; another holder, in this process or another, refuses. */
function lockRecord(file: string, added: readonly KeyBinding[]): Database {
  try {
    return holdFileLock(`${file}.lock`);
  } catch (e) {
    const why =
      (e as { code?: string }).code === "SQLITE_BUSY"
        ? `another writer holds ${file}.lock; retry once it finishes`
        : (e as Error).message;
    throw new KeyBindingError(`cannot record ${kidsOf(added)} in ${file}: ${why}`);
  }
}

/**
 * Check the keys a ring holds against the record at `file`, appending any it
 * has not seen. Refuses a recorded `kid` under other material, a missing or
 * foreign record, a record sharing the ring's directory tree, and an append
 * that cannot be written or whose lock another writer holds. Idempotent: a
 * second pass changes nothing.
 */
export async function checkKeyBindings(
  file: string,
  ring: string,
  issuer: string,
  keys: readonly RingKey[],
  now: () => Date = () => new Date(),
): Promise<void> {
  placement(ring, file);
  const jkts = await Promise.all(keys.map((k) => calculateJwkThumbprint(k.publicJwk as JWK)));
  const at = now().toISOString();
  // Nothing below yields: the record read under the lock is the one replaced.
  const pending = appended(read(file, issuer), file, keys, jkts, at);
  if (!pending) return;
  const lock = lockRecord(file, pending.added);
  try {
    const current = appended(read(file, issuer), file, keys, jkts, at);
    if (!current) return;
    try {
      writeDurableFile(file, serialize(current.next));
    } catch (e) {
      throw new KeyBindingError(`cannot record ${kidsOf(current.added)} in ${file}: ${(e as Error).message}`);
    }
  } finally {
    lock.close();
  }
}
