/**
 * @spec resource-access#resource-contract (#1847, D989, #1866 review): the
 * scope binding ledger. Each scope value a mapping contract has installed is
 * bound once, per credential issuer, to the contract reference it grants its
 * actions under, or to none, and the binding is never changed or removed. A
 * withdrawn value keeps its binding, so a later version cannot reintroduce it
 * under another, and the ledger outlives the cache that reads it, so a restart
 * cannot either: a credential issued under a value never gains a contract it
 * was not issued under.
 */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { isResourceContractRef, type ResourceContractRef, sameResourceContract } from "@mission/core";

/** One scope value's binding. */
export interface ScopeBinding {
  /** The credential issuer whose scope value this is. */
  issuer: string;
  scope: string;
  /** The resource the value maps its actions to. */
  resource: string;
  /** The contract the value grants its actions under, or null for none. */
  resource_contract: ResourceContractRef | null;
}

/** Where a cache's scope bindings are kept. */
export interface ScopeBindingLedger {
  /** Every binding recorded. Throws when the ledger cannot be read. */
  load(): ScopeBinding[];
  /**
   * Record bindings, durably before returning. A binding already recorded
   * identically is kept once; one recorded otherwise throws. Throws when the
   * ledger cannot be written.
   */
  record(bindings: readonly ScopeBinding[]): void;
  /** For the startup summary. */
  describe(): string;
}

/** The ledger key of an issuer's scope value. */
export const bindingKey = (b: Pick<ScopeBinding, "issuer" | "scope">): string => JSON.stringify([b.issuer, b.scope]);

/** Whether two bindings name the same contract, or both none. */
export const sameBinding = (a: ScopeBinding, b: ScopeBinding): boolean =>
  a.resource_contract === null || b.resource_contract === null
    ? a.resource_contract === b.resource_contract
    : sameResourceContract(a.resource_contract, b.resource_contract);

/** `bindings` merged into `recorded`, refusing a value recorded under another binding. */
function merged(recorded: readonly ScopeBinding[], bindings: readonly ScopeBinding[]): ScopeBinding[] {
  const index = new Map(recorded.map((b) => [bindingKey(b), b]));
  const out = [...recorded];
  for (const b of bindings) {
    const was = index.get(bindingKey(b));
    if (was) {
      if (!sameBinding(was, b)) throw new Error(`scope ${b.issuer} ${b.scope} is already bound to another contract`);
      continue;
    }
    index.set(bindingKey(b), b);
    out.push({ ...b });
  }
  return out;
}

/** A ledger in memory: a restart loses it. For tests and development launches only. */
export class MemoryScopeBindingLedger implements ScopeBindingLedger {
  private bindings: ScopeBinding[] = [];
  load(): ScopeBinding[] {
    return this.bindings.map((b) => ({ ...b }));
  }
  record(bindings: readonly ScopeBinding[]): void {
    this.bindings = merged(this.bindings, bindings);
  }
  describe(): string {
    return "in memory (development), lost at restart";
  }
}

/**
 * A ledger in a JSON file, replaced whole through a synced temporary file and
 * a rename. A missing file is an empty ledger; an unreadable or malformed one
 * refuses every load.
 */
export class FileScopeBindingLedger implements ScopeBindingLedger {
  constructor(private readonly path: string) {}

  load(): ScopeBinding[] {
    if (!existsSync(this.path)) return [];
    return parseLedger(JSON.parse(readFileSync(this.path, "utf8")) as unknown, this.path);
  }

  record(bindings: readonly ScopeBinding[]): void {
    const all = merged(this.load(), bindings);
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w");
    try {
      writeSync(fd, `${JSON.stringify({ scope_bindings: all }, null, 1)}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
  }

  describe(): string {
    return `file ${this.path}`;
  }
}

function parseLedger(raw: unknown, path: string): ScopeBinding[] {
  const fail = (why: string): never => {
    throw new Error(`scope binding ledger ${path}: ${why}`);
  };
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) fail("must be an object");
  const list = (raw as { scope_bindings?: unknown }).scope_bindings;
  if (!Array.isArray(list)) fail("scope_bindings must be an array");
  const out: ScopeBinding[] = [];
  for (const [i, entry] of (list as unknown[]).entries()) {
    const e = entry as Record<string, unknown> | null;
    if (e === null || typeof e !== "object") fail(`scope_bindings[${i}] must be an object`);
    const { issuer, scope, resource, resource_contract } = e as Record<string, unknown>;
    if (typeof issuer !== "string" || typeof scope !== "string" || typeof resource !== "string") {
      fail(`scope_bindings[${i}] must name an issuer, a scope and a resource`);
    }
    if (resource_contract !== null && !isResourceContractRef(resource_contract)) {
      fail(`scope_bindings[${i}].resource_contract must be a reference or null`);
    }
    out.push({
      issuer: issuer as string,
      scope: scope as string,
      resource: resource as string,
      resource_contract: resource_contract as ResourceContractRef | null,
    });
  }
  try {
    return merged([], out);
  } catch (e) {
    return fail((e as Error).message);
  }
}

/**
 * The ledger a launch names: `MAS_PILOT_SCOPE_BINDINGS`, a file, or with
 * `MAS_PILOT_DEVELOPMENT_STORE=1` alone, one in memory. Neither refuses, and
 * `env` is what a child process needs to open the same ledger.
 */
export function scopeBindingsFromEnv(env: Readonly<Record<string, string | undefined>>): {
  ledger: ScopeBindingLedger;
  env: Record<string, string>;
} {
  const path = env.MAS_PILOT_SCOPE_BINDINGS;
  if (path !== undefined && path !== "") {
    return { ledger: new FileScopeBindingLedger(path), env: { MAS_PILOT_SCOPE_BINDINGS: path } };
  }
  if (env.MAS_PILOT_DEVELOPMENT_STORE === "1") {
    return { ledger: new MemoryScopeBindingLedger(), env: { MAS_PILOT_DEVELOPMENT_STORE: "1" } };
  }
  throw new Error(
    "no scope binding ledger: set MAS_PILOT_SCOPE_BINDINGS to its file, or MAS_PILOT_DEVELOPMENT_STORE=1 for one in memory that a restart loses",
  );
}
