/**
 * @spec resource-access#resource-contract (#1847, D989, D1019): the scope
 * binding ledger. Each scope value a mapping contract has installed is bound
 * once, per credential issuer, to the contract reference it grants its
 * actions under, or to none, and the binding is never changed or removed. A
 * withdrawn value keeps its binding, so a later version cannot reintroduce it
 * under another, and the ledger outlives the caches that read it, so a
 * restart cannot either: a credential issued under a value never gains a
 * contract it was not issued under. The ledger also holds the mapping's
 * version high-water mark, the highest version installed and its document's
 * digest, committed with the bindings.
 *
 * Every install reads, judges and records under the ledger's write lock, so
 * caches in several processes sharing one ledger take turns, and each judges
 * the history the previous one left (D1019).
 */

import { isAbsolute } from "node:path";
import { isResourceContractRef, type ResourceContractRef, sameResourceContract } from "@mission/core";
import { initSharedStore, openSharedStore } from "@mission/store";

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

/** The highest mapping version installed, and its document's digest. */
export interface MappingHighWater {
  version: number;
  digest: string;
}

/** What a ledger holds. */
export interface ScopeBindingState {
  bindings: ScopeBinding[];
  highWater: MappingHighWater | null;
}

/** What an install records: bindings not yet recorded, and a raised high-water mark. */
export interface ScopeBindingRecord {
  bindings: readonly ScopeBinding[];
  highWater?: MappingHighWater;
}

/** Where a cache's scope bindings are kept. */
export interface ScopeBindingLedger {
  /**
   * Under the ledger's write lock: read the state, let `decide` judge it,
   * and record what `decide` returns before releasing the lock. Throws when
   * the ledger cannot be read, locked or written, and then records nothing.
   */
  commit<T>(decide: (state: ScopeBindingState) => { result: T; record?: ScopeBindingRecord }): T;
  /** For the startup summary. */
  describe(): string;
  close(): void;
}

/** The ledger key of an issuer's scope value. */
export const bindingKey = (b: Pick<ScopeBinding, "issuer" | "scope">): string => JSON.stringify([b.issuer, b.scope]);

/** Whether two bindings name the same contract, or both none. */
export const sameBinding = (a: ScopeBinding, b: ScopeBinding): boolean =>
  a.resource_contract === null || b.resource_contract === null
    ? a.resource_contract === b.resource_contract
    : sameResourceContract(a.resource_contract, b.resource_contract);

/** A ledger in memory: a restart loses it. For tests and development launches only. */
export class MemoryScopeBindingLedger implements ScopeBindingLedger {
  private bindings = new Map<string, ScopeBinding>();
  private highWater: MappingHighWater | null = null;

  commit<T>(decide: (state: ScopeBindingState) => { result: T; record?: ScopeBindingRecord }): T {
    const { result, record } = decide({
      bindings: [...this.bindings.values()].map((b) => ({ ...b })),
      highWater: this.highWater ? { ...this.highWater } : null,
    });
    if (record) {
      const next = new Map(this.bindings);
      for (const b of record.bindings) {
        if (next.has(bindingKey(b))) throw new Error(`scope ${b.issuer} ${b.scope} is already recorded`);
        next.set(bindingKey(b), { ...b });
      }
      if (record.highWater) assertRaises(this.highWater, record.highWater);
      this.bindings = next;
      if (record.highWater) this.highWater = { ...record.highWater };
    }
    return result;
  }

  describe(): string {
    return "in memory (development), lost at restart";
  }

  close(): void {}
}

function assertRaises(was: MappingHighWater | null, next: MappingHighWater): void {
  if (was && (next.version < was.version || (next.version === was.version && next.digest !== was.digest))) {
    throw new Error(`the mapping high-water mark never falls or changes in place (version ${was.version} to ${next.version})`);
  }
}

const OWNER = "mas-pilot-scope-bindings";
const SCHEMA_VERSION = 1;
const SCHEMA = `
CREATE TABLE scope_binding (
  issuer TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  contract_id TEXT,
  contract_version TEXT,
  contract_digest TEXT,
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (issuer, scope),
  CHECK ((contract_id IS NULL) = (contract_version IS NULL) AND (contract_id IS NULL) = (contract_digest IS NULL))
) STRICT;
CREATE TRIGGER scope_binding_never_changed BEFORE UPDATE ON scope_binding
  BEGIN SELECT RAISE(ABORT, 'a scope binding is never changed'); END;
CREATE TRIGGER scope_binding_never_removed BEFORE DELETE ON scope_binding
  BEGIN SELECT RAISE(ABORT, 'a scope binding is never removed'); END;
CREATE TABLE mapping_high_water (
  k INTEGER PRIMARY KEY CHECK (k = 1),
  version INTEGER NOT NULL CHECK (version >= 1),
  digest TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER mapping_high_water_never_falls BEFORE UPDATE ON mapping_high_water
  WHEN NEW.version < OLD.version OR (NEW.version = OLD.version AND NEW.digest <> OLD.digest)
  BEGIN SELECT RAISE(ABORT, 'the mapping high-water mark never falls or changes in place'); END;
CREATE TRIGGER mapping_high_water_never_removed BEFORE DELETE ON mapping_high_water
  BEGIN SELECT RAISE(ABORT, 'the mapping high-water mark is never removed'); END;
`;

/** How long an install waits for another process's write lock, by default. */
export const DEFAULT_LEDGER_LOCK_TIMEOUT_MS = 10_000;

/**
 * Create an empty scope binding ledger at `file`, once. A file that already
 * exists refuses: initializing never replaces history (D1019).
 */
export function initScopeBindingLedger(file: string): void {
  if (!isAbsolute(file)) throw new Error(`the scope binding ledger must be an absolute path, not ${file}`);
  initSharedStore({ file, owner: OWNER, schema: SCHEMA, schemaVersion: SCHEMA_VERSION });
}

/**
 * The ledger in a SQLite file several processes share. A missing, malformed
 * or foreign file refuses at open (D1019). Each commit is one IMMEDIATE
 * transaction: it takes the write lock, waiting up to the lock timeout, reads
 * the state under it, and commits the bindings and the high-water mark
 * together, synchronously flushed.
 */
export class SqliteScopeBindingLedger implements ScopeBindingLedger {
  private constructor(
    private readonly file: string,
    private readonly db: ReturnType<typeof openSharedStore>,
  ) {}

  static open(file: string, opts: { lockTimeoutMs?: number } = {}): SqliteScopeBindingLedger {
    if (!isAbsolute(file)) throw new Error(`the scope binding ledger must be an absolute path, not ${file}`);
    const db = openSharedStore({
      file,
      owner: OWNER,
      schemaVersion: SCHEMA_VERSION,
      lockTimeoutMs: opts.lockTimeoutMs ?? DEFAULT_LEDGER_LOCK_TIMEOUT_MS,
    });
    return new SqliteScopeBindingLedger(file, db);
  }

  commit<T>(decide: (state: ScopeBindingState) => { result: T; record?: ScopeBindingRecord }): T {
    return this.db
      .transaction(() => {
        const { result, record } = decide(this.read());
        if (record) this.write(record);
        return result;
      })
      .immediate();
  }

  private read(): ScopeBindingState {
    type Row = {
      issuer: string;
      scope: string;
      resource: string;
      contract_id: string | null;
      contract_version: string | null;
      contract_digest: string | null;
    };
    const rows = this.db
      .prepare("SELECT issuer, scope, resource, contract_id, contract_version, contract_digest FROM scope_binding")
      .all() as Row[];
    const bindings = rows.map((r): ScopeBinding => {
      const ref = r.contract_id === null ? null : { id: r.contract_id, version: r.contract_version, digest: r.contract_digest };
      if (ref !== null && !isResourceContractRef(ref)) {
        throw new Error(`scope binding ledger ${this.file}: scope ${r.issuer} ${r.scope} has a malformed reference`);
      }
      return { issuer: r.issuer, scope: r.scope, resource: r.resource, resource_contract: ref };
    });
    const hw = this.db.prepare("SELECT version, digest FROM mapping_high_water WHERE k = 1").get() as MappingHighWater | undefined;
    return { bindings, highWater: hw ? { version: hw.version, digest: hw.digest } : null };
  }

  private write(record: ScopeBindingRecord): void {
    const at = new Date().toISOString();
    const insert = this.db.prepare(
      "INSERT INTO scope_binding (issuer, scope, resource, contract_id, contract_version, contract_digest, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    for (const b of record.bindings) {
      const ref = b.resource_contract;
      insert.run(b.issuer, b.scope, b.resource, ref?.id ?? null, ref?.version ?? null, ref?.digest ?? null, at);
    }
    if (record.highWater) {
      this.db
        .prepare(
          "INSERT INTO mapping_high_water (k, version, digest, recorded_at) VALUES (1, ?, ?, ?) ON CONFLICT(k) DO UPDATE SET version = excluded.version, digest = excluded.digest, recorded_at = excluded.recorded_at",
        )
        .run(record.highWater.version, record.highWater.digest, at);
    }
  }

  describe(): string {
    return `file ${this.file}`;
  }

  close(): void {
    this.db.close();
  }
}

/**
 * The ledger a launch names: `MAS_PILOT_SCOPE_BINDINGS`, an initialized
 * file, opened here so a missing or malformed one refuses before anything
 * starts; or, with `MAS_PILOT_DEVELOPMENT_STORE=1` alone, one in memory.
 * Neither refuses. `env` is what a child process needs to open the same one.
 */
export function scopeBindingsFromEnv(env: Readonly<Record<string, string | undefined>>): {
  ledger: ScopeBindingLedger;
  env: Record<string, string>;
} {
  const path = env.MAS_PILOT_SCOPE_BINDINGS;
  if (path !== undefined && path !== "") {
    let ledger: ScopeBindingLedger;
    try {
      ledger = SqliteScopeBindingLedger.open(path);
    } catch (e) {
      throw new Error(
        `MAS_PILOT_SCOPE_BINDINGS: ${(e as Error).message}; a new deployment initializes it once with \`pnpm scope-bindings init --file ${path}\`, and recovery restores its complete history, never a new empty ledger`,
      );
    }
    return { ledger, env: { MAS_PILOT_SCOPE_BINDINGS: path } };
  }
  if (env.MAS_PILOT_DEVELOPMENT_STORE === "1") {
    return { ledger: new MemoryScopeBindingLedger(), env: { MAS_PILOT_DEVELOPMENT_STORE: "1" } };
  }
  throw new Error(
    "no scope binding ledger: set MAS_PILOT_SCOPE_BINDINGS to an initialized ledger file, or MAS_PILOT_DEVELOPMENT_STORE=1 for one in memory that a restart loses",
  );
}

/** `pnpm scope-bindings init --file <absolute path>`: create an empty ledger, once. */
export function scopeBindingsAdmin(args: readonly string[]): string {
  const [command, flag, file] = args;
  if (command !== "init" || flag !== "--file" || file === undefined || args.length !== 3) {
    throw new Error("usage: scope-bindings init --file <absolute path>");
  }
  initScopeBindingLedger(file);
  return `scope-bindings: initialized an empty ledger at ${file}`;
}
