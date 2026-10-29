/**
 * A process that installs one mapping document over the scope binding ledger
 * at `file` (#1866 review, D1019), for the two-process witness in
 * `mas-pilot-mapping.test.ts`. It writes `attempting` just before the install.
 * With `holding` and `release`, it pauses inside the ledger's commit, holding
 * the write lock, until `release` exists. It prints the install's result and
 * exits 0 when the install succeeds, 3 when it is refused, 1 on an error.
 *
 * Usage: scope-binding-install.helper.ts <ledger> <document.json> <attempting> [<holding> <release>]
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { MappingContractCache } from "../src/mas-pilot/mapping-contract.js";
import {
  type ScopeBindingLedger,
  type ScopeBindingRecord,
  type ScopeBindingState,
  SqliteScopeBindingLedger,
} from "../src/mas-pilot/scope-binding-ledger.js";

const [file, documentPath, attempting, holding, release] = process.argv.slice(2) as [string, string, string, string?, string?];

class HoldingLedger implements ScopeBindingLedger {
  constructor(private readonly inner: SqliteScopeBindingLedger) {}
  commit<T>(decide: (state: ScopeBindingState) => { result: T; record?: ScopeBindingRecord }): T {
    return this.inner.commit((state) => {
      writeFileSync(holding as string, "holding the write lock");
      const deadline = Date.now() + 20_000;
      while (!existsSync(release as string)) {
        if (Date.now() > deadline) throw new Error("no release");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
      return decide(state);
    });
  }
  describe(): string {
    return this.inner.describe();
  }
  close(): void {
    this.inner.close();
  }
}

const sqlite = SqliteScopeBindingLedger.open(file, { lockTimeoutMs: 30_000 });
const ledger: ScopeBindingLedger = holding && release ? new HoldingLedger(sqlite) : sqlite;
const cache = new MappingContractCache({ ledger, maxStaleSeconds: 300, now: () => new Date("2026-10-19T12:00:00Z") });
writeFileSync(attempting, "installing");
const result = cache.install(JSON.parse(readFileSync(documentPath, "utf8")));
ledger.close();
process.stdout.write(JSON.stringify(result));
process.exit(result.ok ? 0 : 3);
