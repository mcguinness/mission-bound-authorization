/**
 * `pnpm scope-bindings`: the process around `scopeBindingsAdmin`
 * (`scope-binding-ledger.ts`), which the tests drive directly. It prints the
 * result, or one `scope-bindings:` line and exits 1 when it refuses.
 */
import { scopeBindingsAdmin } from "./scope-binding-ledger.js";

try {
  console.log(scopeBindingsAdmin(process.argv.slice(2)));
} catch (err) {
  console.error(`scope-bindings: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
