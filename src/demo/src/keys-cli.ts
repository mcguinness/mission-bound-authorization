/**
 * `pnpm keys`: the process around `keysAdmin` (`keys-admin.ts`), which the
 * tests drive directly. It prints what it created, or one `keys:` line and
 * exits 1 when it refuses.
 */
import { keysAdmin } from "./keys-admin.js";

try {
  console.log(await keysAdmin(process.argv.slice(2), process.env));
} catch (err) {
  console.error(`keys: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
