/**
 * `pnpm evidence-keys`: the process around `evidenceKeysAdmin`
 * (`evidence-key-files.ts`), which the tests drive directly. It prints what it
 * created, or one `evidence-keys:` line and exits 1 when it refuses.
 */
import { evidenceKeysAdmin } from "./evidence-key-files.js";

try {
  console.log(evidenceKeysAdmin(process.argv.slice(2)));
} catch (err) {
  console.error(`evidence-keys: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
