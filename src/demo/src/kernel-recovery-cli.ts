/**
 * `pnpm kernel-recovery`: the process around `kernelRecoveryAdmin`
 * (`kernel-recovery-admin.ts`), which the tests drive directly. It prints the
 * result, or one `kernel-recovery:` line and exits 1 when it refuses.
 */
import { kernelRecoveryAdmin } from "./kernel-recovery-admin.js";

try {
  console.log(kernelRecoveryAdmin(process.argv.slice(2), process.env));
} catch (err) {
  console.error(`kernel-recovery: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
