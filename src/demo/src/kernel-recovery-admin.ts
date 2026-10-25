/**
 * @spec control-plane#rollback (#250 step 3): `pnpm kernel-recovery`, the
 * offline reconciliation of a file-backed kernel store with its recovery
 * witness. The process around it is `kernel-recovery-cli.ts`; the tests drive
 * this function directly.
 *
 *   pnpm kernel-recovery <init|acknowledge|abandon|accept> --store <path> --witness <path>
 *
 * - `init` creates the witness for a store that has none (a new store, or one
 *   that predates the witness), before the AS first starts with it.
 * - `acknowledge` and `abandon` resolve a commit that was in flight when the AS
 *   stopped: `acknowledge` when the store holds it, `abandon` when it does not.
 *   Each refuses when the store says otherwise.
 * - `accept` takes the store as it is, under a new generation, after a run
 *   recorded an uncertainty (an escaped write, a witness that moved) with no
 *   commit in flight. It refuses an older store than the witness.
 *
 * The store is opened exclusively and the witness's lock taken, so each
 * refuses while an AS holds either. The witness must be outside the store's
 * directory tree, and the store outside the witness's. An
 * older store than the witness is never accepted: restore the witnessed one.
 * Relative paths resolve against the directory `pnpm` was started in
 * (`INIT_CWD`); the result names the absolute paths to give the AS as
 * `MISSION_KERNEL_STORE` and `MISSION_KERNEL_WITNESS`.
 */
import { mkdirSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { reconcileKernelRecovery, type RecoveryReconciliation, witnessSharesStoreTree } from "@mission/authorization-server";

const USAGE = "usage: pnpm kernel-recovery <init|acknowledge|abandon|accept> --store <path> --witness <path>";
const ACTIONS: readonly RecoveryReconciliation[] = ["init", "acknowledge", "abandon", "accept"];

/** Run `argv`; returns the lines to print, or throws. */
export function kernelRecoveryAdmin(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  cwd: string = process.cwd(),
): string {
  const [action, ...rest] = argv;
  if (!ACTIONS.includes(action as RecoveryReconciliation)) throw new Error(USAGE);
  const flags = new Map<string, string>();
  for (let i = 0; i < rest.length; i += 2) {
    const name = rest[i];
    const value = rest[i + 1];
    if ((name !== "--store" && name !== "--witness") || value === undefined || value.startsWith("--")) {
      throw new Error(USAGE);
    }
    flags.set(name, value);
  }
  const storeArg = flags.get("--store");
  const witnessArg = flags.get("--witness");
  if (!storeArg || !witnessArg) throw new Error(USAGE);
  const base = env.INIT_CWD ?? cwd;
  const store = isAbsolute(storeArg) ? storeArg : resolve(base, storeArg);
  const witness = isAbsolute(witnessArg) ? witnessArg : resolve(base, witnessArg);
  if (witnessSharesStoreTree(store, witness)) {
    throw new Error(
      "the witness must be outside the store's directory, and the store outside the witness's, so restoring one cannot restore the other with it",
    );
  }
  if (action === "init") {
    mkdirSync(dirname(store), { recursive: true });
    mkdirSync(dirname(witness), { recursive: true });
  }
  const record = reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: action as RecoveryReconciliation });
  return [
    `${action}: ${store} and ${witness} agree at sequence ${record.committed} (store ${record.store_id}, generation ${record.generation})`,
    `start the AS with MISSION_KERNEL_STORE=${store} MISSION_KERNEL_WITNESS=${witness}`,
  ].join("\n");
}
