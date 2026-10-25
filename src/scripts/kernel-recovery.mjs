// pnpm kernel-recovery <init|acknowledge|abandon> --store <path> --witness <path>:
// reconcile a file-backed kernel store with its recovery witness, offline
// (#250 step 3). Give the absolute paths to the AS as MISSION_KERNEL_STORE and
// MISSION_KERNEL_WITNESS.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/kernel-recovery-cli.ts", process.argv.slice(2));
