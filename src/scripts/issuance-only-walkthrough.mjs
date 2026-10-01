// pnpm issuance-only:walkthrough: drive the reports.read path against a
// running `pnpm issuance-only` (src/docs/issuance-only-deployment.md § Run it).
// Signals are forwarded and the walkthrough's exit status is the wrapper's.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/issuance-only-walkthrough.ts", process.argv.slice(2));
