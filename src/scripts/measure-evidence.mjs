// pnpm measure:evidence: per-action cost of the local accountability minimum
// (#821 Sketch step 6, feeds #288), printed as a Markdown table.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/measure-evidence.ts", process.argv.slice(2));
