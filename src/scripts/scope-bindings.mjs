// pnpm scope-bindings init --file <absolute path>: create the MAS pilot's
// scope binding ledger once, before its first start (#1847, D1019). Give the
// path to the launcher as MAS_PILOT_SCOPE_BINDINGS.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/mas-pilot/scope-bindings-cli.ts", process.argv.slice(2));
