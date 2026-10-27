// pnpm ras-redemptions init --file <path>: create the RAS's durable redemption
// store once (#1767). The RAS refuses a missing store, and one init did not
// create, rather than starting with an empty history. A lost store is
// restored, not replaced, while any grant it could have recorded is still
// acceptable (D901).
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/ras-redemptions-cli.ts", process.argv.slice(2));
