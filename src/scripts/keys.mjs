// pnpm keys init --ring <path> [--issuer <url>]: create the AS's signing key
// ring once (#831). Give its absolute path to the AS as MISSION_KEY_RING.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/keys-cli.ts", process.argv.slice(2));
