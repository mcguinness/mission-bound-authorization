// pnpm issuance-only [--introspection]: the reference AS plus plain-rs in an
// issuance-only configuration (src/docs/issuance-only-deployment.md § Run it).
// The wrapper forwards SIGINT, SIGTERM and SIGHUP to the server process, which
// closes both servers, and exits when it does.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/issuance-only-serve.ts", process.argv.slice(2));
