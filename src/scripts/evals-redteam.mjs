// Launcher for the OPT-IN LLM red-team mode (O-31). Mirrors scripts/evals.mjs:
// set the dev CA from cwd only if present (in CI OpenFGA runs over plain HTTP
// with no cert), then run the red-team scorecard. This is NEVER the D24 gate --
// `pnpm evals` stays the gate. argv is passed through (e.g. --live, --fixture).
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";

const ca = `${process.cwd()}/certs/openfga.crt`;
if (existsSync(ca)) {
  process.env.NODE_EXTRA_CA_CERTS = ca;
  process.env.OPENFGA_CA_CERT = ca;
}

const passthrough = process.argv.slice(2);
const args = passthrough.length > 0 ? ` ${passthrough.join(" ")}` : "";
execSync(`pnpm -C evals exec tsx src/redteam-run.ts${args}`, {
  stdio: "inherit",
  env: process.env,
});
