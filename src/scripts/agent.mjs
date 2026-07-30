// Launcher for the OPT-IN live agent loop (increment 2). Mirrors
// scripts/evals-redteam.mjs: set the dev CA from cwd only if present (in CI
// OpenFGA runs over plain HTTP with no cert), then run the demo agent runner.
// This is NEVER a CI gate -- it requires ANTHROPIC_API_KEY and exits 0 with a
// hint when the key is absent. argv is passed through.
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";

const ca = `${process.cwd()}/certs/openfga.crt`;
if (existsSync(ca)) {
  process.env.NODE_EXTRA_CA_CERTS = ca;
  process.env.OPENFGA_CA_CERT = ca;
}

const passthrough = process.argv.slice(2);
const args = passthrough.length > 0 ? ` ${passthrough.join(" ")}` : "";
execSync(`pnpm -C demo exec tsx src/agent-run.ts${args}`, {
  stdio: "inherit",
  env: process.env,
});
