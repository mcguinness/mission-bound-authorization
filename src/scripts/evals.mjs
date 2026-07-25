// Launcher: set the dev CA from cwd (only if present), then run the eval
// scorecard (reliable vs an inline $PWD in a pnpm script, which does not expand
// consistently). In CI OpenFGA runs over plain HTTP with no cert, so the CA is
// guarded by existence; setting it to a missing path only yields a noisy
// "Ignoring extra certs" warning.
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";

const ca = `${process.cwd()}/certs/openfga.crt`;
if (existsSync(ca)) {
  process.env.NODE_EXTRA_CA_CERTS = ca;
  process.env.OPENFGA_CA_CERT = ca;
}
execSync("pnpm -C evals exec tsx src/run.ts", { stdio: "inherit", env: process.env });
