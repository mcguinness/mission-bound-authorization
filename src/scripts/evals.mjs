// Launcher: set the dev CA from cwd, then run the eval scorecard (reliable
// vs an inline $PWD in a pnpm script, which does not expand consistently).
import { execSync } from "node:child_process";
const ca = `${process.cwd()}/certs/openfga.crt`;
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
execSync("pnpm -C evals exec tsx src/run.ts", { stdio: "inherit", env: process.env });
