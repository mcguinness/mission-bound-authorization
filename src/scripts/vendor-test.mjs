// Launcher for the vendor-test demonstration (see evals.mjs).
import { execSync } from "node:child_process";

const ca = `${process.cwd()}/certs/openfga.crt`;
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
execSync("pnpm -C evals exec tsx src/vendor-test-run.ts", { stdio: "inherit", env: process.env });
