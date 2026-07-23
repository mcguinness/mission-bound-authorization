// Launcher: set the dev CA, then boot the live demo console server.
import { execSync } from "node:child_process";

const ca = `${process.cwd()}/certs/openfga.crt`;
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
execSync("pnpm -C demo exec tsx src/server.ts", { stdio: "inherit", env: process.env });
