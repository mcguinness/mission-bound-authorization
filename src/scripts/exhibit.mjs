// Launcher: set the dev CA from cwd, then run the terminal exhibit.
import { execSync } from "node:child_process";
const ca = `${process.cwd()}/certs/openfga.crt`;
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
execSync("pnpm -C demo exec tsx src/exhibit.ts", { stdio: "inherit", env: process.env });
