// pnpm mas-pilot (in process) and pnpm mas-pilot:separated: the MAS pilot
// (#818), assembled by launchMasPilot (src/docs/mas-pilot-walkthrough.md).
// The docker compose OpenFGA serves TLS under the dev CA that `pnpm setup`
// creates; when it exists and no OPENFGA_CA_CERT is set, the launcher trusts
// it. The wrapper forwards SIGINT, SIGTERM and SIGHUP to the launcher process,
// which closes every listener and stops the MAS process it started.
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runDemoTs } from "./run-demo-ts.mjs";

const topology = process.argv[2];
const ca = fileURLToPath(new URL("../certs/openfga.crt", import.meta.url));
if (!process.env.OPENFGA_CA_CERT && existsSync(ca)) {
  process.env.NODE_EXTRA_CA_CERTS = ca;
  process.env.OPENFGA_CA_CERT = ca;
}
runDemoTs("src/mas-pilot/launcher-serve.ts", [topology ?? ""]);
