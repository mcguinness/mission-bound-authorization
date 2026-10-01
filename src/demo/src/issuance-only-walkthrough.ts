/**
 * `pnpm issuance-only:walkthrough`: drive the `reports.read` path against a
 * running `pnpm issuance-only` deployment, printing each request and result.
 */
import { readFileSync } from "node:fs";
import {
  CREDENTIALS_PATH,
  formatStep,
  type IssuanceOnlyCredentials,
  runWalkthrough,
} from "./issuance-only.js";

const credentials = JSON.parse(readFileSync(CREDENTIALS_PATH, "utf8")) as IssuanceOnlyCredentials;
console.log(`walkthrough against ${credentials.configuration} (${credentials.asUrl}, ${credentials.rsUrl})\n`);
await runWalkthrough(credentials, (s) => console.log(`${formatStep(s)}\n`));
