// pnpm issuance-only:walkthrough: drive the reports.read path against a
// running `pnpm issuance-only` (src/docs/issuance-only-deployment.md § Run it).
import { execFileSync } from "node:child_process";

execFileSync("pnpm", ["-C", "demo", "exec", "tsx", "src/issuance-only-walkthrough.ts"], {
  stdio: "inherit",
  env: process.env,
});
