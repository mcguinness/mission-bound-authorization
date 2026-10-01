// pnpm issuance-only [--introspection]: the issuance-only reference
// deployment (src/docs/issuance-only-deployment.md § Run it). No OpenFGA,
// PDP or PEP is needed.
import { execFileSync } from "node:child_process";

execFileSync(
  "pnpm",
  ["-C", "demo", "exec", "tsx", "src/issuance-only-serve.ts", ...process.argv.slice(2)],
  {
    stdio: "inherit",
    env: process.env,
  },
);
