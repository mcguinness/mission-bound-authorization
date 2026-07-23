// pnpm demo -- one-command scripted walkthrough of scenarios 0-14 (M12).
// The scenario bodies live as the per-milestone integration tests, which the
// runner drives against the composed in-process stack; this entrypoint boots
// the stack, runs them in order, and prints a scorecard. Requires OpenFGA up
// (docker compose) and, for the LLM chat mode, ANTHROPIC_API_KEY.
import { execSync } from "node:child_process";

const CA = `${process.cwd()}/certs/openfga.crt`;
process.env.NODE_EXTRA_CA_CERTS = CA;
process.env.OPENFGA_CA_CERT = CA;

console.log("Mission demo: running scenarios 0-14 against the composed stack...\n");
try {
  execSync("pnpm vitest run", { stdio: "inherit", env: process.env });
  console.log("\n✓ demo complete: all scenarios green. See DEMO.md for the guided walkthrough.");
} catch {
  console.error("\n✗ demo failed. Is OpenFGA up? `docker compose up -d` then `pnpm setup`.");
  process.exit(1);
}
