// pnpm issuance-only [--introspection]: the issuance-only reference
// deployment (src/docs/issuance-only-deployment.md § Run it). No OpenFGA,
// PDP or PEP is needed. Ctrl-C stops both servers; the wrapper waits for the
// child to close them and exits with its status.
import { execFileSync } from "node:child_process";

for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => {});
try {
  execFileSync(
    "pnpm",
    ["-C", "demo", "exec", "tsx", "src/issuance-only-serve.ts", ...process.argv.slice(2)],
    { stdio: "inherit", env: process.env },
  );
} catch (e) {
  process.exit(typeof e.status === "number" ? e.status : 0);
}
