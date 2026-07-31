// Launcher: set the dev CA, then boot the live demo console server. Unlike the
// eval scorecard (CI, plain HTTP, no cert), the live server talks to OpenFGA
// over TLS and cannot start without the dev CA -- so guard on its existence and
// fail with a clear message instead of a cryptic "self-signed certificate".
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";

const ca = `${process.cwd()}/certs/openfga.crt`;
if (!existsSync(ca)) {
  console.error(
    "dev CA not found at certs/openfga.crt — run `pnpm setup` first, then " +
      "`docker compose -f docker-compose.yml up -d`",
  );
  process.exit(1);
}
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
execSync("pnpm -C demo exec tsx src/server.ts", { stdio: "inherit", env: process.env });
