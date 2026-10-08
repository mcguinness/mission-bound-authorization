// pnpm as-native: the AS-native payments target (D284, D315), assembled by
// composeStack({ target: "as-native" }) (src/docs/initial-runtime-deployment.md
// § Run it). OpenFGA runs over TLS, so this needs `pnpm setup` (the dev CA)
// and `docker compose up -d` first. The wrapper forwards SIGINT, SIGTERM and
// SIGHUP to the server process, which closes every listener, and exits when
// it does.
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runDemoTs } from "./run-demo-ts.mjs";

const ca = fileURLToPath(new URL("../certs/openfga.crt", import.meta.url));
if (!existsSync(ca)) {
  console.error(
    "dev CA not found at certs/openfga.crt: run `pnpm setup` first, then `docker compose up -d`",
  );
  process.exit(1);
}
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
runDemoTs("src/as-native-serve.ts");
