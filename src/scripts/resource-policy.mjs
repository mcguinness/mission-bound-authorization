// pnpm resource-policy: administer the independently administered Resource
// policy (#828) in the store a running resource attaches to
// (OPENFGA_STORE_ID, OPENFGA_MODEL_ID). OpenFGA runs over TLS, so this needs
// `pnpm setup` (the dev CA) first, as `pnpm as-native` does.
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
process.env.OPENFGA_CA_CERT ??= ca;
runDemoTs("src/resource-policy-cli.ts", process.argv.slice(2));
