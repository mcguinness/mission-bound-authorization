/**
 * `pnpm as-native`: boot #253's first runtime target, the AS-native payments
 * composition (D284), as `composeStack({ target: "as-native" })` assembles it:
 * the floor's AS, the `mcp-payments` PEP served over HTTP MCP at the declared
 * resource audience with DPoP verified on every request (D315), the reference
 * PDP, OpenFGA and the in-process approval service. No MAS join route is
 * mounted. src/docs/initial-runtime-deployment.md § Run it publishes the
 * command.
 */
import { TOPOLOGY } from "@mission/demo-data";
import { composeStack } from "./stack.js";

const stack = await composeStack({
  openfgaUrl: process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url,
  presharedKey: process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
  ...(process.env.OPENFGA_CA_CERT ? { caCertPath: process.env.OPENFGA_CA_CERT } : {}),
  target: "as-native",
});
const { authServer, resourceChannel } = stack;
if (!authServer || !resourceChannel) throw new Error("the as-native target assembles the AS and the resource endpoint");
console.log("as-native payments target (D284, D315)");
console.log(`  issuer             ${stack.issuer}  (JWKS ${authServer.asUrl}/jwks)`);
console.log(`  resource audience  ${resourceChannel.url}  (HTTP MCP, DPoP verified on every request)`);
console.log(`  PDP mode           ${stack.pdpMode}`);
console.log(`  MAS join route     ${stack.masGovernedChannel ? "mounted" : "not mounted"}`);
console.log("  ready. Ctrl-C to stop.");

// Close once, on the first of SIGINT, SIGTERM or SIGHUP. A terminal Ctrl-C
// reaches this process twice (from the terminal and forwarded by the
// wrapper), so a repeat is ignored while the close runs.
let closing = false;
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(sig, () => {
    if (closing) return;
    closing = true;
    void (async () => {
      await resourceChannel.close();
      authServer.closeAuthServer();
      await stack.decisionChannel.close();
      stack.pdpClaims.close();
      stack.writeReservations.close();
    })().finally(() => process.exit(0));
  });
}
