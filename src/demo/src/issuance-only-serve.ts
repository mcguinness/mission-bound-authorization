/**
 * `pnpm issuance-only [--introspection]`: boot the reference AS and plain-rs
 * in one of the two issuance-only configurations and write the dev
 * credentials the walkthrough reads (see issuance-only.ts).
 */
import { writeFileSync } from "node:fs";
import { CREDENTIALS_PATH, startIssuanceOnly } from "./issuance-only.js";

const introspection = process.argv.includes("--introspection");
const deployment = await startIssuanceOnly({
  introspection,
  ...(process.env.AS_PORT ? { asPort: Number(process.env.AS_PORT) } : {}),
  ...(process.env.PLAIN_RS_PORT ? { rsPort: Number(process.env.PLAIN_RS_PORT) } : {}),
});
const { credentials } = deployment;
writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2), { mode: 0o600 });
console.log(`issuance-only (${credentials.configuration})`);
console.log(`  AS        ${credentials.asUrl}  (issuer; JWKS ${credentials.asUrl}/jwks)`);
console.log(`  plain-rs  ${credentials.rsUrl}  (audience ${credentials.audience})`);
console.log(`  introspection: ${introspection ? `${credentials.asUrl}/introspect as rs-plain` : "off (JWT only)"}`);
console.log(`  dev credentials: ${CREDENTIALS_PATH}`);
console.log("  ready; run `pnpm issuance-only:walkthrough` in another shell. Ctrl-C to stop.");
// Close both servers once, on the first of SIGINT, SIGTERM or SIGHUP. A
// terminal Ctrl-C reaches this process twice (from the terminal and forwarded
// by the wrapper), so a repeat is ignored while the close runs.
let closing = false;
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(sig, () => {
    if (closing) return;
    closing = true;
    void deployment.close().finally(() => process.exit(0));
  });
}
