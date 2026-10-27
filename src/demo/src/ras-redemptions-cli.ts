/**
 * `pnpm ras-redemptions`: the process around `rasRedemptionsAdmin`
 * (`ras-redemptions-admin.ts`), which the tests drive directly. It prints the
 * result, or one `ras-redemptions:` line and exits 1 when it refuses.
 */
import { rasRedemptionsAdmin } from "./ras-redemptions-admin.js";

try {
  console.log(rasRedemptionsAdmin(process.argv.slice(2), process.env));
} catch (err) {
  console.error(`ras-redemptions: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
