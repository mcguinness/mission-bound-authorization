/**
 * `pnpm resource-policy`: the process around `resourcePolicyAdmin`
 * (`resource-policy-admin.ts`), which the tests drive directly. It prints
 * one line for the change it made, or one `resource-policy:` line and exits
 * 1 when it refuses.
 */
import { TOPOLOGY } from "@mission/demo-data";
import { resourcePolicyAdmin } from "./resource-policy-admin.js";

try {
  console.log(await resourcePolicyAdmin(process.argv.slice(2), process.env, TOPOLOGY.openfga));
} catch (err) {
  console.error(`resource-policy: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
