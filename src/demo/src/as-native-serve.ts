/**
 * `pnpm as-native`: boot #253's first runtime target, the AS-native payments
 * composition (D284), as `launchAsNative` (`as-native.ts`) assembles it: the
 * AS with the issuance profile plus exactly `lifecycle-revoke` and
 * `transaction-authorization` and no dev ordinary-token route (D332), the
 * `mcp-payments` PEP served over HTTP MCP at the declared resource audience
 * with DPoP verified on every request (D315), the reference PDP, OpenFGA and
 * the in-process approval service. No MAS join route is mounted.
 * src/docs/initial-runtime-deployment.md § Run it publishes the command.
 *
 * A startup failure prints one `as-native: startup failed:` line and exits 1.
 * SIGINT, SIGTERM or SIGHUP closes every listener and exits 0.
 */
import { type AsNativeLaunch, asNativeLaunchOptions, launchAsNative } from "./as-native.js";

const reason = (err: unknown): string => (err instanceof Error ? err.message : String(err));

let launched: AsNativeLaunch;
try {
  launched = await launchAsNative(asNativeLaunchOptions(process.env));
} catch (err) {
  console.error(`as-native: startup failed: ${reason(err)}`);
  process.exit(1);
}
for (const line of launched.summary) console.log(line);

// Close once, on the first of SIGINT, SIGTERM or SIGHUP. A terminal Ctrl-C
// reaches this process twice (from the terminal and forwarded by the
// wrapper), so a repeat is ignored while the close runs.
let closing = false;
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(sig, () => {
    if (closing) return;
    closing = true;
    launched.close().then(
      () => process.exit(0),
      (err: unknown) => {
        console.error(`as-native: shutdown failed: ${reason(err)}`);
        process.exit(1);
      },
    );
  });
}
