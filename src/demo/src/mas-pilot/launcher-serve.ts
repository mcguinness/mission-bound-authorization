/**
 * `pnpm mas-pilot` and `pnpm mas-pilot:separated` (#818 slice 5B): start the
 * MAS pilot in one topology, as `launchMasPilot` (`launcher.ts`) assembles it,
 * and print the addresses and the operator console's bearer.
 * src/docs/mas-pilot-walkthrough.md walks through it.
 *
 * A startup failure prints one `mas-pilot: startup failed:` line and exits 1.
 * SIGINT, SIGTERM or SIGHUP closes every listener, stops the MAS process this
 * launcher started, and exits 0.
 */
import { launchMasPilot, type MasPilotLaunch, masPilotLaunchOptions, type MasPilotTopology } from "./launcher.js";

const reason = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const topology = process.argv[2];
if (topology !== "in-process" && topology !== "separated") {
  console.error(`mas-pilot: startup failed: the topology must be in-process or separated, not ${String(topology)}`);
  process.exit(1);
}

let launched: MasPilotLaunch;
try {
  launched = await launchMasPilot(masPilotLaunchOptions(process.env, topology as MasPilotTopology));
} catch (err) {
  console.error(`mas-pilot: startup failed: ${reason(err)}`);
  process.exit(1);
}
for (const line of launched.summary) console.log(line);

let closing = false;
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.on(sig, () => {
    if (closing) return;
    closing = true;
    launched.close().then(
      () => process.exit(0),
      (err: unknown) => {
        console.error(`mas-pilot: shutdown failed: ${reason(err)}`);
        process.exit(1);
      },
    );
  });
}
