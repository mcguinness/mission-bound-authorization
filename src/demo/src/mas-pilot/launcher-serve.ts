/**
 * `pnpm mas-pilot` and `pnpm mas-pilot:separated` (#818 slice 5B): start the
 * MAS pilot in one topology, as `launchMasPilot` (`launcher.ts`) assembles it,
 * and print the addresses and the operator console's bearer.
 * src/docs/mas-pilot-walkthrough.md walks through it.
 *
 * A startup failure releases what had started, prints one
 * `mas-pilot: startup failed:` line and exits 1.
 *
 * SIGINT, SIGTERM and SIGHUP are handled from the first line, so a stop at
 * any point stops the launch's MAS process and closes every listener. During
 * startup it cancels the launch: the cleanup stack runs at once, whatever
 * startup is waiting on, and the process exits with the signal's status
 * (128 + its number). After startup it closes everything and exits 0.
 */
import { constants } from "node:os";
import { launchMasPilot, type MasPilotLaunch, masPilotLaunchOptions, type MasPilotTopology } from "./launcher.js";
import { StartupScope } from "./startup.js";

const reason = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const startup = new StartupScope();
let launched: MasPilotLaunch | undefined;
let stopping = false;

function installSignalHandlers(): void {
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.on(sig, () => {
      if (stopping) return;
      stopping = true;
      const duringStartup = launched === undefined;
      if (duringStartup) console.error(`mas-pilot: ${sig} during startup: stopping what has started`);
      startup.cancel().then(
        () => process.exit(duringStartup ? 128 + constants.signals[sig] : 0),
        (err: unknown) => {
          console.error(`mas-pilot: shutdown failed: ${reason(err)}`);
          process.exit(1);
        },
      );
    });
  }
}
installSignalHandlers();

async function main(): Promise<void> {
  const topology = process.argv[2];
  if (topology !== "in-process" && topology !== "separated") {
    console.error(`mas-pilot: startup failed: the topology must be in-process or separated, not ${String(topology)}`);
    process.exit(1);
  }
  let launch: MasPilotLaunch;
  try {
    launch = await launchMasPilot(masPilotLaunchOptions(process.env, topology as MasPilotTopology), {
      startup,
      onProgress: (message) => console.log(`mas-pilot: ${message}`),
    });
  } catch (err) {
    // A signal's handler owns the exit; launchMasPilot released what it had.
    if (stopping) return;
    console.error(`mas-pilot: startup failed: ${reason(err)}`);
    process.exit(1);
  }
  if (stopping) return;
  launched = launch;
  for (const line of launch.summary) console.log(line);
}

await main();
