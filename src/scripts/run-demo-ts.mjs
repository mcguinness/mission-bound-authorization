// Run a TypeScript entry point of the demo package as ONE child process
// (`node --import tsx`, cwd `demo/`), and stay its supervisor: SIGINT, SIGTERM
// and SIGHUP are forwarded to it, the wrapper waits for it to exit, and then
// exits with its status (or 128 + the signal number if a signal ended it).
// There is no intermediate pnpm or tsx CLI process, so a signal sent to the
// wrapper alone reaches the process that owns the listening sockets.
import { spawn } from "node:child_process";
import { constants } from "node:os";
import { fileURLToPath } from "node:url";

const DEMO_DIR = fileURLToPath(new URL("../demo/", import.meta.url));
const FORWARDED = ["SIGINT", "SIGTERM", "SIGHUP"];

export function runDemoTs(entry, args = []) {
  const child = spawn(process.execPath, ["--import", "tsx", entry, ...args], {
    cwd: DEMO_DIR,
    stdio: "inherit",
    env: process.env,
  });
  for (const sig of FORWARDED) {
    process.on(sig, () => {
      if (child.exitCode === null && child.signalCode === null) child.kill(sig);
    });
  }
  child.on("error", (e) => {
    console.error(`could not start ${entry}: ${e.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    process.exit(signal ? 128 + (constants.signals[signal] ?? 0) : (code ?? 0));
  });
}
