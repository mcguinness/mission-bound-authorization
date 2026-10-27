/**
 * @spec cross-domain#validation-at-resource-as (one-time use), #1767 (D887):
 * `pnpm ras-redemptions`, which creates the RAS's durable redemption store
 * once. The process around it is `ras-redemptions-cli.ts`; the tests drive
 * this function directly.
 *
 *   pnpm ras-redemptions init --file <path>
 *
 * `init` refuses an existing file, and the RAS refuses to open a file `init`
 * did not create, so a lost store is never replaced by an empty one without
 * an operator deleting it. A relative path resolves against the directory
 * `pnpm` was started in (`INIT_CWD`); the result names the absolute path.
 */
import { mkdirSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { initRasRedemptionStore } from "@mission/ras";

const USAGE = "usage: pnpm ras-redemptions init --file <path>";

/** Run `argv`; returns the lines to print, or throws. */
export function rasRedemptionsAdmin(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  cwd: string = process.cwd(),
): string {
  const [action, flag, value, ...rest] = argv;
  if (action !== "init" || flag !== "--file" || !value || value.startsWith("--") || rest.length > 0) {
    throw new Error(USAGE);
  }
  const file = isAbsolute(value) ? value : resolve(env.INIT_CWD ?? cwd, value);
  mkdirSync(dirname(file), { recursive: true });
  initRasRedemptionStore(file);
  return [
    `init: created the redemption store ${file}`,
    "give it to the RAS as its redemption store (`redemptions.file`); once configured, the RAS refuses to start without it",
  ].join("\n");
}
