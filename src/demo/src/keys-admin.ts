/**
 * @spec #831 slice 1: `pnpm keys init`, the one explicit step that creates
 * the AS's signing key ring. The process around it is `keys-cli.ts`; the
 * tests drive this function directly.
 *
 *   pnpm keys init --ring <path> [--issuer <url>]
 *
 * The ring holds the four AS role keys (`TOPOLOGY.keys` `asToken`,
 * `asStatus`, `asTxn`, `asContinuation`) under their configured `kid`, for
 * one issuer (default the AS's configured URL, `http://localhost:4400`). A
 * relative `--ring` resolves against the directory `pnpm` was started in
 * (`INIT_CWD`); the result names the absolute path to give the AS as
 * `MISSION_KEY_RING`. An existing ring is never replaced.
 */
import { isAbsolute, resolve } from "node:path";
import { AS_SIGNING_ROLES, initSigningKeyRing } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";

const USAGE = "usage: pnpm keys init --ring <path> [--issuer <url>]";

/** Run `argv` (`init --ring <path> [--issuer <url>]`); returns the line to print, or throws. */
export async function keysAdmin(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  cwd: string = process.cwd(),
): Promise<string> {
  const [command, ...rest] = argv;
  if (command !== "init") throw new Error(USAGE);
  const flags = new Map<string, string>();
  for (let i = 0; i < rest.length; i += 2) {
    const name = rest[i];
    const value = rest[i + 1];
    if ((name !== "--ring" && name !== "--issuer") || value === undefined || value.startsWith("--")) {
      throw new Error(USAGE);
    }
    flags.set(name, value);
  }
  const ringArg = flags.get("--ring");
  if (!ringArg) throw new Error(USAGE);
  const issuer = flags.get("--issuer") ?? `http://localhost:${TOPOLOGY.ports.as}`;
  try {
    const url = new URL(issuer);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error();
  } catch {
    throw new Error(`--issuer is not an http or https URL: ${issuer}`);
  }
  const ring = isAbsolute(ringArg) ? ringArg : resolve(env.INIT_CWD ?? cwd, ringArg);
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  const roles = { asToken, asStatus, asTxn, asContinuation };
  const published = await initSigningKeyRing(ring, issuer, roles);
  const kids = AS_SIGNING_ROLES.map((r) => roles[r].kid).join(", ");
  return [
    `initialized ${ring} for ${issuer}: ${published.length} keys (${kids})`,
    `start the AS with MISSION_KEY_RING=${ring}`,
  ].join("\n");
}
