/**
 * @spec #831: `pnpm keys`, the explicit steps that create and change the
 * AS's signing key ring. The process around it is `keys-cli.ts`; the tests
 * drive this function directly.
 *
 *   pnpm keys init --ring <path> [--issuer <url>]
 *   pnpm keys migrate --ring <path> [--issuer <url>]
 *   pnpm keys rotate --ring <path> --role <role> [--activate] [--issuer <url>]
 *   pnpm keys retire --ring <path> --role <role> --kid <kid> [--issuer <url>]
 *   pnpm keys compromise --ring <path> --role <role> --kid <kid> [--compromised-at <time>] [--issuer <url>]
 *
 * The ring holds the four AS role keys (`TOPOLOGY.keys` `asToken`,
 * `asStatus`, `asTxn`, `asContinuation`), for one issuer (default the AS's
 * configured URL, `http://localhost:4400`). `init` creates it once; an
 * existing ring is never replaced. `migrate` converts a slice 1 ring to the
 * generation format, keeping its keys. `rotate` stages a role's next
 * generation, and `rotate --activate` makes it the signer once it has been
 * published for the `/jwks` freshness lifetime. `retire` removes a
 * generation from the AS's key set after the deployment's audit horizon
 * (`policy.audit_horizon_s`). `compromise` withdraws one at once, replacing
 * the signer when it was the active one. A relative `--ring` resolves
 * against the directory `pnpm` was started in (`INIT_CWD`).
 *
 * Every change takes effect when the AS next starts: the AS reads the ring
 * only at boot.
 */
import { isAbsolute, resolve } from "node:path";
import {
  activateSigningKeyGeneration,
  AS_SIGNING_ROLES,
  compromiseSigningKeyGeneration,
  initSigningKeyRing,
  JWKS_MAX_AGE_SECONDS,
  migrateSigningKeyRing,
  retireSigningKeyGeneration,
  SIGNING_KEY_RING_FORMAT,
  stageSigningKeyGeneration,
} from "@mission/authorization-server";
import { AUDIT_HORIZON_SECONDS, TOPOLOGY } from "@mission/demo-data";

const USAGE = [
  "usage: pnpm keys init --ring <path> [--issuer <url>]",
  "       pnpm keys migrate --ring <path> [--issuer <url>]",
  "       pnpm keys rotate --ring <path> --role <role> [--activate] [--issuer <url>]",
  "       pnpm keys retire --ring <path> --role <role> --kid <kid> [--issuer <url>]",
  "       pnpm keys compromise --ring <path> --role <role> --kid <kid> [--compromised-at <time>] [--issuer <url>]",
].join("\n");

/** Each command's value flags, required and optional, and its boolean flags. */
const COMMANDS: Record<string, { required: string[]; optional: string[]; switches: string[] }> = {
  init: { required: ["--ring"], optional: ["--issuer"], switches: [] },
  migrate: { required: ["--ring"], optional: ["--issuer"], switches: [] },
  rotate: { required: ["--ring", "--role"], optional: ["--issuer"], switches: ["--activate"] },
  retire: { required: ["--ring", "--role", "--kid"], optional: ["--issuer"], switches: [] },
  compromise: { required: ["--ring", "--role", "--kid"], optional: ["--issuer", "--compromised-at"], switches: [] },
};

/** Run `argv` (a command and its flags); returns the lines to print, or throws. */
export async function keysAdmin(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  cwd: string = process.cwd(),
): Promise<string> {
  const [command, ...rest] = argv;
  const spec = command === undefined ? undefined : COMMANDS[command];
  if (!spec) throw new Error(USAGE);
  const flags = new Map<string, string>();
  const switches = new Set<string>();
  for (let i = 0; i < rest.length; ) {
    const name = rest[i] as string;
    if (spec.switches.includes(name)) {
      switches.add(name);
      i += 1;
      continue;
    }
    const value = rest[i + 1];
    if (![...spec.required, ...spec.optional].includes(name) || value === undefined || value.startsWith("--")) {
      throw new Error(USAGE);
    }
    flags.set(name, value);
    i += 2;
  }
  if (spec.required.some((f) => !flags.has(f))) throw new Error(USAGE);
  const issuer = flags.get("--issuer") ?? `http://localhost:${TOPOLOGY.ports.as}`;
  try {
    const url = new URL(issuer);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error();
  } catch {
    throw new Error(`--issuer is not an http or https URL: ${issuer}`);
  }
  const ringArg = flags.get("--ring") as string;
  const ring = isAbsolute(ringArg) ? ringArg : resolve(env.INIT_CWD ?? cwd, ringArg);
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  const roles = { asToken, asStatus, asTxn, asContinuation };
  const kids = AS_SIGNING_ROLES.map((r) => roles[r].kid).join(", ");
  const role = flags.get("--role") as string;
  const kid = flags.get("--kid") as string;
  const restart = "restart the AS to load it; it reads the ring only at boot";

  switch (command) {
    case "init": {
      const published = await initSigningKeyRing(ring, issuer, roles);
      return [
        `initialized ${ring} for ${issuer}: ${published.length} keys (${kids})`,
        `start the AS with MISSION_KEY_RING=${ring}`,
      ].join("\n");
    }
    case "migrate": {
      const published = await migrateSigningKeyRing(ring, issuer, roles);
      return `converted ${ring} to ${SIGNING_KEY_RING_FORMAT}: the same ${published.length} keys (${kids}), each its role's active generation`;
    }
    case "rotate": {
      if (switches.has("--activate")) {
        const done = await activateSigningKeyGeneration(ring, issuer, roles, role, { minPublishedS: JWKS_MAX_AGE_SECONDS });
        return [
          `activated ${done.kid} for ${role}; ${done.previous} stops signing and stays published in overlap`,
          restart,
        ].join("\n");
      }
      const staged = await stageSigningKeyGeneration(ring, issuer, roles, role);
      return [
        `staged ${staged.kid} for ${role}: published, not signing`,
        `${restart}, now: the ${JWKS_MAX_AGE_SECONDS}s publication interval before \`pnpm keys rotate --ring ${ring} --role ${role} --activate\` counts from this staging`,
      ].join("\n");
    }
    case "retire": {
      await retireSigningKeyGeneration(ring, issuer, roles, role, kid, { minRetentionS: AUDIT_HORIZON_SECONDS });
      return [`retired ${kid} for ${role}: it leaves the AS's key set`, restart].join("\n");
    }
    case "compromise": {
      const raw = flags.get("--compromised-at");
      const compromisedAt = raw === undefined ? undefined : new Date(raw);
      if (compromisedAt && Number.isNaN(compromisedAt.getTime())) throw new Error(`--compromised-at is not a time: ${raw}`);
      const done = await compromiseSigningKeyGeneration(ring, issuer, roles, role, kid, compromisedAt ? { compromisedAt } : {});
      return [
        `withdrew ${kid} for ${role} as compromised${done.replacement ? `; ${done.replacement} replaces it as the signer` : ""}`,
        "restart the AS now: until it restarts it keeps the key set it loaded, and a consumer keeps a key set it fetched until it fetches again",
      ].join("\n");
    }
  }
  throw new Error(USAGE);
}
