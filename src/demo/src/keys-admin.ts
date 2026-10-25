/**
 * @spec #831: `pnpm keys`, the explicit steps that create and change the
 * AS's signing key ring. The process around it is `keys-cli.ts`; the tests
 * drive this function directly.
 *
 *   pnpm keys init --ring <path> [--issuer <url>]
 *   pnpm keys migrate --ring <path> [--issuer <url>]
 *   pnpm keys rotate --ring <path> --role <role> [--activate] [--issuer <url>]
 *   pnpm keys retire --ring <path> --role <role> --kid <kid> [--kernel-store <path> | --in-memory-kernel] [--issuer <url>]
 *   pnpm keys compromise --ring <path> --role <role> --kid <kid> [--compromised-at <time>] [--issuer <url>]
 *   pnpm keys verify --ring <path> [--issuer <url>]
 *
 * The ring holds the four AS role keys (`TOPOLOGY.keys` `asToken`,
 * `asStatus`, `asTxn`, `asContinuation`), for one issuer (default the AS's
 * configured URL, `http://localhost:4400`). `init` creates it once; an
 * existing ring is never replaced. `migrate` converts a slice 1 ring to the
 * generation format, keeping its keys. `rotate` stages a role's next
 * generation, and `rotate --activate` makes it the signer once the running
 * AS has been confirmed publishing it for the `/jwks` freshness lifetime.
 * `retire` removes a generation from the AS's key set after its retention
 * deadline (the deployment's audit horizon, `policy.audit_horizon_s`,
 * covering the longest Mission lifetime, `policy.max_mission_lifetime_s`);
 * retiring a Status generation reads the kernel store and refuses while a
 * standing governed-policy consent is attested under it. `compromise`
 * withdraws one at once, replacing the signer when it was the active one.
 * A relative `--ring` resolves against the directory `pnpm` was started in
 * (`INIT_CWD`).
 *
 * The AS reads the ring only at boot, so a successful edit is not a
 * completed change. Every change follows one procedure: stop the AS, edit
 * the ring, start the AS, then `pnpm keys verify`, which confirms from the
 * running AS's `/jwks` that it loaded this revision and records what that
 * confirms. One operator edits a ring at a time; nothing locks it.
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
  standingConsentsAttestedUnder,
  verifySigningKeyRing,
} from "@mission/authorization-server";
import { AUDIT_HORIZON_SECONDS, DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";

const USAGE = [
  "usage: pnpm keys init --ring <path> [--issuer <url>]",
  "       pnpm keys migrate --ring <path> [--issuer <url>]",
  "       pnpm keys rotate --ring <path> --role <role> [--activate] [--issuer <url>]",
  "       pnpm keys retire --ring <path> --role <role> --kid <kid> [--kernel-store <path> | --in-memory-kernel] [--issuer <url>]",
  "       pnpm keys compromise --ring <path> --role <role> --kid <kid> [--compromised-at <time>] [--issuer <url>]",
  "       pnpm keys verify --ring <path> [--issuer <url>]",
].join("\n");

/** Each command's value flags, required and optional, and its boolean flags. */
const COMMANDS: Record<string, { required: string[]; optional: string[]; switches: string[] }> = {
  init: { required: ["--ring"], optional: ["--issuer"], switches: [] },
  migrate: { required: ["--ring"], optional: ["--issuer"], switches: [] },
  rotate: { required: ["--ring", "--role"], optional: ["--issuer"], switches: ["--activate"] },
  retire: { required: ["--ring", "--role", "--kid"], optional: ["--issuer", "--kernel-store"], switches: ["--in-memory-kernel"] },
  compromise: { required: ["--ring", "--role", "--kid"], optional: ["--issuer", "--compromised-at"], switches: [] },
  verify: { required: ["--ring"], optional: ["--issuer"], switches: [] },
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
  const next = `next: start the AS with this ring, then \`pnpm keys verify --ring ${ring} --issuer ${issuer}\`; the edit is not in effect until then`;

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
        return [`activated ${done.kid} for ${role}; ${done.previous} stops signing and stays published in overlap`, next].join(
          "\n",
        );
      }
      const staged = await stageSigningKeyGeneration(ring, issuer, roles, role);
      return [
        `staged ${staged.kid} for ${role}: to be published, not signing`,
        `${next}. Activation waits ${JWKS_MAX_AGE_SECONDS}s from the publication that verification confirms`,
      ].join("\n");
    }
    case "retire": {
      const store = flags.get("--kernel-store") ?? env.MISSION_KERNEL_STORE?.trim();
      if (store && switches.has("--in-memory-kernel")) throw new Error("name a --kernel-store or --in-memory-kernel, not both");
      // An in-memory kernel's consents end with the process stopped for this edit.
      const standingConsents = store
        ? standingConsentsAttestedUnder(isAbsolute(store) ? store : resolve(env.INIT_CWD ?? cwd, store), kid)
        : switches.has("--in-memory-kernel")
          ? 0
          : undefined;
      await retireSigningKeyGeneration(ring, issuer, roles, role, kid, {
        retention: {
          auditHorizonS: AUDIT_HORIZON_SECONDS,
          maxMissionLifetimeS: DERIVATION_POLICY.max_mission_lifetime_s,
          ...(standingConsents !== undefined ? { standingConsents } : {}),
        },
      });
      return [`retired ${kid} for ${role}: it leaves the AS's key set`, next].join("\n");
    }
    case "verify": {
      const done = await verifySigningKeyRing(ring, issuer, roles);
      const list = (kids: string[]) => (kids.length > 0 ? kids.join(", ") : "none new");
      return [
        `the AS at ${issuer} runs revision ${done.revision} of ${ring}`,
        `confirmed published: ${list(done.published)}; stopped signing: ${list(done.stopped)}; withdrawn: ${list(done.withdrawn)}`,
      ].join("\n");
    }
    case "compromise": {
      const raw = flags.get("--compromised-at");
      const compromisedAt = raw === undefined ? undefined : new Date(raw);
      if (compromisedAt && Number.isNaN(compromisedAt.getTime())) throw new Error(`--compromised-at is not a time: ${raw}`);
      const done = await compromiseSigningKeyGeneration(ring, issuer, roles, role, kid, compromisedAt ? { compromisedAt } : {});
      return [
        `withdrew ${kid} for ${role} as compromised${done.replacement ? `; ${done.replacement} replaces it as the signer` : ""}`,
        `${next}. Until the AS restarts it keeps the key set it loaded; a consumer keeps a key set it fetched until it fetches again, and authorizes a replacement only through its own trusted rotation`,
      ].join("\n");
    }
  }
  throw new Error(USAGE);
}
