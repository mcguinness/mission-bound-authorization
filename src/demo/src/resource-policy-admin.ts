/**
 * @spec runtime#input-resource-policy (#828, D426): `pnpm resource-policy`,
 * the command the deployment's OpenFGA administrator uses to change the
 * independently administered Resource policy: grant or revoke a stored
 * entitlement, or move an invoice to another owning vendor.
 *
 * It only attaches: `OPENFGA_STORE_ID` and `OPENFGA_MODEL_ID` name the store
 * and model the resource attaches to, the model is verified, and nothing is
 * created. It never bootstraps a store, so it can only change the policy a
 * running resource reads. Nothing it writes is derived from a Mission.
 */

import { ENTITLEMENT_RELATIONS, Fga, FgaDomainAdmin, principalObject } from "@mission/pdp";

type TupleKey = { user: string; relation: string; object: string };

export type ResourcePolicyCommand =
  | {
      op: "grant" | "revoke";
      subject: { iss: string; sub: string };
      relation: keyof typeof ENTITLEMENT_RELATIONS;
      target: { type: "vendor" | "invoice"; id: string };
    }
  | { op: "move-invoice"; invoice: string; from: string; to: string };

export const RESOURCE_POLICY_USAGE = [
  "usage: pnpm resource-policy grant|revoke --iss <issuer> --sub <subject> --relation reader|payer (--vendor <id> | --invoice <id>)",
  "       pnpm resource-policy move-invoice --invoice <id> --from <vendor> --to <vendor>",
  "Attaches to OPENFGA_STORE_ID and OPENFGA_MODEL_ID (both required); never creates a store.",
].join("\n");

export class ResourcePolicyUsageError extends Error {
  constructor(message: string) {
    super(`${message}\n${RESOURCE_POLICY_USAGE}`);
    this.name = "ResourcePolicyUsageError";
  }
}

/** Parse the command line, refusing anything it does not fully understand. */
export function parseResourcePolicyCommand(argv: readonly string[]): ResourcePolicyCommand {
  const [op, ...rest] = argv;
  const flags = new Map<string, string>();
  for (let i = 0; i < rest.length; i += 2) {
    const flag = rest[i] as string;
    const value = rest[i + 1];
    if (!flag.startsWith("--") || value === undefined || value.startsWith("--") || value.length === 0) {
      throw new ResourcePolicyUsageError(`expected --flag value pairs, got ${JSON.stringify(rest.slice(i))}`);
    }
    if (flags.has(flag)) throw new ResourcePolicyUsageError(`${flag} given twice`);
    flags.set(flag, value);
  }
  const take = (allowed: readonly string[]) => {
    for (const flag of flags.keys()) {
      if (!allowed.includes(flag)) throw new ResourcePolicyUsageError(`${op} does not take ${flag}`);
    }
    return (flag: string) => {
      const value = flags.get(flag);
      if (value === undefined) throw new ResourcePolicyUsageError(`${op} needs ${flag}`);
      return value;
    };
  };
  if (op === "grant" || op === "revoke") {
    const target = flags.has("--vendor") ? "--vendor" : "--invoice";
    const need = take(["--iss", "--sub", "--relation", target]);
    if (flags.has("--vendor") && flags.has("--invoice")) throw new ResourcePolicyUsageError("name one target, --vendor or --invoice");
    const relation = need("--relation");
    if (relation !== "reader" && relation !== "payer") throw new ResourcePolicyUsageError(`--relation must be reader or payer, not ${relation}`);
    return {
      op,
      subject: { iss: need("--iss"), sub: need("--sub") },
      relation,
      target: { type: target === "--vendor" ? "vendor" : "invoice", id: need(target) },
    };
  }
  if (op === "move-invoice") {
    const need = take(["--invoice", "--from", "--to"]);
    return { op, invoice: need("--invoice"), from: need("--from"), to: need("--to") };
  }
  throw new ResourcePolicyUsageError(op === undefined ? "no command" : `unknown command ${op}`);
}

/** The stored entitlement tuple a grant or revoke writes. */
export function entitlementTuple(cmd: Extract<ResourcePolicyCommand, { op: "grant" | "revoke" }>): TupleKey {
  return { user: principalObject(cmd.subject), relation: ENTITLEMENT_RELATIONS[cmd.relation], object: `${cmd.target.type}:${cmd.target.id}` };
}

/** Apply one command through the admin path, returning the line to print. */
export async function runResourcePolicyCommand(
  cmd: ResourcePolicyCommand,
  admin: Pick<FgaDomainAdmin, "grant" | "revoke" | "moveInvoice">,
): Promise<string> {
  if (cmd.op === "move-invoice") {
    await admin.moveInvoice(cmd.invoice, cmd.from, cmd.to);
    return `moved invoice:${cmd.invoice} from vendor:${cmd.from} to vendor:${cmd.to}`;
  }
  const tuple = entitlementTuple(cmd);
  await (cmd.op === "grant" ? admin.grant([tuple]) : admin.revoke([tuple]));
  return `${cmd.op === "grant" ? "granted" : "revoked"} ${tuple.user} ${tuple.relation} ${tuple.object}`;
}

/** The OpenFGA connection and the store to attach to, from the environment. Both ids are required. */
export function resourcePolicyAdminConnection(env: Readonly<Record<string, string | undefined>>, defaults: { url: string; presharedKey: string }) {
  const storeId = env.OPENFGA_STORE_ID;
  const modelId = env.OPENFGA_MODEL_ID;
  if (!storeId || !modelId) {
    throw new ResourcePolicyUsageError("set OPENFGA_STORE_ID and OPENFGA_MODEL_ID to the store and model the resource attaches to");
  }
  return {
    apiUrl: env.OPENFGA_HTTP_URL ?? defaults.url,
    presharedKey: env.OPENFGA_PRESHARED_KEY ?? defaults.presharedKey,
    ...(env.OPENFGA_CA_CERT ? { caCertPath: env.OPENFGA_CA_CERT } : {}),
    storeId,
    authorizationModelId: modelId,
  };
}

/** Parse, attach (verifying the model, creating nothing) and apply. */
export async function resourcePolicyAdmin(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  defaults: { url: string; presharedKey: string },
): Promise<string> {
  const cmd = parseResourcePolicyCommand(argv);
  const fga = await Fga.attach(resourcePolicyAdminConnection(env, defaults));
  return runResourcePolicyCommand(cmd, new FgaDomainAdmin(fga));
}
