/**
 * @spec mission#transformation-capabilities, resource-access#transformation-capabilities
 * (#1377, D1037): the shipped `transformation-capabilities.json` with
 * `delegation` or `projection` omitted, declared `false` or declared `true`,
 * resolved by the loader the server starts from. A server built with a
 * {@link liveCapabilities} object reads each capability at its next use, so
 * one server witnesses every variant.
 */
import { readFileSync } from "node:fs";
import { loadTransformationCapabilities, type TransformationCapabilities } from "@mission/demo-data";

export type CapabilityMember = "delegation" | "projection";
export type CapabilityVariant = "omitted" | "false" | "true";

/** The variants a gate witness refuses under: the capability omitted, and declared `false`. */
export const UNDECLARED_VARIANTS: readonly CapabilityVariant[] = ["omitted", "false"];

const SHIPPED = readFileSync(new URL("../../../config/transformation-capabilities.json", import.meta.url), "utf8");

/** The shipped declaration with each named member omitted or set, through the loader. */
export function capabilitiesWith(
  members: Partial<Record<CapabilityMember, CapabilityVariant>>,
): TransformationCapabilities {
  const config = JSON.parse(SHIPPED) as { types: { mission_resource_access: Record<string, unknown> } };
  const entry = config.types.mission_resource_access;
  for (const [member, variant] of Object.entries(members)) {
    if (variant === "omitted") delete entry[member];
    else entry[member] = variant === "true";
  }
  return loadTransformationCapabilities(JSON.stringify(config));
}

/** A fresh copy of the shipped declaration, for a server whose capabilities a case changes. */
export const liveCapabilities = (): TransformationCapabilities => capabilitiesWith({});

/**
 * Run `run` with `live` (the object a server was built with) holding the
 * shipped declaration with `member` as `variant`, then restore it.
 */
export async function withCapability(
  live: TransformationCapabilities,
  member: CapabilityMember,
  variant: CapabilityVariant,
  run: () => Promise<void>,
): Promise<void> {
  const saved = { ...live };
  Object.assign(live, capabilitiesWith({ [member]: variant }));
  try {
    await run();
  } finally {
    Object.assign(live, saved);
  }
}
