/**
 * @spec mission#authorization-derivation, mission#authority-sources (#818)
 *
 * The pilot MAS's derivation ceiling and authority-source catalog: the
 * shipped ones, with each delegable entry's delegates named by client
 * identifier (`mas_delegates`). The join compares a bare client identifier
 * (rule 4), so a profile matcher such as the shipped `{sub_profile: "ai_agent"}`
 * admits no joined delegate at all. One definition, read by the in-process
 * kernel (`compose.ts`) and by the separated MAS process (`mas-serve.ts`).
 */

import { AUTHORITY_SOURCES, DERIVATION_POLICY } from "@mission/demo-data";
import type { MasPilotConfig } from "./config.js";

export function pilotMissionPolicy(config: MasPilotConfig): {
  policy: typeof DERIVATION_POLICY;
  authoritySources: typeof AUTHORITY_SOURCES;
} {
  const policy = {
    ...DERIVATION_POLICY,
    policy_version: `${DERIVATION_POLICY.policy_version}+${config.pilot}`,
    ceiling: DERIVATION_POLICY.ceiling.map((entry) =>
      entry.delegation
        ? { ...entry, delegation: { ...entry.delegation, allowed_delegates: config.mas_delegates.map((sub) => ({ sub })) } }
        : entry,
    ),
  } as typeof DERIVATION_POLICY;
  // An authority source whose ceiling is the deployment's derivation ceiling
  // ("deployment" in config/authority-sources.json) follows the pilot's.
  const shippedCeiling = JSON.stringify(DERIVATION_POLICY.ceiling);
  const authoritySources = {
    ...AUTHORITY_SOURCES,
    entries: AUTHORITY_SOURCES.entries.map((source) =>
      JSON.stringify(source.ceiling) === shippedCeiling ? { ...source, ceiling: policy.ceiling } : source,
    ),
  } as typeof AUTHORITY_SOURCES;
  return { policy, authoritySources };
}
