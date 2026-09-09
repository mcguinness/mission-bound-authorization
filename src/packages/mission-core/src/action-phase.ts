/**
 * @spec runtime#compound-actions — the four phases a boundary crossing of a
 * compound action can be. One closed vocabulary, shared by the three layers
 * that must agree on it: the deployment's trusted Operation Profile
 * (`config/catalog.json`, validated at load), the decision request and permit
 * condition (`context.action_phase` / `conditions.action_phase`), and the
 * retrospective Decision Evidence member.
 *
 * The list lives here, in the package every one of those layers already
 * depends on, so none of them can drift to a private copy: a phase value the
 * profile accepts is exactly a phase the PDP validates and the executing PEP
 * compares at use.
 */

/** The closed set, in the order the profile defines them. */
export const ACTION_PHASES = ["preflight", "prepare", "commit", "compensate"] as const;

export type ActionPhase = (typeof ACTION_PHASES)[number];

/**
 * Narrowing guard, never a cast: an unrecognized or malformed value is not a
 * phase, and callers refuse or omit it rather than carrying it forward
 * (@spec runtime-evidence#decision-evidence-object `action_phase`: "Malformed
 * or unvalidated phase input MUST be omitted").
 */
export function isActionPhase(value: unknown): value is ActionPhase {
  return typeof value === "string" && (ACTION_PHASES as readonly string[]).includes(value);
}
