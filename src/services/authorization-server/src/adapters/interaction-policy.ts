/**
 * @spec mission#approval-event (#1247): every Mission the authorization
 * server creates follows its own approval event.
 *
 * oidc-provider's default consent prompt treats a request as consented when a
 * Grant the session already holds covers its scopes. That suits an ordinary
 * OAuth request, and stays. A Mission submission is different: each one
 * proposes a new task with its own Intent and derived authority, and its
 * approval binds to that submission, so an earlier Grant whose scopes happen
 * to cover the request is not its approval. The consent prompt therefore
 * gains one check: a request carrying `mission_intent` needs the Mission
 * approval interaction unless that interaction has just finished for it.
 * Under `prompt=none` the check refuses `consent_required`.
 */

import { interactionPolicy, type KoaContextWithOIDC } from "oidc-provider";

/** The reason oidc-provider records when the check requests the interaction. */
export const MISSION_APPROVAL_CHECK = "mission_approval_required";

/**
 * Request the interaction for a Mission submission until its approval has
 * finished. `result.consent` is set only on the resume that follows a
 * finished interaction (`decide`), so a resume after the approval passes and
 * every other request carrying `mission_intent` prompts.
 */
export function missionApprovalRequired(ctx: KoaContextWithOIDC): boolean {
  const params = ctx.oidc.params as { mission_intent?: unknown } | undefined;
  return params?.mission_intent !== undefined && !ctx.oidc.result?.consent;
}

/** oidc-provider's base policy, with the consent prompt's Mission approval check appended. */
export function missionInteractionPolicy(): interactionPolicy.DefaultPolicy {
  const policy = interactionPolicy.base();
  const consent = policy.get("consent");
  if (!consent) throw new Error("oidc-provider's base interaction policy has no consent prompt");
  consent.checks.add(
    new interactionPolicy.Check(
      MISSION_APPROVAL_CHECK,
      "a Mission submission requires its own Mission approval",
      "consent_required",
      missionApprovalRequired,
    ),
  );
  return policy;
}
