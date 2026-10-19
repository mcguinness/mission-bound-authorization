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
 *
 * @spec device-authorization#approval, device-authorization#request (#1202):
 * the same holds on the device flow. A verification user agent already
 * holding a provider session and a grant for the client covering the
 * requested scope would otherwise complete the device session itself, and
 * the device code would redeem under that earlier grant and its Mission. A
 * device decision finishes on the device code, never through the resume, so
 * that check needs no finished-approval guard.
 *
 * @spec mission#grant-binding-resolution (#1259): the converse. A request
 * carrying no `mission_intent` proposes no Mission, so consent reuse never
 * answers it with a Mission-bound grant ({@link loadReusableGrant}).
 */

import { type Grant, interactionPolicy, type KoaContextWithOIDC } from "oidc-provider";

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

/** Request the interaction for a device session carrying a Mission Intent, at verification and on resume. */
export function missionDeviceApprovalRequired(ctx: KoaContextWithOIDC): boolean {
  return (
    (ctx.oidc.route === "code_verification" || ctx.oidc.route === "device_resume") &&
    (ctx.oidc.params as { mission_intent?: unknown }).mission_intent !== undefined
  );
}

/** oidc-provider's base policy, with the consent prompt's Mission approval checks appended. */
export function missionInteractionPolicy(): interactionPolicy.DefaultPolicy {
  const policy = interactionPolicy.base();
  const consent = policy.get("consent");
  if (!consent) throw new Error("oidc-provider's base interaction policy has no consent prompt");
  consent.checks.add(
    new interactionPolicy.Check(
      "mission_device_approval",
      "a Mission device session requires the Mission approval",
      "consent_required",
      missionDeviceApprovalRequired,
    ),
  );
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

/**
 * @spec mission#grant-binding-resolution (#1259): the grant an authorization
 * request reuses (oidc-provider's `loadExistingGrant`). The candidate is the
 * provider default's: the finished interaction's consent grant, else the
 * grant the session holds for the client. A request carrying `mission_intent`
 * keeps it: the Mission approval check prompts that request, and its resume
 * loads the approval's own grant. A request without one is never answered
 * with a Mission-bound candidate: the provider starts a new, empty Grant for
 * it, and the excluded grant, its binding and the session's reference to it
 * stay as they were. `missionBound` classifies by what the AS recorded, never
 * by whether the Mission still resolves.
 */
export async function loadReusableGrant(
  ctx: KoaContextWithOIDC,
  missionBound: (grantId: string) => boolean,
): Promise<Grant | undefined> {
  const { oidc } = ctx;
  const consented = (oidc.result as { consent?: { grantId?: string } } | undefined)?.consent?.grantId;
  const grantId = consented || (oidc.client ? oidc.session?.grantIdFor(oidc.client.clientId) : undefined);
  if (!grantId) return undefined;
  const params = oidc.params as { mission_intent?: unknown } | undefined;
  if (params?.mission_intent === undefined && missionBound(grantId)) return undefined;
  return oidc.provider.Grant.find(grantId);
}

/**
 * @spec mission#grant-binding-resolution (#1259): the reference AS's answer to
 * an authorization request carrying no `mission_intent` that needs an
 * interaction (a login, or consent no eligible grant supplies). Its only
 * interaction is the Mission approval, so the request is refused through the
 * provider's validated authorization response. A local choice, not a protocol
 * rule; the description names no Mission.
 */
export const ORDINARY_REQUEST_REFUSAL = {
  error: "access_denied",
  error_description: "this authorization server offers no interaction for this request",
} as const;
