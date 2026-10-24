/**
 * @spec mission#issuance-gating (#250): the release-fence witnesses each
 * issuing path's own test file runs. A witness commits a lifecycle
 * transition inside the issuing request, after the save-time gate passed,
 * and expects the release fence to refuse the response with the binding's
 * per-surface code: `invalid_request` on a Token Exchange (D369), and
 * `invalid_grant` on any other grant, the deferred, device-code, JWT-bearer
 * and dispatch grants included.
 *
 * Two injection points:
 *  - {@link commitAtNextIssue}: from the `access_token.issued` event, which
 *    oidc-provider emits inside `AccessToken#save()` after the save-time gate
 *    ran and the token was signed, and before the response. It names the
 *    Mission the token carries, a successor or a new Mission included.
 *  - {@link commitDuringDrain}: while the request-path drain runs, the last
 *    awaited step before the fence, for a path whose token is not saved
 *    through the provider; the caller picks the Mission to commit on.
 * A witness that still refuses with the fence disabled is witnessing the
 * save-time gate instead: the fence-disabled mutation must deliver a token.
 */
import { expect, vi } from "vitest";
import type { BuiltAs } from "../src/index.js";

type Json = Record<string, unknown>;
type IssuedListener = (at: { extra?: { mission?: { id?: string } } }) => void;

/** The only members a fence refusal carries: no token member survives it. */
export const FENCE_REFUSAL_MEMBERS = ["error", "error_description", "mission_error"] as const;

const TOKEN_MEMBERS = [
  "access_token",
  "refresh_token",
  "issued_token_type",
  "token_type",
  "expires_in",
  "scope",
  "id_token",
  "mission_id",
  "mission_expires_at",
  "authorization_details",
] as const;

/**
 * Commit `op` on the Mission of the next access token the provider issues,
 * from inside its `save()`. Call {@link FenceInjection.disarm} after the
 * request, fired or not.
 */
export function commitAtNextIssue(as: BuiltAs, op: "revoke" | "suspend"): FenceInjection {
  let committed: string | undefined;
  const listener: IssuedListener = (at) => {
    const id = at.extra?.mission?.id as string;
    as.kernel.transition(id, op);
    committed = id;
  };
  as.provider.once("access_token.issued", listener as never);
  return {
    missionId: () => committed,
    disarm: () => {
      as.provider.removeListener("access_token.issued", listener as never);
    },
  };
}

/**
 * Commit `op` on the Mission `pick` names, once, while the issuing request's
 * request-path drain runs. `pick` runs inside the drain, so it can find a
 * Mission the request itself created. Call {@link FenceInjection.disarm}
 * after the request.
 */
export function commitDuringDrain(
  as: BuiltAs,
  op: "revoke" | "suspend",
  pick: () => string | undefined,
): FenceInjection {
  let committed: string | undefined;
  const drain = as.kernel.drainLifecycleOutbox.bind(as.kernel);
  const spy = vi.spyOn(as.kernel, "drainLifecycleOutbox").mockImplementation(async () => {
    if (committed === undefined) {
      const id = pick();
      if (id !== undefined) {
        as.kernel.transition(id, op);
        committed = id;
      }
    }
    return drain();
  });
  return {
    missionId: () => committed,
    disarm: () => spy.mockRestore(),
  };
}

export interface FenceInjection {
  /** The Mission the transition committed on, once it has. */
  missionId(): string | undefined;
  /** Remove the injection, whether or not it fired. */
  disarm(): void;
}

/**
 * The release fence's refusal: HTTP 400, `code`, `mission_error` `revoked`,
 * and exactly {@link FENCE_REFUSAL_MEMBERS}, so no token member survives.
 */
export function expectFenceRefusal(res: { status: number; body: Json }, code: "invalid_grant" | "invalid_request"): void {
  expect(res.status, JSON.stringify(res.body)).toBe(400);
  expect(res.body.error).toBe(code);
  expect(res.body.mission_error).toBe("revoked");
  expect(Object.keys(res.body).sort()).toEqual([...FENCE_REFUSAL_MEMBERS]);
  for (const member of TOKEN_MEMBERS) expect(Object.hasOwn(res.body, member), member).toBe(false);
}
