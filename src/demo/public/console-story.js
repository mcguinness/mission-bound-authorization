// The console story's revocation proof (step 6), kept apart from the page so
// it can be tested: it may report done only when the run showed the contrast
// it claims. Presentation logic only; every verdict it reads is the server's.

/** Refusals that follow from a revoked Mission: inactive, or no valid token. */
export const REVOCATION_REFUSALS = ["mission_inactive", "mission_not_active", "credential_invalid", "invalid_credential"];

/** The Mission to contrast with: another active Mission, read-only by preference. */
export function contrastMission(missions, revokedId) {
  const others = (missions || []).filter((m) => m.id !== revokedId && m.state === "active");
  const moves = (m) => (m.effective || []).some((e) => (e.actions || []).includes("payments:payment.execute"));
  return others.find((m) => !moves(m)) || others[0];
}

/**
 * Show that revoking `missionId` ended its authority and left the agent's
 * other Mission working. `revoke` is the lifecycle response (or the Mission's
 * recorded revoked state, on a retry); `read(id, heading)` performs one read
 * under the named Mission and resolves its response. Resolves
 * `{ done: true, otherId }` only when the revoke succeeded, the read under the
 * revoked Mission was refused for a revocation reason, and the same read
 * under the other Mission was permitted; otherwise `{ done: false, problem }`,
 * and the reads stop at the first missing piece.
 */
export async function proveRevocation({ revoke, missions, missionId, read }) {
  const fail = (problem) => ({ done: false, problem });
  if (!revoke || revoke.error) return fail(`the revoke was refused${revoke?.error ? ` (${revoke.error})` : ""}`);
  if (revoke.id !== missionId || revoke.state !== "terminated" || revoke.termination?.reason !== "revoked") {
    return fail("the Mission is not recorded as revoked");
  }
  const other = contrastMission(missions, missionId);
  if (!other) return fail("the agent holds no other active Mission to contrast with");
  const revokedRead = await read(missionId, "Same read, revoked Mission");
  if (!revokedRead || revokedRead.ok) return fail("the read under the revoked Mission was permitted");
  const reason = String(revokedRead.reason ?? revokedRead.denial_reason ?? revokedRead.refusal_reason ?? "").split(":")[0];
  if (!REVOCATION_REFUSALS.includes(reason)) {
    return fail(`the read under the revoked Mission was refused for another reason (${reason || revokedRead.error || "none given"})`);
  }
  const otherRead = await read(other.id, "Same read, the agent's other Mission");
  if (!otherRead || !otherRead.ok) {
    return fail(`the read under the agent's other Mission was not permitted (${otherRead?.reason ?? otherRead?.error ?? "no result"})`);
  }
  return { done: true, otherId: other.id };
}
