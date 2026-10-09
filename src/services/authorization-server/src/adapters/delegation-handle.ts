/**
 * @spec continuation#transport-async (#1157, D358): the delegation-handle
 * request.
 *
 * draft-zhu-oauth-async-delegation-05 Section 4.3 takes as its `subject_token`
 * a delegation handle: an access token whose audience identifies the acting
 * client, sender-constrained to it. A Mission access token is audienced to a
 * resource, so an agent first exchanges it here: an RFC 8693 token exchange
 * whose `audience` is the authenticated client's own client_id. The agent
 * proves possession of the presented token's key and receives an access token
 * audienced to itself, bound to the same key, carrying the presented authority
 * narrowed by the Mission's current Effective Authority Set.
 *
 * This is a no-actor self-exchange (mission#self-exchange): rule 1 opens it only
 * to the Mission's approved agent, rule 2 bounds the handle by the presented
 * token's own authority, and rule 3 makes it a derivation gated on `active`,
 * counted once here, as the Dispatch Handoff's redemption that mints a
 * dispatched Agent's handle is (dispatch-handoff.ts).
 */
import type { KoaContextWithOIDC } from "oidc-provider";
import type Provider from "oidc-provider";
import { projectThroughEffective, SourceUnavailableError } from "../kernel/derive.js";
import { GateError } from "../kernel/kernel.js";
import type { AuthorityEntry } from "../kernel/types.js";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  authoritySource,
  presentedTokenAuthority,
  TOKEN_EXCHANGE_GRANT_TYPE,
  txError,
  verifySubjectPossession,
} from "./continuation-grant.js";
import { gateRefusal } from "./dispatch-handoff.js";
import {
  type AdapterOptions,
  gateErrorToMissionError,
  markDelegationHandle,
  newResourceServer,
  resourceServerInfoFor,
  SCOPE_DECIDED_AT_SAVE,
} from "./provider.js";

/** The gate reasons that are lifecycle refusals (the Mission is not `active`), not a limit. */
const LIFECYCLE_GATE_REASONS: ReadonlySet<string> = new Set(["mission_not_active", "mission_expired"]);

/**
 * @spec mission#issuance-gating (#1154, D369): a Token Exchange refused because
 * its Mission is not `active`: the Mission makes the subject token unacceptable
 * for the exchange, so the refusal is `invalid_request` (RFC 8693 Section
 * 2.2.2), keeping the `mission_error` diagnostic. A derivation-limit refusal
 * stays `invalid_grant` (gateRefusal).
 */
function refuseInactive(ctx: KoaContextWithOIDC, description: string, missionError: string | undefined): void {
  txError(ctx, 400, "invalid_request", description);
  if (missionError) (ctx.body as Record<string, unknown>).mission_error = missionError;
}

/**
 * Parameters a delegation-handle request never carries: the selectors and
 * inputs of the other access-token exchanges (expansion), the async transport,
 * and an actor. A request combining `audience` with one is refused, never routed.
 */
export const DELEGATION_HANDLE_CONFLICTS = [
  "request_refresh_token",
  "mission_intent",
  "deferral_code",
  "predecessor",
  "creation_request_id",
  "actor_token",
  "resource",
] as const;

export async function handleDelegationHandleExchange(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
): Promise<void> {
  const { kernel } = opts;
  const params = ctx.oidc.params as Record<string, unknown>;
  const client = ctx.oidc.client as NonNullable<typeof ctx.oidc.client>;

  // The handle's audience is the requesting client itself (D358): any other
  // value names a target this exchange does not serve.
  if (params.audience !== client.clientId) {
    txError(ctx, 400, "invalid_target", "a delegation handle's audience must be the requesting client's own client_id");
    return;
  }
  if (params.scope !== undefined) {
    txError(ctx, 400, "invalid_scope", "a delegation handle carries authority, not scope");
    return;
  }
  if (params.authorization_details !== undefined) {
    txError(
      ctx,
      400,
      "invalid_request",
      "a delegation handle carries the presented authority; narrow it at the async-delegation exchange",
    );
    return;
  }

  // Subject token, Mission, and possession of the token's own key.
  const subject = await verifySubjectPossession(opts, ctx);
  if (!subject) return;
  const { record, jkt, claims } = subject;
  if (claims.act !== undefined) {
    txError(ctx, 400, "invalid_request", "subject_token actor context (act) is not supported on this exchange");
    return;
  }
  if (claims.client_id !== client.clientId) {
    txError(ctx, 400, "invalid_grant", "subject_token was not issued to the requesting client");
    return;
  }
  // @spec mission#self-exchange rule 1: only the Mission's approved agent.
  if (record.client_id !== client.clientId) {
    txError(ctx, 400, "invalid_request", "a no-actor exchange is open only to the Mission's approved agent");
    return;
  }
  // @spec mission#self-exchange rule 2: the presented token's own authority bounds the handle.
  const presented = presentedTokenAuthority(claims);
  if (!presented) {
    txError(ctx, 400, "invalid_grant", "subject_token carries no readable authorization_details");
    return;
  }
  const active = kernel.applyExpiry(record);
  if (active.state !== "active") {
    refuseInactive(
      ctx,
      `mission ${record.id} is ${active.state}`,
      gateErrorToMissionError(active.state === "expired" ? "mission_expired" : "mission_not_active", active.state),
    );
    return;
  }
  let effective: AuthorityEntry[];
  try {
    effective = authoritySource(opts).effectiveAuthoritySet(active);
  } catch (e) {
    if (e instanceof SourceUnavailableError) {
      txError(ctx, 503, "temporarily_unavailable", e.message);
      return;
    }
    throw e;
  }
  const authority = projectThroughEffective(presented, effective);
  if (authority.length === 0) {
    txError(ctx, 400, "invalid_grant", "the presented authority is no longer within the Mission's effective authority");
    return;
  }

  // Mint. The handle rides a provider Grant of its own, recorded in the
  // Mission-bound grant index (kind delegation-handle), so the Mission's own
  // grant_id does not move and the save-time hook re-gates active state only.
  const oidcGrant = new provider.Grant({ accountId: record.subject.sub, clientId: client.clientId });
  for (const entry of authority) {
    (oidcGrant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await oidcGrant.save();
  kernel.missionBoundGrants.record({ grantId, missionId: record.id, kind: "delegation-handle" });
  // @spec mission#self-exchange rule 3, mission#issuance-gating: the one
  // counted derivation of this exchange; nothing is counted again at save.
  try {
    kernel.gateDerivation(record.id);
  } catch (e) {
    await (oidcGrant as unknown as { destroy: () => Promise<void> }).destroy();
    if (e instanceof GateError && LIFECYCLE_GATE_REASONS.has(e.reason)) {
      refuseInactive(ctx, e.message, gateErrorToMissionError(e.reason, kernel.get(record.id)?.state));
      return;
    }
    throw gateRefusal(opts, e, record.id);
  }

  const info = resourceServerInfoFor(client.clientId, opts.accessTokenTTL ?? 300);
  info.accessTokenTTL = Math.min(
    info.accessTokenTTL,
    Math.max(1, Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000)),
  );
  const at = new provider.AccessToken({
    accountId: record.subject.sub,
    client,
    grantId,
    gty: TOKEN_EXCHANGE_GRANT_TYPE,
    rar: authority,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  at.resourceServer = newResourceServer(provider, client.clientId, info);
  at.jkt = jkt; // the presented token's key: the handle stays sender-constrained to it
  markDelegationHandle(at);
  ctx.oidc.entity("AccessToken", at);
  let jwt: string;
  try {
    jwt = await at.save();
  } catch (e) {
    // The save-time gate refused (or the save failed): no handle exists, so
    // its grant does not either.
    await (oidcGrant as unknown as { destroy: () => Promise<void> }).destroy();
    throw e;
  }

  ctx.status = 200;
  ctx.body = {
    access_token: jwt,
    issued_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    token_type: "DPoP",
    expires_in: at.expiration,
    authorization_details: authority,
  };
  ctx.set("cache-control", "no-store");
}
