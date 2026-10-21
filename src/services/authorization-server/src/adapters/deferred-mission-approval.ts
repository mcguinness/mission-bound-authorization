/**
 * @spec deferred-approval#deferred-approval, deferred-approval#deferred-sequencing,
 * deferred-approval#front-channel, deferred-approval#state-machine,
 * deferred-approval#pending-staleness, deferred-approval#queue-pressure,
 * deferred-approval#policy-completion: the wire half of Deferred Mission
 * Approval, over OAuth Deferred Token Response -00 (the deferred substrate).
 * Served only where the opt-in `deferred-approval` capability is on.
 *
 * The flow, end to end:
 *
 * 1. The client pushes its Mission Intent through PAR with
 *    `completion_mode=deferred` (the substrate's pre-token hint), then sends
 *    the authorization request.
 * 2. The approval interaction completes into the deferred state with no
 *    user interaction ({@link completeDeferredAuthorization}): it issues an
 *    authorization code that is pending-request state, bound to the client,
 *    its PKCE challenge, its redirect URI and any `dpop_jkt`, and creates no
 *    Mission, no provider grant and no session.
 * 3. The client redeems that code at the token endpoint with `deferred` in
 *    `completion_mode` and a DPoP proof ({@link redeemDeferredCode}). The
 *    issuer opens one pending approval, bound to the client and the proof's
 *    key, under the per-client queue bound, and answers the substrate's
 *    deferred response: `authorization_pending` with an `mdfr_` deferral code.
 * 4. The client polls with the deferred grant type
 *    ({@link pollMissionApprovalDeferral}). A pending approval no policy
 *    evaluation has resolved is completed under `governed_policy`: the issuer
 *    selects the policy and the policy decides, at the atomic creation commit.
 *    The resolving poll delivers a DPoP-bound, Mission-bound access token
 *    once.
 * 5. The client may cancel through the revocation endpoint
 *    ({@link cancelOnRevocation}).
 *
 * Nothing in any request names an approval basis, a policy, a consent or a
 * Subject: the issuer establishes each from configuration and retained
 * governance state. The review surface on which a human makes a full
 * `direct` approval of a pending proposal is not served here.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { withTransaction } from "@mission/store";
import type Provider from "oidc-provider";
import { errors, type KoaContextWithOIDC } from "oidc-provider";
import {
  handler as authorizationCodeHandler,
  parameters as authorizationCodeParameters,
} from "oidc-provider/lib/actions/grants/authorization_code.js";
import { splitScope } from "@mission/core";
import { DEFERRED_GRANT_TYPE } from "../kernel/deferred.js";
import { IntentError } from "../kernel/intent.js";
import {
  MissionApprovalDeferralError,
  type MissionApprovalDeferralStore,
} from "../kernel/mission-approval-deferral.js";
import type {
  AuthorityEntry,
  IntentSubmissionEvidenceEntry,
  MissionIntent,
  MissionRecord,
} from "../kernel/types.js";
import { verifyTokenEndpointDpop } from "./continuation-grant.js";
import { refuseTokenEndpointProof } from "./dpop-replay.js";
import {
  type AdapterOptions,
  clientProposalParam,
  newResourceServer,
  resourceServerInfoFor,
  SCOPE_DECIDED_AT_SAVE,
} from "./provider.js";

/** The deferral codes this profile issues; any other code belongs to another deferral. */
export const MISSION_APPROVAL_DEFERRAL_PREFIX = "mdfr_";

/** DTR -00: the token type of a deferral code, as the revocation endpoint accepts it. */
export const DEFERRAL_CODE_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:deferral-code";

/** A pending-request authorization code's lifetime, oidc-provider's own default for a code. */
export const DEFERRED_CODE_TTL_S = 60;

/** `Retry-After` on a submission refused because the client's queue is full. */
export const QUEUE_FULL_RETRY_AFTER_S = 30;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS mission_deferred_authorization_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  dpop_jkt TEXT,
  intent_json TEXT NOT NULL,
  proposal_json TEXT,
  expires_at INTEGER NOT NULL,
  deferral_code TEXT UNIQUE
) STRICT;
`;

/** Columns added after the table first existed: added in place, so an earlier database opens. */
const ADDED_COLUMNS: ReadonlyArray<[string, string]> = [
  ["resources_json", "TEXT"],
  ["evidence_json", "TEXT"],
];

interface StagedCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  dpop_jkt: string | null;
  intent_json: string;
  proposal_json: string | null;
  /** Every `resource` the authorization request named, distinct, as a JSON array; null for none. */
  resources_json: string | null;
  /** The Submission envelope's `evidence`, as presented, or null. */
  evidence_json: string | null;
  expires_at: number;
  deferral_code: string | null;
}

/**
 * The resources a request names with RFC 8707 `resource` parameters, one or
 * repeated, distinct and in order. The provider's own default resource (the
 * issuer), filled in when a request names none, names nothing.
 */
export function namedResources(value: unknown, issuer: string): string[] {
  const values = typeof value === "string" ? [value] : Array.isArray(value) ? value : [];
  return [...new Set(values.filter((v): v is string => typeof v === "string" && v !== issuer))];
}

/** A resource selection the pending request cannot honor. */
class ResourceSelectionError extends Error {}

/**
 * @spec deferred-approval#deferred-sequencing ("Deferral changes only the
 * timing of the approval event"): the one audience a deferral delivers its
 * token for, as a synchronous redemption of the same request would select it
 * (RFC 8707 Sections 2.1 and 2.2). One deferral delivers one access token:
 * - a `resource` on the redeeming token request selects it, and must be one
 *   the authorization request named, when it named any;
 * - otherwise the authorization request's one resource selects it, and
 *   several are ambiguous;
 * - every selection must be one of the Mission Intent's target resources,
 *   the only authority the pending request can grant.
 * A selection the pending request cannot honor is refused. Nothing named
 * anywhere selects nothing: the delivery then uses the first entry of the
 * Mission's effective set.
 */
function selectedResource(staged: StagedCode, requested: readonly string[]): string | undefined {
  const named = staged.resources_json ? (JSON.parse(staged.resources_json) as string[]) : [];
  let selected: string | undefined;
  if (requested.length > 1) {
    throw new ResourceSelectionError("a deferred approval delivers one token: name one resource");
  }
  if (requested.length === 1) {
    selected = requested[0] as string;
    if (named.length > 0 && !named.includes(selected)) {
      throw new ResourceSelectionError("the resource is not one the authorization request named");
    }
  } else if (named.length > 1) {
    throw new ResourceSelectionError(
      "the authorization request named several resources: name one at the token endpoint, a deferred approval delivers one token",
    );
  } else {
    selected = named[0];
  }
  const targets = (JSON.parse(staged.intent_json) as MissionIntent).target_resources;
  if (selected !== undefined && !targets.includes(selected)) {
    throw new ResourceSelectionError("the resource is not one of the Mission Intent's target resources");
  }
  return selected;
}

/** @spec deferred-approval#deferred-approval: whether `completion_mode` includes `deferred`; other values are ignored. */
export function requestsDeferral(completionMode: unknown): boolean {
  return typeof completionMode === "string" && completionMode.split(" ").includes("deferred");
}

/** A second redemption of one pending-request code, detected inside the opening commit. */
class CodeAlreadyRedeemed extends Error {}

/**
 * The pending-request authorization codes, on the kernel database so the
 * code's single redemption and the pending approval it opens commit together.
 */
export class DeferredAuthorizationCodes {
  constructor(private readonly store: MissionApprovalDeferralStore) {
    store.db.exec(SCHEMA);
    const columns = new Set(
      (store.db.prepare("PRAGMA table_info(mission_deferred_authorization_codes)").all() as Array<{ name: string }>).map(
        (c) => c.name,
      ),
    );
    for (const [column, type] of ADDED_COLUMNS) {
      if (!columns.has(column)) store.db.exec(`ALTER TABLE mission_deferred_authorization_codes ADD COLUMN ${column} ${type}`);
    }
  }

  stage(row: Omit<StagedCode, "deferral_code">, nowMs: number): void {
    // A code past its lifetime redeems nothing, so its row is dropped.
    this.store.db.prepare("DELETE FROM mission_deferred_authorization_codes WHERE expires_at <= ?").run(nowMs);
    this.store.db
      .prepare(
        `INSERT INTO mission_deferred_authorization_codes (code, client_id, redirect_uri, code_challenge, dpop_jkt,
           intent_json, proposal_json, resources_json, evidence_json, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.code,
        row.client_id,
        row.redirect_uri,
        row.code_challenge,
        row.dpop_jkt,
        row.intent_json,
        row.proposal_json,
        row.resources_json,
        row.evidence_json,
        row.expires_at,
      );
  }

  get(code: string): StagedCode | undefined {
    return this.store.db.prepare("SELECT * FROM mission_deferred_authorization_codes WHERE code = ?").get(code) as
      | StagedCode
      | undefined;
  }

  /**
   * Open the code's one pending approval and record the code redeemed, in
   * one commit: a second redemption, concurrent or later, opens nothing.
   */
  openOnce(staged: StagedCode, jkt: string, resource: string | undefined): ReturnType<MissionApprovalDeferralStore["open"]> {
    return withTransaction(this.store.db, () => {
      const pending = this.store.open({
        intent: JSON.parse(staged.intent_json) as MissionIntent,
        ...(staged.proposal_json ? { proposedAuthority: JSON.parse(staged.proposal_json) as AuthorityEntry[] } : {}),
        clientId: staged.client_id,
        jkt,
        ...(resource ? { resource } : {}),
        ...(staged.evidence_json ? { evidence: JSON.parse(staged.evidence_json) as IntentSubmissionEvidenceEntry[] } : {}),
      });
      const claimed = this.store.db
        .prepare(
          "UPDATE mission_deferred_authorization_codes SET deferral_code = ? WHERE code = ? AND deferral_code IS NULL",
        )
        .run(pending.deferral_code, staged.code).changes;
      if (claimed !== 1) throw new CodeAlreadyRedeemed();
      return pending;
    });
  }
}

type InteractionDetails = Awaited<ReturnType<Provider["interactionDetails"]>>;

/**
 * @spec deferred-approval#front-channel, deferred-approval#deferred-sequencing
 * (steps 1 and 2): complete an authorization request whose pushed parameters
 * carry `completion_mode=deferred` into the deferred state, with no user
 * interaction. The front channel establishes only the pending request: the
 * code it issues represents a pending authorization, never authority, and
 * no Approver, Subject, provider grant, session or Mission exists. The code
 * is bound to the requesting client, its PKCE (`S256`) challenge, its
 * redirect URI and, where the request carried one, its `dpop_jkt`.
 *
 * The Intent and any authority proposal are re-read from the interaction's
 * pushed parameters (validated at PAR) and staged with the code; the client
 * sends nothing else that the approval reads.
 */
export async function completeDeferredAuthorization(
  provider: Provider,
  opts: AdapterOptions,
  ctx: KoaContextWithOIDC,
  details: InteractionDetails,
  codes: DeferredAuthorizationCodes,
): Promise<void> {
  const params = details.params as Record<string, unknown>;
  const refuse = (error: string, description: string) =>
    provider.interactionFinished(ctx.req, ctx.res, { error, error_description: description });
  // This assembly answers a deferred request in the query response mode only.
  if (params.response_mode !== undefined && params.response_mode !== "query") {
    await refuse("invalid_request", "a deferred Mission approval answers in the query response mode");
    return;
  }
  // No End-User authenticates on this front channel, so no ID Token can follow.
  if (splitScope(params.scope).oidc.includes("openid")) {
    await refuse("invalid_scope", "openid is unavailable on a deferred Mission approval");
    return;
  }
  if (typeof params.code_challenge !== "string" || params.code_challenge_method !== "S256") {
    await refuse("invalid_request", "a deferred Mission approval requires PKCE with S256");
    return;
  }
  let intent: MissionIntent;
  let evidence: IntentSubmissionEvidenceEntry[] | undefined;
  let proposal: AuthorityEntry[] | undefined;
  try {
    // The whole Submission envelope rides the deferral: the semantic Intent
    // and the presented evidence, which the activation verifies again.
    ({ intent, evidence } = opts.kernel.validateSubmission(String(params.mission_intent)));
    const raw = clientProposalParam(params);
    proposal = raw !== undefined ? opts.kernel.validateProposal(raw, intent.target_resources) : undefined;
  } catch (e) {
    if (e instanceof IntentError) {
      await refuse(e.code, e.message);
      return;
    }
    throw e;
  }
  const code = `mdac_${randomBytes(32).toString("base64url")}`;
  const nowMs = opts.kernel.nowDate().getTime();
  const named = namedResources(params.resource, opts.issuer);
  codes.stage(
    {
      code,
      client_id: String(params.client_id),
      redirect_uri: String(params.redirect_uri),
      code_challenge: params.code_challenge,
      dpop_jkt: typeof params.dpop_jkt === "string" ? params.dpop_jkt : null,
      intent_json: JSON.stringify(intent),
      proposal_json: proposal?.length ? JSON.stringify(proposal) : null,
      // Every resource the request named (RFC 8707), validated by the
      // provider at PAR and kept whole, so the redemption selects among
      // exactly them.
      resources_json: named.length ? JSON.stringify(named) : null,
      evidence_json: evidence?.length ? JSON.stringify(evidence) : null,
      expires_at: nowMs + DEFERRED_CODE_TTL_S * 1000,
    },
    nowMs,
  );
  // The interaction is spent: no approval decision can be made on it.
  await details.destroy();
  const location = new URL(String(params.redirect_uri));
  location.searchParams.set("code", code);
  if (typeof params.state === "string") location.searchParams.set("state", params.state);
  location.searchParams.set("iss", opts.issuer);
  ctx.status = 303;
  ctx.redirect(location.href);
}

/** RFC 7636 `S256`: the verifier's SHA-256, base64url, equals the challenge. */
function pkceS256Matches(verifier: unknown, challenge: string): boolean {
  if (typeof verifier !== "string" || !/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  const computed = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
  const expected = Buffer.from(challenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}

/**
 * @spec deferred-approval#deferred-approval, deferred-approval#front-channel,
 * deferred-approval#queue-pressure: the token endpoint's `authorization_code`
 * grant, wrapped. A code this profile staged is redeemed here; any other
 * code goes to oidc-provider's own handler unchanged, with any
 * `completion_mode` ignored (the issuer completes it synchronously, as the
 * substrate allows).
 */
export function registerDeferredAuthorizationCodeGrant(
  provider: Provider,
  opts: AdapterOptions,
  store: MissionApprovalDeferralStore,
  codes: DeferredAuthorizationCodes,
): void {
  provider.registerGrantType(
    "authorization_code",
    async (ctx) => {
      const code = (ctx.oidc.params as Record<string, unknown>).code;
      const staged = typeof code === "string" ? codes.get(code) : undefined;
      if (!staged) {
        await authorizationCodeHandler(ctx);
        return;
      }
      await redeemDeferredCode(opts, store, codes, ctx, staged);
    },
    // oidc-provider's own parameter set (already extended with `resource`
    // and `authorization_details`), plus the substrate's opt-in.
    new Set([...authorizationCodeParameters, "completion_mode"]),
    new Set(["resource"]),
  );
}

/**
 * @spec deferred-approval#deferred-approval, deferred-approval#deferred-sequencing
 * (step 2): redeem a pending-request code. The checks of an authorization
 * code redemption hold (the authenticated client, the lifetime, the redirect
 * URI, PKCE, a `dpop_jkt` binding); the substrate's hint rule requires
 * `deferred` in `completion_mode`; a DPoP proof is required, because its key
 * is what the deferral code is bound to. The one pending approval opens
 * under the client's queue bound, and the answer is the substrate's deferred
 * response. A second redemption opens nothing and cancels the approval the
 * first one opened.
 */
async function redeemDeferredCode(
  opts: AdapterOptions,
  store: MissionApprovalDeferralStore,
  codes: DeferredAuthorizationCodes,
  ctx: KoaContextWithOIDC,
  staged: StagedCode,
): Promise<void> {
  const params = ctx.oidc.params as Record<string, unknown>;
  const clientId = ctx.oidc.client?.clientId as string;
  // @spec DTR -00 (pre-token hints): the request that obtained this code sent
  // the hint, so the token request must opt in too.
  if (!requestsDeferral(params.completion_mode)) {
    throw new errors.InvalidRequest("this authorization request asked for deferral: include deferred in completion_mode");
  }
  // As oidc-provider's own redemption: an omitted redirect_uri is the
  // client's one registered value, where it registered exactly one.
  const registered = ctx.oidc.client?.redirectUris ?? [];
  const redirectUri = params.redirect_uri ?? (registered.length === 1 ? registered[0] : undefined);
  if (typeof redirectUri !== "string") throw new errors.InvalidRequest("missing required parameter 'redirect_uri'");
  if (staged.client_id !== clientId) throw new errors.InvalidGrant("client mismatch");
  if (staged.expires_at <= opts.kernel.nowDate().getTime()) throw new errors.InvalidGrant("authorization code is expired");
  if (redirectUri !== staged.redirect_uri) throw new errors.InvalidGrant("authorization code redirect_uri mismatch");
  if (!pkceS256Matches(params.code_verifier, staged.code_challenge)) throw new errors.InvalidGrant("PKCE verification failed");
  const proofJws = ctx.get("DPoP");
  if (!proofJws) throw new errors.InvalidRequest("a deferred Mission approval requires a DPoP proof");
  const verified = await verifyTokenEndpointDpop(opts, proofJws);
  if (!verified.ok) {
    refuseTokenEndpointProof(ctx, verified);
    return;
  }
  if (staged.dpop_jkt !== null && staged.dpop_jkt !== verified.proof.jkt) {
    throw new errors.InvalidGrant("DPoP proof key thumbprint does not match dpop_jkt");
  }
  const replayed = (): Error => {
    // RFC 6749 Section 4.1.2: a code used twice is refused, and what it was
    // first redeemed for is revoked where possible.
    const first = codes.get(staged.code)?.deferral_code;
    if (first) store.cancel(first, clientId);
    return new errors.InvalidGrant("authorization code already used");
  };
  if (staged.deferral_code !== null) throw replayed();
  // The one audience the delivery will serve; a selection the pending
  // request cannot honor is refused here, consuming nothing.
  let resource: string | undefined;
  try {
    resource = selectedResource(staged, namedResources(params.resource, opts.issuer));
  } catch (e) {
    if (e instanceof ResourceSelectionError) throw new errors.InvalidTarget(e.message);
    throw e;
  }
  let pending: ReturnType<MissionApprovalDeferralStore["open"]>;
  try {
    pending = codes.openOnce(staged, verified.proof.jkt, resource);
  } catch (e) {
    if (e instanceof CodeAlreadyRedeemed) throw replayed();
    if (e instanceof MissionApprovalDeferralError && e.code === "queue_full") {
      // @spec deferred-approval#queue-pressure: refused until the queue
      // drains; the code is not consumed, so a retry may succeed.
      ctx.status = 503;
      ctx.body = { error: "temporarily_unavailable", error_description: e.message };
      ctx.set("cache-control", "no-store");
      ctx.set("Retry-After", String(QUEUE_FULL_RETRY_AFTER_S));
      return;
    }
    throw e;
  }
  // The substrate's deferred response, set on ctx directly: the OAuth error
  // renderer keeps only error and error_description. Status before body.
  ctx.status = 400;
  ctx.body = {
    error: pending.error,
    deferral_code: pending.deferral_code,
    expires_in: pending.expires_in,
    interval: pending.interval,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec deferred-approval#deferred-sequencing (step 5),
 * deferred-approval#policy-completion: the deferred grant's poll for an
 * `mdfr_` code. The proof is verified before the store is touched, and the
 * store checks the client and key binding before any completion runs. A
 * pending approval not yet evaluated is completed under `governed_policy`
 * here; the outcome maps to the substrate's errors, and an approved
 * approval is delivered once as a DPoP-bound, Mission-bound access token.
 */
export async function pollMissionApprovalDeferral(
  opts: AdapterOptions,
  provider: Provider,
  store: MissionApprovalDeferralStore,
  ctx: KoaContextWithOIDC,
  code: string,
): Promise<void> {
  const proofJws = ctx.get("DPoP");
  if (!proofJws) throw new errors.InvalidRequest("DPoP proof JWT required");
  const verified = await verifyTokenEndpointDpop(opts, proofJws);
  if (!verified.ok) {
    refuseTokenEndpointProof(ctx, verified);
    return;
  }
  const r = await store.pollAndComplete(code, { clientId: ctx.oidc.client?.clientId as string, jkt: verified.proof.jkt });
  if ("error" in r) {
    switch (r.error) {
      case "authorization_pending":
        throw new errors.AuthorizationPending();
      case "slow_down":
        throw new errors.SlowDown();
      case "expired_token":
        throw new errors.ExpiredToken();
      case "access_denied":
        throw new errors.AccessDenied();
      case "invalid_dpop_proof":
        // DTR -00 Section 10.1 (#1357): the opening client under another key;
        // the deferral stays redeemable under its own.
        refuseTokenEndpointProof(ctx, { description: "DPoP proof key is not the key bound to this deferral_code" });
        return;
      default:
        throw new errors.InvalidGrant("unknown or already-redeemed deferral_code");
    }
  }
  // The approval is redeemed only once the credential exists: a failure
  // before then (a token store fault, say) releases the claim, so a later
  // poll delivers; a claim another poll settled first sends nothing.
  let body: Record<string, unknown>;
  try {
    body = await mintMissionToken(opts, provider, ctx, r.mission, verified.proof.jkt, r.resource);
  } catch (e) {
    store.releaseDelivery(code, r.delivery);
    throw e;
  }
  const settled = store.confirmDelivery(code, r.delivery);
  if (settled === "cancelled") throw new errors.AccessDenied();
  if (settled === "superseded") throw new errors.InvalidGrant("unknown or already-redeemed deferral_code");
  ctx.status = 200;
  ctx.body = body;
  ctx.set("cache-control", "no-store");
}

/**
 * @spec deferred-approval#deferred-sequencing (step 5): mint the Mission-bound
 * token the resolving poll returns, and the response body; the caller sends
 * it only once its delivery claim confirms. The Mission's provider grant is
 * bound on first delivery (compare-and-set, so one grant however many polls
 * race). The token carries the Mission's effective Authority Set, is bound to
 * the poll's DPoP key, and never outlives the Mission; the response carries
 * `mission_id` and `mission_expires_at` from the committed record. Its
 * audience is the resource the submission selected, as the authorization
 * code of a synchronous approval would carry it; with none, the first entry's
 * resource, as on the direct path.
 */
async function mintMissionToken(
  opts: AdapterOptions,
  provider: Provider,
  ctx: KoaContextWithOIDC,
  mission: MissionRecord,
  jkt: string,
  requestedResource: string | undefined,
): Promise<Record<string, unknown>> {
  const { kernel } = opts;
  const record = kernel.get(mission.id) as MissionRecord;
  const effective = kernel.effectiveAuthoritySet(record);
  let grantId: string;
  if (record.grant_id) {
    grantId = record.grant_id;
  } else {
    const grant = new provider.Grant({ accountId: record.subject.sub, clientId: record.client_id });
    for (const entry of effective) (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
    grantId = kernel.bindFirstGrant(record.id, await grant.save());
  }
  const resource = requestedResource ?? effective[0]?.resource ?? opts.issuer;
  const info = resourceServerInfoFor(resource, opts.accessTokenTTL ?? 300);
  info.accessTokenTTL = Math.min(
    info.accessTokenTTL,
    Math.max(1, Math.floor((Date.parse(record.expires_at) - Date.now()) / 1000)),
  );
  const at = new provider.AccessToken({
    accountId: record.subject.sub,
    client: ctx.oidc.client as NonNullable<typeof ctx.oidc.client>,
    grantId,
    gty: DEFERRED_GRANT_TYPE,
    rar: effective,
    scope: SCOPE_DECIDED_AT_SAVE,
  });
  at.resourceServer = newResourceServer(provider, resource, info);
  at.jkt = jkt;
  ctx.oidc.entity("AccessToken", at);
  const jwt = await at.save();
  return {
    access_token: jwt,
    token_type: "DPoP",
    expires_in: at.expiration,
    ...(at.scope ? { scope: at.scope } : {}),
    authorization_details: effective,
    mission_id: record.id,
    mission_expires_at: record.expires_at,
  };
}

/**
 * @spec deferred-approval#state-machine (client cancellation), DTR -00
 * (Cancellation): a deferral code revoked at the RFC 7009 revocation
 * endpoint by the client it is bound to moves its pending approval to
 * `cancelled`. Runs after oidc-provider's revocation route, so the client
 * has authenticated and the response is the route's own 200 either way: an
 * unknown code, another client's code, or a settled approval changes nothing.
 */
export function cancelOnRevocation(store: MissionApprovalDeferralStore) {
  return async (ctx: KoaContextWithOIDC, next: () => Promise<void>): Promise<void> => {
    await next();
    if (ctx.oidc?.route !== "revocation" || ctx.status !== 200) return;
    const token = (ctx.oidc.params as Record<string, unknown> | undefined)?.token;
    const clientId = ctx.oidc.client?.clientId;
    if (typeof token === "string" && token.startsWith(MISSION_APPROVAL_DEFERRAL_PREFIX) && clientId) {
      store.cancel(token, clientId);
    }
  };
}
