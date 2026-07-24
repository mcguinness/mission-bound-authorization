/**
 * Thin adapters over node-oidc-provider 9.10.0 (decision D30): the provider
 * and custom routes call the mission-kernel only through its interface.
 * Wiring facts verified by the pre-flight spike (src/spikes/SPIKE-REPORT.md).
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { DEV_SERVICE_TOKEN, WRITE_ACTIONS } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type CryptoKey,
  type JWK,
} from "jose";
import Provider, { errors, type Configuration } from "oidc-provider";

// @types/oidc-provider (9.5) predates InvalidAuthorizationDetails, present at
// runtime in 9.10 (spec traceability: SPEC_VERSIONS O-2 note). Typed alias.
const InvalidAuthorizationDetails = (errors as unknown as {
  InvalidAuthorizationDetails: new (message?: string) => Error;
}).InvalidAuthorizationDetails;
import { isSubsetSet } from "../kernel/derive.js";
import { IntentError } from "../kernel/intent.js";
import { GateError, LifecycleConflictError, type MissionKernel } from "../kernel/kernel.js";
import { issueTxnToken, validateChallenge } from "../kernel/txn-challenge.js";
import type { AuthorityEntry, LifecycleOperation, MissionIntent } from "../kernel/types.js";

export interface AdapterOptions {
  issuer: string;
  kernel: MissionKernel;
  clients: Record<string, unknown>[];
  jwks: { keys: Record<string, unknown>[] };
  publicJwks: { keys: Record<string, unknown>[] };
  /** Test-only headless adjudication (D40): disabled unless set. */
  allowHeadlessAdjudication?: boolean;
  approverRoleSubs: Set<string>;
  /** Access-token lifetime (seconds) for issued mission tokens. Default 300. */
  accessTokenTTL?: number;
  /** AS-txn signing key + kid: signs txn-bound, single-use approval tokens. */
  txnKey?: CryptoKey;
  txnKid?: string;
  /**
   * The resource's txn-challenge verification keys (its
   * txn_challenge_jwks_uri). Required for the transaction_authorization_endpoint;
   * phase 3 wires it from composeStack, the phase-1 test injects a generated
   * rs-txn pub.
   */
  resourceTxnJwks?: { keys: JWK[] };
  /**
   * AROP transaction task store. The AS vouches for the RS-validated challenge
   * and opens/polls a task here (D37: AS owns the txn pending id, ARS owns the
   * approval). Injected so the AS package takes no dependency on the ARS.
   */
  ars?: TxnArs;
}

/**
 * The subset of the Access Request Service the transaction endpoint uses.
 * Structural so the AS package needs no compile-time dependency on the ARS.
 */
export interface TxnArs {
  openForTxn(input: {
    txn: string;
    missionId: string;
    action: string;
    parameter_digest: string;
    subject: string;
  }): { taskId: string; state: string };
  getTask(taskId: string):
    | {
        state: string;
        approval?: { id: string; approved_at: string; approved_until: string; parameter_digest: string };
      }
    | undefined;
}

interface KoaCtx {
  method: string;
  path: string;
  status: number;
  body: unknown;
  query: Record<string, string | string[] | undefined>;
  req: IncomingMessage;
  res: ServerResponse;
  set: (name: string, value: string) => void;
  get: (name: string) => string;
}

export function buildProvider(opts: AdapterOptions): Provider {
  const { kernel } = opts;

  const configuration: Configuration = {
    clients: opts.clients as never,
    jwks: opts.jwks as never,
    scopes: ["openid", "payments"],
    issueRefreshToken: async (_ctx, client) => client.grantTypeAllowed("refresh_token"),
    pkce: { required: () => true },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    async findAccount(_ctx, id) {
      return { accountId: id, claims: async () => ({ sub: id }) };
    },
    features: {
      // We serve our own approval interaction (the mission-kernel adapter).
      devInteractions: { enabled: false },
      pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: true },
      richAuthorizationRequests: {
        enabled: true,
        ack: "experimental-01",
        // Issuer-derived RAR (@spec mission#authorization-derivation): the
        // grant's rar IS the Mission's Authority Set; every surface projects it.
        rarForAuthorizationCode: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        rarForCodeResponse: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        rarForRefreshTokenResponse: (ctx: { oidc: { grant?: { rar?: unknown } } }) =>
          ctx.oidc.grant?.rar as never,
        types: {
          mission_resource_access: {
            validate: () => {
              // Raw client submission of the issuer-derived type is refused;
              // authority is proposed only inside the Intent.
              // @spec mission#submission-via-par
              throw new InvalidAuthorizationDetails(
                "mission_resource_access is issuer-derived; propose authority via mission_intent",
              );
            },
          },
        },
      },
      dPoP: { enabled: true },
      revocation: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => opts.issuer,
        getResourceServerInfo: (_ctx, resourceIndicator) => ({
          scope: "payments",
          audience: resourceIndicator,
          accessTokenFormat: "jwt",
          accessTokenTTL: opts.accessTokenTTL ?? 300,
        }),
        useGrantedResource: () => true,
      },
    },
    extraParams: {
      // @spec mission#submission-via-par — PAR-only carriage + exclusions.
      async mission_intent(ctx, value) {
        if (value === undefined) return;
        const params = (ctx as { oidc: { params: Record<string, unknown> } }).oidc.params;
        if (params.authorization_details !== undefined) {
          throw new errors.InvalidRequest("mission_intent and authorization_details are mutually exclusive");
        }
        try {
          kernel.validateIntent(String(value));
        } catch (e) {
          if (e instanceof IntentError) {
            throw e.code === "invalid_request"
              ? new errors.InvalidRequest(e.message)
              : new InvalidAuthorizationDetails(e.message);
          }
          throw e;
        }
      },
    },
    // @spec mission#the-mission-claim + state-gated issuance (mission#lifecycle):
    // every mission-bound access token carries the projection; a non-active
    // mission refuses issuance with invalid_grant.
    extraTokenClaims(_ctx, token) {
      const grantId = (token as { grantId?: string }).grantId;
      if (!grantId) return {};
      const record = kernel.findByGrant(grantId);
      if (!record) return {};
      try {
        const gated = kernel.gateDerivation(record.id);
        return { mission: kernel.missionClaim(gated) };
      } catch (e) {
        if (e instanceof GateError) throw new errors.InvalidGrant(e.message);
        throw e;
      }
    },
  };

  const provider = new Provider(opts.issuer, configuration);
  provider.use(makeRoutes(provider, opts));
  return provider;
}

function makeRoutes(provider: Provider, opts: AdapterOptions) {
  const { kernel } = opts;
  const jwksResolver = createLocalJWKSet(opts.publicJwks as never);
  // txn -> ARS taskId. Idempotency for repeated /transaction polls (AROP).
  const txnTasks = new Map<string, string>();

  const requireServiceToken = (ctx: KoaCtx): boolean => {
    if (ctx.get("x-service-token") !== DEV_SERVICE_TOKEN) {
      ctx.status = 401;
      ctx.body = { error: "unauthorized" };
      return false;
    }
    return true;
  };

  return async (ctx: KoaCtx, next: () => Promise<void>) => {
    // --- Approval interaction (minimal approver surface + headless path) ---
    const interactionMatch = ctx.path.match(/^\/interaction\/([^/]+)$/);
    if (interactionMatch && ctx.method === "GET") {
      const details = await provider.interactionDetails(ctx.req, ctx.res);
      const raw = (details.params as Record<string, unknown>).mission_intent;
      const intent = kernel.validateIntent(String(raw));
      const authority = kernel.derive(intent);
      ctx.status = 200;
      ctx.set("content-type", "text/html; charset=utf-8");
      ctx.body = renderApprovalPage(interactionMatch[1] as string, intent, authority);
      return;
    }
    const decideMatch = ctx.path.match(/^\/interaction\/([^/]+)\/decide$/);
    if (decideMatch && ctx.method === "POST") {
      if (!opts.allowHeadlessAdjudication && !requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
      await decide(provider, opts, ctx, body);
      return;
    }

    // --- Signed Status (@spec status#mission-status-response) ---
    const statusMatch = ctx.path.match(/^\/missions\/([^/]+)\/status$/);
    if (statusMatch && ctx.method === "GET") {
      if (!requireServiceToken(ctx)) return;
      try {
        const jws = await kernel.signedStatus(statusMatch[1] as string, {
          ...optional("audience", str(ctx.query.audience)),
          ...optional("nonce", str(ctx.query.nonce)),
          requester: "svc:console",
        });
        ctx.status = 200;
        ctx.set("content-type", "application/mission-status-response+jwt");
        ctx.set("cache-control", "no-store");
        ctx.body = jws;
      } catch {
        ctx.status = 404;
        ctx.body = { error: "unknown_mission" };
      }
      return;
    }

    // --- Lifecycle operations (@spec status#legal-transitions) ---
    const lifecycleMatch = ctx.path.match(/^\/missions\/([^/]+)\/lifecycle$/);
    if (lifecycleMatch && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
      try {
        const record = kernel.transition(
          lifecycleMatch[1] as string,
          body.operation as LifecycleOperation,
        );
        // Revocation/terminal states also revoke the OAuth grant so refresh
        // fails structurally, not just by gating.
        if (record.state !== "active" && record.state !== "suspended" && record.grant_id) {
          const grant = await provider.Grant.find(record.grant_id);
          await grant?.destroy();
        }
        ctx.status = 200;
        ctx.body = { id: record.id, state: record.state, version: record.version };
      } catch (e) {
        if (e instanceof LifecycleConflictError) {
          ctx.status = 409;
          ctx.body = { error: "conflict", error_description: e.message };
        } else {
          ctx.status = 404;
          ctx.body = { error: "unknown_mission" };
        }
      }
      return;
    }

    // --- Adapter introspection (@spec mission#introspection; RFC 7662) ---
    // JWT ATs cannot use the provider's introspection endpoint (spike
    // finding); this route mirrors the JWT claim set per CIA-CORE.
    if (ctx.path === "/introspect" && ctx.method === "POST") {
      if (!requireServiceToken(ctx)) return;
      const body = await readJsonBody(ctx.req);
      ctx.status = 200;
      try {
        const { payload } = await jwtVerify(String(body.token), jwksResolver);
        const mission = payload.mission as { id?: string } | undefined;
        const record = mission?.id ? kernel.get(mission.id) : undefined;
        ctx.body = {
          active: true,
          iss: payload.iss,
          sub: payload.sub,
          aud: payload.aud,
          client_id: payload.client_id,
          exp: payload.exp,
          iat: payload.iat,
          jti: payload.jti,
          cnf: payload.cnf,
          ...(record ? { mission: kernel.introspectionMission(record) } : {}),
        };
      } catch {
        ctx.body = { active: false };
      }
      return;
    }

    // --- AROP Transaction Challenge (@spec txn-challenge; openid/authzen#531) ---
    // The client presents its base mission token (DPoP) + the RS-signed
    // txn-challenge; the AS validates + subset-gates against the ACTIVE Mission
    // (D42), obtains approval, and issues a txn-bound single-use token.
    if (ctx.path === "/transaction" && ctx.method === "POST") {
      await handleTransaction(opts, ctx, txnTasks);
      return;
    }

    await next();

    // --- AS metadata flags (@spec mission#as-metadata) ---
    if (ctx.path === "/.well-known/openid-configuration" && ctx.status === 200) {
      const meta = ctx.body as Record<string, unknown>;
      meta.mission_bound_authorization_supported = true;
      meta.service_catalog_endpoint = `${opts.issuer}/service-catalog`;
      meta.introspection_endpoint = `${opts.issuer}/introspect`;
      meta.transaction_authorization_endpoint = `${opts.issuer}/transaction`;
    }
  };
}

/**
 * transaction_authorization_endpoint handler. Client-authenticated by its base
 * mission token (DPoP), bodied with the RS-signed txn-challenge. On approval it
 * issues a txn-bound, audience-restricted, single-use token carrying the ACTIVE
 * Mission unchanged (D42) plus the verified approval.
 */
async function handleTransaction(
  opts: AdapterOptions,
  ctx: KoaCtx,
  txnTasks: Map<string, string>,
) {
  const { kernel } = opts;

  // 1. Base mission token + DPoP proof (the client authenticates with these).
  const auth = ctx.get("authorization");
  if (!auth || !auth.startsWith("DPoP ")) {
    ctx.status = 401;
    ctx.body = { error: "invalid_token", error_description: "DPoP-bound base mission token required" };
    return;
  }
  const baseToken = auth.slice("DPoP ".length);
  const proofJws = ctx.get("dpop");
  if (!proofJws) {
    ctx.status = 401;
    ctx.body = { error: "invalid_dpop_proof", error_description: "missing DPoP proof" };
    return;
  }
  let baseClaims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(baseToken, createLocalJWKSet(opts.publicJwks as never), {
      issuer: opts.issuer,
    });
    baseClaims = payload as Record<string, unknown>;
  } catch {
    ctx.status = 401;
    ctx.body = { error: "invalid_token" };
    return;
  }
  const cnf = baseClaims.cnf as { jkt?: string } | undefined;
  if (!cnf?.jkt) {
    ctx.status = 401;
    ctx.body = { error: "invalid_token", error_description: "base token missing cnf.jkt" };
    return;
  }
  // Bind the DPoP proof to this endpoint (htu/htm) and to the token's cnf.jkt.
  try {
    const header = decodeProtectedHeader(proofJws);
    const proofJkt = await calculateJwkThumbprint(header.jwk as never);
    if (proofJkt !== cnf.jkt) throw new Error("DPoP key does not match token cnf.jkt");
    const { payload: proof } = await jwtVerify(proofJws, header.jwk as never, { typ: "dpop+jwt" });
    if (proof.htu !== `${opts.issuer}/transaction` || proof.htm !== "POST") {
      throw new Error("DPoP htu/htm mismatch");
    }
  } catch {
    ctx.status = 401;
    ctx.body = { error: "invalid_dpop_proof" };
    return;
  }
  const missionRef = baseClaims.mission as { id?: string } | undefined;
  const missionId = missionRef?.id;
  const subject = baseClaims.sub as string;
  if (!missionId) {
    ctx.status = 401;
    ctx.body = { error: "invalid_token", error_description: "base token missing mission claim" };
    return;
  }

  // 2. Body: the RS-signed txn-challenge.
  const body = await readJsonBody(ctx.req);
  const challenge = body.challenge;
  if (typeof challenge !== "string") {
    ctx.status = 400;
    ctx.body = { error: "invalid_request", error_description: "challenge (a JWS) required" };
    return;
  }
  if (!opts.resourceTxnJwks || !opts.txnKey || !opts.txnKid || !opts.ars) {
    ctx.status = 501;
    ctx.body = { error: "transaction_authorization_unsupported" };
    return;
  }

  // 3. Validate the challenge against the resource's txn-challenge keys.
  let claims;
  try {
    claims = await validateChallenge(challenge, opts.resourceTxnJwks, opts.issuer);
  } catch {
    ctx.status = 400;
    ctx.body = { error: "invalid_challenge" };
    return;
  }
  if (!claims.parameter_digest) {
    ctx.status = 400;
    ctx.body = { error: "invalid_challenge", error_description: "parameter_digest required" };
    return;
  }
  const requested = claims.authorization_details as AuthorityEntry[];

  // 4. D42 subset gate: the requested authority MUST be within the ACTIVE
  // Mission. Widening is not an AROP case (that is the separate Expansion flow).
  const record = kernel.get(missionId);
  if (!record) {
    ctx.status = 404;
    ctx.body = { error: "unknown_mission" };
    return;
  }
  const active = kernel.applyExpiry(record);
  if (active.state !== "active") {
    ctx.status = 403;
    ctx.body = { error: "mission_not_active" };
    return;
  }
  if (!isSubsetSet(requested, active.authority_set)) {
    ctx.status = 403;
    ctx.body = { error: "out_of_authority" };
    return;
  }

  // 5. Approval, idempotent by txn. First call opens an AS-vouched ARS task;
  // subsequent calls poll it.
  const existing = txnTasks.get(claims.txn);
  if (!existing) {
    const action = requested[0]?.actions?.[0] ?? claims.reason;
    const { taskId } = opts.ars.openForTxn({
      txn: claims.txn,
      missionId,
      action,
      parameter_digest: claims.parameter_digest,
      subject,
    });
    txnTasks.set(claims.txn, taskId);
    ctx.status = 200;
    ctx.body = { status: "authorization_pending", txn: claims.txn };
    return;
  }
  const task = opts.ars.getTask(existing);
  if (!task || task.state !== "approved" || !task.approval) {
    ctx.status = 200;
    ctx.body = { status: "authorization_pending", txn: claims.txn };
    return;
  }

  // 6. Approved: gate a derivation on the active Mission and issue the
  // txn-bound single-use token carrying the ACTIVE Mission unchanged (D42).
  const approval = task.approval;
  let gated;
  try {
    gated = kernel.gateDerivation(missionId);
  } catch (e) {
    if (e instanceof GateError) {
      ctx.status = 403;
      ctx.body = { error: "mission_not_active", error_description: e.message };
      return;
    }
    throw e;
  }
  const token = await issueTxnToken({
    txn: claims.txn,
    audience: claims.iss, // the resource
    mission: kernel.missionClaim(gated),
    authorizationDetails: requested,
    approval: {
      id: approval.id,
      approved_at: approval.approved_at,
      approved_until: approval.approved_until,
      parameter_digest: approval.parameter_digest,
    },
    approvedUntil: approval.approved_until,
    cnfJkt: cnf.jkt,
    key: opts.txnKey,
    kid: opts.txnKid,
    issuer: opts.issuer,
  });
  ctx.status = 200;
  ctx.body = { access_token: token, token_type: "DPoP", txn: claims.txn };
}

async function decide(
  provider: Provider,
  opts: AdapterOptions,
  ctx: KoaCtx,
  body: Record<string, unknown>,
) {
  const details = await provider.interactionDetails(ctx.req, ctx.res);
  const params = details.params as Record<string, unknown>;
  const intent = opts.kernel.validateIntent(String(params.mission_intent));
  const approver = String(body.approver ?? "");
  const subject = String(body.subject ?? approver);

  if (body.decision !== "approve") {
    await provider.interactionFinished(ctx.req, ctx.res, {
      error: "access_denied",
      error_description: "approver denied the mission",
    });
    return;
  }

  const authority = opts.kernel.derive(intent);
  // Governance (D37): write-bearing missions require subject != approver
  // with the approver role; read-only may self-approve.
  const writeBearing = authority.some((e) => e.actions.some((a) => WRITE_ACTIONS.has(a)));
  if (writeBearing && (approver === subject || !opts.approverRoleSubs.has(approver))) {
    ctx.status = 403;
    ctx.body = { error: "approval_forbidden", error_description: "write-bearing missions require a distinct approver" };
    return;
  }

  const record = opts.kernel.approve({
    intent: intent as MissionIntent,
    subject: { iss: opts.issuer, sub: subject },
    approver: { iss: opts.issuer, sub: approver },
    clientId: String(params.client_id),
    approvalEventId: `apev_${details.uid}`,
  });

  const grant = new provider.Grant({ accountId: subject, clientId: String(params.client_id) });
  // Grant exactly the requested scopes (openid enables an id_token when asked).
  grant.addOIDCScope(typeof params.scope === "string" ? params.scope : "payments");
  const resource = record.authority_set[0]?.resource ?? opts.issuer;
  grant.addResourceScope(resource, "payments");
  for (const entry of record.authority_set) {
    (grant as unknown as { addRar: (d: unknown) => void }).addRar(entry);
  }
  const grantId = await grant.save();
  opts.kernel.bindGrant(record.id, grantId);

  await provider.interactionFinished(ctx.req, ctx.res, {
    login: { accountId: subject },
    consent: { grantId },
  });
}

function renderApprovalPage(uid: string, intent: unknown, authority: unknown): string {
  return `<!doctype html><title>Mission approval</title>
<h1>Approve mission?</h1>
<h2>Intent (proposal, untrusted)</h2><pre>${escapeHtml(JSON.stringify(intent, null, 2))}</pre>
<h2>Derived authority (what approval grants)</h2><pre>${escapeHtml(JSON.stringify(authority, null, 2))}</pre>
<form method="post" action="/interaction/${uid}/decide" enctype="application/json">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button></form>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function optional<T>(key: string, value: T | undefined): Record<string, T> {
  return value === undefined ? {} : { [key]: value };
}

function str(v: string | string[] | undefined): string | undefined {
  return typeof v === "string" ? v : undefined;
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return Object.fromEntries(new URLSearchParams(text));
  }
}
