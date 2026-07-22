/**
 * Thin adapters over node-oidc-provider 9.10.0 (decision D30): the provider
 * and custom routes call the mission-kernel only through its interface.
 * Wiring facts verified by the pre-flight spike (src/spikes/SPIKE-REPORT.md).
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { DEV_SERVICE_TOKEN, WRITE_ACTIONS } from "@mission/demo-data";
import { createLocalJWKSet, jwtVerify } from "jose";
import Provider, { errors, type Configuration } from "oidc-provider";

// @types/oidc-provider (9.5) predates InvalidAuthorizationDetails, present at
// runtime in 9.10 (spec traceability: SPEC_VERSIONS O-2 note). Typed alias.
const InvalidAuthorizationDetails = (errors as unknown as {
  InvalidAuthorizationDetails: new (message?: string) => Error;
}).InvalidAuthorizationDetails;
import { IntentError } from "../kernel/intent.js";
import { GateError, LifecycleConflictError, type MissionKernel } from "../kernel/kernel.js";
import type { LifecycleOperation, MissionIntent } from "../kernel/types.js";

export interface AdapterOptions {
  issuer: string;
  kernel: MissionKernel;
  clients: Record<string, unknown>[];
  jwks: { keys: Record<string, unknown>[] };
  publicJwks: { keys: Record<string, unknown>[] };
  /** Test-only headless adjudication (D40): disabled unless set. */
  allowHeadlessAdjudication?: boolean;
  approverRoleSubs: Set<string>;
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
    scopes: ["payments"],
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
          accessTokenTTL: 300,
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

    await next();

    // --- AS metadata flags (@spec mission#as-metadata) ---
    if (ctx.path === "/.well-known/openid-configuration" && ctx.status === 200) {
      const meta = ctx.body as Record<string, unknown>;
      meta.mission_bound_authorization_supported = true;
      meta.introspection_endpoint = `${opts.issuer}/introspect`;
    }
  };
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
  grant.addOIDCScope("payments");
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
