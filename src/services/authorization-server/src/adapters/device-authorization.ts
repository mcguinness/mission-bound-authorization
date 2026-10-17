/**
 * @spec device-authorization (#1202): the reference AS side of Mission Device
 * Authorization, built on oidc-provider 9.10.0's RFC 8628 device flow
 * (`features.deviceFlow`): its device authorization endpoint, client
 * authentication, `user_code` entry and confirmation, interaction hand-off and
 * `device_code` grant. Opt-in behind the `device-authorization` capability
 * (D412). This module holds the pieces that do not need the provider's
 * closures: the request intake, the session helpers and the inert pages.
 *
 * Library facts this relies on (oidc-provider 9.10.0):
 *
 * - The device authorization endpoint refuses any `authorization_details`
 *   (lib/actions/authorization/unsupported_rar.js), before the `extraParams`
 *   validators run (lib/actions/authorization/index.js, `unsupportedRar`
 *   before `checkExtraParams`). The intake below lifts the proposal off the
 *   form before the provider parses it, and the `mission_intent` validator
 *   restores it, so the device code stores the whole submission.
 * - The provider's body parser accepts an already-read form body from
 *   `ctx.request.body` (lib/shared/selective_body.js, its fallback for a
 *   request stream that is no longer readable).
 * - Its `device_code` grant checks the client (lib/actions/grants/
 *   device_code.js L56), then expiry (L67), then whether the code is still
 *   pending, which it is until its `accountId` or `error` is set (L71), then
 *   consumption (L75), and mints from the code's `grantId`.
 */

import type { IncomingMessage } from "node:http";
import { parse as parseForm } from "node:querystring";
import { type KoaContextWithOIDC, type Provider } from "oidc-provider";

/** The RFC 8628 grant type. */
export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

/**
 * The `gty` oidc-provider records on the access token its `device_code` grant
 * mints (lib/actions/grants/device_code.js 9.10.0, `export const gty`). A
 * refresh of that lineage carries `device_code refresh_token`.
 */
export const DEVICE_CODE_GTY = "device_code";

/** oidc-provider 9.10.0's default device authorization route. */
export const DEVICE_AUTHORIZATION_PATH = "/device/auth";

/** The `user_code` template (RFC 8628 Section 6.1: 8 base-20 characters). */
export const DEVICE_USER_CODE_MASK = "****-****";

/** The form body bound the provider itself applies (lib/shared/selective_body.js). */
const MAX_FORM_BYTES = 56 * 1024;

/**
 * The provider's router is neither case-sensitive nor strict about a trailing
 * slash, so the intake recognizes the route the way the router does.
 */
function isDeviceAuthorizationPath(path: string): boolean {
  return path.replace(/\/+$/, "").toLowerCase() === DEVICE_AUTHORIZATION_PATH;
}

/** What the intake lifted off one device authorization request. */
export interface DeviceIntake {
  /** The submitted `authorization_details` proposal, when one was sent. */
  proposal?: string;
}

const intakes = new WeakMap<IncomingMessage, DeviceIntake>();

/**
 * @spec device-authorization#request: the intake for a device authorization
 * request carrying `mission_intent`, run before oidc-provider parses it:
 *
 * - a request that also carries `request` or `request_uri` is refused
 *   `invalid_request` and no code is issued (the provider would otherwise
 *   answer `request_not_supported` or `request_uri_not_supported`);
 * - a repeated `authorization_details` is refused `invalid_request`;
 * - the proposal is lifted off the form for the `mission_intent` validator to
 *   restore after client authentication ({@link takeDeviceIntake}).
 *
 * A request without `mission_intent` passes through unchanged; the validator
 * refuses it, so this endpoint never yields an ordinary device grant.
 */
export async function deviceAuthorizationIntake(ctx: KoaContextWithOIDC, next: () => Promise<void>): Promise<void> {
  if (ctx.method !== "POST" || !isDeviceAuthorizationPath(ctx.path) || !ctx.is("application/x-www-form-urlencoded")) {
    return next();
  }
  const raw = await readForm(ctx.req);
  if (raw === undefined) {
    refuse(ctx, "the request body is too large");
    return;
  }
  const form = parseForm(raw);
  if (form.mission_intent !== undefined) {
    if (form.request !== undefined || form.request_uri !== undefined) {
      refuse(ctx, "mission_intent travels only as a form parameter, never with request or request_uri");
      return;
    }
    const proposal = form.authorization_details;
    if (Array.isArray(proposal)) {
      refuse(ctx, "authorization_details must not be repeated");
      return;
    }
    delete form.authorization_details;
    intakes.set(ctx.req, proposal ? { proposal } : {});
  }
  (ctx.request as unknown as { body?: unknown }).body = form;
  await next();
}

/**
 * The intake of this device authorization request, removed once read.
 * Undefined when the intake never saw the request: the caller refuses then,
 * so a route variant the intake did not recognize fails closed.
 */
export function takeDeviceIntake(req: IncomingMessage): DeviceIntake | undefined {
  const intake = intakes.get(req);
  intakes.delete(req);
  return intake;
}

function refuse(ctx: KoaContextWithOIDC, description: string): void {
  ctx.status = 400;
  ctx.set("cache-control", "no-store");
  ctx.body = { error: "invalid_request", error_description: description };
}

async function readForm(req: IncomingMessage): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer);
    size += buf.length;
    if (size > MAX_FORM_BYTES) return undefined;
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** The device code state a decision and a redemption read. */
export type DeviceSession = InstanceType<Provider["DeviceCode"]>;

/** The device code an interaction names, whatever its state. */
export async function loadDeviceSession(provider: Provider, jti: string): Promise<DeviceSession | undefined> {
  return provider.DeviceCode.find(jti, { ignoreExpiration: true });
}

/**
 * @spec device-authorization#approval: whether the session is still
 * pending. It exists, its `device_code` lifetime has not elapsed, and no
 * decision, abort or redemption has ended it.
 */
export function devicePending(code: DeviceSession | undefined): code is DeviceSession {
  return code !== undefined && !code.isExpired && !code.error && !code.accountId && !code.consumed;
}

/**
 * Sessions whose decision is committing. A decision claims its session in
 * the same synchronous step as the record commit, so two decisions over one
 * session (two tabs on one interaction) never both commit. In-process, like
 * the provider's memory adapter.
 */
const committing = new Set<string>();

/** Claim `jti` for a committing decision; false when one already holds it. */
export function claimDeviceDecision(jti: string): boolean {
  if (committing.has(jti)) return false;
  committing.add(jti);
  return true;
}

export function releaseDeviceDecision(jti: string): void {
  committing.delete(jti);
}

/** The normalized `user_code` in the form the device authorization response returned. */
export function formatUserCode(normalized: string): string {
  let i = 0;
  let out = "";
  for (const c of DEVICE_USER_CODE_MASK) {
    if (c === "*") out += normalized[i++] ?? "";
    else out += c;
  }
  return out + normalized.slice(i);
}

/** Inert text: every client-supplied or Intent-derived value passes through this. */
export function inert(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><title>${inert(title)}</title>\n<h1>${inert(title)}</h1>\n${body}`;
}

/** What the verification pages say about the requesting client. */
export interface DeviceClientView {
  clientId: string;
  /** A client-supplied display value (such as a registered `client_name`). */
  clientName?: string | undefined;
  /** The client authenticates at this AS; false for a public client. */
  authenticated: boolean;
}

/** The client view from AS-held registration data. */
export function deviceClientView(client: { clientId: string; clientName?: string | undefined; clientAuthMethod?: string | undefined }): DeviceClientView {
  return {
    clientId: client.clientId,
    ...(client.clientName ? { clientName: client.clientName } : {}),
    authenticated: client.clientAuthMethod !== undefined && client.clientAuthMethod !== "none",
  };
}

/**
 * @spec device-authorization#approval: the requesting client as the AS
 * holds it: its `client_id`, whether the AS authenticated it, and any
 * client-supplied display value as inert text.
 */
export function renderDeviceClient(view: DeviceClientView): string {
  const auth = view.authenticated
    ? "The authorization server authenticated this client."
    : "The authorization server did not authenticate this client: its client_id identifies it, but anyone can send it.";
  const name = view.clientName
    ? `<p>Display name (supplied by the client, unverified): <span class="client-name">${inert(view.clientName)}</span></p>`
    : "";
  return `<h2>Requesting client</h2><p>Client: <code>${inert(view.clientId)}</code></p>${name}<p class="client-authentication">${auth}</p>`;
}

/**
 * The oidc-provider device flow pages, all inert. The confirmation page shows
 * the code and the client before the interaction starts; the Mission
 * decision itself, with the code confirmation it requires, is the approval
 * interaction's.
 */
export function deviceFlowFeature(enabled: boolean) {
  return {
    enabled,
    charset: "base-20" as const,
    mask: DEVICE_USER_CODE_MASK,
    userCodeInputSource: (ctx: KoaContextWithOIDC, form: string, _out?: unknown, err?: unknown) => {
      const note = err ? "<p>The code was not accepted.</p>" : "<p>Enter the code your device displays.</p>";
      ctx.body = page("Device sign-in", `${note}${form}<button type="submit" form="op.deviceInputForm">Continue</button>`);
    },
    userCodeConfirmSource: (
      ctx: KoaContextWithOIDC,
      form: string,
      client: { clientId: string; clientName?: string | undefined; clientAuthMethod?: string | undefined },
      _deviceInfo: unknown,
      userCode: string,
    ) => {
      ctx.body = page(
        "Confirm the device code",
        `${renderDeviceClient(deviceClientView(client))}<p>Code: <code>${inert(userCode)}</code></p>` +
          "<p>Continue only if this code matches the one your device displays and you started this request. Entering a code does not sign you in.</p>" +
          `${form}<button type="submit" form="op.deviceConfirmForm">Continue</button>` +
          '<button type="submit" form="op.deviceConfirmForm" name="abort" value="yes">Abort</button>',
      );
    },
    successSource: (ctx: KoaContextWithOIDC) => {
      ctx.body = page("Done", "<p>You can close this page.</p>");
    },
  };
}

/** The verification user agent's page after a device decision. */
export function deviceDecisionPage(outcome: "approved" | "denied"): string {
  return outcome === "approved"
    ? page("Mission approved", "<p>The requesting device can now complete its request. You can close this page.</p>")
    : page("Mission not approved", "<p>No Mission was created. You can close this page.</p>");
}
