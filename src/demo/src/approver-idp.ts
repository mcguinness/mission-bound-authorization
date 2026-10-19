/**
 * @spec mission#approval-authentication (#1320, D496): the reference
 * upstream OpenID Provider the as-native target's approval surface logs its
 * Approver in through. It is a separate party from the authorization server:
 * its own `oidc-provider` instance, issuer, signing key and listener.
 *
 * It authenticates for real. A login needs the account's password, checked
 * against a salted scrypt hash, and the provider asserts `acr` from what that
 * authentication established, never from configuration: `pwd` when only the
 * password was verified, `mfa` only after the one-time code it delivered to
 * the account's enrolled device was entered correctly, once. `auth_time` is
 * the time the last verified factor completed. A wrong code is refused, and
 * the third wrong code ends the login.
 *
 * The device is a test-only channel: {@link CodeDevice} receives each code
 * the provider sends, as a phone would. Whoever holds the account's password
 * and its device is the Approver; the in-process approval console holds
 * Bob's, generated at each boot and never configured. It shows the reference
 * authentication exchange; it is not evidence of an independently deployed
 * possession factor.
 *
 * A deployment substitutes its own provider. The authorization server's side
 * (`approver-login.ts`) is unchanged by that substitution.
 */
import { randomBytes, randomInt, scryptSync, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair } from "jose";
import Provider, { type Configuration, type KoaContextWithOIDC } from "oidc-provider";

/** The authorization server's client registration at this provider. */
export const APPROVER_LOGIN_CLIENT_ID = "mission-approval-surface";
/** The `acr` values this provider asserts, weakest first. */
export const PASSWORD_ONLY_ACR = "pwd";
export const MULTI_FACTOR_ACR = "mfa";
/** A one-time code's lifetime and the wrong entries that end a login. */
const CODE_LIFETIME_MS = 120_000;
const MAX_CODE_ATTEMPTS = 3;

/**
 * An enrolled second-factor device: the test-only channel the provider
 * delivers one-time codes to. Only the device's holder reads them.
 */
export class CodeDevice {
  private readonly received: string[] = [];
  /** The provider's delivery. */
  deliver(code: string): void {
    this.received.push(code);
  }
  /** The most recent code delivered, as the device shows it. */
  latest(): string | undefined {
    return this.received.at(-1);
  }
}

/** An Approver account at the provider, and what its holder keeps. */
export interface ApproverAccount {
  /** The provider's subject identifier for the account (its ID Token `sub`). */
  sub: string;
  username: string;
  password: string;
  device: CodeDevice;
}

/** A login the provider completed: the factors it verified and the `acr` it asserted. */
export interface CompletedLogin {
  sub: string;
  factors: string[];
  acr: string;
  auth_time: number;
}

export interface ApproverIdp {
  /** This provider's issuer identifier. */
  issuer: string;
  /** The authorization server's client credentials (`client_secret_basic`). */
  client: { clientId: string; clientSecret: string };
  /** Each account by username. */
  accounts: ReadonlyMap<string, ApproverAccount>;
  /** Every login completed, in order. */
  logins: readonly CompletedLogin[];
  /** Close the listener; resolves once the port is released. */
  close: () => Promise<void>;
}

interface StoredAccount {
  sub: string;
  salt: Buffer;
  hash: Buffer;
  device: CodeDevice;
}

/** A login whose password is verified and whose second factor is pending. */
interface PendingFactor {
  sub: string;
  passwordAt: number;
  code: string;
  expires: number;
  attempts: number;
}

/** What this provider's interaction routes use of a request context. */
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  status: number;
  body: unknown;
  set: (name: string, value: string) => void;
}

const hashPassword = (password: string, salt: Buffer): Buffer => scryptSync(password, salt, 32);

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

const page = (title: string, body: string): string =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;

const passwordForm = (uid: string, error?: string): string =>
  page(
    "Sign in",
    `${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}<form method="post" action="/interaction/${uid}/password">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button>Continue</button></form>`,
  );

const codeForm = (uid: string, error?: string): string =>
  page(
    "Enter the code sent to your device",
    `${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}<form method="post" action="/interaction/${uid}/code">
<label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code"></label>
<button>Verify</button></form>
<form method="post" action="/interaction/${uid}/skip"><button>Continue without the second factor</button></form>`,
  );

/**
 * Start the provider on `port` (0: any free port) at `host`, with one account
 * per entry of `accounts` and the authorization server registered as its one
 * client at `redirectUri`. Each account's password and device are generated
 * here and returned to the caller, the accounts' holder.
 */
export async function startApproverIdp(opts: {
  redirectUri: string;
  accounts: readonly { sub: string; username: string }[];
  host?: string;
  port?: number;
}): Promise<ApproverIdp> {
  const host = opts.host ?? "127.0.0.1";
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, host, () => resolve());
  });
  const issuer = `http://${host}:${(server.address() as AddressInfo).port}`;

  const stored = new Map<string, StoredAccount>();
  const bySub = new Map<string, StoredAccount>();
  const accounts = new Map<string, ApproverAccount>();
  for (const a of opts.accounts) {
    const password = randomBytes(18).toString("base64url");
    const salt = randomBytes(16);
    const device = new CodeDevice();
    const account: StoredAccount = { sub: a.sub, salt, hash: hashPassword(password, salt), device };
    stored.set(a.username, account);
    bySub.set(a.sub, account);
    accounts.set(a.username, { sub: a.sub, username: a.username, password, device });
  }
  const logins: CompletedLogin[] = [];
  const pending = new Map<string, PendingFactor>();
  const clientSecret = randomBytes(32).toString("base64url");
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const signingKey = { ...(await exportJWK(privateKey)), kid: "approver-idp-1", alg: "ES256", use: "sig" };

  const configuration: Configuration = {
    clients: [
      {
        client_id: APPROVER_LOGIN_CLIENT_ID,
        client_secret: clientSecret,
        redirect_uris: [opts.redirectUri],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic",
        id_token_signed_response_alg: "ES256",
        require_auth_time: true,
      },
    ],
    jwks: { keys: [signingKey as never] },
    acrValues: [PASSWORD_ONLY_ACR, MULTI_FACTOR_ACR],
    scopes: ["openid"],
    responseTypes: ["code"],
    pkce: { required: () => true },
    features: { devInteractions: { enabled: false } },
    // Distinct names, so a user agent holding this provider's cookies and the
    // authorization server's (both oidc-provider) never mixes them.
    cookies: {
      names: { session: "_idp_session", interaction: "_idp_interaction", resume: "_idp_interaction_resume" },
      keys: [randomBytes(32).toString("base64url")],
    },
    interactions: { url: (_ctx: KoaContextWithOIDC, interaction) => `/interaction/${interaction.uid}` },
    findAccount: (_ctx, id) => (bySub.has(id) ? { accountId: id, claims: () => ({ sub: id }) } : undefined),
    // The authorization server is this provider's first-party client: its
    // `openid` request needs no consent screen.
    loadExistingGrant: async (ctx) => {
      const { client, session } = ctx.oidc;
      if (!client || !session?.accountId) return undefined;
      const existing = session.grantIdFor(client.clientId);
      if (existing) return ctx.oidc.provider.Grant.find(existing);
      const grant = new ctx.oidc.provider.Grant({ clientId: client.clientId, accountId: session.accountId });
      grant.addOIDCScope("openid");
      await grant.save();
      return grant;
    },
  };
  const provider = new Provider(issuer, configuration);

  const finishLogin = async (ctx: Ctx, sub: string, factors: string[], acr: string, at: number) => {
    logins.push({ sub, factors, acr, auth_time: at });
    await provider.interactionFinished(
      ctx.req,
      ctx.res,
      { login: { accountId: sub, acr, amr: factors, ts: at, remember: false } },
      { mergeWithLastSubmission: false },
    );
  };
  const html = (ctx: Ctx, status: number, body: string) => {
    ctx.status = status;
    ctx.set("content-type", "text/html; charset=utf-8");
    ctx.set("cache-control", "no-store");
    ctx.body = body;
  };

  provider.use(async (ctx, next) => {
    const m = /^\/interaction\/([^/]+)(?:\/(password|code|skip))?$/.exec(ctx.path);
    if (!m) return next();
    const details = await provider.interactionDetails(ctx.req, ctx.res).catch(() => undefined);
    const uid = m[1] as string;
    if (!details || details.uid !== uid) {
      html(ctx, 400, page("Sign-in expired", "<p>Start again from the application.</p>"));
      return;
    }
    if (details.prompt.name !== "login") {
      await provider.interactionFinished(
        ctx.req,
        ctx.res,
        { error: "access_denied", error_description: "this provider serves only a login" },
        { mergeWithLastSubmission: false },
      );
      return;
    }
    const step = m[2];
    if (step === undefined && ctx.method === "GET") {
      html(ctx, 200, passwordForm(uid));
      return;
    }
    if (ctx.method !== "POST") return next();
    const form = await readForm(ctx.req);
    if (step === "password") {
      const account = stored.get(form.get("username") ?? "");
      const presented = hashPassword(form.get("password") ?? "", account?.salt ?? randomBytes(16));
      if (!account || !timingSafeEqual(presented, account.hash)) {
        pending.delete(uid);
        html(ctx, 401, passwordForm(uid, "The username or password is not correct."));
        return;
      }
      const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
      pending.set(uid, {
        sub: account.sub,
        passwordAt: Math.floor(Date.now() / 1000),
        code,
        expires: Date.now() + CODE_LIFETIME_MS,
        attempts: 0,
      });
      account.device.deliver(code);
      html(ctx, 200, codeForm(uid));
      return;
    }
    const factor = pending.get(uid);
    if (!factor) {
      html(ctx, 401, passwordForm(uid, "Enter your password first."));
      return;
    }
    if (step === "skip") {
      pending.delete(uid);
      await finishLogin(ctx, factor.sub, ["pwd"], PASSWORD_ONLY_ACR, factor.passwordAt);
      return;
    }
    // step === "code": one verification per delivered code.
    const entered = Buffer.from(form.get("code") ?? "");
    const expected = Buffer.from(factor.code);
    if (Date.now() >= factor.expires) {
      pending.delete(uid);
      html(ctx, 401, passwordForm(uid, "The code expired. Sign in again."));
      return;
    }
    if (entered.length !== expected.length || !timingSafeEqual(entered, expected)) {
      factor.attempts += 1;
      if (factor.attempts >= MAX_CODE_ATTEMPTS) {
        pending.delete(uid);
        await provider.interactionFinished(
          ctx.req,
          ctx.res,
          { error: "access_denied", error_description: "too many wrong codes" },
          { mergeWithLastSubmission: false },
        );
        return;
      }
      html(ctx, 401, codeForm(uid, "The code is not correct."));
      return;
    }
    pending.delete(uid);
    await finishLogin(ctx, factor.sub, ["pwd", "otp"], MULTI_FACTOR_ACR, Math.floor(Date.now() / 1000));
  });

  server.on("request", provider.callback());
  return {
    issuer,
    client: { clientId: APPROVER_LOGIN_CLIENT_ID, clientSecret },
    accounts,
    logins,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
