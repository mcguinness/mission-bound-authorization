/**
 * @spec mission#approval-authentication (#1320, D496): the approval
 * surface's Approver login, as an OpenID Connect relying party to an
 * upstream OpenID Provider.
 *
 * The Approver's user agent starts the login for one approval interaction.
 * This AS sends it to the provider with an authorization code request
 * (PKCE `S256`, `state`, `nonce`, `prompt=login`), bound to that user agent
 * by a cookie of its own. At the callback it exchanges the code at the
 * provider's token endpoint and validates the ID Token as OpenID Connect
 * Core 1.0 Section
 * 3.1.3.7 requires: the signature against the provider's published keys
 * under the registered algorithm, `iss` exactly the provider's issuer, `aud`
 * exactly this client, `azp` if present, `exp`, `iat` and `nonce`. It then
 * maps the issuer-qualified identity (`iss` and `sub`) to a local Approver
 * through the configured mapping, never by an equal `sub`, and records the
 * login for that interaction with the token's `acr` and `auth_time`
 * (`ApprovalSessionStore.establish`). Nothing about the login comes from
 * configuration or from the request.
 *
 * Whether that login is strong and fresh enough is not decided here: the
 * published approval-authentication floor evaluates the recorded context at
 * the approval decision (`evaluateApprovalFloor`), so a password-only login
 * still approves authority the floor does not cover.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTPayload } from "jose";
import type { ApprovalPrincipal } from "./approval-resolution.js";

/**
 * The prefix of each started login's user-agent binding cookie. Every login
 * has a cookie of its own, named from its `state` ({@link loginCookieName})
 * and scoped to the callback, so logins in flight in one user agent never
 * replace one another's binding.
 */
export const APPROVER_LOGIN_COOKIE = "mission_approver_login";
/** The redirect URI path this AS registers at the provider. */
export const APPROVER_LOGIN_CALLBACK_PATH = "/approver-login/callback";

/** One upstream identity this AS maps to one of its local Approvers. */
export interface ApproverIdentityMapping {
  /** The provider's issuer identifier. */
  iss: string;
  /** The provider's subject identifier for the account. */
  sub: string;
  /** The local Approver (`sub` in this AS's principal namespace). */
  approver: string;
}

/** The deployment's configuration of the upstream login. */
export interface ApproverLoginOptions {
  /** The provider's issuer identifier; its metadata is read from `/.well-known/openid-configuration` under it. */
  issuer: string;
  /** This AS's client registration at the provider, authenticated `client_secret_basic`. */
  clientId: string;
  clientSecret: string;
  /** The ID Token signing algorithms accepted: the registration's `id_token_signed_response_alg`. */
  idTokenSigningAlgs: readonly string[];
  /** The issuer-qualified identities mapped to local Approvers. An identity not listed logs no one in. */
  identities: readonly ApproverIdentityMapping[];
  /** `acr_values` requested at the provider (voluntary, OIDC Core 3.1.2.1). The floor still decides. */
  acrValues?: readonly string[];
  /** How long a started login may take to return to the callback, in seconds. Default 300. */
  loginLifetimeSeconds?: number;
  /** The oldest ID Token `iat` accepted at the callback, in seconds. Default 120. */
  maxIdTokenAgeSeconds?: number;
  /** Clock skew tolerated on `exp` and `iat`, in seconds. Default 5. */
  clockToleranceSeconds?: number;
}

/** A refused login: no approval session is recorded. */
export class ApproverLoginError extends Error {}

interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  authorization_response_iss_parameter_supported?: boolean;
}

interface StartedLogin {
  uid: string;
  subject?: string;
  nonce: string;
  verifier: string;
  binding: string;
  expires: number;
}

const random = (): string => randomBytes(32).toString("base64url");

/** The binding cookie's name for the login that sent `state`. */
export const loginCookieName = (state: string): string =>
  `${APPROVER_LOGIN_COOKIE}_${createHash("sha256").update(state).digest("base64url").slice(0, 22)}`;

const sameSecret = (a: string, b: string): boolean => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

const cookieValue = (header: string, name: string): string | undefined => {
  const values = header
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.startsWith(`${name}=`))
    .map((s) => s.slice(name.length + 1));
  return values.length === 1 ? values[0] : undefined;
};

/** A single-valued query parameter, or undefined when absent or repeated. */
const single = (query: Record<string, string | string[] | undefined>, name: string): string | undefined => {
  const v = query[name];
  return typeof v === "string" ? v : undefined;
};

/**
 * The relying party. One per AS; its started logins are in memory and are
 * lost at restart, like the approval sessions they lead to.
 */
export class ApproverLoginRelyingParty {
  private readonly started = new Map<string, StartedLogin>();
  private metadata: Promise<ProviderMetadata> | undefined;
  private jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
  readonly redirectUri: string;

  constructor(
    private readonly opts: ApproverLoginOptions,
    asIssuer: string,
    private readonly now: () => number = () => Date.now(),
  ) {
    if (!opts.issuer || !opts.clientId || !opts.clientSecret || opts.idTokenSigningAlgs.length === 0) {
      throw new Error("the approver login needs a provider issuer, a client registration and its ID Token algorithms");
    }
    this.redirectUri = `${asIssuer}${APPROVER_LOGIN_CALLBACK_PATH}`;
  }

  /** The provider's metadata, read once; its `issuer` must be the configured one (OIDC Discovery 4.3). */
  private providerMetadata(): Promise<ProviderMetadata> {
    this.metadata ??= (async () => {
      const res = await fetch(`${this.opts.issuer}/.well-known/openid-configuration`);
      if (!res.ok) throw new Error(`the approver login provider's metadata is unavailable: ${res.status}`);
      const meta = (await res.json()) as ProviderMetadata;
      if (meta.issuer !== this.opts.issuer) {
        throw new Error("the approver login provider's metadata names another issuer");
      }
      for (const member of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
        if (typeof meta[member] !== "string") throw new Error(`the approver login provider's metadata has no ${member}`);
      }
      this.jwks = createRemoteJWKSet(new URL(meta.jwks_uri));
      return meta;
    })().catch((e: unknown) => {
      this.metadata = undefined;
      throw e;
    });
    return this.metadata;
  }

  /**
   * Start a login for approval interaction `uid`, with the Subject the
   * Approver selects for an approval on another principal's behalf. Returns
   * the provider's authorization URL and this login's own user-agent binding
   * cookie, which only the callback receives and which lives no longer than
   * the login may take.
   */
  async start(uid: string, subject: string | undefined): Promise<{ location: string; cookie: string }> {
    const meta = await this.providerMetadata();
    const now = this.now();
    for (const [state, login] of this.started) if (login.expires <= now) this.started.delete(state);
    const lifetime = this.opts.loginLifetimeSeconds ?? 300;
    const binding = random();
    const state = random();
    const nonce = random();
    const verifier = random();
    this.started.set(state, {
      uid,
      ...(subject ? { subject } : {}),
      nonce,
      verifier,
      binding,
      expires: now + lifetime * 1000,
    });
    const url = new URL(meta.authorization_endpoint);
    const params: Record<string, string> = {
      response_type: "code",
      client_id: this.opts.clientId,
      redirect_uri: this.redirectUri,
      scope: "openid",
      state,
      nonce,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      // An approval asks for an authentication now, never an earlier session.
      prompt: "login",
      ...(this.opts.acrValues?.length ? { acr_values: this.opts.acrValues.join(" ") } : {}),
    };
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    return {
      location: url.toString(),
      cookie: `${loginCookieName(state)}=${binding}; Path=${APPROVER_LOGIN_CALLBACK_PATH}; Max-Age=${lifetime}; HttpOnly; SameSite=Lax`,
    };
  }

  /**
   * Complete a login at the callback: the authorization response in `query`,
   * in the user agent that started it. Returns the interaction and the
   * Approver's achieved context from the validated ID Token; throws
   * {@link ApproverLoginError} for any refusal. A started login completes
   * at most once.
   */
  async complete(
    query: Record<string, string | string[] | undefined>,
    cookieHeader: string,
  ): Promise<{ uid: string; principal: ApprovalPrincipal }> {
    const state = single(query, "state");
    const login = state ? this.started.get(state) : undefined;
    if (!state || !login) throw new ApproverLoginError("the login response names no login this server started");
    this.started.delete(state);
    if (login.expires <= this.now()) throw new ApproverLoginError("the login took too long; start it again");
    const binding = cookieValue(cookieHeader, loginCookieName(state));
    if (!binding || !sameSecret(binding, login.binding)) {
      throw new ApproverLoginError("the login returned to a user agent other than the one that started it");
    }
    const meta = await this.providerMetadata();
    // RFC 9207: the authorization response names its issuer.
    const responseIss = single(query, "iss");
    if (meta.authorization_response_iss_parameter_supported === true || query.iss !== undefined) {
      if (responseIss !== this.opts.issuer) throw new ApproverLoginError("the login response comes from another issuer");
    }
    const error = single(query, "error");
    if (error !== undefined) throw new ApproverLoginError(`the provider refused the login: ${error}`);
    const code = single(query, "code");
    if (!code) throw new ApproverLoginError("the login response carries no code");

    const res = await fetch(meta.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(
          `${encodeURIComponent(this.opts.clientId)}:${encodeURIComponent(this.opts.clientSecret)}`,
        ).toString("base64")}`,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: this.redirectUri,
        code_verifier: login.verifier,
      }).toString(),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new ApproverLoginError(`the provider refused the code exchange: ${String(body.error ?? res.status)}`);
    if (typeof body.id_token !== "string") throw new ApproverLoginError("the provider returned no ID Token");

    const claims = await this.validateIdToken(body.id_token, login.nonce);
    const mapped = this.opts.identities.find((i) => i.iss === claims.iss && i.sub === claims.sub);
    if (!mapped) throw new ApproverLoginError("the provider's identity is not mapped to an Approver here");
    return {
      uid: login.uid,
      principal: {
        sub: mapped.approver,
        acr: claims.acr as string,
        auth_time: claims.auth_time as number,
        ...(login.subject ? { subject: login.subject } : {}),
      },
    };
  }

  /** OpenID Connect Core 1.0 Section 3.1.3.7, for the code flow. */
  private async validateIdToken(idToken: string, nonce: string): Promise<JWTPayload> {
    if (!this.jwks) throw new ApproverLoginError("the provider's keys are not known");
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(idToken, this.jwks, {
        issuer: this.opts.issuer,
        audience: this.opts.clientId,
        algorithms: [...this.opts.idTokenSigningAlgs],
        requiredClaims: ["sub", "exp", "iat", "nonce", "acr", "auth_time"],
        maxTokenAge: this.opts.maxIdTokenAgeSeconds ?? 120,
        clockTolerance: this.opts.clockToleranceSeconds ?? 5,
        currentDate: new Date(this.now()),
      }));
    } catch (e) {
      if (e instanceof joseErrors.JWTClaimValidationFailed || e instanceof joseErrors.JWTExpired) {
        throw new ApproverLoginError(`the ID Token's ${e.claim} claim is not valid: ${e.message}`);
      }
      if (e instanceof joseErrors.JOSEError) {
        throw new ApproverLoginError(`the ID Token does not verify against the provider's keys: ${e.message}`);
      }
      throw e;
    }
    // Step 3: no audience but this client; step 5: `azp`, if present, is this client.
    if (Array.isArray(payload.aud) && payload.aud.length !== 1) {
      throw new ApproverLoginError("the ID Token names an audience other than this client");
    }
    if (payload.azp !== undefined && payload.azp !== this.opts.clientId) {
      throw new ApproverLoginError("the ID Token's azp is not this client");
    }
    // Step 11: the nonce this login sent.
    if (typeof payload.nonce !== "string" || !sameSecret(payload.nonce, nonce)) {
      throw new ApproverLoginError("the ID Token's nonce is not this login's");
    }
    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      throw new ApproverLoginError("the ID Token's sub claim is not valid");
    }
    if (typeof payload.acr !== "string" || payload.acr.length === 0) {
      throw new ApproverLoginError("the ID Token's acr claim is not valid");
    }
    if (!Number.isSafeInteger(payload.auth_time) || (payload.auth_time as number) < 0) {
      throw new ApproverLoginError("the ID Token's auth_time claim is not valid");
    }
    return payload;
  }
}
