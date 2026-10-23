/**
 * @spec authority-server#mission-join rule 8, authority-server#enterprise-prerequisites
 * (#818 slice 3; RFC 7662)
 *
 * The estate route's introspection adapter: an opaque (non-JWT) access token is
 * validated by RFC 7662 token introspection at the estate authorization
 * server, authenticated as the route's registered introspection client, and
 * the response's `sub`, `client_id`, `scope`, `aud`, `exp` and `cnf` become the
 * same facts the JWT path reads from a verified token.
 *
 * Fail-closed rules, each a refusal and never a fallback:
 *
 * - No answer (a timeout, a network error, a non-200 status, a body that is not
 *   a JSON object) throws {@link IntrospectionUnavailableError}: the route
 *   answers 503 and nothing reaches the PEP.
 * - An answer that does not make the token usable (`active` other than `true`,
 *   an `iss` other than the estate's, a non-access token type, an `exp` that
 *   has passed, a missing `sub`, `client_id`, `aud` or `cnf.jkt`) throws
 *   {@link TokenInactiveError}: the route answers 401.
 * - An active answer carrying a `mission` member throws
 *   {@link TokenInactiveError} too (@spec mission#rs-requirements item 6,
 *   #1503): the estate is not trusted to issue Mission-bound authorization
 *   here, so the member is refused, as a JWT `mission` claim is, never
 *   dropped to read the token as ordinary.
 *
 * A positive result is cached, keyed by the token's SHA-256, for at most
 * `cacheMaxSeconds` and never past the token's own `exp`; a negative result is
 * never cached. So a token revoked at the estate stops being accepted within
 * `cacheMaxSeconds` of its last successful introspection.
 */

import { createHash } from "node:crypto";

export interface IntrospectionSettings {
  /** The estate's RFC 7662 introspection endpoint. */
  endpoint: string;
  /** The route's introspection client, authenticated with `client_secret_basic`. */
  clientId: string;
  clientSecret: string;
  /** Upper bound on one introspection call, response body included, milliseconds. */
  timeoutMs: number;
  /** Upper bound on a positive cache entry's life, seconds; never past the token's `exp`. 0 caches nothing. */
  cacheMaxSeconds: number;
  /** Bound on the number of cached entries; the oldest is evicted first. Default 1000. */
  cacheMaxEntries?: number;
  /** The cache's clock. */
  now?: () => Date;
}

/** An introspected access token, as the route reads it. */
export interface IntrospectedToken {
  sub: string;
  clientId: string;
  scope?: string;
  aud: string[];
  /** NumericDate. */
  exp: number;
  iat?: number;
  cnfJkt: string;
}

/** The estate gave no usable answer: the route refuses with 503, never a permit. */
export class IntrospectionUnavailableError extends Error {
  constructor(why: string) {
    super(`token introspection unavailable: ${why}`);
    this.name = "IntrospectionUnavailableError";
  }
}

/**
 * @spec authority-server#join-assertion-request (#1454 review): the estate
 * answered with the RFC 7662 / RFC 6749 error `unsupported_token_type`, read
 * from the response's `error` member exactly: it offers no introspection for
 * this token's type. A subclass of the unavailable error, so a caller that
 * does not tell them apart (the gateway) still answers 503.
 */
export class IntrospectionTokenTypeUnsupportedError extends IntrospectionUnavailableError {
  constructor() {
    super("unsupported_token_type");
    this.name = "IntrospectionTokenTypeUnsupportedError";
  }
}

/** The estate answered and the token is not usable here: the route refuses with 401. */
export class TokenInactiveError extends Error {
  constructor(why: string) {
    super(`introspected token refused: ${why}`);
    this.name = "TokenInactiveError";
  }
}

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;

export class TokenIntrospector {
  private readonly cache = new Map<string, { token: IntrospectedToken; untilMs: number }>();
  private readonly now: () => Date;

  constructor(
    private readonly settings: IntrospectionSettings,
    /** The estate issuer: a response naming any other refuses. */
    private readonly issuer: string,
  ) {
    if (!(settings.timeoutMs > 0)) throw new Error("introspection timeoutMs must be positive");
    if (!(settings.cacheMaxSeconds >= 0)) throw new Error("introspection cacheMaxSeconds must not be negative");
    this.now = settings.now ?? (() => new Date());
  }

  /** This adapter's clock, for a caller that re-checks `exp` after its own awaits. */
  clock(): Date {
    return this.now();
  }

  async introspect(accessToken: string): Promise<IntrospectedToken> {
    const key = createHash("sha256").update(accessToken).digest("base64url");
    const nowMs = this.now().getTime();
    const cached = this.cache.get(key);
    if (cached && nowMs < cached.untilMs) return cached.token;
    this.cache.delete(key);

    const answer = await this.call(accessToken);
    // The clock is read again once the answer is in: a token that expired
    // while the call was in flight is refused, and the cache entry's life
    // starts from this reading (#1400 review).
    const answeredMs = this.now().getTime();
    const token = this.read(answer, answeredMs);
    const untilMs = Math.min(answeredMs + this.settings.cacheMaxSeconds * 1000, token.exp * 1000);
    if (untilMs > answeredMs) {
      if (this.cache.size >= (this.settings.cacheMaxEntries ?? 1000)) {
        const oldest = this.cache.keys().next().value;
        if (oldest !== undefined) this.cache.delete(oldest);
      }
      this.cache.set(key, { token, untilMs });
    }
    return token;
  }

  private async call(accessToken: string): Promise<Record<string, unknown>> {
    const credentials = Buffer.from(
      `${encodeURIComponent(this.settings.clientId)}:${encodeURIComponent(this.settings.clientSecret)}`,
    ).toString("base64");
    let body: unknown;
    try {
      const res = await fetch(this.settings.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
          authorization: `Basic ${credentials}`,
        },
        body: new URLSearchParams({ token: accessToken, token_type_hint: "access_token" }).toString(),
        signal: AbortSignal.timeout(this.settings.timeoutMs),
      });
      if (res.status !== 200) {
        const answer: unknown = await res.json().catch(() => undefined);
        const error = answer !== null && typeof answer === "object" ? (answer as { error?: unknown }).error : undefined;
        if (error === "unsupported_token_type") throw new IntrospectionTokenTypeUnsupportedError();
        throw new Error(`status ${res.status}`);
      }
      body = await res.json();
    } catch (e) {
      if (e instanceof IntrospectionTokenTypeUnsupportedError) throw e;
      throw new IntrospectionUnavailableError(e instanceof Error ? e.message : String(e));
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      throw new IntrospectionUnavailableError("the response is not a JSON object");
    }
    return body as Record<string, unknown>;
  }

  /** The usable token the response describes, or a refusal. */
  private read(r: Record<string, unknown>, nowMs: number): IntrospectedToken {
    if (r.active !== true) throw new TokenInactiveError("not active");
    if (r.iss !== undefined && r.iss !== this.issuer) throw new TokenInactiveError("issued by another issuer");
    if (r.mission !== undefined) throw new TokenInactiveError("carries a mission member, which this issuer is not trusted to issue");
    if (r.token_type !== undefined && (typeof r.token_type !== "string" || r.token_type.toLowerCase() !== "dpop")) {
      throw new TokenInactiveError("not a DPoP-bound access token");
    }
    if (typeof r.exp !== "number" || r.exp * 1000 <= nowMs) throw new TokenInactiveError("expired or without exp");
    if (!nonEmpty(r.sub) || !nonEmpty(r.client_id)) throw new TokenInactiveError("missing sub or client_id");
    const aud = typeof r.aud === "string" ? [r.aud] : r.aud;
    if (!Array.isArray(aud) || aud.length === 0 || !aud.every(nonEmpty)) throw new TokenInactiveError("missing aud");
    const jkt = (r.cnf as { jkt?: unknown } | undefined)?.jkt;
    if (!nonEmpty(jkt)) throw new TokenInactiveError("not sender-constrained (no cnf.jkt)");
    if (r.scope !== undefined && typeof r.scope !== "string") throw new TokenInactiveError("scope is not a string");
    return {
      sub: r.sub,
      clientId: r.client_id,
      ...(typeof r.scope === "string" ? { scope: r.scope } : {}),
      aud,
      exp: r.exp,
      ...(typeof r.iat === "number" ? { iat: r.iat } : {}),
      cnfJkt: jkt,
    };
  }
}
