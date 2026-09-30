/**
 * A plain OAuth 2.0 Resource Server: it validates RFC 9068 JWT access tokens
 * (and RFC 9449 DPoP proofs for sender-constrained ones) and authorizes each
 * operation on the token's `scope` claim alone. It reads no other claim for
 * authorization, knows nothing about how the Authorization Server decided
 * that scope, and depends on no package of this workspace.
 *
 * An optional introspection mode adds a per-request RFC 7662 call and honors
 * only the response's `active` member. Every request makes its own call (no
 * result is cached); the call authenticates with client_secret_basic and is
 * bounded by a timeout; an unreachable, slow, non-200 or non-object response
 * refuses 503 `temporarily_unavailable`, and an object whose `active` is not
 * the boolean `true` refuses 401 `invalid_token`, before any operation runs.
 */

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  type JSONWebKeySet,
  type JWK,
  type JWTPayload,
  jwtVerify,
} from "jose";

/** One protected operation and the scope value it requires. */
export interface Operation {
  method: string;
  /** Path relative to the server's base URL, exact match. */
  path: string;
  scope: string;
}

/** The operation table: the only authorization input is `scope`. */
export const OPERATIONS: readonly Operation[] = [
  { method: "GET", path: "/api/reports", scope: "reports.read" },
  { method: "POST", path: "/api/reports", scope: "reports.write" },
];

/** RFC 7662 introspection client settings (client_secret_basic). */
export interface IntrospectionSettings {
  endpoint: string;
  clientId: string;
  clientSecret: string;
  /**
   * Upper bound on one introspection call, response body included, in
   * milliseconds. Default {@link DEFAULT_INTROSPECTION_TIMEOUT_MS}.
   */
  timeoutMs?: number;
}

/**
 * Two seconds: long enough for an issuer on the same network (or a loaded
 * one) to answer, short enough that a stalled issuer fails the request fast
 * instead of holding the connection open. A timeout refuses service
 * (503 `temporarily_unavailable`); it never falls back to the JWT alone.
 */
export const DEFAULT_INTROSPECTION_TIMEOUT_MS = 2000;

export interface PlainRsOptions {
  /** The expected `iss`. */
  issuer: string;
  /** This server's audience identifier; the token's `aud` must contain it. */
  audience: string;
  /** The Authorization Server's JWKS, by URI or inline. One is required. */
  jwksUri?: string;
  jwks?: JSONWebKeySet;
  /**
   * The external base URL requests arrive at (scheme, host, port), used to
   * rebuild the DPoP `htu`. Defaults to the audience's origin.
   */
  baseUrl?: string;
  operations?: readonly Operation[];
  /** When set, every request is also introspected and must be `active`. */
  introspection?: IntrospectionSettings;
  /** Accepted token and proof signature algorithms (asymmetric only). */
  algorithms?: string[];
  /** Accepted DPoP proof age, in seconds, either side of now. Default 60. */
  dpopWindowSeconds?: number;
  /**
   * Accepted clock skew for the access token's `exp`, `nbf` and `iat`, in
   * seconds, as jose applies it: a token is refused once `exp <= now -
   * tolerance`. Default 0.
   */
  clockToleranceSeconds?: number;
  /** Clock, in seconds. Default: the system clock. */
  now?: () => number;
}

/** The request handler, with a count of operations it has performed. */
export interface PlainRsHandler {
  (req: IncomingMessage, res: ServerResponse): Promise<void>;
  /** Operations that ran (a request refused before its operation never counts). */
  readonly performed: number;
}

const DEFAULT_ALGS = ["RS256", "PS256", "ES256", "ES384", "EdDSA"];
/** RFC 7638 SHA-256 thumbprint, base64url without padding: 32 octets, 43 characters. */
const JWK_THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;

class Refusal extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly scheme: "Bearer" | "DPoP",
    readonly scope?: string,
  ) {
    super(message);
  }
}

const b64url = (buf: Buffer) => buf.toString("base64url");

/** Build the request handler for a plain Resource Server. */
export function plainResourceServer(opts: PlainRsOptions): PlainRsHandler {
  if (!opts.jwks && !opts.jwksUri) throw new Error("plain-rs: jwks or jwksUri is required");
  const keys = opts.jwks ? createLocalJWKSet(opts.jwks) : createRemoteJWKSet(new URL(opts.jwksUri as string));
  const operations = opts.operations ?? OPERATIONS;
  const algorithms = opts.algorithms ?? DEFAULT_ALGS;
  const baseUrl = (opts.baseUrl ?? new URL(opts.audience).origin).replace(/\/$/, "");
  const windowS = opts.dpopWindowSeconds ?? 60;
  const toleranceS = opts.clockToleranceSeconds ?? 0;
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  let performed = 0;
  /** RFC 9449 Section 11.1: proof `jti` values seen inside the window. */
  const seenProofs = new Map<string, number>();
  const reports: { id: string; title: string; created_by: string }[] = [];

  function freshJti(jti: string): boolean {
    const t = now();
    for (const [k, exp] of seenProofs) if (exp < t) seenProofs.delete(k);
    if (seenProofs.has(jti)) return false;
    seenProofs.set(jti, t + 2 * windowS);
    return true;
  }

  /** RFC 9068 Section 4 validation: typ, signature, iss, aud, exp and the required claims. */
  async function validateAccessToken(token: string, scheme: "Bearer" | "DPoP"): Promise<JWTPayload> {
    try {
      const { payload } = await jwtVerify(token, keys, {
        typ: "at+jwt",
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms,
        requiredClaims: ["exp", "iat", "sub", "client_id", "jti"],
        currentDate: new Date(now() * 1000),
        clockTolerance: toleranceS,
      });
      return payload;
    } catch {
      throw new Refusal(401, "invalid_token", "the access token is not valid for this resource", scheme);
    }
  }

  /**
   * RFC 7800 Section 3.1: a `cnf` claim names how the presenter proves
   * possession, and a Resource Server that cannot perform that proof cannot
   * accept the token. Absent: a bearer token. Present: the only method this
   * server verifies is RFC 9449 `jkt`, a base64url SHA-256 JWK thumbprint,
   * alone in the object. Any other shape (a certificate thumbprint, which
   * RFC 8705 Section 3 requires matching against the presented certificate,
   * another or an additional member, a malformed value) is refused, never
   * accepted as bearer.
   */
  function confirmationKey(payload: JWTPayload, scheme: "Bearer" | "DPoP"): string | undefined {
    const cnf = payload.cnf;
    if (cnf === undefined) return undefined;
    const members = cnf !== null && typeof cnf === "object" && !Array.isArray(cnf) ? Object.keys(cnf) : [];
    const jkt = members.length === 1 && members[0] === "jkt" ? (cnf as { jkt?: unknown }).jkt : undefined;
    if (typeof jkt !== "string" || !JWK_THUMBPRINT.test(jkt)) {
      throw new Refusal(401, "invalid_token", "unsupported or malformed confirmation method", scheme);
    }
    return jkt;
  }

  /** RFC 9449 Section 4.3 proof checks, bound to the token's `cnf.jkt`. */
  async function verifyDpop(req: IncomingMessage, token: string, jkt: string): Promise<void> {
    const header = req.headers.dpop;
    if (typeof header !== "string" || !header) {
      throw new Refusal(401, "invalid_dpop_proof", "a DPoP proof is required", "DPoP");
    }
    const fail = (why: string) => new Refusal(401, "invalid_dpop_proof", why, "DPoP");
    let jwk: JWK;
    let proof: JWTPayload;
    try {
      const protectedHeader = decodeProtectedHeader(header);
      jwk = protectedHeader.jwk as JWK;
      if (!jwk || typeof jwk !== "object" || "d" in jwk) throw new Error("jwk");
      ({ payload: proof } = await jwtVerify(header, jwk, { typ: "dpop+jwt", algorithms }));
    } catch {
      throw fail("the DPoP proof does not verify");
    }
    const path = (req.url ?? "/").split("?")[0] as string;
    if (proof.htm !== req.method || proof.htu !== `${baseUrl}${path}`) throw fail("htm or htu mismatch");
    if (typeof proof.iat !== "number" || Math.abs(now() - proof.iat) > windowS) throw fail("stale proof");
    const ath = b64url(createHash("sha256").update(token).digest());
    if (proof.ath !== ath) throw fail("ath does not match the access token");
    if ((await calculateJwkThumbprint(jwk)) !== jkt) throw fail("proof key does not match cnf.jkt");
    if (typeof proof.jti !== "string" || !freshJti(proof.jti)) throw fail("proof jti missing or replayed");
  }

  /**
   * RFC 7662, one fresh call per request: the only member honored is
   * `active`. Unavailable (network error, timeout, non-200) or malformed
   * (not JSON, or JSON that is not an object) refuses 503; an object whose
   * `active` is not the boolean `true` refuses 401. Nothing is cached.
   */
  async function introspectActive(token: string, scheme: "Bearer" | "DPoP"): Promise<void> {
    const settings = opts.introspection;
    if (!settings) return;
    const enc = (v: string) => encodeURIComponent(v).replace(/%20/g, "+");
    const unavailable = () =>
      new Refusal(503, "temporarily_unavailable", "token introspection is unavailable", scheme);
    let body: unknown;
    try {
      const res = await fetch(settings.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${Buffer.from(`${enc(settings.clientId)}:${enc(settings.clientSecret)}`).toString("base64")}`,
        },
        body: new URLSearchParams({ token, token_type_hint: "access_token" }).toString(),
        signal: AbortSignal.timeout(settings.timeoutMs ?? DEFAULT_INTROSPECTION_TIMEOUT_MS),
      });
      if (res.status !== 200) throw new Error(String(res.status));
      body = JSON.parse(await res.text()) as unknown;
    } catch {
      throw unavailable();
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw unavailable();
    if ((body as { active?: unknown }).active !== true) {
      throw new Refusal(401, "invalid_token", "the access token is not active", scheme);
    }
  }

  function challenge(r: Refusal): string {
    const params = [`error="${r.code}"`, `error_description="${r.message}"`];
    if (r.scope) params.push(`scope="${r.scope}"`);
    if (r.scheme === "DPoP") params.push(`algs="${algorithms.join(" ")}"`);
    return `${r.scheme} ${params.join(", ")}`;
  }

  async function authorize(req: IncomingMessage, op: Operation): Promise<JWTPayload> {
    const auth = req.headers.authorization ?? "";
    const m = /^(Bearer|DPoP) +([A-Za-z0-9._~+/-]+=*)$/i.exec(auth);
    if (!m) throw new Refusal(401, "invalid_request", "an access token is required", "Bearer");
    const scheme = (m[1] as string).toLowerCase() === "dpop" ? "DPoP" : "Bearer";
    const token = m[2] as string;
    const payload = await validateAccessToken(token, scheme);
    const jkt = confirmationKey(payload, scheme);
    if (jkt !== undefined) {
      // RFC 9449 Section 7.1: a sender-constrained token is presented under DPoP only.
      if (scheme !== "DPoP") {
        throw new Refusal(401, "invalid_token", "a DPoP-bound token requires the DPoP scheme", "DPoP");
      }
      await verifyDpop(req, token, jkt);
    } else if (scheme === "DPoP") {
      throw new Refusal(401, "invalid_token", "the token is not DPoP-bound", "DPoP");
    }
    await introspectActive(token, scheme);
    const granted = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
    if (!granted.includes(op.scope)) {
      throw new Refusal(403, "insufficient_scope", `the operation requires scope ${op.scope}`, scheme, op.scope);
    }
    return payload;
  }

  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
    res.end(JSON.stringify(body));
  }

  async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    if (!chunks.length) return {};
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  }

  const handle = async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? "/").split("?")[0];
    const op = operations.find((o) => o.method === req.method && o.path === path);
    if (!op) {
      send(res, 404, { error: "not_found" });
      return;
    }
    let payload: JWTPayload;
    try {
      payload = await authorize(req, op);
    } catch (e) {
      if (e instanceof Refusal) {
        send(res, e.status, { error: e.code, error_description: e.message }, { "www-authenticate": challenge(e) });
        return;
      }
      send(res, 500, { error: "server_error" });
      return;
    }
    if (op.scope === "reports.read") {
      performed += 1;
      send(res, 200, { reports });
      return;
    }
    let input: Record<string, unknown>;
    try {
      input = await readJson(req);
    } catch {
      send(res, 400, { error: "invalid_request" });
      return;
    }
    const report = {
      id: `rpt_${reports.length + 1}`,
      title: typeof input.title === "string" ? input.title : "untitled",
      created_by: String(payload.sub),
    };
    reports.push(report);
    performed += 1;
    send(res, 201, report);
  };
  return Object.defineProperty(handle, "performed", { get: () => performed }) as PlainRsHandler;
}

/** Start the Resource Server on `port`. */
export function startPlainResourceServer(opts: PlainRsOptions, port: number): Promise<Server> {
  const handle = plainResourceServer(opts);
  const server = createServer((req, res) => {
    void handle(req, res);
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}
