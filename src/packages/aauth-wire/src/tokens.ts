import {
  compactVerify,
  decodeProtectedHeader,
  type JWTPayload,
  type ProtectedHeaderParameters,
} from "jose";
import { determineAlgorithm, isSupportedAlgorithm, type SupportedAlgorithm } from "./algorithms.js";
import { SignatureError } from "./errors.js";
import { isAgentIdentifier, isServerIdentifier } from "./identifiers.js";
import type { JwksResolver } from "./jwks.js";

export type AAuthTokenType = "aa-agent+jwt" | "aa-person+jwt" | "aa-resource+jwt" | "aa-auth+jwt";

export interface VerifiedToken {
  typ: AAuthTokenType;
  alg: SupportedAlgorithm;
  header: ProtectedHeaderParameters;
  payload: JWTPayload & Record<string, unknown>;
}

export interface TokenVerificationOptions {
  resolver: JwksResolver;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /**
   * Refuse a token whose `iat` is further ahead of this verifier's clock
   * than this many seconds (`clock_skew`). Unset applies no bound; when a
   * bound is applied it SHOULD be the signature window.
   */
  iatSkewSeconds?: number;
  /** Return true when the issuer has revoked this `jti` (`revoked_jwt`). */
  isRevoked?: (issuer: string, jti: string) => boolean | Promise<boolean>;
}

interface CommonRules {
  typ: AAuthTokenType;
  dwk: readonly string[];
  /** A MUST ceiling on `exp - iat`, in seconds. */
  maxLifetimeSeconds?: number;
}

const invalid = (detail: string) => new SignatureError("invalid_jwt", detail);

function decode(jwt: string): {
  header: ProtectedHeaderParameters;
  payload: Record<string, unknown>;
} {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw invalid("not a compact JWS");
  let header: ProtectedHeaderParameters;
  let payload: unknown;
  try {
    header = decodeProtectedHeader(jwt);
    payload = JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf8"));
  } catch {
    throw invalid("malformed JWT");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw invalid("JWT payload is not an object");
  }
  return { header, payload: payload as Record<string, unknown> };
}

/**
 * Common JWT verification for every AAuth token. Cheap checks come first,
 * so a wrong, expired or malformed token fails before any fetch or
 * signature operation: format, `typ`, header `alg` and `kid`, `exp` (no
 * skew tolerance), `iat` (present; the optional ahead-of-clock bound), the
 * lifetime ceiling, `dwk`, `iss` and `jti`. Then the issuer's key is
 * discovered through `{iss}/.well-known/{dwk}` and the signature verified;
 * a cached key that fails is refreshed once before `unknown_key` or
 * `invalid_jwt`. Revocation is checked last, for a token that verifies and
 * is unexpired.
 *
 * @spec aauth#section-11.5.2
 * @spec aauth#section-11.4
 * @spec signature-key#section-3.8
 */
async function verifyCommon(
  jwt: string,
  rules: CommonRules,
  options: TokenVerificationOptions,
): Promise<VerifiedToken> {
  const nowSeconds = (options.now ?? Date.now)() / 1000;
  const { header, payload } = decode(jwt);
  if (header.typ !== rules.typ)
    throw invalid(`typ is ${String(header.typ)}, expected ${rules.typ}`);
  // @spec aauth#section-11.5.1: none, EdDSA and symmetric algorithms are never accepted.
  if (!isSupportedAlgorithm(header.alg)) throw invalid(`alg ${String(header.alg)} is not accepted`);
  if (typeof header.kid !== "string") throw invalid("kid is missing");
  if (typeof payload.exp !== "number") throw invalid("exp is missing");
  if (payload.exp <= nowSeconds) throw new SignatureError("expired_jwt", "token has expired");
  if (typeof payload.iat !== "number") throw invalid("iat is missing");
  if (options.iatSkewSeconds !== undefined && payload.iat > nowSeconds + options.iatSkewSeconds) {
    throw new SignatureError("clock_skew", "iat is ahead of this verifier's clock");
  }
  if (
    rules.maxLifetimeSeconds !== undefined &&
    payload.exp - payload.iat > rules.maxLifetimeSeconds
  ) {
    throw invalid(`lifetime exceeds ${rules.maxLifetimeSeconds} seconds`);
  }
  if (typeof payload.dwk !== "string" || !rules.dwk.includes(payload.dwk)) {
    throw invalid(`dwk is ${String(payload.dwk)}, expected ${rules.dwk.join(" or ")}`);
  }
  if (!isServerIdentifier(payload.iss)) throw invalid("iss is not a server identifier");
  if (typeof payload.jti !== "string" || payload.jti === "") throw invalid("jti is missing");

  const { iss, dwk } = payload as { iss: string; dwk: string };
  const verifyWith = async (jwk: Record<string, unknown>): Promise<boolean> => {
    let determined: ReturnType<typeof determineAlgorithm>;
    try {
      determined = determineAlgorithm(jwk);
    } catch (err) {
      throw invalid(`issuer key is unusable (${(err as SignatureError).detail})`);
    }
    if (determined.alg !== header.alg) throw invalid("header alg disagrees with the issuer key");
    try {
      await compactVerify(jwt, determined.key, { algorithms: [header.alg as string] });
      return true;
    } catch {
      return false;
    }
  };
  const kid = header.kid;
  if (!(await verifyWith(await options.resolver.resolveKey(iss, dwk, kid)))) {
    const refreshed = await options.resolver.resolveKey(iss, dwk, kid, { refresh: true });
    if (!(await verifyWith(refreshed))) throw invalid("signature verification failed");
  }
  if (options.isRevoked && (await options.isRevoked(iss, payload.jti as string))) {
    throw new SignatureError("revoked_jwt", "token has been revoked");
  }
  return {
    typ: rules.typ,
    alg: header.alg as SupportedAlgorithm,
    header,
    payload: payload as JWTPayload & Record<string, unknown>,
  };
}

/**
 * `cnf.jwk` is required, structurally complete for its key type and
 * carries a fully-specified `alg` agreeing with it. A failure keeps the
 * key's own code (`invalid_key`, `unsupported_algorithm`), which a
 * Signature-Key path answers as is and a parameter path maps.
 *
 * @spec aauth#section-9.4.3.2
 * @spec aauth#section-11.5.1
 */
function requireCnfJwk(payload: Record<string, unknown>): void {
  const cnf = payload.cnf as { jwk?: unknown } | undefined;
  if (typeof cnf !== "object" || cnf === null || typeof cnf.jwk !== "object" || cnf.jwk === null) {
    throw invalid("cnf.jwk is missing");
  }
  determineAlgorithm(cnf.jwk);
}

function requireAudience(payload: Record<string, unknown>, audience: string): void {
  if (payload.aud !== audience) throw invalid("aud does not name this recipient");
}

function requireSub(payload: Record<string, unknown>): void {
  if (typeof payload.sub !== "string" || payload.sub === "") throw invalid("sub is missing");
}

/**
 * An agent token (`aa-agent+jwt`, `dwk` `aauth-agent.json`). The caller
 * checks that `cnf.jwk` is the key that signed the request.
 *
 * @spec aauth#section-5.3.1
 * @spec aauth#section-5.3.3
 */
export async function verifyAgentToken(
  jwt: string,
  options: TokenVerificationOptions,
): Promise<VerifiedToken> {
  const token = await verifyCommon(
    jwt,
    { typ: "aa-agent+jwt", dwk: ["aauth-agent.json"] },
    options,
  );
  const { payload } = token;
  if (!isAgentIdentifier(payload.sub)) throw invalid("sub is not an agent identifier");
  // @spec aauth#section-5.1, aauth#section-11.2.1: an AP is named in both the
  // domain of the identifiers it assigns and the iss of the tokens it signs.
  const domain = payload.sub.slice(payload.sub.lastIndexOf("@") + 1);
  if (payload.iss !== `https://${domain}`) {
    throw invalid("sub names an agent of another agent provider");
  }
  requireCnfJwk(payload);
  if (payload.ps !== undefined && !isServerIdentifier(payload.ps)) {
    throw invalid("ps is not a server identifier");
  }
  if (payload.parent_agent !== undefined && !isAgentIdentifier(payload.parent_agent)) {
    throw invalid("parent_agent is not an agent identifier");
  }
  return token;
}

/**
 * A person token (`aa-person+jwt`, `dwk` `aauth-person.json`), verified by
 * the resource named in `aud`. At most one hour; no `scope` or `account`.
 *
 * @spec aauth#section-7.1.2
 * @spec aauth#section-7.1.4
 */
export async function verifyPersonToken(
  jwt: string,
  options: TokenVerificationOptions & { audience: string },
): Promise<VerifiedToken> {
  const token = await verifyCommon(
    jwt,
    { typ: "aa-person+jwt", dwk: ["aauth-person.json"], maxLifetimeSeconds: 3600 },
    options,
  );
  const { payload } = token;
  requireAudience(payload, options.audience);
  requireSub(payload);
  requireCnfJwk(payload);
  if ("scope" in payload || "account" in payload) {
    throw invalid("a person token carries no scope or account");
  }
  return token;
}

/**
 * A resource token (`aa-resource+jwt`, `dwk` `aauth-resource.json`),
 * verified by the PS or AS named in `aud`. It carries `agent_jkt`, never
 * `cnf`. With `agentJkt`, the claim must equal the thumbprint of the key
 * that signed the token request.
 *
 * @spec aauth#section-6.7.1
 * @spec aauth#section-6.7.2 (steps 1 and 2)
 */
export async function verifyResourceToken(
  jwt: string,
  options: TokenVerificationOptions & { audience: string; agentJkt?: string },
): Promise<VerifiedToken> {
  const token = await verifyCommon(
    jwt,
    { typ: "aa-resource+jwt", dwk: ["aauth-resource.json"] },
    options,
  );
  const { payload } = token;
  requireAudience(payload, options.audience);
  if (!isServerIdentifier(payload.ps)) throw invalid("ps is not a server identifier");
  requireSub(payload);
  if (typeof payload.presented_jti !== "string" || payload.presented_jti === "") {
    throw invalid("presented_jti is missing");
  }
  if (typeof payload.agent_jkt !== "string" || payload.agent_jkt === "") {
    throw invalid("agent_jkt is missing");
  }
  if ("cnf" in payload) throw invalid("a resource token carries no cnf");
  if (options.agentJkt !== undefined && payload.agent_jkt !== options.agentJkt) {
    throw invalid("agent_jkt does not match the request's signing key");
  }
  return token;
}

/**
 * An auth token (`aa-auth+jwt`), from an AS (`dwk` `aauth-access.json`)
 * or a PS (`aauth-person.json`, where `ps` equals `iss`), verified by the
 * resource named in `aud`. At most one hour. A person token presented
 * where an auth token is required fails the `typ` check.
 *
 * @spec aauth#section-9.4.1
 * @spec aauth#section-9.4.3
 */
export async function verifyAuthToken(
  jwt: string,
  options: TokenVerificationOptions & { audience: string },
): Promise<VerifiedToken> {
  const token = await verifyCommon(
    jwt,
    {
      typ: "aa-auth+jwt",
      dwk: ["aauth-access.json", "aauth-person.json"],
      maxLifetimeSeconds: 3600,
    },
    options,
  );
  const { payload } = token;
  requireAudience(payload, options.audience);
  requireSub(payload);
  if (!isServerIdentifier(payload.ps)) throw invalid("ps is not a server identifier");
  if (payload.dwk === "aauth-person.json" && payload.ps !== payload.iss) {
    throw invalid("a PS-issued auth token names itself in ps");
  }
  requireCnfJwk(payload);
  return token;
}
