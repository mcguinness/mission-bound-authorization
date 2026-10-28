/**
 * An AAuth Resource for PS authorization access (three-party): it has no
 * access server, accepts identity and consent from whichever PS issued the
 * person token it verified, and applies its own policy (a scope per
 * operation) to the auth token that PS returns.
 *
 * - A request without a verified person token or auth token is answered
 *   401 `requirement=person-token`; one with a person token, or with an
 *   auth token whose scope falls short, is answered 401
 *   `requirement=auth-token` with a resource token that names the token
 *   presented and copies its `mission_s256` (aauth#section-6.4,
 *   aauth#section-6.5, aauth#section-6.7.1).
 * - An auth token whose scope covers the operation runs it, and the run is
 *   appended to the effect log. Nothing else does.
 * - Every signature, key and token check is `@mission/aauth-wire`'s; a
 *   failure is 401 with Signature-Error (aauth#section-11.3.4).
 * - A PS revokes the person tokens and auth tokens it issued at the
 *   revocation endpoint, with a request it signs as a server under the
 *   `jwks_uri` scheme naming `{jti, exp}` (aauth#section-11.12.1). A
 *   revoked token presented afterwards is refused with `revoked_jwt`
 *   (aauth#section-11.12.5).
 *
 * State: the revoked set is durable SQLite (`SqliteRevocationStore`), kept
 * until each entry's `exp`. The effect log, person records, resource
 * tokens issued, the replay cache, the per-issuer revocation rate and the
 * operations' data are held in memory and lost on restart. Deferred (202)
 * delivery, interaction, session tokens and accounts are not implemented.
 *
 * Pinned to draft-hardt-oauth-aauth-protocol-11 (src/SPEC_VERSIONS.md).
 */
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  BODY_COMPONENTS,
  generateSigningKey,
  InMemoryReplayCache,
  type JwksResolver,
  mintToken,
  type ReplayCache,
  SignatureError,
  type SigningKey,
  type VerifiedRequest,
  type VerifiedToken,
  verifyRequest,
} from "@mission/aauth-wire";
import { type Parameters, serializeDictionary, Token } from "structured-headers";
import type { ResourceConfig, ResourceOperation } from "./config.js";
import type { RevocationStore } from "./revocations.js";

export {
  ConfigError,
  DEFAULT_REVOCATION_LIMITS,
  loadResourceConfig,
  parseResourceConfig,
  type ResourceConfig,
  type ResourceOperation,
  type RevocationLimits,
} from "./config.js";
export {
  type AdmitOutcome,
  type RevocationEntry,
  type RevocationStore,
  SqliteRevocationStore,
} from "./revocations.js";

export interface ResourceOptions {
  config: ResourceConfig;
  /**
   * Resolves the keys of the agent, person and auth tokens presented here.
   * Its egress admission decides which issuers can be reached.
   */
  resolver: JwksResolver;
  /** Default: generated at boot with the configured `kid` and `alg`. */
  key?: SigningKey & { kid: string };
  /** Milliseconds since the epoch. */
  now?: () => number;
  /** Default: in memory, one window of entries (aauth#section-11.3.4.2). */
  replayCache?: ReplayCache;
  /**
   * The revoked set, durable: `new SqliteRevocationStore(file)` on a file
   * the deployment names. Its lifetime is the caller's.
   */
  revocations: RevocationStore;
}

/** A person, keyed by the token's (iss, sub) (aauth#section-7.1.4, aauth#section-13.7). */
export interface PersonRecord {
  id: number;
  iss: string;
  sub: string;
}

/** One operation that ran. */
export interface Effect {
  seq: number;
  /** `METHOD /path`. */
  operation: string;
  /** The person record the run was for. */
  person: number;
  iss: string;
  sub: string;
  tenant?: unknown;
  mission_s256?: unknown;
  /** The `jti` of the auth token that authorized the run. */
  authJti: string;
  scope: string;
  at: number;
}

export interface IssuedResourceToken {
  token: string;
  claims: Record<string, unknown>;
  /** `METHOD /path` of the request that produced it. */
  route: string;
}

export interface Resource {
  identifier: string;
  config: ResourceConfig;
  key: SigningKey & { kid: string };
  handler(req: IncomingMessage, res: ServerResponse): Promise<void>;
  readonly effects: readonly Effect[];
  readonly issuedResourceTokens: readonly IssuedResourceToken[];
  readonly persons: readonly PersonRecord[];
  readonly revocations: RevocationStore;
  metadata(): Record<string, unknown>;
}

const JWKS_PATH = "/.well-known/jwks.json";
const METADATA_PATH = "/.well-known/aauth-resource.json";
const AUTHORIZE_PATH = "/authorize";
/** The revocation endpoint's path, published as `revocation_endpoint`. */
export const REVOCATION_PATH = "/revoke";
/** A PS signs in its own right under its `aauth-person.json` document (aauth#section-11.3.2). */
const PERSON_SERVER_DOCUMENT = "aauth-person.json";
const MAX_BODY = 64 * 1024;
/** A space-delimited list of scope values (aauth#section-11.10, RFC 6749 Section 3.3). */
const SCOPE_LIST = /^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$/;

/** A refusal with an error code, answered as problem details (aauth#section-11.9.2). */
class Problem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(`${code}: ${detail}`);
  }
}

/**
 * The AAuth-Requirement field: a Dictionary whose `requirement` member is
 * a Token, with the requirement's data as its parameters.
 *
 * @spec aauth#section-11.6.1
 */
export function requirementField(requirement: string, params: Record<string, string> = {}): string {
  const parameters: Parameters = new Map(Object.entries(params));
  return serializeDictionary(new Map([["requirement", [new Token(requirement), parameters]]]));
}

export interface ResourceTokenInput {
  /** The resource's identifier, `iss`. */
  issuer: string;
  /** The verified person token or auth token the request presented. */
  presented: VerifiedToken;
  /** Thumbprint of the key that signed the request. */
  agentJkt: string;
  scope: string;
  /** Milliseconds since the epoch. */
  now: number;
  lifetimeSeconds: number;
}

/**
 * The claims of a resource token for three-party access. `ps`, `sub` and
 * `presented_jti` come from the token the request presented: `ps` is a
 * person token's `iss` or an auth token's `ps`. `aud` is that PS, the
 * party that redeems the token. `mission_s256` and `tenant` are copied
 * unchanged when the presented token carries them. Exported so a test can
 * build a token a faulty resource would issue, by editing these claims.
 *
 * @spec aauth#section-6.7
 * @spec aauth#section-6.7.1
 * @spec mission-aauth#ref-propagation
 */
export function buildResourceTokenClaims(input: ResourceTokenInput): Record<string, unknown> {
  const { presented } = input;
  if (presented.typ !== "aa-person+jwt" && presented.typ !== "aa-auth+jwt") {
    throw new TypeError("a resource token names a presented person token or auth token");
  }
  const p = presented.payload;
  const ps = presented.typ === "aa-person+jwt" ? p.iss : p.ps;
  const iat = Math.floor(input.now / 1000);
  const claims: Record<string, unknown> = {
    iss: input.issuer,
    dwk: "aauth-resource.json",
    aud: ps,
    ps,
    sub: p.sub,
    presented_jti: p.jti,
    agent_jkt: input.agentJkt,
    scope: input.scope,
    jti: randomUUID(),
    iat,
    exp: iat + input.lifetimeSeconds,
  };
  // @spec aauth#section-6.7.1: REQUIRED when the presented token carried one, copied unchanged.
  if (p.mission_s256 !== undefined) claims.mission_s256 = p.mission_s256;
  if (p.tenant !== undefined) claims.tenant = p.tenant;
  return claims;
}

/** Sign resource token claims with the resource's key. */
export function mintResourceToken(
  key: SigningKey & { kid: string },
  claims: Record<string, unknown>,
): Promise<string> {
  return mintToken("aa-resource+jwt", claims, key);
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Problem(413, "invalid_request", "the request body is too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function send(
  res: ServerResponse,
  status: number,
  body?: unknown,
  headers: Record<string, string> = {},
): void {
  if (body === undefined) {
    res.writeHead(status, headers);
    res.end();
    return;
  }
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

const problem = (
  res: ServerResponse,
  status: number,
  error: string,
  detail: string,
  headers = {},
) =>
  send(res, status, { error, detail }, { "content-type": "application/problem+json", ...headers });

function parseJsonObject(req: IncomingMessage, body: Buffer): Record<string, unknown> {
  const type = (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") {
    throw new Problem(400, "invalid_request", "Content-Type is not application/json");
  }
  let value: unknown;
  try {
    value = JSON.parse(body.toString("utf8"));
  } catch {
    throw new Problem(400, "invalid_request", "the body is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Problem(400, "invalid_request", "the body is not a JSON object");
  }
  return value as Record<string, unknown>;
}

const scopesOf = (value: unknown): string[] =>
  typeof value === "string" ? value.split(" ").filter((s) => s !== "") : [];

/**
 * Build the Resource. Its `handler` serves the metadata document, the
 * JWKS, the authorization endpoint and the configured operations.
 */
export function createResource(options: ResourceOptions): Resource {
  const { config, resolver } = options;
  const identifier = config.issuer;
  const identifierHost = new URL(identifier).hostname;
  const now = options.now ?? Date.now;
  const key = options.key ?? {
    ...generateSigningKey(config.signingKey.alg, config.signingKey.kid),
    kid: config.signingKey.kid,
  };
  const replayCache = options.replayCache ?? new InMemoryReplayCache();
  const effects: Effect[] = [];
  const issued: IssuedResourceToken[] = [];
  const persons: PersonRecord[] = [];
  const personIndex = new Map<string, PersonRecord>();
  const data = new Map<string, Map<number, unknown[]>>();

  const { revocations } = options;
  /** Per issuer: the current one-minute window's start and its request count. */
  const revocationRate = new Map<string, { windowStart: number; count: number }>();

  const metadata = (): Record<string, unknown> => ({
    issuer: identifier,
    jwks_uri: `${identifier}${JWKS_PATH}`,
    name: config.name,
    access_mode: "auth-token",
    authorization_endpoint: `${identifier}${AUTHORIZE_PATH}`,
    revocation_endpoint: `${identifier}${REVOCATION_PATH}`,
    scope_descriptions: config.scopeDescriptions,
    signature_window: config.signatureWindowSeconds,
  });

  /**
   * The request's authority must be this resource's host. The signature
   * base is built from the resource's identifier, never from the Host
   * field, so a request signed for another authority does not verify here
   * either way.
   */
  function hostMatches(host: string | undefined): boolean {
    if (host === undefined) return false;
    try {
      return new URL(`http://${host}`).hostname === identifierHost;
    } catch {
      return false;
    }
  }

  function headersOf(req: IncomingMessage): Record<string, string[]> {
    const headers: Record<string, string[]> = {};
    for (const [name, value] of Object.entries(req.headersDistinct)) {
      if (value) headers[name] = value;
    }
    return headers;
  }

  /**
   * Verify a signed request: undefined when it carries no signature at
   * all. A request with a body must cover Content-Digest and Content-Type.
   * Agent, person and auth tokens are accepted in Signature-Key, a person
   * or auth token naming this resource in `aud`. A person or auth token
   * its issuer has revoked here is refused once the request verifies.
   *
   * @spec aauth#section-11.3.4
   */
  async function authenticate(
    req: IncomingMessage,
    target: string,
    body: Buffer,
  ): Promise<VerifiedRequest | undefined> {
    const headers = headersOf(req);
    if (!headers.signature && !headers["signature-input"] && !headers["signature-key"]) {
      return undefined;
    }
    const verified = await verifyRequest(
      { method: req.method ?? "GET", url: `${identifier}${target}`, headers, body },
      {
        resolver,
        acceptedTokenTypes: ["aa-agent+jwt", "aa-person+jwt", "aa-auth+jwt"],
        audience: identifier,
        requireBodyComponents: true,
        replayCache,
        windowSeconds: config.signatureWindowSeconds,
        now,
      },
    );
    refuseRevoked(verified.token);
    return verified;
  }

  /**
   * A person token or auth token its issuer revoked here: 401 with
   * `Signature-Error: error=revoked_jwt`, never a resource token naming
   * it. A revoked auth token also carries `requirement=person-token`, not
   * `requirement=auth-token`. Agent tokens are revoked at the PS only, so
   * none is held here. The revoked set is keyed by `(iss, jti)`.
   *
   * @spec aauth#section-11.12.2
   * @spec aauth#section-11.12.4
   * @spec aauth#section-11.12.5
   */
  function refuseRevoked(token: VerifiedToken | undefined): void {
    if (!token || token.typ === "aa-agent+jwt") return;
    const { iss, jti } = token.payload as { iss: string; jti: string };
    if (!revocations.isRevoked(iss, jti, now())) return;
    const kind = token.typ === "aa-person+jwt" ? "person token" : "auth token";
    const refusal = new SignatureError("revoked_jwt", `the ${kind} was revoked by its issuer`);
    if (token.typ === "aa-auth+jwt") {
      refusal.headers["aauth-requirement"] = requirementField("person-token");
    }
    throw refusal;
  }

  /**
   * The revocation endpoint. The caller signs as a server under the
   * `jwks_uri` scheme, covering Content-Digest and Content-Type; the
   * issuer is the identity the signature verified, never a request
   * member. Only a PS (`dwk` `aauth-person.json`) issues the tokens this
   * Resource accepts, so any other caller is `unsupported_iss`. Each
   * issuer is bounded in rate and in entries (`rate_limited` with
   * Retry-After). The pair is committed before the answer: 200 with no
   * body, since nothing is downstream of a resource; never 202. A repeat
   * records nothing new and is answered 200.
   *
   * The replay cache keys on the covered Content-Digest as well as the
   * request tuple of aauth#section-11.3.4.2: a PS revoking two tokens here
   * in one second sends two bodies, which the tuple alone would collide;
   * a byte-identical replay still collides.
   *
   * @spec aauth#section-11.12
   * @spec aauth#section-11.12.1
   * @spec aauth#section-11.12.3
   */
  async function revoke(req: IncomingMessage, res: ServerResponse, target: string): Promise<void> {
    const body = await readBody(req);
    const headers = headersOf(req);
    const digest = (headers["content-digest"] ?? []).join(", ");
    const verified = await verifyRequest(
      { method: "POST", url: `${identifier}${target}`, headers, body },
      {
        resolver,
        acceptedSchemes: ["jwks_uri"],
        // Covered on every revocation request, whether or not it carries a body.
        additionalComponents: BODY_COMPONENTS,
        replayCache: {
          checkAndRecord: (key, expiresAtMs, nowMs) =>
            replayCache.checkAndRecord(JSON.stringify([key, digest]), expiresAtMs, nowMs),
        },
        windowSeconds: config.signatureWindowSeconds,
        now,
      },
    );
    const signer = verified.signer as NonNullable<VerifiedRequest["signer"]>;
    if (signer.dwk !== PERSON_SERVER_DOCUMENT) {
      throw new Problem(403, "unsupported_iss", "this resource accepts revocations from a PS only");
    }
    const iss = signer.id;
    limitRate(iss);
    const params = parseJsonObject(req, body);
    const { jti, exp } = params;
    if (typeof jti !== "string" || jti === "") {
      throw new Problem(400, "invalid_request", "jti is missing or is not a string");
    }
    if (typeof exp !== "number" || !Number.isSafeInteger(exp) || exp < 1) {
      throw new Problem(400, "invalid_request", "exp is missing or is not a NumericDate");
    }
    const nowMs = now();
    revocations.purge(nowMs);
    const outcome = revocations.admit(
      { iss, jti, exp, recordedAt: Math.floor(nowMs / 1000) },
      nowMs,
      config.revocationLimits.entriesPerIssuer,
    );
    if (outcome.kind === "full") {
      throw new Problem(429, "rate_limited", "this issuer holds its bound of revocations", {
        "retry-after": String(outcome.retryAfterSeconds),
      });
    }
    send(res, 200);
  }

  /**
   * At most the configured number of revocation requests per issuer in
   * each one-minute window; beyond it, `rate_limited` with Retry-After
   * (REQUIRED) naming the seconds until the window turns.
   *
   * @spec aauth#section-11.12.3
   */
  function limitRate(iss: string): void {
    const nowMs = now();
    const windowStart = nowMs - (nowMs % 60_000);
    let rate = revocationRate.get(iss);
    if (!rate || rate.windowStart !== windowStart) {
      rate = { windowStart, count: 0 };
      revocationRate.set(iss, rate);
    }
    if (rate.count >= config.revocationLimits.requestsPerIssuerPerMinute) {
      const retryAfter = Math.ceil((windowStart + 60_000 - nowMs) / 1000);
      throw new Problem(429, "rate_limited", "too many revocations from this issuer", {
        "retry-after": String(Math.max(1, retryAfter)),
      });
    }
    rate.count += 1;
  }

  /** @spec aauth#section-6.4 */
  function challengePersonToken(res: ServerResponse): void {
    send(res, 401, undefined, { "aauth-requirement": requirementField("person-token") });
  }

  /** @spec aauth#section-6.5 */
  async function challengeAuthToken(
    res: ServerResponse,
    verified: VerifiedRequest,
    scope: string,
    route: string,
  ): Promise<void> {
    const token = await issueResourceToken(verified, scope, route);
    send(res, 401, undefined, {
      "aauth-requirement": requirementField("auth-token", { "resource-token": token }),
    });
  }

  async function issueResourceToken(
    verified: VerifiedRequest,
    scope: string,
    route: string,
  ): Promise<string> {
    const claims = buildResourceTokenClaims({
      issuer: identifier,
      presented: verified.token as VerifiedToken,
      agentJkt: verified.thumbprint,
      scope,
      now: now(),
      lifetimeSeconds: config.resourceTokenLifetimeSeconds,
    });
    const token = await mintResourceToken(key, claims);
    issued.push({ token, claims, route });
    return token;
  }

  /**
   * The record for (iss, sub), established on first sight. A `sub` is
   * unique only within its issuer, so the same value under another issuer
   * is another person.
   *
   * @spec aauth#section-7.1.4
   * @spec aauth#section-9.4.3.2
   * @spec aauth#section-13.7
   */
  function personFor(iss: string, sub: string): PersonRecord {
    const recordKey = JSON.stringify([iss, sub]);
    let record = personIndex.get(recordKey);
    if (!record) {
      record = { id: persons.length + 1, iss, sub };
      persons.push(record);
      personIndex.set(recordKey, record);
    }
    return record;
  }

  /**
   * Run an operation for a person: a GET lists the person's items at the
   * path, a POST appends `{ title }`. Input is checked before anything
   * runs, so a refused input leaves no effect.
   */
  function run(
    op: ResourceOperation,
    person: PersonRecord,
    req: IncomingMessage,
    body: Buffer,
  ): { status: number; result: unknown } {
    let byPerson = data.get(op.path);
    if (!byPerson) {
      byPerson = new Map();
      data.set(op.path, byPerson);
    }
    const items = byPerson.get(person.id) ?? [];
    if (op.method === "GET") return { status: 200, result: { items } };
    const input = parseJsonObject(req, body);
    const title = input.title;
    if (typeof title !== "string" || title.length === 0 || title.length > 200) {
      throw new Problem(400, "invalid_request", "title is not a string of 1 to 200 characters");
    }
    const item = { id: randomUUID(), title };
    byPerson.set(person.id, [...items, item]);
    return { status: 201, result: item };
  }

  /**
   * A protected operation. An agent token, or no signature, is challenged
   * for a person token; a person token is challenged for an auth token,
   * never served (aauth#section-13.11); an auth token runs the operation
   * when its scope covers it, and is challenged again (step-up) when not.
   *
   * @spec aauth#section-6.5
   * @spec aauth#section-9.4.3
   * @spec aauth#section-13.7
   */
  async function operate(
    req: IncomingMessage,
    res: ServerResponse,
    target: string,
    op: ResourceOperation,
  ): Promise<void> {
    const route = `${op.method} ${op.path}`;
    const body = await readBody(req);
    const verified = await authenticate(req, target, body);
    const token = verified?.token;
    if (!verified || !token || token.typ === "aa-agent+jwt") {
      challengePersonToken(res);
      return;
    }
    if (token.typ === "aa-person+jwt") {
      await challengeAuthToken(res, verified, op.scope, route);
      return;
    }
    const claims = token.payload;
    // A resource with no access server accepts auth tokens from a PS only:
    // a PS-issued auth token names its issuer in `ps` (aauth#section-9.4.1).
    if (claims.iss !== claims.ps) {
      throw new SignatureError("invalid_jwt", "this resource has no access server");
    }
    const person = personFor(claims.iss as string, claims.sub as string);
    const granted = scopesOf(claims.scope);
    if (!granted.includes(op.scope)) {
      // @spec aauth#section-6.5: a step-up resource token names the auth token presented.
      const defined = granted.filter((s) => s in config.scopeDescriptions);
      await challengeAuthToken(
        res,
        verified,
        [...new Set([...defined, op.scope])].join(" "),
        route,
      );
      return;
    }
    const { status, result } = run(op, person, req, body);
    const effect: Effect = {
      seq: effects.length + 1,
      operation: route,
      person: person.id,
      iss: person.iss,
      sub: person.sub,
      authJti: claims.jti as string,
      scope: op.scope,
      at: now(),
    };
    if (claims.tenant !== undefined) effect.tenant = claims.tenant;
    if (claims.mission_s256 !== undefined) effect.mission_s256 = claims.mission_s256;
    effects.push(effect);
    send(res, status, result);
  }

  /**
   * The authorization endpoint: a person token is required (otherwise the
   * request is challenged for one), `scope` names values this resource
   * defines, and the answer is a resource token.
   *
   * @spec aauth#section-6.6
   * @spec aauth#section-6.6.2
   * @spec aauth#section-6.6.3
   */
  async function authorize(
    req: IncomingMessage,
    res: ServerResponse,
    target: string,
  ): Promise<void> {
    const body = await readBody(req);
    const verified = await authenticate(req, target, body);
    if (!verified || verified.token?.typ !== "aa-person+jwt") {
      challengePersonToken(res);
      return;
    }
    const params = parseJsonObject(req, body);
    if (typeof params.scope !== "string" || !SCOPE_LIST.test(params.scope)) {
      throw new Problem(400, "invalid_request", "scope is not a space-delimited list of values");
    }
    const requested = [...new Set(params.scope.split(" "))];
    const unknown = requested.filter((s) => !(s in config.scopeDescriptions));
    if (unknown.length > 0) {
      throw new Problem(400, "invalid_scope", `scope ${unknown.join(" ")} is not defined here`);
    }
    // @spec aauth#section-11.11: this resource holds no accounts, so none is held by the person.
    if (params.account !== undefined) {
      throw new Problem(400, "invalid_account", "this resource holds no accounts");
    }
    const token = await issueResourceToken(verified, requested.join(" "), `POST ${AUTHORIZE_PATH}`);
    send(res, 200, { resource_token: token });
  }

  async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const target = req.url ?? "/";
      const path = target.split("?")[0] ?? "/";
      const method = req.method ?? "GET";
      if (!hostMatches(req.headers.host)) {
        throw new Problem(421, "invalid_request", "the request is not for this resource");
      }
      if (method === "GET" && path === METADATA_PATH) return send(res, 200, metadata());
      if (method === "GET" && path === JWKS_PATH) return send(res, 200, { keys: [key.publicJwk] });
      if (method === "POST" && path === AUTHORIZE_PATH) return await authorize(req, res, target);
      if (method === "POST" && path === REVOCATION_PATH) return await revoke(req, res, target);
      const op = config.operations.find((o) => o.method === method && o.path === path);
      if (op) return await operate(req, res, target, op);
      throw new Problem(404, "not_found", `no operation ${method} ${path}`);
    } catch (err) {
      if (err instanceof SignatureError) {
        problem(res, err.status, err.code, err.detail, err.headers);
      } else if (err instanceof Problem) {
        problem(res, err.status, err.code, err.detail, err.headers);
      } else {
        problem(res, 500, "server_error", "internal error");
      }
    }
  }

  return {
    identifier,
    config,
    key,
    handler,
    effects,
    issuedResourceTokens: issued,
    persons,
    revocations,
    metadata,
  };
}

/** Listen with `handler` on `port` (default ephemeral) of `host` (default 127.0.0.1). */
export function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void> | void,
  options: { port?: number; host?: string } = {},
): Promise<Server> {
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, options.host ?? "127.0.0.1", () => resolve(server));
  });
}
