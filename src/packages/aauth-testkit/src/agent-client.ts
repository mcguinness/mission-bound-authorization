import { createHash } from "node:crypto";
import {
  type FetchJson,
  generateSigningKey,
  type JwksResolver,
  jwkThumbprint,
  type SigningKey,
  signRequest,
  type VerifiedToken,
  verifyAuthToken,
  verifyResourceToken,
} from "@mission/aauth-wire";
import { type BareItem, isInnerList, parseDictionary, Token } from "structured-headers";
import type { AgentProvider } from "./agent-provider.js";
import { type Clock, realSleep, type Sleep } from "./clock.js";
import type { LoopbackRequest, LoopbackResponse } from "./network.js";

/** Why the agent stopped. The client refuses rather than continue on a failed check. */
export type AgentErrorCode =
  /** The AAuth-Requirement field is malformed, or lacks the resource token. */
  | "challenge_invalid"
  /** A requirement or status this client does not satisfy (aauth#section-11.6.2). */
  | "requirement_unsupported"
  /** The resource asked again for a token the agent had just presented. */
  | "requirement_unsatisfiable"
  /** The resource token failed Section 6.7.3. */
  | "resource_token_invalid"
  /** The resource token's `mission_s256` is absent or different (the binding's agent rule). */
  | "mission_reference_mismatch"
  /** The auth token failed Section 9.4.4. */
  | "auth_token_invalid"
  /** A metadata document failed Section 11.2, or lacks an endpoint the client needs. */
  | "metadata_invalid"
  /** The PS or resource answered an error; `response` carries it. */
  | "refused"
  /** The approval envelope is malformed. */
  | "mission_invalid"
  /** `s256` is not the digest of the bytes `mission` decodes to. */
  | "mission_digest_mismatch"
  | "too_many_challenges";

export class AgentError extends Error {
  constructor(
    readonly code: AgentErrorCode,
    readonly detail: string,
    readonly response?: { status: number; body: unknown },
  ) {
    super(`${code}: ${detail}`);
    this.name = "AgentError";
  }
}

/**
 * Ways to make the agent misbehave for negative vectors. Each one changes
 * what the agent sends; none disables a check on the receiving side.
 */
export interface Misbehavior {
  /**
   * The `mission_s256` of a person-token request: omitted, malformed, or a
   * given value, in place of the agent's own mission.
   */
  missionReference?: "omit" | "malformed" | { value: string };
  /** Replace a challenge's resource token before anything else sees it. */
  interceptResourceToken?: (resourceToken: string) => string | Promise<string>;
  /**
   * Forward a resource token without the Section 6.7.3 checks and without
   * the binding's mission check, so a tampered token reaches the PS.
   */
  skipChallengeVerification?: boolean;
  /** Forward this as `presented_token` in place of the token presented. */
  presentedToken?: (presented: string) => string | Promise<string>;
}

export interface AgentTransport {
  request(message: LoopbackRequest): Promise<LoopbackResponse>;
  fetchJson: FetchJson;
}

export interface AgentClientOptions {
  transport: AgentTransport;
  /** Resolves the keys of resource tokens and auth tokens. */
  resolver: JwksResolver;
  key: SigningKey;
  agentToken: string;
  /** The agent's person server, as its agent token's `ps` names it. */
  ps: string;
  now?: Clock;
  sleep?: Sleep;
  misbehavior?: Misbehavior;
}

/** One request the agent sent. */
export interface SentRequest {
  method: string;
  url: string;
  /** The `typ` of the token presented in Signature-Key. */
  presented: string;
  body: unknown;
  status: number;
}

export interface MissionApproval {
  s256: string;
  /** The exact bytes `mission` decodes to, preserved as received. */
  blob: Buffer;
  personTokens: Record<string, string>;
  capabilities: unknown;
}

interface PersonServerMetadata {
  person_token_endpoint: string;
  auth_token_endpoint: string;
  mission_endpoint?: string;
}

/** Decode a JWT segment without verifying anything: for the agent's own tokens. */
function decodeSegment(jwt: string, index: 0 | 1): Record<string, unknown> {
  try {
    const value = JSON.parse(
      Buffer.from(jwt.split(".")[index] ?? "", "base64url").toString("utf8"),
    );
    return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export const decodeClaims = (jwt: string) => decodeSegment(jwt, 1);
export const tokenType = (jwt: string) => String(decodeSegment(jwt, 0).typ);

/** Unpadded base64url, decoded only when it re-encodes to the same text. */
function strictBase64url(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? bytes : undefined;
}

/** The AAuth-Requirement field: a Dictionary whose `requirement` member is a Token. */
export function parseRequirement(field: string): {
  requirement: string;
  params: Map<string, BareItem>;
} {
  let dict: ReturnType<typeof parseDictionary>;
  try {
    dict = parseDictionary(field);
  } catch {
    throw new AgentError("challenge_invalid", "AAuth-Requirement is not a Dictionary");
  }
  const member = dict.get("requirement");
  if (!member || isInnerList(member) || !(member[0] instanceof Token)) {
    throw new AgentError("challenge_invalid", "AAuth-Requirement has no requirement token");
  }
  return { requirement: member[0].toString(), params: member[1] };
}

const asBody = (res: LoopbackResponse): unknown => {
  try {
    return res.json();
  } catch {
    return res.text();
  }
};

const refused = (what: string, res: LoopbackResponse) =>
  new AgentError("refused", `${what} answered ${res.status}`, {
    status: res.status,
    body: asBody(res),
  });

/**
 * An AAuth agent. It signs every request with its key under the
 * Signature-Key `jwt` scheme, presenting its agent token, a person token
 * or an auth token; follows a resource's `person-token` and `auth-token`
 * requirements through its PS; and checks what it receives: the resource
 * token (Section 6.7.3, plus the binding's rule that a resource token
 * carries the agent's exact `mission_s256`), the auth token (Section
 * 9.4.4) and a mission approval's `s256` over the exact decoded bytes.
 *
 * Deferred (202) delivery and interaction are out of scope: the client
 * surfaces them as `requirement_unsupported`.
 *
 * @spec aauth#section-6.5
 * @spec aauth#section-6.7.3
 * @spec aauth#section-9.4.4
 * @spec aauth#section-11.3.3
 */
export class AgentClient {
  readonly key: SigningKey;
  readonly agentToken: string;
  readonly ps: string;
  readonly id: string;
  /** RFC 7638 thumbprint of the signing key, as a resource token's `agent_jkt`. */
  readonly thumbprint: string;
  readonly sent: SentRequest[] = [];
  misbehavior: Misbehavior;
  /** The mission the agent operates under, when it has one. */
  mission: { s256: string; blob?: Buffer } | undefined;

  private readonly transport: AgentTransport;
  private readonly resolver: JwksResolver;
  private readonly now: Clock;
  private readonly sleep: Sleep;
  private readonly personTokens = new Map<string, string>();
  private readonly authTokens = new Map<string, string>();
  private readonly lastCreated = new Map<string, number>();
  private psMetadata: PersonServerMetadata | undefined;

  constructor(options: AgentClientOptions & { thumbprint: string }) {
    this.transport = options.transport;
    this.resolver = options.resolver;
    this.key = options.key;
    this.agentToken = options.agentToken;
    this.ps = options.ps;
    this.thumbprint = options.thumbprint;
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? realSleep;
    this.misbehavior = options.misbehavior ?? {};
    this.id = String(decodeClaims(options.agentToken).sub);
  }

  /** Operate under `s256`, a mission the test knows was approved. */
  useMission(s256: string | undefined): void {
    this.mission = s256 === undefined ? undefined : { s256 };
  }

  /** The person token held for `resource` under the current mission. */
  personToken(resource: string): string | undefined {
    return this.personTokens.get(this.cacheKey(resource));
  }

  /** The auth token held for `resource` under the current mission. */
  authToken(resource: string): string | undefined {
    return this.authTokens.get(this.cacheKey(resource));
  }

  forget(resource: string): void {
    this.personTokens.delete(this.cacheKey(resource));
    this.authTokens.delete(this.cacheKey(resource));
  }

  private cacheKey(resource: string): string {
    return `${resource}\n${this.mission?.s256 ?? ""}`;
  }

  /**
   * The `created` for a request: the current second, waiting for the next
   * one when this agent already signed the same (method, authority, path)
   * in it. A verifier's replay cache keys on exactly that tuple and the
   * signing key (aauth#section-11.3.4.2), so a retry within one second of
   * the challenged request would otherwise be refused as a replay.
   */
  private async created(method: string, url: string): Promise<number> {
    const target = new URL(url);
    const tuple = `${method} ${target.host}${target.pathname}`;
    const last = this.lastCreated.get(tuple);
    let created = Math.floor(this.now() / 1000);
    while (last !== undefined && created <= last) {
      await this.sleep(1000 - (this.now() % 1000));
      created = Math.floor(this.now() / 1000);
    }
    this.lastCreated.set(tuple, created);
    return created;
  }

  /**
   * Send one signed request. `token` is presented under the `jwt` scheme
   * (default: the agent token). A body is JSON, and is covered with
   * Content-Digest and Content-Type.
   *
   * @spec aauth#section-11.3.3
   */
  async send(
    url: string,
    options: { method?: string; body?: unknown; token?: string } = {},
  ): Promise<LoopbackResponse> {
    const method = options.method ?? "GET";
    const token = options.token ?? this.agentToken;
    const bytes =
      options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body), "utf8");
    const headers: Record<string, string> = {};
    if (bytes) headers["content-type"] = "application/json";
    const signed = signRequest(
      { method, url, headers, body: bytes },
      {
        alg: this.key.alg,
        privateKey: this.key.privateKey,
        signatureKey: { scheme: "jwt", jwt: token },
        created: await this.created(method, url),
      },
    );
    const message: LoopbackRequest = { method, url, headers: { ...headers, ...signed } };
    if (bytes) message.body = bytes;
    const res = await this.transport.request(message);
    this.sent.push({
      method,
      url,
      presented: tokenType(token),
      body: options.body,
      status: res.status,
    });
    return res;
  }

  /**
   * The PS's metadata, whose `issuer` must be the PS identifier it was
   * fetched under.
   *
   * @spec aauth#section-11.2
   * @spec aauth#section-11.2.2
   */
  async personServer(): Promise<PersonServerMetadata> {
    if (this.psMetadata) return this.psMetadata;
    const { status, body } = await this.transport.fetchJson(
      `${this.ps}/.well-known/aauth-person.json`,
    );
    const doc = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    if (status !== 200) throw new AgentError("metadata_invalid", `PS metadata answered ${status}`);
    if (doc.issuer !== this.ps) {
      throw new AgentError("metadata_invalid", "PS metadata names another issuer");
    }
    if (
      typeof doc.person_token_endpoint !== "string" ||
      typeof doc.auth_token_endpoint !== "string"
    ) {
      throw new AgentError("metadata_invalid", "PS metadata lacks a token endpoint");
    }
    const metadata: PersonServerMetadata = {
      person_token_endpoint: doc.person_token_endpoint,
      auth_token_endpoint: doc.auth_token_endpoint,
    };
    if (typeof doc.mission_endpoint === "string") metadata.mission_endpoint = doc.mission_endpoint;
    this.psMetadata = metadata;
    return metadata;
  }

  /**
   * Propose a mission and, on approval, operate under it. The agent
   * verifies `s256` against the bytes `mission` decodes to before any use,
   * and keeps those bytes exactly (the binding's Native Reference rule; a
   * SHOULD in AAuth), and requires the blob's `agent` to be its own
   * identifier (the binding's approval procedure). A failed check changes
   * neither the mission nor the token cache.
   *
   * @spec aauth#section-8.1
   * @spec aauth#section-8.2
   * @spec mission-aauth#reference
   * @spec mission-aauth#approval
   */
  async proposeMission(proposal: Record<string, unknown>): Promise<MissionApproval> {
    const { mission_endpoint: endpoint } = await this.personServer();
    if (endpoint === undefined)
      throw new AgentError("metadata_invalid", "PS has no mission_endpoint");
    const res = await this.send(endpoint, { method: "POST", body: proposal });
    if (res.status !== 200) throw refused("mission_endpoint", res);
    const approval = asBody(res) as Record<string, unknown> | null;
    const s256 = approval?.s256;
    const encoded = approval?.mission;
    if (typeof s256 !== "string" || typeof encoded !== "string") {
      throw new AgentError("mission_invalid", "approval lacks s256 or mission");
    }
    const blob = strictBase64url(encoded);
    if (!blob) throw new AgentError("mission_invalid", "mission is not unpadded base64url");
    if (createHash("sha256").update(blob).digest("base64url") !== s256) {
      throw new AgentError(
        "mission_digest_mismatch",
        "s256 is not the digest of the mission bytes",
      );
    }
    // The binding's approval procedure, step 4: the blob names this agent.
    // Parsed only to read `agent`; the bytes kept are the decoded ones.
    let approved: { agent?: unknown } | undefined;
    try {
      const parsed: unknown = JSON.parse(blob.toString("utf8"));
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        approved = parsed as { agent?: unknown };
      }
    } catch {
      approved = undefined;
    }
    if (approved === undefined) {
      throw new AgentError("mission_invalid", "the mission blob is not a JSON object");
    }
    if (approved.agent !== this.id) {
      throw new AgentError("mission_invalid", "the mission blob names another agent");
    }
    this.mission = { s256, blob };
    const personTokens: Record<string, string> = {};
    const issued = approval?.person_tokens;
    if (typeof issued === "object" && issued !== null) {
      for (const [resource, token] of Object.entries(issued)) {
        if (typeof token !== "string") continue;
        personTokens[resource] = token;
        this.personTokens.set(this.cacheKey(resource), token);
      }
    }
    return { s256, blob, personTokens, capabilities: approval?.capabilities };
  }

  /** The `mission_s256` a person-token request carries, misbehavior applied. */
  private missionReference(): string | undefined {
    const choice = this.misbehavior.missionReference;
    if (choice === "omit") return undefined;
    if (choice === "malformed") return "not+a/digest=";
    if (choice !== undefined) return choice.value;
    return this.mission?.s256;
  }

  /**
   * Obtain a person token for `resource`, naming the agent's mission.
   *
   * @spec aauth#section-7.1
   */
  async requestPersonToken(resource: string): Promise<string> {
    const { person_token_endpoint: endpoint } = await this.personServer();
    const body: Record<string, unknown> = { resource };
    const reference = this.missionReference();
    if (reference !== undefined) body.mission_s256 = reference;
    const res = await this.send(endpoint, { method: "POST", body });
    if (res.status !== 200) throw refused("person_token_endpoint", res);
    const token = (asBody(res) as { person_token?: unknown } | null)?.person_token;
    if (typeof token !== "string")
      throw new AgentError("refused", "no person_token in the response");
    this.personTokens.set(this.cacheKey(resource), token);
    return token;
  }

  /**
   * Exchange a resource token at the PS, forwarding the token presented to
   * the resource as `presented_token`.
   *
   * @spec aauth#section-7.2.1
   */
  async requestAuthToken(resourceToken: string, presentedToken: string): Promise<string> {
    const { auth_token_endpoint: endpoint } = await this.personServer();
    const res = await this.send(endpoint, {
      method: "POST",
      body: { resource_token: resourceToken, presented_token: presentedToken },
    });
    if (res.status !== 200) throw refused("auth_token_endpoint", res);
    const token = (asBody(res) as { auth_token?: unknown } | null)?.auth_token;
    if (typeof token !== "string") throw new AgentError("refused", "no auth_token in the response");
    return token;
  }

  /**
   * Verify a resource token before carrying it to the PS: its signature and
   * `exp`, `iss` the resource called, `agent_jkt` this agent's key, `ps`
   * this agent's PS, and `sub` and `presented_jti` those of the token
   * presented. In three-party access `aud` is the PS as well. Then the
   * binding's rule: the token carries the agent's exact `mission_s256`
   * (or, with no mission, the presented token's), and neither absent nor
   * different.
   *
   * @spec aauth#section-6.7.3
   * @spec mission-aauth#ref-propagation
   */
  async verifyChallenge(
    resourceToken: string,
    context: { resource: string; presentedToken: string },
  ): Promise<VerifiedToken> {
    const presented = decodeClaims(context.presentedToken);
    let verified: VerifiedToken;
    try {
      verified = await verifyResourceToken(resourceToken, {
        resolver: this.resolver,
        audience: this.ps,
        agentJkt: this.thumbprint,
        now: this.now,
      });
    } catch (err) {
      throw new AgentError(
        "resource_token_invalid",
        err instanceof Error ? err.message : String(err),
      );
    }
    const claims = verified.payload;
    const invalid = (detail: string) => new AgentError("resource_token_invalid", detail);
    if (claims.iss !== context.resource) throw invalid("iss is not the resource called");
    if (claims.ps !== this.ps) throw invalid("ps is not this agent's person server");
    if (claims.sub !== presented.sub) throw invalid("sub is not the presented token's");
    if (claims.presented_jti !== presented.jti) {
      throw invalid("presented_jti does not name the presented token");
    }
    const expected = this.mission?.s256 ?? presented.mission_s256;
    if (claims.mission_s256 !== expected) {
      throw new AgentError(
        "mission_reference_mismatch",
        claims.mission_s256 === undefined
          ? "the resource token carries no mission_s256"
          : "the resource token names another mission",
      );
    }
    return verified;
  }

  /**
   * Verify an auth token the PS returned: its signature, `aud` the
   * resource, `iss` the resource token's `aud`, `cnf.jwk` this agent's
   * key, and `sub` the presented token's.
   *
   * @spec aauth#section-9.4.4
   */
  async verifyAuthTokenResponse(
    authToken: string,
    context: { resourceTokenAud: unknown; resource: string; presentedToken: string },
  ): Promise<VerifiedToken> {
    let verified: VerifiedToken;
    try {
      verified = await verifyAuthToken(authToken, {
        resolver: this.resolver,
        audience: context.resource,
        now: this.now,
      });
    } catch (err) {
      throw new AgentError("auth_token_invalid", err instanceof Error ? err.message : String(err));
    }
    const claims = verified.payload;
    const invalid = (detail: string) => new AgentError("auth_token_invalid", detail);
    if (claims.iss !== context.resourceTokenAud)
      throw invalid("iss is not the resource token's aud");
    const cnf = (claims.cnf as { jwk: Record<string, unknown> }).jwk;
    if ((await jwkThumbprint(cnf)) !== this.thumbprint)
      throw invalid("cnf.jwk is not this agent's key");
    if (claims.sub !== decodeClaims(context.presentedToken).sub) {
      throw invalid("sub is not the presented token's");
    }
    return verified;
  }

  /**
   * Carry a resource token to the PS and return the verified auth token,
   * applying any misbehavior.
   */
  private async redeem(
    resourceToken: string,
    resource: string,
    presented: string,
  ): Promise<string> {
    const rt = this.misbehavior.interceptResourceToken
      ? await this.misbehavior.interceptResourceToken(resourceToken)
      : resourceToken;
    const rtClaims = this.misbehavior.skipChallengeVerification
      ? decodeClaims(rt)
      : (await this.verifyChallenge(rt, { resource, presentedToken: presented })).payload;
    const forwarded = this.misbehavior.presentedToken
      ? await this.misbehavior.presentedToken(presented)
      : presented;
    const authToken = await this.requestAuthToken(rt, forwarded);
    await this.verifyAuthTokenResponse(authToken, {
      resourceTokenAud: rtClaims.aud,
      resource,
      presentedToken: presented,
    });
    this.authTokens.set(this.cacheKey(resource), authToken);
    return authToken;
  }

  /**
   * Call a resource, presenting the best token held for it, and follow its
   * requirements: `person-token` by obtaining a person token, `auth-token`
   * by redeeming the enclosed resource token at the PS (including a
   * step-up on a presented auth token). Any other requirement, or a
   * requirement on a status other than 401, is surfaced as an error.
   *
   * @spec aauth#section-6.4
   * @spec aauth#section-6.5
   * @spec aauth#section-11.6.2
   */
  async call(
    resource: string,
    path: string,
    options: { method?: string; body?: unknown } = {},
  ): Promise<LoopbackResponse> {
    let presented = this.authToken(resource) ?? this.personToken(resource) ?? this.agentToken;
    for (let round = 0; round < 4; round++) {
      const res = await this.send(`${resource}${path}`, { ...options, token: presented });
      const field = res.headers["aauth-requirement"];
      if (field === undefined) return res;
      const { requirement, params } = parseRequirement(field);
      if (res.status !== 401) {
        throw new AgentError("requirement_unsupported", `${requirement} on status ${res.status}`);
      }
      if (requirement === "person-token") {
        if (tokenType(presented) === "aa-person+jwt") {
          throw new AgentError("requirement_unsatisfiable", "a person token was just presented");
        }
        presented = await this.requestPersonToken(resource);
      } else if (requirement === "auth-token") {
        const resourceToken = params.get("resource-token");
        if (typeof resourceToken !== "string") {
          throw new AgentError(
            "challenge_invalid",
            "requirement=auth-token without resource-token",
          );
        }
        presented = await this.redeem(resourceToken, resource, presented);
      } else {
        throw new AgentError("requirement_unsupported", `requirement=${requirement}`);
      }
    }
    throw new AgentError("too_many_challenges", "the resource kept challenging");
  }

  /**
   * Request authorization for `scope` at the resource's authorization
   * endpoint, presenting a person token, then redeem the resource token at
   * the PS. Returns the auth token, which the client then presents.
   *
   * @spec aauth#section-6.6
   */
  async authorize(resource: string, scope: string): Promise<string> {
    const { status, body } = await this.transport.fetchJson(
      `${resource}/.well-known/aauth-resource.json`,
    );
    const doc = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    if (status !== 200 || doc.issuer !== resource) {
      throw new AgentError("metadata_invalid", "resource metadata failed the issuer check");
    }
    if (typeof doc.authorization_endpoint !== "string") {
      throw new AgentError("metadata_invalid", "resource has no authorization_endpoint");
    }
    const personToken = this.personToken(resource) ?? (await this.requestPersonToken(resource));
    const res = await this.send(doc.authorization_endpoint, {
      method: "POST",
      body: { scope },
      token: personToken,
    });
    if (res.status !== 200) throw refused("authorization_endpoint", res);
    const resourceToken = (asBody(res) as { resource_token?: unknown } | null)?.resource_token;
    if (typeof resourceToken !== "string") {
      throw new AgentError("refused", "no resource_token in the response");
    }
    return this.redeem(resourceToken, resource, personToken);
  }
}

export interface CreateAgentOptions {
  provider: AgentProvider;
  transport: AgentTransport & { resolver?: (options: { now?: Clock }) => JwksResolver };
  /** The agent's person server, carried in its agent token as `ps`. */
  ps: string;
  /** Default `assistant`. */
  local?: string;
  resolver?: JwksResolver;
  now?: Clock;
  sleep?: Sleep;
  misbehavior?: Misbehavior;
  /** Claims set over the agent token's defaults. */
  agentTokenClaims?: Record<string, unknown>;
}

/**
 * Generate an agent's Ed25519 key, obtain its agent token from the
 * provider stub, and return the client.
 */
export async function createAgent(options: CreateAgentOptions): Promise<AgentClient> {
  const key = generateSigningKey("Ed25519");
  const agentToken = await options.provider.issueAgentToken({
    local: options.local ?? "assistant",
    publicJwk: key.publicJwk,
    ps: options.ps,
    ...(options.agentTokenClaims ? { claims: options.agentTokenClaims } : {}),
  });
  const resolver =
    options.resolver ??
    options.transport.resolver?.(options.now ? { now: options.now } : {}) ??
    undefined;
  if (!resolver) throw new TypeError("createAgent needs a resolver or a transport that makes one");
  const clientOptions: AgentClientOptions & { thumbprint: string } = {
    transport: options.transport,
    resolver,
    key,
    agentToken,
    ps: options.ps,
    thumbprint: await jwkThumbprint(key.publicJwk),
  };
  if (options.now) clientOptions.now = options.now;
  if (options.sleep) clientOptions.sleep = options.sleep;
  if (options.misbehavior) clientOptions.misbehavior = options.misbehavior;
  return new AgentClient(clientOptions);
}
