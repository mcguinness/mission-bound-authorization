import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type AgentClient,
  type AgentProvider,
  createAgent,
  createAgentProvider,
  createIssuerStub,
  decodeClaims,
  EndpointSwitch,
  type IssuerStub,
  LoopbackNetwork,
  type LoopbackResponse,
  ManualClock,
  type Misbehavior,
  parseRequirement,
} from "@mission/aauth-testkit";
import {
  type HttpRequestMessage,
  type SignatureKeyMember,
  signRequest,
  verifyRequest,
  verifyResourceToken,
} from "@mission/aauth-wire";
import {
  createResource,
  listen,
  loadResourceConfig,
  REVOCATION_PATH,
  type Resource,
  type ResourceConfig,
  type RevocationStore,
  SqliteRevocationStore,
} from "../src/index.js";

export const AP = "https://ap.test";
export const PS = "https://ps.test";
export const RESOURCE = "https://resource.test";
export const M = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const M2 = "Q2h1Y2sgSW50ZWdyaXR5IENoZWNrIGZvciBhIHRlc3Q";

const CONFIG_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../config");

/**
 * A stand-in PS for the Resource's tests. It authenticates the agent's
 * request and checks the resource token's signature, `aud` and `agent_jkt`
 * (Section 6.7.2 steps 1 and 2, through the library), then issues. It
 * performs no mission governance and none of Section 6.7.2 step 3, so
 * nothing it issues is evidence of PS behavior.
 */
export interface FakePs extends IssuerStub {
  requests: { path: string; body: Record<string, unknown> }[];
  /** Narrow the scope of the next auth tokens, or refuse them with this error. */
  tokenPolicy: { grant?: (scope: string) => string; refuse?: string };
  personToken(agent: AgentClient, claims?: Record<string, unknown>): Promise<string>;
  authToken(agent: AgentClient, claims?: Record<string, unknown>): Promise<string>;
  /**
   * Revoke at the Resource as this PS: a POST of `body` to its revocation
   * endpoint, signed as a server under the `jwks_uri` scheme with this
   * PS's key (aauth#section-11.12.1). This is a minimal signer, not the
   * PS's revocation logic.
   */
  revoke(body: unknown, options?: RevokeOptions): Promise<LoopbackResponse>;
}

export interface RevokeOptions {
  /** Sign as this server instead, under its own identifier, document and key. */
  as?: IssuerStub;
  /** Default: the signer's identifier, its document and its key id. */
  signatureKey?: SignatureKeyMember;
  /** Default: base and body components. */
  components?: readonly string[];
  contentType?: string;
  /** Default: the current second. */
  created?: number;
  /** The exact bytes sent; default `JSON.stringify(body)`. */
  raw?: string;
}

export interface World {
  net: LoopbackNetwork;
  clock: ManualClock;
  provider: AgentProvider;
  ps: FakePs;
  resource: Resource;
  /** The switch in front of the Resource's revocation endpoint. */
  revocationSwitch: EndpointSwitch;
  /** The Resource's durable revoked set, on a temporary file. */
  storeFile: string;
  agent: AgentClient;
  seconds(): number;
  /** Stop the Resource and start another on the same store file and key. */
  restartResource(): Promise<void>;
  close(): Promise<void>;
}

/** A revoked set whose reads and writes can be made to fail. */
export class SwitchableStore implements RevocationStore {
  failReads = false;
  failWrites = false;

  constructor(readonly inner: RevocationStore) {}

  admit(...args: Parameters<RevocationStore["admit"]>) {
    if (this.failWrites) throw new Error("the revoked set is unavailable");
    return this.inner.admit(...args);
  }
  isRevoked(...args: Parameters<RevocationStore["isRevoked"]>) {
    if (this.failReads) throw new Error("the revoked set is unavailable");
    return this.inner.isRevoked(...args);
  }
  purge(...args: Parameters<RevocationStore["purge"]>) {
    if (this.failWrites) throw new Error("the revoked set is unavailable");
    return this.inner.purge(...args);
  }
  entries() {
    return this.inner.entries();
  }
  close() {
    this.inner.close();
  }
}

function fakePs(net: LoopbackNetwork, clock: ManualClock, issuer = PS): FakePs {
  const resolver = net.resolver({ now: clock.now });
  const seconds = () => Math.floor(clock.now() / 1000);
  const requests: FakePs["requests"] = [];
  const tokenPolicy: FakePs["tokenPolicy"] = {};
  const stub = createIssuerStub({
    issuer,
    dwk: "aauth-person.json",
    kid: "ps-key-1",
    metadata: {
      person_token_endpoint: `${issuer}/person`,
      auth_token_endpoint: `${issuer}/token`,
    },
  });
  const revoke: FakePs["revoke"] = (body, options = {}) => {
    const url = `${RESOURCE}${REVOCATION_PATH}`;
    const bytes = options.raw ?? JSON.stringify(body);
    const headers: Record<string, string> = {
      "content-type": options.contentType ?? "application/json",
    };
    const signer = options.as ?? stub;
    const added = signRequest(
      { method: "POST", url, headers, body: bytes },
      {
        alg: signer.key.alg,
        privateKey: signer.key.privateKey,
        signatureKey: options.signatureKey ?? {
          scheme: "jwks_uri",
          id: signer.issuer,
          dwk: signer.dwk,
          kid: signer.key.kid,
        },
        created: options.created ?? seconds(),
        ...(options.components ? { components: options.components } : {}),
      },
    );
    return net.request({ method: "POST", url, headers: { ...headers, ...added }, body: bytes });
  };
  const ps: FakePs = {
    ...stub,
    requests,
    tokenPolicy,
    revoke,
    personToken: (agent, claims = {}) => {
      const iat = seconds();
      return stub.mint("aa-person+jwt", {
        iss: issuer,
        dwk: "aauth-person.json",
        aud: RESOURCE,
        sub: "person-1",
        cnf: { jwk: agent.key.publicJwk },
        jti: randomUUID(),
        iat,
        exp: iat + 3600,
        ...claims,
      });
    },
    authToken: (agent, claims = {}) => {
      const iat = seconds();
      return stub.mint("aa-auth+jwt", {
        iss: issuer,
        dwk: "aauth-person.json",
        aud: RESOURCE,
        ps: issuer,
        sub: "person-1",
        scope: "documents.read documents.write",
        cnf: { jwk: agent.key.publicJwk },
        jti: randomUUID(),
        iat,
        exp: iat + 3600,
        ...claims,
      });
    },
  };
  stub.routes["POST /person"] = async (req) => {
    const verified = await verifyRequest(req.message, {
      resolver,
      requireBodyComponents: true,
      now: clock.now,
    });
    const body = (req.json ?? {}) as Record<string, unknown>;
    requests.push({ path: "/person", body });
    const iat = seconds();
    const token = await stub.mint("aa-person+jwt", {
      iss: issuer,
      dwk: "aauth-person.json",
      aud: body.resource,
      sub: "person-1",
      cnf: { jwk: verified.publicJwk },
      jti: randomUUID(),
      iat,
      exp: Math.min(iat + 3600, verified.token?.payload.exp as number),
      ...(body.mission_s256 === undefined ? {} : { mission_s256: body.mission_s256 }),
    });
    return { status: 200, body: { person_token: token, expires_in: 3600 } };
  };
  stub.routes["POST /token"] = async (req) => {
    const verified = await verifyRequest(req.message, {
      resolver,
      requireBodyComponents: true,
      now: clock.now,
    });
    const body = (req.json ?? {}) as Record<string, unknown>;
    requests.push({ path: "/token", body });
    if (tokenPolicy.refuse) return { status: 400, body: { error: tokenPolicy.refuse } };
    const rt = await verifyResourceToken(String(body.resource_token), {
      resolver,
      audience: issuer,
      agentJkt: verified.thumbprint,
      now: clock.now,
    });
    const claims = rt.payload;
    const presented = decodeClaims(String(body.presented_token));
    const iat = seconds();
    const scope = String(claims.scope);
    const token = await stub.mint("aa-auth+jwt", {
      iss: issuer,
      dwk: "aauth-person.json",
      aud: claims.iss,
      ps: issuer,
      sub: claims.sub,
      scope: tokenPolicy.grant ? tokenPolicy.grant(scope) : scope,
      cnf: { jwk: verified.publicJwk },
      jti: randomUUID(),
      iat,
      exp: Math.min(iat + 3600, presented.exp as number),
      ...(claims.mission_s256 === undefined ? {} : { mission_s256: claims.mission_s256 }),
      ...(claims.tenant === undefined ? {} : { tenant: claims.tenant }),
    });
    return { status: 200, body: { auth_token: token, expires_in: 3600 } };
  };
  return ps;
}

/** The shipped Resource configuration. */
export const shippedConfig = (): ResourceConfig => loadResourceConfig(CONFIG_DIR);

export interface WorldOptions {
  /** Default: the shipped configuration. */
  config?: ResourceConfig;
  /** Wrap the Resource's durable store, for a failing-store test. */
  wrapStore?: (store: RevocationStore) => RevocationStore;
}

/**
 * The agent-provider stub, a stand-in PS and the Resource (from the
 * shipped configuration, through its own `listen`, its revoked set durable
 * on a temporary file and its revocation endpoint behind a switch) on one
 * loopback network, with an agent of the provider whose PS is the
 * stand-in.
 */
export async function world(misbehavior?: Misbehavior, opts: WorldOptions = {}): Promise<World> {
  const net = new LoopbackNetwork();
  const clock = new ManualClock();
  const provider = createAgentProvider({ issuer: AP, now: clock.now });
  const ps = fakePs(net, clock);
  const config = opts.config ?? shippedConfig();
  const dir = mkdtempSync(join(tmpdir(), "aauth-resource-"));
  const storeFile = join(dir, "resource.db");
  const open = () => {
    const store = new SqliteRevocationStore(storeFile);
    return opts.wrapStore ? opts.wrapStore(store) : store;
  };
  const revocationSwitch = new EndpointSwitch({ path: REVOCATION_PATH });
  let resource = createResource({
    config,
    resolver: net.resolver({ now: clock.now }),
    now: clock.now,
    revocations: open(),
  });
  await net.serve(AP, provider.handler);
  await net.serve(PS, ps.handler);
  let server: Server = await listen(revocationSwitch.wrap(resource.handler));
  net.attach(RESOURCE, server);
  const agent = await createAgent({
    provider,
    transport: net,
    ps: PS,
    now: clock.now,
    sleep: clock.sleep,
    ...(misbehavior ? { misbehavior } : {}),
  });
  let closed = false;
  const stop = (s: Server) =>
    new Promise<void>((resolve) => {
      s.closeAllConnections();
      s.close(() => resolve());
    });
  const w: World = {
    net,
    clock,
    provider,
    ps,
    get resource() {
      return resource;
    },
    revocationSwitch,
    storeFile,
    agent,
    seconds: () => Math.floor(clock.now() / 1000),
    restartResource: async () => {
      await stop(server);
      resource.revocations.close();
      resource = createResource({
        config,
        resolver: net.resolver({ now: clock.now }),
        now: clock.now,
        key: resource.key,
        revocations: open(),
      });
      server = await listen(revocationSwitch.wrap(resource.handler));
      net.attach(RESOURCE, server);
    },
    close: async () => {
      if (closed) return;
      closed = true;
      await net.close();
      resource.revocations.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return w;
}

/** Serve another stand-in PS at `issuer` on the world's network. */
export async function anotherPs(w: World, issuer: string): Promise<FakePs> {
  const ps = fakePs(w.net, w.clock, issuer);
  await w.net.serve(issuer, ps.handler);
  return ps;
}

/** The AAuth-Requirement of a response, parsed. */
export function requirementOf(res: LoopbackResponse) {
  const field = res.headers["aauth-requirement"];
  if (field === undefined) return undefined;
  const { requirement, params } = parseRequirement(field);
  return { requirement, resourceToken: params.get("resource-token") as string | undefined };
}

/** Verify a challenge's resource token as its PS would (steps 1 and 2). */
export async function verifiedResourceToken(w: World, token: string) {
  return verifyResourceToken(token, {
    resolver: w.net.resolver({ now: w.clock.now }),
    audience: PS,
    agentJkt: w.agent.thumbprint,
    now: w.clock.now,
  });
}

/**
 * Sign a request as the agent with full control of the components, and
 * return the message, so a test can send it, alter it or send it again.
 */
export function signedMessage(
  w: World,
  options: {
    method?: string;
    path: string;
    token?: string;
    body?: string;
    contentType?: string;
    components?: readonly string[];
  },
): HttpRequestMessage & { headers: Record<string, string> } {
  const method = options.method ?? "GET";
  const url = `${RESOURCE}${options.path}`;
  const headers: Record<string, string> = {};
  if (options.body !== undefined) {
    headers["content-type"] = options.contentType ?? "application/json";
  }
  const added = signRequest(
    { method, url, headers, body: options.body },
    {
      alg: w.agent.key.alg,
      privateKey: w.agent.key.privateKey,
      signatureKey: { scheme: "jwt", jwt: options.token ?? w.agent.agentToken },
      created: w.seconds(),
      ...(options.components ? { components: options.components } : {}),
    },
  );
  return { method, url, headers: { ...headers, ...added }, body: options.body };
}

export function sendMessage(
  w: World,
  message: HttpRequestMessage & { headers: Record<string, string> },
): Promise<LoopbackResponse> {
  return w.net.request({
    method: message.method,
    url: message.url,
    headers: message.headers,
    ...(message.body === undefined ? {} : { body: message.body as string }),
  });
}
