import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type AgentClient,
  type AgentProvider,
  createAgent,
  createAgentProvider,
  createIssuerStub,
  decodeClaims,
  type IssuerStub,
  LoopbackNetwork,
  type LoopbackResponse,
  ManualClock,
  type Misbehavior,
  parseRequirement,
} from "@mission/aauth-testkit";
import {
  type HttpRequestMessage,
  signRequest,
  verifyRequest,
  verifyResourceToken,
} from "@mission/aauth-wire";
import { createResource, listen, loadResourceConfig, type Resource } from "../src/index.js";

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
}

export interface World {
  net: LoopbackNetwork;
  clock: ManualClock;
  provider: AgentProvider;
  ps: FakePs;
  resource: Resource;
  agent: AgentClient;
  seconds(): number;
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
  const ps: FakePs = {
    ...stub,
    requests,
    tokenPolicy,
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

/**
 * The agent-provider stub, a stand-in PS and the Resource (from the
 * shipped configuration, through its own `listen`) on one loopback
 * network, with an agent of the provider whose PS is the stand-in.
 */
export async function world(misbehavior?: Misbehavior): Promise<World> {
  const net = new LoopbackNetwork();
  const clock = new ManualClock();
  const provider = createAgentProvider({ issuer: AP, now: clock.now });
  const ps = fakePs(net, clock);
  const resource = createResource({
    config: loadResourceConfig(CONFIG_DIR),
    resolver: net.resolver({ now: clock.now }),
    now: clock.now,
  });
  await net.serve(AP, provider.handler);
  await net.serve(PS, ps.handler);
  net.attach(RESOURCE, await listen(resource.handler));
  const agent = await createAgent({
    provider,
    transport: net,
    ps: PS,
    now: clock.now,
    sleep: clock.sleep,
    ...(misbehavior ? { misbehavior } : {}),
  });
  return {
    net,
    clock,
    provider,
    ps,
    resource,
    agent,
    seconds: () => Math.floor(clock.now() / 1000),
  };
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
