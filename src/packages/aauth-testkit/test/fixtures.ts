import { randomUUID } from "node:crypto";
import {
  type AgentClient,
  type AgentProvider,
  createAgent,
  createAgentProvider,
  createIssuerStub,
  type IssuerStub,
  LoopbackNetwork,
  ManualClock,
  type Misbehavior,
} from "../src/index.js";

export const AP = "https://ap.test";
export const PS = "https://ps.test";
export const RESOURCE = "https://resource.test";
/** A mission reference: the unpadded base64url SHA-256 of some blob. */
export const M = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const M2 = "Q2h1Y2sgSW50ZWdyaXR5IENoZWNrIGZvciBhIHRlc3Q";

export interface World {
  net: LoopbackNetwork;
  clock: ManualClock;
  provider: AgentProvider;
  /** A signing stub standing at the PS identifier; tests add its routes. */
  ps: IssuerStub;
  /** A signing stub standing at the resource identifier; tests add its routes. */
  resource: IssuerStub;
  agent: AgentClient;
  seconds(): number;
}

/** Three stubs on a loopback network and an agent of the provider stub. */
export async function world(misbehavior?: Misbehavior): Promise<World> {
  const net = new LoopbackNetwork();
  const clock = new ManualClock();
  const provider = createAgentProvider({ issuer: AP, now: clock.now });
  const ps = createIssuerStub({
    issuer: PS,
    dwk: "aauth-person.json",
    kid: "ps-key-1",
    metadata: {
      person_token_endpoint: `${PS}/person`,
      auth_token_endpoint: `${PS}/token`,
      mission_endpoint: `${PS}/mission`,
    },
  });
  const resource = createIssuerStub({
    issuer: RESOURCE,
    dwk: "aauth-resource.json",
    kid: "resource-key-1",
  });
  await net.serve(AP, provider.handler);
  await net.serve(PS, ps.handler);
  await net.serve(RESOURCE, resource.handler);
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

/** A person token the PS stub issues to the agent for the resource stub. */
export function personToken(w: World, claims: Record<string, unknown> = {}): Promise<string> {
  const iat = w.seconds();
  return w.ps.mint("aa-person+jwt", {
    iss: PS,
    dwk: "aauth-person.json",
    aud: RESOURCE,
    sub: "person-1",
    cnf: { jwk: w.agent.key.publicJwk },
    jti: randomUUID(),
    iat,
    exp: iat + 3600,
    ...claims,
  });
}

/** Valid resource token claims for a challenge to the agent's `presented` token. */
export function resourceTokenClaims(
  w: World,
  presented: Record<string, unknown>,
  claims: Record<string, unknown> = {},
): Record<string, unknown> {
  const iat = w.seconds();
  const base: Record<string, unknown> = {
    iss: RESOURCE,
    dwk: "aauth-resource.json",
    aud: PS,
    ps: PS,
    sub: presented.sub,
    presented_jti: presented.jti,
    agent_jkt: w.agent.thumbprint,
    scope: "documents.read",
    jti: randomUUID(),
    iat,
    exp: iat + 300,
  };
  if (presented.mission_s256 !== undefined) base.mission_s256 = presented.mission_s256;
  return { ...base, ...claims };
}

/** Valid auth token claims answering a resource token. */
export function authTokenClaims(
  w: World,
  rt: Record<string, unknown>,
  claims: Record<string, unknown> = {},
): Record<string, unknown> {
  const iat = w.seconds();
  const base: Record<string, unknown> = {
    iss: PS,
    dwk: "aauth-person.json",
    aud: rt.iss,
    ps: PS,
    sub: rt.sub,
    scope: rt.scope,
    cnf: { jwk: w.agent.key.publicJwk },
    jti: randomUUID(),
    iat,
    exp: iat + 3600,
  };
  if (rt.mission_s256 !== undefined) base.mission_s256 = rt.mission_s256;
  return { ...base, ...claims };
}

/** Remove `name` from a claims object. */
export function without(claims: Record<string, unknown>, name: string): Record<string, unknown> {
  const { [name]: _removed, ...rest } = claims;
  return rest;
}
