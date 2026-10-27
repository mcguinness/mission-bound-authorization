/**
 * Test topology for the PS: real HTTP on loopback, ephemeral ports.
 *
 * Every party keeps an AAuth server identifier (`https://ps.test`,
 * `https://ap.test`, `https://rs.test`, ...), since `iss`, `aud` and `ps`
 * must be identifiers (no port). Key discovery goes through the library's
 * resolver under the library's egress admission, which admits exactly the
 * mapped test hosts through `admitPrivateDestination` and nothing else,
 * and through the library's pinned `createFetchJson`, which checks and
 * connects to the loopback literal itself. The one bridge is that an
 * `https://<host>` URL travels as plain HTTP to that host's loopback port:
 * the loopback topology carries no TLS.
 *
 * A signed request follows the slice's composition contract (the
 * testkit's `LoopbackNetwork`): the agent signs the identifier URL
 * `https://ps.test/<path>` over -11 Section 11.3.3.1's base set (plus
 * Content-Digest and Content-Type on a body), connects to
 * `127.0.0.1:<port>`, and sends `Host: ps.test` with the request target as
 * written. The PS builds the signature base from its own identifier and
 * the raw target, never from the Host field.
 */
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AAuthTokenType,
  createEgressAdmission,
  createFetchJson,
  type FetchJson,
  generateSigningKey,
  JwksResolver,
  jwkThumbprint,
  mintToken,
  type SigningKey,
  signRequest,
} from "@mission/aauth-wire";
import {
  createPersonServer,
  type IssuedTokenRecord,
  listen,
  type MissionLogEntry,
  type MissionRecord,
  type PersonServer,
  type PsStore,
  parsePsConfig,
  type RunningServer,
  SqlitePsStore,
} from "../src/index.js";

/** 2025-10-09T08:53:20Z. */
export const T0 = 1_760_000_000_000;

export const PS = "https://ps.test";
export const PS2 = "https://ps2.test";
export const AP = "https://ap.test";
export const RS = "https://rs.test";
export const RS2 = "https://rs2.test";
export const ASSISTANT = "aauth:assistant@ap.test";
export const PLANNER = "aauth:planner@ap.test";
export const HELPER = "aauth:helper@ap.test";
export const STRANGER = "aauth:stranger@ap.test";

/** A mutable clock shared by every party, in milliseconds. */
export class Clock {
  ms = T0;
  readonly now = () => this.ms;
  get s(): number {
    return Math.floor(this.ms / 1000);
  }
  advance(seconds: number): void {
    this.ms += seconds * 1000;
  }
}

export class LoopbackNet {
  private readonly origins = new Map<string, string>();
  private readonly pinned: FetchJson = createFetchJson({
    admitPrivateDestination: (url) => [...this.origins.values()].includes(url.origin),
  });

  /** Serve `identifier`'s documents from `origin` (`http://127.0.0.1:<port>`). */
  register(identifier: string, origin: string): void {
    this.origins.set(new URL(identifier).hostname, origin);
  }

  readonly fetchJson: FetchJson = (url) => {
    const target = new URL(url);
    const origin = target.protocol === "https:" ? this.origins.get(target.hostname) : undefined;
    if (!origin) return Promise.reject(new Error(`${target.origin} is not on the loopback net`));
    return this.pinned(`${origin}${target.pathname}${target.search}`);
  };

  /** The loopback port an `https://<host>/...` URL travels to, and its raw target. */
  transport(url: string): { port: number; host: string; path: string } {
    const target = new URL(url);
    const origin = this.origins.get(target.hostname);
    if (target.protocol !== "https:" || target.port !== "" || !origin) {
      throw new Error(`${url} is not an identifier URL on the loopback net`);
    }
    const rest = url.slice(url.indexOf("://") + 3);
    const start = rest.search(/[/?]/);
    return {
      port: Number(new URL(origin).port),
      host: target.hostname,
      path: start >= 0 ? rest.slice(start) : "/",
    };
  }

  resolver(clock: Clock): JwksResolver {
    return new JwksResolver({
      fetchJson: this.fetchJson,
      now: clock.now,
      admitEgress: createEgressAdmission({
        admitPrivateDestination: (url) => this.origins.has(url.hostname),
        lookup: async () => {
          throw new Error("the loopback net has no DNS");
        },
      }),
    });
  }
}

/** An issuer stub: its metadata document and JWKS, served on loopback. */
export interface IssuerStub {
  id: string;
  key: SigningKey;
  kid: string;
  running: RunningServer;
  mint(typ: AAuthTokenType, claims: Record<string, unknown>): Promise<string>;
}

export async function startIssuer(net: LoopbackNet, id: string, dwk: string): Promise<IssuerStub> {
  const kid = `${new URL(id).hostname}-key-1`;
  const key = generateSigningKey("Ed25519", kid);
  const metadata = { issuer: id, jwks_uri: `${id}/.well-known/jwks.json` };
  const running = await listen(async (req, res) => {
    const body =
      req.url === `/.well-known/${dwk}`
        ? metadata
        : req.url === "/.well-known/jwks.json"
          ? { keys: [key.publicJwk] }
          : undefined;
    res.writeHead(body ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(body ?? {}));
  });
  net.register(id, running.origin);
  return {
    id,
    key,
    kid,
    running,
    mint: (typ, claims) =>
      mintToken(typ, claims, { alg: key.alg, privateKey: key.privateKey, kid }),
  };
}

export interface Agent {
  id: string;
  key: SigningKey;
  token: string;
  jkt: string;
}

/** An agent with a fresh key and an agent token from `ap`. */
export async function makeAgent(
  ap: IssuerStub,
  clock: Clock,
  id = ASSISTANT,
  overrides: Record<string, unknown> = {},
): Promise<Agent> {
  const key = generateSigningKey("Ed25519");
  const token = await ap.mint("aa-agent+jwt", {
    iss: ap.id,
    dwk: "aauth-agent.json",
    sub: id,
    jti: randomUUID(),
    iat: clock.s,
    exp: clock.s + 86400,
    cnf: { jwk: key.publicJwk },
    ...overrides,
  });
  return { id, key, token, jkt: await jwkThumbprint(key.publicJwk) };
}

/** The decoded payload of a compact JWT. */
export function claims(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1] ?? "", "base64url").toString("utf8"));
}

export interface Reply {
  status: number;
  headers: Headers;
  body: Record<string, unknown>;
}

/**
 * The loopback net of the running test file's world. Each test file runs
 * in its own worker, and a file's tests run one at a time.
 */
let activeNet: LoopbackNet | undefined;

export interface SendOptions {
  /** The Host field to send. Default: the identifier URL's host. */
  host?: string;
}

/**
 * Send a request addressed by an identifier URL: plain HTTP to the host's
 * loopback port, the request target exactly as written, and `Host` the
 * identifier's host (no port).
 */
export function send(
  method: "GET" | "POST",
  url: string,
  prepared: { headers: Record<string, string>; body?: string },
  options: SendOptions = {},
): Promise<Reply> {
  if (!activeNet) throw new Error("no world is running");
  const { port, host, path } = activeNet.transport(url);
  const headers = { ...prepared.headers, host: options.host ?? host };
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, method, path, headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const received = new Headers();
        for (const [name, values] of Object.entries(res.headersDistinct)) {
          if (values) received.set(name, values.join(", "));
        }
        resolve({
          status: res.statusCode ?? 0,
          headers: received,
          body: text ? JSON.parse(text) : {},
        });
      });
    });
    req.on("error", reject);
    if (prepared.body !== undefined) req.write(prepared.body);
    req.end();
  });
}

export interface SignOptions {
  /** Sign for this URL instead of the one the request is sent to. */
  signedUrl?: string;
  /** Extra request headers, sent and offered to the signer. */
  headers?: Record<string, string>;
  /** Covered components instead of the library default. */
  components?: string[];
  /** Advance the shared clock before signing (default 1 second), so `created` is fresh. */
  tick?: number;
}

/** The headers and body of a request signed by `agent` under the `jwt` scheme. */
export function prepare(
  clock: Clock,
  method: "GET" | "POST",
  url: string,
  agent: Agent,
  body?: unknown,
  options: SignOptions = {},
): { headers: Record<string, string>; body?: string } {
  clock.advance(options.tick ?? 1);
  const text = body === undefined ? undefined : JSON.stringify(body);
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (text !== undefined) headers["content-type"] = "application/json";
  const added = signRequest(
    { method, url: options.signedUrl ?? url, headers, body: text },
    {
      alg: agent.key.alg,
      privateKey: agent.key.privateKey,
      signatureKey: { scheme: "jwt", jwt: agent.token },
      created: clock.s,
      ...(options.components ? { components: options.components } : {}),
    },
  );
  return text === undefined
    ? { headers: { ...headers, ...added } }
    : { headers: { ...headers, ...added }, body: text };
}

/** A signed request from `agent`, with its agent token under the `jwt` scheme. */
export function signed(
  clock: Clock,
  method: "GET" | "POST",
  url: string,
  agent: Agent,
  body?: unknown,
  options: SignOptions = {},
): Promise<Reply> {
  return send(method, url, prepare(clock, method, url, agent, body, options));
}

/** Same status, error body and header names: what an observer can compare. */
export function shape(r: Reply): { status: number; body: unknown; headers: string[] } {
  const headers: string[] = [];
  r.headers.forEach((_value, name) => {
    headers.push(name);
  });
  return { status: r.status, body: r.body, headers: headers.sort() };
}

/**
 * The durable store behind switches a test flips: a mission read that
 * cannot establish state, a record write that fails, or a persisted blob
 * altered after approval.
 */
export class FaultyStore implements PsStore {
  failMissionReads = false;
  failRecords = false;
  tamperBlobs = false;

  constructor(readonly inner: SqlitePsStore) {}

  findOwnedMission(agent: string, s256: string): MissionRecord | undefined {
    if (this.failMissionReads) throw new Error("mission state is unavailable");
    const found = this.inner.findOwnedMission(agent, s256);
    if (found && this.tamperBlobs)
      return { ...found, blob: Buffer.concat([found.blob, Buffer.from(" ")]) };
    return found;
  }
  approve(...args: Parameters<PsStore["approve"]>): void {
    if (this.failRecords) throw new Error("the store refused the write");
    this.inner.approve(...args);
  }
  recordIssued(...args: Parameters<PsStore["recordIssued"]>): void {
    if (this.failRecords) throw new Error("the store refused the write");
    this.inner.recordIssued(...args);
  }
  terminate(...args: Parameters<PsStore["terminate"]>): boolean {
    return this.inner.terminate(...args);
  }
  issuedTokens(): IssuedTokenRecord[] {
    return this.inner.issuedTokens();
  }
  missionLog(s256: string): MissionLogEntry[] {
    return this.inner.missionLog(s256);
  }
  pairwiseKey(): Buffer {
    return this.inner.pairwiseKey();
  }
  close(): void {
    this.inner.close();
  }
}

const CONFIG_FILE = new URL("../../../config/aauth-ps.json", import.meta.url);

/** The shipped configuration document, parsed as JSON for a test to adjust. */
export function shippedConfig(): Record<string, unknown> {
  return JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
}

export interface WorldOptions {
  /** Adjust the configuration document before it is validated. */
  config?: (doc: Record<string, unknown>) => void;
}

export interface World {
  clock: Clock;
  net: LoopbackNet;
  ap: IssuerStub;
  rs: IssuerStub;
  rs2: IssuerStub;
  /** Another person server, publishing its own keys. */
  ps2: IssuerStub;
  ps: PersonServer;
  faults: FaultyStore;
  /** The PS's identifier, under which agents address and sign its endpoints. */
  origin: string;
  /** Where the PS listens: `http://127.0.0.1:<port>`, a transport address. */
  loopback: string;
  /** A token signed with the PS's own key, as the PS would never mint it. */
  psMint(typ: AAuthTokenType, claims: Record<string, unknown>): Promise<string>;
  close(): Promise<void>;
}

/** A PS on loopback with an agent provider, two resources and a second PS. */
export async function world(options: WorldOptions = {}): Promise<World> {
  const clock = new Clock();
  const net = new LoopbackNet();
  const ap = await startIssuer(net, AP, "aauth-agent.json");
  const rs = await startIssuer(net, RS, "aauth-resource.json");
  const rs2 = await startIssuer(net, RS2, "aauth-resource.json");
  const ps2 = await startIssuer(net, PS2, "aauth-person.json");
  const doc = shippedConfig();
  options.config?.(doc);
  const dir = mkdtempSync(join(tmpdir(), "aauth-ps-"));
  const durable = new SqlitePsStore(join(dir, "ps.db"));
  const faults = new FaultyStore(durable);
  const ps = createPersonServer({
    config: parsePsConfig(doc),
    store: faults,
    resolver: net.resolver(clock),
    now: clock.now,
  });
  const running = await ps.listen();
  net.register(PS, running.origin);
  activeNet = net;
  const kid = ps.signingKey.publicJwk.kid as string;
  return {
    clock,
    net,
    ap,
    rs,
    rs2,
    ps2,
    ps,
    faults,
    origin: PS,
    loopback: running.origin,
    psMint: (typ, c) =>
      mintToken(typ, c, { alg: ps.signingKey.alg, privateKey: ps.signingKey.privateKey, kid }),
    close: async () => {
      await running.close();
      for (const stub of [ap, rs, rs2, ps2]) await stub.running.close();
      durable.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** POST {mission_endpoint}. */
export function propose(w: World, agent: Agent, proposal: Record<string, unknown>): Promise<Reply> {
  return signed(w.clock, "POST", `${w.origin}/mission`, agent, proposal);
}

/** Propose and return the approval; fails the test if it is not approved. */
export async function approve(
  w: World,
  agent: Agent,
  proposal: Record<string, unknown> = { description: "Summarize the quarterly report" },
): Promise<{ s256: string; mission: string; person_tokens?: Record<string, string> }> {
  const r = await propose(w, agent, proposal);
  if (r.status !== 200) throw new Error(`approval failed: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body as { s256: string; mission: string };
}

/** POST {person_token_endpoint}. */
export function requestPersonToken(
  w: World,
  agent: Agent,
  params: Record<string, unknown>,
): Promise<Reply> {
  return signed(w.clock, "POST", `${w.origin}/person`, agent, params);
}

/** A person token for `resource`, under `s256` when given. */
export async function personToken(
  w: World,
  agent: Agent,
  resource: string,
  s256?: string,
): Promise<string> {
  const params: Record<string, unknown> = { resource };
  if (s256 !== undefined) params.mission_s256 = s256;
  const r = await requestPersonToken(w, agent, params);
  if (r.status !== 200)
    throw new Error(`person token refused: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.person_token as string;
}

/** POST {auth_token_endpoint}. */
export function requestAuthToken(
  w: World,
  agent: Agent,
  params: Record<string, unknown>,
): Promise<Reply> {
  return signed(w.clock, "POST", `${w.origin}/token`, agent, params);
}

/**
 * A resource token from `resource` (default `rs`) for the token the agent
 * presented: `ps`, `sub`, `presented_jti`, `mission_s256` and `tenant`
 * copied from it as AAuth -11 Section 6.7.1 requires, then `overrides`
 * (a value of `undefined` removes the claim).
 */
export async function resourceTokenFor(
  w: World,
  agent: Agent,
  presented: string,
  overrides: Record<string, unknown> = {},
  resource: IssuerStub = w.rs,
): Promise<string> {
  return resource.mint("aa-resource+jwt", resourceClaims(w, agent, presented, overrides, resource));
}

/** The claims {@link resourceTokenFor} signs. */
export function resourceClaims(
  w: World,
  agent: Agent,
  presented: string,
  overrides: Record<string, unknown> = {},
  resource: IssuerStub = w.rs,
): Record<string, unknown> {
  const p = claims(presented);
  const c: Record<string, unknown> = {
    iss: resource.id,
    dwk: "aauth-resource.json",
    aud: PS,
    ps: p.dwk === "aauth-person.json" && p.ps === undefined ? p.iss : p.ps,
    sub: p.sub,
    presented_jti: p.jti,
    agent_jkt: agent.jkt,
    jti: randomUUID(),
    iat: w.clock.s,
    exp: w.clock.s + 300,
    scope: "data.read",
  };
  if (p.mission_s256 !== undefined) c.mission_s256 = p.mission_s256;
  if (p.tenant !== undefined) c.tenant = p.tenant;
  for (const [name, value] of Object.entries(overrides)) {
    if (value === undefined) delete c[name];
    else c[name] = value;
  }
  return c;
}

/**
 * Person-token claims as this PS would issue them to `agent` for
 * `resource` under `s256`, for a test to adjust and sign with the PS key
 * (or another key) into a token the PS itself would never mint.
 */
export function personClaims(
  w: World,
  agent: Agent,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const c: Record<string, unknown> = {
    iss: PS,
    dwk: "aauth-person.json",
    aud: RS,
    sub: "pairwise-subject",
    jti: randomUUID(),
    iat: w.clock.s,
    exp: w.clock.s + 600,
    cnf: { jwk: agent.key.publicJwk },
    tenant: "acme",
  };
  for (const [name, value] of Object.entries(overrides)) {
    if (value === undefined) delete c[name];
    else c[name] = value;
  }
  return c;
}

/** The number of issued-token records, for refusal tests. */
export function issuedCount(w: World): number {
  return w.ps.store.issuedTokens().length;
}
