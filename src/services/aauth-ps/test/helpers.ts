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
import type { IncomingMessage, ServerResponse } from "node:http";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type AAuthTokenType,
  createEgressAdmission,
  createFetchJson,
  type FetchJson,
  generateSigningKey,
  InMemoryReplayCache,
  JwksResolver,
  jwkThumbprint,
  mintToken,
  SignatureError,
  type SigningKey,
  signRequest,
  type VerifiedRequest,
  verifyRequest,
} from "@mission/aauth-wire";
import { vi } from "vitest";
import {
  createPersonServer,
  type IssuedTokenRecord,
  listen,
  type MissionLogEntry,
  type MissionRecord,
  type OutboundRequest,
  type OutboundResponse,
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
  /** Waiting advances the shared clock instead of the wall clock. */
  readonly sleep = async (ms: number): Promise<void> => {
    this.ms += ms;
  };
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

  /**
   * The PS's outbound transport: an identifier URL travels as plain HTTP
   * to its host's loopback port, the target as written and `Host` the
   * identifier's host. Nothing off the net is reachable, and the attempt's
   * signal aborts the request.
   */
  readonly request = (message: OutboundRequest): Promise<OutboundResponse> => {
    let target: { port: number; host: string; path: string };
    try {
      target = this.transport(message.url);
    } catch (err) {
      return Promise.reject(err);
    }
    return new Promise((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port: target.port,
          method: message.method,
          path: target.path,
          headers: { ...message.headers, host: target.host },
          agent: false,
          ...(message.signal ? { signal: message.signal } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("error", reject);
          res.on("end", () => {
            const headers: Record<string, string> = {};
            for (const [name, values] of Object.entries(res.headersDistinct)) {
              if (values) headers[name] = values.join(", ");
            }
            resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks) });
          });
        },
      );
      req.on("error", reject);
      if (message.body !== undefined) req.write(message.body);
      req.end();
    });
  };
}

/** A further route of a stub: true when it answered the request. */
export type StubRoute = (req: IncomingMessage, res: ServerResponse, body: Buffer) => boolean;

/** An issuer stub: its metadata document and JWKS, served on loopback. */
export interface IssuerStub {
  id: string;
  key: SigningKey;
  kid: string;
  running: RunningServer;
  /** The metadata document; a test may change it. */
  metadata: Record<string, unknown>;
  mint(typ: AAuthTokenType, claims: Record<string, unknown>): Promise<string>;
  /** Stop listening: a connection to the stub is refused until {@link IssuerStub.up}. */
  down(): Promise<void>;
  /** Listen again, on a new port the net maps the identifier to. */
  up(): Promise<void>;
}

export async function startIssuer(
  net: LoopbackNet,
  id: string,
  dwk: string,
  route?: StubRoute,
): Promise<IssuerStub> {
  const kid = `${new URL(id).hostname}-key-1`;
  const key = generateSigningKey("Ed25519", kid);
  const metadata: Record<string, unknown> = { issuer: id, jwks_uri: `${id}/.well-known/jwks.json` };
  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    if (route?.(req, res, Buffer.concat(chunks))) return;
    const body =
      req.url === `/.well-known/${dwk}`
        ? metadata
        : req.url === "/.well-known/jwks.json"
          ? { keys: [key.publicJwk] }
          : undefined;
    res.writeHead(body ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(body ?? {}));
  };
  const stub: IssuerStub = {
    id,
    key,
    kid,
    running: await listen(handler),
    metadata,
    mint: (typ, claims) =>
      mintToken(typ, claims, { alg: key.alg, privateKey: key.privateKey, kid }),
    down: () => stub.running.close(),
    up: async () => {
      stub.running = await listen(handler);
      net.register(id, stub.running.origin);
    },
  };
  net.register(id, stub.running.origin);
  return stub;
}

/** How the revocation recipient answers a verified revocation. */
export type RecipientMode =
  | "ok"
  | "ok-json"
  | "garbage"
  | "unavailable"
  | "rate-limited"
  | "unsupported-iss"
  | "bad-request"
  | "deferred"
  | "hang"
  | "reset";

/** A revocation the recipient verified and recorded. */
export interface RecordedRevocation {
  iss: string;
  jti: string;
  exp: number;
  /** The verified request: its signer and covered components. */
  verified: VerifiedRequest;
  /** The `created` of its signature. */
  created: number;
}

/**
 * A minimal revocation recipient (AAuth -11 Section 11.12): a resource's
 * `revocation_endpoint` that verifies the caller as a server signing under
 * `jwks_uri` through the library, with a replay cache, records `(iss, jti,
 * exp)` with `iss` the verified signer, and answers as `mode` says.
 * Only `revoked` holds what it recorded; `requests` counts every POST.
 */
export interface Recipient extends IssuerStub {
  mode: RecipientMode;
  /** `jti` values answered 503 whatever the mode. */
  failFor: Set<string>;
  revoked: RecordedRevocation[];
  requests: number;
  /** Seconds a `rate-limited` answer asks the PS to wait. */
  retryAfter: number;
  /** Run when a revocation arrives, before it is answered. */
  onRequest?: (jti: string) => void;
}

export const REVOKE_PATH = "/revoke";

export async function startRecipient(
  net: LoopbackNet,
  id: string,
  clock: Clock,
  resolver: () => JwksResolver,
): Promise<Recipient> {
  const replayCache = new InMemoryReplayCache();
  let recipient: Recipient | undefined;
  const route: StubRoute = (req, res, body) => {
    if (req.method !== "POST" || req.url !== REVOKE_PATH || !recipient) return false;
    const r = recipient;
    r.requests += 1;
    const headers: Record<string, string[]> = {};
    for (const [name, value] of Object.entries(req.headersDistinct)) {
      if (value) headers[name] = value;
    }
    const answer = (status: number, json?: unknown, extra: Record<string, string> = {}) => {
      if (json === undefined) {
        res.writeHead(status, extra);
        res.end();
      } else {
        res.writeHead(status, { "content-type": "application/json", ...extra });
        res.end(typeof json === "string" ? json : JSON.stringify(json));
      }
    };
    void verifyRequest(
      { method: "POST", url: `${id}${req.url}`, headers, body },
      {
        resolver: resolver(),
        now: clock.now,
        acceptedSchemes: ["jwks_uri"],
        requireBodyComponents: true,
        replayCache,
      },
    ).then(
      (verified) => {
        const params = JSON.parse(body.toString("utf8")) as { jti: string; exp: number };
        r.onRequest?.(params.jti);
        if (r.mode === "reset") {
          req.socket.destroy();
          return;
        }
        if (r.mode === "hang") return;
        if (r.failFor.has(params.jti) || r.mode === "unavailable") {
          return answer(503, { error: "server_error" });
        }
        if (r.mode === "unsupported-iss") return answer(403, { error: "unsupported_iss" });
        if (r.mode === "bad-request") return answer(400, { error: "invalid_request" });
        if (r.mode === "rate-limited") {
          return answer(429, { error: "rate_limited" }, { "retry-after": String(r.retryAfter) });
        }
        if (r.mode === "deferred") return answer(202, undefined, { location: `${id}/pending/1` });
        r.revoked.push({
          iss: (verified.signer as { id: string }).id,
          jti: params.jti,
          exp: params.exp,
          verified,
          created: verified.created,
        });
        if (r.mode === "garbage") return answer(200, "not json at all");
        if (r.mode === "ok-json") return answer(200, { downstream: [] });
        return answer(200);
      },
      (err: unknown) => {
        if (err instanceof SignatureError) {
          return answer(401, { error: err.code, detail: err.detail }, err.headers);
        }
        return answer(500, { error: "server_error" });
      },
    );
    return true;
  };
  const stub = await startIssuer(net, id, "aauth-resource.json", route);
  stub.metadata.revocation_endpoint = `${id}${REVOKE_PATH}`;
  recipient = Object.assign(stub, {
    mode: "ok" as RecipientMode,
    failFor: new Set<string>(),
    revoked: [],
    requests: 0,
    retryAfter: 120,
  });
  return recipient;
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
  /** The body exactly as received. */
  text: string;
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
          text,
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
 * Everything an observer can compare: the status, the exact body bytes,
 * and every header with its value. `date` is the wall clock at sending,
 * so only its presence is compared.
 */
export function observable(r: Reply): { status: number; text: string; headers: string[][] } {
  const headers: string[][] = [];
  r.headers.forEach((value, name) => {
    headers.push([name, name === "date" ? "<present>" : value]);
  });
  headers.sort(([a], [b]) => ((a as string) < (b as string) ? -1 : 1));
  return { status: r.status, text: r.text, headers };
}

/** A statically configured administrator, with the private half of its enrolled key. */
export interface Admin {
  id: string;
  dwk: string;
  kid: string;
  key: SigningKey;
}

export function makeAdmin(id: string, kid = "admin-1"): Admin {
  return { id, dwk: "mission-admin.json", kid, key: generateSigningKey("Ed25519", kid) };
}

/** Its configuration entry: the enrolled public key, persons and actions. */
export function adminEntry(
  admin: Admin,
  persons: string[],
  actions: string[] = ["status", "terminate"],
): Record<string, unknown> {
  return { id: admin.id, dwk: admin.dwk, key: admin.key.publicJwk, persons, actions };
}

/** The headers and body of a request an administrator signs under `jwks_uri`. */
export function prepareAdmin(
  clock: Clock,
  url: string,
  admin: Admin,
  body: unknown,
  options: { tick?: number; dwk?: string; kid?: string; key?: SigningKey } = {},
): { headers: Record<string, string>; body: string } {
  clock.advance(options.tick ?? 1);
  const text = JSON.stringify(body);
  const headers: Record<string, string> = { "content-type": "application/json" };
  const key = options.key ?? admin.key;
  const added = signRequest(
    { method: "POST", url, headers, body: text },
    {
      alg: key.alg,
      privateKey: key.privateKey,
      signatureKey: {
        scheme: "jwks_uri",
        id: admin.id,
        dwk: options.dwk ?? admin.dwk,
        kid: options.kid ?? admin.kid,
      },
      created: clock.s,
    },
  );
  return { headers: { ...headers, ...added }, body: text };
}

/** A control-plane request to `{mission_control_endpoint}/{s256}` from an agent or an administrator. */
export function control(
  w: World,
  caller: Agent | Admin,
  s256: string,
  body: unknown,
  options: { tick?: number } = {},
): Promise<Reply> {
  const url = `${w.origin}/mission-control/${s256}`;
  if ("dwk" in caller) return send("POST", url, prepareAdmin(w.clock, url, caller, body, options));
  return signed(w.clock, "POST", url, caller, body, options);
}

/** A terminate body with a fresh 128-bit `request_id`. */
export function terminateBody(
  reason = "revoked",
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    action: "terminate",
    reason,
    request_id: `t-${randomUUID().replaceAll("-", "")}`,
    ...extra,
  };
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
  /** Serve the control plane (default true). */
  management?: boolean;
  /** Run revocation work on this interval once listening (default 0: only when asked). */
  pollIntervalMs?: number;
}

export const ADMIN = "https://admin.ps.test";
export const ADMIN_BOB = "https://admin-bob.ps.test";
export const AUDITOR = "https://auditor.ps.test";

/**
 * The test deployment's control-plane policy: the shipped one, with three
 * administrators whose keys the tests hold (alice's, bob's, and a
 * status-only auditor of alice's missions), and a small retry bound.
 */
function testManagement(doc: Record<string, unknown>, admins: Record<string, Admin>): void {
  const m = doc.management as Record<string, unknown>;
  m.administrators = [
    adminEntry(admins.alice as Admin, ["alice"]),
    adminEntry(admins.bob as Admin, ["bob"]),
    adminEntry(admins.auditor as Admin, ["alice"], ["status"]),
  ];
  // Wall-clock limits generous enough for a loaded test run: a test that
  // needs an attempt to time out sets its own.
  m.revocation = {
    max_attempts: 4,
    retry_base_seconds: 30,
    retry_max_seconds: 120,
    attempt_timeout_ms: 4000,
    immediate_wait_ms: 10000,
  };
}

export interface World {
  clock: Clock;
  net: LoopbackNet;
  ap: IssuerStub;
  /** A resource that publishes a revocation endpoint. */
  rs: Recipient;
  /** A resource that publishes none. */
  rs2: IssuerStub;
  /** Another person server, publishing its own keys. */
  ps2: IssuerStub;
  ps: PersonServer;
  faults: FaultyStore;
  /** The durable store behind `faults`, which the control plane uses directly. */
  durable: SqlitePsStore;
  admins: { alice: Admin; bob: Admin; auditor: Admin };
  /** The PS's identifier, under which agents address and sign its endpoints. */
  origin: string;
  /** Where the PS listens: `http://127.0.0.1:<port>`, a transport address. */
  loopback: string;
  /** A token signed with the PS's own key, as the PS would never mint it. */
  psMint(typ: AAuthTokenType, claims: Record<string, unknown>): Promise<string>;
  /**
   * Stop the PS, close its store, and start another PS on the same file
   * with the same signing key: a restart. `config` adjusts the document
   * the world started with, for a restart that changes deployment policy.
   */
  restart(options?: {
    pollIntervalMs?: number;
    config?: (doc: Record<string, unknown>) => void;
  }): Promise<void>;
  close(): Promise<void>;
}

/** A PS on loopback with an agent provider, two resources and a second PS. */
export async function world(options: WorldOptions = {}): Promise<World> {
  const clock = new Clock();
  const net = new LoopbackNet();
  const ap = await startIssuer(net, AP, "aauth-agent.json");
  const rs = await startRecipient(net, RS, clock, () => net.resolver(clock));
  const rs2 = await startIssuer(net, RS2, "aauth-resource.json");
  const ps2 = await startIssuer(net, PS2, "aauth-person.json");
  const admins = {
    alice: makeAdmin(ADMIN),
    bob: makeAdmin(ADMIN_BOB),
    auditor: makeAdmin(AUDITOR),
  };
  const doc = shippedConfig();
  testManagement(doc, admins);
  options.config?.(doc);
  const dir = mkdtempSync(join(tmpdir(), "aauth-ps-"));
  const file = join(dir, "ps.db");
  const managed = options.management ?? true;
  const boot = (
    durable: SqlitePsStore,
    signingKey?: SigningKey,
    pollIntervalMs = 0,
    adjust?: (doc: Record<string, unknown>) => void,
  ) => {
    const faults = new FaultyStore(durable);
    const current = structuredClone(doc);
    adjust?.(current);
    const ps = createPersonServer({
      config: parsePsConfig(current),
      store: faults,
      resolver: net.resolver(clock),
      now: clock.now,
      ...(signingKey ? { signingKey } : {}),
      ...(managed
        ? {
            management: {
              store: durable,
              transport: net.request,
              sleep: clock.sleep,
              pollIntervalMs,
            },
          }
        : {}),
    });
    return { faults, ps };
  };
  const durable = new SqlitePsStore(file);
  const first = boot(durable, undefined, options.pollIntervalMs ?? 0);
  let running = await first.ps.listen();
  net.register(PS, running.origin);
  activeNet = net;
  const w: World = {
    clock,
    net,
    ap,
    rs,
    rs2,
    ps2,
    ps: first.ps,
    faults: first.faults,
    durable,
    admins,
    origin: PS,
    loopback: running.origin,
    psMint: (typ, c) =>
      mintToken(typ, c, {
        alg: w.ps.signingKey.alg,
        privateKey: w.ps.signingKey.privateKey,
        kid: w.ps.signingKey.publicJwk.kid as string,
      }),
    restart: async (restartOptions = {}) => {
      await running.close();
      w.durable.close();
      w.durable = new SqlitePsStore(file);
      const next = boot(
        w.durable,
        w.ps.signingKey,
        restartOptions.pollIntervalMs ?? 0,
        restartOptions.config,
      );
      w.ps = next.ps;
      w.faults = next.faults;
      running = await w.ps.listen();
      net.register(PS, running.origin);
      w.loopback = running.origin;
    },
    close: async () => {
      await running.close();
      for (const stub of [ap, rs, rs2, ps2]) await stub.running.close();
      w.durable.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return w;
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

/**
 * Run `effect` each time a key of `issuer` has been resolved, as if time
 * passed or state changed during that key fetch. A test that uses it
 * restores the resolver with `vi.restoreAllMocks()`.
 */
export function whileResolving(issuer: string, effect: () => void): void {
  const original = JwksResolver.prototype.resolveKey;
  vi.spyOn(JwksResolver.prototype, "resolveKey").mockImplementation(async function (
    this: JwksResolver,
    ...args: Parameters<JwksResolver["resolveKey"]>
  ) {
    const key = await original.apply(this, args);
    if (args[0] === issuer) effect();
    return key;
  });
}
