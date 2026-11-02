/**
 * @spec request-provenance#intake-isolation, request-provenance#capture,
 * request-provenance#signing, request-provenance#assertion,
 * request-provenance#audit (#939 slice 2b-1, D1119 Q6)
 *
 * The demo request intake: a party of its own, with its own listener, issuer
 * and ephemeral ES256 signing key, that wraps `@mission/request-provenance`'s
 * `createRequestIntake` behind four closed HTTP endpoints. It is a demo
 * service, started in-process by a test assembly; the shipped compositions
 * never start it, and the authorization server accepts its assertions only
 * where a caller enables the type with this intake's {@link
 * RequestIntakeService.signer} entry (D1151, D1157).
 *
 * **Originator authentication.** The intake is an OpenID Connect relying
 * party of the reference IdP (`approver-idp.ts`), reusing the authorization
 * server's `ApproverLoginRelyingParty` under its own client registration and
 * callback path: an authorization code request with PKCE, `state`, `nonce`
 * and `prompt=login`, the code redeemed with the intake's client credentials,
 * and the ID Token validated as OpenID Connect Core 1.0 Section 3.1.3.7
 * requires. A completed login opens an intake session, named by an
 * unguessable cookie, that holds the originator (`iss` and `sub` of the
 * validated ID Token) and the channel facts (`acr`, `amr` and `auth_time` as
 * that ID Token asserts them, under this intake's one channel type). Neither
 * ever comes from configuration or from a request.
 *
 * **Endpoints.** Each is closed: a query parameter, or a body member, it
 * does not define is refused, and a refused request creates no capture
 * record and yields no assertion.
 *
 * - `GET /login` (no parameters): starts the originator's login at the IdP.
 * - `GET /login/callback`: the IdP's authorization response (`code`,
 *   `state`, `iss`, or `error`, `error_description`, `error_uri`); opens the
 *   intake session.
 * - `POST /capture`, in the originator's intake session: a JSON body of
 *   exactly `{"instruction": <base64url of the exact bytes>, "media_type":
 *   <the media type as recorded>}`. The originator and the channel come from
 *   the session; the presenter is the one client this intake is configured
 *   to serve (its `client_id`, with no `cnf`, as a pushed authorization
 *   request establishes it). Returns `{capture_id, workflow_token}`: the
 *   workflow token is 256 bits from a cryptographically secure random
 *   source, and it is the only credential the signing endpoint accepts.
 * - `POST /sign`, with `Authorization: Bearer <workflow token>`: a JSON body
 *   of exactly `{"intent": <the candidate Intent>}`. The intake signs only
 *   from the capture record the token's workflow created, for the one
 *   authorization server it is configured for (`aud`), computing
 *   `intent_hash` itself. Returns the evidence entry `{type, assertion}`.
 *
 * **Isolation.** The shaper holds only what the console hands it: the
 * instruction it shapes and the workflow token. Capture needs the
 * originator's session, which only the originator's user agent holds, so
 * the shaper can create no capture record; no endpoint alters one; and the
 * signing endpoint names no capture, takes no originator, channel,
 * presenter, digest, `intent_hash` or audience, and resolves the capture
 * from the token alone, so the shaper can obtain no signature over a request
 * this intake did not capture.
 *
 * **Retention.** Capture records (the instruction, its media type, the
 * capture secret, the request digest, the origin facts, and the `jti` of
 * every assertion issued from the record) live in this process's memory
 * only: nothing writes them to disk, and {@link RequestIntakeService.close}
 * drops them with the sessions and workflow tokens. That is the retention
 * this demo intake declares (request-provenance#audit): for the life of the
 * process. A workflow token signs only while its capture is within the
 * maximum capture age, and a session lasts `sessionLifetimeSeconds`. The
 * draft defines no audit-retrieval endpoint and this intake serves none; no
 * role here reads a capture record, and {@link RequestIntakeService.counts}
 * is an in-process count for a test assembly, not an endpoint.
 *
 * A deployed intake substitutes its own originator authentication, durable
 * capture storage with an enforced retention, and access-controlled audit
 * roles. Nothing here is evidence of an independently deployed intake.
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { ApproverLoginError, ApproverLoginRelyingParty } from "@mission/authorization-server";
import { DuplicateMemberError, parseStrictJson } from "@mission/core";
import type { RequestProvenanceSignerConfig } from "@mission/demo-data";
import {
  type CaptureReceipt,
  type Channel,
  createRequestIntake,
  type JsonObject,
  type Originator,
  type Presenter,
  REQUEST_PROVENANCE_ALG,
  REQUEST_PROVENANCE_TYPE,
  type RequestIntake,
  RequestProvenanceError,
  type SignedProvenance,
} from "@mission/request-provenance";
import { exportJWK, generateKeyPair } from "jose";

/** The intake's client registration at the originator's IdP. */
export const REQUEST_INTAKE_CLIENT_ID = "mission-request-intake";
export const REQUEST_INTAKE_LOGIN_PATH = "/login";
export const REQUEST_INTAKE_CALLBACK_PATH = "/login/callback";
export const REQUEST_INTAKE_CAPTURE_PATH = "/capture";
export const REQUEST_INTAKE_SIGN_PATH = "/sign";
/** The intake session's cookie. */
export const REQUEST_INTAKE_SESSION_COOKIE = "request_intake_session";
/** The intake signing key's `kid`. */
export const REQUEST_INTAKE_KID = "request-intake-1";
/** The workflow token's length in bytes: 256 bits. */
export const WORKFLOW_TOKEN_BYTES = 32;

const MAX_BODY_BYTES = 64 * 1024;
const CALLBACK_PARAMETERS = new Set(["code", "state", "iss", "error", "error_description", "error_uri"]);
const CAPTURE_MEMBERS = new Set(["instruction", "media_type"]);
const SIGN_MEMBERS = new Set(["intent"]);

/** The intake's registration at the originator's IdP, returned once the intake knows its redirect URI. */
export interface OriginatorIdpRegistration {
  /** The IdP's issuer identifier: every originator's `iss`. */
  issuer: string;
  /** The intake's client credentials there (`client_secret_basic`). */
  clientId: string;
  clientSecret: string;
  /** The IdP accounts (`sub`) that may submit instructions here; any other account logs no one in. */
  originators: readonly string[];
  /** `acr_values` requested at the IdP: voluntary, and the channel records what the IdP asserted. */
  acrValues?: readonly string[];
}

export interface RequestIntakeOptions {
  /** The one authorization server this intake signs for: every assertion's `aud`. */
  audience: string;
  /** The one client that submits the workflow: its `client_id`, with no `cnf` (a pushed authorization request establishes none). */
  presenter: { client_id: string };
  /** Register the intake at the originator's IdP, given its redirect URI. */
  originatorIdp: (redirectUri: string) => Promise<OriginatorIdpRegistration>;
  /** `exp` minus `iat`, in seconds. Default 300. */
  assertionLifetimeSeconds?: number;
  /** The largest `iat` minus `captured_at` the intake signs, in seconds. Default 600. */
  maxCaptureAgeSeconds?: number;
  /** How long an intake session lasts, in seconds. Default 900. */
  sessionLifetimeSeconds?: number;
  host?: string;
  /** 0 (the default): any free port. */
  port?: number;
}

export interface RequestIntakeService {
  /** The intake's issuer identifier: the assertion's `iss`. */
  issuer: string;
  kid: string;
  /** The public half of the intake's signing key: curve and coordinates only. */
  publicJwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
  /** The authorization server every assertion names in `aud`. */
  audience: string;
  /** This intake's one channel type. */
  channelType: string;
  /**
   * The trust-configuration signer entry an authorization server needs for
   * this intake (request-provenance#trust-configuration): its `iss`, its one
   * key mapped to `mission-request-provenance` for ES256, the originator
   * IdP's issuer with no `sub` (a service signer), and its one channel type.
   */
  signer(): RequestProvenanceSignerConfig;
  /** In-process counts for a test assembly: no endpoint serves them, and they read no capture record. */
  counts(): { captures: number; assertions: number };
  /** Close the listener and drop every capture record, session and workflow token. */
  close(): Promise<void>;
}

interface Session {
  originator: Originator;
  channel: Channel;
  expires: number;
}

interface Workflow {
  workflow: string;
  captureId: string;
}

/** A refusal: the status and the local diagnostic it returns. */
class Refusal extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    description: string,
  ) {
    super(description);
  }
}

const digestOf = (secret: string): string => createHash("sha256").update(secret).digest("base64url");
const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.setHeader("cache-control", "no-store");
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

/** Refuse any query parameter: these endpoints define none. */
function noParameters(url: URL): void {
  for (const name of url.searchParams.keys()) {
    throw new Refusal(400, "invalid_request", `this endpoint takes no parameter: ${name}`);
  }
}

/** One cookie's value, or undefined when it is absent or repeated. */
function cookie(req: IncomingMessage, name: string): string | undefined {
  const values = (req.headers.cookie ?? "")
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.startsWith(`${name}=`))
    .map((s) => s.slice(name.length + 1));
  return values.length === 1 ? values[0] : undefined;
}

/** The request's closed JSON object body: exactly `members`, each present once, the rest refused. */
async function closedJsonBody(req: IncomingMessage, members: ReadonlySet<string>): Promise<Record<string, unknown>> {
  const type = (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") throw new Refusal(415, "invalid_request", "the body must be application/json");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Refusal(413, "invalid_request", "the body is too large");
    chunks.push(chunk as Buffer);
  }
  let value: unknown;
  try {
    value = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
  } catch (e) {
    const why = e instanceof DuplicateMemberError ? e.message : "the body is not valid JSON";
    throw new Refusal(400, "invalid_request", why);
  }
  if (!isPlainObject(value)) throw new Refusal(400, "invalid_request", "the body must be a JSON object");
  for (const key of Object.keys(value)) {
    if (!members.has(key)) throw new Refusal(400, "invalid_request", `the body carries a member this endpoint does not accept: ${key}`);
  }
  for (const key of members) {
    if (!Object.hasOwn(value, key)) throw new Refusal(400, "invalid_request", `the body has no ${key}`);
  }
  return value;
}

/** The exact bytes a canonical, unpadded base64url string encodes. */
function base64urlBytes(v: unknown): Buffer {
  if (typeof v !== "string" || v.length === 0 || !/^[A-Za-z0-9_-]+$/.test(v)) {
    throw new Refusal(400, "invalid_request", "instruction must be the unpadded base64url of the instruction's bytes");
  }
  const bytes = Buffer.from(v, "base64url");
  if (bytes.length === 0 || bytes.toString("base64url") !== v) {
    throw new Refusal(400, "invalid_request", "instruction must be the canonical base64url of at least one byte");
  }
  return bytes;
}

function positive(v: number | undefined, fallback: number, what: string): number {
  const n = v ?? fallback;
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${what} must be a positive integer number of seconds`);
  return n;
}

/**
 * Start the intake on `port` (0: any free port) at `host`, register it at the
 * originator's IdP through `originatorIdp`, and generate its signing key.
 */
export async function startRequestIntake(opts: RequestIntakeOptions): Promise<RequestIntakeService> {
  if (!opts.audience) throw new Error("the intake signs for one authorization server: audience is required");
  const presenter: Presenter = (() => {
    const p = opts.presenter as unknown;
    if (!isPlainObject(p) || Object.keys(p).some((k) => k !== "client_id") || typeof p.client_id !== "string" || !p.client_id) {
      throw new Error("the presenter is one client_id, with no cnf: a pushed authorization request establishes no confirmation key");
    }
    return { client_id: p.client_id };
  })();
  const assertionLifetime = positive(opts.assertionLifetimeSeconds, 300, "assertionLifetimeSeconds");
  const maxCaptureAge = positive(opts.maxCaptureAgeSeconds, 600, "maxCaptureAgeSeconds");
  const sessionLifetime = positive(opts.sessionLifetimeSeconds, 900, "sessionLifetimeSeconds");

  const host = opts.host ?? "127.0.0.1";
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, host, () => resolve());
  });
  const issuer = `http://${host}:${(server.address() as AddressInfo).port}`;
  const channelType = `${issuer}/channels/oidc-login`;
  const close = () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });

  let registration: OriginatorIdpRegistration;
  let login: ApproverLoginRelyingParty;
  try {
    registration = await opts.originatorIdp(`${issuer}${REQUEST_INTAKE_CALLBACK_PATH}`);
    if (registration.originators.length === 0) throw new Error("the intake serves at least one originator");
    login = new ApproverLoginRelyingParty(
      {
        issuer: registration.issuer,
        clientId: registration.clientId,
        clientSecret: registration.clientSecret,
        idTokenSigningAlgs: ["ES256"],
        // The accounts this intake serves; the mapped name is unused, since
        // the originator is the ID Token's own issuer-qualified identity.
        identities: registration.originators.map((sub) => ({ iss: registration.issuer, sub, approver: sub })),
        ...(registration.acrValues?.length ? { acrValues: registration.acrValues } : {}),
      },
      issuer,
      () => Date.now(),
      REQUEST_INTAKE_CALLBACK_PATH,
    );
  } catch (e) {
    await close();
    throw e;
  }

  const { privateKey, publicKey } = await generateKeyPair(REQUEST_PROVENANCE_ALG, { extractable: true });
  const exported = await exportJWK(publicKey);
  const publicJwk = { kty: "EC" as const, crv: "P-256" as const, x: exported.x as string, y: exported.y as string };
  let intake: RequestIntake | undefined = createRequestIntake({
    issuer,
    kid: REQUEST_INTAKE_KID,
    signingKey: privateKey,
    assertionLifetimeSeconds: assertionLifetime,
    maxCaptureAgeSeconds: maxCaptureAge,
  });

  // Keyed by a hash of each credential, so no stored key is itself a credential.
  const sessions = new Map<string, Session>();
  const workflows = new Map<string, Workflow>();
  let captures = 0;
  let assertions = 0;

  const sessionOf = (req: IncomingMessage): Session => {
    const id = cookie(req, REQUEST_INTAKE_SESSION_COOKIE);
    const session = id ? sessions.get(digestOf(id)) : undefined;
    if (!id || !session) throw new Refusal(401, "login_required", "capture needs the originator's intake session");
    if (session.expires <= Date.now()) {
      sessions.delete(digestOf(id));
      throw new Refusal(401, "login_required", "the intake session ended; sign in again");
    }
    return session;
  };

  const workflowOf = (req: IncomingMessage): Workflow => {
    const m = /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization ?? "");
    const workflow = m ? workflows.get(digestOf(m[1] as string)) : undefined;
    if (!workflow) throw new Refusal(401, "invalid_token", "signing needs the workflow token of a capture this intake made");
    return workflow;
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (!intake) throw new Refusal(503, "unavailable", "the intake is closed");
    const store = intake;
    const url = new URL(req.url ?? "/", issuer);
    if (url.pathname === REQUEST_INTAKE_LOGIN_PATH && req.method === "GET") {
      noParameters(url);
      const started = await login.start(randomBytes(16).toString("base64url"), undefined);
      res.statusCode = 303;
      res.setHeader("location", started.location);
      res.setHeader("set-cookie", started.cookie);
      res.setHeader("cache-control", "no-store");
      res.end();
      return;
    }
    if (url.pathname === REQUEST_INTAKE_CALLBACK_PATH && req.method === "GET") {
      const query: Record<string, string | string[]> = {};
      for (const name of new Set(url.searchParams.keys())) {
        if (!CALLBACK_PARAMETERS.has(name)) throw new Refusal(400, "invalid_request", `the callback takes no parameter ${name}`);
        const values = url.searchParams.getAll(name);
        query[name] = values.length === 1 ? (values[0] as string) : values;
      }
      let completed: Awaited<ReturnType<ApproverLoginRelyingParty["complete"]>>;
      try {
        completed = await login.complete(query, req.headers.cookie ?? "");
      } catch (e) {
        if (e instanceof ApproverLoginError) throw new Refusal(401, "access_denied", e.message);
        throw e;
      }
      const token = completed.login;
      const amr = token.amr;
      if (amr !== undefined && (!Array.isArray(amr) || !amr.every((m) => typeof m === "string" && m.length > 0))) {
        throw new Refusal(401, "access_denied", "the ID Token's amr claim is not an array of strings");
      }
      // The originator and the channel facts, exactly as the IdP asserted them.
      const channel: Channel = {
        type: channelType,
        acr: token.acr,
        ...(amr !== undefined ? { amr: [...(amr as string[])] } : {}),
        auth_time: token.auth_time,
      };
      const id = randomBytes(32).toString("base64url");
      sessions.set(digestOf(id), {
        originator: { iss: token.iss, sub: token.sub },
        channel,
        expires: Date.now() + sessionLifetime * 1000,
      });
      send(res, 200, { signed_in: true }, {
        "set-cookie": `${REQUEST_INTAKE_SESSION_COOKIE}=${id}; Path=/; Max-Age=${sessionLifetime}; HttpOnly; SameSite=Strict`,
      });
      return;
    }
    if (url.pathname === REQUEST_INTAKE_CAPTURE_PATH && req.method === "POST") {
      noParameters(url);
      const session = sessionOf(req);
      const body = await closedJsonBody(req, CAPTURE_MEMBERS);
      const instruction = base64urlBytes(body.instruction);
      if (typeof body.media_type !== "string") throw new Refusal(400, "invalid_request", "media_type must be a string");
      const workflow = randomBytes(16).toString("base64url");
      let receipt: CaptureReceipt;
      try {
        receipt = store.capture({
          workflow,
          instruction,
          mediaType: body.media_type,
          originator: session.originator,
          channel: session.channel,
          presenter,
        });
      } catch (e) {
        if (e instanceof RequestProvenanceError) throw new Refusal(400, "invalid_request", e.message);
        throw e;
      }
      captures += 1;
      const workflowToken = randomBytes(WORKFLOW_TOKEN_BYTES).toString("base64url");
      workflows.set(digestOf(workflowToken), { workflow, captureId: receipt.captureId });
      send(res, 201, { capture_id: receipt.captureId, workflow_token: workflowToken });
      return;
    }
    if (url.pathname === REQUEST_INTAKE_SIGN_PATH && req.method === "POST") {
      noParameters(url);
      const workflow = workflowOf(req);
      const body = await closedJsonBody(req, SIGN_MEMBERS);
      if (!isPlainObject(body.intent)) throw new Refusal(400, "invalid_request", "intent must be a Mission Intent object");
      let signed: SignedProvenance;
      try {
        signed = await store.sign({
          captureId: workflow.captureId,
          workflow: workflow.workflow,
          audience: opts.audience,
          intent: body.intent as JsonObject,
        });
      } catch (e) {
        if (e instanceof RequestProvenanceError) {
          throw new Refusal(400, e.code === "capture_too_old" ? "capture_too_old" : "invalid_request", e.message);
        }
        throw e;
      }
      assertions += 1;
      send(res, 200, signed.entry);
      return;
    }
    throw new Refusal(404, "not_found", "no such endpoint");
  };

  server.on("request", (req, res) => {
    handle(req, res).catch((e: unknown) => {
      if (res.headersSent) return;
      if (e instanceof Refusal) send(res, e.status, { error: e.error, error_description: e.message });
      else send(res, 500, { error: "server_error" });
    });
  });

  return {
    issuer,
    kid: REQUEST_INTAKE_KID,
    publicJwk,
    audience: opts.audience,
    channelType,
    signer: () => ({
      iss: issuer,
      keys: [{ kid: REQUEST_INTAKE_KID, public_jwk: { ...publicJwk }, evidence_types: [REQUEST_PROVENANCE_TYPE], algs: ["ES256"] }],
      originators: [{ iss: registration.issuer }],
      channel_types: [channelType],
    }),
    counts: () => ({ captures, assertions }),
    close: async () => {
      intake = undefined;
      sessions.clear();
      workflows.clear();
      await close();
    },
  };
}
