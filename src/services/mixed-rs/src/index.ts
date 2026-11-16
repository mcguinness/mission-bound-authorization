/**
 * @spec mission#scope-projection-per-audience, mission#rs-requirements (#2072,
 * D1321, D1326): a mixed Resource Server. At one audience it enforces a read
 * through a projected `scope` and a capped write through an
 * `authorization_details` entry, the arrangement the OAuth binding's mixed
 * audience describes. plain-rs stays the scope-only baseline.
 *
 * - `GET /api/reports` needs the `reports.read` scope value, and reads no
 *   entry.
 * - `POST /api/reports` needs one `mission_resource_access` entry that on its
 *   own covers the request: it matches the operation target with the Resource
 *   Access matcher, carries the write action, and every `constraints` key it
 *   carries is one this server enforces against the request (`max_amount`
 *   over the report's `cost`). The write path never reads `scope`, so no scope
 *   value widens or bypasses the entry (rs-requirements). An entry this server
 *   cannot fully enforce provides no authority, and leaves the others to
 *   authorize on their own.
 *
 * Access tokens are RFC 9068 JWTs from one issuer, sender-constrained by RFC
 * 9449 DPoP when they carry `cnf.jkt`, with the same checks plain-rs makes. A
 * write also needs the `mission` claim, naming that issuer as the Mission's.
 */

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  compareAmounts,
  entryMatchesTarget,
  establishOperationTarget,
  isCurrencyCode,
  isValidAmount,
} from "@mission/core";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  type JSONWebKeySet,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
  jwtVerify,
} from "jose";

/** The scope value the read path enforces. */
export const READ_SCOPE = "reports.read";
/** The action the write path enforces through an entry. */
export const WRITE_ACTION = "reports:report.write";

export interface MixedRsOptions {
  /** The expected `iss`, which is also the Mission issuer a write's `mission` claim names. */
  issuer: string;
  /** This server's audience identifier and the write operation's service-level target. */
  audience: string;
  /** The Authorization Server's JWKS, by URI or inline; exactly one. */
  jwksUri?: string;
  jwks?: JSONWebKeySet;
  /** The external base URL requests arrive at, used to rebuild the DPoP `htu`. Defaults to the audience's origin. */
  baseUrl?: string;
  /** Accepted token and proof signature algorithms (asymmetric only). */
  algorithms?: string[];
  /** Accepted DPoP proof age, in seconds, either side of now. Default 60. */
  dpopWindowSeconds?: number;
  /** Clock, in seconds. Default: the system clock. */
  now?: () => number;
}

export interface MixedReport {
  id: string;
  title: string;
  cost: { amount: string; currency: string };
  mission_id: string;
}

/** The request handler, with the reports its writes have created. */
export interface MixedRsHandler {
  (req: IncomingMessage, res: ServerResponse): Promise<void>;
  readonly reports: readonly MixedReport[];
}

const DEFAULT_ALGS = ["RS256", "PS256", "ES256", "ES384", "EdDSA"];
const JWK_THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;
const ENTRY_TYPE = "mission_resource_access";

/**
 * @spec resource-access#rs-enforcement (#1362): the entry members this server
 * recognizes. `delegation` is applied at issuance and disregarded here; any
 * other member has no role and makes the entry one this server cannot fully
 * enforce. Decided by presence.
 */
const ENTRY_MEMBER_ROLES: Readonly<Record<string, "enforced" | "disregarded">> = {
  type: "enforced",
  resource: "enforced",
  resource_match: "enforced",
  actions: "enforced",
  constraints: "enforced",
  delegation: "disregarded",
};

type Cost = { amount: string; currency: string };

/**
 * @spec resource-access#rs-enforcement: the gate for each `constraints` key
 * this server enforces, against the write it serves. `max_amount` admits a
 * report whose `cost` is in the cap's currency and no larger than it. A
 * malformed cap admits nothing.
 */
const CONSTRAINT_GATES: Readonly<Record<string, (value: unknown, cost: Cost) => boolean>> = {
  max_amount: (value, cost) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const cap = value as { amount?: unknown; currency?: unknown };
    if (typeof cap.amount !== "string" || !isValidAmount(cap.amount) || !isCurrencyCode(cap.currency)) return false;
    return cap.currency === cost.currency && compareAmounts(cost.amount, cap.amount) <= 0;
  },
};

/** The `constraints` keys this server enforces, its `mission_constraints_supported`. */
export const MIXED_ENFORCED_CONSTRAINTS: readonly string[] = Object.freeze(Object.keys(CONSTRAINT_GATES));

type EntryVerdict = "covers" | "unenforceable" | "no";

/**
 * Whether one entry, on its own, covers the write at `target`. An entry that
 * applies (it matches the target and carries the write action) but carries a
 * member or `constraints` key this server cannot enforce is `unenforceable`:
 * it provides no authority.
 */
function entryVerdict(entry: unknown, target: string, cost: Cost): EntryVerdict {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return "no";
  const e = entry as Record<string, unknown> & { resource?: unknown; resource_match?: unknown };
  if (e.type !== ENTRY_TYPE) return "no";
  if (!entryMatchesTarget({ resource: e.resource, resource_match: e.resource_match }, target)) return "no";
  if (!Array.isArray(e.actions) || !e.actions.includes(WRITE_ACTION)) return "no";
  if (!Object.keys(e).every((member) => Object.hasOwn(ENTRY_MEMBER_ROLES, member))) return "unenforceable";
  if (!e.actions.every((a: unknown) => typeof a === "string" && a.length > 0)) return "unenforceable";
  if (e.constraints === undefined) return "covers";
  const c = e.constraints;
  if (!c || typeof c !== "object" || Array.isArray(c)) return "unenforceable";
  // Every key is classified before any is evaluated, so the verdict never
  // depends on key order.
  if (!Object.keys(c).every((key) => Object.hasOwn(CONSTRAINT_GATES, key))) return "unenforceable";
  return Object.entries(c).every(([key, value]) => (CONSTRAINT_GATES[key] as (v: unknown, cost: Cost) => boolean)(value, cost))
    ? "covers"
    : "no";
}

class Refusal extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly scheme: "Bearer" | "DPoP",
    readonly extra: Record<string, string> = {},
  ) {
    super(message);
  }
}

/** Build the request handler for a mixed Resource Server. */
export function mixedResourceServer(opts: MixedRsOptions): MixedRsHandler {
  if ([opts.jwks, opts.jwksUri].filter((k) => k !== undefined).length !== 1) {
    throw new Error("mixed-rs: give exactly one of jwks and jwksUri");
  }
  const keys: JWTVerifyGetKey = opts.jwks ? createLocalJWKSet(opts.jwks) : createRemoteJWKSet(new URL(opts.jwksUri as string));
  const algorithms = opts.algorithms ?? DEFAULT_ALGS;
  const baseUrl = (opts.baseUrl ?? new URL(opts.audience).origin).replace(/\/$/, "");
  const windowS = opts.dpopWindowSeconds ?? 60;
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const seenProofs = new Map<string, number>();
  const reports: MixedReport[] = [];
  // @spec resource-access#resource-matching (#1276): the write's target comes
  // from its declared service-level contract, never from an entry.
  const writeTarget = establishOperationTarget({ service: opts.audience });
  if (!writeTarget.ok) throw new Error(`mixed-rs: the write operation has no target: ${writeTarget.reason}`);

  function freshJti(jti: string): boolean {
    const t = now();
    for (const [k, exp] of seenProofs) if (exp < t) seenProofs.delete(k);
    if (seenProofs.has(jti)) return false;
    seenProofs.set(jti, t + 2 * windowS);
    return true;
  }

  async function verifyDpop(req: IncomingMessage, token: string, jkt: string): Promise<void> {
    const header = req.headers.dpop;
    const fail = (why: string) => new Refusal(401, "invalid_dpop_proof", why, "DPoP");
    if (typeof header !== "string" || !header) throw fail("a DPoP proof is required");
    let jwk: JWK;
    let proof: JWTPayload;
    try {
      jwk = decodeProtectedHeader(header).jwk as JWK;
      if (!jwk || typeof jwk !== "object" || "d" in jwk) throw new Error("jwk");
      ({ payload: proof } = await jwtVerify(header, jwk, { typ: "dpop+jwt", algorithms }));
    } catch {
      throw fail("the DPoP proof does not verify");
    }
    const path = (req.url ?? "/").split("?")[0] as string;
    if (proof.htm !== req.method || proof.htu !== `${baseUrl}${path}`) throw fail("htm or htu mismatch");
    if (typeof proof.iat !== "number" || Math.abs(now() - proof.iat) > windowS) throw fail("stale proof");
    const ath = createHash("sha256").update(token).digest().toString("base64url");
    if (proof.ath !== ath) throw fail("ath does not match the access token");
    if ((await calculateJwkThumbprint(jwk)) !== jkt) throw fail("proof key does not match cnf.jkt");
    if (typeof proof.jti !== "string" || !freshJti(proof.jti)) throw fail("proof jti missing or replayed");
  }

  /** RFC 9068 validation, then the token's sender constraint. */
  async function authenticate(req: IncomingMessage): Promise<{ payload: JWTPayload; scheme: "Bearer" | "DPoP" }> {
    const m = /^(Bearer|DPoP) +([A-Za-z0-9._~+/-]+=*)$/i.exec(req.headers.authorization ?? "");
    if (!m) throw new Refusal(401, "invalid_request", "an access token is required", "Bearer");
    const scheme = (m[1] as string).toLowerCase() === "dpop" ? "DPoP" : "Bearer";
    const token = m[2] as string;
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, keys, {
        typ: "at+jwt",
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms,
        requiredClaims: ["exp", "iat", "sub", "client_id", "jti"],
        currentDate: new Date(now() * 1000),
      }));
    } catch {
      throw new Refusal(401, "invalid_token", "the access token is not valid for this resource", scheme);
    }
    const cnf = payload.cnf;
    if (cnf !== undefined) {
      const members = cnf !== null && typeof cnf === "object" && !Array.isArray(cnf) ? Object.keys(cnf) : [];
      const jkt = members.length === 1 && members[0] === "jkt" ? (cnf as { jkt?: unknown }).jkt : undefined;
      if (typeof jkt !== "string" || !JWK_THUMBPRINT.test(jkt)) {
        throw new Refusal(401, "invalid_token", "unsupported or malformed confirmation method", scheme);
      }
      if (scheme !== "DPoP") throw new Refusal(401, "invalid_token", "a DPoP-bound token requires the DPoP scheme", "DPoP");
      await verifyDpop(req, token, jkt);
    } else if (scheme === "DPoP") {
      throw new Refusal(401, "invalid_token", "the token is not DPoP-bound", "DPoP");
    }
    return { payload, scheme };
  }

  /** The read path: the projected scope value alone. */
  function authorizeRead(payload: JWTPayload, scheme: "Bearer" | "DPoP"): void {
    const granted = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
    if (!granted.includes(READ_SCOPE)) {
      throw new Refusal(403, "insufficient_scope", `the operation requires scope ${READ_SCOPE}`, scheme, {
        scope: READ_SCOPE,
      });
    }
  }

  /**
   * The write path: one entry that covers the write on its own. It never reads
   * `scope` (rs-requirements). A refusal carries `mission_denial` and no
   * `scope`, since no scope value remedies it (mission#rs-denials).
   */
  function authorizeWrite(payload: JWTPayload, scheme: "Bearer" | "DPoP", cost: Cost): string {
    const mission = payload.mission as { id?: unknown; issuer?: unknown } | undefined;
    if (!mission || typeof mission.id !== "string" || mission.issuer !== opts.issuer) {
      throw new Refusal(401, "invalid_token", "a write needs this issuer's mission claim", scheme);
    }
    const entries = Array.isArray(payload.authorization_details) ? payload.authorization_details : [];
    const verdicts = entries.map((e) => entryVerdict(e, (writeTarget as { target: string }).target, cost));
    if (verdicts.includes("covers")) return mission.id;
    const denial = verdicts.includes("unenforceable") ? "constraint_unrecognized" : "insufficient_authority";
    throw new Refusal(403, "insufficient_scope", "no entry covers this write", scheme, { mission_denial: denial });
  }

  function challenge(r: Refusal): string {
    const params = [`error="${r.code}"`, `error_description="${r.message}"`];
    for (const [k, v] of Object.entries(r.extra)) params.push(`${k}="${v}"`);
    if (r.scheme === "DPoP") params.push(`algs="${algorithms.join(" ")}"`);
    return `${r.scheme} ${params.join(", ")}`;
  }

  function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
    res.end(JSON.stringify(body));
  }

  async function readCost(req: IncomingMessage): Promise<{ title: string; cost: Cost } | undefined> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    let v: unknown;
    try {
      v = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return undefined;
    }
    if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
    const body = v as { title?: unknown; cost?: { amount?: unknown; currency?: unknown } };
    const cost = body.cost;
    if (!cost || typeof cost.amount !== "string" || !isValidAmount(cost.amount) || !isCurrencyCode(cost.currency)) {
      return undefined;
    }
    return {
      title: typeof body.title === "string" ? body.title : "untitled",
      cost: { amount: cost.amount, currency: cost.currency },
    };
  }

  const handle = async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? "/").split("?")[0];
    if (path !== "/api/reports" || (req.method !== "GET" && req.method !== "POST")) {
      send(res, 404, { error: "not_found" });
      return;
    }
    try {
      const { payload, scheme } = await authenticate(req);
      if (req.method === "GET") {
        authorizeRead(payload, scheme);
        send(res, 200, { reports });
        return;
      }
      const input = await readCost(req);
      if (!input) {
        send(res, 400, { error: "invalid_request", error_description: "a report needs a title and a cost" });
        return;
      }
      const missionId = authorizeWrite(payload, scheme, input.cost);
      const report: MixedReport = { id: `rpt_${reports.length + 1}`, ...input, mission_id: missionId };
      reports.push(report);
      send(res, 201, report);
    } catch (e) {
      if (e instanceof Refusal) {
        send(res, e.status, { error: e.code, error_description: e.message }, { "www-authenticate": challenge(e) });
        return;
      }
      send(res, 500, { error: "server_error" });
    }
  };
  return Object.defineProperty(handle, "reports", { get: () => reports }) as MixedRsHandler;
}

/** Start the mixed Resource Server on `port`, returning the server and its handler. */
export function startMixedResourceServer(
  opts: MixedRsOptions,
  port: number,
): Promise<{ server: Server; handler: MixedRsHandler }> {
  const handler = mixedResourceServer(opts);
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve) => server.listen(port, () => resolve({ server, handler })));
}
