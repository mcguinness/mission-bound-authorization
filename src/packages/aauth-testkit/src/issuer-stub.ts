import type { IncomingMessage, ServerResponse } from "node:http";
import {
  type AAuthTokenType,
  generateSigningKey,
  type HttpRequestMessage,
  isServerIdentifier,
  mintToken,
  type SigningKey,
  type SupportedAlgorithm,
} from "@mission/aauth-wire";

/** A request as a stub route sees it. */
export interface StubRequest {
  method: string;
  /** The path and query as received. */
  target: string;
  /** The path without the query. */
  path: string;
  headers: Record<string, string[]>;
  body: Buffer;
  /**
   * The message to verify a signature over: the target URI under the
   * stub's identifier, since that is the authority the signer covered.
   */
  message: HttpRequestMessage;
  /** The body parsed as JSON, or undefined when it is empty or not JSON. */
  json: unknown;
}

export interface StubResponse {
  status: number;
  headers?: Record<string, string>;
  /** Serialized as JSON unless it is a string or a Buffer. */
  body?: unknown;
}

export type StubRoute = (request: StubRequest) => StubResponse | Promise<StubResponse>;

export interface IssuerStubOptions {
  /** The server identifier, `https://host`. */
  issuer: string;
  /** The metadata document name, for example `aauth-agent.json`. */
  dwk: string;
  kid?: string;
  alg?: SupportedAlgorithm;
  /** Further metadata members. */
  metadata?: Record<string, unknown>;
  /** Further routes, keyed `"METHOD /path"`. */
  routes?: Record<string, StubRoute>;
}

export interface IssuerStub {
  issuer: string;
  dwk: string;
  key: SigningKey & { kid: string };
  /** The JWKS document's URL, on the issuer's own origin. */
  jwksUri: string;
  metadata: Record<string, unknown>;
  routes: Record<string, StubRoute>;
  /** Sign a token of `typ` with the stub's key. */
  mint(typ: AAuthTokenType, claims: Record<string, unknown>): Promise<string>;
  handler(req: IncomingMessage, res: ServerResponse): void;
}

const MAX_BODY = 64 * 1024;

export async function readBody(req: IncomingMessage, limit = MAX_BODY): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new RangeError(`request body exceeds ${limit} bytes`);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export function writeResponse(res: ServerResponse, response: StubResponse): void {
  const headers: Record<string, string> = { ...(response.headers ?? {}) };
  let payload: string | Buffer | undefined;
  if (response.body === undefined) payload = undefined;
  else if (typeof response.body === "string" || Buffer.isBuffer(response.body)) {
    payload = response.body;
  } else {
    payload = JSON.stringify(response.body);
    headers["content-type"] ??= "application/json";
  }
  res.writeHead(response.status, headers);
  res.end(payload);
}

/**
 * A signing server that publishes `/.well-known/{dwk}` (its `issuer` and
 * `jwks_uri`) and its JWKS, signs tokens with an Ed25519 key, and serves
 * any further routes a test gives it. The agent-provider stub is one; a
 * test builds whatever other stand-in it needs from it.
 *
 * @spec aauth#section-11.2
 * @spec aauth#section-11.4
 */
export function createIssuerStub(options: IssuerStubOptions): IssuerStub {
  if (!isServerIdentifier(options.issuer)) {
    throw new TypeError(`${options.issuer} is not a server identifier`);
  }
  const kid = options.kid ?? "key-1";
  const key = { ...generateSigningKey(options.alg ?? "Ed25519", kid), kid };
  const jwksUri = `${options.issuer}/.well-known/jwks.json`;
  const metadata: Record<string, unknown> = {
    issuer: options.issuer,
    jwks_uri: jwksUri,
    ...(options.metadata ?? {}),
  };
  const routes: Record<string, StubRoute> = { ...(options.routes ?? {}) };
  const stub: IssuerStub = {
    issuer: options.issuer,
    dwk: options.dwk,
    key,
    jwksUri,
    metadata,
    routes,
    mint: (typ, claims) => mintToken(typ, claims, key),
    handler(req, res) {
      void serve(req, res);
    },
  };

  async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const target = req.url ?? "/";
      const path = target.split("?")[0] ?? "/";
      const method = req.method ?? "GET";
      if (method === "GET" && path === `/.well-known/${options.dwk}`) {
        writeResponse(res, { status: 200, body: stub.metadata });
        return;
      }
      if (method === "GET" && path === new URL(jwksUri).pathname) {
        writeResponse(res, { status: 200, body: { keys: [key.publicJwk] } });
        return;
      }
      const route = routes[`${method} ${path}`];
      if (!route) {
        writeResponse(res, { status: 404, body: { error: "not_found" } });
        return;
      }
      const body = await readBody(req);
      let json: unknown;
      try {
        json = body.length > 0 ? JSON.parse(body.toString("utf8")) : undefined;
      } catch {
        json = undefined;
      }
      const headers: Record<string, string[]> = {};
      for (const [name, value] of Object.entries(req.headersDistinct)) {
        if (value) headers[name] = value;
      }
      writeResponse(
        res,
        await route({
          method,
          target,
          path,
          headers,
          body,
          json,
          message: { method, url: `${options.issuer}${target}`, headers, body },
        }),
      );
    } catch (err) {
      writeResponse(res, {
        status: 500,
        body: { error: "server_error", detail: err instanceof Error ? err.message : String(err) },
      });
    }
  }

  return stub;
}
