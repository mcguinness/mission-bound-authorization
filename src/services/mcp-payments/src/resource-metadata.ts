/**
 * @spec txn-authorization#two-phase-expiry (key discovery) — the resource's
 * unauthenticated discovery surface: RFC 9728 Protected Resource Metadata and
 * the `txn_challenge_jwks_uri` JWKS the metadata points at.
 *
 * Key discovery rides the upstream metadata: a Challenge-Issuing Resource
 * publishes its challenge-signing keys at `txn_challenge_jwks_uri` with
 * `txn_challenge_signing_alg_values_supported`, and a Transaction Authorization
 * Server resolves that issuer's keys THERE AND NOWHERE ELSE. Both routes are
 * deliberately unauthenticated (they publish public keys and metadata) and are
 * served in front of the credential-gated MCP transport.
 */

import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { McpPaymentsServer } from "./server.js";

/** RFC 9728: the well-known path for Protected Resource Metadata. */
export const PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";

/**
 * Try to serve a discovery route. Returns true when the request was handled, so
 * a caller can fall through to its credential-gated dispatch otherwise.
 */
export function serveResourceMetadata(
  server: McpPaymentsServer,
  req: IncomingMessage,
  res: ServerResponse,
): boolean {
  if (req.method !== "GET") return false;
  const path = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`).pathname;
  if (path === PROTECTED_RESOURCE_METADATA_PATH) {
    return json(res, server.protectedResourceMetadata());
  }
  const jwks = server.txnChallengeJwks();
  if (jwks && path === server.txnChallengeJwksPath()) {
    return json(res, jwks);
  }
  return false;
}

function json(res: ServerResponse, body: unknown): true {
  res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
  return true;
}

/** A running discovery listener: its origin and a shutdown hook. */
export interface ResourceMetadataServer {
  origin: string;
  port: number;
  close: () => Promise<void>;
}

/**
 * Start a standalone discovery listener on an ephemeral port. The in-process
 * demo stack has no HTTP resource server of its own, but the TAS must resolve
 * this resource's challenge keys over a REAL fetch of the published
 * `txn_challenge_jwks_uri`, not from an injected key bag. The server is
 * resolved lazily because its own metadata has to name this listener's origin.
 */
export async function startResourceMetadataServer(
  resolve: () => McpPaymentsServer | undefined,
  opts: { host?: string; port?: number } = {},
): Promise<ResourceMetadataServer> {
  const host = opts.host ?? "127.0.0.1";
  const http: HttpServer = createServer((req, res) => {
    const server = resolve();
    if (server && serveResourceMetadata(server, req, res)) return;
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise<void>((ready) => http.listen(opts.port ?? 0, host, () => ready()));
  const addr = http.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : (opts.port ?? 0);
  return {
    origin: `http://${host}:${port}`,
    port,
    close: async () => {
      http.closeAllConnections();
      await new Promise<void>((resolve, reject) => http.close((e) => (e ? reject(e) : resolve())));
    },
  };
}
