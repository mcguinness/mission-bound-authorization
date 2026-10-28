import { createServer, request as httpRequest, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createEgressAdmission,
  createFetchJson,
  type EgressAdmission,
  type FetchJson,
  type HostLookup,
  isServerIdentifier,
  JwksResolver,
  type JwksResolverOptions,
} from "@mission/aauth-wire";

/** A response read in full. */
export interface LoopbackResponse {
  status: number;
  /** Lowercased names; repeated fields joined with ", ". */
  headers: Record<string, string>;
  body: Buffer;
  text(): string;
  json(): unknown;
}

export interface LoopbackRequest {
  method: string;
  /** The target URI under the server's identifier, `https://host/path?query`. */
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
}

/** The path and query exactly as written after the authority. */
function rawTarget(url: string): string {
  const rest = url.slice(url.indexOf("://") + 3);
  const start = rest.search(/[/?]/);
  const target = start >= 0 ? rest.slice(start) : "";
  return target.startsWith("?") || target === "" ? `/${target}` : target;
}

/**
 * The parties of one test on loopback, each a real HTTP server on an
 * ephemeral port of 127.0.0.1, addressed by its AAuth server identifier.
 *
 * Identifiers are `https://host` with no port (aauth#section-11.1.1), so
 * the network maps each registered host to its port and stands in for DNS
 * and TLS: an `https://host/path` URL travels as plain HTTP to that port,
 * with `Host: host`. Nothing else is reachable.
 *
 * - {@link admitEgress} is the library's egress admission, admitting a
 *   private destination only for a registered host. Its https, origin and
 *   cross-origin JWKS rules still apply.
 * - {@link fetchJson} is the library's bounded fetch (timeout, size limit,
 *   no redirects), pinned: the connection's own lookup resolves only a
 *   registered host, to 127.0.0.1, and the fetch admits only that host's
 *   registered port. It admits exactly what admission admits, as
 *   `JwksResolverOptions.fetchJson` requires of a replacement.
 */
export class LoopbackNetwork {
  private readonly ports = new Map<string, number>();
  private readonly owned: Server[] = [];

  /** Resolves a registered host to 127.0.0.1 and refuses any other name. */
  readonly lookup: HostLookup = async (hostname) => {
    if (this.ports.has(hostname)) return [{ address: "127.0.0.1", family: 4 }];
    throw new Error(`${hostname} is not on this loopback network`);
  };

  readonly admitEgress: EgressAdmission = createEgressAdmission({
    lookup: this.lookup,
    admitPrivateDestination: (url) => this.ports.has(url.hostname),
  });

  private readonly bounded = createFetchJson({
    timeoutMs: 2000,
    lookup: this.lookup,
    admitPrivateDestination: (url) =>
      url.protocol === "http:" && this.ports.get(url.hostname) === Number(url.port),
  });

  readonly fetchJson: FetchJson = async (url) => this.bounded(this.transportUrl(url).href);

  /** Bind `identifier` to a server already listening on 127.0.0.1. */
  register(identifier: string, port: number): void {
    if (!isServerIdentifier(identifier)) {
      throw new TypeError(`${identifier} is not a server identifier`);
    }
    this.ports.set(new URL(identifier).hostname, port);
  }

  /** Bind `identifier` to a listening server; the network closes it on {@link close}. */
  attach(identifier: string, server: Server): void {
    this.register(identifier, (server.address() as AddressInfo).port);
    this.owned.push(server);
  }

  /** Listen with `handler` on an ephemeral port and bind `identifier` to it. */
  async serve(identifier: string, handler: RequestListener): Promise<Server> {
    const server = createServer(handler);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    this.attach(identifier, server);
    return server;
  }

  portOf(identifier: string): number | undefined {
    return this.ports.get(new URL(identifier).hostname);
  }

  /** A key resolver whose fetches stay on this network. */
  resolver(options: Omit<JwksResolverOptions, "fetchJson" | "admitEgress"> = {}): JwksResolver {
    return new JwksResolver({
      ...options,
      fetchJson: this.fetchJson,
      admitEgress: this.admitEgress,
    });
  }

  /**
   * The transport URL for an identifier URL: plain HTTP to the registered
   * port. Refuses a scheme other than https, an explicit port and an
   * unregistered host.
   */
  transportUrl(url: string): URL {
    const target = new URL(url);
    if (target.protocol !== "https:") throw new Error(`${url} is not an https URL`);
    if (target.port !== "") throw new Error(`${url} names a port; identifiers carry none`);
    const port = this.ports.get(target.hostname);
    if (port === undefined) throw new Error(`${target.hostname} is not on this loopback network`);
    return new URL(`http://${target.hostname}:${port}${rawTarget(url)}`);
  }

  /**
   * Send one request to a registered server: HTTP to 127.0.0.1 on its
   * port, the request target exactly as written in `url`, and `Host` the
   * identifier's host, so the authority on the wire is the one a signer
   * covers.
   */
  async request(message: LoopbackRequest): Promise<LoopbackResponse> {
    const target = this.transportUrl(message.url);
    const headers = { ...(message.headers ?? {}), host: target.hostname };
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: Number(target.port),
          method: message.method,
          path: rawTarget(message.url),
          headers,
          agent: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("error", reject);
          res.on("end", () => {
            const body = Buffer.concat(chunks);
            const flat: Record<string, string> = {};
            for (const [name, value] of Object.entries(res.headersDistinct)) {
              if (value) flat[name] = value.join(", ");
            }
            resolve({
              status: res.statusCode ?? 0,
              headers: flat,
              body,
              text: () => body.toString("utf8"),
              json: () => JSON.parse(body.toString("utf8")),
            });
          });
        },
      );
      req.on("error", reject);
      if (message.body !== undefined) req.write(message.body);
      req.end();
    });
  }

  /** Close every server this network started or was handed. */
  async close(): Promise<void> {
    const servers = this.owned.splice(0);
    await Promise.all(
      servers.map(
        (server) =>
          new Promise<void>((resolve) => {
            server.closeAllConnections();
            server.close(() => resolve());
          }),
      ),
    );
  }
}
