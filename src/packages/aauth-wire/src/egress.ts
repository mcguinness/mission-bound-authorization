import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";

/** What a verifier is about to fetch, and on whose behalf. */
export interface EgressRequest {
  url: URL;
  /** The issuer metadata document, or the JWKS it names. */
  kind: "metadata" | "jwks";
  /** The issuer the document was requested under. */
  issuer: string;
}

export type EgressAdmission = (request: EgressRequest) => boolean | Promise<boolean>;

/** Resolve a host name to its addresses. */
export type HostLookup = (hostname: string) => Promise<{ address: string; family: number }[]>;

export interface EgressAdmissionOptions {
  /** Default: the system resolver, all addresses. */
  lookup?: HostLookup;
  /** Admit a JWKS on another origin than its issuer (deployment admission). */
  admitCrossOriginJwks?: (request: EgressRequest) => boolean;
  /** Admit a private, loopback or link-local destination (deployment admission). */
  admitPrivateDestination?: (url: URL) => boolean;
}

const blocked = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(network, prefix, "ipv4");
}
for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const) {
  blocked.addSubnet(network, prefix, "ipv6");
}

/** True for a private, loopback, link-local or otherwise non-public address. */
export function isNonPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, "ipv4");
  if (family !== 6) return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped?.[1]) return blocked.check(mapped[1], "ipv4");
  return blocked.check(address, "ipv6");
}

const systemLookup: HostLookup = (hostname) => dnsLookup(hostname, { all: true, verbatim: true });

/**
 * Egress admission before any issuer metadata or JWKS fetch: https only;
 * a JWKS on another origin than its issuer only with explicit admission;
 * no private, loopback or link-local destination, whether named by an IP
 * literal or resolved from a host name. Admission is checked before the
 * fetch. Its DNS answer is not the one a connection uses, so the
 * DNS-rebinding defense is the fetch's: {@link createFetchJson} checks the
 * addresses it resolves and connects only to them, and a replacement
 * `fetchJson` must do the same.
 *
 * @spec aauth#section-11.4
 * @spec signature-key#section-7.3
 */
export function createEgressAdmission(options: EgressAdmissionOptions = {}): EgressAdmission {
  const lookup = options.lookup ?? systemLookup;
  return async (request) => {
    const { url } = request;
    if (url.protocol !== "https:") return false;
    if (request.kind === "jwks" && url.origin !== new URL(request.issuer).origin) {
      if (!options.admitCrossOriginJwks?.(request)) return false;
    }
    if (options.admitPrivateDestination?.(url)) return true;
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (host === "localhost" || host.endsWith(".localhost")) return false;
    if (isIP(host)) return !isNonPublicAddress(host);
    let addresses: { address: string }[];
    try {
      addresses = await lookup(host);
    } catch {
      return false;
    }
    return addresses.length > 0 && addresses.every((a) => !isNonPublicAddress(a.address));
  };
}

export interface FetchLimits {
  /** Default 5000. */
  timeoutMs?: number;
  /** Default 256 KiB. */
  maxBytes?: number;
}

export interface FetchJsonOptions extends FetchLimits {
  /** Default: the system resolver, all addresses. */
  lookup?: HostLookup;
  /** Admit a private, loopback or link-local destination (deployment admission). */
  admitPrivateDestination?: (url: URL) => boolean;
}

/**
 * The connection's own lookup: resolve once, refuse unless every address is
 * public or the destination is admitted, and hand the socket exactly the
 * addresses checked, so a changed DNS answer cannot redirect the connection.
 */
function pinnedLookup(url: URL, options: FetchJsonOptions): LookupFunction {
  const lookup = options.lookup ?? systemLookup;
  return (hostname, lookupOptions, callback) => {
    const family =
      lookupOptions.family === "IPv4"
        ? 4
        : lookupOptions.family === "IPv6"
          ? 6
          : lookupOptions.family;
    lookup(hostname)
      .then((resolved) => {
        if (
          !options.admitPrivateDestination?.(url) &&
          resolved.some((a) => isNonPublicAddress(a.address))
        ) {
          throw new Error(`${hostname} resolves to a non-public address`);
        }
        const addresses = family ? resolved.filter((a) => a.family === family) : resolved;
        const [first] = addresses;
        if (!first) throw new Error(`${hostname} has no usable address`);
        if (lookupOptions.all) callback(null, addresses);
        else callback(null, first.address, first.family);
      })
      .catch((err: Error) => callback(err, "", 0));
  };
}

/**
 * A JSON fetch with a timeout, a response-size limit and no redirects that
 * pins the connection to the addresses it checked: a host name is resolved
 * once, by the connection itself, and refused unless every address is
 * public; an IP literal is checked directly. Protocol and origin rules stay
 * with egress admission.
 *
 * @spec signature-key#section-7.3
 */
export function createFetchJson(options: FetchJsonOptions = {}) {
  const timeoutMs = options.timeoutMs ?? 5000;
  const maxBytes = options.maxBytes ?? 256 * 1024;
  return (url: string): Promise<{ status: number; body: unknown }> => {
    const target = new URL(url);
    const host = target.hostname.replace(/^\[|\]$/g, "");
    // A connection to an IP literal makes no lookup, so check it here.
    if (isIP(host) && isNonPublicAddress(host) && !options.admitPrivateDestination?.(target)) {
      return Promise.reject(new Error(`${host} is not a public address`));
    }
    const send =
      target.protocol === "https:"
        ? httpsRequest
        : target.protocol === "http:"
          ? httpRequest
          : null;
    if (!send) return Promise.reject(new Error(`${target.protocol} is not fetched`));
    return new Promise((resolve, reject) => {
      const request = send(
        target,
        {
          headers: { accept: "application/json" },
          agent: false,
          lookup: pinnedLookup(target, options),
          signal: AbortSignal.timeout(timeoutMs),
        },
        (response) => {
          const status = response.statusCode ?? 0;
          if (status >= 300 && status < 400) {
            response.destroy();
            reject(new Error(`${url} redirects, and redirects are not followed`));
            return;
          }
          if (status !== 200) {
            response.resume();
            resolve({ status, body: null });
            return;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          response.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > maxBytes) {
              response.destroy();
              reject(new Error(`response from ${url} exceeds ${maxBytes} bytes`));
              return;
            }
            chunks.push(chunk);
          });
          response.on("end", () => {
            try {
              resolve({ status: 200, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
            } catch (err) {
              reject(err);
            }
          });
          response.on("error", reject);
          response.on("close", () => {
            if (!response.complete) reject(new Error(`response from ${url} ended early`));
          });
        },
      );
      request.on("error", reject);
      request.end();
    });
  };
}
