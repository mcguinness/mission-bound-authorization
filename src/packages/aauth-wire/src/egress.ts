import { lookup as dnsLookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

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
 * fetch; pinning the resolved address for the connection is the fetch
 * function's job, so a deployment that needs DNS-rebinding defense
 * supplies a `fetchJson` that pins.
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

/**
 * A JSON fetch with a timeout, a response-size limit and no redirects.
 *
 * @spec signature-key#section-7.3
 */
export function createFetchJson(limits: FetchLimits = {}) {
  const timeoutMs = limits.timeoutMs ?? 5000;
  const maxBytes = limits.maxBytes ?? 256 * 1024;
  return async (url: string): Promise<{ status: number; body: unknown }> => {
    const response = await fetch(url, {
      redirect: "error",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.status !== 200 || !response.body) {
      await response.body?.cancel();
      return { status: response.status, body: null };
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error(`response from ${url} exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
    return { status: 200, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
  };
}
