import { randomUUID } from "node:crypto";
import {
  type FetchJson,
  generateSigningKey,
  JwksResolver,
  mintToken,
  type SigningKey,
  type SupportedAlgorithm,
} from "../src/index.js";

/** A fixed clock: 2025-10-09T08:53:20Z. */
export const NOW_MS = 1_760_000_000_000;
export const NOW = NOW_MS / 1000;

/** An in-memory network of issuer metadata and JWKS documents. */
export class FakeNetwork {
  readonly documents = new Map<string, unknown>();
  readonly fetched: string[] = [];

  readonly fetchJson: FetchJson = async (url) => {
    this.fetched.push(url);
    return this.documents.has(url)
      ? { status: 200, body: this.documents.get(url) }
      : { status: 404, body: null };
  };

  resolver(now: () => number = () => NOW_MS): JwksResolver {
    return new JwksResolver({ fetchJson: this.fetchJson, now });
  }

  /** Publish an issuer's metadata document and JWKS; return its signing key. */
  issuer(
    id: string,
    dwk: string,
    alg: SupportedAlgorithm = "Ed25519",
    kid = "key-1",
  ): SigningKey & { kid: string; id: string } {
    const key = generateSigningKey(alg, kid);
    this.documents.set(`${id}/.well-known/${dwk}`, { issuer: id, jwks_uri: `${id}/jwks.json` });
    const existing = this.documents.get(`${id}/jwks.json`) as { keys: unknown[] } | undefined;
    this.documents.set(`${id}/jwks.json`, { keys: [...(existing?.keys ?? []), key.publicJwk] });
    return { ...key, kid, id };
  }
}

export const AP = "https://ap.example";
export const PS = "https://ps.example";
export const AS = "https://as.example";
export const RESOURCE = "https://resource.example";
export const AGENT = "aauth:assistant@ap.example";

/** Mint an agent token binding `agentKey` to AGENT, issued by `ap`. */
export function agentToken(
  ap: SigningKey & { kid: string; id: string },
  agentKey: SigningKey,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  return mintToken(
    "aa-agent+jwt",
    {
      iss: ap.id,
      dwk: "aauth-agent.json",
      sub: AGENT,
      jti: randomUUID(),
      iat: NOW - 10,
      exp: NOW + 3600,
      cnf: { jwk: agentKey.publicJwk },
      ...overrides,
    },
    ap,
  );
}
