/**
 * @spec cross-org-delegation#chain-presentation — the Chain Presentation: the
 * closed JSON envelope carrying an ordered root-to-leaf compact-JWS chain and
 * hop-aligned actor-binding credentials. Pure structure: parsing, closure,
 * bounds (checked BEFORE any signature verification, which lives with the
 * consumer), and the chain digest over the JCS canonical bytes of the `chain`
 * array exactly as presented.
 */
import { createHash } from "node:crypto";
import { canonicalize, type JsonValue } from "./canonicalize.js";
import { parseStrictJson } from "./strict-json.js";

export const CHAIN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:mission-delegation-chain";
export const CHAIN_MEDIA_TYPE = "application/mission-delegation-chain+json";
export const CHAIN_DIGEST_TYP = "mission-delegation-chain";

export interface ActorCredentialEntry {
  /** 0-based index into `chain` of the hop this credential binds. */
  hop: number;
  /** Registered actor-credential type identifier. */
  type: string;
  /** The credential, in the serialization its type defines. */
  credential: string;
}

export interface ChainPresentation {
  /** Compact-JWS hop tokens, root first, leaf last. */
  chain: string[];
  actor_credentials?: ActorCredentialEntry[];
}

export interface PresentationBounds {
  maxHops: number;
  maxBytes: number;
}

export class ChainPresentationError extends Error {}

/**
 * Parse a base64url-encoded Chain Presentation under declared bounds.
 * @spec cross-org-delegation#chain-presentation — the top level is closed
 * (unknown member refused); bounds are enforced before the caller verifies
 * any signature; `actor_credentials` entries are typed and hop-aligned.
 */
export function parseChainPresentation(
  subjectToken: string,
  bounds: PresentationBounds,
): ChainPresentation {
  if (subjectToken.length > bounds.maxBytes) {
    throw new ChainPresentationError("presentation exceeds the declared size bound");
  }
  let text: string;
  try {
    text = Buffer.from(subjectToken, "base64url").toString("utf8");
  } catch {
    throw new ChainPresentationError("presentation is not base64url");
  }
  let raw: unknown;
  try {
    raw = parseStrictJson(text);
  } catch (e) {
    throw new ChainPresentationError(`presentation is not strict JSON: ${(e as Error).message}`);
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ChainPresentationError("presentation must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (key !== "chain" && key !== "actor_credentials") {
      throw new ChainPresentationError(`unknown top-level member: ${key}`);
    }
  }
  const chain = obj.chain;
  if (!Array.isArray(chain) || chain.length === 0 || !chain.every((t) => typeof t === "string")) {
    throw new ChainPresentationError("chain must be a non-empty array of compact-JWS strings");
  }
  if (chain.length > bounds.maxHops) {
    throw new ChainPresentationError("chain exceeds the declared hop bound");
  }
  for (const t of chain as string[]) {
    if (t.split(".").length !== 3) {
      throw new ChainPresentationError("chain elements must be compact JWS");
    }
  }
  let creds: ActorCredentialEntry[] | undefined;
  if (obj.actor_credentials !== undefined) {
    const arr = obj.actor_credentials;
    if (!Array.isArray(arr)) {
      throw new ChainPresentationError("actor_credentials must be an array");
    }
    const seen = new Set<number>();
    creds = arr.map((e) => {
      if (e === null || typeof e !== "object" || Array.isArray(e)) {
        throw new ChainPresentationError("actor_credentials entries must be objects");
      }
      const entry = e as Record<string, unknown>;
      for (const key of Object.keys(entry)) {
        if (key !== "hop" && key !== "type" && key !== "credential") {
          throw new ChainPresentationError(`unknown actor_credentials member: ${key}`);
        }
      }
      const hop = entry.hop;
      if (typeof hop !== "number" || !Number.isInteger(hop) || hop < 0 || hop >= chain.length) {
        throw new ChainPresentationError("actor_credentials hop index is misaligned");
      }
      if (seen.has(hop)) {
        throw new ChainPresentationError("actor_credentials carries duplicate hop entries");
      }
      seen.add(hop);
      if (typeof entry.type !== "string" || entry.type.length === 0) {
        throw new ChainPresentationError("actor_credentials entries require a type");
      }
      if (typeof entry.credential !== "string" || entry.credential.length === 0) {
        throw new ChainPresentationError("actor_credentials entries require a credential");
      }
      return { hop, type: entry.type, credential: entry.credential };
    });
  }
  return { chain: chain as string[], ...(creds ? { actor_credentials: creds } : {}) };
}

/**
 * @spec cross-org-delegation#chain-presentation — the chain digest: sha-256
 * over the JCS canonical bytes of the `chain` array exactly as presented (an
 * ordered JSON array of compact-JWS strings), in the family's encoded form.
 * It commits to the complete ordered chain and to nothing else; the typ
 * `mission-delegation-chain` names the digest kind.
 */
export function chainDigest(chain: readonly string[]): string {
  const canonical = canonicalize(chain as JsonValue);
  const digest = createHash("sha256").update(canonical, "utf8").digest();
  return `sha-256:${digest.toString("base64url")}`;
}
