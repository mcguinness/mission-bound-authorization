/**
 * @spec attenuation#mission-binding-check, AAT -02 Sections 7 and 8 (#1756
 * slice B3, D902): how a Mission-bound Attenuating Agent Token presentation
 * reaches this resource. The presentation (`aat_chain`, root first, and the
 * proof `aat_pop`) travels with each `tools/call` it authorizes, in the
 * call's `_meta` under {@link AAT_PRESENTATION_META_KEY}, on both channels.
 * It is the call's one credential: a call that also carries an access token
 * (the in-memory `_meta` token, or an HTTP `Authorization` header) is
 * refused, never read as either.
 *
 * The proof binds one invocation: the tool identifier (`aat_tool`) and the
 * arguments as the transport fixed them (`hta`, compared under JCS with the
 * invocation's original arguments text). DPoP and the other credential
 * classes are unchanged.
 */

import { AAT_POP_JWT_TYP, aatSha256B64url, aatUuidV7 } from "@mission/core";
import { type CryptoKey, decodeJwt, exportJWK, SignJWT } from "jose";

/** The namespaced `_meta` key carrying a tools/call's attenuation presentation. */
export const AAT_PRESENTATION_META_KEY = "io.mission-bound/aat-presentation";

/** An attenuation presentation: the chain, root first and leaf last, and the PoP JWT for this invocation. */
export interface AatPresentation {
  aat_chain: string[];
  aat_pop: string;
}

/** A presentation refused before it yields credential facts; the reason is diagnostic only. */
export class AatPresentationRefused extends Error {
  constructor(readonly reason: string) {
    super(`attenuation presentation refused: ${reason}`);
    this.name = "AatPresentationRefused";
  }
}

/**
 * The presentation a `_meta` value carries, or undefined when it is not one:
 * an object whose `aat_chain` is a non-empty array of strings and whose
 * `aat_pop` is a string. Other members are ignored, as -02 ignores them.
 */
export function readAatPresentation(value: unknown): AatPresentation | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const { aat_chain: chain, aat_pop: pop } = value as Record<string, unknown>;
  if (!Array.isArray(chain) || chain.length === 0 || !chain.every((t) => typeof t === "string")) return undefined;
  if (typeof pop !== "string") return undefined;
  return { aat_chain: [...chain] as string[], aat_pop: pop };
}

/** What a holder signs a PoP JWT over: the leaf, the tool identifier and the arguments text. */
export interface AatPopInput {
  /** The leaf token (`aat_chain`'s last member). */
  leaf: string;
  /** The private key the leaf's `cnf.jwk` binds. */
  holderKey: CryptoKey;
  /** The invoked tool identifier (`aat_tool`). */
  tool: string;
  /** The invocation's arguments, as the JSON text the call carries (`hta`). */
  argumentsJson: string;
  /** The enforcement point's audience (`aat_aud`), when the holder names one. */
  aud?: string;
  /** Seconds since the epoch; defaults to now. */
  iat?: number;
}

/**
 * @spec AAT -02 Section 7.2: a holder's PoP JWT for one invocation, signed
 * with the key the leaf's `cnf.jwk` binds, `alg` chosen by that key's type.
 */
export async function signAatPop(input: AatPopInput): Promise<string> {
  const jwk = await exportJWK(input.holderKey);
  const alg = jwk.kty === "OKP" && jwk.crv === "Ed25519" ? "Ed25519" : jwk.kty === "EC" && jwk.crv === "P-256" ? "ES256" : undefined;
  if (alg === undefined) throw new Error(`unsupported holder key ${JSON.stringify(jwk.kty)}/${JSON.stringify(jwk.crv)}`);
  const leaf = decodeJwt(input.leaf);
  if (typeof leaf.jti !== "string") throw new Error("the leaf carries no jti");
  const signingInput = input.leaf.split(".").slice(0, 2).join(".");
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  return new SignJWT({
    aat_id: leaf.jti,
    aat_hash: aatSha256B64url(signingInput),
    aat_tool: input.tool,
    hta: JSON.parse(input.argumentsJson) as Record<string, unknown>,
    ...(input.aud !== undefined ? { aat_aud: input.aud } : {}),
  })
    .setProtectedHeader({ alg, typ: AAT_POP_JWT_TYP })
    .setIssuedAt(iat)
    .setJti(aatUuidV7(iat * 1000))
    .sign(input.holderKey);
}
