import {
  type Dictionary,
  type Item,
  serializeDictionary,
  serializeList,
  Token,
} from "structured-headers";

/**
 * Signature-Error codes this package raises.
 *
 * @spec signature-key#section-5.4
 */
export type SignatureErrorCode =
  | "unsupported_algorithm"
  | "unsupported_scheme"
  | "invalid_signature"
  | "invalid_input"
  | "invalid_key"
  | "unknown_key"
  | "issuer_missing"
  | "issuer_mismatch"
  | "invalid_jwt"
  | "expired_jwt"
  | "revoked_jwt"
  | "clock_skew";

export interface SignatureErrorExtras {
  /** For `invalid_input`: the covered components the server requires. */
  requiredInput?: readonly string[];
  /** For `unsupported_scheme`: the Signature-Key schemes the server accepts. */
  acceptedSchemes?: readonly string[];
  /** For `unsupported_algorithm`: the algorithms the server accepts. */
  acceptedAlgorithms?: readonly string[];
}

const tokenList = (values: readonly string[]): string =>
  serializeList(values.map((v): Item => [new Token(v), new Map()]));

/**
 * A verification failure. AAuth answers every signature failure with 401
 * and a Signature-Error header; `headers` carries that header and, where
 * the code calls for one, Accept-Signature-Scheme or Accept-Signature-Alg.
 * A token verified outside the Signature-Key header raises the same class;
 * its caller maps `code` to the parameter's own error.
 *
 * @spec aauth#section-11.3.4
 * @spec signature-key#section-5.1
 */
export class SignatureError extends Error {
  readonly status = 401;
  readonly headers: Record<string, string>;

  constructor(
    readonly code: SignatureErrorCode,
    readonly detail: string,
    extras: SignatureErrorExtras = {},
  ) {
    super(`${code}: ${detail}`);
    this.name = "SignatureError";
    const members: Dictionary = new Map();
    members.set("error", [new Token(code), new Map()]);
    if (code === "invalid_input" && extras.requiredInput) {
      members.set("required_input", [
        extras.requiredInput.map((c): Item => [c, new Map()]),
        new Map(),
      ]);
    }
    this.headers = { "signature-error": serializeDictionary(members) };
    if (code === "unsupported_scheme" && extras.acceptedSchemes) {
      this.headers["accept-signature-scheme"] = tokenList(extras.acceptedSchemes);
    }
    if (code === "unsupported_algorithm" && extras.acceptedAlgorithms) {
      this.headers["accept-signature-alg"] = tokenList(extras.acceptedAlgorithms);
    }
  }
}
