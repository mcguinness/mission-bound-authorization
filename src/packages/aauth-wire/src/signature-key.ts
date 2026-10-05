import { type Dictionary, type Parameters, serializeDictionary, Token } from "structured-headers";

/**
 * The two Signature-Key schemes AAuth uses: `jwt` for agents, presenting a
 * token whose `cnf.jwk` is the signing key, and `jwks_uri` for a server
 * signing in its own right, naming its issuer, metadata document and key.
 *
 * @spec aauth#section-11.3.2
 * @spec signature-key#section-3.6
 * @spec signature-key#section-3.8
 */
export type SignatureKeyMember =
  | { scheme: "jwt"; jwt: string }
  | { scheme: "jwks_uri"; id: string; dwk: string; kid: string };

export type SignatureKeyScheme = SignatureKeyMember["scheme"];

/**
 * Serialize a one-member Signature-Key field value.
 *
 * @spec signature-key#section-3
 */
export function serializeSignatureKey(label: string, member: SignatureKeyMember): string {
  const params: Parameters =
    member.scheme === "jwt"
      ? new Map([["jwt", member.jwt]])
      : new Map([
          ["id", member.id],
          ["dwk", member.dwk],
          ["kid", member.kid],
        ]);
  const field: Dictionary = new Map([[label, [new Token(member.scheme), params]]]);
  return serializeDictionary(field);
}
