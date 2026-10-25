/**
 * @spec #831 B2: a key oidc-provider verifies with and never signs with.
 *
 * The provider signs ID Tokens and verifies the JWTs it issued (an
 * `id_token_hint` above all) with one keystore. After a rotation, an ID
 * Token signed under the access-token role's previous generation, now in
 * overlap, must still verify, though that generation no longer has a
 * private key. This wraps the overlap generation's public key for the
 * keystore: its `key_ops` (`verify`) keep it out of the provider's signing
 * selection, and `sign` refuses in any case. It needs the provider's
 * `externalSigningSupport` feature, which admits key objects in place of
 * private JWKs.
 */
import { createPublicKey, type KeyObject } from "node:crypto";
import { ExternalSigningKey } from "oidc-provider";

export class VerifyOnlySigningKey extends ExternalSigningKey {
  readonly #kid: string;
  readonly #alg: string;
  readonly #key: KeyObject;

  constructor(publicJwk: Record<string, unknown>) {
    super();
    this.#kid = publicJwk.kid as string;
    this.#alg = publicJwk.alg as string;
    this.#key = createPublicKey({ key: publicJwk as never, format: "jwk" });
  }

  override get kid(): string {
    return this.#kid;
  }

  override get alg(): string {
    return this.#alg;
  }

  override get key_ops(): string[] {
    return ["verify"];
  }

  /** The public key; the provider reads it synchronously. */
  override keyObject(): KeyObject {
    return this.#key;
  }

  override sign(): never {
    throw new Error(`${this.#kid} verifies only: it is not the access-token role's active generation`);
  }
}
