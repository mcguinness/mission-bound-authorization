/**
 * Test support (NOT a spec file): the inputs an attenuation root mint takes
 * that a suite outside the attenuation profile does not care about.
 *
 * @spec attenuation#root-mapping (#1756): a root maps only tools whose
 * operations a resource server declares. {@link TEST_OPERATIONS} declares,
 * for every (resource, action), one operation taking one optional argument
 * and establishing `vendors` and `max_amount`, so a suite's Authority Set
 * maps as it did before the -02 wire. {@link CEILING_ARGS} is that
 * operation's argument map, for a suite that requests a tool.
 */

import type { AttenuationOperations } from "@mission/core";
import { exportJWK, generateKeyPair, type JWK } from "jose";

export const TEST_OPERATIONS: AttenuationOperations = (_resource, action) => [
  { name: action, arguments: { target_id: { required: false } }, establishes: ["vendors", "max_amount"] },
];

/** The argument map {@link TEST_OPERATIONS} yields for every tool. */
export const CEILING_ARGS = { target_id: { constraint_type: "wildcard", optional: true } };

/** A fixed holder public key (P-256), for a suite that never signs a child under it. */
export const HOLDER_JWK: JWK = {
  kty: "EC",
  crv: "P-256",
  x: "0lXkpNVRhPuCgFBH2yb5RH-_U9LXt29DzmOWU5c_xnE",
  y: "CnLkzkW-Qvh-NiOGAPP44b7-F4PyF9f9q2CM8qCG0ho",
};

/** A fresh holder key pair and its public JWK (the root's `cnf.jwk`). */
export async function holderKey(alg: "ES256" | "Ed25519" = "ES256"): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  jwk: JWK;
}> {
  const keys = await generateKeyPair(alg, { extractable: true });
  return { ...keys, jwk: await exportJWK(keys.publicKey) };
}
