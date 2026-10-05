/**
 * AAuth wire foundation: HTTP Message Signatures as AAuth profiles them,
 * the Signature-Key `jwt` and `jwks_uri` schemes, Content-Digest, issuer
 * key discovery, and typed verification of the four AAuth tokens.
 *
 * Pinned to draft-hardt-oauth-aauth-protocol-11 and
 * draft-hardt-httpbis-signature-key-09 (src/SPEC_VERSIONS.md).
 */
export {
  assertSigningKey,
  type DeterminedKey,
  determineAlgorithm,
  httpSign,
  httpVerify,
  isSupportedAlgorithm,
  SUPPORTED_ALGORITHMS,
  type SupportedAlgorithm,
} from "./algorithms.js";
export { contentDigest, type DigestAlgorithm, verifyContentDigest } from "./content-digest.js";
export {
  createEgressAdmission,
  createFetchJson,
  type EgressAdmission,
  type EgressAdmissionOptions,
  type EgressRequest,
  type FetchLimits,
  type HostLookup,
  isNonPublicAddress,
} from "./egress.js";
export { SignatureError, type SignatureErrorCode, type SignatureErrorExtras } from "./errors.js";
export { isAgentIdentifier, isServerIdentifier, isWellKnownName } from "./identifiers.js";
export { type FetchJson, JwksResolver, type JwksResolverOptions } from "./jwks.js";
export { generateSigningKey, jwkThumbprint, mintToken, type SigningKey } from "./keys.js";
export {
  carriesBody,
  type HeaderInput,
  type HttpRequestMessage,
  normalizeRequest,
} from "./message.js";
export { InMemoryReplayCache, type ReplayCache } from "./replay.js";
export {
  AAUTH_SERVER_DOCUMENTS,
  BASE_COMPONENTS,
  BODY_COMPONENTS,
  type PresentedTokenType,
  type SignRequestOptions,
  signRequest,
  type VerifiedRequest,
  type VerifyRequestOptions,
  verifyRequest,
} from "./request.js";
export { buildSignatureBase, SignatureBaseError, signatureParams } from "./signature-base.js";
export {
  type SignatureKeyMember,
  type SignatureKeyScheme,
  serializeSignatureKey,
} from "./signature-key.js";
export {
  type AAuthTokenType,
  type TokenVerificationOptions,
  type VerifiedToken,
  verifyAgentToken,
  verifyAuthToken,
  verifyPersonToken,
  verifyResourceToken,
} from "./tokens.js";
