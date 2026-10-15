/**
 * @spec mission#mission-bound-tokens, runtime-oauth#token-validation (#825,
 * D402) — a Mission-bound credential's sender-constraint binding, the `cnf`
 * claim of RFC 7800: DPoP (`jkt`, RFC 9449) or mTLS (`x5t#S256`, RFC 8705).
 *
 * This reads the binding's structure only, the same way wherever a credential
 * is validated: by the resource and by introspection alike. Possession of the
 * named key is the resource's to prove. An absent binding is not malformed (a
 * bearer profile carries none); whether a profile requires one is the
 * caller's to decide.
 */

/** A well-formed sender-constraint binding: at least one method, each a non-empty string. */
export interface Confirmation {
  jkt?: string;
  "x5t#S256"?: string;
}

/** Thrown when a present `cnf` is malformed. */
export class ConfirmationError extends Error {}

const METHODS = ["jkt", "x5t#S256"] as const;

/**
 * Read a credential's `cnf` claim: `undefined` when absent; otherwise an
 * object naming at least one confirmation method this family defines, each
 * a non-empty string, or a {@link ConfirmationError}. Other members are
 * RFC 7800 extensions and are left unread.
 */
export function parseConfirmation(value: unknown): Confirmation | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConfirmationError("cnf must be an object");
  }
  const cnf = value as Record<string, unknown>;
  const out: Confirmation = {};
  for (const method of METHODS) {
    const v = cnf[method];
    if (v === undefined) continue;
    if (typeof v !== "string" || v.length === 0)
      throw new ConfirmationError(`cnf.${method} must be a non-empty string`);
    out[method] = v;
  }
  if (out.jkt === undefined && out["x5t#S256"] === undefined) {
    throw new ConfirmationError("cnf names no confirmation method");
  }
  return out;
}
