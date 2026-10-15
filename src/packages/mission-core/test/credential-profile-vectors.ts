/**
 * @spec runtime-oauth#token-validation, mission#introspection (#825, D402) —
 * the Mission access-token profile's shared negative vectors for the
 * credential's own authority and its sender-constraint binding. One list
 * drives the resource's profile tests and the AS's introspection tests, so the
 * two cannot drift: each vector, applied to an otherwise conforming token, is
 * refused by the resource and introspects `active: false`.
 *
 * `senderConstrainedProfileOnly` marks the vector that depends on the token's
 * profile: an absent `cnf` is refused only where the profile requires sender
 * constraint, and a bearer profile carries none.
 */

export interface CredentialProfileVector {
  label: string;
  /** Claim overrides on a conforming token; `undefined` removes the claim. */
  claims: Record<string, unknown>;
  senderConstrainedProfileOnly?: true;
}

/** The vectors for a token whose conforming authority names `action` at `resource`. */
export function credentialProfileVectors(
  resource: string,
  action: string,
): CredentialProfileVector[] {
  const entry = (constraints?: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    type: "mission_resource_access",
    resource,
    actions: [action],
    ...(constraints ? { constraints } : {}),
    ...extra,
  });
  return [
    { label: "no authorization_details", claims: { authorization_details: undefined } },
    {
      label: "an unknown authority type",
      claims: { authorization_details: [{ type: "other", resource, actions: [action] }] },
    },
    {
      label: "an unknown entry member",
      claims: { authorization_details: [entry(undefined, { unknown_member: true })] },
    },
    {
      label: "an entry with no actions",
      claims: { authorization_details: [entry(undefined, { actions: [] })] },
    },
    {
      label: "an unknown constraint",
      claims: { authorization_details: [entry({ time_window: "9-5" })] },
    },
    {
      label: "a malformed amount cap",
      claims: {
        authorization_details: [entry({ max_amount: { amount: "ten", currency: "USD" } })],
      },
    },
    {
      label: "an amount cap with no currency",
      claims: { authorization_details: [entry({ max_amount: { amount: "10.00" } })] },
    },
    { label: "no cnf", claims: { cnf: undefined }, senderConstrainedProfileOnly: true },
    { label: "an empty cnf.jkt", claims: { cnf: { jkt: "" } } },
    { label: "a numeric cnf.jkt", claims: { cnf: { jkt: 42 } } },
    { label: "a null cnf", claims: { cnf: null } },
    { label: "an array cnf", claims: { cnf: [] } },
    { label: "a string cnf", claims: { cnf: "jkt" } },
    { label: "a cnf naming no confirmation method", claims: { cnf: {} } },
  ];
}
