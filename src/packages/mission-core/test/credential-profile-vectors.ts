/**
 * @spec runtime-oauth#token-validation, mission#introspection (#825, D402) —
 * the Mission access-token profile's shared negative vectors: one list drives
 * the resource's profile tests and the AS's introspection tests, so the two
 * validators cannot drift. Each vector, applied to an otherwise conforming
 * token, is refused by the resource and introspects `active: false`.
 *
 * `senderConstrainedProfileOnly` marks the vector that depends on the token's
 * profile: an absent `cnf` is refused only where the profile requires sender
 * constraint, and a bearer profile carries none.
 */

export interface CredentialProfileVector {
  label: string;
  /** Claim overrides on a conforming token; `undefined` removes the claim. */
  claims: Record<string, unknown>;
  /** Protected-header overrides; `undefined` removes the member. */
  header?: Record<string, unknown>;
  senderConstrainedProfileOnly?: true;
}

/** The conforming token a vector varies: its authority's resource and action, its Mission, and the clock. */
export interface CredentialProfileBaseline {
  resource: string;
  action: string;
  mission: { id: string; issuer: string };
  /** The validator's clock, in seconds. */
  nowS: number;
}

/** A well-formed actor chain `depth` hops deep, each hop naming `iss`. */
function chain(depth: number, iss: string): Record<string, unknown> {
  let node: Record<string, unknown> | undefined;
  for (let i = depth; i >= 1; i--)
    node = { sub: `agent-${i}`, iss, ...(node ? { act: node } : {}) };
  return node as Record<string, unknown>;
}

export function credentialProfileVectors(
  baseline: CredentialProfileBaseline,
): CredentialProfileVector[] {
  const { resource, action, mission, nowS } = baseline;
  const entry = (constraints?: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    type: "mission_resource_access",
    resource,
    actions: [action],
    ...(constraints ? { constraints } : {}),
    ...extra,
  });
  const withMission = (members: Record<string, unknown>) => ({
    mission: { ...mission, ...members },
  });
  const details = (...entries: unknown[]) => ({ authorization_details: entries });
  return [
    // The token class and the RFC 9068 claim set, typed and clock-bounded.
    { label: "no typ", claims: {}, header: { typ: undefined } },
    { label: "typ JWT", claims: {}, header: { typ: "JWT" } },
    { label: "typ mission-status+jwt", claims: {}, header: { typ: "mission-status+jwt" } },
    { label: "typ aat+jwt", claims: {}, header: { typ: "aat+jwt" } },
    { label: "no exp", claims: { exp: undefined } },
    { label: "a string exp", claims: { exp: String(nowS + 300) } },
    { label: "no iat", claims: { iat: undefined } },
    { label: "an iat in the future", claims: { iat: nowS + 7200, exp: nowS + 10800 } },
    { label: "an nbf in the future", claims: { nbf: nowS + 3600 } },
    { label: "an expired exp", claims: { iat: nowS - 600, exp: nowS - 10 } },
    { label: "no jti", claims: { jti: undefined } },
    { label: "an empty jti", claims: { jti: "" } },
    { label: "no sub", claims: { sub: undefined } },
    { label: "no client_id", claims: { client_id: undefined } },
    { label: "a numeric client_id", claims: { client_id: 7 } },
    // The `mission` claim's profiled members.
    { label: "no mission claim", claims: { mission: undefined } },
    { label: "a mission claim with an empty id", claims: withMission({ id: "" }) },
    { label: "a mission claim with an empty issuer", claims: withMission({ issuer: "" }) },
    {
      label: "a mission claim with an empty authority_hash",
      claims: withMission({ authority_hash: "" }),
    },
    { label: "a mission claim with a numeric expires_at", claims: withMission({ expires_at: 42 }) },
    {
      label: "a mission claim with an unreadable expires_at",
      claims: withMission({ expires_at: "soon" }),
    },
    {
      label: "a mission claim whose subject is not an object",
      claims: withMission({ subject: "alice" }),
    },
    {
      label: "a mission claim whose subject has no sub",
      claims: withMission({ subject: { iss: mission.issuer } }),
    },
    {
      label: "a mission claim whose approval_basis has no type",
      claims: withMission({ approval_basis: {} }),
    },
    // A delegated token's actor chain, under the Actor Profile.
    { label: "an act that is not an object", claims: { act: "agent" } },
    { label: "a null act", claims: { act: null } },
    {
      label: "a nested null act",
      claims: { act: { sub: "agent-b", iss: mission.issuer, act: null } },
    },
    {
      label: "a nested false act",
      claims: { act: { sub: "agent-b", iss: mission.issuer, act: false } },
    },
    { label: "an act hop with no iss", claims: { act: { sub: "agent-b" } } },
    {
      label: "a nested act hop with no sub",
      claims: { act: { sub: "agent-b", iss: mission.issuer, act: { iss: mission.issuer } } },
    },
    {
      label: "client_profile inside an act hop",
      claims: { act: { sub: "agent-b", iss: mission.issuer, client_profile: "native" } },
    },
    {
      label: "an act hop with an invalid sub_profile",
      claims: { act: { sub: "agent-b", iss: mission.issuer, sub_profile: "ai_agent bad!" } },
    },
    { label: "an act chain deeper than the maximum", claims: { act: chain(5, mission.issuer) } },
    // The credential's own authority, read in full.
    { label: "no authorization_details", claims: { authorization_details: undefined } },
    {
      label: "an unknown authority type",
      claims: details({ type: "other", resource, actions: [action] }),
    },
    {
      label: "an unknown entry member",
      claims: details(entry(undefined, { unknown_member: true })),
    },
    { label: "an entry with no actions", claims: details(entry(undefined, { actions: [] })) },
    { label: "an unknown constraint", claims: details(entry({ time_window: "9-5" })) },
    {
      label: "a malformed amount cap",
      claims: details(entry({ max_amount: { amount: "ten", currency: "USD" } })),
    },
    {
      label: "an amount cap with no currency",
      claims: details(entry({ max_amount: { amount: "10.00" } })),
    },
    // The sender-constraint binding's structure.
    { label: "no cnf", claims: { cnf: undefined }, senderConstrainedProfileOnly: true },
    { label: "an empty cnf.jkt", claims: { cnf: { jkt: "" } } },
    { label: "a numeric cnf.jkt", claims: { cnf: { jkt: 42 } } },
    { label: "a null cnf", claims: { cnf: null } },
    { label: "an array cnf", claims: { cnf: [] } },
    { label: "a string cnf", claims: { cnf: "jkt" } },
    { label: "a cnf naming no confirmation method", claims: { cnf: {} } },
  ];
}
