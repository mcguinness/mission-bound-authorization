/**
 * A server identifier: https, scheme and host only (no port, path, query
 * or fragment), no trailing slash, lowercase, internationalized names in
 * A-label form. Comparison is exact string comparison, so a value that any
 * normalization would change is not an identifier.
 *
 * @spec aauth#section-11.1.1
 */
export function isServerIdentifier(value: unknown): value is string {
  if (typeof value !== "string") return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  // URL lowercases the host, converts it to A-labels, drops a default
  // port and adds "/": any other scheme, userinfo, port, path, query,
  // fragment or case fails this equality.
  return url.hostname !== "" && value === `https://${url.hostname}`;
}

const AGENT_LOCAL = /^[A-Za-z0-9\-_+.]{1,255}$/;

/**
 * An agent identifier, `aauth:local@domain`.
 *
 * @spec aauth#section-5.2
 */
export function isAgentIdentifier(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("aauth:")) return false;
  const rest = value.slice("aauth:".length);
  const at = rest.lastIndexOf("@");
  if (at < 0) return false;
  const local = rest.slice(0, at);
  const domain = rest.slice(at + 1);
  return AGENT_LOCAL.test(local) && isServerIdentifier(`https://${domain}`);
}

/**
 * A `dwk` value names a metadata document under `/.well-known/`. Only a
 * single path segment is accepted, so a token cannot steer discovery
 * elsewhere on the issuer's host.
 */
export function isWellKnownName(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
}
