/**
 * @spec authority-server#mission-join, authority-server#enterprise-prerequisites (#818)
 *
 * The MAS pilot's estate authorization server: a stock `oidc-provider`
 * instance configured as a legacy estate would run it, with no Mission code
 * at all. It has its own issuer, its own signing key generated at each boot,
 * its own client registry (client identifiers registered here and nowhere
 * else), and its own account directory. It issues ordinary RFC 9068 JWT access
 * tokens, DPoP-bound, carrying `scope`, `sub` and `client_id` and no `mission`
 * claim, through the authorization code grant with PKCE. A client registered
 * with `token_format: "opaque"` gets an opaque (non-JWT) access token instead,
 * which a resource validates by RFC 7662 introspection: introspection is open
 * only to the registered introspection clients, and RFC 7009 revocation lets a
 * client revoke its own token.
 *
 * It is NOT the AS-native issuer reused: nothing here imports
 * `@mission/authorization-server`, and no Mission, kernel or approval exists
 * on this side. What it does not model is the estate's login page: its
 * interaction logs in the directory account named by `login_hint`, a stand-in
 * for an estate user authenticating. Tokens, keys, client authentication,
 * resource indicators and DPoP binding are the library's own.
 */

import type { Server } from "node:http";
import { exportJWK, generateKeyPair } from "jose";
import Provider, { errors, type KoaContextWithOIDC, type ResourceServer } from "oidc-provider";

/** One client registration at the estate AS. */
export interface EstateClientRegistration {
  client_id: string;
  /** Generated at each boot; never configured. */
  client_secret: string;
  redirect_uri: string;
  /** The scope values this client may be granted. */
  scope: string;
  /** The resource indicators this client may obtain tokens for; any other is `invalid_target`. */
  resources: readonly string[];
  /** The access token format the estate issues this client: an RFC 9068 JWT, or an opaque reference. */
  token_format: "jwt" | "opaque";
}

/** A client the estate lets call its introspection endpoint (a resource server); it has no grants. */
export interface EstateIntrospectionClient {
  client_id: string;
  /** Generated at each boot; never configured. */
  client_secret: string;
}

export interface EstateAuthorizationServerOptions {
  issuer: string;
  host: string;
  port: number;
  /** The estate account directory: account identifiers that can log in. */
  accounts: readonly string[];
  clients: readonly EstateClientRegistration[];
  /** The resource servers allowed to introspect the estate's tokens. */
  introspectionClients?: readonly EstateIntrospectionClient[];
  /** Resource indicator to the scope vocabulary the estate issues for it. */
  resourceServers: Readonly<Record<string, { scope: string }>>;
  /** Access token lifetime, seconds. Default 300. */
  accessTokenTtlSeconds?: number;
}

export interface EstateAuthorizationServer {
  issuer: string;
  /** The estate's published JWKS URI. */
  jwksUri: string;
  /** The estate's published signing keys, as the JWKS URI serves them. */
  jwks: { keys: Record<string, unknown>[] };
  /** The signing key's `kid`. */
  kid: string;
  /** The estate's RFC 7662 introspection endpoint, as its metadata publishes it. */
  introspectionEndpoint: string;
  /** The estate's RFC 7009 revocation endpoint, as its metadata publishes it. */
  revocationEndpoint: string;
  close: () => Promise<void>;
}

/**
 * Start the estate AS on `host:port`. A port in use rejects. `close()`
 * releases the listener.
 */
export async function startEstateAuthorizationServer(
  opts: EstateAuthorizationServerOptions,
): Promise<EstateAuthorizationServer> {
  const kid = "estate-signing-1";
  const signing = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = { ...(await exportJWK(signing.privateKey)), kid, alg: "ES256", use: "sig" };
  const publicJwk = { ...(await exportJWK(signing.publicKey)), kid, alg: "ES256", use: "sig" };
  const accounts = new Set(opts.accounts);
  const registrations = new Map(opts.clients.map((c) => [c.client_id, c]));
  const introspectors = new Set((opts.introspectionClients ?? []).map((c) => c.client_id));

  const provider = new Provider(opts.issuer, {
    clients: [
      ...opts.clients.map((c) => ({
        client_id: c.client_id,
        client_secret: c.client_secret,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        redirect_uris: [c.redirect_uri],
        token_endpoint_auth_method: "client_secret_basic",
        // The estate signs with ES256 only (its one key).
        id_token_signed_response_alg: "ES256",
        dpop_bound_access_tokens: true,
      })),
      ...(opts.introspectionClients ?? []).map((c) => ({
        client_id: c.client_id,
        client_secret: c.client_secret,
        grant_types: [],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "client_secret_basic",
        id_token_signed_response_alg: "ES256",
      })),
    ] as never,
    jwks: { keys: [privateJwk as never] },
    cookies: { keys: [crypto.randomUUID()] },
    // Resource scopes come from each resource server's vocabulary below; the
    // provider's own scope list is OpenID Connect's alone.
    scopes: ["openid"],
    pkce: { required: () => true },
    ttl: { AuthorizationCode: 60, Interaction: 300, Grant: 300, Session: 300 },
    findAccount: async (_ctx, id) =>
      accounts.has(id) ? { accountId: id, claims: async () => ({ sub: id }) } : undefined,
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    // An error the provider cannot redirect is answered as JSON, not a page.
    renderError: async (ctx, out) => {
      ctx.type = "application/json";
      ctx.body = out;
    },
    features: {
      devInteractions: { enabled: false },
      dPoP: { enabled: true },
      // Only a registered introspection client (a resource server) may
      // introspect; a token's own client may not read its token's metadata.
      introspection: {
        enabled: true,
        allowedPolicy: async (_ctx: KoaContextWithOIDC, client: { clientId: string }) => introspectors.has(client.clientId),
      },
      // A client revokes only its own tokens.
      revocation: {
        enabled: true,
        allowedPolicy: async (_ctx: KoaContextWithOIDC, client: { clientId: string }, token: { clientId?: string | undefined }) =>
          token.clientId === client.clientId,
      },
      resourceIndicators: {
        enabled: true,
        // A request names its resource; none is assumed.
        defaultResource: () => undefined as never,
        // The registration restricts which resources a client may obtain
        // tokens for, and which of a resource's scope values: the estate's
        // own controls, not the gateway's.
        getResourceServerInfo: (ctx: KoaContextWithOIDC, resourceIndicator: string) => {
          const clientId = ctx.oidc.client?.clientId;
          const registration = clientId ? registrations.get(clientId) : undefined;
          const rs = opts.resourceServers[resourceIndicator];
          if (!rs || !registration?.resources.includes(resourceIndicator)) throw new errors.InvalidTarget();
          const allowed = new Set(registration.scope.split(" "));
          return {
            scope: rs.scope
              .split(" ")
              .filter((s) => allowed.has(s))
              .join(" "),
            audience: resourceIndicator,
            accessTokenTTL: opts.accessTokenTtlSeconds ?? 300,
            ...(registration.token_format === "opaque"
              ? { accessTokenFormat: "opaque" }
              : { accessTokenFormat: "jwt", jwt: { sign: { alg: "ES256" } } }),
          } as ResourceServer;
        },
        useGrantedResource: () => true,
      },
    },
  });
  provider.proxy = false;

  // The login stand-in: log in the directory account `login_hint` names and
  // grant the requested resource scope, within what the registration allows
  // (the provider filters scopes against the resource server's vocabulary
  // and the client's registered scope). An unknown account is refused.
  provider.use(async (ctx, next) => {
    const match = ctx.path.match(/^\/interaction\/([^/]+)$/);
    if (!match || ctx.method !== "GET") return next();
    const details = await provider.interactionDetails(ctx.req, ctx.res);    const account = details.params.login_hint;
    const clientId = details.params.client_id;
    const resource = details.params.resource;
    const scope = details.params.scope;
    if (typeof account !== "string" || !accounts.has(account) || typeof clientId !== "string") {
      await provider.interactionFinished(
        ctx.req,
        ctx.res,
        { error: "access_denied", error_description: "unknown estate account" },
        { mergeWithLastSubmission: false },
      );
      return;
    }
    const grant = new provider.Grant({ accountId: account, clientId });
    if (typeof resource === "string" && typeof scope === "string") grant.addResourceScope(resource, scope);
    const grantId = await grant.save();
    await provider.interactionFinished(
      ctx.req,
      ctx.res,
      { login: { accountId: account }, consent: { grantId } },
      { mergeWithLastSubmission: false },
    );
  });

  const server: Server = await new Promise((resolve, reject) => {
    const s = provider.listen(opts.port, opts.host, () => resolve(s));
    s.once("error", reject);
  });

  const metadata = (await (await fetch(`${opts.issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
  return {
    issuer: opts.issuer,
    introspectionEndpoint: String(metadata.introspection_endpoint),
    revocationEndpoint: String(metadata.revocation_endpoint),
    jwksUri: `${opts.issuer}/jwks`,
    jwks: { keys: [publicJwk] },
    kid,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
    },
  };
}
