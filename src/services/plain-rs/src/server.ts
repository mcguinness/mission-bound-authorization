/**
 * Standalone launcher. Configuration comes from the environment only:
 * PLAIN_RS_ISSUER, PLAIN_RS_AUDIENCE (default http://localhost:4410/api),
 * PLAIN_RS_JWKS_URI (default `${issuer}/jwks`), PLAIN_RS_BASE_URL, and, for
 * introspection mode, PLAIN_RS_INTROSPECTION_ENDPOINT with
 * PLAIN_RS_INTROSPECTION_CLIENT_ID and PLAIN_RS_INTROSPECTION_CLIENT_SECRET.
 */
import { startPlainResourceServer } from "./index.js";

const env = process.env;
const issuer = env.PLAIN_RS_ISSUER ?? "http://localhost:4400";
const audience = env.PLAIN_RS_AUDIENCE ?? "http://localhost:4410/api";
const endpoint = env.PLAIN_RS_INTROSPECTION_ENDPOINT;
const port = Number(new URL(env.PLAIN_RS_BASE_URL ?? audience).port || 80);

await startPlainResourceServer(
  {
    issuer,
    audience,
    jwksUri: env.PLAIN_RS_JWKS_URI ?? `${issuer}/jwks`,
    ...(env.PLAIN_RS_BASE_URL ? { baseUrl: env.PLAIN_RS_BASE_URL } : {}),
    ...(endpoint
      ? {
          introspection: {
            endpoint,
            clientId: env.PLAIN_RS_INTROSPECTION_CLIENT_ID ?? "",
            clientSecret: env.PLAIN_RS_INTROSPECTION_CLIENT_SECRET ?? "",
          },
        }
      : {}),
  },
  port,
);
console.log(`plain-rs listening on ${port} (audience ${audience})`);
