/**
 * @spec authority-server#join-assertion-request, authority-server#mapping-contract (#1454)
 *
 * The pilot MAS's Join Assertion deployment: how it establishes an estate
 * credential and evaluates its join, for the reference authorization server's
 * Join Assertion endpoint. The MAS calls the estate; it never changes it.
 *
 * - Every acting token, JWT or opaque, is introspected first at the estate
 *   (RFC 7662) as the MAS's own introspection client
 *   (`join_assertion.introspection_client_id`), through the adapter the
 *   gateway uses (#1400): "Where the AS offers token introspection, the MAS
 *   introspects the token". An answer that the token is inactive refuses it,
 *   and nothing checks it locally after that. An estate that cannot be asked
 *   (no answer, a timeout, a redirect, any status but the one below, a
 *   malformed answer, any other error) is `unavailable`, with no local
 *   fallback.
 * - The estate's own contract for a token type it does not introspect is an
 *   HTTP 400 whose JSON `error` is exactly `unsupported_token_type` (the
 *   reference estate answers so for its JWTs). RFC 7662 defines no such
 *   fallback; this is that estate's specific behavior, and only that exact
 *   400 answer counts. Then, the draft's other branch: the token is validated
 *   locally under RFC 9068, signed under a key the estate publishes at its
 *   metadata's `jwks_uri` (fetched when first needed, so the MAS may start
 *   before the estate), issued by the estate, `typ` `at+jwt` and unexpired.
 *   An opaque token fails that validation: nothing resolves it.
 * - Either way the token must be audienced to an enrolled enforcement scope.
 * - A digest-only request is refused: the estate resolves no token by digest.
 *
 * Defined for the owner's confirmation (#1454 review): introspection first,
 * and the estate's 400 `unsupported_token_type` as the one answer that is not
 * a refusal.
 * - The join is evaluated under the pilot's mapping contract, which supplies
 *   `mapping_version`: the subject and client the contract maps the token's
 *   to, against the Mission's own; a delegate under the contract's delegate
 *   policy, at its depth from this MAS's actor records.
 */

import type { ActingToken, ActingTokenResult, JoinAssertionDeployment, JoinEvaluation } from "@mission/authorization-server";
import {
  type ActorRecords,
  type IntrospectedToken,
  IntrospectionTokenTypeUnsupportedError,
  IntrospectionUnavailableError,
  TokenIntrospector,
} from "@mission/mcp-payments";
import { createRemoteJWKSet, type JWTVerifyGetKey, jwtVerify } from "jose";
import type { MasPilotConfig } from "./config.js";
import { MappingContractCache } from "./mapping-contract.js";

export interface PilotJoinAssertionOptions {
  /** The MAS's introspection client secret at the estate, generated where the MAS is started. */
  introspectionSecret: string;
  /** This MAS's actor records: the delegates recorded as acting under a Mission. */
  actorRecords: ActorRecords;
  now?: () => Date;
}

type MissionRecordLike = Parameters<JoinAssertionDeployment["evaluateJoin"]>[1];

/** The pilot's Join Assertion deployment, for `config.join_assertion`. */
export function pilotJoinAssertions(config: MasPilotConfig, opts: PilotJoinAssertionOptions): JoinAssertionDeployment {
  const declared = config.join_assertion;
  if (!declared) throw new Error("the configuration declares no join_assertion");
  const now = opts.now ?? (() => new Date());
  const estate = config.estate.issuer;
  const scopes = new Set(config.separated_mas.enrolled_pdps.flatMap((p) => p.enforcement_scopes));
  const mapping = new MappingContractCache({ maxStaleSeconds: config.mapping_cache.max_stale_seconds, now });
  const installed = mapping.install(config.mapping_contract);
  if (!installed.ok) throw new Error(installed.reason);

  // The estate's published surfaces, read once it answers.
  let published: Promise<{ keys: JWTVerifyGetKey; introspector: TokenIntrospector }> | undefined;
  const estateSurfaces = () => {
    published ??= fetch(`${estate}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(config.introspection.timeout_ms) })
      .then((r) => r.json() as Promise<{ jwks_uri: string; introspection_endpoint: string }>)
      .then((m) => ({
        keys: createRemoteJWKSet(new URL(m.jwks_uri)),
        introspector: new TokenIntrospector(
          {
            endpoint: m.introspection_endpoint,
            clientId: declared.introspection_client_id,
            clientSecret: opts.introspectionSecret,
            timeoutMs: config.introspection.timeout_ms,
            cacheMaxSeconds: config.introspection.cache_max_seconds,
            now,
          },
          estate,
        ),
      }))
      .catch((e: unknown) => {
        published = undefined;
        throw e;
      });
    return published;
  };

  const establishActingToken = async (form: { accessToken: string } | { tokenSha256: string }): Promise<ActingTokenResult> => {
    if (!("accessToken" in form)) return { ok: false, reason: "inactive" };
    let surfaces: Awaited<ReturnType<typeof estateSurfaces>>;
    try {
      surfaces = await estateSurfaces();
    } catch {
      return { ok: false, reason: "unavailable" };
    }
    try {
      let introspected: IntrospectedToken;
      try {
        introspected = await surfaces.introspector.introspect(form.accessToken);
      } catch (e) {
        // The one answer that is not a refusal: no introspection for this
        // token's type, so the token is validated locally.
        if (e instanceof IntrospectionTokenTypeUnsupportedError) return await validateLocally(form.accessToken, surfaces.keys);
        throw e;
      }
      if (!introspected.aud.some((a) => scopes.has(a))) return { ok: false, reason: "inactive" };
      return {
        ok: true,
        token: { issuer: estate, subject: introspected.sub, clientId: introspected.clientId, cnf: { jkt: introspected.cnfJkt }, exp: introspected.exp },
      };
    } catch (e) {
      return { ok: false, reason: e instanceof IntrospectionUnavailableError ? "unavailable" : "inactive" };
    }
  };

  /** RFC 9068 validation under the estate's published keys, where the estate offers no introspection for the token. */
  const validateLocally = async (accessToken: string, keys: JWTVerifyGetKey): Promise<ActingTokenResult> => {
    try {
      const { payload } = await jwtVerify(accessToken, keys, {
        issuer: estate,
        typ: "at+jwt",
        currentDate: now(),
        requiredClaims: ["exp", "sub", "client_id"],
      });
      const aud = typeof payload.aud === "string" ? [payload.aud] : (payload.aud ?? []);
      if (!aud.some((a) => scopes.has(a))) return { ok: false, reason: "inactive" };
      const jkt = (payload.cnf as { jkt?: unknown } | undefined)?.jkt;
      return {
        ok: true,
        token: {
          issuer: estate,
          subject: payload.sub as string,
          clientId: payload.client_id as string,
          ...(typeof jkt === "string" ? { cnf: { jkt } } : {}),
          exp: payload.exp as number,
        },
      };
    } catch {
      return { ok: false, reason: "inactive" };
    }
  };

  const evaluateJoin = (token: ActingToken, mission: MissionRecordLike): JoinEvaluation | undefined => {
    // A stale or missing snapshot resolves nothing, so no join is asserted.
    const contract = mapping.current();
    const at = now();
    const mapped = contract.resolveIdentity({
      subject: { iss: token.issuer, sub: token.subject },
      client: { iss: token.issuer, clientId: token.clientId },
      missionIssuer: mission.issuer,
      now: at,
    });
    if (!mapped || mapped.subject.iss !== mission.subject.iss || mapped.subject.sub !== mission.subject.sub) return undefined;
    const mappingVersion = `${contract.id}@${contract.version}`;
    if (mapped.clientId === mission.client_id) return { clientId: mapped.clientId, disposition: "client", mappingVersion };
    const rule = contract.delegatePolicy?.delegates[mapped.clientId];
    if (!rule) return undefined;
    const depth = opts.actorRecords.resolveDepth({ id: mission.id, issuer: mission.issuer }, mapped.clientId, mission.client_id);
    if (depth === undefined || (rule.maxDepth !== undefined && depth > rule.maxDepth)) return undefined;
    return { clientId: mapped.clientId, disposition: "delegate", depth, mappingVersion };
  };

  return { establishActingToken, evaluateJoin };
}
