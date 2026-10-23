/**
 * @spec authority-server#join-assertion-pdp, authority-server#join-authzen (#1454)
 *
 * The PDP's consumption of a Mission Join Assertion: the MAS's signed,
 * sender-bound statement that an acting credential joins a Mission, carried
 * by the PEP in `context.mission_join.assertion` with the digest and
 * thumbprint of the credential it authenticated.
 *
 * Verified means, in place of the mapping checks of join rules 3 and 4:
 * signed under the MAS's Status keys with a `typ` of `mission-join+jwt` and
 * an `alg` this PDP accepts (the MAS's listed algorithms; jose refuses `none`
 * and an algorithm the key does not suit); `iss` and `mission` naming the
 * referenced Mission, and its `authority_hash` where the assertion carries
 * one; an `exp` not passed and an `aud` naming this PDP (an assertion with no
 * `aud` fails); and a `token` claim equal to the PEP-reported digest and
 * same-method thumbprint. The joining client, disposition and a delegate's
 * depth then come from the `join` claim. The verifier is the same jose call
 * the Status response verifier makes (`state-observation.ts`), with this
 * artifact's `typ` and algorithm list.
 *
 * Whether a joined decision requires an assertion is the deployment's
 * declaration (`required`, or per action class), never inferred from whether
 * one arrived.
 */

import { type JWTVerifyGetKey, jwtVerify } from "jose";

/** The Join Assertion's `typ` header parameter value. */
export const JOIN_ASSERTION_TYP = "mission-join+jwt";

/** This PDP's Join Assertion configuration: present, it consumes assertions. */
export interface JoinAssertionPolicy {
  /** This PDP as the MAS's enrollment identifies it: the `aud` an assertion must name. */
  audience: string;
  /** The MAS's published Status signing keys (its `jwks_uri`), which sign assertions. */
  keys: JWTVerifyGetKey;
  /**
   * The algorithms this PDP accepts: those the MAS lists in
   * `mission_status_signing_alg_values_supported` that its own policy also
   * accepts.
   */
  algorithms: readonly string[];
  /** Declared for the deployment: every joined decision requires an assertion. */
  required?: boolean;
  /** Declared per path: the action classes whose joined decisions require an assertion. */
  requiredActionClasses?: ReadonlySet<string>;
  /** Allowance on `exp` and `iat`, seconds. Default 0. */
  clockToleranceSeconds?: number;
}

/** The token binding the PEP reports beside an assertion (`context.mission_join`). */
export interface ReportedTokenBinding {
  token_sha256?: string;
  token_jkt?: string;
  token_x5t?: string;
}

/** The `join` claim of a verified assertion. */
export type AssertedJoin = { clientId: string; disposition: "client" } | { clientId: string; disposition: "delegate"; depth: number };

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/** Whether this deployment declares that a joined decision of `actionClass` requires an assertion. */
export function joinAssertionRequired(policy: JoinAssertionPolicy, actionClass: string | undefined): boolean {
  return policy.required === true || (actionClass !== undefined && policy.requiredActionClasses?.has(actionClass) === true);
}

/**
 * Verify `assertion` for the referenced Mission and the PEP-reported token
 * binding. Returns the asserted join, or `undefined` when any check fails.
 */
export async function verifyJoinAssertion(
  assertion: string,
  reported: ReportedTokenBinding,
  mission: { id: string; issuer: string; authorityHash: string },
  policy: JoinAssertionPolicy,
  now: Date,
): Promise<AssertedJoin | undefined> {
  try {
    const { payload } = await jwtVerify(assertion, policy.keys, {
      typ: JOIN_ASSERTION_TYP,
      algorithms: [...policy.algorithms],
      issuer: mission.issuer,
      audience: policy.audience,
      currentDate: now,
      clockTolerance: policy.clockToleranceSeconds ?? 0,
      // `aud` is required by the audience check itself.
      requiredClaims: ["exp", "iat"],
    });
    const m = payload.mission;
    if (!isRecord(m) || m.id !== mission.id || m.issuer !== mission.issuer) return undefined;
    if (m.authority_hash !== undefined && m.authority_hash !== mission.authorityHash) return undefined;

    // The token binding: the digest, and exactly one reported thumbprint
    // equal to the assertion's confirmation member of the same method.
    const token = payload.token;
    if (!isRecord(token) || !isString(reported.token_sha256) || token.sha256 !== reported.token_sha256) return undefined;
    if ((reported.token_jkt === undefined) === (reported.token_x5t === undefined)) return undefined;
    const bound = reported.token_jkt !== undefined ? token.jkt === reported.token_jkt : token["x5t#S256"] === reported.token_x5t;
    if (!bound) return undefined;

    const join = payload.join;
    if (!isRecord(join) || !isString(join.client_id)) return undefined;
    if (join.disposition === "client") return { clientId: join.client_id, disposition: "client" };
    if (join.disposition !== "delegate" || !Number.isSafeInteger(join.depth) || (join.depth as number) < 0) return undefined;
    return { clientId: join.client_id, disposition: "delegate", depth: join.depth as number };
  } catch {
    return undefined;
  }
}
