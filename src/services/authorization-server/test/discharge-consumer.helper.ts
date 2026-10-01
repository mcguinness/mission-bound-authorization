/**
 * @spec discharge#discharge-receipt, discharge#discharge-carryover ("Response"),
 * status#mission-status-response — a TEST-SIDE consumer of the two signed
 * artifacts a `discharge` delivery can return. There is no production consumer
 * of either in this repository (no Resource Server or event source verifies a
 * Status envelope), so these verifiers live beside the tests that drive them.
 *
 * Each check is a separate, ordered step so a test can show that every one of
 * them refuses on its own:
 *  - {@link verifyDischargeReceipt}: the eight receipt checks;
 *  - {@link verifyStatusResponse}: the Status procedure's nine checks, where a
 *    forwarded response (`forwarded: true`) replaces step 8 (`mission.id`
 *    equals the requested `mission_id`) with `discharge_result.forwarded_from`
 *    naming the requested Mission and `mission.issuer` equalling its issuer.
 * Both validate `typ` EXACTLY, so neither artifact is ever accepted as the other.
 */

import { compactVerify, decodeProtectedHeader, type JWTVerifyGetKey } from "jose";

/** A refusal, naming the numbered check that failed. */
export class ConsumerVerificationError extends Error {
  constructor(
    readonly check: string,
    message: string,
  ) {
    super(`${check}: ${message}`);
  }
}

export const RECEIPT_TYP = "mission-discharge-receipt+jwt";
export const STATUS_TYP = "mission-status-response+jwt";
const SKEW_S = 30;

interface Common {
  /** The AS's published keys (its `jwks_uri`). */
  keys: JWTVerifyGetKey;
  /** The algorithms the AS advertises for Mission Status signing. */
  algs: readonly string[];
  /** The expected AS issuer URL. */
  issuer: string;
  /** The nonce this consumer sent. */
  nonce: string;
  /** Verification time, epoch seconds. */
  now: number;
}

async function verifySignature(
  jws: string,
  typ: string,
  opts: Common,
): Promise<Record<string, unknown>> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    throw new ConsumerVerificationError("typ", "not a JWS");
  }
  // 1. `typ`, exactly.
  if (header.typ !== typ) throw new ConsumerVerificationError("typ", `typ is ${String(header.typ)}`);
  // 2. an advertised `alg`, never `none`.
  if (typeof header.alg !== "string" || header.alg === "none" || !opts.algs.includes(header.alg)) {
    throw new ConsumerVerificationError("alg", `alg ${String(header.alg)} is not advertised`);
  }
  // 3. the signature against a current `jwks_uri` key.
  let payload: Uint8Array;
  try {
    ({ payload } = await compactVerify(jws, opts.keys, { algorithms: [...opts.algs] }));
  } catch (e) {
    throw new ConsumerVerificationError("signature", (e as Error).message);
  }
  return JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;
}

function verifyLifetime(payload: Record<string, unknown>, now: number): void {
  const iat = payload.iat;
  const exp = payload.exp;
  if (typeof iat !== "number" || iat > now + SKEW_S) {
    throw new ConsumerVerificationError("lifetime", "iat is in the future");
  }
  if (typeof exp !== "number" || exp < now - SKEW_S) {
    throw new ConsumerVerificationError("lifetime", "exp is in the past");
  }
}

/** The target form and `event_id` the request sent. */
export type SentTarget =
  | { condition_selector: string; event_id: string }
  | { entry_digest: string; condition_digest: string; event_id: string };

function sameTarget(echoed: Record<string, unknown>, sent: SentTarget): boolean {
  const keys = ["condition_selector", "entry_digest", "condition_digest"] as const;
  for (const k of keys) {
    const want = (sent as Record<string, unknown>)[k];
    if (echoed[k] !== want) return false;
  }
  return echoed.event_id === sent.event_id;
}

/**
 * @spec discharge#discharge-receipt — the eight checks a consumer makes before
 * relying on a Discharge Receipt (for example before it stops retrying).
 */
export async function verifyDischargeReceipt(
  jws: string,
  opts: Common & { audience: string; missionId: string; sent: SentTarget },
): Promise<Record<string, unknown>> {
  const payload = await verifySignature(jws, RECEIPT_TYP, opts); // 1-3
  // 4. `iss`.
  if (payload.iss !== opts.issuer) throw new ConsumerVerificationError("iss", String(payload.iss));
  // 5. `aud` is this consumer, as the AS authenticated it.
  if (payload.aud !== opts.audience) throw new ConsumerVerificationError("aud", String(payload.aud));
  // 6. `nonce` is the request's.
  if (payload.nonce !== opts.nonce) throw new ConsumerVerificationError("nonce", String(payload.nonce));
  // 7. the echoed Mission, target form and event.
  const receipt = payload.discharge_receipt as Record<string, unknown> | undefined;
  if (!receipt || receipt.mission_id !== opts.missionId || !sameTarget(receipt, opts.sent)) {
    throw new ConsumerVerificationError("echo", "discharge_receipt does not echo the request");
  }
  // 8. `iat` / `exp`, 30 seconds of skew.
  verifyLifetime(payload, opts.now);
  return payload;
}

/**
 * @spec status#mission-status-response — the Status consumer procedure, with
 * @spec discharge#discharge-carryover's one change for a forwarded response.
 */
export async function verifyStatusResponse(
  jws: string,
  opts: Common & {
    audience: string;
    /** The requesting client's identifier (step 6), when the response names one. */
    sub?: string;
    missionId: string;
    /** Implement Discharge After Carryover's replacement for step 8. */
    forwarded?: boolean;
  },
): Promise<Record<string, unknown>> {
  const payload = await verifySignature(jws, STATUS_TYP, opts); // 1-3
  if (payload.iss !== opts.issuer) throw new ConsumerVerificationError("iss", String(payload.iss)); // 4
  if (payload.aud !== opts.audience) throw new ConsumerVerificationError("aud", String(payload.aud)); // 5
  if (opts.sub !== undefined && payload.sub !== opts.sub) {
    throw new ConsumerVerificationError("sub", String(payload.sub)); // 6
  }
  if (payload.nonce !== opts.nonce) throw new ConsumerVerificationError("nonce", String(payload.nonce)); // 7
  // 8. `mission.id` is the requested Mission, OR, for a forwarded response,
  // `forwarded_from` names it and `mission.issuer` is its issuer; `mission` is
  // then read as the replacement the result reports.
  const mission = payload.mission as { id?: unknown; issuer?: unknown } | undefined;
  const forwardedFrom = (payload.discharge_result as { forwarded_from?: { issuer?: unknown; id?: unknown } })
    ?.forwarded_from;
  if (opts.forwarded && forwardedFrom !== undefined) {
    if (forwardedFrom.id !== opts.missionId || mission?.issuer !== forwardedFrom.issuer) {
      throw new ConsumerVerificationError("mission", "forwarded_from does not name the requested Mission");
    }
  } else if (mission?.id !== opts.missionId) {
    throw new ConsumerVerificationError("mission", `mission.id is ${String(mission?.id)}`);
  }
  verifyLifetime(payload, opts.now); // 9
  return payload;
}
