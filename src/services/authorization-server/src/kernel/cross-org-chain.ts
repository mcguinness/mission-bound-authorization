/**
 * @spec cross-org-delegation#verification — the ten-step destination
 * verification of a Cross-Organizational Mission Delegation Chain, and the
 * actor-binding credential validation of #actor-evidence. The Chain
 * Presentation structure (closure, bounds, digest) is mission-core's. The
 * chain itself is verified by the substrate's algorithm (AAT -02 Section 8
 * steps 1 to 5, {@link verifyAatChainLinks}) under trust anchors this
 * deployment's federation names, then by the attenuation profile's Mission
 * layer ({@link verifyMissionAatChain}: the `mission` claim, nested `aud`,
 * and `mission_constraints`). This module adds what this profile requires on
 * top: the origin principal `subject`, exactly the mapped entry, the
 * issuer-asserted root actor, actor classification, and the state gate.
 * Dual-axis local authorization (step 10) and the requested audience
 * (substrate step 6c) are the caller's: they need the local policy surface.
 */
import {
  AAT_DETAIL_TYPE,
  type AatTrustAnchor,
  type AatVerifiedToken,
  type ChainPresentation,
  MissionAatError,
  type MissionConstraints,
  verifyAatChainLinks,
  verifyMissionAatChain,
} from "@mission/core";
import { calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from "jose";
import type { AatToolMap } from "./attenuation.js";

export const WORKLOAD_ATTESTATION_TYPE = "workload-attestation+jwt";

/** An origin Mission Issuer the deployment accepts, with its published keys. */
export interface FederatedIssuer {
  issuer: string;
  jwks: { keys: JWK[] };
}

/** An actor-identity attestation source the deployment accepts. */
export interface AttestationSource {
  /** The credential `iss` this source signs as. */
  iss: string;
  jwks: { keys: JWK[] };
}

export interface FederationConfig {
  issuers: FederatedIssuer[];
  attestationSources: AttestationSource[];
  /** Registered actor-credential types this deployment supports. */
  actorCredentialTypes: string[];
  bounds: { maxHops: number; maxBytes: number };
  /** Maximum age (seconds) of a Mission-state observation. */
  stateFreshnessSeconds: number;
}

export interface VerifiedHop {
  jti: string;
  /** Named actor, when the hop carries a validated `act`; absent = key-only. */
  actor?: { iss: string; sub: string; sub_profile?: string };
  cnfJwk: JWK;
  tools: AatToolMap;
}

export interface VerifiedChain {
  missionId: string;
  missionIssuer: string;
  authorityHash: string;
  subject: { iss: string; sub: string };
  leaf: {
    payload: Record<string, unknown>;
    cnfJwk: JWK;
    tools: AatToolMap;
    /** The leaf's `mission_constraints`, verified present and narrowed at every hop. */
    missionConstraints: MissionConstraints;
    aud: string[];
  };
  /** Root-to-leaf reconstructed actor history ({@spec cross-org-delegation#verification} step 7). */
  lineage: VerifiedHop[];
  /** The verified tokens, root first, for the audience check the caller applies (substrate step 6c). */
  tokens: readonly AatVerifiedToken[];
}

export class ChainVerificationError extends Error {}

type ActClaim = { iss?: unknown; sub?: unknown; sub_profile?: unknown; act?: unknown };

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * @spec cross-org-delegation#verification step 5: the token carries exactly
 * the mapped entry. The substrate ignores an entry of another type (AAT -02
 * Section 8 step 4n); this profile refuses the Chain, because an entry of an
 * unknown or unmapped type is never conferred authority and its presence
 * beyond the mapped entry refuses.
 */
function requireOnlyMappedEntry(claims: Record<string, unknown>, label: string): void {
  const details = claims.authorization_details;
  if (!Array.isArray(details) || details.length !== 1 || !isObject(details[0]) || details[0].type !== AAT_DETAIL_TYPE) {
    throw new ChainVerificationError(
      `${label}: authorization_details must be exactly the mapped ${AAT_DETAIL_TYPE} entry`,
    );
  }
}

/** @spec cross-org-delegation#hop-members: the `mission` claim's origin principal. */
function subjectOf(claims: Record<string, unknown>): { iss: string; sub: string } | undefined {
  const subject = isObject(claims.mission) ? claims.mission.subject : undefined;
  if (!isObject(subject) || typeof subject.iss !== "string" || !subject.iss || typeof subject.sub !== "string" || !subject.sub) {
    return undefined;
  }
  return { iss: subject.iss, sub: subject.sub };
}

/** The hop's `cnf.jwk`, which the substrate verified is a public key (steps 3l and 4b2). */
function cnfJwkOf(claims: Record<string, unknown>): JWK {
  return (claims.cnf as { jwk: JWK }).jwk;
}

/**
 * @spec cross-org-delegation#actor-evidence — validate one actor-binding
 * credential: registered type; trusted attestation source; validity; subject
 * equals the hop's (act.iss, act.sub); bound key equals the hop cnf.jwk by
 * thumbprint. The test/reference credential type `workload-attestation+jwt`
 * is a JWS whose payload carries `subject: {iss, sub}` and `cnf: {jwk}`.
 */
async function validateActorCredential(
  fed: FederationConfig,
  entry: { type: string; credential: string },
  hop: { actIss: string; actSub: string; cnfJwk: JWK },
  nowS: number,
): Promise<void> {
  if (!fed.actorCredentialTypes.includes(entry.type)) {
    throw new ChainVerificationError(`unknown actor-credential type: ${entry.type}`);
  }
  if (entry.type !== WORKLOAD_ATTESTATION_TYPE) {
    throw new ChainVerificationError(`unsupported actor-credential type: ${entry.type}`);
  }
  let payload: Record<string, unknown> | undefined;
  let verified = false;
  for (const source of fed.attestationSources) {
    for (const key of source.jwks.keys) {
      try {
        const result = await jwtVerify(entry.credential, await importJWK(key, key.alg), {
          typ: WORKLOAD_ATTESTATION_TYPE,
          issuer: source.iss,
          currentDate: new Date(nowS * 1000),
        });
        payload = result.payload as Record<string, unknown>;
        verified = true;
        break;
      } catch {
        // try the next accepted source/key; untrusted issuers never validate
      }
    }
    if (verified) break;
  }
  if (!verified || !payload) {
    throw new ChainVerificationError("actor credential failed validation under every accepted attestation source");
  }
  const subject = payload.subject as { iss?: string; sub?: string } | undefined;
  if (subject?.iss !== hop.actIss || subject?.sub !== hop.actSub) {
    throw new ChainVerificationError("actor credential subject differs from the hop act");
  }
  const boundJwk = (payload.cnf as { jwk?: JWK } | undefined)?.jwk;
  if (!boundJwk) throw new ChainVerificationError("actor credential carries no bound key");
  const [a, b] = await Promise.all([
    calculateJwkThumbprint(boundJwk),
    calculateJwkThumbprint(hop.cnfJwk),
  ]);
  if (a !== b) {
    throw new ChainVerificationError("actor credential bound key differs from the hop cnf.jwk");
  }
}

export interface VerifyChainOptions {
  federation: FederationConfig;
  presentation: ChainPresentation;
  nowS: number;
  /** Establishes origin Mission state within the declared freshness bound. */
  stateSource?: (missionId: string, issuer: string) => { state: string; observedAtS: number } | undefined;
  /** Policy: hops that MUST be named (by del_depth). Empty = no requirement. */
  requireNamedDepths?: ReadonlySet<number>;
}

/**
 * @spec cross-org-delegation#verification — steps 1 through 9. Step 10
 * (dual-axis local authorization), the requested audience and the leaf
 * proof of possession are performed by the caller at its own boundary.
 */
export async function verifyCrossOrgChain(opts: VerifyChainOptions): Promise<VerifiedChain> {
  const { federation: fed, presentation, nowS } = opts;
  const credByHop = new Map<number, { type: string; credential: string }>();
  for (const e of presentation.actor_credentials ?? []) credByHop.set(e.hop, e);

  // Step 1: the origin Mission Issuer resolves through the federation's
  // accepted issuers and keys, never because the Chain names it. Steps 2 and
  // 3: the substrate's chain verification, AAT -02 Section 8 steps 1 to 5
  // (typ and alg, the root under a trust anchor, every child under its
  // parent's cnf.jwk, iss, par_hash, depth, time and capability
  // monotonicity, constraint well-formedness).
  const trustAnchors: AatTrustAnchor[] = fed.issuers.flatMap((iss) =>
    iss.jwks.keys.map((jwk) => ({
      issuer: iss.issuer,
      jwk: jwk as Record<string, unknown>,
      ...(typeof jwk.kid === "string" ? { kid: jwk.kid } : {}),
    })),
  );
  const links = verifyAatChainLinks({ chain: presentation.aat_chain, trustAnchors, now: nowS });
  if (links.verdict === "DENY") {
    throw new ChainVerificationError(`substrate step ${links.step}: ${links.reason}`);
  }
  const tokens = links.chain;

  // Steps 2, 4 and 5, the attenuation profile's Mission layer: a root the
  // Mission Issuer minted, the `mission` claim unchanged, nested `aud`, and
  // `mission_constraints` present, understood and narrowed at every hop
  // (attenuation#mission-binding-check, #mission-constraints).
  let missionLayer;
  try {
    missionLayer = verifyMissionAatChain(tokens, links.anchorIssuer);
  } catch (e) {
    if (e instanceof MissionAatError) throw new ChainVerificationError(e.message);
    throw e;
  }

  // Steps 2 and 4, this profile's: the root carries the origin principal,
  // and every hop carries it unchanged; every token carries exactly the
  // mapped entry (step 5).
  const root = tokens[0] as AatVerifiedToken;
  const subject = subjectOf(root.claims);
  if (!subject) {
    throw new ChainVerificationError("root mission.subject is required on a conforming Chain");
  }
  for (const [i, t] of tokens.entries()) {
    requireOnlyMappedEntry(t.claims, i === 0 ? "root" : `hop ${i}`);
    const s = subjectOf(t.claims);
    if (s?.iss !== subject.iss || s?.sub !== subject.sub) {
      throw new ChainVerificationError(`hop ${i}: mission invariants changed across the chain`);
    }
  }

  // Step 2: the issuer-asserted root act.
  const rootAct = root.claims.act as ActClaim | undefined;
  if (!isObject(rootAct) || typeof rootAct.iss !== "string" || !rootAct.iss || typeof rootAct.sub !== "string" || !rootAct.sub) {
    throw new ChainVerificationError("root MUST carry the issuer-asserted act (iss and sub)");
  }
  if (rootAct.act !== undefined) {
    throw new ChainVerificationError("root act carries a nested history: duplicated actor representation");
  }
  const lineage: VerifiedHop[] = [
    {
      jti: String(root.claims.jti ?? ""),
      actor: {
        iss: rootAct.iss,
        sub: rootAct.sub,
        ...(typeof rootAct.sub_profile === "string" ? { sub_profile: rootAct.sub_profile } : {}),
      },
      cnfJwk: cnfJwkOf(root.claims),
      tools: root.tools,
    },
  ];

  // Steps 6 and 7: classify each later hop and reconstruct the actor history.
  for (let i = 1; i < tokens.length; i++) {
    const hop = tokens[i] as AatVerifiedToken;
    const cnfJwk = cnfJwkOf(hop.claims);
    // Step 6: act present => named, credential REQUIRED.
    const act = hop.claims.act as ActClaim | undefined;
    let actor: VerifiedHop["actor"];
    const cred = credByHop.get(i);
    if (act !== undefined) {
      if (!isObject(act) || typeof act.iss !== "string" || !act.iss || typeof act.sub !== "string" || !act.sub) {
        throw new ChainVerificationError(`hop ${i}: a named hop requires both act.iss and act.sub`);
      }
      if (act.act !== undefined) {
        // @spec cross-org-delegation#hop-members — each artifact names only its
        // own hop's actor; a nested history is a duplicated representation.
        throw new ChainVerificationError(`hop ${i}: act carries a nested history`);
      }
      if (!cred) {
        throw new ChainVerificationError(`hop ${i}: named hop has no aligned actor credential`);
      }
      await validateActorCredential(fed, cred, { actIss: act.iss, actSub: act.sub, cnfJwk }, nowS);
      actor = { iss: act.iss, sub: act.sub, ...(typeof act.sub_profile === "string" ? { sub_profile: act.sub_profile } : {}) };
    } else if (cred) {
      throw new ChainVerificationError(`hop ${i}: actor credential aligned to a key-only hop`);
    } else if (opts.requireNamedDepths?.has(i)) {
      throw new ChainVerificationError(`hop ${i}: policy requires a named actor`);
    }
    lineage.push({ jti: String(hop.claims.jti ?? ""), ...(actor ? { actor } : {}), cnfJwk, tools: hop.tools });
  }

  // Step 9: Mission state from a local source within the freshness bound.
  const { id: missionId, issuer: missionIssuer, authority_hash: authorityHash } = missionLayer.mission;
  const observation = opts.stateSource?.(missionId, missionIssuer);
  if (!observation) {
    throw new ChainVerificationError("mission state unavailable: fail closed");
  }
  if (nowS - observation.observedAtS > fed.stateFreshnessSeconds) {
    throw new ChainVerificationError("mission state observation is stale: fail closed");
  }
  if (observation.state !== "active") {
    throw new ChainVerificationError(`mission is not active (${observation.state})`);
  }

  const leaf = tokens[tokens.length - 1] as AatVerifiedToken;
  const leafAud = leaf.claims.aud;
  return {
    missionId,
    missionIssuer,
    authorityHash,
    subject,
    leaf: {
      payload: leaf.claims,
      cnfJwk: cnfJwkOf(leaf.claims),
      tools: leaf.tools,
      missionConstraints: missionLayer.missionConstraints,
      aud: Array.isArray(leafAud) ? (leafAud as string[]) : typeof leafAud === "string" ? [leafAud] : [],
    },
    lineage,
    tokens,
  };
}
