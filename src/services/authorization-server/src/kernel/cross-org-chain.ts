/**
 * @spec cross-org-delegation#verification — the ten-step destination
 * verification of a Cross-Organizational Mission Delegation Chain, and the
 * actor-binding credential validation of #actor-evidence. The Chain
 * Presentation structure (closure, bounds, digest) is mission-core's; this
 * module owns trust resolution, signatures, invariants, subset relations,
 * actor classification, and the state gate. Dual-axis local authorization
 * (step 10) is the caller's: it needs the local policy surface.
 */
import {
  AAT_DETAIL_TYPE,
  AAT_TYP,
  audNesting,
  expNesting,
  parHash,
  toolsSubset,
  type AATTools,
  type ChainPresentation,
} from "@mission/core";
import {
  calculateJwkThumbprint,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
} from "jose";

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
  tools: AATTools;
}

export interface VerifiedChain {
  missionId: string;
  missionIssuer: string;
  authorityHash: string;
  subject: { iss: string; sub: string };
  leaf: { payload: Record<string, unknown>; cnfJwk: JWK; tools: AATTools; aud: string[] };
  /** Root-to-leaf reconstructed actor history ({@spec cross-org-delegation#verification} step 7). */
  lineage: VerifiedHop[];
}

export class ChainVerificationError extends Error {}

interface HopClaims {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  jti?: string;
  cnf?: { jwk?: JWK; jkt?: string };
  act?: { iss?: string; sub?: string; sub_profile?: string; [k: string]: unknown };
  mission?: { id?: string; issuer?: string; authority_hash?: string; subject?: { iss?: string; sub?: string } };
  del_depth?: number;
  del_max_depth?: number;
  par_hash?: string;
  authorization_details?: Array<{ type?: string; tools?: AATTools }>;
}

function toolsOfHop(claims: HopClaims, label: string): AATTools {
  const details = claims.authorization_details;
  if (!Array.isArray(details) || details.length !== 1 || details[0]?.type !== AAT_DETAIL_TYPE) {
    // @spec cross-org-delegation#verification step 5: an entry of an unknown or
    // unmapped type is never conferred authority, and its presence beyond the
    // mapped entry refuses the Chain.
    throw new ChainVerificationError(
      `${label}: authorization_details must be exactly the mapped ${AAT_DETAIL_TYPE} entry`,
    );
  }
  const tools = details[0]?.tools;
  if (tools === undefined || tools === null || typeof tools !== "object") {
    throw new ChainVerificationError(`${label}: mapped entry carries no tools`);
  }
  return tools;
}

function requireCnfJwk(claims: HopClaims, label: string): JWK {
  const jwk = claims.cnf?.jwk;
  if (!jwk) {
    // @spec cross-org-delegation#hop-members — a thumbprint-only confirmation
    // is not conforming on a cross-organizational Chain.
    throw new ChainVerificationError(
      `${label}: cnf must carry the full public jwk (thumbprint-only is not conforming)`,
    );
  }
  return jwk;
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
 * (dual-axis local authorization) and leaf proof-of-possession are performed
 * by the caller at its own boundary.
 */
export async function verifyCrossOrgChain(opts: VerifyChainOptions): Promise<VerifiedChain> {
  const { federation: fed, presentation, nowS } = opts;
  const chain = presentation.chain;
  const credByHop = new Map<number, { type: string; credential: string }>();
  for (const e of presentation.actor_credentials ?? []) credByHop.set(e.hop, e);

  // Step 2: root validation under a trust-model-resolved issuer (step 1).
  const rootHeader = decodeProtectedHeader(chain[0] as string);
  if (rootHeader.typ !== AAT_TYP) {
    throw new ChainVerificationError("root typ is not the substrate token type");
  }
  let rootPayload: HopClaims | undefined;
  for (const iss of fed.issuers) {
    for (const key of iss.jwks.keys) {
      try {
        const result = await jwtVerify(chain[0] as string, await importJWK(key, key.alg), {
          issuer: iss.issuer,
          currentDate: new Date(nowS * 1000),
        });
        rootPayload = result.payload as HopClaims;
        break;
      } catch {
        // not this accepted issuer/key; the chain never selects its own trust
      }
    }
    if (rootPayload) break;
  }
  if (!rootPayload) {
    throw new ChainVerificationError("root is not signed by an accepted origin Mission Issuer");
  }
  const mission = rootPayload.mission;
  if (!mission?.id || !mission.issuer || !mission.authority_hash) {
    throw new ChainVerificationError("root mission claim is incomplete");
  }
  if (mission.issuer !== rootPayload.iss) {
    throw new ChainVerificationError("root iss differs from mission.issuer");
  }
  const subject = mission.subject;
  if (!subject?.iss || !subject.sub) {
    throw new ChainVerificationError("root mission.subject is required on a conforming Chain");
  }
  const rootAct = rootPayload.act;
  if (!rootAct?.iss || !rootAct.sub) {
    throw new ChainVerificationError("root MUST carry the issuer-asserted act (iss and sub)");
  }
  if (rootAct.act !== undefined) {
    throw new ChainVerificationError("root act carries a nested history: duplicated actor representation");
  }
  if (typeof rootPayload.del_depth !== "number" || rootPayload.del_depth !== 0) {
    throw new ChainVerificationError("root del_depth must be 0");
  }
  const delMax = rootPayload.del_max_depth;
  if (typeof delMax !== "number" || delMax < 0) {
    throw new ChainVerificationError("root del_max_depth missing");
  }
  if (chain.length - 1 > delMax) {
    throw new ChainVerificationError("chain depth exceeds del_max_depth");
  }

  let parentPayload: HopClaims = rootPayload;
  let parentToken = chain[0] as string;
  let parentTools = toolsOfHop(rootPayload, "root");
  let parentCnf = requireCnfJwk(rootPayload, "root");
  const lineage: VerifiedHop[] = [
    {
      jti: String(rootPayload.jti ?? ""),
      actor: { iss: rootAct.iss, sub: rootAct.sub, ...(typeof rootAct.sub_profile === "string" ? { sub_profile: rootAct.sub_profile } : {}) },
      cnfJwk: parentCnf,
      tools: parentTools,
    },
  ];
  if (opts.requireNamedDepths?.has(0) && !lineage[0]?.actor) {
    throw new ChainVerificationError("policy requires a named actor at depth 0");
  }

  // Steps 3-7 per child hop.
  for (let i = 1; i < chain.length; i++) {
    const token = chain[i] as string;
    const header = decodeProtectedHeader(token);
    if (header.typ !== AAT_TYP) {
      throw new ChainVerificationError(`hop ${i}: typ is not the substrate token type`);
    }
    let payload: HopClaims;
    try {
      const result = await jwtVerify(token, await importJWK(parentCnf, parentCnf.alg ?? "ES256"), {
        currentDate: new Date(nowS * 1000),
      });
      payload = result.payload as HopClaims;
    } catch {
      // step 3: each child verifies under the public key carried in its
      // parent's cnf.jwk; anything else refuses.
      throw new ChainVerificationError(`hop ${i}: signature does not verify under the parent cnf.jwk`);
    }
    if (payload.par_hash !== parHash(parentToken)) {
      throw new ChainVerificationError(`hop ${i}: par_hash does not commit to the exact parent`);
    }
    // Step 4: mission invariants, value equality including subject.
    const m = payload.mission;
    if (
      m?.id !== mission.id ||
      m?.issuer !== mission.issuer ||
      m?.authority_hash !== mission.authority_hash ||
      m?.subject?.iss !== subject.iss ||
      m?.subject?.sub !== subject.sub
    ) {
      throw new ChainVerificationError(`hop ${i}: mission invariants changed across the chain`);
    }
    // Step 5: depth, audience, expiry, mapped-capability subset.
    if (payload.del_depth !== (parentPayload.del_depth as number) + 1) {
      throw new ChainVerificationError(`hop ${i}: del_depth is not monotonic`);
    }
    if (payload.del_max_depth !== delMax) {
      throw new ChainVerificationError(`hop ${i}: del_max_depth changed`);
    }
    if (!audNesting(payload.aud as string | string[], parentPayload.aud as string | string[])) {
      throw new ChainVerificationError(`hop ${i}: audience widened`);
    }
    if (!expNesting(Number(payload.exp), Number(parentPayload.exp))) {
      throw new ChainVerificationError(`hop ${i}: expiry extended`);
    }
    const tools = toolsOfHop(payload, `hop ${i}`);
    if (!toolsSubset(tools, parentTools)) {
      throw new ChainVerificationError(`hop ${i}: capability is not a subset of the parent`);
    }
    const cnfJwk = requireCnfJwk(payload, `hop ${i}`);
    // Step 6: hop classification. act present => named, credential REQUIRED.
    const act = payload.act;
    let actor: VerifiedHop["actor"];
    const cred = credByHop.get(i);
    if (act !== undefined) {
      if (!act.iss || !act.sub) {
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
    lineage.push({ jti: String(payload.jti ?? ""), ...(actor ? { actor } : {}), cnfJwk, tools });
    parentPayload = payload;
    parentToken = token;
    parentTools = tools;
    parentCnf = cnfJwk;
  }

  // Step 9: Mission state from a local source within the freshness bound.
  const observation = opts.stateSource?.(mission.id, mission.issuer);
  if (!observation) {
    throw new ChainVerificationError("mission state unavailable: fail closed");
  }
  if (nowS - observation.observedAtS > fed.stateFreshnessSeconds) {
    throw new ChainVerificationError("mission state observation is stale: fail closed");
  }
  if (observation.state !== "active") {
    throw new ChainVerificationError(`mission is not active (${observation.state})`);
  }

  const leafPayload = parentPayload as Record<string, unknown>;
  const leafAud = Array.isArray(parentPayload.aud)
    ? (parentPayload.aud as string[])
    : parentPayload.aud
      ? [parentPayload.aud as string]
      : [];
  return {
    missionId: mission.id,
    missionIssuer: mission.issuer,
    authorityHash: mission.authority_hash,
    subject: { iss: subject.iss, sub: subject.sub },
    leaf: { payload: leafPayload, cnfJwk: parentCnf, tools: parentTools, aud: leafAud },
    lineage,
  };
}
