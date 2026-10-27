/**
 * @spec AAT -02 Section 8 (#1756): the chain verification algorithm for
 * Attenuating Agent Tokens, the substrate Mission Offline Attenuation
 * profiles. {@link verifyAatPresentation} runs every step for one tool
 * invocation (the chain, the leaf checks and the PoP JWT);
 * {@link verifyAatChain} runs the steps that need no invocation (1 to 5, 6a
 * and the chain audience 6c), for a consumer that verifies a chain without a
 * tool call. Any failure denies, and the verdict never depends on step order;
 * the replay record (step 7i) is written only after every other check
 * passes.
 *
 * This is the substrate layer only. A Mission-bound consumer adds the
 * profile's checks on top (the `mission` claim, the Mission Issuer as the
 * trust anchor, current Mission state); a token's claims are returned as
 * plain JSON for that. Verified against the published -02 vector suite
 * (test/vectors/aat).
 */

import {
  constraintMapAttenuationProblem,
  constraintMapCheckProblem,
  constraintMapProblem,
} from "./aat-constraints.js";
import {
  AatJcsError,
  type AatJson,
  type AatNumber,
  type AatObject,
  allNumbersAdmissible,
  isAatObject,
  isIntegerSyntax,
  jcs,
  parseAatJson,
  scanTopLevelJti,
  toPlainJson,
} from "./aat-json.js";
import {
  AAT_ALGORITHMS,
  AAT_DETAIL_TYPE_NAME,
  AAT_JWT_TYP,
  AAT_POP_JWT_TYP,
  type AatJwsParts,
  algMatchesKey,
  headerProblem,
  importPublicJwk,
  jwkThumbprintUri,
  publicJwkProblem,
  segmentObject,
  segmentText,
  sha256B64url,
  splitCompactJws,
  verifyJwsSignature,
} from "./aat-jws.js";

/** @spec AAT -02 Sections 4.3, 4.3.1, 4.4, 3.4 and 9.9: implementation limits. */
export interface AatParams {
  maxIatSkew: number;
  maxTokenLifetime: number;
  maxDelegationDepth: number;
  maxConstraintDepth: number;
  maxTokenSize: number;
  maxChainSize: number;
  /** The PoP JWT `iat` window, plus or minus this many seconds (step 7g). */
  popWindow: number;
  algorithms: readonly string[];
}

/** The RECOMMENDED values of -02 (MAX_DELEGATION_DEPTH at its interoperable minimum). */
export const AAT_DEFAULT_PARAMS: AatParams = {
  maxIatSkew: 30,
  maxTokenLifetime: 90 * 24 * 3600,
  maxDelegationDepth: 8,
  maxConstraintDepth: 32,
  maxTokenSize: 65_536,
  maxChainSize: 262_144,
  popWindow: 30,
  algorithms: AAT_ALGORITHMS,
};

/** A configured trust anchor: a root issuer identifier bound to its public key; `kid` only selects among anchors. */
export interface AatTrustAnchor {
  issuer: string;
  jwk: Readonly<Record<string, unknown>>;
  kid?: string;
}

/**
 * @spec AAT -02 Section 7.3 and step 7i: accepted PoP `jti` state, shared by
 * an enforcement point's replicas. The check and the record are one atomic
 * call, so two replicas cannot both accept one proof between a check and a
 * record. It matches `admit(jti)` of the DPoP replay cache (dpop-replay.ts).
 */
export interface AatReplayState {
  /** Track `jti` for this invocation (a tool with side effects, or a sensitive read). */
  trackJti: boolean;
  /**
   * Atomically: false when `jti` was already accepted and is still within the
   * window of its `iat`; otherwise record it, retained until `iat` leaves the
   * window, and return true. Called only after every other check passes, so a
   * refused proof is never recorded.
   */
  admit(jti: string, iat: number): boolean;
}

/** The enforcement point's audience and presentation policy (steps 6c, 7d, 7h, 7i). */
export interface AatPolicy {
  /** The audience identifiers configured at this enforcement point, compared as exact strings. */
  audiences: readonly string[];
  /** Deny a chain in which no token carries `aud` (Section 9.5). */
  requireChainAud?: boolean;
  /** Deny a PoP JWT without `aat_aud` (Section 7.2). */
  requirePopAud?: boolean;
  /** Present when this enforcement point requires a nonce: true for a nonce it issued and still accepts. */
  acceptNonce?: (nonce: string) => boolean;
  replay?: AatReplayState;
}

export interface AatDeny {
  verdict: "DENY";
  /** The Section 8 step that failed (for example "4p4"); informational, since steps may be reordered. */
  step: string;
  reason: string;
}

/** One verified token: its compact form, protected header and claims as plain JSON. */
export interface AatVerifiedToken {
  compact: string;
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  /** The `tools` member of the token's one attenuating_agent_token entry. */
  tools: Record<string, Record<string, unknown>>;
}

export interface AatChainPermit {
  verdict: "PERMIT";
  chain: AatVerifiedToken[];
  root: AatVerifiedToken;
  leaf: AatVerifiedToken;
  /** The issuer of the trust anchor whose key verified the root (step 3k). */
  anchorIssuer: string;
}

export interface AatPresentationPermit extends AatChainPermit {
  pop: { header: Record<string, unknown>; claims: Record<string, unknown> };
}

export interface AatChainInput {
  /** Compact JWS strings, root first and leaf last (`aat_chain`). */
  chain: readonly string[];
  trustAnchors: readonly AatTrustAnchor[];
  /** Seconds since the epoch. */
  now: number;
  params?: Partial<AatParams>;
  policy: Pick<AatPolicy, "audiences" | "requireChainAud">;
}

export interface AatPresentationInput extends Omit<AatChainInput, "policy"> {
  /** The PoP JWT for this invocation (`aat_pop`). */
  pop: string;
  /** The invoked tool identifier, compared as an exact string. */
  tool: string;
  /** The invocation arguments as the JSON text the binding carried, read losslessly. */
  argsJson: string;
  policy: AatPolicy;
}

interface Token {
  compact: string;
  parts: AatJwsParts;
  header: AatObject;
  claims: AatObject;
  cnfJwk: AatObject;
  tools: AatObject;
  jti: string;
  iat: number;
  exp: number;
  depth: number;
  maxDepth: number;
}

const deny = (step: string, reason: string): AatDeny => ({ verdict: "DENY", step, reason });
const num = (v: AatJson | undefined): number => (v as AatNumber).value;
const nonEmpty = (v: AatJson | undefined): v is string => typeof v === "string" && v.length > 0;
/** A non-negative integer written with no fraction or exponent part (Section 3.2). */
const depthOf = (v: AatJson | undefined): number | undefined =>
  isIntegerSyntax(v) && v.value >= 0 ? v.value : undefined;
/** RFC 3986 Section 3.1: a scheme followed by ":". */
const isUri = (v: AatJson | undefined): v is string =>
  typeof v === "string" && /^[A-Za-z][A-Za-z0-9+.-]*:/.test(v);

/** The `tools` of the one attenuating_agent_token entry of `authorization_details`, or a reason. */
function aatTools(claims: AatObject, requireNonEmptyArray: boolean): AatObject | string {
  const details = claims.authorization_details;
  if (!Array.isArray(details) || (requireNonEmptyArray && details.length === 0)) {
    return "authorization_details is not a non-empty array";
  }
  const entries = details.filter(
    (d) => isAatObject(d) && d.type === AAT_DETAIL_TYPE_NAME,
  ) as AatObject[];
  if (entries.length !== 1)
    return `${entries.length} attenuating_agent_token entries, not exactly one`;
  const tools = (entries[0] as AatObject).tools;
  if (!isAatObject(tools)) return "tools is not an object";
  for (const [tool, map] of Object.entries(tools)) {
    if (!isAatObject(map)) return `tools[${JSON.stringify(tool)}] is not an object`;
  }
  return tools;
}

/** Steps 3n and 4o: every constraint map of a token is well-formed. */
function constraintsProblem(tools: AatObject, maxDepth: number): string | undefined {
  for (const [tool, map] of Object.entries(tools)) {
    const p = constraintMapProblem(map as AatObject, maxDepth);
    if (p) return `${tool}: ${p}`;
  }
  return undefined;
}

function resolveParams(params: Partial<AatParams> | undefined): AatParams {
  return { ...AAT_DEFAULT_PARAMS, ...(params ?? {}) };
}

/** Steps 1 to 5 and 6a. */
function verifyChainTokens(
  chain: readonly string[],
  anchors: readonly AatTrustAnchor[],
  now: number,
  p: AatParams,
): { tokens: Token[]; anchorIssuer: string } | AatDeny {
  // Step 1.
  if (chain.length === 0) return deny("1", "the chain is empty");

  // Step 2: size limits, then token-instance cycle detection on the untrusted jti.
  let total = 0;
  for (const t of chain) {
    if (t.length > p.maxTokenSize) return deny("2a", "a token exceeds MAX_TOKEN_SIZE");
    total += t.length;
  }
  if (total > p.maxChainSize) return deny("2b", "the chain exceeds MAX_CHAIN_SIZE");
  const parts: AatJwsParts[] = [];
  const seenJti = new Set<string>();
  for (const t of chain) {
    const split = splitCompactJws(t);
    const payload = split ? segmentText(split.payload) : undefined;
    const jti = payload === undefined ? undefined : scanTopLevelJti(payload);
    if (!split || jti === undefined) return deny("2c", "a string-valued jti cannot be extracted");
    if (seenJti.has(jti)) return deny("2c", "a jti appears more than once in the chain");
    seenJti.add(jti);
    parts.push(split);
  }

  // Step 3: the root.
  const rootParts = parts[0] as AatJwsParts;
  const rootHeader = segmentObject(rootParts.header);
  if (typeof rootHeader === "string") return deny("3a", `root header: ${rootHeader}`);
  const hp = headerProblem(rootHeader, AAT_JWT_TYP, p.algorithms);
  if (hp) return deny("3a", `root header: ${hp}`);
  const alg = rootHeader.alg as string;
  const kid = rootHeader.kid;
  const byKid = typeof kid === "string" ? anchors.filter((a) => a.kid === kid) : [];
  const candidates = (byKid.length > 0 ? byKid : anchors).filter((a) => algMatchesKey(alg, a.jwk));
  if (candidates.length === 0) return deny("3a", "alg is not consistent with any trust anchor key");
  const verifying = candidates.filter((a) =>
    verifyJwsSignature(alg, importPublicJwk(a.jwk), rootParts),
  );
  if (verifying.length === 0)
    return deny("3b", "the root signature does not verify under a trust anchor");
  const rootClaims = segmentObject(rootParts.payload);
  if (typeof rootClaims === "string") return deny("3b", `root claims: ${rootClaims}`);
  if (!isIntegerSyntax(rootClaims.iat) || !isIntegerSyntax(rootClaims.exp)) {
    return deny("3b", "root iat and exp are not NumericDate values");
  }
  const root = rootClaims;
  if (depthOf(root.del_depth) !== 0) return deny("3c", "root del_depth is not the integer 0");
  if (Object.hasOwn(root, "par_hash")) return deny("3d", "the root carries par_hash");
  const rootIat = num(root.iat);
  const rootExp = num(root.exp);
  if (!(rootExp > now)) return deny("3e", "the root is expired");
  if (!(rootIat <= now + p.maxIatSkew)) return deny("3f", "root iat is beyond MAX_IAT_SKEW");
  if (!(rootExp > rootIat)) return deny("3g", "root exp is not after its iat");
  if (!(rootExp <= rootIat + p.maxTokenLifetime))
    return deny("3h", "root lifetime exceeds MAX_TOKEN_LIFETIME");
  const rootMax = depthOf(root.del_max_depth);
  if (rootMax === undefined || rootMax > p.maxDelegationDepth) {
    return deny(
      "3i",
      "root del_max_depth is not a non-negative integer within MAX_DELEGATION_DEPTH",
    );
  }
  if (!nonEmpty(root.jti)) return deny("3j", "root jti is not a non-empty string");
  const rootIss = root.iss;
  const anchor = isUri(rootIss) ? verifying.find((a) => a.issuer === rootIss) : undefined;
  if (!anchor) return deny("3k", "root iss is not the issuer of the trust anchor that verified it");
  const rootCnf = isAatObject(root.cnf) ? root.cnf.jwk : undefined;
  const rootJwkProblem = publicJwkProblem(rootCnf);
  if (rootJwkProblem) return deny("3l", `root cnf.jwk: ${rootJwkProblem}`);
  const rootTools = aatTools(root, true);
  if (typeof rootTools === "string") return deny("3m", `root: ${rootTools}`);
  const rootConstraints = constraintsProblem(rootTools, p.maxConstraintDepth);
  if (rootConstraints) return deny("3n", `root: ${rootConstraints}`);

  const tokens: Token[] = [
    {
      compact: chain[0] as string,
      parts: rootParts,
      header: rootHeader,
      claims: root,
      cnfJwk: rootCnf as AatObject,
      tools: rootTools,
      jti: root.jti,
      iat: rootIat,
      exp: rootExp,
      depth: 0,
      maxDepth: rootMax,
    },
  ];

  // Step 4: each (parent, child) link.
  for (let i = 1; i < chain.length; i++) {
    const parent = tokens[i - 1] as Token;
    const cp = parts[i] as AatJwsParts;
    const header = segmentObject(cp.header);
    if (typeof header === "string") return deny("4a", `token ${i} header: ${header}`);
    const chp = headerProblem(header, AAT_JWT_TYP, p.algorithms);
    if (chp) return deny("4a", `token ${i} header: ${chp}`);
    const calg = header.alg as string;
    if (!algMatchesKey(calg, parent.cnfJwk))
      return deny("4a", `token ${i} alg is not consistent with its parent's cnf.jwk`);
    // I1: the child verifies under the key its parent's cnf.jwk carries, never a header key.
    if (!verifyJwsSignature(calg, importPublicJwk(parent.cnfJwk), cp)) {
      return deny("4b", `token ${i} does not verify under its parent's cnf.jwk`);
    }
    const c = segmentObject(cp.payload);
    if (typeof c === "string") return deny("4b", `token ${i} claims: ${c}`);
    if (!nonEmpty(c.jti)) return deny("4b1", `token ${i} jti is not a non-empty string`);
    const cnf = isAatObject(c.cnf) ? c.cnf.jwk : undefined;
    const jp = publicJwkProblem(cnf);
    if (jp) return deny("4b2", `token ${i} cnf.jwk: ${jp}`);
    if (!Array.isArray(c.authorization_details))
      return deny("4b3", `token ${i} authorization_details is not an array`);
    const depth = depthOf(c.del_depth);
    const maxDepth = depthOf(c.del_max_depth);
    if (depth === undefined || maxDepth === undefined) {
      return deny("4b4", `token ${i} del_depth or del_max_depth is not a non-negative integer`);
    }
    if (
      typeof c.iss !== "string" ||
      typeof c.par_hash !== "string" ||
      !isIntegerSyntax(c.iat) ||
      !isIntegerSyntax(c.exp)
    ) {
      return deny("4b5", `token ${i} iss, par_hash, iat or exp is missing or malformed`);
    }
    if (c.iss !== jwkThumbprintUri(parent.cnfJwk))
      return deny("4c", `token ${i} iss is not its parent's holder key`);
    const iat = num(c.iat);
    const exp = num(c.exp);
    if (depth !== parent.depth + 1)
      return deny("4d", `token ${i} del_depth is not its parent's plus one`);
    if (!(depth <= parent.maxDepth))
      return deny("4e", `token ${i} del_depth exceeds its parent's del_max_depth`);
    if (!(depth <= p.maxDelegationDepth))
      return deny("4f", `token ${i} del_depth exceeds MAX_DELEGATION_DEPTH`);
    if (!(maxDepth <= parent.maxDepth))
      return deny("4g", `token ${i} del_max_depth exceeds its parent's`);
    if (!(exp <= parent.exp)) return deny("4h", `token ${i} exp is after its parent's`);
    if (!(exp > now)) return deny("4i", `token ${i} is expired`);
    if (!(iat >= parent.iat)) return deny("4j", `token ${i} iat is before its parent's`);
    if (!(iat <= now + p.maxIatSkew)) return deny("4k", `token ${i} iat is beyond MAX_IAT_SKEW`);
    if (!(exp > iat)) return deny("4l", `token ${i} exp is not after its iat`);
    if (!(depth <= maxDepth))
      return deny("4m", `token ${i} del_depth exceeds its own del_max_depth`);
    const tools = aatTools(c, false);
    if (typeof tools === "string") return deny("4n", `token ${i}: ${tools}`);
    const wp = constraintsProblem(tools, p.maxConstraintDepth);
    if (wp) return deny("4o", `token ${i}: ${wp}`);
    for (const [tool, map] of Object.entries(tools)) {
      const parentMap = parent.tools[tool];
      if (!isAatObject(parentMap))
        return deny("4p1", `token ${i} adds tool ${JSON.stringify(tool)}`);
      const ap = constraintMapAttenuationProblem(parentMap, map as AatObject);
      if (ap)
        return deny(ap.slice(0, 3), `token ${i} tool ${JSON.stringify(tool)}: ${ap.slice(5)}`);
    }
    if (c.par_hash !== sha256B64url(parent.parts.signingInput)) {
      return deny("4q", `token ${i} par_hash does not commit to its parent's signing input`);
    }
    tokens.push({
      compact: chain[i] as string,
      parts: cp,
      header,
      claims: c,
      cnfJwk: cnf as AatObject,
      tools,
      jti: c.jti,
      iat,
      exp,
      depth,
      maxDepth,
    });
  }

  // Step 5 (defense in depth).
  const leaf = tokens[tokens.length - 1] as Token;
  if (chain.length !== leaf.depth + 1)
    return deny("5", "the chain length is not the leaf's del_depth plus one");
  return { tokens, anchorIssuer: anchor.issuer };
}

/** Step 6c: every `aud` in the chain identifies this enforcement point. */
function chainAudienceProblem(
  tokens: readonly Token[],
  policy: Pick<AatPolicy, "audiences" | "requireChainAud">,
): string | undefined {
  let carried = false;
  for (const [i, t] of tokens.entries()) {
    if (!Object.hasOwn(t.claims, "aud")) continue;
    carried = true;
    const aud = t.claims.aud;
    const values =
      typeof aud === "string"
        ? [aud]
        : Array.isArray(aud) && aud.every((a) => typeof a === "string")
          ? (aud as string[])
          : undefined;
    if (!values) return `token ${i} aud is not a string or an array of strings`;
    if (!values.some((v) => policy.audiences.includes(v)))
      return `token ${i} aud does not identify this enforcement point`;
  }
  if (policy.requireChainAud && !carried)
    return "chain audience is required and no token carries aud";
  return undefined;
}

function verified(t: Token): AatVerifiedToken {
  return {
    compact: t.compact,
    header: toPlainJson(t.header) as Record<string, unknown>,
    claims: toPlainJson(t.claims) as Record<string, unknown>,
    tools: toPlainJson(t.tools) as Record<string, Record<string, unknown>>,
  };
}

function chainPermit(tokens: readonly Token[], anchorIssuer: string): AatChainPermit {
  const chain = tokens.map(verified);
  return {
    verdict: "PERMIT",
    chain,
    root: chain[0] as AatVerifiedToken,
    leaf: chain[chain.length - 1] as AatVerifiedToken,
    anchorIssuer,
  };
}

/**
 * @spec AAT -02 Section 8 steps 1 to 5, 6a and 6c: verify a delegation chain
 * with no tool invocation. PoP and argument checks are the caller's.
 */
export function verifyAatChain(input: AatChainInput): AatChainPermit | AatDeny {
  const p = resolveParams(input.params);
  const r = verifyChainTokens(input.chain, input.trustAnchors, input.now, p);
  if ("verdict" in r) return r;
  // Step 6a holds by construction: every token carries exactly one entry (steps 3m and 4n).
  const aud = chainAudienceProblem(r.tokens, input.policy);
  if (aud) return deny("6c", aud);
  return chainPermit(r.tokens, r.anchorIssuer);
}

/**
 * @spec AAT -02 Section 8: verify one presentation (the chain and its PoP
 * JWT) for the invocation of `tool` with `argsJson`. The PoP signature is
 * verified before argument constraints are evaluated, as Section 8
 * recommends, and the replay record (step 7i) is written last.
 */
export function verifyAatPresentation(
  input: AatPresentationInput,
): AatPresentationPermit | AatDeny {
  const p = resolveParams(input.params);
  const r = verifyChainTokens(input.chain, input.trustAnchors, input.now, p);
  if ("verdict" in r) return r;
  const leaf = r.tokens[r.tokens.length - 1] as Token;
  const { policy } = input;

  // Step 7a.
  const popParts = splitCompactJws(input.pop);
  if (!popParts) return deny("7a", "the PoP JWT is not a compact JWS");
  const popHeader = segmentObject(popParts.header);
  if (typeof popHeader === "string") return deny("7a", `PoP header: ${popHeader}`);
  const php = headerProblem(popHeader, AAT_POP_JWT_TYP, p.algorithms);
  if (php) return deny("7a", `PoP header: ${php}`);
  const popAlg = popHeader.alg as string;
  if (!algMatchesKey(popAlg, leaf.cnfJwk))
    return deny("7a", "PoP alg is not consistent with the leaf's cnf.jwk");
  // Step 7b (I6): the PoP verifies under the leaf's cnf.jwk.
  if (!verifyJwsSignature(popAlg, importPublicJwk(leaf.cnfJwk), popParts)) {
    return deny("7b", "the PoP JWT does not verify under the leaf's cnf.jwk");
  }
  const pop = segmentObject(popParts.payload);
  if (typeof pop === "string") return deny("7b", `PoP claims: ${pop}`);

  // Step 6b: the invoked tool and its arguments, read as written.
  if (!Object.hasOwn(leaf.tools, input.tool))
    return deny("6b", "the leaf does not authorize the tool");
  let args: AatJson;
  try {
    args = parseAatJson(input.argsJson);
  } catch {
    return deny("6b", "the invocation arguments are not a JSON object without duplicate members");
  }
  if (!isAatObject(args)) return deny("6b", "the invocation arguments are not a JSON object");
  if (!allNumbersAdmissible(args)) return deny("6b", "an argument number is not admissible");
  const cp = constraintMapCheckProblem(leaf.tools[input.tool] as AatObject, args);
  if (cp) return deny("6b", cp);

  // Step 6c.
  const aud = chainAudienceProblem(r.tokens, policy);
  if (aud) return deny("6c", aud);

  // Step 7c: the proof's required claims and its binding to the leaf.
  if (
    !nonEmpty(pop.jti) ||
    !nonEmpty(pop.aat_id) ||
    !nonEmpty(pop.aat_hash) ||
    !nonEmpty(pop.aat_tool)
  ) {
    return deny("7c", "PoP jti, aat_id, aat_hash or aat_tool is not a non-empty string");
  }
  if (!isIntegerSyntax(pop.iat)) return deny("7c", "PoP iat is not a NumericDate");
  if (!isAatObject(pop.hta)) return deny("7c", "PoP hta is not an object");
  if (pop.aat_id !== leaf.jti) return deny("7c", "PoP aat_id is not the leaf's jti");
  if (pop.aat_hash !== sha256B64url(leaf.parts.signingInput))
    return deny("7c", "PoP aat_hash does not commit to the leaf");
  // Step 7d: presentation audience.
  if (Object.hasOwn(pop, "aat_aud")) {
    if (typeof pop.aat_aud !== "string" || !policy.audiences.includes(pop.aat_aud)) {
      return deny("7d", "PoP aat_aud does not identify this enforcement point");
    }
  } else if (policy.requirePopAud) return deny("7d", "PoP aat_aud is required");
  // Step 7e.
  if (pop.aat_tool !== input.tool) return deny("7e", "PoP aat_tool is not the invoked tool");
  // Step 7f: hta, as written, equals the invocation's arguments under JCS.
  let htaMatches: boolean;
  try {
    htaMatches = allNumbersAdmissible(pop.hta) && jcs(pop.hta) === jcs(args);
  } catch (e) {
    if (!(e instanceof AatJcsError)) throw e;
    return deny("7f", "PoP hta or the invocation arguments carry a string JCS cannot canonicalize");
  }
  if (!htaMatches) return deny("7f", "PoP hta does not match the invocation arguments");
  // Step 7g: the bilateral clock window.
  const popIat = num(pop.iat);
  if (!(popIat >= input.now - p.popWindow && popIat <= input.now + p.popWindow)) {
    return deny("7g", "PoP iat is outside the clock window");
  }
  // Step 7h.
  if (policy.acceptNonce) {
    if (typeof pop.nonce !== "string" || !policy.acceptNonce(pop.nonce))
      return deny("7h", "PoP nonce is absent or not accepted");
  }
  // Step 7i: one atomic check-and-record, after every other check.
  if (policy.replay?.trackJti && !policy.replay.admit(pop.jti, popIat)) {
    return deny("7i", "PoP jti was already accepted");
  }
  return {
    ...chainPermit(r.tokens, r.anchorIssuer),
    pop: {
      header: toPlainJson(popHeader) as Record<string, unknown>,
      claims: toPlainJson(pop) as Record<string, unknown>,
    },
  };
}
