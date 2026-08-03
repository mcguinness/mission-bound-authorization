/**
 * @spec harness#mediated-egress
 *
 * The execution-environment scope statement a Mission-aware harness MUST
 * PUBLISH (draft § mission-mediation). For the action classes a deployment
 * mediates, the statement states the isolation mechanism that confines governed
 * work, names the unmediated paths excluded from the claim, and enumerates the
 * secondary egress channel classes the environment offers, each marked
 * mediated / excluded / outside the claim.
 *
 * Publish vs. sign. The draft's obligation is to PUBLISH the statement. Signing
 * ({@link signScopeStatement}) makes a published statement VERIFIABLE by a
 * relying party; it is a beyond-the-draft assurance, not a conformance
 * requirement, and SPEC_VERSIONS records it as such. Signing mirrors
 * `@mission/transparency`'s evidence convention: JCS canonicalization via
 * `@mission/core` + a `jose` ES256 JWS.
 *
 * Claim-gated completeness. The full channel-class enumeration is MUST where the
 * deployment claims trifecta containment or agent-compromise-resistant
 * enforcement for a class, and SHOULD otherwise (draft § mission-mediation). A
 * single-process (in-memory transport) harness cannot claim
 * agent-compromise-resistant containment, so {@link buildScopeStatement}
 * downgrades such a claim and emits the honest "no mediation claim for these
 * classes" form; a containment-claiming config that omits any class is rejected.
 *
 * Deferred (named, not built): signed Harness Evidence + transparency
 * registration + harness key publication; session-taint / egress-downgrade
 * logic (the taint policy is carried here only as an opaque pass-through
 * string); discovery-bound channels that enter the enumeration at binding;
 * multi-entry per-mediated-action-class statements; the harness
 * execution-state machine.
 */

import { createHash } from "node:crypto";
import { canonicalize, type JsonValue } from "@mission/core";
import { type CryptoKey, jwtVerify, SignJWT } from "jose";

/**
 * The secondary egress channel classes a scope statement enumerates (draft
 * § mission-mediation, "It covers at minimum"). This list is the enumeration
 * floor: DNS resolution; log and error output; shared stores another process
 * reads; shared vector stores or long-term memory; OS processes the agent
 * spawns; provider-side model context; the inference API itself; and rendering
 * surfaces that dereference remote references.
 */
export const CHANNEL_CLASSES = [
  "dns_resolution",
  "log_error_output",
  "shared_stores",
  "shared_vector_stores",
  "spawned_os_processes",
  "provider_model_context",
  "inference_api",
  "remote_ref_rendering",
] as const;

export type ChannelClass = (typeof CHANNEL_CLASSES)[number];

/**
 * A channel class is either mediated (its only path is the PEP), excluded by the
 * isolation mechanism, or outside the mediation claim (no mediation claim).
 */
export type ChannelDisposition = "mediated" | "excluded" | "outside_claim";

/**
 * The containment a deployment CLAIMS for a mediated action class
 * ({{I-D.draft-mcguinness-mission-runtime}}). `none` makes no
 * agent-compromise-resistance claim; `trifecta` and
 * `agent_compromise_resistant` do, and force the full-enumeration MUST.
 */
export type ContainmentClaim = "none" | "trifecta" | "agent_compromise_resistant";

/** One channel class and how the environment disposes of it. */
export interface ChannelClassStatement {
  channel_class: ChannelClass;
  disposition: ChannelDisposition;
  note?: string;
}

/** Input to {@link buildScopeStatement}. */
export interface ScopeStatementConfig {
  /**
   * The isolation mechanism confining governed work (a container, VM, or
   * network egress policy; for the reference harness, an in-memory process).
   */
  isolation_mechanism: string;
  /**
   * The transport realizing tool access. `in_memory` denotes a single-process
   * harness, which cannot claim agent-compromise-resistant containment.
   */
  transport?: "in_memory" | "http" | (string & Record<never, never>);
  /**
   * The containment the deployment CLAIMS. A single-process (`in_memory`)
   * transport is downgraded to `none` (see the honest-form rule above).
   */
  containment_claim?: ContainmentClaim;
  /** The mediated action classes this statement covers (draft: per action class). */
  mediated_action_classes?: string[];
  /** Unmediated paths explicitly excluded from the claim (debug shell, direct socket, ...). */
  excluded_unmediated_paths?: string[];
  /** Per-channel-class dispositions the deployment asserts. */
  channel_classes?: ChannelClassStatement[];
  /** Opaque taint-policy identifier passed through (session-taint logic is Deferred). */
  taint_policy?: string;
}

/** The published statement (draft § mission-mediation). */
export interface ExecutionEnvironmentScopeStatement {
  statement_type: "mission-harness-scope-statement";
  isolation_mechanism: string;
  transport: string;
  /** The containment actually claimed AFTER any single-process downgrade. */
  containment_claim: ContainmentClaim;
  /** What the config requested, so a downgrade is visible to a reader. */
  requested_containment_claim: ContainmentClaim;
  /** True when `containment_claim` is a containment claim (trifecta / ACR). */
  claims_containment: boolean;
  mediated_action_classes: string[];
  excluded_unmediated_paths: string[];
  channel_classes: ChannelClassStatement[];
  /**
   * `complete` iff the deployment asserted a disposition for every channel
   * class; MUST be `complete` when claiming containment, MAY be `partial`
   * otherwise (auto-filled classes carry the `outside_claim` no-claim form).
   */
  channel_enumeration: "complete" | "partial";
  /** Opaque taint policy pass-through (Deferred: no taint logic this increment). */
  taint_policy?: string;
}

const CONTAINMENT_CLAIMS: ReadonlySet<ContainmentClaim> = new Set([
  "trifecta",
  "agent_compromise_resistant",
]);

/**
 * Build an execution-environment scope statement from a deployment config.
 *
 * A single-process (`in_memory`) transport is downgraded to `containment_claim:
 * "none"` and emits the honest form. When the effective claim IS a containment
 * claim, every channel class MUST carry a disposition or the config is rejected
 * (the MUST branch); otherwise absent classes are auto-filled as `outside_claim`
 * and the enumeration is reported `partial` (the SHOULD branch).
 */
export function buildScopeStatement(
  config: ScopeStatementConfig,
): ExecutionEnvironmentScopeStatement {
  const transport = config.transport ?? "in_memory";
  const requested = config.containment_claim ?? "none";
  // A single-process harness cannot claim agent-compromise-resistant
  // containment: downgrade to the honest no-claim form.
  const effective: ContainmentClaim = transport === "in_memory" ? "none" : requested;
  const claimsContainment = CONTAINMENT_CLAIMS.has(effective);

  const provided = new Map<ChannelClass, ChannelClassStatement>();
  for (const entry of config.channel_classes ?? []) {
    provided.set(entry.channel_class, entry);
  }

  if (claimsContainment) {
    // MUST branch: a containment claim cannot be vacuous. The statement is
    // per mediated action class (draft § mission-mediation), so it must name
    // at least one, and it must enumerate every channel class.
    if ((config.mediated_action_classes ?? []).length === 0) {
      throw new Error(`scope statement claims ${effective} containment but names no mediated action class`);
    }
    const missing = CHANNEL_CLASSES.filter((c) => !provided.has(c));
    if (missing.length > 0) {
      throw new Error(
        `scope statement claims ${effective} containment but omits channel class(es): ${missing.join(", ")}`,
      );
    }
  }

  // Fill the enumeration. In the honest (no-claim) form, a class without an
  // explicit disposition defaults to `outside_claim` ("no mediation claim").
  const channel_classes: ChannelClassStatement[] = CHANNEL_CLASSES.map((channel_class) => {
    const entry = provided.get(channel_class);
    return entry ?? { channel_class, disposition: "outside_claim", note: "no mediation claim" };
  });
  const channel_enumeration: "complete" | "partial" = CHANNEL_CLASSES.every((c) => provided.has(c))
    ? "complete"
    : "partial";

  return {
    statement_type: "mission-harness-scope-statement",
    isolation_mechanism: config.isolation_mechanism,
    transport,
    containment_claim: effective,
    requested_containment_claim: requested,
    claims_containment: claimsContainment,
    mediated_action_classes: config.mediated_action_classes ?? [],
    excluded_unmediated_paths: config.excluded_unmediated_paths ?? [],
    channel_classes,
    channel_enumeration,
    ...(config.taint_policy !== undefined ? { taint_policy: config.taint_policy } : {}),
  };
}

export const SCOPE_STATEMENT_TYP = "mission-harness-scope-statement+jwt";

export interface ScopeStatementSigner {
  key: CryptoKey;
  kid: string;
  iss: string;
}

/** SHA-256 over the JCS-canonical statement bytes (mirrors the evidence digest). */
function scopeDigest(statement: ExecutionEnvironmentScopeStatement): string {
  const bytes = canonicalize(statement as unknown as JsonValue);
  return `sha-256:${createHash("sha256").update(bytes, "utf8").digest("base64url")}`;
}

/**
 * Sign a scope statement as an ES256 JWS, embedding the statement and its JCS
 * digest. This makes a published statement verifiable; it is NOT a
 * draft-mandated step (the draft says MUST publish, not MUST sign).
 */
export async function signScopeStatement(
  statement: ExecutionEnvironmentScopeStatement,
  signer: ScopeStatementSigner,
): Promise<string> {
  return new SignJWT({ scope_statement: statement, digest: scopeDigest(statement) })
    .setProtectedHeader({ alg: "ES256", kid: signer.kid, typ: SCOPE_STATEMENT_TYP })
    .setIssuer(signer.iss)
    .setIssuedAt()
    .sign(signer.key);
}

/**
 * Verify a signed scope statement and return it. Throws (like `jwtVerify`) when
 * the signature is invalid or the embedded statement no longer matches its
 * committed digest (tamper detection).
 */
export async function verifyScopeStatement(
  jws: string,
  publicKey: CryptoKey,
): Promise<ExecutionEnvironmentScopeStatement> {
  const { payload } = await jwtVerify(jws, publicKey, { typ: SCOPE_STATEMENT_TYP });
  const statement = payload.scope_statement as ExecutionEnvironmentScopeStatement | undefined;
  if (statement === undefined || scopeDigest(statement) !== payload.digest) {
    throw new Error("scope statement digest mismatch (tampered)");
  }
  return statement;
}
