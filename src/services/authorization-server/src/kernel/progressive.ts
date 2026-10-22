/**
 * @spec draft-mcguinness-oauth-mission-progressive
 *
 * Progressive authorization: an authority ceiling and a drawdown policy the
 * Approver consents at the initial approval event, and the policy-adjudicated
 * in-ceiling drawdown that creates an Expansion successor under the
 * `ceiling_drawdown` basis and completes in the token-exchange response.
 *
 * Default off. A deployment selects the drawdown path by configuring
 * {@link ProgressiveDrawdownOptions}; without it, an expansion of a Mission
 * that carries a ceiling takes the ordinary fresh-approval path.
 *
 * Adjudication ({@link adjudicateDrawdown}) refuses an out-of-ceiling request
 * with `out_of_ceiling`. An in-ceiling request falls back to a fresh human
 * approval, never to a refusal, whenever: the Mission commits no drawdown
 * policy; the held snapshot no longer matches the committed `digest` (only
 * the current registry is read, never a retained snapshot); the snapshot
 * states no usable per-drawdown bound or review cadence; the ceiling consent
 * is older than that cadence; a widened action is unclassified, in a
 * high-consequence class, satisfies the external-communication predicate, or
 * is cross-domain; the predecessor has a non-terminal Child Mission; the
 * successor overlaps a containment or discharge restriction of its expansion
 * chain; the drawdown exceeds the per-drawdown bound; or the chain has reached
 * its rate bound.
 */

import { randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { ApprovalFloorPolicy, ProgressiveProfile } from "@mission/demo-data";
import {
  type ActivationPolicyRef,
  authorityHash,
  catalogDigest,
  compareAmounts,
  computeAnchor,
  containmentAtEntries,
  type ContainmentSelector,
  intentHash,
  isSubsetSetIgnoringCapabilitySources,
  isValidAmount,
  type JsonValue,
  parseRfc3339Instant,
  proposalHash,
  selectorOverlapsEntry,
} from "@mission/core";
import {
  type ActivationPolicyRegistry,
  mintActivationPolicyRef,
  type RegisteredActivationPolicy,
  verifiedActivationPolicy,
} from "./activation-policy.js";
import { inheritCapabilitySources } from "./capability-binding.js";
import { entryDigest } from "./discharge.js";
import { restrictedSinceAdjudication } from "./expansion.js";
import { childActorCeilingOrigin, inheritChildActorOrigins } from "./child-actor-eligibility.js";
import { ceilingOrigin, inheritOrigins } from "./eligibility-provenance.js";
import { IntentError, validateAuthorityProposal } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type IntentSubmissionEvidenceFact,
  type MissionIntent,
  type MissionRecord,
  TERMINAL_STATES,
} from "./types.js";

/** @spec progressive#progressive-authorization: the `ceiling_hash` envelope `typ`. */
export const MISSION_AUTHORITY_CEILING_TYP = "mission-authority-ceiling";

/**
 * @spec progressive#progressive-authorization: `ceiling_hash`, an object of
 * exactly `authority_ceiling` and, when the Mission carries one,
 * `drawdown_policy` (omitted otherwise, never null or empty).
 */
export function ceilingHash(
  iss: string,
  authorityCeiling: readonly AuthorityEntry[],
  drawdownPolicy?: ActivationPolicyRef,
): string {
  const value = {
    authority_ceiling: authorityCeiling,
    ...(drawdownPolicy ? { drawdown_policy: drawdownPolicy } : {}),
  };
  return computeAnchor(MISSION_AUTHORITY_CEILING_TYP, iss, value as unknown as JsonValue);
}

/** The ceiling an approval surface reports the Approver consented. */
export interface CeilingConsent {
  authority_ceiling: AuthorityEntry[];
  /** The policy's `id` and `version`; the `digest` is minted from the snapshot this issuer holds. */
  drawdown_policy?: { id: string; version: string };
}

/**
 * The ceiling members of an approval decision, as the approval surface posted
 * them; {@link consentCeiling} validates them. Undefined when the decision
 * consents no ceiling.
 */
export function ceilingConsentOf(decision: Record<string, unknown>): CeilingConsent | undefined {
  if (decision.authority_ceiling === undefined) return undefined;
  return {
    authority_ceiling: decision.authority_ceiling as AuthorityEntry[],
    ...(decision.drawdown_policy !== undefined
      ? { drawdown_policy: decision.drawdown_policy as { id: string; version: string } }
      : {}),
  };
}

/**
 * @spec progressive#progressive-authorization: the disclosure line that states
 * how in-ceiling expansion is adjudicated under the offered ceiling.
 */
export function ceilingAdjudicationLine(offer: CeilingConsent): string {
  return offer.drawdown_policy
    ? `Within this ceiling, expansions of this Mission are adjudicated by drawdown policy ${offer.drawdown_policy.id} version ${offer.drawdown_policy.version}, without a further approval from you. Authority beyond the ceiling, and the classes this deployment reserves for a fresh approval, still require your approval.`
    : "No drawdown policy is offered with this ceiling: every expansion of this Mission still requires your approval.";
}

/**
 * @spec progressive#progressive-authorization: whether a decision consents
 * exactly the offered ceiling and drawdown policy, member for member.
 */
export function consentsOffer(consent: CeilingConsent, offer: CeilingConsent | undefined): boolean {
  if (!offer) return false;
  const policy = (c: CeilingConsent) =>
    c.drawdown_policy === undefined ? null : { id: c.drawdown_policy.id, version: c.drawdown_policy.version };
  return (
    isDeepStrictEqual(consent.authority_ceiling, offer.authority_ceiling) &&
    isDeepStrictEqual(policy(consent), policy(offer))
  );
}

/** The ceiling members a Mission record carries. */
export interface MissionCeiling {
  authority_ceiling: AuthorityEntry[];
  drawdown_policy?: ActivationPolicyRef;
  ceiling_hash: string;
  /** The latest explicitly consented ceiling's `ceiling_hash` (#1468); absent on records stored before it. */
  ceiling_consent_hash?: string;
  ceiling_consented_at: string;
  /**
   * @spec progressive#ceiling-drawdown-basis, progressive#ceiling-reconsent
   * (#1413): the Approver who consented this ceiling, the `consent_principal`
   * of every drawdown under it. Kept with the ceiling because a
   * human-approved successor's own Approver need not be the ceiling's.
   * Absent on a record stored before #1413; its `approval_basis` then names it.
   */
  ceiling_consent_principal?: { iss: string; sub: string };
  drawdown_count: number;
  /**
   * @spec progressive#audit-linkage, discovery#resource-identity (#1469): the
   * digest of the self-declaration this successor's adjudication evaluated,
   * computed over the bytes the Mission Issuer retrieved. On that successor
   * only; never carried forward.
   */
  resource_declaration_digest?: string;
}

/**
 * @spec progressive#progressive-authorization: the consented ceiling's
 * entries, each with an Authority Set entry's shape. A malformed ceiling is
 * refused `invalid_request`. The approval decision reads them before any
 * write, to hold the ceiling to the approval-authentication floor
 * (mission#approval-authentication, #1255).
 */
export function consentedCeilingEntries(consent: CeilingConsent): AuthorityEntry[] {
  const entries = consent.authority_ceiling as unknown;
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new IntentError("invalid_request", "authority_ceiling must be a non-empty array");
  }
  const resources: string[] = [];
  for (const e of entries) {
    const resource = (e as { resource?: unknown } | null)?.resource;
    const actions = (e as { actions?: unknown } | null)?.actions;
    if (typeof resource !== "string" || !Array.isArray(actions) || actions.length === 0) {
      throw new IntentError("invalid_request", "each authority_ceiling entry needs a resource and actions");
    }
    resources.push(resource);
  }
  return validateAuthorityProposal(JSON.stringify(entries), resources);
}

/**
 * @spec progressive#progressive-authorization: the consented drawdown
 * policy's reference, minted over the snapshot this issuer holds, or
 * undefined when the consent names none. A policy this issuer does not hold
 * at that version is refused `invalid_request`: the approval cannot commit
 * content the issuer cannot evaluate. The approval decision checks it before
 * any write, with the ceiling's entries (#1255).
 */
export function consentedDrawdownPolicy(
  iss: string,
  registry: ActivationPolicyRegistry | undefined,
  consent: CeilingConsent,
): ActivationPolicyRef | undefined {
  if (consent.drawdown_policy === undefined) return undefined;
  const { id, version } = (consent.drawdown_policy ?? {}) as { id?: unknown; version?: unknown };
  const drawdownPolicy =
    typeof id === "string" && typeof version === "string"
      ? mintActivationPolicyRef(iss, registry, id, version)
      : undefined;
  if (!drawdownPolicy) {
    throw new IntentError("invalid_request", "drawdown_policy names no policy this issuer holds at that version");
  }
  return drawdownPolicy;
}

/**
 * @spec progressive#progressive-authorization: validate a consented ceiling
 * and commit it. Each entry has an Authority Set entry's shape, and the
 * drawdown policy reference is minted by {@link consentedDrawdownPolicy}.
 */
export function consentCeiling(
  iss: string,
  registry: ActivationPolicyRegistry | undefined,
  consent: CeilingConsent,
  consentedAt: string,
  consentPrincipal?: { iss: string; sub: string },
): MissionCeiling {
  const ceiling = consentedCeilingEntries(consent);
  const drawdownPolicy = consentedDrawdownPolicy(iss, registry, consent);
  const hash = ceilingHash(iss, ceiling, drawdownPolicy);
  return {
    authority_ceiling: ceiling,
    ...(drawdownPolicy ? { drawdown_policy: drawdownPolicy } : {}),
    ceiling_hash: hash,
    // @spec progressive#progressive-authorization (#1468): at a consent the
    // consented and effective commitments are equal.
    ceiling_consent_hash: hash,
    ceiling_consented_at: consentedAt,
    ...(consentPrincipal ? { ceiling_consent_principal: consentPrincipal } : {}),
    drawdown_count: 0,
  };
}

/** A ceiling re-consented at a fresh human approval: committed, with that approval's consent instant. */
export type ReconsentedCeiling = Omit<MissionCeiling, "drawdown_count">;

/**
 * @spec progressive#ceiling-reconsent (#1413): the ceiling members of a
 * successor a fresh human approval creates. Approving the successor's
 * authority and re-consenting the ceiling are separate decisions: without an
 * explicit re-consent the predecessor's members and consent instant carry
 * unchanged, so authority approved beyond the ceiling stays outside it; a
 * re-consent replaces them. The chain's cumulative drawdown count continues
 * either way, and its restrictions are read through `predecessor` links.
 */
export function successorCeilingMembers(
  predecessor: MissionRecord,
  reconsent?: ReconsentedCeiling,
  /** @spec progressive#audit-linkage (#1469): the digest of the declaration this successor's adjudication evaluated. */
  resourceDeclarationDigest?: string,
): Partial<MissionCeiling> {
  const drawdownCount = predecessor.drawdown_count ?? 0;
  const digest = resourceDeclarationDigest ? { resource_declaration_digest: resourceDeclarationDigest } : {};
  if (reconsent) return { ...reconsent, drawdown_count: drawdownCount, ...digest };
  if (!predecessor.authority_ceiling || !predecessor.ceiling_hash || !predecessor.ceiling_consented_at) return {};
  return {
    ...digest,
    authority_ceiling: predecessor.authority_ceiling,
    ...(predecessor.drawdown_policy ? { drawdown_policy: predecessor.drawdown_policy } : {}),
    ceiling_hash: predecessor.ceiling_hash,
    ceiling_consent_hash: predecessor.ceiling_consent_hash ?? predecessor.ceiling_hash,
    ceiling_consented_at: predecessor.ceiling_consented_at,
    ceiling_consent_principal: ceilingConsentPrincipal(predecessor),
    drawdown_count: drawdownCount,
  };
}

/**
 * @spec progressive#ceiling-drawdown-basis (#1468): the commitment of the
 * ceiling a human last explicitly consented. A record stored before #1468
 * lacks the member; its ceiling was never narrowed, so `ceiling_hash` is it.
 */
export function ceilingConsentHash(record: MissionRecord): string | undefined {
  return record.ceiling_consent_hash ?? record.ceiling_hash;
}

/**
 * @spec progressive#ceiling-drawdown-basis: the Approver who consented the
 * record's ceiling. A record stored before #1413 lacks the member; its chain
 * then had no human-approved successor, so its `approval_basis` names them.
 */
export function ceilingConsentPrincipal(record: MissionRecord): { iss: string; sub: string } {
  return record.ceiling_consent_principal ?? record.approval_basis.consent_principal;
}

/** The stored form of a record's ceiling members, or null when it carries none. */
export function serializeCeiling(record: MissionRecord): string | null {
  if (!record.authority_ceiling || !record.ceiling_hash || !record.ceiling_consented_at) return null;
  const stored: MissionCeiling = {
    authority_ceiling: record.authority_ceiling,
    ...(record.drawdown_policy ? { drawdown_policy: record.drawdown_policy } : {}),
    ceiling_hash: record.ceiling_hash,
    ...(record.ceiling_consent_hash ? { ceiling_consent_hash: record.ceiling_consent_hash } : {}),
    ceiling_consented_at: record.ceiling_consented_at,
    ...(record.ceiling_consent_principal ? { ceiling_consent_principal: record.ceiling_consent_principal } : {}),
    drawdown_count: record.drawdown_count ?? 0,
    ...(record.resource_declaration_digest ? { resource_declaration_digest: record.resource_declaration_digest } : {}),
  };
  return JSON.stringify(stored);
}

/** Hydrate a stored ceiling column; an absent column is no ceiling. */
export function ceilingMembersOf(raw: unknown): Partial<MissionCeiling> {
  if (typeof raw !== "string" || !raw) return {};
  return JSON.parse(raw) as MissionCeiling;
}

/** The runtime profile's action classes, the vocabulary of the published classification. */
export type RuntimeActionClass =
  | "non_consequential"
  | "consequential_read"
  | "consequential_write"
  | "irreversible_action"
  | "external_commitment"
  | "privileged_administration";

const RUNTIME_ACTION_CLASSES: ReadonlySet<string> = new Set<RuntimeActionClass>([
  "non_consequential",
  "consequential_read",
  "consequential_write",
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** @spec progressive#in-ceiling-expansion: the classes a drawdown never grants by policy alone. */
const FRESH_APPROVAL_CLASSES: ReadonlySet<RuntimeActionClass> = new Set<RuntimeActionClass>([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/**
 * @spec progressive#in-ceiling-expansion: the deployment's selection of the
 * policy-adjudicated drawdown path, with the bounds its Mission Deployment
 * Profile publishes. Absent, no drawdown is adjudicated by policy.
 */
export interface ProgressiveDrawdownOptions {
  /** Policy-adjudicated drawdowns per expansion chain, keyed by its root, per window. */
  chainRateBound: { maxDrawdowns: number; windowSeconds: number };
  /**
   * The mapping from action identifiers to the runtime profile's action
   * classes. A widened action with no entry is not policy-adjudicated.
   */
  actionClasses: Readonly<Record<string, RuntimeActionClass>>;
  /** Actions that satisfy the runtime profile's external-communication predicate. */
  externalCommunicationActions?: readonly string[];
  /**
   * @spec progressive#ceiling-test (#1413): the deployment's policy for a
   * request outside the consented ceiling, never adjudicated by policy.
   * `fresh_approval` (the default) takes it to an ordinary, freshly approved
   * expansion; `refuse` refuses it, and this reference carries
   * `out_of_ceiling` on that refusal (a MAY, #1415).
   */
  beyondCeiling?: "fresh_approval" | "refuse";
  /**
   * @spec progressive#progressive-authorization (#1017): the ceiling and
   * drawdown policy this deployment's approval surface offers beside a
   * Mission, or undefined when it offers none. The approval page renders the
   * offer, and a decision may consent only exactly that offer, so the
   * consented ceiling is always one the Approver was shown. Client input
   * never reaches it.
   */
  ceilingOffer?: (request: { clientId: string; intent: MissionIntent }) => CeilingConsent | undefined;
  /**
   * @spec discovery#resource-identity, progressive#ceiling-test (#1469 stage
   * 1): the deployment's port to a resource's self-declaration, retrieved
   * server-side by origin. The Mission Issuer digests the exact bytes it
   * returns; nothing the agent sends is consulted. Absent, or resolving to
   * nothing, no declaration is evaluated and no digest is recorded.
   */
  resourceDeclarations?: (origin: string) => Promise<Uint8Array | string | undefined>;
  /**
   * @spec discovery#resource-identity (#1469 stage 2): the Mission Issuer's own
   * connection to an encountered origin, through the deployment. It reports
   * whether TLS authenticated the origin on that connection, and returns the
   * exact bytes of the RFC 9728 Protected Resource Metadata it retrieved over
   * it for the origin, if any. The reference performs no network retrieval
   * itself: TLS authentication is this port's report, never the agent's.
   * Absent, or resolving to nothing, no identity is pinned.
   */
  resourceMetadata?: (origin: string) => Promise<ResourceConnection | undefined>;
  /**
   * @spec discovery#resource-identity (#1469 stage 2): whether the issuer an
   * encountered resource's metadata names is authorized for the resource's
   * domain, through a deployment mechanism such as domain-authorized-issuer.
   * Only `true` verifies it; anything else, a failure included, leaves it
   * unverified.
   */
  issuerAuthorized?: (origin: string, issuer: string) => Promise<boolean | undefined>;
  /**
   * @spec discovery#resource-identity, discovery#adjudication (#1469 stage 2):
   * the deployment's policy for an encounter whose identity cannot be
   * established: an origin not TLS-authenticated, or metadata missing,
   * unusable, or naming no single authorization server. `fresh_approval` (the
   * default) routes it to a human; `refuse` refuses it. An encounter whose
   * named issuer is not verified as authorized always routes to a human.
   */
  unpinnedEncounter?: "fresh_approval" | "refuse";
  /**
   * @spec discovery#adjudication (#1469 stage 3): the harness's report of the
   * session taint state, through a channel the agent does not mediate: a
   * harness attestation the deployment verifies behind this port, as the
   * connection port carries TLS. It answers for the session or sessions acting
   * under the Mission for the client, tainted if any is, and returns nothing
   * when it cannot resolve a session. Nothing the request carries reaches it.
   */
  harnessTaint?: (session: { missionId: string; clientId: string }) => Promise<TaintReport | undefined>;
  /**
   * @spec discovery#adjudication (#1469 stage 3): how old, in seconds, a taint
   * report may be and still count. Required with {@link harnessTaint}.
   */
  taintMaxAgeSeconds?: number;
}

/**
 * @spec harness#decision-api-composition, discovery#adjudication (#1469 stage
 * 3): the harness's taint report: the harness profile's taint object, scoped to
 * the session, with the RFC 3339 date-time the harness established it.
 */
export interface TaintReport {
  tainted: boolean;
  granularity: "session";
  source_class?: string;
  reported_at: string;
}

/** @spec discovery#adjudication (#1469 stage 3): why no trustworthy taint report was used. */
export type TaintFailure = "missing" | "stale" | "unverifiable";

/** @spec discovery#resource-identity (#1469 stage 2): what the deployment's connection to an origin established. */
export interface ResourceConnection {
  /** Whether TLS authenticated the origin on the Mission Issuer's own connection. */
  tls_authenticated: boolean;
  /** The exact bytes of the origin's Protected Resource Metadata retrieved over that connection, if any. */
  metadata?: Uint8Array | string;
}

/**
 * @spec discovery#resource-identity (#1469 stage 2): the Encountered Resource
 * object, holding only the Mission Issuer's own verified values. It exists once
 * the origin is TLS-authenticated; `resource_metadata_digest` once usable
 * metadata was retrieved over that connection; `issuer` once that metadata
 * names exactly one authorization server.
 */
export interface EncounteredResource {
  origin: string;
  resource_metadata_digest?: string;
  issuer?: string;
}

/** @spec discovery#resource-identity (#1469 stage 2): why an encountered resource's identity is not pinned. */
export type PinFailure =
  | "origin_unauthenticated"
  | "metadata_unavailable"
  | "metadata_invalid"
  | "issuer_unnamed"
  | "issuer_ambiguous"
  | "issuer_unverified";

/**
 * @spec discovery#adjudication, progressive#ceiling-test (#1469 stage 1): the
 * facts an encounter records for the human approval it falls back to, and
 * for audit. The encountered resources come from the request's own entries,
 * never from the agent's `encountered_resource` hint, which is kept only as
 * the agent's claim.
 */
export interface EncounterFacts {
  origin: string;
  resources: string[];
  /** @spec discovery#resource-identity (#1469 stage 2): the pinned identity, as far as it was established. */
  resource?: EncounteredResource;
  /** Whether the identity is fully pinned: TLS-authenticated origin, usable metadata, one verified issuer. */
  pinned: boolean;
  /** Why it is not, when it is not. */
  pin_failure?: PinFailure;
  /**
   * @spec discovery#adjudication (#1469 stage 3): the taint state the
   * adjudication uses: tainted unless a fresh, well-formed harness report says
   * otherwise. Kept apart from the report itself, so a missing report is never
   * read as the harness having seen untrusted content.
   */
  tainted: boolean;
  /** Why no trustworthy report was used, when none was. */
  taint_failure?: TaintFailure;
  /** The harness's report as given (its known members), when one was obtained. */
  taint_report?: Record<string, unknown>;
  /** The raw-octet digest of the declaration bytes the Mission Issuer retrieved; absent when it retrieved none. */
  declaration_digest?: string;
  /** Whether the declaration lists every action sought at the resource; absent without a usable declaration. */
  declared?: boolean;
  /** The agent's hint, recorded as its claim, and whether each value matched the Mission Issuer's own. */
  hint?: EncounterHint & {
    digest_matched?: boolean;
    resource_metadata_digest_matched?: boolean;
    issuer_matched?: boolean;
  };
}

/** @spec discovery#resource-identity: the agent's Encountered Resource object and declaration digest, as claims. */
export interface EncounterHint {
  origin: string;
  resource_metadata_digest?: string;
  issuer?: string;
  resource_declaration_digest?: string;
}

/** The `scheme://host[:port]` origin of a URI, or undefined when it has none. */
function originOf(uri: string): string | undefined {
  try {
    const origin = new URL(uri).origin;
    return origin === "null" ? undefined : origin;
  } catch {
    return undefined;
  }
}

/**
 * @spec discovery#resource-identity (#1469 stage 1): the agent's
 * `encountered_resource` (an Encountered Resource object) and
 * `resource_declaration_digest` are hints. Each is validated for shape and
 * kept as the agent's claim, never as identity. A hint whose `origin` is not
 * an origin, or names no resource the request seeks, and a digest hint
 * without the object, are refused: the returned string is the reason.
 */
export function encounterHint(
  raw: unknown,
  digest: unknown,
  requested: readonly AuthorityEntry[],
): EncounterHint | undefined | string {
  if (raw === undefined && digest === undefined) return undefined;
  if (typeof raw !== "string") return "resource_declaration_digest rides only with encountered_resource";
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "encountered_resource is not a JSON object";
  }
  const origin = (parsed as { origin?: unknown } | null)?.origin;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || typeof origin !== "string" || originOf(origin) !== origin) {
    return "encountered_resource needs an origin";
  }
  // @spec discovery#resource-identity (#1469 stage 2): the object's other members, claims too.
  const { resource_metadata_digest: metadataDigest, issuer } = parsed as { resource_metadata_digest?: unknown; issuer?: unknown };
  if ((metadataDigest !== undefined && typeof metadataDigest !== "string") || (issuer !== undefined && typeof issuer !== "string")) {
    return "encountered_resource members are strings";
  }
  if (digest !== undefined && typeof digest !== "string") return "resource_declaration_digest is a string";
  if (!requested.some((e) => originOf(e.resource) === origin)) {
    return "the encountered resource names no resource the request seeks";
  }
  return {
    origin,
    ...(typeof metadataDigest === "string" ? { resource_metadata_digest: metadataDigest } : {}),
    ...(typeof issuer === "string" ? { issuer } : {}),
    ...(typeof digest === "string" ? { resource_declaration_digest: digest } : {}),
  };
}

/**
 * @spec discovery#resource-identity (#1469 stage 2): an issuer identifier as
 * RFC 9728 requires of `authorization_servers` (RFC 8414 Section 2): an
 * `https` URL with no query or fragment component, even an empty one. Domain
 * authorization does not make a malformed value an issuer.
 */
export function isIssuerIdentifier(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || !url.hostname) return false;
  if (value.includes("?")) return false;
  if (value.includes("#")) return false;
  return true;
}

/**
 * @spec discovery#resource-identity (#1469 stage 2): pin the encountered
 * resource's identity from the Mission Issuer's own connection, never from the
 * agent. The origin is the one that connection TLS-authenticated. Metadata
 * retrieved over it is used only when its `resource` is exactly the origin it
 * was retrieved for (RFC 9728 Section 3.3) and every authorization server it
 * names is an issuer identifier ({@link isIssuerIdentifier}); it is digested from its exact
 * bytes, and the one authorization server it names must be verified as
 * authorized for the resource's domain. The reference requires the metadata
 * and a named issuer: on the drawdown path, the resource's authorization
 * server association is what pinning establishes.
 */
export async function pinEncounteredResource(
  options: ProgressiveDrawdownOptions,
  origin: string,
): Promise<{ resource?: EncounteredResource; pinned: boolean; pin_failure?: PinFailure }> {
  let connection: ResourceConnection | undefined;
  try {
    connection = await options.resourceMetadata?.(origin);
  } catch {
    connection = undefined;
  }
  if (connection?.tls_authenticated !== true) return { pinned: false, pin_failure: "origin_unauthenticated" };
  const resource: EncounteredResource = { origin };
  const bytes = connection.metadata;
  if (bytes === undefined) return { resource, pinned: false, pin_failure: "metadata_unavailable" };
  let doc: unknown;
  try {
    doc = JSON.parse(typeof bytes === "string" ? bytes : Buffer.from(bytes).toString("utf8"));
  } catch {
    doc = undefined;
  }
  const servers = (doc as { authorization_servers?: unknown } | undefined)?.authorization_servers;
  if (
    !doc ||
    typeof doc !== "object" ||
    Array.isArray(doc) ||
    (doc as { resource?: unknown }).resource !== origin ||
    (servers !== undefined && (!Array.isArray(servers) || !servers.every((s) => typeof s === "string" && isIssuerIdentifier(s))))
  ) {
    return { resource, pinned: false, pin_failure: "metadata_invalid" };
  }
  resource.resource_metadata_digest = catalogDigest(bytes);
  // The same server listed twice is still one named issuer.
  const named = [...new Set((servers ?? []) as string[])];
  if (named.length === 0) return { resource, pinned: false, pin_failure: "issuer_unnamed" };
  if (named.length > 1) return { resource, pinned: false, pin_failure: "issuer_ambiguous" };
  const issuer = named[0] as string;
  resource.issuer = issuer;
  let authorized: boolean | undefined;
  try {
    authorized = await options.issuerAuthorized?.(origin, issuer);
  } catch {
    authorized = undefined;
  }
  if (authorized !== true) return { resource, pinned: false, pin_failure: "issuer_unverified" };
  return { resource, pinned: true };
}

/**
 * @spec discovery#adjudication (#1469 stage 3): the session taint state for an
 * adjudication. It comes only from the harness, through the deployment's port.
 * A missing report, one older than the deployment's bound, and one that is
 * malformed, future-dated or not session-scoped all count as tainted; a stale
 * tainted report is tainted too, so the rule has no asymmetry. A report is
 * fresh when 0 <= now - reported_at <= taintMaxAgeSeconds, `reported_at`
 * being a strict RFC 3339 date-time and `now` read when the report is judged,
 * after every lookup, so a slow one neither freshens a report nor dates one
 * in the future.
 */
export async function sessionTaint(
  options: ProgressiveDrawdownOptions,
  session: { missionId: string; clientId: string },
  now: () => Date,
): Promise<{ tainted: boolean; taint_failure?: TaintFailure; taint_report?: Record<string, unknown> }> {
  let report: unknown;
  try {
    report = await options.harnessTaint?.(session);
  } catch {
    report = undefined;
  }
  if (report === undefined || report === null) return { tainted: true, taint_failure: "missing" };
  if (typeof report !== "object" || Array.isArray(report)) return { tainted: true, taint_failure: "unverifiable" };
  const given = report as Record<string, unknown>;
  const taint_report = Object.fromEntries(
    ["tainted", "granularity", "source_class", "reported_at"].filter((k) => k in given).map((k) => [k, given[k]]),
  );
  const unverifiable = { tainted: true, taint_failure: "unverifiable" as const, taint_report };
  if (typeof given.tainted !== "boolean") return unverifiable;
  if (given.granularity !== "session") return unverifiable;
  if (given.source_class !== undefined && typeof given.source_class !== "string") return unverifiable;
  const at = parseRfc3339Instant(given.reported_at);
  if (at === undefined) return unverifiable;
  const ageSeconds = now().getTime() / 1000 - (Number(at.seconds) + Number(`0.${at.fraction || "0"}`));
  if (ageSeconds < 0) return unverifiable;
  if (ageSeconds > (options.taintMaxAgeSeconds as number)) return { tainted: true, taint_failure: "stale", taint_report };
  return { tainted: given.tainted, taint_report };
}

/**
 * @spec discovery#adjudication (#1469 stage 2): whether the deployment refuses
 * this encounter outright: its identity cannot be established and the
 * deployment does not escalate such encounters. An issuer that is named but
 * not verified always routes to a human.
 */
export function refusesEncounter(options: ProgressiveDrawdownOptions, facts: EncounterFacts): boolean {
  return options.unpinnedEncounter === "refuse" && !facts.pinned && facts.pin_failure !== "issuer_unverified";
}

/**
 * @spec discovery#resource-identity, discovery#adjudication,
 * progressive#ceiling-test (#1469 stage 1): the facts of an encounter. The
 * Mission Issuer retrieves the declaration itself, through the deployment's
 * port, from the origin of the request's own entry, and digests the exact
 * bytes; the hint is recorded beside them as the agent's claim. One origin per
 * request in this reference, and a hint naming another origin is refused, so
 * its digest is never compared with a different resource's declaration; the
 * returned string is the reason.
 */
export async function encounterFacts(
  options: ProgressiveDrawdownOptions,
  encountered: readonly string[],
  requested: readonly AuthorityEntry[],
  hint: EncounterHint | undefined,
  /**
   * @spec discovery#adjudication (#1469 stage 3): the session, from the
   * subject token and client authentication, and the clock, read when the taint
   * report is judged.
   */
  session: { missionId: string; clientId: string; now: () => Date },
): Promise<EncounterFacts | string> {
  const origins = [...new Set(encountered.map(originOf))];
  const origin = origins[0];
  if (origins.length !== 1 || origin === undefined) return "one encountered resource origin per request";
  if (hint && hint.origin !== origin) return "encountered_resource names an origin other than the encounter's";
  const pin = await pinEncounteredResource(options, origin);
  const identity = pin.resource;
  const taint = await sessionTaint(options, { missionId: session.missionId, clientId: session.clientId }, session.now);
  let bytes: Uint8Array | string | undefined;
  try {
    bytes = await options.resourceDeclarations?.(origin);
  } catch {
    bytes = undefined;
  }
  const digest = bytes === undefined ? undefined : catalogDigest(bytes);
  const sought = requested.filter((e) => encountered.includes(e.resource)).flatMap((e) => e.actions);
  const declared = bytes === undefined ? undefined : declaresActions(bytes, sought);
  return {
    origin,
    resources: [...encountered],
    ...(identity ? { resource: identity } : {}),
    pinned: pin.pinned,
    ...(pin.pin_failure ? { pin_failure: pin.pin_failure } : {}),
    tainted: taint.tainted,
    ...(taint.taint_failure ? { taint_failure: taint.taint_failure } : {}),
    ...(taint.taint_report ? { taint_report: taint.taint_report } : {}),
    ...(digest ? { declaration_digest: digest } : {}),
    ...(declared === undefined ? {} : { declared }),
    ...(hint
      ? {
          hint: {
            ...hint,
            ...(hint.resource_declaration_digest && digest ? { digest_matched: hint.resource_declaration_digest === digest } : {}),
            ...(hint.resource_metadata_digest && identity?.resource_metadata_digest
              ? { resource_metadata_digest_matched: hint.resource_metadata_digest === identity.resource_metadata_digest }
              : {}),
            ...(hint.issuer && identity?.issuer ? { issuer_matched: hint.issuer === identity.issuer } : {}),
          },
        }
      : {}),
  };
}

/**
 * The reference's self-declaration form (a deployment assumption: the draft
 * leaves the format to the deployment, R3 being one form): a JSON object whose
 * `operations` lists the action identifiers the resource declares. Whether it
 * lists every sought action; undefined when the bytes are not that form.
 */
export function declaresActions(bytes: Uint8Array | string, sought: readonly string[]): boolean | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof bytes === "string" ? bytes : Buffer.from(bytes).toString("utf8"));
  } catch {
    return undefined;
  }
  const operations = (parsed as { operations?: unknown } | null)?.operations;
  if (!Array.isArray(operations) || !operations.every((o) => typeof o === "string")) return undefined;
  return sought.every((a) => operations.includes(a));
}

const isPositiveInteger = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;

/**
 * @spec progressive#drawdown-bounds, progressive#fresh-approval,
 * progressive#ceiling-review (#1017): the typed option and the drawdown policy
 * snapshots a deployment's published Progressive section states, so the AS
 * enforces exactly what the Mission Deployment Profile publishes. A snapshot's
 * content is the policy's per-drawdown bound, review cadence and optional
 * retirement list, in that order.
 */
export function progressiveFromProfile(profile: ProgressiveProfile): {
  options: ProgressiveDrawdownOptions;
  policies: Record<string, RegisteredActivationPolicy>;
} {
  const policies: Record<string, RegisteredActivationPolicy> = {};
  for (const p of profile.drawdown_policies) {
    policies[p.id] = {
      version: p.version,
      content_type: "application/json",
      content: JSON.stringify({
        max_added_actions: p.max_added_actions,
        ceiling_review_cadence_s: p.ceiling_review_cadence_s,
        ...(p.retire_undrawn_actions ? { retire_undrawn_actions: p.retire_undrawn_actions } : {}),
      }),
    };
  }
  return {
    options: {
      chainRateBound: {
        maxDrawdowns: profile.chain_rate_bound.max_drawdowns,
        windowSeconds: profile.chain_rate_bound.window_seconds,
      },
      actionClasses: profile.action_classes,
      externalCommunicationActions: profile.external_communication_actions,
      beyondCeiling: profile.beyond_ceiling,
    },
    policies,
  };
}

/**
 * Validate the typed deployment configuration; throws on any malformed member,
 * and on a mapping that disagrees with the approval-authentication floor
 * ({@link assertDrawdownClassesMeetApprovalFloor}).
 */
export function validateProgressiveDrawdownOptions(
  o: ProgressiveDrawdownOptions,
  approvalFloor: ApprovalFloorPolicy,
): ProgressiveDrawdownOptions {
  if (!isPositiveInteger(o?.chainRateBound?.maxDrawdowns) || !isPositiveInteger(o.chainRateBound.windowSeconds)) {
    throw new Error("progressive chainRateBound needs positive integer maxDrawdowns and windowSeconds");
  }
  if (!o.actionClasses || typeof o.actionClasses !== "object") {
    throw new Error("progressive actionClasses must map action identifiers to runtime action classes");
  }
  for (const [action, cls] of Object.entries(o.actionClasses)) {
    if (!RUNTIME_ACTION_CLASSES.has(cls)) {
      throw new Error(`progressive actionClasses: ${action} has unknown class ${String(cls)}`);
    }
  }
  if (o.externalCommunicationActions !== undefined && !o.externalCommunicationActions.every((a) => typeof a === "string")) {
    throw new Error("progressive externalCommunicationActions must be action identifiers");
  }
  if (o.beyondCeiling !== undefined && o.beyondCeiling !== "fresh_approval" && o.beyondCeiling !== "refuse") {
    throw new Error("progressive beyondCeiling must be fresh_approval or refuse");
  }
  if (o.ceilingOffer !== undefined && typeof o.ceilingOffer !== "function") {
    throw new Error("progressive ceilingOffer must be a function of the request");
  }
  if (o.resourceDeclarations !== undefined && typeof o.resourceDeclarations !== "function") {
    throw new Error("progressive resourceDeclarations must be a function of the origin");
  }
  if (o.resourceMetadata !== undefined && typeof o.resourceMetadata !== "function") {
    throw new Error("progressive resourceMetadata must be a function of the origin");
  }
  if (o.issuerAuthorized !== undefined && typeof o.issuerAuthorized !== "function") {
    throw new Error("progressive issuerAuthorized must be a function of the origin and issuer");
  }
  if (o.unpinnedEncounter !== undefined && o.unpinnedEncounter !== "fresh_approval" && o.unpinnedEncounter !== "refuse") {
    throw new Error("progressive unpinnedEncounter must be fresh_approval or refuse");
  }
  // @spec discovery#resource-identity (#1469 stage 2): without a connection port
  // no identity is ever pinned, so refusing unpinned encounters would refuse
  // every encounter.
  if (o.unpinnedEncounter === "refuse" && o.resourceMetadata === undefined) {
    throw new Error("progressive unpinnedEncounter refuse needs a resourceMetadata port");
  }
  if (o.harnessTaint !== undefined && typeof o.harnessTaint !== "function") {
    throw new Error("progressive harnessTaint must be a function of the session");
  }
  if (o.taintMaxAgeSeconds !== undefined && !isPositiveInteger(o.taintMaxAgeSeconds)) {
    throw new Error("progressive taintMaxAgeSeconds must be a positive integer");
  }
  // @spec discovery#adjudication (#1469 stage 3): without a bound no report is
  // ever fresh, so the port would be consulted and never believed.
  if (o.harnessTaint !== undefined && o.taintMaxAgeSeconds === undefined) {
    throw new Error("progressive harnessTaint needs taintMaxAgeSeconds");
  }
  assertDrawdownClassesMeetApprovalFloor(o, approvalFloor);
  return o;
}

/**
 * @spec progressive#in-ceiling-expansion, mission#approval-authentication
 * (#1255): the drawdown's published mapping agrees with the
 * approval-authentication floor's classification. An action the floor
 * classifies, at any resource, in a class some floor `applies_to` must not map
 * in `actionClasses` to a class outside the fresh-approval set, or a drawdown
 * would grant by policy alone authority whose approval the floor guards.
 * `actionClasses` is keyed by action alone, so one floor-invoking
 * classification of the action is enough to refuse. An action with no
 * `actionClasses` entry needs nothing here: its drawdown falls back
 * (`unclassified_action`). Throws, so the deployment does not start.
 */
export function assertDrawdownClassesMeetApprovalFloor(
  o: ProgressiveDrawdownOptions,
  approvalFloor: ApprovalFloorPolicy,
): void {
  const invoking = new Set<string>(approvalFloor.floors.flatMap((f) => f.applies_to));
  for (const entry of approvalFloor.classification) {
    for (const [action, floorClass] of Object.entries(entry.actions)) {
      if (!invoking.has(floorClass) || !Object.hasOwn(o.actionClasses, action)) continue;
      const mapped = o.actionClasses[action] as RuntimeActionClass;
      if (!FRESH_APPROVAL_CLASSES.has(mapped)) {
        throw new Error(
          `progressive actionClasses: ${action} maps to ${mapped}, which a drawdown grants by policy, but the approval-authentication floor ${approvalFloor.policy_id} classifies it ${floorClass} at ${entry.resource}, which invokes a floor`,
        );
      }
    }
  }
}

/**
 * @spec progressive#in-ceiling-expansion, progressive#ceiling-review: what a
 * drawdown policy snapshot states, read from its JSON content: the
 * per-drawdown bound (`max_added_actions`, the widened resource-action pairs
 * one drawdown may add) and the review cadence effective under this version
 * (`ceiling_review_cadence_s`). Undefined when either is missing or malformed:
 * such a snapshot authorizes nothing.
 */
export interface DrawdownPolicyRules {
  max_added_actions: number;
  ceiling_review_cadence_s: number;
  /**
   * @spec progressive#drawdown-successor (#1468): optional. Ceiling actions
   * each policy-adjudicated successor retires from the ceiling it carries
   * when it holds none of them: the policy narrows the effective ceiling,
   * never the consent.
   */
  retire_undrawn_actions?: string[];
}

export function drawdownRulesOf(policy: RegisteredActivationPolicy): DrawdownPolicyRules | undefined {
  if (policy.content_type !== "application/json") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(policy.content);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const { max_added_actions, ceiling_review_cadence_s, retire_undrawn_actions } = parsed as Record<string, unknown>;
  if (!isPositiveInteger(max_added_actions) || !isPositiveInteger(ceiling_review_cadence_s)) return undefined;
  if (retire_undrawn_actions === undefined) return { max_added_actions, ceiling_review_cadence_s };
  if (!Array.isArray(retire_undrawn_actions) || !retire_undrawn_actions.every((a) => typeof a === "string")) {
    return undefined;
  }
  return { max_added_actions, ceiling_review_cadence_s, retire_undrawn_actions: retire_undrawn_actions as string[] };
}

/**
 * @spec progressive#drawdown-successor (#1468): the ceiling a
 * policy-adjudicated successor carries. Each entry loses the retired actions
 * the successor's Authority Set holds on no entry of the same type and
 * resource; an entry left with no action leaves the ceiling. The same array
 * when nothing is retired, so an unnarrowed ceiling keeps its hash.
 */
export function narrowedCeiling(
  ceiling: AuthorityEntry[],
  held: readonly AuthorityEntry[],
  retire: readonly string[],
): AuthorityEntry[] {
  if (retire.length === 0) return ceiling;
  const holds = (e: AuthorityEntry, action: string): boolean =>
    held.some((h) => h.type === e.type && h.resource === e.resource && h.actions.includes(action));
  let changed = false;
  const out: AuthorityEntry[] = [];
  for (const e of ceiling) {
    const actions = e.actions.filter((a) => !retire.includes(a) || holds(e, a));
    if (actions.length !== e.actions.length) changed = true;
    if (actions.length > 0) out.push(actions.length === e.actions.length ? e : { ...e, actions });
  }
  return changed ? out : ceiling;
}

/** Why an in-ceiling drawdown falls back to a fresh human approval. */
export type DrawdownFallbackReason =
  | "no_drawdown_policy"
  | "drawdown_policy_changed"
  | "drawdown_policy_unusable"
  | "ceiling_review_overdue"
  | "unclassified_action"
  | "fresh_approval_class"
  | "external_communication"
  | "cross_domain"
  | "live_children"
  | "restricted_overlap"
  | "entire_remaining_ceiling"
  | "per_drawdown_bound"
  | "chain_rate_bound"
  | "encounter";

export type DrawdownAdjudication =
  | { outcome: "out_of_ceiling" }
  | { outcome: "fresh_approval"; reason: DrawdownFallbackReason; encountered?: string[] }
  | { outcome: "policy"; ref: ActivationPolicyRef; snapshot: RegisteredActivationPolicy };

/** One widened resource-action pair: authority the predecessor's effective set does not already hold. */
interface WidenedPair {
  resource: string;
  action: string;
}

function widenedPairs(requested: readonly AuthorityEntry[], effective: readonly AuthorityEntry[]): WidenedPair[] {
  const out: WidenedPair[] = [];
  for (const e of requested) {
    for (const action of e.actions) {
      if (!isSubsetSetIgnoringCapabilitySources([{ ...e, actions: [action] }], effective as AuthorityEntry[])) {
        out.push({ resource: e.resource, action });
      }
    }
  }
  return out;
}

/**
 * @spec progressive#drawdown-bounds (#1414 review): some authority the
 * ceiling grants is shown to lie outside the successor's set taken as a
 * whole. A witness is a request one ceiling entry admits (one of its actions,
 * one of its vendors or any vendor, its full `max_amount` or any amount) that
 * no successor entry authorizes on those dimensions. Every other member is
 * assumed covered, so authority split across successor entries on any
 * dimension counts as held: a witness found is genuine, and one missed only
 * falls back to a fresh human approval. No witness, the drawdown activates the
 * entire remaining ceiling.
 */
export function ceilingAuthorityLeftUndrawn(
  requested: readonly AuthorityEntry[],
  ceiling: readonly AuthorityEntry[],
): boolean {
  for (const c of ceiling) {
    const vendors = c.constraints?.vendors;
    const vendorPoints: Array<string | undefined> = vendors?.length ? vendors : [undefined];
    for (const action of c.actions) {
      for (const vendor of vendorPoints) {
        if (!requested.some((s) => authorizesPoint(s, c, action, vendor))) return true;
      }
    }
  }
  return false;
}

/**
 * Whether successor entry `s` authorizes the request at action `action`,
 * vendor `vendor` (undefined: a vendor the ceiling entry leaves open) and the
 * ceiling entry's own `max_amount` (absent: an unbounded amount).
 */
function authorizesPoint(
  s: AuthorityEntry,
  c: AuthorityEntry,
  action: string,
  vendor: string | undefined,
): boolean {
  if (s.type !== c.type || s.resource !== c.resource || !s.actions.includes(action)) return false;
  const vendors = s.constraints?.vendors;
  if (vendors && (vendor === undefined || !vendors.includes(vendor))) return false;
  const sCap = s.constraints?.max_amount;
  const cCap = c.constraints?.max_amount;
  if (sCap) {
    if (!cCap || sCap.currency !== cCap.currency) return false;
    if (!isValidAmount(sCap.amount) || !isValidAmount(cCap.amount)) return false;
    if (compareAmounts(sCap.amount, cCap.amount) < 0) return false;
  }
  return true;
}

/** The Missions of an expansion chain, from `missionId` back to its root. */
function chainOf(kernel: MissionKernel, missionId: string): MissionRecord[] {
  const chain: MissionRecord[] = [];
  const seen = new Set<string>();
  let next: string | undefined = missionId;
  while (next && !seen.has(next)) {
    seen.add(next);
    const m = kernel.get(next);
    if (!m) break;
    chain.push(m);
    next = m.predecessor;
  }
  return chain;
}

/**
 * @spec progressive#in-ceiling-expansion, containment#restoration,
 * discharge#discharge: every capability under a containment or discharge
 * restriction of the chain. The reference has no explicit restoration
 * disclosure, so no restriction clears.
 */
function chainRestrictions(chain: readonly MissionRecord[]): ContainmentSelector[] {
  const out: ContainmentSelector[] = [];
  for (const m of chain) {
    // @spec containment#selector-matching (#1463): each selector as named,
    // and as it lands on the member's approved entries, the resolution the
    // effective set uses. A fine selector over a broad approved entry removed
    // its actions from the whole entry, so a drawdown restoring them for a
    // sibling resource overlaps a restriction too.
    const contained = m.containment?.contained ?? [];
    out.push(...contained, ...containmentAtEntries(m.authority_set, contained));
    for (const d of m.discharged ?? []) {
      const entry = m.authority_set.find((e) => entryDigest(m.issuer, e) === d.entry_digest);
      if (entry) out.push({ resource: entry.resource, actions: entry.actions });
    }
  }
  return out;
}

/**
 * Overlap in authority: overlapping resource sets and at least one shared
 * action (a restriction with no `actions` overlaps every action). A
 * containment restriction is a selector, so its resource set is compared by
 * Resource Access matching, never by string (@spec
 * containment#selector-matching, #1463).
 */
function overlaps(entry: AuthorityEntry, restricted: ContainmentSelector): boolean {
  if (!selectorOverlapsEntry(restricted, entry)) return false;
  if (!restricted.actions) return true;
  return entry.actions.some((a) => (restricted.actions as string[]).includes(a));
}

/**
 * @spec progressive#in-ceiling-expansion: adjudicate an expansion of a
 * Mission that carries an `authority_ceiling`. `requested` is the successor's
 * complete derived Authority Set. Reads only current state: the current
 * activation policy registry, the chain's records and the clock.
 */
export function adjudicateDrawdown(
  kernel: MissionKernel,
  options: ProgressiveDrawdownOptions,
  input: {
    predecessor: MissionRecord;
    requested: readonly AuthorityEntry[];
    isCrossDomain: (resource: string) => boolean;
  },
): DrawdownAdjudication {
  const { predecessor, requested } = input;
  const ceiling = predecessor.authority_ceiling ?? [];
  // @spec progressive#in-ceiling-expansion: in-ceiling when every successor
  // entry is a subset of some ceiling entry; otherwise refused out_of_ceiling.
  if (!isSubsetSetIgnoringCapabilitySources(requested as AuthorityEntry[], ceiling)) {
    return { outcome: "out_of_ceiling" };
  }
  const fallback = (reason: DrawdownFallbackReason): DrawdownAdjudication => ({ outcome: "fresh_approval", reason });
  // @spec discovery#encounter, discovery#adjudication (#1469 stage 1, D607): a
  // widened resource no ceiling entry names is an encounter. Until identity
  // pinning, trusted taint and the floors are in place, no encounter binds by
  // policy, whatever its other guards: it falls back to a fresh human
  // approval. Authority the predecessor already holds is no new encounter.
  const named = new Set(ceiling.map((e) => e.resource));
  const encountered = [
    ...new Set(
      widenedPairs(requested, kernel.effectiveAuthoritySet(predecessor))
        .filter((w) => !named.has(w.resource))
        .map((w) => w.resource),
    ),
  ];
  if (encountered.length) return { outcome: "fresh_approval", reason: "encounter", encountered };
  const ref = predecessor.drawdown_policy;
  if (!ref) return fallback("no_drawdown_policy");
  // @spec mission#standing-consent-bases, progressive#in-ceiling-expansion: a
  // snapshot that does not match the committed digest authorizes nothing.
  const snapshot = verifiedActivationPolicy(predecessor.issuer, kernel.activationPolicies(), ref);
  if (!snapshot) return fallback("drawdown_policy_changed");
  const rules = drawdownRulesOf(snapshot);
  if (!rules) return fallback("drawdown_policy_unusable");
  const nowMs = kernel.nowDate().getTime();
  // @spec progressive#ceiling-review: no policy adjudication for a chain whose
  // ceiling consent, the initial consent or the latest re-consent, is older
  // than the cadence.
  const consentedAt = Date.parse(predecessor.ceiling_consented_at ?? "");
  if (!Number.isFinite(consentedAt) || nowMs - consentedAt > rules.ceiling_review_cadence_s * 1000) {
    return fallback("ceiling_review_overdue");
  }
  const widened = widenedPairs(requested, kernel.effectiveAuthoritySet(predecessor));
  const external = new Set(options.externalCommunicationActions ?? []);
  for (const { resource, action } of widened) {
    const cls = Object.hasOwn(options.actionClasses, action) ? options.actionClasses[action] : undefined;
    if (cls === undefined) return fallback("unclassified_action");
    if (FRESH_APPROVAL_CLASSES.has(cls)) return fallback("fresh_approval_class");
    if (external.has(action)) return fallback("external_communication");
    if (input.isCrossDomain(resource)) return fallback("cross_domain");
  }
  // @spec progressive#in-ceiling-expansion: no policy adjudication while the
  // predecessor has non-terminal Child Missions.
  if (kernel.findChildren(predecessor.id).some((c) => !TERMINAL_STATES.has(kernel.observe(c).state))) {
    return fallback("live_children");
  }
  const chain = chainOf(kernel, predecessor.id);
  const restrictions = chainRestrictions(chain);
  if (requested.some((e) => restrictions.some((r) => overlaps(e, r)))) return fallback("restricted_overlap");
  // @spec progressive#drawdown-bounds: never the entire remaining ceiling by
  // policy; the final increment takes a fresh human approval.
  if (!ceilingAuthorityLeftUndrawn(requested, ceiling)) return fallback("entire_remaining_ceiling");
  if (widened.length > rules.max_added_actions) return fallback("per_drawdown_bound");
  const windowStart = nowMs - options.chainRateBound.windowSeconds * 1000;
  const recent = chain.filter(
    (m) => m.approval_basis.type === "ceiling_drawdown" && Date.parse(m.created_at) > windowStart,
  ).length;
  if (recent >= options.chainRateBound.maxDrawdowns) return fallback("chain_rate_bound");
  return { outcome: "policy", ref, snapshot };
}

/** A drawdown refused at its activating commit; nothing is created or superseded. */
export class DrawdownRefusal extends Error {
  constructor(
    readonly code: "derivations_exhausted" | "predecessor_not_active" | "authority_restricted_since_approval",
    message: string,
  ) {
    super(message);
  }
}

export interface CeilingDrawdownInput {
  predecessorId: string;
  /** The widened intent, derived under policy exactly as an ordinary expansion's. */
  intent: MissionIntent;
  proposedAuthority?: AuthorityEntry[];
  /** The verified Intent Submission Evidence facts, landed outside all anchors. */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
  /** The requesting client, the basis's `activation_actor`. */
  activationActor: { iss: string; sub: string };
  /** The policy and the held snapshot {@link adjudicateDrawdown} verified. */
  policy: { ref: ActivationPolicyRef; snapshot: RegisteredActivationPolicy };
  /** The predecessor's containment version and discharge-latch count as adjudicated. */
  restrictionsAtAdjudication: { containment: number; discharge: number };
}

/**
 * @spec progressive#in-ceiling-expansion, expansion#successor-source,
 * expansion#superseded-state: create the policy-adjudicated successor and
 * supersede the predecessor. NO OWN TRANSACTION: the caller runs this inside
 * the transaction that also commits the `(client, creation_request_id)`
 * reservation, so activation, supersession and reservation commit as one.
 *
 * The successor's `approval_event_id` is allocated here, once per
 * reservation, and identifies this drawdown, never the ceiling consent. Its
 * Subject, authority source, client and ceiling members are the
 * predecessor's; the source ceiling is checked against the root as it stands
 * at this commit. Where the predecessor has a finite `derivation_limit`, the
 * successor carries its committed count forward under a limit never above
 * the predecessor's (Mission Derivation Limits), and a drawdown whose token
 * would exceed it is refused before anything is written.
 */
export function createCeilingDrawdownInCallerTx(kernel: MissionKernel, input: CeilingDrawdownInput): MissionRecord {
  const predecessor = kernel.get(input.predecessorId);
  if (!predecessor || predecessor.state !== "active" || kernel.observe(predecessor).state !== "active") {
    throw new DrawdownRefusal("predecessor_not_active", "predecessor is not active");
  }
  if (!predecessor.authority_ceiling || !predecessor.ceiling_hash || !predecessor.ceiling_consented_at) {
    throw new Error("a ceiling drawdown requires a predecessor that carries a consented ceiling");
  }
  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  // The successor's Authority Set is derived exactly as an ordinary
  // expansion's, carrying the predecessor's recorded capability bindings.
  const derived = kernel.deriveWithProvenance(input.intent, proposal);
  const authoritySet = kernel.resolveFreshCapabilities(
    inheritCapabilitySources(derived.entries, predecessor.authority_set),
  );
  if (!isSubsetSetIgnoringCapabilitySources(authoritySet, predecessor.authority_ceiling)) {
    throw new Error("ceiling drawdown successor is not within the consented ceiling");
  }
  // @spec expansion#reconciliation check 3, progressive#in-ceiling-expansion:
  // in this atomic step, the successor's complete Authority Set overlaps no
  // restriction of the predecessor that came after adjudication.
  if (restrictedSinceAdjudication(predecessor, authoritySet, input.restrictionsAtAdjudication)) {
    throw new DrawdownRefusal(
      "authority_restricted_since_approval",
      "the successor's authority came under a restriction of the predecessor after adjudication",
    );
  }
  // @spec resource-access#delegate-eligibility: the drawdown keeps its own
  // derivation's origins and every obligation of the consented ceiling entries
  // it falls within (an entry there without `allowed_delegates` defers to
  // policy).
  const provenance = inheritOrigins(
    authoritySet,
    derived.provenance,
    predecessor.authority_ceiling.map((entry) => ({ entry, origin: ceilingOrigin(entry) })),
  );
  // @spec child-delegation#fanout (#1304): the child-actor origins the same
  // way, kept apart (a consented ceiling `children` grant without
  // `allowed_child_actors` defers to the child-creation policy).
  const childActorProvenance = inheritChildActorOrigins(
    authoritySet,
    derived.childActorProvenance,
    predecessor.authority_ceiling.map((entry) => ({ entry, origin: childActorCeilingOrigin(entry) })),
  );
  // @spec expansion#successor-source: the predecessor's Subject and source,
  // checked against the committed root's declaration current at this commit.
  const root = kernel.committedSourceBinding(predecessor.id);
  const resolved = kernel.assertInheritedAuthoritySource(root, authoritySet);
  kernel.assertInheritedSubjectDiscipline(resolved, predecessor.subject);

  // @spec progressive#in-ceiling-expansion (Derivation limits): the inherited
  // finite limit is never raised; a stricter request or policy ceiling narrows it.
  const own = kernel.resolveDerivationLimit(input.intent.requested_derivation_limit);
  const inherited = predecessor.derivation_limit;
  const derivationLimit = inherited === null ? own : own === null ? inherited : Math.min(own, inherited);
  const derivationCount = predecessor.derivation_count;
  if (derivationLimit !== null && derivationCount + 1 > derivationLimit) {
    throw new DrawdownRefusal(
      "derivations_exhausted",
      `the carried derivation count ${derivationCount} leaves no derivation under limit ${derivationLimit}`,
    );
  }

  const createdAt = kernel.nowDate().toISOString();
  const expiresAt = kernel.resolveEffectiveExpiry({
    requested: input.intent.expires_at,
    createdAt,
    ceilings: { predecessor: predecessor.expires_at },
  });
  // @spec mission#standing-consent-bases, progressive#in-ceiling-expansion:
  // one value per reservation, never derived from creation_request_id, so a
  // key reused after its tombstone expires creates a new event.
  const approvalEventId = `cdd_${randomBytes(16).toString("base64url")}`;
  const approvalBasis: ApprovalBasis = {
    type: "ceiling_drawdown",
    // @spec progressive#ceiling-drawdown-basis: the Approver who consented the
    // ceiling, which after a human-approved successor need not be the
    // predecessor's own Approver (#1413).
    consent_principal: ceilingConsentPrincipal(predecessor),
    activation: { policy_id: input.policy.ref.id, policy_version: input.policy.ref.version },
    activation_actor: input.activationActor,
    // @spec progressive#ceiling-drawdown-basis (#1438): the decision mechanism,
    // the drawdown policy this adjudication evaluated.
    adjudication: { kind: "policy", policy: { id: input.policy.ref.id, version: input.policy.ref.version } },
    // @spec progressive#ceiling-drawdown-basis (#1468): the latest explicitly
    // human-consented ceiling, never a hash a policy narrowing recomputed.
    root_commitment: ceilingConsentHash(predecessor) as string,
    approved_at: predecessor.ceiling_consented_at,
  };
  // @spec progressive#drawdown-successor (#1468): the policy may narrow the
  // ceiling the successor carries, under a recomputed `ceiling_hash`; the
  // consent commitment, its instant and its Approver carry unchanged.
  const carried = narrowedCeiling(
    predecessor.authority_ceiling,
    authoritySet,
    drawdownRulesOf(input.policy.snapshot)?.retire_undrawn_actions ?? [],
  );
  const carriedHash =
    carried === predecessor.authority_ceiling
      ? predecessor.ceiling_hash
      : ceilingHash(predecessor.issuer, carried, predecessor.drawdown_policy);
  const id = newMissionId();
  const record: MissionRecord = {
    id,
    issuer: predecessor.issuer,
    state: "active",
    intent: input.intent,
    ...(proposal ? { proposed_authority: proposal } : {}),
    authority_set: authoritySet,
    eligibility_provenance: provenance,
    child_actor_provenance: childActorProvenance,
    intent_hash: intentHash(predecessor.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(predecessor.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    authority_hash: authorityHash(predecessor.issuer, authoritySet as never),
    subject: predecessor.subject,
    approval_basis: approvalBasis,
    authority_source: predecessor.authority_source,
    client_id: predecessor.client_id,
    policy_version: predecessor.policy_version,
    approval_event_id: approvalEventId,
    created_at: createdAt,
    expires_at: expiresAt,
    version: 1,
    derivation_limit: derivationLimit,
    derivation_count: derivationCount,
    grant_id: null,
    status_list_idx: null,
    predecessor: predecessor.id,
    // @spec progressive#drawdown-successor: carried unchanged under the same
    // `ceiling_hash`, or narrowed under a recomputed one.
    authority_ceiling: carried,
    ...(predecessor.drawdown_policy ? { drawdown_policy: predecessor.drawdown_policy } : {}),
    ceiling_hash: carriedHash,
    ceiling_consent_hash: ceilingConsentHash(predecessor) as string,
    ceiling_consented_at: predecessor.ceiling_consented_at,
    ceiling_consent_principal: ceilingConsentPrincipal(predecessor),
    // @spec progressive#audit-linkage: the chain's cumulative drawdown count.
    drawdown_count: (predecessor.drawdown_count ?? 0) + 1,
  };
  kernel.insertRecord(record, undefined, {
    source: { inherited: root },
    // @spec mission#standing-consent-bases: the drawdown policy snapshot this
    // adjudication verified, retained for the successor's audit horizon.
    activationPolicies: [{ ref: input.policy.ref, snapshot: input.policy.snapshot }],
  });
  if (!kernel.supersedeInCallerTx(id)) {
    throw new Error("ceiling drawdown predecessor supersession failed inside the creation transaction");
  }
  return record;
}
