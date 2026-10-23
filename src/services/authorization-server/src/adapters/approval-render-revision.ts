/**
 * @spec mission#approval-context-changes, mission#approval-event (#1446, D583):
 * the approval context a rendering showed, and the binding of a decision to it.
 *
 * Each rendering of the approval page for an authenticated principal (a
 * browser session, or a trusted headless approval service with the Subject it
 * named) gets its own protected render revision, retained server-side with a
 * commitment to the complete context the page showed. The decision names the
 * revision it was shown; a missing, unknown, expired, superseded or foreign
 * revision never approves. The decision recomputes the context and compares
 * commitments: the anchors (`intent_hash`, `proposal_hash` where a proposal was
 * submitted, `authority_hash` over the derived set), the established authority
 * source (its root, catalog revision and provenance), the effective
 * `expires_at` the rendering showed, and the policy inputs that establish
 * them: the derivation policy's content (which carries
 * `max_mission_lifetime_s`), the scope projection, and the activation policies
 * held. A policy edit that leaves every anchor equal still changes the
 * commitment.
 */
import { createHash, randomBytes } from "node:crypto";
import { authorityHash, canonicalize, intentHash, type JsonValue, proposalHash } from "@mission/core";
import type Provider from "oidc-provider";
import type { MissionKernel } from "../kernel/kernel.js";
import type { AuthorityEntry, MissionIntent } from "../kernel/types.js";

/** The committed parts of an approval context; each is compared as one value. */
export interface ApprovalContext {
  intent_hash: string;
  proposal_hash: string | null;
  authority_hash: string;
  source: { provenance: unknown; root_id?: string; catalog_revision?: string };
  expires_at: string;
  derivation_policy: string;
  scope_projection: string | null;
  activation_policies: string | null;
}

const digest = (value: unknown): string =>
  `sha-256:${createHash("sha256").update(canonicalize(value as JsonValue)).digest("base64url")}`;

/**
 * The approval context for an Intent, its proposal and the Authority Set
 * derived from them, as a rendering shows it and a decision re-establishes it.
 * With a Subject, the authority source is that Subject's full resolution;
 * without one, only the provenance a rendering can show, which no decision's
 * context matches. Throws what source resolution throws (an IntentError).
 */
export function approvalContext(input: {
  kernel: MissionKernel;
  issuer: string;
  intent: MissionIntent;
  proposal: readonly AuthorityEntry[] | undefined;
  authority: readonly AuthorityEntry[];
  clientId: string;
  subject: string | undefined;
  scopeProjection: unknown;
  /** The effective `expires_at`: a rendering's own, or a decision's ({@link decisionExpiry}). */
  expiresAt: string;
}): { context: ApprovalContext; commitment: string } {
  const { kernel, issuer } = input;
  let source: ApprovalContext["source"];
  if (input.subject === undefined) {
    source = { provenance: kernel.renderAuthoritySource({ clientId: input.clientId }) };
  } else {
    const resolved = kernel.resolveAuthoritySource({ clientId: input.clientId, subject: { iss: issuer, sub: input.subject } });
    source = { provenance: resolved.provenance, root_id: resolved.rootId, catalog_revision: resolved.catalogRevision };
  }
  const registry = kernel.activationPolicies();
  const context: ApprovalContext = {
    intent_hash: intentHash(issuer, input.intent as unknown as JsonValue),
    proposal_hash: input.proposal?.length ? proposalHash(issuer, input.proposal as unknown as JsonValue[]) : null,
    authority_hash: authorityHash(issuer, input.authority as unknown as JsonValue[]),
    source,
    expires_at: input.expiresAt,
    derivation_policy: kernel.derivationPolicyDigest(),
    scope_projection: input.scopeProjection === undefined ? null : digest(input.scopeProjection),
    activation_policies: registry === undefined ? null : digest(registry),
  };
  return { context, commitment: digest(context) };
}

/**
 * The effective `expires_at` a decision commits. It is the one its rendering
 * showed while the current inputs still admit it (later than now, and no later
 * than the expiry they establish now), so a lifetime measured from the
 * decision never moves it later than the Approver saw. Otherwise it is the
 * expiry established now, which differs from the rendered one and so asks for
 * a fresh decision. Where no expiry later than now remains, it is the rendered
 * one: the commit refuses that approval rather than asking for it again.
 */
export function decisionExpiry(kernel: MissionKernel, requested: string, rendered: string): string {
  const now = kernel.nowDate();
  const established = kernel.resolveEffectiveExpiry({ requested, createdAt: now.toISOString() });
  if (Date.parse(established) <= now.getTime()) return rendered;
  return Date.parse(rendered) > now.getTime() && Date.parse(rendered) <= Date.parse(established) ? rendered : established;
}

/**
 * The anchor over a prepared candidate's complete entries, capability bindings
 * and assembled contracts included, so the candidate a commit records can be
 * checked against the one prepared before the last asynchronous step.
 */
export function candidateHash(issuer: string, entries: readonly AuthorityEntry[]): string {
  return authorityHash(issuer, entries as unknown as JsonValue[]);
}

/** The response header that carries a rendering's revision to a headless approval service. */
export const RENDER_REVISION_HEADER = "x-approval-render-revision";

/** The parts of two contexts that differ, for the refusal's explanation and for tests. */
export function changedParts(rendered: ApprovalContext, current: ApprovalContext): (keyof ApprovalContext)[] {
  return (Object.keys(current) as (keyof ApprovalContext)[]).filter((k) => digest(rendered[k] ?? null) !== digest(current[k] ?? null));
}

/** A rendering's revision, as retained for the principal it was rendered to. */
export interface RenderRevision {
  revision: string;
  clientId: string;
  context: ApprovalContext;
  commitment: string;
  expiresAt: number;
}

/**
 * The latest revision rendered to each principal on each interaction, per
 * provider, for the life of the interaction. A newer rendering to the same
 * principal supersedes the older one, whose form can no longer approve.
 */
const revisions = new WeakMap<Provider, Map<string, Map<string, RenderRevision>>>();

function interactionRevisions(provider: Provider, uid: string, create: boolean): Map<string, RenderRevision> | undefined {
  let byUid = revisions.get(provider);
  if (!byUid) {
    if (!create) return undefined;
    byUid = new Map();
    revisions.set(provider, byUid);
  }
  const now = Date.now();
  for (const [key, held] of byUid) {
    for (const [principal, rec] of held) if (rec.expiresAt <= now) held.delete(principal);
    if (!held.size) byUid.delete(key);
  }
  let held = byUid.get(uid);
  if (!held && create) {
    held = new Map();
    byUid.set(uid, held);
  }
  return held;
}

/** Retain a new revision for this principal's rendering, superseding any earlier one; returns it. */
export function retainRenderRevision(
  provider: Provider,
  uid: string,
  principalKey: string,
  rendered: { clientId: string; context: ApprovalContext; commitment: string },
  exp: number | undefined,
): string {
  const revision = randomBytes(18).toString("base64url");
  const held = interactionRevisions(provider, uid, true) as Map<string, RenderRevision>;
  held.set(principalKey, { revision, ...rendered, expiresAt: (exp ?? Math.floor(Date.now() / 1000) + 600) * 1000 });
  return revision;
}

/** The current revision rendered to this principal on this interaction, if any. */
export function currentRenderRevision(provider: Provider, uid: string, principalKey: string): RenderRevision | undefined {
  return interactionRevisions(provider, uid, false)?.get(principalKey);
}

/**
 * Retire a revision whose context changed, so its form can never approve. Only
 * that revision: a newer rendering to the same principal stays current.
 */
export function retireRenderRevision(provider: Provider, uid: string, principalKey: string, revision: string): void {
  const held = interactionRevisions(provider, uid, false);
  if (held?.get(principalKey)?.revision === revision) held.delete(principalKey);
}

/**
 * @spec mission#approval-event (step 7), mission#approval-context-changes
 * (#1446, D583): the commits on one approval event, per provider, run one at a
 * time, each with its cleanup. Every decision on an interaction writes the same
 * interaction-derived grant, so a decision resuming after asynchronous work
 * must never write over, or destroy, the grant another decision committed; it
 * reads the event afresh once its turn comes, and recovers a commit made
 * meanwhile. A serialization within this process: the reference AS runs as one
 * process (D663).
 */
const commits = new WeakMap<Provider, Map<string, Promise<void>>>();

export async function serializeApprovalEvent<T>(provider: Provider, approvalEventId: string, commit: () => Promise<T>): Promise<T> {
  let queues = commits.get(provider);
  if (!queues) {
    queues = new Map();
    commits.set(provider, queues);
  }
  const run = (queues.get(approvalEventId) ?? Promise.resolve()).then(commit);
  const settled = run.then(
    () => undefined,
    () => undefined,
  );
  queues.set(approvalEventId, settled);
  try {
    return await run;
  } finally {
    if (queues.get(approvalEventId) === settled) queues.delete(approvalEventId);
  }
}

/** The principal key of a trusted headless approval service: its credential, the Approver it acts as, and the Subject it names. */
export function serviceRenderKey(token: string, approver: string, subject: string): string {
  return `service:${createHash("sha256").update(token).digest("base64url")}:${approver}:${subject}`;
}
