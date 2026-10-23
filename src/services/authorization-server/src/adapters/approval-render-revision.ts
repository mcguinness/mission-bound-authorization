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
 * source (its root, catalog revision and provenance), and the policy inputs
 * that establish them: the derivation policy's content (which carries
 * `max_mission_lifetime_s`, so the effective `expires_at` inputs), the scope
 * projection, and the activation policies held. A policy edit that leaves
 * every anchor equal still changes the commitment.
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
    derivation_policy: kernel.derivationPolicyDigest(),
    scope_projection: input.scopeProjection === undefined ? null : digest(input.scopeProjection),
    activation_policies: registry === undefined ? null : digest(registry),
  };
  return { context, commitment: digest(context) };
}

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

/** Retire a revision whose context changed, so its form can never approve. */
export function retireRenderRevision(provider: Provider, uid: string, principalKey: string): void {
  interactionRevisions(provider, uid, false)?.delete(principalKey);
}

/** The principal key of a trusted headless approval service deciding for a Subject. */
export function serviceRenderKey(token: string, subject: string): string {
  return `service:${createHash("sha256").update(token).digest("base64url")}:${subject}`;
}
