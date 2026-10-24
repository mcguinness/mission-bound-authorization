/**
 * @spec expansion#completion-modes, progressive#fresh-approval,
 * progressive#ceiling-reconsent, progressive#ceiling-review,
 * discovery#adjudication, discovery#lying-resource,
 * discovery#injection-discovery (#1558): the approval surface for an
 * expansion deferral.
 *
 * A pending deferral is rendered only to an authenticated Approver: the
 * successor's authority and the request it came from, the client and Subject,
 * the expiry the approval commits, and the consent disclosure the store holds
 * (the chain's restrictions, the re-consent offer and the review record, the
 * Carryover Manifest for the predecessor's live Child Missions, and for a
 * discovery encounter the Encountered Resource, the declaration as the
 * resource's claim, the taint status, the floors and the `encounter_id`). The
 * rendering commits that context under a render revision bound to its
 * principal, as the Mission approval page does (#1446), and the decision is
 * compared with it: a deferral whose disclosure changed since it was rendered
 * approves nothing.
 */
import { authorityHash, intentHash, type JsonValue, proposalHash } from "@mission/core";
import type { CarryoverManifest } from "../kernel/carryover.js";
import type { DeferralReview, ExpansionDisclosure } from "../kernel/deferred.js";
import type { MissionKernel } from "../kernel/kernel.js";
import type { CeilingConsent, EncounterDisclosure } from "../kernel/progressive.js";
import { contentDigest, decisionExpiry } from "./approval-render-revision.js";

/** The committed parts of a deferral's approval context; each is compared as one value. */
export interface DeferralContext {
  predecessor: string;
  client_id: string;
  subject: { iss: string; sub: string };
  intent_hash: string;
  proposal_hash: string | null;
  successor_hash: string;
  expires_at: string;
  fallback: string | null;
  encounter: string | null;
  restrictions: string;
  /** The offer itself, so a re-consent consents exactly the one rendered. */
  reconsent_offer: CeilingConsent | null;
  review: string | null;
  /** The Carryover Manifest the approval commits, fixed while the deferral is pending. */
  carryover: string | null;
}

/** The URL path of a deferral's approval page. */
export const deferralPagePath = (code: string): string => `/expansions/deferrals/${encodeURIComponent(code)}`;

/**
 * @spec expansion#successor-expiry: the expiry an approval rendered now
 * commits, resolved as the successor's creation resolves it (the requested
 * expiry, the deployment's lifetime bound and the predecessor's own
 * `expires_at`). The approval commits it as `approved_until`, so the
 * successor never outlives what the Approver saw.
 */
export function shownExpiry(kernel: MissionKernel, review: DeferralReview): string {
  return kernel.resolveEffectiveExpiry({
    requested: review.intent.expires_at,
    createdAt: kernel.nowDate().toISOString(),
    ceilings: { predecessor: review.predecessor.expires_at },
  });
}

/**
 * The expiry a decision on a rendering commits: the rendered one while the
 * current inputs still admit it, else the one established now, which then
 * differs ({@link decisionExpiry}).
 */
export function deciding(kernel: MissionKernel, review: DeferralReview, rendered: string): string {
  return decisionExpiry(kernel, review.intent.expires_at, rendered, { predecessor: review.predecessor.expires_at });
}

/** The context a deferral's rendering shows, and its commitment. */
export function deferralContext(review: DeferralReview, expiresAt: string): { context: DeferralContext; commitment: string } {
  const issuer = review.predecessor.issuer;
  const { disclosure } = review;
  const review_ = disclosure.ceiling?.review;
  const context: DeferralContext = {
    predecessor: review.predecessor.id,
    client_id: review.clientId,
    subject: review.predecessor.subject,
    intent_hash: intentHash(issuer, review.intent as unknown as JsonValue),
    proposal_hash: review.proposal ? proposalHash(issuer, review.proposal as unknown as JsonValue[]) : null,
    successor_hash: authorityHash(issuer, review.successor as unknown as JsonValue[]),
    expires_at: expiresAt,
    fallback: disclosure.drawdown_fallback ?? null,
    encounter: disclosure.encounter_disclosure ? contentDigest(disclosure.encounter_disclosure) : null,
    restrictions: contentDigest(disclosure.restrictions),
    reconsent_offer: review.offer ?? null,
    // The hourly rate moves with the clock on every rendering, so the record
    // is committed by its count and entries, never by the rate.
    review: review_
      ? contentDigest({
          since: review_.since,
          drawdowns: review_.policy_adjudicated_drawdowns.count,
          escalations: review_.escalations,
          out_of_ceiling_refusals: review_.out_of_ceiling_refusals,
          discharged: review_.discharged,
        })
      : null,
    carryover: review.carryover ? contentDigest(review.carryover) : null,
  };
  return { context, commitment: contentDigest(context) };
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const json = (value: unknown): string => escapeHtml(JSON.stringify(value, null, 2));

/** The taint statement, as the Approver reads it. */
const TAINT_TEXT: Record<EncounterDisclosure["taint"], string> = {
  untrusted_content_ingested: "The session had ingested untrusted content.",
  no_untrusted_content_reported: "The harness reported that the session had ingested no untrusted content.",
  taint_state_unknown: "The session's taint state is unknown, so it is treated as tainted.",
};

function encounterSection(disclosure: ExpansionDisclosure): string {
  const shown = disclosure.encounter_disclosure;
  if (!shown) return "";
  const pinFailure = disclosure.encounter?.pin_failure;
  const declaration = shown.declaration
    ? `<h3>Declaration (the resource's claim, not verified fact)</h3>
<p class="declaration-claim">Claimed by the resource and not verified: digest <code>${escapeHtml(shown.declaration.digest)}</code>${
        shown.declaration.operations?.length
          ? `; claimed operations: ${shown.declaration.operations.map((o) => `<code>${escapeHtml(o)}</code>`).join(", ")}`
          : ""
      }</p>`
    : `<p class="declaration-claim">The resource published no declaration.</p>`;
  return `<section class="encounter"${shown.encounter_id ? ` data-encounter-id="${escapeHtml(shown.encounter_id)}"` : ""}>
<h2>Encountered resource</h2>
<pre class="encountered-resource">${json(shown.resource ?? null)}</pre>
<p class="encounter-pinning">${
    shown.pinned
      ? "Its identity is pinned from the Mission Issuer's own connection."
      : `Its identity is not pinned${pinFailure ? ` (<code>${escapeHtml(String(pinFailure))}</code>)` : ""}.`
  }</p>
${declaration}
<p class="taint-status" data-taint="${escapeHtml(shown.taint)}">${escapeHtml(TAINT_TEXT[shown.taint])}</p>
${shown.floors?.length ? `<p class="encounter-floors">Floors this encounter meets: ${shown.floors.map((f) => `<code>${escapeHtml(f)}</code>`).join(", ")}</p>` : ""}
${shown.encounter_id ? `<p class="encounter-id">Encounter <code>${escapeHtml(shown.encounter_id)}</code></p>` : ""}
</section>`;
}

function restrictionsSection(disclosure: ExpansionDisclosure): string {
  const { contained, discharged } = disclosure.restrictions;
  const items = [
    ...contained.map(
      ({ event_class, mission, ...capability }) =>
        `<li class="restriction-contained" data-event-class="${escapeHtml(event_class)}">Contained by <code>${escapeHtml(event_class)}</code> on Mission <code>${escapeHtml(mission)}</code>: <pre>${json(capability)}</pre></li>`,
    ),
    ...discharged.map(
      (d) =>
        `<li class="restriction-discharged">Discharged on Mission <code>${escapeHtml(d.mission)}</code> at <time datetime="${escapeHtml(d.discharged_at)}">${escapeHtml(d.discharged_at)}</time>: <pre class="discharged-entry">${json(d.entry)}</pre> by the condition <pre class="discharged-condition">${json(d.condition)}</pre></li>`,
    ),
  ];
  return `<h2>The chain's outstanding restrictions (this approval clears none)</h2>
${items.length ? `<ul class="restrictions">\n${items.join("\n")}\n</ul>` : `<p class="restrictions">None.</p>`}`;
}

/**
 * @spec child-delegation#carryover-manifest (#1558 review): the Carryover
 * Manifest the approval commits. Every live Child Mission of the predecessor
 * is rendered: carried, with the replacement's facts, or terminated when the
 * successor supersedes, with the reason; and the exclusion policy that decides
 * what a change before completion does.
 */
function carryoverSection(manifest: CarryoverManifest | undefined): string {
  if (!manifest) return "";
  const policy = manifest.exclusion_policy;
  const policyText =
    policy.mode === "all_or_nothing"
      ? "Any change to these Child Missions before completion refuses the whole expansion, which then needs a fresh approval."
      : `A change of these classes before completion excludes the affected Child Mission instead: ${policy.change_classes.map((c) => `<code>${escapeHtml(c)}</code>`).join(", ")}; a dependent descendant is excluded with it, and a Child Mission not rendered here is terminated.`;
  const entries = manifest.entries.map((entry) =>
    entry.outcome === "carry"
      ? `<li class="carryover-entry" data-child-id="${escapeHtml(entry.child_id)}" data-outcome="carry">Child Mission <code>${escapeHtml(entry.child_id)}</code> (actor <code>${escapeHtml(entry.child_actor.sub)}</code>) is carried to a replacement under the successor: <pre class="carryover-replacement">${json(entry.replacement ?? null)}</pre></li>`
      : `<li class="carryover-entry" data-child-id="${escapeHtml(entry.child_id)}" data-outcome="cascade">Child Mission <code>${escapeHtml(entry.child_id)}</code> (actor <code>${escapeHtml(entry.child_actor.sub)}</code>) is terminated when the successor supersedes the Mission: ${escapeHtml(entry.reason ?? "")}</li>`,
  );
  return `<section class="carryover">
<h2>Child Missions of the Mission being widened</h2>
<p class="carryover-exclusion-policy" data-mode="${escapeHtml(policy.mode)}">${policyText}</p>
${entries.length ? `<ul>\n${entries.join("\n")}\n</ul>` : `<p>None.</p>`}
</section>`;
}

function ceilingSection(disclosure: ExpansionDisclosure): string {
  const ceiling = disclosure.ceiling;
  if (!ceiling) return "";
  const offer = ceiling.reconsent_offer
    ? `<section class="reconsent-offer">
<h2>Re-consent the authority ceiling (optional)</h2>
<pre class="reconsent-ceiling">${json(ceiling.reconsent_offer.authority_ceiling)}</pre>
${ceiling.reconsent_offer.drawdown_policy ? `<p class="reconsent-policy">Drawdown policy <code>${escapeHtml(ceiling.reconsent_offer.drawdown_policy.id)}</code> version <code>${escapeHtml(ceiling.reconsent_offer.drawdown_policy.version)}</code></p>` : ""}
<p class="reconsent-adjudication">${escapeHtml(ceiling.reconsent_offer.adjudication)}</p>
</section>`
    : "";
  const r = ceiling.review;
  const list = <T,>(cls: string, label: string, values: T[], show: (v: T) => string) =>
    `<li class="${cls}">${label}: ${values.length ? values.map(show).join("; ") : "none"}</li>`;
  return `${offer}
<section class="review-record">
<h2>The chain's record since the latest ceiling consent (<time datetime="${escapeHtml(r.since)}">${escapeHtml(r.since)}</time>)</h2>
<ul>
<li class="review-drawdowns">Policy-adjudicated drawdowns: ${r.policy_adjudicated_drawdowns.count} (${r.policy_adjudicated_drawdowns.per_hour} per hour)</li>
${list("review-escalations", "Escalated to human approval", r.escalations, (e) => `<code>${escapeHtml(e.reason)}</code> at <time datetime="${escapeHtml(e.at)}">${escapeHtml(e.at)}</time>`)}
${list("review-refusals", "Refused as out of ceiling", r.out_of_ceiling_refusals, (e) => `<time datetime="${escapeHtml(e.at)}">${escapeHtml(e.at)}</time>`)}
${list("review-discharged", "Entries discharged", r.discharged, (d) => `<code>${escapeHtml(d.entry.resource)}</code> (${d.entry.actions.map((a) => `<code>${escapeHtml(a)}</code>`).join(", ")})`)}
</ul>
</section>`;
}

/** The approval page for a pending deferral, rendered to an eligible, authenticated Approver. */
export function renderDeferralPage(
  review: DeferralReview,
  context: DeferralContext,
  view: { clientName?: string; revision?: string; csrf?: string; changed?: boolean },
): string {
  const { disclosure } = review;
  const why = disclosure.drawdown_fallback
    ? `<p class="deferral-why">The Mission's policy did not adjudicate this widening; it came to you for a fresh approval (<code>${escapeHtml(disclosure.drawdown_fallback)}</code>).</p>`
    : `<p class="deferral-why">This request widens the Mission's authority, so it needs a fresh approval.</p>`;
  const reconsent = context.reconsent_offer
    ? `<label class="reconsent-choice"><input type="checkbox" name="reconsent" value="true"> Also re-consent the ceiling and policy above</label>\n`
    : "";
  return `<!doctype html><title>Expansion approval</title>
<h1>Approve the expansion of a Mission?</h1>
${why}
<h2>Mission being widened</h2><p class="deferral-predecessor"><code>${escapeHtml(review.predecessor.id)}</code></p>
<h2>Client (requests and receives the authority)</h2><p class="deferral-client"><code>${escapeHtml(review.clientId)}</code>${view.clientName ? ` ${escapeHtml(view.clientName)}` : ""}</p>
<h2>Subject (the authority is granted for)</h2><p class="deferral-subject"><code>${escapeHtml(review.predecessor.subject.sub)}</code></p>
<h2>Intent (task context, untrusted)</h2><pre class="deferral-intent">${json(review.intent)}</pre>
${review.proposal ? `<h2>Proposed authority (submitted, untrusted)</h2><pre class="deferral-proposal">${json(review.proposal)}</pre>\n` : ""}<h2>Successor authority (what approval grants)</h2><pre class="successor-authority">${json(review.successor)}</pre>
<h2>Expiry (when the approved authority ends)</h2><p><time class="successor-expires-at" datetime="${escapeHtml(context.expires_at)}">${escapeHtml(context.expires_at)}</time></p>
${encounterSection(disclosure)}
${restrictionsSection(disclosure)}
${carryoverSection(review.carryover)}
${ceilingSection(disclosure)}
${view.changed ? `<p class="deferral-changed"><strong>The request changed since you last reviewed it. Review it again before deciding.</strong></p>\n` : ""}<form method="post" action="${deferralPagePath(review.deferralCode)}/decide">
${view.revision ? `<input type="hidden" name="render_revision" value="${escapeHtml(view.revision)}">\n` : ""}${view.csrf ? `<input type="hidden" name="csrf_token" value="${escapeHtml(view.csrf)}">\n` : ""}${reconsent}<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button></form>`;
}

/** A page for a deferral this principal cannot review: not pending, or not theirs to decide. */
export function deferralNoticePage(message: string, loginHref?: string): string {
  return `<!doctype html><title>Expansion approval</title>
<p class="deferral-notice">${escapeHtml(message)}</p>${loginHref ? `\n<p><a href="${escapeHtml(loginHref)}">Sign in as the Approver</a></p>` : ""}`;
}
