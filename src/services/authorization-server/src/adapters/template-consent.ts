/**
 * @spec mission-template#template-consent — the human consent to a Mission
 * Template. An administrator proposes the template body; the Approver reads
 * its consent disclosure and approves or denies it. Approval creates the
 * template with the authenticated Approver as its approver of record; the
 * proposal never names one.
 *
 * The Dispatch Policy is pinned when the template is proposed: its digest is
 * minted from the snapshot the issuer then holds. The disclosure and the
 * decision both verify the held snapshot against that pin, so a policy edited
 * after the proposal is neither rendered nor consented to; the proposal is
 * then refused and proposed again.
 */
import { randomBytes } from "node:crypto";
import type { ActivationPolicyRef, AuthorityEntry } from "@mission/core";
import { verifiedActivationPolicy } from "../kernel/activation-policy.js";
import { standingConsentLines, standingConsentMaximumOf } from "../kernel/standing-consent-limit.js";
import type { DispatchPolicies, TemplateProposalBody } from "../kernel/template.js";

/** Prefix of a template proposal's identifier. */
export const TEMPLATE_CONSENT_PREFIX = "tcon_";

/** How long a proposal awaits its decision. */
export const TEMPLATE_CONSENT_TTL_MS = 3_600_000;

export interface TemplateProposal {
  id: string;
  body: TemplateProposalBody;
  /** The Dispatch Policy reference minted when the template was proposed. */
  dispatch_policy: ActivationPolicyRef;
  state: "pending" | "approved" | "denied";
  /** The template an approval created. */
  template_id?: string;
  expires: number;
}

/** Proposals awaiting, or settled by, a human decision. */
export class TemplateConsentProposals {
  private readonly proposals = new Map<string, TemplateProposal>();
  constructor(private readonly now: () => number = () => Date.now()) {}

  propose(body: TemplateProposalBody, dispatch_policy: ActivationPolicyRef): TemplateProposal {
    const id = `${TEMPLATE_CONSENT_PREFIX}${randomBytes(18).toString("base64url")}`;
    const proposal: TemplateProposal = {
      id,
      body,
      dispatch_policy,
      state: "pending",
      expires: this.now() + TEMPLATE_CONSENT_TTL_MS,
    };
    this.proposals.set(id, proposal);
    return proposal;
  }

  /** The proposal, or undefined once it is unknown or past its decision window. */
  get(id: string): TemplateProposal | undefined {
    const proposal = this.proposals.get(id);
    if (proposal && proposal.expires <= this.now()) {
      this.proposals.delete(id);
      return undefined;
    }
    return proposal;
  }

  settle(id: string, outcome: { state: "approved"; template_id: string } | { state: "denied" }): void {
    const proposal = this.proposals.get(id);
    if (proposal) Object.assign(proposal, outcome);
  }
}

/** The Template Ceiling statement (@spec mission-template#template-consent). */
export const TEMPLATE_CEILING_STATEMENT =
  "The Template Ceiling is the maximum authority any Mission dispatched from this template may reach.";

/** Dispatch issues without a human at each instance (@spec mission-template#template-consent). */
export const MACHINE_SPEED_STATEMENT =
  "Missions dispatched from this template issue at machine speed, by policy, with no per-instance human approval.";

/** @spec mission-template#prohibited-classes, as the consent renders them. */
export const PROHIBITED_CLASSES_STATEMENT =
  "Policy never dispatches authority in the high-consequence classes, even within the ceiling: " +
  "irreversible, external-commitment or privileged-administration actions; external communication " +
  "(the exfiltration leg); and cross-domain authority. Each still requires a fresh human decision.";

export interface TemplateConsentDisclosure {
  ceiling: readonly AuthorityEntry[];
  /** The ceiling, machine-speed and high-consequence statements. */
  statements: string[];
  /**
   * `max_active` and the dispatch rate, with the per-instance derivation-limit
   * rule, its maximum and its scope beside them
   * (@spec mission-template#template-consent, derivation-limits#approval-rendering).
   */
  bounds: string[];
  /** The remaining consented terms. */
  terms: string[];
}

/**
 * The consent disclosure of a proposal, from the proposal and the Dispatch
 * Policy snapshot this issuer holds, or why it cannot be rendered: a snapshot
 * that no longer verifies against the proposal's pin.
 */
export function templateConsentDisclosure(
  proposal: TemplateProposal,
  dispatchPolicies: DispatchPolicies | undefined,
  opts: { issuer: string; asyncDelegation: boolean },
): { disclosure: TemplateConsentDisclosure } | { refusal: string } {
  const { body } = proposal;
  const held = verifiedActivationPolicy(opts.issuer, dispatchPolicies, proposal.dispatch_policy);
  const maximum = held && standingConsentMaximumOf(held);
  if (!maximum) {
    return {
      refusal: `The Dispatch Policy ${body.dispatch_policy.id} version ${body.dispatch_policy.version} is not the one this template was proposed under, so its per-instance derivation limit cannot be shown. This consent is refused; propose the template again.`,
    };
  }
  return {
    disclosure: {
      ceiling: body.ceiling,
      statements: [TEMPLATE_CEILING_STATEMENT, MACHINE_SPEED_STATEMENT, PROHIBITED_CLASSES_STATEMENT],
      bounds: [
        `At most ${body.max_active} dispatched instances are active at once.`,
        `At most ${body.rate_per_min} dispatches per minute.`,
        ...standingConsentLines(maximum, "dispatched instance", { asyncDelegation: opts.asyncDelegation }),
        `Each dispatched instance establishes and counts its own limit, so this consent admits up to ${body.max_active} such limits at once, and more over time.`,
      ],
      terms: [
        `Each dispatched instance lives at most ${body.per_instance_lifetime_s} seconds.`,
        `Dispatch stops ${body.review_cadence_s} seconds after this approval until a human reviews the template again.`,
        typeof body.expires_at === "string" ? `The template expires at ${body.expires_at}.` : "The template sets no expiry.",
        `Dispatchers: ${body.dispatchers.join(", ")}.`,
        `Recipient Subjects: ${body.recipients.subjects.map((s) => `${s.sub} (${s.iss})`).join(", ")}.`,
        `Recipient Agents: ${body.recipients.agents.join(", ")}.`,
        `Dispatch Policy: ${body.dispatch_policy.id} version ${body.dispatch_policy.version}.`,
        `Template version: ${body.template_version}.`,
      ],
    },
  };
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderLines(lines: readonly string[], cls: string): string {
  return `<ul class="${cls}">${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`;
}

/**
 * The consent page. A pending proposal whose disclosure renders offers the
 * decision; a refused disclosure offers none, and states why.
 */
export function renderTemplateConsentPage(
  proposal: TemplateProposal,
  rendered: { disclosure: TemplateConsentDisclosure } | { refusal: string },
  opts: { loginHref?: string },
): string {
  const id = encodeURIComponent(proposal.id);
  const head = `<!doctype html><title>Template consent</title>
<h1>Consent to a Mission Template?</h1>
`;
  if (proposal.state !== "pending") {
    return `${head}<p class="proposal-state">${
      proposal.state === "approved"
        ? `This proposal was approved as template <code>${escapeHtml(proposal.template_id ?? "")}</code>.`
        : "This proposal was denied."
    }</p>`;
  }
  if ("refusal" in rendered) {
    return `${head}<p class="consent-refused">${escapeHtml(rendered.refusal)}</p>`;
  }
  const { disclosure } = rendered;
  const login = opts.loginHref ? `<p><a href="${escapeHtml(opts.loginHref)}">Sign in to decide</a></p>\n` : "";
  return `${head}<h2>What this consent admits</h2>${renderLines(disclosure.statements, "template-statements")}
<h2>Template Ceiling (the maximum authority of any dispatched Mission)</h2><pre class="template-ceiling">${escapeHtml(
    JSON.stringify(disclosure.ceiling, null, 2),
  )}</pre>
<h2>Dispatch bounds</h2>${renderLines(disclosure.bounds, "dispatch-bounds")}
<h2>Terms</h2>${renderLines(disclosure.terms, "template-terms")}
${login}<form method="post" action="/templates/proposals/${id}/decide" enctype="application/json">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button></form>`;
}
