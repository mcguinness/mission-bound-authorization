/**
 * @spec mission-template#template-consent: the human consent to a Mission
 * Template. An administrator proposes the template body; the Approver reads
 * its consent disclosure and approves or denies it. Approval creates the
 * template with the authenticated Approver as its approver of record; the
 * proposal never names one.
 *
 * Both mutable inputs are fixed when the template is proposed. The Dispatch
 * Policy is pinned: its digest is minted from the snapshot the issuer then
 * holds. The Template Ceiling is resolved: caller-supplied capability bindings
 * are discarded and the trusted ones resolved, as the template will commit
 * them. The disclosure and the decision both re-check each against the
 * issuer's current state, so a policy edited, or a trusted capability
 * definition changed, after the proposal is neither rendered nor consented
 * to; the proposal is then refused and proposed again.
 */
import { randomBytes } from "node:crypto";
import { type ActivationPolicyRef, type AuthorityEntry, canonicalize, type JsonValue } from "@mission/core";
import { verifiedActivationPolicy } from "../kernel/activation-policy.js";
import type { CapabilitySourceResolver } from "../kernel/capability-binding.js";
import { standingConsentLines, standingConsentMaximumOf } from "../kernel/standing-consent-limit.js";
import { type StandingPaymentTerms, standingPaymentTermsOf } from "../kernel/standing-payment.js";
import type { ActionApprovalPolicy } from "@mission/demo-data";
import { contentDigest } from "./approval-render-revision.js";
import { type DispatchPolicies, type TemplateProposalBody, templateCeiling } from "../kernel/template.js";

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
  /** @spec mission-template#prohibited-classes (#813): the standing payment's committed terms, when the template designates one. */
  standing_payment?: string[];
}

/**
 * The consent disclosure of a proposal, from the proposal and the issuer's
 * current state, or why it cannot be rendered: a Dispatch Policy snapshot that
 * no longer verifies against the proposal's pin, or a Template Ceiling whose
 * trusted capability bindings no longer resolve as they did.
 */
export function templateConsentDisclosure(
  proposal: TemplateProposal,
  dispatchPolicies: DispatchPolicies | undefined,
  opts: {
    issuer: string;
    asyncDelegation: boolean;
    capabilityResolver?: CapabilitySourceResolver;
    /** @spec mission-template#prohibited-classes (#813): the `standing-payment-dispatch` capability is on. */
    standingPayment?: boolean;
    /** @spec runtime#action-approval (#813): the deployment's action-approval predicate. */
    actionApprovalPolicy?: ActionApprovalPolicy;
  },
): { disclosure: TemplateConsentDisclosure } | { refusal: string } {
  const { body } = proposal;
  const held = verifiedActivationPolicy(opts.issuer, dispatchPolicies, proposal.dispatch_policy);
  const maximum = held && standingConsentMaximumOf(held);
  if (!maximum) {
    return {
      refusal: `The Dispatch Policy ${body.dispatch_policy.id} version ${body.dispatch_policy.version} is not the one this template was proposed under, so its per-instance derivation limit cannot be shown. This consent is refused; propose the template again.`,
    };
  }
  // @spec mission-template#prohibited-classes, metering#consent (#813): a
  // standing payment's terms are part of what the Approver consents to, so
  // the page renders every committed limit, destination and exception, and
  // the consumption product, or refuses a statement it cannot render.
  let standing: string[] = [];
  if (opts.standingPayment) {
    try {
      const terms = standingPaymentTermsOf(held as NonNullable<typeof held>);
      standing = terms ? standingPaymentLines(terms, body, opts.actionApprovalPolicy) : [];
    } catch (e) {
      return {
        refusal: `The Dispatch Policy ${body.dispatch_policy.id} states standing-payment terms that cannot be shown (${(e as Error).message}). This consent is refused.`,
      };
    }
  }
  // @spec capability-binding#conformance: the page renders the ceiling the
  // template would commit, so a trusted binding that now resolves differently
  // refuses rather than shows a ceiling the approval would not commit.
  let current: AuthorityEntry[] | undefined;
  try {
    current = templateCeiling(body.ceiling, opts.capabilityResolver);
  } catch {
    current = undefined;
  }
  if (!current || canonicalize(current as unknown as JsonValue) !== canonicalize(body.ceiling as unknown as JsonValue)) {
    return {
      refusal:
        "The trusted capability bindings of the Template Ceiling changed since this template was proposed, so the ceiling shown would not be the one committed. This consent is refused; propose the template again.",
    };
  }
  return {
    disclosure: {
      ceiling: body.ceiling,
      statements: [
        TEMPLATE_CEILING_STATEMENT,
        MACHINE_SPEED_STATEMENT,
        standing.length > 0 ? STANDING_PAYMENT_STATEMENT : PROHIBITED_CLASSES_STATEMENT,
      ],
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
      ...(standing.length > 0 ? { standing_payment: standing } : {}),
    },
  };
}

/**
 * @spec mission-template#prohibited-classes (#813): the standing payment's
 * rendering in place of the plain high-consequence statement.
 */
export const STANDING_PAYMENT_STATEMENT =
  "Policy dispatches one high-consequence operation unattended: the standing payment below, whose irreversible-action class alone is waived. " +
  "It never dispatches any other irreversible, external-commitment or privileged-administration action, external communication " +
  "(the exfiltration leg) or cross-domain authority. Each still requires a fresh human decision, and work outside these terms is refused.";

/**
 * @spec mission-template#prohibited-classes, metering#consent (#813, D830
 * rulings 1, 2, 4, 5 and 9): the committed standing-payment terms as plain
 * lines, the consumption product included: the budget is shared by every
 * instance and successor, so `max_active` concurrent instances can each draw
 * up to the per-instance maximum while the shared limit still binds them all.
 */
export function standingPaymentLines(
  terms: StandingPaymentTerms,
  body: TemplateProposalBody,
  actionApproval?: ActionApprovalPolicy,
): string[] {
  const destinations = Object.entries(terms.destinations)
    .map(([vendor, account]) => `${vendor} to account ${account}`)
    .join(", ");
  const exceptions = Object.entries(terms.approval_governance.recency.exceptions)
    .map(([cls, e]) => `${cls} (at most ${e?.max_age_s} seconds after this approval)`)
    .join(", ");
  return [
    `Standing payment: ${terms.operation} at ${terms.resource}, at most ${terms.max_amount.amount} ${terms.max_amount.currency} per payment, only to these committed destinations: ${destinations}. A changed payee account is not approved.`,
    `Budget ${terms.budget.owner}/${terms.budget.id}: at most ${terms.budget.limit} ${terms.budget.currency} in total across every dispatched instance and its successors, retries and replacement credentials included; each instance's own max_budget is at most ${terms.budget.per_instance_max} ${terms.budget.currency}.`,
    `Up to ${body.max_active} instances may each draw up to ${terms.budget.per_instance_max} ${terms.budget.currency} at once, at most ${body.rate_per_min} dispatches per minute, always within the shared ${terms.budget.limit} ${terms.budget.currency} budget.`,
    `Approval Governance exceptions committed by this consent: ${exceptions || "none"}; recency ceiling ${terms.approval_governance.recency.ceilings.default} seconds, clock-skew allowance ${terms.approval_governance.recency.clock_skew_s} seconds.`,
    actionApprovalLine(terms, body, actionApproval),
    "No instance creates a Child Mission, delegates, or is continued across an organization or a domain. Raising any limit needs a new template version and a fresh consent.",
  ];
}

/**
 * @spec mission-template#prohibited-classes, runtime#action-approval (#813):
 * whether each payment requires an action-bound approval, and from whom,
 * rendered as accurately as the runtime enforces it. A payment needs one
 * where the deployment's action-approval predicate names the designated
 * operation, or where the Template Ceiling entry that authorizes it carries
 * the `requires_action_approval` Common Constraint; an entry without it
 * authorizes a payment with no approval. So the requirement is universal
 * only under the predicate, or where every ceiling entry that can authorize
 * the payment carries the constraint. Where only some do, each entry is
 * rendered with its resource, constraints and requirement; where none does,
 * "none". The approver is the one the predicate declares.
 */
export function actionApprovalLine(
  terms: StandingPaymentTerms,
  body: TemplateProposalBody,
  actionApproval?: ActionApprovalPolicy,
): string {
  const from = actionApproval?.approver ?? "an Approver the deployment does not name";
  if (actionApproval?.actions.includes(terms.operation) === true) {
    return `Action-bound approval for each payment: required, from ${from}, bound to that payment's exact parameters (the deployment's action-approval predicate names ${terms.operation}).`;
  }
  const authorizing = body.ceiling
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => entry.actions.includes(terms.operation));
  const requiring = authorizing.filter(({ entry }) => entry.constraints?.requires_action_approval === true);
  if (authorizing.length > 0 && requiring.length === authorizing.length) {
    return `Action-bound approval for each payment: required, from ${from}, bound to that payment's exact parameters (every Template Ceiling entry that can authorize it sets requires_action_approval).`;
  }
  if (requiring.length === 0) {
    return "Action-bound approval for each payment: none. Each payment executes under this standing consent and a fresh runtime decision, with no per-payment human approval.";
  }
  const parts = authorizing.map(({ entry, index }) => {
    const cap = entry.constraints?.max_amount;
    const scope = [
      entry.resource,
      ...(entry.constraints?.vendors ? [`vendors ${entry.constraints.vendors.join(", ")}`] : []),
      ...(cap ? [`at most ${cap.amount} ${cap.currency} per payment`] : []),
    ].join("; ");
    return entry.constraints?.requires_action_approval === true
      ? `ceiling[${index}] (${scope}) requires one, from ${from}, bound to that payment's exact parameters`
      : `ceiling[${index}] (${scope}) requires none, so a payment it authorizes executes with no per-payment human approval`;
  });
  return `Action-bound approval for a payment depends on the Template Ceiling entry that authorizes it: ${parts.join("; and ")}.`;
}

/**
 * @spec mission#approval-context-changes, mission-template#template-consent
 * (#1446, D583, D718; #813): the context a template consent rendering showed,
 * committed so a decision approves exactly what was rendered.
 */
export interface TemplateConsentContext {
  proposal_id: string;
  body: TemplateProposalBody;
  dispatch_policy: ActivationPolicyRef;
  disclosure: TemplateConsentDisclosure;
}

/** The rendering's context and commitment, or undefined when the disclosure cannot be rendered. */
export function templateConsentRendering(
  proposal: TemplateProposal,
  rendered: { disclosure: TemplateConsentDisclosure } | { refusal: string },
): { context: TemplateConsentContext; commitment: string } | undefined {
  if ("refusal" in rendered) return undefined;
  const context: TemplateConsentContext = {
    proposal_id: proposal.id,
    body: proposal.body,
    dispatch_policy: proposal.dispatch_policy,
    disclosure: rendered.disclosure,
  };
  return { context, commitment: contentDigest(context) };
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderLines(lines: readonly string[], cls: string): string {
  return `<ul class="${cls}">${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`;
}

/**
 * The consent page. A pending proposal whose disclosure renders offers the
 * decision to the user agent holding the Approver's login for this proposal:
 * the form carries that login's CSRF secret, which the decision checks. Any
 * other user agent is offered the login. A refused disclosure offers no
 * decision, and states why.
 */
export function renderTemplateConsentPage(
  proposal: TemplateProposal,
  rendered: { disclosure: TemplateConsentDisclosure } | { refusal: string },
  opts: { loginHref?: string; csrf?: string; revision?: string },
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
  const decision = opts.csrf
    ? `<form method="post" action="/templates/proposals/${id}/decide">
<input type="hidden" name="csrf_token" value="${escapeHtml(opts.csrf)}">
${opts.revision ? `<input type="hidden" name="render_revision" value="${escapeHtml(opts.revision)}">\n` : ""}<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button></form>`
    : opts.loginHref
      ? `<p class="sign-in"><a href="${escapeHtml(opts.loginHref)}">Sign in to decide</a></p>`
      : `<p class="sign-in">Sign in on the approval surface to decide.</p>`;
  return `${head}<h2>What this consent admits</h2>${renderLines(disclosure.statements, "template-statements")}
<h2>Template Ceiling (the maximum authority of any dispatched Mission)</h2><pre class="template-ceiling">${escapeHtml(
    JSON.stringify(disclosure.ceiling, null, 2),
  )}</pre>
<h2>Dispatch bounds</h2>${renderLines(disclosure.bounds, "dispatch-bounds")}
<h2>Terms</h2>${renderLines(disclosure.terms, "template-terms")}
${disclosure.standing_payment ? `<h2>Standing payment</h2>${renderLines(disclosure.standing_payment, "standing-payment")}\n` : ""}${decision}`;
}
