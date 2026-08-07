/**
 * Display-only label map: friendly names for the machine identifiers the demo
 * surfaces to humans (MCP tool names, mission-authority action ids, and
 * denial/refusal/status reason codes).
 *
 * This is presentation only. The underlying protocol/wire values NEVER change;
 * callers keep the technical id and add the human gloss BESIDE it. This module
 * is the single source of truth: the terminal exhibit imports {@link label}
 * directly, and the dashboard fetches these maps once via `GET /labels`.
 */

/** MCP tool names -> human names. */
export const TOOL_LABELS: Record<string, string> = {
  get_invoice: "Read invoice",
  execute_wire_transfer: "Execute wire transfer",
  send_remittance_email: "Send remittance email",
  schedule_payment: "Schedule payment",
  lookup_vendor: "Look up vendor",
};

/** Mission-authority action ids -> human names. */
export const ACTION_LABELS: Record<string, string> = {
  "payments:invoice.read": "Read invoices",
  "payments:invoice.list": "List invoices",
  "payments:payment.execute": "Execute payments",
  "payments:remittance.send": "Send remittances",
  "payments:payment.schedule": "Schedule payments",
  "payments:vendor.delete": "Delete vendors",
  "ledger:vendor.read": "Read ledger vendors",
  "ledger:journal.write": "Write ledger journal",
};

/**
 * Denial/refusal/status reason codes -> human names. Codes may arrive
 * colon-suffixed with a state (e.g. `mission_not_active:suspended`); {@link
 * label} strips the suffix before lookup and appends the state in parens.
 *
 * `mission_inactive` is the live PDP's denial code (see services/pdp
 * DenialReason); it maps to the same string as the family-vocabulary
 * `mission_not_active` so the gloss fires on the suspend/supersede path.
 */
export const REASON_LABELS: Record<string, string> = {
  constraint_exceeded: "Exceeds a mission constraint (e.g. amount cap or vendor)",
  out_of_authority: "Outside the mission's granted authority",
  authority_contained: "Capability contained after a protected event (approved, then narrowed)",
  egress_undeclared: "Outbound channel not declared in the harness scope statement",
  egress_destination_unlisted: "Destination not on the declared egress allowlist",
  unknown_mission: "Mission not recognized by the enforcement point",
  parameter_mismatch: "Parameters changed after the decision (time-of-check vs time-of-use)",
  view_inconsistent: "Token's mission view doesn't match the authorization server",
  invalid_credential: "Missing or invalid mission credential",
  mission_not_active: "Mission is not active (suspended, revoked, or expired)",
  mission_inactive: "Mission is not active (suspended, revoked, or expired)",
  permit_consumed: "Single-use permit already consumed",
  derivation_cap_exhausted: "Mission's derivation limit reached",
  authorization_pending: "Awaiting approval",
  access_denied: "Approval was denied",
  action_approval_required: "Requires just-in-time approval",
  stale_state: "Mission status is too stale to rely on (freshness bound exceeded)",
  actor_invalid: "Invalid delegation chain (actor)",
  instance_revoked: "Agent instance has been revoked",
  unknown_tool: "Tool not recognized",
  unknown_invoice: "Invoice not found",
  unknown_vendor: "Vendor not found",
  expired_token: "Credential has expired",
  no_result: "No decision returned by the policy engine",
  txn_missing_approval: "Transaction is missing its approval token",
  txn_cnf_mismatch: "Transaction token not bound to this client",
  txn_invalid: "Invalid transaction approval token",
  txn_replayed: "Transaction approval token already used",
  txn_unknown: "Unknown transaction",
  txn_not_configured: "Transaction assurance not configured",
  // Child-delegation refusal reasons (@spec child-delegation#denial-reasons).
  parent_not_active: "Parent mission is not active",
  parent_mismatch: "Child does not match its declared parent mission",
  not_strict_subset: "Child authority is not within the parent's authority",
  delegation_not_permitted: "Parent authority does not permit child delegation",
  child_actor_not_allowed: "Child actor is not allowed to receive this delegation",
  fanout_exceeded: "Parent's child-delegation limit reached (depth or count)",
  policy_denied: "Child delegation refused by policy",
};

export type LabelKind = "tool" | "action" | "reason";

/**
 * Return the human name for a machine id, or the raw id when unmapped. For
 * reason codes carrying a `:<state>` suffix, the suffix is stripped before
 * lookup and appended in parens (e.g. `mission_not_active:suspended` ->
 * "Mission is not active (...) (suspended)").
 */
export function label(kind: LabelKind, id: string): string {
  if (kind === "reason") {
    // Only reasons are colon-suffixed with a state; action ids also contain a
    // colon (payments:invoice.read) and must NOT be split.
    const base = id.split(":")[0] ?? id;
    const state = id.slice(base.length + 1);
    const human = REASON_LABELS[base];
    if (!human) return id;
    return state ? `${human} (${state})` : human;
  }
  const map = kind === "tool" ? TOOL_LABELS : ACTION_LABELS;
  return map[id] ?? id;
}
