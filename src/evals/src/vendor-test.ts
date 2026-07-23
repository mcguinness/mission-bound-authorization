/**
 * @spec handbook vendor-test demonstration (D22/D40)
 *
 * The demonstration that settles the vendor test: "show me one denied action
 * where the token was valid but the Mission's state, bounds, parameters, or
 * delegation chain made the action impermissible." Four cases, one per axis,
 * each with a structurally valid token that is nonetheless denied. Run by
 * `pnpm demo:vendor-test`.
 */

import { type EvalCase, runCase } from "./index.js";
import type { HarnessDeps } from "./index.js";
import type { TokenFacts } from "@mission/mcp-payments";
import { CANONICAL_RESOURCE } from "@mission/mcp-payments";

const MISSION = { id: "msn_eval", authority_hash: "sha-256:evalhash" };
const validToken = (over: Partial<TokenFacts> = {}): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-1",
  mission: MISSION,
  cnfJkt: "jkt-1",
  ...over,
});

/**
 * The four axes. Each token is valid (well-formed, correct mission ref except
 * where the axis IS the mission state); the denial comes from the Mission, not
 * from a malformed credential.
 */
export function vendorTestCases(revokedInstances: Set<string>): {
  axis: string;
  case: EvalCase;
}[] {
  return [
    {
      axis: "bounds",
      case: {
        id: "vt-bounds",
        suite: "adversarial",
        description: "Valid token, but the payment exceeds the Mission's per-payment cap.",
        tool: "execute_wire_transfer",
        args: { invoice_id: "inv-big" },
        token: () => validToken(),
        expect: "deny",
        expectReason: "constraint_exceeded",
        consequential: true,
      },
    },
    {
      axis: "parameters",
      case: {
        id: "vt-parameters",
        suite: "adversarial",
        description: "Valid token, permitted at decision, but parameters mutate before commit.",
        tool: "execute_wire_transfer",
        args: { invoice_id: "inv-acme" },
        token: () => validToken(),
        beforeCommit: (store) => store.bumpInvoiceAmount("inv-acme", "499.00"),
        expect: "deny",
        expectReason: "parameter_mismatch",
        consequential: true,
      },
    },
    {
      axis: "delegation chain",
      case: {
        id: "vt-delegation",
        suite: "adversarial",
        description: "Valid token whose acting sub-agent instance has been revoked.",
        tool: "execute_wire_transfer",
        args: { invoice_id: "inv-acme" },
        token: () =>
          validToken({
            clientInstanceId: "inst-subagent",
            act: {
              iss: "https://as.test",
              sub: "inst-subagent",
              sub_profile: "ai_agent client_instance",
              act: { iss: "https://as.test", sub: "inst-orchestrator", sub_profile: "ai_agent client_instance" },
            },
          }),
        expect: "deny",
        expectReason: "instance_revoked",
        consequential: true,
        // The harness seeds this revocation before the run (see runVendorTest).
        _revoke: () => revokedInstances.add("https://as.test inst-subagent"),
      } as EvalCase & { _revoke: () => void },
    },
    {
      axis: "state",
      case: {
        id: "vt-state",
        suite: "adversarial",
        description: "Valid token, but the Mission is no longer active (revoked).",
        tool: "execute_wire_transfer",
        args: { invoice_id: "inv-acme" },
        token: () => validToken(),
        expect: "deny",
        // The view is swapped to a revoked state for this case (see runVendorTest).
        expectReason: "mission_inactive",
        consequential: true,
      },
    },
  ];
}

export interface VendorTestRow {
  axis: string;
  tool: string;
  denied: boolean;
  reason?: string;
  tokenWasValid: true;
}

/**
 * Run the four-axis demonstration. `deps` composes the stack; the state axis
 * uses a revoked view, the delegation axis a per-instance revocation.
 */
export async function runVendorTest(deps: HarnessDeps & { revokedInstances: Set<string> }): Promise<{
  rows: VendorTestRow[];
  passed: boolean;
}> {
  const rows: VendorTestRow[] = [];
  for (const { axis, case: c } of vendorTestCases(deps.revokedInstances)) {
    const withRevoke = c as EvalCase & { _revoke?: () => void };
    withRevoke._revoke?.();
    // The state axis needs a revoked view; every other axis uses the active one.
    const view = axis === "state" ? { ...deps.view, state: "revoked" } : deps.view;
    const res = await runCase(c, { ...deps, view });
    rows.push({ axis, tool: c.tool, denied: res.outcome === "deny", ...(res.reason ? { reason: res.reason } : {}), tokenWasValid: true });
    deps.revokedInstances.clear();
  }
  const passed = rows.every((r) => r.denied);
  return { rows, passed };
}

export { CANONICAL_RESOURCE };
