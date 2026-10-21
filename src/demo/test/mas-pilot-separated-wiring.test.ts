/**
 * @spec authority-server#mission-join rule 2, runtime#state-freshness,
 * authzen#failure-condition-coverage (#818 slice 4b)
 *
 * The separated pilot's two adapters around its Mission Status resolver,
 * with the resolver stubbed: the decision point's own read for every
 * decision (`ownReadDecide`) and the PEP's one read per enforcement
 * (`statusViewSource`). Never skips.
 */

import { type EvaluationRequest, type MissionStatusResolution, type MissionView, stalenessBound } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import { ownReadDecide, statusViewSource } from "../src/mas-pilot/separated.js";

const ISSUER = "http://127.0.0.1:14834";
const IAT_MS = Date.parse("2026-10-20T12:00:00Z");
const VIEW: MissionView = {
  id: "msn_wiring",
  issuer: ISSUER,
  state: "active",
  version: 4,
  authority_hash: "sha-256:wiring",
  authority_set: [{ type: "mission_resource_access", resource: "http://localhost:4403/mcp", actions: ["payments:invoice.read"] }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};
const PEP_VIEW: MissionView = { ...VIEW, version: 3 };

function stub(result: MissionStatusResolution) {
  const calls: Array<{ ref: { id: string; issuer: string }; opts: unknown }> = [];
  return {
    calls,
    resolver: {
      resolve: async (ref: { id: string; issuer: string }, opts?: unknown) => {
        calls.push({ ref, opts });
        return result;
      },
    },
  };
}

const request = (actionClass: string, phase?: string) =>
  ({
    subject: { id: "u-1001" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:invoice.read" },
    context: { mission: { id: VIEW.id, issuer: ISSUER }, action_class: actionClass, ...(phase ? { action_phase: phase } : {}) },
  }) as unknown as EvaluationRequest;

/** What the PEP forwards: its own view and its own observation time. */
const forwarded = { view: PEP_VIEW, stalenessBound, stateSourcePlacement: "pdp", stateObservedAt: "2026-10-20T12:00:30Z" } as never;

async function decideWith(result: MissionStatusResolution, req: EvaluationRequest) {
  const { calls, resolver } = stub(result);
  let seen: Record<string, unknown> | undefined;
  const decide = ownReadDecide(resolver as never)(async (_r, options) => {
    seen = options as unknown as Record<string, unknown>;
    return { decision: false, context: {} };
  });
  await decide(req, forwarded);
  return { calls, seen: seen as Record<string, unknown> };
}

describe("the separated PDP's own read for every decision (#818 slice 4b)", () => {
  const ok: MissionStatusResolution = { ok: true, view: VIEW, observedAtMs: IAT_MS, freshUntilMs: IAT_MS + 60_000, source: "cached" };

  it("reads within the decision's class window, and decides on the signed iat and fresh_until in place of what the PEP forwarded", async () => {
    const { calls, seen } = await decideWith(ok, request("consequential_read"));
    expect(calls).toEqual([{ ref: { id: VIEW.id, issuer: ISSUER }, opts: { fresh: false, maxAgeSeconds: 300 } }]);
    expect(seen.view).toBe(VIEW);
    expect(seen.stateSourcePlacement).toBe("pdp");
    expect(seen.stateObservedAt).toBe(new Date(IAT_MS).toISOString());
    expect(seen.stateFreshUntil).toBe(new Date(IAT_MS + 60_000).toISOString());
  });

  it("reads the MAS now for a commit-phase decision, within its own class window", async () => {
    const { calls } = await decideWith(ok, request("irreversible_action", "commit"));
    expect(calls[0]?.opts).toEqual({ fresh: true, maxAgeSeconds: 30 });
    const prepare = await decideWith(ok, request("consequential_write", "prepare"));
    expect(prepare.calls[0]?.opts).toEqual({ fresh: false, maxAgeSeconds: 300 });
  });

  it("with no read, decides with no state option at all, never the PEP's forwarded observation", async () => {
    const { seen } = await decideWith({ ok: false, reason: "unavailable", detail: "transport" }, request("consequential_read"));
    expect(seen.stateSourcePlacement).toBe("pdp");
    expect("stateObservedAt" in seen).toBe(false);
    expect("stateFreshUntil" in seen).toBe(false);
  });
});

describe("the separated PEP's one read per enforcement (#818 slice 4b)", () => {
  it("maps the MAS's not-found to unknown_mission and every other failure to state_unavailable", async () => {
    const ref = { id: VIEW.id, issuer: ISSUER };
    expect(await statusViewSource(stub({ ok: true, view: VIEW, observedAtMs: IAT_MS, freshUntilMs: IAT_MS + 1, source: "fetched" }).resolver as never).prepare(ref)).toEqual({ ok: true });
    expect(await statusViewSource(stub({ ok: false, reason: "not_found", detail: "status 404" }).resolver as never).prepare(ref)).toEqual({
      ok: false,
      refusal: "unknown_mission",
    });
    for (const reason of ["unavailable", "unauthorized", "unverifiable", "stale"] as const) {
      expect(await statusViewSource(stub({ ok: false, reason, detail: reason }).resolver as never).prepare(ref), reason).toEqual({
        ok: false,
        refusal: "state_unavailable",
      });
    }
  });
});
