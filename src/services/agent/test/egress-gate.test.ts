/**
 * @spec harness#mediated-egress (the second mediation boundary)
 *
 * The default-deny egress gate, keyed to the published scope statement. Proves:
 * an undeclared channel and an unlisted destination are refused (and the inner
 * fetch is never reached); a declared destination is permitted; the
 * mission-state guard runs FIRST and fails closed with MediatedHarness's exact
 * refusal styles (non-active state, stale status lease); EVERY request,
 * permitted and refused, is recorded as EgressEvidence with emitter role
 * "egress" and the statement's digest; and a statement whose destinations sit
 * on a non-mediated channel is rejected at both build and construction time.
 * Key-free and OpenFGA-free: the mission state and the inner fetch are stubs.
 */

import type { MissionStatusLease } from "@mission/core";
import { type EgressEvidence, EvidenceStore } from "@mission/mcp-payments";
import { describe, expect, it } from "vitest";
import { EgressGate, type EgressGateConfig, type EgressRefusal } from "../src/egress-gate.js";
import {
  buildScopeStatement,
  type ExecutionEnvironmentScopeStatement,
  scopeDigest,
} from "../src/harness-scope.js";
import type { MissionState } from "../src/harness.js";

const ANTHROPIC = "https://api.anthropic.com";

/** The demo-shaped statement: inference_api mediated to one declared origin. */
const STATEMENT = buildScopeStatement({
  isolation_mechanism: "in-memory test process (no isolation boundary)",
  transport: "in_memory",
  mediated_action_classes: ["payments"],
  excluded_unmediated_paths: ["direct process network access"],
  channel_classes: [{ channel_class: "inference_api", disposition: "mediated", destinations: [ANTHROPIC] }],
});

const active = async (): Promise<MissionState> => "active";
const suspended = async (): Promise<MissionState> => "suspended";

function makeGate(overrides: Partial<EgressGateConfig> = {}): { gate: EgressGate; evidence: EvidenceStore } {
  const evidence = new EvidenceStore();
  const gate = new EgressGate({
    statement: STATEMENT,
    missionId: "msn-egress",
    readState: active,
    evidence,
    emitterId: "test-egress-gate",
    instanceEpoch: "test-epoch",
    authorityHash: "sha-256:test-authority",
    ...overrides,
  });
  return { gate, evidence };
}

function egressRecords(evidence: EvidenceStore): EgressEvidence[] {
  return evidence.all().filter((r): r is EgressEvidence => r.kind === "egress");
}

describe("egress gate: default-deny against the published scope statement", () => {
  it("refuses an undeclared channel and records the refusal (role egress, statement digest)", async () => {
    const { gate, evidence } = makeGate();
    // dns_resolution is auto-filled `outside_claim` by the honest form: not mediated.
    const decision = await gate.request("dns_resolution", `${ANTHROPIC}/v1/messages`);
    expect(decision.permitted).toBe(false);
    expect(decision.refusal_reason).toBe("egress_undeclared:dns_resolution");

    const records = egressRecords(evidence);
    expect(records).toHaveLength(1);
    const rec = records[0] as EgressEvidence;
    expect(rec.outcome).toBe("refused");
    expect(rec.refusal_reason).toBe("egress_undeclared:dns_resolution");
    expect(rec.channel_class).toBe("dns_resolution");
    expect(rec.emitter).toEqual({ id: "test-egress-gate", role: "egress" });
    expect(rec.scope_statement_digest).toBe(scopeDigest(STATEMENT));
    expect(rec.mission_id).toBe("msn-egress");
  });

  it("never reaches the inner fetch through guardedFetch when the channel is not mediated", async () => {
    // A statement whose inference_api carries NO mediated disposition: every
    // guardedFetch call is an undeclared-channel egress.
    const statement = buildScopeStatement({
      isolation_mechanism: "in-memory test process (no isolation boundary)",
      transport: "in_memory",
      mediated_action_classes: ["payments"],
    });
    const { gate, evidence } = makeGate({ statement });
    const calls: string[] = [];
    const inner = (async (input: Parameters<typeof fetch>[0]) => {
      calls.push(String(input));
      return new Response("ok");
    }) as typeof fetch;

    await expect(gate.guardedFetch(inner)(`${ANTHROPIC}/v1/messages`)).rejects.toThrow(
      /egress_undeclared:inference_api/,
    );
    expect(calls).toEqual([]); // the spy inner fetch was NEVER called
    expect(egressRecords(evidence)).toHaveLength(1);
  });

  it("refuses a destination whose origin is not in the channel's declared set, and records it", async () => {
    const { gate, evidence } = makeGate();
    const decision = await gate.request("inference_api", "https://exfil.example.com/v1/messages");
    expect(decision.permitted).toBe(false);
    expect(decision.refusal_reason).toBe("egress_destination_unlisted:https://exfil.example.com");

    const rec = egressRecords(evidence)[0] as EgressEvidence;
    expect(rec.outcome).toBe("refused");
    expect(rec.destination).toBe("https://exfil.example.com/v1/messages");
  });

  it("permits a declared destination and records the permitted outcome too", async () => {
    const { gate, evidence } = makeGate();
    const decision = await gate.request("inference_api", `${ANTHROPIC}/v1/messages`);
    expect(decision.permitted).toBe(true);
    expect(decision.refusal_reason).toBeUndefined();

    const rec = egressRecords(evidence)[0] as EgressEvidence;
    expect(rec.outcome).toBe("permitted");
    expect(rec.refusal_reason).toBeUndefined();
    expect(rec.channel_class).toBe("inference_api");
    expect(rec.emitter).toEqual({ id: "test-egress-gate", role: "egress" });
    expect(rec.scope_statement_digest).toBe(scopeDigest(STATEMENT));
  });
});

describe("egress gate: mission-state guard runs FIRST and fails closed", () => {
  it("refuses mission_not_active:suspended BEFORE any allowlist evaluation", async () => {
    const { gate, evidence } = makeGate({ readState: suspended });
    // Undeclared channel AND unlisted destination: the state refusal wins,
    // proving the guard ran before either allowlist check.
    const decision = await gate.request("dns_resolution", "https://exfil.example.com/x");
    expect(decision.permitted).toBe(false);
    expect(decision.refusal_reason).toBe("mission_not_active:suspended");
    expect(decision.resume?.proceed).toBe(false);

    const rec = egressRecords(evidence)[0] as EgressEvidence;
    expect(rec.outcome).toBe("refused");
    expect(rec.refusal_reason).toBe("mission_not_active:suspended");
  });

  it("refuses mission_status_stale on an expired lease via injected now, even for a declared destination", async () => {
    const lease: MissionStatusLease = {
      state: "active",
      status_checked_at: "2026-01-01T22:00:00Z",
      status_expires_at: "2026-01-01T22:05:00Z",
      state_source: "status",
    };
    const { gate, evidence } = makeGate({
      readStatus: async () => lease,
      now: () => new Date("2026-01-02T02:00:00Z"), // the 02:00 wake-up: lease stale
    });
    const decision = await gate.request("inference_api", `${ANTHROPIC}/v1/messages`);
    expect(decision.permitted).toBe(false);
    expect(decision.refusal_reason).toBe("mission_status_stale:active");
    expect(decision.resume?.stale).toBe(true);
    expect((egressRecords(evidence)[0] as EgressEvidence).refusal_reason).toBe("mission_status_stale:active");
  });
});

describe("egress gate: statement/allowlist consistency", () => {
  it("buildScopeStatement rejects destinations on a non-mediated channel (honesty check)", () => {
    expect(() =>
      buildScopeStatement({
        isolation_mechanism: "in-memory test process",
        transport: "in_memory",
        channel_classes: [
          { channel_class: "inference_api", disposition: "outside_claim", destinations: [ANTHROPIC] },
        ],
      }),
    ).toThrow(/not mediated/);
  });

  it("the constructor rejects a hand-built statement whose destinations sit on a non-mediated channel", () => {
    const inconsistent: ExecutionEnvironmentScopeStatement = {
      ...STATEMENT,
      channel_classes: STATEMENT.channel_classes.map((c) =>
        c.channel_class === "inference_api" ? { ...c, disposition: "excluded" as const } : c,
      ),
    };
    expect(() => makeGate({ statement: inconsistent })).toThrow(/not mediated/);
  });
});

describe("egress gate: onRefusal harness-reporter seam (advisory low-trust class)", () => {
  it("fires onRefusal for an undeclared channel, carrying the refusal payload", async () => {
    const seen: EgressRefusal[] = [];
    const { gate } = makeGate({ onRefusal: (r) => seen.push(r) });
    await gate.request("dns_resolution", `${ANTHROPIC}/v1/messages`);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({
      channel_class: "dns_resolution",
      destination: `${ANTHROPIC}/v1/messages`,
      refusal_reason: "egress_undeclared:dns_resolution",
      mission_id: "msn-egress",
      scope_statement_digest: scopeDigest(STATEMENT),
    });
  });

  it("fires onRefusal for an unlisted destination", async () => {
    const seen: EgressRefusal[] = [];
    const { gate } = makeGate({ onRefusal: (r) => seen.push(r) });
    await gate.request("inference_api", "https://exfil.example.com/v1/messages");
    expect(seen).toHaveLength(1);
    expect(seen[0]?.refusal_reason).toBe("egress_destination_unlisted:https://exfil.example.com");
    expect(seen[0]?.destination).toBe("https://exfil.example.com/v1/messages");
  });

  it("does NOT fire onRefusal for a mission-state refusal (only channel/destination classes)", async () => {
    const seen: EgressRefusal[] = [];
    const { gate } = makeGate({ readState: suspended, onRefusal: (r) => seen.push(r) });
    const decision = await gate.request("dns_resolution", "https://exfil.example.com/x");
    expect(decision.refusal_reason).toBe("mission_not_active:suspended");
    expect(seen).toEqual([]); // the guard's refusal is never forwarded as advisory
  });

  it("does NOT fire onRefusal for a permitted request", async () => {
    const seen: EgressRefusal[] = [];
    const { gate } = makeGate({ onRefusal: (r) => seen.push(r) });
    const decision = await gate.request("inference_api", `${ANTHROPIC}/v1/messages`);
    expect(decision.permitted).toBe(true);
    expect(seen).toEqual([]);
  });

  it("swallows a throwing forwarder (fail-closed component); the refusal is still recorded", async () => {
    const { gate, evidence } = makeGate({
      onRefusal: () => {
        throw new Error("broken forwarder");
      },
    });
    const decision = await gate.request("dns_resolution", `${ANTHROPIC}/v1/messages`);
    expect(decision.permitted).toBe(false);
    expect((egressRecords(evidence)[0] as EgressEvidence).outcome).toBe("refused");
  });
});

describe("egress gate: guardedFetch end-to-end", () => {
  it("forwards a permitted request to the inner fetch and returns its response", async () => {
    const { gate, evidence } = makeGate();
    const calls: string[] = [];
    const inner = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      calls.push(`${String(input)}:${init?.method ?? "GET"}`);
      return new Response("model says hi", { status: 200 });
    }) as typeof fetch;

    const res = await gate.guardedFetch(inner)(`${ANTHROPIC}/v1/messages`, { method: "POST" });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("model says hi");
    expect(calls).toEqual([`${ANTHROPIC}/v1/messages:POST`]);
    expect((egressRecords(evidence)[0] as EgressEvidence).outcome).toBe("permitted");
  });

  it("does not forward a refused request (unlisted destination): the inner fetch is never called", async () => {
    const { gate, evidence } = makeGate();
    const calls: string[] = [];
    const inner = (async (input: Parameters<typeof fetch>[0]) => {
      calls.push(String(input));
      return new Response("ok");
    }) as typeof fetch;

    await expect(gate.guardedFetch(inner)("https://exfil.example.com/v1/messages")).rejects.toThrow(
      /egress_destination_unlisted:https:\/\/exfil\.example\.com/,
    );
    expect(calls).toEqual([]);
    expect((egressRecords(evidence)[0] as EgressEvidence).outcome).toBe("refused");
  });
});
