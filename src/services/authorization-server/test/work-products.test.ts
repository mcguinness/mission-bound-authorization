/**
 * @spec draft-mcguinness-oauth-mission-work-products#conformance, #handoff
 * (issue #413)
 *
 * Unit coverage for the kernel-level work-products functions, independent of
 * the OpenFGA-backed incident e2e (work-products-incident-e2e.test.ts), which
 * skips when OpenFGA is unreachable. Covered here:
 *   - the trusted-mediator custody boundary: produceWorkProduct accepts a
 *     mediator-attached provenance object (harness or issuer role) and
 *     refuses a self-asserted one (mediator.id === producer) and an untrusted
 *     mediator role, WITHOUT ever adding a member to the stamped object;
 *   - produceWorkProduct/ingestWorkProduct still gate on the (receiving)
 *     Mission being live via gateActive, not gateDerivation;
 *   - the MUST-level non-transitive handoff: ingestWorkProduct returns
 *     EXACTLY {provenance, content} and commits nothing to the receiving
 *     Mission (byte-identical version/authority_hash/effective set).
 */

import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  GateError,
  ingestWorkProduct,
  MissionKernel,
  produceWorkProduct,
  ProvenanceCustodyError,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.wp.test";
const RESOURCE = "https://payments.test/mcp";
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const NOW = new Date("2026-08-09T00:00:00Z");

const POLICY = {
  policy_version: "wp-v1",
  ceiling: [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  ],
};

const intent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Reconcile Acme invoices",
      target_resources: [RESOURCE],
      expires_at: EXPIRES_AT,
    }),
  );

let key: CryptoKey;
let kernel: MissionKernel;
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["agent-A1", "agent-A2", "agent-A3", "agent-A4", "agent-A5", "agent-B1", "agent-B2", "agent-B3", "agent-B4"]),
    statusKey: key,
    statusKid: "as-status",
    now: () => NOW,
  });
});

const approveMission = (clientId: string) =>
  kernel.approve({
    intent: intent(),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId,
    approvalEventId: `apev-wp-${++seq}`,
  });

describe("produceWorkProduct: the trusted-mediator custody boundary", () => {
  it("accepts a harness-mediator-attached provenance object with exactly the five members", () => {
    const mission = approveMission("agent-A1");
    const wp = produceWorkProduct(kernel, {
      missionId: mission.id,
      deploymentId: "dep-A1",
      producer: "agent:A1",
      mediator: { id: "harness:dep-A1", role: "harness" },
      content: { note: "remittance approach worked" },
    });
    expect(wp.provenance.kind).toBe("artifact");
    expect(Object.keys(wp.provenance).sort()).toEqual(
      ["created_at", "deployment_id", "kind", "mission_id", "producer"].sort(),
    );
    expect(wp.provenance.mission_id).toBe(mission.id);
    expect(wp.provenance.deployment_id).toBe("dep-A1");
    expect(wp.provenance.producer).toBe("agent:A1");
  });

  it("accepts the Mission Issuer as mediator", () => {
    const mission = approveMission("agent-A2");
    const wp = produceWorkProduct(kernel, {
      missionId: mission.id,
      deploymentId: "dep-A2",
      producer: "agent:A2",
      mediator: { id: ISS, role: "issuer" },
      content: { note: "ok" },
    });
    expect(wp.provenance.producer).toBe("agent:A2");
  });

  it("rejects a self-asserted mediator (mediator.id === producer)", () => {
    const mission = approveMission("agent-A3");
    try {
      produceWorkProduct(kernel, {
        missionId: mission.id,
        deploymentId: "dep-A3",
        producer: "agent:A3",
        mediator: { id: "agent:A3", role: "harness" },
        content: { note: "self-authored" },
      });
      expect.unreachable("a self-asserted mediator must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(ProvenanceCustodyError);
      expect((e as ProvenanceCustodyError).reason).toBe("self_asserted");
    }
  });

  it("rejects an untrusted mediator role", () => {
    const mission = approveMission("agent-A4");
    try {
      produceWorkProduct(kernel, {
        missionId: mission.id,
        deploymentId: "dep-A4",
        producer: "agent:A4",
        mediator: { id: "pdp:1", role: "pdp" } as never,
        content: { note: "bad role" },
      });
      expect.unreachable("an untrusted mediator role must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(ProvenanceCustodyError);
      expect((e as ProvenanceCustodyError).reason).toBe("untrusted_mediator_role");
    }
  });

  it("still requires the producing Mission to be live (gateActive, not gateDerivation)", () => {
    const mission = approveMission("agent-A5");
    kernel.transition(mission.id, "revoke");
    expect(() =>
      produceWorkProduct(kernel, {
        missionId: mission.id,
        deploymentId: "dep-A5",
        producer: "agent:A5",
        mediator: { id: "harness:dep-A5", role: "harness" },
        content: { note: "n/a" },
      }),
    ).toThrow(GateError);
  });
});

describe("ingestWorkProduct: non-transitive MUST-level handoff", () => {
  it("returns exactly {provenance, content} and commits nothing to the receiving Mission", () => {
    const producing = approveMission("agent-B1");
    const receiving = approveMission("agent-B2");
    const before = kernel.get(receiving.id) as NonNullable<ReturnType<MissionKernel["get"]>>;

    const wp = produceWorkProduct(kernel, {
      missionId: producing.id,
      deploymentId: "dep-B1",
      producer: "agent:B1",
      mediator: { id: "harness:dep-B1", role: "harness" },
      content: { secret: "does-not-become-authority" },
    });
    const ingested = ingestWorkProduct(kernel, { workProduct: wp, receivingMissionId: receiving.id });

    // Exactly two members: provenance + content, nothing else through which
    // authority could ride (the type contract, proven at the value level too).
    expect(Object.keys(ingested).sort()).toEqual(["content", "provenance"]);
    expect(ingested.provenance).toEqual(wp.provenance);
    expect(ingested.content).toEqual(wp.content);

    // Non-transitive: the receiving Mission is byte-identical after ingest.
    const after = kernel.get(receiving.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(after.version).toBe(before.version);
    expect(after.authority_hash).toBe(before.authority_hash);
    expect(kernel.effectiveAuthoritySet(after)).toEqual(kernel.effectiveAuthoritySet(before));
  });

  it("requires the receiving Mission to be live", () => {
    const producing = approveMission("agent-B3");
    const receiving = approveMission("agent-B4");
    kernel.transition(receiving.id, "revoke");
    const wp = produceWorkProduct(kernel, {
      missionId: producing.id,
      deploymentId: "dep-B3",
      producer: "agent:B3",
      mediator: { id: "harness:dep-B3", role: "harness" },
      content: { note: "n/a" },
    });
    expect(() => ingestWorkProduct(kernel, { workProduct: wp, receivingMissionId: receiving.id })).toThrow(
      GateError,
    );
  });
});
