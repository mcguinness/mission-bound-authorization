/**
 * @spec authority-server#mission-join rules 3 and 4,
 * authority-server#mapping-contract, authority-server#high-consequence-binding (#818)
 *
 * The PDP's join under a mapping contract (`EvaluateOptions.joinMapping`):
 * the acting credential's issuer qualifies its subject and client, only the
 * contract's resolution reaches the comparison with the Mission's own, and an
 * unresolved mapping denies `mission_binding_failed`. Also the classes a scope
 * reserves for Mission-bound credentials (`missionBoundOnlyClasses`): a joined
 * request in one is denied before the join runs. The contract here is a plain
 * test double, so these tests are about what the PDP does with a resolution,
 * not about any one contract store.
 */

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate as evaluateRequest, type EvaluationRequest, type EvaluateOptions } from "../src/evaluate.js";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  type JoinIdentityResolution,
  type JoinMappingContract,
} from "../src/index.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-19T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const READ = "payments:invoice.read";
const MAS = "https://mas.test";
const ESTATE = "https://estate.test";

const ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ] };
const view: MissionView = {
  id: "msn_818_pdp",
  issuer: MAS,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m818",
  authority_set: [ENTRY],
  subject: { iss: MAS, sub: "alice" },
  client_id: "ap-agent",
};

/** A contract double: exact issuer-qualified rows, nothing else resolves. */
function contract(
  subjects: Record<string, { iss: string; sub: string }>,
  clients: Record<string, string>,
): JoinMappingContract & { calls: number } {
  const c = {
    id: "double",
    version: 1,
    calls: 0,
    resolveIdentity(input: Parameters<JoinMappingContract["resolveIdentity"]>[0]): JoinIdentityResolution | undefined {
      c.calls += 1;
      const subject = subjects[`${input.subject.iss} ${input.subject.sub}`];
      const clientId = clients[`${input.client.iss} ${input.client.clientId}`];
      return subject && clientId ? { subject, clientId } : undefined;
    },
    clientFor: () => undefined,
    credentialAuthority: () => undefined,
  };
  return c;
}

const opts = (extra: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep" as const,
  ...extra,
});

/** A joined request from an estate credential: subject and client in the estate's namespace. */
const estateReq = (sub: string, clientId: string, actionClass = "consequential_read"): EvaluationRequest =>
  withCredential({
    subject: { id: sub, properties: { iss: ESTATE } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: { name: READ },
    context: {
      mission: { id: view.id, issuer: view.issuer },
      actor: { client_id: clientId },
      mission_join: {},
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
      action_class: actionClass,
      credential: {
        issuer: ESTATE,
        authority: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ] }],
      },
    },
  } as EvaluationRequest);

async function evaluatedWithEvidence(req: EvaluationRequest, o: EvaluateOptions) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const emitter = createDecisionEvidenceEmitter({ signer: { kid: "k818", key: privateKey }, emitterId: RESOURCE, audience: RESOURCE });
  const decision = await evaluateRequest(req, { ...o, evidence: emitter });
  return { decision, record: decision.context.decision_evidence as DecisionEvidenceObject };
}

const MAPPED = contract({ [`${ESTATE} u-1001`]: { iss: MAS, sub: "alice" } }, { [`${ESTATE} estate-bot`]: "ap-agent" });

describe("evaluate(): the join under a mapping contract (@spec authority-server#mission-join rules 3 and 4, #mapping-contract, #818)", () => {
  it("permits an estate credential whose issuer-qualified subject and client the contract maps to the Mission's own", async () => {
    const decision = await evaluateRequest(estateReq("u-1001", "estate-bot"), opts({ joinMapping: MAPPED }));
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
  });

  it("denies mission_binding_failed for an estate subject the contract does not cover, even though its client maps", async () => {
    const decision = await evaluateRequest(estateReq("u-9999", "estate-bot"), opts({ joinMapping: MAPPED }));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
  });

  it("never conflates an estate client whose identifier string equals the Mission's client_id: only the contract's resolution is compared", async () => {
    // The estate registered a client named "ap-agent", the Mission's own
    // client_id, and the contract maps it to a DIFFERENT Mission client. A
    // bare string comparison would join it; the contract's resolution does not.
    const sameString = contract({ [`${ESTATE} u-1001`]: { iss: MAS, sub: "alice" } }, { [`${ESTATE} ap-agent`]: "estate-ap-agent" });
    const decision = await evaluateRequest(estateReq("u-1001", "ap-agent"), opts({ joinMapping: sameString }));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
  });

  it("never conflates an estate subject whose sub string equals the Mission subject's: the contract maps it to another person", async () => {
    // Estate account "alice" is a different person from the Mission's alice.
    const otherAlice = contract({ [`${ESTATE} alice`]: { iss: MAS, sub: "carol" } }, { [`${ESTATE} estate-bot`]: "ap-agent" });
    const decision = await evaluateRequest(estateReq("alice", "estate-bot"), opts({ joinMapping: otherAlice }));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
  });

  it("denies mission_binding_failed when the request names no credential issuer to qualify the identities, without consulting the contract", async () => {
    const counted = contract({ [`${ESTATE} u-1001`]: { iss: MAS, sub: "alice" } }, { [`${ESTATE} estate-bot`]: "ap-agent" });
    const req = estateReq("u-1001", "estate-bot");
    const { issuer: _dropped, ...credential } = req.context.credential as Record<string, unknown>;
    const decision = await evaluateRequest(
      { ...req, context: { ...req.context, credential } } as EvaluationRequest,
      opts({ joinMapping: counted }),
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("mission_binding_failed");
    expect(counted.calls).toBe(0);
  });
});

describe("evaluate(): classes reserved for Mission-bound credentials (@spec authority-server#high-consequence-binding, #818)", () => {
  it("denies a joined request in a reserved class before the join runs, recording no join_view_id", async () => {
    const counted = contract({ [`${ESTATE} u-1001`]: { iss: MAS, sub: "alice" } }, { [`${ESTATE} estate-bot`]: "ap-agent" });
    const { decision, record } = await evaluatedWithEvidence(
      estateReq("u-1001", "estate-bot"),
      opts({ joinMapping: counted, missionBoundOnlyClasses: new Set(["consequential_read"]) }),
    );
    expect(decision.decision).toBe(false);
    expect(record.denial_reason).toBe("mission_binding_failed");
    expect(record).not.toHaveProperty("join_view_id");
    expect(counted.calls).toBe(0);
  });

  it("the same joined request permits when its class is not reserved, so the reservation alone denied it above", async () => {
    const { decision, record } = await evaluatedWithEvidence(
      estateReq("u-1001", "estate-bot"),
      opts({ joinMapping: MAPPED, missionBoundOnlyClasses: new Set(["irreversible_action", "external_commitment"]) }),
    );
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
    expect(record.join_view_id).toMatch(/^sha-256:/);
  });
});
