/**
 * @spec containment#selector-matching, runtime#decision-inputs,
 * runtime#input-authority (#1463, D606): the canonical in-process Mission
 * loader, `kernelMissionView`, hands the PDP the containment overlay resolved
 * onto the approved entries. The PDP pairs a delta member with the approved
 * entry it relies on by that entry's own `resource`, so a `prefix` selector
 * over a finer entry approved beneath a `prefix` ceiling still denies
 * `authority_contained` at the point of use, for a credential issued before
 * the contain transition. The kernel and PDP are real; only the OpenFGA
 * client is stubbed, so this file never skips.
 */

import { type AuthorityEntry, MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import { evaluate, type EvaluationRequest, type Fga, relationForAction, stalenessBound } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { kernelMissionView } from "../src/kernel-mission-view.js";

const ISS = "https://as.overlay-view.test";
const SERVICE = "https://payments.test/mcp";
const INV1 = `${SERVICE}/invoices/inv-1`;
const READ = "payments:invoice.read";
const LIST = "payments:invoice.list";
const NOW = new Date("2026-10-20T12:00:00Z");

let statusKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: statusKey } = (await generateKeyPair("ES256", { extractable: true })) as { privateKey: CryptoKey });
});

function approvedMission() {
  const ceiling = [{ type: "mission_resource_access", resource: `${SERVICE}/`, resource_match: "prefix", actions: [READ, LIST] }];
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "overlay-view-1463", ceiling } as never,
    authoritySourceCatalog: {
      humanPrincipals: [],
      entries: [
        { id: "overlay-view", type: "user_delegated", clients: ["ap-agent"], activators: ["bob"], ceiling },
      ],
    } as never,
    statusKey,
    statusKid: "overlay-view-status",
    now: () => NOW,
  });
  const entry: AuthorityEntry = { type: "mission_resource_access", resource: INV1, actions: [READ, LIST] };
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read invoice 1", target_resources: [INV1], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [entry],
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-overlay-view-1463",
  });
  return { kernel, id: mission.id };
}

/** A read of invoice 1 under a credential issued before any containment, carrying both actions. */
const request = (id: string, action: string): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: {
    type: "invoice",
    id: "inv-1",
    properties: { audience: SERVICE, operation_target: INV1, vendor_id: "acme" },
  },
  action: { name: action },
  context: {
    mission: { id, issuer: ISS },
    credential: { authority: [{ type: "mission_resource_access", resource: INV1, actions: [READ, LIST] }] },
    parameter_digest: `sha-256:${Buffer.alloc(32, 7).toString("base64url")}`,
  },
});

async function decide(kernel: MissionKernel, id: string, action: string): Promise<string> {
  const view = kernelMissionView(kernel, id);
  if (!view) throw new Error("no view");
  const d = await evaluate(request(id, action), {
    view,
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "test",
    now: () => NOW,
    relationForAction,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    stalenessBound,
  });
  return d.decision ? "permit" : (d.context.denial_reason as string);
}

describe("the in-process Mission view resolves containment onto approved entries (@spec containment#selector-matching, #1463)", () => {
  it("a prefix selector over a finer approved entry reaches the PDP as that entry's own removal, which denies authority_contained", async () => {
    const { kernel, id } = approvedMission();
    expect(await decide(kernel, id, LIST)).toBe("permit");
    kernel.contain(id, {
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: NOW.toISOString(), event_id: "evt-view-1" },
      remove: [{ resource: SERVICE, resource_match: "prefix", actions: [LIST] }],
    });
    expect(kernelMissionView(kernel, id)?.containment).toEqual({
      version: 1,
      contained: [{ resource: INV1, actions: [LIST] }],
    });
    expect(await decide(kernel, id, LIST)).toBe("authority_contained");
    expect(await decide(kernel, id, READ)).toBe("permit");
  });
});
