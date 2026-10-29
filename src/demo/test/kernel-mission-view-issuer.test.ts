/**
 * @spec control-plane#isolation (#1748): the in-process Mission loaders of the
 * stack and the MAS pilot resolve a Mission reference through
 * `kernelMissionViewFor`, which answers only under the reference's own issuer.
 * A reference naming another issuer resolves nothing, even for a local
 * identifier this kernel holds, so a foreign Mission never reaches the PEP's
 * state keyed by the bare identifier.
 */

import { MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { kernelMissionViewFor } from "../src/kernel-mission-view.js";

const ISS = "https://as.view-issuer.test";
const OTHER = "https://as.other-issuer.test";
const INV1 = "https://payments.test/mcp/invoices/inv-1";
const READ = "payments:invoice.read";
const NOW = new Date("2026-10-27T12:00:00Z");

let statusKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: statusKey } = (await generateKeyPair("ES256", { extractable: true })) as { privateKey: CryptoKey });
});

function approvedMission() {
  const ceiling = [{ type: "mission_resource_access", resource: INV1, actions: [READ] }];
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "view-issuer-1748", ceiling } as never,
    authoritySourceCatalog: {
      humanPrincipals: [],
      entries: [{ id: "view-issuer", type: "user_delegated", clients: ["ap-agent"], activators: ["bob"], ceiling }],
    } as never,
    statusKey,
    statusKid: "view-issuer-status",
    now: () => NOW,
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read invoice 1", target_resources: [INV1], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: INV1, actions: [READ] }],
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "apev-view-issuer-1748",
  });
  return { kernel, id: mission.id };
}

describe("the kernel Mission loader resolves a reference only under its own issuer (@spec control-plane#isolation, #1748)", () => {
  it("resolves the Mission under its issuer, and nothing for the same local identifier under another issuer", () => {
    const { kernel, id } = approvedMission();
    const view = kernelMissionViewFor(kernel, { id, issuer: ISS });
    expect(view?.id).toBe(id);
    expect(view?.issuer).toBe(ISS);
    expect(kernelMissionViewFor(kernel, { id, issuer: OTHER })).toBeUndefined();
  });
});
