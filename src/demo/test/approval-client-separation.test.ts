import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as client from "../src/oauth-client.js";

describe("agent OAuth client has no approval-resolution capability (#759)", () => {
  it("exports only client-side submission and redemption, with no approver credential or callback", () => {
    for (const name of ["issueMissionToken", "completeMissionApproval", "denyMissionApproval", "resolveMissionApproval"]) expect(name in client).toBe(false);
    const source = readFileSync(new URL("../src/oauth-client.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/approval-console|x-service-token|approverServiceToken|\/decide/);
    expect(typeof client.submitMissionApproval).toBe("function");
    expect(typeof client.redeemMissionApproval).toBe("function");
  });
});
