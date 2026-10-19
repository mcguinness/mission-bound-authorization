/**
 * @spec child-delegation#request-processing step 4 (#1326): a child that a
 * client other than its parent's own created before the step-4 check existed
 * is revoked when the AS is built, while its creation operation is retained,
 * so its grant and every credential derived from it are refused. The child
 * record names no creating client; the retained creation operation is the
 * link. A file-backed kernel keeps both across the rebuild.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import { buildAuthorizationServer, type BuiltAs, createChildMission, validateMissionIntent } from "../src/index.js";

const ISSUER = "http://localhost:14833";
const FAR_EXP = "2099-01-01T00:00:00Z";

const intent = (goal: string) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [CANONICAL_RESOURCE], expires_at: FAR_EXP }));

const authority = () => [
  {
    type: "mission_resource_access",
    resource: CANONICAL_RESOURCE,
    actions: ["payments:invoice.read"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

const build = (file: string): Promise<BuiltAs> =>
  buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true, kernelStore: { file } });

describe("child remediation at build (@spec child-delegation#request-processing step 4, #1326)", () => {
  it("building the AS revokes a retained child another client created, and leaves the parent's own child active", async () => {
    const file = join(mkdtempSync(join(tmpdir(), "child-remediation-")), "kernel.db");
    const first = await build(file);
    const parent = first.kernel.approve({
      intent: intent("Pay Acme invoices"),
      proposedAuthority: authority() as never,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `remediation-${crypto.randomUUID()}`,
    });
    /** A child of `parent` whose retained creation operation names `clientId`. */
    const child = (clientId: string): string =>
      first.creationIdempotency.createCompleted(
        {
          clientId,
          creationRequestId: crypto.randomUUID(),
          op: "child-creation",
          fingerprint: "seeded",
          cnfJkt: "seeded",
          sourceMissionId: parent.id,
        },
        () => {
          const created = createChildMission(first.kernel, {
            parentId: parent.id,
            intent: intent("Extract Acme invoices"),
            proposedAuthority: authority() as never,
            childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
          }).child;
          return { missionId: created.id, value: created.id };
        },
      );
    const own = child("ap-agent");
    const other = child("test-carryover-child");
    expect(first.kernel.get(other)?.state).toBe("active");
    first.kernel.db.close();

    const second = await build(file);
    try {
      expect(second.kernel.get(other)?.state).toBe("terminated");
      expect(second.kernel.get(other)?.termination?.reason).toBe("revoked");
      expect(second.kernel.get(own)?.state).toBe("active");
      expect(second.kernel.get(parent.id)?.state).toBe("active");
    } finally {
      second.kernel.db.close();
    }
  });
});
