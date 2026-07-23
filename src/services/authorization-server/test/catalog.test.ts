/**
 * M8 service connectivity discovery. Scenario 0 (discovery bootstrap: scoped
 * catalog request, mcp filter, consent_required before any mission) and
 * scenario 10 (catalog reflection: status flips on approval / revocation /
 * expansion without restart; request-access on the out-of-reach service).
 */

import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { CANONICAL_RESOURCE, CATALOG_SERVICES, DERIVATION_POLICY } from "@mission/demo-data";
import { CatalogProvider, MissionKernel, validateMissionIntent } from "../src/index.js";

const ISS = "https://as.test";
const ARS_INTAKE = "https://ars.test/access-requests";

let kernel: MissionKernel;
let catalog: CatalogProvider;

const approveForAlice = (n: number) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Pay Acme", resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: privateKey, statusKid: "as-status" });
  catalog = new CatalogProvider(kernel, CATALOG_SERVICES, { arsIntakeUrl: ARS_INTAKE, issuer: ISS });
});

describe("M8 scenario 0: discovery bootstrap", () => {
  it("a scoped mcp catalog request lists the payments server; no mission -> consent_required", () => {
    const { services } = catalog.catalog("alice", { type: "mcp" });
    const payments = services.find((s) => s.id === "payments");
    expect(payments?.type).toBe("mcp");
    expect(payments?.server_card_uri).toContain("/.well-known/mcp");
    expect(payments?.connections[0]?.status).toBe("consent_required");
    expect(payments?.connections[0]?.authorization_server).toBe(ISS);
  });

  it("filters by category and tag", () => {
    expect(catalog.catalog("alice", { category: "payments" }).services.map((s) => s.id)).toEqual(["payments"]);
    expect(catalog.catalog("alice", { tag: "saas" }).services.map((s) => s.id)).toEqual(["ledgercloud"]);
  });

  it("the out-of-reach service is unavailable and carries a request-access link into the ARS", () => {
    const hr = catalog.catalog("alice").services.find((s) => s.id === "hr-files");
    expect(hr?.connections[0]?.status).toBe("unavailable");
    const link = hr?.links?.find((l) => l.rel === "request-access");
    expect(link?.href).toContain(ARS_INTAKE);
    expect(link?.href).toContain("service=hr-files");
  });
});

describe("M8 scenario 10: catalog reflection (no restart)", () => {
  it("status flips to connected on approval and back to consent_required on revocation", () => {
    const before = catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments");
    expect(before?.connections[0]?.status).toBe("consent_required");

    const mission = approveForAlice(10);
    const afterApproval = catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments");
    expect(afterApproval?.connections[0]?.status).toBe("connected");

    kernel.transition(mission.id, "revoke");
    const afterRevoke = catalog.catalog("alice", { type: "mcp" }).services.find((s) => s.id === "payments");
    expect(afterRevoke?.connections[0]?.status).toBe("consent_required");
  });

  it("status filter returns only services with a matching connection status", () => {
    approveForAlice(11);
    const connected = catalog.catalog("alice", { status: "connected" }).services.map((s) => s.id);
    expect(connected).toContain("payments");
    expect(connected).not.toContain("hr-files");
  });
});
