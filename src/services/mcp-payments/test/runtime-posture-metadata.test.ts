import { describe, expect, it } from "vitest";
import { IDEMPOTENCY_SCOPE_DIMENSIONS, isVolatileScopeMember } from "@mission/core";
import { openEphemeralClaimDomain, RUNTIME_POSTURE, stalenessBound } from "@mission/pdp";
import { McpPaymentsServer } from "../src/server.js";
import { startResourceMetadataServer, PROTECTED_RESOURCE_METADATA_PATH } from "../src/resource-metadata.js";

describe("runtime posture publication on the resource metadata surface", () => {
  it("publishes the exact validated declaration used by the PDP", async () => {
    const server = new McpPaymentsServer({ issuer: "https://as.test", jwks: { keys: [] } } as never);
    const metadata = server.protectedResourceMetadata();
    expect(metadata.enforcement_scope_statement).toBe(RUNTIME_POSTURE);
    expect(JSON.parse(JSON.stringify(metadata)).enforcement_scope_statement.state_source.per_class.irreversible_action.max_staleness_seconds).toEqual((stalenessBound("irreversible_action") as { seconds: number }).seconds);
    const listener = await startResourceMetadataServer(() => server);
    try {
      const response = await fetch(`${listener.origin}${PROTECTED_RESOURCE_METADATA_PATH}`);
      expect(response.status).toBe(200);
      const published = await response.json() as Record<string, unknown>;
      expect(published.enforcement_scope_statement).toEqual(RUNTIME_POSTURE);
    } finally { await listener.close(); }
  });

  // @spec runtime#idempotency (#917): "The deployment MUST name the Exact
  // claim domain per mediated action class or idempotency scope in its
  // Enforcement Scope Statement, not as an enumeration of individual dynamic
  // claims", and "MUST publish the scope".
  it("publishes the Exact claim domain per high-consequence class, its scope and horizon, and the reconciliation window", async () => {
    const server = new McpPaymentsServer({ issuer: "https://as.test", jwks: { keys: [] } } as never);
    const listener = await startResourceMetadataServer(() => server);
    try {
      const response = await fetch(`${listener.origin}${PROTECTED_RESOURCE_METADATA_PATH}`);
      const statement = ((await response.json()) as { enforcement_scope_statement: typeof RUNTIME_POSTURE }).enforcement_scope_statement;
      const declarations = statement.extensions?.transaction_assurance ?? [];
      const highConsequence = statement.mediated_scope.action_classes.filter((c) =>
        ["irreversible_action", "external_commitment", "privileged_administration"].includes(c),
      );
      // One declaration per mediated class, keyed by the class, never by a key.
      expect(declarations.map((d) => d.mediated_class_or_scope).sort()).toEqual([...highConsequence].sort());
      for (const d of declarations) {
        expect(statement.pdps).toEqual([d.idempotency_claim_owner]);
        expect(d.idempotency_enforcement_profile).toBe("exact");
        expect(d.idempotency_claim_topology).toBe("local-single-writer");
        expect(d.idempotency_scope).toEqual([...IDEMPOTENCY_SCOPE_DIMENSIONS]);
        expect((d.idempotency_scope ?? []).some(isVolatileScopeMember)).toBe(false);
        expect(d.idempotency_horizon_seconds).toBe(604800);
      }
      expect(statement.extensions?.outcome_reconciliation).toEqual({
        window: "PT15M",
        responsible_component: "mcp-payments-pep",
        alerting: expect.any(String),
      });
      // The PDP runs exactly what is published: the statement opens as its domain.
      expect(() => openEphemeralClaimDomain({ owner: statement.pdps[0] as string, statement }).close()).not.toThrow();
    } finally { await listener.close(); }
  });
});
