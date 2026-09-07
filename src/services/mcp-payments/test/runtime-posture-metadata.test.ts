import { describe, expect, it } from "vitest";
import { RUNTIME_POSTURE, stalenessBound } from "@mission/pdp";
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
});
