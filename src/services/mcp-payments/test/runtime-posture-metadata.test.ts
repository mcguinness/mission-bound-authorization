import { describe, expect, it } from "vitest";
import { IDEMPOTENCY_SCOPE_DIMENSIONS, isVolatileScopeMember } from "@mission/core";
import { openEphemeralClaimDomain, reversibleWriteControlFor, reversibleWriteDeclarationFor, RUNTIME_POSTURE, stalenessBound } from "@mission/pdp";
import { McpPaymentsServer } from "../src/server.js";
import { TOOL_ACTIONS } from "../src/pep.js";
import { openEphemeralWriteReservationStore } from "../src/write-reservations.js";
import { startResourceMetadataServer, PROTECTED_RESOURCE_METADATA_PATH } from "../src/resource-metadata.js";

describe("runtime posture publication on the resource metadata surface", () => {
  it("publishes the exact validated declaration used by the PDP", async () => {
    const server = new McpPaymentsServer({ writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }), issuer: "https://as.test", jwks: { keys: [] }, keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] } } as never);
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
    const server = new McpPaymentsServer({ writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }), issuer: "https://as.test", jwks: { keys: [] }, keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] } } as never);
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

  // @spec runtime#idempotency (#918): "Outside those classes a deployment MAY
  // scope the guarantee to the reconciliation window, and it MUST publish
  // which posture applies", and the enforcing PEP retains the record "for at
  // least the retention posture the deployment publishes above".
  it("publishes the reservation domain, its owner and the retention posture for every keyed write outside the high-consequence classes", async () => {
    const server = new McpPaymentsServer({ writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }), issuer: "https://as.test", jwks: { keys: [] }, keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] } } as never);
    const listener = await startResourceMetadataServer(() => server);
    try {
      const response = await fetch(`${listener.origin}${PROTECTED_RESOURCE_METADATA_PATH}`);
      const statement = ((await response.json()) as { enforcement_scope_statement: typeof RUNTIME_POSTURE }).enforcement_scope_statement;
      const keyedWrites = Object.values(TOOL_ACTIONS).filter(
        (m) => m.idempotencyKey && !["irreversible_action", "external_commitment", "privileged_administration"].includes(m.actionClass),
      );
      expect(keyedWrites.map((m) => m.action).sort()).toEqual(["payments:payment.schedule", "payments:payment.schedule.cancel"]);
      for (const mapping of keyedWrites) {
        const d = reversibleWriteDeclarationFor(statement, mapping.actionClass, mapping.action);
        expect(d, mapping.action).toBeDefined();
        expect(d?.permit_lifetime_control).toBe("validity_window_plus_idempotency_key");
        expect(d?.permit_validity_max_seconds).toBe(300);
        expect(d?.retention_posture).toBe("declared_horizon");
        expect(d?.retention_horizon).toBe("P7D");
        expect(d?.reservation_owner).toBe("mcp-payments-pep");
        expect(statement.mediated_scope.pep_locations).toContain(d?.reservation_owner);
        expect(d?.reservation_domain).toMatch(/durable single-writer SQLite/);
        expect(d?.idempotency_scope).toEqual([...IDEMPOTENCY_SCOPE_DIMENSIONS]);
      }
      // The PEP runs exactly what is published: a store owned by the
      // published owner is accepted as the domain, and another owner's is not.
      const store = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
      expect(() => new McpPaymentsServer({ issuer: "https://as.test", jwks: { keys: [] }, keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] }, writeReservations: store } as never)).not.toThrow();
      store.close();
    } finally { await listener.close(); }
  });

  // @spec runtime#permit-binding, runtime#single-use-identifiers (#1080, D333):
  // the statement publishes the single-use default, and the PEP runs only a
  // topology in which every consequential_write it serves is enforced.
  it("publishes single_use_decision_identifier as the consequential_write class default the unkeyed hold resolves to, and refuses to start unless every served consequential_write has a supported control, a configured enforcing store and that store's declared owner", async () => {
    const store = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
    const serve = (o: { statement?: unknown; store?: "none" } = {}) =>
      new McpPaymentsServer({
        issuer: "https://as.test",
        jwks: { keys: [] },
        keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
        ...(o.statement ? { enforcementScopeStatement: o.statement } : {}),
        ...(o.store === "none" ? {} : { writeReservations: store }),
      } as never);
    const server = serve();
    const listener = await startResourceMetadataServer(() => server);
    try {
      const response = await fetch(`${listener.origin}${PROTECTED_RESOURCE_METADATA_PATH}`);
      const statement = ((await response.json()) as { enforcement_scope_statement: typeof RUNTIME_POSTURE }).enforcement_scope_statement;
      const served = Object.entries(TOOL_ACTIONS).filter(([, m]) => m.actionClass === "consequential_write");
      expect(served.map(([tool]) => tool).sort()).toEqual(["cancel_scheduled_payment", "hold_transfer", "schedule_payment"]);
      for (const [tool, m] of served) {
        expect(reversibleWriteControlFor(statement, m.actionClass, m.action)?.permit_lifetime_control, tool).toBe(
          m.idempotencyKey ? "validity_window_plus_idempotency_key" : "single_use_decision_identifier",
        );
      }
      expect(reversibleWriteControlFor(statement, "consequential_write", TOOL_ACTIONS.hold_transfer?.action ?? "")).toEqual({
        mediated_class_or_scope: "consequential_write",
        permit_lifetime_control: "single_use_decision_identifier",
        consumed_identifier_domain: expect.stringMatching(/durable single-writer SQLite/),
        consumed_identifier_owner: "mcp-payments-pep",
        retention_posture: "permit_acceptance_window",
      });
    } finally { await listener.close(); }

    /** The shipped statement, edited: its reversible-write declarations are [schedule, cancel, class default]. */
    const edited = (edit: (decls: Array<Record<string, unknown>>, scope: { pep_locations: string[] }) => void) => {
      const s = structuredClone(RUNTIME_POSTURE) as unknown as {
        mediated_scope: { pep_locations: string[] };
        extensions: { reversible_write_idempotency: Array<Record<string, unknown>> };
      };
      edit(s.extensions.reversible_write_idempotency, s.mediated_scope);
      return s;
    };
    // Uncovered: without the class default the hold has no control.
    expect(() => serve({ statement: edited((d) => void d.splice(2, 1)) })).toThrow(
      "no permit-lifetime control declaration covers hold_transfer",
    );
    // No enforcing store configured.
    expect(() => serve({ store: "none" })).toThrow(
      "schedule_payment's validity_window_plus_idempotency_key control has no configured enforcing store",
    );
    // The default's declared owner is another (declared) PEP location.
    expect(() =>
      serve({
        statement: edited((d, scope) => {
          scope.pep_locations.push("another-pep");
          if (d[2]) d[2].consumed_identifier_owner = "another-pep";
        }),
      }),
    ).toThrow("hold_transfer's consumed-identifier domain is owned by another-pep, not mcp-payments-pep");
    // A control the tool's write path does not enforce: a class-wide key
    // default selected for the unkeyed hold, and single use elected by a keyed write.
    expect(() =>
      serve({ statement: edited((d) => void d.splice(2, 1, { ...d[0], mediated_class_or_scope: "consequential_write" })) }),
    ).toThrow("hold_transfer is served on the unkeyed write path, which does not enforce validity_window_plus_idempotency_key");
    expect(() =>
      serve({ statement: edited((d) => void d.splice(0, 1, { ...d[2], mediated_class_or_scope: "payments:payment.schedule" })) }),
    ).toThrow("schedule_payment is served on the keyed write path, which does not enforce single_use_decision_identifier");
    store.close();
  });
});
