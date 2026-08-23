/**
 * @spec runtime#pep-placement, runtime#rs-runtime-profile, runtime#classification,
 * runtime#action-approval, runtime#decision, runtime#security-considerations,
 * runtime#token-validation
 *
 * Wave 2 slice B (#594): the remaining PEP/RS-facing fail-closed rows for
 * draft-mcguinness-mission-runtime.md that slice A's PDP-only unit tests
 * could not exercise (they name a PEP or RS behavior, not evaluate()'s pure
 * decision function). Every test here is UNCONDITIONAL: `poisonFga` throws
 * if invoked (proving a denial was reached without ever consulting FGA) and
 * `alwaysAllowFga` (the same stub `evaluate-decision.test.ts` uses at the PDP
 * layer) stands in for a live OpenFGA connection wherever a real permit is
 * needed, so none of this file's coverage depends on the OpenFGA-reachability
 * gate the *.test.ts files with a live PDP use.
 */

import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { describe, expect, it } from "vitest";
import type { Fga, MissionView } from "@mission/pdp";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  Connectors,
  createMediatedClient,
  EvidenceStore,
  McpPaymentsServer,
  parameterDigest,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  TransactionEngine,
  type ActionApprovalInput,
  type TokenFacts,
} from "../src/index.js";

const ISSUER = "https://as.test";

/** Proves a denial was reached WITHOUT ever consulting FGA. */
const poisonFga = {
  checkWithContext: async () => {
    throw new Error("fga should not have been called on this path");
  },
} as unknown as Fga;

/** Stands in for a live, permissive OpenFGA authority check (same pattern as
 * evaluate-decision.test.ts's `alwaysAllowFga`, one layer up in the stack). */
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_test", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
  cnfJkt: "jkt-1",
};

function view(actions: string[], overrides: Partial<MissionView["authority_set"][number]> = {}): MissionView {
  return {
    id: "msn_test",
    issuer: ISSUER,
    state: "active",
    version: 1,
    authority_hash: "sha-256:testhash",
    authority_set: actions.length
      ? [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, ...overrides }]
      : [],
    subject: { iss: ISSUER, sub: "alice" },
    client_id: "ap-agent",
  };
}

/** A fresh, fully composed stack (core + transaction tier) over one seeded invoice. */
function buildStack(missionView: MissionView, fga: Fga) {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const evidence = new EvidenceStore();
  const connectors = new Connectors();
  const engine = new TransactionEngine("epoch-1");
  const card = { name: "payments" };
  // @spec runtime#state-freshness: a synchronous live read, freshness-
  // stamped at this read (Finding 1); "load_view" declared trusted below.
  const loadView = (ref: { id: string }) =>
    ref.id === missionView.id
      ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf(card),
    allowedFreshnessSources: new Set(["load_view"]),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    issuer: ISSUER,
    serverCard: card,
    transaction: { engine, connectors, evidence },
  });
  return { payments, evidence, connectors, engine, pep, server };
}

describe("a tool-catalog filter is not a substitute for the runtime gate (@spec runtime#pep-placement)", () => {
  it("a tool absent from tools/list because it is ungranted is still refused by the runtime gate when called directly, never executed", async () => {
    const { server, connectors } = buildStack(view(["payments:invoice.read"]), poisonFga);

    const tools = server.toolsList(TOKEN).map((t) => t.name);
    expect(tools).not.toContain("execute_wire_transfer");

    // Calling it anyway reaches the SAME runtime gate as a listed tool would,
    // not a side door: refused, zero ledger effect, FGA never consulted
    // (poisonFga would throw if the gate were bypassed into an FGA check).
    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
    expect(res.result).toBeUndefined();
    expect(connectors.ledgerEntries()).toHaveLength(0);
  });
});

describe("the PEP sits at the last controllable boundary before the action (@spec runtime#pep-placement)", () => {
  it("a parameter change in the window between decision and connector commit is caught immediately before commit, not upstream of it", async () => {
    const { server, payments, connectors } = buildStack(view(["payments:payment.execute"]), alwaysAllowFga);

    const res = await server.callTransactionTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1" },
      TOKEN,
      () => payments.bumpInvoiceAmount("inv-1", "999.00"), // mutate exactly in the decision->commit window
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("parameter_mismatch");
    // Nothing committed: the boundary that catches the race sits right before
    // the connector, not at some earlier point that a post-decision change
    // could still slip past.
    expect(connectors.ledgerEntries()).toHaveLength(0);
  });
});

describe("every consequential operation passes through a PEP that can refuse it after token validation and before execution (@spec runtime#rs-runtime-profile)", () => {
  it("a denied consequential operation never executes: zero connector side effects", async () => {
    const { server, connectors } = buildStack(view([]), poisonFga);
    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.result).toBeUndefined();
    expect(connectors.ledgerEntries()).toHaveLength(0);
  });

  it("a permitted consequential operation is preceded by an actual PDP decision, not a bypass into a permit", async () => {
    const { server, evidence, connectors } = buildStack(view(["payments:payment.execute"]), alwaysAllowFga);
    const res = await server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(connectors.ledgerEntries()).toHaveLength(1);
    expect(
      evidence.all().some((e) => e.kind === "decision" && e.decision === true && e.action === "payments:payment.execute"),
    ).toBe(true);
  });
});

describe("high-consequence actions are always gated by a PDP permit, never left ungated by classification (@spec runtime#classification)", () => {
  it("execute_wire_transfer (irreversible_action) always reaches a PDP decision: refused without authority, permitted-with-decision-evidence with it", async () => {
    const denied = buildStack(view([]), poisonFga);
    const deny = await denied.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(deny.ok).toBe(false);
    expect(deny.result).toBeUndefined();

    const granted = buildStack(view(["payments:payment.execute"]), alwaysAllowFga);
    const permit = await granted.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(permit.ok, JSON.stringify(permit)).toBe(true);
    const dec = granted.evidence.all().find((e) => e.kind === "decision" && e.decision === true);
    expect(dec?.action).toBe("payments:payment.execute");
  });

  it("send_remittance_email (external_commitment) always reaches a PDP decision: refused without authority, permitted-with-decision-evidence with it", async () => {
    const denied = buildStack(view([]), poisonFga);
    const deny = await denied.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN);
    expect(deny.ok).toBe(false);
    expect(deny.result).toBeUndefined();

    const granted = buildStack(view(["payments:remittance.send"]), alwaysAllowFga);
    const permit = await granted.server.callTransactionTool("send_remittance_email", { invoice_id: "inv-1" }, TOKEN);
    expect(permit.ok, JSON.stringify(permit)).toBe(true);
    const dec = granted.evidence.all().find((e) => e.kind === "decision" && e.decision === true);
    expect(dec?.action).toBe("payments:remittance.send");
  });
});

describe("an action-bound approval is reverified against the concrete parameters, and a parameter change after approval invalidates it (@spec runtime#action-approval)", () => {
  it("an approval whose digest matched the parameters at approval time no longer satisfies the gate once the record changes underneath it", async () => {
    const { pep, payments, connectors } = buildStack(
      view(["payments:payment.schedule"], { constraints: { requires_action_approval: true } }),
      alwaysAllowFga,
    );
    const invoice = payments.getInvoice("inv-1");
    const vendor = invoice ? payments.getVendor(invoice.vendor_id) : undefined;
    if (!invoice || !vendor) throw new Error("seed fixture missing");
    const effective = buildEffectiveParams({ action: "payments:payment.schedule", invoice, vendor, resource: CANONICAL_RESOURCE });
    const approval: ActionApprovalInput = {
      id: "apr_1",
      approved_at: new Date().toISOString(),
      parameter_digest: parameterDigest(effective),
    };

    // The approval matches the CURRENT record: the gate is satisfied.
    const before = await pep.enforce("schedule_payment", { invoice_id: "inv-1" }, TOKEN, approval);
    expect(before.permitted, JSON.stringify(before)).toBe(true);

    // Reparameterization: the record changes after approval. The SAME
    // approval object is presented again, unchanged -- it is its OWN digest,
    // now stale against the freshly recomputed parameters, that invalidates
    // it on this re-decide. (This is the re-decide arm only: pep.enforce()
    // never executes anything by itself, so this does not exercise
    // pep.reverify()'s TOCTOU-at-time-of-use check against the approval --
    // no public server API drives an approval-gated action through that
    // two-phase path; see the manifest row's notes.)
    payments.bumpInvoiceAmount("inv-1", "999.00");
    const after = await pep.enforce("schedule_payment", { invoice_id: "inv-1" }, TOKEN, approval);
    expect(after.permitted).toBe(false);
    expect(after.denial_reason).toBe("action_approval_required");
    // Nothing executed on either call: enforce() alone never commits an
    // effect, on a permit or a deny.
    expect(connectors.ledgerEntries()).toHaveLength(0);
  });
});

describe("a PDP deny is terminal for the attempted action: no execution, and no proceeding on an earlier permit once the decision changes (@spec runtime#decision)", () => {
  it("a previously issued permit is never consulted by a later call: authority withdrawn denies afresh and the action never executes", async () => {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    const evidence = new EvidenceStore();
    let current: MissionView = view(["payments:invoice.read"]);
    const pep = new Pep({
      payments,
      evidence,
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      // @spec runtime#state-freshness: re-reads `current` (the mutable
      // binding below) at each call, so a withdrawal is observed as a fresh
      // read, never a stale cached one (Finding 1).
      loadView: () => ({ view: current, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }),
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
      allowedFreshnessSources: new Set(["load_view"]),
    });

    // A genuine permit exists for this exact action, held only as a local
    // variable -- there is no API on Pep or McpPaymentsServer that accepts a
    // caller-supplied prior decision; every call re-derives one.
    const permitted = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(permitted.permitted, JSON.stringify(permitted)).toBe(true);
    expect((permitted.decision?.context.conditions as { valid_until?: string } | undefined)?.valid_until).toBeDefined();

    // Authority withdrawn: the SAME loadView now resolves to an entry-less
    // view. The fresh evaluation denies, and this attempt has nothing to
    // execute -- the held prior permit above is never reached again.
    current = view([]);
    const after = await pep.enforce("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(after.permitted).toBe(false);
    expect(after.denial_reason).toBe("out_of_authority");
  });
});

describe("a decision bound to one resource is never honored at another (@spec runtime#security-considerations, Confused Deputy Across Resources)", () => {
  it("an authority entry scoped to a different resource is never matched at this resource's boundary, and FGA is never consulted for it", async () => {
    const elsewhere = view(["payments:invoice.read"]);
    elsewhere.authority_set = [{ ...elsewhere.authority_set[0]!, resource: "https://elsewhere.example.com/mcp" }];
    const { server } = buildStack(elsewhere, poisonFga);

    // Same action, same subject; only the entry's resource differs from this
    // boundary's CANONICAL_RESOURCE. The decision's audience/resource match
    // refuses it outright rather than relaxing to an audience-agnostic match.
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("out_of_authority");
  });
});

describe("the PEP establishes token validity before using any of its claims as decision inputs (@spec runtime#token-validation)", () => {
  async function buildTokenValidationServer(pubJwk: Record<string, unknown>) {
    const payments = new PaymentsStore();
    const evidence = new EvidenceStore();
    const pep = new Pep({
      payments,
      evidence,
      fga: poisonFga,
      modelId: "unit-test-model",
      loadView: () => undefined,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView: () => undefined,
      jwks: { keys: [pubJwk] },
      issuer: ISSUER,
      serverCard: { name: "payments" },
    });
    return { server, evidence };
  }

  it("a token signed by an untrusted key is refused outright, before any of its mission/cnf claims are used", async () => {
    const trusted = await generateKeyPair("ES256", { extractable: true });
    const untrusted = await generateKeyPair("ES256", { extractable: true });
    const pubJwk = { ...(await exportJWK(trusted.publicKey)), kid: "mission-key", alg: "ES256" };
    const { server } = await buildTokenValidationServer(pubJwk);

    // A well-formed, plausible payload -- signed by the WRONG key.
    const forged = await new SignJWT({
      sub: "alice",
      client_id: "ap-agent",
      cnf: { jkt: "jkt-1" },
      mission: { id: "msn_test", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    })
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(untrusted.privateKey);

    await expect(server.validateMissionToken(forged)).rejects.toThrow();
  });

  it("a token whose audience does not name this resource is refused, before any of its claims reach a decision (@spec runtime#token-validation, audience)", async () => {
    const kp = await generateKeyPair("ES256", { extractable: true });
    const pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
    const { server } = await buildTokenValidationServer(pubJwk);

    const wrongAudience = await new SignJWT({
      sub: "alice",
      client_id: "ap-agent",
      cnf: { jkt: "jkt-1" },
      mission: { id: "msn_test", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    })
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience("https://other-resource.example.com/mcp") // NOT this resource
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(kp.privateKey);

    await expect(server.validateMissionToken(wrongAudience)).rejects.toThrow();
  });

  it("a token missing the mission claim is refused at the channel before any PDP decision is requested, with zero evidence produced", async () => {
    const kp = await generateKeyPair("ES256", { extractable: true });
    const pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
    const { server, evidence } = await buildTokenValidationServer(pubJwk);
    const { client } = await createMediatedClient(server);

    const noMission = await new SignJWT({ sub: "alice", client_id: "ap-agent", cnf: { jkt: "jkt-1" } }) // no `mission` claim
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(kp.privateKey);

    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" }, noMission);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("invalid_credential");
    // Never asked the PDP for a decision: no decision (or any) evidence
    // exists, so the refusal happened strictly before runtime Mission
    // evaluation, not as an evaluate() outcome.
    expect(evidence.all()).toHaveLength(0);
    await client.close();
  });
});
