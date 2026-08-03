/**
 * @spec harness#mediated-egress
 *
 * The execution-environment scope statement. Proves the claim-gated
 * completeness rule: a compromise-resistant config MUST enumerate every channel
 * class (and its signed statement verifies + tamper-detects), a single-process
 * in-memory config emits the honest "no mediation claim" form without asserting
 * full enumeration, and a containment claim that omits a class is rejected.
 */

import { generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  buildScopeStatement,
  CHANNEL_CLASSES,
  type ChannelClassStatement,
  type ScopeStatementConfig,
  signScopeStatement,
  verifyScopeStatement,
} from "../src/harness-scope.js";

const COMPROMISE_RESISTANT: ScopeStatementConfig = {
  isolation_mechanism: "gVisor sandbox + egress-deny network policy",
  transport: "http",
  containment_claim: "agent_compromise_resistant",
  mediated_action_classes: ["payments:payment.execute"],
  excluded_unmediated_paths: ["debug shell", "direct network socket"],
  channel_classes: [
    { channel_class: "dns_resolution", disposition: "mediated" },
    { channel_class: "log_error_output", disposition: "excluded" },
    { channel_class: "shared_stores", disposition: "excluded" },
    { channel_class: "shared_vector_stores", disposition: "outside_claim" },
    { channel_class: "spawned_os_processes", disposition: "excluded" },
    { channel_class: "provider_model_context", disposition: "outside_claim" },
    { channel_class: "inference_api", disposition: "mediated" },
    { channel_class: "remote_ref_rendering", disposition: "mediated" },
  ],
};

describe("harness scope statement: compromise-resistant claim enumerates every channel class", () => {
  it("emits a disposition for every channel class and marks the enumeration complete", () => {
    const stmt = buildScopeStatement(COMPROMISE_RESISTANT);
    expect(stmt.claims_containment).toBe(true);
    expect(stmt.channel_enumeration).toBe("complete");
    // Every channel class is present with a valid disposition (the MUST branch).
    expect([...stmt.channel_classes].map((c) => c.channel_class).sort()).toEqual([...CHANNEL_CLASSES].sort());
    for (const cc of CHANNEL_CLASSES) {
      const entry = stmt.channel_classes.find((c) => c.channel_class === cc);
      expect(entry).toBeDefined();
      expect(["mediated", "excluded", "outside_claim"]).toContain(entry?.disposition);
    }
  });

  it("signs and verifies round-trip; a mutated statement fails verification", async () => {
    const stmt = buildScopeStatement(COMPROMISE_RESISTANT);
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const jws = await signScopeStatement(stmt, { key: privateKey, kid: "harness-1", iss: "https://harness.test" });

    const verified = await verifyScopeStatement(jws, publicKey);
    expect(verified).toEqual(stmt);

    // Tamper: rewrite a disposition inside the signed payload without re-signing.
    const parts = jws.split(".");
    const payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8"));
    payload.scope_statement.channel_classes[0].disposition = "outside_claim";
    const tampered = `${parts[0]}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${parts[2]}`;
    await expect(verifyScopeStatement(tampered, publicKey)).rejects.toThrow();
  });
});

describe("harness scope statement: single-process cannot claim agent-compromise-resistant containment", () => {
  it("downgrades an in-memory config to the honest no-claim form", () => {
    const stmt = buildScopeStatement({
      isolation_mechanism: "in-memory MCP transport (single process)",
      transport: "in_memory",
      // Even if a caller requests it, a single-process transport cannot claim it.
      containment_claim: "agent_compromise_resistant",
      mediated_action_classes: ["payments:payment.execute"],
    });
    expect(stmt.requested_containment_claim).toBe("agent_compromise_resistant");
    expect(stmt.containment_claim).toBe("none"); // downgraded
    expect(stmt.claims_containment).toBe(false);
    // Honest form: no full-enumeration assertion; classes carry "no mediation claim".
    expect(stmt.channel_enumeration).toBe("partial");
    for (const c of stmt.channel_classes) {
      expect(c.disposition).toBe("outside_claim");
    }
  });
});

describe("harness scope statement: a containment claim that omits a class is rejected", () => {
  it("throws when a trifecta claim does not enumerate every channel class", () => {
    const partial: ChannelClassStatement[] = CHANNEL_CLASSES.slice(0, -1).map((channel_class) => ({
      channel_class,
      disposition: "mediated",
    }));
    expect(() =>
      buildScopeStatement({
        isolation_mechanism: "container + egress policy",
        transport: "http",
        containment_claim: "trifecta",
        mediated_action_classes: ["payments:payment.execute"],
        channel_classes: partial,
      }),
    ).toThrow(/omits channel class/);
  });

  it("throws when a containment claim names no mediated action class (non-vacuous)", () => {
    const full: ChannelClassStatement[] = CHANNEL_CLASSES.map((channel_class) => ({
      channel_class,
      disposition: "mediated",
    }));
    expect(() =>
      buildScopeStatement({
        isolation_mechanism: "container + egress policy",
        transport: "http",
        containment_claim: "trifecta",
        channel_classes: full,
      }),
    ).toThrow(/names no mediated action class/);
  });
});
