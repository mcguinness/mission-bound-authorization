/**
 * @spec draft-mcguinness-mission-runtime.md#record-integrity,
 * draft-mcguinness-mission-runtime.md#failure-modes (#821, D814): the PDP's
 * Decision Evidence sequence and its emission failures, at the decision
 * endpoint (`evaluate()`), as the PDP.
 *
 * The emitter takes its sequence from the PDP's claim domain on a real file
 * (`IdempotencyClaimDomain.evidenceSequences`), as the composed stack binds it.
 * A restart is the claim domain closed and reopened on the same file under a
 * new emitter with a new per-boot key. A stub `Fga` satisfies the one method
 * evaluate() calls, so this file never skips.
 */

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  DecisionRequestRefused,
  evaluate,
  type EvaluateOptions,
  type EvaluationRequest,
  type IdempotencyClaimDomain,
  type MissionView,
  openIdempotencyClaimDomain,
  relationForAction,
  stalenessBound,
} from "../src/index.js";
import { RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { CLAIM_OWNER } from "./claim-fixture.js";
import { withCredential } from "./with-credential.js";

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const NOW = new Date("2026-10-25T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const tempClaimsFile = (): string => join(mkdtempSync(join(tmpdir(), "pdp-sequence-endpoint-")), "claims.sqlite");

const view = (id: string): MissionView => ({
  id,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

const req = (missionId: string, context: Record<string, unknown> = {}): EvaluationRequest =>
  withCredential({
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: { name: "payments:invoice.read" },
    context: { mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:testhash" }, ...context },
  });

function openClaims(file: string): IdempotencyClaimDomain {
  return openIdempotencyClaimDomain({ file, owner: CLAIM_OWNER, statement: RUNTIME_POSTURE });
}

/** One PDP boot over a claim domain: a fresh per-boot key, as the composed stack generates. */
function boot(claims: IdempotencyClaimDomain, signer?: { kid: string; key: KeyObject }, extra: Partial<EvaluateOptions> = {}) {
  const emitter = createDecisionEvidenceEmitter({
    signer: signer ?? { kid: "pdp-decision-evidence", key: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey },
    emitterId: RESOURCE,
    audience: RESOURCE,
    sequences: claims.evidenceSequences(),
  });
  return async (missionId: string, context: Record<string, unknown> = {}) => {
    const decision = await evaluate(req(missionId, context), {
      view: view(missionId),
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      now: () => NOW,
      stalenessBound,
      relationForAction,
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      evidence: emitter,
      ...extra,
    } as EvaluateOptions);
    return decision;
  };
}

const sequenceOf = (decision: { context: Record<string, unknown> }) =>
  (decision.context.decision_evidence as DecisionEvidenceObject).sequence;

describe("the PDP's Decision Evidence sequence at the decision endpoint (@spec runtime#record-integrity, #821)", () => {
  it("a PDP restarted on the same claim file continues each Mission's sequence, and no value is issued twice across a failed signing or the restart", async () => {
    const file = tempClaimsFile();
    const first = openClaims(file);
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    let failSigning = false;
    const signer = {
      kid: "pdp-decision-evidence",
      get key(): KeyObject {
        if (failSigning) throw new Error("signer unavailable");
        return pair.privateKey;
      },
    };
    const before = boot(first, signer);
    const issued = [sequenceOf(await before("msn_a")), sequenceOf(await before("msn_a"))];
    failSigning = true;
    await expect(before("msn_a")).rejects.toThrow(/signer unavailable/);
    failSigning = false;
    issued.push(sequenceOf(await before("msn_a")));
    first.close(); // the process dies

    const reopened = openClaims(file);
    try {
      const after = boot(reopened);
      issued.push(sequenceOf(await after("msn_a")), sequenceOf(await after("msn_a")));
      // Strictly increasing across the failed signing and the restart, so no
      // value is issued twice; a value the failure consumed is a gap.
      expect(issued.slice(0, 2)).toEqual([0, 1]);
      for (let i = 1; i < issued.length; i += 1) expect(issued[i]).toBeGreaterThan(issued[i - 1] as number);
      // Another Mission's stream is its own.
      expect(sequenceOf(await after("msn_b"))).toBe(0);
    } finally {
      reopened.close();
    }
  });
});

describe("a PDP that cannot emit a required record issues no decision (@spec runtime#failure-modes, #821)", () => {
  it("a decision whose Decision Evidence cannot be emitted is not issued: evaluate() rejects when the sequence source is unreachable or the signature fails", async () => {
    const claims = openClaims(tempClaimsFile());
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    let failSigning = false;
    const decide = boot(claims, {
      kid: "pdp-decision-evidence",
      get key(): KeyObject {
        if (failSigning) throw new Error("signer unavailable");
        return pair.privateKey;
      },
    });
    expect((await decide("msn_down")).decision).toBe(true);
    failSigning = true;
    await expect(decide("msn_down")).rejects.toThrow(/signer unavailable/);
    failSigning = false;
    claims.close(); // the durable sequence source becomes unreachable
    await expect(decide("msn_down")).rejects.toThrow();
  });

  it("a request the PDP refuses before evaluation stays refused when its Refusal Record cannot be recorded: no decision is issued", async () => {
    const claims = openClaims(tempClaimsFile());
    try {
      let attempted = 0;
      const decide = boot(claims, undefined, {
        refusals: () => {
          attempted += 1;
          throw new Error("refusal store unavailable");
        },
      });
      // A malformed work item is refused before evaluation (`work_item_invalid`).
      await expect(decide("msn_refused", { work_item: { issuer: 7 } })).rejects.toBeInstanceOf(DecisionRequestRefused);
      expect(attempted).toBe(1);
    } finally {
      claims.close();
    }
  });
});
