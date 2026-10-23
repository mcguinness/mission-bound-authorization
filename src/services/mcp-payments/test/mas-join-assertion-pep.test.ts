/**
 * @spec authority-server#join-authzen, authority-server#join-assertion-request (#1454)
 *
 * The PEP's carriage of a Mission Join Assertion: on a joined request it asks
 * its assertion source for the credential it authenticated
 * (`RequestSignals.accessToken`), and carries the assertion in
 * `context.mission_join` with the credential's digest (`token_sha256`) and
 * exactly one thumbprint, the key its proof of possession verified against
 * (`token_jkt`). No assertion obtained, none of the members is carried.
 */

import type { AuthorityEntry, EvaluationRequest, Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { describe, expect, it } from "vitest";
import {
  accessTokenHash,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type JoinAssertionSource,
  PaymentsStore,
  Pep,
  type TokenFacts,
} from "../src/index.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const ISSUER = "https://mas.test";
const READ = "payments:vendor.read";
const REFERENCE = { id: "msn_1454_pep", issuer: ISSUER };
const ACCESS_TOKEN = "estate-access-token-1454";
const ENTRY: AuthorityEntry = { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [READ] };
const view: MissionView = {
  ...REFERENCE,
  state: "active",
  version: 1,
  authority_hash: "sha-256:h1454",
  authority_set: [ENTRY],
  subject: { iss: "https://idp.test", sub: "alice" },
  client_id: "ap-agent",
};
const TOKEN: TokenFacts = { sub: "alice", clientId: "ap-agent", iss: "https://idp.test", cnfJkt: "jkt-verified" };

/** A PEP whose decision requests are recorded, with `source` as its assertion source. */
function build(source: JoinAssertionSource | undefined) {
  const requests: EvaluationRequest[] = [];
  const payments = new PaymentsStore();
  payments.seed([{ id: "acme", name: "Acme", status: "approved" }], []);
  const pep = new Pep({
    decide: async (request, options) => {
      requests.push(request);
      return EVIDENCE_KEYS.decide(request, options);
    },
    payments,
    evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "unit-test-model",
    loadView: (ref) =>
      ref.id === view.id && ref.issuer === view.issuer
        ? { view, observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
        : undefined,
    instanceEpoch: "epoch-1454",
    masJoin: { resolveOrdinaryAuthority: () => [ENTRY], ...(source ? { assertionSource: source } : {}) },
  });
  return { pep, requests };
}

describe("the PEP carries a Join Assertion with the credential's digest and one thumbprint (@spec authority-server#join-authzen, #1454)", () => {
  it("asks for an assertion for the authenticated credential and carries it with token_sha256 and token_jkt alone", async () => {
    const asked: unknown[] = [];
    const { pep, requests } = build({
      obtain: async (input) => {
        asked.push(input);
        return "header.claims.signature";
      },
    });
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN, undefined, {
      missionReference: REFERENCE,
      accessToken: ACCESS_TOKEN,
    });
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(asked).toEqual([{ mission: REFERENCE, accessToken: ACCESS_TOKEN }]);
    expect(requests).toHaveLength(1);
    const missionJoin = requests[0]?.context.mission_join as Record<string, unknown>;
    expect(missionJoin).toEqual({
      assertion: "header.claims.signature",
      token_sha256: accessTokenHash(ACCESS_TOKEN),
      token_jkt: "jkt-verified",
    });
    // Exactly one thumbprint, matching the credential's confirmation method.
    expect(["token_jkt", "token_x5t"].filter((k) => k in missionJoin)).toEqual(["token_jkt"]);
    // The credential itself never rides the decision request.
    expect(JSON.stringify(requests[0])).not.toContain(ACCESS_TOKEN);
  });

  it("carries none of the assertion members when the source obtains no assertion, or no credential was handed over", async () => {
    const refused = build({ obtain: async () => undefined });
    await refused.pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN, undefined, { missionReference: REFERENCE, accessToken: ACCESS_TOKEN });
    expect(refused.requests[0]?.context.mission_join).toEqual({});

    let called = false;
    const noCredential = build({
      obtain: async () => {
        called = true;
        return "header.claims.signature";
      },
    });
    await noCredential.pep.enforce("lookup_vendor", { vendor_id: "acme" }, TOKEN, undefined, { missionReference: REFERENCE });
    expect(called).toBe(false);
    expect(noCredential.requests[0]?.context.mission_join).toEqual({});
  });
});
