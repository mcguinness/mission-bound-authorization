/**
 * @spec authority-server#mission-join (#557)
 *
 * `McpPaymentsServer.validateOrdinaryToken`: the same issuer/audience/
 * cnf.jkt/DPoP-proof checks `validateToken` performs, but for a credential
 * carrying NO `mission` claim at all. `validateToken` itself is UNCHANGED
 * and still rejects such a credential outright. FGA-independent: neither
 * method calls the PDP.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { CANONICAL_RESOURCE, dpopProofFor, McpPaymentsServer, PaymentsStore, type DpopKeys } from "../src/index.js";

const ISSUER = "https://as.test";
const HTU = CANONICAL_RESOURCE;
const HTM = "POST";

let signKey: CryptoKey;
let pubJwk: Record<string, unknown>;
let dpopKeys: DpopKeys;
let cnfJkt: string;
let server: McpPaymentsServer;

async function signToken(overrides: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({
    client_id: "ordinary-agent",
    cnf: { jkt: cnfJkt },
    ...overrides,
  })
    .setProtectedHeader({ alg: "ES256", kid: "as-key" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signKey);
}

beforeAll(async () => {
  const kp = await generateKeyPair("ES256", { extractable: true });
  signKey = kp.privateKey;
  pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "as-key", alg: "ES256" };
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  cnfJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
  server = new McpPaymentsServer({
    pep: undefined as never, // never invoked by token validation alone
    payments: new PaymentsStore(),
    loadView: () => undefined,
    jwks: { keys: [pubJwk as never] },
    issuer: ISSUER,
    serverCard: { name: "payments" },
  });
});

describe("validateOrdinaryToken (@spec authority-server#mission-join #557)", () => {
  it("returns TokenFacts with mission absent for a valid credential carrying no mission claim", async () => {
    const token = await signToken();
    const proof = await dpopProofFor(dpopKeys, HTU, HTM, token);
    const facts = await server.validateOrdinaryToken(token, proof, HTU, HTM);
    expect(facts.sub).toBe("alice");
    expect(facts.clientId).toBe("ordinary-agent");
    expect(facts.iss).toBe(ISSUER);
    expect(facts.mission).toBeUndefined();
    expect(facts.cnfJkt).toBe(cnfJkt);
  });

  it("still verifies the DPoP proof-of-possession: a proof over the wrong key is rejected", async () => {
    const token = await signToken();
    const wrongKeys = await generateKeyPair("ES256", { extractable: true });
    const badProof = await dpopProofFor(wrongKeys, HTU, HTM, token);
    await expect(server.validateOrdinaryToken(token, badProof, HTU, HTM)).rejects.toThrow();
  });

  it("still refuses a token with no cnf.jkt at all", async () => {
    const token = await new SignJWT({ client_id: "ordinary-agent" })
      .setProtectedHeader({ alg: "ES256", kid: "as-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setSubject("alice")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signKey);
    const proof = await dpopProofFor(dpopKeys, HTU, HTM, token);
    await expect(server.validateOrdinaryToken(token, proof, HTU, HTM)).rejects.toThrow(/cnf\.jkt/);
  });

  it("does NOT reject a token that additionally carries a mission claim (validateOrdinaryToken never requires its absence)", async () => {
    const token = await signToken({ mission: { id: "msn-1", issuer: ISSUER } });
    const proof = await dpopProofFor(dpopKeys, HTU, HTM, token);
    const facts = await server.validateOrdinaryToken(token, proof, HTU, HTM);
    expect(facts.mission).toBeUndefined(); // never surfaced by this validator either way
  });
});

describe("validateToken is unchanged: still rejects a credential with no mission claim (@spec authority-server#mission-join #557)", () => {
  it("rejects outright, exactly as before masJoin existed", async () => {
    const token = await signToken();
    const proof = await dpopProofFor(dpopKeys, HTU, HTM, token);
    await expect(server.validateToken(token, proof, HTU, HTM)).rejects.toThrow(/mission claim/);
  });
});
