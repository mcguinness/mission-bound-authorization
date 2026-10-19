/**
 * @spec authority-server#limitations, authority-server#high-consequence-binding,
 * authority-server#mapping-contract (#818)
 *
 * The estate route's credential validation (`McpServerDeps.ordinaryOnly`): a
 * resource server whose configured issuer is a legacy estate authorization
 * server, not a Mission Issuer. It accepts exactly one credential format, an
 * RFC 9068 JWT access token with no `mission` claim, and never reads a
 * `mission` claim from that issuer as Mission-bound. FGA-independent: token
 * validation calls no PDP.
 */

import { randomUUID } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  type DpopKeys,
  dpopProofFor,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
} from "../src/index.js";

const ESTATE = "https://estate.test";
const HTU = CANONICAL_RESOURCE;
const HTM = "POST";

let signKey: CryptoKey;
let holder: DpopKeys;
let holderJkt: string;
let jwk: Record<string, unknown>;

function server(ordinaryOnly: boolean): McpPaymentsServer {
  return new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep: undefined as never, // token validation alone never reaches the PEP
    payments: new PaymentsStore(),
    loadView: () => undefined,
    jwks: { keys: [jwk as never] },
    keyRoles: { accessToken: ["estate-key"], attenuationRoot: [], transactionToken: [] },
    issuer: ESTATE,
    ordinaryOnly,
  });
}

/** An RFC 9068 access token from the estate key; `undefined` removes a claim or header member. */
async function mint(claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: ESTATE,
    aud: CANONICAL_RESOURCE,
    sub: "u-1001",
    client_id: "estate-bot",
    jti: randomUUID(),
    iat: now,
    exp: now + 300,
    scope: "invoices.read",
    cnf: { jkt: holderJkt },
    ...claims,
  };
  for (const [k, v] of Object.entries(payload)) if (v === undefined) delete payload[k];
  const protectedHeader: Record<string, unknown> = { alg: "ES256", kid: "estate-key", typ: "at+jwt", ...header };
  for (const [k, v] of Object.entries(protectedHeader)) if (v === undefined) delete protectedHeader[k];
  return new SignJWT(payload).setProtectedHeader(protectedHeader as never).sign(signKey);
}

async function present(s: McpPaymentsServer, token: string) {
  return s.validateGatewayCredential(token, { proof: await dpopProofFor(holder, HTU, HTM, token), htu: HTU, htm: HTM }, true);
}

/** A Mission access token profile claim set, as a Mission Issuer would mint it. */
const MISSION_BOUND = {
  mission: { id: "msn_818_estate", issuer: ESTATE },
  authorization_details: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
};

beforeAll(async () => {
  const kp = await generateKeyPair("ES256", { extractable: true });
  signKey = kp.privateKey;
  jwk = { ...(await exportJWK(kp.publicKey)), kid: "estate-key", alg: "ES256" };
  holder = await generateKeyPair("ES256", { extractable: true });
  holderJkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
});

describe("estate route: ordinary credentials only (@spec authority-server#limitations, #818)", () => {
  it("admits an RFC 9068 estate token as ordinary facts qualified by the estate issuer", async () => {
    const admitted = present(server(true), await mint());
    await expect(admitted).resolves.toMatchObject({ sub: "u-1001", clientId: "estate-bot", iss: ESTATE });
    const facts = await admitted;
    expect(facts.mission).toBeUndefined();
    expect(facts.credential?.issuer).toBe(ESTATE);
  });

  it("refuses an estate token carrying a mission claim, which a Mission Issuer's route admits as Mission-bound", async () => {
    const token = await mint(MISSION_BOUND);
    // Positive control: the same token, on a route whose issuer IS the Mission
    // Issuer, verifies as a Mission-bound credential.
    const asMissionIssuer = await present(server(false), token);
    expect(asMissionIssuer.mission?.id).toBe("msn_818_estate");
    // The estate route never reads it as Mission-bound.
    await expect(present(server(true), token)).rejects.toThrow(/not a Mission Issuer/);
  });

  it("refuses every other credential format: a non-at+jwt type, a missing client_id or jti, and an opaque token", async () => {
    const s = server(true);
    await expect(present(s, await mint({}, { typ: "JWT" }))).rejects.toThrow(/unsupported credential format/);
    await expect(present(s, await mint({}, { typ: undefined }))).rejects.toThrow(/unsupported credential format/);
    await expect(present(s, await mint({ client_id: undefined }))).rejects.toThrow(/client_id/);
    await expect(present(s, await mint({ jti: undefined }))).rejects.toThrow(/jti/);
    await expect(present(s, "opaque-reference-token-7f3a9")).rejects.toThrow();
  });

  it("publishes the estate issuer as its authorization server and does not advertise Mission-bound-only acceptance", () => {
    const metadata = server(true).protectedResourceMetadata();
    expect(metadata.authorization_servers).toEqual([ESTATE]);
    expect(metadata).not.toHaveProperty("mission_bound_authorization_required");
    expect(server(false).protectedResourceMetadata().mission_bound_authorization_required).toBe(true);
  });
});
