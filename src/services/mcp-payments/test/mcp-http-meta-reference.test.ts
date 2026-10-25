/**
 * @spec authority-server#mcp-reference, authority-server#reference-verification (#1694)
 *
 * The HTTP MCP transport reads the Mission reference a tools/call carries in
 * `params._meta`, as the in-memory transport does, and requires it to agree
 * with the Mission-Reference field where both are present. Real DPoP-bound
 * Mission tokens over the real HTTP transport; the PDP's FGA check is stubbed
 * to permit, so each result turns on the reference alone and the file runs
 * without OpenFGA.
 */

import { MCP_REFERENCE_META_KEY } from "@mission/core";
import type { Fga, MissionView } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { calculateJwkThumbprint, type CryptoKey, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  createHttpMediatedClient,
  type DpopKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const ISSUER = "https://as.test";
const AUTHORITY_HASH = "sha-256:meta1694";

const VIEW: MissionView = {
  id: "msn_1694",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: AUTHORITY_HASH,
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read"],
      constraints: { vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

let signKey: CryptoKey;
let pubJwk: Record<string, unknown>;
let dpopKeys: DpopKeys;
let cnfJkt: string;

beforeAll(async () => {
  const kp = await generateKeyPair("ES256", { extractable: true });
  signKey = kp.privateKey;
  pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  cnfJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
});

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of cleanups.splice(0).reverse()) await c().catch(() => {});
});

/** A Mission-bound access token for VIEW, bound to the client's DPoP key. */
function missionToken(): Promise<string> {
  return new SignJWT({
    client_id: "ap-agent",
    mission: { id: VIEW.id, issuer: ISSUER, authority_hash: AUTHORITY_HASH },
    cnf: { jkt: cnfJkt },
    authorization_details: [...ALL_ACTIONS_CREDENTIAL],
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key", typ: "at+jwt" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .setExpirationTime("5m")
    .sign(signKey);
}

/** A started HTTP MCP channel over a PEP whose only open question is the reference. */
async function channelUrl(): Promise<string> {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === VIEW.id && ref.issuer === VIEW.issuer
      ? { view: VIEW, observation: { state: VIEW.state, version: VIEW.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const pep = new Pep({
    decide: EVIDENCE_KEYS.decide,
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1",
  });
  const server = new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep,
    payments,
    loadView,
    jwks: { keys: [pubJwk] },
    keyRoles: { accessToken: ["mission-key"], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
  });
  const channel = await createHttpMcpChannel(server);
  cleanups.push(channel.close);
  return channel.url;
}

/** One governed read over HTTP, with the reference in `_meta`, in the field, in both, or in neither. */
async function readInvoice(carriage: { meta?: unknown; field?: string }) {
  const { client, close } = await createHttpMediatedClient(
    await channelUrl(),
    await missionToken(),
    dpopKeys,
    carriage.field === undefined ? {} : { "mission-reference": carriage.field },
  );
  cleanups.push(close);
  return client.callTool(
    "get_invoice",
    { invoice_id: "inv-1" },
    carriage.meta === undefined ? undefined : { [MCP_REFERENCE_META_KEY]: carriage.meta },
  );
}

const META = { mission_id: VIEW.id, issuer: ISSUER };
const OTHER_META = { mission_id: "msn_other", issuer: ISSUER };
const FIELD = `id="${VIEW.id}", issuer="${ISSUER}"`;
const OTHER_FIELD = `id="msn_other", issuer="${ISSUER}"`;

describe("the HTTP MCP transport reads the _meta Mission reference (@spec authority-server#mcp-reference, #1694)", () => {
  it("with neither carriage, the credential-established read permits", async () => {
    const res = await readInvoice({});
    expect(res.ok, JSON.stringify(res)).toBe(true);
  });

  it("a reference in _meta alone reaches the PEP: the matching one permits, one naming another Mission is refused mission_reference_conflict", async () => {
    const matching = await readInvoice({ meta: META });
    expect(matching.ok, JSON.stringify(matching)).toBe(true);
    const other = await readInvoice({ meta: OTHER_META });
    expect(other.ok).toBe(false);
    expect(other.refusal_reason).toBe("mission_reference_conflict");
  });

  it("a malformed _meta reference is refused mission_reference_conflict, never ignored", async () => {
    for (const meta of [{ ...META, state: "active" }, { mission_id: 7, issuer: ISSUER }, "msn_1694"]) {
      const res = await readInvoice({ meta });
      expect(res.ok, JSON.stringify({ meta, res })).toBe(false);
      expect(res.refusal_reason).toBe("mission_reference_conflict");
    }
  });

  it("where the field and _meta both carry a reference they must agree; otherwise the call is refused mission_reference_conflict, never one picked", async () => {
    const agreeing = await readInvoice({ field: FIELD, meta: META });
    expect(agreeing.ok, JSON.stringify(agreeing)).toBe(true);
    for (const carriage of [
      { field: FIELD, meta: OTHER_META },
      { field: OTHER_FIELD, meta: META },
      { field: `${FIELD}, state="active"`, meta: META },
    ]) {
      const res = await readInvoice(carriage);
      expect(res.ok, JSON.stringify({ carriage, res })).toBe(false);
      expect(res.refusal_reason).toBe("mission_reference_conflict");
    }
  });
});
