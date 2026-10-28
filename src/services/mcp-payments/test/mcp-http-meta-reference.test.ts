/**
 * @spec authority-server#mcp-reference, authority-server#reference-verification,
 * harness#work-item-identity (#1694): the HTTP MCP channel honors a Mission
 * reference carried in `params._meta` under `com.karlmcguinness.mission/reference`,
 * as the in-memory channel does. "A server that silently ignores this key is
 * not a conforming Mission PEP."
 *
 * A `_meta` reference alone selects the Mission on a MAS-governed route and
 * carries its work item to the PEP; a malformed one refuses, and is never
 * rescued by a well-formed `Mission-Reference` field beside it; a field and a
 * `_meta` key that disagree refuse `mission_reference_conflict` before any
 * decision, never a silent pick-one; a field and a `_meta` key that agree are
 * one reference.
 *
 * Unconditional: the FGA check is a stub, so this file never skips. The
 * credentials and DPoP proofs are real, minted inline per run, and every call
 * crosses a real HTTP channel to the real PEP.
 */

import { randomUUID } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  type EvaluationRequest,
  type Fga,
  type MissionView,
  readWorkItemAttribution,
  RUNTIME_POSTURE,
  WORK_ITEM_ATTRIBUTION_EXTENSION,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
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
import { pinnedToCurrentContract } from "@mission/demo-data";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const ISSUER = "https://as.test";
const HARNESS = "https://harness.example.com";
const W1 = { issuer: HARNESS, id: "work-1" };
const W2 = { issuer: HARNESS, id: "work-2" };
const MISSION_A = "msn_1694_a";
const MISSION_B = "msn_1694_b";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (id: string): MissionView => ({
  id,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: `sha-256:${id}`,
  authority_set: [
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:invoice.list"],
    }),
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/**
 * A test-only Enforcement Scope Statement: the shipped one plus a work-item
 * declaration naming `ap-agent`'s harness as its attacher, claimed for no
 * class.
 */
function statement(): unknown {
  const stmt = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown> & { extensions: Record<string, unknown> };
  stmt.extensions = {
    ...stmt.extensions,
    [WORK_ITEM_ATTRIBUTION_EXTENSION]: {
      attachers: [{ client_id: "ap-agent", harness: HARNESS }],
      covered_classes: ["consequential_read"],
    },
  };
  return stmt;
}

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

/** A Mission-bound access token for `mission`, bound to the DPoP key. */
function missionToken(mission: string): Promise<string> {
  return new SignJWT({
    client_id: "ap-agent",
    client_instance_id: "inst-1",
    mission: { id: mission, issuer: ISSUER, authority_hash: `sha-256:${mission}` },
    cnf: { jkt: cnfJkt },
    authorization_details: [...ALL_ACTIONS_CREDENTIAL],
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key", typ: "at+jwt" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime("5m")
    .sign(signKey);
}

/** An ordinary access token: a `scope` and no `mission` claim. */
function ordinaryToken(): Promise<string> {
  return new SignJWT({ client_id: "ap-agent", scope: "payments.read", cnf: { jkt: cnfJkt } })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signKey);
}

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of cleanups.splice(0).reverse()) await c().catch(() => {});
});

interface Stack {
  url: string;
  evidence: EvidenceStore;
  /** Every decision request the PEP sent, as sent. */
  requests: EvaluationRequest[];
}

/**
 * The real PEP and payments server behind a real HTTP MCP channel. Both
 * Missions resolve. `governed` makes the route MAS-governed: it admits an
 * ordinary credential and joins it against the propagated reference, the only
 * thing naming a Mission there.
 */
async function stack(governed: boolean): Promise<Stack> {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    (ref.id === MISSION_A || ref.id === MISSION_B) && ref.issuer === ISSUER
      ? { view: view(ref.id), observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const requests: EvaluationRequest[] = [];
  const pep = new Pep({
    decide: async (req, options) => {
      requests.push(structuredClone(req));
      return EVIDENCE_KEYS.decide(req, options);
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1694",
    workItemAttachers: readWorkItemAttribution(statement()).attachers,
    ...(governed
      ? {
          masJoin: {
            resolveOrdinaryAuthority: (token: { mission?: unknown; scope?: string }) =>
              !token.mission && token.scope === "payments.read"
                ? [pinnedToCurrentContract({ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] })]
                : undefined,
          },
        }
      : {}),
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
  const channel = await createHttpMcpChannel(server, { masGoverned: governed });
  cleanups.push(channel.close);
  return { url: channel.url, evidence, requests };
}

/** One `get_invoice` call over the channel, with an optional field and an optional `_meta` reference. */
async function call(s: Stack, credential: string, field: string | undefined, meta: unknown) {
  const { client, close } = await createHttpMediatedClient(
    s.url,
    credential,
    dpopKeys,
    field === undefined ? {} : { "mission-reference": field },
  );
  cleanups.push(close);
  return client.callTool("get_invoice", { invoice_id: "inv-1" }, meta);
}

const fieldFor = (mission: string, workItem?: { issuer: string; id: string }): string =>
  `id="${mission}", issuer="${ISSUER}"` +
  (workItem ? `, work_item_issuer="${workItem.issuer}", work_item="${workItem.id}"` : "");
const metaFor = (mission: string, workItem?: { issuer: string; id: string }): Record<string, string> => ({
  mission_id: mission,
  issuer: ISSUER,
  ...(workItem ? { work_item_issuer: workItem.issuer, work_item: workItem.id } : {}),
});
const contextOf = (r: EvaluationRequest | undefined) => r?.context as Record<string, unknown> | undefined;
const conflictRecords = (s: Stack) =>
  s.evidence.all().filter((e) => e.kind === "refusal" && e.content.denial_reason === "mission_reference_conflict");

describe("HTTP MCP channel: the _meta Mission reference reaches the PEP (@spec authority-server#mcp-reference, #1694)", () => {
  it("a _meta reference alone selects the Mission on a MAS-governed route: an ordinary credential's joined read permits under that Mission", async () => {
    const s = await stack(true);
    const res = await call(s, await ordinaryToken(), undefined, metaFor(MISSION_B));
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(s.requests).toHaveLength(1);
    expect(contextOf(s.requests[0])?.mission).toMatchObject({ id: MISSION_B, issuer: ISSUER });
  });

  it("a _meta reference carries its work item to the PEP where the statement names the attacher", async () => {
    const s = await stack(false);
    const res = await call(s, await missionToken(MISSION_A), undefined, metaFor(MISSION_A, W1));
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(contextOf(s.requests[0])?.work_item).toEqual(W1);
  });

  it("a _meta reference naming another Mission than the credential is refused with mission_reference_conflict before any decision", async () => {
    const s = await stack(false);
    const res = await call(s, await missionToken(MISSION_A), undefined, metaFor(MISSION_B));
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
    expect(s.requests).toHaveLength(0);
  });
});

describe("HTTP MCP channel: a malformed _meta Mission reference is refused (@spec authority-server#mcp-reference, authority-server#reference-tuple, #1694)", () => {
  it("a _meta reference carrying an extra member, or not an object, is refused with mission_reference_conflict before any decision", async () => {
    const s = await stack(false);
    const token = await missionToken(MISSION_A);
    for (const meta of [{ ...metaFor(MISSION_A), state: "active" }, MISSION_A]) {
      const res = await call(s, token, undefined, meta);
      expect(res.ok, JSON.stringify(meta)).toBe(false);
      expect(res.refusal_reason, JSON.stringify(meta)).toBe("mission_reference_conflict");
    }
    expect(s.requests).toHaveLength(0);
  });

  it("a malformed _meta reference is not rescued by a well-formed Mission-Reference field: the governed read is refused with mission_reference_conflict", async () => {
    const s = await stack(true);
    const res = await call(s, await ordinaryToken(), fieldFor(MISSION_A), { ...metaFor(MISSION_A), state: "active" });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
    expect(s.requests).toHaveLength(0);
  });
});

describe("HTTP MCP channel: the Mission-Reference field and the _meta key are one reference (@spec authority-server#reference-verification, #1694)", () => {
  it("a field and a _meta key naming different Missions are refused with mission_reference_conflict in either order, recorded as a Refusal Record, never a silent pick-one", async () => {
    const s = await stack(true);
    const token = await ordinaryToken();
    for (const [field, meta] of [
      [MISSION_A, MISSION_B],
      [MISSION_B, MISSION_A],
    ] as const) {
      const res = await call(s, token, fieldFor(field), metaFor(meta));
      expect(res.ok, `${field} vs ${meta}`).toBe(false);
      expect(res.refusal_reason, `${field} vs ${meta}`).toBe("mission_reference_conflict");
    }
    expect(s.requests).toHaveLength(0);
    expect(conflictRecords(s)).toHaveLength(2);
  });

  it("a field and a _meta key naming the same Mission but disagreeing on the work item, or on its presence, are refused with mission_reference_conflict", async () => {
    const s = await stack(false);
    const token = await missionToken(MISSION_A);
    const cases: [string, Record<string, string>][] = [
      [fieldFor(MISSION_A, W1), metaFor(MISSION_A, W2)],
      [fieldFor(MISSION_A, W1), metaFor(MISSION_A)],
      [fieldFor(MISSION_A), metaFor(MISSION_A, W1)],
    ];
    for (const [field, meta] of cases) {
      const res = await call(s, token, field, meta);
      expect(res.ok, `${field} vs ${JSON.stringify(meta)}`).toBe(false);
      expect(res.refusal_reason, `${field} vs ${JSON.stringify(meta)}`).toBe("mission_reference_conflict");
    }
    expect(s.requests).toHaveLength(0);
  });

  it("a field and a _meta key that agree pass: the governed read joins that Mission, and the work item they both carry reaches the PEP", async () => {
    const governed = await stack(true);
    const joined = await call(governed, await ordinaryToken(), fieldFor(MISSION_B), metaFor(MISSION_B));
    expect(joined.ok, JSON.stringify(joined)).toBe(true);
    expect(contextOf(governed.requests[0])?.mission).toMatchObject({ id: MISSION_B, issuer: ISSUER });

    const bound = await stack(false);
    const carried = await call(bound, await missionToken(MISSION_A), fieldFor(MISSION_A, W1), metaFor(MISSION_A, W1));
    expect(carried.ok, JSON.stringify(carried)).toBe(true);
    expect(contextOf(bound.requests[0])?.work_item).toEqual(W1);
  });
});
