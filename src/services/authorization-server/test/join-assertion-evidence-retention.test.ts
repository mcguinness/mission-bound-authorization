/**
 * @spec authority-server#join-assertion-artifact (#1560): "Each minting is a
 * join evidence event. The MAS records the following, retained for the audit
 * horizon". The reference MAS writes each event to its kernel's store
 * (`MissionKernel.joinEvidence`) before the assertion is cached or returned,
 * keeps it until the Mission's expiry plus the declared audit retention, and
 * prunes it at boot only past that horizon.
 *
 * Restarts here are the deployment's: a key ring and a file-backed kernel
 * store, built again on the same files (`buildAuthorizationServer` runs boot
 * recovery). The deployment hook (the acting token and the join) is a test
 * double, as in `join-assertion-endpoint.test.ts`; the service is driven with
 * no HTTP route in the way, its caller authenticated by a real client
 * assertion.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { openStore } from "@mission/store";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type ActingToken,
  type BuiltAs,
  buildAuthorizationServer,
  DEFAULT_AUDIT_RETENTION_S,
  initSigningKeyRing,
  type JoinAssertionDeployment,
  type JoinAssertionEvent,
  JoinEvidenceRetentionError,
  JoinEvidenceStore,
  type MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { CLIENT_ASSERTION_TYPE, type LifecycleTestClient, lifecycleClientAssertion, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

/** Never listened on: the service is driven directly. */
const ISSUER = "http://localhost:14915";
const ESTATE = "https://estate.example";
const MAPPING_V1 = "mas-pilot-identity@1";
const MAPPING_V2 = "mas-pilot-identity@2";
const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;

const tokens = new Map<string, ActingToken>();
let mappingVersion = MAPPING_V1;
const ath = (token: string) => createHash("sha256").update(token, "ascii").digest("base64url");

/** The acting tokens the double's AS knows, and one mapping: estate account u-1001 is alice, estate-bot the Mission's client. */
const deployment: JoinAssertionDeployment = {
  async establishActingToken(form) {
    const known = "accessToken" in form ? tokens.get(form.accessToken) : undefined;
    return known ? { ok: true, token: known } : { ok: false, reason: "inactive" };
  },
  evaluateJoin(token, mission) {
    if (token.issuer !== ESTATE || token.subject !== "u-1001" || mission.subject.sub !== "alice") return undefined;
    return token.clientId === "estate-bot" ? { clientId: "ap-agent", disposition: "client", mappingVersion } : undefined;
  },
};

function actingToken(): string {
  const token = `estate-token-${crypto.randomUUID()}`;
  tokens.set(token, { issuer: ESTATE, subject: "u-1001", clientId: "estate-bot", exp: Math.floor(Date.now() / 1000) + 3600, cnf: { jkt: `jkt-${token.slice(-8)}` } });
  return token;
}

let pep: LifecycleTestClient;
let pdp: LifecycleTestClient;
const dirs: string[] = [];
let approvals = 0;

beforeAll(async () => {
  pep = await newLifecycleClient("join-evidence-pep");
  pdp = await newLifecycleClient("join-evidence-pdp");
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** A key ring and a kernel file: what a deployment keeps across a restart. */
async function deploymentFiles(): Promise<{ ring: string; file: string }> {
  const dir = mkdtempSync(join(tmpdir(), "join-evidence-"));
  dirs.push(dir);
  const ring = join(dir, "keys", "ring.json");
  await initSigningKeyRing(ring, ISSUER, { asToken, asStatus, asTxn, asContinuation });
  return { ring, file: join(dir, "kernel.db") };
}

/** One boot of the MAS on the deployment's files (none: the in-memory default), its kernel clock `now`. */
function boot(files?: { ring: string; file: string }, now?: () => Date): Promise<BuiltAs> {
  return buildAuthorizationServer({
    issuer: ISSUER,
    ...(files ? { signingKeys: { ring: files.ring }, kernelStore: { file: files.file } } : {}),
    testClients: [pep.metadata, pdp.metadata],
    joinEnrollment: {
      [pep.clientId]: { roles: ["pep"], enforcementScopes: [CANONICAL_RESOURCE] },
      [pdp.clientId]: { roles: ["pdp"], enforcementScopes: [CANONICAL_RESOURCE] },
    },
    joinAssertions: deployment,
    ...(now ? { now } : {}),
  });
}

function approve(kernel: MissionKernel, expiresAt = "2027-01-01T00:00:00Z"): MissionRecord {
  approvals += 1;
  return kernel.approve({
    intent: validateMissionIntent(JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: expiresAt })),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-join-evidence-${approvals}`,
  });
}

/** One request at the service as the PEP, for the PDP's audience. */
async function mint(built: BuiltAs, missionId: string, accessToken: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const service = built.joinAssertions;
  if (!service) throw new Error("no join-assertion service");
  return service.handle(
    JSON.stringify({
      mission_id: missionId,
      audience: pdp.clientId,
      access_token: accessToken,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await lifecycleClientAssertion(ISSUER, pep),
    }),
    "application/json",
    "",
  );
}

/** Mint, expecting an assertion; its claims. */
async function minted(built: BuiltAs, missionId: string, accessToken: string): Promise<Record<string, unknown>> {
  const answer = await mint(built, missionId, accessToken);
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return decodeJwt(answer.body.assertion as string) as Record<string, unknown>;
}

/** The join evidence event an assertion's claims and request imply. */
const eventOf = (claims: Record<string, unknown>, record: MissionRecord): JoinAssertionEvent => ({
  mission: { issuer: record.issuer, id: record.id },
  token: claims.token as JoinAssertionEvent["token"],
  join: claims.join as JoinAssertionEvent["join"],
  caller: pep.clientId,
  audience: pdp.clientId,
  ...(claims.mapping_version !== undefined ? { mapping_version: claims.mapping_version as string } : {}),
  iat: claims.iat as number,
  exp: claims.exp as number,
});

const horizonOf = (record: MissionRecord) => Date.parse(record.expires_at) + DEFAULT_AUDIT_RETENTION_S * 1000;

describe("Join evidence retention (@spec authority-server#join-assertion-artifact, #1560)", () => {
  it("records each minting on the kernel store, and the event survives a restart with the key ring and the kernel file: the Mission reference, the token digest and thumbprint, the join, the caller, the audience, mapping_version and the validity window", async () => {
    const files = await deploymentFiles();
    const first = await boot(files);
    const record = approve(first.kernel);
    const token = actingToken();
    const claims = await minted(first, record.id, token);
    expect(claims.token).toEqual({ sha256: ath(token), jkt: `jkt-${token.slice(-8)}` });
    expect(first.kernel.joinEvidence.forMission(record)).toHaveLength(1);
    first.kernel.close();

    const second = await boot(files);
    try {
      const retained = second.kernel.joinEvidence.forMission(record);
      expect(retained).toEqual([{ event: eventOf(claims, record), retain_until: new Date(horizonOf(record)).toISOString() }]);
      expect(retained[0]?.event).toMatchObject({ caller: pep.clientId, audience: pdp.clientId, mapping_version: MAPPING_V1 });
      // The service reads the same store: its events are the kernel's, not its own memory.
      expect(second.joinAssertions?.events().filter((e) => e.mission.id === record.id)).toEqual([eventOf(claims, record)]);
    } finally {
      second.kernel.close();
    }
  });

  it("makes a mapping change attributable after a restart: each retained event names the mapping_version its assertion was minted under, in minting order", async () => {
    const files = await deploymentFiles();
    const first = await boot(files);
    const record = approve(first.kernel);
    const token = actingToken();
    mappingVersion = MAPPING_V1;
    let before: Record<string, unknown>;
    let after: Record<string, unknown>;
    try {
      before = await minted(first, record.id, token);
      // The mapping changes: the cached assertion carries another join, so the same request mints anew.
      mappingVersion = MAPPING_V2;
      after = await minted(first, record.id, token);
    } finally {
      mappingVersion = MAPPING_V1;
    }
    expect(before.mapping_version).toBe(MAPPING_V1);
    expect(after.mapping_version).toBe(MAPPING_V2);
    first.kernel.close();

    const second = await boot(files);
    try {
      const retained = second.kernel.joinEvidence.forMission(record).map((r) => r.event);
      expect(retained).toEqual([eventOf(before, record), eventOf(after, record)]);
      expect(retained.map((e) => e.mapping_version)).toEqual([MAPPING_V1, MAPPING_V2]);
    } finally {
      second.kernel.close();
    }
  });

  it("keeps each event for its Mission's audit horizon, the Mission's expiry plus the declared audit retention: a boot at that horizon keeps it, and a boot past it prunes it and keeps a later Mission's", async () => {
    let clockMs = Date.now();
    const now = () => new Date(clockMs);
    const files = await deploymentFiles();
    const first = await boot(files, now);
    const early = approve(first.kernel, "2027-01-01T00:00:00Z");
    const later = approve(first.kernel, "2027-03-01T00:00:00Z");
    expect(first.kernel.tombstones.horizons().audit_retention_seconds).toBe(DEFAULT_AUDIT_RETENTION_S);
    await minted(first, early.id, actingToken());
    await minted(first, later.id, actingToken());
    first.kernel.close();

    // Past the early Mission's expiry, at the last instant of its audit horizon.
    clockMs = horizonOf(early);
    const atHorizon = await boot(files, now);
    try {
      expect(atHorizon.kernel.joinEvidence.forMission(early).map((r) => r.retain_until)).toEqual([new Date(horizonOf(early)).toISOString()]);
      expect(atHorizon.kernel.joinEvidence.forMission(later)).toHaveLength(1);
    } finally {
      atHorizon.kernel.close();
    }

    clockMs = horizonOf(early) + 1;
    const pastHorizon = await boot(files, now);
    try {
      expect(pastHorizon.kernel.joinEvidence.forMission(early)).toEqual([]);
      expect(pastHorizon.kernel.joinEvidence.forMission(later).map((r) => r.retain_until)).toEqual([new Date(horizonOf(later)).toISOString()]);
    } finally {
      pastHorizon.kernel.close();
    }
  });

  it("returns no assertion, and caches none, when the event cannot be recorded: unavailable (HTTP 503), and the same request then mints anew and records its event", async () => {
    const built = await boot();
    try {
      const record = approve(built.kernel);
      const token = actingToken();
      const spy = vi.spyOn(built.kernel.joinEvidence, "record").mockImplementationOnce(() => {
        throw new JoinEvidenceRetentionError("the join evidence store is unavailable");
      });
      const refused = await mint(built, record.id, token);
      expect(refused.status, JSON.stringify(refused.body)).toBe(503);
      expect(refused.body.error).toBe("unavailable");
      expect("assertion" in refused.body).toBe(false);
      expect(built.kernel.joinEvidence.forMission(record)).toEqual([]);
      spy.mockRestore();
      // Nothing was cached: the retry is a minting, with its own event.
      const claims = await minted(built, record.id, token);
      expect(built.kernel.joinEvidence.forMission(record).map((r) => r.event)).toEqual([eventOf(claims, record)]);
    } finally {
      built.kernel.close();
    }
  });

  it("the store refuses an event under another Mission, a Mission expiry that is not a date-time, and a retention that is not a non-negative number, writing nothing", () => {
    const db = openStore("", {});
    expect(() => new JoinEvidenceStore(db, { now: () => new Date(), auditRetentionSeconds: -1 })).toThrow(/non-negative/);
    expect(() => new JoinEvidenceStore(db, { now: () => new Date(), auditRetentionSeconds: Number.NaN })).toThrow(/non-negative/);
    const store = new JoinEvidenceStore(db, { now: () => new Date(), auditRetentionSeconds: 60 });
    const event: JoinAssertionEvent = {
      mission: { issuer: ISSUER, id: "msn_a" },
      token: { sha256: "digest", jkt: "thumbprint" },
      join: { client_id: "ap-agent", disposition: "client" },
      caller: pep.clientId,
      audience: pdp.clientId,
      iat: 1,
      exp: 2,
    };
    expect(() => store.record({ issuer: ISSUER, id: "msn_b", expires_at: "2027-01-01T00:00:00Z" }, event)).toThrow(JoinEvidenceRetentionError);
    expect(() => store.record({ issuer: "https://other.example", id: "msn_a", expires_at: "2027-01-01T00:00:00Z" }, event)).toThrow(
      JoinEvidenceRetentionError,
    );
    expect(() => store.record({ issuer: ISSUER, id: "msn_a", expires_at: "not a date" }, event)).toThrow(JoinEvidenceRetentionError);
    expect(store.all()).toEqual([]);
    expect(store.record({ issuer: ISSUER, id: "msn_a", expires_at: "2027-01-01T00:00:00Z" }, event).retain_until).toBe("2027-01-01T00:01:00.000Z");
    expect(store.all().map((r) => r.event)).toEqual([event]);
    db.close();
  });
});
