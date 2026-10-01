/**
 * @spec draft-mcguinness-oauth-mission-discharge (#discharge-carryover,
 * #discharge-receipt, #discharge-result, #discharge-authority,
 * #discharge-idempotency), draft-mcguinness-oauth-mission-child-delegation
 * (#carryover-evidence)
 *
 * Discharge After Carryover (#898 fix 3), over the real lifecycle endpoint and
 * the real deferred-expansion carryover: a delayed assertion that targets a
 * carried-over old child is forwarded to the active replacement's corresponding
 * entry, resolved ONLY through the per-entry pairing Carryover Evidence records,
 * authorized against the replacement's inherited pin, committed before the
 * response, and recorded so a retry recovers the original result. The response
 * is the replacement's signed Status envelope with `forwarded_from` for a caller
 * that may inspect it, and a signed Discharge Receipt otherwise.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import {
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  generateKeyPair,
  type JWTVerifyGetKey,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  type CarryoverConfig,
  type CarryoverMapRow,
  conditionDigest,
  createChildMission,
  decodeCarryoverEvidence,
  type DischargeAuthorityPolicy,
  entryDigest,
  MISSION_DISCHARGE_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import {
  ConsumerVerificationError,
  RECEIPT_TYP,
  STATUS_TYP,
  type SentTarget,
  verifyDischargeReceipt,
  verifyStatusResponse,
} from "./discharge-consumer.helper.js";

const PORT = 14555;
const ISSUER = `http://localhost:${PORT}`;
const PAY = CANONICAL_RESOURCE;
const LEDGER = TOPOLOGY.resources.saas;
const EXPIRES_AT = "2027-01-01T00:00:00Z";

const CLOSE_EVENT = "accounting-period-closed";
const CLOSE_AUTHORITY = "close-management-2026-q3";
const CONDITION = { event_type: CLOSE_EVENT, discharge_authority: CLOSE_AUTHORITY };

/** A discharge source holding the discharge grant and NO Status read grant. */
const SOURCE_TOKEN = "dev-close-source-token";
const SOURCE = "svc:close-source";
/** Holds the discharge grant, but no condition's mapping admits it. */
const UNMAPPED_TOKEN = "dev-unmapped-source-token";

/** The live, issuer-held policy (mutated in place by the pin-inheritance row). */
const POLICY: DischargeAuthorityPolicy = {
  policies: {
    [CLOSE_AUTHORITY]: {
      mapping_id: "close-management",
      mapping_version: "1",
      event_types: [CLOSE_EVENT],
      principals: ["svc:console", SOURCE],
    },
  },
};

const CARRYOVER: CarryoverConfig = {
  enabled: true,
  maxRows: null,
  exclusionPolicy: { mode: "all_or_nothing" },
  noApplicableExternalState: true,
};

let as: BuiltAs;
let server: Server;
let keys: JWTVerifyGetKey;
let seq = 0;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    dischargeAuthority: POLICY,
    childMissionCarryover: CARRYOVER,
    actorProfiles: aiAgents("child-a", "child-b"),
    serviceTokenPrincipals: {
      [SOURCE_TOKEN]: { principal_id: SOURCE, scopes: [MISSION_DISCHARGE_SCOPE] },
      [UNMAPPED_TOKEN]: { principal_id: "svc:unmapped-source", scopes: [MISSION_DISCHARGE_SCOPE] },
    },
  });
  server = as.provider.listen(PORT);
  keys = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
});

afterAll(() => {
  server?.close();
});

// ---------------------------------------------------------------------------
// Fixtures: a predecessor, its child, and expand-and-carry cycles.
// ---------------------------------------------------------------------------

const BASE = { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] };

/** One payments entry completing on the close condition. */
const completing = (actions: string[], extra: Record<string, unknown> = {}): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: PAY,
  actions,
  constraints: { ...BASE, ...extra, terminal_when: [{ ...CONDITION }] },
});

/** Two entries on ONE resource carrying byte-identical conditions. */
const PAIR = (): AuthorityEntry[] => [
  completing(["payments:invoice.read"]),
  completing(["payments:invoice.list"]),
];

const intentOf = (goal: string, resources = [PAY]) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: resources, expires_at: EXPIRES_AT }));

function approvePredecessor(entries: AuthorityEntry[] = PAIR()): MissionRecord {
  seq += 1;
  return as.kernel.approve({
    intent: intentOf("Pay Acme invoices"),
    proposedAuthority: entries,
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-dco-${seq}`,
  });
}

function addChild(parentId: string, entries: AuthorityEntry[] = PAIR(), actor = "child-a"): MissionRecord {
  return createChildMission(as.kernel, {
    parentId,
    intent: intentOf("Work the invoices"),
    proposedAuthority: entries,
    childActor: { sub: actor, sub_profile: "ai_agent" },
  }).child;
}

/**
 * Expand `predecessorId` onto the ledger and carry its children. `payments`
 * overrides the successor's payments entries (to add an inherited constraint).
 */
function expandAndCarry(
  predecessorId: string,
  payments: AuthorityEntry[] = PAIR(),
): { successor: MissionRecord; replacements: MissionRecord[]; map: CarryoverMapRow[] } {
  seq += 1;
  const store = as.expansionDeferrals;
  const pending = store.open({
    predecessorId,
    intent: intentOf("Pay Acme invoices and post the ledger", [PAY, LEDGER]),
    proposedAuthority: [
      ...payments,
      { type: "mission_resource_access", resource: LEDGER, actions: ["ledger:vendor.read"], constraints: { vendors: ["acme"] } },
    ],
    clientId: "ap-agent",
    jkt: "jkt-dco",
    creationRequestId: `crid-dco-${seq}`,
  });
  store.approve(pending.deferral_code, {
    approver: { iss: ISSUER, sub: "bob" },
    approvalEventId: `xapev-dco-${seq}`,
    approvedUntil: EXPIRES_AT,
  });
  const out = store.redeem(pending.deferral_code);
  if ("error" in out || !("successor" in out)) throw new Error(`carryover failed: ${JSON.stringify(out)}`);
  const result = store.carryoverResultFor(pending.deferral_code);
  if (!result) throw new Error("no carryover result");
  return {
    successor: out.successor,
    replacements: out.carryover?.replacements ?? [],
    map: decodeCarryoverEvidence(result.evidence_jws).map,
  };
}

/** The replacement of `oldChild` in a carryover batch. */
function replacementOf(batch: ReturnType<typeof expandAndCarry>, oldChild: MissionRecord): MissionRecord {
  const id = (as.kernel.get(oldChild.id) as MissionRecord).carried_to;
  const found = batch.replacements.find((r) => r.id === id);
  if (!found) throw new Error(`no replacement for ${oldChild.id}`);
  return found;
}

const entryWith = (record: MissionRecord, action: string): AuthorityEntry => {
  const entry = record.authority_set.find((e) => e.actions.includes(action));
  if (!entry) throw new Error(`no ${action} entry on ${record.id}`);
  return entry;
};
const digestOf = (record: MissionRecord, action: string): string =>
  entryDigest(record.issuer, entryWith(record, action));
const CONDITION_DIGEST = conditionDigest(CONDITION);

let nonces = 0;
const freshNonce = (): string => `nonce-dco-${(nonces += 1)}`;

/** A digest-form discharge body for `record`'s entry carrying `action`. */
function body(record: MissionRecord, action: string, over: Record<string, unknown> = {}) {
  return {
    operation: "discharge",
    mission_id: record.id,
    nonce: freshNonce(),
    entry_digest: digestOf(record, action),
    condition_digest: CONDITION_DIGEST,
    event_type: CLOSE_EVENT,
    event_id: `close-${record.id.slice(-8)}-${action.split(".").pop()}`,
    ...over,
  };
}

const lifecycle = (missionId: string, payload: unknown, token = DEV_SERVICE_TOKEN): Promise<Response> =>
  fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": token },
    body: JSON.stringify(payload),
  });

const latched = (id: string): string[] =>
  ((as.kernel.get(id) as MissionRecord).discharged ?? []).map((d) => d.entry_digest);

// ---------------------------------------------------------------------------
// The recorded pairing.
// ---------------------------------------------------------------------------

describe("Carryover Evidence entry pairing (@spec child-delegation#carryover-evidence, #898 fix 3)", () => {
  it("records, per carried entry, the old record entry_digest paired with the replacement's, one counterpart each", () => {
    const entries = (): AuthorityEntry[] => [
      completing(["payments:invoice.read", "payments:invoice.list"]),
      completing(["payments:vendor.read"]),
    ];
    const pred = approvePredecessor(entries());
    const child = addChild(pred.id, entries());
    // Containment narrows the first entry's EFFECTIVE bytes: the pairing still
    // names the old RECORD entry, never the narrowed one.
    as.kernel.contain(child.id, {
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: new Date().toISOString(), event_id: `ev-pair-${seq}` },
      remove: [{ resource: PAY, actions: ["payments:invoice.list"] }],
    });
    const batch = expandAndCarry(pred.id, entries());
    const replacement = replacementOf(batch, child);
    const row = batch.map.find((r) => r.old_child.mission_id === child.id);
    expect(row?.outcome).toBe("carried");
    if (row?.outcome !== "carried") return;
    expect(row.replacement_id).toBe(replacement.id);
    const [oldInvoices, oldVendors] = child.authority_set.map((e) => entryDigest(ISSUER, e));
    const narrowed = entryWith(replacement, "payments:invoice.read");
    expect(narrowed.actions).toEqual(["payments:invoice.read"]);
    expect(row.entry_pairs).toEqual([
      { entry_digest: oldInvoices, replacement_entry_digest: entryDigest(ISSUER, narrowed) },
      { entry_digest: oldVendors, replacement_entry_digest: digestOf(replacement, "payments:vendor.read") },
    ]);
    // The old digest is the RECORD entry's: the narrowed effective entry digests
    // to something else.
    const effectiveOld = as.kernel.effectiveAuthoritySet(as.kernel.get(child.id) as MissionRecord)[0] as AuthorityEntry;
    expect(entryDigest(ISSUER, effectiveOld)).not.toBe(oldInvoices);
    // At most one counterpart per old entry.
    expect(new Set(row.entry_pairs.map((p) => p.entry_digest)).size).toBe(row.entry_pairs.length);
  });
});

// ---------------------------------------------------------------------------
// Forwarding.
// ---------------------------------------------------------------------------

describe("discharge forwarding after carryover (@spec discharge#discharge-carryover, #898 fix 3)", () => {
  it("forwards a delayed assertion to the replacement's corresponding entry and answers with its Status envelope", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    const batch = expandAndCarry(pred.id);
    const replacement = replacementOf(batch, child);
    const before = as.kernel.get(replacement.id) as MissionRecord;
    const oldBefore = as.kernel.get(child.id) as MissionRecord;
    expect(oldBefore.state).toBe("cascaded");

    const req = body(child, "payments:invoice.list");
    const res = await lifecycle(child.id, req);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/mission-status-response+jwt");
    const payload = decodeJwt(await res.text()) as Record<string, unknown>;
    // The envelope describes the REPLACEMENT that changed...
    expect((payload.mission as Record<string, unknown>).id).toBe(replacement.id);
    expect(payload.discharge_result).toEqual({
      entry_digest: req.entry_digest,
      condition_digest: CONDITION_DIGEST,
      event_id: req.event_id,
      outcome: "discharged",
      prior_version: before.version,
      current_version: before.version + 1,
      // ...and names the targeted old child.
      forwarded_from: { issuer: ISSUER, id: child.id },
    });
    // The replacement's corresponding entry is latched, committed before the
    // response; its other entry, carrying the identical condition on the same
    // resource, is not. The old child is untouched.
    expect(latched(replacement.id)).toEqual([digestOf(replacement, "payments:invoice.list")]);
    expect(as.kernel.effectiveAuthoritySet(as.kernel.get(replacement.id) as MissionRecord).map((e) => e.actions)).toEqual([
      ["payments:invoice.read"],
    ]);
    const oldAfter = as.kernel.get(child.id) as MissionRecord;
    expect(oldAfter.version).toBe(oldBefore.version);
    expect(oldAfter.discharged).toBeUndefined();
  });

  it("resolves a chain of two carryovers through both recorded pairings", async () => {
    const a = approvePredecessor();
    const childA = addChild(a.id);
    const first = expandAndCarry(a.id);
    const childB = replacementOf(first, childA);
    const second = expandAndCarry(first.successor.id);
    const childC = replacementOf(second, childB);
    const bVersion = (as.kernel.get(childB.id) as MissionRecord).version;

    // The assertion arrives only now, targeting A.
    const res = await lifecycle(childA.id, body(childA, "payments:invoice.list"));
    expect(res.status).toBe(200);
    const payload = decodeJwt(await res.text()) as Record<string, unknown>;
    expect((payload.mission as Record<string, unknown>).id).toBe(childC.id);
    expect(payload.discharge_result).toMatchObject({
      outcome: "discharged",
      forwarded_from: { issuer: ISSUER, id: childA.id },
    });
    expect(latched(childC.id)).toEqual([digestOf(childC, "payments:invoice.list")]);
    // The intermediate B is terminal and untouched.
    expect((as.kernel.get(childB.id) as MissionRecord).version).toBe(bVersion);
    expect(latched(childB.id)).toEqual([]);
  });

  it("recovers the original result on a retry after a further carryover, which inherits the discharge", async () => {
    const a = approvePredecessor();
    const childA = addChild(a.id);
    const first = expandAndCarry(a.id);
    const childB = replacementOf(first, childA);
    // Delivered once: resolved to B and committed there.
    const req = body(childA, "payments:invoice.list");
    const original = await lifecycle(childA.id, req);
    const originalBytes = await original.text();
    const originalPayload = decodeJwt(originalBytes) as Record<string, unknown>;
    expect((originalPayload.mission as Record<string, unknown>).id).toBe(childB.id);
    const originalResult = originalPayload.discharge_result as Record<string, unknown>;

    // B is then carried to C. C inherits the completed discharge through the
    // no-reset rule: the latched entry is not in B's effective set, so C never
    // receives it.
    const second = expandAndCarry(first.successor.id);
    const childC = replacementOf(second, childB);
    expect(childC.authority_set.map((e) => e.actions)).toEqual([["payments:invoice.read"]]);

    // An at-least-once retry under a FRESH nonce recovers the ORIGINAL result
    // (B, its versions), never a newly resolved target, and changes nothing.
    const cVersion = (as.kernel.get(childC.id) as MissionRecord).version;
    const retryNonce = freshNonce();
    const retry = await lifecycle(childA.id, { ...req, nonce: retryNonce });
    expect(retry.status).toBe(200);
    const retryPayload = decodeJwt(await retry.text()) as Record<string, unknown>;
    expect(retryPayload.nonce).toBe(retryNonce);
    expect((retryPayload.mission as Record<string, unknown>).id).toBe(childB.id);
    expect(retryPayload.discharge_result).toEqual(originalResult);
    expect((as.kernel.get(childC.id) as MissionRecord).version).toBe(cVersion);
    expect(latched(childC.id)).toEqual([]);
    // A byte-identical retransmission replays the stored bytes verbatim.
    expect(await (await lifecycle(childA.id, req)).text()).toBe(originalBytes);
  });

  it("authorizes against the replacement's pinned mapping: a caller only the old child's mapping admits gets not_found", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    // A live policy edit between the old child's creation and the carryover:
    // a fresh resolution would now pin version 2. The replacement INHERITS the
    // old child's pin for every carried condition and never resolves it again.
    const live = POLICY.policies as Record<string, (typeof POLICY.policies)[string]>;
    const approved = live[CLOSE_AUTHORITY];
    live[CLOSE_AUTHORITY] = { mapping_id: "close-management", mapping_version: "2", event_types: [CLOSE_EVENT], principals: ["svc:console"] };
    let batch: ReturnType<typeof expandAndCarry>;
    try {
      batch = expandAndCarry(pred.id);
    } finally {
      live[CLOSE_AUTHORITY] = approved as NonNullable<typeof approved>;
    }
    const replacement = replacementOf(batch, child);
    const oldDigest = digestOf(child, "payments:invoice.list");
    const newDigest = digestOf(replacement, "payments:invoice.list");
    expect(as.kernel.dischargePins.find(replacement.id, newDigest, CONDITION_DIGEST)).toEqual(
      as.kernel.dischargePins.find(child.id, oldDigest, CONDITION_DIGEST),
    );
    expect(as.kernel.dischargePins.find(replacement.id, newDigest, CONDITION_DIGEST)?.mapping_version).toBe("1");

    // Now simulate a deployment that RE-RESOLVED the replacement's mapping (the
    // spec forbids it; the forwarding rule must still hold when it happened):
    // the replacement's pin admits only svc:console.
    as.kernel.db
      .prepare("DELETE FROM discharge_mapping_pins WHERE mission_id = ? AND entry_digest = ? AND condition_digest = ?")
      .run(replacement.id, newDigest, CONDITION_DIGEST);
    as.kernel.dischargePins.pinInCallerTx(replacement.id, newDigest, CONDITION_DIGEST, {
      mapping_id: "close-management",
      mapping_version: "2",
      event_types: [CLOSE_EVENT],
      principals: ["svc:console"],
    });
    // The source the OLD child's pin admits is refused with the collapse...
    const refused = await lifecycle(child.id, body(child, "payments:invoice.list"), SOURCE_TOKEN);
    expect(refused.status).toBe(404);
    const { nonce: _n, ...rest } = (await refused.json()) as Record<string, unknown>;
    expect(rest).toEqual({ error: "not_found", error_description: "Mission reference is not found or not visible." });
    expect(latched(replacement.id)).toEqual([]);
    // ...and the principal the replacement's pin admits is forwarded.
    const admitted = await lifecycle(child.id, body(child, "payments:invoice.list", { event_id: "close-admitted" }));
    expect(admitted.status).toBe(200);
    expect(latched(replacement.id)).toEqual([newDigest]);
  });

  it("checks the old child's own latch first: an entry it had discharged answers already_discharged, unforwarded", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    // The old child completed this entry BEFORE the carryover.
    const early = await lifecycle(child.id, body(child, "payments:invoice.list", { event_id: "close-early" }));
    expect(early.status).toBe(200);
    const batch = expandAndCarry(pred.id);
    const replacement = replacementOf(batch, child);
    expect(replacement.authority_set.map((e) => e.actions)).toEqual([["payments:invoice.read"]]);
    const versions = { old: (as.kernel.get(child.id) as MissionRecord).version, rep: replacement.version };

    // A delayed second assertion of the same condition, under another event.
    const res = await lifecycle(child.id, body(child, "payments:invoice.list", { event_id: "close-late" }));
    expect(res.status).toBe(200);
    const payload = decodeJwt(await res.text()) as Record<string, unknown>;
    expect((payload.mission as Record<string, unknown>).id).toBe(child.id);
    const result = payload.discharge_result as Record<string, unknown>;
    expect(result).toMatchObject({ outcome: "already_discharged", prior_version: versions.old, current_version: versions.old });
    expect(result.forwarded_from).toBeUndefined();
    expect((as.kernel.get(replacement.id) as MissionRecord).version).toBe(versions.rep);
    expect(latched(replacement.id)).toEqual([]);
  });

  it("answers terminal_noop for an entry with no recorded counterpart", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    // The list entry is contained away before the carryover: it holds no
    // authority in the replacement, so the pairing records no counterpart.
    as.kernel.contain(child.id, {
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: new Date().toISOString(), event_id: `ev-dco-${seq}` },
      remove: [{ resource: PAY, actions: ["payments:invoice.list"] }],
    });
    const batch = expandAndCarry(pred.id);
    const replacement = replacementOf(batch, child);
    const row = batch.map.find((r) => r.old_child.mission_id === child.id);
    expect(row?.outcome === "carried" && row.entry_pairs.map((p) => p.entry_digest)).toEqual([
      digestOf(child, "payments:invoice.read"),
    ]);
    const res = await lifecycle(child.id, body(child, "payments:invoice.list"));
    expect(res.status).toBe(200);
    const payload = decodeJwt(await res.text()) as Record<string, unknown>;
    expect((payload.mission as Record<string, unknown>).id).toBe(child.id);
    expect(payload.discharge_result).toMatchObject({ outcome: "terminal_noop" });
    expect(latched(replacement.id)).toEqual([]);
  });

  it("forwards through a chain longer than any fixed hop limit", async () => {
    const a = approvePredecessor();
    const childA = addChild(a.id);
    // 65 expand-and-carry cycles before the assertion arrives.
    let parentId = a.id;
    let last = childA;
    for (let i = 0; i < 65; i++) {
      const batch = expandAndCarry(parentId);
      last = replacementOf(batch, last);
      parentId = batch.successor.id;
    }
    const res = await lifecycle(childA.id, body(childA, "payments:invoice.list"));
    expect(res.status).toBe(200);
    const payload = decodeJwt(await res.text()) as Record<string, unknown>;
    expect((payload.mission as Record<string, unknown>).id).toBe(last.id);
    expect(payload.discharge_result).toMatchObject({
      outcome: "discharged",
      forwarded_from: { issuer: ISSUER, id: childA.id },
    });
    expect(latched(last.id)).toEqual([digestOf(last, "payments:invoice.list")]);
  }, 120_000);

  it("refuses a carryover chain that revisits a record instead of acknowledging it, disclosing nothing to an unauthorized caller", async () => {
    const pred = approvePredecessor();
    const childA = addChild(pred.id);
    const childB = replacementOf(expandAndCarry(pred.id), childA);
    // Corrupt the retained map so B reads as carried back to A: A to B to A.
    const db = as.kernel.db;
    db.prepare("UPDATE missions SET carried_to = ? WHERE id = ?").run(childA.id, childB.id);
    db.prepare(
      `INSERT INTO carryover_results (plan_id, issuer, predecessor_id, successor_id, manifest_hash,
         manifest_json, map_json, evidence_hash, evidence_jws, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      `cycle-plan-${childB.id}`,
      ISSUER,
      "msn_injected_pred",
      "msn_injected_succ",
      "sha-256:injected",
      "{}",
      JSON.stringify([
        {
          old_child: { issuer: ISSUER, mission_id: childB.id },
          outcome: "carried",
          replacement_id: childA.id,
          approval_event_id: "cry_injected",
          entry_pairs: [
            {
              entry_digest: digestOf(childB, "payments:invoice.list"),
              replacement_entry_digest: digestOf(childA, "payments:invoice.list"),
            },
          ],
        },
      ]),
      "sha-256:injected",
      "injected.jws.value",
      new Date().toISOString(),
    );
    db.prepare(
      `INSERT INTO carryover_replacements (issuer, replacement_id, plan_id, old_child_id, approval_event_id, child_evidence_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(ISSUER, childA.id, `cycle-plan-${childB.id}`, childB.id, "cry_injected", "{}");
    const events = (): number =>
      (db.prepare("SELECT COUNT(*) AS n FROM discharge_events WHERE mission_id = ?").get(childA.id) as { n: number }).n;

    // A caller the target's mapping does not admit learns nothing: the collapse.
    const unauthorized = await lifecycle(childA.id, body(childA, "payments:invoice.list"), UNMAPPED_TOKEN);
    expect(unauthorized.status).toBe(404);
    const { nonce: _n, ...rest } = (await unauthorized.json()) as Record<string, unknown>;
    expect(rest).toEqual({ error: "not_found", error_description: "Mission reference is not found or not visible." });

    // An authorized caller gets the server-error path: never a terminal_noop
    // acknowledgement an at-least-once sender would stop retrying on.
    const req = body(childA, "payments:invoice.list");
    for (const attempt of [req, { ...req, nonce: freshNonce() }]) {
      const res = await lifecycle(childA.id, attempt);
      expect(res.status).toBeGreaterThanOrEqual(500);
      const text = await res.text();
      expect(text).not.toContain("terminal_noop");
      expect(text).not.toContain("not_found");
    }
    // Nothing committed or recorded.
    expect(latched(childA.id)).toEqual([]);
    expect(latched(childB.id)).toEqual([]);
    expect(events()).toBe(0);
  });

  it("reaches a replacement entry whose bytes changed under inherited constraints, through the recorded pairing only", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    // The successor's payments entries require action approval: the
    // replacement entries inherit that constraint, so their bytes (and
    // entry_digest values) differ from the old child's.
    const batch = expandAndCarry(pred.id, [
      completing(["payments:invoice.read"], { requires_action_approval: true }),
      completing(["payments:invoice.list"], { requires_action_approval: true }),
    ]);
    const replacement = replacementOf(batch, child);
    const listEntry = entryWith(replacement, "payments:invoice.list");
    expect(listEntry.constraints?.requires_action_approval).toBe(true);
    const oldDigest = digestOf(child, "payments:invoice.list");
    const newDigest = digestOf(replacement, "payments:invoice.list");
    expect(newDigest).not.toBe(oldDigest);
    // The targeted digest names nothing in the replacement; only the pairing
    // reaches its entry, and not the read entry that carries the identical
    // condition on the same resource.
    expect(replacement.authority_set.some((e) => entryDigest(ISSUER, e) === oldDigest)).toBe(false);
    const res = await lifecycle(child.id, body(child, "payments:invoice.list"));
    expect(res.status).toBe(200);
    expect(latched(replacement.id)).toEqual([newDigest]);
    expect(as.kernel.effectiveAuthoritySet(as.kernel.get(replacement.id) as MissionRecord).map((e) => e.actions)).toEqual([
      ["payments:invoice.read"],
    ]);
  });
});

// ---------------------------------------------------------------------------
// The Discharge Receipt.
// ---------------------------------------------------------------------------

describe("the Discharge Receipt (@spec discharge#discharge-receipt, #898 fix 3)", () => {
  it("answers a caller without Status read rights with a signed receipt bound to its aud and nonce, and replays it", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    const target = digestOf(child, "payments:invoice.list");
    // The source learned a SELECTOR for the old child before the carryover.
    const selector = as.kernel.dischargeSelectors.selectorFor({
      mission_id: child.id,
      entry_digest: target,
      condition_digest: CONDITION_DIGEST,
    });
    const batch = expandAndCarry(pred.id);
    const replacement = replacementOf(batch, child);
    const { entry_digest: _e, condition_digest: _c, ...rest } = body(child, "payments:invoice.list");
    const req = { ...rest, condition_selector: selector };

    // The source holds mission_discharge but NOT mission_status: the Status
    // operation refuses it, so it may not inspect the replacement.
    const status = await fetch(`${ISSUER}/missions/${replacement.id}/status`, {
      headers: { "x-service-token": SOURCE_TOKEN },
    });
    expect(status.status).toBe(404);

    const res = await lifecycle(child.id, req, SOURCE_TOKEN);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/mission-discharge-receipt+jwt");
    const bytes = await res.text();
    const header = decodeProtectedHeader(bytes);
    expect(header).toMatchObject({ typ: "mission-discharge-receipt+jwt", alg: "ES256" });
    expect(typeof header.kid).toBe("string");
    const payload = decodeJwt(bytes) as Record<string, unknown>;
    expect(Object.keys(payload).sort()).toEqual(["aud", "discharge_receipt", "exp", "iat", "iss", "nonce"]);
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe(SOURCE);
    expect(payload.nonce).toBe(req.nonce);
    expect((payload.exp as number) - (payload.iat as number)).toBe(60);
    expect(payload.discharge_receipt).toEqual({
      mission_id: child.id,
      condition_selector: selector,
      event_id: req.event_id,
      outcome: "forwarded",
    });
    // No mission member, no versions, never the replacement.
    expect(bytes.includes(replacement.id)).toBe(false);
    expect(JSON.stringify(payload).includes(replacement.id)).toBe(false);
    // The forwarded discharge committed on the replacement.
    expect(latched(replacement.id)).toEqual([digestOf(replacement, "payments:invoice.list")]);
    const committedVersion = (as.kernel.get(replacement.id) as MissionRecord).version;

    // It verifies under the consumer's eight checks, against the AS's jwks_uri.
    await expect(
      verifyDischargeReceipt(bytes, {
        keys,
        algs: ["ES256"],
        issuer: ISSUER,
        audience: SOURCE,
        nonce: req.nonce,
        missionId: child.id,
        sent: { condition_selector: selector, event_id: req.event_id },
        now: Math.floor(Date.now() / 1000),
      }),
    ).resolves.toMatchObject({ aud: SOURCE });

    // A byte-identical retransmission replays the stored receipt bytes.
    const again = await lifecycle(child.id, req, SOURCE_TOKEN);
    expect(again.headers.get("content-type")).toBe("application/mission-discharge-receipt+jwt");
    expect(await again.text()).toBe(bytes);
    // A fresh-nonce replay of the same event, in the OTHER form, is a replay:
    // a NEW receipt echoing the new nonce and the digest form it sent.
    const fresh = await lifecycle(
      child.id,
      { ...rest, nonce: freshNonce(), entry_digest: target, condition_digest: CONDITION_DIGEST },
      SOURCE_TOKEN,
    );
    const freshBytes = await fresh.text();
    expect(freshBytes).not.toBe(bytes);
    const freshPayload = decodeJwt(freshBytes) as Record<string, unknown>;
    expect(freshPayload.nonce).not.toBe(req.nonce);
    expect(freshPayload.discharge_receipt).toEqual({
      mission_id: child.id,
      entry_digest: target,
      condition_digest: CONDITION_DIGEST,
      event_id: req.event_id,
      outcome: "forwarded",
    });
    expect((as.kernel.get(replacement.id) as MissionRecord).version).toBe(committedVersion);
  });
});

// ---------------------------------------------------------------------------
// The consumer side (test-side verifier: no production consumer exists here).
// ---------------------------------------------------------------------------

describe("discharge response consumers (@spec discharge#discharge-receipt, #discharge-carryover)", () => {
  const NOW = 1_800_000_000;
  let signingKey: CryptoKey;
  let localKeys: JWTVerifyGetKey;

  beforeAll(async () => {
    const pair = await generateKeyPair("ES256");
    signingKey = pair.privateKey as CryptoKey;
    localKeys = async () => pair.publicKey;
  });

  const SENT: SentTarget = { condition_selector: "dcs_selectorUnderTest00000", event_id: "close-x" };
  const GOOD_RECEIPT = {
    iss: "https://as.test",
    aud: "svc:close-source",
    nonce: "nonce-x",
    iat: NOW,
    exp: NOW + 60,
    discharge_receipt: { mission_id: "msn_old", ...SENT, outcome: "forwarded" },
  };
  const receiptOpts = {
    algs: ["ES256"],
    issuer: "https://as.test",
    audience: "svc:close-source",
    nonce: "nonce-x",
    missionId: "msn_old",
    sent: SENT,
    now: NOW,
  };

  const sign = (payload: Record<string, unknown>, typ: string, key: CryptoKey = signingKey) =>
    new SignJWT(payload).setProtectedHeader({ alg: "ES256", kid: "as-status", typ }).sign(key);

  it("relies on a Discharge Receipt only after all eight checks, each of which refuses on its own", async () => {
    const opts = { ...receiptOpts, keys: localKeys };
    await expect(verifyDischargeReceipt(await sign(GOOD_RECEIPT, RECEIPT_TYP), opts)).resolves.toBeDefined();
    const refusals: Array<[string, () => Promise<unknown>]> = [
      // 1. typ
      ["typ", async () => verifyDischargeReceipt(await sign(GOOD_RECEIPT, "JWT"), opts)],
      // 2. alg: unsigned `none`, and an algorithm the AS does not advertise
      [
        "alg",
        async () => verifyDischargeReceipt(
          `${Buffer.from(JSON.stringify({ alg: "none", typ: RECEIPT_TYP })).toString("base64url")}.${Buffer.from(JSON.stringify(GOOD_RECEIPT)).toString("base64url")}.`,
          opts,
        ),
      ],
      ["alg", async () => verifyDischargeReceipt(await sign(GOOD_RECEIPT, RECEIPT_TYP), { ...opts, algs: ["RS256"] })],
      // 3. signature: a key that is not the AS's
      [
        "signature",
        async () => verifyDischargeReceipt(
          await sign(GOOD_RECEIPT, RECEIPT_TYP, (await generateKeyPair("ES256")).privateKey as CryptoKey),
          opts,
        ),
      ],
      // 4. iss
      ["iss", async () => verifyDischargeReceipt(await sign({ ...GOOD_RECEIPT, iss: "https://evil.test" }, RECEIPT_TYP), opts)],
      // 5. aud
      ["aud", async () => verifyDischargeReceipt(await sign({ ...GOOD_RECEIPT, aud: "svc:other" }, RECEIPT_TYP), opts)],
      // 6. nonce
      ["nonce", async () => verifyDischargeReceipt(await sign({ ...GOOD_RECEIPT, nonce: "nonce-y" }, RECEIPT_TYP), opts)],
      // 7. the echoed mission_id, target form and event_id
      [
        "echo",
        async () => verifyDischargeReceipt(
          await sign({ ...GOOD_RECEIPT, discharge_receipt: { ...GOOD_RECEIPT.discharge_receipt, mission_id: "msn_other" } }, RECEIPT_TYP),
          opts,
        ),
      ],
      [
        "echo",
        async () => verifyDischargeReceipt(
          await sign(
            { ...GOOD_RECEIPT, discharge_receipt: { ...GOOD_RECEIPT.discharge_receipt, condition_selector: "dcs_other" } },
            RECEIPT_TYP,
          ),
          opts,
        ),
      ],
      [
        "echo",
        async () => verifyDischargeReceipt(
          await sign({ ...GOOD_RECEIPT, discharge_receipt: { ...GOOD_RECEIPT.discharge_receipt, event_id: "close-y" } }, RECEIPT_TYP),
          opts,
        ),
      ],
      // 8. iat in the future, exp in the past (beyond 30 s of skew)
      ["lifetime", async () => verifyDischargeReceipt(await sign({ ...GOOD_RECEIPT, iat: NOW + 31 }, RECEIPT_TYP), opts)],
      ["lifetime", async () => verifyDischargeReceipt(await sign({ ...GOOD_RECEIPT, exp: NOW - 31 }, RECEIPT_TYP), opts)],
    ];
    for (const [check, attempt] of refusals) {
      await expect(attempt()).rejects.toMatchObject({ check });
    }
    // Within the skew: accepted.
    await expect(
      verifyDischargeReceipt(await sign({ ...GOOD_RECEIPT, iat: NOW + 30, exp: NOW - 30 }, RECEIPT_TYP), opts),
    ).resolves.toBeDefined();
  });

  it("verifies a forwarded Status response by forwarded_from in place of the mission.id check", async () => {
    const pred = approvePredecessor();
    const child = addChild(pred.id);
    const batch = expandAndCarry(pred.id);
    const replacement = replacementOf(batch, child);
    const req = body(child, "payments:invoice.list");
    const jws = await (await lifecycle(child.id, req)).text();
    const base = {
      keys,
      algs: ["ES256"],
      issuer: ISSUER,
      audience: "svc:console",
      nonce: req.nonce,
      missionId: child.id,
      now: Math.floor(Date.now() / 1000),
    };
    // A consumer implementing Discharge After Carryover accepts it, reading
    // `mission` as the replacement.
    const payload = await verifyStatusResponse(jws, { ...base, forwarded: true });
    expect((payload.mission as Record<string, unknown>).id).toBe(replacement.id);
    // A consumer that does not implement it rejects at step 8: fails closed.
    await expect(verifyStatusResponse(jws, base)).rejects.toMatchObject({ check: "mission" });

    // forwarded_from must name the REQUESTED Mission, and its issuer must be
    // the envelope's mission.issuer.
    const forged = (over: Record<string, unknown>) =>
      new SignJWT({
        nonce: "n",
        iat: NOW,
        exp: NOW + 60,
        mission: { id: "msn_replacement", issuer: "https://as.test" },
        discharge_result: { outcome: "discharged", forwarded_from: { issuer: "https://as.test", id: "msn_old" } },
        ...over,
      })
        .setProtectedHeader({ alg: "ES256", kid: "as-status", typ: STATUS_TYP })
        .setIssuer("https://as.test")
        .setAudience("svc:console")
        .sign(signingKey);
    const local = { keys: localKeys, algs: ["ES256"], issuer: "https://as.test", audience: "svc:console", nonce: "n", now: NOW, forwarded: true };
    await expect(verifyStatusResponse(await forged({}), { ...local, missionId: "msn_old" })).resolves.toBeDefined();
    await expect(verifyStatusResponse(await forged({}), { ...local, missionId: "msn_someone_else" })).rejects.toMatchObject({
      check: "mission",
    });
    await expect(
      verifyStatusResponse(
        await forged({
          discharge_result: { outcome: "discharged", forwarded_from: { issuer: "https://other-as.test", id: "msn_old" } },
        }),
        { ...local, missionId: "msn_old" },
      ),
    ).rejects.toMatchObject({ check: "mission" });
  });

  it("never accepts a Discharge Receipt as a Mission Status Response, nor the reverse", async () => {
    const receipt = await sign(GOOD_RECEIPT, RECEIPT_TYP);
    const status = await new SignJWT({
      nonce: "nonce-x",
      iat: NOW,
      exp: NOW + 60,
      mission: { id: "msn_old", issuer: "https://as.test" },
    })
      .setProtectedHeader({ alg: "ES256", kid: "as-status", typ: STATUS_TYP })
      .setIssuer("https://as.test")
      .setAudience("svc:close-source")
      .sign(signingKey);
    const common = { keys: localKeys, algs: ["ES256"], issuer: "https://as.test", audience: "svc:close-source", nonce: "nonce-x", now: NOW };
    // Each verifies as itself...
    await expect(verifyDischargeReceipt(receipt, { ...common, missionId: "msn_old", sent: SENT })).resolves.toBeDefined();
    await expect(verifyStatusResponse(status, { ...common, missionId: "msn_old" })).resolves.toBeDefined();
    // ...and neither as the other, refused at the exact typ check.
    await expect(verifyStatusResponse(receipt, { ...common, missionId: "msn_old" })).rejects.toBeInstanceOf(
      ConsumerVerificationError,
    );
    await expect(verifyStatusResponse(receipt, { ...common, missionId: "msn_old" })).rejects.toMatchObject({ check: "typ" });
    await expect(verifyDischargeReceipt(status, { ...common, missionId: "msn_old", sent: SENT })).rejects.toMatchObject({
      check: "typ",
    });
  });
});
