/**
 * @spec mission#approval-idempotency (#1922): an approval reservation is pruned
 * once it is older than the authorization interaction's lifetime plus the
 * declared clock skew, never less than the provider's clock tolerance (within
 * which an expired interaction is still accepted): every lapsed one when a
 * kernel opens the store, and a bounded batch on each reservation. A
 * reservation its interaction can still decide is never pruned, and a
 * committed decision replayed after its reservation was pruned still resolves
 * to its one Mission through `missions.approval_event_id`. A decision on an expired interaction is
 * refused before any reservation is consulted (approval-grant-binding.test.ts).
 *
 * Each kernel runs on a controlled clock; the intent's expiry derives from it.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MissionKernel, validateMissionIntent } from "../src/index.js";
import { INTERACTION_TTL_S, PROVIDER_CLOCK_TOLERANCE_S } from "../src/kernel/interaction-lifetime.js";
import { APPROVAL_RESERVATION_PRUNE_BATCH } from "../src/kernel/kernel.js";
import { DEFAULT_CLOCK_SKEW_S } from "../src/kernel/tombstones.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const TAG = "(@spec mission#approval-idempotency, #1922)";
const ISS = "https://as.test";
const KRESOURCE = DERIVATION_POLICY.ceiling[0].resource;
/** The reservation retention a kernel derives under the default declared skew. */
const RETENTION_MS = (INTERACTION_TTL_S + DEFAULT_CLOCK_SKEW_S) * 1000;
/** The controlled clock's starting instant. */
const T0 = Date.now();

let statusKey: CryptoKey;
const dirs: string[] = [];

beforeAll(async () => {
  statusKey = (await generateKeyPair("ES256")).privateKey;
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** A kernel reading `clock`, in memory or over `file`, with any declared skew. */
const kernelOn = (clock: { ms: number }, file?: string, clockSkewSeconds?: number) =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["worker"], ["bob"]),
    statusKey,
    statusKid: "as-status",
    now: () => new Date(clock.ms),
    ...(file ? { store: { file } } : {}),
    ...(clockSkewSeconds === undefined ? {} : { tombstoneHorizons: { clock_skew_seconds: clockSkewSeconds } }),
  });

const reserve = (k: MissionKernel, approvalEventId: string, approver = "bob") =>
  k.reserveApproval({
    approvalEventId,
    approver: { iss: ISS, sub: approver },
    subject: { iss: ISS, sub: "alice" },
    clientId: "worker",
    grantId: `grant-${approvalEventId}`,
  });

/** The reservations the store holds, read from the table itself. */
const reserved = (k: MissionKernel) =>
  (
    k.db.prepare("SELECT approval_event_id FROM approval_reservations ORDER BY approval_event_id").all() as Array<{
      approval_event_id: string;
    }>
  ).map((r) => r.approval_event_id);

const approveInput = (approvalEventId: string) => ({
  intent: validateMissionIntent(
    JSON.stringify({
      goal: "reconcile Acme",
      target_resources: [KRESOURCE],
      expires_at: new Date(T0 + 30 * 24 * 60 * 60 * 1000).toISOString(),
    }),
  ),
  subject: { iss: ISS, sub: "alice" },
  approver: { iss: ISS, sub: "bob" },
  clientId: "worker",
  approvalEventId,
});

describe(`approval reservation pruning ${TAG}`, () => {
  it(`keeps a reservation exactly at the interaction lifetime plus skew and prunes it 1 ms after, on the next reservation ${TAG}`, () => {
    const clock = { ms: T0 };
    const k = kernelOn(clock);
    expect(reserve(k, "apev-a")).toBe(true);
    clock.ms = T0 + RETENTION_MS;
    expect(reserve(k, "apev-b")).toBe(true);
    expect(reserved(k)).toEqual(["apev-a", "apev-b"]);
    clock.ms = T0 + RETENTION_MS + 1;
    expect(reserve(k, "apev-c")).toBe(true);
    expect(reserved(k)).toEqual(["apev-b", "apev-c"]);
  });

  it(`keeps a reservation for the provider's clock tolerance past the interaction lifetime when a smaller skew is declared ${TAG}`, () => {
    const clock = { ms: T0 };
    const k = kernelOn(clock, undefined, 0);
    const floorMs = (INTERACTION_TTL_S + PROVIDER_CLOCK_TOLERANCE_S) * 1000;
    expect(reserve(k, "apev-a")).toBe(true);
    clock.ms = T0 + floorMs;
    expect(reserve(k, "apev-b")).toBe(true);
    expect(reserved(k)).toEqual(["apev-a", "apev-b"]);
    clock.ms = T0 + floorMs + 1;
    expect(reserve(k, "apev-c")).toBe(true);
    expect(reserved(k)).toEqual(["apev-b", "apev-c"]);
  });

  it(`never prunes a reservation its interaction can still decide: at the bound a retry still matches and another Approver is still refused ${TAG}`, () => {
    const clock = { ms: T0 };
    const k = kernelOn(clock);
    expect(reserve(k, "apev-live")).toBe(true);
    clock.ms = T0 + RETENTION_MS;
    expect(reserve(k, "apev-live", "mallory")).toBe(false);
    expect(reserve(k, "apev-live")).toBe(true);
    expect(reserved(k)).toEqual(["apev-live"]);
  });

  it(`prunes every lapsed reservation, more than one reservation's batch, when a kernel opens the store, and keeps the rest ${TAG}`, () => {
    const dir = mkdtempSync(join(tmpdir(), "reservation-prune-"));
    dirs.push(dir);
    const file = join(dir, "kernel.sqlite");
    const clock = { ms: T0 };
    const first = kernelOn(clock, file);
    for (let i = 0; i <= APPROVAL_RESERVATION_PRUNE_BATCH; i++) expect(reserve(first, `apev-old-${i}`)).toBe(true);
    clock.ms = T0 + 1;
    expect(reserve(first, "apev-young")).toBe(true);
    first.close();

    clock.ms = T0 + RETENTION_MS + 1;
    const reopened = kernelOn(clock, file);
    try {
      expect(reserved(reopened)).toEqual(["apev-young"]);
    } finally {
      reopened.close();
    }
  });

  it(`prunes at most ${APPROVAL_RESERVATION_PRUNE_BATCH} lapsed reservations on one reservation, oldest first, so a backlog drains over the next ones ${TAG}`, () => {
    const clock = { ms: T0 };
    const k = kernelOn(clock);
    const lapsing = APPROVAL_RESERVATION_PRUNE_BATCH + 20;
    const ids = Array.from({ length: lapsing }, (_, i) => `apev-old-${String(i).padStart(4, "0")}`);
    ids.forEach((id, i) => {
      clock.ms = T0 + i;
      expect(reserve(k, id)).toBe(true);
    });
    clock.ms = T0 + lapsing + RETENTION_MS;
    expect(reserve(k, "apev-new-1")).toBe(true);
    expect(reserved(k)).toEqual([...ids.slice(APPROVAL_RESERVATION_PRUNE_BATCH), "apev-new-1"].sort());
    expect(reserve(k, "apev-new-2")).toBe(true);
    expect(reserved(k)).toEqual(["apev-new-1", "apev-new-2"]);
  });

  it(`a decision replayed after its reservation was pruned resolves to its one Mission and creates none ${TAG}`, () => {
    const clock = { ms: T0 };
    const k = kernelOn(clock);
    const event = "apev-committed";
    expect(reserve(k, event)).toBe(true);
    const committed = k.approve(approveInput(event));

    clock.ms = T0 + RETENTION_MS + 1;
    expect(reserve(k, "apev-other")).toBe(true);
    expect(reserved(k), "the committed decision's reservation was not pruned").toEqual(["apev-other"]);

    // The decision delivered again: the reservation is taken afresh, and the
    // commit meets the Mission its event already created.
    expect(reserve(k, event)).toBe(true);
    const replayed = k.approve(approveInput(event));
    expect(replayed.id).toBe(committed.id);
    expect(k.findByApprovalEvent(event)?.id).toBe(committed.id);
    expect(k.db.prepare("SELECT COUNT(*) AS n FROM missions WHERE approval_event_id = ?").get(event)).toEqual({ n: 1 });
    expect(k.db.prepare("SELECT COUNT(*) AS n FROM missions").get()).toEqual({ n: 1 });
  });
});
