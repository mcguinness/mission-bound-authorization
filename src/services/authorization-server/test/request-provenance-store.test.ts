/**
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1, Q2 and Q5, #1963)
 *
 * The replay store's own guards, for both implementations: the in-memory
 * store, explicitly ephemeral, and the SQLite store the authorization server
 * keeps on its kernel's database. Each reserves a pair once, releases only a
 * reservation, answers a second commit of a committed token by its
 * reference, checks committability without changing anything, and keeps a
 * committed pair until the later of `exp` plus skew and its retention. The
 * SQLite store also returns the acceptance record exactly as reserved, and
 * keeps its pairs across a reopen of its database file.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Database, openStore } from "@mission/store";
import { afterAll, describe, expect, it } from "vitest";
import {
  InMemoryRequestProvenanceStore,
  type RequestProvenanceRecord,
  type RequestProvenanceStore,
  SqliteRequestProvenanceStore,
} from "../src/index.js";

const AT = Date.UTC(2026, 10, 2, 12);
const EXP = AT + 25_000;
const RETAIN = AT + 600_000;

const record = (jti: string, over: Partial<RequestProvenanceRecord> = {}): RequestProvenanceRecord => ({
  iss: "https://intake.example.org",
  jti,
  expiresAtMs: EXP,
  issuer: "https://as.example.org",
  intentHash: "sha-256:intent",
  presenter: { clientId: "ap-agent" },
  assertion: `header.${jti}.signature`,
  artifactHash: "sha-256:artifact",
  verifiedAt: new Date(AT).toISOString(),
  facts: { signer: "https://intake.example.org", assertion_id: jti },
  ...over,
});

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const STORES: Array<[string, () => RequestProvenanceStore]> = [
  ["in memory", () => new InMemoryRequestProvenanceStore()],
  ["on SQLite", () => new SqliteRequestProvenanceStore(openStore(""))],
];

describe.each(STORES)("the replay store's guards, %s (@spec request-provenance#replay, #1963)", (_name, create) => {
  it("reserves a pair once: while it is reserved or committed, another reservation of the pair is refused, and another pair reserves", async () => {
    const store = create();
    const token = await store.reserve(record("once"), AT);
    expect(token).toBeDefined();
    expect(await store.reserve(record("once", { assertion: "another.assertion.bytes" }), AT)).toBeUndefined();
    expect(store.commit(token as string, "par:once", AT, RETAIN)).toBe(true);
    expect(await store.reserve(record("once"), AT + 1)).toBeUndefined();
    expect(await store.reserve(record("other"), AT)).toBeDefined();
  });

  it("releases only a reservation: a committed pair's release keeps its acceptance record and its pair, and a reservation's frees the pair", async () => {
    const store = create();
    const committed = await store.reserve(record("store-committed"), AT);
    expect(store.commit(committed as string, "par:store-test", AT, RETAIN)).toBe(true);
    store.release(committed as string);
    expect(store.accepted(record("x").iss, "store-committed", AT)?.submissionRef).toBe("par:store-test");
    expect(await store.reserve(record("store-committed"), AT)).toBeUndefined();
    // The control: a reservation does release, idempotently, and its pair is free again.
    const reserved = await store.reserve(record("store-reserved"), AT);
    store.release(reserved as string);
    store.release(reserved as string);
    expect(store.committable(reserved as string, AT)).toBe(false);
    expect(await store.reserve(record("store-reserved"), AT)).toBeDefined();
  });

  it("answers a second commit of a committed token by its reference alone, and keeps the first commit's reference and retention", async () => {
    const store = create();
    const token = (await store.reserve(record("twice"), AT)) as string;
    expect(store.commit(token, "par:first", AT, RETAIN)).toBe(true);
    expect(store.commit(token, "par:first", AT + 1, RETAIN + 10_000)).toBe(true);
    expect(store.commit(token, "par:second", AT + 1, RETAIN + 10_000)).toBe(false);
    expect(store.accepted(record("x").iss, "twice", AT)?.submissionRef).toBe("par:first");
    // The first retention holds: past it the record is gone, though a later one was offered.
    expect(store.accepted(record("x").iss, "twice", RETAIN)).toBeUndefined();
  });

  it("checks committability without changing anything: true for a held reservation before exp plus skew, false once it lapses, is released, or is committed", async () => {
    const store = create();
    const token = (await store.reserve(record("check"), AT)) as string;
    expect(store.committable(token, AT)).toBe(true);
    expect(store.committable(token, AT)).toBe(true);
    expect(store.committable(token, EXP)).toBe(false);
    // Asking changed nothing: the reservation still commits before it lapses.
    expect(store.accepted(record("x").iss, "check", AT)).toBeUndefined();
    expect(store.commit(token, "par:check", AT, RETAIN)).toBe(true);
    expect(store.committable(token, AT)).toBe(false);
    const lapsing = (await store.reserve(record("lapsing"), AT)) as string;
    expect(store.commit(lapsing, "par:late", EXP, RETAIN)).toBe(false);
    expect(store.committable("rpr-unknown", AT)).toBe(false);
  });

  it("keeps a committed pair until the later of exp plus skew and its retention: found past exp within its retention, kept by the sweep there, and gone at its end", async () => {
    const store = create();
    const token = (await store.reserve(record("kept"), AT)) as string;
    expect(store.commit(token, "par:kept", AT, RETAIN)).toBe(true);
    // Past exp plus skew: a reservation would have lapsed; the committed pair is retained.
    expect(store.accepted(record("x").iss, "kept", EXP + 1)?.submissionRef).toBe("par:kept");
    // A reservation sweeps lapsed rows first, and this one has not lapsed.
    expect(await store.reserve(record("sweeper-1"), EXP + 1)).toBeDefined();
    expect(store.accepted(record("x").iss, "kept", EXP + 1)?.submissionRef).toBe("par:kept");
    expect(await store.reserve(record("kept"), EXP + 1)).toBeUndefined();
    // At the end of its retention the record is no longer found, swept or not.
    expect(store.accepted(record("x").iss, "kept", RETAIN)).toBeUndefined();
    expect(await store.reserve(record("sweeper-2", { expiresAtMs: RETAIN + 25_000 }), RETAIN)).toBeDefined();
    expect(await store.reserve(record("kept", { expiresAtMs: RETAIN + 25_000 }), RETAIN)).toBeDefined();
  });

  it("keeps a committed pair until exp plus skew when that is the later instant", async () => {
    const store = create();
    const token = (await store.reserve(record("exp-later"), AT)) as string;
    expect(store.commit(token, "par:exp-later", AT, AT + 1_000)).toBe(true);
    expect(store.accepted(record("x").iss, "exp-later", AT + 2_000)?.submissionRef).toBe("par:exp-later");
    expect(await store.reserve(record("exp-later"), AT + 2_000)).toBeUndefined();
    expect(store.accepted(record("x").iss, "exp-later", EXP)).toBeUndefined();
  });

  it("lets a reservation lapse at exp plus skew: the pair reserves again at that instant, and the lapsed token commits nothing", async () => {
    const store = create();
    const stale = (await store.reserve(record("lapse"), AT)) as string;
    expect(await store.reserve(record("lapse", { expiresAtMs: EXP + 25_000 }), EXP - 1)).toBeUndefined();
    const fresh = await store.reserve(record("lapse", { expiresAtMs: EXP + 25_000 }), EXP);
    expect(fresh).toBeDefined();
    expect(fresh).not.toBe(stale);
    expect(store.commit(stale, "par:stale", EXP, RETAIN)).toBe(false);
    expect(store.commit(fresh as string, "par:fresh", EXP, RETAIN)).toBe(true);
  });
});

describe("the SQLite replay store (@spec request-provenance#replay, D1119 Q5, #1963)", () => {
  it("returns the acceptance record exactly as reserved: presenter, facts, verification time, assertion and artifact hash", async () => {
    const store = new SqliteRequestProvenanceStore(openStore(""));
    const exact = record("exact", {
      presenter: { clientId: "ap-agent", cnf: { jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } },
      assertion: "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJleGFjdCJ9.c2ln",
      artifactHash: "sha-256:Ab-_09",
      verifiedAt: "2026-11-02T12:00:00.123Z",
      facts: {
        signer: "https://intake.example.org",
        originator: { iss: "https://idp.example.org", sub: "alice" },
        channel: { type: "https://intake.example.org/ch/app", amr: ["pwd", "otp"], auth_time: 1793534400, acr: null },
        captured_at: "2026-11-02T11:59:55Z",
        request_digest: "sha-256:digest",
        note: "café ☃ 🔒 \"quoted\" \\ back",
        nested: [[1, 2.5, -3], { empty: {}, none: [] }, true, false],
      },
    });
    const token = (await store.reserve(exact, AT)) as string;
    expect(store.commit(token, "par:exact", AT, RETAIN)).toBe(true);
    expect(store.accepted(exact.iss, exact.jti, AT)).toStrictEqual({ ...exact, submissionRef: "par:exact" });
  });

  it("keeps its pairs across a reopen of its database file: a committed pair is still refused and its record found, a reservation still holds its pair until exp plus skew, and a released pair is free", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rp-store-reopen-"));
    dirs.push(dir);
    const file = join(dir, "kernel.db");
    const open = (): { db: Database; store: SqliteRequestProvenanceStore } => {
      const db = openStore("", { file, synchronous: "FULL" });
      return { db, store: new SqliteRequestProvenanceStore(db) };
    };
    const first = open();
    const committed = (await first.store.reserve(record("reopen-committed"), AT)) as string;
    expect(first.store.commit(committed, "par:reopen", AT, RETAIN)).toBe(true);
    expect(await first.store.reserve(record("reopen-reserved"), AT)).toBeDefined();
    const released = (await first.store.reserve(record("reopen-released"), AT)) as string;
    first.store.release(released);
    first.db.close();

    const second = open();
    try {
      expect(second.store.accepted(record("x").iss, "reopen-committed", AT)).toStrictEqual({
        ...record("reopen-committed"),
        submissionRef: "par:reopen",
      });
      expect(await second.store.reserve(record("reopen-committed"), AT)).toBeUndefined();
      expect(second.store.commit(committed, "par:reopen", AT, RETAIN)).toBe(true);
      expect(await second.store.reserve(record("reopen-reserved"), AT)).toBeUndefined();
      expect(await second.store.reserve(record("reopen-released"), AT)).toBeDefined();
      // The reservation of the closed handle lapses at exp plus skew, as any uncommitted one does.
      expect(await second.store.reserve(record("reopen-reserved", { expiresAtMs: EXP + 25_000 }), EXP)).toBeDefined();
    } finally {
      second.db.close();
    }
  });
});
