import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DurableStoreError } from "@mission/store";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteRevocationStore } from "../src/index.js";

const PS = "https://ps.test";
const PS2 = "https://ps2.test";

let dir: string;
const open: SqliteRevocationStore[] = [];
const store = () => {
  const s = new SqliteRevocationStore(join(dir, "resource.db"));
  open.push(s);
  return s;
};

afterEach(() => {
  for (const s of open.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});

const entry = (iss: string, jti: string, exp: number) => ({ iss, jti, exp, recordedAt: 0 });

describe("the revoked set (@spec aauth#section-11.12.1, aauth#section-11.12.3)", () => {
  it("holds (iss, jti) while the time is before its exp", () => {
    dir = mkdtempSync(join(tmpdir(), "revoked-set-"));
    const s = store();
    expect(s.admit(entry(PS, "a", 100), 0, 10)).toEqual({ kind: "recorded" });
    expect(s.isRevoked(PS, "a", 99_999)).toBe(true);
    expect(s.isRevoked(PS, "a", 100_000)).toBe(false);
    expect(s.isRevoked(PS2, "a", 0)).toBe(false);
    expect(s.isRevoked(PS, "b", 0)).toBe(false);
  });

  it("records nothing new for a repeat and keeps the first exp", () => {
    dir = mkdtempSync(join(tmpdir(), "revoked-set-"));
    const s = store();
    s.admit(entry(PS, "a", 100), 0, 10);
    expect(s.admit(entry(PS, "a", 900), 0, 10)).toEqual({ kind: "repeat" });
    expect(s.entries()).toEqual([entry(PS, "a", 100)]);
  });

  it("counts only an issuer's unexpired entries against its bound, purged or not", () => {
    dir = mkdtempSync(join(tmpdir(), "revoked-set-"));
    const s = store();
    s.admit(entry(PS, "a", 100), 0, 1);
    expect(s.admit(entry(PS, "b", 200), 0, 1)).toEqual({ kind: "full", retryAfterSeconds: 100 });
    expect(s.admit(entry(PS2, "b", 200), 0, 1)).toEqual({ kind: "recorded" });
    // "a" lapsed at 100 and was never purged; it no longer counts.
    expect(s.admit(entry(PS, "b", 200), 100_000, 1)).toEqual({ kind: "recorded" });
  });

  it("discards entries whose exp has passed, and only those", () => {
    dir = mkdtempSync(join(tmpdir(), "revoked-set-"));
    const s = store();
    s.admit(entry(PS, "a", 100), 0, 10);
    s.admit(entry(PS, "b", 101), 0, 10);
    expect(s.purge(100_000)).toBe(1);
    expect(s.entries().map((e) => e.jti)).toEqual(["b"]);
  });

  it("is durable: a store reopened on the file holds what the first committed", () => {
    dir = mkdtempSync(join(tmpdir(), "revoked-set-"));
    const first = store();
    first.admit(entry(PS, "a", 100), 0, 10);
    first.close();
    open.splice(0);
    expect(store().isRevoked(PS, "a", 0)).toBe(true);
  });

  it("has one writer: a second store on the same file is refused", () => {
    dir = mkdtempSync(join(tmpdir(), "revoked-set-"));
    store();
    expect(() => new SqliteRevocationStore(join(dir, "resource.db"))).toThrow(DurableStoreError);
  });
});
