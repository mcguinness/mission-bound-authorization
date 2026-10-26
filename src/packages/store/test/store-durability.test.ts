/**
 * #1684 (D826): a store's durability is configured independently of its
 * locking. `synchronous: "FULL"` sets and verifies synchronous=FULL (2) under
 * normal locking; `exclusive` keeps implying it; and an open whose requested
 * durability did not take is refused.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { openStore, StoreDurabilityError } from "../src/index.js";

const dirs: string[] = [];
const fileIn = (): string => {
  const dir = mkdtempSync(join(tmpdir(), "store-durability-"));
  dirs.push(dir);
  return join(dir, "store.db");
};

afterEach(() => {
  vi.restoreAllMocks();
});
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("store durability, independent of locking (#1684, D826)", () => {
  it("sets synchronous=FULL under normal locking on every open, a reopened WAL file included, and a second connection still opens the file", () => {
    const file = fileIn();
    for (let open = 0; open < 2; open++) {
      const db = openStore("", { file, synchronous: "FULL" });
      expect(String(db.pragma("journal_mode", { simple: true })).toLowerCase()).toBe("wal");
      expect(db.pragma("synchronous", { simple: true }), `open ${open}`).toBe(2);
      expect(String(db.pragma("locking_mode", { simple: true })).toLowerCase()).toBe("normal");
      const second = openStore("", { file });
      second.close();
      db.close();
    }
  });

  it("without the option, a reopened WAL file runs at WAL's default NORMAL; exclusive locking keeps FULL", () => {
    // A fresh file switched into WAL reports FULL, but a reopened WAL file
    // takes WAL's default, NORMAL (1): durability that held only until the
    // first restart.
    const file = fileIn();
    openStore("", { file }).close();
    const reopened = openStore("", { file });
    expect(reopened.pragma("synchronous", { simple: true })).toBe(1);
    reopened.close();
    const exclusiveFile = fileIn();
    openStore("", { file: exclusiveFile, exclusive: true }).close();
    const exclusive = openStore("", { file: exclusiveFile, exclusive: true });
    expect(exclusive.pragma("synchronous", { simple: true })).toBe(2);
    expect(String(exclusive.pragma("locking_mode", { simple: true })).toLowerCase()).toBe(
      "exclusive",
    );
    exclusive.close();
  });

  it("refuses the open when synchronous=FULL does not take", () => {
    const pragma = Database.prototype.pragma;
    vi.spyOn(Database.prototype, "pragma").mockImplementation(function (
      this: Database.Database,
      source: string,
      options?: Database.PragmaOptions,
    ) {
      if (source === "synchronous" && options?.simple) return 1;
      return pragma.call(this, source, options);
    });
    expect(() => openStore("", { file: fileIn(), synchronous: "FULL" })).toThrow(
      StoreDurabilityError,
    );
  });
});
