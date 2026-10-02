/**
 * The durable single-writer initializer (#917): the store a component names
 * in configuration is opened on that file, never on `openStore()`'s
 * `:memory:` default, and an unsafe topology is refused at open rather than
 * discovered at use. Every test runs against a real file in a fresh
 * temporary directory.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { DurableStoreError, openDurableStore } from "../src/index.js";

const MIGRATIONS = [
  "CREATE TABLE claims (k TEXT PRIMARY KEY) STRICT",
  "ALTER TABLE claims ADD COLUMN note TEXT",
];

function tempFile(): string {
  return join(mkdtempSync(join(tmpdir(), "durable-store-")), "store.sqlite");
}

describe("openDurableStore (#917)", () => {
  it("refuses an absent, empty or in-memory file", () => {
    for (const file of [undefined, "", "  ", ":memory:", "file::memory:?cache=shared"]) {
      expect(() => openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" }), String(file)).toThrow(
        DurableStoreError,
      );
    }
  });

  it("keeps committed rows across a close and reopen of the same file", () => {
    const file = tempFile();
    const first = openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" });
    first.prepare("INSERT INTO claims (k, note) VALUES ('a', 'kept')").run();
    first.close();
    const second = openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" });
    expect(second.prepare("SELECT note FROM claims WHERE k = 'a'").get()).toEqual({ note: "kept" });
    expect(second.pragma("user_version", { simple: true })).toBe(MIGRATIONS.length);
    second.close();
  });

  it("refuses a second handle while the first lives, and admits it after the first closes", () => {
    const file = tempFile();
    const first = openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" });
    expect(() => openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" })).toThrow(/locked/);
    // Not even a plain reader on the same file gets through.
    const raw = new Database(file, { timeout: 0 });
    expect(() => raw.prepare("SELECT COUNT(*) FROM claims").get()).toThrow(/locked/);
    raw.close();
    first.close();
    const second = openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" });
    second.close();
  });

  it("refuses a store whose schema is newer than this build's migrations", () => {
    const file = tempFile();
    openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" }).close();
    expect(() => openDurableStore({ file, migrations: MIGRATIONS.slice(0, 1), owner: "pdp" })).toThrow(
      /newer than this build/,
    );
  });

  it("refuses a store recorded for a different owner", () => {
    const file = tempFile();
    openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp-a" }).close();
    expect(() => openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp-b" })).toThrow(/owned by pdp-a/);
  });

  it("applies each pending migration once, in order", () => {
    const file = tempFile();
    openDurableStore({ file, migrations: MIGRATIONS.slice(0, 1), owner: "pdp" }).close();
    const db = openDurableStore({ file, migrations: MIGRATIONS, owner: "pdp" });
    db.prepare("INSERT INTO claims (k, note) VALUES ('b', 'second migration ran')").run();
    expect(db.pragma("user_version", { simple: true })).toBe(2);
    db.close();
  });
});
