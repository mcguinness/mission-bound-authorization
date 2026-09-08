import { describe, expect, it } from "vitest";
import { afterCommit, openStore, withTransaction } from "../src/index.js";

describe("managed transaction publication", () => {
  it("publishes nested work only after the outermost commit and discards rolled-back savepoint work", () => {
    const db = openStore("CREATE TABLE facts (value TEXT)");
    const observed: string[] = [];
    try {
      withTransaction(db, () => {
        db.prepare("INSERT INTO facts VALUES (?)").run("outer");
        afterCommit(db, () => {
          expect(db.inTransaction).toBe(false);
          observed.push("outer");
        });
        expect(() =>
          withTransaction(db, () => {
            db.prepare("INSERT INTO facts VALUES (?)").run("rolled back");
            afterCommit(db, () => observed.push("rolled back"));
            throw new Error("savepoint fault");
          }),
        ).toThrow("savepoint fault");
        withTransaction(db, () => afterCommit(db, () => observed.push("inner")));
        expect(observed).toEqual([]);
      });
      expect(observed).toEqual(["outer", "inner"]);
      expect(db.prepare("SELECT value FROM facts").all()).toEqual([{ value: "outer" }]);
    } finally {
      db.close();
    }
  });
  it("discards successful inner work when the outer transaction rolls back", () => {
    const db = openStore("CREATE TABLE facts (value TEXT)");
    const observed: string[] = [];
    try {
      expect(() =>
        withTransaction(db, () => {
          withTransaction(db, () => {
            db.prepare("INSERT INTO facts VALUES (?)").run("inner");
            afterCommit(db, () => observed.push("inner"));
          });
          throw new Error("outer fault");
        }),
      ).toThrow("outer fault");
      expect(observed).toEqual([]);
      expect(db.prepare("SELECT value FROM facts").all()).toEqual([]);
      afterCommit(db, () => observed.push("outside"));
      expect(observed).toEqual(["outside"]);
    } finally {
      db.close();
    }
  });
  it("never mistakes a post-commit subscriber failure for a database rollback", () => {
    const db = openStore("CREATE TABLE facts (value TEXT)");
    try {
      expect(() =>
        withTransaction(db, () => {
          db.prepare("INSERT INTO facts VALUES (?)").run("committed");
          afterCommit(db, () => {
            throw new Error("subscriber fault");
          });
        }),
      ).toThrow("subscriber fault");
      expect(db.prepare("SELECT value FROM facts").all()).toEqual([{ value: "committed" }]);
      expect(db.inTransaction).toBe(false);
    } finally {
      db.close();
    }
  });
  it("refuses unmanaged outer transactions rather than publishing before their commit", () => {
    const db = openStore("CREATE TABLE facts (value TEXT)");
    try {
      db.exec("BEGIN");
      expect(() => afterCommit(db, () => {})).toThrow("managed transaction");
      expect(() => withTransaction(db, () => {})).toThrow("unmanaged transaction");
      db.exec("ROLLBACK");
    } finally {
      db.close();
    }
  });
});
