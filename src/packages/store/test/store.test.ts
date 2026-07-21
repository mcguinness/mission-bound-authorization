import { describe, expect, it } from "vitest";
import {
  openStore,
  redeemOnce,
  redemptionSchema,
  UniqueViolationError,
  withTransaction,
} from "../src/index.js";

const SCHEMA = `
CREATE TABLE missions (
  id TEXT PRIMARY KEY,
  approval_event_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL
) STRICT;
${redemptionSchema("permit_redemptions")}
`;

describe("store baseline (D27)", () => {
  it("enforces idempotency via UNIQUE (approval_event_id)", () => {
    const db = openStore(SCHEMA);
    const insert = () =>
      withTransaction(db, () => {
        db.prepare("INSERT INTO missions (id, approval_event_id, state) VALUES (?, ?, ?)").run(
          crypto.randomUUID(),
          "appr-1",
          "active",
        );
      });
    insert();
    expect(insert).toThrow(UniqueViolationError);
  });

  it("transactions are atomic", () => {
    const db = openStore(SCHEMA);
    expect(() =>
      withTransaction(db, () => {
        db.prepare("INSERT INTO missions (id, approval_event_id, state) VALUES (?, ?, ?)").run(
          "m1",
          "appr-2",
          "active",
        );
        throw new Error("boom");
      }),
    ).toThrow("boom");
    expect(db.prepare("SELECT COUNT(*) AS n FROM missions").get()).toEqual({ n: 0 });
  });

  it("redeemOnce returns true exactly once per permit key (D28 PEP redemption)", () => {
    const db = openStore(SCHEMA);
    expect(redeemOnce(db, "permit_redemptions", "permit-1", "epoch-a")).toBe(true);
    expect(redeemOnce(db, "permit_redemptions", "permit-1", "epoch-a")).toBe(false);
    expect(redeemOnce(db, "permit_redemptions", "permit-2", "epoch-a")).toBe(true);
  });
});
