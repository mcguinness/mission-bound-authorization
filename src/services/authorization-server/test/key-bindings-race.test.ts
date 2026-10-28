/**
 * @spec #1815 gap 5 (D945), #1833: the key binding record under concurrent
 * writers. Two loads, initializations or appends in one process never both
 * succeed against one version of the record, and never lose each other's
 * appends. Across processes an append takes the record's lock and re-reads
 * and re-checks the record under it; another process's append finished just
 * before the lock is taken is simulated by a hook in `holdFileLock`, which
 * this file wraps along with `writeDurableFile`.
 */

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it, vi } from "vitest";

/** One `beforeLock` runs once, as another process's write finished just before the lock is taken; `failWrite` fails the next record write once. */
const hooks = vi.hoisted(() => ({ beforeLock: undefined as (() => void) | undefined, failWrite: false }));

vi.mock("@mission/store", async (importOriginal) => {
  const store = await importOriginal<typeof import("@mission/store")>();
  return {
    ...store,
    holdFileLock: (file: string) => {
      const before = hooks.beforeLock;
      hooks.beforeLock = undefined;
      before?.();
      return store.holdFileLock(file);
    },
    writeDurableFile: (file: string, contents: string) => {
      if (hooks.failWrite) {
        hooks.failWrite = false;
        throw Object.assign(new Error("injected write failure"), { code: "EIO" });
      }
      store.writeDurableFile(file, contents);
    },
  };
});

const { holdFileLock } = await import("@mission/store");
const {
  checkKeyBindings,
  compromiseSigningKeyGeneration,
  initKeyBindings,
  initSigningKeyRing,
  KeyBindingError,
  loadSigningKeyRing,
} = await import("../src/index.js");
type KeyBindingRecord = import("../src/index.js").KeyBindingRecord;

const ISSUER = "https://as.example.test";
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

/** A ring path and a binding record in separate directories. */
function layout() {
  const root = mkdtempSync(join(tmpdir(), "key-bindings-race-"));
  return { root, ring: join(root, "keys", "ring.json"), file: join(root, "bindings", "key-bindings.json") };
}

async function key(kid: string) {
  const { publicKey } = await generateKeyPair("ES256");
  return { role: "asStatus", baseKid: "status", kid, publicJwk: { ...(await exportJWK(publicKey)), kid } };
}

const record = (file: string) => JSON.parse(readFileSync(file, "utf8")) as KeyBindingRecord;
const kidsOf = (file: string) => record(file).bindings.map((b) => b.kid);
const jktOf = (file: string, kid: string) => record(file).bindings.find((b) => b.kid === kid)?.jkt;
const rejected = (results: PromiseSettledResult<unknown>[]) =>
  results.filter((r): r is PromiseRejectedResult => r.status === "rejected").map((r) => r.reason as Error);

describe("the key binding record under concurrent writers (@spec #1815, #1833)", () => {
  it("concurrent appends retain both accepted identifiers", async () => {
    const { ring, file } = layout();
    const [base, a, b] = await Promise.all([key("status"), key("status-2"), key("status-3")]);
    await initKeyBindings(file, ring, ISSUER, [base]);
    await Promise.all([checkKeyBindings(file, ring, ISSUER, [base, a]), checkKeyBindings(file, ring, ISSUER, [base, b])]);
    expect(kidsOf(file).sort()).toEqual(["status", "status-2", "status-3"]);
  });

  it("concurrent conflicting first uses of a kid cannot both succeed", async () => {
    const { ring, file } = layout();
    const [base, a, b] = await Promise.all([key("status"), key("status-2"), key("status-2")]);
    await initKeyBindings(file, ring, ISSUER, [base]);
    const results = await Promise.allSettled([
      checkKeyBindings(file, ring, ISSUER, [base, a]),
      checkKeyBindings(file, ring, ISSUER, [base, b]),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual(["fulfilled", "rejected"]);
    expect(rejected(results)[0]?.message).toMatch(/the ring holds status-2 with key material other than/);
    expect(kidsOf(file)).toEqual(["status", "status-2"]);
  });

  it("concurrent initialization cannot replace a record created by the other caller", async () => {
    const { ring, file } = layout();
    const [a, b] = await Promise.all([key("status"), key("status")]);
    const results = await Promise.allSettled([
      initKeyBindings(file, ring, ISSUER, [a]),
      initKeyBindings(file, ring, ISSUER, [b]),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual(["fulfilled", "rejected"]);
    expect(rejected(results)[0]).toBeInstanceOf(KeyBindingError);
    expect(rejected(results)[0]?.message).toMatch(/already exists; a key binding record is created once/);
    const created = results.find((r): r is PromiseFulfilledResult<KeyBindingRecord> => r.status === "fulfilled")?.value;
    expect(record(file)).toEqual(created);
  });

  it("two boot loads cannot accept competing replacement material under the same kid", async () => {
    const root = mkdtempSync(join(tmpdir(), "key-bindings-race-"));
    const ringA = join(root, "a", "ring.json");
    const ringB = join(root, "b", "ring.json");
    const bindings = join(root, "bindings", "key-bindings.json");
    await initSigningKeyRing(ringA, ISSUER, ROLES, undefined, { bindings });
    mkdirSync(join(root, "b"), { mode: 0o700 });
    writeFileSync(ringB, readFileSync(ringA), { mode: 0o600 });
    const status = ROLES.asStatus.kid;
    // Each copy mints its own replacement under the same next kid.
    const [doneA, doneB] = [
      await compromiseSigningKeyGeneration(ringA, ISSUER, ROLES, "asStatus", status, { bindings }),
      await compromiseSigningKeyGeneration(ringB, ISSUER, ROLES, "asStatus", status, { bindings }),
    ];
    expect(doneA.replacement).toBe(`${status}-2`);
    expect(doneB.replacement).toBe(`${status}-2`);
    const results = await Promise.allSettled([
      loadSigningKeyRing(ringA, ISSUER, ROLES, { bindings }),
      loadSigningKeyRing(ringB, ISSUER, ROLES, { bindings }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual(["fulfilled", "rejected"]);
    expect(rejected(results)[0]?.message).toMatch(new RegExp(`the ring holds ${status}-2 with key material other than`));
    expect(kidsOf(bindings).filter((k) => k === `${status}-2`)).toHaveLength(1);
  });

  it("refuses an append while another writer holds the record's lock, leaving the record as it was; a check with nothing to append still passes", async () => {
    const { ring, file } = layout();
    const [base, a] = await Promise.all([key("status"), key("status-2")]);
    await initKeyBindings(file, ring, ISSUER, [base]);
    const before = readFileSync(file, "utf8");
    const held = holdFileLock(`${file}.lock`);
    try {
      await expect(checkKeyBindings(file, ring, ISSUER, [base, a])).rejects.toThrow(
        /cannot record status-2 in .*: another writer holds .*\.lock; retry once it finishes/,
      );
      expect(readFileSync(file, "utf8")).toBe(before);
      await checkKeyBindings(file, ring, ISSUER, [base]);
    } finally {
      held.close();
    }
    await checkKeyBindings(file, ring, ISSUER, [base, a]);
    expect(kidsOf(file)).toEqual(["status", "status-2"]);
  });

  it("re-reads the record under its lock: another process's append finished just before it is kept", async () => {
    const { ring, file } = layout();
    const [base, a] = await Promise.all([key("status"), key("status-2")]);
    await initKeyBindings(file, ring, ISSUER, [base]);
    const theirs = record(file);
    let ran = false;
    hooks.beforeLock = () => {
      ran = true;
      theirs.bindings.push({ role: "asStatus", kid: "status-3", jkt: "their-jkt", recorded_at: "2026-10-28T00:00:00.000Z" });
      writeFileSync(file, `${JSON.stringify(theirs, null, 2)}\n`);
    };
    await checkKeyBindings(file, ring, ISSUER, [base, a]);
    expect(ran).toBe(true);
    expect(kidsOf(file).sort()).toEqual(["status", "status-2", "status-3"]);
    expect(jktOf(file, "status-3")).toBe("their-jkt");
  });

  it("re-checks the record under its lock: another process's binding of the same kid finished just before it refuses this one", async () => {
    const { ring, file } = layout();
    const [base, a] = await Promise.all([key("status"), key("status-2")]);
    await initKeyBindings(file, ring, ISSUER, [base]);
    const theirs = record(file);
    let ran = false;
    hooks.beforeLock = () => {
      ran = true;
      theirs.bindings.push({ role: "asStatus", kid: "status-2", jkt: "their-jkt", recorded_at: "2026-10-28T00:00:00.000Z" });
      writeFileSync(file, `${JSON.stringify(theirs, null, 2)}\n`);
    };
    await expect(checkKeyBindings(file, ring, ISSUER, [base, a])).rejects.toThrow(
      /the ring holds status-2 with key material other than .* records for it/,
    );
    expect(ran).toBe(true);
    expect(kidsOf(file)).toEqual(["status", "status-2"]);
    expect(jktOf(file, "status-2")).toBe("their-jkt");
  });

  it("refuses an append whose write fails under the lock, leaving the record as it was", async () => {
    const { ring, file } = layout();
    const [base, a] = await Promise.all([key("status"), key("status-2")]);
    await initKeyBindings(file, ring, ISSUER, [base]);
    const before = readFileSync(file, "utf8");
    hooks.failWrite = true;
    await expect(checkKeyBindings(file, ring, ISSUER, [base, a])).rejects.toThrow(
      /cannot record status-2 in .*: injected write failure/,
    );
    expect(hooks.failWrite).toBe(false);
    expect(readFileSync(file, "utf8")).toBe(before);
    await checkKeyBindings(file, ring, ISSUER, [base, a]);
    expect(kidsOf(file)).toEqual(["status", "status-2"]);
  });
});
