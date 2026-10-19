/**
 * @spec #250, #831: `pnpm issuance-only` keeps its kernel in the file
 * `MISSION_KERNEL_STORE` names (with a key ring, `kernelStoreFromEnv`), and
 * releases it on close. The launcher's environment parsing is witnessed in
 * signing-key-ring.test.ts; this witnesses the composition it feeds.
 */
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSigningKeyRing } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";
import { afterAll, describe, expect, it } from "vitest";
import { startIssuanceOnly } from "../src/issuance-only.js";

const AS_PORT = 14844;
const RS_PORT = 14845;
const dirs: string[] = [];

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("issuance-only with a kernel store (#250)", () => {
  it("opens the kernel in the named file, creating its directory, keeps it across a restart and releases it on close", async () => {
    const dir = mkdtempSync(join(tmpdir(), "issuance-only-kernel-"));
    dirs.push(dir);
    const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
    const ring = join(dir, "keys", "ring.json");
    await initSigningKeyRing(ring, `http://localhost:${AS_PORT}`, { asToken, asStatus, asTxn, asContinuation });
    const file = join(dir, "state", "kernel.db");
    const start = () =>
      startIssuanceOnly({ introspection: false, asPort: AS_PORT, rsPort: RS_PORT, signingKeys: { ring }, kernelStore: { file } });

    const first = await start();
    let marker: string;
    try {
      expect(existsSync(file)).toBe(true);
      // A row written through the running kernel lands in the named file.
      marker = `marker-${crypto.randomUUID()}`;
      first.as.kernel.db.exec("CREATE TABLE IF NOT EXISTS restart_marker (value TEXT NOT NULL)");
      first.as.kernel.db.prepare("INSERT INTO restart_marker (value) VALUES (?)").run(marker);
    } finally {
      await first.close();
    }
    // Closed with the deployment.
    expect(() => first.as.kernel.db.prepare("SELECT 1").get()).toThrow();

    const second = await start();
    try {
      expect(second.as.kernel.db.prepare("SELECT value FROM restart_marker").get()).toEqual({ value: marker });
    } finally {
      await second.close();
    }
  });
});
