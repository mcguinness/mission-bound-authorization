/**
 * @spec runtime#idempotency (#918, D223): the load-time refusals for the
 * PEP's write-reservation store in `topology.json`. The store is a separate
 * file from the PDP's claim domain, named in configuration and never
 * defaulted, so a topology that omits it or names the claim domain's file is
 * refused at boot.
 *
 * Each case copies the shipped `config/` with one member broken, points the
 * loader at the copy through `MISSION_CONFIG_DIR`, and resets the module
 * registry, so the refusal under test is the real boot path.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const SHIPPED_CONFIG = join(import.meta.dirname, "../../../config");

describe("the write-reservation store's topology (@spec runtime#idempotency, #918)", () => {
  const dirs: string[] = [];
  const original = process.env.MISSION_CONFIG_DIR;

  afterEach(() => {
    if (original === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = original;
    vi.resetModules();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const configWith = (edit: (stores: Record<string, unknown>) => void): string => {
    const dir = mkdtempSync(join(tmpdir(), "mission-reservation-config-"));
    dirs.push(dir);
    cpSync(SHIPPED_CONFIG, dir, { recursive: true });
    const file = join(dir, "topology.json");
    const doc = JSON.parse(readFileSync(file, "utf8")) as { stores: Record<string, unknown> };
    edit(doc.stores);
    writeFileSync(file, JSON.stringify(doc, null, 2));
    return dir;
  };

  it("refuses a topology whose write-reservation file is the claim domain's file, or that names none", async () => {
    process.env.MISSION_CONFIG_DIR = configWith((stores) => {
      stores.pepWriteReservations = { file: (stores.pdpIdempotencyClaims as { file: string }).file };
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /stores.pepWriteReservations.file must differ from stores.pdpIdempotencyClaims.file/,
    );

    process.env.MISSION_CONFIG_DIR = configWith((stores) => {
      delete stores.pepWriteReservations;
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(/stores.pepWriteReservations/);
  });
});
