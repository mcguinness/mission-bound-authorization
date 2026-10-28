/**
 * @spec cross-domain#validation-at-resource-as (one-time use), #1767 (D887):
 * `pnpm ras-redemptions`, which creates the RAS's durable redemption store
 * once, driven through `rasRedemptionsAdmin`.
 */
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openRasRedemptionStore } from "@mission/ras";
import { afterAll, describe, expect, it } from "vitest";
import { rasRedemptionsAdmin } from "../src/ras-redemptions-admin.js";

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
function root(): string {
  const dir = mkdtempSync(join(tmpdir(), "ras-redemptions-admin-"));
  dirs.push(dir);
  return dir;
}

describe("pnpm ras-redemptions (@spec cross-domain#validation-at-resource-as, #1767)", () => {
  it("init creates a store the RAS opens, resolving a relative path against the directory pnpm started in, and refuses a second init", () => {
    const dir = root();
    const out = rasRedemptionsAdmin(["init", "--file", "state/redemptions.sqlite"], { INIT_CWD: dir });
    const file = join(dir, "state", "redemptions.sqlite");
    expect(out).toContain(`created the redemption store ${file}`);
    expect(out).toContain(`start the as-native target with MISSION_RAS_REDEMPTIONS=${file}`);
    openRasRedemptionStore(file).close();
    expect(() => rasRedemptionsAdmin(["init", "--file", file], {})).toThrow(/already exists/);
  });

  it("refuses anything but init with one file", () => {
    const dir = root();
    const x = join(dir, "x");
    for (const argv of [[], ["init"], ["init", "--file"], ["open", "--file", x], ["init", "--file", x, "extra"]]) {
      expect(() => rasRedemptionsAdmin(argv, {})).toThrow(/usage: pnpm ras-redemptions init --file <path>/);
    }
    expect(existsSync(x)).toBe(false);
  });
});
