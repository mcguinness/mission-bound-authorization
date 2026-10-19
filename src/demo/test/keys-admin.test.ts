/**
 * @spec #831 slice 1: `pnpm keys init`, driven through `keysAdmin`.
 */
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import { keysAdmin } from "../src/keys-admin.js";

describe("pnpm keys init (@spec #831 slice 1)", () => {
  it("creates the ring once at a path resolved against the directory pnpm started in, for the configured AS issuer, and names it for MISSION_KEY_RING", async () => {
    const started = mkdtempSync(join(tmpdir(), "keys-admin-"));
    const out = await keysAdmin(["init", "--ring", "var/keys/as-signing-keys.json"], { INIT_CWD: started }, "/elsewhere");
    const ring = join(started, "var/keys/as-signing-keys.json");
    expect(out).toBe(
      [
        `initialized ${ring} for http://localhost:${TOPOLOGY.ports.as}: 4 keys (as-token, as-status, as-txn, as-continuation)`,
        `start the AS with MISSION_KEY_RING=${ring}`,
      ].join("\n"),
    );
    expect(statSync(ring).mode & 0o777).toBe(0o600);
    expect((JSON.parse(readFileSync(ring, "utf8")) as { issuer: string }).issuer).toBe(`http://localhost:${TOPOLOGY.ports.as}`);
    await expect(keysAdmin(["init", "--ring", ring], {})).rejects.toThrow(/already exists; a ring is initialized once/);
  });

  it("takes an explicit issuer", async () => {
    const ring = join(mkdtempSync(join(tmpdir(), "keys-admin-")), "keys", "ring.json");
    await keysAdmin(["init", "--ring", ring, "--issuer", "https://as.example.com"], {});
    expect((JSON.parse(readFileSync(ring, "utf8")) as { issuer: string }).issuer).toBe("https://as.example.com");
  });

  it("refuses anything but init with a ring path, and an issuer that is not an http or https URL", async () => {
    const usage = /^usage: pnpm keys init --ring <path> \[--issuer <url>\]$/;
    for (const argv of [[], ["rotate"], ["init"], ["init", "--ring"], ["init", "--path", "x"], ["init", "--ring", "--issuer"]]) {
      await expect(keysAdmin(argv, {}), JSON.stringify(argv)).rejects.toThrow(usage);
    }
    await expect(keysAdmin(["init", "--ring", "/tmp/x.json", "--issuer", "ftp://as"], {})).rejects.toThrow(
      /--issuer is not an http or https URL: ftp:\/\/as/,
    );
  });
});
