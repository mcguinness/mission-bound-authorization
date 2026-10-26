/**
 * @spec #831 C2 (D825): an edit to `topology.json` reaches a running
 * consumer through an explicit reload, and only through it.
 *
 * The issuance-only deployment runs on a copy of `config/` (named by
 * `MISSION_CONFIG_DIR` before any configuration loads, so nothing here edits
 * the shared files). Its plain-rs keeps serving while the copy's
 * `keys.asToken.trusted` changes: an edit alone changes nothing, a reload
 * removes trust and restores it, and a reload of a configuration that would
 * break trust is refused with the configuration in force kept.
 */
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CONFIG = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "config");
const AS_PORT = 14944;
const RS_PORT = 14945;

describe("plain-rs's trusted kids, reloaded from topology.json while it runs (@spec #831 C2, D825)", () => {
  it("an edit alone changes nothing; a reload removes and restores trust; a reload that would break trust is refused", { timeout: 120_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "trust-reload-config-"));
    cpSync(CONFIG, dir, { recursive: true });
    process.env.MISSION_CONFIG_DIR = dir;
    const topologyFile = join(dir, "topology.json");
    const setTrusted = (trusted: unknown) => {
      const topology = JSON.parse(readFileSync(topologyFile, "utf8")) as { keys: Record<string, Record<string, unknown>> };
      topology.keys.asToken = { ...topology.keys.asToken, trusted };
      writeFileSync(topologyFile, JSON.stringify(topology, null, 2));
    };
    // Loaded only now, so the configuration they read is the copy.
    const { startIssuanceOnly } = await import("../src/issuance-only.js");
    const { mintPlainRsToken } = await import("./plain-rs-token.helper.js");
    const deployment = await startIssuanceOnly({ introspection: false, asPort: AS_PORT, rsPort: RS_PORT });
    try {
      const { token, read } = await mintPlainRsToken(deployment.credentials, deployment.credentials.rsUrl);
      expect(JSON.parse(Buffer.from(token.split(".")[0] as string, "base64url").toString()).kid).toBe("as-token");
      expect(await read()).toBe(200);

      setTrusted(["as-other"]);
      // The file alone reaches nothing running.
      expect(await read()).toBe(200);
      deployment.reloadTrust();
      expect(await read()).toBe(401);

      setTrusted(["as-token", "as-other"]);
      deployment.reloadTrust();
      expect(await read()).toBe(200);

      // A configuration that does not load is refused, and the one in force stays.
      setTrusted([]);
      expect(() => deployment.reloadTrust()).toThrow(/trusted must list at least one non-empty kid/);
      expect(await read()).toBe(200);
    } finally {
      await deployment.close();
      delete process.env.MISSION_CONFIG_DIR;
    }
  });
});
