/**
 * @spec authority-server#discovery (#972, D1088)
 *
 * The MAS pilot's MAS, the reference authorization server, publishes
 * `mission_max_stale_seconds` in its metadata, an integer, as the MAS draft
 * requires of every MAS: the staleness bound its joining PDPs rely on.
 */

import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { loadMasPilotConfig } from "../src/mas-pilot/config.js";
import { buildPilotMas } from "../src/mas-pilot/mas-as.js";

describe("the pilot MAS's metadata (@spec authority-server#discovery, #972)", () => {
  it("carries mission_max_stale_seconds, a positive integer", async () => {
    const mas = await buildPilotMas(loadMasPilotConfig());
    const server = createServer(mas.built.provider.callback());
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const { port } = server.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${port}/.well-known/openid-configuration`);
      expect(res.status).toBe(200);
      const meta = (await res.json()) as Record<string, unknown>;
      expect(meta.issuer).toBe(mas.issuer);
      expect(Number.isInteger(meta.mission_max_stale_seconds)).toBe(true);
      expect(meta.mission_max_stale_seconds as number).toBeGreaterThan(0);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      mas.built.kernel.close();
    }
  });
});
