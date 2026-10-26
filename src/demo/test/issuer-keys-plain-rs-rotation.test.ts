/**
 * @spec #831 C2: a real resource server that follows the AS's key rotation
 * without restarting.
 *
 * One plain-rs, holding the AS's access-token keys through `IssuerKeys`,
 * serves throughout while the AS is stopped, edited, started and verified:
 * staged, activated, then retired. Its trusted configuration starts with
 * generation 1 alone and changes while it runs (D825): the operator adds
 * generation 2 during the pending window and removes generation 1 once it is
 * retired, each through `setRoles`. Its key clock is injected so the AS's
 * declared `max-age` is crossed on purpose. It refuses generation 2 until
 * trusted, then accepts it at once; accepts generation 1 while in overlap;
 * refuses everything while the AS is down and its set is stale; and refuses
 * generation 1 once withdrawn from trust and from the set.
 */
import { mkdtempSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  activateSigningKeyGeneration,
  initSigningKeyRing,
  JWKS_MAX_AGE_SECONDS,
  retireSigningKeyGeneration,
  stageSigningKeyGeneration,
  verifySigningKeyRing,
} from "@mission/authorization-server";
import { IssuerKeys } from "@mission/core";
import { TOPOLOGY } from "@mission/demo-data";
import { startPlainResourceServer } from "@mission/plain-rs";
import { decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { PLAIN_RS_AUDIENCE, startIssuanceOnly } from "../src/issuance-only.js";
import { mintPlainRsToken } from "./plain-rs-token.helper.js";

const AS_PORT = 14941;
const DEPLOYMENT_RS_PORT = 14942;
const RS_PORT = 14943;
const ISSUER = `http://localhost:${AS_PORT}`;
const RS_URL = `http://localhost:${RS_PORT}`;
const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
const ROLES = { asToken, asStatus, asTxn, asContinuation };

describe("a resource server across the AS's key rotation (@spec #831 C2)", () => {
  it("accepts the trusted new generation at once and the old one in overlap, refuses while it cannot revalidate, and refuses the retired generation", { timeout: 180_000 }, async () => {
    const ring = join(mkdtempSync(join(tmpdir(), "plain-rs-rotation-")), "keys", "ring.json");
    const start = Date.now();
    const at = (s: number) => () => new Date(start + s * 1000);
    await initSigningKeyRing(ring, ISSUER, ROLES, at(0));
    let t = start;
    const advance = (s: number) => {
      t += s * 1000;
    };
    // The resource server's trusted configuration: the access-token role, generation 1 alone.
    const keys = new IssuerKeys({
      jwksUri: `${ISSUER}/jwks`,
      roles: { accessToken: { kids: [asToken.kid], algs: [asToken.alg] } },
      now: () => t,
    });
    const trust = (...kids: string[]) => keys.setRoles({ accessToken: { kids, algs: [asToken.alg] } });
    const rs: Server = await startPlainResourceServer(
      { issuer: ISSUER, audience: PLAIN_RS_AUDIENCE, keys: keys.resolver("accessToken") as never, baseUrl: RS_URL },
      RS_PORT,
    );
    const boot = () =>
      startIssuanceOnly({ introspection: false, asPort: AS_PORT, rsPort: DEPLOYMENT_RS_PORT, signingKeys: { ring } });
    try {
      let deployment = await boot();
      const first = await mintPlainRsToken(deployment.credentials, RS_URL);
      expect(decodeProtectedHeader(first.token).kid).toBe(asToken.kid);
      expect(await first.read()).toBe(200);
      await deployment.close();

      await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", at(1));
      deployment = await boot();
      await verifySigningKeyRing(ring, ISSUER, ROLES, { now: at(2) });
      await deployment.close();
      // The pending window: the operator adds generation 2 to the running resource server's trust.
      trust(asToken.kid, `${asToken.kid}-2`);
      await activateSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", {
        minPublishedS: JWKS_MAX_AGE_SECONDS,
        now: at(2 + JWKS_MAX_AGE_SECONDS),
      });

      // Activated: the resource server never restarted, and its cached set is still fresh.
      deployment = await boot();
      await verifySigningKeyRing(ring, ISSUER, ROLES, { now: at(3 + JWKS_MAX_AGE_SECONDS) });
      const second = await mintPlainRsToken(deployment.credentials, RS_URL);
      expect(decodeProtectedHeader(second.token).kid).toBe(`${asToken.kid}-2`);
      // Generation 2, once untrusted, is refused; trusted again, it verifies at once.
      trust(asToken.kid);
      expect(await second.read()).toBe(401);
      trust(asToken.kid, `${asToken.kid}-2`);
      expect(await second.read()).toBe(200);
      expect(await first.read()).toBe(200);
      await deployment.close();

      // The AS is down and the resource server's set goes stale: no current reliance.
      advance(JWKS_MAX_AGE_SECONDS);
      expect(await second.read()).toBe(401);

      await retireSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", asToken.kid, {
        retention: { auditHorizonS: 3600, maxMissionLifetimeS: 3600 },
        now: at(3 + JWKS_MAX_AGE_SECONDS + 3600),
      });
      // Retired: the operator removes generation 1 from trust as well.
      trust(`${asToken.kid}-2`);
      deployment = await boot();
      expect(await first.read()).toBe(401);
      expect(await second.read()).toBe(200);
      await deployment.close();
    } finally {
      await new Promise<void>((r) => {
        rs.close(() => r());
        rs.closeAllConnections();
      });
    }
  });
});
