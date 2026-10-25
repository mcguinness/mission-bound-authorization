/**
 * @spec #831 C1: a consumer that holds an issuer's keys across the issuer's
 * rotation, retirement and compromise without restarting.
 *
 * One `IssuerKeys` (from @mission/core) stays alive while the AS is
 * stopped, edited, started and verified, rotating its Status role. The
 * consumer's trusted configuration lists the new generation's `kid` before
 * activation (the operator authorizes it during the pending window), and the
 * consumer's clock is injected so the AS's declared `max-age` is crossed
 * deliberately. The consumer:
 *
 * - accepts the new generation at once, through the refresh an unknown
 *   trusted `kid` triggers;
 * - keeps accepting the old generation while it is in overlap;
 * - stops accepting a retired or compromised generation once its cached
 *   set is stale and revalidated, within the declared lifetime;
 * - refuses current reliance while the AS is down and its set is stale.
 */
import { mkdtempSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IssuerKeys } from "@mission/core";
import { TOPOLOGY } from "@mission/demo-data";
import { compactVerify } from "jose";
import { describe, expect, it } from "vitest";
import {
  activateSigningKeyGeneration,
  buildAuthorizationServer,
  compromiseSigningKeyGeneration,
  initSigningKeyRing,
  JWKS_MAX_AGE_SECONDS,
  retireSigningKeyGeneration,
  stageSigningKeyGeneration,
  verifySigningKeyRing,
} from "../src/index.js";

const PORT = 14932;
const ISSUER = `http://localhost:${PORT}`;
const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
const ROLES = { asToken, asStatus, asTxn, asContinuation };

type As = Awaited<ReturnType<typeof buildAuthorizationServer>>;

/** Boot an AS on PORT from `ring`, run `body`, then close it. */
async function withAs<T>(ring: string, body: (as: As) => Promise<T>): Promise<T> {
  const as = await buildAuthorizationServer({ issuer: ISSUER, signingKeys: { ring } });
  const server: Server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  try {
    return await body(as);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

/** A JWS the AS's Status signer signs now, under its active generation's `kid`. */
function statusSigned(as: As): string {
  const signer = as.kernel.statusSigner();
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const input = `${b64({ alg: "ES256", kid: signer.kid, typ: "issuer-keys-test+jwt" })}.${b64({ iss: ISSUER, n: crypto.randomUUID() })}`;
  return `${input}.${signer.sign(input).toString("base64url")}`;
}

describe("a consumer's issuer keys across the issuer's rotation, retirement and compromise (@spec #831 C1)", () => {
  it("accepts a trusted new generation at once, the old one while in overlap, and neither once withdrawn and stale; refuses while it cannot revalidate", { timeout: 120_000 }, async () => {
    const ring = join(mkdtempSync(join(tmpdir(), "issuer-keys-rotation-")), "keys", "ring.json");
    const start = Date.now();
    const at = (s: number) => () => new Date(start + s * 1000);
    await initSigningKeyRing(ring, ISSUER, ROLES, at(0));
    let t = start;
    const advance = (s: number) => {
      t += s * 1000;
    };
    // The consumer's trusted configuration: the Status role, generation 2 authorized ahead of activation.
    const consumer = new IssuerKeys({
      jwksUri: `${ISSUER}/jwks`,
      roles: { status: { kids: [asStatus.kid, `${asStatus.kid}-2`], algs: ["ES256"] } },
      now: () => t,
    });
    const status = consumer.resolver("status");
    const verifies = async (jws: string): Promise<boolean | string> => {
      try {
        await compactVerify(jws, status as never);
        return true;
      } catch (e) {
        return (e as { code?: string }).code ?? (e as Error).message;
      }
    };

    const first = await withAs(ring, async (as) => {
      const jws = statusSigned(as);
      expect(await verifies(jws)).toBe(true);
      return jws;
    });
    await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asStatus", at(1));
    await withAs(ring, async () => {
      await verifySigningKeyRing(ring, ISSUER, ROLES, { now: at(2) });
    });
    await activateSigningKeyGeneration(ring, ISSUER, ROLES, "asStatus", {
      minPublishedS: JWKS_MAX_AGE_SECONDS,
      now: at(2 + JWKS_MAX_AGE_SECONDS),
    });

    // Activated: the consumer, its cache still fresh, meets the new kid and refreshes for it once.
    const second = await withAs(ring, async (as) => {
      await verifySigningKeyRing(ring, ISSUER, ROLES, { now: at(3 + JWKS_MAX_AGE_SECONDS) });
      const jws = statusSigned(as);
      expect(await verifies(jws)).toBe(true);
      expect(await verifies(first)).toBe(true);
      return jws;
    });

    // The AS is down and the consumer's set goes stale: no current reliance at all.
    advance(JWKS_MAX_AGE_SECONDS);
    expect(await verifies(second)).toBe("unavailable");

    await retireSigningKeyGeneration(ring, ISSUER, ROLES, "asStatus", asStatus.kid, {
      retention: { auditHorizonS: 3600, maxMissionLifetimeS: 3600, standingConsents: 0 },
      now: at(3 + JWKS_MAX_AGE_SECONDS + 3600),
    });
    await withAs(ring, async () => {
      // Revalidated on this boot: generation 1 is gone from the set, generation 2 stays.
      expect(await verifies(first)).toBe("unknown_kid");
      expect(await verifies(second)).toBe(true);
    });

    await compromiseSigningKeyGeneration(ring, ISSUER, ROLES, "asStatus", `${asStatus.kid}-2`, {
      now: at(4 + JWKS_MAX_AGE_SECONDS + 3600),
    });
    await withAs(ring, async (as) => {
      // Within the cached set's declared lifetime the consumer still holds generation 2...
      expect(await verifies(second)).toBe(true);
      advance(JWKS_MAX_AGE_SECONDS);
      // ...and once it is stale, revalidation withdraws it. The replacement, not yet trusted, is refused.
      expect(await verifies(second)).toBe("unknown_kid");
      expect(await verifies(statusSigned(as))).toBe("untrusted_kid");
    });
  });
});
