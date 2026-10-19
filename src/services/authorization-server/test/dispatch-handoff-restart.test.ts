/**
 * @spec mission-template#dispatch-handoff (single use), #831: a key ring
 * keeps the AS's signing keys across a restart, but the record of a consumed
 * Dispatch Handoff grant is in memory. Without a check, a grant redeemed
 * before a restart would verify and redeem again after it. Each grant names
 * the process that issued it (a boot identity in its `jti`), and the AS
 * refuses a grant another process issued, so neither a redeemed grant nor an
 * unredeemed one minted before the restart is redeemable after it (a
 * deliberate, documented invalidation), even when the restart lands in the
 * same clock second as the grant.
 *
 * The exposure needs both durable parts: a key ring, and a file-backed
 * kernel that keeps the dispatched instance's Mission across the restart.
 */
import { mkdtempSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, demoReconciliationTemplate, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { CHILD_JWT_BEARER_GRANT_TYPE } from "../src/adapters/child-grant.js";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import { buildAuthorizationServer, type BuiltAs, initSigningKeyRing } from "../src/index.js";

const PORT = 14832;
const ISSUER = `http://localhost:${PORT}`;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const AGENT_ID = "subagent-invoice-extractor";
type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Party = "dispatcher" | "agent";
const clientIds: Record<Party, string> = { dispatcher: "ap-agent", agent: AGENT_ID };
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

/** One running AS on PORT and the client keys its boot generated. */
interface Running {
  as: BuiltAs;
  server: Server;
  clientKeys: Record<Party, CryptoKey>;
}

async function boot(ring: string, kernelFile: string, now?: () => Date): Promise<Running> {
  const as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    signingKeys: { ring },
    kernelStore: { file: kernelFile },
    ...(now ? { now } : {}),
  });
  const server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  return {
    as,
    server,
    clientKeys: {
      dispatcher: (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey,
      agent: (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey,
    },
  };
}

async function shutdown(running: Running): Promise<void> {
  await new Promise<void>((r) => running.server.close(() => r()));
  running.as.kernel.db.close();
}

async function tokenRequest(running: Running, party: Party, keys: Keys, params: Record<string, string>): Promise<Response> {
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu: TOKEN_ENDPOINT, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(keys.privateKey),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await new SignJWT({})
          .setProtectedHeader({ alg: "ES256", kid: `${clientIds[party]}-auth` })
          .setIssuer(clientIds[party])
          .setSubject(clientIds[party])
          .setAudience(ISSUER)
          .setIssuedAt()
          .setExpirationTime("2m")
          .setJti(crypto.randomUUID())
          .sign(running.clientKeys[party]),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

const json = async (res: Response) => (await res.json()) as Record<string, unknown>;

/**
 * Dispatch an instance, take two handoff grants, redeem one, restart on the
 * same key ring and kernel file, and present both again. `now` pins both
 * boots' clocks; absent, the restart waits into a later second.
 */
async function presentAcrossRestart(now?: () => Date): Promise<void> {
    const dir = mkdtempSync(join(tmpdir(), "handoff-restart-"));
    const ring = join(dir, "keys", "ring.json");
    const kernelFile = join(dir, "kernel.db");
    await initSigningKeyRing(ring, ISSUER, ROLES);
    const dispatcherDpop = await generateKeyPair("ES256", { extractable: true });
    const agentDpop = await generateKeyPair("ES256", { extractable: true });

    const first = await boot(ring, kernelFile, now);
    let redeemed: string;
    let unredeemed: string;
    try {
      const created = await fetch(`${ISSUER}/templates`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
        body: JSON.stringify({ ...demoReconciliationTemplate(ISSUER), approval_event_id: "restart-tmpl" }),
      });
      const { template_id } = (await created.json()) as { template_id: string };
      const dispatched = await tokenRequest(first, "dispatcher", dispatcherDpop, {
        grant_type: MISSION_DISPATCH_GRANT_TYPE,
        template_id,
        mission_intent: JSON.stringify({
          intent: { goal: "reconcile Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: FAR_FUTURE },
        }),
        dispatch_event_id: "restart-evt",
      });
      const instance = await json(dispatched);
      expect(dispatched.status, JSON.stringify(instance)).toBe(200);
      const handoff = async () => {
        const res = await tokenRequest(first, "dispatcher", dispatcherDpop, {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: instance.access_token as string,
          subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          requested_token_type: JWT_TOKEN_TYPE,
          mission_dispatch_handoff: "true",
        });
        const body = await json(res);
        expect(res.status, JSON.stringify(body)).toBe(200);
        return body.access_token as string;
      };
      redeemed = await handoff();
      unredeemed = await handoff();
      const r = await tokenRequest(first, "agent", agentDpop, { grant_type: CHILD_JWT_BEARER_GRANT_TYPE, assertion: redeemed });
      expect(r.status, JSON.stringify(await json(r))).toBe(200);
    } finally {
      await shutdown(first);
    }

    // Without a pinned clock, the restart lands in a later second than every
    // grant's iat; with one, both boots observe the same second.
    if (!now) await new Promise((r) => setTimeout(r, 1100));
    const second = await boot(ring, kernelFile, now);
    try {
      for (const grant of [redeemed, unredeemed]) {
        const res = await tokenRequest(second, "agent", agentDpop, { grant_type: CHILD_JWT_BEARER_GRANT_TYPE, assertion: grant });
        const body = await json(res);
        expect(res.status, JSON.stringify(body)).toBe(400);
        expect(body.error).toBe("invalid_grant");
        expect(body.error_description).toBe(
          "dispatch handoff grant was issued by an earlier process; single-use state is not retained across restarts",
        );
      }
    } finally {
      await shutdown(second);
    }
}

describe("Dispatch Handoff single use across a restart with durable signing keys (@spec mission-template#dispatch-handoff, #831)", () => {
  it("refuses, after a restart, both a grant redeemed before it and one never redeemed: the consumption record does not survive, so nothing an earlier process issued redeems", async () => {
    await presentAcrossRestart();
  }, 60_000);

  it("refuses them when the restart lands in the same clock second as the grants: the check is the issuing process, not its start time", async () => {
    const sameSecond = new Date();
    await presentAcrossRestart(() => sameSecond);
  }, 60_000);
});
