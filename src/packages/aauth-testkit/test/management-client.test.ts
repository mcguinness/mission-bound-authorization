import {
  buildSignatureBase,
  determineAlgorithm,
  generateSigningKey,
  httpVerify,
  InMemoryReplayCache,
  normalizeRequest,
  type SignatureError,
  verifyContentDigest,
  verifyRequest,
} from "@mission/aauth-wire";
import { type InnerList, type Item, parseDictionary } from "structured-headers";
import { afterEach, describe, expect, it } from "vitest";
import { ManagementClient, ManagementError, newRequestId, type StubRequest } from "../src/index.js";
import { M, M2, PS, type World, world } from "./fixtures.js";

let w: World;
afterEach(() => w.net.close());

const CONTROL = `${PS}/control`;

/** Publish a control plane at a path unrelated to `mission_endpoint`. */
function publish(actions: unknown = ["status", "terminate"]) {
  w.ps.metadata.mission_control_endpoint = CONTROL;
  w.ps.metadata.mission_control_actions_supported = actions;
}

const refusal = async (promise: Promise<unknown>): Promise<ManagementError> => {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ManagementError);
  return err as ManagementError;
};

/**
 * A control-plane route that verifies the owning agent's signature with the
 * library, its replay cache included, and echoes what it saw.
 */
function agentRoute(seen: StubRequest[], cache = new InMemoryReplayCache()) {
  return async (req: StubRequest) => {
    seen.push(req);
    try {
      const verified = await verifyRequest(req.message, {
        resolver: w.net.resolver({ now: w.clock.now }),
        requireBodyComponents: true,
        replayCache: cache,
        now: w.clock.now,
      });
      return {
        status: 200,
        body: { sub: verified.token?.payload.sub, covered: verified.coveredComponents },
      };
    } catch (err) {
      const e = err as SignatureError;
      return { status: 401, headers: e.headers, body: { error: e.code } };
    }
  };
}

/** Verify a request's signature against a known key, with the library's primitives. */
function signedBy(req: StubRequest, publicJwk: Record<string, unknown>): string[] {
  const input = parseDictionary(req.headers["signature-input"]?.[0] ?? "").get("sig") as InnerList;
  const signature = parseDictionary(req.headers.signature?.[0] ?? "").get("sig") as Item;
  const base = buildSignatureBase(normalizeRequest(req.message), input);
  const { alg, key } = determineAlgorithm(publicJwk);
  const ok = httpVerify(
    alg,
    key,
    Buffer.from(base, "ascii"),
    new Uint8Array(signature[0] as ArrayBuffer),
  );
  expect(ok).toBe(true);
  expect(verifyContentDigest(req.headers["content-digest"]?.[0] ?? "", req.body)).toBe(true);
  return input[0].map(([name]) => String(name));
}

describe("the owning agent (@spec mission-aauth-management#endpoint)", () => {
  it("reads status at the control-plane URL the metadata names, signed with its agent token", async () => {
    w = await world();
    publish();
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, {
      now: w.clock.now,
      sleep: w.clock.sleep,
    });
    const result = await client.status(M);
    expect(result.status).toBe(200);
    expect(result.body).toEqual({
      sub: "aauth:assistant@ap.test",
      covered: [
        "@method",
        "@authority",
        "@path",
        "signature-key",
        "content-digest",
        "content-type",
      ],
    });
    expect(seen.map((r) => [r.method, r.path])).toEqual([["POST", `/control/${M}`]]);
    expect(seen[0]?.headers["content-type"]).toEqual(["application/json"]);
    expect(seen[0]?.json).toEqual({ action: "status" });
    expect(client.role).toBe("owning-agent");
  });

  it("terminates with action, reason and a fresh request_id, never naming the mission in the body", async () => {
    w = await world();
    publish();
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, {
      now: w.clock.now,
      sleep: w.clock.sleep,
    });
    await client.terminate(M, { reason: "revoked" });
    await client.terminate(M, { reason: "revoked", purpose: "done" });
    const [first, second] = seen.map((r) => r.json as Record<string, unknown>);
    expect(first).toEqual({
      action: "terminate",
      reason: "revoked",
      request_id: first?.request_id,
    });
    expect(second).toEqual({
      action: "terminate",
      reason: "revoked",
      request_id: second?.request_id,
      purpose: "done",
    });
    expect(first?.request_id).toMatch(/^t-[0-9a-f]{32}$/);
    expect(second?.request_id).not.toBe(first?.request_id);
    expect(seen.every((r) => !("mission_s256" in (r.json as object)))).toBe(true);
  });

  it("sends a named request_id, replacement_s256 and extra members as given", async () => {
    w = await world();
    publish();
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, {
      now: w.clock.now,
      sleep: w.clock.sleep,
    });
    await client.terminate(M, {
      reason: "superseded",
      requestId: "t-fixed",
      replacementS256: M2,
      extra: { note: 1 },
    });
    expect(seen[0]?.json).toEqual({
      action: "terminate",
      reason: "superseded",
      request_id: "t-fixed",
      replacement_s256: M2,
      note: 1,
    });
  });

  it("signs two requests to one mission URL in different seconds, so neither is a replay", async () => {
    w = await world();
    publish();
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, {
      now: w.clock.now,
      sleep: w.clock.sleep,
    });
    const start = w.clock.now();
    const statuses = [(await client.status(M)).status, (await client.status(M)).status];
    expect(statuses).toEqual([200, 200]);
    expect(w.clock.now() - start).toBeGreaterThanOrEqual(1000);
  });

  it("returns a refusal as it was answered: status, headers and body bytes", async () => {
    w = await world();
    publish();
    w.ps.routes[`POST /control/${M}`] = () => ({
      status: 404,
      headers: { "content-type": "application/problem+json" },
      body: '{"error":"mission_not_found"}',
    });
    const client = ManagementClient.forAgent(w.agent, w.net, { now: w.clock.now });
    const result = await client.status(M);
    expect(result.status).toBe(404);
    expect(result.headers["content-type"]).toBe("application/problem+json");
    expect(result.text).toBe('{"error":"mission_not_found"}');
    expect(result.body).toEqual({ error: "mission_not_found" });
    expect(client.sent).toEqual([
      { url: `${CONTROL}/${M}`, body: { action: "status" }, status: 404 },
    ]);
  });

  it("sends exact bytes through send(), with no action check", async () => {
    w = await world();
    publish([]);
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, { now: w.clock.now });
    const raw = '{"action":"status","action":"terminate"}';
    const result = await client.send(M, raw, { contentType: "application/json; charset=utf-8" });
    expect(result.status).toBe(200);
    expect(seen[0]?.body.toString("utf8")).toBe(raw);
    expect(seen[0]?.headers["content-type"]).toEqual(["application/json; charset=utf-8"]);
    expect(client.sent[0]?.body).toBe(raw);
  });
});

describe("discovery (@spec mission-aauth-management#metadata)", () => {
  it("refuses a PS that publishes no mission_control_endpoint, and never derives one from mission_endpoint", async () => {
    w = await world();
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /mission/${M}`] = agentRoute(seen);
    w.ps.routes[`POST /mission-control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, { now: w.clock.now });
    const err = await refusal(client.status(M));
    expect(err.code).toBe("metadata_invalid");
    expect(seen).toEqual([]);
  });

  it("refuses metadata that names another issuer", async () => {
    w = await world();
    publish();
    w.ps.metadata.issuer = "https://other.test";
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, { now: w.clock.now });
    expect((await refusal(client.status(M))).code).toBe("metadata_invalid");
    expect(seen).toEqual([]);
  });

  it.each([
    ["terminate", ["status"]],
    ["status", ["terminate"]],
    ["status", "status"],
    ["status", "absent"],
  ])("does not send %s when the PS does not list it (%j)", async (action, actions) => {
    w = await world();
    publish(actions);
    if (actions === "absent") delete w.ps.metadata.mission_control_actions_supported;
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = agentRoute(seen);
    const client = ManagementClient.forAgent(w.agent, w.net, { now: w.clock.now });
    const call =
      action === "status" ? client.status(M) : client.terminate(M, { reason: "revoked" });
    expect((await refusal(call)).code).toBe("action_unsupported");
    expect(seen).toEqual([]);
  });
});

describe("an administrator (@spec mission-aauth-management#terminate)", () => {
  const ADMIN = {
    scheme: "jwks_uri",
    id: "https://admin.test",
    dwk: "admin.json",
    kid: "admin-1",
  } as const;

  it("signs with its own key under the Signature-Key member it is given", async () => {
    w = await world();
    publish();
    const key = generateSigningKey("Ed25519", "admin-1");
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = (req) => {
      seen.push(req);
      return { status: 200, body: { ok: true } };
    };
    const admin = ManagementClient.forAdministrator({
      transport: w.net,
      ps: PS,
      key,
      signatureKey: ADMIN,
      now: w.clock.now,
      sleep: w.clock.sleep,
    });
    expect(admin.role).toBe("administrator");
    await admin.terminate(M, { reason: "administrative", purpose: "offboarding" });
    const [req] = seen as [StubRequest];
    expect(req.headers["signature-key"]).toEqual([
      'sig=jwks_uri;id="https://admin.test";dwk="admin.json";kid="admin-1"',
    ]);
    expect(signedBy(req, key.publicJwk)).toEqual([
      "@method",
      "@authority",
      "@path",
      "signature-key",
      "content-digest",
      "content-type",
    ]);
    expect(req.json).toMatchObject({
      action: "terminate",
      reason: "administrative",
      purpose: "offboarding",
    });
  });

  it("does not send a terminate without a purpose", async () => {
    w = await world();
    publish();
    const seen: StubRequest[] = [];
    w.ps.routes[`POST /control/${M}`] = (req) => {
      seen.push(req);
      return { status: 200, body: {} };
    };
    const admin = ManagementClient.forAdministrator({
      transport: w.net,
      ps: PS,
      key: generateSigningKey("Ed25519"),
      signatureKey: ADMIN,
      now: w.clock.now,
    });
    expect((await refusal(admin.terminate(M, { reason: "administrative" }))).code).toBe(
      "purpose_required",
    );
    expect(seen).toEqual([]);
  });
});

describe("request identifiers", () => {
  it("carry 128 bits of entropy and do not repeat", () => {
    const ids = new Set(Array.from({ length: 64 }, () => newRequestId()));
    expect(ids.size).toBe(64);
    for (const id of ids) expect(id).toMatch(/^t-[0-9a-f]{32}$/);
  });
});
