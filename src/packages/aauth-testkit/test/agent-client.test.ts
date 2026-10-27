import { createHash } from "node:crypto";
import {
  generateSigningKey,
  InMemoryReplayCache,
  mintToken,
  type SignatureError,
  verifyRequest,
} from "@mission/aauth-wire";
import { afterEach, describe, expect, it } from "vitest";
import { AgentError, createIssuerStub, decodeClaims, type StubRequest } from "../src/index.js";
import {
  authTokenClaims,
  M,
  M2,
  PS,
  personToken,
  RESOURCE,
  resourceTokenClaims,
  type World,
  without,
  world,
} from "./fixtures.js";

let w: World;
afterEach(() => w.net.close());

const refusal = async (promise: Promise<unknown>): Promise<AgentError> => {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AgentError);
  return err as AgentError;
};

/** A route at the resource stub that verifies the agent's signature with the library. */
function verifyingRoute(cache = new InMemoryReplayCache()) {
  return async (req: StubRequest) => {
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

describe("signing (@spec aauth#section-11.3.3)", () => {
  it("signs with the jwt scheme, its agent token verifying at the receiver", async () => {
    w = await world();
    w.resource.routes["GET /api/x"] = verifyingRoute();
    w.resource.routes["POST /api/x"] = verifyingRoute();
    const get = await w.agent.send(`${RESOURCE}/api/x`);
    expect(get.status).toBe(200);
    expect(get.json()).toEqual({
      sub: "aauth:assistant@ap.test",
      covered: ["@method", "@authority", "@path", "signature-key"],
    });
    const post = await w.agent.send(`${RESOURCE}/api/x`, { method: "POST", body: { a: 1 } });
    expect(post.status).toBe(200);
    expect((post.json() as { covered: string[] }).covered).toEqual([
      "@method",
      "@authority",
      "@path",
      "signature-key",
      "content-digest",
      "content-type",
    ]);
  });

  it("never repeats a (method, authority, path, created) tuple, so a retry is not a replay", async () => {
    w = await world();
    w.resource.routes["GET /api/x"] = verifyingRoute();
    const start = w.clock.now();
    const first = await w.agent.send(`${RESOURCE}/api/x`);
    const second = await w.agent.send(`${RESOURCE}/api/x`);
    // The receiver keeps a replay cache; the agent waited for the next second.
    expect([first.status, second.status]).toEqual([200, 200]);
    expect(w.clock.now() - start).toBeGreaterThanOrEqual(1000);
  });
});

describe("challenge verification (@spec aauth#section-6.7.3)", () => {
  async function challenge(rt: Record<string, unknown>, presentedToken: string) {
    const token = await w.resource.mint("aa-resource+jwt", rt);
    return w.agent.verifyChallenge(token, { resource: RESOURCE, presentedToken });
  }

  it("accepts a resource token naming the token presented", async () => {
    w = await world();
    const pt = await personToken(w);
    const verified = await challenge(resourceTokenClaims(w, decodeClaims(pt)), pt);
    expect(verified.payload.presented_jti).toBe(decodeClaims(pt).jti);
  });

  it("refuses a resource token another resource issued (iss)", async () => {
    w = await world();
    const other = createIssuerStub({
      issuer: "https://other.test",
      dwk: "aauth-resource.json",
      kid: "resource-key-1",
    });
    await w.net.serve(other.issuer, other.handler);
    const pt = await personToken(w);
    const rt = await other.mint(
      "aa-resource+jwt",
      resourceTokenClaims(w, decodeClaims(pt), { iss: other.issuer }),
    );
    const err = await refusal(
      w.agent.verifyChallenge(rt, { resource: RESOURCE, presentedToken: pt }),
    );
    expect(err.code).toBe("resource_token_invalid");
    expect(err.detail).toBe("iss is not the resource called");
  });

  it.each([
    ["ps is not this agent's person server", { ps: "https://other-ps.test" }],
    ["sub is not the presented token's", { sub: "person-2" }],
    ["presented_jti does not name the presented token", { presented_jti: "pt-other" }],
  ])("refuses a resource token whose %s", async (detail, change) => {
    w = await world();
    const pt = await personToken(w);
    const err = await refusal(challenge(resourceTokenClaims(w, decodeClaims(pt), change), pt));
    expect(err.code).toBe("resource_token_invalid");
    expect(err.detail).toBe(detail);
  });

  it("refuses a resource token bound to another key (agent_jkt)", async () => {
    w = await world();
    const pt = await personToken(w);
    const err = await refusal(
      challenge(resourceTokenClaims(w, decodeClaims(pt), { agent_jkt: "x".repeat(43) }), pt),
    );
    expect(err.code).toBe("resource_token_invalid");
    expect(err.detail).toMatch(/agent_jkt/);
  });

  it("refuses an expired resource token, and one the resource did not sign", async () => {
    w = await world();
    const pt = await personToken(w);
    const iat = w.seconds() - 400;
    const expired = await refusal(
      challenge(resourceTokenClaims(w, decodeClaims(pt), { iat, exp: iat + 300 }), pt),
    );
    expect(expired.detail).toMatch(/expired/);
    const forger = { ...generateSigningKey("Ed25519", "resource-key-1"), kid: "resource-key-1" };
    const forged = await mintToken(
      "aa-resource+jwt",
      resourceTokenClaims(w, decodeClaims(pt)),
      forger,
    );
    const err = await refusal(
      w.agent.verifyChallenge(forged, { resource: RESOURCE, presentedToken: pt }),
    );
    expect(err.code).toBe("resource_token_invalid");
  });

  describe("the binding's mission check (@spec mission-aauth#ref-propagation)", () => {
    it("accepts the agent's exact mission_s256", async () => {
      w = await world();
      w.agent.useMission(M);
      const pt = await personToken(w, { mission_s256: M });
      await challenge(resourceTokenClaims(w, decodeClaims(pt)), pt);
    });

    it("refuses a resource token whose mission_s256 was stripped", async () => {
      w = await world();
      w.agent.useMission(M);
      const pt = await personToken(w, { mission_s256: M });
      const err = await refusal(
        challenge(without(resourceTokenClaims(w, decodeClaims(pt)), "mission_s256"), pt),
      );
      expect(err.code).toBe("mission_reference_mismatch");
    });

    it("refuses a resource token naming another mission", async () => {
      w = await world();
      w.agent.useMission(M);
      const pt = await personToken(w, { mission_s256: M });
      const err = await refusal(
        challenge(resourceTokenClaims(w, decodeClaims(pt), { mission_s256: M2 }), pt),
      );
      expect(err.code).toBe("mission_reference_mismatch");
    });

    it("refuses a mission the agent does not operate under, even when the presented token lacks one", async () => {
      w = await world();
      w.agent.useMission(M);
      const pt = await personToken(w);
      const err = await refusal(challenge(resourceTokenClaims(w, decodeClaims(pt)), pt));
      expect(err.code).toBe("mission_reference_mismatch");
    });

    it("refuses a mission on the resource token of a missionless agent", async () => {
      w = await world();
      const pt = await personToken(w);
      const err = await refusal(
        challenge(resourceTokenClaims(w, decodeClaims(pt), { mission_s256: M }), pt),
      );
      expect(err.code).toBe("mission_reference_mismatch");
    });
  });
});

describe("auth token response verification (@spec aauth#section-9.4.4)", () => {
  async function respond(at: Record<string, unknown>, rt: Record<string, unknown>, pt: string) {
    const token = await w.ps.mint("aa-auth+jwt", at);
    return w.agent.verifyAuthTokenResponse(token, {
      resourceTokenAud: rt.aud,
      resource: RESOURCE,
      presentedToken: pt,
    });
  }

  it("accepts an auth token answering the resource token", async () => {
    w = await world();
    const pt = await personToken(w);
    const rt = resourceTokenClaims(w, decodeClaims(pt));
    await respond(authTokenClaims(w, rt), rt, pt);
  });

  it("refuses an auth token whose iss is not the resource token's aud", async () => {
    w = await world();
    const pt = await personToken(w);
    const rt = resourceTokenClaims(w, decodeClaims(pt));
    const err = await refusal(
      respond(authTokenClaims(w, rt), { ...rt, aud: "https://as.test" }, pt),
    );
    expect(err.detail).toBe("iss is not the resource token's aud");
  });

  it("refuses an auth token for another resource", async () => {
    w = await world();
    const pt = await personToken(w);
    const rt = resourceTokenClaims(w, decodeClaims(pt));
    const err = await refusal(
      respond(authTokenClaims(w, rt, { aud: "https://other.test" }), rt, pt),
    );
    expect(err.code).toBe("auth_token_invalid");
    expect(err.detail).toMatch(/aud/);
  });

  it("refuses an auth token bound to another key", async () => {
    w = await world();
    const pt = await personToken(w);
    const rt = resourceTokenClaims(w, decodeClaims(pt));
    const other = generateSigningKey("Ed25519");
    const err = await refusal(
      respond(authTokenClaims(w, rt, { cnf: { jwk: other.publicJwk } }), rt, pt),
    );
    expect(err.detail).toBe("cnf.jwk is not this agent's key");
  });

  it("refuses an auth token for another person", async () => {
    w = await world();
    const pt = await personToken(w);
    const rt = resourceTokenClaims(w, decodeClaims(pt));
    const err = await refusal(respond(authTokenClaims(w, rt, { sub: "person-2" }), rt, pt));
    expect(err.detail).toBe("sub is not the presented token's");
  });
});

describe("PS metadata and mission approval (@spec aauth#section-11.2, aauth#section-8.2)", () => {
  /** Answer the mission endpoint with `blob` encoded and digested as given. */
  function approve(blob: Buffer, overrides: Record<string, unknown> = {}) {
    w.ps.routes["POST /mission"] = () => ({
      status: 200,
      body: {
        s256: createHash("sha256").update(blob).digest("base64url"),
        mission: blob.toString("base64url"),
        person_tokens: { [RESOURCE]: "pt-from-approval" },
        ...overrides,
      },
    });
  }

  it("refuses PS metadata that names another issuer", async () => {
    w = await world();
    w.ps.metadata.issuer = "https://other-ps.test";
    const err = await refusal(w.agent.requestPersonToken(RESOURCE));
    expect(err.code).toBe("metadata_invalid");
    expect(w.agent.sent).toEqual([]);
  });

  it("verifies s256 over the exact decoded bytes, and keeps those bytes", async () => {
    w = await world();
    // Unusual whitespace and member order: a reserialization would change the bytes.
    const blob = Buffer.from(
      '{ "agent":"aauth:assistant@ap.test",\n  "approved_at":"2026-10-27T00:00:00Z","description":"# Q"}',
    );
    approve(blob);
    const approval = await w.agent.proposeMission({ description: "# Q" });
    expect(approval.blob.equals(blob)).toBe(true);
    expect(w.agent.mission?.s256).toBe(approval.s256);
    expect(w.agent.personToken(RESOURCE)).toBe("pt-from-approval");
  });

  it("refuses an approval whose s256 is not the digest of the mission bytes", async () => {
    w = await world();
    approve(Buffer.from('{"agent":"a"}'), { s256: M });
    const err = await refusal(w.agent.proposeMission({ description: "# Q" }));
    expect(err.code).toBe("mission_digest_mismatch");
    expect(w.agent.mission).toBeUndefined();
  });

  it("refuses a mission that is not unpadded base64url", async () => {
    w = await world();
    const blob = Buffer.from('{"agent":"a"}');
    approve(blob, { mission: `${blob.toString("base64")}=` });
    const err = await refusal(w.agent.proposeMission({ description: "# Q" }));
    expect(err.code).toBe("mission_invalid");
    expect(w.agent.mission).toBeUndefined();
  });

  it("surfaces a refused proposal with the PS's error", async () => {
    w = await world();
    w.ps.routes["POST /mission"] = () => ({ status: 403, body: { error: "denied" } });
    const err = await refusal(w.agent.proposeMission({ description: "# Q" }));
    expect(err.code).toBe("refused");
    expect(err.response).toEqual({ status: 403, body: { error: "denied" } });
  });
});

describe("person-token requests and misbehavior (@spec aauth#section-7.1)", () => {
  function recordPersonRequests(): unknown[] {
    const bodies: unknown[] = [];
    w.ps.routes["POST /person"] = (req) => {
      bodies.push(req.json);
      return { status: 200, body: { person_token: "pt", expires_in: 3600 } };
    };
    return bodies;
  }

  it("names the agent's mission, or none when it has none", async () => {
    w = await world();
    const bodies = recordPersonRequests();
    await w.agent.requestPersonToken(RESOURCE);
    w.agent.useMission(M);
    await w.agent.requestPersonToken(RESOURCE);
    expect(bodies).toEqual([{ resource: RESOURCE }, { resource: RESOURCE, mission_s256: M }]);
  });

  it.each([
    ["omit", { resource: RESOURCE }],
    ["malformed", { resource: RESOURCE, mission_s256: "not+a/digest=" }],
    [{ value: M2 }, { resource: RESOURCE, mission_s256: M2 }],
  ] as const)("misbehaves with missionReference %j", async (choice, expected) => {
    w = await world({ missionReference: choice });
    w.agent.useMission(M);
    const bodies = recordPersonRequests();
    await w.agent.requestPersonToken(RESOURCE);
    expect(bodies).toEqual([expected]);
  });

  it("signs PS requests with its agent token over the body", async () => {
    w = await world();
    w.ps.routes["POST /person"] = async (req) => {
      const verified = await verifyRequest(req.message, {
        resolver: w.net.resolver({ now: w.clock.now }),
        requireBodyComponents: true,
        now: w.clock.now,
      });
      return { status: 200, body: { person_token: String(verified.token?.payload.sub) } };
    };
    expect(await w.agent.requestPersonToken(RESOURCE)).toBe("aauth:assistant@ap.test");
  });
});

describe("following requirements (@spec aauth#section-11.6.2)", () => {
  it("surfaces a requirement it does not satisfy, and a 202, as unsupported", async () => {
    w = await world();
    w.resource.routes["GET /a"] = () => ({
      status: 401,
      headers: { "aauth-requirement": "requirement=payment" },
    });
    w.resource.routes["GET /b"] = () => ({
      status: 202,
      headers: { "aauth-requirement": 'requirement=interaction; url="https://resource.test/i"' },
    });
    expect((await refusal(w.agent.call(RESOURCE, "/a"))).code).toBe("requirement_unsupported");
    expect((await refusal(w.agent.call(RESOURCE, "/b"))).code).toBe("requirement_unsupported");
  });

  it("refuses an auth-token requirement without a resource token", async () => {
    w = await world();
    w.resource.routes["GET /a"] = () => ({
      status: 401,
      headers: { "aauth-requirement": "requirement=auth-token" },
    });
    expect((await refusal(w.agent.call(RESOURCE, "/a"))).code).toBe("challenge_invalid");
  });

  it("does not carry a refused resource token to the PS", async () => {
    w = await world();
    w.agent.useMission(M);
    w.ps.routes["POST /person"] = async () => ({
      status: 200,
      body: { person_token: await personToken(w, { mission_s256: M }) },
    });
    w.resource.routes["GET /a"] = async (req) => {
      const presented = String(req.headers["signature-key"]?.[0]).match(/jwt="([^"]+)"/)?.[1] ?? "";
      if (decodeClaims(presented).dwk !== "aauth-person.json") {
        return { status: 401, headers: { "aauth-requirement": "requirement=person-token" } };
      }
      const rt = await w.resource.mint(
        "aa-resource+jwt",
        without(resourceTokenClaims(w, decodeClaims(presented)), "mission_s256"),
      );
      return {
        status: 401,
        headers: { "aauth-requirement": `requirement=auth-token; resource-token="${rt}"` },
      };
    };
    const err = await refusal(w.agent.call(RESOURCE, "/a"));
    expect(err.code).toBe("mission_reference_mismatch");
    expect(w.agent.sent.map((s) => s.url)).toEqual([
      `${RESOURCE}/a`,
      `${PS}/person`,
      `${RESOURCE}/a`,
    ]);
  });
});
