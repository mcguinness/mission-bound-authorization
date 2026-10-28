import { AgentError, decodeClaims } from "@mission/aauth-testkit";
import { afterEach, describe, expect, it } from "vitest";
import { mintResourceToken } from "../src/index.js";
import { M, M2, PS, RESOURCE, type World, world } from "./helpers.js";

let w: World;
afterEach(() => w?.close());

const refusal = async (promise: Promise<unknown>): Promise<AgentError> => {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AgentError);
  return err as AgentError;
};

/** A resource token re-signed by the resource with `edit` applied: a faulty resource. */
const tampered =
  (edit: (claims: Record<string, unknown>) => void) =>
  async (token: string): Promise<string> => {
    const claims = decodeClaims(token);
    edit(claims);
    return mintResourceToken(w.resource.key, claims);
  };

const urls = () => w.agent.sent.map((s) => `${s.method} ${s.url} ${s.presented} ${s.status}`);

describe("the three-party route through the agent client (@spec aauth#section-4.2.4)", () => {
  it("follows both requirements, and the run carries the agent's mission", async () => {
    w = await world();
    w.agent.useMission(M);
    const res = await w.agent.call(RESOURCE, "/api/documents", {
      method: "POST",
      body: { title: "plan" },
    });
    expect(res.status).toBe(201);
    expect(urls()).toEqual([
      `POST ${RESOURCE}/api/documents aa-agent+jwt 401`,
      `POST ${PS}/person aa-agent+jwt 200`,
      `POST ${RESOURCE}/api/documents aa-person+jwt 401`,
      `POST ${PS}/token aa-agent+jwt 200`,
      `POST ${RESOURCE}/api/documents aa-auth+jwt 201`,
    ]);
    const pt = w.agent.personToken(RESOURCE) as string;
    const at = w.agent.authToken(RESOURCE) as string;
    expect(w.ps.requests).toEqual([
      { path: "/person", body: { resource: RESOURCE, mission_s256: M } },
      {
        path: "/token",
        body: { resource_token: w.resource.issuedResourceTokens[0]?.token, presented_token: pt },
      },
    ]);
    expect(w.resource.issuedResourceTokens[0]?.claims).toMatchObject({
      presented_jti: decodeClaims(pt).jti,
      mission_s256: M,
    });
    expect(decodeClaims(at).mission_s256).toBe(M);
    expect(w.resource.effects).toEqual([
      expect.objectContaining({ operation: "POST /api/documents", mission_s256: M }),
    ]);
  });

  it("presents the auth token it holds on the next call, with no challenge", async () => {
    w = await world();
    await w.agent.call(RESOURCE, "/api/documents");
    w.agent.sent.length = 0;
    const res = await w.agent.call(RESOURCE, "/api/documents");
    expect(res.status).toBe(200);
    expect(urls()).toEqual([`GET ${RESOURCE}/api/documents aa-auth+jwt 200`]);
  });

  it("steps up from a presented auth token, forwarding it as presented_token (V5)", async () => {
    w = await world();
    w.agent.useMission(M);
    w.ps.tokenPolicy.grant = () => "documents.read";
    expect((await w.agent.call(RESOURCE, "/api/documents")).status).toBe(200);
    const readToken = w.agent.authToken(RESOURCE) as string;
    w.ps.tokenPolicy.grant = undefined;
    w.agent.sent.length = 0;
    const res = await w.agent.call(RESOURCE, "/api/documents", {
      method: "POST",
      body: { title: "plan" },
    });
    expect(res.status).toBe(201);
    expect(urls()).toEqual([
      `POST ${RESOURCE}/api/documents aa-auth+jwt 401`,
      `POST ${PS}/token aa-agent+jwt 200`,
      `POST ${RESOURCE}/api/documents aa-auth+jwt 201`,
    ]);
    const stepUp = w.resource.issuedResourceTokens.at(-1)?.claims;
    expect(stepUp).toMatchObject({ presented_jti: decodeClaims(readToken).jti, mission_s256: M });
    expect(w.ps.requests.at(-1)?.body.presented_token).toBe(readToken);
    expect(w.resource.effects.map((e) => [e.operation, e.mission_s256])).toEqual([
      ["GET /api/documents", M],
      ["POST /api/documents", M],
    ]);
  });

  it("requests authorization at the authorization endpoint, then calls without a challenge", async () => {
    w = await world();
    w.agent.useMission(M);
    const at = await w.agent.authorize(RESOURCE, "documents.read documents.write");
    expect(decodeClaims(at)).toMatchObject({
      scope: "documents.read documents.write",
      mission_s256: M,
    });
    w.agent.sent.length = 0;
    const res = await w.agent.call(RESOURCE, "/api/documents", {
      method: "POST",
      body: { title: "plan" },
    });
    expect(res.status).toBe(201);
    expect(urls()).toEqual([`POST ${RESOURCE}/api/documents aa-auth+jwt 201`]);
  });

  it("carries no mission for a missionless agent (V14 at the resource)", async () => {
    w = await world();
    expect((await w.agent.call(RESOURCE, "/api/documents")).status).toBe(200);
    expect(w.ps.requests[0]?.body).toEqual({ resource: RESOURCE });
    expect("mission_s256" in (w.resource.issuedResourceTokens[0]?.claims ?? {})).toBe(false);
    expect(w.resource.effects[0]?.mission_s256).toBeUndefined();
  });
});

describe("a resource token without the agent's mission (@spec mission-aauth#ref-propagation)", () => {
  it("is refused by the agent when stripped (V2): nothing reaches the token endpoint, nothing runs", async () => {
    w = await world({
      interceptResourceToken: tampered((claims) => {
        delete claims.mission_s256;
      }),
    });
    w.agent.useMission(M);
    const err = await refusal(w.agent.call(RESOURCE, "/api/documents"));
    expect(err.code).toBe("mission_reference_mismatch");
    expect(w.ps.requests.map((r) => r.path)).toEqual(["/person"]);
    expect(w.resource.effects).toEqual([]);
  });

  it("is refused by the agent when it names another mission (V3)", async () => {
    w = await world({
      interceptResourceToken: tampered((claims) => {
        claims.mission_s256 = M2;
      }),
    });
    w.agent.useMission(M);
    const err = await refusal(w.agent.call(RESOURCE, "/api/documents"));
    expect(err.code).toBe("mission_reference_mismatch");
    expect(w.ps.requests.map((r) => r.path)).toEqual(["/person"]);
    expect(w.resource.effects).toEqual([]);
  });

  it("reaches the PS unchanged when the agent skips its checks, and a refusal there runs nothing", async () => {
    w = await world({
      interceptResourceToken: tampered((claims) => {
        delete claims.mission_s256;
      }),
      skipChallengeVerification: true,
    });
    w.agent.useMission(M);
    w.ps.tokenPolicy.refuse = "invalid_resource_token";
    const err = await refusal(w.agent.call(RESOURCE, "/api/documents"));
    expect(err.response).toEqual({ status: 400, body: { error: "invalid_resource_token" } });
    const forwarded = String(w.ps.requests.at(-1)?.body.resource_token);
    expect("mission_s256" in decodeClaims(forwarded)).toBe(false);
    expect(decodeClaims(forwarded).iss).toBe(RESOURCE);
    expect(w.resource.effects).toEqual([]);
  });
});

describe("misbehavior reaching the PS (V4, V7, V8, V9)", () => {
  it("forwards another person token as presented_token (V4)", async () => {
    let other = "";
    w = await world({
      presentedToken: async () => {
        other = await w.ps.personToken(w.agent, { mission_s256: M });
        return other;
      },
    });
    w.agent.useMission(M);
    w.ps.tokenPolicy.refuse = "invalid_resource_token";
    await refusal(w.agent.call(RESOURCE, "/api/documents"));
    const sent = w.ps.requests.at(-1)?.body;
    expect(sent?.presented_token).toBe(other);
    expect(decodeClaims(other).jti).not.toBe(
      w.resource.issuedResourceTokens[0]?.claims.presented_jti,
    );
    expect(w.resource.effects).toEqual([]);
  });

  it.each([
    ["omit", undefined],
    ["malformed", "not+a/digest="],
    [{ value: M2 }, M2],
  ] as const)("names the mission as %j on the person-token request", async (choice, sent) => {
    w = await world({ missionReference: choice, skipChallengeVerification: true });
    w.agent.useMission(M);
    w.ps.tokenPolicy.refuse = "invalid_resource_token";
    await refusal(w.agent.call(RESOURCE, "/api/documents"));
    expect(w.ps.requests[0]?.body.mission_s256).toBe(sent);
    expect(w.resource.effects).toEqual([]);
  });
});
