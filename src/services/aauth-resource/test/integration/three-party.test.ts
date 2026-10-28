/**
 * The AAuth Mission propagation vectors (notes/aauth-propagation-vectors.md)
 * run end to end through the real agent client, Person Server and
 * Resource (#836 slice 2): V1-V5, V7-V12, V14 and P1 at the PS endpoints
 * this slice builds. V6, V13 and V15 (four-party or chained) and P2 (the
 * management control plane) are outside the slice.
 *
 * Every negative vector asserts its exact refusal, that the PS issued and
 * recorded nothing for the refused request (its issued-token records and
 * mission logs are unchanged and the response carries no token), and that
 * the Resource ran nothing (its effect log is unchanged). Misbehavior is
 * the testkit's: it changes what the agent sends, or what a faulty
 * Resource signs, and never disables a check on the receiving side.
 */
import { createHash } from "node:crypto";
import { parsePsConfig, rfc3339 } from "@mission/aauth-ps";
import { createIssuerStub, decodeClaims, parseRequirement } from "@mission/aauth-testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  detailOf,
  expectRefused,
  observable,
  PS,
  type PsRecords,
  psTokenRequests,
  RESOURCE,
  refusal,
  shippedPsConfig,
  tamperedBy,
  trail,
  type World,
  world,
} from "./world.js";

let w: World;
beforeEach(async () => {
  w = await world();
});
afterEach(async () => {
  await w.close();
});

/** A well-formed `mission_s256` that names no mission. */
const ABSENT = createHash("sha256")
  .update("no mission was approved with this blob")
  .digest("base64url");

const strip = (claims: Record<string, unknown>) => {
  delete claims.mission_s256;
};

/** The resource token the Resource issued for the agent's last challenge. */
const lastResourceToken = () => w.resource.issuedResourceTokens.at(-1);

/** No issuance, no record and no effect since `before` and `effects` were taken. */
function nothingHappened(before: PsRecords, effects: number): void {
  expect(w.records()).toEqual(before);
  expect(w.resource.effects).toHaveLength(effects);
}

describe("three-party propagation through the real agent, PS and Resource (@spec mission-aauth#ref-propagation)", () => {
  it("V1: the governed path carries the agent's exact mission from approval through every token to the run", async () => {
    const agent = await w.agent();
    const approval = await agent.proposeMission({ description: "Draft the quarterly plan" });
    const M = approval.s256;
    w.missions.add(M);

    const res = await agent.call(RESOURCE, "/api/documents", {
      method: "POST",
      body: { title: "plan" },
    });

    expect(res.status).toBe(201);
    expect(trail(agent)).toEqual([
      `POST ${PS}/mission aa-agent+jwt 200`,
      `POST ${RESOURCE}/api/documents aa-agent+jwt 401`,
      `POST ${PS}/person aa-agent+jwt 200`,
      `POST ${RESOURCE}/api/documents aa-person+jwt 401`,
      `POST ${PS}/token aa-agent+jwt 200`,
      `POST ${RESOURCE}/api/documents aa-auth+jwt 201`,
    ]);
    const pt = decodeClaims(agent.personToken(RESOURCE) as string);
    const rt = lastResourceToken()?.claims ?? {};
    const at = decodeClaims(agent.authToken(RESOURCE) as string);
    // The PS stamps the named mission into the person token.
    expect(pt).toMatchObject({ iss: PS, aud: RESOURCE, mission_s256: M });
    // The Resource copies it, exactly, into the resource token naming that person token.
    expect(rt).toMatchObject({ iss: RESOURCE, aud: PS, ps: PS, presented_jti: pt.jti });
    expect(rt.mission_s256).toBe(pt.mission_s256);
    // The PS copies it onward, exactly, into the auth token.
    expect(at).toMatchObject({ iss: PS, ps: PS, aud: RESOURCE, sub: rt.sub });
    expect(at.mission_s256).toBe(rt.mission_s256);
    expect(w.resource.effects).toEqual([
      expect.objectContaining({
        operation: "POST /api/documents",
        mission_s256: M,
        authJti: at.jti,
      }),
    ]);
    // Each token is recorded under the mission, and the log keeps the order.
    const issued = w.store.issuedTokens();
    expect(issued).toHaveLength(2);
    expect(issued).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "person", jti: pt.jti, missionS256: M, aud: RESOURCE }),
        expect.objectContaining({ kind: "auth", jti: at.jti, missionS256: M, aud: RESOURCE }),
      ]),
    );
    expect(w.store.missionLog(M).map((e) => e.event)).toEqual([
      "approved",
      "person_token_issued",
      "auth_token_issued",
    ]);
    // The agent kept the decoded blob bytes exactly: the owner's read returns the same bytes.
    const read = await agent.send(`${PS}/mission/${M}`);
    expect(read.status).toBe(200);
    const persisted = Buffer.from(
      String((read.json() as { mission: string }).mission),
      "base64url",
    );
    expect(persisted.equals(approval.blob)).toBe(true);
    expect(agent.mission?.blob?.equals(persisted)).toBe(true);
  });

  it("V2: a resource token stripped of the person token's mission is refused at the PS: invalid_resource_token", async () => {
    const agent = await w.agent();
    await w.approve(agent);
    let before: PsRecords | undefined;
    agent.misbehavior = {
      interceptResourceToken: async (token) => {
        before = w.records();
        return tamperedBy(w.resource, strip)(token);
      },
      skipChallengeVerification: true,
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 400, "invalid_resource_token");
    expect(detailOf(err)).toBe("mission_s256 does not match the presented token");
    nothingHappened(before as PsRecords, 0);
    expect(w.store.issuedTokens().map((t) => t.kind)).toEqual(["person"]);
    // The agent does not retry the refused request without the reference.
    expect(psTokenRequests(agent).map((s) => s.url)).toEqual([`${PS}/person`, `${PS}/token`]);
    expect(agent.sent.at(-1)).toMatchObject({ url: `${PS}/token`, status: 400 });
  });

  it("V3: a resource token naming the agent's other mission is refused at the PS and surfaced to operators", async () => {
    const agent = await w.agent();
    const M2 = await w.approve(agent, { description: "Plan the offsite" });
    const M = await w.approve(agent);
    let before: PsRecords | undefined;
    agent.misbehavior = {
      interceptResourceToken: async (token) => {
        before = w.records();
        return tamperedBy(w.resource, (claims) => {
          claims.mission_s256 = M2;
        })(token);
      },
      skipChallengeVerification: true,
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 400, "invalid_resource_token");
    expect(decodeClaims(agent.personToken(RESOURCE) as string).mission_s256).toBe(M);
    nothingHappened(before as PsRecords, 0);
    expect(w.ps.securityEvents).toEqual([
      expect.objectContaining({
        type: "presented_token_mismatch",
        agent: agent.id,
        detail: "mission_s256 does not match the presented token",
      }),
    ]);
    expect(psTokenRequests(agent).map((s) => s.url)).toEqual([`${PS}/person`, `${PS}/token`]);
  });

  it("V4: a person token other than the one presented_jti names is refused at the PS: invalid_resource_token", async () => {
    const agent = await w.agent();
    await w.approve(agent);
    const first = await agent.requestPersonToken(RESOURCE);
    await agent.requestPersonToken(RESOURCE);
    let before: PsRecords | undefined;
    agent.misbehavior = {
      presentedToken: () => {
        before = w.records();
        return first;
      },
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 400, "invalid_resource_token");
    expect(detailOf(err)).toBe("presented_jti does not name the presented token");
    // The Resource named the token presented to it, not the one forwarded.
    expect(lastResourceToken()?.claims.presented_jti).toBe(
      decodeClaims(agent.personToken(RESOURCE) as string).jti,
    );
    expect(lastResourceToken()?.claims.presented_jti).not.toBe(decodeClaims(first).jti);
    nothingHappened(before as PsRecords, 0);
  });

  it("V5: an honest step-up on a presented auth token carries the mission into the new auth token", async () => {
    const agent = await w.agent();
    const M = await w.approve(agent);
    const narrow = await agent.authorize(RESOURCE, "documents.read");
    // The authorization endpoint's resource token copies the person token's mission too.
    expect(w.resource.issuedResourceTokens[0]).toMatchObject({
      route: "POST /authorize",
      claims: { mission_s256: M },
    });
    expect(decodeClaims(narrow).mission_s256).toBe(M);

    const res = await agent.call(RESOURCE, "/api/documents", {
      method: "POST",
      body: { title: "minutes" },
    });

    expect(res.status).toBe(201);
    const stepUp = lastResourceToken()?.claims ?? {};
    expect(stepUp.presented_jti).toBe(decodeClaims(narrow).jti);
    expect(stepUp.mission_s256).toBe(M);
    const wide = decodeClaims(agent.authToken(RESOURCE) as string);
    expect(wide.mission_s256).toBe(M);
    expect(wide.scope).toBe("documents.read documents.write");
    expect(w.resource.effects).toEqual([expect.objectContaining({ mission_s256: M })]);
  });

  it("V5: a step-up resource token stripped of the auth token's mission is refused by the agent, and at the PS: invalid_resource_token", async () => {
    const agent = await w.agent();
    await w.approve(agent);
    const narrow = await agent.authorize(RESOURCE, "documents.read");
    const write = { method: "POST", body: { title: "minutes" } };

    // The agent's own check stops it before the PS.
    agent.misbehavior = { interceptResourceToken: tamperedBy(w.resource, strip) };
    const sent = psTokenRequests(agent).length;
    const held = await refusal(agent.call(RESOURCE, "/api/documents", write));
    expect(held.code).toBe("mission_reference_mismatch");
    expect(psTokenRequests(agent)).toHaveLength(sent);

    // An agent that skips its check reaches the PS, which refuses.
    let before: PsRecords | undefined;
    agent.misbehavior = {
      interceptResourceToken: async (token) => {
        before = w.records();
        return tamperedBy(w.resource, strip)(token);
      },
      skipChallengeVerification: true,
    };
    const err = await refusal(agent.call(RESOURCE, "/api/documents", write));

    expectRefused(err, 400, "invalid_resource_token");
    expect(lastResourceToken()?.claims.presented_jti).toBe(decodeClaims(narrow).jti);
    nothingHappened(before as PsRecords, 0);
  });

  it("V7: a malformed mission_s256 at the person token endpoint is refused: invalid_request", async () => {
    const agent = await w.agent("assistant", { missionReference: "malformed" });
    await w.approve(agent);
    const before = w.records();

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 400, "invalid_request");
    expect(detailOf(err)).toBe("mission_s256 is malformed");
    nothingHappened(before, 0);
    expect(psTokenRequests(agent).map((s) => s.body)).toEqual([
      { resource: RESOURCE, mission_s256: "not+a/digest=" },
    ]);
    expect(agent.sent.at(-1)).toMatchObject({ url: `${PS}/person`, status: 400 });
  });

  it("V8: a well-formed mission_s256 naming no mission, or another agent's, is refused at the person token endpoint", async () => {
    const planner = await w.agent("planner");
    const theirs = await w.approve(planner, { description: "Plan the offsite" });
    const agent = await w.agent();
    await w.approve(agent);

    for (const reference of [ABSENT, theirs]) {
      agent.misbehavior = { missionReference: { value: reference } };
      agent.forget(RESOURCE);
      const before = w.records();

      const err = await refusal(agent.call(RESOURCE, "/api/documents"));

      expectRefused(err, 400, "invalid_request");
      expect(detailOf(err)).toBe("mission_s256 does not name a mission of this agent");
      nothingHappened(before, 0);
      expect(psTokenRequests(agent).at(-1)?.body).toEqual({
        resource: RESOURCE,
        mission_s256: reference,
      });
    }
    // Neither refusal was followed by a request without the reference.
    expect(
      psTokenRequests(agent).every((s) => (s.body as { mission_s256?: string }).mission_s256),
    ).toBe(true);
  });

  it("V9: a missionless person token request from an agent under mission governance is refused", async () => {
    const agent = await w.agent();
    const before = w.records();

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 403, "denied");
    nothingHappened(before, 0);
    expect(w.store.issuedTokens()).toEqual([]);
    expect(psTokenRequests(agent).map((s) => s.body)).toEqual([{ resource: RESOURCE }]);
  });

  it("V9: after a restart places an agent under governance, its missionless requests are refused at both token endpoints", async () => {
    const helper = await w.agent("helper");
    const pt = await helper.requestPersonToken(RESOURCE);
    expect(decodeClaims(pt).mission_s256).toBeUndefined();
    const doc = shippedPsConfig();
    for (const entry of doc.agents as { agent: string; mission_governed: boolean }[]) {
      if (entry.agent === helper.id) entry.mission_governed = true;
    }
    await w.restartPs(parsePsConfig(doc));

    // The person token issued before the change still verifies, so the
    // Resource issues a missionless resource token for it.
    let before: PsRecords | undefined;
    helper.misbehavior = {
      presentedToken: (presented) => {
        before = w.records();
        return presented;
      },
    };
    const atToken = await refusal(helper.call(RESOURCE, "/api/documents"));
    expectRefused(atToken, 403, "denied");
    expect(lastResourceToken()?.claims.mission_s256).toBeUndefined();
    nothingHappened(before as PsRecords, 0);

    helper.forget(RESOURCE);
    const again = w.records();
    const atPerson = await refusal(helper.requestPersonToken(RESOURCE));
    expectRefused(atPerson, 403, "denied");
    nothingHappened(again, 0);
  });

  it("V10: a mission terminated after its person token was issued is refused: mission_terminated", async () => {
    const agent = await w.agent();
    const M = await w.approve(agent);
    let before: PsRecords | undefined;
    agent.misbehavior = {
      interceptResourceToken: (token) => {
        w.ps.store.terminate(agent.id, M, "revoked", w.seconds());
        before = w.records();
        return token;
      },
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 403, "mission_terminated");
    expect(err.response?.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "revoked",
    });
    nothingHappened(before as PsRecords, 0);

    agent.forget(RESOURCE);
    const again = w.records();
    const atPerson = await refusal(agent.requestPersonToken(RESOURCE));
    expectRefused(atPerson, 403, "mission_terminated");
    nothingHappened(again, 0);
  });

  it("V11: once the mission's expires_at passes, its person token fails presented-token verification: expired_presented_token", async () => {
    const agent = await w.agent();
    const expiresAt = w.seconds() + 120;
    await w.approve(agent, { description: "Summarize", expires_at: rfc3339(expiresAt) });
    let before: PsRecords | undefined;
    agent.misbehavior = {
      // Time passes between the Resource's challenge and the redemption.
      interceptResourceToken: (token) => {
        w.clock.advance(150_000);
        before = w.records();
        return token;
      },
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 400, "expired_presented_token");
    // The PS capped the person token at the mission's expires_at, and the
    // resource token, still valid, carried the mission.
    expect(decodeClaims(agent.personToken(RESOURCE) as string).exp).toBe(expiresAt);
    expect(lastResourceToken()?.claims.exp as number).toBeGreaterThan(w.seconds());
    nothingHappened(before as PsRecords, 0);
  });

  it("V12: when the mission's state cannot be established, the PS refuses: server_error", async () => {
    const agent = await w.agent();
    await w.approve(agent);
    let before: PsRecords | undefined;
    agent.misbehavior = {
      interceptResourceToken: (token) => {
        w.store.failMissionReads = true;
        before = w.records();
        return token;
      },
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expectRefused(err, 500, "server_error");
    expect(detailOf(err)).toBe("mission state is unavailable");
    nothingHappened(before as PsRecords, 0);

    agent.forget(RESOURCE);
    const atPerson = await refusal(agent.requestPersonToken(RESOURCE));
    expectRefused(atPerson, 500, "server_error");
    nothingHappened(before as PsRecords, 0);
  });

  it("V14: an agent admitted missionless from the outset is served without a mission, and a failed reference is never served missionless", async () => {
    const helper = await w.agent("helper");

    const res = await helper.call(RESOURCE, "/api/documents", {
      method: "POST",
      body: { title: "note" },
    });

    expect(res.status).toBe(201);
    const pt = decodeClaims(helper.personToken(RESOURCE) as string);
    const at = decodeClaims(helper.authToken(RESOURCE) as string);
    expect("mission_s256" in pt).toBe(false);
    expect("mission_s256" in (lastResourceToken()?.claims ?? {})).toBe(false);
    expect("mission_s256" in at).toBe(false);
    expect(w.resource.effects).toEqual([
      expect.not.objectContaining({ mission_s256: expect.anything() }),
    ]);
    expect(w.store.issuedTokens().map((t) => [t.kind, t.missionS256])).toEqual(
      expect.arrayContaining([
        ["person", undefined],
        ["auth", undefined],
      ]),
    );

    // The same agent naming a mission that fails validation is refused, not served missionless.
    helper.forget(RESOURCE);
    for (const reference of ["malformed", { value: ABSENT }] as const) {
      helper.misbehavior = { missionReference: reference };
      const before = w.records();
      const err = await refusal(helper.requestPersonToken(RESOURCE));
      expectRefused(err, 400, "invalid_request");
      nothingHappened(before, 1);
    }
  });
});

describe("the agent's mission check (@spec mission-aauth#ref-propagation)", () => {
  it("V2 at the agent: a resource token stripped of its mission is never carried to the PS", async () => {
    const agent = await w.agent("assistant", {
      interceptResourceToken: async (token) => tamperedBy(w.resource, strip)(token),
    });
    await w.approve(agent);
    const before = w.records();

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expect(err.code).toBe("mission_reference_mismatch");
    expect(psTokenRequests(agent).map((s) => s.url)).toEqual([`${PS}/person`]);
    expect(w.records().issued.filter((t) => t.kind === "auth")).toEqual([]);
    expect(w.records().issued).toHaveLength(before.issued.length + 1);
    expect(w.resource.effects).toEqual([]);
  });

  it("V3 at the agent: a resource token naming another of its missions is never carried to the PS", async () => {
    const agent = await w.agent();
    const M2 = await w.approve(agent, { description: "Plan the offsite" });
    await w.approve(agent);
    agent.misbehavior = {
      interceptResourceToken: tamperedBy(w.resource, (claims) => {
        claims.mission_s256 = M2;
      }),
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expect(err.code).toBe("mission_reference_mismatch");
    expect(psTokenRequests(agent).map((s) => s.url)).toEqual([`${PS}/person`]);
    expect(w.store.issuedTokens().filter((t) => t.kind === "auth")).toEqual([]);
    expect(w.resource.effects).toEqual([]);
  });
});

describe("the PS's own checks before mission state (@spec mission-aauth#ref-propagation)", () => {
  it("refuses a resource token whose ps names another PS before reading any mission state, even when it names this agent's own mission", async () => {
    const other = createIssuerStub({
      issuer: "https://ps2.test",
      dwk: "aauth-person.json",
      kid: "ps2-key-1",
    });
    await w.net.serve(other.issuer, other.handler);
    const agent = await w.agent();
    const M = await w.approve(agent);
    // A person token from another PS whose mission_s256 equals this agent's mission here.
    const foreignPt = await other.mint("aa-person+jwt", {
      iss: other.issuer,
      dwk: "aauth-person.json",
      aud: RESOURCE,
      sub: "someone-at-ps2",
      jti: "ps2-person-token-1",
      iat: w.seconds(),
      exp: w.seconds() + 600,
      cnf: { jwk: agent.key.publicJwk },
      mission_s256: M,
    });
    const challenge = await agent.send(`${RESOURCE}/api/documents`, { token: foreignPt });
    expect(challenge.status).toBe(401);
    const issued = parseRequirement(challenge.headers["aauth-requirement"] as string).params.get(
      "resource-token",
    ) as string;
    expect(decodeClaims(issued)).toMatchObject({
      aud: other.issuer,
      ps: other.issuer,
      mission_s256: M,
    });
    // A faulty Resource addresses that resource token to this PS.
    const misaddressed = await tamperedBy(w.resource, (claims) => {
      claims.aud = PS;
    })(issued);
    const before = w.records();
    const reads = w.store.missionReads;

    const res = await agent.send(`${PS}/token`, {
      method: "POST",
      body: { resource_token: misaddressed, presented_token: foreignPt },
    });

    expect(res.status).toBe(400);
    expect(res.json()).toEqual({
      error: "invalid_resource_token",
      detail: "ps does not name this person server",
    });
    expect(w.store.missionReads).toBe(reads);
    nothingHappened(before, 0);
  });
});

describe("P1: a guessed reference from a non-owner agent discloses nothing (@spec mission-aauth#reference)", () => {
  /** The planner owns one active and one terminated mission; the assistant owns another. */
  async function missions() {
    const planner = await w.agent("planner");
    const active = await w.approve(planner, { description: "Plan the offsite" });
    const ended = await w.approve(planner, { description: "Book the venue" });
    w.ps.store.terminate(planner.id, ended, "revoked", w.seconds());
    const agent = await w.agent();
    const own = await w.approve(agent);
    return { planner, agent, own, active, ended };
  }

  it("P1 at the person token endpoint: another agent's mission, active or terminated, is answered exactly as an absent one", async () => {
    const { planner, agent, active, ended } = await missions();
    const before = w.records();
    const ask = (reference: string) =>
      agent.send(`${PS}/person`, {
        method: "POST",
        body: { resource: RESOURCE, mission_s256: reference },
      });

    const absent = observable(await ask(ABSENT));
    const foreign = observable(await ask(active));
    const foreignEnded = observable(await ask(ended));

    expect(absent.status).toBe(400);
    expect(JSON.parse(absent.body)).toEqual({
      error: "invalid_request",
      detail: "mission_s256 does not name a mission of this agent",
    });
    expect(foreign).toEqual(absent);
    expect(foreignEnded).toEqual(absent);
    nothingHappened(before, 0);
    // Only the owner learns that the mission terminated.
    const owner = await planner.send(`${PS}/person`, {
      method: "POST",
      body: { resource: RESOURCE, mission_s256: ended },
    });
    expect(owner.status).toBe(403);
    expect(owner.json()).toMatchObject({ error: "mission_terminated" });
  });

  it("P1 at {mission_endpoint}/{mission_s256}: another agent's mission, active or terminated, is answered exactly as an absent one", async () => {
    const { planner, agent, active, ended } = await missions();
    const before = w.records();

    const absent = observable(await agent.send(`${PS}/mission/${ABSENT}`));
    const foreign = observable(await agent.send(`${PS}/mission/${active}`));
    const foreignEnded = observable(await agent.send(`${PS}/mission/${ended}`));

    expect(absent.status).toBe(404);
    expect(JSON.parse(absent.body)).toEqual({
      error: "mission_not_found",
      detail: "no such mission",
    });
    expect(foreign).toEqual(absent);
    expect(foreignEnded).toEqual(absent);
    nothingHappened(before, 0);
    expect((await planner.send(`${PS}/mission/${active}`)).status).toBe(200);
    expect((await planner.send(`${PS}/mission/${ended}`)).json()).toMatchObject({
      error: "mission_terminated",
    });
  });

  it("P1 at the auth token endpoint's mission check: another agent's mission, active or terminated, is answered exactly as an absent one", async () => {
    const { agent, own, active, ended } = await missions();
    // No honest PS issues a person token naming a mission the agent does
    // not own, so the probe re-signs the agent's real person token with
    // the PS's own key, changing only mission_s256 and jti. The Resource
    // and the PS that process it are the real services.
    const real = decodeClaims(await agent.requestPersonToken(RESOURCE));
    expect(real.mission_s256).toBe(own);
    const probe = async (reference: string) => {
      const pt = await w.psMint("aa-person+jwt", {
        ...real,
        jti: `probe-${reference.slice(0, 8)}`,
        mission_s256: reference,
      });
      const challenge = await agent.send(`${RESOURCE}/api/documents`, { token: pt });
      const rt = parseRequirement(challenge.headers["aauth-requirement"] as string).params.get(
        "resource-token",
      ) as string;
      expect(decodeClaims(rt).mission_s256).toBe(reference);
      return agent.send(`${PS}/token`, {
        method: "POST",
        body: { resource_token: rt, presented_token: pt },
      });
    };
    const before = w.records();

    const absent = observable(await probe(ABSENT));
    const foreign = observable(await probe(active));
    const foreignEnded = observable(await probe(ended));

    expect(absent.status).toBe(400);
    expect(JSON.parse(absent.body)).toEqual({
      error: "invalid_resource_token",
      detail: "mission_s256 does not name a mission of this agent",
    });
    expect(foreign).toEqual(absent);
    expect(foreignEnded).toEqual(absent);
    nothingHappened(before, 0);
  });
});
