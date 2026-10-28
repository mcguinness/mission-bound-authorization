/**
 * Tracking and revocation after termination (the management companion's
 * Tracking Credentials, Revocation Attempts and Honest Residual Bounds;
 * AAuth -11 Section 11.12): each unexpired Tracked Credential revoked at
 * the Resource in its `aud` with a server-signed `{jti, exp}`, each
 * outcome recorded, an unconfirmed credential counted until its `exp`,
 * `complete` false while any Person Token is live and unconfirmed (D299),
 * bounded retries, and recovery of terminal state, receipts and pending
 * work across a restart.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type RevocationRecord, rfc3339 } from "../src/index.js";
import {
  type Agent,
  ASSISTANT,
  approve,
  claims,
  control,
  HELPER,
  makeAgent,
  PS,
  personToken,
  REVOKE_PATH,
  RS,
  RS2,
  requestAuthToken,
  requestPersonToken,
  resourceTokenFor,
  terminateBody,
  type World,
  world,
} from "./helpers.js";

let w: World;
let assistant: Agent;

async function boot(options: Parameters<typeof world>[0] = {}) {
  w = await world(options);
  assistant = await makeAgent(w.ap, w.clock);
}

afterEach(async () => {
  vi.restoreAllMocks();
  await w.close();
});

/** A mission with a person token for RS from its approval, and an auth token for RS on it. */
async function missionWithTokens() {
  const approval = await approve(w, assistant, {
    description: "Summarize the quarterly report",
    resources: [RS],
  });
  const person = approval.person_tokens?.[RS] as string;
  const r = await requestAuthToken(w, assistant, {
    resource_token: await resourceTokenFor(w, assistant, person),
    presented_token: person,
  });
  expect(r.status).toBe(200);
  return { s256: approval.s256, person, auth: r.body.auth_token as string };
}

const residualOf = async (s256: string) =>
  (await control(w, assistant, s256, { action: "status" })).body.token_residual as Record<
    string,
    unknown
  >;
const events = (s256: string, event: string) =>
  w.durable.missionLog(s256).filter((e) => e.event === event);

describe("revocation after termination", () => {
  beforeEach(() => boot());

  it("revokes each Tracked Credential at the Resource in its aud, signed as the PS under jwks_uri", async () => {
    const { s256, person, auth } = await missionWithTokens();
    // A missionless token is no Tracked Credential: never revoked here.
    const helper = await makeAgent(w.ap, w.clock, HELPER);
    const missionless = claims(await personToken(w, helper, RS));
    const r = await control(w, assistant, s256, terminateBody());
    expect(r.body.token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 2,
      complete: true,
    });
    const p = claims(person);
    const a = claims(auth);
    // Attempts run in no particular order between the two credentials.
    const byJti = <T>(rows: T[], jti: (row: T) => unknown) =>
      [...rows].sort((x, y) => (String(jti(x)) < String(jti(y)) ? -1 : 1));
    const expected = byJti(
      [
        { iss: PS, jti: p.jti, exp: p.exp, kind: "person" },
        { iss: PS, jti: a.jti, exp: a.exp, kind: "auth" },
      ],
      (x) => x.jti,
    );
    expect(
      byJti(
        w.rs.revoked.map(({ iss, jti, exp }) => ({ iss, jti, exp })),
        (x) => x.jti,
      ),
    ).toEqual(expected.map(({ iss, jti, exp }) => ({ iss, jti, exp })));
    expect(w.rs.revoked.map((x) => x.jti)).not.toContain(missionless.jti);
    for (const revoked of w.rs.revoked) {
      expect(revoked.verified.scheme).toBe("jwks_uri");
      expect(revoked.verified.signer).toEqual({
        id: PS,
        dwk: "aauth-person.json",
        kid: "ps-signing-1",
      });
      expect(revoked.verified.coveredComponents).toEqual(
        expect.arrayContaining([
          "@method",
          "@authority",
          "@path",
          "signature-key",
          "content-digest",
          "content-type",
        ]),
      );
    }
    // Two requests to one endpoint: distinct seconds, so a replay cache keyed
    // on `created` takes both.
    const [first, second] = w.rs.revoked;
    expect(second?.created).toBeGreaterThan(first?.created as number);
    // Each attempt and its result, identified by (iss, jti).
    const results = events(s256, "revocation_result");
    expect(
      byJti(
        results.map((e) => e.detail),
        (d) => (d.token as { jti: string }).jti,
      ),
    ).toEqual(
      expected.map(({ jti, kind }) => ({
        token: { iss: PS, jti },
        kind,
        recipient: RS,
        attempt: 1,
        outcome: "revoked",
        state: "confirmed",
        endpoint: `${RS}${REVOKE_PATH}`,
        status: 200,
      })),
    );
    expect(
      byJti(
        events(s256, "revocation_attempted").map((e) => e.detail.token as { jti: string }),
        (t) => t.jti,
      ),
    ).toEqual(expected.map(({ jti }) => ({ iss: PS, jti })));
  });

  it("records an attempt before it sends it", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    const seen: string[][] = [];
    w.rs.onRequest = () => {
      seen.push(w.durable.missionLog(s256).map((e) => e.event));
    };
    await control(w, assistant, s256, terminateBody());
    expect(seen).toEqual([["approved", "terminated", "revocation_attempted"]]);
  });

  it("tracks a credential already expired at termination without attempting it", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.clock.advance(3600);
    const r = await control(w, assistant, s256, terminateBody());
    expect(r.body.token_residual).toEqual({
      tracked: 1,
      revocation_attempted: 0,
      revocation_confirmed: 0,
      complete: true,
    });
    expect(w.rs.requests).toBe(0);
    expect(w.durable.revocations(s256)).toEqual([]);
  });

  it("keeps complete false while a Person Token is unconfirmed, though every Auth Token is confirmed (D299)", async () => {
    const { s256, person, auth } = await missionWithTokens();
    const p = claims(person);
    w.rs.failFor.add(p.jti as string);
    const r = await control(w, assistant, s256, terminateBody());
    expect(r.body.token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 1,
      residual_until: rfc3339(p.exp as number),
      complete: false,
    });
    expect(w.rs.revoked.map((x) => x.jti)).toEqual([claims(auth).jti]);
  });

  it("leaves a credential unconfirmed while its recipient is unreachable, and a later attempt confirms it", async () => {
    const { s256, person } = await approve(w, assistant, {
      description: "Summarize",
      resources: [RS],
    }).then((a) => ({ s256: a.s256, person: a.person_tokens?.[RS] as string }));
    const p = claims(person);
    await w.rs.down();
    const r = await control(w, assistant, s256, terminateBody());
    const at = w.clock.s;
    expect(r.status).toBe(200);
    expect(r.body.mission_status).toBe("terminated");
    expect(r.body.token_residual).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 0,
      residual_until: rfc3339(p.exp as number),
      complete: false,
    });
    expect(events(s256, "revocation_result").at(-1)?.detail).toMatchObject({
      outcome: "revocation_unavailable",
      state: "pending",
      next_attempt_at: at + 30,
    });
    // Gating does not wait on revocation.
    const pt = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    expect(pt.body.error).toBe("mission_terminated");
    await w.rs.up();
    w.clock.advance(10);
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(0);
    w.clock.advance(30);
    await w.ps.revocations?.runDue();
    expect(w.rs.revoked.map((x) => x.jti)).toEqual([p.jti]);
    expect(await residualOf(s256)).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 1,
      complete: true,
    });
  });

  it("retries a 5xx with growing spacing, stops at the bound, and counts the credential until its exp", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    const exp = w.durable.missionTokens(s256)[0]?.exp as number;
    w.rs.mode = "unavailable";
    await control(w, assistant, s256, terminateBody());
    expect(w.rs.requests).toBe(1);
    // Backoff 30, 60, 120 (the cap); the fourth attempt is the last.
    for (const [wait, expected] of [
      [29, 1],
      [1, 2],
      [59, 2],
      [1, 3],
      [120, 4],
      [600, 4],
    ] as const) {
      w.clock.advance(wait);
      await w.ps.revocations?.runDue();
      expect(w.rs.requests).toBe(expected);
    }
    expect(w.durable.revocations(s256)[0]).toMatchObject({ state: "exhausted", attempts: 4 });
    expect(await residualOf(s256)).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 0,
      residual_until: rfc3339(exp),
      complete: false,
    });
    // Natural expiry closes the residual.
    w.clock.ms = exp * 1000;
    expect(await residualOf(s256)).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 0,
      complete: true,
    });
  });

  it("never attempts a revocation once the credential has expired", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    const exp = w.durable.missionTokens(s256)[0]?.exp as number;
    await w.rs.down();
    await control(w, assistant, s256, terminateBody());
    await w.rs.up();
    w.clock.ms = exp * 1000;
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(0);
    expect(w.durable.revocations(s256)[0]).toMatchObject({ state: "pending", attempts: 1 });
  });

  it("waits the Retry-After of a 429 before revoking again", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.rs.mode = "rate-limited";
    w.rs.retryAfter = 100;
    await control(w, assistant, s256, terminateBody());
    expect(w.durable.revocations(s256)[0]).toMatchObject({
      state: "pending",
      lastOutcome: "rate_limited",
      lastStatus: 429,
    });
    w.rs.mode = "ok";
    w.clock.advance(60);
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(1);
    w.clock.advance(40);
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(2);
    expect(w.durable.revocations(s256)[0]?.state).toBe("confirmed");
  });

  it("stops at unsupported_iss: the recipient honors the token until its exp", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.rs.mode = "unsupported-iss";
    const r = await control(w, assistant, s256, terminateBody());
    expect((r.body.token_residual as Record<string, unknown>).complete).toBe(false);
    w.clock.advance(1000);
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(1);
    expect(w.durable.revocations(s256)[0]).toMatchObject({
      state: "unsupported",
      lastOutcome: "unsupported_iss",
    });
  });

  it("stops at a 400: the request will not succeed by repetition", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.rs.mode = "bad-request";
    await control(w, assistant, s256, terminateBody());
    w.clock.advance(1000);
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(1);
    expect(w.durable.revocations(s256)[0]?.state).toBe("rejected");
  });

  it("sends nothing to a Resource that advertises no revocation endpoint, and counts the credential until its exp", async () => {
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS2] });
    const exp = w.durable.missionTokens(s256)[0]?.exp as number;
    const r = await control(w, assistant, s256, terminateBody());
    expect(r.body.token_residual).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 0,
      residual_until: rfc3339(exp),
      complete: false,
    });
    expect(w.durable.revocations(s256)[0]).toMatchObject({
      recipient: RS2,
      state: "unsupported",
      lastOutcome: "no_revocation_endpoint",
    });
    expect(w.durable.revocations(s256)[0]).not.toHaveProperty("endpoint");
    w.clock.advance(1000);
    await w.ps.revocations?.runDue();
    expect(events(s256, "revocation_attempted")).toHaveLength(1);
  });

  it("finds the endpoint the Resource publishes, wherever it is", async () => {
    w.rs.metadata.revocation_endpoint = `${RS}/elsewhere`;
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    await control(w, assistant, s256, terminateBody());
    expect(w.rs.requests).toBe(0);
    expect(w.durable.revocations(s256)[0]).toMatchObject({
      endpoint: `${RS}/elsewhere`,
      state: "pending",
    });
  });

  it("trusts no metadata document whose issuer is not the Resource, and no endpoint but https", async () => {
    w.rs.metadata.issuer = "https://elsewhere.test";
    const first = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    await control(w, assistant, first.s256, terminateBody());
    expect(w.durable.revocations(first.s256)[0]).toMatchObject({
      state: "pending",
      lastOutcome: "revocation_unavailable",
    });
    w.rs.metadata.issuer = RS;
    w.rs.metadata.revocation_endpoint = `http://rs.test${REVOKE_PATH}`;
    const second = await approve(w, assistant, { description: "Draft", resources: [RS] });
    await control(w, assistant, second.s256, terminateBody());
    expect(w.durable.revocations(second.s256)[0]).toMatchObject({
      state: "unsupported",
      lastOutcome: "no_revocation_endpoint",
    });
    expect(w.rs.requests).toBe(0);
  });

  it("confirms on a 200 with an empty body or a JSON object, and on nothing else", async () => {
    const outcomes: Record<string, string | undefined> = {};
    for (const mode of ["ok", "ok-json", "garbage", "deferred", "reset"] as const) {
      w.rs.mode = mode;
      const { s256 } = await approve(w, assistant, {
        description: `Summarize under ${mode}`,
        resources: [RS],
      });
      await control(w, assistant, s256, terminateBody());
      outcomes[mode] = w.durable.revocations(s256)[0]?.state;
    }
    expect(outcomes).toEqual({
      ok: "confirmed",
      "ok-json": "confirmed",
      garbage: "pending",
      deferred: "pending",
      reset: "pending",
    });
  });
});

describe("revocation timing", () => {
  it("answers within its bounded wait while a recipient hangs, with the termination already committed", async () => {
    await boot({
      config: (doc) => {
        const m = doc.management as Record<string, Record<string, unknown>>;
        (m.revocation as Record<string, unknown>).attempt_timeout_ms = 2500;
        (m.revocation as Record<string, unknown>).immediate_wait_ms = 150;
      },
    });
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.rs.mode = "hang";
    const started = Date.now();
    const r = await control(w, assistant, s256, terminateBody());
    // The answer came at the wait's bound, well before the attempt's own limit.
    expect(Date.now() - started).toBeLessThan(2000);
    expect(r.body.mission_status).toBe("terminated");
    expect(r.body.token_residual).toMatchObject({
      revocation_attempted: 1,
      revocation_confirmed: 0,
      complete: false,
    });
    // The attempt in flight ends at its own limit, unconfirmed.
    await w.ps.revocations?.runDue();
    expect(w.durable.revocations(s256)[0]).toMatchObject({
      state: "pending",
      lastOutcome: "revocation_unavailable",
    });
  });

  it("never reports complete where an untracked access mode may serve the mission", async () => {
    await boot({
      config: (doc) => {
        (doc.management as Record<string, unknown>).untracked_access = true;
      },
    });
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    const r = await control(w, assistant, s256, terminateBody());
    expect(r.body.token_residual).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 1,
      complete: false,
    });
  });
});

describe("restart recovery", () => {
  it("keeps terminal state, receipts and pending revocations across a restart, and resumes the work", async () => {
    await boot();
    const { s256, person, auth } = await missionWithTokens();
    await w.rs.down();
    const body = terminateBody("revoked", { purpose: "stop" });
    const first = await control(w, assistant, s256, body);
    const latest = Math.max(claims(person).exp as number, claims(auth).exp as number);
    expect(first.body.token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 0,
      residual_until: rfc3339(latest),
      complete: false,
    });

    // The new process runs revocation work on its own interval.
    await w.restart({ pollIntervalMs: 20 });
    await w.rs.up();

    const status = await control(w, assistant, s256, { action: "status" });
    expect(status.body).toMatchObject({
      mission_status: "terminated",
      terminated_at: first.body.terminated_at,
      termination_reason: "revoked",
      token_residual: { revocation_attempted: 2, revocation_confirmed: 0, complete: false },
    });
    const pt = await requestPersonToken(w, assistant, { resource: RS, mission_s256: s256 });
    expect([pt.status, pt.body.error]).toEqual([403, "mission_terminated"]);
    const replay = await control(w, assistant, s256, body);
    expect(replay.body.terminated_at).toBe(first.body.terminated_at);
    expect(w.durable.missionLog(s256).filter((e) => e.event === "terminated")).toHaveLength(1);
    expect(w.durable.missionLog(s256).at(-1)?.event).toBe("terminate_replayed");
    expect(w.rs.requests).toBe(0);

    // Due after the backoff: the restarted PS's own loop resumes it.
    w.clock.advance(30);
    await vi.waitFor(() => expect(w.rs.revoked).toHaveLength(2), { timeout: 3000 });
    await vi.waitFor(() =>
      expect(w.durable.revocations(s256).map((r) => r.state)).toEqual(["confirmed", "confirmed"]),
    );
    expect(await residualOf(s256)).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 2,
      complete: true,
    });
    expect(w.durable.findOwnedMission(ASSISTANT, s256)?.state).toBe("terminated");
  });

  it("sends nothing for a pending revocation whose attempts already reach the bound when the PS restarts", async () => {
    await boot();
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.rs.mode = "unavailable";
    await control(w, assistant, s256, terminateBody());
    const row = w.durable.revocations(s256)[0] as RevocationRecord;
    // What a crash leaves at the last permitted attempt: recorded, never answered.
    w.durable.updateRevocation({ ...row, attempts: 4, state: "pending", nextAt: w.clock.s });
    const before = w.rs.requests;
    await w.restart();
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(before);
    expect(w.durable.revocations(s256)[0]).toMatchObject({ attempts: 4, state: "exhausted" });
  });

  it("sends nothing more after a final attempt cut short by a restart: the credential stays unconfirmed, exhausted at the bound", async () => {
    await boot();
    const { s256 } = await approve(w, assistant, { description: "Summarize", resources: [RS] });
    w.rs.mode = "unavailable";
    await control(w, assistant, s256, terminateBody());
    // The second and third attempts fail too, after backoffs of 30 and 60 seconds.
    for (const wait of [30, 60]) {
      w.clock.advance(wait);
      await w.ps.revocations?.runDue();
    }
    expect(w.rs.requests).toBe(3);
    expect(w.durable.revocations(s256)[0]).toMatchObject({ state: "pending", attempts: 3 });
    // The fourth and last attempt is recorded and sent; the PS restarts
    // before the recipient answers.
    w.rs.mode = "hang";
    let restarted: Promise<void> | undefined;
    w.rs.onRequest = () => {
      restarted ??= w.restart();
    };
    w.clock.advance(120);
    void w.ps.revocations?.runDue();
    await vi.waitFor(() => expect(restarted).toBeDefined());
    await restarted;
    expect(w.rs.requests).toBe(4);
    expect(w.durable.revocations(s256)[0]).toMatchObject({ state: "pending", attempts: 4 });

    // Its outcome is unknown: the restarted PS sends nothing more, and the
    // credential stays unconfirmed until its exp.
    w.rs.mode = "ok";
    w.clock.advance(120);
    await w.ps.revocations?.runDue();
    expect(w.rs.requests).toBe(4);
    expect(w.rs.revoked).toEqual([]);
    expect(w.durable.revocations(s256)[0]).toMatchObject({
      state: "exhausted",
      attempts: 4,
      lastOutcome: "interrupted",
    });
    expect(events(s256, "revocation_result").at(-1)?.detail).toMatchObject({
      attempt: 4,
      outcome: "interrupted",
      state: "exhausted",
    });
    expect(await residualOf(s256)).toMatchObject({
      tracked: 1,
      revocation_confirmed: 0,
      complete: false,
    });
  });
});
