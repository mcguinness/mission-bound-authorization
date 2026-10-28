/**
 * Status, termination and revocation end to end (#836 slice 3), through
 * the real agent client, the PS with its mission control plane (AAuth
 * Mission Management) and the Resource with its revocation endpoint
 * (AAuth -11 Section 11.12): termination with live tokens and their
 * revocation, revocation while the Resource is unavailable, a restart of
 * the PS mid-revocation and of the Resource after it, local gating of new
 * issuance from the termination commit on, P2 at
 * `mission_control_endpoint`, and idempotent and concurrent terminates.
 *
 * Every refusal asserts its exact status and code, that the PS issued and
 * recorded nothing for it, and that the Resource ran nothing. Callers use
 * the testkit's management client: the owning agent signs with its agent
 * token, an administrator with the key the world enrolled for it.
 */
import { createHash } from "node:crypto";
import { parsePsConfig, rfc3339, SCHEDULER } from "@mission/aauth-ps";
import {
  type AgentClient,
  createIssuerStub,
  decodeClaims,
  ManagementClient,
  type ManagementResult,
  newRequestId,
  parseRequirement,
} from "@mission/aauth-testkit";
import { generateSigningKey, JwksResolver } from "@mission/aauth-wire";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ADMIN,
  expectRefused,
  observable,
  PS,
  type PsRecords,
  RESOURCE,
  refusal,
  trail,
  type World,
  world,
} from "./world.js";

let w: World;
beforeEach(async () => {
  w = await world();
});
afterEach(async () => {
  vi.restoreAllMocks();
  await w.close();
});

/** A well-formed `mission_s256` that names no mission. */
const ABSENT = createHash("sha256")
  .update("no mission was approved with this blob")
  .digest("base64url");

/** A second Resource, with metadata and keys but no revocation endpoint. */
const ARCHIVE = "https://archive.test";

const DOCS = `${RESOURCE}/api/documents`;

/** No issuance, no record and no effect since `before` and `effects` were taken. */
function nothingHappened(before: PsRecords, effects: number): void {
  expect(w.records()).toEqual(before);
  expect(w.resource.effects).toHaveLength(effects);
}

/** The mission's log events, in order. */
const events = (s256: string) => w.store.missionLog(s256).map((e) => e.event);

/** What the Resource's revoked set holds, as `{iss, jti, exp}`. */
const revokedAtResource = () =>
  w.resource.revocations.entries().map(({ iss, jti, exp }) => ({ iss, jti, exp }));

/** The PS's revocation work for the mission, by token. */
const revocationStates = (s256: string) =>
  Object.fromEntries(w.store.inner.revocations(s256).map((r) => [r.jti, r.state]));

/** `{jti, exp}` of a token, as a revocation names it. */
const pair = (token: string) => {
  const c = decodeClaims(token);
  return { iss: c.iss, jti: c.jti, exp: c.exp };
};

/** A governed agent with a mission, a person token and an auth token from one honest call. */
async function liveTokens() {
  const agent = await w.agent();
  const s256 = await w.approve(agent);
  const ok = await agent.call(RESOURCE, "/api/documents");
  expect(ok.status).toBe(200);
  const person = agent.personToken(RESOURCE) as string;
  const auth = agent.authToken(RESOURCE) as string;
  expect(decodeClaims(person).mission_s256).toBe(s256);
  expect(decodeClaims(auth).mission_s256).toBe(s256);
  return { agent, s256, person, auth };
}

/** The approved blob's lifecycle members, as status reports them. */
function approvedTimes(agent: AgentClient): { approved_at: unknown; expires_at: unknown } {
  const bytes = agent.mission?.blob;
  if (!bytes) throw new Error("the agent holds no approved blob");
  const blob = JSON.parse(bytes.toString("utf8"));
  return { approved_at: blob.approved_at, expires_at: blob.expires_at };
}

/** A presented token refused at the Resource with revoked_jwt (AAuth -11 Section 11.12.5). */
async function expectRevokedAtResource(agent: AgentClient, token: string, requirement?: string) {
  const res = await agent.send(DOCS, { token });
  expect(res.status).toBe(401);
  expect(res.headers["signature-error"]).toBe("error=revoked_jwt");
  expect(res.json()).toMatchObject({ error: "revoked_jwt" });
  if (requirement === undefined) {
    expect(res.headers["aauth-requirement"]).toBeUndefined();
  } else {
    expect(typeof res.headers["aauth-requirement"]).toBe("string");
    const field = parseRequirement(res.headers["aauth-requirement"] as string);
    expect(field.requirement).toBe(requirement);
    expect(field.params.get("resource-token")).toBeUndefined();
  }
}

/** A control-plane refusal: exactly `status` and `error`, and no lifecycle member. */
function expectControlRefused(r: ManagementResult, status: number, error: string): void {
  expect(r.status, r.text).toBe(status);
  expect(r.headers["cache-control"]).toBe("no-store");
  expect(r.body).toMatchObject({ error });
  expect(r.body).not.toHaveProperty("mission_status");
  expect(r.body).not.toHaveProperty("terminated_at");
}

describe("termination through the control plane, with revocation at the Resource (@spec mission-aauth-management#terminate, aauth#section-11.12)", () => {
  it("terminate with a live person token and auth token: the PS commits, revokes both at the Resource, which refuses them, and the agent's next request is refused at the PS", async () => {
    const { agent, s256, person, auth } = await liveTokens();
    const owner = w.manager(agent);

    const committed = w.seconds();
    const ended = await owner.terminate(s256, { reason: "revoked" });

    // 200 with the full status representation, whose token_residual is the
    // revocation summary: here both revocations were confirmed in the wait.
    expect(ended.status).toBe(200);
    const receipt = ended.body as Record<string, unknown>;
    expect(receipt).toEqual({
      mission_s256: s256,
      mission_status: "terminated",
      ...approvedTimes(agent),
      terminated_at: rfc3339(committed),
      termination_reason: "revoked",
      observed_at: expect.any(String),
      fresh_until: expect.any(String),
      accepted_updates: 0,
      token_residual: {
        tracked: 2,
        revocation_attempted: 2,
        revocation_confirmed: 2,
        complete: true,
      },
    });
    const observed = Date.parse(receipt.observed_at as string) / 1000;
    expect(observed).toBeGreaterThanOrEqual(committed);
    expect(receipt.fresh_until).toBe(rfc3339(observed + 30));
    // The PS signed one revocation per Tracked Credential at the Resource in
    // its aud; the Resource verified the PS and holds each {jti, exp} under
    // the PS's identity until the token's own exp.
    expect(w.revocationSwitch.attempts.map((a) => a.mode)).toEqual(["available", "available"]);
    expect(revokedAtResource()).toEqual(expect.arrayContaining([pair(person), pair(auth)]));
    expect(revokedAtResource()).toHaveLength(2);
    // Each attempt and its result is in the mission log, the token named by (iss, jti).
    const results = w.store
      .missionLog(s256)
      .filter((e) => e.event === "revocation_result")
      .map((e) => e.detail);
    expect(results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          token: { iss: PS, jti: decodeClaims(person).jti },
          kind: "person",
          recipient: RESOURCE,
          endpoint: `${RESOURCE}/revoke`,
          outcome: "revoked",
          state: "confirmed",
          status: 200,
        }),
        expect.objectContaining({
          token: { iss: PS, jti: decodeClaims(auth).jti },
          kind: "auth",
          recipient: RESOURCE,
          outcome: "revoked",
          state: "confirmed",
          status: 200,
        }),
      ]),
    );
    expect(events(s256).slice(0, 4)).toEqual([
      "approved",
      "person_token_issued",
      "auth_token_issued",
      "terminated",
    ]);

    // The Resource refuses both tokens: revoked_jwt, the auth token sent back for a person token.
    const effects = w.resource.effects.length;
    const resourceTokens = w.resource.issuedResourceTokens.length;
    await expectRevokedAtResource(agent, auth, "person-token");
    await expectRevokedAtResource(agent, person);
    expect(w.resource.effects).toHaveLength(effects);
    expect(w.resource.issuedResourceTokens).toHaveLength(resourceTokens);

    // The agent's next request follows the requirement to the PS, which refuses it.
    const before = w.records();
    const sent = agent.sent.length;
    const err = await refusal(agent.call(RESOURCE, "/api/documents"));
    expectRefused(err, 403, "mission_terminated");
    expect(err.response?.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "revoked",
    });
    expect(trail(agent).slice(sent)).toEqual([
      `GET ${DOCS} aa-auth+jwt 401`,
      `POST ${PS}/person aa-agent+jwt 403`,
    ]);
    nothingHappened(before, effects);

    // status: terminated with its reason and time, and a complete residual.
    const status = await owner.status(s256);
    const at = w.seconds();
    expect(status.status).toBe(200);
    // No shared cache may keep a status or terminate response.
    expect(status.headers["cache-control"]).toBe("no-store");
    expect(ended.headers["cache-control"]).toBe("no-store");
    expect(status.body).toEqual({
      mission_s256: s256,
      mission_status: "terminated",
      ...approvedTimes(agent),
      terminated_at: (ended.body as Record<string, unknown>).terminated_at,
      termination_reason: "revoked",
      observed_at: rfc3339(at),
      fresh_until: rfc3339(at + 30),
      accepted_updates: 0,
      token_residual: {
        tracked: 2,
        revocation_attempted: 2,
        revocation_confirmed: 2,
        complete: true,
      },
    });
  });

  it("expiry: past expires_at the PS commits terminated, reason expired, attributed to its scheduler; the agent's request is refused mission_terminated and status reports it", async () => {
    const agent = await w.agent();
    const expiresAt = w.seconds() + 120;
    const s256 = await w.approve(agent, {
      description: "Summarize the quarterly report",
      expires_at: rfc3339(expiresAt),
    });
    const person = await agent.requestPersonToken(RESOURCE);
    expect(decodeClaims(person).exp).toBe(expiresAt);
    w.clock.advance(150_000);
    const issued = w.store.issuedTokens();

    const err = await refusal(agent.requestPersonToken(RESOURCE));

    expectRefused(err, 403, "mission_terminated");
    expect(err.response?.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "expired",
    });
    expect(w.store.issuedTokens()).toEqual(issued);
    // The transition is committed at expires_at, attributed to the PS scheduler.
    expect(w.store.missionLog(s256).filter((e) => e.event === "terminated")).toEqual([
      {
        s256,
        at: expiresAt,
        event: "terminated",
        detail: { reason: "expired", actor: SCHEDULER, decision: "permit", policy: "expires_at" },
      },
    ]);
    // status reports it as terminated, with no separate status value.
    const status = await w.manager(agent).status(s256);
    expect(status.body).toMatchObject({
      mission_status: "terminated",
      terminated_at: rfc3339(expiresAt),
      termination_reason: "expired",
      token_residual: {
        tracked: 1,
        revocation_attempted: 0,
        revocation_confirmed: 0,
        complete: true,
      },
    });
  });
});

describe("unavailable revocation (@spec mission-aauth-management#residuals, aauth#section-11.12.3)", () => {
  it("unavailable revocation: while the endpoint answers 5xx, drops the connection or answers a malformed 200, the person token stays unconfirmed and complete false, and when it returns the retry confirms it", async () => {
    const agent = await w.agent();
    const s256 = await w.approve(agent);
    const person = await agent.requestPersonToken(RESOURCE);
    const exp = decodeClaims(person).exp as number;
    w.revocationSwitch.mode = "error";

    const ended = await w.manager(agent).terminate(s256, { reason: "revoked" });

    expect(ended.status).toBe(200);
    expect((ended.body as Record<string, unknown>).token_residual).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 0,
      residual_until: rfc3339(exp),
      complete: false,
    });
    expect(revokedAtResource()).toEqual([]);
    // The residual is real: the Resource still honors the unrevoked person
    // token, while the PS's own gate refuses the mission.
    const challenge = await agent.send(DOCS, { token: person });
    expect(challenge.status).toBe(401);
    expect(parseRequirement(challenge.headers["aauth-requirement"] as string).requirement).toBe(
      "auth-token",
    );
    const before = w.records();
    const effects = w.resource.effects.length;
    expectRefused(await refusal(agent.call(RESOURCE, "/api/documents")), 403, "mission_terminated");
    nothingHappened(before, effects);

    // The next attempts, each after its backoff, meet a dropped connection
    // and then a malformed 200: still unconfirmed.
    const admin = w.manager(w.admins.alice);
    for (const [mode, backoff] of [
      ["reset", 30_000],
      ["malformed", 60_000],
    ] as const) {
      w.revocationSwitch.mode = mode;
      w.clock.advance(backoff);
      await w.ps.revocations?.runDue();
      expect(((await admin.status(s256)).body as Record<string, unknown>).token_residual).toEqual({
        tracked: 1,
        revocation_attempted: 1,
        revocation_confirmed: 0,
        residual_until: rfc3339(exp),
        complete: false,
      });
    }
    expect(w.revocationSwitch.attempts.map((a) => a.mode)).toEqual(["error", "reset", "malformed"]);
    expect(revokedAtResource()).toEqual([]);

    // The endpoint returns: the next due retry confirms the person token.
    w.revocationSwitch.mode = "available";
    w.clock.advance(120_000);
    await w.ps.revocations?.runDue();
    expect(revokedAtResource()).toEqual([pair(person)]);
    expect(((await admin.status(s256)).body as Record<string, unknown>).token_residual).toEqual({
      tracked: 1,
      revocation_attempted: 1,
      revocation_confirmed: 1,
      complete: true,
    });
    await expectRevokedAtResource(agent, person);
  });

  it("unavailable revocation: while the network refuses the Resource nothing is confirmed and residual_until is the latest unconfirmed exp, the person token's; once reachable, the retry confirms what is unexpired", async () => {
    // Auth tokens live shorter than person tokens here, so the two exps differ.
    const doc = w.psConfigDoc();
    (doc.lifetimes as Record<string, number>).auth_token_seconds = 600;
    await w.restartPs(parsePsConfig(doc));
    const { agent, s256, person, auth } = await liveTokens();
    const personExp = decodeClaims(person).exp as number;
    const authExp = decodeClaims(auth).exp as number;
    expect(authExp).toBeLessThan(personExp);
    await w.net.refuse(RESOURCE);

    const ended = await w.manager(agent).terminate(s256, { reason: "revoked" });

    expect((ended.body as Record<string, unknown>).token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 0,
      residual_until: rfc3339(personExp),
      complete: false,
    });
    expect(
      w.store
        .missionLog(s256)
        .filter((e) => e.event === "revocation_result")
        .map((e) => [e.detail.outcome, e.detail.state]),
    ).toEqual([
      ["revocation_unavailable", "pending"],
      ["revocation_unavailable", "pending"],
    ]);
    expect(w.revocationSwitch.attempts).toEqual([]);

    // Past the auth token's exp, the unconfirmed person token alone keeps the residual open.
    w.clock.advance((authExp - w.seconds()) * 1000);
    const admin = w.manager(w.admins.alice);
    expect(((await admin.status(s256)).body as Record<string, unknown>).token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 0,
      residual_until: rfc3339(personExp),
      complete: false,
    });

    // Reachable again: the retry revokes the person token, and the expired
    // auth token is not attempted again; its own expiry closed its residual.
    w.net.restore(RESOURCE);
    await w.ps.revocations?.runDue();
    expect(revokedAtResource()).toEqual([pair(person)]);
    expect(revocationStates(s256)).toEqual({
      [decodeClaims(person).jti as string]: "confirmed",
      [decodeClaims(auth).jti as string]: "pending",
    });
    expect(((await admin.status(s256)).body as Record<string, unknown>).token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 1,
      complete: true,
    });
  });

  it("a person token at a Resource that advertises no revocation endpoint keeps complete false until its exp, though every other token is confirmed (D299)", async () => {
    const archive = createIssuerStub({ issuer: ARCHIVE, dwk: "aauth-resource.json" });
    await w.net.serve(ARCHIVE, archive.handler);
    const { agent, s256, person, auth } = await liveTokens();
    const elsewhere = await agent.requestPersonToken(ARCHIVE);
    const exp = decodeClaims(elsewhere).exp as number;

    const ended = await w.manager(agent).terminate(s256, { reason: "revoked" });

    expect((ended.body as Record<string, unknown>).token_residual).toEqual({
      tracked: 3,
      revocation_attempted: 3,
      revocation_confirmed: 2,
      residual_until: rfc3339(exp),
      complete: false,
    });
    expect(revokedAtResource()).toEqual(expect.arrayContaining([pair(person), pair(auth)]));
    expect(revocationStates(s256)[decodeClaims(elsewhere).jti as string]).toBe("unsupported");

    // Natural expiry closes the residual; status still reports the termination.
    w.clock.advance((exp - w.seconds()) * 1000);
    const status = await w.manager(w.admins.alice).status(s256);
    expect(status.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "revoked",
      token_residual: {
        tracked: 3,
        revocation_attempted: 3,
        revocation_confirmed: 2,
        complete: true,
      },
    });
    expect((status.body as Record<string, unknown>).token_residual).not.toHaveProperty(
      "residual_until",
    );
  });
});

describe("restart mid-revocation (@spec mission-aauth-management#races-and-failures)", () => {
  it("a restart mid-revocation: terminal state, gating and receipts hold, the restarted PS's own loop revokes both tokens, and a restarted Resource keeps its revoked set", async () => {
    const { agent, s256, person, auth } = await liveTokens();
    const owner = w.manager(agent);
    const admin = w.manager(w.admins.alice);
    w.revocationSwitch.mode = "error";
    const request = { reason: "revoked", requestId: newRequestId(), purpose: "Stop the work" };
    const first = await owner.terminate(s256, request);
    const receipt = first.body as Record<string, unknown>;
    const latest = Math.max(decodeClaims(person).exp as number, decodeClaims(auth).exp as number);
    expect(receipt.token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 0,
      residual_until: rfc3339(latest),
      complete: false,
    });

    // A new PS process on the same store file and signing key, running
    // revocation work on its own interval.
    await w.restartPs(undefined, { pollIntervalMs: 20 });

    const status = await owner.status(s256);
    expect(status.body).toMatchObject({
      mission_status: "terminated",
      terminated_at: receipt.terminated_at,
      termination_reason: "revoked",
      token_residual: {
        tracked: 2,
        revocation_attempted: 2,
        revocation_confirmed: 0,
        complete: false,
      },
    });
    const before = w.records();
    expectRefused(await refusal(agent.requestPersonToken(RESOURCE)), 403, "mission_terminated");
    nothingHappened(before, w.resource.effects.length);
    const attempts = w.revocationSwitch.attempts.length;
    const replay = await owner.terminate(s256, request);
    expect(replay.status).toBe(200);
    for (const member of [
      "mission_s256",
      "mission_status",
      "terminated_at",
      "termination_reason",
    ]) {
      expect((replay.body as Record<string, unknown>)[member]).toBe(receipt[member]);
    }
    expect(events(s256).filter((e) => e === "terminated")).toHaveLength(1);
    expect(events(s256).at(-1)).toBe("terminate_replayed");
    expect(w.revocationSwitch.attempts).toHaveLength(attempts);

    // The endpoint returns; once the backoff passes, the restarted PS's own loop revokes both.
    w.revocationSwitch.mode = "available";
    w.clock.advance(30_000);
    await vi.waitFor(
      () =>
        expect(revocationStates(s256)).toEqual({
          [decodeClaims(person).jti as string]: "confirmed",
          [decodeClaims(auth).jti as string]: "confirmed",
        }),
      // Within the test's own time limit, so a loop that never runs fails here.
      { timeout: 3000, interval: 20 },
    );
    expect(revokedAtResource()).toEqual(expect.arrayContaining([pair(person), pair(auth)]));
    expect(((await admin.status(s256)).body as Record<string, unknown>).token_residual).toEqual({
      tracked: 2,
      revocation_attempted: 2,
      revocation_confirmed: 2,
      complete: true,
    });

    // A restarted Resource still refuses both: its revoked set is durable.
    await w.restartResource();
    expect(revokedAtResource()).toEqual(expect.arrayContaining([pair(person), pair(auth)]));
    await expectRevokedAtResource(agent, auth, "person-token");
    await expectRevokedAtResource(agent, person);
    expect(w.resource.effects).toEqual([]);

    // Past every token's exp, the terminal state and its reason are still reported.
    w.clock.advance((latest - w.seconds() + 1) * 1000);
    const later = await admin.status(s256);
    expect(later.body).toMatchObject({
      mission_status: "terminated",
      terminated_at: receipt.terminated_at,
      termination_reason: "revoked",
      token_residual: { tracked: 2, complete: true },
    });
  });
});

describe("local gating from the termination commit (@spec mission-aauth-management#token-consequences)", () => {
  it("new issuance is refused once termination commits: a person token and an auth token, each mission_terminated, nothing issued", async () => {
    const agent = await w.agent();
    const s256 = await w.approve(agent);
    const admin = w.manager(w.admins.alice);
    let before: PsRecords | undefined;
    let terminated: ManagementResult | undefined;
    agent.misbehavior = {
      // The agent holds a resource token for its person token when an
      // administrator terminates the mission; then it redeems it.
      interceptResourceToken: async (token) => {
        terminated = await admin.terminate(s256, {
          reason: "administrative",
          purpose: "Stop the work",
        });
        before = w.records();
        return token;
      },
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expect(terminated?.status).toBe(200);
    expectRefused(err, 403, "mission_terminated");
    expect(err.response?.body).toMatchObject({
      mission_status: "terminated",
      termination_reason: "administrative",
    });
    nothingHappened(before as PsRecords, 0);
    // The administrator's request is recorded with its principal, role,
    // decision, policy and declared purpose.
    expect(w.store.missionLog(s256).find((e) => e.event === "terminated")?.detail).toMatchObject({
      reason: "administrative",
      actor: { id: ADMIN, role: "administrator" },
      decision: "permit",
      policy: `administrator:${ADMIN}`,
      purpose: "Stop the work",
    });
    agent.misbehavior = {};
    agent.forget(RESOURCE);
    const again = w.records();
    expectRefused(await refusal(agent.requestPersonToken(RESOURCE)), 403, "mission_terminated");
    nothingHappened(again, 0);
  });

  /** Run `effect` once, the next time a key of `issuer` resolves, after it resolves. */
  function duringResolve(issuer: string, effect: () => Promise<void>): void {
    const original = JwksResolver.prototype.resolveKey;
    let fired = false;
    vi.spyOn(JwksResolver.prototype, "resolveKey").mockImplementation(async function (
      this: JwksResolver,
      ...args: Parameters<JwksResolver["resolveKey"]>
    ) {
      const key = await original.apply(this, args);
      if (args[0] === issuer && !fired) {
        fired = true;
        await effect();
      }
      return key;
    });
  }

  it("new issuance is refused once termination commits: a person token request racing termination is refused mission_terminated", async () => {
    const agent = await w.agent();
    const s256 = await w.approve(agent);
    const admin = w.manager(w.admins.alice);
    await admin.controlPlane();
    let terminated: ManagementResult | undefined;
    let before: PsRecords | undefined;
    // The PS resolves the agent provider's key while it authenticates the
    // request; termination commits then, before the mission gate runs.
    duringResolve("https://ap.test", async () => {
      terminated = await admin.terminate(s256, { reason: "administrative", purpose: "Stop" });
      before = w.records();
    });

    const err = await refusal(agent.requestPersonToken(RESOURCE));

    expect(terminated?.status).toBe(200);
    expectRefused(err, 403, "mission_terminated");
    nothingHappened(before as PsRecords, 0);
  });

  it("new issuance is refused once termination commits: an auth token request racing termination is refused mission_terminated", async () => {
    const agent = await w.agent();
    const s256 = await w.approve(agent);
    const admin = w.manager(w.admins.alice);
    await admin.controlPlane();
    let terminated: ManagementResult | undefined;
    let before: PsRecords | undefined;
    agent.misbehavior = {
      // Armed once the agent has checked the challenge: the next resolution
      // of the Resource's key is the PS verifying the resource token, and
      // termination commits then, before the mission gate runs.
      presentedToken: (presented) => {
        duringResolve(RESOURCE, async () => {
          terminated = await admin.terminate(s256, { reason: "administrative", purpose: "Stop" });
          before = w.records();
        });
        return presented;
      },
    };

    const err = await refusal(agent.call(RESOURCE, "/api/documents"));

    expect(terminated?.status).toBe(200);
    expectRefused(err, 403, "mission_terminated");
    expect(err.response?.body).toMatchObject({ termination_reason: "administrative" });
    nothingHappened(before as PsRecords, 0);
    // The person token issued before the commit was revoked at the Resource.
    expect(revokedAtResource()).toEqual([pair(agent.personToken(RESOURCE) as string)]);
  });
});

describe("P2 at mission_control_endpoint: an unauthorized caller learns nothing (@spec mission-aauth-management#errors)", () => {
  /** alice's assistant owns one active and one terminated mission. */
  async function missions() {
    const owner = await w.agent();
    const active = await w.approve(owner, { description: "Plan the offsite" });
    const ended = await w.approve(owner, { description: "Book the venue" });
    expect((await w.manager(owner).terminate(ended, { reason: "revoked" })).status).toBe(200);
    return { owner, active, ended };
  }

  /** Every probe answered exactly as the absent one: status, body bytes and headers. */
  async function expectAlike(probe: (s256: string) => Promise<ManagementResult>, refs: string[]) {
    const absent = await probe(ABSENT);
    expect(absent.status).toBe(404);
    expect(absent.headers["cache-control"]).toBe("no-store");
    expect(JSON.parse(absent.text)).toEqual({
      error: "mission_not_found",
      detail: "no such mission",
    });
    for (const s256 of refs) {
      expect(observable((await probe(s256)).response)).toEqual(observable(absent.response));
    }
  }

  it("P2: a non-owner agent gets the same mission_not_found for another agent's mission, active or terminated, as for an absent one", async () => {
    const { owner, active, ended } = await missions();
    const planner = w.manager(await w.agent("planner"));
    const helper = w.manager(await w.agent("helper"));
    const before = w.records();

    for (const caller of [planner, helper]) {
      await expectAlike((s256) => caller.status(s256), [active, ended]);
      await expectAlike((s256) => caller.terminate(s256, { reason: "revoked" }), [active, ended]);
    }

    nothingHappened(before, 0);
    expect(w.ps.securityEvents.filter((e) => e.type === "control_plane_miss")).toHaveLength(12);
    expect(JSON.stringify(w.ps.securityEvents)).not.toContain(active);
    // The owner still reads its mission as it was.
    expect((await w.manager(owner).status(active)).body).toMatchObject({
      mission_status: "active",
    });
  });

  it("P2: an administrator outside the mission's scope gets the same mission_not_found as for an absent one", async () => {
    const { owner, active, ended } = await missions();
    const outside = w.manager(w.admins.bob);
    const before = w.records();

    await expectAlike((s256) => outside.status(s256), [active, ended]);
    await expectAlike(
      (s256) => outside.terminate(s256, { reason: "administrative", purpose: "Probe" }),
      [active, ended],
    );

    nothingHappened(before, 0);
    expect((await w.manager(owner).status(active)).body).toMatchObject({
      mission_status: "active",
    });
  });
});

describe("authentication before anything else (@spec mission-aauth-management#authorization)", () => {
  it("an unauthenticated control-plane request is refused 401 before any disclosure or change: unsigned, and signed by a key no administrator enrolled", async () => {
    const agent = await w.agent();
    const s256 = await w.approve(agent);
    const { endpoint } = await w.manager(agent).controlPlane();
    const unsigned = (reference: string, body: Record<string, unknown>) =>
      w.net.request({
        method: "POST",
        url: `${endpoint}/${reference}`,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    const impostor = ManagementClient.forAdministrator({
      transport: w.net,
      ps: PS,
      key: generateSigningKey("Ed25519", "admin-1"),
      signatureKey: { scheme: "jwks_uri", id: ADMIN, dwk: "mission-admin.json", kid: "admin-1" },
      now: w.clock.now,
      sleep: w.clock.sleep,
    });
    const before = w.records();

    const status = { action: "status" };
    const terminate = { action: "terminate", reason: "revoked", request_id: newRequestId() };
    const unsignedStatus = await unsigned(s256, status);
    const answers = [
      unsignedStatus,
      await unsigned(s256, terminate),
      (await impostor.status(s256)).response,
      (await impostor.terminate(s256, { reason: "administrative", purpose: "Probe" })).response,
    ];

    for (const res of answers) {
      expect(res.status).toBe(401);
      expect(res.headers["signature-error"]).toBeDefined();
      expect(res.headers["cache-control"]).toBe("no-store");
      const body = res.json() as Record<string, unknown>;
      expect(body.error).not.toBe("mission_not_found");
      for (const member of ["mission_s256", "mission_status", "terminated_at", "token_residual"]) {
        expect(body).not.toHaveProperty(member);
      }
    }
    // Nor does the refusal differ for an absent mission.
    expect(observable(await unsigned(ABSENT, status))).toEqual(observable(unsignedStatus));
    nothingHappened(before, 0);
    expect((await w.manager(agent).status(s256)).body).toMatchObject({ mission_status: "active" });
  });
});

describe("idempotent and concurrent terminate (@spec mission-aauth-management#idempotency)", () => {
  it("idempotent terminate: a repeat replays the committed receipt, with no second event and no second revocation, a day later included", async () => {
    const { s256 } = await liveTokens();
    const admin = w.manager(w.admins.alice);
    const request = { reason: "administrative", requestId: newRequestId(), purpose: "Stop" };
    const first = await admin.terminate(s256, request);
    const receipt = first.body as Record<string, unknown>;
    const revocations = w.store.inner.revocations(s256);
    const attempts = w.revocationSwitch.attempts.length;
    expect(attempts).toBe(2);

    // Five seconds later, and again 24 hours after the first request.
    for (const wait of [5000, 24 * 3600 * 1000]) {
      w.clock.advance(wait);
      const replay = await admin.terminate(s256, request);

      expect(replay.status).toBe(200);
      const again = replay.body as Record<string, unknown>;
      for (const member of [
        "mission_s256",
        "mission_status",
        "terminated_at",
        "termination_reason",
      ]) {
        expect(again[member]).toBe(receipt[member]);
      }
      // The rest is observed at the replay.
      expect(again.observed_at).toBe(rfc3339(w.seconds()));
      expect(again.observed_at).not.toBe(receipt.observed_at);
      expect(events(s256).filter((e) => e === "terminated")).toHaveLength(1);
      expect(events(s256).at(-1)).toBe("terminate_replayed");
      expect(w.store.inner.revocations(s256)).toEqual(revocations);
      expect(w.revocationSwitch.attempts).toHaveLength(attempts);
    }
  });

  it("idempotent terminate: a request_id reused with a changed request or for another mission is refused 409 idempotency_conflict, and nothing changes", async () => {
    const agent = await w.agent();
    const s256 = await w.approve(agent, { description: "Plan the offsite" });
    const other = await w.approve(agent, { description: "Book the venue" });
    const owner = w.manager(agent);
    const requestId = newRequestId();
    expect((await owner.terminate(s256, { reason: "revoked", requestId })).status).toBe(200);
    const before = w.records();

    const changed = await owner.terminate(s256, { reason: "revoked", requestId, purpose: "Again" });
    const elsewhere = await owner.terminate(other, { reason: "revoked", requestId });

    for (const r of [changed, elsewhere]) expectControlRefused(r, 409, "idempotency_conflict");
    nothingHappened(before, 0);
    expect((await owner.status(other)).body).toMatchObject({ mission_status: "active" });
  });

  it("concurrent terminates make one transition: the owning agent and an administrator race, and both see the one committed outcome", async () => {
    const { agent, s256 } = await liveTokens();

    const [a, b] = await Promise.all([
      w.manager(agent).terminate(s256, { reason: "revoked" }),
      w.manager(w.admins.alice).terminate(s256, { reason: "administrative", purpose: "Race" }),
    ]);

    expect([a.status, b.status]).toEqual([200, 200]);
    const ra = a.body as Record<string, unknown>;
    const rb = b.body as Record<string, unknown>;
    expect(ra.terminated_at).toBe(rb.terminated_at);
    expect(ra.termination_reason).toBe(rb.termination_reason);
    const log = w.store.missionLog(s256);
    const ended = log.filter((e) => e.event === "terminated");
    expect(ended).toHaveLength(1);
    expect(ended[0]?.detail.reason).toBe(ra.termination_reason);
    expect(log.filter((e) => e.event === "termination_request_after_terminal")).toHaveLength(1);
    // One transition, so one revocation per token.
    expect(w.store.inner.revocations(s256)).toHaveLength(2);
    expect(w.revocationSwitch.attempts).toHaveLength(2);
  });
});
