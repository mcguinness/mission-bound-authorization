/**
 * @spec mission#approval-event (step 7) (#916, D415) — the approval decision's
 * order of writes, over HTTP. The approval is prepared first (every refusal
 * before any write), the provider grant is saved under an identity derived
 * from the interaction, and the record then commits already bound to it. So:
 *
 * - a repeated or concurrent decision on one interaction recovers its one
 *   grant and binding, and can never rebind the Mission and strand the first
 *   approval grant outside the derivation count;
 * - a failure before the record commit leaves no Mission, only an inert grant
 *   that a retry overwrites;
 * - a failure after the commit leaves an `active`, bound Mission whose code is
 *   not issued yet, which a retry on the interaction completes. That window,
 *   full record/code atomicity, stays #250's.
 */
import { createHash } from "node:crypto";
import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import type { AuthoritySourceResolver } from "../src/kernel/authority-source.js";
import { IntentError } from "../src/kernel/intent.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14794;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "approval-grant-binding-verifier-0123456789-0123456789";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

const newKeys = async (): Promise<Keys> => (await generateKeyPair("ES256", { extractable: true })) as Keys;

const clientAssertion = () =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);

async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(keys.privateKey),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/** An open interaction: PAR and the authorization request, with its decide and resume steps. */
async function open(intentOver: Json = {}) {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP, ...intentOver },
      }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as Json;
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  const res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  /**
   * The page rendered to Bob deciding for Alice, rendered once (#1446): every
   * repeated, concurrent or retried decision of his submits that one form.
   */
  let bobsRendering: Promise<string> | undefined;
  /**
   * A decision on this interaction: Bob for Alice unless another approval is
   * given. Another approval renders its own page first; where the surface
   * renders none for it, its decision is posted without one.
   */
  const decide = async (approval?: Record<string, string>) => {
    const headers = approval ?? trustedApprovalHeaders();
    const render_revision = approval
      ? await renderedRevision(ISSUER, uid, { ...headers, cookie: cookie() }).catch(() => undefined)
      : await (bobsRendering ??= renderedRevision(ISSUER, uid, { ...headers, cookie: cookie() }));
    const r = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...headers, "content-type": "application/json", cookie: cookie() },
      body: JSON.stringify({ decision: "approve", render_revision }),
    });
    keep(r);
    return r;
  };
  /** Follow a decision's redirect to the client's redirect URI: its code. */
  const finish = async (decided: Response) => {
    let location = decided.headers.get("location") ?? "";
    while (location.startsWith(ISSUER)) {
      const r = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
      keep(r);
      location = r.headers.get("location") ?? "";
    }
    return new URL(location).searchParams.get("code") as string;
  };
  /** Follow a decision's redirect to the client's redirect URI: its error, if any. */
  const errorOf = async (decided: Response) => {
    let location = decided.headers.get("location") ?? "";
    while (location.startsWith(ISSUER)) {
      const r = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
      keep(r);
      location = r.headers.get("location") ?? "";
    }
    return new URL(location).searchParams.get("error");
  };
  /** Redeem a code: the Mission and its refresh token. */
  const redeem = async (code: string) => {
    const keys = await newKeys();
    const exchanged = await token(
      { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
      keys,
    );
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
    const claims = JSON.parse(
      Buffer.from((exchanged.body.access_token as string).split(".")[1] as string, "base64url").toString(),
    ) as { mission: { id: string } };
    return { missionId: claims.mission.id, refreshToken: exchanged.body.refresh_token as string, keys };
  };
  return { uid, approvalEventId: `apev_${uid}`, decide, finish, errorOf, redeem };
}

/** The grant identity the approval decision derives from the interaction. */
const grantIdFor = (uid: string) => createHash("sha256").update(`mission-approval-grant:${uid}`).digest("base64url");

const boundGrantsOf = (missionId: string) =>
  (
    as.kernel.missionBoundGrants.db
      .prepare("SELECT grant_id FROM mission_bound_grants WHERE mission_id = ?")
      .all(missionId) as Array<{ grant_id: string }>
  ).map((r) => r.grant_id);

const until = async (done: () => boolean) => {
  for (let i = 0; i < 400 && !done(); i++) await new Promise((r) => setTimeout(r, 5));
  expect(done()).toBe(true);
};

describe("the approval decision's order of writes (@spec mission#approval-event, #916, D415)", () => {
  it("an overlapping approval retry cannot bypass the derivation limit: the binding never moves, and the first approval grant keeps counting", async () => {
    const flow = await open({ requested_derivation_limit: 1 });
    // The commits on one approval event run one at a time (#1446), so the
    // overlapping retry recovers the first decision's commit. Hold it at its
    // grant save until the first decision has been redeemed and refused at the
    // limit.
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const save = as.provider.Grant.prototype.save;
    let saves = 0;
    vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: object, ...args: unknown[]) {
      saves += 1;
      if (saves === 2) await gate;
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    const first = await flow.decide();
    expect(first.status).toBe(303);
    const held = flow.decide();
    await until(() => saves >= 2);
    const { missionId, refreshToken, keys } = await flow.redeem(await flow.finish(first));
    expect(as.kernel.get(missionId)?.derivation_count).toBe(1);
    const refused = await token({ grant_type: "refresh_token", refresh_token: refreshToken }, keys);
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.mission_error).toBe("derivations_exhausted");
    const bound = as.kernel.get(missionId)?.grant_id;
    expect(bound).toBe(grantIdFor(flow.uid));

    release();
    await held;
    // The late decision named the same grant and the same approval event: the
    // binding did not move, and the refresh token is still refused at the limit.
    expect(as.kernel.get(missionId)?.grant_id).toBe(bound);
    expect(boundGrantsOf(missionId)).toEqual([bound]);
    const again = await token({ grant_type: "refresh_token", refresh_token: refreshToken }, keys);
    expect(again.status, JSON.stringify(again.body)).toBe(400);
    expect(again.body.mission_error).toBe("derivations_exhausted");
    expect(as.kernel.get(missionId)?.derivation_count).toBe(1);
  });

  it("concurrent duplicate decisions on one interaction commit one Mission, one grant identity and one binding", async () => {
    const flow = await open();
    const saved = new Set<string>();
    const save = as.provider.Grant.prototype.save;
    vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: { jti?: string }, ...args: unknown[]) {
      saved.add(this.jti as string);
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    const [a, b] = await Promise.all([flow.decide(), flow.decide()]);
    expect([a.status, b.status]).toContain(303);
    const record = as.kernel.findByApprovalEvent(flow.approvalEventId);
    expect(record?.state).toBe("active");
    expect(record?.version).toBe(1);
    expect([...saved]).toEqual([grantIdFor(flow.uid)]);
    expect(record?.grant_id).toBe(grantIdFor(flow.uid));
    expect(boundGrantsOf(record?.id as string)).toEqual([grantIdFor(flow.uid)]);
    // The one grant carries the committed decision: Bob's account and the
    // record's authority, whichever decision wrote it last.
    const grant = (await as.provider.Grant.find(grantIdFor(flow.uid))) as unknown as { accountId?: string; rar?: unknown };
    expect(grant.accountId).toBe("bob");
    expect(grant.rar).toEqual(record?.authority_set);
  });

  it("a retry by another Approver, or selecting another Subject, is refused before the grant is touched, and the committed decision's own retry still completes", async () => {
    const flow = await open();
    const first = await flow.decide();
    expect(first.status).toBe(303);
    const grantId = grantIdFor(flow.uid);
    const record = as.kernel.findByApprovalEvent(flow.approvalEventId);
    expect(record?.grant_id).toBe(grantId);
    // Alice approving for herself, and Bob selecting another Subject, are not
    // this committed decision.
    const otherApprover = await flow.decide(trustedApprovalHeaders("alice", {}, null));
    expect(otherApprover.status).toBe(403);
    expect(((await otherApprover.json()) as { error?: string }).error).toBe("approval_forbidden");
    const otherSubject = await flow.decide(trustedApprovalHeaders("bob", {}, "acme-accounts-payable"));
    expect(otherSubject.status).toBe(403);
    const grant = (await as.provider.Grant.find(grantId)) as unknown as { accountId?: string };
    expect(grant.accountId).toBe("bob");
    expect(as.kernel.get(record?.id as string)?.grant_id).toBe(grantId);
    expect(as.kernel.get(record?.id as string)?.subject.sub).toBe("alice");
    const retried = await flow.decide();
    expect(retried.status).toBe(303);
    const { missionId } = await flow.redeem(await flow.finish(retried));
    expect(missionId).toBe(record?.id);
  });

  it("a grant-save failure commits no Mission, and a retry on the interaction recovers one grant and one binding", async () => {
    const flow = await open();
    vi.spyOn(as.provider.Grant.prototype, "save").mockRejectedValueOnce(new Error("injected grant-save failure"));
    const failed = await flow.decide();
    expect(failed.status).toBe(500);
    expect(as.kernel.findByApprovalEvent(flow.approvalEventId)).toBeUndefined();
    vi.restoreAllMocks();
    const retried = await flow.decide();
    expect(retried.status).toBe(303);
    const { missionId } = await flow.redeem(await flow.finish(retried));
    expect(as.kernel.get(missionId)?.grant_id).toBe(grantIdFor(flow.uid));
    expect(boundGrantsOf(missionId)).toEqual([grantIdFor(flow.uid)]);
  });

  it("a commit failure after the grant save leaves only an inert grant, no Mission and no binding, and the retry recovers through that grant", async () => {
    const flow = await open();
    vi.spyOn(as.kernel, "approve").mockImplementationOnce(() => {
      throw new Error("injected record-commit failure");
    });
    const failed = await flow.decide();
    expect(failed.status).toBe(500);
    expect(as.kernel.findByApprovalEvent(flow.approvalEventId)).toBeUndefined();
    const grantId = grantIdFor(flow.uid);
    expect(await as.provider.Grant.find(grantId)).toBeDefined();
    expect(as.kernel.missionBoundGrants.resolve(grantId)).toBeUndefined();
    expect(as.kernel.findByGrant(grantId)).toBeUndefined();
    vi.restoreAllMocks();
    const retried = await flow.decide();
    expect(retried.status).toBe(303);
    const { missionId } = await flow.redeem(await flow.finish(retried));
    expect(as.kernel.get(missionId)?.grant_id).toBe(grantId);
  });

  it("a failure after the record commit leaves an active, bound Mission whose code is not issued yet (the #250 window), which a retry on the interaction completes", async () => {
    const flow = await open();
    vi.spyOn(as.provider, "interactionFinished").mockRejectedValueOnce(new Error("injected failure before code creation"));
    const failed = await flow.decide();
    expect(failed.status).toBe(500);
    const record = as.kernel.findByApprovalEvent(flow.approvalEventId);
    expect(record?.state).toBe("active");
    expect(record?.grant_id).toBe(grantIdFor(flow.uid));
    vi.restoreAllMocks();
    const retried = await flow.decide();
    expect(retried.status).toBe(303);
    const { missionId } = await flow.redeem(await flow.finish(retried));
    expect(missionId).toBe(record?.id);
    expect(boundGrantsOf(missionId)).toEqual([grantIdFor(flow.uid)]);
  });

  it("a Mission's grant binding never moves: bindGrant is idempotent for the grant it holds and refuses any other", async () => {
    const flow = await open();
    const decided = await flow.decide();
    expect(decided.status).toBe(303);
    const record = as.kernel.findByApprovalEvent(flow.approvalEventId);
    const bound = record?.grant_id as string;
    expect(() => as.kernel.bindGrant(record?.id as string, bound)).not.toThrow();
    expect(() => as.kernel.bindGrant(record?.id as string, "another-grant")).toThrow(/a binding never moves/);
    expect(as.kernel.get(record?.id as string)?.grant_id).toBe(bound);
    expect(as.kernel.missionBoundGrants.resolve("another-grant")).toBeUndefined();
  });

  it("the minting paths' first bind adopts the winner: bindFirstGrant binds an unbound Mission once and returns that grant to every later caller", async () => {
    const flow = await open();
    expect((await flow.decide()).status).toBe(303);
    const record = as.kernel.findByApprovalEvent(flow.approvalEventId);
    const id = record?.id as string;
    // A Mission minted outside the approval decision starts unbound.
    as.kernel.db.prepare("UPDATE missions SET grant_id = NULL WHERE id = ?").run(id);
    expect(as.kernel.bindFirstGrant(id, "first-grant")).toBe("first-grant");
    expect(as.kernel.bindFirstGrant(id, "second-grant")).toBe("first-grant");
    expect(as.kernel.get(id)?.grant_id).toBe("first-grant");
    expect(as.kernel.missionBoundGrants.resolve("second-grant")).toBeUndefined();
  });

  it("concurrent decisions by different principals cannot disagree on identity: the first to reserve holds the interaction, the other is refused before saving a grant", async () => {
    const flow = await open();
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const save = as.provider.Grant.prototype.save;
    const accounts: string[] = [];
    vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: { accountId?: string }, ...args: unknown[]) {
      accounts.push(this.accountId as string);
      if (accounts.length === 1) await gate;
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    // Bob's decision for Alice reserves the interaction, then waits at its grant save.
    const bob = flow.decide();
    await until(() => accounts.length >= 1);
    // Alice deciding for herself meanwhile waits for Bob's commit (#1446), and
    // is refused before any grant save.
    const alice = flow.decide(trustedApprovalHeaders("alice", {}, null));
    await new Promise((r) => setTimeout(r, 50));
    expect(accounts).toEqual(["bob"]);
    release();
    const decided = await bob;
    expect(decided.status).toBe(303);
    const refused = await alice;
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { error?: string }).error).toBe("approval_forbidden");
    expect(accounts).toEqual(["bob"]);
    const { missionId } = await flow.redeem(await flow.finish(decided));
    const record = as.kernel.get(missionId);
    expect(record?.approval_basis.consent_principal?.sub).toBe("bob");
    expect(record?.subject.sub).toBe("alice");
    const grant = (await as.provider.Grant.find(record?.grant_id as string)) as unknown as { accountId?: string };
    expect(grant.accountId).toBe("bob");
  });

  it("a reservation outlives a failed commit: a decision by another principal is refused before saving a grant", async () => {
    const flow = await open();
    const save = as.provider.Grant.prototype.save;
    const accounts: string[] = [];
    vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: { accountId?: string }, ...args: unknown[]) {
      accounts.push(this.accountId as string);
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    vi.spyOn(as.kernel, "approve").mockImplementationOnce(() => {
      throw new Error("injected record-commit failure");
    });
    const failed = await flow.decide();
    expect(failed.status).toBe(500);
    expect(as.kernel.findByApprovalEvent(flow.approvalEventId)).toBeUndefined();
    // Bob's reservation stands: Alice deciding for herself is refused before any grant save.
    const alice = await flow.decide(trustedApprovalHeaders("alice", {}, null));
    expect(alice.status).toBe(403);
    const body = (await alice.json()) as { error?: string; error_description?: string };
    expect(body.error).toBe("approval_forbidden");
    expect(body.error_description).toMatch(/reserved/);
    expect(accounts).toEqual(["bob"]);
    expect((await flow.decide()).status).toBe(303);
  });

  it("the commit revalidates the prepared authority source: a source withdrawn during the grant save refuses access_denied and creates no Mission", async () => {
    const flow = await open();
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const save = as.provider.Grant.prototype.save;
    let saves = 0;
    vi.spyOn(as.provider.Grant.prototype, "save").mockImplementation(async function (this: object, ...args: unknown[]) {
      saves += 1;
      if (saves === 1) await gate;
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    const held = flow.decide();
    await until(() => saves >= 1);
    // The source is withdrawn while the grant is being saved: the resolver no
    // longer resolves it for an approval.
    const resolver = (as.kernel as unknown as { sourceResolver: AuthoritySourceResolver }).sourceResolver;
    vi.spyOn(resolver, "resolveForApproval").mockImplementation(() => {
      throw new IntentError("access_denied", "the authority source was withdrawn");
    });
    release();
    const decided = await held;
    expect(decided.status).toBe(303);
    expect(await flow.errorOf(decided)).toBe("access_denied");
    expect(as.kernel.findByApprovalEvent(flow.approvalEventId)).toBeUndefined();
    expect(as.kernel.findByGrant(grantIdFor(flow.uid))).toBeUndefined();
  });
});

describe("the approval event as the idempotency key (@spec mission#mission-record, #1608)", () => {
  /** The Missions recorded for an approval event, read from the store itself. */
  const missionsFor = (approvalEventId: string) =>
    (
      as.kernel.db.prepare("SELECT id FROM missions WHERE approval_event_id = ?").all(approvalEventId) as Array<{
        id: string;
      }>
    ).map((r) => r.id);

  it("a repeated delivery of the same approval decision creates no second Mission: it completes with the committed Mission, the only one for its approval_event_id, at an unchanged version", async () => {
    const flow = await open();
    const first = await flow.decide();
    expect(first.status).toBe(303);
    const committed = as.kernel.findByApprovalEvent(flow.approvalEventId);
    expect(committed?.state).toBe("active");
    expect(missionsFor(flow.approvalEventId)).toEqual([committed?.id]);

    // The same decision delivered again on the interaction (a double-submitted
    // consent form): the same Approver, Subject, client and rendering, so the
    // same approval_event_id.
    const repeated = await flow.decide();
    expect(missionsFor(flow.approvalEventId), "a second Mission was created for the approval event").toEqual([
      committed?.id,
    ]);
    expect(as.kernel.get(committed?.id as string)?.version).toBe(committed?.version);
    expect(repeated.status).toBe(303);
    const { missionId } = await flow.redeem(await flow.finish(repeated));
    expect(missionId).toBe(committed?.id);
  });
});
