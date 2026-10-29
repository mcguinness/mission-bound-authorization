/**
 * @spec mission#approval-event (step 7) (#1863, D1001): "Create the Mission
 * Record ... in the `active` state atomically with the approval decision and
 * issuance of the authorization code."
 *
 * A direct browser approval is held at the decision and commits when the
 * resume request saves its authorization code (adapters/approval-hold.ts).
 * These are the witnesses over HTTP, on the in-memory kernel and on the
 * file-backed kernel with its recovery witness:
 *
 * - a code-storage failure, a refused commit and a commit whose recovery
 *   witness fails leave no released, redeemable code, and (except the last,
 *   whose state cannot be told) no Mission;
 * - a notification failure after the commit is recovered: the code redeems
 *   under the bound Mission;
 * - the held grant is Mission-bound from its first save and stays so through
 *   refusal, hold expiry and failed cleanup;
 * - a decision racing the resume is ordered against it;
 * - with no failure, the decision commits nothing and the code save commits
 *   the record bound to the grant.
 */
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import MemoryAdapter from "oidc-provider/lib/adapters/memory_adapter.js";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { approvalHoldsOf } from "../src/adapters/approval-hold.js";
import { ORDINARY_REQUEST_REFUSAL } from "../src/adapters/interaction-policy.js";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs, reconcileKernelRecovery } from "../src/index.js";
import type { AuthoritySourceResolver } from "../src/kernel/authority-source.js";
import { IntentError } from "../src/kernel/intent.js";
import type { LifecycleCommit } from "../src/kernel/types.js";
import {
  browserApprovalHeaders,
  floorApprovalHeaders,
  renderedRevision,
  TEST_APPROVAL_PRINCIPALS,
  trustedApprovalHeaders,
} from "./approval-fixture.js";

const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const PLAIN = TOPOLOGY.resources.plainRs;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "approval-code-atomicity-verifier-0123456789-0123456789";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
const SESSIONS = new ApprovalSessionStore();

type Json = Record<string, unknown>;
type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Jar = Map<string, string>;
type Stored = { grantId?: string };

const dirs: string[] = [];
const closers: Array<() => Promise<void> | void> = [];
afterAll(async () => {
  for (const close of closers.reverse()) await close();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.restoreAllMocks();
});

const grantIdFor = (uid: string) => createHash("sha256").update(`mission-approval-grant:${uid}`).digest("base64url");

/** An AS on `port`: in-memory, or on a file-backed kernel store guarded by its recovery witness. */
async function start(port: number, options: { fileBacked?: boolean; onLifecycleCommit?: (c: LifecycleCommit) => void } = {}) {
  const issuer = `http://localhost:${port}`;
  let paths: { store: string; witness: string } | undefined;
  if (options.fileBacked) {
    const root = mkdtempSync(join(tmpdir(), "approval-code-atomicity-"));
    dirs.push(root);
    paths = { store: join(root, "state", "kernel.db"), witness: join(root, "witness", "kernel.witness") };
    mkdirSync(dirname(paths.store), { recursive: true });
    mkdirSync(dirname(paths.witness), { recursive: true });
    reconcileKernelRecovery({ storeFile: paths.store, witnessFile: paths.witness, action: "init" });
  }
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    ...(paths ? { kernelStore: { file: paths.store, witness: paths.witness } } : {}),
    ...(options.onLifecycleCommit ? { onLifecycleCommit: options.onLifecycleCommit } : {}),
  });
  const server: Server = as.provider.listen(port);
  await new Promise<void>((r) => server.once("listening", () => r()));
  closers.push(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    if (paths) as.kernel.close();
  });
  const clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  return harness(issuer, as, clientKey);
}

function harness(issuer: string, as: BuiltAs, clientKey: CryptoKey) {
  const clientAssertion = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(issuer)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);

  async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
    const send = async (extra: Json = {}) =>
      fetch(`${issuer}/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: await new SignJWT({ htu: `${issuer}/token`, htm: "POST", ...extra })
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

  const keep = (jar: Jar, res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

  /**
   * A pushed request: Bob's read of Acme invoices for Alice, Bob's Intent-only
   * payment of them for Alice (high-risk authority, under the approval floor),
   * Alice's Intent-only report read with `openid`, or with no goal an ordinary
   * request.
   */
  async function push(kind: "headless" | "floor" | "browser" | "ordinary"): Promise<string> {
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
    const target = kind === "headless" || kind === "floor" ? RESOURCE : PLAIN;
    const res = await fetch(`${issuer}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: target,
        code_challenge: challenge,
        code_challenge_method: "S256",
        ...(kind === "headless"
          ? {
              mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP } }),
              authorization_details: JSON.stringify(READ),
            }
          : kind === "floor"
            ? { mission_intent: JSON.stringify({ intent: { goal: "Pay the approved Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP } }) }
            : { scope: "openid" }),
        ...(kind === "browser"
          ? { mission_intent: JSON.stringify({ intent: { goal: "Read the quarterly reports", target_resources: [PLAIN], expires_at: FAR_EXP } }) }
          : {}),
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    const body = (await res.json()) as { request_uri?: string };
    expect(res.status, JSON.stringify(body)).toBe(201);
    return body.request_uri as string;
  }

  /** Follow `location` in `jar`'s user agent to the client's redirect: its code or error, or the status of a response that is not a redirect. */
  async function walk(location: string, jar: Jar) {
    let next = location;
    let status = 0;
    for (let hops = 0; hops < 10 && next; hops += 1) {
      const absolute = new URL(next, issuer).toString();
      if (!absolute.startsWith(issuer)) {
        const q = new URL(absolute).searchParams;
        return { status, code: q.get("code"), error: q.get("error"), description: q.get("error_description") };
      }
      const res = await fetch(absolute, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
      keep(jar, res);
      status = res.status;
      next = res.headers.get("location") ?? "";
    }
    return { status, code: null, error: null, description: null };
  }

  /**
   * An approval interaction, decided by Bob for Alice through the trusted
   * approval service, by Bob for Alice in his browser with the suite's `mfa`
   * login (the floor), or by Alice in her browser.
   */
  async function open(kind: "headless" | "floor" | "browser" = "headless") {
    const jar: Jar = new Map();
    const res = await fetch(`${issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: await push(kind) })}`, {
      redirect: "manual",
    });
    keep(jar, res);
    const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
    expect(uid, res.headers.get("location") ?? "").toBeTruthy();
    let rendering: Promise<string> | undefined;
    const approvalHeaders = () =>
      kind === "browser"
        ? browserApprovalHeaders(SESSIONS, uid, { sub: "alice", acr: "mfa" }, cookieOf(jar))
        : kind === "floor"
          ? floorApprovalHeaders(SESSIONS, uid, cookieOf(jar))
          : { ...trustedApprovalHeaders(), cookie: cookieOf(jar) };
    let headers: Record<string, string> | undefined;
    /** A decision on the one rendering: every repeated or concurrent decision submits that form. */
    const decide = async () => {
      headers ??= approvalHeaders();
      const render_revision = await (rendering ??= renderedRevision(issuer, uid, headers));
      const decided = await fetch(`${issuer}/interaction/${uid}/decide`, {
        method: "POST",
        redirect: "manual",
        headers: { ...headers, "content-type": "application/json" },
        body: JSON.stringify({ decision: "approve", render_revision }),
      });
      keep(jar, decided);
      return decided;
    };
    const resume = (decided: Response) => walk(decided.headers.get("location") ?? "", jar);
    const redeem = async (code: string) => {
      const keys = (await generateKeyPair("ES256", { extractable: true })) as Keys;
      return token(
        {
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: VERIFIER,
          resource: kind === "browser" ? PLAIN : RESOURCE,
        },
        keys,
      );
    };
    const missionOf = (body: Json) =>
      (JSON.parse(Buffer.from((body.access_token as string).split(".")[1] as string, "base64url").toString()) as { mission: { id: string } })
        .mission.id;
    return { uid, jar, grantId: grantIdFor(uid), approvalEventId: `apev_${uid}`, decide, resume, redeem, missionOf };
  }

  /** The Missions recorded for an approval event, read from the store itself. */
  const missionsFor = (approvalEventId: string) =>
    (as.kernel.db.prepare("SELECT id FROM missions WHERE approval_event_id = ?").all(approvalEventId) as Array<{ id: string }>).map(
      (r) => r.id,
    );

  return { issuer, as, open, walk, push, missionsFor, cookieOf, keep };
}

/** Record every code id the provider's in-memory code storage is asked to store. */
function stagedCodes(): string[] {
  const ids: string[] = [];
  const upsert = MemoryAdapter.prototype.upsert;
  vi.spyOn(MemoryAdapter.prototype, "upsert").mockImplementation(function (this: { model: string }, ...args: Parameters<typeof upsert>) {
    if (this.model === "AuthorizationCode") ids.push(args[0]);
    return upsert.apply(this as never, args);
  });
  return ids;
}

/** The code storage's deletions fail, so a staged code stays stored. */
function codeDeletionFails(): void {
  const destroy = MemoryAdapter.prototype.destroy;
  vi.spyOn(MemoryAdapter.prototype, "destroy").mockImplementation(function (this: { model: string }, ...args: Parameters<typeof destroy>) {
    if (this.model === "AuthorizationCode") return Promise.reject(new Error("injected code deletion failure"));
    return destroy.apply(this as never, args);
  });
}

/** What the in-memory code storage holds for `id`, read beneath the provider's fence. */
const storedCode = (id: string) => new MemoryAdapter("AuthorizationCode").find(id) as Promise<Stored | undefined>;

/** Nothing usable: no Mission for the event, no binding, no index entry, and the grant still classified. */
function expectNoMission(h: Awaited<ReturnType<typeof start>>, flow: { approvalEventId: string; grantId: string }) {
  expect(h.missionsFor(flow.approvalEventId)).toEqual([]);
  expect(h.as.kernel.findByGrant(flow.grantId)).toBeUndefined();
  expect(h.as.kernel.missionBoundGrants.resolve(flow.grantId)).toBeUndefined();
  expect(h.as.kernel.missionBoundGrants.heldApproval(flow.grantId)).toEqual({ approvalEventId: flow.approvalEventId });
}

describe("the Mission Record commits with its authorization code (@spec mission#approval-event, #1863, D1001)", () => {
  for (const [kernel, port] of [
    ["in-memory", 15601],
    ["file-backed", 15602],
  ] as const) {
    it(`${kernel} kernel: the decision commits nothing; the code save commits the record bound to the grant, and the code redeems under it`, async () => {
      const h = await start(port, { fileBacked: kernel === "file-backed" });
      const flow = await h.open();
      const decided = await flow.decide();
      expect(decided.status).toBe(303);
      expect(h.missionsFor(flow.approvalEventId)).toEqual([]);
      expect(h.as.kernel.findByGrant(flow.grantId)).toBeUndefined();
      expect(h.as.kernel.missionBoundGrants.heldApproval(flow.grantId)).toEqual({ approvalEventId: flow.approvalEventId });
      const out = await flow.resume(decided);
      expect(out.code, JSON.stringify(out)).toBeTruthy();
      const record = h.as.kernel.findByApprovalEvent(flow.approvalEventId);
      expect(record?.state).toBe("active");
      expect(record?.grant_id).toBe(flow.grantId);
      expect(h.as.kernel.missionBoundGrants.resolve(flow.grantId)?.missionId).toBe(record?.id);
      const redeemed = await flow.redeem(out.code as string);
      expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
      expect(flow.missionOf(redeemed.body)).toBe(record?.id);
    });

    it(`${kernel} kernel: a code-storage failure commits nothing: no Mission, no binding, no redeemable code, and the grant stays classified`, async () => {
      const h = await start(port + 10, { fileBacked: kernel === "file-backed" });
      const flow = await h.open();
      const decided = await flow.decide();
      expect(decided.status).toBe(303);
      const writes: string[] = [];
      const upsert = MemoryAdapter.prototype.upsert;
      vi.spyOn(MemoryAdapter.prototype, "upsert").mockImplementation(function (this: { model: string }, ...args: Parameters<typeof upsert>) {
        if (this.model !== "AuthorizationCode") return upsert.apply(this as never, args);
        writes.push(args[0]);
        return Promise.reject(new Error("injected code-storage write failure"));
      });
      const out = await flow.resume(decided);
      expect(out.status).toBe(500);
      expect(out.code).toBeNull();
      expect(writes).toHaveLength(1);
      expect(await storedCode(writes[0] as string)).toBeUndefined();
      expectNoMission(h, flow);
      expect(await h.as.provider.Grant.find(flow.grantId)).toBeUndefined();
    });
  }

  it("a refused commit completes access_denied: an authority source withdrawn after the decision leaves no code, no Mission and a classified grant", async () => {
    const h = await start(15603);
    const flow = await h.open();
    const decided = await flow.decide();
    expect(decided.status).toBe(303);
    const codes = stagedCodes();
    const resolver = (h.as.kernel as unknown as { sourceResolver: AuthoritySourceResolver }).sourceResolver;
    vi.spyOn(resolver, "resolveForApproval").mockImplementation(() => {
      throw new IntentError("access_denied", "the authority source was withdrawn");
    });
    const out = await flow.resume(decided);
    expect(out.error).toBe("access_denied");
    expect(out.code).toBeNull();
    expect(codes).toHaveLength(1);
    expect(await h.as.provider.AuthorizationCode.find(codes[0] as string)).toBeUndefined();
    expectNoMission(h, flow);
    expect(await h.as.provider.Grant.find(flow.grantId)).toBeUndefined();
  });

  it("file-backed kernel: a recovery-witness failure at the commit fails closed: the record's state cannot be told, and the staged code is never released", async () => {
    const h = await start(15604, { fileBacked: true });
    const flow = await h.open();
    const decided = await flow.decide();
    expect(decided.status).toBe(303);
    const codes = stagedCodes();
    codeDeletionFails();
    // The witness write that finalizes the commit fails: SQLite has committed,
    // and the kernel becomes uncertain.
    const guard = h.as.kernel.recovery as unknown as { persist: (record: { intent: number | null }) => void };
    const persist = guard.persist.bind(guard);
    vi.spyOn(guard, "persist").mockImplementation((record) => {
      if (record.intent === null) throw new Error("injected witness finalize failure");
      persist(record);
    });
    const out = await flow.resume(decided);
    expect(out.status).toBe(500);
    expect(out.code).toBeNull();
    expect(h.as.kernel.recoveryUncertainty()).toBeDefined();
    expect(codes).toHaveLength(1);
    // The staged code is still stored (its deletion failed) and is never found.
    expect((await storedCode(codes[0] as string))?.grantId).toBe(flow.grantId);
    expect(await h.as.provider.AuthorizationCode.find(codes[0] as string)).toBeUndefined();
  });

  for (const [kernel, port] of [
    ["in-memory", 15605],
    ["file-backed", 15606],
  ] as const) {
    it(`${kernel} kernel: a notification failure after the commit is recovered: the code redeems under the bound Mission, and the notification is retried`, async () => {
      let failNext = false;
      const h = await start(port, {
        fileBacked: kernel === "file-backed",
        onLifecycleCommit: () => {
          if (!failNext) return;
          failNext = false;
          throw new Error("injected notification failure");
        },
      });
      const flow = await h.open();
      const decided = await flow.decide();
      failNext = true;
      const out = await flow.resume(decided);
      expect(failNext).toBe(false);
      expect(out.code, JSON.stringify(out)).toBeTruthy();
      expect(h.as.kernel.recoveryUncertainty()).toBeUndefined();
      const record = h.as.kernel.findByApprovalEvent(flow.approvalEventId);
      expect(record?.state).toBe("active");
      expect(record?.grant_id).toBe(flow.grantId);
      expect(h.as.kernel.missionBoundGrants.resolve(flow.grantId)?.missionId).toBe(record?.id);
      const redeemed = await flow.redeem(out.code as string);
      expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
      expect(flow.missionOf(redeemed.body)).toBe(record?.id);
      // The creation's event row was durable; the request-path drain published it.
      const event = h.as.kernel.db
        .prepare("SELECT published FROM lifecycle_events WHERE mission_id = ? AND version = 1")
        .get(record?.id) as { published: number } | undefined;
      expect(event?.published).toBe(1);
    });
  }

  for (const [moment, port] of [
    ["before the resume", 15607],
    ["between the code's lifetime and its save", 15613],
  ] as const) {
    it(`a hold that lapsed ${moment} is refused access_denied: no code and no Mission`, async () => {
      const h = await start(port);
      const flow = await h.open();
      const decided = await flow.decide();
      const holds = approvalHoldsOf(h.as.provider);
      const held = holds.pending(flow.grantId) as { expiresAt: number };
      expect(held.expiresAt).toBeGreaterThan(Date.now());
      // The hold lapses as its interaction would, short of the interaction
      // itself expiring (which would end the resume before any code).
      const lapse = () => {
        held.expiresAt = Date.now() - 1;
      };
      if (moment === "before the resume") lapse();
      else {
        // The code's lifetime is the first read of the hold; it lapses right after.
        const read = holds.prospectiveExpiresAt.bind(holds);
        vi.spyOn(holds, "prospectiveExpiresAt").mockImplementationOnce((h) => {
          const value = read(h);
          lapse();
          return value;
        });
      }
      const codes = stagedCodes();
      const out = await flow.resume(decided);
      expect(out.error).toBe("access_denied");
      expect(out.code).toBeNull();
      expect(codes).toEqual([]);
      expectNoMission(h, flow);
    });
  }

  it("the approval-authentication floor is measured again at the commit: an Approver login that ages past it before the code save completes access_denied with no Mission", async () => {
    const h = await start(15614);
    const flow = await h.open("floor");
    const decided = await flow.decide();
    expect(decided.status).toBe(303);
    // At the commit the AS's clock reads 400 s later: the suite's mfa login is
    // past the high-risk floor's 300 s bound. Nothing else about the context changed.
    const later = Date.now() + 400_000;
    vi.spyOn(h.as.kernel as unknown as { now: () => Date }, "now").mockImplementation(() => new Date(later));
    const codes = stagedCodes();
    const out = await flow.resume(decided);
    expect(out.error).toBe("access_denied");
    expect(out.description).toMatch(/older than the high-risk-authority floor allows/);
    expect(out.code).toBeNull();
    expect(codes).toHaveLength(1);
    expect(await h.as.provider.AuthorizationCode.find(codes[0] as string)).toBeUndefined();
    expectNoMission(h, flow);
  });
});

describe("the held approval grant is Mission-bound from its first save (@spec mission#grant-binding-resolution, #1863, D1001)", () => {
  it("after a refused commit whose grant deletion failed, the grant stays classified and unusable: an ordinary request on the same session is not answered with it, and a token minted under it is refused", async () => {
    const h = await start(15608);
    const flow = await h.open("browser");
    const decided = await flow.decide();
    expect(decided.status).toBe(303);
    const destroy = vi.spyOn(h.as.provider.Grant.adapter, "destroy").mockRejectedValue(new Error("injected grant deletion failure"));
    vi.spyOn(h.as.kernel, "approve").mockImplementationOnce(() => {
      throw new IntentError("access_denied", "refused at the commit");
    });
    const out = await flow.resume(decided);
    expect(out.error).toBe("access_denied");
    expect(out.code).toBeNull();
    expect(destroy).toHaveBeenCalledWith(flow.grantId);
    expectNoMission(h, flow);
    // The grant survived its failed deletion, carrying the Authority Set, and
    // Alice's provider session in this user agent still names it.
    const grant = (await h.as.provider.Grant.find(flow.grantId)) as unknown as { rar?: unknown[] } | undefined;
    expect(grant?.rar?.length).toBeGreaterThan(0);
    const session = await h.as.provider.Session.find(flow.jar.get("_session") as string);
    expect(session?.grantIdFor("ap-agent")).toBe(flow.grantId);
    vi.restoreAllMocks();

    // An ordinary request on that session is not answered with the grant: it
    // reaches the interaction this AS offers no ordinary request.
    const missions = h.as.kernel.allMissions().length;
    const ordinary = await h.walk(`/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: await h.push("ordinary") })}`, flow.jar);
    expect(ordinary.code).toBeNull();
    expect(ordinary.error).toBe(ORDINARY_REQUEST_REFUSAL.error);
    expect(ordinary.description).toBe(ORDINARY_REQUEST_REFUSAL.error_description);
    expect(h.as.kernel.allMissions()).toHaveLength(missions);

    // A token-plane mint under the grant fails closed.
    const client = await h.as.provider.Client.find("ap-agent");
    const at = new h.as.provider.AccessToken({ accountId: "alice", client, grantId: flow.grantId } as never);
    await expect(at.save()).rejects.toMatchObject({ error: "invalid_grant", error_detail: "the grant's Mission approval has not committed" });
  });
});

describe("a decision racing the resume is ordered by the approval event's serialization (@spec mission#approval-event, #1863, D1001)", () => {
  const until = async (done: () => boolean) => {
    for (let i = 0; i < 400 && !done(); i++) await new Promise((r) => setTimeout(r, 5));
    expect(done()).toBe(true);
  };

  it("a retried decision in its grant save holds the resume's commit back; the code then commits one record, one binding, and agrees with the record", async () => {
    const h = await start(15609);
    const flow = await h.open();
    const first = await flow.decide();
    expect(first.status).toBe(303);
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let saving = false;
    const save = h.as.provider.Grant.prototype.save;
    vi.spyOn(h.as.provider.Grant.prototype, "save").mockImplementation(async function (this: object, ...args: unknown[]) {
      saving = true;
      await gate;
      return (save as (...a: unknown[]) => Promise<string>).apply(this, args);
    });
    // Each read of the held decision's prospective expiry: the code's lifetime, then the fence's clamp.
    const reads = vi.spyOn(approvalHoldsOf(h.as.provider), "prospectiveExpiresAt");
    const retry = flow.decide();
    await until(() => saving);
    let resumed = false;
    const resume = flow.resume(first).then((out) => {
      resumed = true;
      return out;
    });
    await until(() => reads.mock.calls.length >= 1);
    await new Promise((r) => setTimeout(r, 100));
    // The resume reached its code save, whose commit waits for the retried decision.
    expect(reads).toHaveBeenCalledTimes(1);
    expect(resumed).toBe(false);
    expect(h.missionsFor(flow.approvalEventId)).toEqual([]);
    release();
    // The retry held the decision again; the resume had consumed its interaction, so it completes nothing itself.
    await retry;
    const out = await resume;
    expect(out.code, JSON.stringify(out)).toBeTruthy();
    const record = h.as.kernel.findByApprovalEvent(flow.approvalEventId);
    expect(h.missionsFor(flow.approvalEventId)).toEqual([record?.id]);
    expect(record?.grant_id).toBe(flow.grantId);
    expect(h.as.kernel.missionBoundGrants.resolve(flow.grantId)?.missionId).toBe(record?.id);
    const grant = (await h.as.provider.Grant.find(flow.grantId)) as unknown as { rar?: unknown };
    expect(grant.rar).toEqual(record?.authority_set);
    const redeemed = await flow.redeem(out.code as string);
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(flow.missionOf(redeemed.body)).toBe(record?.id);
  });

  it("a retried decision reaching its commit while the code save commits waits for it and recovers the one binding: one record, and the code redeems under it", async () => {
    const h = await start(15610);
    const flow = await h.open();
    const first = await flow.decide();
    expect(first.status).toBe(303);
    // The retry loads the interaction, then waits before its commit until the resume is staging its code.
    let evidenceReached = false;
    let releaseRetry!: () => void;
    const retryGate = new Promise<void>((r) => {
      releaseRetry = r;
    });
    const verify = h.as.kernel.verifySubmissionEvidence.bind(h.as.kernel);
    vi.spyOn(h.as.kernel, "verifySubmissionEvidence").mockImplementationOnce(async (...args: Parameters<typeof verify>) => {
      evidenceReached = true;
      await retryGate;
      return verify(...args);
    });
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let staging = false;
    const upsert = MemoryAdapter.prototype.upsert;
    vi.spyOn(MemoryAdapter.prototype, "upsert").mockImplementation(async function (this: { model: string }, ...args: Parameters<typeof upsert>) {
      if (this.model === "AuthorizationCode") {
        staging = true;
        await gate;
      }
      return upsert.apply(this as never, args);
    });
    const saves = vi.spyOn(h.as.provider.Grant.prototype, "save");
    const retry = flow.decide();
    await until(() => evidenceReached);
    const resume = flow.resume(first);
    await until(() => staging);
    releaseRetry();
    await new Promise((r) => setTimeout(r, 100));
    // The retry waits for the commit: it has not saved its grant.
    expect(saves).not.toHaveBeenCalled();
    release();
    const out = await resume;
    await retry;
    expect(out.code, JSON.stringify(out)).toBeTruthy();
    const record = h.as.kernel.findByApprovalEvent(flow.approvalEventId);
    expect(h.missionsFor(flow.approvalEventId)).toEqual([record?.id]);
    expect(h.as.kernel.get(record?.id as string)?.grant_id).toBe(flow.grantId);
    const grant = (await h.as.provider.Grant.find(flow.grantId)) as unknown as { rar?: unknown };
    expect(grant.rar).toEqual(record?.authority_set);
    const redeemed = await flow.redeem(out.code as string);
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(flow.missionOf(redeemed.body)).toBe(record?.id);
  });
});
