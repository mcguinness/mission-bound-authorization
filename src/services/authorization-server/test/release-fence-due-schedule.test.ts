/**
 * @spec status#mission-lifecycle-endpoint ("Operations"), mission#issuance-gating
 * (#1659, D771): the release fence decides on a due revocation schedule.
 *
 * From a current schedule's deadline, every decision treats the Mission as in
 * the state its `on_expiry` produces. The release fence projects a due
 * `on_expiry=revoke` read-only, for the Mission and its ancestors: a token
 * whose Mission's revocation deadline passed after the issuance gate is
 * refused at release, and nothing is written there. Expiry precedes the
 * deadline, a replaced schedule projects nothing, and a due `resume` still
 * releases, as a suspension committed after the gate does. Each schedule here
 * is committed from inside the issuing request, after the save-time gate
 * passed (oidc-provider's `access_token.issued` event), and the controlled
 * clock then moves to the deadline without delivering the timer.
 *
 * A due transition whose write fails fails issuance closed with
 * `temporarily_unavailable`, and the retried request succeeds once storage
 * accepts the write.
 */
import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { releaseFenceRefusal } from "../src/adapters/provider.js";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  createChildMission,
  MissionKernel,
  type ScheduleTimers,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const PORT = 14574;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "due-schedule-fence-verifier-0123456789-0123456789-01234567";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
const REFUSAL_MEMBERS = ["error", "error_description", "mission_error"];

/** The kernel's clock and the scheduler's timers in one; `skip` moves time and delivers no timer. */
class ControlledClock implements ScheduleTimers {
  at: Date;
  private seq = 0;
  private readonly pending = new Map<number, { dueMs: number; callback: () => Promise<unknown> }>();

  constructor(start: Date) {
    this.at = start;
  }

  readonly now = (): Date => this.at;

  set(callback: () => Promise<unknown>, delayMs: number): unknown {
    this.seq += 1;
    this.pending.set(this.seq, { dueMs: this.at.getTime() + delayMs, callback });
    return this.seq;
  }

  clear(handle: unknown): void {
    this.pending.delete(handle as number);
  }

  skip(ms: number): void {
    this.at = new Date(this.at.getTime() + ms);
  }
}

const clock = new ControlledClock(new Date(Math.floor(Date.now() / 1000) * 1000));
/** An RFC 3339 instant `seconds` from the controlled clock's now. */
const at = (seconds: number, c: ControlledClock = clock): string =>
  new Date(c.at.getTime() + seconds * 1000).toISOString();

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

async function newKeys(): Promise<Keys> {
  return (await generateKeyPair("ES256", { extractable: true })) as Keys;
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(keys: Keys): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const res = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys) },
    body: new URLSearchParams({
      ...params,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Json };
}

/** PAR and the approval: an active Mission's authorization code. */
async function authorize(expiresAt: string = FAR_EXP): Promise<string> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
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
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: expiresAt },
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
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  // The approver authenticated at the AS clock's now, not the wall clock's.
  const approver = trustedApprovalHeaders("bob", { approver_auth_time: Math.floor(clock.at.getTime() / 1000) });
  const decideHeaders = { ...approver, "content-type": "application/json", cookie: cookie() };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  return new URL(location).searchParams.get("code") as string;
}

const exchange = (code: string, keys: Keys) =>
  token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );

function missionOf(accessToken: string): string {
  const claims = JSON.parse(Buffer.from(accessToken.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return claims.mission.id;
}

/** What a write at the fence would change: the stored row and the Mission's lifecycle events. */
function stored(id: string): { state: string; version: number; derivations: number; schedule: string | null; events: number } {
  const row = as.kernel.db
    .prepare("SELECT state, version, derivation_count, schedule_json FROM missions WHERE id = ?")
    .get(id) as { state: string; version: number; derivation_count: number; schedule_json: string | null };
  const events = as.kernel.db.prepare("SELECT COUNT(*) AS n FROM lifecycle_events WHERE mission_id = ?").get(id) as {
    n: number;
  };
  return {
    state: row.state,
    version: row.version,
    derivations: row.derivation_count,
    schedule: row.schedule_json,
    events: events.n,
  };
}

/**
 * Run `commit` on the Mission of the next access token oidc-provider issues,
 * from inside its `save()`: after the save-time gate and the signature, before
 * the response. Records the stored row it left, for the no-write assertion.
 */
function atNextIssue(commit: (missionId: string) => void): {
  missionId: () => string | undefined;
  left: () => ReturnType<typeof stored> | undefined;
} {
  let seen: string | undefined;
  let left: ReturnType<typeof stored> | undefined;
  const listener = (issued: { extra?: { mission?: { id?: string } } }) => {
    const id = issued.extra?.mission?.id as string;
    commit(id);
    seen = id;
    left = stored(id);
  };
  armed.push(listener);
  as.provider.once("access_token.issued", listener);
  return { missionId: () => seen, left: () => left };
}

const armed: Array<(issued: { extra?: { mission?: { id?: string } } }) => void> = [];

function expectNoTokenMaterial(body: Json): void {
  expect(Object.keys(body).sort()).toEqual(REFUSAL_MEMBERS);
}

const suspendWith = (id: string, until: string, onExpiry: "resume" | "revoke"): void => {
  as.kernel.transition(id, "suspend", { schedule: { suspend_until: until, on_expiry: onExpiry, committing_party: "svc:ops" } });
};

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    suspensionSchedules: { timers: clock },
    now: clock.now,
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
  for (const listener of armed.splice(0)) as.provider.removeListener("access_token.issued", listener as never);
});

describe("the release fence projects a due revocation schedule read-only (@spec status#mission-lifecycle-endpoint, mission#issuance-gating, #1659 D771)", () => {
  it("refuses a token whose Mission's revocation deadline is reached, exactly, after the gate, mission_error revoked, and writes nothing", async () => {
    const hooked = atNextIssue((id) => {
      suspendWith(id, at(1), "revoke");
      clock.skip(1000);
    });
    const res = await exchange(await authorize(), await newKeys());
    const id = hooked.missionId() as string;
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_grant", mission_error: "revoked" });
    expectNoTokenMaterial(res.body);
    // No write at the fence: the row, its version, its schedule, its events
    // and the gate's counted derivation are as the commit left them.
    expect(stored(id)).toEqual(hooked.left());
    expect(stored(id).state).toBe("suspended");
  });

  it("releases when the deadline that passed belongs to a schedule an authorized replacement superseded", async () => {
    const hooked = atNextIssue((id) => {
      suspendWith(id, at(1), "revoke");
      suspendWith(id, at(60), "revoke");
      clock.skip(1000);
    });
    const res = await exchange(await authorize(), await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(typeof res.body.access_token).toBe("string");
    expect(stored(hooked.missionId() as string)).toEqual(hooked.left());
  });

  it("lets expiry govern a revocation deadline at expires_at: the release is refused mission_error expired, never revoked, and nothing is written", async () => {
    const expiresAt = at(120);
    const hooked = atNextIssue((id) => {
      suspendWith(id, expiresAt, "revoke");
      clock.skip(Date.parse(expiresAt) - clock.at.getTime());
    });
    const res = await exchange(await authorize(expiresAt), await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_grant", mission_error: "expired" });
    expect(stored(hooked.missionId() as string)).toEqual(hooked.left());
  });

  it("releases a token whose derivation passed its gate and whose Mission's due schedule is a resume, as a suspension committed after the gate does", async () => {
    const hooked = atNextIssue((id) => {
      suspendWith(id, at(1), "resume");
      clock.skip(1000);
    });
    const res = await exchange(await authorize(), await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(missionOf(res.body.access_token as string)).toBe(hooked.missionId());
    expect(stored(hooked.missionId() as string)).toEqual(hooked.left());
  });

  it("refuses a Child Mission's release when its parent's revocation deadline has passed, as parent_terminated, writing neither row", async () => {
    const childClock = new ControlledClock(new Date(clock.at.getTime()));
    const resource = DERIVATION_POLICY.ceiling[0].resource as string;
    const entry = (actions: string[]): AuthorityEntry[] => [
      {
        type: "mission_resource_access",
        resource,
        actions,
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const kernel = new MissionKernel({
      issuer: "https://as.test",
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]),
      statusKey: (await generateKeyPair("ES256")).privateKey,
      statusKid: "as-status",
      now: childClock.now,
      actorProfiles: aiAgents("child-agent"),
    });
    const expiresAt = at(30 * 86400, childClock);
    const parent = kernel.approve({
      intent: kernel.validateIntent(JSON.stringify({ goal: "Pay Acme", target_resources: [resource], expires_at: expiresAt })),
      proposedAuthority: entry(["payments:invoice.read", "payments:payment.execute"]),
      subject: { iss: "https://as.test", sub: "alice" },
      approver: { iss: "https://as.test", sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: "apev-fence-parent",
    });
    const child = createChildMission(kernel, {
      parentId: parent.id,
      intent: kernel.validateIntent(
        JSON.stringify({ goal: "Read Acme invoices", target_resources: [resource], expires_at: expiresAt }),
      ),
      proposedAuthority: entry(["payments:invoice.read"]),
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    }).child;
    const row = (id: string) => kernel.db.prepare("SELECT state, version, schedule_json FROM missions WHERE id = ?").get(id);
    kernel.transition(parent.id, "suspend", {
      schedule: { suspend_until: at(30, childClock), on_expiry: "revoke", committing_party: "svc:ops" },
    });
    const parentLeft = row(parent.id);
    const childLeft = row(child.id);
    // Before the deadline the parent is only suspended: the child releases.
    childClock.skip(29_000);
    expect(releaseFenceRefusal(kernel, child.id)).toBeUndefined();
    expect(kernel.observedForRelease(child.id)?.state).not.toBe("terminated");
    childClock.skip(1_000);
    const refusal = releaseFenceRefusal(kernel, child.id);
    expect(refusal?.reason).toBe("mission_not_active");
    expect(kernel.observedForRelease(child.id)).toMatchObject({
      state: "terminated",
      termination: { reason: "parent_terminated" },
    });
    expect(kernel.observedForRelease(parent.id)).toMatchObject({
      state: "terminated",
      termination: { reason: "revoked", terminated_at: at(0, childClock) },
    });
    expect(row(parent.id)).toEqual(parentLeft);
    expect(row(child.id)).toEqual(childLeft);
    kernel.db.close();
  });
});

describe("issuance fails closed when a due transition cannot be persisted (@spec status#mission-lifecycle-endpoint, mission#issuance-gating, #1659 D771)", () => {
  it("refuses a refresh temporarily_unavailable while a due resume cannot be written, consuming nothing, and serves the retry once storage accepts it", async () => {
    const keys = await newKeys();
    const issued = await exchange(await authorize(), keys);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const id = missionOf(issued.body.access_token as string);
    suspendWith(id, at(1), "resume");
    clock.skip(1000);
    const before = stored(id);
    const kernel = as.kernel as unknown as { setState: (...args: unknown[]) => unknown };
    vi.spyOn(kernel, "setState").mockImplementationOnce(() => {
      throw new Error("SQLITE_IOERR: disk I/O error");
    });
    const failed = await token({ grant_type: "refresh_token", refresh_token: issued.body.refresh_token as string }, keys);
    expect(failed.status, JSON.stringify(failed.body)).toBe(503);
    expect(failed.body.error).toBe("temporarily_unavailable");
    expect(stored(id)).toEqual(before);
    const retried = await token({ grant_type: "refresh_token", refresh_token: issued.body.refresh_token as string }, keys);
    expect(retried.status, JSON.stringify(retried.body)).toBe(200);
    expect(stored(id).state).toBe("active");
  });
});
