/**
 * @spec control-plane#rollback (#250 step 3): the Authorization Server on a
 * file-backed kernel with a recovery witness.
 *
 * - The main token flows run with every kernel write guarded: none escapes the
 *   guard, and the witness and the store's marker advance together.
 * - A store that does not match its witness does not build an AS at all.
 * - A running AS whose kernel becomes uncertain refuses every state-dependent
 *   request with 503 `temporarily_unavailable`, and still serves discovery and
 *   the key set.
 */
import { type Server } from "node:http";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  readRecoveryWitness,
  reconcileKernelRecovery,
  RecoveryUncertainError,
  type RecoveryWitnessRecord,
} from "../src/index.js";
import { renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "recovery-witness-as-verifier-0123456789-0123456789-01";
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

const dirs: string[] = [];
const closers: Array<() => Promise<void> | void> = [];
afterAll(async () => {
  for (const close of closers.reverse()) await close();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.restoreAllMocks();
});

/** A store and its witness in separate directories, the witness created once. */
function witnessedStore(init = true): { store: string; witness: string } {
  const root = mkdtempSync(join(tmpdir(), "recovery-witness-as-"));
  dirs.push(root);
  const store = join(root, "state", "kernel.db");
  const witness = join(root, "witness", "kernel.witness");
  mkdirSync(dirname(store), { recursive: true });
  mkdirSync(dirname(witness), { recursive: true });
  if (init) reconcileKernelRecovery({ storeFile: store, witnessFile: witness, action: "init" });
  return { store, witness };
}

interface Target {
  issuer: string;
  as: BuiltAs;
  clientKey: CryptoKey;
  paths: { store: string; witness: string };
}

async function start(port: number): Promise<Target> {
  const issuer = `http://localhost:${port}`;
  const paths = witnessedStore();
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    kernelStore: { file: paths.store, witness: paths.witness },
  });
  const server: Server = as.provider.listen(port);
  await new Promise<void>((r) => server.once("listening", () => r()));
  closers.push(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    as.kernel.close();
  });
  const clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  return { issuer, as, clientKey, paths };
}

async function newKeys(): Promise<Keys> {
  return (await generateKeyPair("ES256", { extractable: true })) as Keys;
}

async function clientAssertion(t: Target): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(t.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(t.clientKey);
}

async function token(t: Target, params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${t.issuer}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu: `${t.issuer}/token`, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(keys.privateKey),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(t),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  const raw = await res.text();
  return { status: res.status, body: raw.startsWith("{") ? (JSON.parse(raw) as Json) : { error_text: raw } };
}

/** PAR, approval and the code exchange: an active Mission's access and refresh token. */
async function issue(t: Target): Promise<{ missionId: string; accessToken: string; refreshToken: string; keys: Keys }> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const par = await fetch(`${t.issuer}/request`, {
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
      mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP } }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(t),
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
  let res = await fetch(`${t.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`, {
    redirect: "manual",
  });
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  const decideHeaders = { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() };
  const render_revision = await renderedRevision(t.issuer, uid, decideHeaders);
  res = await fetch(`${t.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(t.issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") as string;
  const keys = await newKeys();
  const exchanged = await token(
    t,
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
    keys,
  );
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const accessToken = exchanged.body.access_token as string;
  const claims = JSON.parse(Buffer.from(accessToken.split(".")[1] as string, "base64url").toString()) as { mission: { id: string } };
  return { missionId: claims.mission.id, accessToken, refreshToken: exchanged.body.refresh_token as string, keys };
}

const marker = (t: Target): number =>
  (t.as.kernel.db.prepare("SELECT sequence FROM recovery_marker").get() as { sequence: number }).sequence;

describe("the AS on a witnessed kernel store (@spec control-plane#rollback, #250 step 3)", () => {
  it("runs the code exchange, a refresh, a delegation handle, an async family and its refresh with every write guarded: nothing escapes, and the witness and the store advance together", async () => {
    const t = await start(14971);
    const before = marker(t);
    const m = await issue(t);
    const refreshed = await token(t, { grant_type: "refresh_token", refresh_token: m.refreshToken }, m.keys);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    const handle = await token(t, delegationHandleParams(m.accessToken, "ap-agent"), m.keys);
    expect(handle.status, JSON.stringify(handle.body)).toBe(200);
    const family = await token(
      t,
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: handle.body.access_token as string,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource: RESOURCE,
        creation_request_id: crypto.randomUUID(),
      },
      m.keys,
    );
    expect(family.status, JSON.stringify(family.body)).toBe(200);
    const familyRefresh = await token(t, { grant_type: "refresh_token", refresh_token: family.body.refresh_token as string }, m.keys);
    expect(familyRefresh.status, JSON.stringify(familyRefresh.body)).toBe(200);
    t.as.kernel.transition(m.missionId, "suspend");
    t.as.kernel.transition(m.missionId, "resume");

    expect(t.as.kernel.recoveryUncertainty()).toBeUndefined();
    const witness = readRecoveryWitness(t.paths.witness) as RecoveryWitnessRecord;
    expect(witness.intent).toBeNull();
    expect(witness.committed).toBe(marker(t));
    expect(witness.committed).toBeGreaterThan(before);
  });

  it("a running AS whose kernel became uncertain answers every state-dependent request 503 temporarily_unavailable, and still serves discovery and the key set", async () => {
    const t = await start(14972);
    const m = await issue(t);
    // The next witness write fails: the kernel stops accepting writes.
    const guard = t.as.kernel.recovery as unknown as { persist(record: RecoveryWitnessRecord): void };
    vi.spyOn(guard, "persist").mockImplementationOnce(() => {
      throw new Error("injected: the witness cannot be written");
    });
    expect(() => t.as.kernel.transition(m.missionId, "suspend")).toThrow(RecoveryUncertainError);
    expect(t.as.kernel.recoveryUncertainty()?.reason).toBe("witness_write_failed");

    const refreshed = await token(t, { grant_type: "refresh_token", refresh_token: m.refreshToken }, m.keys);
    expect(refreshed.status).toBe(503);
    expect(refreshed.body.error).toBe("temporarily_unavailable");
    expect(refreshed.body.access_token).toBeUndefined();
    const introspected = await fetch(`${t.issuer}/token/introspection`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: m.accessToken }).toString(),
    });
    expect(introspected.status).toBe(503);
    const pushed = await fetch(`${t.issuer}/request`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "" });
    expect(pushed.status).toBe(503);

    const discovery = await fetch(`${t.issuer}/.well-known/openid-configuration`);
    expect(discovery.status).toBe(200);
    const jwks = await fetch(`${t.issuer}/jwks`);
    expect(jwks.status).toBe(200);
    expect(((await jwks.json()) as { keys: unknown[] }).keys.length).toBeGreaterThan(0);
  });

  it("an AS whose kernel store does not match its witness does not build, and releases the store", async () => {
    const paths = witnessedStore(false);
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:14973",
        allowHeadlessAdjudication: true,
        kernelStore: { file: paths.store, witness: paths.witness },
      }),
    ).rejects.toThrow(RecoveryUncertainError);
    // The refused open held nothing: the store initializes now.
    expect(reconcileKernelRecovery({ storeFile: paths.store, witnessFile: paths.witness, action: "init" })).toMatchObject({
      committed: 0,
    });
  });
});

describe("the AS on a witnessed kernel store: review fixes (@spec control-plane#rollback, #250 step 3)", () => {
  it("review: refuses a refresh whose kernel becomes uncertain during the final awaited drain, releasing no token", async () => {
    const t = await start(14974);
    const m = await issue(t);
    let armed = false;
    let injected = false;
    t.as.provider.once("access_token.issued", () => {
      armed = true;
    });
    const original = t.as.kernel.drainLifecycleOutbox.bind(t.as.kernel);
    vi.spyOn(t.as.kernel, "drainLifecycleOutbox").mockImplementation(async () => {
      await original();
      if (armed && !injected) {
        injected = true;
        // Another write, made while this refresh is in flight, finds the witness unwritable.
        const guard = t.as.kernel.recovery as unknown as { persist(record: RecoveryWitnessRecord): void };
        vi.spyOn(guard, "persist").mockImplementationOnce(() => {
          throw new Error("injected witness write failure");
        });
        expect(() => t.as.kernel.gateDerivation(m.missionId)).toThrow(RecoveryUncertainError);
      }
    });
    const refreshed = await token(t, { grant_type: "refresh_token", refresh_token: m.refreshToken }, m.keys);
    expect(injected).toBe(true);
    expect(t.as.kernel.recoveryUncertainty()?.reason).toBe("witness_write_failed");
    expect(refreshed.status).toBe(503);
    expect(refreshed.body.error).toBe("temporarily_unavailable");
    expect(refreshed.body.access_token).toBeUndefined();
  });

  it("the kernel database holds exactly the tables the transaction inventory names (control-plane-deployment.md, Restore admission)", async () => {
    const paths = witnessedStore();
    const as = await buildAuthorizationServer({
      issuer: "http://localhost:14975",
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
      capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "deferred-approval"]),
      deferredApproval: { pendingLifetimeS: 600, maxPendingPerClient: 3 },
      kernelStore: { file: paths.store, witness: paths.witness },
    });
    try {
      const tables = (
        as.kernel.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as Array<{
          name: string;
        }>
      ).map((r) => r.name);
      expect(tables).toEqual([...KERNEL_TABLE_INVENTORY].sort());
    } finally {
      as.kernel.close();
    }
  });
});

/**
 * @spec control-plane#partitions (#250 step 4): with one writer and no replica,
 * every operation reads and writes the authoritative kernel record in its own
 * transaction. When the kernel cannot establish that its state is current (it
 * is uncertain), the AS refuses rather than serving from what it last knew.
 */
describe("the AS refuses control-plane mutation while its state is uncertain (@spec control-plane#partitions, #250 step 4)", () => {
  it("an uncertain kernel refuses the agent's self Token Exchange for a delegation handle 503, though the same exchange succeeded before, and every lifecycle mutation, and nothing moves: the Mission's version and the store's marker stay where they were", async () => {
    const t = await start(14976);
    const m = await issue(t);
    // The control: the same exchange (the agent's own token, audienced to
    // itself) succeeds while the kernel is certain.
    const control = await token(t, delegationHandleParams(m.accessToken, "ap-agent"), m.keys);
    expect(control.status, JSON.stringify(control.body)).toBe(200);
    expect(control.body.access_token).toBeDefined();
    const before = { version: t.as.kernel.get(m.missionId)?.version, marker: marker(t) };
    const guard = t.as.kernel.recovery as unknown as { persist(record: RecoveryWitnessRecord): void };
    vi.spyOn(guard, "persist").mockImplementationOnce(() => {
      throw new Error("injected: the witness cannot be written");
    });
    expect(() => t.as.kernel.transition(m.missionId, "suspend")).toThrow(RecoveryUncertainError);

    const exchanged = await token(t, delegationHandleParams(m.accessToken, "ap-agent"), m.keys);
    expect(exchanged.status).toBe(503);
    expect(exchanged.body.error).toBe("temporarily_unavailable");
    expect(exchanged.body.access_token).toBeUndefined();
    for (const operation of ["suspend", "revoke", "complete"] as const) {
      expect(() => t.as.kernel.transition(m.missionId, operation), operation).toThrow(RecoveryUncertainError);
    }
    expect(() =>
      t.as.kernel.contain(m.missionId, {
        event: { type: "incident", source: "soc", observed_at: new Date().toISOString(), event_id: "partition-1" },
        remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
      }),
    ).toThrow(RecoveryUncertainError);
    expect(t.as.kernel.get(m.missionId)).toMatchObject({ state: "active", version: before.version });
    expect(marker(t)).toBe(before.marker);
  });
});

/**
 * @spec control-plane#rollback (#250 step 3): the kernel database's tables, as
 * control-plane-deployment.md's transaction inventory names them. A new table
 * fails the test above until it is added there and here.
 */
const KERNEL_TABLE_INVENTORY = [
  "activation_policy_snapshots",
  "approval_governance_records",
  "approval_reservations",
  "authority_source_bindings",
  "carryover_replacements",
  "carryover_reservations",
  "carryover_results",
  "continuation_anchors",
  "continuation_handles",
  "creation_idempotency",
  "delegation_families",
  "derivation_reservations",
  "direct_approval_inputs",
  "direct_approval_rules",
  "discharge_events",
  "discharge_mapping_pins",
  "discharge_selectors",
  "drawdown_record_inputs",
  "drawdown_recording_rules",
  "expansion_deferrals",
  "governed_policy_activations",
  "governed_policy_consents",
  "governed_policy_roots",
  "join_assertion_events",
  "kernel_issuer",
  "lifecycle_deliveries",
  "lifecycle_events",
  "lifecycle_responses",
  "mission_approval_deferrals",
  "mission_deferred_authorization_codes",
  "mission_tombstones",
  "missions",
  "progressive_refusals",
  "recovery_marker",
  "standing_payment_admissions",
  "standing_payment_budget_bindings",
  "standing_payment_dispatches",
  "template_record_inputs",
  "template_recording_rules",
];
