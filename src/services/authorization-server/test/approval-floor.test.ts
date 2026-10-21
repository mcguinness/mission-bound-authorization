/**
 * @spec mission#approval-authentication (#826, D425) — the published
 * approval-authentication floor at the approval decision, over HTTP: the
 * complete derived Authority Set is classified through the AS-owned policy
 * (config/approval-floor.json), and high-risk authority needs a browser
 * Approver whose achieved `acr` the floor accepts inside its age bound. An
 * absent or weaker client request never relaxes it. A refusal is
 * `access_denied` with no Mission, Grant, code or Subject session.
 *
 * The shipped high-risk actions (payment execution, remittance) are all
 * write-bearing, so they need a distinct Approver (D37), and a delegated
 * request cannot carry `acr_values` (D305): the floor/request conjunction
 * cannot arise on shipped authority. It is exercised on a second AS whose
 * floor policy classifies `payments:invoice.read` as high-risk, so a
 * self-approval with `openid` can carry a request.
 */
import { type Server } from "node:http";
import {
  APPROVAL_FLOOR,
  type ApprovalFloorPolicy,
  AUTHORITY_SOURCES,
  DERIVATION_POLICY,
  loadApprovalFloor,
} from "@mission/demo-data";
import { TOOL_ACTIONS } from "@mission/mcp-payments";
import { importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { evaluateApprovalFloor } from "../src/kernel/approval-floor.js";
import type { AuthorityEntry } from "../src/kernel/types.js";
import { browserApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14791;
const OVERRIDE_PORT = 14792;
const PROGRESSIVE_PORT = 14793;
const ISSUER = `http://localhost:${PORT}`;
const OVERRIDE_ISSUER = `http://localhost:${OVERRIDE_PORT}`;
const PROGRESSIVE_ISSUER = `http://localhost:${PROGRESSIVE_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PAYMENTS = DERIVATION_POLICY.ceiling[0].resource as string;
const VERIFIER = "approval-floor-verifier-0123456789-0123456789-0123";
const FLOOR = APPROVAL_FLOOR.floors[0];
const MAX_AGE = FLOOR?.max_authentication_age_seconds as number;

const READ: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] },
];
const REMIT: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: PAYMENTS,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];
/** A low-risk entry first, the high-risk entry second. */
const MIXED: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] },
  {
    type: "mission_resource_access",
    resource: PAYMENTS,
    actions: ["payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

/**
 * The override AS's policy: the shipped floor, but `payments:invoice.read`
 * is high-risk and `payments:vendor.read` is unclassified.
 */
const OVERRIDE_POLICY: ApprovalFloorPolicy = {
  ...APPROVAL_FLOOR,
  classification: APPROVAL_FLOOR.classification.map((c) => {
    if (c.resource !== PAYMENTS) return c;
    const actions: Record<string, (typeof c.actions)[string]> = { ...c.actions, "payments:invoice.read": "irreversible_action" };
    delete actions["payments:vendor.read"];
    return { ...c, actions };
  }),
};

/**
 * The Progressive AS's deployment (#1255): a drawdown mapping that agrees
 * with the shipped floor, and a drawdown policy the Approver can consent.
 */
const PROGRESSIVE_DEPLOYMENT = {
  progressive: {
    chainRateBound: { maxDrawdowns: 2, windowSeconds: 3600 },
    actionClasses: {
      "payments:invoice.read": "consequential_read",
      "payments:payment.execute": "irreversible_action",
      "payments:remittance.send": "external_commitment",
    },
    // The approval surface offers the payments ceiling under drawdown-std; a
    // decision may consent only exactly what the page rendered (#1017).
    ceilingOffer: () => CEILING_CONSENT,
  },
  activationPolicies: {
    "drawdown-std": {
      version: "1",
      content_type: "application/json",
      content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 2_592_000 }),
    },
  },
} satisfies Pick<Parameters<typeof buildAuthorizationServer>[0], "progressive" | "activationPolicies">;

/** The payments ceiling as the derivation policy states it: it admits payment execution and remittance. */
const PAYMENTS_CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === PAYMENTS) as unknown as AuthorityEntry[];
const CEILING_CONSENT = {
  authority_ceiling: PAYMENTS_CEILING,
  drawdown_policy: { id: "drawdown-std", version: "1" },
};

type Server2 = { as: BuiltAs; server: Server; sessions: ApprovalSessionStore; key: CryptoKey; issuer: string };
let shipped: Server2;
let override: Server2;
let progressive: Server2;

async function start(
  issuer: string,
  port: number,
  approvalFloor?: ApprovalFloorPolicy,
  deployment: Partial<typeof PROGRESSIVE_DEPLOYMENT> = {},
): Promise<Server2> {
  const sessions = new ApprovalSessionStore();
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: sessions,
    ...(approvalFloor ? { approvalFloor } : {}),
    ...deployment,
  });
  const server = as.provider.listen(port);
  const key = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  return { as, server, sessions, key, issuer };
}

beforeAll(async () => {
  shipped = await start(ISSUER, PORT);
  override = await start(OVERRIDE_ISSUER, OVERRIDE_PORT, OVERRIDE_POLICY);
  progressive = await start(PROGRESSIVE_ISSUER, PROGRESSIVE_PORT, undefined, PROGRESSIVE_DEPLOYMENT);
});

afterAll(() => {
  shipped?.server.close();
  override?.server.close();
  progressive?.server.close();
});

afterEach(() => {
  vi.restoreAllMocks();
});

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};

type Approval =
  | { browser: { sub: string; acr: string; auth_time?: number; subject?: string } }
  | { headless: { sub: string; acr: string; subject: string | null } };

/**
 * One authorization in its own user agent: PAR, the approval, the resume,
 * and the redirect's code or error. Counts the Missions and provider Grants
 * the attempt created.
 */
async function authorize(
  s: Server2,
  args: {
    authority?: AuthorityEntry[];
    scope?: string;
    extra?: Record<string, string>;
    approval: Approval;
    /** The ceiling members the decision consents (#1255). */
    ceiling?: Record<string, unknown>;
  },
): Promise<{ code?: string; error?: string; description?: string; jar: Jar; missions: number; grants: number }> {
  const jar: Jar = new Map();
  const missionsBefore = s.as.kernel.allMissions().length;
  let grants = 0;
  const onGrant = () => {
    grants += 1;
  };
  s.as.provider.on("grant.saved", onGrant);
  try {
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(s.issuer)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(s.key);
    const par = await fetch(`${s.issuer}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: PAYMENTS,
        code_challenge: challenge,
        code_challenge_method: "S256",
        ...(args.scope ? { scope: args.scope } : {}),
        ...(args.extra ?? {}),
        mission_intent: JSON.stringify({
          intent: { goal: "Pay Acme invoices", target_resources: [PAYMENTS], expires_at: "2027-01-01T00:00:00Z" },
        }),
        authorization_details: JSON.stringify(args.authority ?? READ),
        client_assertion: assertion,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    expect(par.status, await par.clone().text()).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    let res = await fetch(`${s.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
      redirect: "manual",
    });
    keep(jar, res);
    let location = res.headers.get("location") ?? "";
    const uid = location.split("/interaction/")[1] as string;
    const headers =
      "browser" in args.approval
        ? browserApprovalHeaders(s.sessions, uid, args.approval.browser, cookieOf(jar))
        : {
            ...trustedApprovalHeaders(args.approval.headless.sub, { approver_acr: args.approval.headless.acr }, args.approval.headless.subject),
            cookie: cookieOf(jar),
          };
    res = await fetch(`${s.issuer}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve", ...(args.ceiling ?? {}) }),
    });
    expect(res.status, await res.clone().text()).toBe(303);
    keep(jar, res);
    location = res.headers.get("location") ?? "";
    while (location.startsWith(s.issuer)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
      keep(jar, res);
      location = res.headers.get("location") ?? "";
    }
    const q = new URL(location).searchParams;
    return {
      jar,
      missions: s.as.kernel.allMissions().length - missionsBefore,
      grants,
      ...(q.get("code") ? { code: q.get("code") as string } : {}),
      ...(q.get("error") ? { error: q.get("error") as string } : {}),
      ...(q.get("error_description") ? { description: q.get("error_description") as string } : {}),
    };
  } finally {
    s.as.provider.off("grant.saved", onGrant);
  }
}

/** The provider session this user agent holds, if any. */
async function sessionAccount(s: Server2, jar: Jar): Promise<string | undefined> {
  const id = jar.get("_session");
  if (!id) return undefined;
  return ((await s.as.provider.Session.find(id)) as { accountId?: string } | undefined)?.accountId;
}

/** A refusal left nothing behind: no Mission, no Grant, no code, no Subject session. */
async function expectRefusedClean(s: Server2, r: Awaited<ReturnType<typeof authorize>>): Promise<void> {
  expect(r.error).toBe("access_denied");
  expect(r.code).toBeUndefined();
  expect(r.missions).toBe(0);
  expect(r.grants).toBe(0);
  expect(await sessionAccount(s, r.jar)).not.toBe("alice");
}

const now = () => Math.floor(Date.now() / 1000);

describe("the published approval-authentication floor at the approval decision (@spec mission#approval-authentication, #826, D425)", () => {
  it("admits high-risk authority from a browser Approver whose achieved acr the floor accepts, inside its age bound", async () => {
    const r = await authorize(shipped, { authority: REMIT, approval: { browser: { sub: "bob", acr: "mfa", subject: "alice" } } });
    expect(r.code, r.description).toBeTruthy();
    expect(r.missions).toBe(1);
    const created = shipped.as.kernel.allMissions().at(-1);
    expect(created?.authority_set.flatMap((e) => e.actions)).toContain("payments:remittance.send");
  });

  it("refuses high-risk authority, with no client request, from a browser Approver whose achieved acr the floor does not accept: no Mission, Grant, code or Subject session", async () => {
    const r = await authorize(shipped, { authority: REMIT, approval: { browser: { sub: "bob", acr: "password", subject: "alice" } } });
    await expectRefusedClean(shipped, r);
    expect(r.description).toMatch(/high-risk-authority floor/);
  });

  it("refuses high-risk authority approved headlessly, even when the approval service's registration claims mfa", async () => {
    const r = await authorize(shipped, { authority: REMIT, approval: { headless: { sub: "bob", acr: "mfa", subject: "alice" } } });
    await expectRefusedClean(shipped, r);
    expect(r.description).toMatch(/browser approval surface/);
  });

  it("the age bound: an Approver authenticated exactly max_authentication_age_seconds ago satisfies it, one second older does not", async () => {
    const t = now();
    vi.spyOn(shipped.as.kernel, "nowDate").mockReturnValue(new Date(t * 1000));
    const atBound = await authorize(shipped, {
      authority: REMIT,
      approval: { browser: { sub: "bob", acr: "mfa", auth_time: t - MAX_AGE, subject: "alice" } },
    });
    expect(atBound.code, atBound.description).toBeTruthy();
    const older = await authorize(shipped, {
      authority: REMIT,
      approval: { browser: { sub: "bob", acr: "mfa", auth_time: t - MAX_AGE - 1, subject: "alice" } },
    });
    await expectRefusedClean(shipped, older);
    expect(older.description).toMatch(/older than the high-risk-authority floor allows/);
  });

  it("classifies the complete derived set: a high-risk entry after a low-risk one still invokes the floor", async () => {
    const weak = await authorize(shipped, { authority: MIXED, approval: { browser: { sub: "bob", acr: "password", subject: "alice" } } });
    await expectRefusedClean(shipped, weak);
    const headless = await authorize(shipped, { authority: MIXED, approval: { headless: { sub: "bob", acr: "mfa", subject: "alice" } } });
    await expectRefusedClean(shipped, headless);
    const strong = await authorize(shipped, { authority: MIXED, approval: { browser: { sub: "bob", acr: "mfa", subject: "alice" } } });
    expect(strong.code, strong.description).toBeTruthy();
  });

  it("leaves low-risk authority alone: a headless approval of read-only authority still completes", async () => {
    const r = await authorize(shipped, { authority: READ, approval: { headless: { sub: "bob", acr: "password", subject: "alice" } } });
    expect(r.code, r.description).toBeTruthy();
    expect(r.missions).toBe(1);
  });

  it("refuses admitted authority the classification does not name: unclassified authority fails closed", async () => {
    const r = await authorize(override, {
      authority: [{ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:vendor.read"] }],
      approval: { browser: { sub: "bob", acr: "mfa", subject: "alice" } },
    });
    await expectRefusedClean(override, r);
    expect(r.description).toMatch(/does not name payments:vendor\.read/);
  });
});

describe("the floor and the client's requested strength are conjunctive (@spec mission#approval-authentication, #826, D425)", () => {
  // On the override AS, invoice.read is high-risk, so Alice's own read-only
  // Mission can carry openid and a requested acr_values.
  it("a satisfied weaker request does not relax the floor: Alice requests and achieves password, and the floor refuses", async () => {
    const r = await authorize(override, {
      scope: "openid",
      extra: { acr_values: "password" },
      approval: { browser: { sub: "alice", acr: "password" } },
    });
    await expectRefusedClean(override, r);
    expect(r.description).toMatch(/high-risk-authority floor/);
  });

  it("a satisfied floor does not satisfy a stronger unmet request: Alice achieves mfa, requests passkey, and the request check refuses", async () => {
    const r = await authorize(override, {
      scope: "openid",
      extra: { acr_values: "passkey" },
      approval: { browser: { sub: "alice", acr: "mfa" } },
    });
    expect(r.error).toBe("access_denied");
    expect(r.missions).toBe(0);
    expect(r.grants).toBe(0);
    expect(r.description).toMatch(/requested acr_values/);
  });

  it("both satisfied: Alice achieves and requests mfa, and the approval completes", async () => {
    const r = await authorize(override, {
      scope: "openid",
      extra: { acr_values: "mfa" },
      approval: { browser: { sub: "alice", acr: "mfa" } },
    });
    expect(r.code, r.description).toBeTruthy();
    expect(r.missions).toBe(1);
  });
});

describe("the floor over a consented authority ceiling (@spec mission#approval-authentication, progressive#progressive-authorization, #1255)", () => {
  // The derived set is read-only, which invokes no floor; the ceiling admits
  // payment execution and remittance, which a later drawdown could grant
  // under this consent with no Approver authenticating.
  it("refuses a ceiling admitting floor-class authority for a password Approver, though the derived set invokes no floor: access_denied, with no Mission, Grant or code", async () => {
    const r = await authorize(progressive, {
      authority: READ,
      ceiling: CEILING_CONSENT,
      approval: { browser: { sub: "bob", acr: "password", subject: "alice" } },
    });
    await expectRefusedClean(progressive, r);
    expect(r.description).toMatch(/high-risk-authority floor/);
    // Without the ceiling, the same derived set and login are approved: the ceiling invoked the floor.
    const uncapped = await authorize(progressive, {
      authority: READ,
      approval: { browser: { sub: "bob", acr: "password", subject: "alice" } },
    });
    expect(uncapped.code, uncapped.description).toBeTruthy();
    expect(uncapped.missions).toBe(1);
  });

  it("approves the same ceiling for an mfa Approver inside the age bound, and the Mission records it", async () => {
    const r = await authorize(progressive, {
      authority: READ,
      ceiling: CEILING_CONSENT,
      approval: { browser: { sub: "bob", acr: "mfa", auth_time: now() - 1, subject: "alice" } },
    });
    expect(r.code, r.description).toBeTruthy();
    expect(r.missions).toBe(1);
    const created = progressive.as.kernel.allMissions().at(-1);
    expect(created?.authority_ceiling).toEqual(PAYMENTS_CEILING);
    expect(created?.drawdown_policy?.id).toBe("drawdown-std");
    expect(typeof created?.ceiling_hash).toBe("string");
  });

  it("refuses a consented drawdown_policy the issuer does not hold, at an unknown id or another version, invalid_request before any write: no grant, Mission or code", async () => {
    for (const drawdownPolicy of [{ id: "drawdown-unknown", version: "1" }, { id: "drawdown-std", version: "2" }]) {
      const r = await authorize(progressive, {
        authority: READ,
        ceiling: { ...CEILING_CONSENT, drawdown_policy: drawdownPolicy },
        approval: { browser: { sub: "bob", acr: "mfa", auth_time: now() - 1, subject: "alice" } },
      });
      const label = JSON.stringify(drawdownPolicy);
      expect(r.error, label).toBe("invalid_request");
      expect(r.description, label).toBe("drawdown_policy names no policy this issuer holds at that version");
      expect(r.code, label).toBeUndefined();
      expect(r.missions, label).toBe(0);
      expect(r.grants, label).toBe(0);
    }
  });
});

describe("the floor's classification agrees with the deployment's operation definitions (@spec mission#approval-authentication, #826, D425)", () => {
  const payments = APPROVAL_FLOOR.classification.find((c) => c.resource === PAYMENTS);
  const highRisk = new Set(APPROVAL_FLOOR.floors.flatMap((f) => f.applies_to));

  it("the high-risk payments actions are exactly those with an irreversible or external-commitment operation", () => {
    const fromOperations = new Set(
      Object.values(TOOL_ACTIONS)
        .filter((m) => m.actionClass === "irreversible_action" || m.actionClass === "external_commitment")
        .map((m) => m.action),
    );
    const fromFloor = new Set(
      Object.entries(payments?.actions ?? {})
        .filter(([, cls]) => highRisk.has(cls))
        .map(([action]) => action),
    );
    expect([...fromFloor].sort()).toEqual([...fromOperations].sort());
    expect([...fromFloor].sort()).toEqual(["payments:payment.execute", "payments:remittance.send"]);
    for (const m of Object.values(TOOL_ACTIONS)) expect(Object.keys(payments?.actions ?? {})).toContain(m.action);
  });

  it("every action of every configured ceiling is classified, so fail-closed classification refuses no configured path", () => {
    const ceilings = [...DERIVATION_POLICY.ceiling, ...AUTHORITY_SOURCES.entries.flatMap((e) => e.ceiling)];
    for (const entry of ceilings) {
      const c = APPROVAL_FLOOR.classification.find((x) => x.type === entry.type && x.resource === entry.resource);
      expect(c, `${entry.type} at ${entry.resource}`).toBeDefined();
      for (const action of entry.actions) expect(Object.keys(c?.actions ?? {}), action).toContain(action);
    }
  });
});

describe("evaluateApprovalFloor guards the achieved context (@spec mission#approval-authentication, #826, D425)", () => {
  const t = 2_000_000_000;
  const remit = REMIT;

  it("refuses a missing or malformed achieved context", () => {
    for (const achieved of [{}, { acr: "", auth_time: t }, { acr: "mfa", auth_time: t + 0.5 }, { acr: "mfa", auth_time: "now" }, { acr: 1, auth_time: t }]) {
      expect(evaluateApprovalFloor(APPROVAL_FLOOR, remit, achieved, { interactive: true, nowSeconds: t }).outcome).toBe("refused");
    }
  });

  it("refuses an authentication time in the future", () => {
    const out = evaluateApprovalFloor(APPROVAL_FLOOR, remit, { acr: "mfa", auth_time: t + 1 }, { interactive: true, nowSeconds: t });
    expect(out).toEqual({ outcome: "refused", reason: "the Approver's authentication time is in the future" });
  });

  it("every invoked floor must hold: a second floor the same class invokes refuses what the first accepts", () => {
    const two: ApprovalFloorPolicy = {
      ...APPROVAL_FLOOR,
      floors: [
        ...APPROVAL_FLOOR.floors,
        { id: "fresh-commitments", applies_to: ["external_commitment"], approval_surface: "browser", accepted_acr: ["mfa"], max_authentication_age_seconds: 60 },
      ],
    };
    expect(evaluateApprovalFloor(two, remit, { acr: "mfa", auth_time: t - 120 }, { interactive: true, nowSeconds: t }).outcome).toBe("refused");
    expect(evaluateApprovalFloor(two, remit, { acr: "mfa", auth_time: t - 30 }, { interactive: true, nowSeconds: t })).toEqual({
      outcome: "satisfied",
      floors: ["high-risk-authority", "fresh-commitments"],
    });
  });

  it("is not applicable to low-risk authority, whatever the approval surface", () => {
    expect(evaluateApprovalFloor(APPROVAL_FLOOR, READ, {}, { interactive: false, nowSeconds: t })).toEqual({ outcome: "not_applicable" });
  });
});

describe("evaluateApprovalFloor classifies through the shared matcher (@spec mission#approval-authentication, resource-access#subset, #1440)", () => {
  const t = 2_000_000_000;
  const SERVICE = "https://erp.example.com";
  const ADMIN = `${SERVICE}/admin`;
  const policy: ApprovalFloorPolicy = {
    ...APPROVAL_FLOOR,
    classification: [
      { type: "mission_resource_access", resource: SERVICE, actions: { "erp:read": "consequential_read", "erp:close": "consequential_read" } },
      { type: "mission_resource_access", resource: ADMIN, actions: { "erp:read": "consequential_read", "erp:close": "privileged_administration" } },
    ],
  };
  const at = (resource: string, actions: string[], resource_match?: "prefix"): AuthorityEntry[] => [
    { type: "mission_resource_access", resource, ...(resource_match ? { resource_match } : {}), actions },
  ];
  const headless = { interactive: false, nowSeconds: t };

  it("an entry beneath a classified service is classified by it; a prefix entry reaching a finer classified resource meets that classification too; one no classification contains, or a sibling sharing its characters, is unclassified", () => {
    // Exact and prefix descendants of the service root: the root's low-risk class.
    expect(evaluateApprovalFloor(policy, at(`${SERVICE}/invoices/inv-1`, ["erp:read"]), {}, headless)).toEqual({ outcome: "not_applicable" });
    expect(evaluateApprovalFloor(policy, at(`${SERVICE}/invoices`, ["erp:close"], "prefix"), {}, headless)).toEqual({ outcome: "not_applicable" });
    // A prefix entry at the service root reaches the admin tree, whose class invokes the floor.
    expect(evaluateApprovalFloor(policy, at(SERVICE, ["erp:close"], "prefix"), {}, headless).outcome).toBe("refused");
    expect(evaluateApprovalFloor(policy, at(SERVICE, ["erp:close"], "prefix"), { acr: "mfa", auth_time: t - 10 }, { interactive: true, nowSeconds: t })).toEqual({
      outcome: "satisfied",
      floors: ["high-risk-authority"],
    });
    // Beneath the admin tree, the admin classification applies as well as the root's.
    expect(evaluateApprovalFloor(policy, at(`${ADMIN}/users`, ["erp:close"]), {}, headless).outcome).toBe("refused");
    // A host sharing the service's characters, and a prefix entry broader than
    // the only classification of its host, are unclassified.
    const adminOnly: ApprovalFloorPolicy = { ...policy, classification: [policy.classification[1] as ApprovalFloorPolicy["classification"][number]] };
    for (const [p, entry] of [
      [policy, at("https://erp.example.com.evil/invoices", ["erp:read"])],
      [adminOnly, at(SERVICE, ["erp:read"], "prefix")],
    ] as const) {
      const out = evaluateApprovalFloor(p, entry, {}, headless);
      expect(out.outcome, entry[0]?.resource).toBe("refused");
      expect(out.outcome === "refused" ? out.reason : "", entry[0]?.resource).toMatch(/unclassified authority is refused/);
    }
  });
});

describe("the published floor policy loads strictly (@spec mission#approval-authentication, #826, D425)", () => {
  const valid = {
    policy_id: "p",
    deployment_scope: "s",
    floors: [{ id: "f", applies_to: ["irreversible_action"], approval_surface: "browser", accepted_acr: ["mfa"], max_authentication_age_seconds: 300 }],
    classification: [{ type: "mission_resource_access", resource: "https://r.example", actions: { "a:b": "irreversible_action" } }],
  };

  it("loads a valid policy", () => {
    expect(loadApprovalFloor(JSON.stringify(valid)).floors[0]?.accepted_acr).toEqual(["mfa"]);
  });

  it.each([
    ["an unknown member", { ...valid, extra: true }],
    ["an unknown action class", { ...valid, classification: [{ ...valid.classification[0], actions: { "a:b": "risky" } }] }],
    ["an empty accepted_acr", { ...valid, floors: [{ ...valid.floors[0], accepted_acr: [] }] }],
    ["a non-positive age bound", { ...valid, floors: [{ ...valid.floors[0], max_authentication_age_seconds: 0 }] }],
    ["a second classification for one type and resource", { ...valid, classification: [valid.classification[0], valid.classification[0]] }],
    ["no floors", { ...valid, floors: [] }],
    ["a headless approval surface", { ...valid, floors: [{ ...valid.floors[0], approval_surface: "headless" }] }],
  ])("refuses %s", (_case, policy) => {
    expect(() => loadApprovalFloor(JSON.stringify(policy))).toThrow(/approval-floor\.json/);
  });

  it("refuses a duplicated member", () => {
    expect(() => loadApprovalFloor('{"policy_id":"a","policy_id":"b"}')).toThrow(/ambiguous policy/);
  });
});
