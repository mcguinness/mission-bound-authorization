/**
 * @spec derivation-limits#approval-rendering, child-delegation#subtree-rendering
 * (#2040 review: P2 and ruling 4)
 *
 * An approval consents to a delegable entry's policy-created children only
 * with that entry's per-child rule and maximum disclosed. Where the entry
 * commits a `child_creation_policy` this issuer does not hold at its digest,
 * or one stating a malformed maximum, the figure cannot be shown, and the
 * consent is refused before anything is recorded, at each standing consent
 * that renders one: the ceiling consented on the Mission approval page, the
 * Expansion successor and the ceiling it can re-consent, and the Mission
 * Template consent (refused at the proposal). Each surface also has a
 * valid-policy control, a Derivation Limits off control and recovery through
 * a fresh rendering that shows the restored rule. A rendering that could not
 * show a figure never approves it: the decision is bound to the disclosure
 * the page showed, so restoring the policy asks for a fresh rendering.
 *
 * Three deployments, on fixed ports: one whose two child creation policies
 * (on the payments read entry and the plain RS entry) are valid and held by
 * reference, so a case can withdraw and restore one; one whose plain RS
 * policy states a malformed maximum; and one with Derivation Limits off.
 */

import { type Server } from "node:http";
import { activationPolicyDigest } from "@mission/core";
import {
  AUTHORITY_SOURCES,
  CANONICAL_RESOURCE,
  DERIVATION_POLICY,
  demoReconciliationTemplate,
  DEV_SERVICE_TOKEN,
  PROGRESSIVE_PROFILE,
  TOPOLOGY,
} from "@mission/demo-data";
import { type CryptoKey, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";
import type { RegisteredActivationPolicy } from "../src/kernel/activation-policy.js";
import { assembledCeilingOffer, type CeilingConsent, progressiveFromProfile } from "../src/kernel/progressive.js";
import type { AuthorityEntry, MissionRecord } from "../src/kernel/types.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  validateMissionIntent,
} from "../src/index.js";
import {
  browserApprovalHeaders,
  floorApprovalHeaders,
  TEST_APPROVAL_PRINCIPALS,
  trustedApprovalHeaders,
} from "./approval-fixture.js";

/** The controlled clock every component here reads, installed before any import runs (D1091). */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

const PAYMENTS = CANONICAL_RESOURCE;
const PLAIN = TOPOLOGY.resources.plainRs;
const REDIRECT_URI = "http://localhost:9999/cb";
const FAR_EXP = "2027-01-01T00:00:00Z";
const PUBLISHED = progressiveFromProfile(PROGRESSIVE_PROFILE);
const A_ID = "urn:policy:review-child-a";
const B_ID = "urn:policy:review-child-b";
const snapshot = (limit: number): RegisteredActivationPolicy => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ rule: "children within the entry", derivation_limit_ceiling: limit }),
});
const A_SNAPSHOT = snapshot(3);
const B_SNAPSHOT = snapshot(4);
/** A maximum of 0 is malformed: an integer of at least 1, or null. */
const MALFORMED = snapshot(0);

const RULE = (n: number) =>
  `Each child Mission created under this consent establishes its own derivation limit from its own request, never above ${n}.`;
const CANNOT = "The per-child derivation limit cannot be shown";
const UNHELD_A = `child creation policy ${A_ID} version 1 is not one this issuer holds at its committed digest`;
const UNHELD_B = `child creation policy ${B_ID} version 1 is not one this issuer holds at its committed digest`;
const MALFORMED_B = `child creation policy ${B_ID} states a malformed derivation_limit_ceiling`;

interface Deployment {
  as: BuiltAs;
  issuer: string;
  server: Server;
  sessions: ApprovalSessionStore;
  agentKey: CryptoKey;
  /** The held activation policies, by reference: a case withdraws and restores one in place. */
  held: Record<string, RegisteredActivationPolicy>;
  /** The payments read entry and the plain RS entry, each committing its child creation policy. */
  readEntry: AuthorityEntry;
  plainEntry: AuthorityEntry;
}

async function deploy(port: number, opts: { malformedB?: boolean; derivationLimits?: boolean } = {}): Promise<Deployment> {
  const issuer = `http://localhost:${port}`;
  const bSnapshot = opts.malformedB ? MALFORMED : B_SNAPSHOT;
  const ref = (id: string, s: RegisteredActivationPolicy) => ({ id, version: "1", digest: activationPolicyDigest(issuer, s) });
  const aRef = ref(A_ID, A_SNAPSHOT);
  const bRef = ref(B_ID, bSnapshot);
  const ceiling = DERIVATION_POLICY.ceiling.map((entry, i) => {
    const e = entry as unknown as AuthorityEntry;
    if (e.resource === PAYMENTS && i === 0) {
      const children = (e.delegation as { children: Record<string, unknown> }).children;
      return { ...e, delegation: { ...e.delegation, children: { ...children, child_creation_policy: aRef } } };
    }
    if (e.resource === PLAIN) return { ...e, delegation: { max_depth: 1, children: { max_children: 2, child_creation_policy: bRef } } };
    return e;
  }) as unknown as AuthorityEntry[];
  const policy = { ...DERIVATION_POLICY, derivation_limit_ceiling: null, ceiling };
  const held: Record<string, RegisteredActivationPolicy> = { ...PUBLISHED.policies, [A_ID]: A_SNAPSHOT, [B_ID]: bSnapshot };
  const readEntry = ceiling.find((e) => e.resource === PAYMENTS && e.actions.includes("payments:invoice.read")) as AuthorityEntry;
  const plainEntry = ceiling.find((e) => e.resource === PLAIN) as AuthorityEntry;
  const offer = { authority_ceiling: [readEntry, plainEntry], drawdown_policy: { id: "drawdown-std", version: "1" } };
  const sessions = new ApprovalSessionStore();
  const as = await buildAuthorizationServer({
    issuer,
    derivationPolicy: policy as never,
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling } : e)),
    } as never,
    approvalSessions: sessions,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    activationPolicies: held,
    progressive: { ...PUBLISHED.options, ceilingOffer: () => offer },
    ...(opts.derivationLimits === false
      ? { capabilities: new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "derivation-limits")) }
      : {}),
  });
  const server = as.provider.listen(port);
  const agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  return { as, issuer, server, sessions, agentKey, held, readEntry, plainEntry };
}

let main: Deployment;
let malformed: Deployment;
let off: Deployment;

beforeAll(async () => {
  main = await deploy(15412);
  malformed = await deploy(15413, { malformedB: true });
  off = await deploy(15414, { derivationLimits: false });
});

afterAll(() => {
  for (const d of [main, malformed, off]) d?.server.close();
  controlledClock.restore();
});

/** Runs `body` with policy `id` withdrawn from `d`'s held registry, restoring it after. */
async function without<T>(d: Deployment, id: string, body: () => Promise<T>): Promise<T> {
  const kept = d.held[id] as RegisteredActivationPolicy;
  delete d.held[id];
  try {
    return await body();
  } finally {
    d.held[id] = kept;
  }
}

/** The items of every `ul.<cls>` on a page. */
function items(html: string, cls: string): string[][] {
  return [...html.matchAll(new RegExp(`<ul class="${cls}">(.*?)</ul>`, "g"))].map((list) =>
    [...(list[1] as string).matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1] as string),
  );
}
const lines = (html: string, cls: string): string[] => items(html, cls).flat();

const proposalEntry = (resource: string, actions: string[]) => ({
  type: "mission_resource_access",
  resource,
  actions,
  ...(resource === PAYMENTS ? { constraints: { vendors: ["acme"] } } : {}),
});
const intent = (d: Deployment, goal: string) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [PAYMENTS, PLAIN], expires_at: FAR_EXP }), {
    now: d.as.kernel.nowDate(),
  });

// --- The Mission approval page and its ceiling consent ---------------------

function cookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

/** PAR and /auth for a payments read Mission at `d`: the interaction and the Approver's headers on it. */
async function interaction(d: Deployment): Promise<{ uid: string; headers: Record<string, string> }> {
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(d.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(d.agentKey);
  const par = await fetch(`${d.issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: PAYMENTS,
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [PAYMENTS], expires_at: FAR_EXP } }),
      authorization_details: JSON.stringify([proposalEntry(PAYMENTS, ["payments:invoice.read"])]),
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const parBody = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(parBody)).toBe(201);
  const jar = new Map<string, string>();
  const res = await fetch(`${d.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: parBody.request_uri })}`, {
    redirect: "manual",
  });
  cookies(res, jar);
  const uid = (res.headers.get("location") as string).split("/interaction/")[1] as string;
  const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  return { uid, headers: floorApprovalHeaders(d.sessions, uid, cookie) };
}

async function renderApproval(d: Deployment, uid: string, headers: Record<string, string>) {
  const res = await fetch(`${d.issuer}/interaction/${uid}`, { headers: { cookie: headers.cookie as string } });
  const html = await res.text();
  expect(res.status, html.slice(0, 300)).toBe(200);
  return { html, revision: res.headers.get(RENDER_REVISION_HEADER) as string };
}

/**
 * The Approver's decision, consenting the offered ceiling when `ceiling`,
 * followed to its end: the refusal it asks a review with (409), or the
 * client's redirect, and the Mission the approval event committed, if any.
 */
async function decideApproval(
  d: Deployment,
  uid: string,
  headers: Record<string, string>,
  revision: string,
  ceiling: boolean,
): Promise<{ status: number; changed?: string[]; redirect?: URL; mission?: MissionRecord }> {
  const offer = assembledCeilingOffer(
    { authority_ceiling: [d.readEntry, d.plainEntry], drawdown_policy: { id: "drawdown-std", version: "1" } },
    d.as.kernel.resourceContracts(),
  ) as CeilingConsent;
  const res = await fetch(`${d.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision: revision, ...(ceiling ? offer : {}) }),
  });
  if (res.status === 409) return { status: 409, changed: ((await res.json()) as { changed?: string[] }).changed ?? [] };
  let location = res.headers.get("location");
  while (location?.startsWith(d.issuer)) {
    const next = await fetch(location, { redirect: "manual", headers: { cookie: headers.cookie as string } });
    location = next.headers.get("location");
  }
  const mission = d.as.kernel.findByApprovalEvent(`apev_${uid}`);
  return { status: res.status, ...(location ? { redirect: new URL(location) } : {}), ...(mission ? { mission } : {}) };
}

describe("the per-child disclosure of a consented ceiling gates the Mission approval (#2040 review, ruling 4; @spec derivation-limits#approval-rendering, progressive#progressive-authorization)", () => {
  it("a consented ceiling whose child creation policy is not held is refused access_denied, committing no Mission, while the same offer left unselected approves the Mission without a ceiling", async () => {
    await without(main, B_ID, async () => {
      const consented = await interaction(main);
      const page = await renderApproval(main, consented.uid, consented.headers);
      expect(lines(page.html, "ceiling-child-subtree").join(" ")).toContain(UNHELD_B);
      const refused = await decideApproval(main, consented.uid, consented.headers, page.revision, true);
      expect(refused.redirect?.searchParams.get("error")).toBe("access_denied");
      expect(refused.redirect?.searchParams.get("error_description")).toContain(UNHELD_B);
      expect(refused.mission).toBeUndefined();
      const unselected = await interaction(main);
      const shown = await renderApproval(main, unselected.uid, unselected.headers);
      const approved = await decideApproval(main, unselected.uid, unselected.headers, shown.revision, false);
      expect(approved.redirect?.searchParams.get("code")).toBeTruthy();
      expect(approved.mission?.authority_ceiling).toBeUndefined();
    });
  });

  it("a consented ceiling whose child creation policy states a malformed maximum is refused access_denied, committing no Mission", async () => {
    const { uid, headers } = await interaction(malformed);
    const page = await renderApproval(malformed, uid, headers);
    expect(lines(page.html, "ceiling-child-subtree").join(" ")).toContain(MALFORMED_B);
    const refused = await decideApproval(malformed, uid, headers, page.revision, true);
    expect(refused.redirect?.searchParams.get("error")).toBe("access_denied");
    expect(refused.redirect?.searchParams.get("error_description")).toContain(MALFORMED_B);
    expect(refused.mission).toBeUndefined();
  });

  it("a held, valid child creation policy: the page renders the rule and maximum it states for the ceiling entry, and the consent commits the Mission with the ceiling (control)", async () => {
    const { uid, headers } = await interaction(main);
    const page = await renderApproval(main, uid, headers);
    expect(lines(page.html, "ceiling-child-subtree")).toContain(RULE(4));
    const approved = await decideApproval(main, uid, headers, page.revision, true);
    expect(approved.mission?.authority_ceiling).toHaveLength(2);
  });

  it("with Derivation Limits off, a ceiling whose child creation policy is not held is consented, and no per-child rule is rendered (control)", async () => {
    await without(off, B_ID, async () => {
      const { uid, headers } = await interaction(off);
      const page = await renderApproval(off, uid, headers);
      expect(page.html).not.toContain(CANNOT);
      const approved = await decideApproval(off, uid, headers, page.revision, true);
      expect(approved.mission?.authority_ceiling).toHaveLength(2);
    });
  });

  it("a policy restored after a rendering that could not show it approves nothing on that rendering: the decision is refused approval_context_changed, committing no Mission, and a fresh rendering shows the rule and is approved", async () => {
    const { uid, headers } = await interaction(main);
    const stale = await without(main, B_ID, () => renderApproval(main, uid, headers));
    expect(lines(stale.html, "ceiling-child-subtree").join(" ")).toContain(UNHELD_B);
    const refused = await decideApproval(main, uid, headers, stale.revision, true);
    expect(refused.status).toBe(409);
    expect(refused.changed).toContain("activation_policies");
    expect(main.as.kernel.findByApprovalEvent(`apev_${uid}`)).toBeUndefined();
    const fresh = await renderApproval(main, uid, headers);
    expect(lines(fresh.html, "ceiling-child-subtree")).toContain(RULE(4));
    const approved = await decideApproval(main, uid, headers, fresh.revision, true);
    expect(approved.mission?.authority_ceiling).toHaveLength(2);
  });
});

// --- The Expansion deferral page: successor and ceiling re-consent ---------

/** A predecessor Mission on the payments read entry, with the ceiling consented when `ceiling`. */
const predecessor = (d: Deployment, ceiling = false): MissionRecord =>
  d.as.kernel.approve({
    intent: intent(d, "Read Acme invoices"),
    proposedAuthority: [proposalEntry(PAYMENTS, ["payments:invoice.read"])] as never,
    subject: { iss: d.issuer, sub: "alice" },
    approver: { iss: d.issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `pred-${crypto.randomUUID()}`,
    ...(ceiling
      ? {
          ceiling: assembledCeilingOffer(
            { authority_ceiling: [d.readEntry, d.plainEntry], drawdown_policy: { id: "drawdown-std", version: "1" } },
            d.as.kernel.resourceContracts(),
          ) as CeilingConsent,
        }
      : {}),
  });

/** A deferral widening `pred` by a separate entry: the payments list (policy A) or the plain RS read (policy B). */
const open = (d: Deployment, pred: MissionRecord, added: "list" | "plain" = "list"): string =>
  d.as.expansionDeferrals.open({
    predecessorId: pred.id,
    intent: intent(d, `Widen ${crypto.randomUUID()}`),
    proposedAuthority: [
      proposalEntry(PAYMENTS, ["payments:invoice.read"]),
      added === "list" ? proposalEntry(PAYMENTS, ["payments:invoice.list"]) : proposalEntry(PLAIN, ["reports:report.read"]),
    ] as never,
    clientId: "ap-agent",
    jkt: "jkt",
    creationRequestId: crypto.randomUUID(),
  }).deferral_code;

const HEADLESS = () => trustedApprovalHeaders("bob");

async function renderDeferral(d: Deployment, code: string) {
  const res = await fetch(`${d.issuer}/expansions/deferrals/${code}`, { headers: HEADLESS() });
  const html = await res.text();
  expect(res.status, html.slice(0, 300)).toBe(200);
  return { html, revision: res.headers.get(RENDER_REVISION_HEADER) as string };
}

async function decideDeferral(d: Deployment, code: string, revision: string, reconsent = false) {
  const res = await fetch(`${d.issuer}/expansions/deferrals/${code}/decide`, {
    method: "POST",
    headers: { ...HEADLESS(), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision: revision, ...(reconsent ? { reconsent: true } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as { error?: string; error_description?: string; changed?: string[] } };
}

const stateOf = (d: Deployment, code: string) =>
  (d.as.kernel.db.prepare("SELECT state, approval_event_id FROM expansion_deferrals WHERE deferral_code = ?").get(code) as {
    state: string;
    approval_event_id: string | null;
  });

function complete(d: Deployment, code: string): MissionRecord {
  const result = d.as.expansionDeferrals.redeem(code);
  if (!("successor" in result)) throw new Error(`completion refused: ${JSON.stringify(result)}`);
  return result.successor;
}

/** Nothing recorded: the deferral pending with no approval event, and no successor of `pred`. */
function expectNothingRecorded(d: Deployment, code: string, pred: MissionRecord): void {
  expect(stateOf(d, code)).toEqual({ state: "authorization_pending", approval_event_id: null });
  expect(d.as.kernel.allMissions().filter((m) => m.predecessor === pred.id)).toEqual([]);
}

describe("the per-child disclosure of an Expansion successor gates the decision (#2040 review, ruling 4; @spec derivation-limits#approval-rendering, expansion#completion-modes)", () => {
  it("a successor entry whose child creation policy is not held is refused access_denied, recording nothing and leaving the deferral pending", async () => {
    const pred = predecessor(main);
    const code = open(main, pred);
    await without(main, A_ID, async () => {
      const page = await renderDeferral(main, code);
      expect(lines(page.html, "child-subtree").join(" ")).toContain(UNHELD_A);
      const refused = await decideDeferral(main, code, page.revision);
      expect(refused.status).toBe(403);
      expect(refused.body.error).toBe("access_denied");
      expect(refused.body.error_description).toContain(UNHELD_A);
      expectNothingRecorded(main, code, pred);
    });
  });

  it("a successor entry whose child creation policy states a malformed maximum is refused access_denied, recording nothing and leaving the deferral pending", async () => {
    const pred = predecessor(malformed);
    const code = open(malformed, pred, "plain");
    const page = await renderDeferral(malformed, code);
    expect(lines(page.html, "child-subtree").join(" ")).toContain(MALFORMED_B);
    const refused = await decideDeferral(malformed, code, page.revision);
    expect(refused.status).toBe(403);
    expect(refused.body.error_description).toContain(MALFORMED_B);
    expectNothingRecorded(malformed, code, pred);
  });

  it("a held, valid child creation policy: the page renders the rule and maximum it states, the decision approves, and a child under the added authority records it (control)", async () => {
    const code = open(main, predecessor(main));
    const page = await renderDeferral(main, code);
    expect(lines(page.html, "child-subtree")).toContain(RULE(3));
    expect((await decideDeferral(main, code, page.revision)).status).toBe(200);
    const child = createChildMission(main.as.kernel, {
      parentId: complete(main, code).id,
      intent: intent(main, "List Acme invoices"),
      proposedAuthority: [proposalEntry(PAYMENTS, ["payments:invoice.list"])] as never,
      childActor: { sub: "subagent-invoice-extractor", sub_profile: "ai_agent" },
    }).child;
    expect(child.derivation_limit).toBe(3);
  });

  it("with Derivation Limits off, a successor whose child creation policy is not held is approved, and no per-child rule is rendered (control)", async () => {
    const pred = predecessor(off);
    const code = open(off, pred);
    await without(off, A_ID, async () => {
      const page = await renderDeferral(off, code);
      expect(page.html).not.toContain(CANNOT);
      expect((await decideDeferral(off, code, page.revision)).status).toBe(200);
      expect(stateOf(off, code).state).toBe("approved");
    });
  });

  it("a rendering that could not show the successor's rule approves nothing once the policy is restored: a decision after a refused one, and a first decision, on that rendering are refused approval_context_changed naming child_grants, the deferral stays pending, and a fresh rendering shows the rule and is approved", async () => {
    const pred = predecessor(main);
    // After a refused decision on the rendering.
    const refusedFirst = open(main, pred);
    const stale = await without(main, A_ID, async () => {
      const page = await renderDeferral(main, refusedFirst);
      expect(lines(page.html, "child-subtree").join(" ")).toContain(UNHELD_A);
      expect((await decideDeferral(main, refusedFirst, page.revision)).status).toBe(403);
      return page;
    });
    const again = await decideDeferral(main, refusedFirst, stale.revision);
    expect(again.status).toBe(409);
    expect(again.body.changed).toContain("child_grants");
    expectNothingRecorded(main, refusedFirst, pred);
    // Restored before the first decision on the rendering.
    const decidedFirst = open(main, pred);
    const unseen = await without(main, A_ID, () => renderDeferral(main, decidedFirst));
    const first = await decideDeferral(main, decidedFirst, unseen.revision);
    expect(first.status).toBe(409);
    expect(first.body.error).toBe("approval_context_changed");
    expect(first.body.changed).toContain("child_grants");
    expectNothingRecorded(main, decidedFirst, pred);
    // Recovery: a fresh rendering shows the restored rule and is approved.
    const fresh = await renderDeferral(main, decidedFirst);
    expect(lines(fresh.html, "child-subtree")).toContain(RULE(3));
    expect((await decideDeferral(main, decidedFirst, fresh.revision)).status).toBe(200);
    expect(stateOf(main, decidedFirst).state).toBe("approved");
  });
});

describe("the per-child disclosure of an Expansion's ceiling re-consent gates the re-consent (#2040 review, ruling 4; @spec derivation-limits#approval-rendering, progressive#ceiling-reconsent)", () => {
  it("a re-consent of a ceiling whose child creation policy is not held is refused access_denied, recording nothing, while the same deferral approved without re-consenting completes with the predecessor's ceiling unchanged", async () => {
    const pred = predecessor(main, true);
    const code = open(main, pred);
    await without(main, B_ID, async () => {
      const page = await renderDeferral(main, code);
      expect(lines(page.html, "reconsent-child-subtree").join(" ")).toContain(UNHELD_B);
      expect(lines(page.html, "child-subtree").join(" ")).not.toContain(CANNOT);
      const refused = await decideDeferral(main, code, page.revision, true);
      expect(refused.status).toBe(403);
      expect(refused.body.error_description).toContain(UNHELD_B);
      expectNothingRecorded(main, code, pred);
      expect((await decideDeferral(main, code, page.revision, false)).status).toBe(200);
    });
    const successor = complete(main, code);
    expect(successor.ceiling_hash).toBe(pred.ceiling_hash);
    expect(successor.ceiling_consented_at).toBe(pred.ceiling_consented_at);
  });

  it("a re-consent of a ceiling whose child creation policy states a malformed maximum is refused access_denied, recording nothing", async () => {
    const pred = predecessor(malformed, true);
    const code = open(malformed, pred);
    const page = await renderDeferral(malformed, code);
    expect(lines(page.html, "reconsent-child-subtree").join(" ")).toContain(MALFORMED_B);
    const refused = await decideDeferral(malformed, code, page.revision, true);
    expect(refused.status).toBe(403);
    expect(refused.body.error_description).toContain(MALFORMED_B);
    expectNothingRecorded(malformed, code, pred);
  });

  it("a held, valid child creation policy: the re-consent block renders the rule and maximum it states, and the re-consent is recorded with the successor's ceiling (control)", async () => {
    const pred = predecessor(main, true);
    const code = open(main, pred);
    const page = await renderDeferral(main, code);
    expect(lines(page.html, "reconsent-child-subtree")).toContain(RULE(4));
    expect((await decideDeferral(main, code, page.revision, true)).status).toBe(200);
    const successor = complete(main, code);
    expect(Date.parse(successor.ceiling_consented_at as string)).toBeGreaterThan(Date.parse(pred.ceiling_consented_at as string));
  });

  it("with Derivation Limits off, a re-consent of a ceiling whose child creation policy is not held is recorded, and no per-child rule is rendered (control)", async () => {
    const pred = predecessor(off, true);
    const code = open(off, pred);
    await without(off, B_ID, async () => {
      const page = await renderDeferral(off, code);
      expect(page.html).not.toContain(CANNOT);
      expect((await decideDeferral(off, code, page.revision, true)).status).toBe(200);
    });
    expect(Date.parse(complete(off, code).ceiling_consented_at as string)).toBeGreaterThan(
      Date.parse(pred.ceiling_consented_at as string),
    );
  });

  it("a rendering that could not show the re-consent's rule approves no re-consent once the policy is restored: the decision on that rendering is refused approval_context_changed naming child_grants, and a fresh rendering shows the rule and is re-consented", async () => {
    const pred = predecessor(main, true);
    const code = open(main, pred);
    const stale = await without(main, B_ID, () => renderDeferral(main, code));
    expect(lines(stale.html, "reconsent-child-subtree").join(" ")).toContain(UNHELD_B);
    const refused = await decideDeferral(main, code, stale.revision, true);
    expect(refused.status).toBe(409);
    expect(refused.body.changed).toContain("child_grants");
    expectNothingRecorded(main, code, pred);
    const fresh = await renderDeferral(main, code);
    expect(lines(fresh.html, "reconsent-child-subtree")).toContain(RULE(4));
    expect((await decideDeferral(main, code, fresh.revision, true)).status).toBe(200);
  });
});

// --- The Mission Template consent -------------------------------------------

/** The demo template body, its ceiling the one delegable entry given. */
function templateBody(d: Deployment, entry: AuthorityEntry, actions: string[]): Record<string, unknown> {
  const { approver: _a, approval_event_id: _e, issuer: _i, ...body } = demoReconciliationTemplate(d.issuer);
  return { ...body, ceiling: [{ ...entry, actions }] };
}

async function propose(d: Deployment, body: Record<string, unknown>) {
  const res = await fetch(`${d.issuer}/templates/proposals`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as { proposal_id?: string; error?: string; error_description?: string } };
}

const loggedIn = (d: Deployment, id: string) => browserApprovalHeaders(d.sessions, id, { sub: "bob" }, "");
const templatePage = async (d: Deployment, id: string) =>
  (await fetch(`${d.issuer}/templates/proposals/${id}`, { headers: { cookie: loggedIn(d, id).cookie as string } })).text();
const decideTemplate = (d: Deployment, id: string) =>
  fetch(`${d.issuer}/templates/proposals/${id}/decide`, {
    method: "POST",
    headers: { "content-type": "application/json", ...loggedIn(d, id) },
    body: JSON.stringify({ decision: "approve" }),
  });

describe("the per-child disclosure of a delegable Template Ceiling entry gates the template consent (#2040 review, ruling 4; @spec derivation-limits#approval-rendering, mission-template#template-consent)", () => {
  const READ = ["payments:invoice.read"];

  it("a proposal whose delegable ceiling entry commits a child creation policy not held is refused at the proposal, creating no proposal; once held, the same body is proposed and its page renders the rule", async () => {
    const before = main.as.templateStore.db.prepare("SELECT COUNT(*) AS n FROM templates").get();
    const refused = await without(main, A_ID, () => propose(main, templateBody(main, main.readEntry, READ)));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.error_description).toContain(UNHELD_A);
    expect(refused.body.proposal_id).toBeUndefined();
    expect(main.as.templateStore.db.prepare("SELECT COUNT(*) AS n FROM templates").get()).toEqual(before);
    const accepted = await propose(main, templateBody(main, main.readEntry, READ));
    expect(accepted.status).toBe(201);
    expect(lines(await templatePage(main, accepted.body.proposal_id as string), "template-child-subtree")).toContain(RULE(3));
  });

  it("a proposal whose delegable ceiling entry commits a child creation policy stating a malformed maximum is refused at the proposal", async () => {
    const refused = await propose(malformed, templateBody(malformed, malformed.plainEntry, ["reports:report.read"]));
    expect(refused.status).toBe(400);
    expect(refused.body.error_description).toContain(MALFORMED_B);
  });

  it("a policy withdrawn after the proposal refuses the page and the decision, creating no template and keeping the proposal pending; restored, a fresh rendering shows the rule and the consent is approved", async () => {
    const { body } = await propose(main, templateBody(main, main.readEntry, READ));
    const id = body.proposal_id as string;
    await without(main, A_ID, async () => {
      const html = await templatePage(main, id);
      expect(html).toContain(UNHELD_A);
      expect(html).not.toContain("<form");
      const refused = await decideTemplate(main, id);
      expect(refused.status).toBe(403);
      expect(main.as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeUndefined();
    });
    expect(lines(await templatePage(main, id), "template-child-subtree")).toContain(RULE(3));
    const approved = await decideTemplate(main, id);
    expect(approved.status).toBe(201);
    expect(main.as.templateStore.getByApprovalEvent(`apev_${id}`)).toBeDefined();
  });

  it("a held, valid child creation policy: the page renders the rule and maximum it states, and the consent creates the template (control)", async () => {
    const { body } = await propose(main, templateBody(main, main.readEntry, READ));
    const id = body.proposal_id as string;
    expect(lines(await templatePage(main, id), "template-child-subtree")).toContain(RULE(3));
    expect((await decideTemplate(main, id)).status).toBe(201);
  });

  it("with Derivation Limits off, a proposal whose child creation policy is not held is accepted and consented, rendering no per-child rule (control)", async () => {
    await without(off, A_ID, async () => {
      const { status, body } = await propose(off, templateBody(off, off.readEntry, READ));
      expect(status).toBe(201);
      const id = body.proposal_id as string;
      expect(await templatePage(off, id)).not.toContain(CANNOT);
      expect((await decideTemplate(off, id)).status).toBe(201);
    });
  });
});
