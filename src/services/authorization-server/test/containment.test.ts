/**
 * Mission Containment: the issuer-held, versioned, MONOTONIC narrowing overlay
 * on an active Mission's effective authority. Covered here:
 *   - monotonic union of contained entries + event_id idempotency (a repeat
 *     returns the current record: no version bump, no extra event row);
 *   - the metadata-only commit (version n+1, prior_state === state) rides the
 *     existing lifecycle-commit fan-out: the Status List republishes with the
 *     bit unchanged for an active Mission;
 *   - authority_hash is byte-identical before/after while signedStatus omits
 *     the contained entry and carries containment_version; introspectionMission
 *     carries it only when containment exists (absent-means-none);
 *   - derivation draws on the EFFECTIVE set: a mint after containment omits the
 *     contained capability; a fully contained Mission refuses with GateError
 *     authority_contained;
 *   - the delegation surfaces are bound to the effective set: child creation
 *     (not_strict_subset), the cross-domain audience-scoped grant, and the
 *     attenuation root mapping all exclude contained capability;
 *   - terminal-state contain refused (409 on the wire); suspended permitted;
 *   - the lifecycle endpoint's operation: "contain" end-to-end via the dev
 *     service token.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { decodeJwt, generateKeyPair, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  ChildDelegationError,
  CONTAINMENT_EVIDENCE_MEDIA_TYPE,
  containmentEvidenceBytes,
  createChildMission,
  deriveAttenuationRoot,
  GateError,
  issueCrossDomainGrant,
  type LifecycleCommit,
  LifecycleConflictError,
  MissionKernel,
  mintChildGrant,
  readStatusBit,
  STATUS_VALID,
  StatusListPublisher,
  statusListUri,
  validateMissionIntent,
  verifyStatusListToken,
} from "../src/index.js";

const ISS = "https://as.containment.test";
const RES_PAY = "https://payments.test/mcp";
const RES_FILE = "https://files.test/mcp";
const NOW = new Date("2026-08-06T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

/** RES_PAY is delegable (child-creation on-switch); RES_FILE is plain. */
const POLICY = {
  policy_version: "containment-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RES_PAY,
      actions: ["payments:invoice.read", "payments:payment.execute"],
      delegation: { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } },
    },
    { type: "mission_resource_access", resource: RES_FILE, actions: ["files:doc.read"] },
  ],
};

const intent = (over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Pay Acme invoices for Q3",
      resources: [RES_PAY, RES_FILE],
      expires_at: EXPIRES_AT,
      ...over,
    }),
  );

const ev = (id: string) => ({
  type: "anomaly.detected",
  source: "svc:soc",
  observed_at: NOW.toISOString(),
  event_id: id,
});

let statusKeys: { privateKey: CryptoKey; publicKey: CryptoKey };

interface Harness {
  kernel: MissionKernel;
  commits: LifecycleCommit[];
  publisher: StatusListPublisher;
  dirtyMarks: () => number;
}

function makeHarness(): Harness {
  const commits: LifecycleCommit[] = [];
  let marks = 0;
  let publisher: StatusListPublisher | undefined;
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: POLICY as never,
    statusKey: statusKeys.privateKey,
    statusKid: "as-status",
    now: () => NOW,
    onLifecycleCommit: (c) => {
      commits.push(c);
      marks++;
      publisher?.markDirty();
    },
  });
  publisher = new StatusListPublisher(() => kernel.publishStatusList());
  return { kernel, commits, publisher, dirtyMarks: () => marks };
}

let seq = 0;
const approve = (kernel: MissionKernel, over: Record<string, unknown> = {}) =>
  kernel.approve({
    intent: intent(over),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-cnt-${++seq}`,
  });

beforeAll(async () => {
  statusKeys = await generateKeyPair("ES256", { extractable: true });
});

describe("contain(): monotonic union + event_id idempotency", () => {
  it("unions removals across events; a repeated event_id is a no-op", () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    expect(m.containment).toBeUndefined(); // a fresh mission has none

    const r1 = kernel.contain(m.id, {
      event: ev("evt-1"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    expect(r1.record.version).toBe(2);
    expect(r1.record.containment?.containment_version).toBe(1);
    expect(r1.record.containment?.contained).toEqual([
      { resource: RES_PAY, actions: ["payments:payment.execute"] },
    ]);
    expect(r1.record.containment?.events).toHaveLength(1);
    expect(r1.evidence).toMatchObject({
      mission: { id: m.id, issuer: ISS, authority_hash: m.authority_hash },
      policy: "containment-v1",
      prior_version: 1,
      new_version: 2,
      prior_containment_version: 0,
      new_containment_version: 1,
      removed: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    // Evidence conventions: JCS canonical bytes round-trip; the media type.
    expect(JSON.parse(containmentEvidenceBytes(r1.evidence))).toEqual(
      JSON.parse(JSON.stringify(r1.evidence)),
    );
    expect(CONTAINMENT_EVIDENCE_MEDIA_TYPE).toBe("application/mission-containment-evidence+json");

    // Second event: per-action union on RES_PAY plus a whole-resource removal.
    const r2 = kernel.contain(m.id, {
      event: ev("evt-2"),
      remove: [{ resource: RES_PAY, actions: ["payments:invoice.read"] }, { resource: RES_FILE }],
    });
    expect(r2.record.version).toBe(3);
    expect(r2.record.containment?.containment_version).toBe(2);
    const contained = r2.record.containment?.contained ?? [];
    expect(contained.find((c) => c.resource === RES_PAY)?.actions?.sort()).toEqual([
      "payments:invoice.read",
      "payments:payment.execute",
    ]);
    expect(contained.find((c) => c.resource === RES_FILE)).toEqual({ resource: RES_FILE });
    expect(r2.record.containment?.events).toHaveLength(2);

    // Idempotent repeat of evt-1: current record, no version bump, no event row.
    const r3 = kernel.contain(m.id, { event: ev("evt-1"), remove: [{ resource: RES_FILE }] });
    expect(r3.record.version).toBe(3);
    expect(r3.record.containment?.containment_version).toBe(2);
    expect(r3.record.containment?.events).toHaveLength(2);
    expect(r3.evidence.prior_version).toBe(r3.evidence.new_version);
    expect(r3.evidence.prior_containment_version).toBe(r3.evidence.new_containment_version);
  });
});

describe("the metadata-only commit rides the lifecycle fan-out", () => {
  it("emits version n+1 with prior_state === state and republishes the Status List (bit unchanged)", async () => {
    const { kernel, commits, publisher, dirtyMarks } = makeHarness();
    const m = approve(kernel);
    const idx = kernel.participateInStatusList(m.id);
    await publisher.current(); // publish once, clearing the dirty flag
    const marksBefore = dirtyMarks();

    kernel.contain(m.id, {
      event: ev("evt-commit"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });

    const last = commits.at(-1);
    expect(last).toMatchObject({
      id: m.id,
      issuer: ISS,
      state: "active",
      prior_state: "active",
      version: 2,
      expires_at: EXPIRES_AT,
    });
    // The commit marked the publisher dirty: the next fetch is a regeneration.
    expect(dirtyMarks()).toBe(marksBefore + 1);
    const tok = await verifyStatusListToken(await publisher.current(), statusKeys.publicKey, {
      uri: statusListUri(ISS),
      now: NOW,
    });
    // Containment does not change lifecycle state: the bit stays VALID.
    expect(readStatusBit(tok, idx)).toBe(STATUS_VALID);
  });
});

describe("authority_hash immutability + projections", () => {
  it("keeps authority_hash byte-identical while signedStatus omits the contained entry and carries containment_version", async () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    const hashBefore = m.authority_hash;

    kernel.contain(m.id, { event: ev("evt-hash"), remove: [{ resource: RES_FILE }] });
    const fresh = kernel.get(m.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    expect(fresh.authority_hash).toBe(hashBefore); // immutable approval anchor

    // The contained entry is omitted from the audience-scoped Status surface.
    const jwsFile = await kernel.signedStatus(m.id, { audience: RES_FILE, requester: "svc:test" });
    const { payload: pFile } = await jwtVerify(jwsFile, statusKeys.publicKey, {
      issuer: ISS,
      audience: RES_FILE,
      currentDate: NOW,
    });
    expect(pFile.authorization_details).toEqual([]);
    expect((pFile.mission as { containment_version?: number }).containment_version).toBe(1);
    expect((pFile.mission as { authority_hash: string }).authority_hash).toBe(hashBefore);

    // An uncontained resource still projects, minus nothing.
    const jwsPay = await kernel.signedStatus(m.id, { audience: RES_PAY, requester: "svc:test" });
    const { payload: pPay } = await jwtVerify(jwsPay, statusKeys.publicKey, {
      issuer: ISS,
      audience: RES_PAY,
      currentDate: NOW,
    });
    expect((pPay.authorization_details as AuthorityEntry[])).toHaveLength(1);

    // Introspection carries containment_version; absent means none.
    expect(kernel.introspectionMission(fresh).containment_version).toBe(1);
    const m2 = approve(kernel);
    expect("containment_version" in kernel.introspectionMission(m2)).toBe(false);
  });
});

describe("derivation over the effective set", () => {
  it("a mint after containment omits the contained capability from authorization_details", async () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({ resources: [RES_PAY] }),
      childActor: { sub: "subagent", sub_profile: "ai_agent" },
    });
    kernel.contain(child.id, {
      event: ev("evt-child-mint"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    const contained = kernel.get(child.id) as NonNullable<ReturnType<MissionKernel["get"]>>;
    const { assertion } = await mintChildGrant(
      kernel,
      { key: statusKeys.privateKey, kid: "as-status", alg: "ES256" },
      { child: contained, tokenEndpoint: `${ISS}/token` },
    );
    const details = decodeJwt(assertion).authorization_details as AuthorityEntry[];
    expect(details).toHaveLength(1);
    expect(details[0]?.resource).toBe(RES_PAY);
    expect(details[0]?.actions).toEqual(["payments:invoice.read"]);
    // The assertion still commits the child's APPROVED set.
    expect((decodeJwt(assertion).mission as { authority_hash: string }).authority_hash).toBe(
      contained.authority_hash,
    );
  });

  it("a fully contained mission refuses derivation with GateError authority_contained", () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    kernel.contain(m.id, {
      event: ev("evt-full"),
      remove: [{ resource: RES_PAY }, { resource: RES_FILE }],
    });
    expect(kernel.effectiveAuthoritySet(kernel.get(m.id) as never)).toEqual([]);
    try {
      kernel.gateDerivation(m.id);
      expect.unreachable("gateDerivation must refuse a fully contained mission");
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("authority_contained");
    }
  });
});

describe("delegation surfaces bound to the effective set", () => {
  it("refuses a child whose intent needs the contained capability (not_strict_subset)", () => {
    const { kernel } = makeHarness();
    const parent = approve(kernel);
    kernel.contain(parent.id, {
      event: ev("evt-deleg"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }],
    });
    try {
      createChildMission(kernel, {
        parentId: parent.id,
        intent: intent({
          resources: [RES_PAY],
          proposed_authority: [
            {
              type: "mission_resource_access",
              resource: RES_PAY,
              actions: ["payments:payment.execute"],
            },
          ],
        }),
        childActor: { sub: "subagent", sub_profile: "ai_agent" },
      });
      expect.unreachable("child needing the contained capability must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
    }
    // A child within the effective set is still creatable.
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({
        resources: [RES_PAY],
        proposed_authority: [
          { type: "mission_resource_access", resource: RES_PAY, actions: ["payments:invoice.read"] },
        ],
      }),
      childActor: { sub: "subagent", sub_profile: "ai_agent" },
    });
    expect(child.authority_set[0]?.actions).toEqual(["payments:invoice.read"]);
  });

  it("excludes contained capability from the cross-domain audience-scoped set and the attenuation root", async () => {
    const { kernel } = makeHarness();
    const m = approve(kernel);
    kernel.contain(m.id, {
      event: ev("evt-surfaces"),
      remove: [{ resource: RES_PAY, actions: ["payments:payment.execute"] }, { resource: RES_FILE }],
    });

    const { audienceScoped } = await issueCrossDomainGrant(kernel, statusKeys.privateKey, "as-status", {
      missionId: m.id,
      targetAs: ISS,
      clientId: "ap-agent",
      cnfJkt: "test-jkt",
      resourceToAs: () => ISS,
    });
    expect(audienceScoped).toHaveLength(1);
    expect(audienceScoped[0]?.resource).toBe(RES_PAY);
    expect(audienceScoped[0]?.actions).toEqual(["payments:invoice.read"]);

    const { tools } = await deriveAttenuationRoot(kernel, statusKeys.privateKey, "as-status", {
      missionId: m.id,
      aud: RES_PAY,
      clientId: "ap-agent",
      cnfJkt: "test-jkt",
      delMaxDepth: 0,
    });
    expect(Object.keys(tools)).toEqual([`${RES_PAY}#payments:invoice.read`]);
  });
});

describe("contain legality by lifecycle state", () => {
  it("refuses a terminal-state contain; permits a suspended-state contain", () => {
    const { kernel, commits } = makeHarness();
    const revoked = approve(kernel);
    kernel.transition(revoked.id, "revoke");
    expect(() =>
      kernel.contain(revoked.id, { event: ev("evt-term"), remove: [{ resource: RES_FILE }] }),
    ).toThrow(LifecycleConflictError);

    const held = approve(kernel);
    kernel.transition(held.id, "suspend");
    const { record } = kernel.contain(held.id, {
      event: ev("evt-susp"),
      remove: [{ resource: RES_FILE }],
    });
    expect(record.state).toBe("suspended");
    expect(record.version).toBe(3); // approve v1, suspend v2, contain v3
    expect(record.containment?.containment_version).toBe(1);
    expect(commits.at(-1)).toMatchObject({
      id: held.id,
      state: "suspended",
      prior_state: "suspended",
      version: 3,
    });
  });
});

describe("lifecycle endpoint operation: contain (end-to-end)", () => {
  const PORT = 14490;
  const ISSUER = `http://localhost:${PORT}`;
  let as: BuiltAs;
  let server: Server;

  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    server = as.provider.listen(PORT);
  });
  afterAll(() => {
    server?.close();
  });

  const lifecycle = (missionId: string, body: unknown, token: string | null = DEV_SERVICE_TOKEN) =>
    fetch(`${ISSUER}/missions/${missionId}/lifecycle`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token !== null ? { "x-service-token": token } : {}),
      },
      body: JSON.stringify(body),
    });

  it("contains via the dev service token, idempotently, and 409s from a terminal state", async () => {
    const record = as.kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices for Q3",
          resources: [CANONICAL_RESOURCE],
          expires_at: EXPIRES_AT,
        }),
      ),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-cnt-e2e-1",
    });
    const containBody = {
      operation: "contain",
      event: ev("evt-e2e-1"),
      remove: [{ resource: CANONICAL_RESOURCE, actions: ["payments:payment.schedule"] }],
    };

    // The same dev service-token guard as the other lifecycle operations.
    expect((await lifecycle(record.id, containBody, null)).status).toBe(401);
    // A malformed contain (no event/remove) is refused.
    expect((await lifecycle(record.id, { operation: "contain" })).status).toBe(400);

    const res = await lifecycle(record.id, containBody);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      id: record.id,
      state: "active",
      version: 2,
      containment_version: 1,
    });

    // Idempotent repeat by event_id: no version bump.
    const repeat = await lifecycle(record.id, containBody);
    expect(repeat.status).toBe(200);
    expect(await repeat.json()).toEqual({
      id: record.id,
      state: "active",
      version: 2,
      containment_version: 1,
    });

    // Terminal state: contain conflicts (mirrors the other operations' 409).
    expect((await lifecycle(record.id, { operation: "revoke" })).status).toBe(200);
    const conflict = await lifecycle(record.id, {
      ...containBody,
      event: ev("evt-e2e-2"),
    });
    expect(conflict.status).toBe(409);
    expect(((await conflict.json()) as { error: string }).error).toBe("conflict");
  });
});
