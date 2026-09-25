/**
 * @spec draft-mcguinness-oauth-mission-signals (#lifecycle-event),
 * draft-mcguinness-oauth-mission-child-delegation (#carryover-evidence)
 *
 * A Child Mission Carryover cascade is an ordinary terminal commit that
 * additionally carries `carried_to`, the committed replacement Mission
 * identifier. This drives the REAL carryover completion transaction through a
 * real kernel wired to the emitter, captures the DELIVERED SET bytes from the
 * emission path (never a hand-built payload), and asserts the correlation is on
 * the carried child's `cascaded` event and absent from an excluded child's.
 *
 * In-process and deterministic, mirroring the containment-commit harness.
 */

import {
  type CarryoverConfig,
  createChildMission,
  ExpansionDeferralStore,
  type LifecycleCommit,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { decodeJwt, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { LIFECYCLE_CHANGE_EVENT_URI, MissionSignalEmitter } from "../src/index.js";

const ISS = "https://as.test";
const CONSUMER_AUD = "https://erp.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const LEDGER = "https://ledger.test/mcp";
const NOW = new Date("2026-08-06T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";

const POLICY = {
  policy_version: "carryover-signal-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:invoice.list"],
      delegation: {
        max_depth: 2,
        children: {
          max_children: 5,
          max_child_depth: 2,
          allowed_child_actors: [{ sub: "child-a" }, { sub: "child-b" }],
        },
      },
    },
    { type: "mission_resource_access", resource: LEDGER, actions: ["ledger:vendor.read"] },
  ],
};

const CARRYOVER: CarryoverConfig = {
  enabled: true,
  maxRows: null,
  exclusionPolicy: { mode: "all_or_nothing" },
  noApplicableExternalState: true,
};

const intentFor = (resources: string[]) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Read approved invoices",
      target_resources: resources,
      expires_at: EXPIRES_AT,
    }),
  );

/** The lifecycle-change event body of one delivered SET. */
const eventOf = (set: string): Record<string, unknown> =>
  (decodeJwt(set).events as Record<string, Record<string, unknown>>)[
    LIFECYCLE_CHANGE_EVENT_URI
  ] as Record<string, unknown>;

describe("carryover cascade propagated by Mission Signals", () => {
  it("delivers carried_to on the carried child's cascaded SET and omits it on an excluded child's", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const emitter = new MissionSignalEmitter({
      key: statusKeys.privateKey,
      kid: "as-status",
      consumers: [{ audience: CONSUMER_AUD }],
    });
    const delivered: string[] = [];
    emitter.onDeliver(CONSUMER_AUD, (set) => delivered.push(set));

    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      onLifecycleCommit: (c) => {
        commits.push(c);
        emitter.onCommit(c);
      },
    });

    const predecessor = kernel.approve({
      intent: intentFor([RESOURCE]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-carryover-signal-1",
    });
    const addChild = (actor: string) =>
      createChildMission(kernel, {
        parentId: predecessor.id,
        intent: intentFor([RESOURCE]),
        childActor: { sub: actor },
      }).child;
    const carried = addChild("child-a");
    const excluded = addChild("child-b");
    // A suspended child is excluded by carryover, never resumed: its cascade
    // carries no replacement, so the correlation MUST be absent from its event.
    kernel.transition(excluded.id, "suspend");
    await emitter.drain();
    delivered.length = 0;

    const store = new ExpansionDeferralStore(kernel, () => NOW, CARRYOVER);
    const pending = store.open({
      predecessorId: predecessor.id,
      intent: intentFor([RESOURCE, LEDGER]),
      clientId: "ap-agent",
      jkt: "jkt-signal",
      creationRequestId: "crid-carryover-signal-1",
    });
    store.approve(pending.deferral_code, {
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: "xapev-carryover-signal-1",
      approvedUntil: EXPIRES_AT,
    });
    const out = store.redeem(pending.deferral_code);
    expect("error" in out).toBe(false);
    if ("error" in out) return;
    await emitter.drain();

    const replacementId = (kernel.get(carried.id) as MissionRecord).carried_to as string;
    expect(replacementId).toBeDefined();

    // The DELIVERED SET for the carried child: an ordinary `cascaded` event
    // that additionally carries the committed replacement identifier.
    const carriedSets = delivered.filter((set) => {
      const event = eventOf(set);
      return (event.mission as { id: string }).id === carried.id && event.state === "cascaded";
    });
    expect(carriedSets).toHaveLength(1);
    const carriedEvent = eventOf(carriedSets[0] as string);
    expect(carriedEvent.carried_to).toBe(replacementId);
    expect(carriedEvent.prior_state).toBe("active");
    expect(decodeJwt(carriedSets[0] as string).iss).toBe(ISS);

    // The excluded child's SET carries the same state and NO correlation.
    const excludedSets = delivered.filter((set) => {
      const event = eventOf(set);
      return (event.mission as { id: string }).id === excluded.id && event.state === "cascaded";
    });
    expect(excludedSets).toHaveLength(1);
    const excludedEvent = eventOf(excludedSets[0] as string);
    expect(excludedEvent.carried_to).toBeUndefined();
    expect(excludedEvent.prior_state).toBe("suspended");

    // The replacement's own activation event is an ordinary creation event: it
    // carries no correlation member, so a consumer pairs through the batch map
    // rather than reading authority off either pointer.
    const replacementSets = delivered.filter(
      (set) => (eventOf(set).mission as { id: string }).id === replacementId,
    );
    expect(replacementSets).toHaveLength(1);
    expect(eventOf(replacementSets[0] as string).state).toBe("active");
    expect(eventOf(replacementSets[0] as string).carried_to).toBeUndefined();
  });
});
