/**
 * @spec draft-mcguinness-oauth-mission-signals, child-delegation#child-state
 *
 * The suspend->resume RESTORE is the one lifecycle commit shaped like a revive
 * (`suspended` -> `active`). This proves the Mission Signals anti-revive guard
 * does NOT reject it: acceptance is VERSION-based (strict forward progress), not
 * state-based, so the restore lift of a projected Child Mission is applied and
 * the Status List reads back the restored state. In-process, deterministic (no
 * HTTP, no OpenFGA): a real kernel fires its lifecycle-commit hook into a
 * MissionSignalEmitter that hands SETs to a MissionSignalReceiver.
 */

import {
  createChildMission,
  type LifecycleCommit,
  MissionKernel,
  readStatusBit,
  STATUS_SUSPENDED,
  STATUS_VALID,
  statusListUri,
  validateMissionIntent,
  verifyStatusListToken,
} from "@mission/authorization-server";
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  type ApplyResult,
  MissionSignalEmitter,
  MissionSignalReceiver,
  signLifecycleEvent,
} from "../src/index.js";

const ISS = "https://as.test";
const CONSUMER_AUD = "https://erp.consumer.test";
const RESOURCE = "https://payments.test/mcp";
const NOW = new Date("2026-08-02T12:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const URI = statusListUri(ISS);

/** A delegable ceiling: the child entry INHERITS `delegation.children` when the
 *  parent proposal omits it (derive.ts carry rule), so a child is creatable. */
const POLICY = {
  policy_version: "suspend-lift-v1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
      delegation: {
        max_depth: 2,
        // Explicit child-actor eligibility (fail-closed matcher): the child actor
        // below is an AS-asserted ai_agent (kernel actorProfiles).
        children: {
          max_children: 5,
          max_child_depth: 2,
          allowed_child_actors: [{ sub_profile: "ai_agent" }],
        },
      },
    },
  ],
};

const intent = (actions: string[]) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Read approved invoices",
      resources: [RESOURCE],
      expires_at: EXPIRES_AT,
      proposed_authority: [{ type: "mission_resource_access", resource: RESOURCE, actions }],
    }),
  );

describe("suspend->resume lift accepted by the Signal receiver (@spec child-delegation#child-state)", () => {
  it("applies a projected child's suspended->active restore lift and the Status List reads back the restored state", async () => {
    const statusKeys = await generateKeyPair("ES256", { extractable: true });
    const statusPub = {
      ...(await exportJWK(statusKeys.publicKey)),
      kid: "as-status",
      alg: "ES256",
      use: "sig",
    };

    const emitter = new MissionSignalEmitter({
      key: statusKeys.privateKey,
      kid: "as-status",
      consumers: [{ audience: CONSUMER_AUD }],
    });
    const receiver = new MissionSignalReceiver({
      jwks: { keys: [statusPub] },
      issuer: ISS,
      audience: CONSUMER_AUD,
    });
    emitter.register(receiver); // the wired path: exactly one delivery per SET

    const commits: LifecycleCommit[] = [];
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: POLICY as never,
      statusKey: statusKeys.privateKey,
      statusKid: "as-status",
      now: () => NOW,
      // The child actor is an AS-asserted ai_agent (config-driven in production).
      actorProfiles: { subagent: "ai_agent" },
      onLifecycleCommit: (c) => {
        commits.push(c);
        emitter.onCommit(c);
      },
    });

    const parent = kernel.approve({
      intent: intent(["payments:invoice.read", "payments:payment.execute"]),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "parent-agent",
      approvalEventId: "apev-lift-1",
    });
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent(["payments:invoice.read"]),
      childActor: { sub: "subagent", sub_profile: "ai_agent" },
    });

    // Enroll the child while ACTIVE (enrollment refuses a non-active Mission), so
    // the readback below sees its published bit.
    const idx = kernel.participateInStatusList(child.id);

    // Suspend the parent: the child is projected to `suspended` (commit v2).
    kernel.transition(parent.id, "suspend");
    await emitter.drain();
    const suspendedTok = await verifyStatusListToken(
      await kernel.publishStatusList(),
      statusKeys.publicKey,
      { uri: URI, now: NOW },
    );
    expect(readStatusBit(suspendedTok, idx)).toBe(STATUS_SUSPENDED);

    // Resume the parent: the child is restored to `active` (commit v3 -- the LIFT).
    kernel.transition(parent.id, "resume");
    await emitter.drain();

    // The wired receiver ACCEPTED the suspended->active lift: its view is active/v3,
    // not stuck at suspended/v2 (which a rejected lift would leave). v3 applying
    // last also clears any transient gap from concurrent v1/v2 signing.
    expect(receiver.viewState(child.id)).toMatchObject({ state: "active", version: 3 });
    expect(receiver.hasGap(child.id)).toBe(false);

    // The Status List reads back the RESTORED state.
    const resumedTok = await verifyStatusListToken(
      await kernel.publishStatusList(),
      statusKeys.publicKey,
      { uri: URI, now: NOW },
    );
    expect(readStatusBit(resumedTok, idx)).toBe(STATUS_VALID);

    // Explicit anti-revive proof on a FRESH receiver fed the child's own ordered
    // commit sequence: v2 (suspended) and v3 (active) BOTH apply -- the lift is
    // not `stale`, because the version strictly increments (forward progress).
    const childCommits = commits.filter((c) => c.id === child.id);
    expect(childCommits.map((c) => [c.state, c.version])).toEqual([
      ["active", 1],
      ["suspended", 2],
      ["active", 3],
    ]);
    const fresh = new MissionSignalReceiver({
      jwks: { keys: [statusPub] },
      issuer: ISS,
      audience: CONSUMER_AUD,
    });
    const results: ApplyResult[] = [];
    for (const c of childCommits) {
      const set = await signLifecycleEvent(c, {
        audience: CONSUMER_AUD,
        key: statusKeys.privateKey,
        kid: "as-status",
      });
      results.push(await fresh.verifyAndApply(set));
    }
    expect(results[0]).toMatchObject({ status: "applied", state: "active", version: 1 });
    expect(results[1]).toMatchObject({ status: "applied", state: "suspended", version: 2 });
    expect(results[2]).toMatchObject({ status: "applied", state: "active", version: 3 }); // LIFT
  });
});
