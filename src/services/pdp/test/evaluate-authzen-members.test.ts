/**
 * @spec authzen#pdp-request, authzen#context-audience-freshness (#1004): the
 * PDP reads the AuthZEN profile's own members. The approved entry's resource
 * is matched against the PEP-established `resource.properties.operation_target`
 * (#1276, D457), never against `resource.properties.audience` or the AuthZEN
 * `resource` object's `type`/`id` identity.
 *
 * The FGA layer is a stub that always permits, so only evaluate()'s own
 * steps decide, and this file never skips.
 */

import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { evaluate as evaluateRequest, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type MissionView, policyViewId } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

// Every decision carries the credential's own authority (#825 PR 2b); the
// fixture adds a neutral one where a test does not name it.
const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) =>
  evaluateRequest(withCredential(req), opts);

const RESOURCE = "http://localhost:4403/mcp";
const OTHER_RESOURCE = "http://localhost:4499/mcp";
const NOW = new Date("2026-10-02T12:00:00Z");

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const CLAIMS = openTestClaims({ now: () => NOW });

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_1004",
  issuer: "https://as.test",
  state: "active",
  version: 3,
  authority_hash: "sha-256:h1004",
  authority_set: [
    {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const options = (over: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view: view(),
  fga: alwaysAllowFga,
  modelId: "model-1004",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  claims: CLAIMS,
  ...over,
});

/** A read of one invoice: below the high-consequence floor, no observation needed. */
const readRequest = (resource: EvaluationRequest["resource"]): EvaluationRequest =>
  ({
    subject: { id: "alice" },
    resource,
    action: { name: "payments:invoice.read", properties: { idempotency_key: freshKey() } },
    context: {
      mission: { id: "msn_1004", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
    },
  }) as EvaluationRequest;

const HIGH_CONSEQUENCE_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"];

/** A well-formed `fresh` observation read at the decision instant. */
const observed = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  state: "active",
  mode: "fresh",
  freshness_at: NOW.toISOString(),
  ...over,
});

interface ObservedRequest {
  actionClass?: string;
  /** The observation carried; `null` omits the member. Defaults to {@link observed}(). */
  observation?: Record<string, unknown> | null;
}

/** A keyed payment request; the class label is the request's own. */
const observedRequest = (o: ObservedRequest = {}): EvaluationRequest =>
  ({
    subject: { id: "alice", properties: { iss: "https://as.test" } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: { name: "payments:payment.execute", properties: { idempotency_key: freshKey() } },
    context: {
      mission: { id: "msn_1004", issuer: "https://as.test" },
      actor: { client_id: "ap-agent" },
      ...(o.actionClass !== undefined ? { action_class: o.actionClass } : {}),
      ...(o.observation === null ? {} : { mission_state_observation: o.observation ?? observed() }),
    },
  }) as EvaluationRequest;

describe("AuthZEN profile members (@spec authzen#pdp-request, authzen#context-audience-freshness, #1004)", () => {
  describe("under PEP placement the PDP reads context.mission_state_observation", () => {
    it("a well-formed, fresh observation establishes Mission state for every high-consequence class, with no context.freshness", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const req = observedRequest({ actionClass });
        expect((req.context as Record<string, unknown>).freshness).toBeUndefined();
        const dec = await evaluate(req, options({ stateSourcePlacement: "pep" }));
        expect(dec.decision, `${actionClass}: ${JSON.stringify(dec.context)}`).toBe(true);
      }
    });

    it("a missing observation denies stale_state for every high-consequence class", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(observedRequest({ actionClass, observation: null }), options({ stateSourcePlacement: "pep" }));
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    // #1049 owner ruling: the observation is REQUIRED by placement. A lower
    // class may rely on token-lifetime freshness as its state source, but that
    // never excuses omitting the required state input.
    it("a missing observation denies stale_state at every class below the high-consequence floor too, audit_only included", async () => {
      for (const actionClass of ["consequential_write", "consequential_read", undefined, "audit_only"]) {
        const label = actionClass ?? "no class (consequential_read)";
        const classed = actionClass !== undefined ? { actionClass } : {};
        const denied = await evaluate(observedRequest({ ...classed, observation: null }), options({ stateSourcePlacement: "pep" }));
        expect(denied.decision, label).toBe(false);
        expect(denied.context.denial_reason, label).toBe("stale_state");
        // Control: the same request carrying the observation is permitted.
        const permitted = await evaluate(observedRequest(classed), options({ stateSourcePlacement: "pep" }));
        expect(permitted.decision, `${label}: ${JSON.stringify(permitted.context)}`).toBe(true);
      }
    });

    it("an observation lacking a member its mode requires, or carrying one that is malformed, denies stale_state in every mode", async () => {
      const issued = NOW.toISOString();
      const expires = new Date(NOW.getTime() + 60_000).toISOString();
      const cached = (mode: string, over: Record<string, unknown> = {}) =>
        observed({ mode, mission_status_issued_at: issued, mission_status_expires_at: expires, ...over });
      const malformed: Array<[string, Record<string, unknown>]> = [
        ["fresh: no state", observed({ state: undefined })],
        ["fresh: a non-string state", observed({ state: 1 })],
        ["fresh: no mode", observed({ mode: undefined })],
        ["fresh: a mode outside the three", observed({ mode: "stale" })],
        ["fresh: no freshness_at", observed({ freshness_at: undefined })],
        ["fresh: a freshness_at that is not RFC 3339", observed({ freshness_at: "2026-10-02" })],
        ["fresh: a non-integer version", observed({ version: 3.5 })],
        ["fresh: a string version", observed({ version: "3" })],
        ["fresh: a malformed mission_status_expires_at", observed({ mission_status_expires_at: "soon" })],
        ["fresh: a non-string assertion", observed({ assertion: 7 })],
        ["cached: no mission_status_issued_at", cached("cached", { mission_status_issued_at: undefined })],
        ["cached: no mission_status_expires_at", cached("cached", { mission_status_expires_at: undefined })],
        ["cached: a malformed mission_status_issued_at", cached("cached", { mission_status_issued_at: "noon" })],
        ["event_driven: no mission_status_issued_at", cached("event_driven", { mission_status_issued_at: undefined })],
        ["event_driven: no mission_status_expires_at", cached("event_driven", { mission_status_expires_at: undefined })],
        // freshness_at "can precede this value by no more than the published maximum clock skew"
        [
          "cached: freshness_at earlier than mission_status_issued_at by more than the skew",
          cached("cached", { freshness_at: new Date(NOW.getTime() - 20_000).toISOString() }),
        ],
        [
          "cached: a mission_status_issued_at beyond the skew in the future",
          cached("cached", { mission_status_issued_at: new Date(NOW.getTime() + 60_000).toISOString() }),
        ],
      ];
      for (const [label, observation] of malformed) {
        for (const actionClass of [...HIGH_CONSEQUENCE_CLASSES, "consequential_write"]) {
          const dec = await evaluate(observedRequest({ actionClass, observation }), options({ stateSourcePlacement: "pep" }));
          expect(dec.decision, `${label} (${actionClass})`).toBe(false);
          expect(dec.context.denial_reason, `${label} (${actionClass})`).toBe("stale_state");
        }
      }
      // Control: each mode, complete, establishes state.
      for (const observation of [observed(), cached("cached"), cached("event_driven")]) {
        const dec = await evaluate(observedRequest({ actionClass: "irreversible_action", observation }), options({ stateSourcePlacement: "pep" }));
        expect(dec.decision, `${observation.mode}: ${JSON.stringify(dec.context)}`).toBe(true);
      }
    });
  });

  // @spec authzen#context-audience-freshness `assertion`: "The signed Mission
  // Status Response ... the PEP obtained `state` and `version` from, ... so
  // the PDP can verify the snapshot instead of trusting an unsigned PEP
  // assertion." The trusted source is the declared one, so the key is that
  // source's: here, the Mission issuer's status-response key.
  describe("a present assertion is verified against the declared state source's key", () => {
    const issued = Math.floor(NOW.getTime() / 1000);
    const freshUntil = new Date(NOW.getTime() + 60_000).toISOString();

    async function statusKeys() {
      const { publicKey, privateKey } = await generateKeyPair("ES256");
      const jwk = { ...(await exportJWK(publicKey)), kid: "status-1004", alg: "ES256" };
      return { privateKey, keys: createLocalJWKSet({ keys: [jwk] }) };
    }

    type Signing = {
      privateKey: CryptoKey;
      kid?: string;
      typ?: string;
      iss?: string;
      aud?: string;
      exp?: number;
      mission?: Record<string, unknown>;
      /** Sign with no `iat`, or no `exp`, claim at all. */
      omit?: "iat" | "exp";
      /** The envelope `sub`: the caller the response was signed for; `null` for none. */
      sub?: string | null;
    };
    const signStatus = (s: Signing) => {
      const jwt = new SignJWT({
        ...(s.sub === null ? {} : { sub: s.sub ?? "pep-status-client" }),
        mission: {
          id: "msn_1004",
          issuer: "https://as.test",
          state: "active",
          version: 3,
          expires_at: "2027-06-01T00:00:00Z",
          fresh_until: freshUntil,
          ...s.mission,
        },
      })
        .setProtectedHeader({ alg: "ES256", kid: s.kid ?? "status-1004", typ: s.typ ?? "mission-status-response+jwt" })
        .setIssuer(s.iss ?? "https://as.test")
        .setAudience(s.aud ?? RESOURCE);
      if (s.omit !== "iat") jwt.setIssuedAt(issued);
      if (s.omit !== "exp") jwt.setExpirationTime(s.exp ?? issued + 60);
      return jwt.sign(s.privateKey);
    };

    const withAssertion = (assertion: string, over: Record<string, unknown> = {}) =>
      observed({
        version: 3,
        mode: "cached",
        mission_status_issued_at: new Date(issued * 1000).toISOString(),
        mission_status_expires_at: freshUntil,
        assertion,
        ...over,
      });

    it("a status response signed by the declared source's key and matching the observation is verified and establishes state", async () => {
      const { privateKey, keys } = await statusKeys();
      const dec = await evaluate(
        observedRequest({ actionClass: "irreversible_action", observation: withAssertion(await signStatus({ privateKey })) }),
        options({ stateSourcePlacement: "pep" as const, stateAssertionKeys: keys }),
      );
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });

    // @spec status#mission-status-response check 6 (#1407): the envelope
    // `sub` names the client that requested the response, here the PEP.
    // Checks 6 and 7 are the requester's: the PEP makes them when it obtains
    // the response, and the PDP, which did not request it, cannot check the
    // nonce either. The PDP relies on what binds the snapshot to its decision:
    // the declared source's signature, the issuer, the enforcement scope as
    // `aud`, the Mission, `state`, `version` and the signed times.
    it("an assertion verifies whichever caller its envelope sub names, or none: sub binds the response to the PEP that requested it, not to the PDP", async () => {
      const { privateKey, keys } = await statusKeys();
      for (const sub of ["another-pep", "ap-agent", null] as const) {
        const dec = await evaluate(
          observedRequest({ actionClass: "irreversible_action", observation: withAssertion(await signStatus({ privateKey, sub })) }),
          options({ stateSourcePlacement: "pep" as const, stateAssertionKeys: keys }),
        );
        expect(dec.decision, `${String(sub)}: ${JSON.stringify(dec.context)}`).toBe(true);
      }
    });

    it("an assertion the PDP cannot verify, or one that does not match the observation, denies stale_state", async () => {
      const { privateKey, keys } = await statusKeys();
      const stranger = await statusKeys();
      const good = await signStatus({ privateKey });
      const cases: Array<[string, Record<string, unknown>, boolean]> = [
        ["no key declared for the source", withAssertion(good), false],
        ["not a JWS", withAssertion("not-a-jws"), true],
        ["signed by a key the source does not publish", withAssertion(await signStatus({ privateKey: stranger.privateKey })), true],
        ["another media type", withAssertion(await signStatus({ privateKey, typ: "JWT" })), true],
        ["another issuer", withAssertion(await signStatus({ privateKey, iss: "https://other-as.test" })), true],
        ["another audience", withAssertion(await signStatus({ privateKey, aud: OTHER_RESOURCE })), true],
        ["already expired", withAssertion(await signStatus({ privateKey, exp: issued - 60 })), true],
        ["another Mission", withAssertion(await signStatus({ privateKey, mission: { id: "msn_other" } })), true],
        [
          "a state other than the observation's",
          withAssertion(
            await signStatus({
              privateKey,
              mission: { state: "terminated", termination: { reason: "revoked", terminated_at: NOW.toISOString(), version: 3 } },
            }),
          ),
          true,
        ],
        ["a version other than the observation's", withAssertion(await signStatus({ privateKey, mission: { version: 2 } })), true],
        ["an issuance other than mission_status_issued_at", withAssertion(good, { mission_status_issued_at: new Date((issued - 1) * 1000).toISOString() }), true],
        ["an expiry later than its fresh_until", withAssertion(good, { mission_status_expires_at: new Date(NOW.getTime() + 61_000).toISOString() }), true],
        // @spec status#mission-status-response consumer checks 4 and 10 (#1535).
        ["a mission.issuer other than its iss", withAssertion(await signStatus({ privateKey, mission: { issuer: "https://other-as.test" } })), true],
        ["a signed fresh_until later than its exp", withAssertion(await signStatus({ privateKey, exp: issued + 40 })), true],
      ];
      for (const [label, observation, keyed] of cases) {
        for (const actionClass of ["consequential_write", "irreversible_action"]) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation }),
            options({ stateSourcePlacement: "pep" as const, ...(keyed ? { stateAssertionKeys: keys } : {}) }),
          );
          expect(dec.decision, `${label} (${actionClass})`).toBe(false);
          expect(dec.context.denial_reason, `${label} (${actionClass})`).toBe("stale_state");
        }
      }
    });

    // @spec status#mission-status-response consumer check 9 compares `iat`
    // and `exp`: a response carrying either not at all has no lifetime to
    // check, so it does not verify. Fresh mode repeats neither, so nothing in
    // the observation catches the omission instead.
    it("an assertion signed without exp, or without iat, denies stale_state", async () => {
      const { privateKey, keys } = await statusKeys();
      for (const omit of ["exp", "iat"] as const) {
        const assertion = await signStatus({ privateKey, omit });
        for (const actionClass of ["consequential_write", "irreversible_action"]) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation: observed({ version: 3, assertion }) }),
            options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
          );
          expect(dec.decision, `no ${omit} (${actionClass})`).toBe(false);
          expect(dec.context.denial_reason, `no ${omit} (${actionClass})`).toBe("stale_state");
        }
      }
      // Control: the same signing with both claims verifies and permits.
      const both = await signStatus({ privateKey });
      const permitted = await evaluate(
        observedRequest({ actionClass: "irreversible_action", observation: observed({ version: 3, assertion: both }) }),
        options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
      );
      expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
    });

    // #1049 review P2-a: `mission_status_expires_at` is OPTIONAL in `fresh`
    // mode, so the signed `mission.fresh_until` must bind on its own: an
    // observation that omits the repeat cannot discard the signed ceiling.
    it("a verified assertion's signed fresh_until caps the permit in fresh mode, though the observation does not repeat it", async () => {
      const { privateKey, keys } = await statusKeys();
      const signedUntil = new Date(NOW.getTime() + 5_000);
      const assertion = await signStatus({ privateKey, mission: { fresh_until: signedUntil.toISOString() } });
      // irreversible_action (30 s bound, 120 s lifetime) and consequential_write
      // (300 s bound and lifetime): both would otherwise outlive the signed state.
      for (const actionClass of ["irreversible_action", "consequential_write"]) {
        const dec = await evaluate(
          observedRequest({ actionClass, observation: observed({ version: 3, assertion }) }),
          options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
        );
        expect(dec.decision, `${actionClass}: ${JSON.stringify(dec.context)}`).toBe(true);
        const validUntil = (dec.context.conditions as { valid_until: string }).valid_until;
        expect(Date.parse(validUntil), `${actionClass}: ${validUntil}`).toBeLessThanOrEqual(signedUntil.getTime());
      }
    });

    it("a verified assertion whose signed fresh_until has already passed denies stale_state, in fresh mode too", async () => {
      const { privateKey, keys } = await statusKeys();
      // The JWS itself is unexpired; only the signed state ceiling has passed.
      const assertion = await signStatus({ privateKey, mission: { fresh_until: new Date(NOW.getTime() - 1_000).toISOString() } });
      for (const actionClass of ["irreversible_action", "consequential_write"]) {
        const dec = await evaluate(
          observedRequest({ actionClass, observation: observed({ version: 3, assertion }) }),
          options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
        );
        expect(dec.decision, actionClass).toBe(false);
        expect(dec.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    // @spec status#mission-status-caching (#1535): a consumer "MUST NOT rely
    // on a reported `active` state at or after `mission.expires_at`", however
    // far its `fresh_until` and `exp` run.
    it("a verified assertion reporting active is relied on only before the Mission's expires_at: it caps the permit there, and once reached denies stale_state (#1535)", async () => {
      const { privateKey, keys } = await statusKeys();
      const expiresAt = new Date(NOW.getTime() + 5_000);
      const capped = await signStatus({ privateKey, mission: { expires_at: expiresAt.toISOString() } });
      const reached = await signStatus({ privateKey, mission: { expires_at: NOW.toISOString() } });
      for (const actionClass of ["irreversible_action", "consequential_write"]) {
        const dec = await evaluate(
          observedRequest({ actionClass, observation: observed({ version: 3, assertion: capped }) }),
          options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
        );
        expect(dec.decision, `${actionClass}: ${JSON.stringify(dec.context)}`).toBe(true);
        const validUntil = (dec.context.conditions as { valid_until: string }).valid_until;
        expect(Date.parse(validUntil), `${actionClass}: ${validUntil}`).toBeLessThanOrEqual(expiresAt.getTime());
        const denied = await evaluate(
          observedRequest({ actionClass, observation: observed({ version: 3, assertion: reached }) }),
          options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
        );
        expect(denied.decision, actionClass).toBe(false);
        expect(denied.context.denial_reason, actionClass).toBe("stale_state");
      }
    });

    // @spec status#mission-status-response: `expires_at` is REQUIRED. A
    // response without it carries no Mission expiry to enforce, so it does
    // not verify, rather than being relied on as though the Mission never
    // expired.
    it("an assertion signed without mission.expires_at denies stale_state, where the same assertion with it permits (#1535)", async () => {
      const { privateKey, keys } = await statusKeys();
      // An undefined member is dropped when the payload is serialized.
      const missing = await signStatus({ privateKey, mission: { expires_at: undefined } });
      const present = await signStatus({ privateKey });
      for (const actionClass of ["irreversible_action", "consequential_write"]) {
        const denied = await evaluate(
          observedRequest({ actionClass, observation: observed({ version: 3, assertion: missing }) }),
          options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
        );
        expect(denied.decision, actionClass).toBe(false);
        expect(denied.context.denial_reason, actionClass).toBe("stale_state");
        const permitted = await evaluate(
          observedRequest({ actionClass, observation: observed({ version: 3, assertion: present }) }),
          options({ stateSourcePlacement: "pep", stateAssertionKeys: keys }),
        );
        expect(permitted.decision, `${actionClass}: ${JSON.stringify(permitted.context)}`).toBe(true);
      }
    });
  });

  // @spec runtime#state-freshness, authzen#response-context: "A permit issued
  // from that state view MUST expire no later than this state valid-through:
  // the reported expiry or lease end, or, absent one, the observation time
  // plus the published staleness bound." Under PEP placement the reported
  // expiry is `mission_status_expires_at`.
  describe("under PEP placement the permit is capped at the accepted observation's state valid-through", () => {
    const cachedUntil = (expiresAt: Date) =>
      observed({
        mode: "cached",
        mission_status_issued_at: NOW.toISOString(),
        mission_status_expires_at: expiresAt.toISOString(),
      });

    it("caps valid_until at mission_status_expires_at when the observation reports one, earlier or later than the observation plus the class bound", async () => {
      // irreversible_action: a 120 s permit lifetime and a 30 s class bound.
      for (const offsetMs of [15_000, 60_000]) {
        const expiresAt = new Date(NOW.getTime() + offsetMs);
        const dec = await evaluate(
          observedRequest({ actionClass: "irreversible_action", observation: cachedUntil(expiresAt) }),
          options({ stateSourcePlacement: "pep" }),
        );
        expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
        expect((dec.context.conditions as { valid_until: string }).valid_until, `+${offsetMs} ms`).toBe(expiresAt.toISOString());
      }
    });

    it("absent a reported expiry, caps valid_until at freshness_at plus the class bound", async () => {
      const dec = await evaluate(
        observedRequest({ actionClass: "irreversible_action", observation: observed({ freshness_at: new Date(NOW.getTime() - 10_000).toISOString() }) }),
        options({ stateSourcePlacement: "pep" }),
      );
      expect((dec.context.conditions as { valid_until: string }).valid_until).toBe(new Date(NOW.getTime() + 20_000).toISOString());
    });

    it("a reported expiry already reached yields no permit: stale_state", async () => {
      const dec = await evaluate(
        observedRequest({ actionClass: "irreversible_action", observation: cachedUntil(NOW) }),
        options({ stateSourcePlacement: "pep" }),
      );
      expect(dec.decision).toBe(false);
      expect(dec.context.denial_reason).toBe("stale_state");
    });
  });

  // @spec authzen#pdp-request rule 1: "Where state establishment is placed
  // with the PDP and the member is absent ..., the PDP MUST establish state
  // from its own source or deny with `stale_state`." This PDP's own source is
  // the read that produced its view, observed at `stateObservedAt`.
  describe("under PDP placement the observation is absent and the PDP establishes state from its own read", () => {
    it("an absent observation is accepted: the PDP's own read within the bound establishes state for every high-consequence class", async () => {
      for (const actionClass of HIGH_CONSEQUENCE_CLASSES) {
        const dec = await evaluate(
          observedRequest({ actionClass, observation: null }),
          options({ stateSourcePlacement: "pdp", stateObservedAt: NOW.toISOString() }),
        );
        expect(dec.decision, `${actionClass}: ${JSON.stringify(dec.context)}`).toBe(true);
      }
    });

    it("with no read of its own, a stale one or a malformed one, the PDP denies stale_state", async () => {
      const stale = new Date(NOW.getTime() - 3_600_000).toISOString();
      for (const [label, stateObservedAt, classes] of [
        ["no read", undefined, HIGH_CONSEQUENCE_CLASSES],
        ["a read an hour old", stale, [...HIGH_CONSEQUENCE_CLASSES, "consequential_write"]],
        ["a malformed read time", "an hour ago", [...HIGH_CONSEQUENCE_CLASSES, "consequential_write"]],
      ] as const) {
        for (const actionClass of classes) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation: null }),
            options({ stateSourcePlacement: "pdp", ...(stateObservedAt !== undefined ? { stateObservedAt } : {}) }),
          );
          expect(dec.decision, `${label} ${actionClass}`).toBe(false);
          expect(dec.context.denial_reason, `${label} ${actionClass}`).toBe("stale_state");
        }
      }
    });

    // #1049 review P2-b: the requirement is rule 1's, not the high-consequence
    // floor's, so it holds for every class that reaches a permit under a bound.
    it("with no read of its own, denies stale_state below the high-consequence floor too: a consequential write and a read", async () => {
      for (const actionClass of ["consequential_write", "consequential_read", undefined]) {
        const label = actionClass ?? "no class (consequential_read)";
        const denied = await evaluate(
          observedRequest({ ...(actionClass !== undefined ? { actionClass } : {}), observation: null }),
          options({ stateSourcePlacement: "pdp" }),
        );
        expect(denied.decision, label).toBe(false);
        expect(denied.context.denial_reason, label).toBe("stale_state");
        // Control: the PDP's own read within the bound establishes state.
        const permitted = await evaluate(
          observedRequest({ ...(actionClass !== undefined ? { actionClass } : {}), observation: null }),
          options({ stateSourcePlacement: "pdp", stateObservedAt: NOW.toISOString() }),
        );
        expect(permitted.decision, `${label}: ${JSON.stringify(permitted.context)}`).toBe(true);
      }
    });

    // #1049 owner ruling: rule 1 has no class exception. A class with no
    // active-freshness requirement still has the state-establishment one.
    it("with no read of its own, denies stale_state for audit_only too; with a read, permits it", async () => {
      const denied = await evaluate(
        observedRequest({ actionClass: "audit_only", observation: null }),
        options({ stateSourcePlacement: "pdp" }),
      );
      expect(denied.decision).toBe(false);
      expect(denied.context.denial_reason).toBe("stale_state");
      const permitted = await evaluate(
        observedRequest({ actionClass: "audit_only", observation: null }),
        options({ stateSourcePlacement: "pdp", stateObservedAt: NOW.toISOString() }),
      );
      expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);
    });

    it("relies on its own read, never the PEP's telemetry, and caps the permit at that read plus the class bound", async () => {
      // A PEP-supplied observation an hour old does not make the PDP's own
      // fresh read stale, and a fresher one does not lengthen the permit.
      for (const freshnessAt of [new Date(NOW.getTime() - 3_600_000), NOW]) {
        const dec = await evaluate(
          observedRequest({ actionClass: "irreversible_action", observation: observed({ freshness_at: freshnessAt.toISOString() }) }),
          options({ stateSourcePlacement: "pdp", stateObservedAt: new Date(NOW.getTime() - 10_000).toISOString() }),
        );
        expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
        // irreversible_action publishes a 30 s bound: the read plus 30 s.
        expect((dec.context.conditions as { valid_until: string }).valid_until).toBe(new Date(NOW.getTime() + 20_000).toISOString());
      }
    });
  });

  // @spec authzen#pdp-request rule 1: "When present, the Mission state
  // conveyed in `context.mission_state_observation.state` is exactly `active`;
  // every other value, recognized or not, is non-active ... A PDP with direct
  // access to a Mission state source MUST prefer its own fresher view ... and
  // MUST return `mission_inactive` when its view disagrees with the
  // PEP-supplied state." This PDP always holds its own view (`view.state`).
  describe("the PEP-supplied state is exactly active, and the PDP's own view wins on disagreement (@spec authzen#pdp-request rule 1)", () => {
    const CLASSES = ["consequential_write", ...HIGH_CONSEQUENCE_CLASSES];

    it("the PDP's own active view against a PEP-supplied revoked state denies mission_inactive", async () => {
      // A revoked Mission is observed `terminated` with its OPTIONAL
      // `termination` beside the state; the PDP keys on exactly `active` alone.
      const revoked = { state: "terminated", termination: { reason: "revoked", terminated_at: NOW.toISOString() } };
      for (const placement of ["pep", "pdp"] as const) {
        for (const actionClass of CLASSES) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation: observed(revoked) }),
            options({ stateSourcePlacement: placement, stateObservedAt: NOW.toISOString() }),
          );
          expect(dec.decision, `${placement} ${actionClass}`).toBe(false);
          expect(dec.context.denial_reason, `${placement} ${actionClass}`).toBe("mission_inactive");
        }
      }
    });

    it("an unknown PEP-supplied state, against the PDP's own active view, denies mission_inactive", async () => {
      for (const state of ["ACTIVE", "Active", "active ", "", "paused", "future_lifecycle_state"]) {
        for (const actionClass of CLASSES) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation: observed({ state }) }),
            options({ stateSourcePlacement: "pep" }),
          );
          expect(dec.decision, `${JSON.stringify(state)} ${actionClass}`).toBe(false);
          expect(dec.context.denial_reason, `${JSON.stringify(state)} ${actionClass}`).toBe("mission_inactive");
        }
      }
    });

    it("the PDP's own revoked view against a PEP-supplied active state denies mission_inactive: the PDP's view wins", async () => {
      for (const placement of ["pep", "pdp"] as const) {
        for (const actionClass of CLASSES) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation: observed({ state: "active" }) }),
            options({ view: view({ state: "terminated" }), stateSourcePlacement: placement, stateObservedAt: NOW.toISOString() }),
          );
          expect(dec.decision, `${placement} ${actionClass}`).toBe(false);
          expect(dec.context.denial_reason, `${placement} ${actionClass}`).toBe("mission_inactive");
        }
      }
    });
  });

  // @spec authzen#pdp-request rule 4: "When
  // `context.mission_state_observation.version` is present, the PDP compares
  // it against its own tracked Mission state version ... never against
  // `policy_view_id` ... and treats a mismatch as staleness (`stale_state`)".
  // This PDP's tracked version is the loaded view's `version`.
  describe("an observation version the PDP does not track is staleness (@spec authzen#pdp-request rule 4)", () => {
    it("an observation version other than the PDP's tracked Mission state version denies stale_state", async () => {
      for (const version of [2, 4, 0]) {
        for (const actionClass of ["consequential_write", "irreversible_action"]) {
          const dec = await evaluate(
            observedRequest({ actionClass, observation: observed({ version }) }),
            options({ stateSourcePlacement: "pep" }),
          );
          expect(dec.decision, `v${version} ${actionClass}`).toBe(false);
          expect(dec.context.denial_reason, `v${version} ${actionClass}`).toBe("stale_state");
        }
      }
    });

    it("the version is compared against the tracked version, never against policy_view_id: a matching version permits beside the view's policy_view_id", async () => {
      const req = observedRequest({ actionClass: "irreversible_action", observation: observed({ version: 3 }) });
      req.context.mission.policy_view_id = policyViewId(view(), "model-1004");
      const dec = await evaluate(req, options({ stateSourcePlacement: "pep" }));
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
      expect(dec.context.policy_view_id).toBe(req.context.mission.policy_view_id);
    });
  });

  describe("the entry match reads resource.properties.operation_target (#1276, D457)", () => {
    it("matches the approved entry's resource against the operation target, with no context.audience, a resource id that names an object, and an audience the entry does not name", async () => {
      const req = readRequest({
        type: "invoice",
        id: "inv-1",
        properties: { audience: "urn:example:payments-pep", operation_target: RESOURCE, vendor_id: "acme" },
      });
      expect((req.context as Record<string, unknown>).audience).toBeUndefined();
      const dec = await evaluate(req, options());
      expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    });

    it("never matches on the resource object's id or type: an id and type naming the entry's resource under another target are out_of_authority", async () => {
      const dec = await evaluate(
        readRequest({ type: RESOURCE, id: RESOURCE, properties: { audience: RESOURCE, operation_target: OTHER_RESOURCE, vendor_id: "acme" } }),
        options(),
      );
      expect(dec.decision).toBe(false);
      expect(dec.context.denial_reason).toBe("out_of_authority");
    });
  });
});
