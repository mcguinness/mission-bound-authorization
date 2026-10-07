/**
 * @spec runtime#input-authority, runtime-oauth#authorization-details-mapping,
 * authzen#context-credential, authzen#pdp-request rule 6 (#825 PR 2b, D312)
 *
 * The PDP enforces the credential bound itself, independently of the Mission
 * bound and of any PEP pre-check: every case calls `evaluate()` directly, with
 * an allowing Mission and an allowing policy (`fga` always permits), so the
 * credential's own authority is the only thing that can refuse. Unconditional
 * (no live OpenFGA needed).
 */

import { AUTHORITY_ENTRY_TYP, authorityHash, computeAnchor, type JsonValue } from "@mission/core";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import {
  type Decision,
  type EvaluationRequest,
  evaluate,
  type MissionView,
  relationForAction,
  stalenessBound,
} from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const NOW = new Date("2026-10-05T12:00:00Z");
const CLOSE = { event_type: "accounting-period-closed", discharge_authority: "close-2026-q3" };

const allowingFga = { checkWithContext: async () => true } as unknown as Fga;

/** A Mission that allows both reads, with no constraint of its own. */
const BROAD_MISSION = [
  { type: "mission_resource_access" as const, resource: RESOURCE, actions: ["payments:invoice.read", "payments:vendor.read"] },
];

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_credential_1",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: BROAD_MISSION,
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const opts = (v: MissionView = view()) => ({
  view: v,
  fga: allowingFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
});

type Credential = NonNullable<EvaluationRequest["context"]["credential"]>;

/** A decision request carrying exactly the credential given (no fixture default). */
const req = (
  credential: Credential,
  over: { action?: string; vendor?: string; vendors?: string[]; extra?: Record<string, unknown> } = {},
): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: {
    type: over.vendors ? "vendor" : "invoice",
    id: over.vendors ? (over.vendors[0] as string) : "inv-1",
    properties: {
      audience: RESOURCE,
      vendor_id: over.vendor ?? "acme",
      ...(over.vendors ? { vendor_ids: over.vendors } : {}),
    },
  },
  action: { name: over.action ?? "payments:invoice.read" },
  context: {
    mission: { id: "msn_credential_1", issuer: ISSUER, authority_hash: "sha-256:testhash" },
    credential,
    ...over.extra,
  },
});

const entry = (actions: string[], constraints?: Record<string, unknown>) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  ...(constraints ? { constraints } : {}),
});

const reason = (d: Decision) => (d.decision ? "permit" : d.context.denial_reason);

describe("the PDP enforces the credential bound independently (@spec runtime#input-authority, D312)", () => {
  it("refuses an action the allowing Mission and policy permit but the narrower credential omits", async () => {
    const invoiceOnly = { authority: [entry(["payments:invoice.read"])] };
    expect(reason(await evaluate(req(invoiceOnly), opts()))).toBe("permit");
    expect(reason(await evaluate(req(invoiceOnly, { action: "payments:vendor.read" }), opts()))).toBe(
      "out_of_authority",
    );
  });

  it("applies both bounds: a Mission narrowed after issuance refuses what the broader credential covers", async () => {
    const broad = { authority: [entry(["payments:invoice.read", "payments:vendor.read"])] };
    const narrowed = view({ authority_set: [entry(["payments:invoice.read"]) as MissionView["authority_set"][number]] });
    expect(reason(await evaluate(req(broad), opts(narrowed)))).toBe("permit");
    expect(reason(await evaluate(req(broad, { action: "payments:vendor.read" }), opts(narrowed)))).toBe(
      "out_of_authority",
    );
  });

  it("holds the credential's vendor constraint for one object and for every member of a collection", async () => {
    const acmeOnly = { authority: [entry(["payments:invoice.read", "payments:vendor.read"], { vendors: ["acme"] })] };
    expect(reason(await evaluate(req(acmeOnly), opts()))).toBe("permit");
    expect(reason(await evaluate(req(acmeOnly, { vendor: "globex" }), opts()))).toBe("parameter_violation");
    expect(
      reason(await evaluate(req(acmeOnly, { action: "payments:vendor.read", vendors: ["acme", "globex"] }), opts())),
    ).toBe("parameter_violation");
  });

  it("holds the credential's amount cap, by exact decimal comparison and currency", async () => {
    const capped = { authority: [entry(["payments:invoice.read"], { max_amount: { amount: "100.00", currency: "USD" } })] };
    const amount = (value: string, currency = "USD") => ({ extra: { amount: { amount: value, currency } } });
    expect(reason(await evaluate(req(capped, amount("100.00")), opts()))).toBe("permit");
    expect(reason(await evaluate(req(capped, amount("100.01")), opts()))).toBe("parameter_violation");
    expect(reason(await evaluate(req(capped, amount("50.00", "EUR")), opts()))).toBe("parameter_violation");
    expect(reason(await evaluate(req(capped), opts()))).toBe("parameter_violation");
  });

  it("matches one whole entry: an action from one entry never combines with another entry's coverage", async () => {
    const split = {
      authority: [
        entry(["payments:invoice.read"], { vendors: ["globex"] }),
        entry(["payments:vendor.read"], { vendors: ["acme"] }),
      ],
    };
    // invoice.read for acme would permit only by unioning the first entry's
    // action with the second entry's vendor. The first entry names the action
    // and fails its own vendor constraint, so this is a parameter violation
    // (D324); the second never names the action.
    expect(reason(await evaluate(req(split), opts()))).toBe("parameter_violation");
  });
});

describe("the credential's discharge and approval conditions are decided at the PDP (D312)", () => {
  /** An entry as the Mission Issuer committed it, before any PDP-local member. */
  const committed = (actions: string[], constraints?: Record<string, unknown>) => entry(actions, constraints);
  /** The issuer's digest of a committed entry: what its discharge is keyed by. */
  const issuerDigest = (e: unknown) => computeAnchor(AUTHORITY_ENTRY_TYP, ISSUER, e as JsonValue);
  /**
   * A view holding exactly `set`, its `authority_hash` the issuer's over the
   * committed entries; `local` adds PDP-local members as the canonical loader
   * does (`join_delegation`), outside the commitment.
   */
  const committedView = (set: unknown[], local: (i: number) => Record<string, unknown> = () => ({}), over: Partial<MissionView> = {}) =>
    view({
      authority_set: set.map((e, i) => ({ ...(e as object), ...local(i) })) as unknown as MissionView["authority_set"],
      authority_hash: authorityHash(ISSUER, set as JsonValue[]),
      ...over,
    });
  /** The request's Mission reference, bound to `v`. */
  const on = (v: MissionView) => ({ extra: { mission: { id: v.id, issuer: v.issuer, authority_hash: v.authority_hash } } });
  const delegable = () => ({ join_delegation: { max_depth: 2, allowed_delegates: [] } });

  const closeEntry = committed(["payments:invoice.read"], { terminal_when: [CLOSE] });
  const missionWithClose = committedView([closeEntry], delegable);

  it("honors a discharge condition its source Mission entry carries, so that entry's discharge state governs it", async () => {
    const credential = { authority: [entry(["payments:invoice.read"], { terminal_when: [CLOSE] })] };
    const permitted = await evaluate(req(credential, on(missionWithClose)), opts(missionWithClose));
    expect(reason(permitted)).toBe("permit");
    // The permit names the issuer's entry commitment, not the materialized entry's bytes.
    expect(permitted.context.entry_digest).toBe(issuerDigest(closeEntry));
    const discharged = committedView([closeEntry], delegable, { version: 2, discharged: { entry_digests: [issuerDigest(closeEntry)] } });
    expect(reason(await evaluate(req(credential, on(discharged)), opts(discharged)))).toBe("authority_discharged");
  });

  it("refuses a discharge condition no Mission entry it derives from carries: the PDP holds no state for it", async () => {
    const credential = {
      authority: [entry(["payments:invoice.read"], { terminal_when: [{ event_type: "other-event" }] })],
    };
    expect(reason(await evaluate(req(credential, on(missionWithClose)), opts(missionWithClose)))).toBe("out_of_authority");
    expect(reason(await evaluate(req(credential), opts()))).toBe("out_of_authority");
    // A further condition the source lacks, and one that differs from the
    // source's only in discharge_authority, are no more established.
    const added = { authority: [entry(["payments:invoice.read"], { terminal_when: [CLOSE, { event_type: "other-event" }] })] };
    expect(reason(await evaluate(req(added, on(missionWithClose)), opts(missionWithClose)))).toBe("out_of_authority");
    const unpinned = { authority: [entry(["payments:invoice.read"], { terminal_when: [{ event_type: CLOSE.event_type }] })] };
    expect(reason(await evaluate(req(unpinned, on(missionWithClose)), opts(missionWithClose)))).toBe("out_of_authority");
  });

  const live = committed(["payments:invoice.read", "payments:vendor.read"], { terminal_when: [CLOSE] });
  const done = committed(["payments:invoice.read"], { terminal_when: [CLOSE] });
  const doneDigest = issuerDigest(done);

  it("never borrows another Mission entry's live state: any discharged source refuses, whatever the entry order (#1133 review P1)", async () => {
    // The discharged entry carries the loader's join_delegation in both orders.
    const mission = (set: unknown[]) =>
      committedView(set, (i) => (set[i] === done ? delegable() : {}), { discharged: { entry_digests: [doneDigest] } });
    const credential = { authority: [done] };
    for (const set of [[live, done], [done, live]]) {
      const v = mission(set);
      const decision = await evaluate(req(credential, on(v)), opts(v));
      expect(reason(decision)).toBe("authority_discharged");
      expect(decision.context.entry_digest).toBe(doneDigest);
    }
    // The live entry's own credential, and one narrowed from it to vendor
    // reads, derive from no discharged entry and permit.
    const both = mission([live, done]);
    expect(reason(await evaluate(req({ authority: [live] }, on(both)), opts(both)))).toBe("permit");
    const vendorOnly = { authority: [entry(["payments:vendor.read"], { terminal_when: [CLOSE] })] };
    expect(
      reason(await evaluate(req(vendorOnly, { action: "payments:vendor.read", ...on(both) }), opts(both))),
    ).toBe("permit");
  });

  it("keys discharge by the committed entry, though the loader adds join_delegation (#1133 re-review P1)", async () => {
    // The committed view refuses; adding the loader's PDP-local member leaves the delta's key unchanged.
    const credential = { authority: [closeEntry] };
    for (const local of [() => ({}), delegable]) {
      const v = committedView([closeEntry], local, { discharged: { entry_digests: [issuerDigest(closeEntry)] } });
      expect(reason(await evaluate(req(credential, on(v)), opts(v)))).toBe("authority_discharged");
    }
  });

  it("refuses a credential discharge condition unless the view proves it holds the committed Authority Set (#1133 re-review P1)", async () => {
    // The committed set is [live, done] with done discharged. An effective-set
    // view, as Status or introspection supplies, omits done: with or without the
    // delta, the surviving overlapping entry cannot show which one issued the
    // credential, so a discharge-conditioned credential entry is refused.
    const committedHash = authorityHash(ISSUER, [live, done] as JsonValue[]);
    const effective = (over: Partial<MissionView>) => view({ authority_set: [live] as MissionView["authority_set"], authority_hash: committedHash, ...over });
    for (const v of [effective({ discharged: { entry_digests: [doneDigest] } }), effective({})]) {
      expect(reason(await evaluate(req({ authority: [done] }, on(v)), opts(v)))).toBe("out_of_authority");
      // Fail-closed: the live entry's own credential cannot be established either.
      expect(reason(await evaluate(req({ authority: [live] }, on(v)), opts(v)))).toBe("out_of_authority");
      // A credential entry without a discharge condition, and the Mission bound, are unaffected.
      expect(reason(await evaluate(req({ authority: [entry(["payments:invoice.read"])] }, on(v)), opts(v)))).toBe("permit");
    }
  });

  it("requires the action-bound approval a credential entry demands, though neither the Mission nor the deployment does", async () => {
    const approvalOnly = { authority: [entry(["payments:invoice.read"], { requires_action_approval: true })] };
    const digest = { extra: { parameter_digest: "sha-256:op" } };
    expect(reason(await evaluate(req(approvalOnly, digest), opts()))).toBe("action_approval_required");
    const approved = {
      extra: {
        parameter_digest: "sha-256:op",
        action_approval: { id: "apr_1", approved_at: NOW.toISOString(), parameter_digest: "sha-256:op" },
      },
    };
    expect(reason(await evaluate(req(approvalOnly, approved), opts()))).toBe("permit");
  });

  it("needs no approval when another covering credential entry does not demand one", async () => {
    const either = {
      authority: [
        entry(["payments:invoice.read"], { requires_action_approval: true }),
        entry(["payments:invoice.read"]),
      ],
    };
    expect(reason(await evaluate(req(either, { extra: { parameter_digest: "sha-256:op" } }), opts()))).toBe("permit");
  });
});

describe("credential facts the PDP cannot use refuse credential_invalid (@spec authzen#pdp-request rule 6)", () => {
  it("refuses a decision that carries no credential authority, never falling back to the Mission", async () => {
    expect(reason(await evaluate(req({}), opts()))).toBe("credential_invalid");
    expect(reason(await evaluate(req({ authority: undefined }), opts()))).toBe("credential_invalid");
  });

  it.each([
    ["an entry type it does not understand", [{ type: "other", resource: RESOURCE, actions: ["payments:invoice.read"] }]],
    ["a constraint it cannot enforce", [entry(["payments:invoice.read"], { time_window: "9-5" })]],
    ["a malformed amount cap", [entry(["payments:invoice.read"], { max_amount: { amount: "ten", currency: "USD" } })]],
    ["a non-array value", { type: "mission_resource_access" }],
    ["an empty discharge condition list", [entry(["payments:invoice.read"], { terminal_when: [] })]],
    [
      "two discharge conditions sharing a canonical form",
      [
        entry(["payments:invoice.read"], {
          terminal_when: [CLOSE, { discharge_authority: CLOSE.discharge_authority, event_type: CLOSE.event_type }],
        }),
      ],
    ],
    [
      "a malformed discharge_authority",
      [entry(["payments:invoice.read"], { terminal_when: [{ event_type: "x", discharge_authority: "two words" }] })],
    ],
  ])("refuses a credential authority with %s", async (_label, authority) => {
    expect(reason(await evaluate(req({ authority }), opts()))).toBe("credential_invalid");
  });

  it("refuses a discharge condition carrying a member the profile does not define, though the Mission entry carries it without one (#1133 review P2)", async () => {
    const set = [entry(["payments:invoice.read"], { terminal_when: [CLOSE] })];
    const mission = view({ authority_set: set as MissionView["authority_set"], authority_hash: authorityHash(ISSUER, set as JsonValue[]) });
    const bound = { extra: { mission: { id: mission.id, issuer: ISSUER, authority_hash: mission.authority_hash } } };
    const extended = { authority: [entry(["payments:invoice.read"], { terminal_when: [{ ...CLOSE, scope: "q3" }] })] };
    expect(reason(await evaluate(req({ authority: set }, bound), opts(mission)))).toBe("permit");
    expect(reason(await evaluate(req(extended, bound), opts(mission)))).toBe("credential_invalid");
  });

  it("refuses a credential whose expiry has passed or cannot be read", async () => {
    const authority = [entry(["payments:invoice.read"])];
    const at = (offsetMs: number) => new Date(NOW.getTime() + offsetMs).toISOString();
    expect(reason(await evaluate(req({ authority, expires_at: at(60_000) }), opts()))).toBe("permit");
    expect(reason(await evaluate(req({ authority, expires_at: at(0) }), opts()))).toBe("credential_invalid");
    expect(reason(await evaluate(req({ authority, expires_at: at(-1) }), opts()))).toBe("credential_invalid");
    expect(reason(await evaluate(req({ authority, expires_at: "not-a-date" }), opts()))).toBe("credential_invalid");
  });
});
