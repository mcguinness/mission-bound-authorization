import { randomBytes } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { authorityHash, intentHash } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  deriveAuthoritySet,
  GateError,
  IntentError,
  isSubsetSet,
  LifecycleConflictError,
  MISSION_ID_ENTROPY_BYTES,
  MissionKernel,
  type MissionRecord,
  newMissionId,
  validateAuthorityProposal,
  validateMissionIntent,
  validateMissionIntentSubmission,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

const intent = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    goal: "Pay Acme invoices for Q3",
    target_resources: [RESOURCE],
    expires_at: "2027-01-01T00:00:00Z",
    ...over,
  });

let kernel: MissionKernel;
beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256");
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: privateKey,
    statusKid: "as-status",
  });
});

const approve = (raw: string, n: number) =>
  kernel.approve({
    intent: validateMissionIntent(raw),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

describe("intent validation (@spec mission#submission-via-par)", () => {
  it("rejects unknown top-level members (closed top level)", () => {
    expect(() => validateMissionIntent(intent({ authority_hash: "sneaky" }))).toThrow(IntentError);
  });
  it("rejects duplicate member names", () => {
    expect(() => validateMissionIntent('{"goal":"x","goal":"y"}')).toThrow(/duplicate/);
  });
  it("rejects missing required members and bad expires_at", () => {
    expect(() => validateMissionIntent('{"goal":"x"}')).toThrow(IntentError);
    expect(() => validateMissionIntent(intent({ expires_at: "not-a-date" }))).toThrow(IntentError);
  });
  it("rejects requested_derivation_limit below 1", () => {
    expect(() => validateMissionIntent(intent({ requested_derivation_limit: 0 }))).toThrow(
      /requested_derivation_limit/,
    );
  });
  it("accepts well-formed goal_lang, refuses malformed with invalid_request, and commits it in intent_hash (@spec mission#mission-intent)", () => {
    const wellFormed = [
      "en",
      "en-US",
      "zh-Hant-TW",
      "de-419",
      "x-private",
      "i-klingon", // grandfathered irregular
      "art-lojban", // grandfathered regular
      "sl-rozaj-biske", // two variants
      "en-Latn-US-variant-a-extended-x-private", // 39 chars: valid past RFC 5646 4.4.1's 35-char support floor
    ];
    for (const ok of wellFormed) {
      expect(validateMissionIntent(intent({ goal_lang: ok })).goal_lang).toBe(ok);
    }
    const malformed = [
      "", // empty
      "english language", // not a tag
      "-en", // leading separator
      "en--US", // empty subtag
      "a1", // digit in primary language
      "en-", // trailing separator
      "e", // one-char primary that is not a singleton form
      "x", // private use requires at least one following subtag
      "i-foo", // i-* is not a general form; only fixed grandfathered tags
      "de-419-DE", // two region subtags
      "en-a", // extension singleton without content
      "en-x", // private-use singleton without content
      "ar-a-aaa-b-bbb-a-ccc", // repeated extension singleton
      "de-DE-1901-1901", // repeated variant
      7, // not a string
    ];
    for (const bad of malformed) {
      let thrown: unknown;
      try {
        validateMissionIntent(intent({ goal_lang: bad }));
      } catch (e) {
        thrown = e;
      }
      expect(thrown, JSON.stringify(bad)).toBeInstanceOf(IntentError);
      // The registered refusal the conformance row claims, not just any throw.
      expect((thrown as IntentError).code, JSON.stringify(bad)).toBe("invalid_request");
      expect((thrown as IntentError).message).toMatch(/goal_lang/);
    }
    // Committed like every Intent member: two Intents differing only in
    // goal_lang commit to different intent hashes.
    const a = approve(intent({ goal_lang: "en" }), 534001);
    const b = approve(intent({ goal_lang: "de" }), 534002);
    expect(a.intent_hash).not.toBe(b.intent_hash);
  });
  it("refuses a malformed goal_lang at the Submission-envelope intake with invalid_request (@spec mission#submission-via-par)", () => {
    let thrown: unknown;
    try {
      validateMissionIntentSubmission(
        JSON.stringify({ intent: JSON.parse(intent({ goal_lang: "de-419-DE" })) }),
      );
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(IntentError);
    expect((thrown as IntentError).code).toBe("invalid_request");
  });
  it("rejects proposed_authority resources outside the Intent's target_resources", () => {
    expect(() =>
      validateAuthorityProposal(
        JSON.stringify([
          { type: "mission_resource_access", resource: "https://other.example", actions: ["x"] },
        ]),
        [RESOURCE],
      ),
    ).toThrow(/not among Intent target_resources/);
  });

  // @spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata: a
  // proposal entry whose type is not one this AS advertises via the
  // authorization_details_types_metadata_endpoint MUST be refused.
  it("refuses a proposed_authority entry of an unadvertised type with invalid_authorization_details", () => {
    try {
      validateAuthorityProposal(
        JSON.stringify([{ type: "payment_initiation", resource: RESOURCE, actions: ["x"] }]),
        [RESOURCE],
      );
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/unsupported authorization details type/);
    }
  });

  // @spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata: a
  // same-type entry that fails its published JSON Schema MUST be refused too
  // (never silently carried into derivation with a malformed constraint).
  it("refuses a same-type proposed_authority entry that fails its published schema", () => {
    const badVendors = JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: "acme" },
      },
    ]);
    try {
      validateAuthorityProposal(badVendors, [RESOURCE]);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/fails its published schema/);
    }

    const badMaxAmount = JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: 100 },
      },
    ]);
    expect(() => validateAuthorityProposal(badMaxAmount, [RESOURCE])).toThrow(
      /fails its published schema/,
    );
  });

  // Regression: a schema-conformant proposal (the shape the published schema
  // and this check both accept) still validates and derives unchanged.
  it("still accepts a schema-conformant proposed_authority entry", () => {
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { max_amount: { amount: "10.00", currency: "USD" }, vendors: ["acme"] },
        },
      ]),
      [RESOURCE],
    );
    const validated = validateMissionIntent(intent());
    const derived = deriveAuthoritySet(validated, DERIVATION_POLICY as never, proposal);
    expect(derived[0]?.constraints?.vendors).toEqual(["acme"]);
  });
});

describe("derivation (@spec mission#authorization-derivation)", () => {
  it("compromised shaper: an over-broad proposal never widens past the ceiling", () => {
    const broad = validateMissionIntent(intent());
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:payment.execute", "payments:vendor.delete", "payments:invoice.read"],
          constraints: {
            max_amount: { amount: "999999.00", currency: "USD" },
            vendors: ["acme", "globex", "evilcorp"],
          },
        },
      ]),
      [RESOURCE],
    );
    const derived = deriveAuthoritySet(broad, DERIVATION_POLICY as never, proposal);
    expect(isSubsetSet(derived, DERIVATION_POLICY.ceiling as never)).toBe(true);
    const entry = derived[0];
    expect(entry?.actions).not.toContain("payments:vendor.delete");
    expect(entry?.constraints?.max_amount?.amount).toBe("500.00");
    expect(entry?.constraints?.vendors).toEqual(["acme"]);
  });

  it("refuses an Intent yielding no authority with invalid_authorization_details", () => {
    const bad = validateMissionIntent(intent());
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        { type: "mission_resource_access", resource: RESOURCE, actions: ["not:allowed"] },
      ]),
      [RESOURCE],
    );
    try {
      deriveAuthoritySet(bad, DERIVATION_POLICY as never, proposal);
      expect.unreachable();
    } catch (e) {
      expect((e as IntentError).code).toBe("invalid_authorization_details");
    }
  });

  // @spec mission#error-mapping — configured-mapping mode (no `authorization_details`
  // proposal submitted): a well-formed Intent the AS's own policy derives nothing
  // for is `access_denied`, never `invalid_authorization_details`, because no
  // proposal was ever submitted to be invalid.
  it("refuses a no-proposal Intent yielding no authority with access_denied", () => {
    const noMapping = validateMissionIntent(
      intent({ target_resources: ["https://unmapped.example.com"] }),
    );
    try {
      deriveAuthoritySet(noMapping, DERIVATION_POLICY as never, undefined);
      expect.unreachable();
    } catch (e) {
      expect((e as IntentError).code).toBe("access_denied");
    }
  });
});

describe("approval event and record (@spec mission#integrity-anchors)", () => {
  it("creates an active record with both anchors and is idempotent by approval_event_id", () => {
    const record = approve(intent(), 1);
    expect(record.state).toBe("active");
    expect(record.intent_hash).toMatch(/^sha-256:/);
    expect(record.authority_hash).toMatch(/^sha-256:/);
    expect(record.id).toMatch(/^msn_/);
    const again = approve(intent(), 1);
    expect(again.id).toBe(record.id);
  });
});

describe("mission record expiry ceiling (@spec mission#mission-record)", () => {
  it("commits an effective expires_at never later than the Intent's requested ceiling", () => {
    const raw = intent({ expires_at: "2026-12-01T00:00:00Z" });
    const requested = validateMissionIntent(raw);
    const record = approve(raw, 200);
    expect(Date.parse(record.expires_at)).toBeLessThanOrEqual(Date.parse(requested.expires_at));
  });
});

describe("approval basis (@spec mission#approval-basis)", () => {
  it("records a direct basis, round-tripped through the store, with approver == consent_principal == activation_actor", () => {
    const record = approve(intent(), 100);
    const stored = kernel.get(record.id);
    expect(stored?.approval_basis).toEqual({
      type: "direct",
      consent_principal: { iss: ISS, sub: "bob" },
      activation: { approval_event_id: "apev-100" },
      activation_actor: { iss: ISS, sub: "bob" },
      root_commitment: record.authority_hash,
    });
    // approver IS approval_basis.consent_principal (D48/O-38 convergence).
    expect(stored?.approver).toEqual(stored?.approval_basis.consent_principal);
    // Not folded into either integrity anchor: recomputing both from `intent`
    // and `authority_set` alone still matches, so approval_basis carries no
    // weight in the digests (the lock's hashing decision, made checkable).
    expect(record.intent_hash).toBe(intentHash(ISS, record.intent as never));
    expect(record.authority_hash).toBe(authorityHash(ISS, record.authority_set as never));
  });

  it("keeps the baseline mission claim to exactly {id, issuer}, with no authority_hash/approval_basis (#702)", () => {
    const record = approve(intent(), 101);
    const claim = kernel.missionClaim(kernel.get(record.id) as MissionRecord);
    expect(claim).toEqual({ id: record.id, issuer: ISS });
  });

  it("discloses approval_basis.type as a read-only signal only to a caller holding the disclosure privilege", () => {
    const record = approve(intent(), 102);
    const fresh = kernel.get(record.id) as MissionRecord;
    const privileged = kernel.introspectionProjection(fresh, { disclose: new Set(["provenance"]) });
    expect(privileged.approval_basis).toEqual({ type: "direct" });
    const unprivileged = kernel.introspectionProjection(fresh, { disclose: new Set() });
    expect(unprivileged.approval_basis).toBeUndefined();
  });
});

describe("approved context commitment (@spec mission-substrate#approved-context)", () => {
  it("the approved authority_set and its integrity anchor survive a state transition unchanged, while state and version (the mutable fields) advance", () => {
    const record = approve(intent(), 300);
    const authoritySetSnapshot = structuredClone(record.authority_set); // content snapshot, not a live reference
    const fresh = kernel.transition(record.id, "suspend");
    expect(fresh.authority_set).toEqual(authoritySetSnapshot);
    expect(fresh.authority_hash).toBe(record.authority_hash);
    expect(fresh.state).toBe("suspended");
    expect(fresh.version).toBeGreaterThan(record.version);
  });

  // The Approved Context is the Mission Intent, the recorded authority
  // proposal WHERE ONE WAS SUBMITTED, and the derived Authority Set
  // ({{mission-substrate#oauth-statement}} item 4) -- three components, not
  // one. This exercises a Mission approved WITH a submitted proposal (so all
  // three are present) and snapshots all three components and their three
  // typed anchors (intent_hash, proposal_hash, authority_hash) byte-for-byte
  // across TWO successive lifecycle transitions.
  it("all three Approved Context components (intent, proposal, derived authority_set) and their anchors survive successive state transitions unchanged", () => {
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { max_amount: { amount: "10.00", currency: "USD" }, vendors: ["acme"] },
        },
      ]),
      [RESOURCE],
    );
    const record = kernel.approve({
      intent: validateMissionIntent(intent()),
      proposedAuthority: proposal,
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-420",
    });
    // A proposal was actually submitted: both the record and proposal_hash
    // must be present, or this test would silently degrade to template mode.
    expect(record.proposed_authority).toBeDefined();
    expect(record.proposal_hash).toBeDefined();

    const intentSnapshot = structuredClone(record.intent);
    const proposalSnapshot = structuredClone(record.proposed_authority);
    const authoritySetSnapshot = structuredClone(record.authority_set);
    const anchors = {
      intent_hash: record.intent_hash,
      proposal_hash: record.proposal_hash,
      authority_hash: record.authority_hash,
    };

    kernel.transition(record.id, "suspend");
    // Re-read from the store, not transition()'s return value: setState()
    // returns a spread of its in-memory input record ({ ...record, state,
    // version }), so asserting against that return value would prove only
    // that the spread copied the field, never that the PERSISTED column was
    // left untouched. kernel.get() round-trips through rowToRecord, the same
    // path a fresh process restart would take.
    const afterSuspend = kernel.get(record.id) as MissionRecord;
    kernel.transition(record.id, "resume");
    const afterResume = kernel.get(record.id) as MissionRecord;

    for (const fresh of [afterSuspend, afterResume]) {
      expect(fresh.intent).toEqual(intentSnapshot);
      expect(fresh.proposed_authority).toEqual(proposalSnapshot);
      expect(fresh.authority_set).toEqual(authoritySetSnapshot);
      expect(fresh.intent_hash).toBe(anchors.intent_hash);
      expect(fresh.proposal_hash).toBe(anchors.proposal_hash);
      expect(fresh.authority_hash).toBe(anchors.authority_hash);
    }
    // Mutable fields DID advance, distinguishing them from the immutable value.
    expect(afterResume.state).toBe("active");
    expect(afterResume.version).toBeGreaterThan(afterSuspend.version);
    expect(afterSuspend.version).toBeGreaterThan(record.version);
  });
});

describe("actor binding at approval (@spec mission-substrate#actor-binding)", () => {
  it("binds the Mission Context to the client_id Actor handle at approval, and the binding round-trips unchanged", () => {
    const record = approve(intent(), 301);
    expect(record.client_id).toBe("ap-agent");
    const stored = kernel.get(record.id);
    expect(stored?.client_id).toBe("ap-agent");
  });
});

describe("mission reference unguessability (@spec mission-substrate#reference)", () => {
  it("the Mission Reference's random component carries at least 128 bits of entropy", () => {
    const record = approve(intent(), 302);
    const suffix = record.id.replace(/^msn_/, "");
    const decoded = Buffer.from(suffix, "base64url");
    expect(decoded.length).toBeGreaterThanOrEqual(16); // 128-bit floor; the kernel mints 18 bytes (144 bits)
  });

  // Length is not entropy: these test the SOURCE the helper draws from, not
  // merely the length of one identifier from one call site.
  it("newMissionId draws at least 18 bytes (144 bits) from a caller-injected random source", () => {
    let requestedSize: number | undefined;
    const observedSource = (size: number) => {
      requestedSize = size;
      return randomBytes(size); // still the real cryptographic source
    };
    const id = newMissionId(observedSource);
    expect(requestedSize).toBe(MISSION_ID_ENTROPY_BYTES);
    expect(requestedSize).toBeGreaterThanOrEqual(18);
    expect(id).toMatch(/^msn_/);
  });

  it("newMissionId's default source is node:crypto's randomBytes and needs no argument", () => {
    const id = newMissionId(); // no source supplied: exercises the default parameter itself
    const decoded = Buffer.from(id.replace(/^msn_/, ""), "base64url");
    expect(decoded.length).toBe(MISSION_ID_ENTROPY_BYTES);
    // The runtime check above proves the OUTPUT is shaped like the entropy
    // source's; this grounds the SOURCE identity itself: the default
    // parameter is bound to node:crypto's randomBytes, imported by name, not
    // a same-named local or an unrelated random function.
    const src = readFileSync(new URL("../src/kernel/mission-id.ts", import.meta.url), "utf8");
    expect(src).toContain('import { randomBytes } from "node:crypto"');
    expect(src).toMatch(/source:\s*\(size:\s*number\)\s*=>\s*Buffer\s*=\s*randomBytes/);
  });

  it("successive draws are distinct (sanity check, not a substitute for the entropy proof above)", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => newMissionId()));
    expect(ids.size).toBe(1000);
  });

  it("the four known msn_ minting sites all call the single newMissionId helper", () => {
    const sites = [
      "../src/kernel/kernel.ts",
      "../src/kernel/expansion.ts",
      "../src/kernel/template.ts",
      "../src/kernel/child-delegation.ts",
    ];
    for (const rel of sites) {
      const src = readFileSync(new URL(rel, import.meta.url), "utf8");
      expect(src.includes("newMissionId()"), `${rel} calls newMissionId()`).toBe(true);
    }
  });

  // Closes the class, not just the four known instances: a FIFTH minting
  // site added later, in a file this test does not name, would still be
  // caught, because every file in kernel/ is scanned, not only the four
  // above.
  it("no file in kernel/ other than mission-id.ts itself constructs an msn_ id inline", () => {
    const dirUrl = new URL("../src/kernel/", import.meta.url);
    const files = readdirSync(dirUrl).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
    expect(files.length).toBeGreaterThan(10); // sanity: the scan found the real kernel dir
    expect(files).toContain("mission-id.ts");
    for (const f of files) {
      if (f === "mission-id.ts") continue; // the one file allowed to construct it
      const src = readFileSync(new URL(f, dirUrl), "utf8");
      expect(src.includes("msn_${"), `${f} has no inline msn_ construction`).toBe(false);
    }
  });
});

describe("lifecycle (@spec status#legal-transitions)", () => {
  it("enforces the legal-transitions table with idempotent success", () => {
    const r = approve(intent(), 2);
    expect(kernel.transition(r.id, "suspend").state).toBe("suspended");
    expect(kernel.transition(r.id, "suspend").state).toBe("suspended"); // idempotent
    expect(kernel.transition(r.id, "resume").state).toBe("active");
    expect(() => kernel.transition(r.id, "resume")).toThrow(LifecycleConflictError); // resume exception
    expect(kernel.transition(r.id, "revoke").state).toBe("revoked");
    expect(() => kernel.transition(r.id, "suspend")).toThrow(LifecycleConflictError); // terminal
    expect(kernel.transition(r.id, "revoke").state).toBe("revoked"); // idempotent on terminal
  });

  it("gates derivation on state and derivation cap (@spec mission#lifecycle)", () => {
    const r = approve(intent({ requested_derivation_limit: 2 }), 3);
    expect(kernel.get(r.id)?.derivation_limit).toBe(2);
    kernel.gateDerivation(r.id);
    kernel.gateDerivation(r.id);
    expect(() => kernel.gateDerivation(r.id)).toThrow(GateError);
    const r2 = approve(intent(), 4);
    kernel.transition(r2.id, "suspend");
    expect(() => kernel.gateDerivation(r2.id)).toThrow(/suspended/);
  });

  it("@spec mission#derivation-issuance-policy: derivation_limit is min(policy ceiling, requested), never the request copied verbatim", async () => {
    // A LOCAL kernel whose policy ceiling (5) is narrower than one request and
    // wider than another, proving the clamp engages in both directions and
    // that omission defers entirely to the policy ceiling.
    const { privateKey } = await generateKeyPair("ES256");
    const localKernel = new MissionKernel({
      issuer: ISS,
      policy: { ...DERIVATION_POLICY, derivation_limit_ceiling: 5 } as never,
      statusKey: privateKey,
      statusKid: "as-status",
    });
    const localApprove = (over: Record<string, unknown>, n: number) =>
      localKernel.approve({
        intent: validateMissionIntent(intent(over)),
        subject: { iss: ISS, sub: "alice" },
        approver: { iss: ISS, sub: "bob" },
        clientId: "ap-agent",
        approvalEventId: `apev-clamp-${n}`,
      });
    // Requested (20) exceeds the ceiling (5): clamped down to the ceiling.
    expect(localApprove({ requested_derivation_limit: 20 }, 1).derivation_limit).toBe(5);
    // Requested (2) narrows below the ceiling (5): the narrower request wins.
    expect(localApprove({ requested_derivation_limit: 2 }, 2).derivation_limit).toBe(2);
    // Omitted request: the deployment's own ceiling applies unchanged, never
    // "unbounded by omission".
    expect(localApprove({}, 3).derivation_limit).toBe(5);
  });

  it("expiry clock: past expires_at the mission is expired and non-deriving", () => {
    const r = approve(intent({ expires_at: "2020-01-01T00:00:00Z" }), 5);
    expect(() => kernel.gateDerivation(r.id)).toThrow(GateError);
    expect(kernel.get(r.id)?.state).toBe("expired");
  });
});

// The Controller's Basic Governance Gate (@spec mission-substrate#basic-gate)
// is realized here, not by the resource-side PDP: gateActive and
// gateDerivation are the AS's state-gated issuance and derivation paths. The
// active predicate is a whitelist (`state === "active"`), so any persisted
// value outside the recognized MissionState set fails closed by construction,
// never by an explicit blocklist entry.
describe("basic governance gate: state-gated issuance and derivation (@spec mission-substrate#basic-gate)", () => {
  it("active predicate true -> gateActive and gateDerivation proceed", () => {
    const r = approve(intent(), 400);
    expect(kernel.gateActive(r.id).state).toBe("active");
    expect(kernel.gateDerivation(r.id).state).toBe("active");
  });

  it("active predicate false -> gateActive and gateDerivation refuse, for every recognized non-active state", () => {
    const nonActive = ["suspended", "revoked", "expired", "completed", "superseded", "cascaded"] as const;
    nonActive.forEach((state, i) => {
      const r = approve(intent(), 401 + i);
      kernel.db.prepare("UPDATE missions SET state = ? WHERE id = ?").run(state, r.id);
      expect(() => kernel.gateActive(r.id), state).toThrow(GateError);
      expect(() => kernel.gateDerivation(r.id), state).toThrow(GateError);
    });
  });

  it("a persisted state value outside the recognized lifecycle set fails closed, never treated as active", () => {
    const r = approve(intent(), 410);
    kernel.db.prepare("UPDATE missions SET state = ? WHERE id = ?").run("quantum_supervened", r.id);
    try {
      kernel.gateActive(r.id);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("mission_not_active");
    }
    try {
      kernel.gateDerivation(r.id);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("mission_not_active");
    }
  });
});

describe("signed status (@spec status#mission-status-response)", () => {
  it("emits a JWS with the mission object and audience-scoped authority", async () => {
    const r = approve(intent(), 6);
    const jws = await kernel.signedStatus(r.id, { audience: RESOURCE, requester: "svc:test", nonce: "n1" });
    const [h, p] = jws.split(".");
    const header = JSON.parse(Buffer.from(h as string, "base64url").toString());
    const payload = JSON.parse(Buffer.from(p as string, "base64url").toString());
    expect(header.typ).toBe("mission-status-response+jwt");
    expect(payload.mission.state).toBe("active");
    expect(payload.mission.fresh_until).toBeDefined();
    expect(payload.nonce).toBe("n1");
    expect(payload.authorization_details[0].resource).toBe(RESOURCE);
  });
});
