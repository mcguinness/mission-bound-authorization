/**
 * @spec authority-server#mission-join (#557)
 *
 * Standalone unit coverage for the baseline mapping join resolver: subject
 * join (rule 3), client join direct/delegate (rule 4), delegate narrowing
 * (rule 5), and uniform mission_mismatch denial with no fallback (rule 6).
 * Exercised directly against MissionView fixtures, independent of the PEP.
 */

import { describe, expect, it } from "vitest";
import { resolveBaselineJoin } from "../src/mas-join.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";

const RESOURCE = "https://api.example.test";
const READ = "payments:invoice.read";
const WRITE = "payments:payment.schedule";

const DIRECT_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ, WRITE] };
const DELEGABLE_ENTRY: AuthorityEntry = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: RESOURCE,
  actions: [READ],
  join_delegation: { max_depth: 2, allowed_delegates: ["delegate-a"] },
};
const NON_DELEGABLE_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [WRITE] };

function view(overrides: Partial<MissionView> = {}): MissionView {
  return {
    id: "mission-1",
    issuer: "https://as.example.test",
    state: "active",
    version: 1,
    authority_hash: "sha-256:test",
    authority_set: [DIRECT_ENTRY],
    subject: { iss: "https://idp.example.test", sub: "alice" },
    client_id: "ap-agent",
    ...overrides,
  };
}

const SUBJECT = { iss: "https://idp.example.test", sub: "alice" };

describe("resolveBaselineJoin: subject join (@spec authority-server#mission-join rule 3)", () => {
  it("joins when the authenticated subject matches the Mission's subject exactly", () => {
    const result = resolveBaselineJoin({ view: view(), subject: SUBJECT, clientId: "ap-agent" });
    expect(result).toEqual({ ok: true, disposition: "direct", authoritySet: [DIRECT_ENTRY] });
  });

  it("denies mission_mismatch when the subject sub differs", () => {
    const result = resolveBaselineJoin({ view: view(), subject: { ...SUBJECT, sub: "mallory" }, clientId: "ap-agent" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("denies mission_mismatch when the subject issuer differs (same sub)", () => {
    const result = resolveBaselineJoin({ view: view(), subject: { iss: "https://other-idp.test", sub: "alice" }, clientId: "ap-agent" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("resolveBaselineJoin: client join (@spec authority-server#mission-join rule 4)", () => {
  it("joins directly when the client_id matches the Mission's own client_id", () => {
    const result = resolveBaselineJoin({ view: view(), subject: SUBJECT, clientId: "ap-agent" });
    expect(result.ok).toBe(true);
    expect(result.ok && result.disposition).toBe("direct");
  });

  it("denies mission_mismatch for an unrecognized client with no delegate policy at all", () => {
    const result = resolveBaselineJoin({ view: view(), subject: SUBJECT, clientId: "unknown-client" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("denies mission_mismatch for a client not named in the delegate policy (no default)", () => {
    const result = resolveBaselineJoin({
      view: view(),
      subject: SUBJECT,
      clientId: "unknown-client",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("resolveBaselineJoin: delegate narrowing (@spec authority-server#mission-join rule 5)", () => {
  it("joins as a delegate and narrows to only the delegable, allowed entries", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DIRECT_ENTRY, DELEGABLE_ENTRY, NON_DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { depth: 1, maxDepth: 3 } } },
    });
    expect(result).toEqual({ ok: true, disposition: "delegate", authoritySet: [DELEGABLE_ENTRY] });
  });

  it("excludes an entry with no delegation member entirely, even for an authorized delegate", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [NON_DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("excludes an entry whose allowed_delegates does not name this delegate", () => {
    const otherDelegateEntry: AuthorityEntry = {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: [READ],
      join_delegation: { allowed_delegates: ["delegate-b"] },
    };
    const result = resolveBaselineJoin({
      view: view({ authority_set: [otherDelegateEntry] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("denies mission_mismatch when the recorded depth exceeds the delegate's max_depth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { depth: 5, maxDepth: 3 } } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("joins as a delegate when the recorded depth is within max_depth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { depth: 2, maxDepth: 3 } } },
    });
    expect(result.ok).toBe(true);
  });
});

describe("resolveBaselineJoin: no fallback (@spec authority-server#mission-join rule 6)", () => {
  it("a failed join never returns a partial or unjoined authoritySet", () => {
    const result = resolveBaselineJoin({ view: view(), subject: { ...SUBJECT, sub: "mallory" }, clientId: "ap-agent" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
    expect((result as { authoritySet?: unknown }).authoritySet).toBeUndefined();
  });
});
