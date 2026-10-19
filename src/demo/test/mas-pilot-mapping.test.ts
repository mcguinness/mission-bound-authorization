/**
 * @spec authority-server#mapping-contract (#818)
 *
 * The MAS pilot's versioned mapping contract and its governed cache, below the
 * gateway: the strict loader (ambiguous mappings refused, many-to-one
 * accepted), issuer-qualified resolution, disabled rows, reassignment by a
 * newer version, refused rollback, the staleness bound, invalidation, the
 * scope mapping, and the audit record of every mapping decision.
 */

import { describe, expect, it } from "vitest";
import { loadMasPilotConfig } from "../src/mas-pilot/config.js";
import {
  MappingContractCache,
  type MappingContractDocument,
  parseMappingContract,
} from "../src/mas-pilot/mapping-contract.js";

const MAS = "https://mas.test";
const ESTATE = "https://estate.test";
const RESOURCE = "http://localhost:4403/mcp";

function doc(over: Partial<MappingContractDocument> = {}): MappingContractDocument {
  return {
    contract_id: "test-contract",
    version: 1,
    issued_at: "2026-10-19T00:00:00Z",
    provenance: { source: "directory-export", export_id: "export-1", exported_at: "2026-10-19T00:00:00Z" },
    mission_issuer: MAS,
    subjects: [
      { from: { iss: ESTATE, sub: "u-1001" }, to: { iss: MAS, sub: "alice" }, status: "active" },
      { from: { iss: ESTATE, sub: "u-1002" }, to: { iss: MAS, sub: "alice" }, status: "active" },
      { from: { iss: ESTATE, sub: "u-1003" }, to: { iss: MAS, sub: "alice" }, status: "disabled" },
    ],
    clients: [{ from: { iss: ESTATE, client_id: "estate-bot" }, to: "ap-agent", status: "active" }],
    scopes: { resource: RESOURCE, issuers: { [ESTATE]: { "invoices.read": ["payments:invoice.read"], "vendors.read": ["payments:vendor.read"] } } },
    delegates: {},
    instance: { supported: false, required: false },
    failure: "mission_binding_failed",
    ...over,
  };
}

/** A clock the test moves. */
function clock(start = "2026-10-19T12:00:00Z") {
  let t = Date.parse(start);
  return { now: () => new Date(t), advance: (seconds: number) => { t += seconds * 1000; } };
}

const ask = (sub: string, clientId = "estate-bot", iss = ESTATE, now = new Date("2026-10-19T12:00:00Z")) => ({
  subject: { iss, sub },
  client: { iss, clientId },
  missionIssuer: MAS,
  now,
});

describe("mapping contract loader (@spec authority-server#mapping-contract, #818)", () => {
  it("accepts the shipped pilot contract, whose subject rows include a many-to-one mapping", () => {
    const shipped = loadMasPilotConfig().mapping_contract;
    expect(() => parseMappingContract(shipped)).not.toThrow();
    const parsed = parseMappingContract(shipped);
    expect(parsed.version).toBe(1);
    expect(parsed.failure).toBe("mission_binding_failed");
    expect(parsed.subjects.filter((r) => r.to.sub === "alice").length).toBeGreaterThan(1);
  });

  it("refuses a second row for one issuer-qualified estate subject as an ambiguous mapping", () => {
    const ambiguous = doc({
      subjects: [
        { from: { iss: ESTATE, sub: "u-1001" }, to: { iss: MAS, sub: "alice" }, status: "active" },
        { from: { iss: ESTATE, sub: "u-1001" }, to: { iss: MAS, sub: "bob" }, status: "active" },
      ],
    });
    expect(() => parseMappingContract(ambiguous)).toThrow(/ambiguous/);
  });

  it("refuses a second row for one issuer-qualified estate client as an ambiguous mapping", () => {
    const ambiguous = doc({
      clients: [
        { from: { iss: ESTATE, client_id: "estate-bot" }, to: "ap-agent", status: "active" },
        { from: { iss: ESTATE, client_id: "estate-bot" }, to: "other-agent", status: "active" },
      ],
    });
    expect(() => parseMappingContract(ambiguous)).toThrow(/ambiguous/);
  });

  it("accepts one sub string under two issuers: the issuer qualifies the row", () => {
    const twoIssuers = doc({
      subjects: [
        { from: { iss: ESTATE, sub: "u-1001" }, to: { iss: MAS, sub: "alice" }, status: "active" },
        { from: { iss: "https://other-estate.test", sub: "u-1001" }, to: { iss: MAS, sub: "bob" }, status: "active" },
      ],
    });
    expect(() => parseMappingContract(twoIssuers)).not.toThrow();
    expect(parseMappingContract(twoIssuers).subjects).toHaveLength(2);
  });

  it("refuses an unknown member, a claimed instance-identity mapping, and any failure semantics but mission_binding_failed", () => {
    expect(() => parseMappingContract({ ...doc(), extra: true })).toThrow(/unknown member/);
    expect(() => parseMappingContract({ ...doc(), instance: { supported: true, required: false } })).toThrow(/instance/);
    expect(() => parseMappingContract({ ...doc(), failure: "out_of_authority" })).toThrow(/failure/);
  });
});

describe("mapping contract cache: resolution (@spec authority-server#mission-join rules 3 and 4, #818)", () => {
  it("maps an issuer-qualified estate subject and client into the Mission's namespace", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    expect(cache.install(doc()).ok).toBe(true);
    expect(cache.current().resolveIdentity(ask("u-1001"))).toEqual({ subject: { iss: MAS, sub: "alice" }, clientId: "ap-agent" });
  });

  it("resolves nothing for the same sub and client strings under another issuer", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity(ask("u-1001", "estate-bot", "https://other-estate.test"))).toBeUndefined();
  });

  it("resolves nothing for a disabled account, though its row maps to the Mission's subject", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity(ask("u-1003"))).toBeUndefined();
  });

  it("resolves two estate accounts mapped to one Mission subject, and audits which account each decision resolved", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity(ask("u-1001"))?.subject.sub).toBe("alice");
    expect(cache.current().resolveIdentity(ask("u-1002"))?.subject.sub).toBe("alice");
    const resolved = cache.audit().filter((r) => r.kind === "identity" && r.outcome === "resolved");
    expect(resolved.map((r) => (r.kind === "identity" ? r.from.subject.sub : undefined))).toEqual(["u-1001", "u-1002"]);
    for (const r of resolved) {
      if (r.kind === "identity") expect(r.contract).toEqual({ id: "test-contract", version: 1, export_id: "export-1" });
    }
  });

  it("resolves nothing for a Mission at another Mission Issuer than the contract's", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity({ ...ask("u-1001"), missionIssuer: "https://other-mas.test" })).toBeUndefined();
    expect(cache.audit().at(-1)).toMatchObject({ kind: "identity", outcome: "wrong_mission_issuer" });
  });
});

describe("mapping contract cache: versions and freshness (@spec authority-server#mapping-contract, #818)", () => {
  it("a newer version reassigning an estate account changes the join: the account no longer resolves to its former owner", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity(ask("u-1001"))?.subject.sub).toBe("alice");
    const reassigned = doc({
      version: 2,
      provenance: { source: "directory-export", export_id: "export-2", exported_at: "2026-10-19T06:00:00Z" },
      subjects: [{ from: { iss: ESTATE, sub: "u-1001" }, to: { iss: MAS, sub: "carol" }, status: "active" }],
    });
    expect(cache.install(reassigned)).toEqual({ ok: true, version: 2 });
    expect(cache.current().resolveIdentity(ask("u-1001"))?.subject).toEqual({ iss: MAS, sub: "carol" });
  });

  it("refuses an install at or below the installed version, keeping the installed one", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc({ version: 2 }));
    const rollback = cache.install(doc({ version: 1, subjects: [] }));
    expect(rollback.ok).toBe(false);
    expect(cache.current().version).toBe(2);
    expect(cache.current().resolveIdentity(ask("u-1001"))?.subject.sub).toBe("alice");
    expect(cache.audit().some((r) => r.kind === "install_refused")).toBe(true);
  });

  it("fails closed once the installed version is older than the staleness bound, and recovers on the next install", () => {
    const c = clock();
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: c.now });
    cache.install(doc());
    c.advance(300);
    expect(cache.current().resolveIdentity(ask("u-1001", "estate-bot", ESTATE, c.now()))?.subject.sub).toBe("alice");
    c.advance(1);
    const stale = cache.current();
    expect(stale.resolveIdentity(ask("u-1001", "estate-bot", ESTATE, c.now()))).toBeUndefined();
    expect(stale.clientFor({ iss: ESTATE, clientId: "estate-bot" }, c.now())).toBeUndefined();
    expect(stale.credentialAuthority({ issuer: ESTATE, scope: "invoices.read", resource: RESOURCE, now: c.now() })).toBeUndefined();
    expect(cache.audit().at(-1)).toMatchObject({ kind: "identity", outcome: "stale" });
    cache.install(doc({ version: 2 }));
    expect(cache.current().resolveIdentity(ask("u-1001", "estate-bot", ESTATE, c.now()))?.subject.sub).toBe("alice");
  });

  it("an invalidated cache resolves nothing, and records each refused decision", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    cache.invalidate();
    expect(cache.current().resolveIdentity(ask("u-1001"))).toBeUndefined();
    expect(cache.audit().at(-1)).toMatchObject({ kind: "identity", outcome: "no_snapshot" });
  });
});

describe("mapping contract cache: the scope mapping (@spec authority-server#mission-join rule 8, #818)", () => {
  it("maps each covered scope value to its actions at the contract's resource, and an uncovered value to nothing", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    const now = new Date("2026-10-19T12:00:00Z");
    expect(cache.current().credentialAuthority({ issuer: ESTATE, scope: "invoices.read admin.all", resource: RESOURCE, now })).toEqual([
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
    ]);
    expect(cache.current().credentialAuthority({ issuer: ESTATE, scope: "admin.all", resource: RESOURCE, now })).toBeUndefined();
  });

  it("maps nothing for another issuer's identical scope value, another resource, or a credential with no scope", () => {
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    const now = new Date("2026-10-19T12:00:00Z");
    const current = cache.current();
    expect(current.credentialAuthority({ issuer: "https://other-estate.test", scope: "invoices.read", resource: RESOURCE, now })).toBeUndefined();
    expect(current.credentialAuthority({ issuer: ESTATE, scope: "invoices.read", resource: "https://other.test/mcp", now })).toBeUndefined();
    expect(current.credentialAuthority({ issuer: ESTATE, scope: undefined, resource: RESOURCE, now })).toBeUndefined();
  });
});
