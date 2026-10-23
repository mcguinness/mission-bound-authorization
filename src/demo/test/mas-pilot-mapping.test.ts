/**
 * @spec authority-server#mapping-contract (#818)
 *
 * The MAS pilot's versioned mapping contract and its governed cache, below the
 * gateway: the strict loader (ambiguous mappings refused, many-to-one
 * accepted), issuer-qualified resolution, disabled rows, reassignment by a
 * newer version, refused rollback, the staleness bound, invalidation, the
 * scope mapping, and the audit record of every mapping decision.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadMasPilotConfig, parseMasPilotConfig, relocateMissionIssuer } from "../src/mas-pilot/config.js";
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

  it("reports a snapshot usable within the staleness bound and unusable once stale, invalidated, or never installed", () => {
    const c = clock();
    const cache = new MappingContractCache({ maxStaleSeconds: 300, now: c.now });
    expect(cache.current().usable(c.now())).toBe(false);
    cache.install(doc());
    expect(cache.current().usable(c.now())).toBe(true);
    c.advance(301);
    expect(cache.current().usable(c.now())).toBe(false);
    cache.install(doc({ version: 2 }));
    expect(cache.current().usable(c.now())).toBe(true);
    cache.invalidate();
    expect(cache.current().usable(c.now())).toBe(false);
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

describe("pilot configuration: the estate's development Resource-policy grants (@spec runtime#input-resource-policy, #818 slice 2)", () => {
  const raw = () =>
    JSON.parse(readFileSync(new URL("../../config/mas-pilot.json", import.meta.url), "utf8")) as Record<string, unknown>;
  const withPolicy = (resourcePolicy: unknown) => ({ ...raw(), resource_policy: resourcePolicy });
  const tenants = [{ tenant: "t", vendors: ["acme"], members: [{ sub: "u-1001" }] }];

  it("loads the shipped grants: every entitled principal is a tenant member, subjects as readers, clients with authorized_client", () => {
    const policy = loadMasPilotConfig().resource_policy;
    const members = new Set(policy.tenants.flatMap((t) => t.members.map((m) => JSON.stringify(m))));
    expect(policy.entitlements.length).toBeGreaterThan(0);
    for (const e of policy.entitlements) {
      const who = "sub" in e ? { sub: e.sub } : { client: e.client };
      expect(members.has(JSON.stringify(who)), JSON.stringify(e)).toBe(true);
      expect(e.relation).toBe("sub" in e ? "authorized_reader" : "authorized_client");
    }
  });

  it("refuses a client holding a subject relation and a subject holding authorized_client", () => {
    const clientAsReader = withPolicy({ tenants, entitlements: [{ client: "estate-ap-bot-7f3", relation: "authorized_reader", vendor: "acme" }] });
    const subjectAsClient = withPolicy({ tenants, entitlements: [{ sub: "u-1001", relation: "authorized_client", vendor: "acme" }] });
    expect(() => parseMasPilotConfig(clientAsReader)).toThrow(/authorized_client for a client/);
    expect(() => parseMasPilotConfig(subjectAsClient)).toThrow(/authorized_reader or authorized_payer for a subject/);
  });

  it("loads the shipped separated MAS: its PDP enrolled for the payments enforcement scope, the state source placed with the PDP (#818 slice 4b)", () => {
    const separated = loadMasPilotConfig().separated_mas;
    expect(separated.state_source.placement).toBe("pdp");
    // The pilot's PEP and PDP are one enforcement point under one client: both roles (#1591).
    expect(separated.enrollment).toContainEqual({ client_id: separated.pdp_client_id, roles: ["pep", "pdp"], enforcement_scopes: [RESOURCE] });
  });

  it("refuses a separated MAS whose state source is placed anywhere but the PDP, a non-positive bound, or an unknown member (#818 slice 4b)", () => {
    const separated = raw().separated_mas as Record<string, unknown> & { state_source: Record<string, unknown> };
    const withSeparated = (over: Record<string, unknown>) => ({ ...raw(), separated_mas: { ...separated, ...over } });
    expect(() => parseMasPilotConfig(withSeparated({ state_source: { ...separated.state_source, placement: "pep" } }))).toThrow(
      /placement must be "pdp"/,
    );
    expect(() => parseMasPilotConfig(withSeparated({ state_source: { ...separated.state_source, timeout_ms: 0 } }))).toThrow(
      /timeout_ms must be a positive integer/,
    );
    expect(() => parseMasPilotConfig(withSeparated({ extra: true }))).toThrow(/unknown member extra/);
  });

  it("refuses a member or an entitlement naming both a subject and a client", () => {
    const bothMember = withPolicy({ tenants: [{ tenant: "t", vendors: ["acme"], members: [{ sub: "u-1001", client: "x" }] }], entitlements: [] });
    const bothEntitlement = withPolicy({ tenants, entitlements: [{ sub: "u-1001", client: "x", relation: "authorized_reader", vendor: "acme" }] });
    expect(() => parseMasPilotConfig(bothMember)).toThrow(/sub or client|unknown member/);
    expect(() => parseMasPilotConfig(bothEntitlement)).toThrow(/sub or client|unknown member/);
  });
});

describe("pilot configuration: relocating the Mission issuer (#818 slice 5B, #1466 review)", () => {
  const shippedRaw = () => readFileSync(new URL("../../config/mas-pilot.json", import.meta.url), "utf8");
  const NEW = "http://127.0.0.1:14834";

  /** The configuration with only the Mission-issuer fields set to `url`: what a relocation must produce. */
  function expectedAt(config: ReturnType<typeof parseMasPilotConfig>, url: string) {
    const contract = config.mapping_contract as MappingContractDocument;
    return {
      ...config,
      mission_issuer: url,
      mapping_contract: { ...contract, mission_issuer: url, subjects: contract.subjects.map((r) => ({ ...r, to: { ...r.to, iss: url } })) },
      routes: config.routes.map((r) => (r.admits === "mission-bound" ? { ...r, issuer: url } : r)),
    };
  }

  it("moves only the Mission-issuer fields when the old issuer is a prefix of the estate issuer, leaving estate URLs and identities intact", () => {
    // The owner's reproduction: a Mission issuer that is a string prefix of the estate issuer.
    const config = parseMasPilotConfig(JSON.parse(shippedRaw().replaceAll("https://mas.pilot.invalid", "http://127.0.0.1")));
    expect(config.mission_issuer).toBe("http://127.0.0.1");
    expect(config.estate.issuer).toBe("http://127.0.0.1:14818");
    const relocated = relocateMissionIssuer(config, NEW);
    expect(relocated).toEqual(expectedAt(config, NEW));
    expect(relocated.estate.issuer).toBe("http://127.0.0.1:14818");
    const contract = relocated.mapping_contract as MappingContractDocument;
    expect(contract.subjects.map((r) => r.from.iss)).toEqual(contract.subjects.map(() => "http://127.0.0.1:14818"));
    expect(contract.clients.map((r) => r.from.iss)).toEqual(contract.clients.map(() => "http://127.0.0.1:14818"));
    expect(Object.keys(contract.scopes.issuers)).toEqual(["http://127.0.0.1:14818"]);
    expect(relocated.routes.find((r) => r.route === "gateway")?.issuer).toBe("http://127.0.0.1:14818");
    expect(JSON.stringify(relocated)).not.toContain(`${NEW}:`);
    expect(parseMappingContract(relocated.mapping_contract).mission_issuer).toBe(NEW);
  });

  it("moves the shipped configuration's Mission issuer in its four fields and nowhere else, and the contract still loads", () => {
    const config = loadMasPilotConfig();
    const relocated = relocateMissionIssuer(config, NEW);
    expect(relocated).toEqual(expectedAt(config, NEW));
    const contract = parseMappingContract(relocated.mapping_contract);
    expect(contract.mission_issuer).toBe(NEW);
    expect(contract.subjects.every((r) => r.to.iss === NEW)).toBe(true);
    expect(relocated.routes.find((r) => r.admits === "mission-bound")?.issuer).toBe(NEW);
  });

  it("returns the configuration unchanged when it already names the URL", () => {
    const config = loadMasPilotConfig();
    expect(relocateMissionIssuer(config, config.mission_issuer)).toBe(config);
  });
});
