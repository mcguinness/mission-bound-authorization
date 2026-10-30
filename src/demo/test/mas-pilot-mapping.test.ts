/**
 * @spec authority-server#mapping-contract (#818)
 *
 * The MAS pilot's versioned mapping contract and its governed cache, below the
 * gateway: the strict loader (ambiguous mappings refused, many-to-one
 * accepted), issuer-qualified resolution, disabled rows, reassignment by a
 * newer version, refused rollback, the staleness bound, invalidation, the
 * scope mapping, and the audit record of every mapping decision.
 */

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { initSharedStore, openSharedStore } from "@mission/store";
import { describe, expect, it } from "vitest";
import { RESOURCE_CONTRACTS } from "@mission/demo-data";
import {
  initScopeBindingLedger,
  MemoryScopeBindingLedger,
  type ScopeBindingLedger,
  SqliteScopeBindingLedger,
} from "../src/mas-pilot/scope-binding-ledger.js";
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

describe("mapping contract delegates: each client identifier is the policy's own entry (@spec authority-server#mission-join rule 4, #1884)", () => {
  it("installs a delegate named __proto__ as an ordinary entry of the snapshot's delegate policy, which has no prototype", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    expect(cache.install(doc({ delegates: JSON.parse('{"__proto__": {"max_depth": 1}}') })).ok).toBe(true);
    const delegates = cache.current().delegatePolicy?.delegates as Record<string, { maxDepth?: number }>;
    expect(Object.getPrototypeOf(delegates)).toBeNull();
    expect(Object.keys(delegates)).toEqual(["__proto__"]);
    expect(Object.getOwnPropertyDescriptor(delegates, "__proto__")?.value).toEqual({ maxDepth: 1 });
  });
});

describe("mapping contract cache: resolution (@spec authority-server#mission-join rules 3 and 4, #818)", () => {
  it("maps an issuer-qualified estate subject and client into the Mission's namespace", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    expect(cache.install(doc()).ok).toBe(true);
    expect(cache.current().resolveIdentity(ask("u-1001"))).toEqual({ subject: { iss: MAS, sub: "alice" }, clientId: "ap-agent" });
  });

  it("resolves nothing for the same sub and client strings under another issuer", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity(ask("u-1001", "estate-bot", "https://other-estate.test"))).toBeUndefined();
  });

  it("resolves nothing for a disabled account, though its row maps to the Mission's subject", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity(ask("u-1003"))).toBeUndefined();
  });

  it("resolves two estate accounts mapped to one Mission subject, and audits which account each decision resolved", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
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
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    expect(cache.current().resolveIdentity({ ...ask("u-1001"), missionIssuer: "https://other-mas.test" })).toBeUndefined();
    expect(cache.audit().at(-1)).toMatchObject({ kind: "identity", outcome: "wrong_mission_issuer" });
  });
});

describe("mapping contract cache: versions and freshness (@spec authority-server#mapping-contract, #818)", () => {
  it("a newer version reassigning an estate account changes the join: the account no longer resolves to its former owner", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
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
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    cache.install(doc({ version: 2 }));
    const rollback = cache.install(doc({ version: 1, subjects: [] }));
    expect(rollback.ok).toBe(false);
    expect(cache.current().version).toBe(2);
    expect(cache.current().resolveIdentity(ask("u-1001"))?.subject.sub).toBe("alice");
    expect(cache.audit().some((r) => r.kind === "install_refused")).toBe(true);
  });

  it("fails closed once the installed version is older than the staleness bound, and recovers on the next install", () => {
    const c = clock();
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: c.now });
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
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: c.now });
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
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    cache.invalidate();
    expect(cache.current().resolveIdentity(ask("u-1001"))).toBeUndefined();
    expect(cache.audit().at(-1)).toMatchObject({ kind: "identity", outcome: "no_snapshot" });
  });
});

describe("mapping contract cache: the scope mapping (@spec authority-server#mission-join rule 8, #818)", () => {
  it("maps each covered scope value to its actions at the contract's resource, and an uncovered value to nothing", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    cache.install(doc());
    const now = new Date("2026-10-19T12:00:00Z");
    expect(cache.current().credentialAuthority({ issuer: ESTATE, scope: "invoices.read admin.all", resource: RESOURCE, now })).toEqual([
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
    ]);
    expect(cache.current().credentialAuthority({ issuer: ESTATE, scope: "admin.all", resource: RESOURCE, now })).toBeUndefined();
  });

  it("maps nothing for another issuer's identical scope value, another resource, or a credential with no scope", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
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

  it("names the estate issuer's trusted kids explicitly, and refuses a configuration that names none (#831 C2b, D825)", () => {
    expect(loadMasPilotConfig().estate.trusted_kids).toEqual(["estate-signing-1"]);
    const estate = raw().estate as Record<string, unknown>;
    const { trusted_kids: _dropped, ...without } = estate;
    expect(() => parseMasPilotConfig({ ...raw(), estate: without })).toThrow(/estate is missing trusted_kids/);
    expect(() => parseMasPilotConfig({ ...raw(), estate: { ...estate, trusted_kids: [] } })).toThrow(/estate.trusted_kids must list at least one kid/);
  });

  it("refuses an enrollee with no roles member, no role, an unknown role, or one role twice (#1591, D708)", () => {
    const separated = raw().separated_mas as Record<string, unknown> & { enrollment: Array<Record<string, unknown>> };
    const enrollee = separated.enrollment[0] as Record<string, unknown>;
    const withEnrollee = (over: Record<string, unknown>) => ({ ...raw(), separated_mas: { ...separated, enrollment: [{ ...enrollee, ...over }] } });
    const { roles: _roles, ...noRoles } = enrollee;
    expect(() => parseMasPilotConfig({ ...raw(), separated_mas: { ...separated, enrollment: [noRoles] } })).toThrow(/missing roles/);
    for (const roles of [[], ["admin"], ["pdp", "pdp"]]) {
      expect(() => parseMasPilotConfig(withEnrollee({ roles })), JSON.stringify(roles)).toThrow(/roles must be "pep", "pdp", or both/);
    }
    expect(parseMasPilotConfig(withEnrollee({ roles: ["pep"] })).separated_mas.enrollment[0]?.roles).toEqual(["pep"]);
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

const [PAYMENTS_DECLARED] = RESOURCE_CONTRACTS.declarations;
/** The reference of the payments contract's declared `version`. */
const contractAt = (version: string) => {
  const v = PAYMENTS_DECLARED?.versions.find((x) => x.version === version);
  return { id: PAYMENTS_DECLARED?.id as string, version, digest: v?.digest as string };
};
const CURRENT_VERSION = PAYMENTS_DECLARED?.versions.find((v) => v.state === "current")?.version as string;
const OLDER_VERSION = PAYMENTS_DECLARED?.versions.find((v) => v.state === "superseded")?.version as string;
const LACKING_REVERSE = PAYMENTS_DECLARED?.versions.find(
  (v) => v.state !== "retired" && !v.operations.includes("payments:payment.reverse"),
)?.version as string;

/**
 * @spec authority-server#mapping-contract, resource-access#resource-contract
 * (#1847, D989): the MAS pilot's versioned mapping contract may state the
 * contract a scope value grants its actions under. The bound is one entry per
 * distinct contract; a newer version never repoints an existing value's
 * contract, so a credential issued under an earlier mapping never gains one,
 * and a new contract takes a new value.
 */
describe("mapping contract cache: a scope value's stated contract (@spec authority-server#mapping-contract, resource-access#resource-contract, #1847, D989)", () => {
  const now = new Date("2026-10-19T12:00:00Z");
  const READ = ["payments:invoice.read"];
  const withScopes = (values: Record<string, unknown>, version = 1) =>
    doc({ version, scopes: { resource: RESOURCE, issuers: { [ESTATE]: values } } as never });

  it("confers an entry carrying a value's stated contract, a legacy value's entry without one, never combining contracts", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    const current = contractAt(CURRENT_VERSION);
    const older = contractAt(OLDER_VERSION);
    expect(
      cache.install(
        withScopes({
          "invoices.read": READ,
          "invoices.read.contract-current": { actions: READ, resource_contract: current },
          "invoices.read.contract-older": { actions: READ, resource_contract: older },
        }),
      ),
    ).toMatchObject({ ok: true });
    expect(
      cache.current().credentialAuthority({
        issuer: ESTATE,
        scope: "invoices.read invoices.read.contract-current invoices.read.contract-older",
        resource: RESOURCE,
        now,
      }),
    ).toEqual([
      { type: "mission_resource_access", resource: RESOURCE, actions: READ },
      { type: "mission_resource_access", resource: RESOURCE, actions: READ, resource_contract: current },
      { type: "mission_resource_access", resource: RESOURCE, actions: READ, resource_contract: older },
    ]);
  });

  it("refuses at load a value stating a reference the declarations do not support for the action", () => {
    expect(() => parseMappingContract(withScopes({ "invoices.read.bad": { actions: READ, resource_contract: contractAt("1999-01-01") } }))).toThrow(
      /resource_contract/,
    );
    expect(() =>
      parseMappingContract(withScopes({ "reverse.bad": { actions: ["payments:payment.reverse"], resource_contract: contractAt(LACKING_REVERSE) } })),
    ).toThrow(/every action/);
  });

  it("refuses a newer version that repoints an existing value's contract, and accepts one that adds a new value", () => {
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    const current = contractAt(CURRENT_VERSION);
    const older = contractAt(OLDER_VERSION);
    expect(cache.install(withScopes({ "invoices.read": READ, "invoices.read.contract-older": { actions: READ, resource_contract: older } }, 1))).toMatchObject({ ok: true });
    // A legacy value given a contract, and a stated value given another: both refused.
    for (const repointed of [
      { "invoices.read": { actions: READ, resource_contract: current }, "invoices.read.contract-older": { actions: READ, resource_contract: older } },
      { "invoices.read": READ, "invoices.read.contract-older": { actions: READ, resource_contract: current } },
    ]) {
      const refused = cache.install(withScopes(repointed, 2));
      expect(refused.ok).toBe(false);
      expect(!refused.ok && refused.reason).toMatch(/repoints scope/);
    }
    // A new value for the newer contract: accepted, the earlier values unchanged.
    expect(
      cache.install(
        withScopes(
          {
            "invoices.read": READ,
            "invoices.read.contract-older": { actions: READ, resource_contract: older },
            "invoices.read.contract-current": { actions: READ, resource_contract: current },
          },
          2,
        ),
      ),
    ).toMatchObject({ ok: true, version: 2 });
  });

  it("refuses a newer version that withdraws a value whose stated contract is still supported, and accepts the withdrawal of a value stating none, or once its contract is not supported", () => {
    const c = clock();
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: c.now });
    const current = contractAt(CURRENT_VERSION);
    const older = contractAt(OLDER_VERSION);
    const stated = (ref: typeof current) => ({ actions: READ, resource_contract: ref });
    expect(
      cache.install(
        withScopes(
          { "invoices.read": READ, "invoices.read.contract-older": stated(older), "invoices.read.contract-current": stated(current) },
          1,
        ),
      ),
    ).toMatchObject({ ok: true });
    // Withdrawing either stated value while its contract is supported: refused.
    for (const kept of [
      { "invoices.read": READ, "invoices.read.contract-current": stated(current) },
      { "invoices.read": READ, "invoices.read.contract-older": stated(older) },
    ]) {
      const refused = cache.install(withScopes(kept, 2));
      expect(refused.ok).toBe(false);
      expect(!refused.ok && refused.reason).toMatch(/withdraws scope/);
    }
    // The legacy value states no contract: it may be withdrawn.
    expect(
      cache.install(withScopes({ "invoices.read.contract-older": stated(older), "invoices.read.contract-current": stated(current) }, 2)),
    ).toMatchObject({ ok: true, version: 2 });
    // Past the older version's declared retention, its value may be withdrawn too.
    const retainedUntil = PAYMENTS_DECLARED?.versions.find((v) => v.version === OLDER_VERSION)?.retained_until as string;
    expect(cache.install(withScopes({ "invoices.read.contract-current": stated(current) }, 3)).ok).toBe(false);
    c.advance((Date.parse(retainedUntil) - c.now().getTime()) / 1000 + 1);
    expect(cache.install(withScopes({ "invoices.read.contract-current": stated(current) }, 3))).toMatchObject({ ok: true, version: 3 });
  });
});

/**
 * @spec authority-server#mapping-contract, authority-server#mission-join rule 8
 * (#1847, #1866 review): the pilot's snapshot reads only the mapping's own
 * entries, for a credential's scope values and for its issuer.
 */
describe("mapping contract cache: only the mapping's own entries confer authority (@spec authority-server#mapping-contract, #1847)", () => {
  const now = new Date("2026-10-19T12:00:00Z");
  const READ = ["payments:invoice.read"];

  it.each(["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"])(
    "a credential scope or issuer named %s confers nothing and never throws, alone or beside a mapped value",
    (name) => {
      const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
      expect(cache.install(doc()).ok).toBe(true);
      const authority = (scope: string, issuer = ESTATE) =>
        cache.current().credentialAuthority({ issuer, scope, resource: RESOURCE, now });
      expect(authority(name)).toBeUndefined();
      expect(authority(`${name} invoices.read`)).toEqual([{ type: "mission_resource_access", resource: RESOURCE, actions: READ }]);
      expect(authority("invoices.read", name)).toBeUndefined();
    },
  );

  it("parses a mapping key named __proto__ as an ordinary scope value", () => {
    const raw = JSON.parse(JSON.stringify(doc()).replace('"invoices.read":', '"__proto__":["payments:invoice.list"],"invoices.read":'));
    const cache = new MappingContractCache({ ledger: new MemoryScopeBindingLedger(), maxStaleSeconds: 300, now: clock().now });
    expect(cache.install(raw).ok).toBe(true);
    expect(cache.current().credentialAuthority({ issuer: ESTATE, scope: "__proto__", resource: RESOURCE, now })).toEqual([
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.list"] },
    ]);
  });
});

/**
 * @spec resource-access#resource-contract (#1847, D989, #1866 review): a scope
 * value's binding, its stated contract or none, is kept in the deployment's
 * scope binding ledger, never removed and never changed. A withdrawn value
 * keeps it, and a cache started again over the same ledger reads it, so no
 * version, withdrawal or restart lets an issued credential gain a contract;
 * and the keep-while-supported rule reads the same history.
 */
describe("mapping contract cache: the scope binding ledger (@spec authority-server#mapping-contract, resource-access#resource-contract, #1847, #1866 review)", () => {
  const READ = ["payments:invoice.read"];
  const withScopes = (values: Record<string, unknown>, version: number) =>
    doc({ version, scopes: { resource: RESOURCE, issuers: { [ESTATE]: values } } as never });
  const stated = (ref: ReturnType<typeof contractAt>) => ({ actions: READ, resource_contract: ref });
  const cacheOver = (ledger: ScopeBindingLedger, now = clock().now) => new MappingContractCache({ ledger, maxStaleSeconds: 300, now });
  const refusedFor = (r: { ok: boolean; reason?: string }, why: RegExp) => {
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(why);
  };

  it("refuses reintroducing a withdrawn value under another binding, a value stating none included", () => {
    const current = contractAt(CURRENT_VERSION);
    const cache = cacheOver(new MemoryScopeBindingLedger());
    expect(cache.install(withScopes({ legacy: READ, other: READ }, 1)).ok).toBe(true);
    expect(cache.install(withScopes({ other: READ }, 2)).ok).toBe(true);
    refusedFor(cache.install(withScopes({ other: READ, legacy: stated(current) }, 3)), /repoints scope .* legacy/);
    // Reintroduced as it was bound: accepted.
    expect(cache.install(withScopes({ other: READ, legacy: READ }, 3))).toMatchObject({ ok: true, version: 3 });
  });

  it("refuses reintroducing a value withdrawn after its contract's retention under the current contract", () => {
    const c = clock();
    const current = contractAt(CURRENT_VERSION);
    const older = contractAt(OLDER_VERSION);
    const cache = cacheOver(new MemoryScopeBindingLedger(), c.now);
    expect(cache.install(withScopes({ "invoices.read.contract-older": stated(older) }, 1)).ok).toBe(true);
    const retainedUntil = PAYMENTS_DECLARED?.versions.find((v) => v.version === OLDER_VERSION)?.retained_until as string;
    c.advance((Date.parse(retainedUntil) - c.now().getTime()) / 1000 + 1);
    expect(cache.install(withScopes({}, 2)).ok).toBe(true);
    refusedFor(cache.install(withScopes({ "invoices.read.contract-older": stated(current) }, 3)), /repoints scope/);
  });

  it("a cache started again over the same ledger keeps every binding and the keep-while-supported rule", () => {
    const current = contractAt(CURRENT_VERSION);
    const ledger = new MemoryScopeBindingLedger();
    expect(cacheOver(ledger).install(withScopes({ legacy: READ, "invoices.read.contract-current": stated(current) }, 1)).ok).toBe(true);
    const restarted = cacheOver(ledger);
    refusedFor(restarted.install(withScopes({ legacy: stated(current), "invoices.read.contract-current": stated(current) }, 2)), /repoints scope/);
    refusedFor(restarted.install(withScopes({ legacy: READ }, 2)), /withdraws scope .* invoices\.read\.contract-current/);
    expect(restarted.install(withScopes({ legacy: READ, "invoices.read.contract-current": stated(current) }, 2)).ok).toBe(true);
  });

  it("two caches over one ledger, as the gateway and the MAS's Join Assertion path are, install the same document", () => {
    const ledger = new MemoryScopeBindingLedger();
    const current = contractAt(CURRENT_VERSION);
    const document = withScopes({ legacy: READ, "invoices.read.contract-current": stated(current) }, 1);
    expect(cacheOver(ledger).install(document).ok).toBe(true);
    expect(cacheOver(ledger).install(document).ok).toBe(true);
    expect(stateOf(ledger).bindings).toHaveLength(2);
  });

  // D1019: the version high-water mark is kept with the bindings.
  it("refuses an older version and another document under the recorded version; the identical document loads again in another cache, recording nothing", () => {
    const ledger = new MemoryScopeBindingLedger();
    const v2 = withScopes({ legacy: READ }, 2);
    expect(cacheOver(ledger).install(v2).ok).toBe(true);
    refusedFor(cacheOver(ledger).install(withScopes({ legacy: READ }, 1)), /below the recorded version 2/);
    refusedFor(cacheOver(ledger).install(withScopes({ legacy: READ, other: READ }, 2)), /version 2 is recorded with another document/);
    const before = stateOf(ledger);
    expect(cacheOver(ledger).install(v2)).toMatchObject({ ok: true, version: 2 });
    expect(stateOf(ledger)).toEqual(before);
    expect(cacheOver(ledger).install(withScopes({ legacy: READ, other: READ }, 3)).ok).toBe(true);
    expect(stateOf(ledger).highWater?.version).toBe(3);
  });

  it("an initialized ledger file outlives its handle: another handle, as in another process or after a restart, keeps its bindings and high-water mark", () => {
    const file = initializedLedger();
    const current = contractAt(CURRENT_VERSION);
    const first = SqliteScopeBindingLedger.open(file);
    expect(cacheOver(first).install(withScopes({ legacy: READ }, 2)).ok).toBe(true);
    first.close();
    const second = SqliteScopeBindingLedger.open(file);
    try {
      expect(stateOf(second)).toMatchObject({
        bindings: [{ issuer: ESTATE, scope: "legacy", resource: RESOURCE, resource_contract: null }],
        highWater: { version: 2 },
      });
      refusedFor(cacheOver(second).install(withScopes({ legacy: stated(current) }, 3)), /repoints scope/);
      refusedFor(cacheOver(second).install(withScopes({ legacy: READ }, 1)), /below the recorded version 2/);
      refusedFor(cacheOver(second).install(withScopes({ legacy: READ, other: READ }, 2)), /recorded with another document/);
      expect(cacheOver(second).install(withScopes({ legacy: READ }, 2)).ok).toBe(true);
    } finally {
      second.close();
    }
  });

  it("refuses at open a ledger that is missing, removed after use, not a database, or another component's; initializes only once, at an absolute path", () => {
    const dir = mkdtempSync(join(tmpdir(), "scope-bindings-"));
    expect(() => SqliteScopeBindingLedger.open(join(dir, "never.db"))).toThrow(/does not exist/);

    const used = initializedLedger();
    const ledger = SqliteScopeBindingLedger.open(used);
    expect(cacheOver(ledger).install(withScopes({ legacy: READ }, 1)).ok).toBe(true);
    ledger.close();
    for (const suffix of ["", "-wal", "-shm"]) rmSync(`${used}${suffix}`, { force: true });
    expect(() => SqliteScopeBindingLedger.open(used)).toThrow(/does not exist/);

    const garbage = join(dir, "garbage.db");
    writeFileSync(garbage, "not a ledger, only bytes ".repeat(200));
    expect(() => SqliteScopeBindingLedger.open(garbage)).toThrow(/cannot read|not a database/);

    const foreign = join(dir, "foreign.db");
    initSharedStore({ file: foreign, owner: "another-component", schema: "", schemaVersion: 1 });
    expect(() => SqliteScopeBindingLedger.open(foreign)).toThrow(/owned by another-component/);

    // Initializing again never replaces history: the recorded binding stays.
    const once = initializedLedger();
    const kept = SqliteScopeBindingLedger.open(once);
    expect(cacheOver(kept).install(withScopes({ legacy: READ }, 1)).ok).toBe(true);
    kept.close();
    expect(() => initScopeBindingLedger(once)).toThrow(/already exists: a store is initialized once/);
    const reopened = SqliteScopeBindingLedger.open(once);
    expect(stateOf(reopened).bindings).toEqual([{ issuer: ESTATE, scope: "legacy", resource: RESOURCE, resource_contract: null }]);
    reopened.close();
    expect(() => initScopeBindingLedger("relative/scope-bindings.db")).toThrow(/absolute path/);
  });

  it("the store itself refuses changing or removing a recorded binding, and lowering or replacing the high-water mark", () => {
    const file = initializedLedger();
    const ledger = SqliteScopeBindingLedger.open(file);
    expect(cacheOver(ledger).install(withScopes({ legacy: READ }, 2)).ok).toBe(true);
    ledger.close();
    const db = openSharedStore({ file, owner: "mas-pilot-scope-bindings", schemaVersion: 1, lockTimeoutMs: 1000 });
    try {
      expect(() => db.prepare("UPDATE scope_binding SET contract_id = 'x', contract_version = 'v', contract_digest = 'd'").run()).toThrow(/never changed/);
      expect(() => db.prepare("DELETE FROM scope_binding").run()).toThrow(/never removed/);
      expect(() => db.prepare("UPDATE mapping_high_water SET version = 1").run()).toThrow(/never falls/);
      expect(() => db.prepare("UPDATE mapping_high_water SET digest = 'sha-256:other'").run()).toThrow(/never falls or changes in place/);
      expect(() => db.prepare("DELETE FROM mapping_high_water").run()).toThrow(/never removed/);
    } finally {
      db.close();
    }
  });
});

/** An empty, initialized SQLite ledger in a fresh directory. */
function initializedLedger(): string {
  const file = join(mkdtempSync(join(tmpdir(), "scope-bindings-")), "scope-bindings.db");
  initScopeBindingLedger(file);
  return file;
}

/** The ledger's state, read under its lock. */
const stateOf = (ledger: ScopeBindingLedger) => ledger.commit((state) => ({ result: state }));

/**
 * @spec resource-access#resource-contract (#1847, D1019): installs in two
 * processes over one ledger take turns. The first holds the write lock inside
 * its commit; the second, already installing, waits for it, then reads the
 * first one's binding under the lock and is refused, whichever binding came
 * first, and the ledger keeps the first one's.
 */
describe("the scope binding ledger serializes installs across processes (@spec authority-server#mapping-contract, resource-access#resource-contract, #1847, D1019)", () => {
  const DEMO = fileURLToPath(new URL("..", import.meta.url));
  const READ = ["payments:invoice.read"];
  const pinned = () => ({ actions: READ, resource_contract: contractAt(CURRENT_VERSION) });
  const run = (args: string[]) => {
    const child = spawn(process.execPath, ["--import", "tsx", "test/scope-binding-install.helper.ts", ...args], {
      cwd: DEMO,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (b) => {
      out += String(b);
    });
    child.stderr.on("data", (b) => {
      err += String(b);
    });
    const done = new Promise<{ code: number | null; out: string; err: string }>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) => resolve({ code, out, err }));
    });
    return { child, done };
  };
  const until = async (path: string, child: { exitCode: number | null }) => {
    const deadline = Date.now() + 20_000;
    while (!existsSync(path)) {
      if (Date.now() > deadline || child.exitCode !== null) throw new Error(`${path} never appeared`);
      await new Promise((r) => setTimeout(r, 20));
    }
  };

  it.each([
    ["a value stating none first, then the same value stating a contract", READ, pinned()],
    ["a value stating a contract first, then the same value stating none", pinned(), READ],
  ])("%s: the second waits for the lock, then is refused", async (_case, first, second) => {
    const dir = mkdtempSync(join(tmpdir(), "scope-bindings-race-"));
    const file = join(dir, "scope-bindings.db");
    initScopeBindingLedger(file);
    const doc1 = join(dir, "v1.json");
    const doc2 = join(dir, "v2.json");
    writeFileSync(doc1, JSON.stringify(doc({ version: 1, scopes: { resource: RESOURCE, issuers: { [ESTATE]: { legacy: first } } } as never })));
    writeFileSync(doc2, JSON.stringify(doc({ version: 2, scopes: { resource: RESOURCE, issuers: { [ESTATE]: { legacy: second } } } as never })));
    const a = run([file, doc1, join(dir, "a.attempting"), join(dir, "a.holding"), join(dir, "a.release")]);
    let b: ReturnType<typeof run> | undefined;
    try {
      await until(join(dir, "a.holding"), a.child);
      b = run([file, doc2, join(dir, "b.attempting")]);
      await until(join(dir, "b.attempting"), b.child);
      await new Promise((r) => setTimeout(r, 500));
      // Installing for half a second yet not done: it waits on the lock.
      expect(b.child.exitCode).toBeNull();
      writeFileSync(join(dir, "a.release"), "go");
      const firstDone = await a.done;
      expect(firstDone.code, firstDone.err).toBe(0);
      const secondDone = await b.done;
      expect(secondDone.code, secondDone.err).toBe(3);
      expect(secondDone.out).toMatch(/repoints scope .* legacy/);
      const ledger = SqliteScopeBindingLedger.open(file);
      try {
        const state = stateOf(ledger);
        expect(state.bindings).toHaveLength(1);
        expect(state.bindings[0]?.resource_contract).toEqual(Array.isArray(first) ? null : contractAt(CURRENT_VERSION));
        expect(state.highWater?.version).toBe(1);
      } finally {
        ledger.close();
      }
    } finally {
      a.child.kill();
      b?.child.kill();
    }
  }, 60_000);
});
