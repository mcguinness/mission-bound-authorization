/**
 * Seed data (single source of demo state; PLAN.md runbook). The values live in
 * static JSON under the repo-root `config/` directory and are loaded + validated
 * at module init; editing the JSON needs no recompile. Keys for the agent client
 * are still generated per boot: nothing here is deterministic across restarts
 * (D25).
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair } from "jose";

/** Fail-fast config error naming the offending file (cf. IntentError style). */
class ConfigError extends Error {
  constructor(file: string, message: string) {
    super(`[config:${file}] ${message}`);
    this.name = "ConfigError";
  }
}

/**
 * Resolve the `config/` directory module-relative (never via process.cwd), so
 * loading works under vitest, the tsx demo launchers, and standalone service
 * imports alike. `MISSION_CONFIG_DIR` overrides; otherwise walk parent dirs from
 * this module until a `config/` holding `topology.json` is found.
 */
function resolveConfigDir(): string {
  const override = process.env.MISSION_CONFIG_DIR;
  if (override) return override;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(dir, "config");
    if (existsSync(join(candidate, "topology.json"))) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new ConfigError(
    "topology.json",
    "could not locate config/ directory (searched upward from module; set MISSION_CONFIG_DIR)",
  );
}

const CONFIG_DIR = resolveConfigDir();

function readJson(file: string): unknown {
  const path = join(CONFIG_DIR, file);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new ConfigError(file, `missing config file at ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new ConfigError(file, `invalid JSON: ${(e as Error).message}`);
  }
}

function asArray(file: string, v: unknown, ctx: string): unknown[] {
  if (!Array.isArray(v)) throw new ConfigError(file, `${ctx} must be an array`);
  return v;
}

function asObject(file: string, v: unknown, ctx: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new ConfigError(file, `${ctx} must be an object`);
  }
  return v as Record<string, unknown>;
}

function reqString(file: string, obj: Record<string, unknown>, key: string, ctx: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new ConfigError(file, `${ctx}.${key} must be a non-empty string`);
  }
  return v;
}

function reqStringArray(
  file: string,
  obj: Record<string, unknown>,
  key: string,
  ctx: string,
): string[] {
  const v = obj[key];
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) {
    throw new ConfigError(file, `${ctx}.${key} must be a string array`);
  }
  return v as string[];
}

function reqEnum<T extends string>(
  file: string,
  obj: Record<string, unknown>,
  key: string,
  ctx: string,
  allowed: readonly T[],
): T {
  const v = reqString(file, obj, key, ctx);
  if (!(allowed as readonly string[]).includes(v)) {
    throw new ConfigError(file, `${ctx}.${key} must be one of ${allowed.join(", ")}`);
  }
  return v as T;
}

function reqNumber(file: string, obj: Record<string, unknown>, key: string, ctx: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new ConfigError(file, `${ctx}.${key} must be a number`);
  }
  return v;
}

export interface TopologyKey {
  kid: string;
  alg: string;
}

/** The full deployment topology (issuers, ports, ttls, keys, resources). */
export interface Topology {
  resources: { payments: string; saas: string; hrFiles: string };
  issuers: { as: string; ras: string; transparency: string; pdp: string };
  endpoints: { arsIntake: string };
  ports: { as: number; console: number };
  ttls: {
    accessTokenSeconds: number;
    rasLocalTokenSeconds: number;
    approvalSeconds: number;
    maxApprovalAgeSeconds: number;
  };
  devServiceToken: string;
  keys: {
    asToken: TopologyKey;
    asStatus: TopologyKey;
    pdpDenial: TopologyKey;
    pdpEvidence: TopologyKey;
    transparency: TopologyKey;
    rasToken: TopologyKey;
    crossDomain: TopologyKey;
  };
  openfga: { url: string; presharedKey: string };
}

function reqKey(file: string, obj: Record<string, unknown>, key: string, ctx: string): TopologyKey {
  const k = asObject(file, obj[key], `${ctx}.${key}`);
  return {
    kid: reqString(file, k, "kid", `${ctx}.${key}`),
    alg: reqString(file, k, "alg", `${ctx}.${key}`),
  };
}

function loadTopology(): Topology {
  const file = "topology.json";
  const root = asObject(file, readJson(file), "topology");
  const resources = asObject(file, root.resources, "resources");
  const issuers = asObject(file, root.issuers, "issuers");
  const endpoints = asObject(file, root.endpoints, "endpoints");
  const ports = asObject(file, root.ports, "ports");
  const ttls = asObject(file, root.ttls, "ttls");
  const keys = asObject(file, root.keys, "keys");
  const openfga = asObject(file, root.openfga, "openfga");
  return {
    resources: {
      payments: reqString(file, resources, "payments", "resources"),
      saas: reqString(file, resources, "saas", "resources"),
      hrFiles: reqString(file, resources, "hrFiles", "resources"),
    },
    issuers: {
      as: reqString(file, issuers, "as", "issuers"),
      ras: reqString(file, issuers, "ras", "issuers"),
      transparency: reqString(file, issuers, "transparency", "issuers"),
      pdp: reqString(file, issuers, "pdp", "issuers"),
    },
    endpoints: {
      arsIntake: reqString(file, endpoints, "arsIntake", "endpoints"),
    },
    ports: {
      as: reqNumber(file, ports, "as", "ports"),
      console: reqNumber(file, ports, "console", "ports"),
    },
    ttls: {
      accessTokenSeconds: reqNumber(file, ttls, "accessTokenSeconds", "ttls"),
      rasLocalTokenSeconds: reqNumber(file, ttls, "rasLocalTokenSeconds", "ttls"),
      approvalSeconds: reqNumber(file, ttls, "approvalSeconds", "ttls"),
      maxApprovalAgeSeconds: reqNumber(file, ttls, "maxApprovalAgeSeconds", "ttls"),
    },
    devServiceToken: reqString(file, root, "devServiceToken", "topology"),
    keys: {
      asToken: reqKey(file, keys, "asToken", "keys"),
      asStatus: reqKey(file, keys, "asStatus", "keys"),
      pdpDenial: reqKey(file, keys, "pdpDenial", "keys"),
      pdpEvidence: reqKey(file, keys, "pdpEvidence", "keys"),
      transparency: reqKey(file, keys, "transparency", "keys"),
      rasToken: reqKey(file, keys, "rasToken", "keys"),
      crossDomain: reqKey(file, keys, "crossDomain", "keys"),
    },
    openfga: {
      url: reqString(file, openfga, "url", "openfga"),
      presharedKey: reqString(file, openfga, "presharedKey", "openfga"),
    },
  };
}

/** The validated deployment topology; consumers inject these values (no cycles). */
export const TOPOLOGY: Topology = loadTopology();

/** The default (pre-env-override) payments resource, from topology.json. */
const DEFAULT_PAYMENTS_RESOURCE = TOPOLOGY.resources.payments;

export const CANONICAL_RESOURCE = process.env.MCP_PAYMENTS_RESOURCE ?? DEFAULT_PAYMENTS_RESOURCE;

export interface SeededUser {
  sub: string;
  name: string;
  roles: string[];
}

function loadUsers(): SeededUser[] {
  const file = "identity.json";
  return asArray(file, readJson(file), "identity").map((raw, i) => {
    const u = asObject(file, raw, `identity[${i}]`);
    return {
      sub: reqString(file, u, "sub", `identity[${i}]`),
      name: reqString(file, u, "name", `identity[${i}]`),
      roles: reqStringArray(file, u, "roles", `identity[${i}]`),
    };
  });
}

export const USERS: SeededUser[] = loadUsers();

export interface VendorSeed {
  id: string;
  name: string;
  status: string;
}

function loadVendors(): VendorSeed[] {
  const file = "seed/vendors.json";
  return asArray(file, readJson(file), "vendors").map((raw, i) => {
    const v = asObject(file, raw, `vendors[${i}]`);
    return {
      id: reqString(file, v, "id", `vendors[${i}]`),
      name: reqString(file, v, "name", `vendors[${i}]`),
      status: reqString(file, v, "status", `vendors[${i}]`),
    };
  });
}

export const VENDORS: VendorSeed[] = loadVendors();

export interface InvoiceSeed {
  id: string;
  vendor_id: string;
  amount: { amount: string; currency: string };
  status: string;
  version: number;
}

function loadInvoices(): InvoiceSeed[] {
  const file = "seed/invoices.json";
  return asArray(file, readJson(file), "invoices").map((raw, i) => {
    const inv = asObject(file, raw, `invoices[${i}]`);
    const amount = asObject(file, inv.amount, `invoices[${i}].amount`);
    const version = inv.version;
    if (typeof version !== "number" || !Number.isInteger(version)) {
      throw new ConfigError(file, `invoices[${i}].version must be an integer`);
    }
    return {
      id: reqString(file, inv, "id", `invoices[${i}]`),
      vendor_id: reqString(file, inv, "vendor_id", `invoices[${i}]`),
      amount: {
        amount: reqString(file, amount, "amount", `invoices[${i}].amount`),
        currency: reqString(file, amount, "currency", `invoices[${i}].amount`),
      },
      status: reqString(file, inv, "status", `invoices[${i}]`),
      version,
    };
  });
}

export const INVOICES: InvoiceSeed[] = loadInvoices();

export interface CeilingConstraints {
  max_amount?: { amount: string; currency: string };
  vendors?: string[];
}

export interface CeilingEntry {
  type: string;
  resource: string;
  actions: string[];
  constraints?: CeilingConstraints;
}

/** Non-empty tuple keeps `ceiling[0]` defined under noUncheckedIndexedAccess. */
export interface DerivationPolicy {
  policy_version: string;
  ceiling: [CeilingEntry, ...CeilingEntry[]];
}

interface LoadedPolicy {
  policy_version: string;
  ceiling: CeilingEntry[];
  write_actions: string[];
}

function loadPolicy(): LoadedPolicy {
  const file = "policy.json";
  const root = asObject(file, readJson(file), "policy");
  const ceiling = asArray(file, root.ceiling, "policy.ceiling").map((raw, i) => {
    const e = asObject(file, raw, `policy.ceiling[${i}]`);
    const entry: CeilingEntry = {
      type: reqString(file, e, "type", `policy.ceiling[${i}]`),
      resource: reqString(file, e, "resource", `policy.ceiling[${i}]`),
      actions: reqStringArray(file, e, "actions", `policy.ceiling[${i}]`),
    };
    if (e.constraints !== undefined) {
      entry.constraints = asObject(
        file,
        e.constraints,
        `policy.ceiling[${i}].constraints`,
      ) as CeilingConstraints;
    }
    return entry;
  });
  if (ceiling.length === 0) throw new ConfigError(file, "policy.ceiling must be non-empty");
  return {
    policy_version: reqString(file, root, "policy_version", "policy"),
    ceiling,
    write_actions: reqStringArray(file, root, "write_actions", "policy"),
  };
}

const POLICY = loadPolicy();

/** Actions whose presence makes a mission write-bearing (D37 governance). */
export const WRITE_ACTIONS = new Set(POLICY.write_actions);

/**
 * Derivation policy ceiling (@spec mission#authorization-derivation): the
 * AS derives each Authority Set entry as a subset of a proposed entry,
 * bounded by this ceiling. Nothing a client proposes can widen past it. The
 * payments ceiling resource resolves to the (possibly env-overridden)
 * CANONICAL_RESOURCE so it tracks MCP_PAYMENTS_RESOURCE.
 */
export const DERIVATION_POLICY: DerivationPolicy = {
  policy_version: POLICY.policy_version,
  ceiling: POLICY.ceiling.map((e) =>
    e.resource === DEFAULT_PAYMENTS_RESOURCE ? { ...e, resource: CANONICAL_RESOURCE } : e,
  ) as [CeilingEntry, ...CeilingEntry[]],
};

export interface SeededClient {
  metadata: Record<string, unknown>;
  privateJwk: Record<string, unknown>;
}

interface ClientSeed {
  client_id: string;
  client_name: string;
  grant_types: string[];
  response_types: string[];
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  token_endpoint_auth_signing_alg: string;
  scope: string;
  authorization_details_types: string[];
  key: { kid: string; alg: string };
}

function loadClients(): [ClientSeed, ...ClientSeed[]] {
  const file = "clients.json";
  const clients = asArray(file, readJson(file), "clients").map((raw, i) => {
    const c = asObject(file, raw, `clients[${i}]`);
    const key = asObject(file, c.key, `clients[${i}].key`);
    return {
      client_id: reqString(file, c, "client_id", `clients[${i}]`),
      client_name: reqString(file, c, "client_name", `clients[${i}]`),
      grant_types: reqStringArray(file, c, "grant_types", `clients[${i}]`),
      response_types: reqStringArray(file, c, "response_types", `clients[${i}]`),
      redirect_uris: reqStringArray(file, c, "redirect_uris", `clients[${i}]`),
      token_endpoint_auth_method: reqString(file, c, "token_endpoint_auth_method", `clients[${i}]`),
      token_endpoint_auth_signing_alg: reqString(
        file,
        c,
        "token_endpoint_auth_signing_alg",
        `clients[${i}]`,
      ),
      scope: reqString(file, c, "scope", `clients[${i}]`),
      authorization_details_types: reqStringArray(
        file,
        c,
        "authorization_details_types",
        `clients[${i}]`,
      ),
      key: {
        kid: reqString(file, key, "kid", `clients[${i}].key`),
        alg: reqString(file, key, "alg", `clients[${i}].key`),
      },
    };
  });
  if (clients.length === 0) throw new ConfigError(file, "clients must be non-empty");
  return clients as [ClientSeed, ...ClientSeed[]];
}

const CLIENTS = loadClients();

/** The agent's confidential client: private_key_jwt + separate DPoP key (D38). */
export async function seedAgentClient(): Promise<SeededClient> {
  const client = CLIENTS[0];
  const { publicKey, privateKey } = await generateKeyPair(client.key.alg, { extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  pub.kid = client.key.kid;
  priv.kid = client.key.kid;
  pub.alg = client.key.alg;
  return {
    metadata: {
      client_id: client.client_id,
      client_name: client.client_name,
      grant_types: client.grant_types,
      response_types: client.response_types,
      redirect_uris: client.redirect_uris,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      token_endpoint_auth_signing_alg: client.token_endpoint_auth_signing_alg,
      jwks: { keys: [pub] },
      scope: client.scope,
      authorization_details_types: client.authorization_details_types,
    },
    privateJwk: priv as Record<string, unknown>,
  };
}

/** Dev-only service token for control-plane edges (channel matrix). */
export const DEV_SERVICE_TOKEN = TOPOLOGY.devServiceToken;

export interface CatalogServiceSeed {
  id: string;
  display_name: string;
  type: "mcp" | "http" | "a2a";
  endpoint: string;
  categories?: string[];
  tags?: string[];
  server_card_uri?: string;
  resource: string;
  connection: { profile: "oauth"; type: "authorization_code" | "token_exchange" | "id_jag" };
  approvable: boolean;
}

function loadCatalog(): CatalogServiceSeed[] {
  const file = "catalog.json";
  // Validate in place, then cast the parsed object so JSON key order is preserved.
  return asArray(file, readJson(file), "catalog").map((raw, i) => {
    const ctx = `catalog[${i}]`;
    const s = asObject(file, raw, ctx);
    const conn = asObject(file, s.connection, `${ctx}.connection`);
    reqString(file, s, "id", ctx);
    reqString(file, s, "display_name", ctx);
    reqEnum(file, s, "type", ctx, ["mcp", "http", "a2a"] as const);
    reqString(file, s, "endpoint", ctx);
    reqString(file, s, "resource", ctx);
    reqEnum(file, conn, "profile", `${ctx}.connection`, ["oauth"] as const);
    reqEnum(file, conn, "type", `${ctx}.connection`, [
      "authorization_code",
      "token_exchange",
      "id_jag",
    ] as const);
    if (typeof s.approvable !== "boolean") {
      throw new ConfigError(file, `${ctx}.approvable must be a boolean`);
    }
    if (s.categories !== undefined) reqStringArray(file, s, "categories", ctx);
    if (s.tags !== undefined) reqStringArray(file, s, "tags", ctx);
    if (s.server_card_uri !== undefined) reqString(file, s, "server_card_uri", ctx);
    return s as unknown as CatalogServiceSeed;
  });
}

/**
 * @spec svc-connectivity-disco: seeded catalog services (D8). The payments
 * entry's endpoint/resource/server_card_uri resolve to the (possibly
 * env-overridden) CANONICAL_RESOURCE so they track MCP_PAYMENTS_RESOURCE.
 */
export const CATALOG_SERVICES: CatalogServiceSeed[] = loadCatalog().map((svc) => {
  if (svc.resource !== DEFAULT_PAYMENTS_RESOURCE) return svc;
  const resolved: CatalogServiceSeed = {
    ...svc,
    endpoint: CANONICAL_RESOURCE,
    resource: CANONICAL_RESOURCE,
  };
  if (typeof resolved.server_card_uri === "string") {
    resolved.server_card_uri = `${CANONICAL_RESOURCE.replace(/\/mcp$/, "")}/.well-known/mcp`;
  }
  return resolved;
});
