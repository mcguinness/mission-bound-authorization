/**
 * @spec authority-server#mapping-contract, authority-server#deployment-adoption (#818)
 *
 * The strict loader for `config/mas-pilot.json`: the pilot's estate
 * authorization server (issuer, directory accounts, client registrations,
 * resource vocabulary), its mapping-cache freshness bound, the classes the
 * gateway reserves for Mission-bound credentials, the estate's development
 * Resource-policy grants, the initial mapping contract version, the route
 * table and the consequential-path inventory. The mapping
 * contract itself is validated by `parseMappingContract` when the cache
 * installs it. Client secrets and signing keys are generated at each boot and
 * never configured.
 */

import { readFileSync } from "node:fs";
import type { ResourcePolicyPrincipalSeed, ResourcePolicySeed } from "@mission/demo-data";
import { CANONICAL_RESOURCE } from "@mission/mcp-payments";

export interface MasPilotClientConfig {
  client_id: string;
  redirect_uri: string;
  scope: string;
  resources: string[];
  /** The access token format the estate issues this client (#818 slice 3). */
  token_format: "jwt" | "opaque";
}

/** The gateway's RFC 7662 introspection of the estate's opaque tokens (#818 slice 3). */
export interface MasPilotIntrospectionConfig {
  /** The introspection client the estate registers for the gateway; its secret is generated at each boot. */
  client_id: string;
  timeout_ms: number;
  /** A positive result is cached at most this long, and never past the token's `exp`; a negative one never. */
  cache_max_seconds: number;
}

/**
 * @spec authority-server#join-disclosure, authority-server#mission-join rule 2
 * (#818 slice 4b): the separated configuration. The MAS is the reference
 * authorization server in its own process at `http://{host}:{port}`, which
 * is then the Mission issuer; the PDP reads Missions through its Mission
 * Status endpoint as the client `pdp_client_id`, authenticating by
 * private-key JWT under a key generated where the PDP runs (#1407).
 * `enrolled_pdps` is the MAS-held enrollment, keyed by client, that releases
 * Join Disclosure. The state source is placed with the PDP, read within
 * `timeout_ms` and `max_response_bytes`.
 */
export interface MasPilotSeparatedConfig {
  host: string;
  port: number;
  pdp_client_id: string;
  enrolled_pdps: Array<{ client_id: string; enforcement_scopes: string[] }>;
  state_source: { placement: "pdp"; timeout_ms: number; max_response_bytes: number };
}

export interface MasPilotInventoryEntry {
  tool: string;
  class: string;
  /** `joined`: governed by the mapping join. `mission_bound_only`: refused to a joined credential. */
  gateway: "joined" | "mission_bound_only";
}

export interface MasPilotRoute {
  route: "gateway" | "resource";
  admits: "estate-ordinary" | "mission-bound";
  issuer: string;
}

export interface MasPilotConfig {
  pilot: string;
  mission_issuer: string;
  /** The Mission-namespace clients the pilot MAS's derivation ceiling admits as delegates. */
  mas_delegates: string[];
  estate: {
    issuer: string;
    host: string;
    port: number;
    accounts: string[];
    clients: MasPilotClientConfig[];
    resource_servers: Record<string, { scope: string }>;
  };
  mapping_cache: { max_stale_seconds: number };
  introspection: MasPilotIntrospectionConfig;
  separated_mas: MasPilotSeparatedConfig;
  mission_bound_only_classes: string[];
  /**
   * @spec runtime#input-resource-policy (#828, #818): the grants a development
   * bootstrap of the pilot's Resource-policy store writes, every principal
   * under the estate issuer (the identities the resource authenticates). An
   * attached store is used as it stands and never seeded.
   */
  resource_policy: ResourcePolicySeed;
  /** The initial contract version, validated at install. */
  mapping_contract: unknown;
  routes: MasPilotRoute[];
  inventory: MasPilotInventoryEntry[];
}

export class MasPilotConfigError extends Error {
  constructor(message: string) {
    super(`config/mas-pilot.json: ${message}`);
    this.name = "MasPilotConfigError";
  }
}

function obj(v: unknown, ctx: string, members: readonly string[]): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new MasPilotConfigError(`${ctx} must be an object`);
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!members.includes(k)) throw new MasPilotConfigError(`${ctx} has unknown member ${k}`);
  for (const k of members) if (!Object.hasOwn(o, k)) throw new MasPilotConfigError(`${ctx} is missing ${k}`);
  return o;
}

function str(v: unknown, ctx: string): string {
  if (typeof v !== "string" || v === "") throw new MasPilotConfigError(`${ctx} must be a non-empty string`);
  return v;
}

function strs(v: unknown, ctx: string): string[] {
  if (!Array.isArray(v)) throw new MasPilotConfigError(`${ctx} must be an array`);
  return v.map((x, i) => str(x, `${ctx}[${i}]`));
}

/** Exactly one of `sub` or `client`, as a non-empty string. */
function principal(o: Record<string, unknown>, ctx: string): ResourcePolicyPrincipalSeed {
  if (Object.hasOwn(o, "sub") === Object.hasOwn(o, "client")) throw new MasPilotConfigError(`${ctx} must name exactly one of sub or client`);
  return Object.hasOwn(o, "sub") ? { sub: str(o.sub, `${ctx}.sub`) } : { client: str(o.client, `${ctx}.client`) };
}

/**
 * The estate's development Resource-policy grants, under the rules the shipped
 * seed's loader applies: closed shapes, one principal kind per entry, and a
 * relation that kind may hold (a subject `authorized_reader` or
 * `authorized_payer`, a client `authorized_client`).
 */
function resourcePolicySeed(raw: unknown): ResourcePolicySeed {
  const root = obj(raw, "resource_policy", ["tenants", "entitlements"]);
  if (!Array.isArray(root.tenants)) throw new MasPilotConfigError("resource_policy.tenants must be an array");
  if (!Array.isArray(root.entitlements)) throw new MasPilotConfigError("resource_policy.entitlements must be an array");
  const tenants = root.tenants.map((t, i) => {
    const ctx = `resource_policy.tenants[${i}]`;
    const o = obj(t, ctx, ["tenant", "vendors", "members"]);
    if (!Array.isArray(o.members)) throw new MasPilotConfigError(`${ctx}.members must be an array`);
    return {
      tenant: str(o.tenant, `${ctx}.tenant`),
      vendors: strs(o.vendors, `${ctx}.vendors`),
      members: o.members.map((m, j) => {
        const mctx = `${ctx}.members[${j}]`;
        const mo = m as Record<string, unknown>;
        obj(m, mctx, Object.hasOwn(mo ?? {}, "sub") ? ["sub"] : ["client"]);
        return principal(mo, mctx);
      }),
    };
  });
  const entitlements = root.entitlements.map((e, i) => {
    const ctx = `resource_policy.entitlements[${i}]`;
    const eo = e as Record<string, unknown>;
    const o = obj(e, ctx, [Object.hasOwn(eo ?? {}, "sub") ? "sub" : "client", "relation", "vendor"]);
    const who = principal(o, ctx);
    const relation = str(o.relation, `${ctx}.relation`);
    const vendor = str(o.vendor, `${ctx}.vendor`);
    if ("client" in who) {
      if (relation !== "authorized_client") throw new MasPilotConfigError(`${ctx}.relation must be authorized_client for a client`);
      return { client: who.client, relation, vendor } as const;
    }
    if (relation !== "authorized_reader" && relation !== "authorized_payer") {
      throw new MasPilotConfigError(`${ctx}.relation must be authorized_reader or authorized_payer for a subject`);
    }
    return { sub: who.sub, relation, vendor } as const;
  });
  return { tenants, entitlements };
}

function positiveInt(v: unknown, ctx: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) throw new MasPilotConfigError(`${ctx} must be a positive integer`);
  return v;
}

/** The separated configuration: closed shapes, a `pdp` placement, positive bounds. */
function separatedMas(raw: unknown): MasPilotSeparatedConfig {
  const o = obj(raw, "separated_mas", ["host", "port", "pdp_client_id", "enrolled_pdps", "state_source"]);
  if (!Array.isArray(o.enrolled_pdps)) throw new MasPilotConfigError("separated_mas.enrolled_pdps must be an array");
  const enrolled = o.enrolled_pdps.map((e, i) => {
    const ctx = `separated_mas.enrolled_pdps[${i}]`;
    const eo = obj(e, ctx, ["client_id", "enforcement_scopes"]);
    return { client_id: str(eo.client_id, `${ctx}.client_id`), enforcement_scopes: strs(eo.enforcement_scopes, `${ctx}.enforcement_scopes`) };
  });
  const source = obj(o.state_source, "separated_mas.state_source", ["placement", "timeout_ms", "max_response_bytes"]);
  // The PDP is the party that resolves the Mission at the MAS (rule 2).
  if (source.placement !== "pdp") throw new MasPilotConfigError('separated_mas.state_source.placement must be "pdp"');
  return {
    host: str(o.host, "separated_mas.host"),
    port: positiveInt(o.port, "separated_mas.port"),
    pdp_client_id: str(o.pdp_client_id, "separated_mas.pdp_client_id"),
    enrolled_pdps: enrolled,
    state_source: {
      placement: "pdp",
      timeout_ms: positiveInt(source.timeout_ms, "separated_mas.state_source.timeout_ms"),
      max_response_bytes: positiveInt(source.max_response_bytes, "separated_mas.state_source.max_response_bytes"),
    },
  };
}

/** Validate a parsed pilot configuration. */
export function parseMasPilotConfig(raw: unknown): MasPilotConfig {
  const root = obj(raw, "root", [
    "pilot",
    "mission_issuer",
    "mas_delegates",
    "estate",
    "mapping_cache",
    "introspection",
    "separated_mas",
    "mission_bound_only_classes",
    "resource_policy",
    "mapping_contract",
    "routes",
    "inventory",
  ]);
  const estate = obj(root.estate, "estate", ["issuer", "host", "port", "accounts", "clients", "resource_servers"]);
  const port = estate.port;
  if (typeof port !== "number" || !Number.isInteger(port) || port <= 0) {
    throw new MasPilotConfigError("estate.port must be a positive integer");
  }
  const issuer = str(estate.issuer, "estate.issuer");
  const missionIssuer = str(root.mission_issuer, "mission_issuer");
  if (issuer === missionIssuer) {
    throw new MasPilotConfigError("estate.issuer must differ from mission_issuer: the estate is a separate issuer");
  }
  if (!Array.isArray(estate.clients)) throw new MasPilotConfigError("estate.clients must be an array");
  const seen = new Set<string>();
  const clients = estate.clients.map((c, i): MasPilotClientConfig => {
    const ctx = `estate.clients[${i}]`;
    const o = obj(c, ctx, ["client_id", "redirect_uri", "scope", "resources", "token_format"]);
    if (o.token_format !== "jwt" && o.token_format !== "opaque") {
      throw new MasPilotConfigError(`${ctx}.token_format must be "jwt" or "opaque"`);
    }
    const id = str(o.client_id, `${ctx}.client_id`);
    if (seen.has(id)) throw new MasPilotConfigError(`${ctx}.client_id ${id} is registered twice`);
    seen.add(id);
    return {
      client_id: id,
      redirect_uri: str(o.redirect_uri, `${ctx}.redirect_uri`),
      scope: str(o.scope, `${ctx}.scope`),
      resources: strs(o.resources, `${ctx}.resources`),
      token_format: o.token_format,
    };
  });
  const rsRaw = estate.resource_servers;
  if (rsRaw === null || typeof rsRaw !== "object" || Array.isArray(rsRaw)) {
    throw new MasPilotConfigError("estate.resource_servers must be an object");
  }
  const resource_servers: Record<string, { scope: string }> = {};
  for (const [resource, v] of Object.entries(rsRaw as Record<string, unknown>)) {
    resource_servers[resource] = { scope: str(obj(v, `estate.resource_servers.${resource}`, ["scope"]).scope, `${resource}.scope`) };
  }
  // The gateway verifies `aud` against the payments resource identifier, so
  // the estate must serve it; its other resources are the estate's own.
  if (!Object.hasOwn(resource_servers, CANONICAL_RESOURCE)) {
    throw new MasPilotConfigError(`estate.resource_servers must name the gateway's resource ${CANONICAL_RESOURCE}`);
  }
  const intro = obj(root.introspection, "introspection", ["client_id", "timeout_ms", "cache_max_seconds"]);
  const timeoutMs = intro.timeout_ms;
  const cacheMax = intro.cache_max_seconds;
  if (typeof timeoutMs !== "number" || !Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new MasPilotConfigError("introspection.timeout_ms must be a positive integer");
  }
  if (typeof cacheMax !== "number" || !Number.isInteger(cacheMax) || cacheMax < 0) {
    throw new MasPilotConfigError("introspection.cache_max_seconds must be a non-negative integer");
  }
  const introspectionClient = str(intro.client_id, "introspection.client_id");
  if (seen.has(introspectionClient)) {
    throw new MasPilotConfigError("introspection.client_id must not be one of the estate's own clients");
  }
  const cache = obj(root.mapping_cache, "mapping_cache", ["max_stale_seconds"]);
  const maxStale = cache.max_stale_seconds;
  if (typeof maxStale !== "number" || !Number.isInteger(maxStale) || maxStale <= 0) {
    throw new MasPilotConfigError("mapping_cache.max_stale_seconds must be a positive integer");
  }
  if (!Array.isArray(root.routes)) throw new MasPilotConfigError("routes must be an array");
  const routes = root.routes.map((r, i): MasPilotRoute => {
    const o = obj(r, `routes[${i}]`, ["route", "admits", "issuer"]);
    if (o.route !== "gateway" && o.route !== "resource") throw new MasPilotConfigError(`routes[${i}].route is unknown`);
    if (o.admits !== "estate-ordinary" && o.admits !== "mission-bound") throw new MasPilotConfigError(`routes[${i}].admits is unknown`);
    return { route: o.route, admits: o.admits, issuer: str(o.issuer, `routes[${i}].issuer`) };
  });
  if (!Array.isArray(root.inventory)) throw new MasPilotConfigError("inventory must be an array");
  const inventory = root.inventory.map((e, i): MasPilotInventoryEntry => {
    const o = obj(e, `inventory[${i}]`, ["tool", "class", "gateway"]);
    if (o.gateway !== "joined" && o.gateway !== "mission_bound_only") {
      throw new MasPilotConfigError(`inventory[${i}].gateway must be "joined" or "mission_bound_only"`);
    }
    return { tool: str(o.tool, `inventory[${i}].tool`), class: str(o.class, `inventory[${i}].class`), gateway: o.gateway };
  });
  return {
    pilot: str(root.pilot, "pilot"),
    mission_issuer: missionIssuer,
    mas_delegates: strs(root.mas_delegates, "mas_delegates"),
    estate: { issuer, host: str(estate.host, "estate.host"), port, accounts: strs(estate.accounts, "estate.accounts"), clients, resource_servers },
    mapping_cache: { max_stale_seconds: maxStale },
    introspection: { client_id: introspectionClient, timeout_ms: timeoutMs, cache_max_seconds: cacheMax },
    separated_mas: separatedMas(root.separated_mas),
    mission_bound_only_classes: strs(root.mission_bound_only_classes, "mission_bound_only_classes"),
    resource_policy: resourcePolicySeed(root.resource_policy),
    mapping_contract: root.mapping_contract,
    routes,
    inventory,
  };
}

/** Read and validate `config/mas-pilot.json`. */
export function loadMasPilotConfig(path: URL | string = new URL("../../../config/mas-pilot.json", import.meta.url)): MasPilotConfig {
  return parseMasPilotConfig(JSON.parse(readFileSync(path, "utf8")));
}

/**
 * The configuration with its Mission issuer moved to `url`, in exactly the
 * fields that name it: `mission_issuer`, the mapping contract's
 * `mission_issuer` and each subject row's `to.iss`, and the Mission-bound
 * route's `issuer`. Each moves only where its value equals the old issuer
 * exactly; every other string is kept, including an estate issuer, URL or
 * identity that merely contains the old issuer (#1466 review). When the MAS
 * is the reference authorization server, its own URL is the Mission issuer
 * (#818 slice 5B), in either topology. Unchanged when it already names `url`.
 */
export function relocateMissionIssuer(config: MasPilotConfig, url: string): MasPilotConfig {
  const from = config.mission_issuer;
  if (from === url) return config;
  const moved = (value: string): string => (value === from ? url : value);
  return {
    ...config,
    mission_issuer: url,
    mapping_contract: relocateContractIssuer(config.mapping_contract, moved),
    routes: config.routes.map((r) => (r.admits === "mission-bound" ? { ...r, issuer: moved(r.issuer) } : r)),
  };
}

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** The contract's Mission-issuer fields moved; it is validated later, at install, so anything else passes through. */
function relocateContractIssuer(contract: unknown, moved: (value: string) => string): unknown {
  if (!isObject(contract)) return contract;
  return {
    ...contract,
    ...(typeof contract.mission_issuer === "string" ? { mission_issuer: moved(contract.mission_issuer) } : {}),
    ...(Array.isArray(contract.subjects)
      ? {
          subjects: contract.subjects.map((row: unknown) =>
            isObject(row) && isObject(row.to) && typeof row.to.iss === "string"
              ? { ...row, to: { ...row.to, iss: moved(row.to.iss) } }
              : row,
          ),
        }
      : {}),
  };
}
