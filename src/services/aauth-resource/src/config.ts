import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  isServerIdentifier,
  isSupportedAlgorithm,
  type SupportedAlgorithm,
} from "@mission/aauth-wire";

/** One protected operation and the scope an auth token must grant for it. */
export interface ResourceOperation {
  method: "GET" | "POST";
  /** Exact path match. */
  path: string;
  scope: string;
}

/**
 * The Resource's deployment configuration (`config/aauth-resource.json`).
 * Keys are generated at boot; only the `kid` and `alg` are configured.
 */
export interface ResourceConfig {
  /** The resource's server identifier: `iss` of its resource tokens. */
  issuer: string;
  name: string;
  signingKey: { kid: string; alg: SupportedAlgorithm };
  /** Resource tokens SHOULD NOT live longer than 300 seconds (aauth#section-6.7.1). */
  resourceTokenLifetimeSeconds: number;
  /** Signature validity window for `created` (aauth#section-11.3.4). */
  signatureWindowSeconds: number;
  /** Scope values this resource defines (aauth#section-11.10), for consent display. */
  scopeDescriptions: Record<string, string>;
  operations: ResourceOperation[];
}

export class ConfigError extends Error {
  constructor(detail: string) {
    super(`aauth-resource config: ${detail}`);
    this.name = "ConfigError";
  }
}

const SCOPE_VALUE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

function object(
  value: unknown,
  where: string,
  members: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConfigError(`${where} is not an object`);
  }
  for (const name of Object.keys(value)) {
    if (!members.includes(name)) throw new ConfigError(`${where} has unknown member ${name}`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, where: string): string {
  if (typeof value !== "string" || value === "") throw new ConfigError(`${where} is not a string`);
  return value;
}

function seconds(value: unknown, where: string, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > max) {
    throw new ConfigError(`${where} is not an integer from 1 to ${max}`);
  }
  return value;
}

/** Validate a parsed configuration document; unknown members are refused. */
export function parseResourceConfig(value: unknown): ResourceConfig {
  const doc = object(value, "the document", [
    "issuer",
    "name",
    "signing_key",
    "resource_token_lifetime_seconds",
    "signature_window_seconds",
    "scope_descriptions",
    "operations",
  ]);
  const issuer = string(doc.issuer, "issuer");
  if (!isServerIdentifier(issuer)) throw new ConfigError("issuer is not a server identifier");
  const key = object(doc.signing_key, "signing_key", ["kid", "alg"]);
  const alg = key.alg;
  if (!isSupportedAlgorithm(alg)) throw new ConfigError("signing_key.alg is not supported");
  const descriptions = object(
    doc.scope_descriptions,
    "scope_descriptions",
    Object.keys((doc.scope_descriptions as object | null) ?? {}),
  );
  const scopeDescriptions: Record<string, string> = {};
  for (const [scope, text] of Object.entries(descriptions)) {
    if (!SCOPE_VALUE.test(scope)) throw new ConfigError(`scope ${scope} is not a scope value`);
    scopeDescriptions[scope] = string(text, `scope_descriptions.${scope}`);
  }
  if (!Array.isArray(doc.operations) || doc.operations.length === 0) {
    throw new ConfigError("operations is not a non-empty array");
  }
  const seen = new Set<string>();
  const operations = doc.operations.map((entry, i): ResourceOperation => {
    const op = object(entry, `operations[${i}]`, ["method", "path", "scope"]);
    if (op.method !== "GET" && op.method !== "POST") {
      throw new ConfigError(`operations[${i}].method is not GET or POST`);
    }
    const path = string(op.path, `operations[${i}].path`);
    if (!path.startsWith("/") || path.startsWith("/.well-known/") || path === "/authorize") {
      throw new ConfigError(`operations[${i}].path is not an operation path`);
    }
    const scope = string(op.scope, `operations[${i}].scope`);
    if (!(scope in scopeDescriptions)) {
      throw new ConfigError(`operations[${i}].scope is not in scope_descriptions`);
    }
    const id = `${op.method} ${path}`;
    if (seen.has(id)) throw new ConfigError(`operations names ${id} twice`);
    seen.add(id);
    return { method: op.method, path, scope };
  });
  return {
    issuer,
    name: string(doc.name, "name"),
    signingKey: { kid: string(key.kid, "signing_key.kid"), alg },
    resourceTokenLifetimeSeconds: seconds(
      doc.resource_token_lifetime_seconds,
      "resource_token_lifetime_seconds",
      300,
    ),
    signatureWindowSeconds: seconds(doc.signature_window_seconds, "signature_window_seconds", 300),
    scopeDescriptions,
    operations,
  };
}

/**
 * Read `aauth-resource.json` from the configuration directory: `dir`, else
 * `MISSION_CONFIG_DIR`, else `config` under the working directory.
 */
export function loadResourceConfig(dir?: string): ResourceConfig {
  const base = dir ?? process.env.MISSION_CONFIG_DIR ?? join(process.cwd(), "config");
  const file = join(base, "aauth-resource.json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new ConfigError(`${file}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return parseResourceConfig(parsed);
}
