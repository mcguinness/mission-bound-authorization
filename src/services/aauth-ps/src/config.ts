import { readFileSync } from "node:fs";
import {
  AAUTH_SERVER_DOCUMENTS,
  determineAlgorithm,
  isAgentIdentifier,
  isServerIdentifier,
  isWellKnownName,
} from "@mission/aauth-wire";

/** A configuration file that fails validation; the boot stops. */
export class PsConfigError extends Error {
  constructor(message: string) {
    super(`aauth-ps config: ${message}`);
    this.name = "PsConfigError";
  }
}

/** A person the PS represents. */
export interface PersonEntry {
  id: string;
  /** OpenID Connect Enterprise `tenant`, stamped into the tokens issued for this person. */
  tenant?: string;
}

/**
 * An agent the PS serves, bound to exactly one person (AAuth -11 Section
 * 13.14). The list is the deterministic approver's agent allowlist: an
 * agent it does not name is refused at every endpoint.
 */
export interface AgentEntry {
  agent: string;
  person: string;
  /**
   * Under mission governance: a missionless person-token or auth-token
   * request from this agent is refused (the binding's Reference
   * Propagation rule, vector V9). False admits intentionally missionless
   * access from the outset (V14).
   */
  missionGoverned: boolean;
}

/** One description rule: a case-insensitive substring and its decision. */
export interface DescriptionRule {
  contains: string;
  decision: "approve" | "deny";
}

export interface PsLifetimes {
  /** At most 3600 (AAuth -11 Section 7.1.2). */
  personTokenSeconds: number;
  /** At most 3600 (AAuth -11 Section 9.4.1). */
  authTokenSeconds: number;
  /** The `expires_at` a mission gets when its proposal requests none. */
  missionDefaultSeconds: number;
  /** The latest `expires_at` the PS approves, from approval time. */
  missionMaxSeconds: number;
}

/** The control-plane actions this PS implements (the management companion). */
export const CONTROL_ACTIONS = ["status", "terminate"] as const;
export type ControlAction = (typeof CONTROL_ACTIONS)[number];

/**
 * A statically configured administrator (the management companion's
 * Administrator caller class). It signs control-plane requests under the
 * AAuth HTTP Message Signatures profile with Signature-Key `jwks_uri`:
 * `id` its identifier, `dwk` a deployment-chosen document name, `kid` its
 * key. The PS resolves that key from this registration, its own
 * administrative channel, and never fetches it: a pinned, enrolled key,
 * so the request is sender-constrained and nothing the administrator
 * types can be phished. Its privilege is scoped by person population and
 * by action.
 */
export interface AdministratorEntry {
  id: string;
  dwk: string;
  kid: string;
  /** The enrolled public key, with its `kid` and a fully-specified `alg`. */
  key: Readonly<Record<string, string>>;
  /** The persons whose missions this administrator governs. */
  persons: ReadonlySet<string>;
  actions: ReadonlySet<ControlAction>;
}

/** Revocation attempts after termination: bounded, spaced, and timed out. */
export interface RevocationPolicy {
  /** Attempts per Tracked Credential and recipient before the PS stops. */
  maxAttempts: number;
  /** The first retry's delay; each later one doubles, up to `retryMaxSeconds`. */
  retryBaseSeconds: number;
  retryMaxSeconds: number;
  /** One attempt's limit, discovery and request together. */
  attemptTimeoutMs: number;
  /** How long a terminate waits for immediate results before it answers; 0 does not wait. */
  immediateWaitMs: number;
}

/** The mission control plane's deployment policy. */
export interface ManagementConfig {
  /** The management companion's Owning Agent: admitted for status and `revoked` termination. */
  admitOwningAgent: boolean;
  /** `fresh_until` is this many seconds after `observed_at`. */
  statusFreshSeconds: number;
  /**
   * True when an access mode the PS does not track (agent identity access,
   * resource-managed access) may serve a mission's work; `complete` is then
   * never true.
   */
  untrackedAccess: boolean;
  revocation: RevocationPolicy;
  administrators: readonly AdministratorEntry[];
}

/** The PS's static deployment configuration. */
export interface PsConfig {
  /** The PS's server identifier: `iss` of every token it mints. */
  issuer: string;
  /** The signing key's `kid` and `alg`; the key pair is generated per boot. */
  signingKey: { kid: string; alg: "Ed25519" | "ES256" };
  lifetimes: PsLifetimes;
  persons: ReadonlyMap<string, PersonEntry>;
  agents: ReadonlyMap<string, AgentEntry>;
  /** Evaluated in order against a proposal's description; the first match decides. */
  descriptionRules: readonly DescriptionRule[];
  /** The decision when no rule matches. */
  defaultDecision: "approve" | "deny";
  /** The mission control plane's policy; absent, the PS implements no control plane. */
  management?: ManagementConfig;
}

type Json = Record<string, unknown>;

function object(value: unknown, where: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PsConfigError(`${where} is not an object`);
  }
  return value as Json;
}

function only(value: Json, where: string, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new PsConfigError(`${where} has unknown member ${key}`);
  }
}

function string(value: unknown, where: string): string {
  if (typeof value !== "string" || value === "") {
    throw new PsConfigError(`${where} is not a non-empty string`);
  }
  return value;
}

function seconds(value: unknown, where: string, max?: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new PsConfigError(`${where} is not a positive integer`);
  }
  if (max !== undefined && value > max) throw new PsConfigError(`${where} exceeds ${max}`);
  return value;
}

function decision(value: unknown, where: string): "approve" | "deny" {
  if (value !== "approve" && value !== "deny") {
    throw new PsConfigError(`${where} is neither approve nor deny`);
  }
  return value;
}

function nonNegative(value: unknown, where: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new PsConfigError(`${where} is not a non-negative integer`);
  }
  return value;
}

function boolean(value: unknown, where: string): boolean {
  if (typeof value !== "boolean") throw new PsConfigError(`${where} is not a boolean`);
  return value;
}

/** A non-empty array of distinct strings, each accepted by `accept`. */
function stringSet(
  value: unknown,
  where: string,
  accept: (s: string) => boolean,
  what: string,
): Set<string> {
  if (!Array.isArray(value) || value.length === 0) {
    throw new PsConfigError(`${where} is not a non-empty array`);
  }
  const out = new Set<string>();
  for (const item of value) {
    const s = string(item, `${where}[]`);
    if (!accept(s)) throw new PsConfigError(`${where} names ${what} ${s}`);
    if (out.has(s)) throw new PsConfigError(`${where} names ${s} twice`);
    out.add(s);
  }
  return out;
}

const PUBLIC_KEY_MEMBERS = ["kty", "crv", "x", "y", "alg", "kid"] as const;

/**
 * An administrator's enrolled public key: public members only, a `kid`,
 * and a fully-specified `alg` its key type agrees with.
 */
function administratorKey(value: unknown, where: string): Record<string, string> {
  const key = object(value, where);
  only(key, where, PUBLIC_KEY_MEMBERS);
  const out: Record<string, string> = {};
  for (const name of PUBLIC_KEY_MEMBERS) {
    if (key[name] !== undefined) out[name] = string(key[name], `${where}.${name}`);
  }
  if (out.kid === undefined) throw new PsConfigError(`${where}.kid is missing`);
  try {
    determineAlgorithm(out);
  } catch (err) {
    throw new PsConfigError(`${where} is not a usable public key: ${(err as Error).message}`);
  }
  return out;
}

function parseManagement(
  raw: unknown,
  issuer: string,
  persons: ReadonlyMap<string, PersonEntry>,
): ManagementConfig {
  const doc = object(raw, "management");
  only(doc, "management", [
    "admit_owning_agent",
    "status_fresh_seconds",
    "untracked_access",
    "revocation",
    "administrators",
  ]);
  const rev = object(doc.revocation, "management.revocation");
  only(rev, "management.revocation", [
    "max_attempts",
    "retry_base_seconds",
    "retry_max_seconds",
    "attempt_timeout_ms",
    "immediate_wait_ms",
  ]);
  const revocation: RevocationPolicy = {
    maxAttempts: seconds(rev.max_attempts, "management.revocation.max_attempts"),
    retryBaseSeconds: seconds(rev.retry_base_seconds, "management.revocation.retry_base_seconds"),
    retryMaxSeconds: seconds(rev.retry_max_seconds, "management.revocation.retry_max_seconds"),
    attemptTimeoutMs: seconds(rev.attempt_timeout_ms, "management.revocation.attempt_timeout_ms"),
    immediateWaitMs: nonNegative(rev.immediate_wait_ms, "management.revocation.immediate_wait_ms"),
  };
  if (revocation.retryBaseSeconds > revocation.retryMaxSeconds) {
    throw new PsConfigError("management.revocation.retry_base_seconds exceeds retry_max_seconds");
  }

  if (!Array.isArray(doc.administrators)) {
    throw new PsConfigError("management.administrators is not an array");
  }
  const ids = new Set<string>();
  const administrators = doc.administrators.map((entry, i): AdministratorEntry => {
    const where = `management.administrators[${i}]`;
    const a = object(entry, where);
    only(a, where, ["id", "dwk", "key", "persons", "actions"]);
    if (!isServerIdentifier(a.id))
      throw new PsConfigError(`${where}.id is not a server identifier`);
    if (a.id === issuer) throw new PsConfigError(`${where}.id is the person server's own issuer`);
    if (ids.has(a.id)) throw new PsConfigError(`management.administrators names ${a.id} twice`);
    ids.add(a.id);
    // An AAuth document name would let an AAuth server's own signature, or a
    // token naming that document, be read as this administrator's.
    if (
      !isWellKnownName(a.dwk) ||
      (AAUTH_SERVER_DOCUMENTS as readonly string[]).includes(a.dwk as string)
    ) {
      throw new PsConfigError(`${where}.dwk is not a deployment-chosen document name`);
    }
    const key = administratorKey(a.key, `${where}.key`);
    return {
      id: a.id,
      dwk: a.dwk as string,
      kid: key.kid as string,
      key,
      persons: stringSet(a.persons, `${where}.persons`, (p) => persons.has(p), "unknown person"),
      actions: stringSet(
        a.actions,
        `${where}.actions`,
        (s) => (CONTROL_ACTIONS as readonly string[]).includes(s),
        "unknown action",
      ) as Set<ControlAction>,
    };
  });

  return {
    admitOwningAgent: boolean(doc.admit_owning_agent, "management.admit_owning_agent"),
    statusFreshSeconds: seconds(doc.status_fresh_seconds, "management.status_fresh_seconds"),
    untrackedAccess: boolean(doc.untracked_access, "management.untracked_access"),
    revocation,
    administrators,
  };
}

/**
 * Validate a parsed configuration document. Strict: unknown members,
 * duplicates, an agent bound to an unknown person, and a token lifetime
 * over AAuth's one-hour ceiling all refuse.
 */
export function parsePsConfig(raw: unknown): PsConfig {
  const doc = object(raw, "the document");
  only(doc, "the document", [
    "issuer",
    "signing_key",
    "lifetimes",
    "persons",
    "agents",
    "description_rules",
    "default_decision",
    "management",
  ]);
  if (!isServerIdentifier(doc.issuer)) throw new PsConfigError("issuer is not a server identifier");

  const key = object(doc.signing_key, "signing_key");
  only(key, "signing_key", ["kid", "alg"]);
  let alg: "Ed25519" | "ES256";
  if (key.alg === "Ed25519" || key.alg === "ES256") alg = key.alg;
  else throw new PsConfigError("signing_key.alg is neither Ed25519 nor ES256");
  const signingKey = { kid: string(key.kid, "signing_key.kid"), alg };

  const life = object(doc.lifetimes, "lifetimes");
  only(life, "lifetimes", [
    "person_token_seconds",
    "auth_token_seconds",
    "mission_default_seconds",
    "mission_max_seconds",
  ]);
  const lifetimes: PsLifetimes = {
    personTokenSeconds: seconds(life.person_token_seconds, "lifetimes.person_token_seconds", 3600),
    authTokenSeconds: seconds(life.auth_token_seconds, "lifetimes.auth_token_seconds", 3600),
    missionDefaultSeconds: seconds(
      life.mission_default_seconds,
      "lifetimes.mission_default_seconds",
    ),
    missionMaxSeconds: seconds(life.mission_max_seconds, "lifetimes.mission_max_seconds"),
  };
  if (lifetimes.missionDefaultSeconds > lifetimes.missionMaxSeconds) {
    throw new PsConfigError("lifetimes.mission_default_seconds exceeds mission_max_seconds");
  }

  if (!Array.isArray(doc.persons)) throw new PsConfigError("persons is not an array");
  const persons = new Map<string, PersonEntry>();
  doc.persons.forEach((entry, i) => {
    const p = object(entry, `persons[${i}]`);
    only(p, `persons[${i}]`, ["id", "tenant"]);
    const id = string(p.id, `persons[${i}].id`);
    if (persons.has(id)) throw new PsConfigError(`persons names ${id} twice`);
    const person: PersonEntry = { id };
    if (p.tenant !== undefined) person.tenant = string(p.tenant, `persons[${i}].tenant`);
    persons.set(id, person);
  });

  if (!Array.isArray(doc.agents)) throw new PsConfigError("agents is not an array");
  const agents = new Map<string, AgentEntry>();
  doc.agents.forEach((entry, i) => {
    const a = object(entry, `agents[${i}]`);
    only(a, `agents[${i}]`, ["agent", "person", "mission_governed"]);
    if (!isAgentIdentifier(a.agent)) {
      throw new PsConfigError(`agents[${i}].agent is not an agent identifier`);
    }
    if (agents.has(a.agent)) throw new PsConfigError(`agents names ${a.agent} twice`);
    const person = string(a.person, `agents[${i}].person`);
    if (!persons.has(person))
      throw new PsConfigError(`agents[${i}] names unknown person ${person}`);
    if (typeof a.mission_governed !== "boolean") {
      throw new PsConfigError(`agents[${i}].mission_governed is not a boolean`);
    }
    agents.set(a.agent, { agent: a.agent, person, missionGoverned: a.mission_governed });
  });

  if (!Array.isArray(doc.description_rules)) {
    throw new PsConfigError("description_rules is not an array");
  }
  const descriptionRules = doc.description_rules.map((entry, i): DescriptionRule => {
    const r = object(entry, `description_rules[${i}]`);
    only(r, `description_rules[${i}]`, ["contains", "decision"]);
    return {
      contains: string(r.contains, `description_rules[${i}].contains`),
      decision: decision(r.decision, `description_rules[${i}].decision`),
    };
  });

  const config: PsConfig = {
    issuer: doc.issuer,
    signingKey,
    lifetimes,
    persons,
    agents,
    descriptionRules,
    defaultDecision: decision(doc.default_decision, "default_decision"),
  };
  if (doc.management !== undefined) {
    config.management = parseManagement(doc.management, doc.issuer, persons);
  }
  return config;
}

/** Read and validate the configuration file at `file`. */
export function loadPsConfig(file: string): PsConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new PsConfigError(`cannot read ${file}: ${(err as Error).message}`);
  }
  return parsePsConfig(raw);
}
