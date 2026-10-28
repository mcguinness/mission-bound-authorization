import { readFileSync } from "node:fs";
import { isAgentIdentifier, isServerIdentifier } from "@mission/aauth-wire";

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

  return {
    issuer: doc.issuer,
    signingKey,
    lifetimes,
    persons,
    agents,
    descriptionRules,
    defaultDecision: decision(doc.default_decision, "default_decision"),
  };
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
