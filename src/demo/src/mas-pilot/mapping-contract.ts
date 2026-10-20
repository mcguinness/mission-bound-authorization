/**
 * @spec authority-server#mapping-contract, authority-server#mission-join
 * rules 3, 4, 5 and 8 (#818)
 *
 * The MAS pilot's versioned mapping contract and the governed,
 * pre-materialized cache the gateway applies it from. The contract states,
 * for the joins the pilot performs: the subject namespace mapping, the client
 * namespace mapping, the scope mapping, the delegate policy, whether
 * client-instance identity is supported (it is not), a version identifier,
 * its provenance, and the failure semantics (`mission_binding_failed` on any
 * unresolved or ambiguous mapping).
 *
 * Resolution is synchronous over an installed snapshot: the pilot chose a
 * governed cache over asynchronous lookups (#818 Sketch step 3). A snapshot is
 * usable for `maxStaleSeconds` after the cache installed it; after that every
 * resolution fails closed until a newer version is installed. Versions only
 * move forward. Every mapping decision and every install, refusal and
 * invalidation is recorded in the cache's audit log.
 */

import {
  type AuthorityEntry,
  type DelegatePolicy,
  type JoinIdentityResolution,
  type JoinMappingContract,
  UNRESOLVED_JOIN_MAPPING,
} from "@mission/pdp";

/** One subject row: an issuer-qualified estate subject and the Mission-namespace subject it maps to. */
export interface SubjectMappingRow {
  from: { iss: string; sub: string };
  to: { iss: string; sub: string };
  status: "active" | "disabled";
}

/** One client row: an issuer-qualified estate client and the Mission client it maps to. */
export interface ClientMappingRow {
  from: { iss: string; client_id: string };
  to: string;
  status: "active" | "disabled";
}

/** The published mapping contract, as the strict loader accepts it. */
export interface MappingContractDocument {
  contract_id: string;
  version: number;
  issued_at: string;
  provenance: { source: string; export_id: string; exported_at: string };
  /** The Mission Issuer whose Missions this contract's joins apply to. */
  mission_issuer: string;
  subjects: SubjectMappingRow[];
  clients: ClientMappingRow[];
  /** Scope value to actions at `resource`, per credential issuer. */
  scopes: { resource: string; issuers: Record<string, Record<string, string[]>> };
  /** Rule 4's enumerated delegates, keyed by Mission-namespace client. */
  delegates: Record<string, { max_depth: number }>;
  instance: { supported: false; required: false };
  failure: "mission_binding_failed";
}

export class MappingContractError extends Error {
  constructor(message: string) {
    super(`mapping contract: ${message}`);
    this.name = "MappingContractError";
  }
}

const TOP_LEVEL = [
  "contract_id",
  "version",
  "issued_at",
  "provenance",
  "mission_issuer",
  "subjects",
  "clients",
  "scopes",
  "delegates",
  "instance",
  "failure",
] as const;

function object(v: unknown, ctx: string, members: readonly string[]): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new MappingContractError(`${ctx} must be an object`);
  const o = v as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (!members.includes(key)) throw new MappingContractError(`${ctx} has unknown member ${key}`);
  }
  for (const key of members) {
    if (!Object.hasOwn(o, key)) throw new MappingContractError(`${ctx} is missing ${key}`);
  }
  return o;
}

function text(v: unknown, ctx: string): string {
  if (typeof v !== "string" || v === "") throw new MappingContractError(`${ctx} must be a non-empty string`);
  return v;
}

function instant(v: unknown, ctx: string): string {
  const s = text(v, ctx);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s) || !Number.isFinite(Date.parse(s))) {
    throw new MappingContractError(`${ctx} must be an RFC 3339 date-time`);
  }
  return s;
}

function status(v: unknown, ctx: string): "active" | "disabled" {
  if (v !== "active" && v !== "disabled") throw new MappingContractError(`${ctx} must be "active" or "disabled"`);
  return v;
}

const keyOf = (iss: string, id: string): string => JSON.stringify([iss, id]);

/**
 * @spec authority-server#mapping-contract: the strict loader. It refuses an
 * unknown or missing member, a malformed value, and an AMBIGUOUS mapping: a
 * second row for one issuer-qualified estate subject or client, since one
 * credential identity mapping to two Mission identities cannot be resolved.
 * Several estate identities mapping to ONE Mission identity (many-to-one) is
 * accepted: each row is still one decision, and the audit log records which
 * estate identity was resolved.
 */
export function parseMappingContract(raw: unknown): MappingContractDocument {
  const root = object(raw, "contract", TOP_LEVEL);
  const version = root.version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new MappingContractError("version must be a positive integer");
  }
  const provenance = object(root.provenance, "provenance", ["source", "export_id", "exported_at"]);
  const missionIssuer = text(root.mission_issuer, "mission_issuer");

  if (!Array.isArray(root.subjects)) throw new MappingContractError("subjects must be an array");
  const seenSubjects = new Set<string>();
  const subjects = root.subjects.map((rowRaw, i): SubjectMappingRow => {
    const ctx = `subjects[${i}]`;
    const row = object(rowRaw, ctx, ["from", "to", "status"]);
    const from = object(row.from, `${ctx}.from`, ["iss", "sub"]);
    const to = object(row.to, `${ctx}.to`, ["iss", "sub"]);
    const mapped: SubjectMappingRow = {
      from: { iss: text(from.iss, `${ctx}.from.iss`), sub: text(from.sub, `${ctx}.from.sub`) },
      to: { iss: text(to.iss, `${ctx}.to.iss`), sub: text(to.sub, `${ctx}.to.sub`) },
      status: status(row.status, `${ctx}.status`),
    };
    const key = keyOf(mapped.from.iss, mapped.from.sub);
    if (seenSubjects.has(key)) throw new MappingContractError(`${ctx} maps an estate subject a second time (ambiguous)`);
    seenSubjects.add(key);
    return mapped;
  });

  if (!Array.isArray(root.clients)) throw new MappingContractError("clients must be an array");
  const seenClients = new Set<string>();
  const clients = root.clients.map((rowRaw, i): ClientMappingRow => {
    const ctx = `clients[${i}]`;
    const row = object(rowRaw, ctx, ["from", "to", "status"]);
    const from = object(row.from, `${ctx}.from`, ["iss", "client_id"]);
    const mapped: ClientMappingRow = {
      from: { iss: text(from.iss, `${ctx}.from.iss`), client_id: text(from.client_id, `${ctx}.from.client_id`) },
      to: text(row.to, `${ctx}.to`),
      status: status(row.status, `${ctx}.status`),
    };
    const key = keyOf(mapped.from.iss, mapped.from.client_id);
    if (seenClients.has(key)) throw new MappingContractError(`${ctx} maps an estate client a second time (ambiguous)`);
    seenClients.add(key);
    return mapped;
  });

  const scopesRaw = object(root.scopes, "scopes", ["resource", "issuers"]);
  const issuersRaw = scopesRaw.issuers;
  if (issuersRaw === null || typeof issuersRaw !== "object" || Array.isArray(issuersRaw)) {
    throw new MappingContractError("scopes.issuers must be an object");
  }
  const issuers: Record<string, Record<string, string[]>> = {};
  for (const [iss, valuesRaw] of Object.entries(issuersRaw as Record<string, unknown>)) {
    if (valuesRaw === null || typeof valuesRaw !== "object" || Array.isArray(valuesRaw)) {
      throw new MappingContractError(`scopes.issuers.${iss} must be an object`);
    }
    const values: Record<string, string[]> = {};
    for (const [scope, actions] of Object.entries(valuesRaw as Record<string, unknown>)) {
      if (!Array.isArray(actions) || actions.length === 0) {
        throw new MappingContractError(`scopes.issuers.${iss}.${scope} must be a non-empty array`);
      }
      values[scope] = actions.map((a, i) => text(a, `scopes.issuers.${iss}.${scope}[${i}]`));
    }
    issuers[iss] = values;
  }

  const delegatesRaw = root.delegates;
  if (delegatesRaw === null || typeof delegatesRaw !== "object" || Array.isArray(delegatesRaw)) {
    throw new MappingContractError("delegates must be an object");
  }
  const delegates: Record<string, { max_depth: number }> = {};
  for (const [client, entryRaw] of Object.entries(delegatesRaw as Record<string, unknown>)) {
    const entry = object(entryRaw, `delegates.${client}`, ["max_depth"]);
    const depth = entry.max_depth;
    if (typeof depth !== "number" || !Number.isInteger(depth) || depth < 0) {
      throw new MappingContractError(`delegates.${client}.max_depth must be a non-negative integer`);
    }
    delegates[client] = { max_depth: depth };
  }

  const instanceRaw = object(root.instance, "instance", ["supported", "required"]);
  if (instanceRaw.supported !== false || instanceRaw.required !== false) {
    throw new MappingContractError("instance: this pilot supports no client-instance identity");
  }
  if (root.failure !== "mission_binding_failed") {
    throw new MappingContractError('failure must be "mission_binding_failed"');
  }

  return {
    contract_id: text(root.contract_id, "contract_id"),
    version,
    issued_at: instant(root.issued_at, "issued_at"),
    provenance: {
      source: text(provenance.source, "provenance.source"),
      export_id: text(provenance.export_id, "provenance.export_id"),
      exported_at: instant(provenance.exported_at, "provenance.exported_at"),
    },
    mission_issuer: missionIssuer,
    subjects,
    clients,
    scopes: { resource: text(scopesRaw.resource, "scopes.resource"), issuers },
    delegates,
    instance: { supported: false, required: false },
    failure: "mission_binding_failed",
  };
}

/** One audit record: a mapping decision, or a change to what the cache holds. */
export type MappingAuditRecord =
  | {
      kind: "identity";
      at: string;
      /** The contract version applied; absent when no snapshot was usable. */
      contract?: { id: string; version: number; export_id: string };
      from: { subject: { iss: string; sub: string }; client: { iss: string; clientId: string } };
      mission_issuer: string;
      outcome: "resolved" | "unresolved" | "stale" | "wrong_mission_issuer" | "no_snapshot";
      to?: JoinIdentityResolution;
    }
  | { kind: "install"; at: string; contract: { id: string; version: number; export_id: string } }
  | { kind: "install_refused"; at: string; reason: string }
  | { kind: "invalidate"; at: string };

class MappingSnapshot implements JoinMappingContract {
  readonly id: string;
  readonly version: number;
  readonly delegatePolicy: DelegatePolicy;
  private readonly subjects = new Map<string, SubjectMappingRow>();
  private readonly clients = new Map<string, ClientMappingRow>();
  private readonly scopes = new Map<string, Map<string, string[]>>();

  constructor(
    private readonly doc: MappingContractDocument,
    private readonly installedAtMs: number,
    private readonly maxStaleMs: number,
    private readonly record: (entry: MappingAuditRecord) => void,
  ) {
    this.id = doc.contract_id;
    this.version = doc.version;
    this.delegatePolicy = {
      delegates: Object.fromEntries(Object.entries(doc.delegates).map(([c, d]) => [c, { maxDepth: d.max_depth }])),
    };
    for (const row of doc.subjects) this.subjects.set(keyOf(row.from.iss, row.from.sub), row);
    for (const row of doc.clients) this.clients.set(keyOf(row.from.iss, row.from.client_id), row);
    for (const [iss, values] of Object.entries(doc.scopes.issuers)) this.scopes.set(iss, new Map(Object.entries(values)));
  }

  /** Usable from install until `maxStaleSeconds` later, and never before install. */
  private fresh(now: Date): boolean {
    const age = now.getTime() - this.installedAtMs;
    return age >= 0 && age <= this.maxStaleMs;
  }

  private ref(): { id: string; version: number; export_id: string } {
    return { id: this.id, version: this.version, export_id: this.doc.provenance.export_id };
  }

  resolveIdentity(input: {
    subject: { iss: string; sub: string };
    client: { iss: string; clientId: string };
    missionIssuer: string;
    now: Date;
  }): JoinIdentityResolution | undefined {
    const base = {
      kind: "identity" as const,
      at: input.now.toISOString(),
      contract: this.ref(),
      from: { subject: { ...input.subject }, client: { ...input.client } },
      mission_issuer: input.missionIssuer,
    };
    if (!this.fresh(input.now)) {
      this.record({ ...base, outcome: "stale" });
      return undefined;
    }
    if (input.missionIssuer !== this.doc.mission_issuer) {
      this.record({ ...base, outcome: "wrong_mission_issuer" });
      return undefined;
    }
    const subjectRow = this.subjects.get(keyOf(input.subject.iss, input.subject.sub));
    const clientRow = this.clients.get(keyOf(input.client.iss, input.client.clientId));
    if (subjectRow?.status !== "active" || clientRow?.status !== "active") {
      this.record({ ...base, outcome: "unresolved" });
      return undefined;
    }
    const to: JoinIdentityResolution = { subject: { ...subjectRow.to }, clientId: clientRow.to };
    this.record({ ...base, outcome: "resolved", to });
    return to;
  }

  clientFor(client: { iss: string; clientId: string }, now: Date): string | undefined {
    if (!this.fresh(now)) return undefined;
    const row = this.clients.get(keyOf(client.iss, client.clientId));
    return row?.status === "active" ? row.to : undefined;
  }

  credentialAuthority(input: {
    issuer: string;
    scope: string | undefined;
    resource: string;
    now: Date;
  }): AuthorityEntry[] | undefined {
    if (!this.fresh(input.now) || input.resource !== this.doc.scopes.resource || input.scope === undefined) return undefined;
    const values = this.scopes.get(input.issuer);
    if (!values) return undefined;
    const actions = [...new Set(input.scope.split(" ").flatMap((value) => values.get(value) ?? []))];
    if (actions.length === 0) return undefined;
    return [{ type: "mission_resource_access", resource: input.resource, actions }];
  }
}

/**
 * @spec authority-server#mapping-contract (#818): the governed cache. It
 * holds at most one installed contract version. `install` accepts only a
 * contract the strict loader accepts with a version above the installed one,
 * so a replayed or rolled-back export is refused; a refused install leaves the
 * installed version in place until it goes stale. `current()` hands out one
 * immutable snapshot, which a caller uses for a whole request.
 */
export class MappingContractCache {
  private snapshot: MappingSnapshot | undefined;
  private highestVersion = 0;
  private readonly log: MappingAuditRecord[] = [];
  private readonly maxStaleMs: number;
  private readonly now: () => Date;

  constructor(opts: { maxStaleSeconds: number; now?: () => Date }) {
    if (!Number.isInteger(opts.maxStaleSeconds) || opts.maxStaleSeconds <= 0) {
      throw new MappingContractError("maxStaleSeconds must be a positive integer");
    }
    this.maxStaleMs = opts.maxStaleSeconds * 1000;
    this.now = opts.now ?? (() => new Date());
  }

  /** Install a newer contract version, or refuse it and say why. */
  install(raw: unknown): { ok: true; version: number } | { ok: false; reason: string } {
    const at = this.now();
    let doc: MappingContractDocument;
    try {
      doc = parseMappingContract(raw);
    } catch (e) {
      const reason = (e as Error).message;
      this.log.push({ kind: "install_refused", at: at.toISOString(), reason });
      return { ok: false, reason };
    }
    if (doc.version <= this.highestVersion) {
      const reason = `mapping contract: version ${doc.version} is not above installed version ${this.highestVersion}`;
      this.log.push({ kind: "install_refused", at: at.toISOString(), reason });
      return { ok: false, reason };
    }
    this.highestVersion = doc.version;
    this.snapshot = new MappingSnapshot(doc, at.getTime(), this.maxStaleMs, (entry) => this.log.push(entry));
    this.log.push({
      kind: "install",
      at: at.toISOString(),
      contract: { id: doc.contract_id, version: doc.version, export_id: doc.provenance.export_id },
    });
    return { ok: true, version: doc.version };
  }

  /** Drop the installed snapshot: every join fails closed until the next install. */
  invalidate(): void {
    this.snapshot = undefined;
    this.log.push({ kind: "invalidate", at: this.now().toISOString() });
  }

  /**
   * The snapshot one request applies. With none installed it resolves
   * nothing, and still records each identity decision it refuses.
   */
  current(): JoinMappingContract {
    if (this.snapshot) return this.snapshot;
    const record = (entry: MappingAuditRecord): void => {
      this.log.push(entry);
    };
    return {
      ...UNRESOLVED_JOIN_MAPPING,
      resolveIdentity: (input) => {
        record({
          kind: "identity",
          at: input.now.toISOString(),
          from: { subject: { ...input.subject }, client: { ...input.client } },
          mission_issuer: input.missionIssuer,
          outcome: "no_snapshot",
        });
        return undefined;
      },
    };
  }

  /** The audit log, oldest first. */
  audit(): readonly MappingAuditRecord[] {
    return this.log;
  }
}
