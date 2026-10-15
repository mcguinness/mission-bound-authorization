/**
 * @spec fga-hygiene (docs/fga-hygiene.md), decision D26, #828
 *
 * OpenFGA integration. Stored tuples hold ONLY the durable domain substrate:
 * invoice ownership and the principal entitlements an administrator grants.
 * Mission authority is injected per check as contextual tuples derived from
 * the Mission Record; nothing mission-scoped is ever written to the store.
 * Every check pins an explicit authorization_model_id.
 *
 * Creating a store is a development operation ({@link Fga.bootstrap}); a
 * deployment attaches to its configured store and model and verifies the
 * model ({@link Fga.attach}). Granting and revoking stored entitlements is a
 * separate administrative capability ({@link FgaDomainAdmin}).
 */

import { readFileSync } from "node:fs";
import { canonicalize, type JsonValue } from "@mission/core";
import { getTracer } from "@mission/telemetry";
import { CredentialsMethod, OpenFgaClient, type TupleKey } from "@openfga/sdk";

/** A stored entitlement inherited by every invoice the vendor owns. */
const FROM_VENDOR = (relation: string) => ({
  tupleToUserset: { tupleset: { object: "", relation: "vendor" }, computedUserset: { object: "", relation } },
});

/**
 * Domain model, two disjoint relation families:
 *
 * - Mission context (`payer`/`reader` on invoices and vendors, `approved` on
 *   vendors): admits only `mission` subjects and is never stored. Mission
 *   authority arrives as contextual tuples keyed by a per-check ephemeral
 *   `mission:<id>` object.
 * - Stored entitlement (`authorized_payer`/`authorized_reader`, #828):
 *   admits only `user` principals, granted directly on a vendor or invoice,
 *   or inherited by an invoice from its owning vendor (`invoice#vendor`).
 *   No rewrite reaches a Mission-context relation, so no `mission:` tuple,
 *   stored or contextual, can satisfy an entitlement.
 */
export const DOMAIN_MODEL = {
  schema_version: "1.1",
  type_definitions: [
    { type: "user" },
    { type: "client" },
    {
      type: "vendor",
      relations: {
        approved: { this: {} },
        reader: { this: {} },
        authorized_reader: { this: {} },
        authorized_payer: { this: {} },
      },
      metadata: {
        relations: {
          approved: { directly_related_user_types: [{ type: "mission" }] },
          reader: { directly_related_user_types: [{ type: "mission" }] },
          authorized_reader: { directly_related_user_types: [{ type: "user" }] },
          authorized_payer: { directly_related_user_types: [{ type: "user" }] },
        },
      },
    },
    {
      type: "invoice",
      relations: {
        payer: { this: {} },
        reader: { this: {} },
        vendor: { this: {} },
        authorized_reader: { union: { child: [{ this: {} }, FROM_VENDOR("authorized_reader")] } },
        authorized_payer: { union: { child: [{ this: {} }, FROM_VENDOR("authorized_payer")] } },
      },
      metadata: {
        relations: {
          payer: { directly_related_user_types: [{ type: "mission" }] },
          reader: { directly_related_user_types: [{ type: "mission" }] },
          vendor: { directly_related_user_types: [{ type: "vendor" }] },
          authorized_reader: { directly_related_user_types: [{ type: "user" }] },
          authorized_payer: { directly_related_user_types: [{ type: "user" }] },
        },
      },
    },
    { type: "mission" },
  ],
} as const;

export interface FgaConfig {
  apiUrl: string;
  storeId: string;
  authorizationModelId: string;
  presharedKey: string;
  caCertPath?: string;
  /** Per-request timeout, milliseconds. A request that exceeds it is a failed read, never an answer. */
  requestTimeoutMs?: number;
}

/**
 * Attach refused: the configured store or model cannot be read, or the
 * model is not {@link DOMAIN_MODEL}. A startup error, never a fallback to
 * creating a store or to an unpinned model.
 */
export class FgaAttachError extends Error {
  constructor(why: string) {
    super(`OpenFGA attach refused: ${why}`);
    this.name = "FgaAttachError";
  }
}

type Rewrite = Record<string, unknown> | undefined;

/** An authorization model as the API returns it; only the members verification reads. */
type ModelJson = {
  schema_version?: string;
  type_definitions?: readonly unknown[];
  conditions?: Readonly<Record<string, unknown>> | null;
};

type TypeDefinitionJson = {
  type: string;
  relations?: Record<string, Rewrite> | null;
  metadata?: { relations?: Record<string, { directly_related_user_types?: unknown[] | null } | null> | null } | null;
};

type RelationReferenceJson = { type?: unknown; relation?: unknown; wildcard?: unknown; condition?: unknown };

/**
 * A string member as the model states it. `""` and `null` are the proto3
 * forms a server emits for an unset member, so they read as absent.
 */
function stated(v: unknown): JsonValue {
  return v === undefined || v === null || v === "" ? null : (v as JsonValue);
}

/** Both members of an `ObjectRelation` (a computed userset or a tupleset). */
function objectRelation(r: unknown): JsonValue {
  if (typeof r !== "object" || r === null) return null;
  const { object, relation } = r as { object?: unknown; relation?: unknown };
  return { object: stated(object), relation: stated(relation) };
}

/** Every member of one directly related user type: type, userset relation, wildcard and condition. */
function relationReference(u: unknown): string {
  const ref = (u ?? {}) as RelationReferenceJson;
  return canonicalize({
    type: stated(ref.type),
    relation: stated(ref.relation),
    wildcard: ref.wildcard !== undefined && ref.wildcard !== null,
    condition: stated(ref.condition),
  });
}

/** The relation names a type defines, in its rewrites or only in its metadata. */
function relationNames(t: TypeDefinitionJson): string[] {
  return [...new Set([...Object.keys(t.relations ?? {}), ...Object.keys(t.metadata?.relations ?? {})])].sort();
}

const USERSET_MEMBERS = new Set([
  "this",
  "computedUserset",
  "computed_userset",
  "tupleToUserset",
  "tuple_to_userset",
  "union",
  "intersection",
  "difference",
]);

/**
 * The semantic content of one relation rewrite, ignoring server-added
 * metadata. Reads both the JSON names the API documents (`computedUserset`)
 * and the proto field names (`computed_userset`). A userset is a proto
 * oneof: one with no member, several, or one this function does not know is
 * compared verbatim, never read as its first recognized member.
 */
function rewriteShape(r: Rewrite): JsonValue {
  if (!r) return null;
  const members = Object.keys(r).filter((k) => r[k] !== undefined && r[k] !== null);
  if (members.length !== 1 || !USERSET_MEMBERS.has(members[0] as string)) return { unknown: canonicalize(r as JsonValue) };
  if (r.this !== undefined && r.this !== null) return "this";
  const computed = r.computedUserset ?? r.computed_userset;
  if (computed) return { computed: objectRelation(computed) };
  const ttu = (r.tupleToUserset ?? r.tuple_to_userset) as
    | { tupleset?: unknown; computedUserset?: unknown; computed_userset?: unknown }
    | undefined;
  if (ttu) {
    return { ttu: [objectRelation(ttu.tupleset), objectRelation(ttu.computedUserset ?? ttu.computed_userset)] };
  }
  for (const op of ["union", "intersection"] as const) {
    const children = (r[op] as { child?: Rewrite[] } | undefined)?.child;
    if (children) return { [op]: children.map(rewriteShape) };
  }
  if (r.difference) {
    const d = r.difference as { base?: Rewrite; subtract?: Rewrite };
    return { difference: [rewriteShape(d.base), rewriteShape(d.subtract)] };
  }
  return { unknown: canonicalize(r as JsonValue) };
}

/** A condition parameter's type, generics included. */
function parameterType(raw: unknown): JsonValue {
  const p = (raw ?? {}) as { type_name?: unknown; generic_types?: unknown[] | null };
  return { type_name: stated(p.type_name), generic_types: (p.generic_types ?? []).map(parameterType) };
}

/** A model's condition definitions: key, name, expression and typed parameters, without metadata. */
function conditionsShape(conditions: ModelJson["conditions"]): JsonValue {
  if (conditions === undefined || conditions === null) return [];
  if (typeof conditions !== "object" || Array.isArray(conditions)) return { unknown: canonicalize(conditions as JsonValue) };
  return Object.keys(conditions)
    .sort()
    .map((key) => {
      const c = (conditions[key] ?? {}) as { name?: unknown; expression?: unknown; parameters?: Record<string, unknown> | null };
      const parameters = c.parameters ?? {};
      return {
        key,
        name: stated(c.name),
        expression: stated(c.expression),
        parameters: Object.keys(parameters)
          .sort()
          .map((name) => ({ name, type: parameterType(parameters[name]) })),
      };
    });
}

/**
 * A canonical fingerprint of a model's semantics: the schema version; each
 * type's relations (named in a rewrite or only in metadata), their rewrites
 * with both members of every object relation, and their directly related
 * types with relation, wildcard and condition; and the model's condition
 * definitions. Server-added members (ids, module, source info), proto3
 * empty forms and the order of types, relations, directly related types and
 * conditions do not change it.
 */
export function modelFingerprint(model: ModelJson): string {
  const types = [...(model.type_definitions ?? [])].map((raw) => {
    const t = raw as TypeDefinitionJson;
    const relations = relationNames(t).map((name) => {
      const direct = (t.metadata?.relations?.[name]?.directly_related_user_types ?? []).map(relationReference).sort();
      return { name, rewrite: rewriteShape(t.relations?.[name] ?? undefined), direct };
    });
    return { type: t.type, relations };
  });
  types.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));
  return canonicalize({ schema_version: model.schema_version ?? null, types, conditions: conditionsShape(model.conditions) } as unknown as JsonValue);
}

/**
 * Every condition a model declares and every directly related user type
 * that names one. {@link DOMAIN_MODEL} declares none, and no check sends
 * condition context, so attach refuses a model with any.
 */
function conditionsIn(model: ModelJson): string[] {
  const found: string[] = [];
  const declared = model.conditions;
  if (declared !== undefined && declared !== null) {
    if (typeof declared !== "object" || Array.isArray(declared)) found.push("a conditions member that is not a map");
    else for (const key of Object.keys(declared).sort()) found.push(`condition ${key}`);
  }
  for (const raw of model.type_definitions ?? []) {
    const t = raw as TypeDefinitionJson;
    for (const name of Object.keys(t.metadata?.relations ?? {}).sort()) {
      for (const u of t.metadata?.relations?.[name]?.directly_related_user_types ?? []) {
        const ref = (u ?? {}) as RelationReferenceJson;
        const condition = stated(ref.condition);
        if (condition === null) continue;
        const subject = `${String(ref.type)}${stated(ref.relation) !== null ? `#${String(ref.relation)}` : ""}${ref.wildcard !== undefined && ref.wildcard !== null ? ":*" : ""}`;
        found.push(`${t.type}#${name} admits ${subject} with condition ${typeof condition === "string" ? condition : canonicalize(condition)}`);
      }
    }
  }
  return found;
}

function clientFor(cfg: { apiUrl: string; presharedKey: string; caCertPath?: string; requestTimeoutMs?: number }, storeId?: string): OpenFgaClient {
  if (cfg.caCertPath) {
    // Trust the dev CA for the TLS edge (channel matrix D39).
    process.env.NODE_EXTRA_CA_CERTS = cfg.caCertPath;
  }
  return new OpenFgaClient({
    apiUrl: cfg.apiUrl,
    ...(storeId ? { storeId } : {}),
    credentials: { method: CredentialsMethod.ApiToken, config: { token: cfg.presharedKey } },
    ...(cfg.requestTimeoutMs !== undefined ? { baseOptions: { timeout: cfg.requestTimeoutMs } } : {}),
  });
}

export class Fga {
  private constructor(
    readonly client: OpenFgaClient,
    readonly modelId: string,
    readonly storeId: string,
  ) {}

  /**
   * DEVELOPMENT OPERATION: create a new store and write {@link DOMAIN_MODEL}.
   * The new store holds no tuples, so every stored entitlement check refuses
   * until an administrator grants one ({@link FgaDomainAdmin}). Tests and
   * the development demo call this; a deployment attaches instead.
   */
  static async bootstrap(cfg: {
    apiUrl: string;
    presharedKey: string;
    caCertPath?: string;
    requestTimeoutMs?: number;
  }): Promise<{ fga: Fga; storeId: string; modelId: string }> {
    const store = await clientFor(cfg).createStore({ name: "mission-payments" });
    const client = clientFor(cfg, store.id);
    const model = await client.writeAuthorizationModel(DOMAIN_MODEL as never);
    const modelId = model.authorization_model_id as string;
    return { fga: new Fga(client, modelId, store.id as string), storeId: store.id as string, modelId };
  }

  /**
   * Normal startup: attach to the configured store and model, read the model
   * back and verify it is {@link DOMAIN_MODEL}. Never creates a store or
   * writes a model; a store, model or schema that does not match refuses
   * with {@link FgaAttachError}, and so does a model that declares or uses
   * any condition, named in the refusal. Tuples already in the store, a
   * revocation included, are exactly what the next check reads.
   */
  static async attach(cfg: FgaConfig): Promise<Fga> {
    let client: OpenFgaClient;
    let model: ModelJson | undefined;
    try {
      client = clientFor(cfg, cfg.storeId);
      const read = await client.readAuthorizationModel({ authorizationModelId: cfg.authorizationModelId });
      model = read.authorization_model;
    } catch (e) {
      throw new FgaAttachError(`cannot read model ${cfg.authorizationModelId} in store ${cfg.storeId}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!model) throw new FgaAttachError(`model ${cfg.authorizationModelId} not found in store ${cfg.storeId}`);
    // Named before the fingerprint, so the refusal says which conditions.
    const conditions = conditionsIn(model);
    if (conditions.length > 0) {
      throw new FgaAttachError(
        `model ${cfg.authorizationModelId} uses conditions, which the domain model does not declare and no check supplies context for: ${conditions.join("; ")}`,
      );
    }
    const observed = modelFingerprint(model);
    const expected = modelFingerprint(DOMAIN_MODEL);
    if (observed !== expected) {
      // Both fingerprints, so a mismatch is diagnosable from a log line.
      throw new FgaAttachError(
        `model ${cfg.authorizationModelId} is not the expected domain model (expected ${expected.slice(0, 2000)}, observed ${observed.slice(0, 2000)})`,
      );
    }
    return new Fga(client, cfg.authorizationModelId, cfg.storeId);
  }

  /**
   * Authority check with contextual tuples (D26): mission-scoped tuples are
   * supplied per check, never stored. Higher consistency is used when the
   * caller just wrote substrate (fga-hygiene).
   */
  async checkWithContext(
    check: { user: string; relation: string; object: string },
    contextualTuples: TupleKey[],
    opts: { higherConsistency?: boolean } = {},
  ): Promise<boolean> {
    return getTracer("pdp").startActiveSpan("fga.check", async (span) => {
      span.setAttribute("fga.relation", check.relation);
      span.setAttribute("fga.object", check.object);
      try {
        return await this.doCheck(check, contextualTuples, opts);
      } finally {
        span.end();
      }
    });
  }

  /**
   * Stored-only check (#828): the answer comes from durable tuples alone. The
   * signature takes no contextual tuples, so no Mission-derived tuple can
   * reach it.
   */
  async checkStored(
    check: { user: string; relation: string; object: string },
    opts: { higherConsistency?: boolean } = {},
  ): Promise<boolean> {
    return getTracer("pdp").startActiveSpan("fga.check_stored", async (span) => {
      span.setAttribute("fga.relation", check.relation);
      span.setAttribute("fga.object", check.object);
      try {
        return await this.doCheck(check, [], opts);
      } finally {
        span.end();
      }
    });
  }

  private async doCheck(
    check: { user: string; relation: string; object: string },
    contextualTuples: TupleKey[],
    opts: { higherConsistency?: boolean } = {},
  ): Promise<boolean> {
    const res = await this.client.check(
      {
        user: check.user,
        relation: check.relation,
        object: check.object,
        ...(contextualTuples.length ? { contextualTuples } : {}),
      },
      {
        authorizationModelId: this.modelId,
        consistency: opts.higherConsistency ? "HIGHER_CONSISTENCY" : "MINIMIZE_LATENCY",
      } as never,
    );
    // An omitted `allowed` is the proto3 default, false. Any other non-boolean
    // is not an answer, and throws rather than reading as a refusal.
    if (res.allowed === undefined) return false;
    if (typeof res.allowed !== "boolean") throw new Error("OpenFGA check returned a malformed decision");
    return res.allowed;
  }
}

/** Relations an administrator may write, with the user and object types each admits. */
const ADMIN_RELATIONS: Readonly<Record<string, { user: string; objects: readonly string[] }>> = {
  authorized_reader: { user: "user", objects: ["vendor", "invoice"] },
  authorized_payer: { user: "user", objects: ["vendor", "invoice"] },
  vendor: { user: "vendor", objects: ["invoice"] },
};

/** Refused before any write reaches the store: not a durable domain tuple. */
export class DomainTupleError extends Error {
  constructor(tuple: TupleKey, why: string) {
    super(`not a durable domain tuple (${tuple.user} ${tuple.relation} ${tuple.object}): ${why}`);
    this.name = "DomainTupleError";
  }
}

function typeOf(ref: string): string | undefined {
  const i = ref.indexOf(":");
  return i > 0 && i < ref.length - 1 ? ref.slice(0, i) : undefined;
}

/**
 * A durable domain tuple: a stored entitlement for a `user` principal, or an
 * invoice's owning vendor. Mission-context relations, `mission:` objects and
 * any other shape are refused, so nothing a Mission approval or a token
 * carries can be written as durable policy through this path.
 */
export function assertDomainTuple(tuple: TupleKey): void {
  const rule = ADMIN_RELATIONS[tuple.relation];
  if (!rule) throw new DomainTupleError(tuple, `relation ${tuple.relation} is not administered`);
  if (typeOf(tuple.user) !== rule.user) throw new DomainTupleError(tuple, `user must be a ${rule.user}`);
  const objectType = typeOf(tuple.object);
  if (objectType === undefined || !rule.objects.includes(objectType)) {
    throw new DomainTupleError(tuple, `object must be one of ${rule.objects.join(", ")}`);
  }
  if ((tuple as { condition?: unknown }).condition !== undefined) throw new DomainTupleError(tuple, "conditions are not administered");
}

/**
 * The administrative capability over durable domain tuples: grant, revoke,
 * and move an invoice between vendors. Separate from {@link Fga} so the
 * decision path holds a read-only checker and nothing that writes policy.
 * Every tuple is validated by {@link assertDomainTuple} before any write,
 * and writes are batched under OpenFGA's 100-tuple limit.
 */
export class FgaDomainAdmin {
  constructor(private readonly fga: Pick<Fga, "client" | "modelId">) {}

  async grant(tuples: readonly TupleKey[]): Promise<void> {
    await this.write(tuples, []);
  }

  async revoke(tuples: readonly TupleKey[]): Promise<void> {
    await this.write([], tuples);
  }

  /** Change an invoice's owning vendor in one write: the old ownership tuple and the new one. */
  async moveInvoice(invoiceId: string, fromVendorId: string, toVendorId: string): Promise<void> {
    await this.write(
      [{ user: `vendor:${toVendorId}`, relation: "vendor", object: `invoice:${invoiceId}` }],
      [{ user: `vendor:${fromVendorId}`, relation: "vendor", object: `invoice:${invoiceId}` }],
    );
  }

  private async write(writes: readonly TupleKey[], deletes: readonly TupleKey[]): Promise<void> {
    for (const t of [...writes, ...deletes]) assertDomainTuple(t);
    if (writes.length + deletes.length <= 100) {
      if (writes.length + deletes.length === 0) return;
      await this.fga.client.write(
        { ...(writes.length ? { writes: [...writes] } : {}), ...(deletes.length ? { deletes: [...deletes] } : {}) },
        { authorizationModelId: this.fga.modelId },
      );
      return;
    }
    for (let i = 0; i < writes.length; i += 100) {
      await this.fga.client.write({ writes: writes.slice(i, i + 100) }, { authorizationModelId: this.fga.modelId });
    }
    for (let i = 0; i < deletes.length; i += 100) {
      await this.fga.client.write({ deletes: deletes.slice(i, i + 100) }, { authorizationModelId: this.fga.modelId });
    }
  }
}

export function loadCa(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    readFileSync(path);
    return path;
  } catch {
    return undefined;
  }
}
