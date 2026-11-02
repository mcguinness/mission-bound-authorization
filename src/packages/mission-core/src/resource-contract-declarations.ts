/**
 * @spec runtime#resource-contract, resource-access#resource-contract (#249,
 * D553): a resource's declared contract versions, read from trusted
 * deployment configuration, and the two questions every party asks of them.
 *
 * Runtime: "A resource that adopts resource contracts declares, in its
 * Resource Server runtime profile, each contract version it serves, the
 * operations each covers, the operations that require a reference, and each
 * version's state":
 *
 * - "**current**: resolves for every entry that references it. A new
 *   approval references only a current version."
 * - "**superseded**: resolves only for an entry that already references it,
 *   and only within the retention the profile declares for that version."
 * - "**retired**: resolves for nothing. Its bytes MAY be kept for audit."
 *
 * Resolution ({@link ResourceContractDeclarations.resolve}): "A reference
 * resolves when its version is in a state that resolves for the entry, the
 * contract covers the operation, and the declared contract's `digest` equals
 * the reference's. An unknown or unavailable version, a changed `digest`, a
 * retired version, and a superseded version outside its retention do not
 * resolve." Resolution is always of a reference an entry already carries, so
 * a superseded version resolves within its retention.
 *
 * Approval ({@link ResourceContractDeclarations.forEntry}): Resource Access
 * reads the same declarations as the configuration "which states whether an
 * entry's `resource` requires a reference and which contract version is
 * current for it".
 *
 * Immutability is checked at load: "Published contract bytes MUST remain
 * immutable for a reference." Each declared `digest` is recomputed over the
 * declared document, and a declaration whose document does not hash to its
 * own `digest` is refused, so a changed document cannot be served under the
 * reference it changed.
 *
 * The declarations live in the Enforcement Scope Statement's
 * `extensions.resource_contracts`, the reference-statement representation of
 * the runtime profile items, and every consumer (the authorization server,
 * the PDP, the PEP, the Transaction Authorization Server) reads them from
 * there. A declaration is a reference-statement representation, not a wire
 * member.
 */

import { ACTION_VALUE, resourceWithin } from "./authority-subset.js";
import type { JsonValue } from "./canonicalize.js";
import {
  type EvaluationContextBindingDeclarations,
  type EvaluationContextBindingRef,
  isEvaluationContextBindingRef,
  sameEvaluationContextBinding,
} from "./evaluation-context.js";
import {
  entryMatchesTarget,
  isAbsoluteUri,
  isEnforceablePrefixBase,
  resourceMatchViolation,
} from "./operation-target.js";
import {
  isResourceContractRef,
  type ResourceContractRef,
  resourceContractDigest,
  sameResourceContract,
} from "./resource-contract.js";
import { compareInstants, instantFromMs, parseRfc3339Instant } from "./rfc3339-instant.js";

/** The version states Runtime defines. */
export const RESOURCE_CONTRACT_STATES = ["current", "superseded", "retired"] as const;
export type ResourceContractState = (typeof RESOURCE_CONTRACT_STATES)[number];

/** One declared version of a contract. */
export interface DeclaredContractVersion {
  readonly version: string;
  readonly state: ResourceContractState;
  /** For a superseded version: the RFC 3339 instant its declared retention ends. */
  readonly retained_until?: string;
  readonly digest: string;
  /**
   * The contract document. REQUIRED for a current or superseded version; a
   * retired version MAY keep it for audit.
   */
  readonly document?: JsonValue;
  /** The action identifiers (and any action families) the version covers, from its document. */
  readonly operations: readonly string[];
  /** The Operation Profile version the document names (`operation_profile`). */
  readonly operation_profile?: string;
  /**
   * @spec runtime#resource-contract, runtime#evaluation-context-binding (#249,
   * D1155): for a version whose document names no evaluation-context
   * descriptor, the deployment's explicit association, keyed by the
   * document's operation names: the descriptor each covered operation was
   * performed under while the version was current, declared beside the
   * document and never inside its bytes. {@link contractDescriptor} reads it.
   */
  readonly evaluation_context_descriptors?: Readonly<Record<string, EvaluationContextBindingRef>>;
}

/** One contract a resource serves, with every version it declares. */
export interface ResourceContractDeclaration {
  /** The protected resource the declaration serves, matched as `resource_match` says. */
  readonly resource: string;
  readonly resource_match?: "exact" | "prefix";
  /** The contract's `id`: the absolute URI naming it across its versions. */
  readonly id: string;
  /**
   * The operations (action identifiers) for which the resource requires a
   * reference: each one a current or superseded version defines, never an
   * action family.
   */
  readonly requires_reference: readonly string[];
  readonly versions: readonly DeclaredContractVersion[];
}

/** Why a reference did not resolve. */
export type ResourceContractRefusal =
  | "malformed"
  | "unknown"
  | "resource_not_covered"
  | "retired"
  | "outside_retention"
  | "digest_mismatch"
  | "operation_not_covered";

export type ResourceContractResolution =
  | {
      ok: true;
      ref: ResourceContractRef;
      declaration: ResourceContractDeclaration;
      version: DeclaredContractVersion;
    }
  | { ok: false; reason: ResourceContractRefusal };

/** A declaration fault at load, naming the offending member. */
export class ResourceContractConfigError extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(`${path} ${message}`);
    this.name = "ResourceContractConfigError";
  }
}

function obj(v: unknown, path: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new ResourceContractConfigError(path, "must be an object");
  }
  return v as Record<string, unknown>;
}

function only(o: Record<string, unknown>, members: readonly string[], path: string): void {
  for (const k of Object.keys(o)) {
    if (!members.includes(k))
      throw new ResourceContractConfigError(`${path}.${k}`, "is not a known member");
  }
}

function nonEmpty(v: unknown, path: string): string {
  if (typeof v !== "string" || v.length === 0) {
    throw new ResourceContractConfigError(path, "must be a non-empty string");
  }
  return v;
}

function strings(v: unknown, path: string): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x.length > 0)) {
    throw new ResourceContractConfigError(path, "must be an array of non-empty strings");
  }
  return [...(v as string[])];
}

/**
 * The action identifiers a contract document covers: the `action` of each
 * member of its `operations` object. A document names the Operation Profile
 * version it assembles in `operation_profile`, and its own `id` and `version`,
 * which must be the declaration's.
 */
function readDocument(
  doc: unknown,
  id: string,
  version: string,
  path: string,
): { operations: string[]; operation_profile: string } {
  const d = obj(doc, path);
  if (d.id !== id)
    throw new ResourceContractConfigError(`${path}.id`, "must be the declaration's id");
  if (d.version !== version) {
    throw new ResourceContractConfigError(`${path}.version`, "must be the declared version");
  }
  const operation_profile = nonEmpty(d.operation_profile, `${path}.operation_profile`);
  const ops = obj(d.operations, `${path}.operations`);
  const names = Object.keys(ops);
  if (names.length === 0) {
    throw new ResourceContractConfigError(`${path}.operations`, "must name at least one operation");
  }
  const actions = new Set<string>();
  for (const name of names) {
    const op = obj(ops[name], `${path}.operations.${name}`);
    actions.add(nonEmpty(op.action, `${path}.operations.${name}.action`));
    if (
      op.evaluation_context_descriptor !== undefined &&
      !isEvaluationContextBindingRef(op.evaluation_context_descriptor)
    ) {
      throw new ResourceContractConfigError(
        `${path}.operations.${name}.evaluation_context_descriptor`,
        "must be an evaluation-context descriptor reference {id, version, digest}",
      );
    }
  }
  return { operations: [...actions], operation_profile };
}

/** The document's operations by name, as `{ action, phase, descriptor }`; empty for a version without a document. */
function documentOperations(
  document: JsonValue | undefined,
): Array<{ name: string; action: string; phase: string | undefined; descriptor: unknown }> {
  const ops =
    (document as { operations?: Record<string, Record<string, unknown>> } | undefined)
      ?.operations ?? {};
  return Object.entries(ops).map(([name, op]) => ({
    name,
    action: op.action as string,
    phase: typeof op.phase === "string" ? op.phase : undefined,
    descriptor: op.evaluation_context_descriptor,
  }));
}

/**
 * The deployment's explicit descriptor association for a version
 * (`evaluation_context_descriptors`): an object from the document's operation
 * names to descriptor references, declared only for a current or superseded
 * version whose document names no descriptor itself, so each operation has
 * one source.
 */
function parseAssociation(
  raw: unknown,
  document: JsonValue,
  path: string,
): Record<string, EvaluationContextBindingRef> {
  const a = obj(raw, path);
  const ops = documentOperations(document);
  if (ops.some((o) => o.descriptor !== undefined)) {
    throw new ResourceContractConfigError(
      path,
      "is declared only for a version whose document names no descriptor",
    );
  }
  const out: Record<string, EvaluationContextBindingRef> = {};
  for (const [name, ref] of Object.entries(a)) {
    if (!ops.some((o) => o.name === name)) {
      throw new ResourceContractConfigError(
        `${path}.${name}`,
        "must name an operation the version's document defines",
      );
    }
    if (!isEvaluationContextBindingRef(ref)) {
      throw new ResourceContractConfigError(
        `${path}.${name}`,
        "must be an evaluation-context descriptor reference {id, version, digest}",
      );
    }
    out[name] = { id: ref.id, version: ref.version, digest: ref.digest };
  }
  return out;
}

function parseVersion(raw: unknown, id: string, path: string): DeclaredContractVersion {
  const v = obj(raw, path);
  only(
    v,
    ["version", "state", "retained_until", "digest", "document", "evaluation_context_descriptors"],
    path,
  );
  const version = nonEmpty(v.version, `${path}.version`);
  const state = v.state;
  if (
    typeof state !== "string" ||
    !(RESOURCE_CONTRACT_STATES as readonly string[]).includes(state)
  ) {
    throw new ResourceContractConfigError(
      `${path}.state`,
      `must be one of ${RESOURCE_CONTRACT_STATES.join(", ")}`,
    );
  }
  // A superseded version resolves "only within the retention the profile
  // declares for that version": the retention is stated, never implied.
  if (state === "superseded") {
    if (parseRfc3339Instant(v.retained_until) === undefined) {
      throw new ResourceContractConfigError(
        `${path}.retained_until`,
        "a superseded version declares its retention as an RFC 3339 instant",
      );
    }
  } else if (v.retained_until !== undefined) {
    throw new ResourceContractConfigError(
      `${path}.retained_until`,
      "is declared only for a superseded version",
    );
  }
  const digest = nonEmpty(v.digest, `${path}.digest`);
  if (!isResourceContractRef({ id, version, digest })) {
    throw new ResourceContractConfigError(
      `${path}.digest`,
      "must be sha-256: and an unpadded base64url SHA-256",
    );
  }
  if (v.document === undefined) {
    if (state !== "retired") {
      throw new ResourceContractConfigError(
        `${path}.document`,
        "is required for a current or superseded version",
      );
    }
    if (v.evaluation_context_descriptors !== undefined) {
      throw new ResourceContractConfigError(
        `${path}.evaluation_context_descriptors`,
        "is declared only for a current or superseded version",
      );
    }
    return { version, state, digest, operations: [] };
  }
  const { operations, operation_profile } = readDocument(
    v.document,
    id,
    version,
    `${path}.document`,
  );
  // @spec runtime#resource-contract: "Published contract bytes MUST remain
  // immutable for a reference." The declared digest must commit the declared
  // document; a document changed under an unchanged reference is refused here,
  // at load, never served.
  const computed = resourceContractDigest(v.document as JsonValue);
  if (computed !== digest) {
    throw new ResourceContractConfigError(
      `${path}.digest`,
      `does not commit the declared document (computed ${computed}); a changed contract is a new version with its own digest`,
    );
  }
  const association =
    v.evaluation_context_descriptors === undefined
      ? undefined
      : parseAssociation(
          v.evaluation_context_descriptors,
          v.document as JsonValue,
          `${path}.evaluation_context_descriptors`,
        );
  return {
    version,
    state: state as ResourceContractState,
    ...(state === "superseded" ? { retained_until: v.retained_until as string } : {}),
    digest,
    document: structuredClone(v.document) as JsonValue,
    operations,
    operation_profile,
    ...(association !== undefined ? { evaluation_context_descriptors: association } : {}),
  };
}

/**
 * @spec runtime#resource-contract, runtime#evaluation-context-binding (#249,
 * D1155): the evaluation-context descriptor `version` names for a crossing of
 * `action` (and, for a compound action, `phase`): the document's own
 * `evaluation_context_descriptor` member of every operation performing that
 * crossing, or the deployment's explicit association for each. `undefined`
 * when the version names none for it, or names different descriptors for
 * operations performing the same crossing: a covered crossing under such a
 * version is refused, never captured under the descriptor another version
 * names.
 */
export function contractDescriptor(
  version: DeclaredContractVersion,
  action: string,
  phase: string | undefined,
): EvaluationContextBindingRef | undefined {
  const crossing = documentOperations(version.document).filter(
    (o) => o.action === action && o.phase === phase,
  );
  if (crossing.length === 0) return undefined;
  const named = crossing.map((o) =>
    o.descriptor !== undefined ? o.descriptor : version.evaluation_context_descriptors?.[o.name],
  );
  const [first] = named;
  if (
    !isEvaluationContextBindingRef(first) ||
    !named.every((r) => sameEvaluationContextBinding(r, first))
  )
    return undefined;
  return { id: first.id, version: first.version, digest: first.digest };
}

/**
 * @spec runtime#resource-contract, runtime#evaluation-context-binding (#249,
 * D1155): the load-time guard over the two declarations, so a deployment
 * never ships contract versions whose descriptors disagree with its claim.
 * For every operation of a current or superseded version that the claim
 * covers: the current version names exactly the descriptor the claim
 * declares for it; any version that names one names a descriptor the claim
 * publishes, of the same `id` as the claim's for that crossing, whose
 * document hashes to the reference; and no version names a descriptor for an
 * operation the claim does not cover. A superseded version may name none for
 * a covered operation: that crossing is then refused under it. A descriptor
 * a supported version names cannot leave the claim while that version
 * resolves.
 */
export function assertContractDescriptors(
  contracts: ResourceContractDeclarations,
  binding: EvaluationContextBindingDeclarations,
): void {
  contracts.declarations.forEach((d, di) => {
    d.versions.forEach((v, vi) => {
      if (v.state === "retired") return;
      for (const o of documentOperations(v.document)) {
        const path = `resource_contracts[${di}].versions[${vi}] (${v.version}), operation ${o.name}`;
        const named =
          o.descriptor !== undefined ? o.descriptor : v.evaluation_context_descriptors?.[o.name];
        const declared = binding.claimed ? binding.operation(o.action, o.phase) : undefined;
        if (declared === undefined) {
          if (named !== undefined) {
            throw new ResourceContractConfigError(
              path,
              "names a descriptor for an operation the Evaluation-Context Binding claim does not cover",
            );
          }
          continue;
        }
        if (v.state === "current" && !sameEvaluationContextBinding(named, declared.descriptor)) {
          throw new ResourceContractConfigError(
            path,
            "must name the descriptor the Evaluation-Context Binding claim declares for the operation",
          );
        }
        if (named === undefined) continue;
        if (!isEvaluationContextBindingRef(named) || named.id !== declared.descriptor.id) {
          throw new ResourceContractConfigError(
            path,
            "must name a descriptor of the claim's id for the operation",
          );
        }
        if (!binding.descriptor(named).ok) {
          throw new ResourceContractConfigError(
            path,
            "names a descriptor the claim does not publish under that reference",
          );
        }
      }
    });
  });
}

function parseDeclaration(raw: unknown, path: string): ResourceContractDeclaration {
  const d = obj(raw, path);
  only(d, ["resource", "resource_match", "id", "requires_reference", "versions"], path);
  if (!isAbsoluteUri(d.resource)) {
    throw new ResourceContractConfigError(`${path}.resource`, "must be an absolute URI");
  }
  const resource = d.resource;
  const violation = resourceMatchViolation({ resource, resource_match: d.resource_match });
  if (violation !== undefined)
    throw new ResourceContractConfigError(`${path}.resource_match`, violation);
  if (d.resource_match === "prefix" && !isEnforceablePrefixBase(resource)) {
    throw new ResourceContractConfigError(
      `${path}.resource`,
      "is not a prefix base the matcher can enforce",
    );
  }
  if (!isAbsoluteUri(d.id))
    throw new ResourceContractConfigError(`${path}.id`, "must be an absolute URI");
  const id = d.id;
  const requires_reference = strings(d.requires_reference, `${path}.requires_reference`);
  if (!Array.isArray(d.versions) || d.versions.length === 0) {
    throw new ResourceContractConfigError(`${path}.versions`, "must declare at least one version");
  }
  const versions = d.versions.map((v, i) => parseVersion(v, id, `${path}.versions[${i}]`));
  const seen = new Set<string>();
  for (const v of versions) {
    if (seen.has(v.version)) {
      throw new ResourceContractConfigError(
        `${path}.versions`,
        `declares version ${JSON.stringify(v.version)} twice`,
      );
    }
    seen.add(v.version);
  }
  if (versions.filter((v) => v.state === "current").length > 1) {
    throw new ResourceContractConfigError(
      `${path}.versions`,
      "declares more than one current version",
    );
  }
  // @spec runtime#resource-contract (#1752, D875): "the operations that
  // require a reference" are operations the resource serves. Each value is an
  // action identifier, never an action family, which no reader expands; and
  // some current or superseded version defines it, so a misspelled action is
  // refused here rather than silently requiring nothing. A retired version's
  // operations do not count, and a newer version's operation may be required
  // though an older supported version lacks it.
  const served = new Set(
    versions.filter((v) => v.state !== "retired").flatMap((v) => v.operations),
  );
  requires_reference.forEach((action, i) => {
    const at = `${path}.requires_reference[${i}]`;
    if (action.endsWith(".*")) {
      throw new ResourceContractConfigError(
        at,
        `${JSON.stringify(action)} is an action family; name each action it covers`,
      );
    }
    if (!ACTION_VALUE.test(action)) {
      throw new ResourceContractConfigError(
        at,
        `${JSON.stringify(action)} is not an action identifier`,
      );
    }
    if (!served.has(action)) {
      throw new ResourceContractConfigError(
        at,
        `${JSON.stringify(action)} is not an operation any current or superseded version defines`,
      );
    }
  });
  return {
    resource,
    ...(d.resource_match === "prefix" ? { resource_match: "prefix" as const } : {}),
    id,
    requires_reference,
    versions,
  };
}

/** The reference of one declared version. */
function refOf(
  declaration: ResourceContractDeclaration,
  version: DeclaredContractVersion,
): ResourceContractRef {
  return { id: declaration.id, version: version.version, digest: version.digest };
}

/** What configuration says about one entry at approval. */
export interface EntryContractConfiguration {
  /**
   * The current reference of each declared contract whose resource set
   * contains the entry's and whose current version defines every action and
   * action family the entry lists.
   */
  current: ResourceContractRef[];
  /**
   * Whether configuration requires a reference for the entry's `resource`:
   * some declaration whose resource set contains the entry's requires one
   * for any operation (#1847, D989).
   */
  required: boolean;
}

export class ResourceContractDeclarations {
  /** No declarations: nothing is required and no reference resolves. */
  static readonly NONE = new ResourceContractDeclarations([]);

  readonly declarations: readonly ResourceContractDeclaration[];

  /**
   * Parse and validate `raw`, the `extensions.resource_contracts` array.
   * Throws {@link ResourceContractConfigError} on the first fault.
   */
  constructor(raw: unknown) {
    if (!Array.isArray(raw))
      throw new ResourceContractConfigError("resource_contracts", "must be an array");
    const parsed = raw.map((d, i) => parseDeclaration(d, `resource_contracts[${i}]`));
    const ids = new Set<string>();
    for (const d of parsed) {
      if (ids.has(d.id)) {
        throw new ResourceContractConfigError(
          "resource_contracts",
          `declares contract ${d.id} twice`,
        );
      }
      ids.add(d.id);
    }
    this.declarations = Object.freeze(parsed);
  }

  /**
   * @spec runtime#resource-contract: resolve `ref` for `action` at the
   * operation target `target` at `now`. Exact: the declared version named by
   * `ref.version` under `ref.id`, never a newer or equivalent one.
   */
  resolve(
    ref: unknown,
    at: { target: string; action: string; now: Date },
  ): ResourceContractResolution {
    if (!isResourceContractRef(ref)) return { ok: false, reason: "malformed" };
    const named = this.declarations.filter((d) => d.id === ref.id);
    if (named.length === 0) return { ok: false, reason: "unknown" };
    const declaration = named.find((d) => entryMatchesTarget(d, at.target));
    if (declaration === undefined) return { ok: false, reason: "resource_not_covered" };
    const version = declaration.versions.find((v) => v.version === ref.version);
    if (version === undefined) return { ok: false, reason: "unknown" };
    if (version.state === "retired") return { ok: false, reason: "retired" };
    if (version.state === "superseded") {
      const until = parseRfc3339Instant(version.retained_until);
      if (until === undefined || compareInstants(instantFromMs(at.now.getTime()), until) > 0) {
        return { ok: false, reason: "outside_retention" };
      }
    }
    if (version.digest !== ref.digest) return { ok: false, reason: "digest_mismatch" };
    if (!version.operations.includes(at.action))
      return { ok: false, reason: "operation_not_covered" };
    return { ok: true, ref: refOf(declaration, version), declaration, version };
  }

  /**
   * @spec runtime#resource-contract: whether the resource requires a
   * reference for `action` at `target` ("the resource requires a reference
   * for the operation").
   */
  requiresReference(target: string, action: string): boolean {
    return this.declarations.some(
      (d) => entryMatchesTarget(d, target) && d.requires_reference.includes(action),
    );
  }

  /**
   * The declared version `ref` names, by `id` and `version` only, whatever its
   * state or digest: the lookup that finds the Operation Profile a reference
   * names before the operation's target is known. Resolution
   * ({@link resolve}) still decides whether it may be used.
   */
  versionOf(
    ref: unknown,
  ): { declaration: ResourceContractDeclaration; version: DeclaredContractVersion } | undefined {
    if (!isResourceContractRef(ref)) return undefined;
    for (const declaration of this.declarations) {
      if (declaration.id !== ref.id) continue;
      const version = declaration.versions.find((v) => v.version === ref.version);
      if (version) return { declaration, version };
    }
    return undefined;
  }

  /**
   * @spec resource-access#resource-contract: what configuration states for
   * an entry at approval: the current references that may stand for it, and
   * whether it requires one. A declaration applies when its resource set
   * contains the entry's (the subset rule's resource step, `resourceWithin`).
   */
  forEntry(entry: {
    resource: unknown;
    resource_match?: unknown;
    actions: readonly string[];
  }): EntryContractConfiguration {
    const applicable = this.declarations.filter((d) => resourceWithin(entry, d));
    // @spec resource-access#resource-contract (#1847, D989): the approval
    // rule is per resource: configuration "states whether an entry's
    // `resource` requires a reference", so an entry on a resource that
    // requires one for any operation records it, a read-only entry
    // included. Enforcement stays per operation ({@link requiresReference}).
    const required = applicable.some((d) => d.requires_reference.length > 0);
    const current: ResourceContractRef[] = [];
    for (const d of applicable) {
      const v = d.versions.find((x) => x.state === "current");
      if (v && entry.actions.every((a) => v.operations.includes(a))) current.push(refOf(d, v));
    }
    return { current, required };
  }

  /**
   * @spec resource-access#resource-contract: the violation for an entry
   * carried from an earlier approval (a delegation, a child, a template or
   * successor re-derivation), or undefined. The reference is preserved, not
   * re-assembled, so a superseded version within its retention stands; an
   * unknown, retired, changed or out-of-retention reference, or one whose
   * version does not define every action the entry lists, is refused: "a
   * reference that does not resolve there authorizes nothing."
   */
  carriedViolation(
    entry: {
      resource: unknown;
      resource_match?: unknown;
      actions: readonly string[];
      resource_contract?: unknown;
    },
    now: Date,
  ): string | undefined {
    const ref = entry.resource_contract;
    if (ref === undefined) return undefined;
    if (!isResourceContractRef(ref)) return "resource_contract is malformed";
    const declaration = this.declarations.find((d) => d.id === ref.id && resourceWithin(entry, d));
    const version = declaration?.versions.find((v) => v.version === ref.version);
    if (!declaration || !version)
      return "resource_contract names no contract version configured for the entry's resource";
    if (version.state === "retired") return "resource_contract names a retired version";
    if (version.state === "superseded") {
      const until = parseRfc3339Instant(version.retained_until);
      if (until === undefined || compareInstants(instantFromMs(now.getTime()), until) > 0) {
        return "resource_contract names a superseded version outside its retention";
      }
    }
    if (version.digest !== ref.digest)
      return "resource_contract digest is not the declared version's";
    if (!entry.actions.every((a) => version.operations.includes(a))) {
      return "resource_contract does not define every action the entry lists";
    }
    return undefined;
  }

  /** Whether `ref` equals the current reference configuration names for the entry. */
  isCurrentFor(
    entry: { resource: unknown; resource_match?: unknown; actions: readonly string[] },
    ref: unknown,
  ): boolean {
    return this.forEntry(entry).current.some((c) => sameResourceContract(c, ref));
  }
}
