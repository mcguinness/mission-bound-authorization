/**
 * The payments resource side of a composition: the payments store, the PDP
 * with its claim domain and evidence, the PEP and its stores, the MCP server,
 * the outcome reconciler and the HTTP channels, assembled from what the
 * composition supplies. `composeStack` supplies an authorization server it
 * runs in process and the Mission state its kernel holds.
 */

import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { exportJWK, generateKeyPair } from "jose";
import {
  ACTION_APPROVAL_POLICY,
  AUDIT_HORIZON_SECONDS,
  keyedRecordFrom,
  type MasJoinPolicy,
  RUNTIME_SCOPE_CONFIG,
  scopeMappingEntries,
  TOPOLOGY,
} from "@mission/demo-data";
import { type DurableEvidenceKey, evidenceKeyBundle } from "./evidence-key-files.js";
import {
  type AuthorityEntry as PdpAuthorityEntry,
  type BoundaryEvidenceKey,
  buildBoundaryEvidenceKeyResolver,
  createDecisionPoint,
  createDecisionChannel,
  createPdpRefusalRecorder,
  evidenceKeyConsumer,
  type DecisionFn,
  type IdempotencyClaimDomain,
  loadRuntimePosture,
  openIdempotencyClaimDomain,
  type RuntimePosture,
  stalenessBound,
  stateSourcePlacement,
  type Fga,
  fgaResourcePolicy,
  issuerLocalClients,
  issuerLocalPrincipals,
  relationForAction,
} from "@mission/pdp";
import {
  ActorRecords,
  boundaryEvidenceAuthorization,
  budgetOverspendAlert,
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createHttpMcpChannel,
  deploymentReceiptIssuerScope,
  deploymentRetentionWindowSeconds,
  EVIDENCE_KEY_SET_LOCATION,
  evidenceKeySetLocation,
  EvidenceRetentionStore,
  openEvidenceRetentionStore,
  type EvidenceSigningConfig,
  EvidenceStore,
  type EvidenceVerificationKey,
  type HttpMcpChannel,
  heldReservationAlert,
  indeterminateClaimAlert,
  type KeyRoles,
  type LoadedView,
  McpPaymentsServer,
  type MissionReference,
  type MissionViewSource,
  OutcomeReconciler,
  PaymentsStore,
  paymentsBoundaryContext,
  Pep,
  type PepDeps,
  type ReceiptIssuerScope,
  redemptionStatusFor,
  releasedReservationNotice,
  settlementConflictAlert,
  stderrAlertSink,
  type TokenFacts,
  TransactionEngine,
  openWriteReservationStore,
  type WriteReservationStore,
} from "@mission/mcp-payments";
import { seedDevelopmentResourcePolicy } from "./resource-policy-store.js";

/**
 * @spec authority-server#mission-join, runtime-oauth#boundary-audience
 * (#1531, D741): `statement` with the MAS Join route's resource identifier
 * declared as an audience alias of the payments boundary, accepted only from
 * `issuer` for the `at+jwt` token profile, in every boundary version. Absent
 * `join`, the statement is unchanged.
 */
function withJoinAudienceAlias(statement: RuntimePosture, join: { issuer: string; alias: string } | undefined): RuntimePosture {
  const declared = statement.enforcement_boundaries;
  if (!join || !declared) return statement;
  const alias = { issuer: join.issuer, token_profile: "at+jwt", alias: join.alias };
  return {
    ...statement,
    enforcement_boundaries: {
      ...declared,
      versions: declared.versions.map((version) => ({
        ...version,
        boundaries: version.boundaries.map((b) =>
          b.boundary === CANONICAL_RESOURCE ? { ...b, audience_aliases: [...(b.audience_aliases ?? []), alias] } : b,
        ),
      })),
    },
  };
}

/**
 * @spec runtime#mission-binding (#956, D814): `statement` declaring exactly the
 * Mission-establishment modes this stack serves for the payments scope. The
 * credential-carried mode is always served; the externally established mode
 * only where the MAS-governed channel's baseline Join governs the payments
 * resource. Declaring both creates no fallback: the MAS profile's precedence
 * still lets a credential-carried reference govern. The AS-native target,
 * which excludes the MAS, therefore declares `credential_carried` only.
 */
export function withServedEstablishmentModes(statement: RuntimePosture, servesExternal: boolean): RuntimePosture {
  return {
    ...statement,
    mediated_scope: {
      ...statement.mediated_scope,
      mission_establishment_mode: servesExternal ? ["credential_carried", "externally_established"] : "credential_carried",
    },
  };
}

/** What a composition supplies to its payments resource side. */
export interface PaymentsResourceContext {
  /** The composition's own store files, as `composeStack` names them. */
  opts: { claimsFile?: string; writeReservationsFile?: string; evidenceRetentionFile?: string };
  durableEvidence: { pep: DurableEvidenceKey[]; pdp: DurableEvidenceKey[] } | undefined;
  baseStatement: RuntimePosture;
  masJoin: MasJoinPolicy;
  masGovernedResources: readonly string[];
  /** The Mission issuer this resource's tokens come from. */
  issuer: string;
  conn: { fga: Fga; modelId: string; development: boolean; storeId: string };
  mode: "co-resident" | "remote";
  /** The authorization server as this resource knows it. */
  as: {
    jwksUri: string | undefined;
    jwks: { keys: Record<string, unknown>[] };
    keyRoles: KeyRoles;
    challengeSigner: PepDeps["challengeSigner"];
    asIssuer: string | undefined;
    txnChallenge: NonNullable<ConstructorParameters<typeof McpPaymentsServer>[0]["txnChallenge"]> | undefined;
  };
  /** The PEP's Mission view read. */
  loadView: (ref: MissionReference) => LoadedView | undefined;
  /**
   * The remote read the PEP awaits at the start of each enforcement, where
   * Mission state is reached over a network (#1101); `loadView` then answers
   * from it. Absent: `loadView` reads in process.
   */
  viewSource?: MissionViewSource;
  /**
   * Wraps the decision the PEP calls: where the PDP owns the state source,
   * its own read for every decision (`ownReadDecide`, #1101). Absent: the
   * decision channel's own.
   */
  decide?: (inner: DecisionFn) => DecisionFn;
  /**
   * Each Mission's budget binding, derived on the PDP side. Absent: the
   * decision point has no source, so a view carrying a binding is one it
   * cannot derive, never metered.
   */
  budgetBindings?: NonNullable<Parameters<typeof createDecisionPoint>[0]["budgetBindings"]>;
  /** Serve the HTTP MCP transport at the declared resource audience (D315). */
  serveAudience: boolean;
  /** What a failed audience startup releases besides the resource side, in this order around it. */
  release: { closeAuthServer: () => Promise<void>; closeOwnedStores: () => void };
}

/** The assembled resource side. */
export interface PaymentsResource {
  payments: PaymentsStore;
  pdpClaims: IdempotencyClaimDomain;
  writeReservations: WriteReservationStore;
  evidenceRetention: EvidenceRetentionStore;
  evidenceKeySets: EvidenceRetentionStore;
  receiptIssuerScope: ReceiptIssuerScope | undefined;
  evidence: EvidenceStore;
  egressEvidence: EvidenceStore;
  connectors: Connectors;
  revokedInstances: Set<string>;
  actorRecords: ActorRecords;
  decisionChannel: Awaited<ReturnType<typeof createDecisionChannel>>;
  pep: Pep;
  server: McpPaymentsServer;
  reconciler: OutcomeReconciler;
  masGovernedChannel: HttpMcpChannel | undefined;
  resourceChannel: HttpMcpChannel | undefined;
  /** Install the PEP's observer. */
  onEnforce: (fn: PepDeps["observe"]) => void;
}

export async function assemblePaymentsResource(ctx: PaymentsResourceContext): Promise<PaymentsResource> {
  const { opts, durableEvidence, baseStatement, masJoin, masGovernedResources, issuer, conn, mode, loadView } = ctx;
  const { fga, modelId } = conn;
  const {
    jwksUri: serverJwksUri,
    jwks: serverJwks,
    keyRoles: rsKeyRoles,
    challengeSigner,
    asIssuer: rsAsIssuer,
    txnChallenge: txnChallengePublication,
  } = ctx.as;

  const payments = new PaymentsStore();
  payments.seed(
    [
      { id: "acme", name: "Acme Corp", status: "approved" },
      { id: "globex", name: "Globex", status: "pending" },
    ],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
      { id: "inv-3", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex-001", status: "payable" },
      { id: "inv-seed", vendor_id: "acme", amount: "75.00", currency: "USD", payee_account: "acct-acme-001", status: "payable" },
    ],
  );

  // @spec runtime-evidence#decision-evidence-integrity (issue #649, #741): a
  // fresh, per-process ES256 signer per emitter role: fine for this demo
  // stack (nothing outside this process ever needs to verify a record it
  // signs), NOT a substitute for a deployment's own published, durable JWKS.
  //
  // The PDP's Decision Evidence key is its OWN (#741): a distinct kid, static
  // in config with the key generated per boot (D25), never the `pdpEvidence`
  // kid the transparency producer Statements already spend. The runtime
  // profile forbids inferring one key plane's isolation from custody of
  // another, so the two planes do not share a kid. `emitterId`/`audience` are
  // this deployment's real values, so the verifier's key-to-emitter and
  // key-to-audience binding is checked against what the records actually
  // carry rather than a placeholder.
  const decisionEvidenceKey = TOPOLOGY.keys.pdpDecisionEvidence;
  // @spec #831 (scope inventory): with durable evidence key files (loaded
  // first, by the composition), each holder's keys are the same at every
  // boot; without them, generated now.
  const decisionEvidenceKeys = durableEvidence
    ? (durableEvidence.pdp[0] as DurableEvidenceKey)
    : await generateKeyPair(decisionEvidenceKey.alg, { extractable: true });
  // The decision point owns the emission path (#741, PR #753 review): the
  // emitter is constructed inside `createDecisionPoint` and closed over by
  // `decide`. This wiring, and the PEP it wires, hold the decision function
  // and the published verification material, and nothing that can emit.
  const evidenceKeys: { signing: EvidenceSigningConfig; verification: EvidenceVerificationKey[] } = durableEvidence
    ? evidenceKeyBundle(durableEvidence.pep, CANONICAL_RESOURCE, CANONICAL_RESOURCE)
    : createEphemeralEvidenceKeys();
  // @spec runtime#runtime-conformance (#853, D487): the one declared boundary
  // context every producer here reads: the PEP establishes its boundary from
  // it, and the PDP's Decision Evidence and Refusal Records and the PEP's own
  // records sign only for a boundary it authorizes their emitter for, so all
  // of them switch together at a declared cutover.
  // @spec authority-server#mission-join, mission#authority-proposal (#1531,
  // D741): the MAS Join route is served under its own resource identifier
  // (`join_resource`), which is not Mission-governed, so the AS mints the
  // join's ordinary credential for that audience and never for the payments
  // resource. Where the route mounts, the payments boundary accepts that
  // identifier as an audience alias scoped to this issuer and the `at+jwt`
  // token profile (runtime-oauth#boundary-audience), declared in the
  // statement every consumer here reads and the resource publishes.
  const statement = withServedEstablishmentModes(
    withJoinAudienceAlias(
      baseStatement,
      masGovernedResources.includes(CANONICAL_RESOURCE) ? { issuer, alias: masJoin.join_resource } : undefined,
    ),
    masGovernedResources.includes(CANONICAL_RESOURCE),
  );
  const boundary = paymentsBoundaryContext(statement);
  const pdpBoundary = (): string | undefined => {
    const established = boundary.establish();
    return established.ok ? established.boundary : undefined;
  };
  // @spec runtime#idempotency (#917, D223): the PDP's Exact claim domain, a
  // durable single-writer SQLite file named in configuration and owned by the
  // statement's one PDP. It verifies settlement against exactly the
  // enforcement keys this PEP signs Execution Evidence with. A file another
  // process holds, or a statement it cannot run, refuses the stack at boot.
  const claimsFile = opts.claimsFile ?? TOPOLOGY.stores.pdpIdempotencyClaims.file;
  mkdirSync(dirname(claimsFile), { recursive: true });
  // @spec runtime#evidence (outcome reconciliation) (#1103): the declared
  // alerting obligation, one JSON line on stderr per alert. A claim that
  // closes indeterminate alerts where the claim domain moves it, after the
  // move commits, so a prior process's claim alerts too.
  const operatorAlerts = stderrAlertSink();
  // @spec runtime#boundary-identifier-change (#853 review): settlement
  // verifies Execution Evidence under the declared versions, by the record's
  // (audience, kid) pair, so a record produced under an earlier version still
  // settles after a change and one under the new version settles once its
  // key is held. Its readiness for each version is bound below.
  const settlementKeys: BoundaryEvidenceKey[] = evidenceKeys.verification.flatMap((k) =>
    k.role === "pep" || k.role === "executor"
      ? [{ kid: k.kid, publicKey: k.publicKey, emitterId: k.emitterId, role: k.role }]
      : [],
  );
  const pdpClaims = openIdempotencyClaimDomain({
    file: claimsFile,
    owner: statement.pdps[0] as string,
    statement,
    settlementKeys: buildBoundaryEvidenceKeyResolver(boundary.declaration, settlementKeys),
    onIndeterminate: (claim) => operatorAlerts.alert(indeterminateClaimAlert(claim)),
    // @spec metering#settlement-states (#816, D830 rulings 7 and 10): a
    // budget reservation the domain holds stays charged until an operator
    // reconciles it, and a late completed settlement that pushes a counter
    // past its limit commits anyway: both raise the declared alert, after the
    // move commits, a prior process's reservation included.
    onReservationHeld: (reservation) => operatorAlerts.alert(heldReservationAlert(reservation)),
    onBudgetOverspend: (overspend) => operatorAlerts.alert(budgetOverspendAlert(overspend)),
    // #813: and a held reservation later released resolves its alert.
    onReservationReleased: (released) => operatorAlerts.alert(releasedReservationNotice(released)),
    // @spec metering#settlement-contract "Conflicting redelivery" (#816,
    // D877): a settlement that conflicts with the applied one is retained by
    // the domain and surfaced on the same alarm path.
    onSettlementConflict: (conflict) => operatorAlerts.alert(settlementConflictAlert(conflict)),
  });
  // @spec runtime#boundary-identifier-change step 1 (#853 review): the
  // consumers whose bindings are provisioned outside the statement. Until
  // each is provisioned for the version in force, the boundary is not
  // established and every request refuses (`boundary_unprovisioned`): the
  // settlement verifier holds a key for every enforcement key the version
  // authorizes, and the claim domain's own statement declares the version.
  boundary.bindConsumer(
    evidenceKeyConsumer({ name: "pdp-settlement-keys", roles: ["pep", "executor"], audienceBound: false, keys: () => settlementKeys }),
  );
  boundary.bindConsumer(pdpClaims.boundaryConsumer());
  // @spec runtime#input-resource-policy (#828): the independently
  // administered Resource policy, stored OpenFGA entitlements read with no
  // Mission input, for principals authenticated under this stack's issuer.
  // A development store is seeded here, after the payments store it takes
  // invoice ownership from; an attached store is used as it stands.
  if (conn.development) {
    await seedDevelopmentResourcePolicy(fga, issuer, payments.listInvoices());
    console.log(`development Resource-policy store ${conn.storeId} model ${conn.modelId} (set OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach)`);
  }
  const decisionPoint = createDecisionPoint({
    evidence: {
      signer: { kid: decisionEvidenceKey.kid, key: decisionEvidenceKeys.privateKey },
      verificationKey: decisionEvidenceKeys.publicKey,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
      authorizesAudience: (audience) =>
        boundary.authorizesEvidence({ audience, kid: decisionEvidenceKey.kid, emitter: CANONICAL_RESOURCE, role: "pdp" }, "current"),
      // @spec runtime-evidence#decision-evidence-object, runtime#record-integrity
      // (#821, D814): the per-Mission Decision Evidence counters live in the
      // PDP's own durable claim file, so a restarted PDP continues each
      // stream rather than re-issuing a sequence a retained record carries.
      sequences: pdpClaims.evidenceSequences(),
    },
    claims: pdpClaims,
    // @spec metering#metering, mission-template#standing-payment-exception
    // (#813, #816, decision d): each Mission's budget binding, as the
    // composition derives it on the PDP side. The PEP's view is never
    // consulted for it.
    ...(ctx.budgetBindings ? { budgetBindings: ctx.budgetBindings } : {}),
    resourcePolicy: fgaResourcePolicy(fga, { principals: issuerLocalPrincipals(issuer), clients: issuerLocalClients(issuer) }),
    // @spec authzen#pdp-request consistency check 11 (#1276, D457): a request
    // refused before evaluation (`operation_target_invalid`) is recorded as a
    // PDP Refusal Record, signed under the PDP's own published key and
    // retained in the deployment's evidence retention store (declared below;
    // a refusal arrives only once the stack serves requests).
    refusals: createPdpRefusalRecorder({
      signer: { kid: decisionEvidenceKey.kid, key: decisionEvidenceKeys.privateKey },
      emitterId: CANONICAL_RESOURCE,
      scope: (requested) => (requested !== undefined && requested === pdpBoundary() ? requested : undefined),
      retain: (record) => {
        const missionId = "unknown";
        evidenceRetention.retain({
          kind: "refusal",
          record_id: record.refusal_id,
          mission_id: missionId,
          emitter_id: record.emitter.id,
          emitter_role: "pdp",
          signing_kid: decisionEvidenceKey.kid,
          row: { kind: "refusal", mission_id: missionId, at: record.evaluated_at, content: record } as never,
          record: record as never,
        });
      },
    }),
  });
  // @spec runtime#idempotency (#918, D223): the PEP's own durable,
  // single-writer reservation store for keyed reversible writes, named in
  // configuration and owned by the statement's PEP location. The server
  // refuses it at construction unless the statement publishes it as the
  // domain of every keyed reversible write.
  const writeReservationsFile = opts.writeReservationsFile ?? TOPOLOGY.stores.pepWriteReservations.file;
  mkdirSync(dirname(writeReservationsFile), { recursive: true });
  const writeReservations = openWriteReservationStore({
    file: writeReservationsFile,
    owner: statement.mediated_scope.pep_locations[0] as string,
  });
  // @spec runtime-evidence#execution-evidence-object (Retention),
  // runtime#record-integrity (#594 W4-8, #821, D814): this deployment's
  // durable retention store, a single-writer SQLite file named in
  // configuration and owned by the statement's PEP location. Every record the
  // PEP retains and every sequence it allocates is written through it, so a
  // restart keeps them and continues each emitter's stream. The window is the
  // retention floor the runtime profile puts under every runtime-enforced
  // deployment: the Mission audit horizon, since this deployment's statement
  // claims no evidence capability and so declares no longer window of its own.
  const retentionWindowSeconds = deploymentRetentionWindowSeconds(RUNTIME_SCOPE_CONFIG, AUDIT_HORIZON_SECONDS);
  const evidenceRetentionFile =
    opts.evidenceRetentionFile ??
    (opts.writeReservationsFile
      ? join(dirname(opts.writeReservationsFile), "pep-evidence-retention.sqlite")
      : TOPOLOGY.stores.pepEvidenceRetention.file);
  mkdirSync(dirname(evidenceRetentionFile), { recursive: true });
  const evidenceRetention = openEvidenceRetentionStore({
    file: evidenceRetentionFile,
    owner: statement.mediated_scope.pep_locations[0] as string,
    retentionWindowSeconds,
  });
  // @spec runtime-evidence#evidence-integrity-signing-keys (#821, #831): the
  // key sets this boot publishes, in a store of their own, so a key's
  // retirement anchor is not moved by the records retained in the other.
  // A published kid is append-only. With durable evidence keys the store is
  // a file beside the retention file: each boot republishes the same keys,
  // a no-op, and a lost or regenerated key file is refused here rather than
  // stranding the records the old key signed. With keys generated per boot it
  // stays in memory, since a durable set would refuse the next boot's key
  // under the same kid, and a record an earlier boot signed does not verify
  // after a restart.
  const evidenceKeySets = durableEvidence
    ? openEvidenceRetentionStore({
        file: join(dirname(evidenceRetentionFile), "pep-evidence-key-sets.sqlite"),
        owner: statement.mediated_scope.pep_locations[0] as string,
        retentionWindowSeconds,
      })
    : new EvidenceRetentionStore({ retentionWindowSeconds });
  const heldKeys = [
    ...evidenceKeys.verification.filter((k) => k.role !== "pdp"),
    { ...decisionPoint.evidenceVerification, role: "pdp" as const },
  ];
  for (const key of heldKeys) {
    evidenceKeySets.publishKey({
      location: EVIDENCE_KEY_SET_LOCATION,
      kid: key.kid,
      emitterId: key.emitterId,
      role: key.role,
      ...(key.audience !== undefined ? { audience: key.audience } : {}),
      // A published set carries JWKs; the PDP's own verification key is a
      // WebCrypto key, so it is exported here rather than at publication.
      publicKey: await exportJWK(key.publicKey as Parameters<typeof exportJWK>[0]),
    });
  }
  // @spec runtime#boundary-identifier-change (#853 review): every key this
  // deployment holds is also published, at each declared boundary's own
  // key-set location, bound to that boundary, for every version that
  // authorizes it, so the key set is provisioned for a declared change
  // before its cutover and keeps the earlier boundary's set. A version that
  // authorizes a key this deployment does not hold leaves that boundary's
  // set unprovisioned, and the consumer bound below holds the cutover.
  for (const version of boundary.declaration.versions) {
    for (const declared of version.boundaries) {
      for (const authorized of declared.evidence_keys) {
        const key = heldKeys.find((k) => k.kid === authorized.kid && k.emitterId === authorized.emitter && k.role === authorized.role);
        if (!key) continue;
        evidenceKeySets.publishKey({
          location: evidenceKeySetLocation(declared.boundary),
          kid: key.kid,
          emitterId: key.emitterId,
          role: key.role,
          audience: declared.boundary,
          publicKey: await exportJWK(key.publicKey as Parameters<typeof exportJWK>[0]),
        });
      }
    }
  }
  boundary.bindConsumer(
    evidenceKeyConsumer({
      name: "published-evidence-keys",
      roles: ["pdp", "pep", "executor"],
      audienceBound: true,
      keys: (declared) => evidenceKeySets.publishedVerificationKeys(evidenceKeySetLocation(declared)),
    }),
  );
  // @spec runtime-evidence#decision-evidence-integrity (#853, D487): the
  // PEP verifies the PDP's Decision Evidence under the declared statement
  // versions, by the record's (audience, kid) pair, against exactly what the
  // decision point publishes for the records it emits. The executor's own
  // key is held there too (#252): a compensation links the committed effect
  // it offsets only after re-verifying that effect's retained Execution
  // Evidence, and an unverifiable record links nothing.
  const evidence = new EvidenceStore(
    evidenceKeys.signing,
    buildBoundaryEvidenceKeyResolver(boundary.declaration, [
      {
        kid: decisionPoint.evidenceVerification.kid,
        publicKey: decisionPoint.evidenceVerification.publicKey,
        emitterId: decisionPoint.evidenceVerification.emitterId,
        role: "pdp",
      },
      ...evidenceKeys.verification
        .filter((k) => k.role === "executor")
        .map((k) => ({ kid: k.kid, publicKey: k.publicKey, emitterId: k.emitterId, role: "executor" as const })),
    ]),
    evidenceRetention,
    boundaryEvidenceAuthorization(boundary),
  );
  // @spec runtime#runtime-conformance — the deployment's own receipt-issuer
  // designation, over the key sets above and the locations its own statement
  // declares. `undefined` here, and that is the point: config/enforcement-scope.json
  // claims no evidence capability, so this deployment designates no receipt
  // issuer and receipt verification is unreachable for it. Switching the claim
  // on is a deployment assertion, gated on the producer and consumer duties
  // #594's W4-3/W4-4/W4-16 still own.
  const receiptIssuerScope = deploymentReceiptIssuerScope(RUNTIME_SCOPE_CONFIG, evidenceKeySets);
  // The egress gate's OWN store (D32); the agent run's EgressGate writes here.
  // Egress stays on the pre-existing unsigned path (issue #649's deferred slice B).
  const egressEvidence = new EvidenceStore();
  const connectors = new Connectors();
  const revokedInstances = new Set<string>();
  // @spec authority-server#mission-join rule 5 (#557) — the deployment's own
  // actor records. Nothing seeds it: a delegate joins only once this
  // deployment has recorded the edge, which is what makes an unrecorded
  // delegate fail closed rather than join on a declared ceiling alone.
  const actorRecords = new ActorRecords();



  /**
   * @spec authority-server#mission-join rule 8, bound 1 (#557) — the acting
   * credential's OWN authority, read from the token AS ISSUED: its verified
   * `scope` claim, mapped through the deployment's `scope_actions` to entries
   * on this resource. Client registration is deliberately not consulted; the
   * bound is what the presented credential carries, so a narrower token
   * yields a narrower permit even for the same client. A credential with no
   * scope, or a scope this deployment maps to nothing, resolves to no
   * authority, and the joined route then refuses `out_of_authority` rather
   * than treating an unmapped scope as unbounded.
   */
  // @spec resource-access#resource-contract (#1847, D989): one entry per
  // contract a scope value states, the values stating none in their own.
  const resolveOrdinaryAuthority = (token: TokenFacts): PdpAuthorityEntry[] | undefined => {
    if (token.mission || !token.scope) return undefined;
    return scopeMappingEntries(
      token.scope.split(/\s+/),
      { actions: masJoin.scope_actions, contracts: masJoin.scope_contracts ?? {} },
      CANONICAL_RESOURCE,
    );
  };

  const runtimeDecisionPolicy = {
    // @spec runtime#action-approval (#813): the one declaration the AS's
    // standing-payment consent disclosure also reads.
    requiresActionApproval: (action: string) => ACTION_APPROVAL_POLICY.actions.includes(action),
    maxApprovalAgeSeconds: TOPOLOGY.ttls.maxApprovalAgeSeconds,
    stateSourcePlacement: stateSourcePlacement(statement),
    delegatePolicy: {
      delegates: keyedRecordFrom(Object.entries(masJoin.delegates).map(([id, d]) => [id, { maxDepth: d.max_depth }] as const)),
    },
  };
  // D28: the PEP owns redemption. Its store's epoch is the requester epoch
  // the channel binds, and its read-only answer is retransmission condition 6.
  const engine = new TransactionEngine("demo-epoch");
  const redemption = redemptionStatusFor(engine);
  const pepId = "mcp-payments-pep";
  const decisionChannel = await createDecisionChannel(decisionPoint, {
    mode, pepId, audience: CANONICAL_RESOURCE,
    // @spec runtime#boundary-identifier (#853, D487): the PDP accepts a
    // boundary identifier only from a PEP authorized for it, read from the
    // version in force on every request.
    scopes: () => {
      const established = pdpBoundary();
      return established !== undefined ? [established] : [];
    },
    // @spec runtime#boundary-identifier-change (#853 review): settlement and
    // reconciliation are scoped to the boundary in force too, never to a
    // configured audience a cutover would leave behind.
    claimAudience: pdpBoundary,
    // @spec resource-access#resource-matching (#1276, D457), runtime#boundary-
    // identifier-change (#853 review): the one target the payments operation
    // contracts establish, the service CANONICAL_RESOURCE names, registered
    // apart from the boundary: a change of boundary identifier does not move
    // the operation target, so it stays in scope across the cutover.
    operationTargets: [CANONICAL_RESOURCE],
    pepEpoch: redemption.epoch,
    consumptionStatus: redemption.status,
    redeemingExecution: redemption.redeemer,
    getOptions: (request) => {
      const ref = request.context.mission;
      const loaded = ref ? loadView(ref) : undefined;
      if (!loaded) throw new Error("PDP cannot establish the Mission view");
      // @spec authzen#pdp-request rule 1: the PDP side's own read, the one a
      // `pdp` placement relies on; under the published `pep` placement the
      // PEP's observation is relied on instead.
      return {
        view: loaded.view,
        stateObservedAt: loaded.observation.freshness_at,
        fga,
        modelId,
        now: () => new Date(),
        stalenessBound,
        relationForAction,
        ...runtimeDecisionPolicy,
      };
    },
  });
  const enforcementScopeStatement = loadRuntimePosture({ ...statement, remote_decision_channels: decisionChannel.remoteDecisionChannels });
  let observer: PepDeps["observe"];
  const pep = new Pep({
    payments,
    evidence,
    // @spec runtime#compound-actions (#252): a compensation reads the
    // committed wire's own ledger record for the parameters it offsets.
    committedEffects: connectors,
    boundary,
    decide: ctx.decide ? ctx.decide(decisionChannel.decide) : decisionChannel.decide,
    claims: decisionChannel.claims,
    fga,
    modelId,
    loadView,
    ...(ctx.viewSource ? { viewSource: ctx.viewSource } : {}),
    instanceEpoch: "demo-epoch",
    revokedInstances,
    observe: (e) => observer?.(e),
    // JIT gate: sending a remittance email is in the mission's authority but
    // requires an action-bound approval, resolved just-in-time. On the auth
    // server path the denial carries an RS-signed txn-challenge (AROP); the
    // client presents it to the AS transaction endpoint, which vouches the
    // approval and issues a txn-token. The approval is never an agent input.
    ...runtimeDecisionPolicy,
    // @spec authority-server#mission-join (#557) — this deployment's Join
    // configuration, from config/mas-join.json. It is one of the two keys the
    // joined path needs; the other is a route that validates an ordinary
    // credential (the MAS-governed channel below). Configured here even when
    // no such route runs, so a credential with no `mission` claim arriving on
    // a Mission-bound route is still refused by that route's validator rather
    // than by a missing config.
    masJoin: {
      delegatePolicy: {
        delegates: keyedRecordFrom(
          Object.entries(masJoin.delegates).map(([clientId, d]) => [clientId, { maxDepth: d.max_depth }] as const),
        ),
      },
      resolveOrdinaryAuthority,
      // Rule 5's depth source. The hook takes the canonical (issuer, id) pair
      // and the Mission's own client, so the ledger satisfies it directly.
      resolveDelegateDepth: actorRecords.resolveDepth.bind(actorRecords),
    },
    ...(challengeSigner ? { challengeSigner } : {}),
  });

  const server = new McpPaymentsServer({
    enforcementScopeStatement,
    pep,
    payments,
    loadView,
    ...(serverJwksUri ? { jwksUri: serverJwksUri, txnTokenJwksUri: serverJwksUri } : { jwks: serverJwks }),
    keyRoles: rsKeyRoles,
    issuer,
    transaction: { engine, connectors, evidence },
    writeReservations,
    // #821: a disposition record the transaction tier could not write is
    // alerted on the declared operator sink, as an indeterminate claim is.
    alerts: operatorAlerts,
    // AROP (RS side): validate a presented txn-token against the AS txn public
    // JWKS (published on /jwks under the as-txn kid) and issuer.
    ...(rsAsIssuer ? { asIssuer: rsAsIssuer } : {}),
    ...(txnChallengePublication ? { txnChallenge: txnChallengePublication } : {}),
  });
  // @spec runtime#evidence (outcome reconciliation) (#1103): this PEP is the
  // statement's responsible component, so it runs the reconciliation over its
  // own claim channel, redemption store, connectors, evidence and
  // reservations. Constructed here and not started: see `DemoStack.reconciler`.
  const reconciler = new OutcomeReconciler({
    statement,
    component: pepId,
    claims: decisionChannel.claims,
    evidence,
    redemption,
    connectors,
    writeReservations,
    alerts: operatorAlerts,
  });

  // @spec authority-server#mission-join (#557) — the MAS-governed route, on
  // its own listener, started only for a resource this deployment declares
  // governed. It is a SECOND channel: the Mission-bound channels keep
  // `validateCredential` and keep rejecting a credential with no `mission`
  // claim, so turning the Join on never loosens an existing route.
  // @spec mission#authority-proposal (#1531, D741): it is served under the
  // join's own resource identifier, whose metadata does not declare
  // Mission-bound-only acceptance.
  const masGovernedChannel = masGovernedResources.includes(CANONICAL_RESOURCE)
    ? await createHttpMcpChannel(server, { masGoverned: true, resource: masJoin.join_resource })
    : undefined;
  // D315: the as-native target's one resource entry point, at the declared
  // audience itself, so the `htu` a client signs and the `aud` the AS issues
  // name the same URL. It is the Mission-bound channel (`validateCredential`
  // with the request's DPoP proof); the in-process mediated channel is outside
  // this target's claims.
  let resourceChannel: HttpMcpChannel | undefined;
  if (ctx.serveAudience) {
    const audience = new URL(CANONICAL_RESOURCE);
    // A failed startup releases what it already opened: the AS and discovery
    // listeners, the decision channel, both single-writer store files and,
    // last, a kernel kept in a file (#250).
    const release = async (): Promise<void> => {
      await reconciler.stop();
      await ctx.release.closeAuthServer();
      await decisionChannel.close();
      pdpClaims.close();
      writeReservations.close();
      evidenceRetention.close();
      evidenceKeySets.close();
      ctx.release.closeOwnedStores();
    };
    try {
      resourceChannel = await createHttpMcpChannel(server, { host: audience.hostname, port: Number(audience.port) });
    } catch (err) {
      await release();
      throw err;
    }
    if (resourceChannel.url !== CANONICAL_RESOURCE) {
      await resourceChannel.close();
      await release();
      throw new Error(`the as-native endpoint ${resourceChannel.url} is not the declared audience ${CANONICAL_RESOURCE}`);
    }
  }

  return {
    payments,
    pdpClaims,
    writeReservations,
    evidenceRetention,
    evidenceKeySets,
    receiptIssuerScope,
    evidence,
    egressEvidence,
    connectors,
    revokedInstances,
    actorRecords,
    decisionChannel,
    pep,
    server,
    reconciler,
    masGovernedChannel,
    resourceChannel,
    onEnforce: (fn) => {
      observer = fn;
    },
  };
}
