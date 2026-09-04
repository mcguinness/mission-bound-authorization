/**
 * @spec authority-server#mission-join rule 5 (#557)
 *
 * The deployment's actor records: who was recorded as acting under which
 * Mission, and on whose delegation. Rule 5 evaluates a delegate's
 * `max_depth` "from the deployment's actor records rather than from a
 * Mission-bound token's `act` chain", and this is that store. It is
 * deployment state, not a protocol artifact, so it stays out of
 * `@mission/core` and sits beside `PaymentsStore` and `revokedInstances`.
 *
 * Nothing here reads a token's `act` chain. On the MAS Join path the acting
 * credential is an ordinary OAuth token that carries no chain at all, which
 * is exactly why rule 5 names the deployment's records as the depth source.
 *
 * Records are keyed on the canonical (issuer, id) Mission pair, so a record
 * appended under one issuer is never consumed for a same-id Mission from
 * another issuer (@spec authority-server#reference-verification: byte
 * equality on the pair, never the bare id).
 */

/** One recorded delegation edge under one Mission. */
export interface ActorRecord {
  /** The canonical Mission reference this delegation was recorded under. */
  mission: MissionRef;
  /** The delegate's authenticated OAuth client identifier. */
  clientId: string;
  /** The client that delegated to `clientId`, one hop closer to the Mission. */
  delegatedBy: string;
  /** When the deployment recorded the edge (RFC 3339). */
  recordedAt: string;
}

/**
 * A canonical Mission reference. Distinct from `MissionReference` (`pep.ts`),
 * which models a PROPAGATED reference and carries a `malformed` arm: a
 * reference that failed strict parsing never reaches this store.
 */
export interface MissionRef {
  issuer: string;
  id: string;
}

const keyOf = (mission: MissionRef, clientId: string): string =>
  JSON.stringify([mission.issuer, mission.id, clientId]);

/**
 * @spec authority-server#mission-join rule 5 (#557) — a deployment-local
 * ledger of delegation edges, and the depth resolution rule 5 evaluates
 * against.
 *
 * Depth follows the core draft's definition
 * (@spec mission#delegation-constraints): the Mission's own client is depth 0,
 * the first delegate is depth 1, and each further delegate adds 1.
 */
export class ActorRecords {
  /** Latest edge per (issuer, id, clientId); a re-record replaces the prior edge. */
  private readonly byClient = new Map<string, ActorRecord>();

  /**
   * Appends a delegation edge: `clientId` is recorded as acting under
   * `mission` on `delegatedBy`'s delegation. A later record for the same
   * (Mission, client) supersedes the earlier one, so the ledger answers with
   * the client's CURRENT delegation rather than its first.
   */
  record(input: { mission: MissionRef; clientId: string; delegatedBy: string; recordedAt?: string }): ActorRecord {
    const entry: ActorRecord = {
      mission: { issuer: input.mission.issuer, id: input.mission.id },
      clientId: input.clientId,
      delegatedBy: input.delegatedBy,
      recordedAt: input.recordedAt ?? new Date().toISOString(),
    };
    this.byClient.set(keyOf(entry.mission, entry.clientId), entry);
    return entry;
  }

  /** The recorded edge for one client under one Mission, if any. */
  get(mission: MissionRef, clientId: string): ActorRecord | undefined {
    return this.byClient.get(keyOf(mission, clientId));
  }

  /**
   * Resolves `clientId`'s current delegation depth under `mission`, walking
   * `delegatedBy` toward `missionClientId` (the Mission's own client, depth
   * 0) and adding 1 per hop. `missionClientId` is a parameter rather than
   * ledger state: the Mission's client is the loaded `MissionView`'s
   * `client_id`, and the walk's base case is byte equality against it.
   *
   * Resolves to `undefined`, an ABSENT depth, in every case where the ledger
   * does not actually record this client as acting under this Mission: no
   * record at all, a chain that runs out of records before reaching the
   * Mission's client (unrooted), a cycle, or a chain that never reaches the
   * Mission's client. An absent depth denies the join
   * (@spec authority-server#mission-join rule 5, the delegate disposition),
   * so an incomplete ledger never resolves to a permissive number.
   */
  resolveDepth(mission: MissionRef, clientId: string, missionClientId: string): number | undefined {
    if (clientId === missionClientId) return 0;
    const seen = new Set<string>([clientId]);
    let current = clientId;
    let depth = 0;
    // Bounded by the ledger's own size: every hop visits a distinct client
    // (the `seen` guard), so a cycle terminates instead of spinning.
    while (true) {
      const record = this.byClient.get(keyOf(mission, current));
      if (!record) return undefined;
      depth += 1;
      if (record.delegatedBy === missionClientId) return depth;
      if (seen.has(record.delegatedBy)) return undefined;
      seen.add(record.delegatedBy);
      current = record.delegatedBy;
    }
  }
}
