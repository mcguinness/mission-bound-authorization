/**
 * @spec mission#approval-event (step 7) (#1863, D1001): "Create the Mission
 * Record ... in the `active` state atomically with the approval decision and
 * issuance of the authorization code."
 *
 * oidc-provider issues the code on the resume request that follows the
 * decision, so a direct browser approval does not commit at the decision. The
 * decision is HELD: everything the commit needs (the approval as decided, its
 * prepared authority, and the final checks it runs again) is kept here, keyed
 * by the decision's provider grant, until that grant's authorization code is
 * saved. The provider's `AuthorizationCode` storage is wrapped
 * ({@link missionProviderAdapter}) so that the code save commits the record:
 *
 * 1. it joins the approval event's serialization, so a decision racing the
 *    resume is ordered against it;
 * 2. it STAGES the code. A staged code is stored but not redeemable, so a
 *    code-storage failure happens before anything is committed;
 * 3. then, with nothing awaited, it runs the final checks and
 *    `kernel.approve`;
 * 4. and on success it RELEASES the code: only a released code under a held
 *    approval grant is ever found again.
 *
 * A refused commit completes `access_denied`; any other failure before the
 * commit stores no redeemable code. Either way the staged code and the grant
 * are removed best effort, and a deletion that fails leaves a code that is
 * never released under a grant that stays classified as Mission-bound
 * (`MissionBoundGrantStore.recordHeldApproval`), so nothing is usable.
 * After the commit, recovery-witness uncertainty fails closed with nothing
 * released. Only two post-commit failures are recovered, each by its type and
 * only when the committed record agrees with the held decision: a failed
 * notification (`LifecycleNotificationError`: the event row is durable and the
 * drain retries it) and a failed bound-grant index write
 * (`BoundGrantIndexWriteError`: the entry is written again). Any other
 * exception after the commit releases nothing, so an unrelated failure never
 * releases a code; the Mission it committed then has no usable code, as before
 * #1863, until its expiry or a revocation.
 *
 * In-process: the reference AS runs as one process (D663), and these holds
 * live in its memory, as the provider's codes and grants do.
 */
import MemoryAdapter from "oidc-provider/lib/adapters/memory_adapter.js";
import { type Adapter, type AdapterFactory, type AdapterPayload, errors } from "oidc-provider";
import type Provider from "oidc-provider";
import { IntentError } from "../kernel/intent.js";
import type { ApproveInput, MissionKernel, PreparedApproval } from "../kernel/kernel.js";
import { LifecycleNotificationError } from "../kernel/lifecycle-outbox.js";
import { BoundGrantIndexWriteError } from "../kernel/mission-bound-grant-store.js";
import { RecoveryUncertainError } from "../kernel/recovery-witness.js";
import type { MissionRecord } from "../kernel/types.js";
import { serializeApprovalEvent } from "./approval-render-revision.js";

/** A direct approval decided and not yet committed. */
export interface HeldApproval {
  grantId: string;
  approvalEventId: string;
  /** The approval as decided, naming its grant; `kernel.approve` commits it at code issuance. */
  input: ApproveInput & { grantId: string };
  prepared: PreparedApproval;
  /**
   * When the hold lapses, in epoch milliseconds on the provider's clock (the
   * one its interaction expires by): no later than its interaction.
   */
  expiresAt: number;
  /**
   * The decision's final checks, run again at the commit with nothing awaited
   * before `kernel.approve`: the approval context its rendering showed
   * (#1446) and the approval-authentication floor. Throws an IntentError.
   */
  finalChecks: () => void;
}

/** The holds of one provider, and the codes released under held approval grants. */
export class ApprovalHolds {
  private readonly holds = new Map<string, HeldApproval>();
  /** Released code ids, each kept for its code's stored lifetime (epoch ms). */
  private readonly released = new Map<string, number>();

  constructor(private readonly kernel: MissionKernel) {}

  /** Hold a decision, replacing an earlier hold of the same grant (a retried decision). */
  hold(held: HeldApproval): void {
    const now = Date.now();
    for (const [grantId, h] of this.holds) if (h.expiresAt <= now) this.holds.delete(grantId);
    this.holds.set(held.grantId, held);
  }

  /** The live hold of `grantId`; a lapsed one is dropped. */
  pending(grantId: string): HeldApproval | undefined {
    const held = this.holds.get(grantId);
    if (held && held.expiresAt <= Date.now()) {
      this.holds.delete(grantId);
      return undefined;
    }
    return held;
  }

  drop(grantId: string): void {
    this.holds.delete(grantId);
  }

  /** Make the code `id` redeemable for the `seconds` it is stored. */
  release(id: string, seconds: number): void {
    const now = Date.now();
    for (const [code, until] of this.released) if (until <= now) this.released.delete(code);
    this.released.set(id, now + Math.max(0, seconds) * 1000);
  }

  isReleased(id: string): boolean {
    const until = this.released.get(id);
    return until !== undefined && until > Date.now();
  }

  /**
   * The `expires_at` the held decision's commit would establish now, as
   * `kernel.approve` does: the requested ceiling, narrowed by the deployment's
   * lifetime bound from this instant and by the expiry the rendering showed.
   * A commit made later establishes the same value or a later one, so a code
   * clamped to this never outlives its Mission.
   */
  prospectiveExpiresAt(held: HeldApproval): string {
    return this.kernel.resolveEffectiveExpiry({
      requested: held.input.intent.expires_at,
      createdAt: this.kernel.nowDate().toISOString(),
      ...(held.input.renderedExpiresAt ? { ceilings: { rendered: held.input.renderedExpiresAt } } : {}),
    });
  }
}

const registry = new WeakMap<Provider, ApprovalHolds>();

export function registerApprovalHolds(provider: Provider, holds: ApprovalHolds): void {
  registry.set(provider, holds);
}

export function approvalHoldsOf(provider: Provider): ApprovalHolds {
  const holds = registry.get(provider);
  if (!holds) throw new Error("this provider holds no approval decisions");
  return holds;
}

/** Whether a committed record is the held decision: the same Approver, Subject, client and grant. */
function isHeldDecision(record: MissionRecord, held: HeldApproval): boolean {
  return (
    record.grant_id === held.grantId &&
    record.approval_basis.consent_principal?.iss === held.input.approver.iss &&
    record.approval_basis.consent_principal?.sub === held.input.approver.sub &&
    record.subject.iss === held.input.subject.iss &&
    record.subject.sub === held.input.subject.sub &&
    record.client_id === held.input.clientId
  );
}

const NOT_PENDING = "the approval decision is no longer pending";

/**
 * The provider's storage (oidc-provider's `adapter` factory): its in-memory
 * adapter for every model, with `AuthorizationCode` fenced as described
 * above. `provider` resolves the provider the factory serves, which the
 * fence serializes on and whose grants it removes.
 */
export function missionProviderAdapter(deps: {
  kernel: MissionKernel;
  holds: ApprovalHolds;
  provider: () => Provider;
}): AdapterFactory {
  return (name: string) => {
    const inner = new MemoryAdapter(name);
    return name === "AuthorizationCode" ? fenceAuthorizationCodes(inner, deps) : inner;
  };
}

function fenceAuthorizationCodes(
  inner: Adapter,
  deps: { kernel: MissionKernel; holds: ApprovalHolds; provider: () => Provider },
): Adapter {
  const { kernel, holds } = deps;
  const heldEvent = (grantId: unknown) =>
    typeof grantId === "string" ? kernel.missionBoundGrants.heldApproval(grantId) : undefined;

  /**
   * Best effort. A deletion that fails changes nothing that matters: the code
   * is never released, and the grant stays classified as Mission-bound.
   */
  const discard = async (codeId: string | undefined, grantId: string | undefined): Promise<void> => {
    if (codeId) await inner.destroy(codeId).catch(() => undefined);
    if (grantId) await deps.provider().Grant.adapter.destroy(grantId).catch(() => undefined);
  };

  /** The resolution of a commit that threw, from the state it left. */
  const settleFailedCommit = async (e: unknown, id: string, seconds: number, held: HeldApproval): Promise<void> => {
    holds.drop(held.grantId);
    // Recovery-witness uncertainty: what is durable cannot be told, so
    // nothing is released, whatever the store now reads.
    if (e instanceof RecoveryUncertainError || kernel.recoveryUncertainty()) {
      await discard(id, undefined);
      throw e;
    }
    const record = kernel.findByApprovalEvent(held.approvalEventId);
    if (record) {
      // Committed, and a known post-commit step failed after it: a
      // notification whose delivery row is durable and retried by the
      // request-path drain, or the bound-grant index write `approve` makes
      // after its transaction. The entry is made sure of here, and the code is
      // released, with nothing awaited since the commit. Any other exception
      // after a commit is not recognized and releases nothing.
      if (isHeldDecision(record, held) && (e instanceof LifecycleNotificationError || e instanceof BoundGrantIndexWriteError)) {
        kernel.missionBoundGrants.record({ grantId: held.grantId, missionId: record.id, kind: "approval" });
        holds.release(id, seconds);
        return;
      }
      await discard(id, undefined);
      throw e;
    }
    // Nothing committed.
    await discard(id, held.grantId);
    if (e instanceof IntentError) throw new errors.AccessDenied(e.message);
    throw e;
  };

  /** The code save of a held approval grant, serialized on its approval event. */
  const issueHeldCode = async (id: string, payload: AdapterPayload, expiresIn: number, grantId: string): Promise<void> => {
    const held = holds.pending(grantId);
    if (!held) {
      // Lapsed with its interaction, refused or failed earlier, or committed
      // with an earlier code: this code is not issued. A committed grant is kept.
      const committed = kernel.findByGrant(grantId) !== undefined;
      await discard(undefined, committed ? undefined : grantId);
      throw new errors.AccessDenied(NOT_PENDING);
    }
    // The expiry clamp, against the hold read in this turn: a retried decision
    // may have replaced the one the code's lifetime was computed from.
    let seconds = expiresIn;
    const latest = Math.floor(Date.parse(holds.prospectiveExpiresAt(held)) / 1000);
    if (typeof payload.exp === "number" && payload.exp > latest) {
      seconds = latest - Math.floor(Date.now() / 1000);
      if (seconds < 1) {
        holds.drop(grantId);
        await discard(undefined, grantId);
        throw new errors.AccessDenied("the Mission expires before the authorization can complete");
      }
      payload.exp = latest;
    }
    // Stage: stored, not redeemable. A failure here commits nothing.
    try {
      await inner.upsert(id, payload, seconds);
    } catch (e) {
      holds.drop(grantId);
      await discard(id, grantId);
      throw e;
    }
    // From here to the release nothing is awaited: the final checks, the
    // commit and the release are one synchronous turn.
    if (holds.pending(grantId) !== held) {
      holds.drop(grantId);
      await discard(id, grantId);
      throw new errors.AccessDenied(NOT_PENDING);
    }
    try {
      held.finalChecks();
      kernel.approve(held.input, held.prepared);
    } catch (e) {
      await settleFailedCommit(e, id, seconds, held);
      return;
    }
    holds.drop(grantId);
    holds.release(id, seconds);
  };

  return {
    upsert(id, payload, expiresIn) {
      const classified = heldEvent(payload.grantId);
      if (!classified) return inner.upsert(id, payload, expiresIn);
      return serializeApprovalEvent(deps.provider(), classified.approvalEventId, () =>
        issueHeldCode(id, payload, expiresIn, payload.grantId as string),
      );
    },
    // Redeemability is an explicit release: under a held approval grant only a
    // released code is found, so a staged, refused or failed one never redeems.
    async find(id) {
      const stored = await inner.find(id);
      if (stored && heldEvent(stored.grantId) && !holds.isReleased(id)) return undefined;
      return stored;
    },
    findByUid: (uid) => inner.findByUid(uid),
    findByUserCode: (userCode) => inner.findByUserCode(userCode),
    consume: (id) => inner.consume(id),
    destroy: (id) => inner.destroy(id),
    revokeByGrantId: (grantId) => inner.revokeByGrantId(grantId),
  };
}
