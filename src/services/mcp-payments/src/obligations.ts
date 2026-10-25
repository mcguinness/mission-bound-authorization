/**
 * @spec authzen#obligation-processing, authzen#obligations (#1640, D744
 * ruling 8): the obligation types this PEP performs, and the one processing
 * step every decision that carries obligations goes through.
 *
 * "An obligation MAY accompany a permit or a denial: on a permit the PEP MUST
 * fulfill each obligation before releasing the action's effect; on a denial
 * the PEP MUST still deny the action and MUST additionally execute every
 * returned obligation. The PEP MUST treat an obligation it does not
 * recognize, or cannot fulfill, as an effective deny and MUST release no
 * protected effect; it still executes every obligation it understands and can
 * perform, as on any denial."
 *
 * The one type this PEP performs is the AuthZEN Obligations Profile's
 * `notification`: "requires the PEP to transmit a message to a destination",
 * with `to` and `body` REQUIRED strings and `topic` an OPTIONAL string, carried
 * in the obligation's `properties`. It is performable only where the
 * deployment configures a transport ({@link ObligationNotifier}); without one
 * the type is recognized and not implemented, which that profile counts as
 * "cannot comply". A malformed instance and a transmission that fails are
 * also "cannot comply". Every other type, `step-up` included, is one this PEP
 * does not implement.
 *
 * This module only performs and classifies. The caller decides what the
 * outcome means: on a permit, any obligation not fulfilled suppresses the
 * permit before release; on a denial, the outcomes are not evidenced (the
 * Obligations Profile's no-proof-of-execution posture the AuthZEN profile
 * inherits).
 */

import type { ExecutionEvidenceObject } from "./evidence.js";

/** One `notification` obligation as this PEP transmits it. */
export interface ObligationNotification {
  /** The obligation's `id`, as the decision returned it. */
  obligation_id: string;
  /** The decision the obligation rode on (`decision_id`), when it carried one. */
  evaluation_id?: string;
  to: string;
  body: string;
  topic?: string;
}

/**
 * The deployment's notification transport. `send` resolves once the message
 * is transmitted and rejects when it cannot be (an unknown or refused
 * destination, a transport failure after its own retries). The Obligations
 * Profile asks a PEP to treat `to` and `body` as untrusted input; validation,
 * rate limiting and content controls on them are the transport's.
 */
export interface ObligationNotifier {
  send(notification: ObligationNotification): Promise<void>;
}

/**
 * An in-process notification transport: it keeps every message it accepted,
 * in order. `deliver`, when given, runs first for each message and a throw
 * from it is a failed transmission, so a caller can refuse a destination or
 * observe the moment of transmission.
 */
export class NotificationOutbox implements ObligationNotifier {
  private readonly accepted: ObligationNotification[] = [];

  constructor(private readonly deliver?: (notification: ObligationNotification) => void | Promise<void>) {}

  async send(notification: ObligationNotification): Promise<void> {
    await this.deliver?.(notification);
    this.accepted.push(Object.freeze({ ...notification }));
  }

  /** Every message transmitted, in order. */
  sent(): readonly ObligationNotification[] {
    return [...this.accepted];
  }
}

export type ObligationOutcome = NonNullable<ExecutionEvidenceObject["obligation_outcomes"]>[number];

/** What processing one decision's obligations established. */
export interface ObligationProcessing {
  /** Every attached obligation was fulfilled. */
  fulfilled: boolean;
  /**
   * @spec runtime-evidence#execution-evidence-object `obligation_outcomes`
   * (#786): "One object per attached obligation, in the order the decision
   * returned them ... `id` and `type` are each REQUIRED when the decision
   * supplied that member as a non-empty string, and absent otherwise, never
   * invented. An obligation lacking either is malformed, and its `outcome`
   * is `unsupported`." {@link processObligations} always sets it, one entry
   * per attached obligation, a malformed one included, so the list is
   * complete whatever the obligations look like. It is absent only for a
   * present `obligations` member that is not a list, which names no
   * obligation: refused, with no fabricated outcome list (D770 ruling 5).
   */
  outcomes?: ObligationOutcome[];
}

/** The `error` detail of an attached obligation that does not identify itself. */
export const MALFORMED_OBLIGATION = "the obligation lacks a non-empty id or type";

/**
 * @spec runtime-evidence#execution-evidence-object `obligation_outcomes`
 * (#786): the entry for a malformed obligation. `id` and `type` are copied
 * only when supplied as non-empty strings and omitted otherwise, never
 * invented; the outcome is `unsupported`. Nothing in it is performed. Only
 * the record's representation is relaxed: the obligation stays malformed,
 * and the permit it rides on stays unusable.
 */
export function malformedObligationOutcome(raw: unknown, error: string): ObligationOutcome {
  const supplied = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as { id?: unknown; type?: unknown }) : {};
  const id = typeof supplied.id === "string" && supplied.id.length > 0 ? supplied.id : undefined;
  const type = typeof supplied.type === "string" && supplied.type.length > 0 ? supplied.type : undefined;
  return {
    ...(id !== undefined ? { id } : {}),
    ...(type !== undefined ? { type } : {}),
    outcome: "unsupported",
    error,
  };
}

/** The `notification` members this PEP transmits, or undefined when the instance is malformed. */
function notificationMembers(properties: unknown): { to: string; body: string; topic?: string } | undefined {
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) return undefined;
  const { to, body, topic } = properties as { to?: unknown; body?: unknown; topic?: unknown };
  if (typeof to !== "string" || to.length === 0 || typeof body !== "string") return undefined;
  if (topic !== undefined && typeof topic !== "string") return undefined;
  return { to, body, ...(topic !== undefined ? { topic } : {}) };
}

/**
 * Perform every obligation this PEP understands and can perform, in the order
 * the decision returned them, and classify each. An obligation that does not
 * identify itself is performed by no one: without its `type` nothing is
 * understood, and without its `id` it is not a well-formed obligation. It
 * still keeps its positional entry, with nothing invented (#786).
 */
export async function processObligations(
  obligations: readonly unknown[],
  notifier: ObligationNotifier | undefined,
  evaluationId: string | undefined,
): Promise<ObligationProcessing> {
  const outcomes: ObligationOutcome[] = [];
  let fulfilled = true;
  for (const raw of obligations) {
    const { id, type, properties } =
      raw && typeof raw === "object" && !Array.isArray(raw)
        ? (raw as { id?: unknown; type?: unknown; properties?: unknown })
        : {};
    if (typeof id !== "string" || id.length === 0 || typeof type !== "string" || type.length === 0) {
      fulfilled = false;
      outcomes.push(malformedObligationOutcome(raw, MALFORMED_OBLIGATION));
      continue;
    }
    const outcome = await performOne(id, type, properties, notifier, evaluationId);
    if (outcome.outcome !== "fulfilled") fulfilled = false;
    outcomes.push(outcome);
  }
  return { fulfilled, outcomes };
}

async function performOne(
  id: string,
  type: string,
  properties: unknown,
  notifier: ObligationNotifier | undefined,
  evaluationId: string | undefined,
): Promise<ObligationOutcome> {
  if (type !== "notification") {
    return { id, type, outcome: "unsupported", error: "obligation type not implemented at this PEP" };
  }
  if (!notifier) {
    return { id, type, outcome: "unsupported", error: "no notification transport is configured at this PEP" };
  }
  const members = notificationMembers(properties);
  if (!members) return { id, type, outcome: "failed", error: "malformed notification obligation" };
  try {
    await notifier.send({ obligation_id: id, ...(evaluationId !== undefined ? { evaluation_id: evaluationId } : {}), ...members });
  } catch {
    return { id, type, outcome: "failed", error: "notification transmission failed" };
  }
  return { id, type, outcome: "fulfilled" };
}
