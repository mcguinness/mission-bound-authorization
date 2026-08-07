/**
 * @spec harness#mediated-egress (the second mediation boundary)
 *
 * A default-deny egress gate for the agent's SECONDARY channels, keyed to the
 * published execution-environment scope statement. The tool path is already
 * mediated ({@link MediatedHarness}: MCP channel + PEP); this gate mediates the
 * agent's other declared channel, the inference API, so the demo agent has NO
 * unmediated egress path. The statement is the gate's authoritative input: a
 * channel the statement does not mark `mediated`, or a destination outside a
 * mediated channel's declared set, is refused. Every request, permitted AND
 * refused, is recorded as {@link EgressEvidence} in the gate's OWN evidence
 * store (producers retain their own, D32), with `emitter.role: "egress"` and
 * the `scope_statement_digest` joining each record to the published claim.
 *
 * The mission-state guard runs FIRST and fails closed, mirroring
 * {@link MediatedHarness}'s duty-1 rule exactly (same state/status inputs, same
 * refusal styles): work whose Mission is not active does not egress, before any
 * allowlist is consulted.
 *
 * This is an in-process reference realization: it mediates the egress API for a
 * NON-COMPROMISED agent and supports no containment claim. The existing
 * `in_memory` -> `containment_claim: "none"` downgrade in
 * {@link buildScopeStatement} already encodes this. Session-taint and
 * egress-downgrade remain Deferred; the gate is a channel/destination check,
 * not the taint rule.
 */

import type { MissionStatusLease } from "@mission/core";
import type { EvidenceStore } from "@mission/mcp-payments";
import type { MissionState, ResumeDecision } from "./harness.js";
import { checkStatusContinuity } from "./harness.js";
import {
  type ChannelClass,
  type ExecutionEnvironmentScopeStatement,
  scopeDigest,
} from "./harness-scope.js";
import { resumeGuard } from "./mediated-harness.js";

/**
 * @spec containment#containment-plane (low-trust advisory class) — the refusal a
 * harness may FORWARD as a harness-sourced protected event. The in-process
 * egress gate does NOT sign or POST anything itself (its scope statement
 * declares `containment_claim: "none"`); it only surfaces the refusal through
 * this callback so a harness can forward it as an ADVISORY, low-trust report.
 * Carries the two channel/destination refusal classes only, never the
 * mission-state guard's refusals.
 */
export interface EgressRefusal {
  channel_class: string;
  destination: string;
  /** `egress_undeclared:*` or `egress_destination_unlisted:*`. */
  refusal_reason: string;
  mission_id: string;
  /** The published scope statement's digest, joining the refusal to the claim. */
  scope_statement_digest: string;
}

/** The gate's verdict for one egress request. */
export interface EgressDecision {
  permitted: boolean;
  /** Present when refused: `mission_not_active:*` / `mission_status_stale:*` /
   * `egress_undeclared:*` / `egress_destination_unlisted:*`. */
  refusal_reason?: string;
  /** Present when the mission-state guard blocked (mirrors HarnessToolResult). */
  resume?: ResumeDecision;
}

/**
 * Constructor input. The state/status inputs mirror {@link MediatedHarness}'s
 * shape exactly: `readState` is the duty-1 reader; `readStatus` (when present)
 * takes precedence and re-checks lease freshness at each request via
 * {@link checkStatusContinuity}, with `now` injectable for tests.
 */
export interface EgressGateConfig {
  /** The published scope statement: the claim and the allowlist are the same object. */
  statement: ExecutionEnvironmentScopeStatement;
  missionId: string;
  /** Duty-1 state reader (fail closed when missing/non-active). */
  readState: (id: string) => Promise<MissionState | undefined>;
  /** Status-lease reader; when present it takes precedence over `readState`. */
  readStatus?: (id: string) => Promise<MissionStatusLease | undefined>;
  /** Injectable clock (defaults to `() => new Date()`). */
  now?: () => Date;
  /** The gate's OWN evidence store (producers retain their own, D32). */
  evidence: EvidenceStore;
  /** The emitting component's identifier (evidence `emitter.id`, role `egress`). */
  emitterId: string;
  instanceEpoch: string;
  /** The Mission's Authority Set commitment, when known ("unknown" otherwise). */
  authorityHash?: string;
  /**
   * @spec containment#containment-plane — OPTIONAL harness reporter seam. Fires
   * ONLY on the two channel/destination refusals (`egress_undeclared` /
   * `egress_destination_unlisted`), never on the mission-state guard's
   * refusals, so a harness can forward the refusal as an ADVISORY (low-trust)
   * protected event. The gate never signs or POSTs; forwarding is the harness's
   * job. A throw here is swallowed (this is a fail-closed security component).
   */
  onRefusal?: (refusal: EgressRefusal) => void;
}

/** The origin of a destination URL, or undefined when it does not parse. */
function originOf(destination: string): string | undefined {
  try {
    return new URL(destination).origin;
  } catch {
    return undefined;
  }
}

export class EgressGate {
  /** Allowed destination ORIGINS per channel the statement marks `mediated`. */
  private readonly mediated: Map<string, ReadonlySet<string>>;
  private readonly statementDigest: string;
  private readonly now: () => Date;

  constructor(private readonly config: EgressGateConfig) {
    // Consistency rejection: a destination set on a channel the statement does
    // not mark `mediated` would enforce an allowlist the published claim does
    // not make. buildScopeStatement already rejects this at build time; the
    // gate re-checks because it accepts any (e.g. hand-built) statement.
    this.mediated = new Map();
    for (const entry of config.statement.channel_classes) {
      if (entry.destinations !== undefined && entry.disposition !== "mediated") {
        throw new Error(
          `egress gate: statement names destinations for channel class ${entry.channel_class}, which is ${entry.disposition}, not mediated`,
        );
      }
      if (entry.disposition === "mediated") {
        this.mediated.set(entry.channel_class, new Set((entry.destinations ?? []).map((d) => originOf(d) ?? d)));
      }
    }
    this.statementDigest = scopeDigest(config.statement);
    this.now = config.now ?? (() => new Date());
  }

  /** Mirrors {@link MediatedHarness}'s guard: readStatus (fresh-at-submission)
   * takes precedence; otherwise the duty-1 resume guard over readState. */
  private async guard(): Promise<ResumeDecision> {
    if (this.config.readStatus !== undefined) {
      const lease = await this.config.readStatus(this.config.missionId);
      return checkStatusContinuity(lease, this.now());
    }
    return resumeGuard(this.config.missionId, this.config.readState);
  }

  /**
   * Decide one egress request, default-deny, in order: (1) mission-state guard
   * FIRST, fail closed, with MediatedHarness.callTool's exact refusal style;
   * (2) a channel the statement does not mark `mediated` is refused; (3) a
   * destination whose origin is not in the channel's declared set is refused.
   * EVERY request is recorded as EgressEvidence, permitted and refused alike.
   */
  async request(
    channel_class: ChannelClass | (string & Record<never, never>),
    destination: string,
  ): Promise<EgressDecision> {
    const resume = await this.guard();
    if (!resume.proceed) {
      const refusal_reason = resume.stale
        ? `mission_status_stale:${resume.state}`
        : `mission_not_active:${resume.state}`;
      return this.refuse(channel_class, destination, refusal_reason, resume);
    }
    const allowed = this.mediated.get(channel_class);
    if (allowed === undefined) {
      const reason = `egress_undeclared:${channel_class}`;
      const decision = this.refuse(channel_class, destination, reason);
      this.reportRefusal(channel_class, destination, reason);
      return decision;
    }
    const origin = originOf(destination);
    if (origin === undefined || !allowed.has(origin)) {
      const reason = `egress_destination_unlisted:${origin ?? destination}`;
      const decision = this.refuse(channel_class, destination, reason);
      this.reportRefusal(channel_class, destination, reason);
      return decision;
    }
    this.record(channel_class, destination, "permitted");
    return { permitted: true };
  }

  /**
   * Forward one channel/destination refusal to the OPTIONAL harness reporter
   * seam (never the mission-state guard's refusals; those never call here). The
   * gate does not sign or POST; a throw from the forwarder is swallowed so a
   * broken reporter cannot break this fail-closed component.
   */
  private reportRefusal(channel_class: string, destination: string, refusal_reason: string): void {
    const onRefusal = this.config.onRefusal;
    if (!onRefusal) return;
    try {
      onRefusal({
        channel_class,
        destination,
        refusal_reason,
        mission_id: this.config.missionId,
        scope_statement_digest: this.statementDigest,
      });
    } catch {
      // A broken forwarder must not affect the (already recorded) refusal.
    }
  }

  /**
   * A `fetch` wrapper that egresses ONLY through the gate: each call is decided
   * as an `inference_api` request against the statement, and the inner fetch is
   * reached on permit alone; a refusal throws (fail closed, already recorded).
   */
  guardedFetch(inner: typeof fetch = fetch): typeof fetch {
    const guarded = async (...args: Parameters<typeof fetch>): Promise<Response> => {
      const [input] = args;
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const decision = await this.request("inference_api", url);
      if (!decision.permitted) {
        throw new Error(`egress refused: ${decision.refusal_reason}`);
      }
      return inner(...args);
    };
    return guarded as typeof fetch;
  }

  private refuse(
    channel_class: string,
    destination: string,
    refusal_reason: string,
    resume?: ResumeDecision,
  ): EgressDecision {
    this.record(channel_class, destination, "refused", refusal_reason);
    return { permitted: false, refusal_reason, ...(resume ? { resume } : {}) };
  }

  private record(
    channel_class: string,
    destination: string,
    outcome: "permitted" | "refused",
    refusal_reason?: string,
  ): void {
    this.config.evidence.record({
      kind: "egress",
      channel_class,
      destination,
      outcome,
      ...(refusal_reason !== undefined ? { refusal_reason } : {}),
      mission_id: this.config.missionId,
      authority_hash: this.config.authorityHash ?? "unknown",
      action: `egress:${channel_class}`,
      instance_epoch: this.config.instanceEpoch,
      emitter: { id: this.config.emitterId, role: "egress" },
      scope_statement_digest: this.statementDigest,
    });
  }
}
