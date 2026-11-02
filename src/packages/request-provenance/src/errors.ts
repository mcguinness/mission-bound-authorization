/**
 * Refusal codes the intake library raises. They are local diagnostics of
 * this implementation, not protocol error codes: the draft defines no error
 * for the intake, and an AS refuses a bad assertion with
 * `invalid_mission_intent_evidence` under its own verification rules.
 */
export type RequestProvenanceErrorCode =
  /** The intake configuration is malformed or unbounded. */
  | "invalid_config"
  /** A capture request is malformed (shape, media type, origin facts). */
  | "invalid_capture"
  /** A signing request is malformed or carries a member the intake does not accept. */
  | "invalid_sign_request"
  /** The signing request names no capture record this intake retains. */
  | "unknown_capture"
  /** The capture record belongs to another workflow. */
  | "workflow_mismatch"
  /** The capture is older than the intake's maximum capture age. */
  | "capture_too_old"
  /** The clock reads earlier than the capture time. */
  | "clock_regressed"
  /** The random source failed to produce the bytes requested, or repeated an identifier. */
  | "random_source_failure";

export class RequestProvenanceError extends Error {
  readonly code: RequestProvenanceErrorCode;

  constructor(code: RequestProvenanceErrorCode, message: string) {
    super(message);
    this.name = "RequestProvenanceError";
    this.code = code;
  }
}
