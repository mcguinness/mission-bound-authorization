/**
 * @spec runtime#state-freshness (#1101, D293, D1258)
 *
 * The separated AS-native configuration (`config/as-native-separated.json`):
 * the AS-native payments target with its authorization server in its own
 * process, and the PEP and PDP reaching it over HTTP alone. Its PDP reads each
 * Mission's state over the AS's signed Mission Status, as the client
 * `pdp_client_id` (private-key JWT); the PEP and PDP hold no Mission records.
 *
 * - `authorization_server`: where the AS listens; its URL is the Mission
 *   issuer.
 * - `pdp_client_id`: the PDP's client at the AS's Mission Status endpoint.
 * - `txn_challenge_metadata`: where the resource publishes its
 *   txn-challenge keys, which the AS's Transaction Authorization Server
 *   resolves over HTTP.
 * - `state_source`: the PDP owns the read (`placement` is `pdp` and nothing
 *   else), bounded by `timeout_ms` and `max_response_bytes`.
 *
 * Closed shapes: a member this loader does not read is refused.
 */

import { readFileSync } from "node:fs";
import { loadRuntimePosture, type RuntimePosture } from "@mission/pdp";

export class AsNativeSeparatedConfigError extends Error {}

export interface AsNativeSeparatedConfig {
  authorization_server: { host: string; port: number };
  pdp_client_id: string;
  txn_challenge_metadata: { host: string; port: number };
  state_source: { placement: "pdp"; timeout_ms: number; max_response_bytes: number };
}

function obj(v: unknown, ctx: string, members: readonly string[]): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new AsNativeSeparatedConfigError(`${ctx} must be an object`);
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!members.includes(k)) throw new AsNativeSeparatedConfigError(`${ctx} carries an unknown member: ${k}`);
  }
  for (const k of members) {
    if (!Object.hasOwn(o, k)) throw new AsNativeSeparatedConfigError(`${ctx}.${k} is required`);
  }
  return o;
}

function str(v: unknown, ctx: string): string {
  if (typeof v !== "string" || v === "") throw new AsNativeSeparatedConfigError(`${ctx} must be a non-empty string`);
  return v;
}

function positiveInt(v: unknown, ctx: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) throw new AsNativeSeparatedConfigError(`${ctx} must be a positive integer`);
  return v;
}

function listener(v: unknown, ctx: string): { host: string; port: number } {
  const o = obj(v, ctx, ["host", "port"]);
  return { host: str(o.host, `${ctx}.host`), port: positiveInt(o.port, `${ctx}.port`) };
}

/** Validate a parsed configuration. */
export function parseAsNativeSeparatedConfig(raw: unknown): AsNativeSeparatedConfig {
  const root = obj(raw, "root", ["authorization_server", "pdp_client_id", "txn_challenge_metadata", "state_source"]);
  const source = obj(root.state_source, "state_source", ["placement", "timeout_ms", "max_response_bytes"]);
  // @spec runtime#state-freshness (D1258): this configuration demonstrates
  // the PDP-owned read only. A PEP-forwarded observation is not a source it
  // declares, so any other placement is refused here, before anything
  // connects, rather than run with a source it does not demonstrate.
  if (source.placement !== "pdp") throw new AsNativeSeparatedConfigError('state_source.placement must be "pdp"');
  return {
    authorization_server: listener(root.authorization_server, "authorization_server"),
    pdp_client_id: str(root.pdp_client_id, "pdp_client_id"),
    txn_challenge_metadata: listener(root.txn_challenge_metadata, "txn_challenge_metadata"),
    state_source: {
      placement: "pdp",
      timeout_ms: positiveInt(source.timeout_ms, "state_source.timeout_ms"),
      max_response_bytes: positiveInt(source.max_response_bytes, "state_source.max_response_bytes"),
    },
  };
}

export function loadAsNativeSeparatedConfig(
  path: URL | string = new URL("../../../config/as-native-separated.json", import.meta.url),
): AsNativeSeparatedConfig {
  return parseAsNativeSeparatedConfig(JSON.parse(readFileSync(path, "utf8")));
}

/** The Mission issuer: the authorization server's URL. */
export const separatedAsIssuer = (config: AsNativeSeparatedConfig): string =>
  `http://${config.authorization_server.host}:${config.authorization_server.port}`;

/** Where the resource publishes its txn-challenge keys, and where the AS resolves them. */
export const txnChallengeOrigin = (config: AsNativeSeparatedConfig): string =>
  `http://${config.txn_challenge_metadata.host}:${config.txn_challenge_metadata.port}`;

/** The state source this configuration's statement names. */
export const SEPARATED_STATE_SOURCE = "signed Mission Status at the Mission-holding AS, read by the PDP";

/**
 * @spec runtime#state-freshness, authzen#pdp-request rule 1 (#1101, D293):
 * `statement` with its state source declared as this configuration runs it:
 * the AS's signed Mission Status, placed with the PDP. Every other member,
 * the per-class bounds, `mission_max_stale_seconds` and the unavailability
 * posture included, is the published statement's, so the separated
 * configuration keeps the co-located target's freshness, skew, permit and
 * execution bounds. Validated as the PDP loads it.
 */
export function separatedStatement(statement: RuntimePosture): RuntimePosture {
  return loadRuntimePosture({
    ...statement,
    state_source: { ...statement.state_source, source: SEPARATED_STATE_SOURCE, placement: "pdp" },
  });
}
