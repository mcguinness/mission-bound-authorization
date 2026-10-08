#!/usr/bin/env node
// Executable examples for draft-mcguinness-mission-aauth-management (#838).
//
// Extracts every JSON example in the draft (fenced `~~~ json` blocks and the
// JSON body of fenced `~~~ http` blocks), classifies each by the operation it
// illustrates, and validates the members the draft makes REQUIRED or
// conditional for that operation. A JSON fragment that is not a complete
// object (for example the `"replacement_s256": ...` member line) is validated
// by wrapping it in braces and checking its members are ones the draft
// defines.
//
// The rules restate the draft's own requirements and are kept beside it:
//   status / terminate response: mission_s256, mission_status, approved_at,
//     observed_at, fresh_until REQUIRED; terminated_at, termination_reason,
//     token_residual REQUIRED when terminated and absent when active;
//     accepted_updates, when present, a non-negative integer, with
//     latest_update_s256 (an unpadded base64url SHA-256 digest) present
//     exactly when accepted_updates is greater than zero and never without it.
//   token_residual: tracked, revocation_attempted, revocation_confirmed
//     (non-negative integers) and complete (boolean) REQUIRED;
//     residual_until a date-time when present.
//   every request: no mission_s256 body member (the path names the mission).
//   terminate request: action, reason, request_id REQUIRED;
//     replacement_s256 REQUIRED when reason is superseded.
//   delegation-tree response: mission_s256, as_of, nodes, complete REQUIRED;
//     each node has agent and relationship; a non-root node has parent_agent;
//     next_cursor is present exactly when complete is false.
//   metadata: issuer, mission_control_endpoint and
//     mission_control_actions_supported, which MUST contain status and
//     terminate.
//   timestamps: RFC 3339 date-time values that name a real instant; ordering
//     (fresh_until not before observed_at) compares instants, never strings.
//
// The check fails if any expected kind of example is missing, so removing an
// example cannot make it pass vacuously.
//
// Usage: node scripts/check-aauth-management-examples.mjs [path-to-draft]
// Chained from scripts/check-family-manifest.mjs.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DRAFT = "draft-mcguinness-mission-aauth-management.md";

const ACTIONS = ["status", "terminate", "delegation_tree"];
const REASONS = ["completed", "revoked", "expired", "superseded", "administrative"];
const STATES = ["active", "terminated"];
const RELATIONSHIPS = ["root", "sub_agent", "call_chain"];
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const S256 = /^[A-Za-z0-9_-]{43}$/;

// An RFC 3339 date-time as an instant in milliseconds, or NaN when the value
// is not a well-formed date-time or names no real calendar instant.
export function instant(v) {
  if (typeof v !== "string" || !DATE_TIME.test(v)) return NaN;
  const ms = Date.parse(v);
  if (Number.isNaN(ms)) return NaN;
  // Date.parse rolls invalid calendar dates (2026-02-30) forward; reject them.
  const [y, mo, d] = v.slice(0, 10).split("-").map(Number);
  const days = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (mo < 1 || mo > 12 || d < 1 || d > days) return NaN;
  return ms;
}

export function extractExamples(text) {
  const lines = text.split("\n");
  const out = [];
  let heading = "";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const h = line.match(/^#+\s+(.*?)(\s+\{#[^}]+\})?\s*$/);
    if (h) heading = h[1];
    const fence = line.match(/^~~~\s*(json|http)\s*$/);
    if (!fence) continue;
    const body = [];
    let j = i + 1;
    while (j < lines.length && lines[j] !== "~~~") body.push(lines[j++]);
    let raw = body.join("\n");
    if (fence[1] === "http") {
      const blank = raw.indexOf("\n\n");
      if (blank < 0) { i = j; continue; }
      raw = raw.slice(blank + 2);
    }
    out.push({ line: i + 1, heading, kind: fence[1], raw: raw.trim() });
    i = j;
  }
  return out;
}

function parse(raw) {
  try { return { value: JSON.parse(raw), fragment: false }; } catch {}
  try { return { value: JSON.parse(`{${raw}}`), fragment: true }; } catch {}
  return null;
}

function classify(obj, heading, fragment) {
  if (fragment) return "fragment";
  if ("mission_control_endpoint" in obj) return "metadata";
  if ("nodes" in obj) return "tree-response";
  if ("mission_status" in obj) {
    return heading === "Atomic Transition" ? "terminate-response" : "status-response";
  }
  if (obj.action === "terminate") return "terminate-request";
  if (obj.action === "delegation_tree") return "tree-request";
  if (obj.action === "status") return "status-request";
  return null;
}

function checkTokenResidual(tr, err) {
  if (typeof tr !== "object" || tr === null) return err("token_residual is not an object");
  for (const m of ["tracked", "revocation_attempted", "revocation_confirmed"]) {
    if (!Number.isInteger(tr[m]) || tr[m] < 0) err(`token_residual.${m} missing or not a non-negative integer`);
  }
  if (typeof tr.complete !== "boolean") err("token_residual.complete missing or not a boolean");
  if ("residual_until" in tr && Number.isNaN(instant(tr.residual_until))) err("token_residual.residual_until is not a date-time");
  if (tr.revocation_confirmed > tr.revocation_attempted || tr.revocation_attempted > tr.tracked) {
    err("token_residual counters are not monotone (confirmed <= attempted <= tracked)");
  }
}

function checkStatusRepresentation(obj, err) {
  for (const m of ["mission_s256", "mission_status", "approved_at", "observed_at", "fresh_until"]) {
    if (!(m in obj)) err(`missing REQUIRED member ${m}`);
  }
  if ("mission_s256" in obj && !S256.test(obj.mission_s256)) err("mission_s256 is not an unpadded base64url SHA-256 digest");
  if ("mission_status" in obj && !STATES.includes(obj.mission_status)) err(`mission_status ${obj.mission_status} is not a protocol state`);
  for (const m of ["approved_at", "observed_at", "fresh_until", "expires_at", "terminated_at"]) {
    if (m in obj && Number.isNaN(instant(obj[m]))) err(`${m} is not an RFC 3339 date-time`);
  }
  const observed = instant(obj.observed_at), fresh = instant(obj.fresh_until);
  if (!Number.isNaN(observed) && !Number.isNaN(fresh) && fresh < observed) err("fresh_until precedes observed_at");
  if ("accepted_updates" in obj && (!Number.isInteger(obj.accepted_updates) || obj.accepted_updates < 0)) {
    err("accepted_updates is not a non-negative integer");
  }
  if ("latest_update_s256" in obj) {
    if (!("accepted_updates" in obj)) err("latest_update_s256 without accepted_updates");
    if (!S256.test(obj.latest_update_s256)) err("latest_update_s256 is not an unpadded base64url SHA-256 digest");
  }
  if (Number.isInteger(obj.accepted_updates)) {
    if (obj.accepted_updates > 0 && !("latest_update_s256" in obj)) err("accepted_updates is greater than zero but latest_update_s256 is absent");
    if (obj.accepted_updates === 0 && "latest_update_s256" in obj) err("latest_update_s256 present with zero accepted_updates");
  }
  const conditional = ["terminated_at", "termination_reason", "token_residual"];
  if (obj.mission_status === "terminated") {
    for (const m of conditional) if (!(m in obj)) err(`missing ${m}, REQUIRED when terminated`);
    if ("termination_reason" in obj && !REASONS.includes(obj.termination_reason)) err(`termination_reason ${obj.termination_reason} is not defined`);
    if ("token_residual" in obj) checkTokenResidual(obj.token_residual, err);
  } else if (obj.mission_status === "active") {
    for (const m of conditional) if (m in obj) err(`${m} MUST be absent while active`);
  }
}

function noBodyReference(o, err) {
  if ("mission_s256" in o) err("a request body MUST NOT carry mission_s256; the path names the mission");
}

const CHECKS = {
  "status-request": (o, err) => {
    noBodyReference(o, err);
    if (o.action !== "status") err("action is not status");
  },
  "status-response": checkStatusRepresentation,
  "terminate-response": (o, err) => {
    checkStatusRepresentation(o, err);
    if (o.mission_status !== "terminated") err("a terminate response reports a terminated mission");
  },
  "terminate-request": (o, err) => {
    noBodyReference(o, err);
    for (const m of ["action", "reason", "request_id"]) if (!(m in o)) err(`missing REQUIRED member ${m}`);
    if ("reason" in o && !REASONS.includes(o.reason)) err(`reason ${o.reason} is not defined`);
    if (o.reason === "superseded" && !("replacement_s256" in o)) err("superseded requires replacement_s256");
  },
  "tree-request": (o, err) => {
    noBodyReference(o, err);
    if ("max_results" in o && (!Number.isInteger(o.max_results) || o.max_results < 1)) err("max_results is not a positive integer");
    if ("cursor" in o && typeof o.cursor !== "string") err("cursor is not a string");
  },
  "tree-response": (o, err) => {
    for (const m of ["mission_s256", "as_of", "nodes", "complete"]) if (!(m in o)) err(`missing REQUIRED member ${m}`);
    if ("as_of" in o && Number.isNaN(instant(o.as_of))) err("as_of is not an RFC 3339 date-time");
    if ("complete" in o && typeof o.complete !== "boolean") err("complete is not a boolean");
    if ("next_cursor" in o && o.complete !== false) err("next_cursor present but complete is not false");
    if (o.complete === false && !("next_cursor" in o)) err("complete is false but next_cursor is absent; another page REQUIRES next_cursor");
    for (const [k, n] of (o.nodes || []).entries()) {
      if (!n.agent) err(`node ${k} missing agent`);
      if (!RELATIONSHIPS.includes(n.relationship)) err(`node ${k} relationship ${n.relationship} is not defined`);
      if (n.relationship && n.relationship !== "root" && !n.parent_agent) err(`node ${k} is non-root without parent_agent`);
    }
  },
  "metadata": (o, err) => {
    for (const m of ["issuer", "mission_control_endpoint", "mission_control_actions_supported"]) if (!(m in o)) err(`missing ${m}`);
    const actions = o.mission_control_actions_supported;
    if (!Array.isArray(actions)) return err("mission_control_actions_supported is not an array");
    for (const a of ["status", "terminate"]) if (!actions.includes(a)) err(`mission_control_actions_supported MUST contain ${a}`);
    for (const a of actions) if (!ACTIONS.includes(a)) err(`action ${a} is not defined`);
  },
  "fragment": (o, err) => {
    for (const k of Object.keys(o)) if (k !== "replacement_s256") err(`fragment member ${k} is not a defined request member`);
    if ("replacement_s256" in o && !S256.test(o.replacement_s256)) err("replacement_s256 is not an unpadded base64url SHA-256 digest");
  },
};

const REQUIRED_KINDS = ["status-request", "status-response", "terminate-request", "terminate-response", "tree-request", "tree-response", "metadata"];

export function validate(text) {
  const errors = [];
  const seen = new Set();
  for (const ex of extractExamples(text)) {
    const where = `line ${ex.line} (${ex.heading})`;
    const parsed = parse(ex.raw);
    if (!parsed) { errors.push(`${where}: example is not valid JSON`); continue; }
    const kind = classify(parsed.value, ex.heading, parsed.fragment);
    if (!kind) { errors.push(`${where}: example matches no known operation`); continue; }
    seen.add(kind);
    CHECKS[kind](parsed.value, (msg) => errors.push(`${where} [${kind}]: ${msg}`));
  }
  for (const k of REQUIRED_KINDS) if (!seen.has(k)) errors.push(`no ${k} example found`);
  return { errors, seen: [...seen] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const file = process.argv[2] || path.join(ROOT, DRAFT);
  const { errors, seen } = validate(fs.readFileSync(file, "utf8"));
  if (errors.length) {
    console.error(`aauth-management-examples check FAILED with ${errors.length} finding(s):`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`aauth-management-examples check OK: ${seen.length} example kinds validated.`);
}
