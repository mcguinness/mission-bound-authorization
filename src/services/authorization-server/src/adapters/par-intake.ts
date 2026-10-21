/**
 * @spec mission#submission-processing (#1411): the intake for a pushed
 * authorization request carrying `mission_intent`, run before oidc-provider
 * parses it.
 *
 * oidc-provider 9.10.0 runs its RAR check (lib/shared/check_rar.js) before
 * the `extraParams` validators (lib/actions/authorization/index.js,
 * `checkRar` before `checkExtraParams`), so a malformed `authorization_details`
 * proposal would be refused before the Submission envelope and the Intent are
 * validated, against the Submission Processing Order (steps 1 and 2 before
 * step 3). The intake lifts the proposal off the form; the `mission_intent`
 * validator restores it after steps 1 and 2 and runs checkRar's own checks
 * there, so client authentication still precedes every Mission refusal.
 *
 * The intake reads each parameter as the provider does: present only when
 * non-empty (lib/helpers/params.js reads `params[prop] || undefined`). Only a
 * request with one present `mission_intent`, one present
 * `authorization_details` and no present `request` is changed. Any other
 * request, including one that repeats a parameter, passes through for the
 * provider's own handling, so a proposal beside an empty `mission_intent`
 * stays with the provider's own RAR check.
 *
 * The same trades the device intake makes (device-authorization.ts): the
 * provider reads the already-read form from `ctx.request.body`
 * (lib/shared/selective_body.js) and warns once that it did, and a body over
 * the provider's own bound is refused here as the provider would refuse it.
 *
 * @spec mission#submission-via-par (#1503): the Request Object carriage. The
 * provider drops every parameter outside a pushed Request Object
 * (lib/actions/authorization/strip_outside_jar_params.js) before any hook
 * runs, so the intake records a present `mission_intent` beside a present
 * `request`, and the Request Object hook ({@link requestObjectIntake}) refuses
 * it after client authentication. The provider also reads a Request Object's
 * claims with JSON.parse and turns an object claim into `String(value)`
 * (lib/actions/authorization/process_request_object.js), so the hook
 * re-parses the signed payload strictly, refusing duplicate member names,
 * reads the claim's own JSON value from it, and keeps that value's
 * serialization for the `mission_intent` validator.
 *
 * @spec mission#submission-processing (#1512): the provider's RAR check runs
 * on a proposal inside a Request Object before the `extraParams` validators,
 * and the intake cannot lift it, since the object is signed. The hook runs
 * before that check, so it validates the Submission envelope and the Intent
 * (steps 1 and 2) there; the validator repeats them and runs the later steps.
 */

import type { IncomingMessage } from "node:http";
import { parse as parseForm } from "node:querystring";
import { DuplicateMemberError, type JsonValue, parseStrictJson } from "@mission/core";
import { errors, type KoaContextWithOIDC } from "oidc-provider";
import { readForm } from "./device-authorization.js";

/** oidc-provider 9.10.0's default pushed authorization request route. */
export const PAR_PATH = "/request";

/**
 * The provider's router is neither case-sensitive nor strict about a trailing
 * slash, so the intake recognizes the route the way the router does.
 */
function isParPath(path: string): boolean {
  return path.replace(/\/+$/, "").toLowerCase() === PAR_PATH;
}

/** What the intake lifted off one pushed authorization request. */
export interface ParIntake {
  /** The submitted `authorization_details` proposal. */
  proposal: string;
}

const intakes = new WeakMap<IncomingMessage, ParIntake>();

/** Pushed requests that carried a `mission_intent` beside a Request Object. */
const outsideRequestObject = new WeakSet<IncomingMessage>();

/** What the hook read from this request's client-signed Request Object. */
interface RequestObjectIntake {
  /** The serialization of the `mission_intent` claim's value; undefined when the object carries none. */
  submission: string | undefined;
}

const requestObjects = new WeakMap<IncomingMessage, RequestObjectIntake>();

/** One value of the parameter, present as the provider reads it; undefined otherwise. */
function single(v: string | string[] | undefined): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

/** Whether the provider reads the parameter as present (a repeated one counts). */
function present(v: string | string[] | undefined): boolean {
  return Array.isArray(v) || (v !== undefined && v !== "");
}

export async function pushedRequestIntake(ctx: KoaContextWithOIDC, next: () => Promise<void>): Promise<void> {
  if (ctx.method !== "POST" || !isParPath(ctx.path) || !ctx.is("application/x-www-form-urlencoded")) {
    return next();
  }
  const raw = await readForm(ctx.req);
  if (raw === undefined) {
    ctx.status = 400;
    ctx.set("cache-control", "no-store");
    ctx.body = { error: "invalid_request", error_description: "failed to parse the request body" };
    return;
  }
  const form = parseForm(raw);
  const proposal = single(form.authorization_details);
  if (single(form.mission_intent) !== undefined && proposal !== undefined && !present(form.request)) {
    delete form.authorization_details;
    intakes.set(ctx.req, { proposal });
  }
  if (present(form.request) && present(form.mission_intent)) {
    outsideRequestObject.add(ctx.req);
  }
  (ctx.request as unknown as { body?: unknown }).body = form;
  await next();
}

/** The proposal the intake lifted off this request, removed once read. */
export function takeParIntake(req: IncomingMessage): ParIntake | undefined {
  const intake = intakes.get(req);
  intakes.delete(req);
  return intake;
}

/**
 * @spec mission#submission-via-par (#1503): the provider's
 * `features.requestObjects.assertJwtClaimsAndHeader` hook (9.10.0), run
 * inside its Request Object processing after client authentication, after the
 * algorithm and `iss`, `aud`, `exp` and `client_id` checks, and before the
 * signature is verified and the RAR check runs. It replaces the provider's
 * default hook, whose required-claim checks serve FAPI profiles and CIBA,
 * neither enabled here.
 *
 * - A Request Object is accepted only at PAR, and read again from the pushed
 *   request at the authorization endpoint; any other route, such as the
 *   device authorization endpoint, refuses it `request_not_supported`, as it
 *   did before Request Objects were enabled.
 * - A `mission_intent` the push carried outside the Request Object is refused
 *   `invalid_request` (the Request Object is authoritative).
 * - A client-signed payload is re-parsed strictly: a duplicate member name
 *   anywhere in it is refused `invalid_request`, as a duplicate in a form
 *   value of `mission_intent` is. The provider's own pushed request object
 *   for a form push (`alg` none, built after the form passed this intake)
 *   carries the form's values and is not read.
 * - A `mission_intent` claim must be a JSON object, the Submission envelope
 *   itself ({@link requestObjectSubmission}), and `validateSubmission` checks
 *   the envelope and the Intent before the RAR check (#1512). These checks
 *   only refuse; the validator acts on the value once the signature is
 *   verified.
 */
export function requestObjectIntake(validateSubmission: (submission: string) => void) {
  return (ctx: KoaContextWithOIDC, _claims: unknown, header: Record<string, unknown>): void => {
    const route = ctx.oidc.route;
    if (route !== "pushed_authorization_request" && route !== "authorization") {
      throw new errors.RequestNotSupported();
    }
    if (route === "pushed_authorization_request" && outsideRequestObject.has(ctx.req)) {
      outsideRequestObject.delete(ctx.req);
      throw new errors.InvalidRequest("mission_intent must not be submitted outside the Request Object");
    }
    if (header.alg === "none") return;
    const jws = (ctx.oidc.params as { request?: unknown } | undefined)?.request;
    const segment = typeof jws === "string" ? jws.split(".")[1] : undefined;
    let payload: JsonValue;
    try {
      payload = parseStrictJson(Buffer.from(segment ?? "", "base64url").toString("utf8"));
    } catch (e) {
      if (e instanceof DuplicateMemberError) {
        throw new errors.InvalidRequest(`Request Object payload: ${e.message}`);
      }
      throw new errors.InvalidRequestObject("could not parse Request Object");
    }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      throw new errors.InvalidRequestObject("could not parse Request Object");
    }
    const submission = requestObjectSubmission(payload);
    if (submission !== undefined) validateSubmission(submission);
    requestObjects.set(ctx.req, { submission });
  };
}

/**
 * @spec mission#submission-via-par (#1503): the Submission envelope a Request
 * Object carries, as the serialization a form value carries; undefined when
 * the object has no `mission_intent` claim. A claim whose value is not a JSON
 * object is refused `invalid_request`.
 */
function requestObjectSubmission(payload: Record<string, JsonValue>): string | undefined {
  if (!Object.hasOwn(payload, "mission_intent")) return undefined;
  const claim = payload.mission_intent;
  if (claim === null || typeof claim !== "object" || Array.isArray(claim)) {
    throw new errors.InvalidRequest(
      "mission_intent in a Request Object must be a JSON object, the Submission envelope itself, not its serialization",
    );
  }
  return JSON.stringify(claim);
}

/**
 * What the hook read from this request's client-signed Request Object,
 * removed once read; undefined for a request that carried none, including a
 * form push redeemed at the authorization endpoint.
 */
export function takeRequestObjectIntake(req: IncomingMessage): RequestObjectIntake | undefined {
  const intake = requestObjects.get(req);
  requestObjects.delete(req);
  return intake;
}
