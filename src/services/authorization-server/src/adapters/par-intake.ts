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
 */

import type { IncomingMessage } from "node:http";
import { parse as parseForm } from "node:querystring";
import { type KoaContextWithOIDC } from "oidc-provider";
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
  (ctx.request as unknown as { body?: unknown }).body = form;
  await next();
}

/** The proposal the intake lifted off this request, removed once read. */
export function takeParIntake(req: IncomingMessage): ParIntake | undefined {
  const intake = intakes.get(req);
  intakes.delete(req);
  return intake;
}
