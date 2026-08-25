/**
 * The `transaction_authorization_endpoint` over real HTTP. An authenticated
 * client submits the resource's signed challenge with the Mission-bound access
 * token as an RFC 8693 `subject_token`, proving possession of the challenge's
 * `cnf` key; initial validation only ADMITS a workflow, and the authorization
 * result is the fresh decision at completion.
 */

import { type Server } from "node:http";
import { AccessRequestService, txnTaskId } from "@mission/access-request";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  TXN_TOKEN_PROHIBITED_CLAIMS,
  txnApprovalBindingDigest,
  type TxnApprovalBinding,
} from "@mission/core";
import {
  buildAuthorizationServer,
  MISSION_TXN_TOKEN_TYP,
  TXN_CHALLENGE_TYP,
  type AuthorityEntry,
  type BuiltAs,
  type ChallengeIssuers,
} from "../src/index.js";
import { missionResourceAccessProfile, OperationProfileRegistry } from "../src/index.js";
import { newDpopProofReplay } from "../src/adapters/dpop-replay.js";
import {
  handleTransactionAuthorization,
  newTxnWorkflows,
  type SubjectNamespacePolicy,
  type TxnAuthorizationDeps,
} from "../src/adapters/transaction-authorization.js";
import type { TxnWorkflowStore } from "../src/kernel/txn-workflow-store.js";
import { Readable } from "node:stream";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createLocalJWKSet, decodeJwt, type JWK } from "jose";

const PORT = 14450;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
/** The pending workflow's own lifetime, independent of any challenge exp. */
const WORKFLOW_LIFETIME_S = 600;
/** The deployment maximum for an issued transaction token. */
const MAX_TOKEN_LIFETIME_S = 300;
/** A second accepted Challenge-Issuing Resource the subject_token is NOT for. */
const OTHER_RESOURCE = "http://localhost:4499/mcp";
/** @spec txn-authorization#offline-verification — `txn` is unique within a
 *  Challenge-Issuing Resource, so the ARS task id carries the resource too. */
const taskFor = (txn: string, resource: string = RESOURCE): string => txnTaskId(resource, txn);

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let ars: AccessRequestService;
let clientKey: CryptoKey;
let dpopKeys: DpopKeys;
let dpopJkt: string;
let rsTxnKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
/** The agent client's PUBLIC assertion key, for a deps built in-test. */
let agentClientPublicJwk: JWK;
/** @spec txn-authorization#resource-challenge — the deployment's registry, so a
 *  run can supersede a profile version mid-suite. */
const operationProfiles = new OperationProfileRegistry();
let baseToken = "";
let missionId = "";
let missionClaim: Record<string, unknown> = {};
/** `txn` values the deployment's fresh decision refuses. */
const policyDeniesTxns = new Set<string>();
/** Every `txn` the fresh decision was asked about (it must run before issuance). */
const freshDecisionCalls: string[] = [];
/** What the fresh decision was handed, so a test can read the pinned snapshot. */
const freshDecisionInputs: { txn: string; operationType: string; parameterDigest: string }[] = [];
/**
 * @spec txn-authorization#applicability — the approval basis the TAS computed
 * at step 4 for every approval it opened.
 */
const openedApprovals: { txn: string; requires_action_approval: boolean }[] = [];
/** The transaction binding (and its digest) every opened approval carries. */
const openedBindings: { txn: string; binding: TxnApprovalBinding; digest: string }[] = [];
/** The basis recorded for one `txn` (undefined when no approval was opened). */
const approvalBasisFor = (txn: string): boolean | undefined =>
  openedApprovals.find((o) => o.txn === txn)?.requires_action_approval;
/**
 * Per-task `approved_until` the ARS reports, so a run can make the approval's
 * own validity, or something else, the minimum term of the token's exp bound.
 */
const approvalOverrides = new Map<string, string>();
/** Per-task `approved_at` the ARS reports (grant-time sanity vectors). */
const approvedAtOverrides = new Map<string, string>();
/**
 * @spec txn-authorization#challenge-redemption step 5 — per-`txn` mutations of
 * the transaction binding the approval is OPENED under, so a run can produce an
 * approval genuinely adjudicated for a DIFFERENT transaction and prove the TAS
 * refuses it at completion.
 */
const bindingMutations = new Map<string, (b: TxnApprovalBinding) => TxnApprovalBinding>();
/**
 * @spec txn-authorization#challenge-redemption step 7 — a hook that runs INSIDE
 * the deployment's fresh decision for one `txn`, so a run can land a real state
 * change in the window between the decision's inputs and the mint.
 */
const freshDecisionHooks = new Map<string, () => void | Promise<void>>();

/**
 * Stand in for the Challenge-Issuing Resource: sign a challenge carrying every
 * REQUIRED claim, including this profile's `mission`, `parameter_digest` and
 * `cnf` (which a real resource derives from the request and the verified
 * Mission-bound access token).
 */
async function signChallenge(
  claims: {
    txn: string;
    authorization_details: unknown[];
    iss: string;
    aud: string;
    reason: string;
    parameter_digest: string;
    mission?: Record<string, unknown>;
    cnf?: { jkt: string };
    lifetimeSeconds?: number;
    act?: unknown;
  },
  key: CryptoKey,
  kid: string,
): Promise<string> {
  return new SignJWT({
    txn: claims.txn,
    authorization_details: claims.authorization_details,
    reason: claims.reason,
    parameter_digest: claims.parameter_digest,
    mission: claims.mission ?? missionClaim,
    cnf: claims.cnf ?? { jkt: dpopJkt },
    ...(claims.act !== undefined ? { act: claims.act } : {}),
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: TXN_CHALLENGE_TYP })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${claims.lifetimeSeconds ?? 300}s`)
    .sign(key);
}

const cookies = new Map<string, string>();
function cookieHeader(jar: Map<string, string> = cookies): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response, jar: Map<string, string> = cookies): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(
  htu: string,
  htm: string,
  keys: DpopKeys = dpopKeys,
  extra: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function tokenRequest(params: Record<string, string>, keys: DpopKeys = dpopKeys): Promise<Response> {
  const htu = `${ISSUER}/token`;
  let res = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", keys) },
    body: new URLSearchParams({
      ...params,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) {
    res = await fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", keys, { nonce }) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  }
  return res;
}

/**
 * Full PAR -> approval -> token dance yielding a base DPoP-bound mission token.
 * `constraints` overrides the proposed entry's constraints, so a run can put the
 * Mission's own authority under `requires_action_approval`.
 */
async function issueBaseMissionToken(
  keys: DpopKeys = dpopKeys,
  jar: Map<string, string> = cookies,
  constraints: Record<string, unknown> = {
    max_amount: { amount: "500.00", currency: "USD" },
    vendors: ["acme"],
  },
): Promise<{ token: string; missionId: string }> {
  const verifier = "txn-endpoint-verifier-0123456789-0123456789-01234";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  // @spec mission#submission-via-par — the wire value is the Submission envelope.
  const intent = JSON.stringify({
    intent: {
      goal: "Pay Acme invoices and send remittance",
      target_resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    },
  });
  const authorizationDetails = JSON.stringify([
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:remittance.send"],
      constraints,
    },
  ]);
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: intent,
      authorization_details: authorizationDetails,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const { request_uri } = (await par.json()) as { request_uri: string };

  const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
  let res = await fetch(authUrl, { redirect: "manual" });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;

  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const tok = await tokenRequest(
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: RESOURCE,
    },
    keys,
  );
  const body = (await tok.json()) as { access_token: string };
  const claims = JSON.parse(Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString()) as {
    mission: { id: string };
  };
  return { token: body.access_token, missionId: claims.mission.id };
}

/**
 * @spec txn-authorization#challenge-redemption — POST to the transaction
 * endpoint: authenticated client, a DPoP proof of the challenge's `cnf` key
 * bound to this endpoint, and either an initial submission
 * (`transaction_challenge` + `subject_token`) or a poll
 * (`transaction_authorization_id`).
 */
async function postTransaction(
  payload: Record<string, string>,
  opts: {
    keys?: DpopKeys;
    assertion?: string;
    /** The `client_id` parameter presented alongside the assertion. */
    clientId?: string;
    /** Present the assertion with no `client_id` parameter at all. */
    omitClientId?: boolean;
    omitClientAuth?: boolean;
  } = {},
): Promise<Response> {
  const htu = `${ISSUER}/transaction`;
  const auth = opts.omitClientAuth
    ? {}
    : {
        ...(opts.omitClientId ? {} : { client_id: opts.clientId ?? "ap-agent" }),
        client_assertion: opts.assertion ?? (await clientAssertion()),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      };
  return fetch(htu, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: await dpopProof(htu, "POST", opts.keys ?? dpopKeys),
    },
    body: new URLSearchParams({ ...auth, ...payload }).toString(),
  });
}

/**
 * Drive the endpoint DIRECTLY, with a caller-supplied `deps`. The AS's own
 * `authorization_code` path mints only local subjects, so the Origin Principal
 * profile's credential shape (local `sub` + issuer-qualified
 * `mission.subject`, exactly as the cross-org grant mints one) is presented
 * here against a deps whose `publicJwks` the test holds the private half of.
 * Everything else -- client authentication, the DPoP proof, the real kernel and
 * the real ARS -- is unchanged.
 */
async function callTransactionEndpoint(
  deps: TxnAuthorizationDeps,
  workflows: TxnWorkflowStore,
  params: Record<string, string>,
): Promise<{ status: number; body: unknown }> {
  const htu = `${ISSUER}/transaction`;
  const encoded = new URLSearchParams({
    client_id: "ap-agent",
    client_assertion: await clientAssertion(),
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    ...params,
  }).toString();
  const proof = await dpopProof(htu, "POST");
  const ctx = {
    method: "POST",
    path: "/transaction",
    status: 0,
    body: undefined as unknown,
    req: Readable.from([Buffer.from(encoded, "utf8")]) as unknown as IncomingMessage,
    res: {} as ServerResponse,
    set: () => {},
    get: (name: string) =>
      name.toLowerCase() === "dpop"
        ? proof
        : name.toLowerCase() === "content-type"
          ? "application/x-www-form-urlencoded"
          : "",
  };
  await handleTransactionAuthorization(deps, ctx, workflows);
  return { status: ctx.status, body: ctx.body };
}

/** An initial submission carrying the Mission-bound access token as subject_token. */
async function submit(
  challenge: string,
  opts: { token?: string; keys?: DpopKeys } = {},
): Promise<Response> {
  return postTransaction(
    {
      transaction_challenge: challenge,
      subject_token: opts.token ?? baseToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    },
    { ...(opts.keys ? { keys: opts.keys } : {}) },
  );
}

beforeAll(async () => {
  // RS txn-challenge signing key (its txn_challenge_jwks_uri); the AS is
  // configured with its public half.
  rsTxnKeys = await generateKeyPair("ES256", { extractable: true });
  const rsTxnPub = { ...(await exportJWK(rsTxnKeys.publicKey)), kid: "rs-txn", alg: "ES256" };

  // The AS-owned ARS (D37). No PDP binding is needed for the AS-vouched path,
  // so pdpJwks is empty; adjudicate uses the approval key.
  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  ars = new AccessRequestService({
    pdpJwks: { keys: [] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
    issuer: "https://ars.test",
    approvalAudience: "https://pdp.test",
    approvalTtlSeconds: 300,
  });

  const challengeIssuers: ChallengeIssuers = new Map([
    [RESOURCE, { jwks: createLocalJWKSet({ keys: [rsTxnPub as JWK] }), algs: ["ES256"] }],
    // A SECOND accepted resource, so an audience mismatch can be exercised
    // against a challenge whose issuer the TAS does accept.
    [OTHER_RESOURCE, { jwks: createLocalJWKSet({ keys: [rsTxnPub as JWK] }), algs: ["ES256"] }],
  ]);
  // The endpoint's view of the ARS. It records the approval BASIS the TAS
  // computed at step 4, and lets a run pin an approval's `approved_until` so a
  // chosen term of the token's exp bound is the minimum. Everything else is the
  // real service: the suite adjudicates through `ars` directly.
  const txnArs = {
    openForTxn: (input: {
      txn: string;
      resource: string;
      missionId: string;
      action: string;
      parameter_digest: string;
      subject: string;
      requires_action_approval: boolean;
      binding: TxnApprovalBinding;
      binding_digest: string;
    }) => {
      openedApprovals.push({ txn: input.txn, requires_action_approval: input.requires_action_approval });
      openedBindings.push({ txn: input.txn, binding: input.binding, digest: input.binding_digest });
      // A run can make the approval be opened against a DIFFERENT transaction
      // than the one the workflow pinned: the approver still adjudicates a real
      // task, and the TAS must refuse to rely on it at completion.
      const mutate = bindingMutations.get(input.txn);
      if (!mutate) return ars.openForTxn(input);
      const mutated = mutate(input.binding);
      return ars.openForTxn({ ...input, binding: mutated, binding_digest: txnApprovalBindingDigest(mutated) });
    },
    getTask: (taskId: string) => {
      const task = ars.getTask(taskId);
      if (!task?.approval) return task;
      const until = approvalOverrides.get(taskId);
      const at = approvedAtOverrides.get(taskId);
      if (!until && !at) return task;
      return {
        ...task,
        approval: {
          ...task.approval,
          ...(until ? { approved_until: until } : {}),
          ...(at ? { approved_at: at } : {}),
        },
      };
    },
  };

  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    transactionAuthorization: {
      challengeIssuers,
      ars: txnArs,
      // @spec txn-authorization#resource-challenge — the Operation Profiles
      // this deployment recognizes. BOTH accepted resources challenge with the
      // family's `mission_resource_access` entry; a run can supersede a version
      // to prove drift behaves.
      operationProfiles: operationProfiles
        .register(RESOURCE, missionResourceAccessProfile())
        .register(OTHER_RESOURCE, missionResourceAccessProfile()),
      workflowLifetimeSeconds: WORKFLOW_LIFETIME_S,
      maxTokenLifetimeSeconds: MAX_TOKEN_LIFETIME_S,
      // @spec txn-authorization#challenge-redemption step 7 — a deployment
      // entitlement/policy decision, run fresh at completion. The suite drives
      // it through `policyDeniesTxns` to prove an approved workflow still
      // refuses when a current input no longer holds.
      freshDecision: async (input) => {
        freshDecisionCalls.push(input.txn);
        freshDecisionInputs.push({
          txn: input.txn,
          operationType: input.operationType,
          parameterDigest: input.parameterDigest,
        });
        await freshDecisionHooks.get(input.txn)?.();
        return policyDeniesTxns.has(input.txn)
          ? { decision: "deny", reason: "entitlement_denied" }
          : { decision: "permit" };
      },
    },
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  {
    const { d: _private, ...pub } = as.agentClientJwk as Record<string, unknown>;
    agentClientPublicJwk = pub as JWK;
  }
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));

  const base = await issueBaseMissionToken();
  baseToken = base.token;
  missionId = base.missionId;
  missionClaim = decodeJwt(baseToken).mission as Record<string, unknown>;
});

afterAll(() => {
  asServer?.close();
});

describe("transaction endpoint redemption (@spec txn-authorization#challenge-redemption)", () => {
  it("advertises the transaction endpoint in Authorization Server metadata", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.transaction_authorization_endpoint).toBe(`${ISSUER}/transaction`);
  });

  it("admits a workflow, pends on poll, then on approval issues a conforming transaction token", async () => {
    // Requested authority is a genuine subset of the active Mission (the RS
    // read the Mission's Authority Set from the base token).
    const record = as.kernel.get(missionId);
    expect(record).toBeDefined();
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set
      // @spec txn-authorization#resource-challenge — a challenge names ONE
      // operation, so the entry it carries names exactly one action.
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
    expect(requested.length).toBeGreaterThan(0);

    const txn = "txn_http_1";
    const parameter_digest = "sha-256:aa11bb22cc33dd44";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "over-cap remittance requires approval",
        parameter_digest,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );

    // §4.2: the challenge is typ txn-authz-challenge+jwt, carries the txn as a
    // body claim (not sub), and a jti is REQUIRED.
    const chHeader = JSON.parse(Buffer.from(challenge.split(".")[0] as string, "base64url").toString());
    const chBody = JSON.parse(Buffer.from(challenge.split(".")[1] as string, "base64url").toString());
    expect(chHeader.typ).toBe("txn-authz-challenge+jwt");
    expect(chBody.txn).toBe(txn);
    expect(typeof chBody.jti).toBe("string");
    expect(chBody.sub).toBeUndefined();

    // Initiation: the client presents the challenge ONCE -> a continuation
    // handle, expires_in, interval; and NO access_token yet.
    const initRes = await submit(challenge);
    const initBody = (await initRes.json()) as {
      transaction_authorization_id?: string;
      expires_in?: number;
      interval?: number;
      access_token?: string;
    };
    expect(initRes.status, JSON.stringify(initBody)).toBe(200);
    expect(initBody.transaction_authorization_id).toMatch(/^txa_/);
    // @spec txn-authorization#two-phase-expiry — the workflow's OWN lifetime,
    // not the challenge's remaining admission window.
    expect(initBody.expires_in).toBe(WORKFLOW_LIFETIME_S);
    expect(initBody.interval).toBe(5);
    expect(initBody.access_token).toBeUndefined();
    const txaId = initBody.transaction_authorization_id as string;

    // Poll WITH the handle before approval -> 400 authorization_pending (§5.3,
    // RFC 8628-shaped), no token. The client already has interval/expires_in
    // from initiation, so the pending body stays minimal.
    const pollPending = await postTransaction({ transaction_authorization_id: txaId });
    const pendingBody = (await pollPending.json()) as { error?: string; access_token?: string };
    expect(pollPending.status).toBe(400);
    expect(pendingBody.error).toBe("authorization_pending");
    expect(pendingBody.access_token).toBeUndefined();

    // Bob approves via the AS's ARS (endpoint ARS == injected ARS).
    const queued = ars.pending();
    expect(queued.length).toBe(1);
    const approval = await ars.adjudicate(queued[0]?.id as string, "approve", "bob");
    expect(approval).not.toBeNull();
    const approvedUntil = (approval as { approved_until: string }).approved_until;

    // Poll WITH the handle after approval -> 200 with the txn-token.
    const tokenRes = await postTransaction({ transaction_authorization_id: txaId });
    const tokenBody = (await tokenRes.json()) as {
      access_token?: string;
      token_type?: string;
      expires_in?: number;
      txn?: string;
      authorization_details?: unknown;
    };
    expect(tokenRes.status, JSON.stringify(tokenBody)).toBe(200);
    expect(tokenBody.token_type).toBe("DPoP");
    // A standard OAuth token response: no bespoke members ride alongside it.
    expect(tokenBody.txn).toBeUndefined();
    expect(tokenBody.expires_in).toBeGreaterThan(0);
    // The RFC 9396 response parameter carries the EXACT permitted set.
    expect(tokenBody.authorization_details).toEqual(requested);

    // Verify the TAS-signed transaction token against the AS /jwks.
    const jwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
    const { payload, protectedHeader } = await jwtVerify(tokenBody.access_token as string, jwks, {
      issuer: ISSUER,
      audience: RESOURCE,
      typ: MISSION_TXN_TOKEN_TYP,
    });
    expect(protectedHeader.typ).toBe(MISSION_TXN_TOKEN_TYP);
    // @spec txn-authorization#transaction-token — the REQUIRED claim set.
    expect(payload.txn).toBe(txn);
    expect(typeof payload.jti).toBe("string");
    // aud is a SINGLETON string, exactly the challenge's iss. Never a list.
    expect(payload.aud).toBe(RESOURCE);
    expect(Array.isArray(payload.aud)).toBe(false);
    // sub is the verified effective subject, never the Approver (bob).
    expect(payload.sub).toBe("alice");
    expect(payload.client_id).toBe("ap-agent");
    expect(payload.parameter_digest).toBe(parameter_digest);
    // ...and it is identical to the token's own claim, never wider.
    expect(payload.authorization_details).toEqual(tokenBody.authorization_details);
    expect((payload.cnf as { jkt: string }).jkt).toBe(dpopJkt);
    expect((payload.mission as { id: string }).id).toBe(missionId);
    expect((payload.mission as { predecessor?: string }).predecessor).toBeUndefined();
    // The MUST NOT list: no approval object, no single_use bearer flag, no raw
    // parameters or rendered text, no refresh token or token-exchange input.
    for (const prohibited of TXN_TOKEN_PROHIBITED_CLAIMS) {
      expect(payload[prohibited], prohibited).toBeUndefined();
    }
    // @spec txn-authorization#transaction-token — never later than the earliest
    // of the approval's validity and the deployment maximum, and NEVER bounded
    // by the already-consumed challenge exp.
    expect(payload.exp as number).toBeLessThanOrEqual(Math.floor(Date.parse(approvedUntil) / 1000));
    expect(payload.exp as number).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("refuses a challenge whose authority widens beyond the Mission", async () => {
    // Same action, but a cap above the Mission's max_amount -> not a subset.
    const widen: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:remittance.send"],
        constraints: { max_amount: { amount: "999999.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const challenge = await signChallenge(
      {
        txn: "txn_http_widen",
        authorization_details: widen,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "attempt to widen",
        parameter_digest: "sha-256:ffffffffffffffff",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("refuses a poll for a transaction_authorization_id it never admitted", async () => {
    const res = await postTransaction({ transaction_authorization_id: "txa_does-not-exist" });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("refuses a poll from a client the workflow was not admitted for", async () => {
    // Initiate a fresh handle, bound to the real base token's DPoP key.
    const record = as.kernel.get(missionId);
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set
      // @spec txn-authorization#resource-challenge — a challenge names ONE
      // operation, so the entry it carries names exactly one action.
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
    const challenge = await signChallenge(
      {
        txn: "txn_http_cnf",
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "cnf-binding test",
        parameter_digest: "sha-256:cccccccccccccccc",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const initBody = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    const txaId = initBody.transaction_authorization_id;

    // A DIFFERENT client: a second base token minted under a different DPoP key.
    const otherKeys = await generateKeyPair("ES256", { extractable: true });
    const other = await issueBaseMissionToken(otherKeys, new Map());

    // Polling the handle with that client's token + DPoP passes the base-token
    // DPoP check but fails the handle-to-client binding -> 403 invalid_token.
    const res = await postTransaction({ transaction_authorization_id: txaId }, { keys: otherKeys });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("reports a denied approval as access_denied so the client stops polling", async () => {
    const record = as.kernel.get(missionId);
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set
      // @spec txn-authorization#resource-challenge — a challenge names ONE
      // operation, so the entry it carries names exactly one action.
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
    const txn = "txn_http_denied";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "deny-path test",
        parameter_digest: "sha-256:dddddddddddddddd",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const initBody = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    expect(initBody.transaction_authorization_id).toMatch(/^txa_/);

    // Bob denies the AS-vouched task (the id is resource-scoped: taskFor).
    const denied = await ars.adjudicate(taskFor(txn), "deny", "bob");
    expect(denied).toBeNull();

    // Poll -> 400 access_denied, terminal.
    const res = await postTransaction({ transaction_authorization_id: initBody.transaction_authorization_id });
    const body = (await res.json()) as { error?: string; access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.access_token).toBeUndefined();
  });
});

describe("two-phase expiry and idempotency (@spec txn-authorization#two-phase-expiry)", () => {
  const requestedEntry = (): AuthorityEntry[] => {
    const record = as.kernel.get(missionId) as { authority_set: AuthorityEntry[] };
    return record.authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
  };

  const challengeFor = async (txn: string, over: Record<string, unknown> = {}) =>
    signChallenge(
      {
        txn,
        authorization_details: requestedEntry(),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        ...over,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );

  it("returns the existing workflow when the same challenge is submitted again", async () => {
    const challenge = await challengeFor("txn_repeat_submit");
    const first = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    const second = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    expect(first.transaction_authorization_id).toMatch(/^txa_/);
    expect(second.transaction_authorization_id).toBe(first.transaction_authorization_id);
    // Exactly one approval task was opened for the one admitted challenge.
    expect(ars.pending().filter((t) => t.id === taskFor("txn_repeat_submit"))).toHaveLength(1);
  });

  it("opens exactly one approval when the same challenge is submitted concurrently", async () => {
    const challenge = await challengeFor("txn_concurrent_submit");
    const bodies = (await Promise.all(
      (await Promise.all([submit(challenge), submit(challenge), submit(challenge)])).map((r) => r.json()),
    )) as { transaction_authorization_id?: string }[];

    // The admission insert IS the reservation and runs before the ARS is
    // invoked, so the three submissions resolve to ONE workflow and only the
    // one that won it opened an approval.
    const ids = new Set(bodies.map((b) => b.transaction_authorization_id));
    expect(ids.size, JSON.stringify(bodies)).toBe(1);
    expect(openedApprovals.filter((o) => o.txn === "txn_concurrent_submit")).toHaveLength(1);
    expect(ars.pending().filter((t) => t.id === taskFor("txn_concurrent_submit"))).toHaveLength(1);
  });

  it("refuses a challenge that expired before it was submitted, rather than reviving one", async () => {
    const challenge = await challengeFor("txn_late", { lifetimeSeconds: -60 });
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("expired_challenge");
  });

  it("still issues when the approval lands after the challenge expired but inside the workflow lifetime", async () => {
    // A challenge whose admission window is seconds wide: it admits now, and is
    // long expired by the time the approver acts.
    const challenge = await challengeFor("txn_slow_approval", { lifetimeSeconds: 2 });
    const init = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    await new Promise((r) => setTimeout(r, 2500));

    // The challenge would no longer admit anything now...
    const late = await submit(challenge);
    expect((await late.json()).error).toBe("invalid_grant");

    // ...but the workflow it already admitted still completes.
    const approval = await ars.adjudicate(taskFor("txn_slow_approval"), "approve", "bob");
    expect(approval).not.toBeNull();
    const res = await postTransaction({
      transaction_authorization_id: init.transaction_authorization_id,
    });
    const body = (await res.json()) as { access_token?: string; expires_in?: number };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.access_token).toBeTruthy();
    // The token's lifetime comes from the workflow and the approval, never from
    // the already-consumed challenge exp.
    expect(body.expires_in as number).toBeGreaterThan(2);
  });

  it("returns the same token, under the same jti, on every poll after the decision", async () => {
    const challenge = await challengeFor("txn_stable_result");
    const init = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    await ars.adjudicate(taskFor("txn_stable_result"), "approve", "bob");
    const first = (await (
      await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
    ).json()) as { access_token: string };
    const second = (await (
      await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
    ).json()) as { access_token: string };
    expect(second.access_token).toBe(first.access_token);
    expect(decodeJwt(second.access_token).jti).toBe(decodeJwt(first.access_token).jti);
  });

  it("bounds the token by the earliest live term, never by the challenge exp", async () => {
    const subjectTokenExpS = decodeJwt(baseToken).exp as number;

    // Run 1: an approval that outlives nothing. `approved_until` is the
    // earliest of the four terms, so it is what the token's exp equals.
    const approvedUntil = new Date(Date.now() + 20_000).toISOString();
    approvalOverrides.set(taskFor("txn_exp_approval"), approvedUntil);
    const short = await challengeFor("txn_exp_approval");
    const shortInit = (await (await submit(short)).json()) as { transaction_authorization_id: string };
    await ars.adjudicate(taskFor("txn_exp_approval"), "approve", "bob");
    const shortBody = (await (
      await postTransaction({ transaction_authorization_id: shortInit.transaction_authorization_id })
    ).json()) as { access_token: string };
    const shortClaims = decodeJwt(shortBody.access_token);
    expect(shortClaims.exp).toBe(Math.floor(Date.parse(approvedUntil) / 1000));
    expect(shortClaims.exp as number).toBeLessThan(subjectTokenExpS);

    // Run 2: the same operation under an approval that outlives everything.
    // A DIFFERENT term is now the earliest -- `subject_token`'s own validity --
    // and the token follows it rather than the approval or the deployment
    // maximum. Either way the already-consumed challenge exp never binds.
    const longUntil = new Date(Date.now() + 5_000_000).toISOString();
    approvalOverrides.set(taskFor("txn_exp_bound"), longUntil);
    const challenge = await challengeFor("txn_exp_bound");
    const init = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    await ars.adjudicate(taskFor("txn_exp_bound"), "approve", "bob");
    const body = (await (
      await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
    ).json()) as { access_token: string };
    const claims = decodeJwt(body.access_token);
    expect(claims.exp).toBe(subjectTokenExpS);
    expect(claims.exp as number).toBeLessThan(Math.floor(Date.parse(longUntil) / 1000));
    expect(claims.exp as number).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + MAX_TOKEN_LIFETIME_S);
    expect(claims.exp).not.toBe(decodeJwt(challenge).exp as number);
  });
});

describe("challenge trust boundaries (@spec txn-authorization#two-phase-expiry)", () => {
  it("refuses a challenge signed by another issuer's key under this resource's iss", async () => {
    const foreign = await generateKeyPair("ES256", { extractable: true });
    const record = as.kernel.get(missionId) as { authority_set: AuthorityEntry[] };
    const challenge = await signChallenge(
      {
        txn: "txn_cross_issuer",
        authorization_details: record.authority_set
          .filter((e) => e.actions.includes("payments:remittance.send"))
          .map((e) => ({ ...e, actions: ["payments:remittance.send"] })),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:cross-issuer",
      },
      foreign.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error_description).toContain("invalid_signature");
  });

  it("refuses a challenge from an issuer this TAS does not accept", async () => {
    const challenge = await signChallenge(
      {
        txn: "txn_unknown_issuer",
        authorization_details: [
          { type: "mission_resource_access", resource: "https://elsewhere.test/mcp", actions: ["x"] },
        ],
        iss: "https://elsewhere.test/mcp",
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:elsewhere",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error_description?: string };
    expect(body.error_description).toContain("unknown_issuer");
  });

  it("refuses an unauthenticated client and a proof of the wrong key", async () => {
    const challenge = await signChallenge(
      {
        txn: "txn_auth_guards",
        authorization_details: (as.kernel.get(missionId) as { authority_set: AuthorityEntry[] }).authority_set
          .filter((e) => e.actions.includes("payments:remittance.send"))
          .map((e) => ({ ...e, actions: ["payments:remittance.send"] })),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:auth-guards",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const unauth = await postTransaction(
      {
        transaction_challenge: challenge,
        subject_token: baseToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      },
      { omitClientAuth: true },
    );
    expect(unauth.status).toBe(401);
    expect((await unauth.json()).error).toBe("invalid_client");

    // A proof of a key the challenge never committed to.
    const otherKeys = await generateKeyPair("ES256", { extractable: true });
    const wrongKey = await submit(challenge, { keys: otherKeys });
    const body = (await wrongKey.json()) as { error?: string; error_description?: string };
    expect(wrongKey.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("same key");
  });
});

/**
 * @spec txn-authorization#challenge-redemption step 5, step 6 — the approval is
 * bound to the COMPLETE transaction, not to its parameters. `parameter_digest`
 * identifies the operation's parameters; the same parameters are reachable
 * under another Mission, principal, client or presenter key, so an approval
 * carrying only that digest would satisfy a transaction it was never granted
 * for.
 */
describe("approval bound to the whole transaction (@spec txn-authorization#challenge-redemption)", () => {
  /** Admit one challenge and return its handle and `txn`. */
  async function admitOne(
    txn: string,
    opts: { parameter_digest?: string } = {},
  ): Promise<{ txaId: string; status: number; body: Record<string, unknown> }> {
    const record = as.kernel.get(missionId);
    const requested = (record as { authority_set: AuthorityEntry[] }).authority_set
      // @spec txn-authorization#resource-challenge — a challenge names ONE
      // operation, so the entry it carries names exactly one action.
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "over-cap remittance requires approval",
        parameter_digest: opts.parameter_digest ?? `sha-256:${txn}`,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as Record<string, unknown>;
    return { txaId: String(body.transaction_authorization_id ?? ""), status: res.status, body };
  }

  it("carries the Mission, both identities, the client and the presenter key into the approval it opens", async () => {
    const txn = "txn_binding_shape";
    await admitOne(txn);
    const opened = openedBindings.find((b) => b.txn === txn);
    expect(opened).toBeDefined();
    const binding = (opened as { binding: TxnApprovalBinding }).binding;
    expect(binding.resource).toBe(RESOURCE);
    expect(binding.txn).toBe(txn);
    expect(binding.mission.id).toBe(missionId);
    expect(binding.operation_type).toBe("mission_resource_access");
    // The destination-local subject is bound; this fixture's Mission carries
    // no origin principal, so the Origin Principal profile's half is absent
    // rather than one identity standing in for the other.
    expect(binding.subject).toBe("alice");
    expect(binding.origin_principal).toBeUndefined();
    expect(binding.client_id).toBe("ap-agent");
    expect(binding.cnf_jkt).toBe(dpopJkt);
    expect(binding.parameter_digest).toBe(`sha-256:${txn}`);
    // The digest is the whole binding, reproducibly.
    expect((opened as { digest: string }).digest).toBe(txnApprovalBindingDigest(binding));
    expect((opened as { digest: string }).digest).toMatch(/^sha-256:/);
  });

  it("refuses an approval adjudicated for a different transaction", async () => {
    const txn = "txn_binding_foreign_client";
    // The approval is genuinely opened, genuinely adjudicated -- but against a
    // transaction whose authenticated client is someone else.
    bindingMutations.set(txn, (b) => ({ ...b, client_id: "some-other-client" }));
    const { txaId, status } = await admitOne(txn);
    expect(status).toBe(200);
    await ars.adjudicate(taskFor(txn), "approve", "bob");

    const res = await postTransaction({ transaction_authorization_id: txaId });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toMatch(/not bound to this transaction/);
    expect(body.access_token).toBeUndefined();
    // Refused BEFORE the fresh decision: an approval this workflow cannot
    // reproduce is never carried into step 7 as context.
    expect(freshDecisionCalls).not.toContain(txn);
    bindingMutations.delete(txn);
  });

  it("refuses an approval whose binding the workflow cannot reproduce at all", async () => {
    const txn = "txn_binding_absent";
    // An ARS that reports an approval carrying NO binding at all: absent is
    // never equal to the digest the workflow recomputes.
    bindingMutations.set(txn, (b) => ({ ...b, subject: "mallory" }));
    const { txaId } = await admitOne(txn);
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const res = await postTransaction({ transaction_authorization_id: txaId });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toMatch(/not bound to this transaction/);
    bindingMutations.delete(txn);
  });

  it("fails closed when one resource-scoped txn is opened under two different transactions", async () => {
    const txn = "txn_binding_duplicate";
    const first = await admitOne(txn, { parameter_digest: "sha-256:first-parameters" });
    expect(first.status).toBe(200);
    // A SECOND challenge naming the same (resource, txn) but a different
    // operation. It is a different transaction wearing the first one's
    // correlation identity; resolving it to the existing approval would hand it
    // an adjudication granted for something else.
    const second = await admitOne(txn, { parameter_digest: "sha-256:second-parameters" });
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("invalid_grant");
    expect(String(second.body.error_description)).toMatch(/already bound to a different transaction/);
    // The FIRST transaction is untouched: one task, one binding.
    expect(openedBindings.filter((b) => b.txn === txn)).toHaveLength(2);
    const task = ars.getTask(taskFor(txn));
    expect(task?.state).toBe("pending");
  });

  it("refuses an approval granted in the future beyond the clock skew", async () => {
    const txn = "txn_approval_future";
    const { txaId } = await admitOne(txn);
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const futureS = Math.floor(Date.now() / 1000) + 600;
    approvedAtOverrides.set(taskFor(txn), new Date(futureS * 1000).toISOString());
    approvalOverrides.set(taskFor(txn), new Date((futureS + 300) * 1000).toISOString());

    const res = await postTransaction({ transaction_authorization_id: txaId });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toMatch(/granted in the future/);
    expect(body.access_token).toBeUndefined();
    approvedAtOverrides.delete(taskFor(txn));
    approvalOverrides.delete(taskFor(txn));
  });

  it("refuses an approval whose validity ends before it was granted", async () => {
    const txn = "txn_approval_inverted";
    const { txaId } = await admitOne(txn);
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const nowS = Math.floor(Date.now() / 1000);
    // approved_until is still in the future (so it is "current"), but it
    // precedes the moment the approval says it was granted.
    approvedAtOverrides.set(taskFor(txn), new Date((nowS + 20) * 1000).toISOString());
    approvalOverrides.set(taskFor(txn), new Date((nowS + 10) * 1000).toISOString());

    const res = await postTransaction({ transaction_authorization_id: txaId });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toMatch(/ends before it was granted/);
    expect(body.access_token).toBeUndefined();
    approvedAtOverrides.delete(taskFor(txn));
    approvalOverrides.delete(taskFor(txn));
  });
});

/**
 * @spec txn-authorization#challenge-redemption step 1, step 7 — the subject's
 * credential is checked against the ISSUER's records, not only against its own
 * `exp`, and every completion input is re-read on a fresh clock immediately
 * before the mint.
 */
/**
 * @spec mission#the-mission-claim, txn-authorization#transaction-token — OAuth
 * subject semantics where the Origin Principal profile applies.
 *
 * The credential carries BOTH identities: a destination-local `sub` in this
 * Authorization Server's namespace, and the issuer-qualified origin principal
 * inside `mission.subject`. The transaction token's `sub` is the LOCAL one and
 * `mission.subject` survives verbatim; substituting one for the other would put
 * a foreign namespace's identifier in a local OAuth subject and lose exactly
 * the qualification the cross-domain profile keeps.
 *
 * This AS's own `authorization_code` path mints no origin principal (its
 * subjects are already local), so the profile is exercised against the endpoint
 * directly, with a `subject_token` shaped the way the cross-org grant mints one.
 */
/**
 * @spec txn-authorization#failure-semantics, #two-phase-expiry — a stored
 * authorization result is still subject to expiry. The terminal states are
 * ORDERED: expiry is decided before the stored token is served, so a client is
 * never handed a dead credential inside a 200.
 */
describe("terminal result ordering (@spec txn-authorization#failure-semantics)", () => {
  it("reports expired_token rather than serving a stored token that has expired", async () => {
    const rsKeys = await generateKeyPair("ES256", { extractable: true });
    const txnKeys = await generateKeyPair("ES256", { extractable: true });
    const rsPub = { ...(await exportJWK(rsKeys.publicKey)), kid: "expiry-rs", alg: "ES256" } as JWK;
    const asJwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: JWK[] };

    // A movable clock, so a token can be watched past its own exp.
    let clockMs = Date.now();
    const TOKEN_LIFETIME_S = 60;
    const deps = {
      issuer: ISSUER,
      kernel: as.kernel,
      clients: [{ client_id: "ap-agent", jwks: { keys: [agentClientPublicJwk] } }],
      publicJwks: asJwks,
      dpopProofReplay: newDpopProofReplay(),
      subjectTokenLive: async () => true,
      now: () => new Date(clockMs),
      txn: {
        challengeIssuers: new Map([
          [RESOURCE, { jwks: createLocalJWKSet({ keys: [rsPub] }), algs: ["ES256"] }],
        ]) as ChallengeIssuers,
        ars,
        operationProfiles: new OperationProfileRegistry().register(RESOURCE, missionResourceAccessProfile()),
        tokenKey: txnKeys.privateKey,
        tokenKid: "expiry-txn",
        workflowLifetimeSeconds: WORKFLOW_LIFETIME_S,
        maxTokenLifetimeSeconds: TOKEN_LIFETIME_S,
        freshDecision: async () => ({ decision: "permit" as const }),
      },
    };
    const workflows = newTxnWorkflows();

    const txn = "txn_stored_expiry";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: (as.kernel.get(missionId) as { authority_set: AuthorityEntry[] }).authority_set
          .filter((e) => e.actions.includes("payments:remittance.send"))
          .map((e) => ({ ...e, actions: ["payments:remittance.send"] })),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
      },
      rsKeys.privateKey,
      "expiry-rs",
    );
    const admitted = await callTransactionEndpoint(deps, workflows, {
      transaction_challenge: challenge,
      subject_token: baseToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const handle = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");

    const issued = await callTransactionEndpoint(deps, workflows, {
      transaction_authorization_id: handle,
    });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    // The REAL remaining lifetime, unclamped.
    expect((issued.body as { expires_in: number }).expires_in).toBe(TOKEN_LIFETIME_S);

    // The stored result is still there; its lifetime is not.
    clockMs += (TOKEN_LIFETIME_S + 5) * 1000;
    const stale = await callTransactionEndpoint(deps, workflows, {
      transaction_authorization_id: handle,
    });
    expect(stale.status).toBe(400);
    expect((stale.body as { error: string }).error).toBe("expired_token");
    expect((stale.body as { access_token?: string }).access_token).toBeUndefined();
  });
});

describe("origin principal vs the local subject (@spec txn-authorization#transaction-token)", () => {
  const ORIGIN = { iss: "https://partner.example", sub: "origin-alice" };
  const LOCAL_SUB = "alice-local";

  it("mints the LOCAL subject and preserves the origin principal, and the decision sees both", async () => {
    const asKeys = await generateKeyPair("ES256", { extractable: true });
    const rsKeys = await generateKeyPair("ES256", { extractable: true });
    const txnKeys = await generateKeyPair("ES256", { extractable: true });
    const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "local-at", alg: "ES256" } as JWK;
    const rsPub = { ...(await exportJWK(rsKeys.publicKey)), kid: "local-rs", alg: "ES256" } as JWK;

    const record = as.kernel.get(missionId) as { authority_set: AuthorityEntry[]; expires_at: string };
    const requested = record.authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
    // The mission claim as a cross-domain credential carries it: the invariants
    // PLUS the issuer-qualified origin principal.
    const claim = { ...missionClaim, subject: ORIGIN };

    // A `subject_token` whose own `sub` is destination-local while the origin
    // principal rides, qualified, on the mission claim.
    const subjectToken = await new SignJWT({
      sub: LOCAL_SUB,
      client_id: "ap-agent",
      cnf: { jkt: dpopJkt },
      mission: claim,
      authorization_details: requested,
    })
      .setProtectedHeader({ alg: "ES256", kid: "local-at", typ: "at+jwt" })
      .setIssuer(ISSUER)
      .setAudience(RESOURCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .setJti(`at_${crypto.randomUUID()}`)
      .sign(asKeys.privateKey);

    const txn = "txn_origin_principal";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        mission: claim,
      },
      rsKeys.privateKey,
      "local-rs",
    );

    const opened: Array<{ subject: string; binding: TxnApprovalBinding }> = [];
    const decisions: Array<{ subject: string; originPrincipal?: { iss: string; sub: string } }> = [];
    const localArs = {
      openForTxn: (input: {
        txn: string;
        resource: string;
        missionId: string;
        action: string;
        parameter_digest: string;
        subject: string;
        requires_action_approval: boolean;
        binding: TxnApprovalBinding;
        binding_digest: string;
      }) => {
        opened.push({ subject: input.subject, binding: input.binding });
        return ars.openForTxn(input);
      },
      getTask: (taskId: string) => ars.getTask(taskId),
    };
    const deps = {
      issuer: ISSUER,
      kernel: as.kernel,
      clients: [{ client_id: "ap-agent", jwks: { keys: [agentClientPublicJwk] } }],
      publicJwks: { keys: [asPub] },
      dpopProofReplay: newDpopProofReplay(),
      subjectTokenLive: async () => true,
      now: () => new Date(),
      txn: {
        challengeIssuers: new Map([
          [RESOURCE, { jwks: createLocalJWKSet({ keys: [rsPub] }), algs: ["ES256"] }],
        ]) as ChallengeIssuers,
        ars: localArs,
        operationProfiles: new OperationProfileRegistry().register(RESOURCE, missionResourceAccessProfile()),
        tokenKey: txnKeys.privateKey,
        tokenKid: "local-txn",
        workflowLifetimeSeconds: WORKFLOW_LIFETIME_S,
        maxTokenLifetimeSeconds: MAX_TOKEN_LIFETIME_S,
        freshDecision: async (input: {
          subject: string;
          originPrincipal?: { iss: string; sub: string };
        }) => {
          decisions.push({
            subject: input.subject,
            ...(input.originPrincipal ? { originPrincipal: input.originPrincipal } : {}),
          });
          return { decision: "permit" as const };
        },
      },
    };
    const workflows = newTxnWorkflows();

    const admitted = await callTransactionEndpoint(deps, workflows, {
      transaction_challenge: challenge,
      subject_token: subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const handle = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;

    // The approval is opened against the LOCAL subject, with the origin
    // principal carried alongside it in the binding -- both, never one for the
    // other.
    expect(opened[0]?.subject).toBe(LOCAL_SUB);
    expect(opened[0]?.binding.subject).toBe(LOCAL_SUB);
    expect(opened[0]?.binding.origin_principal).toEqual(ORIGIN);

    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const issued = await callTransactionEndpoint(deps, workflows, {
      transaction_authorization_id: handle,
    });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const token = (issued.body as { access_token: string }).access_token;
    const claims = decodeJwt(token);
    // `sub` is the DESTINATION-LOCAL subject...
    expect(claims.sub).toBe(LOCAL_SUB);
    // ...and the origin principal survives issuer-qualified on the claim.
    expect((claims.mission as { subject: unknown }).subject).toEqual(ORIGIN);
    // The fresh decision saw both identities.
    expect(decisions).toEqual([{ subject: LOCAL_SUB, originPrincipal: ORIGIN }]);
  });
});

/**
 * @spec txn-authorization#challenge-redemption steps 5 and 7,
 * #transaction-token — the dual-identity fail-closed paths (#588 review,
 * finding 3). Each test below is the negative mirror of one clause the
 * review's six-step algorithm requires: flattening the origin principal into
 * `sub` never happens, a subject_token this AS never signed is refused
 * (today's fail-closed default for the namespace-mapping "otherwise" branch
 * {{transaction-token}} now defines: only a same-issuer subject_token is
 * accepted, so the injective foreign-issuer mapping branch itself has no
 * code path here yet), a challenge and subject_token that disagree about the
 * origin principal for one local subject are refused before any approval
 * opens, an approval bound to a different identity than the workflow pinned
 * is refused, and a post-admission identity substitution is refused when the
 * workflow reaches completion.
 */
describe("dual identity fail-closed paths (@spec txn-authorization#challenge-redemption, #transaction-token)", () => {
  const ORIGIN = { iss: "https://partner.example", sub: "origin-alice" };
  const LOCAL_SUB = "alice-local";

  /**
   * The same in-test rig as "origin principal vs the local subject" above
   * (own AS/RS/TAS keys, own workflow store), parameterized so each test
   * below can vary exactly one thing: the subject_token's issuer or signing
   * key, the origin principal it carries vs. the one the challenge carries,
   * or a mutation applied to the binding the ARS actually stores.
   */
  async function harness(opts: {
    txn: string;
    subjectTokenIssuer?: string;
    subjectTokenKid?: string;
    subjectTokenSigningKey?: CryptoKey;
    subjectTokenOrigin?: { iss: string; sub: string };
    challengeOrigin?: { iss: string; sub: string };
    bindingMutate?: (b: TxnApprovalBinding) => TxnApprovalBinding;
    subjectNamespaces?: SubjectNamespacePolicy;
  }): Promise<{
    admit: () => Promise<{ status: number; body: Record<string, unknown> }>;
    complete: (txaId: string) => Promise<{ status: number; body: Record<string, unknown> }>;
    workflows: TxnWorkflowStore;
  }> {
    const asKeys = await generateKeyPair("ES256", { extractable: true });
    const rsKeys = await generateKeyPair("ES256", { extractable: true });
    const txnKeys = await generateKeyPair("ES256", { extractable: true });
    const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "local-at", alg: "ES256" } as JWK;
    const rsPub = { ...(await exportJWK(rsKeys.publicKey)), kid: "local-rs", alg: "ES256" } as JWK;

    const record = as.kernel.get(missionId) as { authority_set: AuthorityEntry[] };
    const requested = record.authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));

    const subjectOrigin = opts.subjectTokenOrigin ?? ORIGIN;
    const challengeOrigin = opts.challengeOrigin ?? subjectOrigin;

    const subjectToken = await new SignJWT({
      sub: LOCAL_SUB,
      client_id: "ap-agent",
      cnf: { jkt: dpopJkt },
      mission: { ...missionClaim, subject: subjectOrigin },
      authorization_details: requested,
    })
      .setProtectedHeader({ alg: "ES256", kid: opts.subjectTokenKid ?? "local-at", typ: "at+jwt" })
      .setIssuer(opts.subjectTokenIssuer ?? ISSUER)
      .setAudience(RESOURCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .setJti(`at_${crypto.randomUUID()}`)
      .sign(opts.subjectTokenSigningKey ?? asKeys.privateKey);

    const challenge = await signChallenge(
      {
        txn: opts.txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${opts.txn}`,
        mission: { ...missionClaim, subject: challengeOrigin },
      },
      rsKeys.privateKey,
      "local-rs",
    );

    const localArs = {
      openForTxn: (input: {
        txn: string;
        resource: string;
        missionId: string;
        action: string;
        parameter_digest: string;
        subject: string;
        requires_action_approval: boolean;
        binding: TxnApprovalBinding;
        binding_digest: string;
      }) => {
        if (!opts.bindingMutate) return ars.openForTxn(input);
        const mutated = opts.bindingMutate(input.binding);
        return ars.openForTxn({ ...input, binding: mutated, binding_digest: txnApprovalBindingDigest(mutated) });
      },
      getTask: (taskId: string) => ars.getTask(taskId),
    };
    const deps = {
      issuer: ISSUER,
      kernel: as.kernel,
      clients: [{ client_id: "ap-agent", jwks: { keys: [agentClientPublicJwk] } }],
      publicJwks: { keys: [asPub] },
      dpopProofReplay: newDpopProofReplay(),
      subjectTokenLive: async () => true,
      now: () => new Date(),
      txn: {
        challengeIssuers: new Map([
          [RESOURCE, { jwks: createLocalJWKSet({ keys: [rsPub] }), algs: ["ES256"] }],
        ]) as ChallengeIssuers,
        ars: localArs,
        operationProfiles: new OperationProfileRegistry().register(RESOURCE, missionResourceAccessProfile()),
        tokenKey: txnKeys.privateKey,
        tokenKid: "local-txn",
        workflowLifetimeSeconds: WORKFLOW_LIFETIME_S,
        maxTokenLifetimeSeconds: MAX_TOKEN_LIFETIME_S,
        freshDecision: async () => ({ decision: "permit" as const }),
        ...(opts.subjectNamespaces ? { subjectNamespaces: opts.subjectNamespaces } : {}),
      },
    };
    const workflows = newTxnWorkflows();

    return {
      admit: async () =>
        (await callTransactionEndpoint(deps, workflows, {
          transaction_challenge: challenge,
          subject_token: subjectToken,
          subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        })) as { status: number; body: Record<string, unknown> },
      complete: async (txaId: string) =>
        (await callTransactionEndpoint(deps, workflows, {
          transaction_authorization_id: txaId,
        })) as { status: number; body: Record<string, unknown> },
      workflows,
    };
  }

  it("never flattens the origin principal's sub into the token's local sub", async () => {
    const txn = "txn_dual_no_flatten";
    const { admit, complete } = await harness({ txn });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const txaId = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const issued = await complete(txaId);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const claims = decodeJwt((issued.body as { access_token: string }).access_token);
    expect(claims.sub).toBe(LOCAL_SUB);
    expect(claims.sub).not.toBe(ORIGIN.sub);
    expect((claims.mission as { subject: unknown }).subject).toEqual(ORIGIN);
  });

  it("refuses a foreign subject_token issuer on the namespace policy alone", async () => {
    const txn = "txn_dual_foreign_issuer";
    // @spec txn-authorization#subject-namespaces — issuer policy is isolated
    // from key trust: the token is signed by THIS harness's trusted key under
    // its usual kid, so the signature verifies, and only `iss` varies. The
    // default policy accepts only the AS's own issuer, so the refusal below is
    // the namespace decision and nothing upstream of it.
    const { admit } = await harness({
      txn,
      subjectTokenIssuer: "https://foreign-tas.example",
    });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(400);
    expect((admitted.body as { error?: string }).error).toBe("invalid_grant");
    expect((admitted.body as { error_description?: string }).error_description).toBe(
      "subject_token issuer is not accepted by namespace policy",
    );
  });

  it("maps an accepted foreign namespace injectively and mints the mapped subject", async () => {
    const txn = "txn_dual_mapped_foreign";
    // @spec txn-authorization#subject-namespaces — an accepted foreign
    // namespace goes through the configured issuer-qualified mapping, and the
    // token carries the MAPPED destination-local value, never the source sub.
    const { admit, complete } = await harness({
      txn,
      subjectTokenIssuer: "https://partner-as.example",
      subjectNamespaces: {
        establish: ({ iss, sub }) =>
          iss === "https://partner-as.example" && sub === LOCAL_SUB
            ? { subject: "mapped-alice-local", policy: "partner-map-v1" }
            : undefined,
      },
    });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const txaId = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const issued = await complete(txaId);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const claims = decodeJwt((issued.body as { access_token: string }).access_token);
    expect(claims.sub).toBe("mapped-alice-local");
    expect(claims.sub).not.toBe(LOCAL_SUB);
  });

  it("refuses at completion when the pinned mapping no longer produces the pinned subject", async () => {
    const txn = "txn_dual_mapping_revoked";
    // @spec txn-authorization#subject-establishment step 5 — the workflow
    // pinned the source identity and the subject the policy produced at
    // admission; completion re-resolves the CURRENT policy and must get the
    // pinned subject back. Disabling the mapping in between refuses, after
    // approval and before any mint.
    let disabled = false;
    const { admit, complete } = await harness({
      txn,
      subjectTokenIssuer: "https://partner-as.example",
      subjectNamespaces: {
        establish: ({ iss, sub }) =>
          !disabled && iss === "https://partner-as.example" && sub === LOCAL_SUB
            ? { subject: "mapped-alice-local", policy: "partner-map-v1" }
            : undefined,
      },
    });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const txaId = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    disabled = true;
    const refused = await complete(txaId);
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect((refused.body as { error?: string }).error).toBe("access_denied");
    expect((refused.body as { error_description?: string }).error_description).toBe(
      "subject mapping is no longer current",
    );
  });

  it("refuses an approval whose binding names a different local subject", async () => {
    const txn = "txn_dual_binding_subject";
    // The approval is bound to BOTH identities; this isolates the LOCAL half:
    // an approval opened under a different destination-local subject fails the
    // binding-digest recomputation at completion, before the fresh decision.
    const { admit, complete } = await harness({
      txn,
      bindingMutate: (b) => ({ ...b, subject: "mallory-local" }),
    });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const txaId = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const refused = await complete(txaId);
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect((refused.body as { error?: string }).error).toBe("access_denied");
    expect((refused.body as { error_description?: string }).error_description).toBe(
      "approval is not bound to this transaction",
    );
  });

  it("refuses when the challenge and subject_token disagree about the origin principal for one local subject", async () => {
    const txn = "txn_dual_origin_mismatch";
    const OTHER_ORIGIN = { iss: "https://partner.example", sub: "origin-mallory" };
    const { admit } = await harness({ txn, subjectTokenOrigin: ORIGIN, challengeOrigin: OTHER_ORIGIN });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(400);
    expect((admitted.body as { error?: string }).error).toBe("invalid_grant");
    expect((admitted.body as { error_description?: string }).error_description).toBe(
      "challenge mission does not match subject_token",
    );
  });

  it("refuses an approval bound to a different origin principal than the workflow pinned", async () => {
    const txn = "txn_dual_approval_wrong_origin";
    const { admit, complete } = await harness({
      txn,
      bindingMutate: (b) => ({ ...b, origin_principal: { iss: ORIGIN.iss, sub: "origin-eve" } }),
    });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const txaId = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const completed = await complete(txaId);
    expect(completed.status, JSON.stringify(completed.body)).toBe(400);
    expect((completed.body as { error?: string }).error).toBe("access_denied");
    expect((completed.body as { error_description?: string }).error_description).toMatch(
      /not bound to this transaction/,
    );
  });

  it("refuses when the workflow's pinned local subject changes between admission and completion", async () => {
    // Driven through the workflow STORE directly, not the wire: the poll
    // request carries only transaction_authorization_id, so no wire request
    // can resubmit a different identity at completion. This proves the
    // completion-time binding recompute -- not merely the ARS's own copy --
    // refuses a post-admission substitution, whichever of the two pinned
    // identities it hits; the local subject is exercised here because it is
    // the simpler column to mutate directly, and the recompute
    // (approvalBindingFor) treats both identities identically.
    const txn = "txn_dual_identity_drift";
    const { admit, complete, workflows } = await harness({ txn });
    const admitted = await admit();
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    const txaId = (admitted.body as { transaction_authorization_id: string }).transaction_authorization_id;
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    workflows.db.prepare("UPDATE txn_workflows SET subject = ? WHERE id = ?").run("mallory-local", txaId);
    const completed = await complete(txaId);
    expect(completed.status, JSON.stringify(completed.body)).toBe(400);
    expect((completed.body as { error?: string }).error).toBe("access_denied");
    expect((completed.body as { error_description?: string }).error_description).toMatch(
      /not bound to this transaction/,
    );
  });
});

describe("subject credential liveness and the post-decision fence (@spec txn-authorization#challenge-redemption)", () => {
  /** A dedicated Mission + base token, so revoking it disturbs nothing else. */
  async function ownMission(): Promise<{ token: string; missionId: string; claim: Record<string, unknown> }> {
    const jar = new Map<string, string>();
    const issued = await issueBaseMissionToken(dpopKeys, jar);
    return {
      token: issued.token,
      missionId: issued.missionId,
      claim: decodeJwt(issued.token).mission as Record<string, unknown>,
    };
  }

  async function admitFor(
    txn: string,
    mission: { token: string; missionId: string; claim: Record<string, unknown> },
  ): Promise<string> {
    const requested = (as.kernel.get(mission.missionId) as { authority_set: AuthorityEntry[] }).authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        mission: mission.claim,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge, { token: mission.token });
    const body = (await res.json()) as { transaction_authorization_id?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    return body.transaction_authorization_id as string;
  }

  /** RFC 7009-style grant destruction: the credential is individually revoked
   *  at the issuer while its own `exp` is still in the future. */
  async function revoke(missionId: string): Promise<void> {
    const grantId = (as.kernel.get(missionId) as { grant_id?: string }).grant_id as string;
    expect(grantId).toBeDefined();
    await (
      as.provider.Grant as unknown as { adapter: { destroy(id: string): Promise<void> } }
    ).adapter.destroy(grantId);
  }

  it("refuses a subject_token revoked between admission and completion", async () => {
    const mission = await ownMission();
    const txn = "txn_subject_revoked";
    const id = await admitFor(txn, mission);
    await ars.adjudicate(taskFor(txn), "approve", "bob");

    // The credential's own exp is still in the future; only the issuer knows.
    expect(decodeJwt(mission.token).exp as number).toBeGreaterThan(Math.floor(Date.now() / 1000));
    await revoke(mission.missionId);

    const res = await postTransaction({ transaction_authorization_id: id });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toMatch(/no longer live/);
    expect(body.access_token).toBeUndefined();
  });

  it("refuses when the credential is revoked DURING the fresh decision, and mints nothing", async () => {
    const mission = await ownMission();
    const txn = "txn_subject_revoked_midflight";
    const id = await admitFor(txn, mission);
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    // The revocation lands inside the decision's own await: every input the
    // decision saw was true when it ran, and false by the time it returned.
    freshDecisionHooks.set(txn, async () => {
      await revoke(mission.missionId);
    });

    const res = await postTransaction({ transaction_authorization_id: id });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toMatch(/no longer live/);
    expect(body.access_token).toBeUndefined();
    // The decision genuinely ran and permitted; the fence is what refused.
    expect(freshDecisionCalls).toContain(txn);
    // Nothing was minted, so the single issuance slot is still free: a later
    // poll is refused on the same fresh ground, never served a stored token.
    const again = await postTransaction({ transaction_authorization_id: id });
    const againBody = (await again.json()) as { error?: string; access_token?: string };
    expect(againBody.access_token).toBeUndefined();
    expect(againBody.error).toBe("access_denied");
    freshDecisionHooks.delete(txn);
  });

});

describe("fresh decision at completion (@spec txn-authorization#challenge-redemption)", () => {
  const requested = (): AuthorityEntry[] =>
    (as.kernel.get(missionId) as { authority_set: AuthorityEntry[] }).authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));

  const admit = async (txn: string, over: Record<string, unknown> = {}) => {
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested(),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        ...over,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const body = (await (await submit(challenge)).json()) as { transaction_authorization_id: string };
    return body.transaction_authorization_id;
  };

  it("refuses an approved workflow when current entitlement or policy denies", async () => {
    policyDeniesTxns.add("txn_policy_denies");
    const id = await admit("txn_policy_denies");
    const approval = await ars.adjudicate(taskFor("txn_policy_denies"), "approve", "bob");
    expect(approval).not.toBeNull();

    const res = await postTransaction({ transaction_authorization_id: id });
    const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toBe("entitlement_denied");
    expect(body.access_token).toBeUndefined();
    // The decision ran: completing the approval did not bypass it.
    expect(freshDecisionCalls).toContain("txn_policy_denies");
  });

  it("never issues on a step-up context alone: only approval state satisfies the requirement", async () => {
    // The subject_token carries a stronger authentication context; the workflow
    // is admitted and never approved. No amount of polling issues a token.
    const id = await admit("txn_stepup_only");
    for (let i = 0; i < 3; i++) {
      const res = await postTransaction({ transaction_authorization_id: id });
      const body = (await res.json()) as { error?: string; access_token?: string };
      expect(res.status).toBe(400);
      expect(body.error).toBe("authorization_pending");
      expect(body.access_token).toBeUndefined();
    }
    // And the fresh decision was never even reached without an approval.
    expect(freshDecisionCalls).not.toContain("txn_stepup_only");
  });

  it("refuses after containment narrows the entry away between admission and approval", async () => {
    const id = await admit("txn_contained_after_admission");
    as.kernel.contain(missionId, {
      event: {
        type: "vendor.compromise",
        source: "svc:test",
        observed_at: new Date().toISOString(),
        event_id: "ev_txn_contained",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
    });
    await ars.adjudicate(taskFor("txn_contained_after_admission"), "approve", "bob");
    const res = await postTransaction({ transaction_authorization_id: id });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("access_denied");
    expect(body.error_description).toContain("effective Authority Set");
  });
});

/**
 * @spec txn-authorization#challenge-redemption — the endpoint reads an OAuth
 * request: one body format, bounded, and no security-sensitive parameter with
 * two answers.
 */
describe("request parsing at the transaction endpoint (@spec txn-authorization#challenge-redemption)", () => {
  const post = async (body: string, contentType: string): Promise<Response> =>
    fetch(`${ISSUER}/transaction`, {
      method: "POST",
      headers: {
        "content-type": contentType,
        dpop: await dpopProof(`${ISSUER}/transaction`, "POST"),
      },
      body,
    });

  it("refuses a JSON body, and anything that is not form encoding", async () => {
    // A token-endpoint-shaped request has ONE body format; a second parser is
    // a second opinion about what the same request says.
    const json = await post(
      JSON.stringify({
        client_id: "ap-agent",
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        transaction_authorization_id: "txa_whatever",
      }),
      "application/json",
    );
    const body = (await json.json()) as { error?: string; error_description?: string };
    expect(json.status).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/x-www-form-urlencoded/);

    const none = await post("client_id=ap-agent", "text/plain");
    expect(none.status).toBe(400);
    expect(((await none.json()) as { error?: string }).error).toBe("invalid_request");
  });

  it("refuses a repeated security-sensitive parameter rather than picking one", async () => {
    const form = new URLSearchParams({
      client_id: "ap-agent",
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    // Two answers to one question: whichever this server reads, a proxy, a log
    // or the client itself may read the other.
    form.append("subject_token", baseToken);
    form.append("subject_token", "an-entirely-different-credential");
    const res = await post(form.toString(), "application/x-www-form-urlencoded");
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/subject_token MUST NOT appear more than once/);
  });

  it("refuses a body beyond the endpoint's limit", async () => {
    const form = new URLSearchParams({ transaction_authorization_id: "txa_x" });
    form.append("padding", "p".repeat(70 * 1024));
    const res = await post(form.toString(), "application/x-www-form-urlencoded");
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/too large/);
  });
});

describe("subject_token binding (@spec txn-authorization#challenge-redemption)", () => {
  const entry = (resource: string): AuthorityEntry[] => [
    {
      type: "mission_resource_access",
      resource,
      actions: ["payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ];

  it("refuses a subject_token that was not issued for the challenged resource", async () => {
    // The challenge names a resource this TAS accepts, but the presented
    // Mission-bound token's audience is a different one.
    const challenge = await signChallenge(
      {
        txn: "txn_wrong_audience",
        authorization_details: entry(OTHER_RESOURCE),
        iss: OTHER_RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:wrong-audience",
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("not issued for the challenged resource");
  });

  it("refuses a challenge whose mission invariants differ from the subject_token's", async () => {
    const challenge = await signChallenge(
      {
        txn: "txn_mission_mismatch",
        authorization_details: entry(RESOURCE),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:mission-mismatch",
        mission: { ...missionClaim, id: "msn_not_this_one" },
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await submit(challenge);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("mission does not match");
  });
});

/**
 * The describes below each mint their OWN Mission, so nothing here depends on
 * the state the containment run above left the base Mission in.
 */
async function freshMission(
  constraints?: Record<string, unknown>,
): Promise<{ token: string; missionId: string; mission: Record<string, unknown> }> {
  const issued = constraints
    ? await issueBaseMissionToken(dpopKeys, new Map(), constraints)
    : await issueBaseMissionToken(dpopKeys, new Map());
  return {
    token: issued.token,
    missionId: issued.missionId,
    mission: decodeJwt(issued.token).mission as Record<string, unknown>,
  };
}

/** The Mission's own entry for the gated action, narrowed to that one action. */
function remittanceEntry(id: string): AuthorityEntry[] {
  return (as.kernel.get(id) as { authority_set: AuthorityEntry[] }).authority_set
    .filter((e) => e.actions.includes("payments:remittance.send"))
    .map((e) => ({ ...e, actions: ["payments:remittance.send"] }));
}

describe("the approval requirement under delegation (@spec txn-authorization#applicability)", () => {
  /** A Mission whose own authority carries the Common Constraint. */
  let gated: Awaited<ReturnType<typeof freshMission>>;
  /** An otherwise identical Mission that does not. */
  let ungated: Awaited<ReturnType<typeof freshMission>>;

  beforeAll(async () => {
    gated = await freshMission({
      max_amount: { amount: "500.00", currency: "USD" },
      vendors: ["acme"],
      requires_action_approval: true,
    });
    ungated = await freshMission();
  });

  const challengeFor = async (
    txn: string,
    details: AuthorityEntry[],
    mission: Record<string, unknown>,
  ): Promise<string> =>
    signChallenge(
      {
        txn,
        authorization_details: details,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );

  it("carries the requirement onto the Mission's own effective entry", () => {
    expect(remittanceEntry(gated.missionId)[0]?.constraints?.requires_action_approval).toBe(true);
    expect(remittanceEntry(ungated.missionId)[0]?.constraints?.requires_action_approval).toBeUndefined();
  });

  it("refuses a leaf entry that drops the requirement its grant carries", async () => {
    // The leaf restates the entry it was delegated but omits the designation.
    // Under the subset rule that is a WIDENING, so it never admits a workflow.
    const dropped = remittanceEntry(gated.missionId).map((e) => ({
      ...e,
      constraints: { max_amount: e.constraints?.max_amount, vendors: e.constraints?.vendors },
    }));
    const challenge = await challengeFor("txn_leaf_drops_approval", dropped, gated.mission);
    const res = await submit(challenge, { token: gated.token });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("Authority Set");
  });

  it("gates a leaf that inherited the requirement, on the entry alone", async () => {
    // This TAS is configured with no destination policy, so the requirement the
    // endpoint recorded when it opened the approval can only have come from the
    // matched entry's Common Constraint.
    const txn = "txn_leaf_keeps_approval";
    const challenge = await challengeFor(txn, remittanceEntry(gated.missionId), gated.mission);
    const init = (await (await submit(challenge, { token: gated.token })).json()) as {
      transaction_authorization_id: string;
    };
    expect(approvalBasisFor(txn)).toBe(true);

    // The same operation on a Mission whose entry does not carry it records no
    // such basis: the flag tracks the entry, not this endpoint's own profile
    // requirement (which opens an approval either way).
    const plain = await challengeFor("txn_ungated_entry", remittanceEntry(ungated.missionId), ungated.mission);
    await submit(plain, { token: ungated.token });
    expect(approvalBasisFor("txn_ungated_entry")).toBe(false);

    // And the gated leaf is still bound: nothing issues until the approval lands.
    const pending = await postTransaction({ transaction_authorization_id: init.transaction_authorization_id });
    expect((await pending.json()).error).toBe("authorization_pending");
    await ars.adjudicate(taskFor(txn), "approve", "bob");
    const issued = await postTransaction({ transaction_authorization_id: init.transaction_authorization_id });
    const body = (await issued.json()) as { access_token?: string };
    expect(issued.status, JSON.stringify(body)).toBe(200);
    expect(decodeJwt(body.access_token as string).txn).toBe(txn);
  });
});

/**
 * @spec txn-authorization#resource-challenge — the operation is read through
 * the Challenge-Issuing Resource's OWN Operation Profile, and profile VERSIONS
 * are retained: superseding one stops new challenges naming it without revising
 * the basis of a workflow already admitted under it.
 */
describe("Operation Profile resolution and drift (@spec txn-authorization#resource-challenge)", () => {
  const challengeFor = async (
    mission: { missionId: string; mission: Record<string, unknown> },
    txn: string,
    details: unknown[],
  ): Promise<string> =>
    signChallenge(
      {
        txn,
        authorization_details: details,
        iss: RESOURCE,
        aud: ISSUER,
        reason: "payments:invoice.read",
        parameter_digest: `sha-256:${txn}`,
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );

  it("refuses an entry naming more than one action", async () => {
    const mission = await freshMission();
    const multi = (as.kernel.get(mission.missionId) as { authority_set: AuthorityEntry[] }).authority_set
      .filter((e) => e.actions.includes("payments:remittance.send"))
      .map((e) => ({ ...e, actions: ["payments:invoice.read", "payments:remittance.send"] }));
    const res = await submit(await challengeFor(mission, "txn_profile_multi", multi), {
      token: mission.token,
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/exactly one action/);
    // Nothing was admitted, so no approval was opened for it either.
    expect(openedApprovals.find((o) => o.txn === "txn_profile_multi")).toBeUndefined();
  });

  it("refuses an entry whose action is blank", async () => {
    const mission = await freshMission();
    const blank = remittanceEntry(mission.missionId).map((e) => ({ ...e, actions: ["   "] }));
    const res = await submit(await challengeFor(mission, "txn_profile_blank", blank), {
      token: mission.token,
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("refuses an entry whose type no Operation Profile governs", async () => {
    const mission = await freshMission();
    const unknown = remittanceEntry(mission.missionId).map((e) => ({ ...e, type: "payments_wire_v9" }));
    const res = await submit(await challengeFor(mission, "txn_profile_unknown", unknown), {
      token: mission.token,
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/no Operation Profile governs/);
  });

  it("never reads the human-readable reason as the operation's action", async () => {
    // The challenge's `reason` names a REAL action of this Mission, and the
    // entry is unreadable. A TAS that fell back to `reason` would admit an
    // operation the resource never described.
    const mission = await freshMission();
    const unreadable = remittanceEntry(mission.missionId).map((e) => ({ ...e, actions: [] }));
    const res = await submit(await challengeFor(mission, "txn_profile_reason", unreadable), {
      token: mission.token,
    });
    expect(res.status).toBe(400);
    expect(openedApprovals.find((o) => o.txn === "txn_profile_reason")).toBeUndefined();
  });

  it("completes a workflow admitted under a superseded version, and refuses new challenges naming it", async () => {
    const mission = await freshMission();
    const details = remittanceEntry(mission.missionId);
    const supersededDigest = "sha-256:operation-profile-v1";

    // Version 1: the workflow is admitted on this snapshot.
    const admitted = (await (
      await submit(
        await signChallenge(
          {
            txn: "txn_profile_v1",
            authorization_details: details,
            iss: RESOURCE,
            aud: ISSUER,
            reason: "action_approval_required",
            parameter_digest: supersededDigest,
            mission: mission.mission,
          },
          rsTxnKeys.privateKey,
          "rs-txn",
        ),
        { token: mission.token },
      )
    ).json()) as { transaction_authorization_id: string };
    expect(admitted.transaction_authorization_id).toBeDefined();

    // The resource then versions its Operation Profile: the old type leaves
    // ADMISSION eligibility. The registry retains it, because a workflow
    // already references it.
    operationProfiles.supersede(RESOURCE, "mission_resource_access");
    try {
      // A NEW challenge naming the superseded type is refused outright.
      const stale = await submit(
        await signChallenge(
          {
            txn: "txn_profile_v2",
            authorization_details: details,
            iss: RESOURCE,
            aud: ISSUER,
            reason: "action_approval_required",
            parameter_digest: "sha-256:operation-profile-v2",
            mission: mission.mission,
          },
          rsTxnKeys.privateKey,
          "rs-txn",
        ),
        { token: mission.token },
      );
      const staleBody = (await stale.json()) as { error?: string; error_description?: string };
      expect(stale.status).toBe(400);
      expect(staleBody.error_description).toMatch(/no Operation Profile governs/);

      // ...while the PENDING workflow completes on the version it was admitted
      // under: the retention is what makes drift survivable rather than a
      // silent loss of in-flight approvals.
      await ars.adjudicate(taskFor("txn_profile_v1"), "approve", "bob");
      const res = await postTransaction({
        transaction_authorization_id: admitted.transaction_authorization_id,
      });
      const body = (await res.json()) as { access_token?: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      expect(decodeJwt(body.access_token as string).parameter_digest).toBe(supersededDigest);
      // The fresh decision ran on the PINNED snapshot, not on a current profile.
      expect(freshDecisionInputs.find((i) => i.txn === "txn_profile_v1")).toEqual({
        txn: "txn_profile_v1",
        operationType: "mission_resource_access",
        parameterDigest: supersededDigest,
      });
    } finally {
      operationProfiles.register(RESOURCE, missionResourceAccessProfile());
    }
  });
});

describe("at most one authorization result per txn (@spec txn-authorization#offline-verification)", () => {
  it("mints no second jti when a decided workflow is polled concurrently", async () => {
    const mission = await freshMission();
    const txn = "txn_concurrent_poll";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: remittanceEntry(mission.missionId),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: `sha-256:${txn}`,
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const init = (await (await submit(challenge, { token: mission.token })).json()) as {
      transaction_authorization_id: string;
    };
    await ars.adjudicate(taskFor(txn), "approve", "bob");

    const poll = () => postTransaction({ transaction_authorization_id: init.transaction_authorization_id });
    const bodies = (await Promise.all(
      (await Promise.all([poll(), poll(), poll(), poll()])).map((r) => r.json()),
    )) as { access_token?: string }[];
    const jtis = new Set(
      bodies.filter((b) => b.access_token).map((b) => decodeJwt(b.access_token as string).jti as string),
    );
    expect(jtis.size).toBe(1);

    // And the single result is stable: a later poll returns that same token.
    const later = (await (await poll()).json()) as { access_token: string };
    expect(decodeJwt(later.access_token).jti).toBe([...jtis][0]);
  });
});

describe("transaction token identity projection (@spec txn-authorization#transaction-token)", () => {
  it("projects the effective subject and authenticated client, and carries act only where actor context existed", async () => {
    const mission = await freshMission();
    const details = remittanceEntry(mission.missionId);
    const act = { sub: "subagent-invoice-extractor", iss: ISSUER };
    const redeem = async (txn: string, actor?: unknown): Promise<Record<string, unknown>> => {
      const challenge = await signChallenge(
        {
          txn,
          authorization_details: details,
          iss: RESOURCE,
          aud: ISSUER,
          reason: "action_approval_required",
          parameter_digest: `sha-256:${txn}`,
          mission: mission.mission,
          ...(actor !== undefined ? { act: actor } : {}),
        },
        rsTxnKeys.privateKey,
        "rs-txn",
      );
      const init = (await (await submit(challenge, { token: mission.token })).json()) as {
        transaction_authorization_id: string;
      };
      await ars.adjudicate(taskFor(txn), "approve", "bob");
      const body = (await (
        await postTransaction({ transaction_authorization_id: init.transaction_authorization_id })
      ).json()) as { access_token?: string };
      expect(body.access_token, JSON.stringify(body)).toBeTruthy();
      return decodeJwt(body.access_token as string) as Record<string, unknown>;
    };

    // Actor context on the challenge makes `act` REQUIRED on the token.
    const withActor = await redeem("txn_identity_actor", act);
    expect(withActor.act).toEqual(act);
    // Alice is the Mission's subject; bob adjudicated. The Approver is never it.
    expect(withActor.sub).toBe("alice");
    expect(withActor.client_id).toBe("ap-agent");

    // No actor context anywhere upstream: the member is absent, not empty.
    const withoutActor = await redeem("txn_identity_plain");
    expect(withoutActor.act).toBeUndefined();
    expect(withoutActor.sub).toBe("alice");
    expect(withoutActor.client_id).toBe("ap-agent");
  });
});

describe("client identification (@spec txn-authorization#challenge-redemption)", () => {
  const assertionFor = (iss: string, sub: string, key: CryptoKey, kid: string): Promise<string> =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuer(iss)
      .setSubject(sub)
      .setAudience(ISSUER)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(key);

  it("resolves the authenticated client from its own assertion, never from another client's record", async () => {
    const childKey = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
    const CHILD = "subagent-invoice-extractor";
    const CHILD_KID = "subagent-invoice-extractor-auth";
    const mission = await freshMission();
    const challenge = await signChallenge(
      {
        txn: "txn_client_identity",
        authorization_details: remittanceEntry(mission.missionId),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:client-identity",
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const payload = {
      transaction_challenge: challenge,
      subject_token: mission.token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    };

    // One client's assertion presented under ANOTHER's client_id: the parameter
    // is corroboration, never the selector.
    const mismatched = await postTransaction(payload, {
      assertion: await assertionFor(CHILD, CHILD, childKey, CHILD_KID),
      clientId: "ap-agent",
    });
    expect(mismatched.status).toBe(401);
    expect((await mismatched.json()).error).toBe("invalid_client");

    // The child's identity signed with the AP agent's key, and no client_id at
    // all: the record comes from the assertion, so it is verified under the
    // child's registered keys and fails there.
    const wrongKey = await postTransaction(payload, {
      assertion: await assertionFor(CHILD, CHILD, clientKey, "ap-agent-auth"),
      omitClientId: true,
    });
    expect(wrongKey.status).toBe(401);
    expect((await wrongKey.json()).error).toBe("invalid_client");

    // `iss` and `sub` disagreeing is not a client identity at all.
    const split = await postTransaction(payload, {
      assertion: await assertionFor("ap-agent", CHILD, clientKey, "ap-agent-auth"),
      omitClientId: true,
    });
    expect(split.status).toBe(401);

    // Nor is an identity no registered client claims.
    const unregistered = await postTransaction(payload, {
      assertion: await assertionFor("rogue-agent", "rogue-agent", clientKey, "ap-agent-auth"),
      omitClientId: true,
    });
    expect(unregistered.status).toBe(401);

    // Presenting only its own assertion, the child authenticates AS the child:
    // the workflow it admits belongs to it, and the AP agent cannot poll it.
    const admitted = await postTransaction(payload, {
      assertion: await assertionFor(CHILD, CHILD, childKey, CHILD_KID),
      omitClientId: true,
    });
    const admittedBody = (await admitted.json()) as { transaction_authorization_id?: string };
    expect(admitted.status, JSON.stringify(admittedBody)).toBe(200);
    const asAgent = await postTransaction({
      transaction_authorization_id: admittedBody.transaction_authorization_id as string,
    });
    expect(asAgent.status).toBe(400);
    expect((await asAgent.json()).error).toBe("invalid_grant");
  });
});

describe("proof and credential freshness (@spec txn-authorization#challenge-redemption)", () => {
  it("refuses a transaction token presented as subject_token", async () => {
    // Obtain a REAL transaction token through the flow first.
    const mission = await freshMission();
    const txn = "txn_f4_class";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: remittanceEntry(mission.missionId),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:f4-class",
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const init = await submit(challenge, { token: mission.token });
    const initBody = (await init.json()) as { transaction_authorization_id?: string };
    expect(init.status, JSON.stringify(initBody)).toBe(200);
    const task = ars.pending().find((t) => t.id.endsWith(txn));
    expect(task).toBeDefined();
    await ars.adjudicate(task?.id as string, "approve", "bob");
    const tokenRes = await postTransaction({
      transaction_authorization_id: initBody.transaction_authorization_id as string,
    });
    const txnToken = ((await tokenRes.json()) as { access_token?: string }).access_token as string;
    expect(tokenRes.status).toBe(200);

    // Replayed as the subject's credential on a NEW challenge, it is refused on
    // its CLASS, even though its audience, mission, authority and cnf claims
    // would all satisfy the checks that follow.
    const second = await signChallenge(
      {
        txn: "txn_f4_class_2",
        authorization_details: remittanceEntry(mission.missionId),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:f4-class-2",
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const replay = await submit(second, { token: txnToken });
    expect(replay.status).toBe(400);
    expect((await replay.json()).error).toBe("invalid_grant");
  });

  it("refuses a client assertion without exp", async () => {
    // RFC 7523 §3: exp is REQUIRED; jose only validates it when present.
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(ISSUER)
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(clientKey);
    const mission = await freshMission();
    const challenge = await signChallenge(
      {
        txn: "txn_f4_exp",
        authorization_details: remittanceEntry(mission.missionId),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:f4-exp",
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const res = await postTransaction(
      {
        transaction_challenge: challenge,
        subject_token: mission.token,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      },
      { assertion },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_client");
  });

  it("refuses a DPoP proof whose iat is outside the acceptance window, in both directions", async () => {
    const mission = await freshMission();
    const challenge = await signChallenge(
      {
        txn: "txn_f4_iat",
        authorization_details: remittanceEntry(mission.missionId),
        iss: RESOURCE,
        aud: ISSUER,
        reason: "action_approval_required",
        parameter_digest: "sha-256:f4-iat",
        mission: mission.mission,
      },
      rsTxnKeys.privateKey,
      "rs-txn",
    );
    const htu = `${ISSUER}/transaction`;
    const proofAt = async (iat: number): Promise<string> =>
      new SignJWT({ htu, htm: "POST", iat })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(dpopKeys.publicKey) })
        .setJti(crypto.randomUUID())
        .sign(dpopKeys.privateKey);
    const nowS = Math.floor(Date.now() / 1000);
    // A captured proof stops being usable; a future-dated one never starts.
    for (const iat of [nowS - 400, nowS + 400]) {
      const res = await fetch(htu, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proofAt(iat) },
        body: new URLSearchParams({
          client_id: "ap-agent",
          client_assertion: await clientAssertion(),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          transaction_challenge: challenge,
          subject_token: mission.token,
          subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error?: string }).error).toBe("invalid_dpop_proof");
    }
  });
});
