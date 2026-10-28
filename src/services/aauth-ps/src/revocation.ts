import { type SigningKey, signRequest } from "@mission/aauth-wire";
import type { RevocationPolicy } from "./config.js";
import type { MissionControlStore, RevocationRecord, RevocationState } from "./store.js";

/** An outbound request the PS makes: resource metadata, then a signed revocation. */
export interface OutboundRequest {
  method: "GET" | "POST";
  /** The target URI under the recipient's identifier, `https://host/path`. */
  url: string;
  headers: Record<string, string>;
  body?: string;
  /** Aborted when the attempt's time limit passes. */
  signal?: AbortSignal;
}

export interface OutboundResponse {
  status: number;
  /** Lowercased names. */
  headers: Record<string, string>;
  body: Buffer;
}

/**
 * Sends the PS's outbound requests. It is the egress boundary: it reaches
 * only destinations the deployment admits (https, no private address
 * unless admitted, no redirects), since a token's `aud` is a server
 * identifier an agent named.
 */
export type OutboundTransport = (request: OutboundRequest) => Promise<OutboundResponse>;

export interface RevocationWorkerOptions {
  /** The PS's issuer: the `id` it signs under. */
  issuer: string;
  signingKey: SigningKey;
  kid: string;
  store: MissionControlStore;
  policy: RevocationPolicy;
  transport: OutboundTransport;
  /** Milliseconds since the epoch. */
  now: () => number;
  /** Wait `ms`; spaces two requests to one endpoint into distinct seconds. */
  sleep: (ms: number) => Promise<void>;
}

export interface RevocationWorker {
  /**
   * Attempt every pending revocation that is due and whose credential is
   * unexpired, one at a time. Calls made while a pass runs share the one
   * pass queued after it.
   */
  runDue(): Promise<void>;
  /** Run a pass now and every `intervalMs` until {@link stop}. */
  start(intervalMs: number): void;
  stop(): void;
}

/** What one attempt established. */
type Outcome =
  | { state: "confirmed"; outcome: "revoked"; status: number }
  | { state: "unsupported"; outcome: "no_revocation_endpoint" | "unsupported_iss"; status?: number }
  | { state: "rejected"; outcome: "rejected"; status: number }
  /** The credential reached its `exp` before the request could be sent. */
  | { state: "expired"; outcome: "expired"; status?: number }
  | {
      state: "pending";
      outcome: "revocation_unavailable" | "rate_limited" | "signature_refused" | "deferred";
      status?: number;
      /** Seconds the recipient asked the PS to wait (`Retry-After`). */
      retryAfter?: number;
    };

const RESOURCE_METADATA = "/.well-known/aauth-resource.json";

const unavailable = (status?: number): Outcome =>
  status === undefined
    ? { state: "pending", outcome: "revocation_unavailable" }
    : { state: "pending", outcome: "revocation_unavailable", status };

function jsonObject(body: Buffer): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(body.toString("utf8"));
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** `Retry-After` as delta-seconds or an HTTP-date, in whole seconds from `nowS`. */
function retryAfterSeconds(value: string | undefined, nowS: number): number | undefined {
  if (value === undefined) return undefined;
  if (/^\d+$/.test(value.trim())) return Number(value.trim());
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil(at / 1000) - nowS);
}

function httpsUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    return new URL(value).protocol === "https:" ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The PS's revocation attempts after termination (the management
 * companion's Revocation Attempts; AAuth -11 Section 11.12). Each
 * attempt discovers the recipient's `revocation_endpoint` from its
 * metadata, then POSTs `{jti, exp}` signed as a server under the
 * `jwks_uri` scheme (`id` the PS's issuer, `dwk` `aauth-person.json`),
 * covering Content-Digest and Content-Type. A `200` confirms; every other
 * outcome leaves the credential unconfirmed, retried with bounded
 * exponential backoff (or after `Retry-After`) while it is unexpired, up
 * to the configured number of attempts. Each attempt is recorded and
 * logged before it is sent, and its result after, so the work is durable
 * and resumes after a restart.
 *
 * @spec mission-aauth-management#revocation-attempts
 * @spec aauth#section-11.12.1
 * @spec aauth#section-11.12.3
 * @spec aauth#section-11.12.4
 */
export function createRevocationWorker(options: RevocationWorkerOptions): RevocationWorker {
  const { store, policy, transport, issuer } = options;
  const nowS = () => Math.floor(options.now() / 1000);
  /** The last `created` second signed per endpoint (the replay key's granularity). */
  const lastCreated = new Map<string, number>();
  let running: Promise<void> | undefined;
  let queued: Promise<void> | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;

  const backoff = (attempt: number) =>
    Math.min(policy.retryBaseSeconds * 2 ** (attempt - 1), policy.retryMaxSeconds);

  const discover = async (recipient: string, signal: AbortSignal): Promise<Outcome | string> => {
    let response: OutboundResponse;
    try {
      response = await transport({
        method: "GET",
        url: `${recipient}${RESOURCE_METADATA}`,
        headers: { accept: "application/json" },
        signal,
      });
    } catch {
      return unavailable();
    }
    if (response.status !== 200) return unavailable(response.status);
    const metadata = jsonObject(response.body);
    // @spec aauth#section-11.2: a document whose issuer is not the
    // recipient is not its metadata.
    if (!metadata || metadata.issuer !== recipient) return unavailable(response.status);
    const endpoint = httpsUrl(metadata.revocation_endpoint);
    return endpoint ?? { state: "unsupported", outcome: "no_revocation_endpoint" };
  };

  const revoke = async (
    row: RevocationRecord,
    endpoint: string,
    signal: AbortSignal,
  ): Promise<Outcome> => {
    // The replay key a recipient may keep is (key, created, method,
    // authority, path): a second request to one endpoint waits for the
    // next second rather than collide with the first.
    const last = lastCreated.get(endpoint);
    if (last !== undefined && nowS() <= last) {
      await options.sleep((last + 1) * 1000 - options.now());
    }
    // Discovery and the wait above took time, so the clock is read again
    // immediately before signing: a credential at or past its `exp` needs
    // no revocation, and an attempt its time limit already ended sends
    // nothing more.
    if (nowS() >= row.exp) return { state: "expired", outcome: "expired" };
    if (signal.aborted) return unavailable();
    const created = nowS();
    lastCreated.set(endpoint, created);
    const body = JSON.stringify({ jti: row.jti, exp: row.exp });
    const headers: Record<string, string> = { "content-type": "application/json" };
    const added = signRequest(
      { method: "POST", url: endpoint, headers, body },
      {
        alg: options.signingKey.alg,
        privateKey: options.signingKey.privateKey,
        signatureKey: {
          scheme: "jwks_uri",
          id: issuer,
          dwk: "aauth-person.json",
          kid: options.kid,
        },
        created,
      },
    );
    let response: OutboundResponse;
    try {
      response = await transport({
        method: "POST",
        url: endpoint,
        headers: { ...headers, ...added },
        body,
        signal,
      });
    } catch {
      return unavailable();
    }
    const status = response.status;
    if (status === 200) {
      // @spec aauth#section-11.12.3: an absent body is the revocation
      // recorded; a non-empty one must be a JSON object, and one the PS
      // cannot parse is revocation_unavailable.
      if (response.body.length === 0) return { state: "confirmed", outcome: "revoked", status };
      const type = (response.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
      if (type === "application/json" && jsonObject(response.body)) {
        return { state: "confirmed", outcome: "revoked", status };
      }
      return unavailable(status);
    }
    const error = jsonObject(response.body)?.error;
    if (status === 403 && error === "unsupported_iss") {
      return { state: "unsupported", outcome: "unsupported_iss", status };
    }
    if (status === 429) {
      const retryAfter = retryAfterSeconds(response.headers["retry-after"], nowS());
      return retryAfter === undefined
        ? { state: "pending", outcome: "rate_limited", status }
        : { state: "pending", outcome: "rate_limited", status, retryAfter };
    }
    if (status === 400) return { state: "rejected", outcome: "rejected", status };
    if (status === 401) return { state: "pending", outcome: "signature_refused", status };
    // A recipient with nothing downstream MUST NOT answer 202; a Resource's
    // 202 establishes nothing, and the PS revokes again later rather than poll.
    if (status === 202) return { state: "pending", outcome: "deferred", status };
    return unavailable(status);
  };

  const attempt = async (due: RevocationRecord): Promise<void> => {
    const at = nowS();
    if (due.exp <= at) return;
    // The budget is spent before anything is counted or sent. A pending row
    // whose attempts already reach the bound is one whose last attempt was
    // recorded and then cut short (a crash, a stop): its outcome is unknown,
    // so the credential stays unconfirmed, exhausted, with no further try.
    if (due.attempts >= policy.maxAttempts) {
      const spent: RevocationRecord = {
        ...due,
        state: "exhausted",
        lastOutcome: "interrupted",
        updatedAt: at,
      };
      delete spent.lastStatus;
      store.atomically(() => {
        store.updateRevocation(spent);
        store.appendLog([
          {
            s256: due.s256,
            at,
            event: "revocation_result",
            detail: {
              token: { iss: due.iss, jti: due.jti },
              kind: due.kind,
              recipient: due.recipient,
              attempt: due.attempts,
              outcome: "interrupted",
              state: "exhausted",
            },
          },
        ]);
      });
      return;
    }
    const n = due.attempts + 1;
    // Recorded before it is sent, with the next attempt already scheduled,
    // so an attempt cut short by a crash is retried, never lost.
    const sent: RevocationRecord = { ...due, attempts: n, nextAt: at + backoff(n), updatedAt: at };
    const token = { iss: due.iss, jti: due.jti };
    store.atomically(() => {
      store.updateRevocation(sent);
      store.appendLog([
        {
          s256: due.s256,
          at,
          event: "revocation_attempted",
          detail: { token, kind: due.kind, recipient: due.recipient, attempt: n },
        },
      ]);
    });

    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<Outcome>((resolve) => {
      timeout = setTimeout(() => {
        controller.abort();
        resolve(unavailable());
      }, policy.attemptTimeoutMs);
    });
    const work = (async (): Promise<Outcome> => {
      let endpoint = sent.endpoint;
      if (endpoint === undefined) {
        const found = await discover(due.recipient, controller.signal);
        if (typeof found !== "string") return found;
        endpoint = found;
        sent.endpoint = found;
      }
      return revoke(sent, endpoint, controller.signal);
    })();
    let outcome: Outcome;
    try {
      outcome = await Promise.race([work, expired]);
    } catch {
      outcome = unavailable();
    } finally {
      clearTimeout(timeout);
    }

    const after = nowS();
    let state: RevocationState = outcome.state;
    let nextAt = sent.nextAt;
    if (outcome.state === "pending") {
      if (outcome.retryAfter !== undefined) nextAt = after + Math.max(1, outcome.retryAfter);
      if (n >= policy.maxAttempts) state = "exhausted";
    }
    const settled: RevocationRecord = {
      ...sent,
      state,
      nextAt,
      lastOutcome: outcome.outcome,
      updatedAt: after,
    };
    if (outcome.status === undefined) delete settled.lastStatus;
    else settled.lastStatus = outcome.status;
    const detail: Record<string, unknown> = {
      token,
      kind: due.kind,
      recipient: due.recipient,
      attempt: n,
      outcome: outcome.outcome,
      state,
    };
    if (sent.endpoint !== undefined) detail.endpoint = sent.endpoint;
    if (outcome.status !== undefined) detail.status = outcome.status;
    if (state === "pending") detail.next_attempt_at = nextAt;
    store.atomically(() => {
      store.updateRevocation(settled);
      store.appendLog([{ s256: due.s256, at: after, event: "revocation_result", detail }]);
    });
  };

  const pass = async (): Promise<void> => {
    let due: RevocationRecord[];
    try {
      due = store.dueRevocations(nowS());
    } catch {
      return;
    }
    for (const row of due) {
      try {
        await attempt(row);
      } catch {
        // A store failure leaves the row as it was; the next pass retries it.
      }
    }
  };

  const runDue = (): Promise<void> => {
    if (queued) return queued;
    if (!running) {
      running = pass().finally(() => {
        running = undefined;
      });
      return running;
    }
    queued = running.then(() => {
      queued = undefined;
      return runDue();
    });
    return queued;
  };

  return {
    runDue,
    start(intervalMs) {
      if (timer) return;
      void runDue();
      timer = setInterval(() => void runDue(), intervalMs);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = undefined;
    },
  };
}
