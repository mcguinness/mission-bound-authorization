import { randomBytes } from "node:crypto";
import {
  type HttpRequestMessage,
  type SignatureKeyMember,
  type SigningKey,
  signRequest,
} from "@mission/aauth-wire";
import type { AgentTransport } from "./agent-client.js";
import { type Clock, realSleep, type Sleep } from "./clock.js";
import type { LoopbackRequest, LoopbackResponse } from "./network.js";

/**
 * The caller classes this client acts as. The Person and a management
 * service are not built.
 */
export type ManagementRole = "owning-agent" | "administrator";

/**
 * Sign one control-plane request: return the fields to add (Signature-Key,
 * Signature-Input, Signature and Content-Digest). `created` is the second
 * the client chose.
 */
export type ManagementSigner = (
  message: HttpRequestMessage,
  created: number,
) => Record<string, string>;

/**
 * The owning agent's signer: the Signature-Key `jwt` scheme presenting its
 * agent token, signed with the token's `cnf.jwk` key, exactly as at the
 * other PS endpoints (the management companion's Owning Agent).
 */
export function agentSigner(agent: { key: SigningKey; agentToken: string }): ManagementSigner {
  return keySigner(agent.key, { scheme: "jwt", jwt: agent.agentToken });
}

/**
 * A signer for `key` under a given Signature-Key member, for a caller that
 * authenticates by an HTTP Message Signature of its own key (an
 * administrator, as the PS's configuration defines). The signature covers
 * `@method`, `@authority`, `@path`, `signature-key`, `content-digest` and
 * `content-type`.
 */
export function keySigner(key: SigningKey, signatureKey: SignatureKeyMember): ManagementSigner {
  return (message, created) =>
    signRequest(message, {
      alg: key.alg,
      privateKey: key.privateKey,
      signatureKey,
      created,
      components: [
        "@method",
        "@authority",
        "@path",
        "signature-key",
        "content-digest",
        "content-type",
      ],
    });
}

export type ManagementErrorCode =
  /** The PS metadata failed the issuer check or names no `mission_control_endpoint`. */
  | "metadata_invalid"
  /** The PS does not list the action in `mission_control_actions_supported`. */
  | "action_unsupported"
  /** An administrator's terminate needs a `purpose`. */
  | "purpose_required";

/** A refusal by this client, before anything is sent. */
export class ManagementError extends Error {
  constructor(
    readonly code: ManagementErrorCode,
    readonly detail: string,
  ) {
    super(`${code}: ${detail}`);
    this.name = "ManagementError";
  }
}

/** The PS's control plane, as its metadata publishes it. */
export interface ControlPlane {
  endpoint: string;
  actions: string[];
}

/** A control-plane answer, whatever its status. */
export interface ManagementResult {
  status: number;
  /** Lowercased names. */
  headers: Record<string, string>;
  /** The body parsed as JSON; undefined when it is empty or not JSON. */
  body: unknown;
  /** The body's exact bytes, as text. */
  text: string;
  response: LoopbackResponse;
}

export interface TerminateOptions {
  reason: string;
  /** Default: a fresh {@link newRequestId}. Reuse one to replay a request. */
  requestId?: string;
  purpose?: string;
  /** For `superseded`. */
  replacementS256?: string;
  /** Members set over the others, for negative tests. */
  extra?: Record<string, unknown>;
}

/** One request this client sent. */
export interface SentManagementRequest {
  url: string;
  body: unknown;
  status: number;
}

export interface ManagementClientOptions {
  transport: AgentTransport;
  /** The PS identifier. */
  ps: string;
  role: ManagementRole;
  signer: ManagementSigner;
  now?: Clock;
  sleep?: Sleep;
}

/**
 * A `request_id` with 128 bits of entropy, as the terminate operation
 * requires ("at least 128 bits of unpredictable or collision-resistant
 * entropy encoded as a string").
 */
export function newRequestId(): string {
  return `t-${randomBytes(16).toString("hex")}`;
}

/**
 * A client of the PS's mission control plane (the AAuth Mission
 * Management companion), acting as the owning agent or as an
 * administrator. It resolves `mission_control_endpoint` from the PS's
 * metadata, never from `mission_endpoint`, and confirms an action is in
 * `mission_control_actions_supported` before sending it. Each action is a
 * signed JSON `POST` to `{mission_control_endpoint}/{mission_s256}`; the
 * body never carries `mission_s256`. Every answer is returned, whatever
 * its status, so a test can compare refusals exactly.
 *
 * The signer decides how the caller authenticates: {@link agentSigner}
 * for the owning agent, and for an administrator whatever the PS's
 * configuration defines, through {@link keySigner} or a custom
 * {@link ManagementSigner}.
 *
 * @spec mission-aauth-management#endpoint
 * @spec mission-aauth-management#status
 * @spec mission-aauth-management#terminate
 */
export class ManagementClient {
  readonly role: ManagementRole;
  readonly ps: string;
  readonly sent: SentManagementRequest[] = [];

  private readonly transport: AgentTransport;
  private readonly signer: ManagementSigner;
  private readonly now: Clock;
  private readonly sleep: Sleep;
  private readonly lastCreated = new Map<string, number>();
  private plane: ControlPlane | undefined;

  constructor(options: ManagementClientOptions) {
    this.transport = options.transport;
    this.ps = options.ps;
    this.role = options.role;
    this.signer = options.signer;
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? realSleep;
  }

  /** The owning agent, signing with its agent token at its own PS. */
  static forAgent(
    agent: { key: SigningKey; agentToken: string; ps: string },
    transport: AgentTransport,
    options: { now?: Clock; sleep?: Sleep } = {},
  ): ManagementClient {
    return new ManagementClient({
      transport,
      ps: agent.ps,
      role: "owning-agent",
      signer: agentSigner(agent),
      ...options,
    });
  }

  /** An administrator signing with `key` under `signatureKey`. */
  static forAdministrator(options: {
    transport: AgentTransport;
    ps: string;
    key: SigningKey;
    signatureKey: SignatureKeyMember;
    now?: Clock;
    sleep?: Sleep;
  }): ManagementClient {
    const { key, signatureKey, ...rest } = options;
    return new ManagementClient({
      ...rest,
      role: "administrator",
      signer: keySigner(key, signatureKey),
    });
  }

  /**
   * The control plane from `{ps}/.well-known/aauth-person.json`, whose
   * `issuer` must be the PS. A PS that publishes no
   * `mission_control_endpoint` implements no management operation.
   *
   * @spec mission-aauth-management#metadata
   */
  async controlPlane(): Promise<ControlPlane> {
    if (this.plane) return this.plane;
    const { status, body } = await this.transport.fetchJson(
      `${this.ps}/.well-known/aauth-person.json`,
    );
    const doc = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    if (status !== 200 || doc.issuer !== this.ps) {
      throw new ManagementError("metadata_invalid", "PS metadata failed the issuer check");
    }
    if (typeof doc.mission_control_endpoint !== "string") {
      throw new ManagementError("metadata_invalid", "PS metadata has no mission_control_endpoint");
    }
    const listed = doc.mission_control_actions_supported;
    const actions = Array.isArray(listed)
      ? listed.filter((a): a is string => typeof a === "string")
      : [];
    this.plane = { endpoint: doc.mission_control_endpoint, actions };
    return this.plane;
  }

  /** Read a mission's status. */
  async status(s256: string): Promise<ManagementResult> {
    await this.requireAction("status");
    return this.send(s256, { action: "status" });
  }

  /**
   * Terminate a mission with `reason`. An administrator must give a
   * `purpose`; `request_id` is fresh unless the caller names one.
   */
  async terminate(s256: string, options: TerminateOptions): Promise<ManagementResult> {
    if (this.role === "administrator" && options.purpose === undefined) {
      throw new ManagementError("purpose_required", "an administrator's terminate needs a purpose");
    }
    await this.requireAction("terminate");
    const body: Record<string, unknown> = {
      action: "terminate",
      reason: options.reason,
      request_id: options.requestId ?? newRequestId(),
    };
    if (options.purpose !== undefined) body.purpose = options.purpose;
    if (options.replacementS256 !== undefined) body.replacement_s256 = options.replacementS256;
    return this.send(s256, { ...body, ...(options.extra ?? {}) });
  }

  /**
   * POST `body` to `{mission_control_endpoint}/{segment}`, signed. An
   * object is sent as JSON; a string or bytes are sent exactly, for
   * malformed or duplicate-member bodies. No action check is made.
   */
  async send(
    segment: string,
    body: Record<string, unknown> | string | Uint8Array,
    options: { contentType?: string } = {},
  ): Promise<ManagementResult> {
    const { endpoint } = await this.controlPlane();
    const url = `${endpoint}/${segment}`;
    const bytes =
      typeof body === "string" || body instanceof Uint8Array
        ? Buffer.from(body)
        : Buffer.from(JSON.stringify(body), "utf8");
    const headers: Record<string, string> = {
      "content-type": options.contentType ?? "application/json",
    };
    const signed = this.signer(
      { method: "POST", url, headers, body: bytes },
      await this.created(url),
    );
    const message: LoopbackRequest = {
      method: "POST",
      url,
      headers: { ...headers, ...signed },
      body: bytes,
    };
    const response = await this.transport.request(message);
    let parsed: unknown;
    try {
      parsed = response.body.length > 0 ? response.json() : undefined;
    } catch {
      parsed = undefined;
    }
    this.sent.push({
      url,
      body: typeof body === "string" || body instanceof Uint8Array ? bytes.toString("utf8") : body,
      status: response.status,
    });
    return {
      status: response.status,
      headers: response.headers,
      body: parsed,
      text: response.text(),
      response,
    };
  }

  private async requireAction(action: string): Promise<void> {
    const { actions } = await this.controlPlane();
    if (!actions.includes(action)) {
      throw new ManagementError("action_unsupported", `the PS does not list ${action}`);
    }
  }

  /**
   * The `created` for a request to `url`: the current second, or the next
   * one when this client already signed a POST to the same authority and
   * path in it, since a replay cache keys on that tuple and the signing
   * key (aauth#section-11.3.4.2).
   */
  private async created(url: string): Promise<number> {
    const target = new URL(url);
    const tuple = `${target.host}${target.pathname}`;
    const last = this.lastCreated.get(tuple);
    let created = Math.floor(this.now() / 1000);
    while (last !== undefined && created <= last) {
      await this.sleep(1000 - (this.now() % 1000));
      created = Math.floor(this.now() / 1000);
    }
    this.lastCreated.set(tuple, created);
    return created;
  }
}
