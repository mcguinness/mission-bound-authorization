import { randomUUID } from "node:crypto";
import { isAgentIdentifier, isServerIdentifier } from "@mission/aauth-wire";
import type { Clock } from "./clock.js";
import { createIssuerStub, type IssuerStub } from "./issuer-stub.js";

export interface AgentTokenRequest {
  /** The local part of the agent identifier; top-level agents only. */
  local: string;
  /** The agent's public signing key, with its fully-specified `alg`. */
  publicJwk: Record<string, unknown>;
  /** The agent's person server, carried as the `ps` claim. */
  ps?: string;
  /** Default 3600. */
  lifetimeSeconds?: number;
  /** Claims set over the defaults, for negative tests. */
  claims?: Record<string, unknown>;
}

export interface AgentProvider extends IssuerStub {
  /** `aauth:{local}@{domain}`, the domain being this provider's host. */
  agentIdentifier(local: string): string;
  issueAgentToken(request: AgentTokenRequest): Promise<string>;
  /** The `jti` of every agent token issued, in order. */
  readonly issued: string[];
}

export interface AgentProviderOptions {
  /** Default `https://ap.test`. */
  issuer?: string;
  kid?: string;
  now?: Clock;
}

/**
 * The agent-provider stub. It publishes `aauth-agent.json` and its JWKS
 * and issues agent tokens (`aa-agent+jwt`). The platform-specific
 * bootstrap that would authenticate the agent first is out of scope: the
 * test hands over the agent's public key.
 *
 * An agent identifier's domain is this provider's host, the `iss` of the
 * tokens it signs (aauth#section-5.1: an AP is named in both).
 *
 * @spec aauth#section-5.1
 * @spec aauth#section-5.2
 * @spec aauth#section-5.3.1
 * @spec aauth#section-11.2.1
 */
export function createAgentProvider(options: AgentProviderOptions = {}): AgentProvider {
  const issuer = options.issuer ?? "https://ap.test";
  if (!isServerIdentifier(issuer)) throw new TypeError(`${issuer} is not a server identifier`);
  const now = options.now ?? Date.now;
  const domain = new URL(issuer).hostname;
  const stub = createIssuerStub({
    issuer,
    dwk: "aauth-agent.json",
    kid: options.kid ?? "ap-key-1",
    metadata: { name: "AAuth test agent provider" },
  });
  const issued: string[] = [];

  const agentIdentifier = (local: string): string => {
    const id = `aauth:${local}@${domain}`;
    // @spec aauth#section-5.2: `+` is reserved for sub-agents, out of scope here.
    if (local.includes("+") || !isAgentIdentifier(id)) {
      throw new TypeError(`${local} is not a top-level agent local part`);
    }
    return id;
  };

  return {
    ...stub,
    issued,
    agentIdentifier,
    async issueAgentToken(request) {
      const iat = Math.floor(now() / 1000);
      const jti = randomUUID();
      const claims: Record<string, unknown> = {
        iss: issuer,
        dwk: "aauth-agent.json",
        sub: agentIdentifier(request.local),
        jti,
        iat,
        exp: iat + (request.lifetimeSeconds ?? 3600),
        cnf: { jwk: request.publicJwk },
        ...(request.ps === undefined ? {} : { ps: request.ps }),
        ...(request.claims ?? {}),
      };
      issued.push(jti);
      return stub.mint("aa-agent+jwt", claims);
    },
  };
}
