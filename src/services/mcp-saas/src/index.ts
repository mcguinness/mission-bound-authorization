/**
 * @spec mission#rs-enforcement (token-only), MCP EMA
 *
 * LedgerCloud: the SaaS MCP server. The lifetime-bounded estate (D16): it
 * enforces from the RAS-issued token alone -- mission claim + audience-scoped
 * authorization_details + DPoP cnf -- with no PDP. Declares the MCP EMA
 * extension. Tools: get_vendor_bank_details (read), post_journal_entry
 * (consequential, reversible).
 */

import { entryMatchesTarget, establishOperationTarget, type OperationContract } from "@mission/core";
import { calculateJwkThumbprint, createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JWK } from "jose";

export const SAAS_RESOURCE = "http://localhost:4406/mcp";

export interface SaasTool {
  name: string;
  action: string;
}
export const SAAS_TOOLS: SaasTool[] = [
  { name: "get_vendor_bank_details", action: "ledger:vendor.read" },
  { name: "post_journal_entry", action: "ledger:journal.write" },
];

/**
 * @spec resource-access#rs-enforcement (#1266, review on PR #1298): the gate
 * for each `constraints` key this resource enforces, against the request it
 * serves. Every tool here addresses one vendor by its `vendor_id` argument
 * and acts on exactly that string, so `vendors` admits the request only when
 * that string is listed. A malformed value makes the entry unenforceable.
 */
const CONSTRAINT_GATES: Readonly<Record<string, (value: unknown, args: Record<string, unknown>) => boolean>> = {
  vendors: (value, args) =>
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((v) => typeof v === "string" && v.length > 0) &&
    typeof args.vendor_id === "string" &&
    value.includes(args.vendor_id),
};

/**
 * @spec resource-access#protected-resource-metadata: the `constraints` keys
 * this resource understands and enforces, advertised as
 * `mission_constraints_supported`. Any other key is one it cannot enforce.
 */
export const SAAS_ENFORCED_CONSTRAINTS: readonly string[] = Object.freeze(Object.keys(CONSTRAINT_GATES));

interface SaasEntry {
  resource: string;
  resource_match?: unknown;
  actions: string[];
  constraints?: unknown;
}

/**
 * @spec resource-access#rs-enforcement: whether one entry, on its own, covers
 * the request. An entry carrying a `constraints` key this resource does not
 * enforce, or a malformed `constraints` member, provides no authority: no key
 * is ever set aside as advisory.
 */
function entryCovers(entry: SaasEntry, target: string, action: string, args: Record<string, unknown>): boolean {
  if (!entry || typeof entry !== "object") return false;
  // The entry matches the operation target with the Resource Access matcher (#1276).
  if (!entryMatchesTarget(entry, target) || !Array.isArray(entry.actions) || !entry.actions.includes(action)) {
    return false;
  }
  if (entry.constraints === undefined) return true;
  const c = entry.constraints;
  if (!c || typeof c !== "object" || Array.isArray(c)) return false;
  return Object.entries(c).every(([key, value]) => {
    const gate = Object.hasOwn(CONSTRAINT_GATES, key) ? CONSTRAINT_GATES[key] : undefined;
    return gate !== undefined && gate(value, args);
  });
}

/**
 * @spec resource-access#resource-matching (#1276, D447, D457): the operation
 * contract a tool declares: how this server establishes the tool's target. A
 * tool with no declaration has no target and is refused.
 */
export type SaasOperationContracts = Readonly<Record<string, OperationContract | readonly OperationContract[] | undefined>>;

/**
 * The LedgerCloud operation contract: explicitly service-level. Every SaaS
 * tool acts on the service `resource` identifies, so an `exact` entry naming
 * that identifier covers the tool's action there; actions determine the
 * permitted operations within the service.
 */
export function serviceLevelContracts(resource: string): SaasOperationContracts {
  return Object.fromEntries(SAAS_TOOLS.map((t) => [t.name, { service: resource }]));
}

interface SaasToken {
  sub: string;
  /**
   * @spec mission#the-mission-claim (#702) — the baseline claim is exactly
   * `{id, issuer}`; this token-only enforcement path (no PDP, no
   * introspection) never reads `authority_hash`, so it is not typed here.
   */
  mission: { id: string; issuer: string };
  authorizationDetails: SaasEntry[];
  cnfJkt: string;
}

export class SaasMcpServer {
  private readonly resolveKey;
  private readonly resource: string;
  private readonly contracts: SaasOperationContracts;
  private readonly journal: Array<{ vendor_id: string; amount: string; mission_id: string }> = [];

  constructor(
    private readonly deps: {
      rasIssuer: string;
      rasJwks: { keys: JWK[] };
      resource?: string;
      /** The tools' operation contracts; defaults to {@link serviceLevelContracts} over `resource`. */
      operationContracts?: SaasOperationContracts;
    },
  ) {
    this.resolveKey = createLocalJWKSet(deps.rasJwks as never);
    this.resource = deps.resource ?? SAAS_RESOURCE;
    this.contracts = deps.operationContracts ?? serviceLevelContracts(this.resource);
  }

  /** RFC 9728 PRM + EMA declaration (client uses ID-JAG/EMA, not local login). */
  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.resource,
      authorization_servers: [this.deps.rasIssuer],
      bearer_methods_supported: ["dpop"],
      "io.modelcontextprotocol/enterprise-managed-authorization": { required: true },
      mission_constraints_supported: [...SAAS_ENFORCED_CONSTRAINTS],
    };
  }

  private async validate(accessToken: string, dpopProof: string, htu: string): Promise<SaasToken> {
    const { payload } = await jwtVerify(accessToken, this.resolveKey, {
      issuer: this.deps.rasIssuer,
      audience: this.resource,
    });
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new Error("token missing cnf.jkt");
    const proofHeader = decodeProtectedHeader(dpopProof);
    const proofJkt = await calculateJwkThumbprint(proofHeader.jwk as never);
    if (proofJkt !== cnf.jkt) throw new Error("DPoP key mismatch");
    const { payload: proof } = await jwtVerify(dpopProof, proofHeader.jwk as never, { typ: "dpop+jwt" });
    if (proof.htu !== htu) throw new Error("DPoP htu mismatch");
    const mission = payload.mission as SaasToken["mission"] | undefined;
    if (!mission?.id) throw new Error("token missing mission claim");
    return {
      sub: payload.sub as string,
      mission,
      authorizationDetails: Array.isArray(payload.authorization_details)
        ? (payload.authorization_details as SaasEntry[])
        : [],
      cnfJkt: cnf.jkt,
    };
  }

  /**
   * Token-only enforcement: one entry of the token's audience-scoped
   * authority must cover the request on its own (@spec
   * resource-access#rs-enforcement). Entries are alternatives, never
   * combined, and one this resource cannot fully enforce lends nothing.
   */
  async callTool(
    tool: string,
    args: Record<string, unknown>,
    accessToken: string,
    dpopProof: string,
  ): Promise<{ ok: boolean; result?: unknown; error?: string }> {
    let token: SaasToken;
    try {
      token = await this.validate(accessToken, dpopProof, this.resource);
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
    const def = SAAS_TOOLS.find((t) => t.name === tool);
    if (!def) return { ok: false, error: "unknown_tool" };
    // @spec resource-access#resource-matching (#1276, D447, D457): the
    // operation target comes from the tool's declared contract, never from
    // this server's own identifier by default, an entry, or an argument. No
    // one target, no operation. The token's audience was validated above, as
    // its own check.
    const target = establishOperationTarget(Object.hasOwn(this.contracts, def.name) ? this.contracts[def.name] : undefined);
    if (!target.ok) return { ok: false, error: "target_unresolvable" };
    const authorized = token.authorizationDetails.some((e) => entryCovers(e, target.target, def.action, args));
    if (!authorized) return { ok: false, error: "out_of_authority" };
    if (tool === "post_journal_entry") {
      this.journal.push({
        vendor_id: String(args.vendor_id),
        amount: String(args.amount),
        mission_id: token.mission.id,
      });
      return { ok: true, result: { posted: true } };
    }
    return { ok: true, result: { vendor_id: String(args.vendor_id), bank_account: "IBAN-DEMO-001" } };
  }

  journalEntries(): ReadonlyArray<{ vendor_id: string; amount: string; mission_id: string }> {
    return this.journal;
  }
}
