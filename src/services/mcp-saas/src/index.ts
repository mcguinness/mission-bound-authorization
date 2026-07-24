/**
 * @spec mission#rs-enforcement (token-only), MCP EMA
 *
 * LedgerCloud: the SaaS MCP server. The lifetime-bounded estate (D16): it
 * enforces from the RAS-issued token alone -- mission claim + audience-scoped
 * authorization_details + DPoP cnf -- with no PDP. Declares the MCP EMA
 * extension. Tools: get_vendor_bank_details (read), post_journal_entry
 * (consequential, reversible).
 */

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

interface SaasToken {
  sub: string;
  mission: { id: string; issuer: string; authority_hash: string };
  authorizationDetails: Array<{ resource: string; actions: string[] }>;
  cnfJkt: string;
}

export class SaasMcpServer {
  private readonly resolveKey;
  private readonly resource: string;
  private readonly journal: Array<{ vendor_id: string; amount: string; mission_id: string }> = [];

  constructor(
    private readonly deps: { rasIssuer: string; rasJwks: { keys: JWK[] }; resource?: string },
  ) {
    this.resolveKey = createLocalJWKSet(deps.rasJwks as never);
    this.resource = deps.resource ?? SAAS_RESOURCE;
  }

  /** RFC 9728 PRM + EMA declaration (client uses ID-JAG/EMA, not local login). */
  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.resource,
      authorization_servers: [this.deps.rasIssuer],
      bearer_methods_supported: ["dpop"],
      "io.modelcontextprotocol/enterprise-managed-authorization": { required: true },
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
      authorizationDetails: (payload.authorization_details as SaasToken["authorizationDetails"]) ?? [],
      cnfJkt: cnf.jkt,
    };
  }

  /** Token-only enforcement: action must be within the token's audience-scoped authority. */
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
    const authorized = token.authorizationDetails.some(
      (e) => e.resource === this.resource && e.actions.includes(def.action),
    );
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
