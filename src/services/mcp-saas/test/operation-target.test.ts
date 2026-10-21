/**
 * @spec resource-access#resource-matching, resource-access#rs-enforcement
 * (#1276, D447, D457): the token-only SaaS resource establishes each tool's
 * operation target from its declared, service-level contract and matches the
 * token's entries against it with the Resource Access matcher. It never falls
 * back to its own identifier for a tool that declares no contract.
 */

import { CompactSign, calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { SAAS_RESOURCE, SaasMcpServer, type SaasOperationContracts, serviceLevelContracts } from "../src/index.js";

const RAS_ISS = "https://ras.ledgercloud.test";
let rasKey: CryptoKey;
let rasJwk: JWK;
let holder: { privateKey: CryptoKey; publicKey: CryptoKey };
let holderJwk: JWK;
let holderJkt: string;

beforeAll(async () => {
  const ras = await generateKeyPair("ES256", { extractable: true });
  rasKey = ras.privateKey;
  rasJwk = { ...(await exportJWK(ras.publicKey)), kid: "ras-1", alg: "ES256" };
  holder = await generateKeyPair("ES256", { extractable: true });
  holderJwk = await exportJWK(holder.publicKey);
  holderJkt = await calculateJwkThumbprint(holderJwk);
});

const entry = (resource: string, over: Record<string, unknown> = {}) => ({
  type: "mission_resource_access",
  resource,
  actions: ["ledger:vendor.read", "ledger:journal.write"],
  ...over,
});

/** A DPoP proof for one SaaS request. */
async function proofNow(now: number): Promise<string> {
  return new SignJWT({ htu: SAAS_RESOURCE, htm: "POST", jti: crypto.randomUUID(), iat: now })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: holderJwk })
    .sign(holder.privateKey);
}

/** A RAS-issued local token and its DPoP proof, as the SaaS resource validates them. */
async function present(authorization_details: unknown[]): Promise<[string, string]> {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    sub: "alice@ledgercloud",
    mission: { id: "msn_1276_saas", issuer: "https://as.test" },
    authorization_details,
    cnf: { jkt: holderJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: "ras-1" })
    .setIssuer(RAS_ISS)
    .setAudience(SAAS_RESOURCE)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(rasKey);
  return [token, await proofNow(now)];
}

/** The same token signed over exact JSON text, so an entry's `resource` can be spelled with JSON escapes. */
async function presentJsonText(detailsJson: string): Promise<[string, string]> {
  const now = Math.floor(Date.now() / 1000);
  const payload =
    `{"iss":${JSON.stringify(RAS_ISS)},"aud":${JSON.stringify(SAAS_RESOURCE)},"sub":"alice@ledgercloud",` +
    `"mission":{"id":"msn_1276_saas","issuer":"https://as.test"},"authorization_details":${detailsJson},` +
    `"cnf":{"jkt":${JSON.stringify(holderJkt)}},"iat":${now},"exp":${now + 300}}`;
  const token = await new CompactSign(new TextEncoder().encode(payload)).setProtectedHeader({ alg: "ES256", kid: "ras-1" }).sign(rasKey);
  return [token, await proofNow(now)];
}

const saas = (operationContracts?: SaasOperationContracts) =>
  new SaasMcpServer({ rasIssuer: RAS_ISS, rasJwks: { keys: [rasJwk] }, trustedMissionIssuers: ["https://as.test"], ...(operationContracts ? { operationContracts } : {}) });

describe("the SaaS resource matches the token's entries against the operation target (@spec resource-access#resource-matching, #1276)", () => {
  it("under its service-level contract, only an exact entry spelled as the target authorizes; another spelling, a prefix entry or an unrecognized resource_match does not", async () => {
    const [ok, okProof] = await present([entry(SAAS_RESOURCE)]);
    expect(await saas().callTool("get_vendor_bank_details", { vendor_id: "acme" }, ok, okProof)).toMatchObject({ ok: true });
    // Compared after JSON decoding: the token's JSON text spells the resource with `\/` escapes.
    const escaped = JSON.stringify(SAAS_RESOURCE).replaceAll("/", "\\/");
    expect(escaped).toContain("\\/");
    const [esc, escProof] = await presentJsonText(`[{"type":"mission_resource_access","resource":${escaped},"actions":["ledger:vendor.read"]}]`);
    expect(await saas().callTool("get_vendor_bank_details", { vendor_id: "acme" }, esc, escProof)).toMatchObject({ ok: true });
    const u = new URL(SAAS_RESOURCE);
    for (const details of [
      [entry(`${u.protocol.toUpperCase()}//${u.host.toUpperCase()}${u.pathname}`)],
      [entry(`${SAAS_RESOURCE}/`)],
      [entry(`${SAAS_RESOURCE}?`)],
      [entry(SAAS_RESOURCE, { resource_match: "glob" })],
    ]) {
      const [token, proof] = await present(details);
      expect(await saas().callTool("get_vendor_bank_details", { vendor_id: "acme" }, token, proof), JSON.stringify(details)).toEqual({
        ok: false,
        error: "out_of_authority",
      });
    }
  });

  it("a prefix entry covers the service-level target at its base and a finer declared target beneath it, never a sibling sharing its characters or a target a decoded dot-segment moves out; a prefix entry whose resource carries a query provides no authority (#1276)", async () => {
    const declared = serviceLevelContracts(SAAS_RESOURCE);
    const JOURNAL = `${SAAS_RESOURCE}/journal`;
    const post = async (contracts: SaasOperationContracts, details: unknown[]) => {
      const [token, proof] = await present(details);
      const server = saas(contracts);
      const res = await server.callTool("post_journal_entry", { vendor_id: "acme", amount: "10.00" }, token, proof);
      return { res, posted: server.journalEntries().length };
    };
    // The base itself, under the shipped service-level contract.
    const atBase = await post(declared, [entry(SAAS_RESOURCE, { resource_match: "prefix" })]);
    expect(atBase.res).toMatchObject({ ok: true });
    expect(atBase.posted).toBe(1);
    // A finer declared target beneath the base, and the finer base itself.
    for (const base of [SAAS_RESOURCE, JOURNAL, `${JOURNAL}/`]) {
      const beneath = await post({ ...declared, post_journal_entry: { service: `${JOURNAL}/entries` } }, [entry(base, { resource_match: "prefix" })]);
      expect(beneath.res, base).toMatchObject({ ok: true });
      expect(beneath.posted, base).toBe(1);
    }
    // Not covered: a sibling sharing the base's characters, a target a decoded
    // dot-segment moves out of the base, the bare path under a base ending in
    // /, and an exact entry naming the base.
    const refused: Array<[string, string, Record<string, unknown>]> = [
      ["sibling", `${SAAS_RESOURCE}/journal-archive/entries`, { resource: JOURNAL, resource_match: "prefix" }],
      ["dot-segment", `${JOURNAL}/%2e%2e/vendors`, { resource: JOURNAL, resource_match: "prefix" }],
      ["bare path under a / base", JOURNAL, { resource: `${JOURNAL}/`, resource_match: "prefix" }],
      ["exact base", `${JOURNAL}/entries`, { resource: JOURNAL }],
      ["prefix with a query", `${JOURNAL}?x=1`, { resource: `${JOURNAL}?x=1`, resource_match: "prefix" }],
    ];
    for (const [label, target, over] of refused) {
      const out = await post({ ...declared, post_journal_entry: { service: target } }, [entry(SAAS_RESOURCE, over)]);
      expect(out.res, label).toEqual({ ok: false, error: "out_of_authority" });
      expect(out.posted, label).toBe(0);
    }
  });

  it("refuses a tool whose contract names a target that breaks RFC 3986 syntax as target_unresolvable, though the token's entry names the identical string", async () => {
    // pct-encoded = "%" HEXDIG HEXDIG (RFC 3986, Section 2.1), and an http
    // or https target names a non-empty host (RFC 9110, Section 4.2).
    const declared = serviceLevelContracts(SAAS_RESOURCE);
    for (const target of [`${SAAS_RESOURCE}/%zz`, `${SAAS_RESOURCE}%`, `${SAAS_RESOURCE}/%4`, "https:///journal"]) {
      const [token, proof] = await present([entry(SAAS_RESOURCE), entry(target)]);
      const server = saas({ ...declared, post_journal_entry: { service: target } });
      expect(await server.callTool("post_journal_entry", { vendor_id: "acme", amount: "10.00" }, token, proof), target).toEqual({
        ok: false,
        error: "target_unresolvable",
      });
      expect(server.journalEntries(), target).toHaveLength(0);
    }
    // Control: the declared service-level contract posts the entry for the same token shape.
    const [token, proof] = await present([entry(SAAS_RESOURCE)]);
    const server = saas(declared);
    expect(await server.callTool("post_journal_entry", { vendor_id: "acme", amount: "10.00" }, token, proof)).toMatchObject({ ok: true });
    expect(server.journalEntries()).toHaveLength(1);
  });

  it("refuses a tool with no contract, an unsupported contract or ambiguous contracts as target_unresolvable, though the token's entry names the service root", async () => {
    const declared = serviceLevelContracts(SAAS_RESOURCE);
    const variants: Array<[string, SaasOperationContracts]> = [
      ["no contract", { ...declared, post_journal_entry: undefined }],
      ["unsupported contract", { ...declared, post_journal_entry: { template: `${SAAS_RESOURCE}/journal/{id}` } as never }],
      ["ambiguous contracts", { ...declared, post_journal_entry: [{ service: SAAS_RESOURCE }, { service: `${SAAS_RESOURCE}/journal` }] }],
    ];
    for (const [label, contracts] of variants) {
      const [token, proof] = await present([entry(SAAS_RESOURCE)]);
      const server = saas(contracts);
      expect(await server.callTool("post_journal_entry", { vendor_id: "acme", amount: "10.00" }, token, proof), label).toEqual({
        ok: false,
        error: "target_unresolvable",
      });
      expect(server.journalEntries(), label).toHaveLength(0);
    }
    // Control: the declared service-level contract posts the entry.
    const [token, proof] = await present([entry(SAAS_RESOURCE)]);
    const server = saas(declared);
    expect(await server.callTool("post_journal_entry", { vendor_id: "acme", amount: "10.00" }, token, proof)).toMatchObject({ ok: true });
    expect(server.journalEntries()).toHaveLength(1);
  });
});
