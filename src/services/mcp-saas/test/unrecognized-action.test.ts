/**
 * @spec resource-access#entry-validation (#1376)
 *
 * An action value this resource does not define grants nothing, and it does
 * not make its entry one the resource cannot fully enforce: the entry's other
 * actions still authorize. The SaaS resource evaluates the requested action
 * alone against each entry's `actions`, so a value no tool maps to is never
 * matched and never taints the rest of the entry.
 *
 * Tokens are minted as the RAS would issue them, so the decision below is the
 * resource server's own.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { SAAS_RESOURCE, SAAS_TOOLS, SaasMcpServer } from "../src/index.js";

const RAS_ISS = "https://ras.ledgercloud.test";
const READ = "ledger:vendor.read";
const WRITE = "ledger:journal.write";
/** An action in the LedgerCloud namespace that no tool of this resource defines. */
const UNDEFINED_ACTION = "ledger:vendor.purge";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
let rasKeys: Keys;
let agentKeys: Keys;
let agentJkt: string;
let saas: SaasMcpServer;

beforeAll(async () => {
  rasKeys = await generateKeyPair("ES256", { extractable: true });
  agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));
  const rasPub = { ...(await exportJWK(rasKeys.publicKey)), kid: "ras-token", alg: "ES256" };
  saas = new SaasMcpServer({ rasIssuer: RAS_ISS, rasJwks: { keys: [rasPub as never] }, trustedMissionIssuers: ["https://as.test"] });
});

/** A RAS-issued local token carrying exactly one entry with `actions`. */
async function tokenFor(actions: string[]): Promise<string> {
  const nowS = Math.floor(Date.now() / 1000);
  return new SignJWT({
    mission: { id: "msn-direct", issuer: "https://as.test" },
    authorization_details: [{ type: "mission_resource_access", resource: SAAS_RESOURCE, actions }],
    cnf: { jkt: agentJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: "ras-token", typ: "at+jwt" })
    .setSubject("alice-ledgercloud")
    .setIssuer(RAS_ISS)
    .setAudience(SAAS_RESOURCE)
    .setIssuedAt(nowS)
    .setExpirationTime(nowS + 120)
    .sign(rasKeys.privateKey);
}

async function dpopProof(): Promise<string> {
  return new SignJWT({ htu: SAAS_RESOURCE, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(agentKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(agentKeys.privateKey);
}

async function read(token: string) {
  return saas.callTool("get_vendor_bank_details", { vendor_id: "acme" }, token, await dpopProof());
}
async function write(token: string) {
  return saas.callTool("post_journal_entry", { vendor_id: "acme", amount: "125.00" }, token, await dpopProof());
}

describe("an unrecognized action value grants nothing (@spec resource-access#entry-validation, #1376)", () => {
  it("the fixture's action is one no tool of this resource defines", () => {
    expect(SAAS_TOOLS.map((t) => t.action)).not.toContain(UNDEFINED_ACTION);
  });

  it("an entry carrying an action this resource does not define still authorizes the actions it does define", async () => {
    const token = await tokenFor([READ, UNDEFINED_ACTION]);
    expect(await read(token)).toMatchObject({ ok: true });
    // Only the listed actions: the undefined value lends the entry nothing more.
    const before = saas.journalEntries().length;
    expect(await write(token)).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
  });

  it("an entry whose only action this resource does not define authorizes no operation", async () => {
    const token = await tokenFor([UNDEFINED_ACTION]);
    expect(await read(token)).toEqual({ ok: false, error: "out_of_authority" });
    const before = saas.journalEntries().length;
    expect(await write(token)).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
  });

  it("an entry carrying both defined actions and an undefined one authorizes both defined actions", async () => {
    const token = await tokenFor([UNDEFINED_ACTION, READ, WRITE]);
    expect(await read(token)).toMatchObject({ ok: true });
    const before = saas.journalEntries().length;
    expect(await write(token)).toMatchObject({ ok: true });
    expect(saas.journalEntries()).toHaveLength(before + 1);
  });
});
