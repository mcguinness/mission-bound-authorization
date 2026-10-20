/**
 * @spec resource-access#rs-enforcement, mission#rs-enforcement (#1362)
 *
 * The SaaS resource gives each member of a `mission_resource_access` entry
 * its resource-server role. It enforces `type`, `resource`, `resource_match`,
 * `actions` and `constraints`, disregards `delegation`, and implements no
 * extension member, so an entry carrying any other member (`locations`,
 * `capability_sources`, or a name it does not recognize) provides no
 * authority there. A request only such an entry covers is refused with the
 * resource's usual insufficient-authority error and has no effect. Entries
 * are alternatives, so a clean entry that covers the whole request on its
 * own still authorizes beside one the resource cannot fully enforce.
 *
 * Every case mints the RAS-issued token directly: the pipeline cannot
 * produce these entries. The RAS refuses a grant whose entry carries
 * `locations`, derivation drops a member it does not define, the kernel
 * attaches `capability_sources` only to catalog-sourced actions (no
 * `ledger:` action is), and the SaaS ceiling grants no delegation. A trusted
 * issuer's token can still carry any of them, which is what SaaS must handle.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { SAAS_RESOURCE, SaasMcpServer } from "../src/index.js";

const RAS_ISS = "https://ras.ledgercloud.test";
const READ = "ledger:vendor.read";
const WRITE = "ledger:journal.write";
const REFUSED = { ok: false, error: "out_of_authority" };

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
  saas = new SaasMcpServer({ rasIssuer: RAS_ISS, rasJwks: { keys: [rasPub as never] } });
});

/** A clean entry: only the members SaaS enforces. */
const entry = (actions: string[], over: Record<string, unknown> = {}): Record<string, unknown> => ({
  type: "mission_resource_access",
  resource: SAAS_RESOURCE,
  actions,
  ...over,
});

/** A RAS-issued local token carrying exactly `authorizationDetails`. */
async function mintedToken(authorizationDetails: unknown[]): Promise<string> {
  const nowS = Math.floor(Date.now() / 1000);
  return new SignJWT({
    mission: { id: "msn-member-roles", issuer: "https://as.test" },
    authorization_details: authorizationDetails,
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

async function write(token: string, vendorId = "acme") {
  return saas.callTool("post_journal_entry", { vendor_id: vendorId, amount: "125.00" }, token, await dpopProof());
}
async function read(token: string, vendorId = "acme") {
  return saas.callTool("get_vendor_bank_details", { vendor_id: vendorId }, token, await dpopProof());
}

/** Expect both tools refused for `details`, and no journal entry posted. */
async function expectRefusedWithNoEffect(details: unknown[]): Promise<void> {
  const token = await mintedToken(details);
  const label = JSON.stringify(details);
  const before = saas.journalEntries().length;
  expect(await write(token), label).toEqual(REFUSED);
  expect(saas.journalEntries(), label).toHaveLength(before);
  expect(await read(token), label).toEqual(REFUSED);
}

describe("the SaaS resource gives each entry member its resource-server role (@spec resource-access#rs-enforcement, #1362)", () => {
  it("refuses a journal write whose only entry carries a member it does not recognize, with no effect", async () => {
    // Decided by presence: a null or false value makes the entry unenforceable too.
    for (const value of [true, null, false]) {
      await expectRefusedWithNoEffect([entry([READ, WRITE], { x_member: value })]);
    }
    // Control: the same entry without the member authorizes the write.
    const before = saas.journalEntries().length;
    const res = await write(await mintedToken([entry([READ, WRITE])]));
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(before + 1);
  });

  it("refuses an entry carrying the RFC 9396 locations field, whatever its value", async () => {
    for (const locations of [[SAAS_RESOURCE], []]) {
      await expectRefusedWithNoEffect([entry([READ, WRITE], { locations })]);
    }
  });

  it("refuses an entry carrying capability_sources, an extension member this resource does not implement", async () => {
    const binding = {
      action: WRITE,
      tool_id: "post_journal_entry",
      source_uri: SAAS_RESOURCE,
      source_digest: "sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
      operation_ref: "post_journal_entry",
    };
    await expectRefusedWithNoEffect([entry([READ, WRITE], { capability_sources: [binding] })]);
  });

  it("disregards delegation, a member a companion profile adds inside it included, and still enforces the entry's other members", async () => {
    const delegation = {
      max_depth: 1,
      allowed_delegates: [{ sub_profile: "ai_agent" }],
      children: { max_children: 2, x_companion_member: true },
    };
    const token = await mintedToken([entry([WRITE], { delegation, constraints: { vendors: ["acme"] } })]);
    const before = saas.journalEntries().length;
    const permitted = await write(token, "acme");
    expect(permitted.ok, JSON.stringify(permitted)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(before + 1);
    // The entry's own members still bind: an unlisted vendor and an unlisted action are refused.
    expect(await write(token, "globex")).toEqual(REFUSED);
    expect(await read(token, "acme")).toEqual(REFUSED);
    expect(saas.journalEntries()).toHaveLength(before + 1);
  });

  it("refuses an entry whose type it does not implement, though its resource and actions cover the request", async () => {
    const { type: _type, ...untyped } = entry([READ, WRITE]);
    for (const other of [entry([READ, WRITE], { type: "payment_initiation" }), untyped]) {
      await expectRefusedWithNoEffect([other]);
    }
  });
});

describe("an entry SaaS cannot fully enforce lends no authority, and a clean entry still authorizes beside it (@spec resource-access#rs-enforcement, #1362)", () => {
  it("authorizes a journal write through a clean covering entry listed after one carrying a member it does not recognize", async () => {
    const token = await mintedToken([entry([WRITE], { x_member: true }), entry([WRITE])]);
    const before = saas.journalEntries().length;
    const res = await write(token);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(before + 1);
  });

  it("refuses a request that only the entry carrying a member it does not recognize covers, while a clean entry still authorizes its own action", async () => {
    const token = await mintedToken([entry([WRITE], { x_member: true }), entry([READ])]);
    const before = saas.journalEntries().length;
    expect(await write(token)).toEqual(REFUSED);
    expect(saas.journalEntries()).toHaveLength(before);
    const res = await read(token);
    expect(res.ok, JSON.stringify(res)).toBe(true);
  });
});
