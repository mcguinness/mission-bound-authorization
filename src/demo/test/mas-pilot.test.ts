/**
 * @spec authority-server#mission-join, authority-server#mapping-contract,
 * authority-server#limitations, authority-server#high-consequence-binding (#818, D284)
 *
 * The MAS pilot end to end: a stock estate authorization server issues an
 * ordinary DPoP-bound access token through the authorization code grant, the
 * client presents it at the gateway with a `Mission-Reference`, and the
 * reference PEP and PDP join it to a Mission at a separate Mission Issuer under
 * the versioned mapping contract. Nothing is stubbed across the estate seam:
 * the estate's keys, client registrations and accounts are its own, and the
 * gateway trusts the keys the estate publishes at its jwks_uri. The decision
 * point's Resource policy is the pilot's own, stored OpenFGA entitlements for
 * the estate's identities (slice 2), so this file needs a live OpenFGA and is
 * skipped without one; the always-run anchors are the mapping, estate-route
 * and PDP unit files.
 *
 * Each D284 vector here is a gateway outcome: bypass of the gateway, the same
 * `sub` or `client_id` string in another namespace, disabled and reassigned
 * accounts, many-to-one mappings, a missing delegate record, and a joined
 * ordinary token on a high-consequence path.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CANONICAL_RESOURCE, canonicalHtu, dpopProofFor, TOOL_ACTIONS } from "@mission/mcp-payments";
import type { EvaluationRequest } from "@mission/pdp";
import { generateKeyPair } from "jose";
import type { MasPilot } from "../src/mas-pilot/compose.js";
import { obtainEstateToken } from "../src/mas-pilot/estate-client.js";
import { admin, approve, call, composeRecorded, estateToken, openfgaReachable, READ_ACTIONS, reference } from "./mas-pilot-support.js";

const HIGH_CONSEQUENCE = new Set(["irreversible_action", "external_commitment", "privileged_administration"]);

const up = await openfgaReachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the MAS pilot end-to-end tests");

const claimsOf = (token: string) =>
  JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString()) as Record<string, unknown>;

d("MAS pilot: the estate is a separate issuer with its own client registrations (#818)", () => {
  let pilot: MasPilot;
  beforeAll(async () => {
    ({ pilot } = await composeRecorded());
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("issues an ordinary RFC 9068 token under the estate issuer, with no mission claim and a client the MAS never registered", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const claims = claimsOf(credential.token);
    expect(claims.iss).toBe(pilot.estate.issuer);
    expect(claims.iss).not.toBe(pilot.missionIssuer);
    expect(claims.mission).toBeUndefined();
    expect(claims.client_id).toBe("estate-ap-bot-7f3");
    expect(claims.aud).toBe(CANONICAL_RESOURCE);
    expect((claims.cnf as { jkt?: string }).jkt).toEqual(expect.any(String));
  });

  it("refuses to issue for a resource the client's estate registration does not name (invalid_target)", async () => {
    const registration = pilot.estateClients.get("estate-ap-bot-7f3");
    const result = await obtainEstateToken({
      issuer: pilot.estate.issuer,
      clientId: "estate-ap-bot-7f3",
      clientSecret: registration?.client_secret ?? "",
      redirectUri: registration?.redirect_uri ?? "",
      account: "u-1001",
      resource: "https://ledger.estate.invalid/api",
      scope: "invoices.read",
      dpopKeys: await generateKeyPair("ES256", { extractable: true }),
    });
    expect(result).toMatchObject({ ok: false, error: "invalid_target" });
  });
});

d("MAS pilot: the gateway joins estate credentials under the mapping contract (#818, D284)", () => {
  let pilot: MasPilot;
  let requests: EvaluationRequest[];
  let aliceMission: string;
  let danaMission: string;

  beforeAll(async () => {
    ({ pilot, requests } = await composeRecorded());
    aliceMission = approve(pilot, "alice", { label: "alice-reads" });
    danaMission = approve(pilot, "dana", { label: "dana-reads" });
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("permits a joined read: the estate subject and client map to the Mission's own, and authority comes from the Mission", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    // The PEP attested the estate-namespace identity; the PDP mapped it.
    const last = requests.at(-1);
    expect(last?.subject).toEqual({ id: "u-1001", properties: { iss: pilot.estate.issuer } });
    expect(last?.context.actor?.client_id).toBe("estate-ap-bot-7f3");
    expect(last?.context.credential?.issuer).toBe(pilot.estate.issuer);
    // The actor-record lookup used the client the contract maps to, the
    // Mission's own client, which is depth 0.
    expect(last?.context.mission_join).toEqual({ delegate_depth: 0 });
  });

  it("refuses the same estate credential on the resource's own route before any decision, though the gateway admits it (bypass)", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const decided = requests.length;
    const retained = pilot.evidence.all().length;
    const url = pilot.resourceRoute.url;
    // A whole attempt on the resource's own route: the MCP handshake, then the
    // read the gateway permits. Nothing reaches the PEP: no decision request
    // and no evidence record (refusals and decisions are both retained).
    const attempt = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" }, url).then(
      (result) => ({ admitted: true, result }),
      () => ({ admitted: false }),
    );
    expect(requests.length).toBe(decided);
    expect(pilot.evidence.all().length).toBe(retained);
    expect(attempt.admitted).toBe(false);
    // The route answers the handshake 401.
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `DPoP ${credential.token}`,
        dpop: await dpopProofFor(credential.dpopKeys, canonicalHtu(url), "POST", credential.token),
        "mission-reference": reference(pilot, aliceMission),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bypass", version: "0" } },
      }),
    });
    expect(res.status).toBe(401);
    // Positive control: the gateway admits and permits the same credential.
    const viaGateway = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(viaGateway.ok, JSON.stringify(viaGateway)).toBe(true);
  });

  it("never conflates an estate client registered under the Mission's own client_id string: the join denies mission_binding_failed", async () => {
    // The estate registered "ap-agent", the Mission's client_id, but the
    // contract maps no estate client of that name.
    const credential = await estateToken(pilot, "ap-agent", "u-1001", "invoices.read");
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("mission_binding_failed");
  });

  it("never conflates estate account \"alice\" with the Mission subject alice: it joins dana's Mission, which its row maps it to, and not alice's", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "alice", "invoices.read");
    const onAlice = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(onAlice.ok).toBe(false);
    expect(onAlice.denial_reason).toBe("mission_binding_failed");
    const onDana = await call(pilot, credential, danaMission, "get_invoice", { invoice_id: "inv-1" });
    expect(onDana.ok, JSON.stringify(onDana)).toBe(true);
  });

  it("denies a disabled estate account whose row still names the Mission's subject", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1003", "invoices.read");
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("mission_binding_failed");
  });

  it("denies an estate account the contract does not map at all", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1004", "invoices.read");
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("mission_binding_failed");
  });

  it("joins two estate accounts mapped to one Mission subject (many-to-one), and the audit log keeps which account acted", async () => {
    const first = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const second = await estateToken(pilot, "estate-ap-bot-7f3", "u-1002", "invoices.read");
    const before = pilot.mapping.audit().length;
    expect((await call(pilot, first, aliceMission, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    expect((await call(pilot, second, aliceMission, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const decisions = pilot.mapping
      .audit()
      .slice(before)
      .filter((r) => r.kind === "identity" && r.outcome === "resolved");
    expect(decisions.map((r) => (r.kind === "identity" ? [r.from.subject.sub, r.to?.subject.sub] : []))).toEqual([
      ["u-1001", "alice"],
      ["u-1002", "alice"],
    ]);
  });

  it("bounds a joined credential by its own scope as the contract maps it: an action its scope does not carry is refused", async () => {
    // vendors.read is not in this token's scope, though the Mission grants it.
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const res = await call(pilot, credential, aliceMission, "lookup_vendor", { vendor_id: "acme" });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("out_of_authority");
  });
});

d("MAS pilot: delegates need a recorded actor edge under the Mission (#818, D284)", () => {
  let pilot: MasPilot;
  let delegableMission: string;
  beforeAll(async () => {
    ({ pilot } = await composeRecorded());
    delegableMission = approve(pilot, "alice", { label: "delegable", delegable: "subagent-invoice-extractor" });  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("denies a mapped delegate with no actor record, then joins it once the deployment records the edge", async () => {
    const credential = await estateToken(pilot, "estate-extractor-2c1", "u-1001", "invoices.read");
    const missing = await call(pilot, credential, delegableMission, "get_invoice", { invoice_id: "inv-1" });
    expect(missing.ok).toBe(false);
    expect(missing.denial_reason).toBe("mission_binding_failed");
    // The actor records name the Mission-namespace client the contract maps to.
    pilot.actorRecords.record({
      mission: { issuer: pilot.missionIssuer, id: delegableMission },
      clientId: "subagent-invoice-extractor",
      delegatedBy: "ap-agent",
    });
    const recorded = await call(pilot, credential, delegableMission, "get_invoice", { invoice_id: "inv-1" });
    expect(recorded.ok, JSON.stringify(recorded)).toBe(true);
  });
});

d("MAS pilot: a joined ordinary token never takes a high-consequence path (#818, D284)", () => {
  let pilot: MasPilot;
  let requests: EvaluationRequest[];
  let remitMission: string;
  beforeAll(async () => {
    ({ pilot, requests } = await composeRecorded());
    remitMission = approve(pilot, "alice", {
      label: "remittance",
      actions: [...READ_ACTIONS, "payments:remittance.send"],
    });
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("the inventory names every payments tool with its class, and reserves exactly the high-consequence classes for Mission-bound credentials", () => {
    const inventory = new Map(pilot.config.inventory.map((e) => [e.tool, e]));
    expect([...inventory.keys()].sort()).toEqual(Object.keys(TOOL_ACTIONS).sort());
    for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
      expect(inventory.get(tool)?.class, tool).toBe(mapping.actionClass);
      expect(inventory.get(tool)?.gateway, tool).toBe(HIGH_CONSEQUENCE.has(mapping.actionClass ?? "") ? "mission_bound_only" : "joined");
    }
    expect(new Set(pilot.config.mission_bound_only_classes)).toEqual(HIGH_CONSEQUENCE);
  });

  it("denies a remittance under a joined credential whose scope, Mission and Resource policy all carry it, commits nothing, and still permits the joined read", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read remit.send");
    // Resource policy entitles the estate account to pay, so only the class
    // reservation stands between the joined credential and the effect.
    await admin(pilot, "grant", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    try {
      const res = await call(pilot, credential, remitMission, "send_remittance_email", {
        invoice_id: "inv-1",
        idempotency_key: "mas-pilot-remit-0001",
      });
      expect(res.ok).toBe(false);
      expect(res.denial_reason).toBe("mission_binding_failed");
      expect(requests.at(-1)?.context.action_class).toBe("external_commitment");
      expect(pilot.connectors.committedEffects()).toEqual([]);
    } finally {
      await admin(pilot, "revoke", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    }
    const read = await call(pilot, credential, remitMission, "get_invoice", { invoice_id: "inv-1" });
    expect(read.ok, JSON.stringify(read)).toBe(true);
  });
});

d("MAS pilot: a newer contract version moves a reassigned account (#818, D284)", () => {
  let pilot: MasPilot;
  let aliceMission: string;
  let danaMission: string;
  beforeAll(async () => {
    ({ pilot } = await composeRecorded());
    aliceMission = approve(pilot, "alice", { label: "alice-before-reassign" });
    danaMission = approve(pilot, "dana", { label: "dana-after-reassign" });
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("an outstanding estate token for u-1001 stops joining alice's Mission once version 2 reassigns the account to dana", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    expect((await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const v1 = pilot.config.mapping_contract as Record<string, unknown> & { subjects: Array<Record<string, unknown>> };
    const v2 = {
      ...v1,
      version: 2,
      provenance: { source: "estate-directory-export", export_id: "estate-dir-2026-10-19-002", exported_at: "2026-10-19T09:00:00Z" },
      subjects: v1.subjects.map((row) =>
        (row.from as { sub: string }).sub === "u-1001" ? { ...row, to: { iss: pilot.missionIssuer, sub: "dana" } } : row,
      ),
    };
    expect(pilot.mapping.install(v2)).toEqual({ ok: true, version: 2 });
    const onAlice = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(onAlice.ok).toBe(false);
    expect(onAlice.denial_reason).toBe("mission_binding_failed");
    const onDana = await call(pilot, credential, danaMission, "get_invoice", { invoice_id: "inv-1" });
    expect(onDana.ok, JSON.stringify(onDana)).toBe(true);
  });
});

/** The shipped contract at a later version, under a new export identifier. */
function contractVersion(pilot: MasPilot, version: number): Record<string, unknown> {
  return {
    ...(pilot.config.mapping_contract as Record<string, unknown>),
    version,
    provenance: {
      source: "estate-directory-export",
      export_id: `estate-dir-2026-10-19-${String(version).padStart(3, "0")}`,
      exported_at: "2026-10-19T09:00:00Z",
    },
  };
}

d("MAS pilot: a committed containment narrows a joined Mission (#818 review P1)", () => {
  let pilot: MasPilot;
  beforeAll(async () => {
    ({ pilot } = await composeRecorded());
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("denies authority_contained for the action a containment removed, while the uncontained read still permits", async () => {
    const missionId = approve(pilot, "alice", { label: "contained" });
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read vendors.read");
    expect((await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const contained = pilot.kernel.contain(missionId, {
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: new Date().toISOString(), event_id: "mas-pilot-contain-1" },
      remove: [{ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    });
    expect(contained.record.containment?.contained).toEqual([{ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }]);
    const after = await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
    expect(after.ok).toBe(false);
    expect(after.denial_reason).toBe("authority_contained");
    const vendor = await call(pilot, credential, missionId, "lookup_vendor", { vendor_id: "acme" });
    expect(vendor.ok, JSON.stringify(vendor)).toBe(true);
  });
});

d("MAS pilot: an unavailable mapping fails the join, not the credential bound (#818 review P2)", () => {
  let pilot: MasPilot;
  let requests: EvaluationRequest[];
  let aliceMission: string;
  // The mapping cache's clock runs this far behind the PEP's and PDP's, so an
  // install can be stamped already past the staleness bound.
  let mappingSkewMs = 0;
  beforeAll(async () => {
    ({ pilot, requests } = await composeRecorded({ mappingNow: () => new Date(Date.now() - mappingSkewMs) }));
    aliceMission = approve(pilot, "alice", { label: "unavailable-mapping" });
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  const lastIdentityOutcome = () => {
    const record = [...pilot.mapping.audit()].reverse().find((r) => r.kind === "identity");
    return record?.kind === "identity" ? record.outcome : undefined;
  };

  it("control: a usable contract whose scope mapping does not cover the action refuses out_of_authority before any decision", async () => {
    // invoices.read maps to the invoice actions only, not the vendor read.
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const decided = requests.length;
    const res = await call(pilot, credential, aliceMission, "lookup_vendor", { vendor_id: "acme" });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("out_of_authority");
    expect(res.denial_reason).toBeUndefined();
    expect(requests.length).toBe(decided);
  });

  it("an invalidated contract denies mission_binding_failed at the PDP's join, and a newly installed version permits the same request", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    pilot.mapping.invalidate();
    const decided = requests.length;
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("mission_binding_failed");
    expect(requests.length).toBe(decided + 1);
    expect(lastIdentityOutcome()).toBe("no_snapshot");
    expect(pilot.mapping.install(contractVersion(pilot, 2))).toEqual({ ok: true, version: 2 });
    const retry = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(retry.ok, JSON.stringify(retry)).toBe(true);
  });

  it("a contract past its staleness bound denies mission_binding_failed at the PDP's join, and a fresh version permits the same request", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    mappingSkewMs = (pilot.config.mapping_cache.max_stale_seconds + 1) * 1000;
    expect(pilot.mapping.install(contractVersion(pilot, 3))).toEqual({ ok: true, version: 3 });
    mappingSkewMs = 0;
    const decided = requests.length;
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("mission_binding_failed");
    expect(requests.length).toBe(decided + 1);
    expect(lastIdentityOutcome()).toBe("stale");
    expect(pilot.mapping.install(contractVersion(pilot, 4))).toEqual({ ok: true, version: 4 });
    const retry = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(retry.ok, JSON.stringify(retry)).toBe(true);
  });
});
