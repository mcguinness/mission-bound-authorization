/**
 * @spec authority-server#reference-tuple (#685 review)
 *
 * `loadView` is keyed by the canonical (issuer, id) tuple, but not every
 * implementation enforces that itself: a store that indexes by `id` alone
 * (or a misconfigured cache) can hand back a real Mission's view for a
 * credential naming that Mission's ID under a DIFFERENT issuer.
 * `Pep.enforceInner` catches this today via its own explicit view-issuer
 * check, but `McpPaymentsServer.toolsList` and `Pep.reverifyList` did not:
 * they trusted whatever the injected loader returned. Pure unit tests --
 * neither method touches FGA -- so these never skip.
 */

import { describe, expect, it } from "vitest";
import type { Fga, MissionView } from "@mission/pdp";
import {
  buildListEffectiveParams,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  parameterDigest,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "../src/index.js";

// @spec runtime-evidence#decision-evidence-object (#741): one bundle per
// test module. `signing`/`resolver` wire the PEP's store; `decide` is the
// decision point's entry point, which closes over the PDP's emission path.
const EVIDENCE_KEYS = createEphemeralEvidenceKeys();

const REAL_ISSUER = "https://real-issuer.test";
const WRONG_ISSUER = "https://attacker-issuer.test";
const SHARED_ID = "msn_shared_id";

/** The Mission a legitimate, different issuer actually owns. */
const REAL_VIEW: MissionView = {
  id: SHARED_ID,
  issuer: REAL_ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:realhash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.list", "payments:payment.execute"],
      constraints: { vendors: ["globex"] },
    },
  ],
  subject: { iss: REAL_ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

/** A credential naming the SAME Mission ID under a DIFFERENT (wrong) issuer. */
const WRONG_ISSUER_TOKEN: TokenFacts = {
  sub: "mallory",
  clientId: "some-other-client",
  mission: { id: SHARED_ID, issuer: WRONG_ISSUER, authority_hash: "sha-256:realhash" },
  cnfJkt: "jkt-mallory",
};

/**
 * A deliberately NONCONFORMING loader (@spec authority-server#reference-tuple):
 * matches on `id` alone, ignoring the requested issuer -- exactly the shape a
 * real (issuer, id)-agnostic store, or a cache keyed only on Mission ID,
 * could take. Proves `toolsList`/`reverifyList` do not simply trust it.
 */
const nonconformingLoadView = (ref: { id: string }) =>
  ref.id === REAL_VIEW.id
    ? { view: REAL_VIEW, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
    : undefined;

function build(): { pep: Pep; server: McpPaymentsServer } {
  const payments = new PaymentsStore();
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const pep = new Pep({
    decide: EVIDENCE_KEYS.decide,
    payments,
    evidence,
    // Never reached: neither reverifyList nor toolsList calls into FGA.
    fga: {} as unknown as Fga,
    modelId: "unused",
    loadView: nonconformingLoadView,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf({ name: "payments" }),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView: nonconformingLoadView,
    jwks: { keys: [] },
    issuer: "https://as.test",
    serverCard: { name: "payments" },
  });
  return { pep, server };
}

describe("a same-ID different-issuer collision is a miss for every loadView consumer, not just enforceInner (#685 review)", () => {
  it("toolsList() exposes nothing for a credential naming the wrong issuer, even though a nonconforming loader would hand back the real Mission's view", () => {
    const { server } = build();
    expect(server.toolsList(WRONG_ISSUER_TOKEN)).toEqual([]);
  });

  it("reverifyList() cannot consume the wrong Mission's data: a digest crafted to match what the wrongly-returned view would produce still fails closed", async () => {
    const { pep } = build();
    // The normal form reverifyList would (wrongly) recompute if it used
    // REAL_VIEW's own entry: its `vendors` constraint, no requested vendor.
    // Matching expectedDigest to this proves the refusal below comes from
    // the loaded-view check, not from an unrelated digest mismatch --
    // absent that check, this call returns true.
    const effective = buildListEffectiveParams({
      action: "payments:invoice.list",
      resource: CANONICAL_RESOURCE,
      vendor_scope: ["globex"],
      vendor_scope_source: "entry",
    });
    const wronglyConsumableDigest = parameterDigest(effective);

    const ok = await pep.reverifyList(effective, wronglyConsumableDigest, WRONG_ISSUER_TOKEN);
    expect(ok).toBe(false);
  });
});
