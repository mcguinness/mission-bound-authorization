/**
 * @spec draft-mcguinness-oauth-mission-work-products — the incident reconstructed
 * against the LIVE stack (a real Authorization Server over HTTP plus the
 * OpenFGA-backed PDP; nothing simulated).
 *
 * The one invariant under test: no authority may be acquired by information
 * propagation alone. An agent may inherit another agent's KNOWLEDGE; it never
 * inherits another agent's AUTHORITY.
 *
 * Mission A (agent A1) produces a shared-state work product whose CONTENT names a
 * credential and an endpoint and says the approach worked: useful knowledge
 * pointing at capability. An agent under Mission B reads it. B now HAS the
 * content and its provenance (knowledge changed). B gains NO authority: the PDP
 * denies the action the artifact effectively proposes under B's OWN Authority Set
 * (out_of_authority), because the artifact conferred nothing. The ONLY way B
 * acquires the authority to act on what it read is a Child Mission bounded by B's
 * parent (subset rule), obtained through the authority plane. The assertion that
 * carries the whole point: reading the artifact changed what B KNOWS, not what B
 * may DO.
 *
 * Skipped automatically when OpenFGA is unreachable (docker compose up).
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  evaluate,
  Fga,
  type MissionView,
  relationForAction,
  stalenessBoundSeconds,
} from "@mission/pdp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  bindWorkProduct,
  type BuiltAs,
  buildAuthorizationServer,
  ChildDelegationError,
  createChildMission,
  ingestWorkProduct,
  isSubsetSet,
  produceWorkProduct,
  ProvenanceCustodyError,
  validateMissionIntent,
  verifyWorkProductBinding,
} from "../src/index.js";
import { exportJWK, generateKeyPair } from "jose";
import { aiAgents } from "./actor-profiles.helper.js";

const PORT = 14498;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const EXPIRES_AT = "2027-01-01T00:00:00Z";

/** The action the artifact effectively proposes (use the credential at the endpoint). */
const ARTIFACT_ACTION = "payments:remittance.send";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    const res = await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } });
    return res.ok;
  } catch {
    return false;
  }
}

const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping work-products incident e2e (docker compose up)");

let as: BuiltAs;
let server: Server;
let fga: Fga;
let modelId: string;

/** A restated ceiling entry for the given actions, so the derived entry carries
 * the Common Constraints (max_amount/vendors) and inherits the ceiling delegation. */
const proposed = (actions: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

const intent = (goal: string) =>
  validateMissionIntent(JSON.stringify({ goal, resources: [RESOURCE], expires_at: EXPIRES_AT }));

/** The PDP's view of a Mission (the demo stack's viewFor mapping). */
function viewFor(missionId: string): MissionView {
  const r = as.kernel.get(missionId);
  if (!r) throw new Error(`mission ${missionId} missing`);
  const fresh = as.kernel.applyExpiry(r);
  return {
    id: fresh.id,
    issuer: fresh.issuer,
    state: fresh.state,
    version: fresh.version,
    authority_hash: fresh.authority_hash,
    authority_set: fresh.authority_set,
    subject: fresh.subject,
    client_id: fresh.client_id,
    ...(fresh.containment
      ? { containment: { version: fresh.containment.containment_version, contained: fresh.containment.contained } }
      : {}),
  };
}

const evalAction = async (missionId: string, action: string) => {
  const view = viewFor(missionId);
  return evaluate(
    {
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
      action: { name: action },
      context: { audience: RESOURCE, mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash } },
    },
    { view, fga, modelId, now: () => new Date(), stalenessBoundSeconds, relationForAction },
  );
};

d("work products: information may propagate, authority may not", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({
      issuer: ISSUER,
      allowHeadlessAdjudication: true,
      actorProfiles: aiAgents("agent-B1"),
    });
    server = as.provider.listen(PORT);
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });
  afterAll(() => {
    server?.close();
  });

  it("reading a work product changes what B KNOWS, not what B may DO", async () => {
    // Mission A (agent A1): an active Mission that legitimately holds the
    // capability, did the remittance, and wrote the result to shared state.
    const missionA = as.kernel.approve({
      intent: intent("Pay Acme and send remittance"),
      proposedAuthority: proposed(["payments:invoice.read", "payments:remittance.send"]),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "agent-A1",
      approvalEventId: "apev-wp-A",
    });

    // Parent P: the standing authority that HOLDS the remittance capability (its
    // derived entry inherits the ceiling delegation on-switch, so it is delegable).
    const parentP = as.kernel.approve({
      intent: intent("Acme payments program"),
      proposedAuthority: proposed(["payments:invoice.read", "payments:remittance.send"]),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "parent-P",
      approvalEventId: "apev-wp-P",
    });

    // Mission B: a Child Mission bounded by P, deliberately NARROW (invoice.read
    // only). agent-B1 is the agent under Mission B that will read the artifact.
    const { child: missionB } = createChildMission(as.kernel, {
      parentId: parentP.id,
      intent: intent("Reconcile Acme invoices"),
      proposedAuthority: proposed(["payments:invoice.read"]),
      childActor: { sub: "agent-B1", sub_profile: "ai_agent" },
    });
    expect(missionB.parent?.id).toBe(parentP.id);
    // B's own Authority Set does not include the artifact's proposed action.
    expect(missionB.authority_set.some((e) => e.actions.includes(ARTIFACT_ACTION))).toBe(false);

    // Baseline BEFORE the artifact exists: B is already denied the proposed action
    // under its OWN Authority Set. Snapshot B's authority state so we can prove the
    // ingest commits nothing.
    const beforeDeny = await evalAction(missionB.id, ARTIFACT_ACTION);
    expect(beforeDeny.decision).toBe(false);
    expect(beforeDeny.context.denial_reason).toBe("out_of_authority");
    // Pin the mechanism: the SAME PDP on B PERMITS an action B IS authorized for
    // (invoice.read). B's Mission is live, its view is consistent, and the FGA
    // path works for B, so the remittance denial is attributable to the missing
    // Authority Set entry alone, not a dead view or a broken authority check.
    const bAuthorized = await evalAction(missionB.id, "payments:invoice.read");
    expect(bAuthorized.decision, JSON.stringify(bAuthorized.context)).toBe(true);
    const bBefore = as.kernel.get(missionB.id);
    const effBefore = as.kernel.effectiveAuthoritySet(bBefore!);
    const versionBefore = bBefore!.version;
    const hashBefore = bBefore!.authority_hash;

    // --- Mission A produces the shared-state work product -----------------------
    // The CONTENT names a credential and an endpoint and says the approach worked:
    // useful knowledge pointing straight at capability.
    const content = {
      note: "remittance approach worked end to end for Acme",
      credential: "svc:remittance-signing-key",
      endpoint: "https://payments.example/remittance/send",
    };
    const workProduct = produceWorkProduct(as.kernel, {
      missionId: missionA.id,
      deploymentId: "dep_A1",
      producer: "agent:A1",
      mediator: { id: "harness:dep_A1", role: "harness" },
      content,
    });
    // Provenance is attribution to the PRODUCING Mission/principal, NOT the reader.
    expect(workProduct.provenance.kind).toBe("artifact");
    expect(workProduct.provenance.mission_id).toBe(missionA.id);
    expect(workProduct.provenance.mission_id).not.toBe(missionB.id);
    expect(workProduct.provenance.producer).toBe("agent:A1");
    expect(workProduct.provenance.deployment_id).toBe("dep_A1");

    // --- The agent under Mission B reads it -------------------------------------
    const ingested = ingestWorkProduct(as.kernel, { workProduct, receivingMissionId: missionB.id });

    // (1) Knowledge changed: B now HAS the content AND its provenance.
    expect(ingested.content).toEqual(content);
    expect(ingested.content.credential).toBe("svc:remittance-signing-key");
    expect(ingested.content.endpoint).toBe("https://payments.example/remittance/send");
    // The provenance claim attributes the artifact to A (a provenance claim), and
    // makes NO claim that B may act (it is not an authority claim).
    expect(ingested.provenance.mission_id).toBe(missionA.id);
    expect(ingested.provenance.producer).toBe("agent:A1");

    // Provenance chain: a derived work product carries a back-reference to the
    // artifact it derived from, and that reference survives ingest unchanged.
    const derived = produceWorkProduct(as.kernel, {
      missionId: missionA.id,
      deploymentId: "dep_A1",
      producer: "agent:A1",
      mediator: { id: "harness:dep_A1", role: "harness" },
      content: { note: "follow-up derived from the remittance note" },
      parentArtifact: "artifact:remittance-note-v1",
    });
    expect(derived.provenance.parent_artifact).toBe("artifact:remittance-note-v1");
    const ingestedDerived = ingestWorkProduct(as.kernel, {
      workProduct: derived,
      receivingMissionId: missionB.id,
    });
    expect(ingestedDerived.provenance.parent_artifact).toBe("artifact:remittance-note-v1");

    // (2) Authority did NOT change. The ingest committed nothing to B: same
    // version, same authority_hash, byte-identical effective Authority Set.
    const bAfter = as.kernel.get(missionB.id);
    expect(bAfter!.version).toBe(versionBefore);
    expect(bAfter!.authority_hash).toBe(hashBefore);
    expect(as.kernel.effectiveAuthoritySet(bAfter!)).toEqual(effBefore);
    // The artifact did not add the proposed action to B's Authority Set.
    expect(bAfter!.authority_set.some((e) => e.actions.includes(ARTIFACT_ACTION))).toBe(false);

    // The SAME PDP request that was denied before ingest is denied identically
    // after: reading changed knowledge, not authority. This is the headline.
    const afterDeny = await evalAction(missionB.id, ARTIFACT_ACTION);
    expect(afterDeny.decision).toBe(false);
    expect(afterDeny.context.denial_reason).toBe("out_of_authority");
    expect(afterDeny.decision).toBe(beforeDeny.decision);
    expect(afterDeny.context.denial_reason).toBe(beforeDeny.context.denial_reason);

    // (3) B cannot MINT the capability from itself either. B is delegable (its
    // entry inherited the ceiling on-switch), but the subset rule is what stops
    // it: B's Authority Set lacks remittance.send, so a Child of B claiming it is
    // refused not_strict_subset. The artifact conferred nothing, on the
    // delegation plane as well as the enforcement plane.
    try {
      createChildMission(as.kernel, {
        parentId: missionB.id,
        intent: intent("Escalate: send remittance from what I read"),
        proposedAuthority: proposed([ARTIFACT_ACTION]),
        childActor: { sub: "agent-B1", sub_profile: "ai_agent" },
      });
      expect.unreachable("B minted remittance authority from an artifact it merely read");
    } catch (e) {
      expect(e).toBeInstanceOf(ChildDelegationError);
      expect((e as ChildDelegationError).reason).toBe("not_strict_subset");
    }

    // --- The ONLY way B acquires the authority: the authority plane -------------
    // A Child Mission bounded by B's parent P (subset rule), granting a bounded
    // capability, still a subset of the parent. Same agent (agent-B1) that read
    // the artifact, so "the agent got authority only through the plane" is literal.
    const { child: childC, evidence } = createChildMission(as.kernel, {
      parentId: parentP.id,
      intent: intent("Send the approved Acme remittance"),
      proposedAuthority: proposed([ARTIFACT_ACTION]),
      childActor: { sub: "agent-B1", sub_profile: "ai_agent" },
    });
    expect(evidence.decision).toBe("created");
    expect(evidence.attenuation.result).toBe("strict_subset");
    // Still a subset of the parent: authority flowed bounded, through the plane.
    expect(isSubsetSet(childC.authority_set, parentP.authority_set)).toBe(true);
    expect(childC.parent?.id).toBe(parentP.id);

    // With that authority, the PDP now PERMITS the very action the artifact
    // proposed. The capability came from the plane, never from the artifact.
    const permitted = await evalAction(childC.id, ARTIFACT_ACTION);
    expect(permitted.decision, JSON.stringify(permitted.context)).toBe(true);

    // And B itself, which only READ the artifact, is STILL denied: knowledge
    // propagated to B; authority did not.
    const stillDenied = await evalAction(missionB.id, ARTIFACT_ACTION);
    expect(stillDenied.decision).toBe(false);
    expect(stillDenied.context.denial_reason).toBe("out_of_authority");
  });

  it("a mediator-signed binding proves attribution integrity for THIS artifact", async () => {
    // A trusted-mediator (harness) key: in the stack the Agent Deployment's
    // execution environment holds this. It is NOT the producing agent's key.
    const kp = await generateKeyPair("ES256", { extractable: true });
    const kid = "harness-dep-A1";
    const jwks = {
      keys: [{ ...(await exportJWK(kp.publicKey)), kid, alg: "ES256", use: "sig" }],
    };

    const missionA = as.kernel.approve({
      intent: intent("Pay Acme and send remittance"),
      proposedAuthority: proposed(["payments:invoice.read", "payments:remittance.send"]),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "agent-A1",
      approvalEventId: "apev-wp-bind-A",
    });

    const content = {
      note: "remittance approach worked end to end for Acme",
      credential: "svc:remittance-signing-key",
      endpoint: "https://payments.example/remittance/send",
    };
    const wp = produceWorkProduct(as.kernel, {
      missionId: missionA.id,
      deploymentId: "dep_A1",
      producer: "agent:A1",
      mediator: { id: "harness:dep_A1", role: "harness" },
      content,
    });

    // Custody boundary: the PRODUCING agent MUST NOT sign its own binding.
    await expect(
      bindWorkProduct({
        workProduct: wp,
        mediator: { id: "agent:A1", role: "harness" },
        iss: ISSUER,
        key: kp.privateKey,
        kid,
      }),
    ).rejects.toBeInstanceOf(ProvenanceCustodyError);

    // The harness binds the provenance to THIS artifact.
    const binding = await bindWorkProduct({
      workProduct: wp,
      mediator: { id: "harness:dep_A1", role: "harness" },
      iss: ISSUER,
      key: kp.privateKey,
      kid,
    });

    // The bound artifact verifies: signature plus both recomputed digests match.
    const ok = await verifyWorkProductBinding({
      jws: binding,
      provenance: wp.provenance,
      content: wp.content,
      jwks,
    });
    expect(ok.valid, JSON.stringify(ok)).toBe(true);
    if (ok.valid) {
      // The signer is the harness mediator; iss is the Mission Issuer URL.
      expect(ok.mediator).toEqual({ id: "harness:dep_A1", role: "harness" });
      expect(ok.iss).toBe(ISSUER);
    }

    // A provenance re-attached to a DIFFERENT artifact FAILS: the subject digest
    // no longer matches, so the binding cannot be lifted onto other content.
    const different = { ...content, credential: "svc:some-other-key" };
    const reattached = await verifyWorkProductBinding({
      jws: binding,
      provenance: wp.provenance,
      content: different,
      jwks,
    });
    expect(reattached).toEqual({ valid: false, reason: "artifact_digest" });

    // Symmetrically, a DIFFERENT attribution cannot claim this binding: the
    // provenance digest no longer matches.
    const wp2 = produceWorkProduct(as.kernel, {
      missionId: missionA.id,
      deploymentId: "dep_A1",
      producer: "agent:other",
      mediator: { id: "harness:dep_A1", role: "harness" },
      content,
    });
    const swapped = await verifyWorkProductBinding({
      jws: binding,
      provenance: wp2.provenance,
      content: wp.content,
      jwks,
    });
    expect(swapped).toEqual({ valid: false, reason: "provenance_digest" });

    // The binding is attribution integrity, NEVER authority, and it added no
    // member to the sealed five-member provenance object.
    expect(Object.keys(wp.provenance).sort()).toEqual([
      "created_at",
      "deployment_id",
      "kind",
      "mission_id",
      "producer",
    ]);
  });
});
