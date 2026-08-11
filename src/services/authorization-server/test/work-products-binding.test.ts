/**
 * @spec draft-mcguinness-oauth-mission-work-products (#binding) — unit tests for
 * the signed provenance -> artifact binding: digest encodings, sign, and verify,
 * plus the two custody refusals (a tampered artifact and a binding whose signer
 * is the producer). Pure crypto and custody, so no OpenFGA and nothing skipped.
 *
 * `iss` is the Issuer / deployment URL under which the mediator publishes its
 * key set; it is INDEPENDENT of `mediator.id` (which names the signer). The
 * provenance digest uses that same URL as its anchor `iss`, so it reproduces
 * from the record.
 */

import { buildArtifactEvidence } from "@mission/mcp-payments";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  bindWorkProduct,
  computeArtifactDigest,
  computeProvenanceDigest,
  ProvenanceCustodyError,
  type ProvenanceMediator,
  signWorkProductBinding,
  verifyWorkProductBinding,
  WORK_PRODUCT_BINDING_TYP,
  type WorkProduct,
} from "../src/index.js";

const PRODUCER = "agent:A1";
const HARNESS: ProvenanceMediator = { id: "harness:dep_A1", role: "harness" };
/** The Issuer / deployment URL under which the mediator publishes its key set. */
const ISSUER = "https://issuer.example";

async function mediatorKeys(kid = "mediator-1") {
  const kp = await generateKeyPair("ES256", { extractable: true });
  const pub = { ...(await exportJWK(kp.publicKey)), kid, alg: "ES256", use: "sig" };
  return { key: kp.privateKey, kid, jwks: { keys: [pub] } };
}

function workProduct(content: unknown, parentArtifact?: string): WorkProduct {
  const provenance = buildArtifactEvidence({
    mission_id: "mission:A",
    deployment_id: "dep_A1",
    producer: PRODUCER,
    created_at: "2026-01-01T00:00:00Z",
    ...(parentArtifact ? { parent_artifact: parentArtifact } : {}),
  });
  return { provenance, content: content as WorkProduct["content"] };
}

describe("work-product binding: digests", () => {
  it("computes sha-256: base64url (no padding) over raw bytes, not JCS", () => {
    // Insertion order is significant (opaque bytes, NOT canonicalized): two key
    // orders of the same object produce DIFFERENT digests.
    const a = computeArtifactDigest({ x: 1, y: 2 });
    const b = computeArtifactDigest({ y: 2, x: 1 });
    expect(a).not.toBe(b);
    expect(a.startsWith("sha-256:")).toBe(true);
    expect(a.includes("=")).toBe(false);
    // A string and its UTF-8 bytes agree.
    expect(computeArtifactDigest("hello")).toBe(
      computeArtifactDigest(new TextEncoder().encode("hello")),
    );
  });

  it("pins the artifact_digest encoding (SHA-256 of empty bytes)", () => {
    expect(computeArtifactDigest("")).toBe(
      "sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    );
  });

  it("pins the provenance_digest anchor with iss = Issuer/deployment URL", () => {
    const provenance = buildArtifactEvidence({
      mission_id: "mission:A",
      deployment_id: "dep_A1",
      producer: "agent:A1",
      created_at: "2026-01-01T00:00:00Z",
    });
    expect(computeProvenanceDigest(ISSUER, provenance)).toBe(
      "sha-256:OjtCG7IPBZxSHbMhL_LpOonSsva_gFEjznXdXC3Ps0I",
    );
    // iss is committed: a different issuer URL yields a different digest.
    expect(computeProvenanceDigest("https://other.example", provenance)).not.toBe(
      computeProvenanceDigest(ISSUER, provenance),
    );
  });

  it("uses the family-consistent binding typ", () => {
    expect(WORK_PRODUCT_BINDING_TYP).toBe("mission-work-product-binding+jwt");
  });
});

describe("work-product binding: sign and verify", () => {
  it("binds and verifies; the sealed provenance object is unchanged", async () => {
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "remittance worked", n: 1 });
    const before = Object.keys(wp.provenance).sort();
    const jws = await bindWorkProduct({ workProduct: wp, mediator: HARNESS, iss: ISSUER, key, kid });

    // Sealed: binding added NO member to the five-member provenance object.
    expect(Object.keys(wp.provenance).sort()).toEqual([
      "created_at",
      "deployment_id",
      "kind",
      "mission_id",
      "producer",
    ]);
    expect(Object.keys(wp.provenance).sort()).toEqual(before);

    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: wp.content,
      jwks,
    });
    expect(res.valid).toBe(true);
    if (res.valid) {
      // The signer (mediator) is INDEPENDENT of iss (the Issuer/deployment URL).
      expect(res.mediator).toEqual({ id: "harness:dep_A1", role: "harness" });
      expect(res.iss).toBe(ISSUER);
    }
  });

  it("accepts a role-issuer binding whose mediator.id legitimately equals iss", async () => {
    // Now that iss is a URL, a Mission Issuer mediator's own id IS that URL, so
    // mediator.id === iss is the NATURAL case. The removed shape-check must NOT
    // reject it: this proves signer/iss independence in BOTH directions and
    // guards against reinstating a mediator.id === iss equation.
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "issuer-signed" });
    const jws = await bindWorkProduct({
      workProduct: wp,
      mediator: { id: ISSUER, role: "issuer" },
      iss: ISSUER,
      key,
      kid,
    });
    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: wp.content,
      jwks,
    });
    expect(res.valid, JSON.stringify(res)).toBe(true);
    if (res.valid) {
      expect(res.mediator).toEqual({ id: ISSUER, role: "issuer" });
      expect(res.iss).toBe(ISSUER);
    }
  });

  it("a derived provenance keeps parent_artifact and binding adds no member", async () => {
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "derived" }, "artifact:v1");
    const jws = await bindWorkProduct({ workProduct: wp, mediator: HARNESS, iss: ISSUER, key, kid });
    expect(Object.keys(wp.provenance).sort()).toEqual([
      "created_at",
      "deployment_id",
      "kind",
      "mission_id",
      "parent_artifact",
      "producer",
    ]);
    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: wp.content,
      jwks,
    });
    expect(res.valid).toBe(true);
  });

  it("a tampered artifact fails the artifact_digest match", async () => {
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "original", amount: 100 });
    const jws = await bindWorkProduct({ workProduct: wp, mediator: HARNESS, iss: ISSUER, key, kid });
    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: { note: "original", amount: 999 },
      jwks,
    });
    expect(res).toEqual({ valid: false, reason: "artifact_digest" });
  });

  it("a mutated provenance object fails the provenance_digest match", async () => {
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "x" });
    const jws = await bindWorkProduct({ workProduct: wp, mediator: HARNESS, iss: ISSUER, key, kid });
    const res = await verifyWorkProductBinding({
      jws,
      provenance: { ...wp.provenance, mission_id: "mission:OTHER" },
      content: wp.content,
      jwks,
    });
    expect(res).toEqual({ valid: false, reason: "provenance_digest" });
  });

  it("a signature from an untrusted key is refused", async () => {
    const signer = await mediatorKeys();
    const other = await mediatorKeys(); // different keypair, same kid
    const wp = workProduct({ note: "x" });
    const jws = await bindWorkProduct({
      workProduct: wp,
      mediator: HARNESS,
      iss: ISSUER,
      key: signer.key,
      kid: signer.kid,
    });
    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: wp.content,
      jwks: other.jwks,
    });
    expect(res).toEqual({ valid: false, reason: "signature" });
  });

  it("rejects an unrecognized digest algorithm prefix before any compare", async () => {
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "x" });
    const jws = await new SignJWT({
      artifact_digest: "md5:deadbeef",
      provenance_digest: computeProvenanceDigest(ISSUER, wp.provenance),
      mediator: HARNESS,
    })
      .setProtectedHeader({ alg: "ES256", kid, typ: WORK_PRODUCT_BINDING_TYP })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .sign(key);
    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: wp.content,
      jwks,
    });
    expect(res).toEqual({ valid: false, reason: "unrecognized_algorithm" });
  });
});

describe("work-product binding: custody boundary", () => {
  it("refuses a binding SIGNED BY THE PRODUCER at bind (self_asserted)", async () => {
    const { key, kid } = await mediatorKeys();
    const wp = workProduct({ note: "x" });
    await expect(
      bindWorkProduct({
        workProduct: wp,
        mediator: { id: PRODUCER, role: "harness" },
        iss: ISSUER,
        key,
        kid,
      }),
    ).rejects.toBeInstanceOf(ProvenanceCustodyError);
    try {
      await bindWorkProduct({
        workProduct: wp,
        mediator: { id: PRODUCER, role: "harness" },
        iss: ISSUER,
        key,
        kid,
      });
      expect.unreachable("producer signed its own binding");
    } catch (e) {
      expect((e as ProvenanceCustodyError).reason).toBe("self_asserted");
    }
  });

  it("refuses an untrusted mediator role at bind (untrusted_mediator_role)", async () => {
    const { key, kid } = await mediatorKeys();
    const wp = workProduct({ note: "x" });
    const badRole = { id: "pep:1", role: "pep" } as unknown as ProvenanceMediator;
    try {
      await bindWorkProduct({ workProduct: wp, mediator: badRole, iss: ISSUER, key, kid });
      expect.unreachable("untrusted role bound");
    } catch (e) {
      expect(e).toBeInstanceOf(ProvenanceCustodyError);
      expect((e as ProvenanceCustodyError).reason).toBe("untrusted_mediator_role");
    }
  });

  it("refuses a producer-signed binding at verify even if a sign path emitted it", async () => {
    const { key, kid, jwks } = await mediatorKeys();
    const wp = workProduct({ note: "x" });
    // The low-level primitive does NOT enforce custody; a hostile signer could
    // emit this. iss is still the Issuer/deployment URL (independent of the
    // signer), so this is not caught as malformed; verify is the receiver-side
    // backstop that rejects signer == producer.
    const jws = await signWorkProductBinding({
      provenance: wp.provenance,
      content: wp.content,
      mediator: { id: PRODUCER, role: "harness" },
      iss: ISSUER,
      key,
      kid,
    });
    const res = await verifyWorkProductBinding({
      jws,
      provenance: wp.provenance,
      content: wp.content,
      jwks,
    });
    expect(res).toEqual({ valid: false, reason: "self_asserted" });
  });
});
