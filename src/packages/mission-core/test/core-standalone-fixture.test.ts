/**
 * @spec mission#integrity-anchors, mission#canonicalization (#2009, P4): the
 * core-standalone example fixture's commitments, recomputed by this
 * package's own JCS and anchor code. The fixture's generator
 * (scripts/generate-core-standalone-fixture.mjs) uses a separate JCS; this
 * test imports nothing from it, so agreement here is a second computation
 * of each preimage and digest, not a re-read of the generator's output.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AUTHORITY_SET_TYP,
  authorityHash,
  canonicalize,
  computeAnchor,
  INTENT_TYP,
  intentHash,
  type JsonValue,
  PROPOSED_AUTHORITY_TYP,
  proposalHash,
  verifyAnchor,
} from "../src/index.js";

type AnchorName = "intent_hash" | "proposal_hash" | "authority_hash";

interface Fixture {
  mission: { issuer: string; id: string };
  submission: { mission_intent: { intent: JsonValue }; authorization_details: JsonValue[] };
  anchors: Record<AnchorName, string>;
  commitments: {
    anchor: AnchorName;
    typ: string;
    iss: string;
    value_source: string;
    envelope: { typ: string; iss: string; value: JsonValue };
    jcs: string;
    digest: string;
  }[];
  record: {
    issuer: string;
    intent: JsonValue;
    proposed_authority: JsonValue[];
    authority_set: JsonValue[];
  } & Record<AnchorName, string>;
}

const FIXTURE = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../../../../vectors/core-standalone/core-standalone.json", import.meta.url),
    ),
    "utf8",
  ),
) as Fixture;

const { record } = FIXTURE;
const ISS = record.issuer;

const TYP: Record<AnchorName, string> = {
  intent_hash: INTENT_TYP,
  proposal_hash: PROPOSED_AUTHORITY_TYP,
  authority_hash: AUTHORITY_SET_TYP,
};

const COMMITTED: Record<AnchorName, JsonValue> = {
  intent_hash: record.intent,
  proposal_hash: record.proposed_authority,
  authority_hash: record.authority_set,
};

describe("core-standalone fixture (vectors/core-standalone)", () => {
  it("binds every commitment to the record's issuer and to the record member it names", () => {
    expect(FIXTURE.mission.issuer).toBe(ISS);
    expect(FIXTURE.commitments.map((c) => c.anchor)).toEqual([
      "intent_hash",
      "proposal_hash",
      "authority_hash",
    ]);
    for (const c of FIXTURE.commitments) {
      expect(c.typ, c.anchor).toBe(TYP[c.anchor]);
      expect(c.iss, c.anchor).toBe(ISS);
      expect(c.value_source, c.anchor).toBe(
        `record.${{ intent_hash: "intent", proposal_hash: "proposed_authority", authority_hash: "authority_set" }[c.anchor]}`,
      );
      expect(c.envelope, c.anchor).toEqual({
        typ: TYP[c.anchor],
        iss: ISS,
        value: COMMITTED[c.anchor],
      });
    }
  });

  it("commits what the client submitted: the envelope's intent and the proposal exactly as pushed", () => {
    expect(record.intent).toEqual(FIXTURE.submission.mission_intent.intent);
    expect(record.proposed_authority).toEqual(FIXTURE.submission.authorization_details);
  });

  it("reproduces each envelope's exact JCS bytes", () => {
    for (const c of FIXTURE.commitments) {
      expect(
        canonicalize({ typ: TYP[c.anchor], iss: ISS, value: COMMITTED[c.anchor] }),
        c.anchor,
      ).toBe(c.jcs);
    }
  });

  it("reproduces each expected digest from the record's objects", () => {
    const computed: Record<AnchorName, string> = {
      intent_hash: intentHash(ISS, record.intent),
      proposal_hash: proposalHash(ISS, record.proposed_authority),
      authority_hash: authorityHash(ISS, record.authority_set),
    };
    expect(computed).toEqual(FIXTURE.anchors);
    for (const c of FIXTURE.commitments) {
      expect(computeAnchor(c.typ, c.iss, c.envelope.value), c.anchor).toBe(c.digest);
      expect(c.digest, c.anchor).toBe(FIXTURE.anchors[c.anchor]);
      expect(
        verifyAnchor(FIXTURE.anchors[c.anchor], TYP[c.anchor], ISS, COMMITTED[c.anchor]),
        c.anchor,
      ).toBe(true);
    }
  });

  it("records each anchor at its implied value", () => {
    for (const name of ["intent_hash", "proposal_hash", "authority_hash"] as const) {
      expect(record[name], name).toBe(computeAnchor(TYP[name], ISS, COMMITTED[name]));
    }
  });

  // The entry is carried through unchanged, so the proposal and the Authority
  // Set are one array; only `typ` separates their commitments.
  it("separates proposal_hash from authority_hash by typ alone", () => {
    expect(canonicalize(record.proposed_authority)).toBe(canonicalize(record.authority_set));
    expect(FIXTURE.anchors.proposal_hash).not.toBe(FIXTURE.anchors.authority_hash);
  });
});
