import { describe, expect, it } from "vitest";
import {
  parseMcpReferenceMeta,
  parseMissionReferenceField,
  reconcilePropagatedReferences,
} from "../src/mission-reference.js";

const ID = "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-";
const ISS = "https://mas.example.com";
const OK = `id="${ID}", issuer="${ISS}"`;

describe("Mission-Reference field parsing (@spec authority-server#mission-reference-field)", () => {
  it("accepts exactly id and issuer as Strings", () => {
    expect(parseMissionReferenceField(OK)).toEqual({ id: ID, issuer: ISS });
    // Member order is not significant; whitespace around the comma is OWS.
    expect(parseMissionReferenceField(`issuer="${ISS}",id="${ID}"`)).toEqual({
      id: ID,
      issuer: ISS,
    });
  });

  it("returns undefined for an absent field", () => {
    expect(parseMissionReferenceField(undefined)).toBeUndefined();
  });

  it("rejects a duplicate member before map collapse", () => {
    expect(parseMissionReferenceField(`id="a", id="${ID}", issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
    expect(parseMissionReferenceField(`${OK}, issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
  });

  it("rejects a parameter on either member", () => {
    expect(parseMissionReferenceField(`id="${ID}";v=1, issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
  });

  it("rejects an Inner List or non-String value", () => {
    expect(parseMissionReferenceField(`id=("${ID}"), issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
    expect(parseMissionReferenceField(`id=${ID}, issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
    expect(parseMissionReferenceField(`id, issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
  });

  it("rejects any member other than id and issuer", () => {
    expect(parseMissionReferenceField(`${OK}, state="active"`)).toEqual({
      malformed: true,
    });
    expect(parseMissionReferenceField(`${OK}, authority_hash="sha-256:x"`)).toEqual({
      malformed: true,
    });
  });

  it("rejects an id longer than 256 or an issuer longer than 512", () => {
    const longId = "x".repeat(257);
    const longIss = `https://${"y".repeat(512)}`;
    expect(parseMissionReferenceField(`id="${longId}", issuer="${ISS}"`)).toEqual({
      malformed: true,
    });
    expect(parseMissionReferenceField(`id="${ID}", issuer="${longIss}"`)).toEqual({
      malformed: true,
    });
  });

  it("rejects more than one field line", () => {
    expect(parseMissionReferenceField(OK, 2)).toEqual({ malformed: true });
    expect(parseMissionReferenceField([OK, OK])).toEqual({ malformed: true });
  });

  it("rejects a missing member, an empty value, and a trailing comma", () => {
    expect(parseMissionReferenceField(`id="${ID}"`)).toEqual({ malformed: true });
    expect(parseMissionReferenceField("")).toEqual({ malformed: true });
    expect(parseMissionReferenceField(`${OK},`)).toEqual({ malformed: true });
  });
});

describe("MCP _meta reference parsing (@spec authority-server#mcp-reference)", () => {
  it("accepts exactly mission_id and issuer strings", () => {
    expect(parseMcpReferenceMeta({ mission_id: ID, issuer: ISS })).toEqual({
      id: ID,
      issuer: ISS,
    });
    expect(parseMcpReferenceMeta(undefined)).toBeUndefined();
  });

  it("rejects extra members and non-string values", () => {
    expect(parseMcpReferenceMeta({ mission_id: ID, issuer: ISS, state: "active" })).toEqual({
      malformed: true,
    });
    expect(parseMcpReferenceMeta({ mission_id: ID })).toEqual({ malformed: true });
    expect(parseMcpReferenceMeta({ mission_id: 7, issuer: ISS })).toEqual({
      malformed: true,
    });
    expect(parseMcpReferenceMeta("id")).toEqual({ malformed: true });
    expect(parseMcpReferenceMeta([ID, ISS])).toEqual({ malformed: true });
  });
});

describe("the harness profile's work-item members on the reference tuple (@spec harness#work-item-identity, authority-server#reference-tuple, #815)", () => {
  const HARNESS = "https://harness.example.com";
  const WORK = "work_jrnl_2026q3_0042";

  it("accepts work_item_issuer and work_item together, as Strings, in both carriages", () => {
    expect(
      parseMissionReferenceField(`${OK}, work_item_issuer="${HARNESS}", work_item="${WORK}"`),
    ).toEqual({
      id: ID,
      issuer: ISS,
      workItem: { issuer: HARNESS, id: WORK },
    });
    expect(
      parseMcpReferenceMeta({
        mission_id: ID,
        issuer: ISS,
        work_item_issuer: HARNESS,
        work_item: WORK,
      }),
    ).toEqual({
      id: ID,
      issuer: ISS,
      workItem: { issuer: HARNESS, id: WORK },
    });
  });

  it("rejects one work-item member without the other, a non-String or empty one, and one past its bound", () => {
    const fieldCases = [
      `${OK}, work_item="${WORK}"`,
      `${OK}, work_item_issuer="${HARNESS}"`,
      `${OK}, work_item_issuer="${HARNESS}", work_item=${WORK}`,
      `${OK}, work_item_issuer="${HARNESS}", work_item=""`,
      `${OK}, work_item_issuer="${HARNESS}", work_item="${"w".repeat(257)}"`,
      `${OK}, work_item_issuer="https://${"h".repeat(512)}", work_item="${WORK}"`,
      `${OK}, work_item_issuer="${HARNESS}", work_item="${WORK}", work_item="other"`,
    ];
    for (const value of fieldCases)
      expect(parseMissionReferenceField(value), value).toEqual({ malformed: true });
    const metaCases: unknown[] = [
      { mission_id: ID, issuer: ISS, work_item: WORK },
      { mission_id: ID, issuer: ISS, work_item_issuer: HARNESS },
      { mission_id: ID, issuer: ISS, work_item_issuer: HARNESS, work_item: 7 },
      { mission_id: ID, issuer: ISS, work_item_issuer: HARNESS, work_item: "" },
      { mission_id: ID, issuer: ISS, work_item_issuer: HARNESS, work_item: "w".repeat(257) },
      {
        mission_id: ID,
        issuer: ISS,
        work_item_issuer: HARNESS,
        work_item: WORK,
        work_item_mission: ID,
      },
    ];
    for (const value of metaCases)
      expect(parseMcpReferenceMeta(value), JSON.stringify(value)).toEqual({ malformed: true });
  });
});

describe("one reference from two carriages (@spec authority-server#reference-verification, authority-server#mcp-reference, #1694)", () => {
  const REF = { id: ID, issuer: ISS };
  const W1 = { issuer: "https://harness.example.com", id: "work-1" };
  const W2 = { issuer: "https://harness.example.com", id: "work-2" };

  it("takes either carriage alone, and two that agree on every member", () => {
    expect(reconcilePropagatedReferences(undefined, undefined)).toBeUndefined();
    expect(reconcilePropagatedReferences(REF, undefined)).toEqual(REF);
    expect(reconcilePropagatedReferences(undefined, REF)).toEqual(REF);
    expect(reconcilePropagatedReferences(REF, { ...REF })).toEqual(REF);
    expect(
      reconcilePropagatedReferences({ ...REF, workItem: W1 }, { ...REF, workItem: { ...W1 } }),
    ).toEqual({
      ...REF,
      workItem: W1,
    });
  });

  it("is unusable when the carriages disagree on the Mission, the issuer, or the work item, never a pick-one", () => {
    const pairs: [object, object][] = [
      [REF, { ...REF, id: "msn_other" }],
      [REF, { ...REF, issuer: "https://other.example" }],
      [
        { ...REF, workItem: W1 },
        { ...REF, workItem: W2 },
      ],
      [
        { ...REF, workItem: W1 },
        { ...REF, workItem: { ...W1, issuer: "https://other-harness.example" } },
      ],
      [{ ...REF, workItem: W1 }, REF],
    ];
    for (const [a, b] of pairs) {
      const label = JSON.stringify([a, b]);
      expect(reconcilePropagatedReferences(a as typeof REF, b as typeof REF), label).toEqual({
        malformed: true,
      });
      expect(reconcilePropagatedReferences(b as typeof REF, a as typeof REF), label).toEqual({
        malformed: true,
      });
    }
  });

  it("is unusable when either carriage is malformed, even beside a well-formed one", () => {
    expect(reconcilePropagatedReferences({ malformed: true }, REF)).toEqual({ malformed: true });
    expect(reconcilePropagatedReferences(REF, { malformed: true })).toEqual({ malformed: true });
    expect(reconcilePropagatedReferences({ malformed: true }, undefined)).toEqual({
      malformed: true,
    });
    expect(reconcilePropagatedReferences(undefined, { malformed: true })).toEqual({
      malformed: true,
    });
  });
});
