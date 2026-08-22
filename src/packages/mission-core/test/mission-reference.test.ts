import { describe, expect, it } from "vitest";
import { parseMcpReferenceMeta, parseMissionReferenceField } from "../src/mission-reference.js";

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
