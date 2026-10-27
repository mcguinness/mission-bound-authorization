/** The PS's strict configuration loader and the shipped `config/aauth-ps.json`. */
import { describe, expect, it } from "vitest";
import { parsePsConfig } from "../src/index.js";
import { ASSISTANT, HELPER, shippedConfig } from "./helpers.js";

function refuses(adjust: (doc: Record<string, unknown>) => void, message: RegExp): void {
  const doc = shippedConfig();
  adjust(doc);
  expect(() => parsePsConfig(doc)).toThrow(message);
}

describe("aauth-ps configuration", () => {
  it("parses the shipped configuration", () => {
    const config = parsePsConfig(shippedConfig());
    expect(config.issuer).toBe("https://ps.test");
    expect(config.agents.get(ASSISTANT)).toEqual({
      agent: ASSISTANT,
      person: "alice",
      missionGoverned: true,
    });
    expect(config.agents.get(HELPER)?.missionGoverned).toBe(false);
    expect(config.lifetimes.personTokenSeconds).toBe(3600);
  });

  it("refuses a token lifetime over AAuth's one-hour ceiling", () => {
    refuses((doc) => {
      (doc.lifetimes as Record<string, unknown>).person_token_seconds = 3601;
    }, /person_token_seconds exceeds 3600/);
    refuses((doc) => {
      (doc.lifetimes as Record<string, unknown>).auth_token_seconds = 3601;
    }, /auth_token_seconds exceeds 3600/);
  });

  it("refuses an agent bound to a person it does not configure", () => {
    refuses((doc) => {
      (doc.agents as Record<string, unknown>[]).push({
        agent: "aauth:extra@ap.test",
        person: "carol",
        mission_governed: true,
      });
    }, /names unknown person carol/);
  });

  it("refuses an agent named twice", () => {
    refuses((doc) => {
      (doc.agents as Record<string, unknown>[]).push({
        agent: ASSISTANT,
        person: "bob",
        mission_governed: false,
      });
    }, /names aauth:assistant@ap.test twice/);
  });

  it("refuses an issuer or an agent that is not an identifier", () => {
    refuses((doc) => {
      doc.issuer = "https://ps.test:8443";
    }, /issuer is not a server identifier/);
    refuses((doc) => {
      (doc.agents as Record<string, unknown>[])[0] = {
        agent: "assistant@ap.test",
        person: "alice",
        mission_governed: true,
      };
    }, /is not an agent identifier/);
  });

  it("refuses an unknown member and a missing governance mode", () => {
    refuses((doc) => {
      doc.approver = "model";
    }, /unknown member approver/);
    refuses((doc) => {
      delete (doc.agents as Record<string, unknown>[])[0]?.mission_governed;
    }, /mission_governed is not a boolean/);
  });
});
