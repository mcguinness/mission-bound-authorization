/** The PS's strict configuration loader and the shipped `config/aauth-ps.json`. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JwksResolver } from "@mission/aauth-wire";
import { describe, expect, it } from "vitest";
import { createPersonServer, parsePsConfig, SqlitePsStore } from "../src/index.js";
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

  it("parses the shipped control-plane policy and its administrator", () => {
    const m = parsePsConfig(shippedConfig()).management;
    expect(m).toMatchObject({
      admitOwningAgent: true,
      statusFreshSeconds: 30,
      untrackedAccess: false,
      revocation: {
        maxAttempts: 6,
        retryBaseSeconds: 30,
        retryMaxSeconds: 900,
        attemptTimeoutMs: 5000,
        immediateWaitMs: 2000,
      },
    });
    const [admin] = m?.administrators ?? [];
    expect(admin?.id).toBe("https://admin.ps.test");
    expect(admin?.dwk).toBe("mission-admin.json");
    expect(admin?.kid).toBe("admin-1");
    expect([...(admin?.persons ?? [])]).toEqual(["alice"]);
    expect([...(admin?.actions ?? [])]).toEqual(["status", "terminate"]);
    expect(admin?.key).not.toHaveProperty("d");
  });

  it("serves no control plane without the management member", () => {
    const doc = shippedConfig();
    delete doc.management;
    expect(parsePsConfig(doc).management).toBeUndefined();
  });

  it("refuses an administrator that could be confused with an AAuth server, or holds a private key", () => {
    const admin = (doc: Record<string, unknown>) =>
      (
        (doc.management as Record<string, unknown>).administrators as Record<string, unknown>[]
      )[0] as Record<string, unknown>;
    refuses((doc) => {
      admin(doc).dwk = "aauth-person.json";
    }, /dwk is not a deployment-chosen document name/);
    refuses((doc) => {
      admin(doc).dwk = "../x";
    }, /dwk is not a deployment-chosen document name/);
    refuses((doc) => {
      (admin(doc).key as Record<string, unknown>).d = "secret";
    }, /unknown member d/);
    refuses((doc) => {
      delete (admin(doc).key as Record<string, unknown>).kid;
    }, /kid is missing/);
    refuses((doc) => {
      (admin(doc).key as Record<string, unknown>).alg = "EdDSA";
    }, /not a usable public key/);
    refuses((doc) => {
      admin(doc).id = "https://ps.test";
    }, /the person server's own issuer/);
    refuses((doc) => {
      admin(doc).persons = ["carol"];
    }, /names unknown person carol/);
    refuses((doc) => {
      admin(doc).actions = ["status", "delegation_tree"];
    }, /names unknown action delegation_tree/);
    refuses((doc) => {
      admin(doc).actions = [];
    }, /actions is not a non-empty array/);
    refuses((doc) => {
      const m = doc.management as Record<string, unknown>;
      m.administrators = [admin(doc), admin(doc)];
    }, /names https:\/\/admin.ps.test twice/);
  });

  it("refuses a retry policy whose base exceeds its cap, and an unknown management member", () => {
    refuses((doc) => {
      const m = doc.management as Record<string, Record<string, unknown>>;
      (m.revocation as Record<string, unknown>).retry_base_seconds = 1000;
    }, /retry_base_seconds exceeds retry_max_seconds/);
    refuses((doc) => {
      (doc.management as Record<string, unknown>).fleet_bulk_terminate = true;
    }, /management has unknown member fleet_bulk_terminate/);
  });

  it("refuses control-plane options without the configuration's management member", () => {
    const doc = shippedConfig();
    delete doc.management;
    const dir = mkdtempSync(join(tmpdir(), "aauth-ps-config-"));
    const store = new SqlitePsStore(join(dir, "ps.db"));
    try {
      expect(() =>
        createPersonServer({
          config: parsePsConfig(doc),
          store,
          resolver: new JwksResolver(),
          management: { store, transport: () => Promise.reject(new Error("unused")) },
        }),
      ).toThrow(/needs the configuration's management member/);
    } finally {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
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
