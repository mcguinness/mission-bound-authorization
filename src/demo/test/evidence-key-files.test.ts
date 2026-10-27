/**
 * @spec runtime-evidence#evidence-integrity-signing-keys (#831 scope inventory)
 *
 * The evidence key files: created once per holder, 0600 in a directory open
 * to no one else, refused rather than regenerated, and chosen for a launcher
 * by two environment variables or neither.
 */

import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import {
  EVIDENCE_KEY_FILE_FORMAT,
  evidenceKeysAdmin,
  evidenceKeysFromEnv,
  initEvidenceKeyFile,
  loadEvidenceKeyFile,
} from "../src/evidence-key-files.js";

const dir = () => mkdtempSync(join(tmpdir(), "evidence-key-files-"));

describe("an evidence key file (@spec runtime-evidence#evidence-integrity-signing-keys, #831)", () => {
  it("is created once, 0600, with each of its holder's roles under the declared kid, and loads the same keys every time", () => {
    const file = join(dir(), "keys", "pep.json");
    initEvidenceKeyFile(file, "pep");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(join(file, "..")).mode & 0o077).toBe(0);
    expect(() => initEvidenceKeyFile(file, "pep")).toThrow(/already exists; an evidence key file is created once/);
    const first = loadEvidenceKeyFile(file, "pep");
    expect(first.map((k) => [k.role, k.kid])).toEqual([
      ["pep", "ephemeral-pep"],
      ["executor", "ephemeral-executor"],
      ["receipt_issuer", "ephemeral-receipt_issuer"],
    ]);
    const again = loadEvidenceKeyFile(file, "pep");
    expect(again.map((k) => k.publicKey.export({ format: "jwk" }))).toEqual(first.map((k) => k.publicKey.export({ format: "jwk" })));
    const pdp = join(dir(), "pdp.json");
    initEvidenceKeyFile(pdp, "pdp");
    expect(loadEvidenceKeyFile(pdp, "pdp").map((k) => [k.role, k.kid])).toEqual([["pdp", TOPOLOGY.keys.pdpDecisionEvidence.kid]]);
  });

  it("refuses a relative path, a missing file, wider permissions, another holder's file, another format, or a key under another kid", () => {
    expect(() => initEvidenceKeyFile("keys/pep.json", "pep")).toThrow(/absolute path/);
    const d = dir();
    expect(() => loadEvidenceKeyFile(join(d, "absent.json"), "pep")).toThrow(/pnpm evidence-keys init --pep/);
    const file = join(d, "pep.json");
    initEvidenceKeyFile(file, "pep");
    chmodSync(file, 0o644);
    expect(() => loadEvidenceKeyFile(file, "pep")).toThrow(/must be mode 0600/);
    chmodSync(file, 0o600);
    expect(() => loadEvidenceKeyFile(file, "pdp")).toThrow(/holds the pep keys, not the pdp keys/);
    const stored = JSON.parse(readFileSync(file, "utf8")) as { format: string; keys: { kid: string }[] };
    writeFileSync(file, JSON.stringify({ ...stored, format: "something-else/1" }), { mode: 0o600 });
    expect(() => loadEvidenceKeyFile(file, "pep")).toThrow(new RegExp(`not a ${EVIDENCE_KEY_FILE_FORMAT} file`));
    stored.keys[0] = { ...stored.keys[0], kid: "renamed" } as { kid: string };
    writeFileSync(file, JSON.stringify(stored), { mode: 0o600 });
    expect(() => loadEvidenceKeyFile(file, "pep")).toThrow(/no ES256 pep key under ephemeral-pep/);
  });
});

describe("a launcher's evidence keys (@spec #831)", () => {
  it("are both files or neither: per boot with neither, refused with one, a relative path or one shared file", () => {
    expect(evidenceKeysFromEnv({})).toBeUndefined();
    expect(evidenceKeysFromEnv({ MISSION_PEP_EVIDENCE_KEYS: "/k/pep.json", MISSION_PDP_EVIDENCE_KEYS: "/k/pdp.json" })).toEqual({
      pep: "/k/pep.json",
      pdp: "/k/pdp.json",
    });
    expect(() => evidenceKeysFromEnv({ MISSION_PEP_EVIDENCE_KEYS: "/k/pep.json" })).toThrow(/both .* or neither/);
    expect(() => evidenceKeysFromEnv({ MISSION_PEP_EVIDENCE_KEYS: "k/pep.json", MISSION_PDP_EVIDENCE_KEYS: "/k/pdp.json" })).toThrow(
      /must be an absolute path/,
    );
    expect(() => evidenceKeysFromEnv({ MISSION_PEP_EVIDENCE_KEYS: "/k/one.json", MISSION_PDP_EVIDENCE_KEYS: "/k/one.json" })).toThrow(/two files/);
  });

  it("are created by `pnpm evidence-keys init`, which names what it made and how to start the stack with it", () => {
    const d = dir();
    const out = evidenceKeysAdmin(["init", "--pep", join(d, "pep.json"), "--pdp", join(d, "pdp.json")]);
    expect(out).toMatch(/created the pep evidence keys at .*pep\.json/);
    expect(out).toMatch(/created the pdp evidence keys at .*pdp\.json/);
    expect(out).toMatch(/MISSION_PEP_EVIDENCE_KEYS and MISSION_PDP_EVIDENCE_KEYS/);
    expect(() => evidenceKeysAdmin(["init"])).toThrow(/usage/);
    expect(() => evidenceKeysAdmin(["rotate", "--pep", join(d, "x.json")])).toThrow(/usage/);
  });
});
