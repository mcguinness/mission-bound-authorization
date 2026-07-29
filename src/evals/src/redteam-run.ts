/**
 * @spec O-31 entrypoint. Opt-in red-team mode; NEVER the D24 gate (`pnpm evals`
 * stays the gate). Connects to live OpenFGA (mirrors run.ts), then either:
 *   - live:   generate attacks (needs ANTHROPIC_API_KEY and --live/REDTEAM_LIVE=1),
 *             run them, persist to a NON-committed fixture, print the scorecard.
 *   - replay: run the committed seed fixture (or --fixture <path>) deterministically.
 * Exits non-zero ONLY on a containment breach.
 */

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PaymentsStore } from "@mission/mcp-payments";
import { Fga, type MissionView } from "@mission/pdp";
import type { HarnessDeps } from "./index.js";
import { type Attack, loadFixture, type RedTeamFixture, runRedTeam } from "./redteam.js";
import { EVAL_VIEW_AUTHORITY } from "./suites.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";

// Same seed as run.ts: acme approved / globex pending; inv-acme 100, inv-globex 50, inv-big 900.
const seedStore = () => {
  const s = new PaymentsStore();
  s.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "pending" },
    ],
    [
      { id: "inv-acme", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "a", status: "payable" },
      { id: "inv-globex", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "g", status: "payable" },
      { id: "inv-big", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "a", status: "payable" },
    ],
  );
  return s;
};

function parseArgs(argv: string[]): { live: boolean; fixturePath?: string } {
  let live = false;
  let fixturePath: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--live") live = true;
    else if (a === "--fixture") fixturePath = argv[++i];
  }
  return { live, ...(fixturePath ? { fixturePath } : {}) };
}

async function main() {
  const { live, fixturePath } = parseArgs(process.argv.slice(2));
  const ca = process.env.OPENFGA_CA_CERT;
  const { fga, modelId } = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, ...(ca ? { caCertPath: ca } : {}) });
  const view: MissionView = {
    id: "msn_eval",
    issuer: "https://as.test",
    state: "active",
    version: 1,
    authority_hash: "sha-256:evalhash",
    authority_set: EVAL_VIEW_AUTHORITY,
  };
  const deps: HarnessDeps = { fga, modelId, view, seedStore };

  const here = dirname(fileURLToPath(import.meta.url));
  const wantLive = live || process.env.REDTEAM_LIVE === "1";

  let attacks: Attack[];
  let source: string;
  if (wantLive && process.env.ANTHROPIC_API_KEY) {
    const { generateAttacks, DEFAULT_REDTEAM_MODEL } = await import("./redteam-generate.js");
    const model = process.env.REDTEAM_MODEL ?? DEFAULT_REDTEAM_MODEL;
    attacks = await generateAttacks({ model });
    const latestPath = join(here, "..", "fixtures", "redteam-latest.json");
    const fixture: RedTeamFixture = { generatedAt: new Date().toISOString(), model, attacks };
    writeFileSync(latestPath, `${JSON.stringify(fixture, null, 2)}\n`);
    source = `live generate (${model}, ${attacks.length} attacks) -> ${latestPath}`;
  } else {
    if (wantLive) console.warn("REDTEAM_LIVE/--live set but ANTHROPIC_API_KEY is missing; falling back to replay.");
    const path = fixturePath ?? join(here, "..", "fixtures", "redteam-seed.json");
    attacks = loadFixture(path).attacks;
    source = `replay ${path}`;
  }

  const { results, scorecard } = await runRedTeam(attacks, deps);

  console.log(`Red-team source: ${source}\n`);
  for (const [i, r] of results.entries()) {
    const flag = r.breach ? "BREACH" : r.oracle === r.outcome ? "OK  " : "NOTE";
    const line = `${flag}  #${String(i + 1).padStart(2)} ${r.attack.tool.padEnd(22)} ${r.attack.args.invoice_id.padEnd(10)} oracle=${r.oracle.padEnd(6)} outcome=${r.outcome.padEnd(6)} breach=${r.breach}`;
    console.log(`${line}${r.reason ? ` (${r.reason})` : ""}`);
  }
  console.log("\nRedTeamScorecard:", JSON.stringify(scorecard, null, 2));

  if (scorecard.breaches > 0) {
    console.error("\n✗ red-team FAILED: unauthorized side effect(s) escaped mission bounds.");
    process.exit(1);
  }
  console.log("\n✓ red-team passed: zero breaches (every oracle-deny attack was contained).");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
