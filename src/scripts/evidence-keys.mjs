// pnpm evidence-keys init --pep <path> --pdp <path>: create the PEP's and the
// PDP's evidence signing keys once (#831). Give their absolute paths to the
// stack as MISSION_PEP_EVIDENCE_KEYS and MISSION_PDP_EVIDENCE_KEYS.
import { runDemoTs } from "./run-demo-ts.mjs";

runDemoTs("src/evidence-keys-cli.ts", process.argv.slice(2));
