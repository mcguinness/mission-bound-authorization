/** Standalone entrypoint: boots the AS on its configured port. */
import { initTelemetry } from "@mission/telemetry";
import { buildAuthorizationServer, type SigningKeySource, signingKeysFromEnv } from "./index.js";

const port = Number(process.env.AS_PORT ?? 4400);
const issuer = process.env.AS_ISSUER ?? `http://localhost:${port}`;
const { logger, shutdown } = initTelemetry("authorization-server");

// @spec #831: the deployment says where its signing keys come from:
// MISSION_KEY_RING=<absolute path> (`pnpm keys init`) or MISSION_EPHEMERAL_KEYS=1.
let signingKeys: SigningKeySource;
try {
  signingKeys = signingKeysFromEnv(process.env);
} catch (err) {
  console.error(`authorization-server: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
const { provider, signingKeyMode } = await buildAuthorizationServer({
  issuer,
  allowHeadlessAdjudication: process.env.ALLOW_HEADLESS_ADJUDICATION === "true",
  signingKeys,
});
provider.listen(port, () => logger.info({ issuer, port, signingKeyMode }, "authorization-server listening"));

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => shutdown().finally(() => process.exit(0)));
}
