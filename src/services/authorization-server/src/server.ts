/** Standalone entrypoint: boots the AS on its configured port. */
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { initTelemetry } from "@mission/telemetry";
import { buildAuthorizationServer, kernelStoreFromEnv, type SigningKeySource, signingKeysFromEnv } from "./index.js";

const port = Number(process.env.AS_PORT ?? 4400);
const issuer = process.env.AS_ISSUER ?? `http://localhost:${port}`;
const { logger, shutdown } = initTelemetry("authorization-server");

// @spec #831: the deployment says where its signing keys come from:
// MISSION_KEY_RING=<absolute path> (`pnpm keys init`) or MISSION_EPHEMERAL_KEYS=1.
// @spec #250: MISSION_KERNEL_STORE=<absolute path> keeps the kernel across
// restarts, and requires the key ring.
let signingKeys: SigningKeySource;
let kernelStore: { file: string } | undefined;
try {
  signingKeys = signingKeysFromEnv(process.env);
  kernelStore = kernelStoreFromEnv(process.env);
  if (kernelStore) mkdirSync(dirname(kernelStore.file), { recursive: true });
} catch (err) {
  console.error(`authorization-server: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
const { provider, signingKeyMode, kernel, startupRemediation } = await buildAuthorizationServer({
  issuer,
  allowHeadlessAdjudication: process.env.ALLOW_HEADLESS_ADJUDICATION === "true",
  signingKeys,
  ...(kernelStore ? { kernelStore } : {}),
});
// #1326, #1349: what boot revoked from before the acting-client checks, and
// the committed expansions from another client it could not resolve.
const { revokedChildren, successors } = startupRemediation;
if (revokedChildren.length + successors.revoked.length > 0) {
  logger.info({ revokedChildren, revokedSuccessors: successors.revoked }, "revoked Missions another client created before #1340");
}
if (successors.unresolved.length > 0) {
  logger.warn({ unresolved: successors.unresolved }, "committed expansions from another client whose successor could not be identified");
}
provider.listen(port, () =>
  logger.info({ issuer, port, signingKeyMode, kernelStore: kernelStore?.file ?? "memory" }, "authorization-server listening"),
);

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () =>
    shutdown().finally(() => {
      kernel.close();
      process.exit(0);
    }),
  );
}
