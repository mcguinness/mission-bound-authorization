/** Standalone entrypoint: boots the AS on its configured port. */
import { initTelemetry } from "@mission/telemetry";
import { buildAuthorizationServer } from "./index.js";

const port = Number(process.env.AS_PORT ?? 4400);
const issuer = process.env.AS_ISSUER ?? `http://localhost:${port}`;
const { logger, shutdown } = initTelemetry("authorization-server");

const { provider } = await buildAuthorizationServer({
  issuer,
  allowHeadlessAdjudication: process.env.ALLOW_HEADLESS_ADJUDICATION === "true",
});
provider.listen(port, () => logger.info({ issuer, port }, "authorization-server listening"));

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => shutdown().finally(() => process.exit(0)));
}
