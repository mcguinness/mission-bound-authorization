// Launcher: set the dev CA + point OTLP at Jaeger, then run the traced flow.
import { execSync } from "node:child_process";

const ca = `${process.cwd()}/certs/openfga.crt`;
process.env.NODE_EXTRA_CA_CERTS = ca;
process.env.OPENFGA_CA_CERT = ca;
process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4318";
execSync("pnpm -C demo exec tsx src/traced-exhibit.ts", { stdio: "inherit", env: process.env });
