/**
 * Telemetry baseline (decision D12): OpenTelemetry tracing with W3C context
 * propagation, OTLP/HTTP export (Jaeger in docker-compose), and pino
 * structured logs that carry trace_id and mission_id.
 */

import { context, trace } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { NodeSDK } from "@opentelemetry/sdk-node";
import pino from "pino";

export interface Telemetry {
  sdk: NodeSDK;
  logger: pino.Logger;
  shutdown: () => Promise<void>;
}

export function initTelemetry(serviceName: string): Telemetry {
  const sdk = new NodeSDK({
    serviceName,
    traceExporter: new OTLPTraceExporter({
      url: `${process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4318"}/v1/traces`,
    }),
  });
  sdk.start();

  const logger = pino({
    name: serviceName,
    mixin() {
      const span = trace.getSpan(context.active());
      if (!span) return {};
      const { traceId, spanId } = span.spanContext();
      return { trace_id: traceId, span_id: spanId };
    },
  });

  return { sdk, logger, shutdown: () => sdk.shutdown() };
}

/** The current span's trace id, for the evidence extension member (D13). */
export function currentTraceId(): string | undefined {
  return trace.getSpan(context.active())?.spanContext().traceId;
}

export function getTracer(serviceName: string) {
  return trace.getTracer(serviceName);
}
