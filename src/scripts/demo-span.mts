// M0 exit check: emits one span visible in Jaeger (http://localhost:16686).
import { getTracer, initTelemetry } from "@mission/telemetry";

const { logger, shutdown } = initTelemetry("m0-demo");
const tracer = getTracer("m0-demo");
await tracer.startActiveSpan("m0.demo-span", async (span) => {
  logger.info("hello from the M0 telemetry baseline");
  span.end();
});
await shutdown();
console.log('span exported; check Jaeger service list for "m0-demo"');
