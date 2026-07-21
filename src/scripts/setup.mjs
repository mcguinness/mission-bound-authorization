// One-time dev setup: .env from example, self-signed certs for OpenFGA TLS.
import { execSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";

if (!existsSync(".env")) {
  copyFileSync(".env.example", ".env");
  console.log("created .env from .env.example");
}
mkdirSync("certs", { recursive: true });
if (!existsSync("certs/openfga.crt")) {
  execSync(
    "openssl req -x509 -newkey rsa:2048 -nodes -days 365 " +
      "-keyout certs/openfga.key -out certs/openfga.crt " +
      '-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:openfga,IP:127.0.0.1"',
    { stdio: "inherit" },
  );
  console.log("generated certs/openfga.{crt,key} (self-signed, dev only)");
}
console.log("setup complete: docker compose up -d");
