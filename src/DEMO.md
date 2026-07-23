# Mission Reference Implementation — Guided Demo

`pnpm demo` runs scenarios 0–14 against the composed in-process stack. The
scenario bodies are the per-milestone integration tests (they compose the
services in one process; OpenFGA must be up). Boot:

```
docker compose up -d          # OpenFGA (TLS + preshared) + Jaeger
pnpm -C src setup             # dev certs + .env
pnpm -C src install
pnpm -C src demo              # scenarios 0-14 + scorecard
```

## Scenarios

| # | Scenario | Milestone |
|---|---|---|
| 0 | Discovery bootstrap (catalog, consent_required) | M8 |
| 1 | Issuance (shaper -> PAR -> Bob approves -> DPoP token) | M1 |
| 2 | Happy path (in-authority read/schedule, Decision Evidence) | M4 |
| 3 | Parameter binding / TOCTOU refusal | M4 |
| 4 | Wire transfer (permit, lease, evidence, reconciliation) | M5 |
| 5 | ARAP reevaluate (approval as input context, no new token) | M6 |
| 6 | AROP / DTR (subset-of-Mission deferred token; never expands) | M7 |
| 7 | AROP / Transaction Challenge (txn-bound single-use token) | M7 |
| 8 | Revocation freshness (revoke -> denied within bound) | M1/M3 |
| 9 | Completion (residual tokens no longer authorize) | M1 |
| 10 | Catalog reflection (status flips on approval/revocation) | M8 |
| 11 | Transparent audit (feed, five-step verify, tamper demo) | M10 |
| 12 | Cross-domain via EMA/ID-JAG (LedgerCloud, lifetime-bounded) | M9 |
| 13 | Sub-agent delegation (two-hop chain, per-instance revocation) | M12 |
| 14 | The 02:00 resume (harness stop-on-non-active) | M12 |

Exhibit mode (annotated wire captures, handbook Appendix B) is a follow-on
(O-28); the scenario runner is the reproducible path today.
