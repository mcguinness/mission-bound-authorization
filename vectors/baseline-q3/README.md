# Baseline Mission fixture

`baseline-q3.json` is the one Mission that every example of the baseline reference follows (#1176 item 5, D510): issuer `https://as.example.com`, ID `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-`. An example of that reference shows these objects and values, or a value derived from them by its draft's own construction. An example whose flow needs a different Mission uses a named variant with its own reference.

`scripts/generate-baseline-fixture.mjs` builds the file; `--check` fails when the file is not what the script builds. The script first reproduces the core's test vectors, so the construction that computes the anchors is the one the core specifies.

## Contents

| Member | Meaning |
|---|---|
| `mission` | The full reference (`issuer`, `id`) |
| `cast` | Client `s6BhdRkqt3`; Alice (`https://idp.example.com` / `user_3p2q8mN1a0kV7tR`) as Subject and direct Approver; the resource `https://erp.example.com` |
| `expiry` | Requested and effective `expires_at`, `2026-12-31T23:59:59Z`, and its NumericDate |
| `anchors` | `intent_hash`, `proposal_hash` and `authority_hash` over the record's objects, and `root_commitment` (for a direct approval, the Mission's own `authority_hash`) |
| `record` | The Mission Record the core's Worked Example displays |
| `timeline` | Each event with its instant, NumericDate, state and Status version |
| `first_token` | The first access token's `iat` and `exp` |
| `tokens` | The access tokens the examples show: grant, client, `jti` where shown, `iat`, `exp`, and the Authority Set entries each carries |
| `revocation` | Who revokes at 08:53:20, through which operation, and its `reason` text |
| `variants` | The named variants (below) |

## Anchors

Each anchor is the core's integrity anchor (draft-mcguinness-oauth-mission, Section "Integrity Anchors"): JCS (RFC 8785) over `{"typ", "iss", "value"}`, SHA-256, then `sha-256:` and the unpadded base64url digest. `typ` is `mission-intent`, `mission-proposed-authority` or `mission-authority-set`, and `iss` is the issuer.

## Timeline

All instants are UTC on 2026-11-02.

| Time | NumericDate | Event | State | Status version |
|---|---:|---|---|---:|
| 08:00:00 | 1793606400 | Direct approval and creation | `active` | 1 |
| 08:00:05 | 1793606405 | First token issuance (`exp` 1793606705) | `active` | 1 |
| 08:20:00 | 1793607600 | Explicit suspension | `suspended` | 2 |
| 08:30:00 | 1793608200 | Explicit resume | `active` | 3 |
| 08:53:20 | 1793609600 | Revocation | `terminated` (`revoked`) | 4 |

Token issuance and ordinary execution leave the Status version unchanged. The Mission issues and executes only in [08:00:05, 08:20:00) and [08:30:00, 08:53:20). A token issued before a suspension or the revocation can remain valid after it: the issuer's state and an already-issued token's validity are distinct. The token refreshed at 08:50:00 is that case: it is valid until 08:55:00, and introspection after 08:53:20 reports it inactive because its Mission is terminated.

The revocation is the Status lifecycle `revoke` by the Mission's client `s6BhdRkqt3`, with the `reason` "Quarterly reconcile completed early". The scenario grants that client an explicit lifecycle authorization to revoke this Mission (a `mission_lifecycle` grant, Status Section "Authorization"); being the Mission's client, holding its resource tokens, or a DPoP binding does not by itself confer that authority.

## Variants

An alternative ending, a scheduled suspension, changed authority, or `reconciliation.run` uses a named variant and is never inserted into this history. A variant's ID is `msn_` followed by the first 32 base64url characters of SHA-256 over its label, `baseline-q3/variant/<name>`; its issuer is `https://as.example.com` unless the table says otherwise. A variant's anchors are computed over the objects its examples display. One entry, `mas-issued`, keeps the baseline ID under another issuer: examples are keyed by (`issuer`, `id`), so it is a different Mission.

The generator writes this table.

<!-- variants:begin -->
| Name | Issuer | ID | Differs from the baseline by | Used in |
|---|---|---|---|---|
| `overnight-revocation` | `https://as.example.com` | `msn_ozWdThJGIbqzWd0NzyTCY9qv3zFUReI9` | Active by 2026-11-01T22:00:00Z; Alice revokes it at 2026-11-01T23:00:00Z, and the harness suppresses a queued resume at 2026-11-02T02:00:05Z. | harness |
| `scheduled-suspend-revoke` | `https://as.example.com` | `msn_TaLyTFRdyHq4zLDxwrwkEbj062oXcTX5` | Suspended at 08:20:00 (version 2) with `suspend_until` 2026-11-09T08:15:00Z and `on_expiry` `revoke`; never resumed, so the deadline revokes it (version 3). | status |
| `superseded-by-expansion` | `https://as.example.com` | `msn_QBZj5JSIV6tkkb93ZTvbiz_9dOMMXfJS` | Never suspended; superseded at 09:40:00 (version 2) by the expanded Mission `msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX`. | expansion, signals |
| `subject-compromise-sweep` | `https://as.example.com` | `msn_hmJWfikLFPQykayEyxPaiqril0TBUnyM` | Follows the baseline through the 08:30:00 resume (version 3) but is not revoked at 08:53:20; a bulk subject sweep revokes it at 09:33:00 (version 4). | management |
| `mas-issued` | `https://mas.example.com` | `msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-` | The baseline task and Authority Set issued by a Mission Authority Server under its own issuer, with no proposal; its anchors use `iss` `https://mas.example.com`. | authority-server, issuance-grant |
| `cap-expansion` | `https://mas.example.com` | `msn_w9zhlsZxoTTlSeSsZOHDG7gr0Z0Ok-lZ` | A Mission Authority Server Mission whose 1,200 USD adjustment leads to an approved expansion to a 2,000 USD cap. | authority-server |
| `agr-backed-direct` | `https://as.example.com` | `msn_h8ucQfVYsc9ttvVWaQ2SN6ZKc5KLpUlj` | Alice's approval is recorded through an Approval Governance Record. | approval-governance |
| `metered-consumption` | `https://as.example.com` | `msn_YJRRFCK6J8RraBk7ryPypDdFbezmGlLg` | The Intent adds consumption bounds and the Authority Set adds a `reconciliation.run` entry. | metering |
| `children-enabled` | `https://as.example.com` | `msn_M9nCx5pbv3KEbM7Xz7gT0_OB9bKOSUZ-` | The invoice-read entry's `delegation` adds `children`. | child-delegation |
| `write-delegable` | `https://as.example.com` | `msn_wJDMty6vSvxrbyZ2F5B_qqWbtovA6Sns` | The journal-write entry carries a `delegation` member. | attenuation |
| `contained-on-taint` | `https://as.example.com` | `msn_boI-VDB1ZAjwTOvq9ZFAo-vsEGk6a_FU` | After the 08:30:00 resume, a containment at 08:41:02 (version 4) removes `journal-entries.write`. | containment |
| `discharge-at-close` | `https://as.example.com` | `msn_ONfClQ7GEkjX8YRu8n_N3js79ifrskm9` | The journal-write entry carries a `terminal_when` discharge condition. | discharge |
| `derivation-limited` | `https://as.example.com` | `msn_yus7U3N_e3iDkgiz5tLJseuV5ytwgt-i` | The Intent requests a derivation limit of 200. | derivation-limits |
| `cross-domain-partner` | `https://as.example.com` | `msn_dYrf3sza_VS0UXcy-OHITvyReMNXzlOY` | The Intent and Authority Set add the partner ERP `https://erp.partner.example.com`. | cross-domain |
| `revision-read-only` | `https://as.example.com` | `msn_BZ0X6ddT5JmWo5krirQjkgYXUq_T4loG` | A deferred, revised approval: the Approver refuses `journal-entries.write`, so the Mission holds only the invoice-read entry. | approval-revision |
| `ceiling-drawdown` | `https://as.example.com` | `msn_pasG9An7Ivj9cOdd3RqWWonuaLAbDHtM` | Holds only the invoice-read entry, with Alice's consent to an authority ceiling (the baseline's two entries plus `invoices.write`) under drawdown policy `q3-reconcile-drawdown` version 1. A policy-adjudicated drawdown at 09:15:00 adds the journal-write entry and supersedes it with `msn_uG1kkHwXSlzUs4OKztGGk5FOmBnkpTOb`, whose request at 09:18:00 for a 2,000 USD cap falls back to a fresh human approval. | progressive |
<!-- variants:end -->
