# External Pins

This is the planning-pin registry: exact external commits and content digests the
plan of record (`notes/adoption-plan.md`) relies on before any bundle publishes. It
is deliberately not `src/SPEC_VERSIONS.md`, which describes surfaces already
implemented against a dependency; this registry pins a dependency the plan cites
ahead of implementation. The bundle manifest (defined in the plan's Baseline
section) consumes this registry at Ship 3, carrying every external normative
dependency by repository, commit, and file path alongside a content digest.

A commit is never abbreviated here. Every `commit` value is the full SHA; a
shortened form is not a valid entry.

| id | repo | ref | commit | path | sha256 | note |
|---|---|---|---|---|---|---|
| AAUTH | dickhardt/AAuth | PR #73 merged | f1569261d0b9d179324f1665db1597f81cd0a851 | draft-hardt-oauth-aauth-protocol.md | 041f6a1f0ece3ca5b2f9820821e8fb6b1d7a8f2c2e8c58b53b52157684a5c4b6 | datatracker -10 is divergent (pre-person-token); disclosed, not the pin |
| ARAP | openid/authzen | PR #508 merged | 670f5831f6e786c70944887dec6ab14de26986f8 | profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md | 621cebdba15a99eff00398052b560904793564de28b2062fce161fd73320094d | commit column is the git blob hash, matching src/SPEC_VERSIONS.md's own pin convention for this row; path confirmed against PR #508's changed files and against the blob at the current default branch tip; content digest established here |
| AUTHZEN-OBL | openid/authzen | (to be established at Ship 3) | (to be established at Ship 3) | (to be established at Ship 3) | (to be established at Ship 3) | no pin exists anywhere yet for the Obligations Profile; established from scratch at Ship 3, not invented here |
