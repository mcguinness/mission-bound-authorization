# Backlog regroom, 2026-09-30

The whole open issue set was regroomed in one pass on 2026-09-30 and
2026-10-01. Baseline: origin/main 4853b1d7 (after D183). The stack rank
lives in #302; this note records how the pass was run and what it changed.

## Method

1. Every open issue (72, plus three filed during the pass) was digested
   from its full thread against origin/main, `src/PLAN.md` and PR state.
2. The owner approved a dispositions table: label scheme, structural
   changes, rank.
3. Each body was rewritten to one template, with an analysis and a sketch
   where one was missing. Every decision of record carries a permalink or
   a D-row; reviews posted under the owner's account that no D-row or
   ruling adopts are labeled recommendations, not decisions.
4. A script applied all changes after a dry run. The previous bodies are
   in GitHub's edit history; #896's previous body is also preserved as a
   comment, because its decision 7 is the starting point if it unparks.

## Labels

- Tier, exactly one: `now`, `decide`, `blocked` (new), `roadmap`,
  `parked`, `tracking`.
- Priority, exactly one on every non-parked, non-tracking issue: `P1`
  (next round), `P2`, `P3` (new).
- Type, at most one: `bug`, `enhancement`, `documentation`, `question`.
- `upstream` (new): an owner-only external action (#445, #481, #286).
- `foundation` and `coordinated` are no longer applied; sequencing is in
  #302 and each body's Dependencies line.

## Body template

Problem, Current state, Decisions of record, Analysis, Sketch,
Acceptance, Dependencies, Open questions. Parked issues use Trigger and
When triggered in place of Sketch; trackers use Purpose, Items, Rules,
Exit condition.

## Structural changes

| Change | Result |
|---|---|
| #894 split before PR #903 ("Fixes #894") merged | item 2 is #916, item 3 is #914; item 4 is the port doc's stated non-goal; #894 closed by #903 |
| AAuth protocol baseline split out of #445 | #915 (AAuth `-11` and R3 `-00` are published) |
| IDEM-PDP and IDEM-PEP filed (#302 comment 9) | #917, #918 |
| #576 closed as implemented (PRs #581, #778, #809) | residual is #919 |
| #578 folded into #424 | #424 carries the key-custody ruling in its Acceptance |
| #288's degraded-mode item moved | to #310 |
| #824, #833, #841, #842 closed into #302 | each with a finding-to-issue map; reports in this directory |

## Open owner items surfaced by the pass

- The 3 ledger rows still `blocked_by: "#648"` (closed) move to #917 or
  #918 in a manifest PR (#917 open question 3).
- Coverage with no owning issue: substrate (72 todo), Evidence Envelope
  (23 todo, 0 tested), AuthZEN beyond #594's sweep.
- AAuth frozen-class fixes need one maintenance-exception ruling (#915).
- `txn-authorization.consumption.linearizable-cross-replica` is `tested`
  on a single-process witness (#288 open question 1).
