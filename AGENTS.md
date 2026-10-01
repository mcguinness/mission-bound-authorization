# Agent instructions

Read [CONTRIBUTING.md](CONTRIBUTING.md) before filing, editing, labeling,
or closing an issue or pull request, and before editing a draft or the
conformance ledger. Its Issue Convention section governs every issue;
#302 is the stack rank.

Rules every agent follows:

- Read current state from `origin/main` (`git fetch`, then
  `git show origin/main:<path>`). A local checkout or worktree can be
  far behind, and parallel sessions merge while you work.
- A delegated agent (one started by another session to do part of a
  task) never pushes, merges, comments, labels, edits, closes or creates
  issues or pull requests, unless the session that started it said to.
  It writes its result to a file and reports; the delegating session
  does the GitHub writes.
- Owner-only, always: sending or filing anything upstream or to a
  working group, pushing a tag (tags publish drafts), and merging to
  `main`. The one standing exception is a `src/PLAN.md` decision-log
  row, committed directly to `main`, appended after the last row.
- Never `git stash` in a worktree; the stash is shared across
  worktrees. Use a work-in-progress commit.
- Keep review reports and working files local and untracked unless the
  owner asks to commit them. Issue bodies carry what a reader needs.
- No em-dashes in anything you write for this repository.

## Checks before calling work done

- Drafts: `make draft-<name>.txt` (uses the repository's own gems;
  needs GNU sed on PATH).
- Manifests: `node scripts/check-family-manifest.mjs`,
  `node scripts/check-conformance-manifest.mjs` and
  `node scripts/check-external-pins.mjs`; after a manifest change,
  regenerate the index with `node scripts/generate-drafts-index.mjs`.
- Code, in `src/`: `pnpm typecheck && pnpm lint && pnpm test`. Tests
  that need a live PDP are skipped without OpenFGA, so CI can fail
  where a local run passes.
- Ledger changes follow the coverage rules in CONTRIBUTING.md's
  Conformance Traceability Convention.

## Editing drafts

- `draft-mcguinness-oauth-mission.md` (the OAuth binding) is the
  Editor's Draft: change it only through a reviewable PR on the
  owner's explicit go-ahead, and file findings against it as issues
  first.
- "Binding" names a substrate binding only; runtime companions are
  Profiles. Refer to the core document as "the OAuth binding";
  `check-family-manifest.mjs` rejects the retired names.
- Spec prose is timeless and short: state the current design as fact,
  with no "now" or "new in this revision" framing outside Document
  History, and no academic or research citations.
- Never propose merging drafts (see Consolidation Policy). Prefer an
  existing OAuth or JOSE surface over a new endpoint or metadata
  member.

## Pull requests and merging

- Merge with a merge commit, never squash: ledger pins name branch
  commits.
- Merge only after every check has completed.
- In a stacked chain, retarget the dependent PR to `main` before
  deleting its parent's branch; deleting it first closes the
  dependent.
- A PR in the CONFLICTING state gets no CI runs; resolve the conflict
  first.
- A change under `.github/workflows` needs a token with `workflow`
  scope.

## Parallel sessions

- Re-read an issue or PR body immediately before editing it.
- D-numbers in `src/PLAN.md` race between sessions: fetch `main` and
  take the next number just before committing the row.
- Never force-push over another session's commits.
- Parked issues and dormant PRs (for example #281) move only on the
  owner's word.
