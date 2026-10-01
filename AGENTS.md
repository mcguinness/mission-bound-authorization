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
