#!/usr/bin/env bash
# Removes gh-pages branch previews whose branch is deleted or merged.
#
# Usage: prune-ghpages-previews.sh <gh-pages-checkout> [--dry-run]
#
# A preview is a directory below the gh-pages root that directly holds
# draft-*.txt files; its path is the name of the branch that published
# it. The root (the default branch's copy) is never touched. A preview
# is removed when no branch of that name exists on GitHub, or when the
# branch has a merged pull request and no open one. Every publish runs
# i-d-template's build-index.sh over every preview, so stale previews
# cost minutes on each push.
#
# Without --dry-run the script commits the removals in the checkout and
# pushes them to gh-pages without force, retrying after a fresh fetch
# when a concurrent publish moved the branch first.
#
# Requires git and an authenticated gh CLI (GH_TOKEN in Actions).

set -euo pipefail

root="${1:?usage: $0 <gh-pages-checkout> [--dry-run]}"
dry_run=false
[[ "${2:-}" == "--dry-run" ]] && dry_run=true
repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

live=$(gh api "repos/${repo}/git/matching-refs/heads" --paginate --jq '.[].ref' |
  sed 's#^refs/heads/##' | sort -u)
merged=$(gh pr list -R "$repo" --state merged --limit 5000 --json headRefName \
  --jq '.[].headRefName' | sort -u)
open=$(gh pr list -R "$repo" --state open --limit 1000 --json headRefName \
  --jq '.[].headRefName' | sort -u)

# Prints one "<dir>\t<reason>" line per preview to remove.
stale_previews() {
  git -C "$root" ls-files |
    grep -E '/draft-[^/]*\.txt$' | sed -E 's#/[^/]*$##' | sort -u |
    while IFS= read -r dir; do
      if ! grep -Fxq -- "$dir" <<<"$live"; then
        printf '%s\tdeleted branch\n' "$dir"
      elif grep -Fxq -- "$dir" <<<"$merged" && ! grep -Fxq -- "$dir" <<<"$open"; then
        printf '%s\tmerged branch\n' "$dir"
      fi
    done
}

prune_once() {
  local stale count
  stale=$(stale_previews)
  count=$(grep -c . <<<"$stale" || true)
  echo "previews to remove: $count"
  [[ "$count" -eq 0 ]] && return 1
  printf '%s\n' "$stale"
  $dry_run && return 1
  cut -f1 <<<"$stale" | while IFS= read -r dir; do
    git -C "$root" rm -rq -- "$dir"
  done
  git -C "$root" -c user.name="ID Bot" -c user.email="idbot@example.com" \
    commit -q -m "Prune $count branch previews (deleted or merged branches) [ci skip]"
}

for attempt in 1 2 3; do
  if ! prune_once; then
    exit 0
  fi
  if git -C "$root" push -q origin HEAD:gh-pages; then
    echo "pushed on attempt $attempt"
    exit 0
  fi
  echo "push rejected on attempt $attempt; refetching gh-pages" >&2
  sleep $((attempt * 15))
  git -C "$root" fetch -q --depth 1 origin gh-pages
  git -C "$root" reset -q --hard FETCH_HEAD
done
echo "could not push after 3 attempts" >&2
exit 1
