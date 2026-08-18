#!/usr/bin/env bash
# Builds one reader edition: per-document HTML copies with injected
# navigation, an ordered index page, and a concatenated text bundle.
#
# Usage: build-reader-editions.sh <edition-name> <output-basename> <doc>...
#
# <doc> is a draft basename with no extension (e.g.
# draft-mcguinness-mission-architecture), listed by the caller in
# reading order. <doc>.html and <doc>.txt must already be built (the
# top-level Makefile arranges this from lib/main.mk's pattern rules
# before this script runs; nothing here rebuilds a canonical draft).
#
# Failure modes that abort the whole build (nonzero exit, message on
# stderr): a member's .html/.txt is missing; a copy does not contain
# exactly one external-metadata insertion point (the nav's anchor) or
# exactly one head style block (the injected CSS's anchor); a
# family-host bibliography link survives the rewrite/mark pass without
# being rewritten or marked (an internal consistency check).
#
# Canonical draft-*.html files are read, never edited: every output is
# a copy under an edition-prefixed flat filename.

set -euo pipefail

if ! sed --version 2>/dev/null | grep -q GNU; then
  echo "error: GNU sed is required on PATH (see repo Makefile note)" >&2
  exit 1
fi

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <edition-name> <output-basename> <doc>..." >&2
  exit 1
fi

EDITION_NAME="$1"; shift
OUT="$1"; shift
DOCS=("$@")
N=${#DOCS[@]}

FAMILY_HOST="https://mcguinness.github.io/mission-bound-authorization/"
FAMILY_HOST_RE=$(printf '%s' "$FAMILY_HOST" | sed 's/\./\\./g')
COMMIT="$(git rev-parse HEAD)"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

case "$EDITION_NAME" in
  floor) EDITION_TITLE="OAuth Mission Floor" ;;
  agent) EDITION_TITLE="OAuth Mission Governed Agent" ;;
  *) EDITION_TITLE="$EDITION_NAME" ;;
esac

# Titles and one-line pull-triggers are the plan of record's own words
# (notes/adoption-plan.md, per-document pull-triggers table); kept here
# as data rather than re-derived from the drafts at build time.
title_for() {
  case "$1" in
    draft-mcguinness-mission-architecture) echo "An Architecture for Mission-Bound Authorization" ;;
    draft-mcguinness-mission-substrate) echo "Mission Substrate Requirements" ;;
    draft-mcguinness-oauth-mission) echo "Mission-Bound Authorization for OAuth 2.0" ;;
    draft-mcguinness-oauth-mission-status) echo "Mission Status and Lifecycle for OAuth 2.0" ;;
    draft-mcguinness-mission-runtime) echo "Mission-Bound Runtime Enforcement" ;;
    draft-mcguinness-mission-runtime-evidence) echo "Mission Runtime Evidence" ;;
    draft-mcguinness-mission-authzen) echo "Mission-Bound Runtime Enforcement: AuthZEN Profile" ;;
    draft-mcguinness-mission-harness) echo "Mission-Aware Agent Harnesses" ;;
    draft-mcguinness-oauth-mission-consent-evidence) echo "Mission Consent Evidence for OAuth 2.0" ;;
    *) echo "$1" ;;
  esac
}

role_for() {
  case "$1" in
    draft-mcguinness-mission-architecture) echo "Before adopting anything: the Mission model, invariants, and assurance levels the rest cite." ;;
    draft-mcguinness-mission-substrate) echo "Runtime implementers consume its commitment construction and kernel contract; binding authors profile it." ;;
    draft-mcguinness-oauth-mission) echo "Any agent's approval must bind durably to the tokens it later uses. The floor; start here." ;;
    draft-mcguinness-oauth-mission-status) echo "You must observe or change Mission state beyond token expiry (revoke, suspend, complete)." ;;
    draft-mcguinness-mission-runtime) echo "Actions need a point-of-use check, not just issuance-time gating." ;;
    draft-mcguinness-mission-runtime-evidence) echo "Runtime enforcement is deployed and decisions need durable, verifiable records." ;;
    draft-mcguinness-mission-authzen) echo "The PDP speaks AuthZEN and needs the decision-contract wire mapping." ;;
    draft-mcguinness-mission-harness) echo "A harness holds session state across restarts and must stop work when the Mission dies." ;;
    draft-mcguinness-oauth-mission-consent-evidence) echo "You must prove what the Approver actually saw, not only what was approved." ;;
    *) echo "" ;;
  esac
}

flat_html() {
  echo "${OUT}-$1-${DOCS[$(( $1 - 1 ))]}.html"
}

require_exactly_one() {
  # $1 = literal string (no sed/grep metacharacters expected), $2 = file, $3 = description
  local count
  count=$(grep -F -c -- "$1" "$2" || true)
  if [[ "$count" -ne 1 ]]; then
    echo "error: $2 has $count occurrences of $3, expected exactly 1" >&2
    exit 1
  fi
}

for doc in "${DOCS[@]}"; do
  [[ -f "$doc.html" ]] || { echo "error: missing $doc.html; build members before reader-editions" >&2; exit 1; }
  [[ -f "$doc.txt" ]] || { echo "error: missing $doc.txt; build members before reader-editions" >&2; exit 1; }
done

rm -f "${OUT}"-[0-9]*-draft-mcguinness-*.html "${OUT}.html" "${OUT}.txt"

NAV_CSS='.reader-edition-nav{margin:0 0 1em;padding:.5em 1em;background-color:var(--highlight-color);border:1px solid var(--line-color);font-size:.9em}.reader-edition-nav a{color:var(--link-color)}.reader-edition-ext-marker{font-size:.8em;opacity:.7}'

for ((i = 1; i <= N; i++)); do
  doc="${DOCS[$((i - 1))]}"
  out="$(flat_html "$i")"
  cp -f "$doc.html" "$out"

  require_exactly_one '<div id="external-metadata" class="document-information"></div>' "$out" "the external-metadata insertion point"
  require_exactly_one '</style>' "$out" "the head style block"

  # Drop the relative .xml alternate link; the flat edition copy has no
  # matching .xml sibling to point at.
  sed -i '/rel="alternate" type="application\/rfc+xml"/d' "$out"

  # Add the reader-edition CSS to the existing style block.
  css_file=$(mktemp)
  printf '%s\n' "$NAV_CSS" >"$css_file"
  sed -i "/<\/style>/r $css_file" "$out"
  rm -f "$css_file"

  # Build the navigation bar: permanent index link, position, prev/next.
  nav_file=$(mktemp)
  {
    printf '<div id="reader-edition-nav" class="reader-edition-nav">\n'
    printf '<p>Part of the <a href="%s.html">%s</a> reader edition, document %s of %s.' \
      "$OUT" "$EDITION_TITLE" "$i" "$N"
    if [[ "$i" -gt 1 ]]; then
      printf ' <a href="%s">previous</a>' "$(flat_html $((i - 1)))"
    fi
    if [[ "$i" -lt "$N" ]]; then
      printf ' <a href="%s">next</a>' "$(flat_html $((i + 1)))"
    fi
    printf '</p>\n</div>\n'
  } >"$nav_file"
  sed -i "/<div id=\"external-metadata\" class=\"document-information\"><\/div>/r $nav_file" "$out"
  rm -f "$nav_file"

  # Rewrite in-edition bibliography links to the local copy. Scoped to
  # reference-list lines (class="refTitle") so front-matter links (the
  # "About This Document" note, IETF boilerplate) are never touched.
  for ((j = 1; j <= N; j++)); do
    [[ "$j" -eq "$i" ]] && continue
    other="${DOCS[$((j - 1))]}"
    target="$(flat_html "$j")"
    sed -i "/class=\"refTitle\"/ s#href=\"${FAMILY_HOST_RE}${other}\.html\"#href=\"${target}\"#g" "$out"
  done

  # Mark every bibliography link still absolute at this point: either an
  # out-of-edition family link, or any other reference. New tab,
  # rel=noopener, visible suffix; the in-edition rewrite above already
  # removed the links this pass is not supposed to touch.
  sed -i -E '/class="refTitle"/ s#(<a href="https?://[^"]+")>([^<]*)</a>#\1 class="reader-edition-ext-link" target="_blank" rel="noopener">\2</a><span class="reader-edition-ext-marker"> (opens in a new tab)</span>#g' "$out"

  # Internal consistency check: no family-host bibliography link may
  # survive both passes unrewritten and unmarked.
  if grep -F "class=\"refTitle\"" "$out" | grep -F "href=\"${FAMILY_HOST}" | grep -qv 'reader-edition-ext-link'; then
    echo "error: $out has an unmarked family-host bibliography link" >&2
    exit 1
  fi
done

INDEX_CSS='body{font-family:sans-serif;max-width:48em;margin:2em auto;padding:0 1em;color:#222;background:#fff}a{color:#2a6496}ol{padding-left:1.5em}li{margin-bottom:.75em}@media (prefers-color-scheme:dark){body{color:#f0f0f0;background:#121212}a{color:#4da4f0}}'

# Ordered per-edition index page.
{
  printf '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
  printf '<title>%s Reader Edition</title>\n' "$EDITION_TITLE"
  printf '<style>%s</style>\n</head>\n<body>\n' "$INDEX_CSS"
  printf '<h1>%s Reader Edition</h1>\n' "$EDITION_TITLE"
  printf '<p>Reading order for this edition. Source repository commit %s, generated %s.</p>\n' "$COMMIT" "$GENERATED"
  printf '<ol>\n'
  for ((i = 1; i <= N; i++)); do
    doc="${DOCS[$((i - 1))]}"
    printf '<li><a href="%s">%s</a>: %s</li>\n' "$(flat_html "$i")" "$(title_for "$doc")" "$(role_for "$doc")"
  done
  printf '</ol>\n'
  printf '<p><a href="%s.txt">Download the concatenated text bundle</a>.</p>\n' "$OUT"
  printf '</body>\n</html>\n'
} >"${OUT}.html"

# Concatenated text bundle: cover, edition manifest, then each member's
# .txt separated by a form feed (none leading, none trailing: N members
# get N-1 separators).
{
  printf '================================================================\n'
  printf '%s: Reader Edition Bundle\n' "$EDITION_TITLE"
  printf '================================================================\n\n'
  printf "This bundle concatenates the %s reader edition's member\n" "$EDITION_TITLE"
  printf 'documents, in reading order, for offline review. It is a\n'
  printf 'convenience concatenation, not a new specification: each member\n'
  printf 'remains the normative text; consult its own front matter for\n'
  printf 'authorship, status, and boilerplate.\n\n'
  printf 'Edition: %s\n' "$EDITION_NAME"
  printf 'Generated: %s\n' "$GENERATED"
  printf 'Source repository commit: %s\n' "$COMMIT"
  printf 'Member count: %s\n\n' "$N"
  printf 'Reading order:\n'
  for ((i = 1; i <= N; i++)); do
    doc="${DOCS[$((i - 1))]}"
    printf '  %s. %s (%s)\n' "$i" "$(title_for "$doc")" "$doc"
  done
  printf '\n'
} >"${OUT}.txt"

for ((i = 1; i <= N; i++)); do
  doc="${DOCS[$((i - 1))]}"
  if [[ "$i" -gt 1 ]]; then
    printf '\f' >>"${OUT}.txt"
  fi
  cat "$doc.txt" >>"${OUT}.txt"
done

echo "built ${EDITION_NAME} edition: ${N} members -> ${OUT}.html, ${OUT}.txt"
