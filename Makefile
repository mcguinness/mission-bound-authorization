LIBDIR := lib

# GNU sed is required: the template's draft-name rewriting exceeds BSD
# sed's per-expression buffer at this repository's draft count, failing
# with 'sed: unterminated substitute pattern'. CI (GNU sed) is fine.
ifndef SKIP_SED_CHECK
ifeq (,$(findstring GNU,$(shell sed --version 2>/dev/null)))
$(error GNU sed required. Install it (brew install gnu-sed) and prepend /opt/homebrew/opt/gnu-sed/libexec/gnubin to PATH, or set SKIP_SED_CHECK=1)
endif
endif

## Reader editions (Ship 2 of notes/adoption-plan.md: two curated,
## cross-linked HTML+text bundles built from the canonical drafts).
##
## Members are listed once here, in reading order; the two lists feed
## both the build recipes below and GHPAGES_EXTRA, which must carry its
## final value before lib/ghpages.mk (included via main.mk below) reads
## it to compute what gets published.

READER_EDITION_FLOOR_DOCS := draft-mcguinness-mission-architecture \
  draft-mcguinness-mission-substrate \
  draft-mcguinness-oauth-mission \
  draft-mcguinness-oauth-mission-status \
  draft-mcguinness-mission-runtime \
  draft-mcguinness-mission-runtime-evidence \
  draft-mcguinness-mission-authzen

READER_EDITION_AGENT_DOCS := $(READER_EDITION_FLOOR_DOCS) \
  draft-mcguinness-mission-harness \
  draft-mcguinness-oauth-mission-consent-evidence

READER_EDITION_FLOOR_HTML := edition-floor-1-draft-mcguinness-mission-architecture.html \
  edition-floor-2-draft-mcguinness-mission-substrate.html \
  edition-floor-3-draft-mcguinness-oauth-mission.html \
  edition-floor-4-draft-mcguinness-oauth-mission-status.html \
  edition-floor-5-draft-mcguinness-mission-runtime.html \
  edition-floor-6-draft-mcguinness-mission-runtime-evidence.html \
  edition-floor-7-draft-mcguinness-mission-authzen.html

READER_EDITION_AGENT_HTML := edition-agent-1-draft-mcguinness-mission-architecture.html \
  edition-agent-2-draft-mcguinness-mission-substrate.html \
  edition-agent-3-draft-mcguinness-oauth-mission.html \
  edition-agent-4-draft-mcguinness-oauth-mission-status.html \
  edition-agent-5-draft-mcguinness-mission-runtime.html \
  edition-agent-6-draft-mcguinness-mission-runtime-evidence.html \
  edition-agent-7-draft-mcguinness-mission-authzen.html \
  edition-agent-8-draft-mcguinness-mission-harness.html \
  edition-agent-9-draft-mcguinness-oauth-mission-consent-evidence.html

READER_EDITION_INDEXES := edition-floor.html edition-agent.html
READER_EDITION_BUNDLES := edition-floor.txt edition-agent.txt

GHPAGES_EXTRA += $(READER_EDITION_FLOOR_HTML) $(READER_EDITION_AGENT_HTML) \
  $(READER_EDITION_INDEXES) $(READER_EDITION_BUNDLES)

-include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update --init
else
ifneq (,$(wildcard $(ID_TEMPLATE_HOME)))
	ln -s "$(ID_TEMPLATE_HOME)" $(LIBDIR)
else
	git clone -q --depth 10 -b main \
	    https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
endif

## Each edition's outputs are built in a single script invocation (the
## script needs the full membership list at once to decide in-edition
## vs. out-of-edition links), so a single stamp file carries the real
## recipe and every output file is a no-op rule keyed off that stamp.
## This is the standard-library idiom for "one command, many outputs":
## safe under parallel make, unlike listing all outputs as one rule's
## targets directly.

.reader-edition-floor.stamp: $(addsuffix .html,$(READER_EDITION_FLOOR_DOCS)) \
    $(addsuffix .txt,$(READER_EDITION_FLOOR_DOCS)) scripts/build-reader-editions.sh
	bash scripts/build-reader-editions.sh floor edition-floor $(READER_EDITION_FLOOR_DOCS)
	touch $@

.reader-edition-agent.stamp: $(addsuffix .html,$(READER_EDITION_AGENT_DOCS)) \
    $(addsuffix .txt,$(READER_EDITION_AGENT_DOCS)) scripts/build-reader-editions.sh
	bash scripts/build-reader-editions.sh agent edition-agent $(READER_EDITION_AGENT_DOCS)
	touch $@

## The stamp is evidence the script last ran to completion, not that
## every output is still on disk: a member deleted by hand, or left
## missing by a prior run the script interrupted, must invalidate the
## stamp and trigger a fresh build rather than a hard failure. The
## invalidation (`rm -f`) is kept on its own recipe line, separate from
## the `$(MAKE)` recipe line: any recipe line referencing $(MAKE) is
## run for real even under `make -n` (so the sub-make can print its
## own dry-run output), which would make a combined line delete the
## stamp during a dry run.

$(READER_EDITION_FLOOR_HTML) edition-floor.html edition-floor.txt: .reader-edition-floor.stamp
	@test -e $@ || rm -f .reader-edition-floor.stamp
	@test -e $@ || $(MAKE) .reader-edition-floor.stamp
	@test -f $@ || { echo "error: $@ not produced by the floor edition build" >&2; exit 1; }

$(READER_EDITION_AGENT_HTML) edition-agent.html edition-agent.txt: .reader-edition-agent.stamp
	@test -e $@ || rm -f .reader-edition-agent.stamp
	@test -e $@ || $(MAKE) .reader-edition-agent.stamp
	@test -f $@ || { echo "error: $@ not produced by the agent edition build" >&2; exit 1; }

.PHONY: reader-editions
reader-editions: $(READER_EDITION_FLOOR_HTML) edition-floor.html edition-floor.txt \
    $(READER_EDITION_AGENT_HTML) edition-agent.html edition-agent.txt
