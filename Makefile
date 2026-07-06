LIBDIR := lib

# GNU sed is required: the template's draft-name rewriting exceeds BSD
# sed's per-expression buffer at this repository's draft count, failing
# with 'sed: unterminated substitute pattern'. CI (GNU sed) is fine.
ifndef SKIP_SED_CHECK
ifeq (,$(findstring GNU,$(shell sed --version 2>/dev/null)))
$(error GNU sed required. Install it (brew install gnu-sed) and prepend /opt/homebrew/opt/gnu-sed/libexec/gnubin to PATH, or set SKIP_SED_CHECK=1)
endif
endif

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
