#
# list versions of mdbook and mdbook plugins
#

MDBOOK_VERSION = 0.4.22
MDBOOK_ADMONISH_VERSION = 1.8.0
MDBOOK_KATEX_VERSION = 0.2.17
MDBOOK_LINKCHECK_VERSION = 0.7.6
MDBOOK_MERMAID_VERSION = 0.12.2
MDBOOK_TOC_VERSION = 0.10.0

#
# use `make deps` to install the dependencies required to serve or build the book
#

deps:
	cargo install "mdbook@$(MDBOOK_VERSION)"
	cargo install "mdbook-admonish@$(MDBOOK_ADMONISH_VERSION)"
	cargo install "mdbook-katex@$(MDBOOK_KATEX_VERSION)"
	# cargo install "mdbook-linkcheck@$(MDBOOK_LINKCHECK_VERSION)"
	cargo install "mdbook-mermaid@$(MDBOOK_MERMAID_VERSION)"
	cargo install "mdbook-toc@$(MDBOOK_TOC_VERSION)"

#
# use `make check` to check if your installed dependencies match what we've listed above
#

define check_version
	(cargo install --list | grep "$(1) v" | cut -d " " -f 2 | tr -d ':' | grep -Fx "v$(2)") || (echo "your $(1) version needs to be $(2)" && exit 1)
endef

check:
	$(call check_version,mdbook,$(MDBOOK_VERSION))
	$(call check_version,mdbook-admonish,$(MDBOOK_ADMONISH_VERSION))
	$(call check_version,mdbook-katex,$(MDBOOK_KATEX_VERSION))
	$(call check_version,mdbook-mermaid,$(MDBOOK_MERMAID_VERSION))
	$(call check_version,mdbook-toc,$(MDBOOK_TOC_VERSION))

#
# use `make` to serve the book locally
#

all: check
	mdbook serve --open

#
# use `make build` to build the book
#

build: check
	mdbook build
