#
# mdbook and plugin versions
#

MDBOOK_VERSION = 0.4.35
MDBOOK_KATEX_VERSION = 0.3.8
MDBOOK_ADMONISH_VERSION = 1.14.0
MDBOOK_LINKCHECK_VERSION = 0.7.7
MDBOOK_MERMAID_VERSION = 0.12.6
MDBOOK_TOC_VERSION = 0.14.1

#
# Version checking macro
#

define check_version
	@(cargo install --list | grep "$(1) v" | cut -d " " -f 2 | tr -d ':' | \
		grep -Fx "v$(2)") || \
		(echo "your $(1) version needs to be $(2)" && exit 1)
endef

#
# Targets
#

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: deps check build serve ## Run deps, check, build, and serve

.PHONY: deps
deps: ## Install dependencies required to serve or build the book
	cargo install --locked "mdbook@$(MDBOOK_VERSION)"
	cargo install --locked "mdbook-admonish@$(MDBOOK_ADMONISH_VERSION)"
	cargo install --locked "mdbook-katex@$(MDBOOK_KATEX_VERSION)"
	cargo install --locked --git \
		https://github.com/o1-labs/mdbook-linkcheck \
		--rev 8cccfc8fee397092ecdf1236a42871c5c980672e mdbook-linkcheck
	cargo install --locked "mdbook-mermaid@$(MDBOOK_MERMAID_VERSION)"
	cargo install --locked "mdbook-toc@$(MDBOOK_TOC_VERSION)"

.PHONY: check
check: ## Check if installed dependencies match required versions
	$(call check_version,mdbook,$(MDBOOK_VERSION))
	$(call check_version,mdbook-admonish,$(MDBOOK_ADMONISH_VERSION))
	$(call check_version,mdbook-katex,$(MDBOOK_KATEX_VERSION))
	$(call check_version,mdbook-linkcheck,$(MDBOOK_LINKCHECK_VERSION))
	$(call check_version,mdbook-mermaid,$(MDBOOK_MERMAID_VERSION))
	$(call check_version,mdbook-toc,$(MDBOOK_TOC_VERSION))

.PHONY: build
build: check ## Build the book
	mdbook build

.PHONY: serve
serve: check ## Serve the book locally
	mdbook serve --open

.PHONY: clean
clean: ## Clean generated artifacts
	mdbook clean
