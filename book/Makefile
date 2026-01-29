#
# Makefile for Docusaurus-based Mina book
#

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: deps build ## Run deps and build

.PHONY: deps
deps: ## Install dependencies required to build the book
	npm install

.PHONY: specs
specs: ## Build kimchi and poly-commitment specifications
	$(MAKE) -C specifications/kimchi build
	$(MAKE) -C specifications/poly-commitment build

.PHONY: build
build: specs ## Build the book
	npx docusaurus build

.PHONY: serve
serve: specs ## Serve the book locally with hot reload
	npx docusaurus start --no-open

.PHONY: serve-built
serve-built: ## Serve the production build locally
	npx docusaurus serve --no-open

.PHONY: clean
clean: ## Clean generated artifacts
	rm -rf build node_modules .docusaurus

.PHONY: typecheck
typecheck: ## Run TypeScript type checker
	npx tsc --noEmit

.PHONY: clear
clear: ## Clear Docusaurus cache
	npx docusaurus clear
