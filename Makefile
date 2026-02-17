# Variables
# Known coverage limitations and issues:
# - https://github.com/rust-lang/rust/issues/79417
# - https://github.com/nextest-rs/nextest/issues/16
# FIXME: Update or remove the `codecov.yml` file to enable the `patch` coverage
# report and the corresponding PR check, once situation with the Rust's Doctests
# will be improved.
COVERAGE_ENV = CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' RUSTDOCFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE=$(shell pwd)/target/profraw/cargo-test-%p-%m.profraw
# FIXME: In latest 0.8.19+ -t CLI argument can accept comma separated list of
# custom output types, hence, no need in double invocation
GRCOV_CALL = grcov ./target/profraw --binary-path ./target/release/deps/ -s . --branch --ignore-not-existing --ignore "**/tests/**"
RISCV32_TOOLCHAIN_PATH = $(shell pwd)/_riscv32-gnu-toolchain

O1VM_RESOURCES_PATH = $(shell pwd)/o1vm/resources/programs
O1VM_RISCV32IM_SOURCE_DIR = ${O1VM_RESOURCES_PATH}/riscv32im/src
O1VM_RISCV32IM_SOURCE_FILES = $(wildcard ${O1VM_RISCV32IM_SOURCE_DIR}/*.S)
O1VM_RISCV32IM_BIN_DIR = ${O1VM_RESOURCES_PATH}/riscv32im/bin
O1VM_RISCV32IM_BIN_FILES = $(patsubst ${O1VM_RISCV32IM_SOURCE_DIR}/%.S,${O1VM_RISCV32IM_BIN_DIR}/%.o,${O1VM_RISCV32IM_SOURCE_FILES})
RISCV32_AS_FLAGS = --warn --fatal-warnings

OPTIMISM_MIPS_SOURCE_DIR = $(shell pwd)/o1vm/ethereum-optimism/cannon/mipsevm/open_mips_tests/test
OPTIMISM_MIPS_SOURCE_FILES = $(wildcard ${OPTIMISM_MIPS_SOURCE_DIR}/*.asm)
O1VM_MIPS_SOURCE_DIR = ${O1VM_RESOURCES_PATH}/mips/src
O1VM_MIPS_SOURCE_FILES = $(patsubst ${OPTIMISM_MIPS_SOURCE_DIR}/%.asm,${O1VM_MIPS_SOURCE_DIR}/%.asm,${OPTIMISM_MIPS_SOURCE_FILES})
O1VM_MIPS_BIN_DIR = ${O1VM_RESOURCES_PATH}/mips/bin
O1VM_MIPS_BIN_FILES = $(patsubst ${O1VM_MIPS_SOURCE_DIR}/%.asm,${O1VM_MIPS_BIN_DIR}/%.o,${O1VM_MIPS_SOURCE_FILES})

# MIPS toolchain configuration (can be overridden for different platforms)
MIPS_AS ?= mips-linux-gnu-as
MIPS_LD ?= mips-linux-gnu-ld

# This should be updated if rust-toolchain.toml is updated, and the nightly
# version should be close to the date of the release of the stable version used
# in rust-toolchain.toml.
# In addition to that, the version in the CI (see file
# .github/workflows/wasm.yml) should be changed accordingly.
# Can be overridden via environment variable, e.g.:
#   NIGHTLY_RUST_VERSION=nightly make build-web
NIGHTLY_RUST_VERSION ?= nightly-2025-12-11
PLONK_WASM_NODEJS_OUTDIR ?= target/nodejs
PLONK_WASM_WEB_OUTDIR ?= target/web

# Feature flags for building with all features except no-std.
# The no-std feature conflicts with std-dependent code.
# See https://github.com/o1-labs/mina-rust/issues/1984
WORKSPACE_FEATURES = \
	arkworks/std,\
	arkworks/wasm,\
	internal-tracing/enabled,\
	internal-tracing/ocaml_types,\
	kimchi/bn254,\
	kimchi/check_feature_flags,\
	kimchi/diagnostics,\
	kimchi/internal_tracing,\
	kimchi/ocaml_types,\
	kimchi/wasm_types,\
	mina-curves/asm,\
	mina-poseidon/ocaml_types,\
	o1-utils/diagnostics,\
	poly-commitment/ocaml_types

# Additional feature flags for o1vm builds
O1VM_FEATURES = \
	$(WORKSPACE_FEATURES),\
	o1vm/open_mips

# Default target
.PHONY: all
all: release

.PHONY: setup
setup: setup-git setup-wasm-toolchain

.PHONY: setup-git
setup-git:
		@echo ""
		@echo "Syncing the Git submodules."
		@echo ""
		git submodule sync
		git submodule update --init --recursive
		@echo ""
		@echo "Git submodules synced."

.PHONY: setup-wasm-toolchain
setup-wasm-toolchain:
		@ARCH=$$(uname -m); \
		OS=$$(uname -s | tr A-Z a-z); \
		case $$OS in \
			linux) OS_PART="unknown-linux-gnu" ;; \
			darwin) OS_PART="apple-darwin" ;; \
			*) echo "Unsupported OS: $$OS" && exit 1 ;; \
		esac; \
		case $$ARCH in \
			x86_64) ARCH_PART="x86_64" ;; \
			aarch64) ARCH_PART="aarch64" ;; \
			arm64) ARCH_PART="aarch64" ;; \
			*) echo "Unsupported architecture: $$ARCH" && exit 1 ;; \
		esac; \
		TARGET="$$ARCH_PART-$$OS_PART"; \
		echo "Installing rust-src for ${NIGHTLY_RUST_VERSION}-$$TARGET"; \
		rustup component add rust-src --toolchain ${NIGHTLY_RUST_VERSION}-$$TARGET

# https://nexte.st/book/pre-built-binaries.html#using-nextest-in-github-actions
# FIXME: update to 0.9.68 when we get rid of 1.71 and 1.72.
# FIXME: latest 0.8.19+ requires rustc 1.74+
.PHONY: install-test-deps
install-test-deps: ## Install test dependencies
		@echo ""
		@echo "Installing the test dependencies."
		@echo ""
		rustup component add llvm-tools-preview
		cargo install cargo-nextest@=0.9.67 --locked
		cargo install grcov@=0.8.13 --locked
		@echo ""
		@echo "Test dependencies installed."
		@echo ""

.PHONY: clean
clean: ## Clean the project
		@cargo clean
		@rm -rf $(O1VM_RISCV32IM_BIN_FILES)
		@rm -rf $(O1VM_MIPS_BIN_DIR)

.PHONY: build
build: ## Build the project (without o1vm)
		cargo build \
			--all-targets \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--workspace

.PHONY: build-all
build-all: ## Build the project including o1vm
		cargo build \
			--all-targets \
			--features "$(O1VM_FEATURES)" \
			--exclude plonk_wasm \
			--workspace

.PHONY: release
release: ## Build the project in release mode (without o1vm)
		cargo build \
			--all-targets \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release \
			--workspace

.PHONY: release-all
release-all: ## Build in release mode including o1vm
		cargo build \
			--all-targets \
			--features "$(O1VM_FEATURES)" \
			--exclude plonk_wasm \
			--release \
			--workspace

.PHONY: test-doc
test-doc: ## Test the project's docs comments (without o1vm)
		cargo test \
			--features "$(WORKSPACE_FEATURES)" \
			--doc \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release \
			--workspace

.PHONY: test-doc-with-coverage
test-doc-with-coverage:
		$(COVERAGE_ENV) $(MAKE) test-doc

.PHONY: test
test: ## Test the project with non-heavy tests (without o1vm)
		cargo test \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release $(CARGO_EXTRA_ARGS) \
			-- --nocapture \
			--skip heavy $(BIN_EXTRA_ARGS)

.PHONY: test-with-coverage
test-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test

.PHONY: test-heavy
test-heavy: ## Test the project with heavy tests (without o1vm)
		cargo test \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release $(CARGO_EXTRA_ARGS) \
			-- --nocapture heavy $(BIN_EXTRA_ARGS)

.PHONY: test-heavy-with-coverage
test-heavy-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test-heavy

.PHONY: test-all
test-all: ## Test the project with all tests (without o1vm)
		cargo test \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release $(CARGO_EXTRA_ARGS) \
			-- --nocapture $(BIN_EXTRA_ARGS)

.PHONY: test-all-with-coverage
test-all-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test-all

.PHONY: nextest
nextest: ## Test with non-heavy tests using nextest (without o1vm)
		cargo nextest run \
			--all \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release $(CARGO_EXTRA_ARGS) \
			--profile ci \
			-E "not test(heavy)" $(BIN_EXTRA_ARGS)

.PHONY: nextest-with-coverage
nextest-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest

.PHONY: nextest-heavy
nextest-heavy: ## Test with heavy tests using nextest (without o1vm)
		cargo nextest run \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release $(CARGO_EXTRA_ARGS) \
			--profile ci \
			-E "test(heavy)" $(BIN_EXTRA_ARGS)

.PHONY: nextest-heavy-with-coverage
nextest-heavy-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest-heavy

.PHONY: nextest-all
nextest-all: ## Test with all tests using nextest (without o1vm)
		cargo nextest run \
			--workspace \
			--features "$(WORKSPACE_FEATURES)" \
			--exclude plonk_wasm \
			--exclude o1vm \
			--release $(CARGO_EXTRA_ARGS) \
			--profile ci $(BIN_EXTRA_ARGS)

.PHONY: nextest-all-with-coverage
nextest-all-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest-all

.PHONY: check-format
check-format: ## Check the code formatting
		cargo +nightly fmt -- --check
		taplo fmt --check

.PHONY: format
format: ## Format the code
		cargo +nightly fmt
		taplo fmt

.PHONY: check-format-md
check-format-md: ## Check markdown formatting
		npx prettier --check '**/*.md'

.PHONY: format-md
format-md: ## Format markdown files
		npx prettier --write '**/*.md'

.PHONY: lint
lint: ## Lint the code (without o1vm)
		cargo clippy --all \
			--features "$(WORKSPACE_FEATURES)" \
			--all-targets --tests \
			--exclude o1vm \
			$(CARGO_EXTRA_ARGS) \
			-- -W clippy::all -D warnings

.PHONY: lint-all
lint-all: ## Lint the code including o1vm
		cargo clippy --all \
			--features "$(O1VM_FEATURES)" \
			--all-targets --tests \
			$(CARGO_EXTRA_ARGS) \
			-- -W clippy::all -D warnings

.PHONY: generate-test-coverage-report
generate-test-coverage-report: ## Generate the code coverage report
		@echo ""
		@echo "Generating the test coverage report."
		@echo ""
		mkdir -p ./target/coverage
		GRCOV_OUTPUT_TYPE=html GRCOV_OUTPUT_PATH=./target/coverage
		$(eval GRCOV_HTML_CMD=$(GRCOV_CALL) -t html -o ./target/coverage)
		$(GRCOV_HTML_CMD)
		$(eval GRCOV_LCOV_CMD=$(GRCOV_CALL) -t lcov -o ./target/coverage/lcov.info)
		$(GRCOV_LCOV_CMD)
		@echo ""
		@echo "The test coverage report is available at: ./target/coverage"
		@echo ""

.PHONY: generate-doc
generate-doc: ## Generate the Rust documentation (without o1vm)
		@echo ""
		@echo "Generating the documentation."
		@echo ""
		RUSTDOCFLAGS="--enable-index-page -Zunstable-options" \
			cargo +nightly doc \
			--document-private-items \
			--features "$(WORKSPACE_FEATURES)" \
			--no-deps \
			--exclude plonk_wasm \
			--exclude o1vm \
			--workspace
		@echo ""
		@echo "The documentation is available at: ./target/doc"
		@echo ""

.PHONY: help
help: ## Ask for help!
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: setup-riscv32-toolchain
setup-riscv32-toolchain: ## Download and compile the RISC-V 32bits toolchain
		@echo ""
		@echo "Setting up the RISC-V 32-bit toolchain"
		@echo ""
		if [ ! -d $(RISCV32_TOOLCHAIN_PATH) ]; then \
			git clone https://github.com/riscv-collab/riscv-gnu-toolchain ${RISCV32_TOOLCHAIN_PATH}; \
		fi
		cd ${RISCV32_TOOLCHAIN_PATH} && ./configure --with-arch=rv32gc --with-abi=ilp32d --prefix=${RISCV32_TOOLCHAIN_PATH}/build
		cd ${RISCV32_TOOLCHAIN_PATH} && make -j 32 # require a good internet connection and some minutes
		@echo ""
		@echo "RISC-V 32-bits toolchain is ready in ${RISCV32_TOOLCHAIN_PATH}/build"
		@echo ""

.PHONY: build-riscv32-programs
build-riscv32-programs: setup-riscv32-toolchain ${O1VM_RISCV32IM_BIN_FILES} ## Build all RISC-V 32 bits programs written for the o1vm

${O1VM_RISCV32IM_BIN_DIR}/%.o: ${O1VM_RISCV32IM_SOURCE_DIR}/%.S
		@echo ""
		@echo "Building the RISC-V 32-bits binary: $@ using $<"
		@echo ""
		mkdir -p ${O1VM_RISCV32IM_BIN_DIR}
		${RISCV32_TOOLCHAIN_PATH}/build/bin/riscv32-unknown-elf-as ${RISCV32_AS_FLAGS} -o $@ $<
		${RISCV32_TOOLCHAIN_PATH}/build/bin/riscv32-unknown-elf-ld -s -o $(basename $@) $@
		@echo ""

.PHONY: build-mips-programs
build-mips-programs: ${O1VM_MIPS_SOURCE_FILES} ${O1VM_MIPS_BIN_FILES} ## Build all MIPS programs written for the o1vm

${O1VM_MIPS_SOURCE_DIR}/%.asm: ${OPTIMISM_MIPS_SOURCE_DIR}/%.asm
		@mkdir -p ${O1VM_MIPS_SOURCE_DIR}
		@echo "Transforming $< to $@, making it compatible for o1vm"
		@sed \
				-e '/\.balign 4/d' \
				-e 's/^\s*\.set\s*noreorder/.set noreorder/' \
				-e '/\.ent\s*test/d' \
				-e '/\.end test/d' \
				-e 's/\.section .test, "x"/.section .text/' \
				-e 's/\s*\.section .text/.section .text/' \
				-e 's/\.global test/.global __start/' \
				-e "s/^\s*\.global __start/.global __start/" \
				-e "s/test\:/__start:/" \
				-e "/\.global __start/a\\" \
				$< > $@

${O1VM_MIPS_BIN_DIR}/%.o: ${O1VM_MIPS_SOURCE_DIR}/%.asm
		@echo "Building the MIPS binary: $(basename $@) using $<"
		@mkdir -p ${O1VM_MIPS_BIN_DIR}
		@${MIPS_AS} -defsym big_endian=1 -march=mips32r2 -o $@ $<
		@${MIPS_LD} -s -o $(basename $@) $@

.PHONY: fclean
fclean: clean ## Clean the tooling artefacts in addition to running clean
		rm -rf ${RISCV32_TOOLCHAIN_PATH}

.PHONY: build-nodejs
build-nodejs: ## Compile the Kimchi library into WebAssembly to be used in NodeJS
		cargo +$(NIGHTLY_RUST_VERSION) run --package xtask -- build-wasm \
		--target nodejs \
		--out-dir ${PLONK_WASM_NODEJS_OUTDIR} \
		--rust-version $(NIGHTLY_RUST_VERSION)

.PHONY: build-web
build-web: ## Compile the Kimchi library into WebAssembly to be used in the browser
		cargo +$(NIGHTLY_RUST_VERSION) run --package xtask -- build-wasm \
		--target web \
		--out-dir ${PLONK_WASM_WEB_OUTDIR} \
		--rust-version $(NIGHTLY_RUST_VERSION)
