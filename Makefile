# Variables

# =============================================================================
# Per-crate feature flags for native builds
# =============================================================================
# These variables define the cargo feature arguments for each crate.
# This allows fine-grained control instead of using --all-features,
# which can enable incompatible feature combinations (e.g., OCaml features
# for WASM crates).
#
# Format: -F <crate-name>/<feature> ...
# Empty value means the crate uses only default features.

# Crates with no optional features (use default only)
NATIVE_FEATURES_ARRABBIATA =
NATIVE_FEATURES_EXPORT_TEST_VECTORS =
NATIVE_FEATURES_GROUPMAP =
NATIVE_FEATURES_KIMCHI_MSM =
NATIVE_FEATURES_KIMCHI_STUBS =
NATIVE_FEATURES_KIMCHI_VISU =
NATIVE_FEATURES_MINA_BOOK =
NATIVE_FEATURES_MINA_HASHER =
NATIVE_FEATURES_MINA_SIGNER =
NATIVE_FEATURES_MVPOLY =
NATIVE_FEATURES_PLONK_NEON =
NATIVE_FEATURES_TURSHI =
NATIVE_FEATURES_WASM_TYPES =

# arkworks: enable std (wasm feature is for WASM builds only)
NATIVE_FEATURES_ARKWORKS = -F arkworks/std

# internal-tracing: enable all features for native builds
NATIVE_FEATURES_INTERNAL_TRACING = \
	-F internal-tracing/enabled \
	-F internal-tracing/ocaml_types \
	-F internal-tracing/serde

# kimchi: enable native features (ocaml_types, not wasm_types)
NATIVE_FEATURES_KIMCHI = \
	-F kimchi/bn254 \
	-F kimchi/check_feature_flags \
	-F kimchi/internal_tracing \
	-F kimchi/ocaml_types

# mina-curves: enable asm optimizations
NATIVE_FEATURES_MINA_CURVES = -F mina-curves/asm

# mina-poseidon: enable OCaml bindings
NATIVE_FEATURES_MINA_POSEIDON = -F mina-poseidon/ocaml_types

# o1-utils: enable diagnostics
NATIVE_FEATURES_O1_UTILS = -F o1-utils/diagnostics

# o1vm: enable open_mips for MIPS support
NATIVE_FEATURES_O1VM = -F o1vm/open_mips

# poly-commitment: enable OCaml bindings
NATIVE_FEATURES_POLY_COMMITMENT = -F poly-commitment/ocaml_types

# =============================================================================
# Per-crate feature flags for WebAssembly builds
# =============================================================================
# These variables define the cargo feature arguments for WASM builds.
# WASM builds exclude OCaml bindings and enable WASM-specific features.

# Crates with no optional features (use default only)
WASM_FEATURES_ARRABBIATA =
WASM_FEATURES_EXPORT_TEST_VECTORS =
WASM_FEATURES_GROUPMAP =
WASM_FEATURES_KIMCHI_MSM =
WASM_FEATURES_MINA_BOOK =
WASM_FEATURES_MINA_HASHER =
WASM_FEATURES_MINA_SIGNER =
WASM_FEATURES_MVPOLY =
WASM_FEATURES_TURSHI =
WASM_FEATURES_WASM_TYPES =

# arkworks: enable std and wasm features
WASM_FEATURES_ARKWORKS = -F arkworks/std -F arkworks/wasm

# internal-tracing: enable without OCaml
WASM_FEATURES_INTERNAL_TRACING = \
	-F internal-tracing/enabled \
	-F internal-tracing/serde

# kimchi: enable WASM features (wasm_types instead of ocaml_types)
WASM_FEATURES_KIMCHI = \
	-F kimchi/bn254 \
	-F kimchi/check_feature_flags \
	-F kimchi/internal_tracing \
	-F kimchi/wasm_types

# mina-curves: enable asm optimizations
WASM_FEATURES_MINA_CURVES = -F mina-curves/asm

# mina-poseidon: no OCaml for WASM (default features only)
WASM_FEATURES_MINA_POSEIDON =

# o1-utils: enable diagnostics
WASM_FEATURES_O1_UTILS = -F o1-utils/diagnostics

# o1vm: enable open_mips
WASM_FEATURES_O1VM = -F o1vm/open_mips

# poly-commitment: no OCaml for WASM (default features only)
WASM_FEATURES_POLY_COMMITMENT =

# plonk_wasm: the main WASM crate with nodejs feature
WASM_FEATURES_PLONK_WASM = -F plonk_wasm/nodejs

# =============================================================================
# Combined feature arguments for cargo commands
# =============================================================================
# Aggregates all per-crate feature arguments for use in cargo commands.
# Use with: cargo <cmd> --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES)

NATIVE_FEATURES = \
	$(NATIVE_FEATURES_ARKWORKS) \
	$(NATIVE_FEATURES_INTERNAL_TRACING) \
	$(NATIVE_FEATURES_KIMCHI) \
	$(NATIVE_FEATURES_MINA_CURVES) \
	$(NATIVE_FEATURES_MINA_POSEIDON) \
	$(NATIVE_FEATURES_O1_UTILS) \
	$(NATIVE_FEATURES_O1VM) \
	$(NATIVE_FEATURES_POLY_COMMITMENT)

WASM_FEATURES = \
	$(WASM_FEATURES_ARKWORKS) \
	$(WASM_FEATURES_INTERNAL_TRACING) \
	$(WASM_FEATURES_KIMCHI) \
	$(WASM_FEATURES_MINA_CURVES) \
	$(WASM_FEATURES_O1_UTILS) \
	$(WASM_FEATURES_O1VM) \
	$(WASM_FEATURES_PLONK_WASM)

# =============================================================================
# Excluded crates
# =============================================================================

# Native builds: exclude WASM-only crates and build tools
NATIVE_EXCLUDE = --exclude plonk_wasm --exclude xtask

# WASM builds: exclude OCaml stubs and build tools
WASM_EXCLUDE = \
	--exclude kimchi-stubs \
	--exclude kimchi-visu \
	--exclude xtask

# Doc generation: exclude crates that cause linker issues
DOC_EXCLUDE = --exclude plonk_wasm --exclude plonk_neon --exclude xtask

# =============================================================================
# Coverage and other existing variables
# =============================================================================
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
NIGHTLY_RUST_VERSION ?= nightly-2024-09-05
PLONK_WASM_NODEJS_OUTDIR ?= target/nodejs
PLONK_WASM_WEB_OUTDIR ?= target/web

# =============================================================================
# Phony targets declaration
# =============================================================================
.PHONY: all setup install-test-deps clean \
	build release build-wasm release-wasm \
	test-doc test-doc-with-coverage \
	test test-with-coverage test-heavy test-heavy-with-coverage test-all test-all-with-coverage \
	test-wasm \
	nextest nextest-with-coverage nextest-heavy nextest-heavy-with-coverage nextest-all nextest-all-with-coverage \
	nextest-wasm \
	format check-format lint lint-native lint-wasm \
	generate-test-coverage-report generate-doc \
	setup-riscv32-toolchain setup-git setup-wasm-toolchain \
	help fclean build-riscv32-programs build-mips-programs \
	build-nodejs build-web

# =============================================================================
# Default and setup targets
# =============================================================================

# Default target
all: release

setup: setup-git setup-wasm-toolchain

setup-git:
		@echo ""
		@echo "Syncing the Git submodules."
		@echo ""
		git submodule sync
		git submodule update --init --recursive
		@echo ""
		@echo "Git submodules synced."

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


clean: ## Clean the project
		@cargo clean
		@rm -rf $(O1VM_RISCV32IM_BIN_FILES)
		@rm -rf $(O1VM_MIPS_BIN_DIR)


# =============================================================================
# Native build targets
# =============================================================================

build: ## Build the project (native)
		cargo build --all-targets --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES)

release: ## Build the project in release mode (native)
		cargo build --release --all-targets --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES)

# =============================================================================
# Native test targets
# =============================================================================

test-doc: ## Test the project's docs comments (native)
		cargo test --release --doc --workspace $(DOC_EXCLUDE) $(NATIVE_FEATURES)

test-doc-with-coverage:
		$(COVERAGE_ENV) $(MAKE) test-doc

test: ## Test the project with non-heavy tests using native cargo test runner
		cargo test --release --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			$(CARGO_EXTRA_ARGS) -- --nocapture --skip heavy $(BIN_EXTRA_ARGS)

test-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test

test-heavy: ## Test the project with heavy tests using native cargo test runner
		cargo test --release --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			$(CARGO_EXTRA_ARGS) -- --nocapture heavy $(BIN_EXTRA_ARGS)

test-heavy-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test-heavy

test-all: ## Test the project with all tests using native cargo test runner
		cargo test --release --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			$(CARGO_EXTRA_ARGS) -- --nocapture $(BIN_EXTRA_ARGS)

test-all-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test-all

nextest: ## Test the project with non-heavy tests using nextest test runner
		cargo nextest run --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			--release $(CARGO_EXTRA_ARGS) --profile ci -E "not test(heavy)" $(BIN_EXTRA_ARGS)

nextest-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest

nextest-heavy: ## Test the project with heavy tests using nextest test runner
		cargo nextest run --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			--release $(CARGO_EXTRA_ARGS) --profile ci -E "test(heavy)" $(BIN_EXTRA_ARGS)

nextest-heavy-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest-heavy

nextest-all: ## Test the project with all tests using nextest test runner
		cargo nextest run --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			--release $(CARGO_EXTRA_ARGS) --profile ci $(BIN_EXTRA_ARGS)

nextest-all-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest-all

# =============================================================================
# WASM build targets
# =============================================================================

build-wasm: ## Build the project for WebAssembly
		cargo build --all-targets --workspace $(WASM_EXCLUDE) $(WASM_FEATURES)

release-wasm: ## Build the project in release mode for WebAssembly
		cargo build --release --all-targets --workspace $(WASM_EXCLUDE) $(WASM_FEATURES)

# =============================================================================
# WASM test targets
# =============================================================================

test-wasm: ## Test the WASM crates with non-heavy tests
		cargo test --release --workspace $(WASM_EXCLUDE) $(WASM_FEATURES) \
			$(CARGO_EXTRA_ARGS) -- --nocapture --skip heavy $(BIN_EXTRA_ARGS)

nextest-wasm: ## Test the WASM crates with non-heavy tests using nextest
		cargo nextest run --workspace $(WASM_EXCLUDE) $(WASM_FEATURES) \
			--release $(CARGO_EXTRA_ARGS) --profile ci -E "not test(heavy)" $(BIN_EXTRA_ARGS)


check-format: ## Check the code formatting
		cargo +nightly fmt -- --check
		taplo fmt --check

format: ## Format the code
		cargo +nightly fmt
		taplo fmt

lint: lint-native lint-wasm ## Lint all code (native and WASM)

lint-native: ## Lint the native code
		cargo clippy --workspace $(NATIVE_EXCLUDE) $(NATIVE_FEATURES) \
			--all-targets --tests $(CARGO_EXTRA_ARGS) -- -W clippy::all -D warnings

lint-wasm: ## Lint the WASM crates
		cargo clippy --workspace $(WASM_EXCLUDE) $(WASM_FEATURES) \
			--all-targets --tests $(CARGO_EXTRA_ARGS) -- -W clippy::all -D warnings

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

generate-doc: ## Generate the Rust documentation (native)
		@echo ""
		@echo "Generating the documentation."
		@echo ""
		RUSTDOCFLAGS="--enable-index-page -Zunstable-options" cargo +nightly doc \
			--no-deps --workspace $(DOC_EXCLUDE) $(NATIVE_FEATURES)
		@echo ""
		@echo "The documentation is available at: ./target/doc"
		@echo ""

help: ## Ask for help!
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


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

build-riscv32-programs: setup-riscv32-toolchain ${O1VM_RISCV32IM_BIN_FILES} ## Build all RISC-V 32 bits programs written for the o1vm

${O1VM_RISCV32IM_BIN_DIR}/%.o: ${O1VM_RISCV32IM_SOURCE_DIR}/%.S
		@echo ""
		@echo "Building the RISC-V 32-bits binary: $@ using $<"
		@echo ""
		mkdir -p ${O1VM_RISCV32IM_BIN_DIR}
		${RISCV32_TOOLCHAIN_PATH}/build/bin/riscv32-unknown-elf-as ${RISCV32_AS_FLAGS} -o $@ $<
		${RISCV32_TOOLCHAIN_PATH}/build/bin/riscv32-unknown-elf-ld -s -o $(basename $@) $@
		@echo ""

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
