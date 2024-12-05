# Variables
# Known coverage limitations and issues:
# - https://github.com/rust-lang/rust/issues/79417
# - https://github.com/nextest-rs/nextest/issues/16
# FIXME: Update or remove the `codecov.yml` file to enable the `patch` coverage report and the corresponding PR check,
#        once situation with the Rust's Doctests will be improved.
COVERAGE_ENV = CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' RUSTDOCFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE=$(shell pwd)/target/profraw/cargo-test-%p-%m.profraw
# FIXME: In latest 0.8.19+ -t CLI argument can accept comma separated list of custom output types, hence, no need in double invocation
GRCOV_CALL = grcov ./target/profraw --binary-path ./target/release/deps/ -s . --branch --ignore-not-existing --ignore "**/tests/**"
RISCV32_TOOLCHAIN_PATH = $(shell pwd)/_riscv32-gnu-toolchain

# Default target
all: release

setup:
		@echo ""
		@echo "Syncing the Git submodules."
		@echo ""
		git submodule sync
		git submodule update --init --recursive
		@echo ""
		@echo "Git submodules synced."
		@echo ""

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
		cargo clean


build: ## Build the project
		cargo build --all-targets --all-features


release: ## Build the project in release mode
		cargo build --release --all-targets --all-features


test-doc: ## Test the project's docs comments
		cargo test --all-features --release --doc

test-doc-with-coverage:
		$(COVERAGE_ENV) $(MAKE) test-doc


test: ## Test the project with non-heavy tests and using native cargo test runner
		cargo test --all-features --release $(CARGO_EXTRA_ARGS) -- --nocapture --skip heavy $(BIN_EXTRA_ARGS)

test-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test


test-heavy: ## Test the project with heavy tests and using native cargo test runner
		cargo test --all-features --release $(CARGO_EXTRA_ARGS) -- --nocapture heavy $(BIN_EXTRA_ARGS)

test-heavy-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test-heavy


test-all: ## Test the project with all tests and using native cargo test runner
		cargo test --all-features --release $(CARGO_EXTRA_ARGS) -- --nocapture $(BIN_EXTRA_ARGS)

test-all-with-coverage:
		$(COVERAGE_ENV) CARGO_EXTRA_ARGS="$(CARGO_EXTRA_ARGS)" BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) test-all


nextest: ## Test the project with non-heavy tests and using nextest test runner
		cargo nextest run --all-features --release --profile ci -E "not test(heavy)" $(BIN_EXTRA_ARGS)

nextest-with-coverage:
		$(COVERAGE_ENV) BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest


nextest-heavy: ## Test the project with heavy tests and using nextest test runner
		cargo nextest run --all-features --release --profile ci -E "test(heavy)" $(BIN_EXTRA_ARGS)

nextest-heavy-with-coverage:
		$(COVERAGE_ENV) BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest-heavy


nextest-all: ## Test the project with all tests and using nextest test runner
		cargo nextest run --all-features --release --profile ci $(BIN_EXTRA_ARGS)

nextest-all-with-coverage:
		$(COVERAGE_ENV) BIN_EXTRA_ARGS="$(BIN_EXTRA_ARGS)" $(MAKE) nextest-all


format: ## Format the code
		cargo +nightly fmt -- --check


lint: ## Lint the code
		cargo clippy --all-features --all-targets --tests $(CARGO_EXTRA_ARGS) -- -W clippy::all -D warnings

generate-test-coverage-report:
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

generate-doc:
		@echo ""
		@echo "Generating the documentation."
		@echo ""
		RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
		@echo ""
		@echo "The documentation is available at: ./target/doc"
		@echo ""

help: ## Ask for help!
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


setup-riscv32-toolchain:
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

fclean: clean
		rm -rf ${RISCV32_TOOLCHAIN_PATH}

.PHONY: all setup install-test-deps clean build release test-doc test-doc-with-coverage test test-with-coverage test-heavy test-heavy-with-coverage test-all test-all-with-coverage nextest nextest-with-coverage nextest-heavy nextest-heavy-with-coverage nextest-all nextest-all-with-coverage format lint generate-test-coverage-report generate-doc setup-riscv32-toolchain help fclean
