#!/bin/bash


USAGE=$(cat <<-END

Dependencies installation:

 Add the \`wasm32-wasi\` target:
    rustup target add wasm32-wasi

 Install \`cargo-wasi\`:
    cargo install cargo-wasi

 Install the wasmer JS CLI:
    npm install -g @wasmer/cli
END
)

#read -r -d '' DEPENDENCIES_README << EOM
#rustup target add wasm32-wasi
#
#- Install `cargo-wasi`
#cargo install cargo-wasi
#
#- Install the wasmer JS CLI
#npm install -g @wasmer/cli
#EOM


# Default benchmark name
BENCH_NAME=""

GIT_ROOT=$(git rev-parse --show-toplevel);
if [ "$(pwd)" != "$GIT_ROOT" ]; then
    echo "WARNING: it is recommended to launch this script from the git repo root"
fi

# Checking dependencies

if ! which wasmer-js > /dev/null; then
    echo "ERROR: No wasmer-js found in PATH:"
    echo "$USAGE"
    exit 1
fi

if ! rustup target list --installed | grep wasm32-wasi > /dev/null; then
    echo "ERROR: cargo wasm32-wasi target is not installed"
    echo "$USAGE"
    exit 1
fi

if ! cargo wasi > /dev/null; then
    echo "ERROR: cargo-wasi is not installed"
    echo "$USAGE"
    exit 1
fi

# Parse the optional --bench=<NAME> argument
for i in "$@"; do
    case $i in
        --bench=*)
        BENCH_NAME="${i#*=}"
        shift # Remove --bench=<NAME> from processing
        ;;
        *)
        # unknown option
        ;;
    esac
done

# Throw an error if --bench was not provided
if [ -z "$BENCH_NAME" ]; then
    echo "Error: You must specify a benchmark using --bench=<NAME>"
    exit 1
fi

# Function to delete any old .wasm files related to the current benchmark
cleanup_old_wasm_files() {
    WASM_FILES=$(find target/wasm32-wasi/release/deps/ -type f -name "*$BENCH_NAME*.wasm")

    if [ -n "$WASM_FILES" ]; then
        echo "Cleaning up old WASM files for benchmark '$BENCH_NAME'..."
        rm -f $WASM_FILES
    else
        echo "No old WASM files found for benchmark '$BENCH_NAME'."
    fi
}

# Call the cleanup function
cleanup_old_wasm_files

# Build the WASM benchmark with cargo-wasi
echo "Building benchmark '$BENCH_NAME' with cargo-wasi..."
cargo wasi build --bench="$BENCH_NAME" --release -p mina-poseidon

# Function to find the correct WASM file
find_wasm_file() {
    # Search for the WASM file corresponding to the benchmark name
    WASM_FILE=$(find target/wasm32-wasi/release/deps/ -type f -name "*$BENCH_NAME*.wasm" | head -n 1)

    if [ -z "$WASM_FILE" ]; then
        echo "Error: No WASM file found for benchmark '$BENCH_NAME'."
        exit 1
    fi
}

# Call the function to find the correct WASM file
find_wasm_file

echo "Running benchmark at $WASM_FILE with wasmer-js..."
# Run the WASM file with wasmer-js
wasmer-js run --dir=. "$WASM_FILE" -- --bench
