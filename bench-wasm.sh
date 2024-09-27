#!/bin/bash

# Default benchmark name
BENCH_NAME=""

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

# Build the WASM benchmark with cargo-wasi
echo "Building benchmark '$BENCH_NAME' with cargo-wasi..."
cargo wasi build --bench="$BENCH_NAME" --release

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
