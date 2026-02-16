#!/bin/bash

# Check if correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <program-filepath> <srs-filepath>"
    echo "Example: $0 path/to/my_program.bin /path/to/srs"
    exit 1
fi

# Store arguments in descriptive variables
PROGRAM_FILEPATH="$1"
SRS_FILEPATH="$2"

# Extract just the program name from the filepath
PROGRAM_NAME=$(basename "$PROGRAM_FILEPATH")
STATE_JSON="${PROGRAM_NAME}-state.json"

# Set up cleanup trap
cleanup() {
    rm -f "$STATE_JSON"
}
trap cleanup EXIT

# Generate state JSON
echo "Generating state JSON for $PROGRAM_NAME..."
cargo run --bin pickles_o1vm -- cannon gen-state-json \
    -i "$PROGRAM_FILEPATH" \
    -o "$STATE_JSON"

if [ $? -ne 0 ]; then
    echo "Error: Failed to generate state JSON"
    exit 1
fi

# Run the program with the generated state
echo "Running program with generated state..."
cargo run --release --bin pickles_o1vm -- cannon run \
    --input "$STATE_JSON" \
    --srs-filepath "$SRS_FILEPATH" \
    --halt-address 0

if [ $? -ne 0 ]; then
    echo "Error: Failed to run program"
    exit 1
fi

echo "Execution completed successfully"