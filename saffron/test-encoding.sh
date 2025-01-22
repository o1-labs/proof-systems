#!/bin/bash

# Check if input file is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

INPUT_FILE="$1"
ENCODED_FILE="${INPUT_FILE%.*}.bin"
DECODED_FILE="${INPUT_FILE%.*}-decoded${INPUT_FILE##*.}"

# Ensure input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist"
    exit 1
fi

# Run encode
echo "Encoding $INPUT_FILE to $ENCODED_FILE"
if ! cargo run --release --bin saffron encode -i "$INPUT_FILE" -o "$ENCODED_FILE"; then
    echo "Encoding failed"
    exit 1
fi

# Run decode
echo "Decoding $ENCODED_FILE to $DECODED_FILE"
if ! cargo run --release --bin saffron decode -i "$ENCODED_FILE" -o "$DECODED_FILE"; then
    echo "Decoding failed"
    exit 1
fi

# Compare files
echo "Comparing original and decoded files..."
if cmp -s "$INPUT_FILE" "$DECODED_FILE"; then
    echo "✓ Success: Files are identical"
    echo "Cleaning up temporary files..."
    rm -f "$ENCODED_FILE" "$DECODED_FILE"
    exit 0
else
    echo "✗ Error: Files differ"
    echo "Keeping temporary files for inspection"
    diff "$INPUT_FILE" "$DECODED_FILE"
    exit 1
fi
