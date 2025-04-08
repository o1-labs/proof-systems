#!/bin/bash

# Check if input file is provided
if [ $# -lt 1 ]; then
   echo "Usage: $0 <input_file> [srs-filepath]"
   exit 1
fi

INPUT_FILE="$1"
SRS_ARG=""
if [ $# -eq 2 ]; then
   SRS_ARG="--srs-filepath $2"
fi
COMMITMENT_FILE="${INPUT_FILE%.*}_commitment.bin"
ENCODED_FILE="${INPUT_FILE%.*}.bin"
DECODED_FILE="${INPUT_FILE%.*}_decoded.${INPUT_FILE##*.}"

# Ensure input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist"
    exit 1
fi

FILE_LEN_BYTES=$(wc -c < $INPUT_FILE)

# Generate 32-byte random challenge as hex string
echo "Generating random challenge..."
CHALLENGE_SEED=$(head -c 32 /dev/urandom | xxd -p -c 32)
echo "Challenge seed: $CHALLENGE_SEED"

# Compute commitment and capture last line
COMMITMENT=$(cargo run --release --bin saffron -p saffron compute-commitment --challenge-seed "$CHALLENGE_SEED" -i "$INPUT_FILE" -o "$COMMITMENT_FILE" $SRS_ARG | tee /dev/stderr | tail -n 1 | cut -d' ' -f2)

# Run encode with captured commitment
echo "Encoding $INPUT_FILE to $ENCODED_FILE"
if ! cargo run --release --bin saffron -p saffron encode -i "$INPUT_FILE" -o "$ENCODED_FILE" --assert-commitment "$COMMITMENT" --challenge-seed "$CHALLENGE_SEED" $SRS_ARG; then
   echo "Encoding failed"
   exit 1
fi

# Generate storage proof and capture proof output
echo "Generating storage proof..."
PROOF=$(cargo run --release --bin saffron -p saffron storage-proof -i "$ENCODED_FILE" --challenge-seed "$CHALLENGE_SEED" $SRS_ARG | tee /dev/stderr | tail -n 1 | cut -d' ' -f2)
if [ $? -ne 0 ]; then
    echo "Storage proof generation failed"
    exit 1
fi

# Verify the storage proof
echo "Verifying proof..."

if ! cargo run --release --bin saffron -p saffron verify-storage-proof --commitment "$COMMITMENT" --challenge-seed "$CHALLENGE_SEED" --proof "$PROOF" $SRS_ARG; then
    echo "Proof verification failed"
    exit 1
fi
echo "✓ Proof verification successful"


# Run decode
echo "Decoding $ENCODED_FILE to $DECODED_FILE"
if ! cargo run --release --bin saffron -p saffron decode -i "$ENCODED_FILE" -o "$DECODED_FILE" --truncate-to-bytes $FILE_LEN_BYTES $SRS_ARG; then
    echo "Decoding failed"
    exit 1
fi

# Compare files
echo "Comparing original and decoded files..."
if cmp -s "$INPUT_FILE" "$DECODED_FILE"; then
    echo "✓ Success: Files are identical"
    echo "Cleaning up temporary files..."
    rm -f "$ENCODED_FILE" "$DECODED_FILE" "$COMMITMENT_FILE"
    exit 0
else
    echo "✗ Error: Files differ"
    echo "Keeping temporary files for inspection"
    diff "$INPUT_FILE" "$DECODED_FILE"
    exit 1
fi
