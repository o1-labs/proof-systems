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

ENCODED_FILE="${INPUT_FILE%.*}.bin"
DECODED_FILE="${INPUT_FILE%.*}-decoded${INPUT_FILE##*.}"
PERTURBED_FILE="${INPUT_FILE%.*}_perturbed${INPUT_FILE##*.}"
ENCODED_DIFF_FILE="${ENCODED_FILE%.*}_diff.bin"
DECODED_PERTURBED_FILE="${PERTURBED_FILE}-decoded${INPUT_FILE##*.}"

compare_files() {
   local file1="$1"
   local file2="$2"
   
   echo "Comparing files..."
   if cmp -s "$file1" "$file2"; then
       echo "✓ Success: Files are identical"
   else
       echo "✗ Error: Files differ"
       echo "Keeping files for inspection"
       diff "$file1" "$file2"
       exit 1
   fi
}

perturb_bytes() {
   local input_file=$1
   local output_file=$2
   local threshold=${3:-0.1}  # Default 10% chance
   perl -pe 'rand() < '$threshold' and $_ = chr(rand(256)) for split ""' "$input_file" > "$output_file"
}

# Ensure input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' does not exist"
    exit 1
fi

# Compute commitment and capture last line
COMMITMENT=$(cargo run --release --bin saffron compute-commitment -i "$INPUT_FILE" $SRS_ARG | tee /dev/stderr | tail -n 1)

# Run encode with captured commitment
echo "Encoding $INPUT_FILE to $ENCODED_FILE"
if ! cargo run --release --bin saffron encode -i "$INPUT_FILE" -o "$ENCODED_FILE" --assert-commitment "$COMMITMENT" $SRS_ARG; then
   echo "Encoding failed"
   exit 1
fi

# Generate 32-byte random challenge as hex string
echo "Generating random challenge..."
CHALLENGE=$(head -c 32 /dev/urandom | xxd -p -c 32)
echo "Challenge: $CHALLENGE"

# Generate storage proof and capture proof output
echo "Generating storage proof..."
PROOF=$(cargo run --release --bin saffron storage-proof -i "$ENCODED_FILE" --challenge "$CHALLENGE" $SRS_ARG | tee /dev/stderr | tail -n 1)
if [ $? -ne 0 ]; then
    echo "Storage proof generation failed"
    exit 1
fi

# Verify the storage proof
echo "Verifying proof..."
if ! cargo run --release --bin saffron verify-storage-proof --commitment "$COMMITMENT" --challenge "$CHALLENGE" --proof "$PROOF" $SRS_ARG; then
    echo "Proof verification failed"
    exit 1
fi
echo "✓ Proof verification successful"


# Run decode
echo "Decoding $ENCODED_FILE to $DECODED_FILE"
if ! cargo run --release --bin saffron decode -i "$ENCODED_FILE" -o "$DECODED_FILE" $SRS_ARG; then
    echo "Decoding failed"
    exit 1
fi

# Compare file to original
compare_files "$INPUT_FILE" "$DECODED_FILE"

# Usage example in your script:
perturb_bytes "$INPUT_FILE" "$PERTURBED_FILE" 0.1

echo "Calculating diff for upated $INPUT_FILE (stored updated data in $PERTURBED_FILE)"
cargo run --release --bin saffron calculate-diff --old "$INPUT_FILE" --new "$PERTURBED_FILE" -o "$ENCODED_DIFF_FILE" $SRS_ARG

echo "Updating file with Storage Provider"
cargo run --release --bin saffron update -i "$ENCODED_FILE" --diff-file "$ENCODED_DIFF_FILE" --assert-commitment "$COMMITMENT" $SRS_ARG

# Run decode
echo "Decoding $ENCODED_FILE to $DECODED_FILE"
if ! cargo run --release --bin saffron decode -i "$ENCODED_FILE" -o "$DECODED_PERTURBED_FILE" $SRS_ARG; then
    echo "Decoding failed"
    exit 1
fi

# Compare update file to perturbed file
compare_files "$PERTURBED_FILE" "$DECODED_PERTURBED_FILE"

echo "Cleaning up temporary files..."
rm -f "$ENCODED_FILE" "$DECODED_FILE" "$PERTURBED_FILE" "$ENCODED_DIFF_FILE" "$DECODED_PERTURBED_FILE"
exit 0
