#!/bin/bash

BIN_DIR=${1:-${BIN_DIR:-o1vm/resources/programs/mips/bin}}

# Ensure the directory exists
if [[ ! -d "$BIN_DIR" ]]; then
  echo "Error: Directory '$BIN_DIR' does not exist."
  exit 1
fi

find "$BIN_DIR" -type f ! -name "*.o" | while read -r file; do
  echo "Processing: $file"
  cargo run --bin pickles_o1vm -- cannon gen-state-json -i "$file"
done
