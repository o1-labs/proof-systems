#!/bin/bash

# Run encode and decode
cargo run --bin saffron encode -i fixtures/lorem.txt -o fixtures/lorem.bin
cargo run --bin saffron decode -i fixtures/lorem.bin -o fixtures/lorem-decoded.txt

# Compare files
if cmp -s fixtures/lorem.txt fixtures/lorem-decoded.txt; then
    echo "Files are identical"
    exit 0
else
    echo "Files differ"
    diff fixtures/lorem.txt fixtures/lorem-decoded.txt
    exit 1
fi