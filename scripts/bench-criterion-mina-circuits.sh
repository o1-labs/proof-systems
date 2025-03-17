#!/bin/bash

# Queries all test circuits from the cloud
list_objects() {
  curl -s "https://storage.googleapis.com/storage/v1/b/o1labs-ci-test-data/o" | grep -o '"name": "serialised-test-mina-circuits/[^"]*.ser"' | cut -d'"' -f4
}

for test_file in $(list_objects); do
    # Local temporary path for the downloaded file
    LOCAL_PATH="/tmp/${2:-$(basename "$test_file")}"

    echo "Processing benchmark $test_file in $LOCAL_PATH"

    # Download the inputs
    curl -s "https://storage.googleapis.com/o1labs-ci-test-data/$test_file" -o $LOCAL_PATH

    # Run the bench
    BENCH_PROOF_CREATION_MINA_INPUTS=$LOCAL_PATH cargo criterion -p kimchi --bench proof_criterion_mina

    # Remove the input file
    rm $LOCAL_PATH
done
