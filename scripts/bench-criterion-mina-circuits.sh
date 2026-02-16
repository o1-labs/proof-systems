#!/bin/bash

echo "Starting bench-criterion-mina-circuits.sh"

set -ex

# Queries all test circuits from the cloud
list_objects() {
  curl -s "https://storage.googleapis.com/storage/v1/b/o1labs-ci-test-data/o" | grep -o '"name": "serialised-test-mina-circuits/[^"]*.ser"' | cut -d'"' -f4
}

for test_file in $(list_objects); do
    # Local temporary path for the downloaded file
    LOCAL_PATH="/tmp/$(basename "$test_file")"

    echo "Processing benchmark $test_file in $LOCAL_PATH"

    # Download the inputs
    curl -s "https://storage.googleapis.com/o1labs-ci-test-data/$test_file" -o $LOCAL_PATH

    if [[ -v SAVE_BASELINE_NAME ]]; then
        echo "In --save-baseline mode"
        BENCH_PROOF_CREATION_MINA_INPUTS=$LOCAL_PATH cargo bench --bench proof_criterion_mina -- --save-baseline $SAVE_BASELINE_NAME
    elif [[ -v BASELINE_NAME ]]; then
        echo "In --baseline mode"
        # run against the existing baseline and fail if performance regression has been noticed
        # The noise threshold is higher than default because our CI machines are not super precise
        REPORT_FILE=/tmp/criterion-result-$(date +%Y-%m-%d_%H-%M-%S).txt
        BENCH_PROOF_CREATION_MINA_INPUTS=$LOCAL_PATH cargo bench --bench proof_criterion_mina -- --noise-threshold 0.05 --baseline $BASELINE_NAME 2>&1 | tee $REPORT_FILE

        BENCH_EXIT_STATUS=${PIPESTATUS[0]}
        if [ $BENCH_EXIT_STATUS -ne 0 ]; then
          echo "Cargo bench command failed with exit status $BENCH_EXIT_STATUS"
          exit $BENCH_EXIT_STATUS
        fi

        # Fail if there is 'regressed' in the logs
        grep 'regressed' $REPORT_FILE && exit 1 || echo "No regressions detected, continuing..."
    else
        echo "In default mode"
        BENCH_PROOF_CREATION_MINA_INPUTS=$LOCAL_PATH cargo bench --bench proof_criterion_mina
    fi

    # Remove the input file
    rm $LOCAL_PATH
done
