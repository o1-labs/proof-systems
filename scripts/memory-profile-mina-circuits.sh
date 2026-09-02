#!/bin/bash

# Runs the kimchi memory_profile binary over every serialised mina circuit
# fixture and appends one JSON line per fixture to the file given as $1.
#
# Fixtures are taken from $FIXTURES_DIR if set, otherwise downloaded from the
# CI bucket (and cached in /tmp/mina-fixtures for the next invocation, so the
# baseline and head runs of a comparison profile identical inputs).

set -eu

OUT=${1:?usage: $0 <output.jsonl>}

list_objects() {
  curl -s "https://storage.googleapis.com/storage/v1/b/o1labs-ci-test-data/o" | grep -o '"name": "serialised-test-mina-circuits/[^"]*.ser"' | cut -d'"' -f4
}

if [[ -z "${FIXTURES_DIR:-}" ]]; then
  FIXTURES_DIR=/tmp/mina-fixtures
  mkdir -p "$FIXTURES_DIR"
  for object in $(list_objects); do
    local_path="$FIXTURES_DIR/$(basename "$object")"
    if [[ ! -s "$local_path" ]]; then
      echo "Downloading $object" >&2
      curl -s "https://storage.googleapis.com/o1labs-ci-test-data/$object" -o "$local_path"
    fi
  done
fi

cargo build --release -p kimchi --bin memory_profile --features diagnostics

: > "$OUT"
for fixture in "$FIXTURES_DIR"/kimchi_inputs_*.ser; do
  echo "Profiling $(basename "$fixture")" >&2
  # One process per fixture: jemalloc retains pages across proofs, so
  # peak_resident is only trustworthy for the first proof in a process.
  "${CARGO_TARGET_DIR:-target}/release/memory_profile" fixture "$fixture" >> "$OUT"
done
