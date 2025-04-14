# Poseidon

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```text
cargo run -p export_test_vectors -- [Hex|B10] [legacy|kimchi] <OUTPUT_FILE>
```

Examples

```text
cargo run -p export_test_vectors -- B10 legacy -
cargo run -p export_test_vectors -- b10 legacy legacy.json
cargo run -p export_test_vectors -- hex kimchi kimchi.json
```

## Benchmark

This folder contains a Poseidon benchmark `poseidon_bench`.

To run the benchmark natively, do:

```sh
cargo bench --bench=poseidon_bench
```

The benchmark can also be run in WebAssembly (executed by Node.js), launched
from the repository root:

```sh
./scripts/bench-wasm.sh --bench=poseidon_bench
```

For this to work, the filename of your benchmark has to be the same as the
benchmark name!
