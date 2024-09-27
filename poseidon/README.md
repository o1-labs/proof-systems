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

It can also be run in WebAssembly (executed by Node.js), with the following prerequisites:

- Add the `wasm32-wasi` target
- Install `cargo-wasi`
- Install the wasmer JS CLI

```sh
rustup target add wasm32-wasi
cargo install cargo-wasi
npm install -g @wasmer/cli
```

Now, you can run this and other benchmarks in Wasm, using the following from the repository root:

```sh
./bench-wasm.sh --bench=poseidon_bench
```
