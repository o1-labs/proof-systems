# Oracle

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```
usage: cargo run --features [basic|15w] -- [Hex|B10] <OUTPUT_FILE>
```

Examples

```
cargo run --features basic -- B10 -
cargo run --features basic -- Hex basic.json
cargo run --features 15w -- Hex 15w.json

```
