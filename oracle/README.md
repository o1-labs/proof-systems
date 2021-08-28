# Oracle

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```
usage: cargo run --features [3w|5w|3] -- [Hex|B10] <OUTPUT_FILE>
```

Examples

```
cargo run --features 3 -- B10 -

cargo run --features 3w -- Hex 3w.json
cargo run --features 5w -- Hex 5w.json
cargo run --features 3 -- Hex 3.json

```
