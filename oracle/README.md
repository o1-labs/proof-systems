# Oracle

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```
usage: cargo run --all-features -- [Hex|B10] [3|3w|5w] <OUTPUT_FILE>
```

Examples

```
cargo run --all-features -- B10 3 -

cargo run --all-features -- Hex 3w 3w.json
cargo run --all-features -- Hex 5w 5w.json
cargo run --all-features -- Hex 3 3.json

```
