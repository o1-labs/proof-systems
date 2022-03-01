# Oracle

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```
usage: cargo run --all-features -- [Hex|B10] [basic|15w] <OUTPUT_FILE>
```

Examples

```
cargo run --all-features -- B10 basic -
cargo run --all-features -- b10 basic basic.json
cargo run --all-features -- hex 15w 15w.json
```
