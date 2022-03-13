# Oracle

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```text
usage: cargo run -p export_test_vectors --all-features -- [Hex|B10] [legacy|kimchi] <OUTPUT_FILE>
```

Examples

```text
cargo run -p export_test_vectors --all-features -- B10 legacy -
cargo run -p export_test_vectors --all-features -- b10 legacy legacy.json
cargo run -p export_test_vectors --all-features -- hex kimchi kimchi.json
```
