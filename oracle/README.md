# Oracle

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
