# Oracle

## Test vectors

Tests are ran against our own test vectors in `tests/test_vectors`.

You can re-generate the test vectors by using:

```
cargo run --bin export_test_vectors --no-default-features --features [five_wire|three_wire] -- test_vectors.json
```
