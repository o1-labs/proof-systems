# Export Test Vectors

A command-line tool for exporting test vectors from the mina-poseidon crate.

## Usage

```bash
cargo run --bin export_test_vectors --all-features -- <MODE> <PARAM_TYPE> <OUTPUT_FILE>
```

### Arguments

- `<MODE>`: Output format for the test vectors
  - `b10`: Base-10 format
  - `hex`: Hexadecimal format

- `<PARAM_TYPE>`: Parameter type to use
  - `legacy`: Legacy parameters
  - `kimchi`: Kimchi parameters

- `<OUTPUT_FILE>`: Output file path, use `-` for stdout

### Examples

```bash
# Export b10 legacy vectors to a file
cargo run --bin export_test_vectors --all-features -- b10 legacy vectors.json

# Export hex kimchi vectors to stdout
cargo run --bin export_test_vectors --all-features -- hex kimchi -

# Export hex legacy vectors to a file
cargo run --bin export_test_vectors --all-features -- hex legacy test_vectors.json
```

### Help

```bash
cargo run --bin export_test_vectors --all-features -- --help
```

## Building

```bash
cargo build --bin export_test_vectors --all-features
```

## Testing

The tool is tested in CI with all valid command combinations. See
`.github/workflows/test-export-vectors.yml` for the test suite.
