# Export Test Vectors

A command-line tool for exporting test vectors from the mina-poseidon crate.

## Usage

```bash
cargo run --bin export_test_vectors --all-features -- <MODE> <PARAM_TYPE> <OUTPUT_FILE> [--format <FORMAT>]
```

### Arguments

- `<MODE>`: Number encoding format
  - `b10`: Base-10 format
  - `hex`: Hexadecimal format

- `<PARAM_TYPE>`: Parameter type to use
  - `legacy`: Legacy parameters
  - `kimchi`: Kimchi parameters

- `<OUTPUT_FILE>`: Output file path, use `-` for stdout

### Options

- `--format <FORMAT>`: Output file format (default: `json`)
  - `es5`: ES5 JavaScript format
  - `json`: JSON format

### Examples

```bash
# Export b10 legacy vectors to a JSON file
cargo run --bin export_test_vectors --all-features -- b10 legacy vectors.json

# Export hex kimchi vectors to stdout in JSON format
cargo run --bin export_test_vectors --all-features -- hex kimchi -

# Export hex legacy vectors to a JSON file
cargo run --bin export_test_vectors --all-features -- hex legacy test_vectors.json

# Export hex kimchi vectors to an ES5 JavaScript file
cargo run --bin export_test_vectors --all-features -- hex kimchi poseidon-kimchi.js --format es5

# Export hex legacy vectors to ES5 format on stdout
cargo run --bin export_test_vectors --all-features -- hex legacy - --format es5
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
