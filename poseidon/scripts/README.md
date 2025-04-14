# Utility scripts

## params.sage

A script for generating cryptographic parameters (round constants and MDS
matrices) for the Poseidon hash function over Pasta fields.

### Overview

This SageMath script generates secure parameters for the Poseidon hash function,
which is used in zero-knowledge proof systems. It creates:

- Round constants
- MDS (Maximum Distance Separable) matrices

These parameters can be output in either Rust or OCaml format for use in
cryptographic implementations.

### Requirements

- [SageMath](https://www.sagemath.org/)
- Python 3.x

### Usage

```bash
./params.sage [language] [width] [name] [--rounds ROUNDS]
```

#### Parameters

- `language`: Output format (`rust` or `ocaml`)
- `width`: Sponge width (typically 3 or 5)
- `name`: Parameter set name (use '' for legacy mode)
- `--rounds`: Number of round constants (default: 100)

#### Examples

Generate legacy 3-wire Poseidon parameters in Rust format:
```bash
./params.sage rust 3 ''
```

Generate named 3-wire Poseidon parameters with 54 rounds:
```bash
./params.sage rust 3 3 --rounds 54
```

Generate parameters for the "kimchi" parameter set:
```bash
./params.sage rust 3 kimchi --rounds 55
```

### Operating Modes

#### Legacy Mode

Activated when `name` is set to '' and width is either 3 or 5. Used for the
original Poseidon implementations.

#### Named Mode

The current recommended approach where each parameter set has a unique name,
ensuring completely unique parameters for each hash function definition.

### Parameter Sets

| Name   | Parameters                     |
|--------|--------------------------------|
| ''     | Reserved for legacy            |
| kimchi | rounds=55, width=3, rate=2, alpha=7 |

### Implementation Details

The script uses deterministic randomness based on cryptographic hashing
(SHA-256) to generate the parameters. The MDS matrices are created using the
Cauchy matrix construction method to ensure they have the necessary
cryptographic properties.

### Output

The script outputs parameter declarations ready to be included in Rust or OCaml
code.
