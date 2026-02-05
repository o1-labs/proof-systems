# Changelog

All notable changes to this project will be documented in this file, organized
by crate. Each change must be linked to a pull request or commit.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Dependencies

#### Changed

- Bump strum from 0.26.1 to 0.27.2
  ([#3457](https://github.com/o1-labs/proof-systems/pull/3457))
- Bump env_logger from 0.11.1 to 0.11.6
  ([#3461](https://github.com/o1-labs/proof-systems/pull/3461))
- Bump raw-cpuid from 11.5.0 to 11.6.0
  ([#3460](https://github.com/o1-labs/proof-systems/pull/3460))
- Bump thiserror from 2.0.12 to 2.0.18
  ([#3459](https://github.com/o1-labs/proof-systems/pull/3459))

### Book

#### Changed

- Migrate book from mdBook to Docusaurus
  ([#3456](https://github.com/o1-labs/proof-systems/pull/3456))

### CI

#### Changed

- Update Node.js to v24 and remove markdownlint-cli dependency
  ([#3456](https://github.com/o1-labs/proof-systems/pull/3456))
- Use cargo-spec docusaurus flavor for specification generation
  ([#3456](https://github.com/o1-labs/proof-systems/pull/3456))

### [groupmap](./groupmap)

#### Added

- Add `no_std` support
  ([#3415](https://github.com/o1-labs/proof-systems/pull/3415))

### [kimchi](./kimchi)

#### Added

- Added test for the behavior of padding inside Poseidon circuits
  ([#3467](https://github.com/o1-labs/proof-systems/pull/3467))

### [mina-poseidon](./poseidon)

#### Added

- Add documentation for the `from_field` methods
  ([#3450](https://github.com/o1-labs/proof-systems/pull/3450)).
- Add constructor `new` in `ScalarChallenge` with documentation describing the
  coming deprecation
  ([#3450](https://github.com/o1-labs/proof-systems/pull/3450)).
- Add constructor `from_limbs` in `ScalarChallenge` to be used later instead of
  `ScalarChallenge::new`
  ([#3450](https://github.com/o1-labs/proof-systems/pull/3450)).
- Add method `inner` and make inner field of `ScalarChallenge` private
  ([#3450](https://github.com/o1-labs/proof-systems/pull/3450)).
- Propagate the usage of `new` in all the crate
  ([#3450](https://github.com/o1-labs/proof-systems/pull/3450)).
- Add documentation for the `poseidon_block_cipher` function
  ([#3467](https://github.com/o1-labs/proof-systems/pull/3467))
- Add check that the state input length of `poseidon_block_cipher` is
  `SC::SPONGE_WIDTH` (e.g. 3)
  ([#3467](https://github.com/o1-labs/proof-systems/pull/3467))

### plonk_neon

#### Removed

- Remove unused `plonk_neon` crate from workspace
  ([#3440](https://github.com/o1-labs/proof-systems/pull/3440))

### [poly-commitment](./poly-commitment)

#### Added

- Add documentation for the method `endos`
  ([#3450](https://github.com/o1-labs/proof-systems/pull/3450)).

### [turshi](./turshi)

#### Changed

- Remove crate as it will never be used
  ([#3466](https://github.com/o1-labs/proof-systems/pull/3466))

## 0.3.0

### CI

- Remove Rust 1.81 from CI matrix, update MSRV to 1.92 to match mina-rust and
  MinaProtocol/mina
  ([#3419](https://github.com/o1-labs/proof-systems/pull/3419))
- Skip macOS tests and docs jobs on PRs to improve CI velocity; macOS runs on
  master only ([#3429](https://github.com/o1-labs/proof-systems/pull/3429),
  [o1-labs/mina-rust#2024](https://github.com/o1-labs/mina-rust/issues/2024))
- Flag `test_lazy_mode_benchmark` as a heavy test to skip on regular CI runs
  ([#3430](https://github.com/o1-labs/proof-systems/pull/3430))
- Add no-std compatibility check workflow that verifies crates compile with
  `--no-default-features`
  ([#3414](https://github.com/o1-labs/proof-systems/pull/3414))

### [arrabbiata](./arrabbiata)

#### Changed

- (No changes in current release)

### [groupmap](./groupmap)

#### Changed

- (No changes in current release)

### [kimchi](./kimchi)

#### Changed

- Update `KimchiCurve` trait to be generic over `const FULL_ROUNDS: usize`.
- Update `verify_poseidon`, `generate_witness` and other sponge-dependent
  functions to be generic over the number of full rounds.
  ([#3386](https://github.com/o1-labs/proof-systems/pull/3386))

#### Added

- Added regression tests for the behavior of padding inside Poseidon instances
  ([#3467](https://github.com/o1-labs/proof-systems/pull/3467))

### [kimchi-msm](./msm)

#### Removed

- remove some unused code like the generic prover and the verifier
  ([#3422](https://github.com/o1-labs/proof-systems/pull/3422))

### [kimchi-stubs](./kimchi-stubs)

#### Changed

- (No changes in current release)

### [mina-curves](./curves)

#### Added

- Add `asm` feature (enabled by default) for assembly optimizations from ark_ff.
  The MontConfig derive macro generates code with `cfg(feature = "asm")`.

### [mina-hasher](./hasher)

#### Added

- Add unit tests for `domain_prefix_to_field` padding behavior
  ([#3428](https://github.com/o1-labs/proof-systems/pull/3428))

#### Changed

- Document asterisk padding behavior in `domain_prefix_to_field`
  ([#3428](https://github.com/o1-labs/proof-systems/pull/3428))
- Move `MAX_DOMAIN_STRING_LEN` to module-level constant
  ([#3428](https://github.com/o1-labs/proof-systems/pull/3428))

### [mina-poseidon](./poseidon)

#### Changed

- Update `ArithmeticSpongeParams` to be generic over `const FULL_ROUNDS: usize`,
  replacing `Vec` fields with fixed-size arrays.
- Update `Sponge` trait and `ArithmeticSponge` struct to be generic over the
  number of full rounds.
  ([#3386](https://github.com/o1-labs/proof-systems/pull/3386))

### [mina-signer](./signer)

#### Changed

- Implement (de)serialize + comparison for NetworkId, fix
  [#3411](https://github.com/o1-labs/proof-systems/issues/3411)
  ([#3423](https://github.com/o1-labs/proof-systems/pull/3423))

#### Added

- Add `into_domain_string()` method to `NetworkId` for domain string conversion
  ([#3428](https://github.com/o1-labs/proof-systems/pull/3428))

### [mvpoly](./mvpoly)

#### Changed

- (No changes in current release)

### [o1-utils](./utils)

#### Removed

- Remove `div_ceil`, `is_multiple_of`, and `repeat_n` compatibility wrappers now
  that MSRV is 1.92
  ([#3419](https://github.com/o1-labs/proof-systems/pull/3419))
- Remove module `array` as it was only used by some modules from kimchi-msm that
  are now removed. ([#3422](https://github.com/o1-labs/proof-systems/pull/3422))

### [o1vm](./o1vm)

#### Changed

- (No changes in current release)

### [plonk_wasm](./plonk-wasm)

#### Changed

- (No changes in current release)

### [poly-commitment](./poly-commitment)

#### Changed

- (No changes in current release)

### [turshi](./turshi)

#### Changed

- (No changes in current release)

## 0.2.0 (2025-11-26)

### CI

#### Added

- CI: add support for macos-latest with Rust 1.84
  ([#3131](https://github.com/o1-labs/proof-systems/pull/3131))

### [arrabbiata](./arrabbiata)

#### Changed

- (No changes in current release)

### [folding](./folding)

#### Changed

- Remove crate as it will never be used
  ([#3374](https://github.com/o1-labs/proof-systems/pull/3374))

### [groupmap](./groupmap)

#### Changed

- Make field of BWParameters public
  ([#3326](https://github.com/o1-labs/proof-systems/pull/3326))

### [ivc](./ivc)

#### Changed

- Remove crate as it will never be used
  ([#3373](https://github.com/o1-labs/proof-systems/pull/3373))

### [kimchi](./kimchi)

#### Changed

- (No changes in current release)

### [kimchi-msm](./msm)

#### Changed

- (No changes in current release)

### [kimchi-stubs](./kimchi-stubs)

#### Changed

- Remove warnings `+adx/+bmi2 is not a recognised feature for this target, issue
  [#3322](https://github.com/o1-labs/proof-systems/issues/3322)
  ([#3248](https://github.com/o1-labs/proof-systems/pull/3248))
- Move lagrange_basis module from kimchi-stubs in poly-commitment
  ([#3329](https://github.com/o1-labs/proof-systems/pull/3329))

### [mina-curves](./curves)

#### Changed

- (No changes in current release)

### [mina-hasher](./hasher)

#### Changed

- (No changes in current release)

### [mina-poseidon](./poseidon)

#### Changed

- (No changes in current release)

### [mina-signer](./signer)

#### Added

- Implement a method to return a dummy signature
  ([#3327](https://github.com/o1-labs/proof-systems/pull/3327))
- Implement `derive_nonce_compatible` function, a nonce derivation algorithm
  compatible with the TypeScript and OCaml implementation
  ([#3302](https://github.com/o1-labs/proof-systems/pull/3302/))
- Add `packed` parameter to `Signer::sign` method to control nonce derivation
  method
  - `packed: true` uses OCaml/TypeScript compatible nonce derivation
  - `packed: false` uses standard Rust nonce derivation (will be deprecated)
    ([#3302](https://github.com/o1-labs/proof-systems/pull/3302/))

#### Changed

- Make CompressedPubKey orderable
  ([#3328](https://github.com/o1-labs/proof-systems/pull/3328))
- Make the structure `Message` from `schnorr.rs` public
  ([#3302](https://github.com/o1-labs/proof-systems/pull/3302/))
- Make the fields of the structure `Schnorr` from `schnorr.rs` public
  ([#3302](https://github.com/o1-labs/proof-systems/pull/3302/))

### [mvpoly](./mvpoly)

#### Changed

- (No changes in current release)

### [o1-utils](./utils)

#### Changed

- (No changes in current release)

### [o1vm](./o1vm)

#### Changed

- (No changes in current release)

### [plonk_wasm](./plonk-wasm)

#### Changed

- `WasmProverProof.deserialize` to accept `&[u8]` instead of `&str`
  ([[#3369]](https://github.com/o1-labs/proof-systems/pull/3369))

#### Added

- Add function to `deserialize` a `WasmProverProof`
  ([#3354](https://github.com/o1-labs/proof-systems/pull/3354))

### [poly-commitment](./poly-commitment)

#### Changed

- Move lagrange_basis module from kimchi-stubs in poly-commitment
  ([#3329](https://github.com/o1-labs/proof-systems/pull/3329))

### [turshi](./turshi)

#### Changed

- (No changes in current release)

## Previous Changes

For changes prior to this changelog introduction, please refer to the git commit
history and individual component changelogs in their respective directories.
