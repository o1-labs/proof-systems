# Changelog

All notable changes to this project will be documented in this file, organized by crate.
Each change must be linked to a pull request or commit.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### [arrabbiata](./arrabbiata)

#### Changed
- (No changes in current release)

### [folding](./folding)

#### Changed
- (No changes in current release)

### [groupmap](./groupmap)

#### Changed
- (No changes in current release)

### [ivc](./ivc)

#### Changed
- (No changes in current release)

### [kimchi](./kimchi)

#### Changed
- (No changes in current release)

### [kimchi-msm](./msm)

#### Changed
- (No changes in current release)

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
- Implement `derive_nonce_compatible` function, a nonce derivation algorithm
  compatible with the TypeScript and OCaml implementation
  ([#3302](https://github.com/o1-labs/proof-systems/pull/3302/))
- Add `packed` parameter to `Signer::sign` method to control nonce derivation method
  - `packed: true` uses OCaml/TypeScript compatible nonce derivation
  - `packed: false` uses standard Rust nonce derivation (will be deprecated)
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
- (No changes in current release)

### [poly-commitment](./poly-commitment)

#### Changed
- (No changes in current release)

### [saffron](./saffron)

#### Changed
- (No changes in current release)

### [turshi](./turshi)

#### Changed
- (No changes in current release)

## Previous Changes

For changes prior to this changelog introduction, please refer to the git commit history
and individual component changelogs in their respective directories.
