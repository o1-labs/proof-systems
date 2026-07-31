//! Pins the canonical constants the OpenVM path hardcodes.
//!
//! Under `feature = "openvm"` on a zkVM target, `fp.rs` and `fq.rs` set
//! `R = 1`, which switches `Fp`/`Fq` from arkworks' Montgomery storage to
//! canonical storage. `GENERATOR` and `TWO_ADIC_ROOT_OF_UNITY` then have to be
//! written as canonical decimals rather than carried over as Montgomery limbs,
//! and a wrong digit there does not fail to compile — it produces a field that
//! works for everything except FFT-adjacent code, which is the kind of bug that
//! surfaces three layers away.
//!
//! This test runs on the host, where `FqConfigDerived`/`FrConfigDerived` are
//! ark-ff's own derived configs, so it compares the literals against the
//! reference implementation rather than against another copy of themselves.
//! It is deliberately not gated on the `openvm` feature: the literals live in
//! the source unconditionally, so they should be checked unconditionally.

use ark_ff::{MontConfig, PrimeField};
use mina_curves::pasta::fields::{fp::FqConfigDerived, fq::FrConfigDerived};

/// The decimal in `fp.rs`'s `TWO_ADIC_ROOT_OF_UNITY` under `openvm`.
const FP_TWO_ADIC_ROOT_OF_UNITY: &str =
    "19814229590243028906643993866117402072516588566294623396325693409366934201135";

/// The decimal in `fq.rs`'s `TWO_ADIC_ROOT_OF_UNITY` under `openvm`.
const FQ_TWO_ADIC_ROOT_OF_UNITY: &str =
    "20761624379169977859705911634190121761503565370703356079647768903521299517535";

#[test]
fn fp_canonical_constants() {
    let root = <FqConfigDerived as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY;
    assert_eq!(root.into_bigint().to_string(), FP_TWO_ADIC_ROOT_OF_UNITY);

    let generator = <FqConfigDerived as MontConfig<4>>::GENERATOR;
    assert_eq!(generator.into_bigint().to_string(), "5");
}

#[test]
fn fq_canonical_constants() {
    let root = <FrConfigDerived as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY;
    assert_eq!(root.into_bigint().to_string(), FQ_TWO_ADIC_ROOT_OF_UNITY);

    let generator = <FrConfigDerived as MontConfig<4>>::GENERATOR;
    assert_eq!(generator.into_bigint().to_string(), "5");
}
