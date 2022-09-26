//! While we could have create a custom type Fp256, and type aliases for Fp and Fq,
//! We create two custom types using this macro: one for Fp and one for Fq.
//! This makes bindings easier to reason about.
//!
//! The strategy used is to create wrappers around `ark_ff::Fp256<Fp_params>` and `ark_ff::Fp256<Fq_params>`,
//! and implement `ark_ff::Field` and related traits that are needed
//! to pretend that these are the actual types.
//!
//! Note: We can't use ark_ff::Fp256 directly because it doesn't implement `ocaml::ToValue`.
//! And we can't implement `ocaml::ToValue` for `ark_ff::Fp256` because it's not defined in this crate.

use crate::arkworks::fp256::impl_field;
use paste::paste;
use std::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::Hash,
    io::{Read, Result as IoResult, Write},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr,
};

macro_rules! impl_fp256 {
    ($name: ident, $CamlF: ident, $ArkF: ty, $Params: ty) => {
        paste! {
            //
            // the wrapper struct
            //

            #[cfg_attr(feature = "ocaml_types", derive(ocaml_gen::CustomType))]
            pub struct $CamlF($ArkF);

            //
            // Field implementation
            //

            impl_field!($CamlF, $ArkF, $Params);

            //
            // OCaml
            //

            #[cfg(feature = "ocaml_types")]
            pub mod caml {
                use super::*;

                use crate::arkworks::{BigInteger256, caml_bytes_string::CamlBytesString};

                use ark_ff::bytes::ToBytes;
                use ark_ff::{FftField, Field, One, PrimeField, SquareRootField, UniformRand, Zero};
                use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
                use num_bigint::BigUint;
                use rand::rngs::StdRng;

                use std::{
                    cmp::Ordering::{Equal, Greater, Less},
                    convert::{TryFrom, TryInto},
                };

                //
                // Ocaml opaque type
                //

                ocaml::custom!($CamlF);

                unsafe impl<'a> ocaml::FromValue<'a> for $CamlF {
                    fn from_value(value: ocaml::Value) -> Self {
                        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
                        x.as_ref().clone()
                    }
                }

                //
                // Helpers
                //

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _size_in_bits>]() -> ocaml::Int {
                    <$Params as ark_ff::FpParameters>::MODULUS_BITS as isize
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _size>]() -> BigInteger256 {
                    <$Params as ark_ff::FpParameters>::MODULUS.into()
                }

                //
                // Arithmetic methods
                //

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _add>](x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) -> $CamlF {
                    *x.as_ref() + *y.as_ref()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _sub>](x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) -> $CamlF {
                    *x.as_ref() - *y.as_ref()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _negate>](x: ocaml::Pointer<$CamlF>) -> $CamlF {
                    x.as_ref().neg()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _mul>](x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) -> $CamlF {
                    *x.as_ref() * *y.as_ref()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _div>](x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) -> $CamlF {
                    *x.as_ref() / *y.as_ref()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _inv>](x: ocaml::Pointer<$CamlF>) -> Option<$CamlF> {
                    x.as_ref().inverse().map(Into::into)
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _square>](x: ocaml::Pointer<$CamlF>) -> $CamlF {
                    x.as_ref().square()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _is_square>](x: ocaml::Pointer<$CamlF>) -> bool {
                    let s = x.as_ref().pow(<$Params as ark_ff::FpParameters>::MODULUS_MINUS_ONE_DIV_TWO);
                    s.is_zero() || s.is_one()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _sqrt>](x: ocaml::Pointer<$CamlF>) -> Option<$CamlF> {
                    x.as_ref().sqrt().map(Into::into)
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _of_int>](i: ocaml::Int) -> $CamlF {
                    $CamlF::from(i as u64)
                }

                //
                // Conversion methods
                //

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _to_string>](x: ocaml::Pointer<$CamlF>) -> String {
                    x.as_ref().into_repr().to_string()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _of_string>](s: CamlBytesString) -> Result<$CamlF, ocaml::Error> {
                    let biguint = BigUint::parse_bytes(s.0, 10).ok_or(ocaml::Error::Message(
                        "[<$name:snake _of_string>]: couldn't parse input",
                    ))?;
                    let bigint: ark_ff::BigInteger256 = biguint
                        .try_into()
                        .map_err(|_| ocaml::Error::Message("[<$name:snake _of_string>]: Biguint is too large"))?;
                    $CamlF::try_from(bigint).map_err(|_| ocaml::Error::Message("[<$name:snake _of_string>]"))
                }

                //
                // Data methods
                //

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _print>](x: ocaml::Pointer<$CamlF>) {
                    println!("{}", x.as_ref().into_repr().to_string());
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _copy>](mut x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) {
                    *x.as_mut() = *y.as_ref()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _mut_add>](mut x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) {
                    *x.as_mut() += y.as_ref();
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _mut_sub>](mut x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) {
                    *x.as_mut() -= y.as_ref();
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _mut_mul>](mut x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) {
                    *x.as_mut() *= y.as_ref();
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _mut_square>](mut x: ocaml::Pointer<$CamlF>) {
                    x.as_mut().square_in_place();
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _compare>](x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) -> ocaml::Int {
                    match x.as_ref().cmp(&y.as_ref()) {
                        Less => -1,
                        Equal => 0,
                        Greater => 1,
                    }
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _equal>](x: ocaml::Pointer<$CamlF>, y: ocaml::Pointer<$CamlF>) -> bool {
                    x.as_ref() == y.as_ref()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _random>]() -> $CamlF {
                    let fp: $ArkF = UniformRand::rand(&mut rand::thread_rng());
                    fp.into()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _rng>](i: ocaml::Int) -> $CamlF {
                    // We only care about entropy here, so we force a conversion i32 -> u32.
                    let i: u64 = (i as u32).into();
                    let mut rng: StdRng = rand::SeedableRng::seed_from_u64(i);
                    let fp: $ArkF = UniformRand::rand(&mut rng);
                    fp.into()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _to_bigint>](x: ocaml::Pointer<$CamlF>) -> BigInteger256 {
                    x.as_ref().into_repr().into()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _of_bigint>](x: BigInteger256) -> Result<$CamlF, ocaml::Error> {
                    $ArkF::from_repr(x.0).map($CamlF::from).ok_or_else(|| {
                        let err = format!(
                            "[<$name:snake _of_bigint>] was given an invalid CamlBigInteger256: {}",
                            x
                        );
                        ocaml::Error::Error(err.into())
                    })
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _two_adic_root_of_unity>]() -> $CamlF {
                    let res: $ArkF = FftField::two_adic_root_of_unity();
                    res.into()
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _domain_generator>](log2_size: ocaml::Int) -> Result<$CamlF, ocaml::Error> {
                    Domain::new(1 << log2_size)
                        .map(|x| x.group_gen)
                        .ok_or(ocaml::Error::Message("[<$name:snake _domain_generator>]"))
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _to_bytes>](x: ocaml::Pointer<$CamlF>) -> [u8; std::mem::size_of::<$ArkF>()] {
                    let mut res = [0u8; std::mem::size_of::<$ArkF>()];
                    x.as_ref().write(&mut res[..]).unwrap();
                    res
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _of_bytes>](x: &[u8]) -> Result<$CamlF, ocaml::Error> {
                    let len = std::mem::size_of::<$CamlF>();
                    if x.len() != len {
                        ocaml::Error::failwith("[<$name:snake _of_bytes>]")?;
                    };
                    let x = unsafe { *(x.as_ptr() as *const $CamlF) };
                    Ok(x)
                }

                #[ocaml_gen::func]
                #[ocaml::func]
                pub fn [<$name:snake _deep_copy>](x: $CamlF) -> $CamlF {
                    x
                }

            }
        }
    };
}

pub mod fp {
    use super::*;
    use crate::pasta::{fields::fp::Fp as PastaFp, FpParameters};

    impl_fp256!(caml_pasta_fp, Fp, PastaFp, FpParameters);
}

pub mod fq {
    use super::*;
    use crate::pasta::{fields::fq::Fq as PastaFq, FqParameters};

    impl_fp256!(caml_pasta_fq, Fq, PastaFq, FqParameters);
}
