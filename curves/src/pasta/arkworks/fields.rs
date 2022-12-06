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
            #[serde_with::serde_as]
            #[derive(serde::Serialize, serde::Deserialize)]
            pub struct $CamlF(
                #[serde_as(as = "o1_utils::serialization::SerdeAs")]
                pub $ArkF
            );

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

                ocaml::custom!($CamlF);

                unsafe impl<'a> ocaml::FromValue<'a> for $CamlF {
                    fn from_value(value: ocaml::Value) -> Self {
                        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
                        x.as_ref().clone()
                    }
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
