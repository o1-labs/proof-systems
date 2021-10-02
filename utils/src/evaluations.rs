//! This adds a few utility functions for the [Evaluations] arkworks type.

use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use rayon::prelude::*;
use serde_with::{DeserializeAs, SerializeAs};

/// An extension for the [Evaluations] type.
pub trait ExtendedEvaluations<F: FftField> {
    /// This function "scales" (multiplies) a polynomial with a scalar
    /// It is implemented to have the desired functionality for DensePolynomial
    fn scale(&self, elm: F) -> Self;
    /// square each evaluation
    fn square(&self) -> Self;
    /// raise each evaluation to some power `pow`
    fn pow(&self, pow: usize) -> Self;
    /// utility function for shifting poly along domain coordinate
    fn shift(&self, len: usize) -> Self;
}

impl<F: FftField> ExtendedEvaluations<F> for Evaluations<F, Radix2EvaluationDomain<F>> {
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        result.evals.par_iter_mut().for_each(|coeff| *coeff *= &elm);
        result
    }

    fn square(&self) -> Self {
        let mut result = self.clone();
        result.evals.par_iter_mut().for_each(|e| {
            let _ = e.square_in_place();
        });
        result
    }

    fn pow(&self, pow: usize) -> Self {
        let mut result = self.clone();
        result
            .evals
            .par_iter_mut()
            .for_each(|e| *e = e.pow([pow as u64]));
        result
    }

    fn shift(&self, len: usize) -> Self {
        let len = len % self.evals.len();
        let mut result = self.clone();
        result.evals.clear();
        result.evals = self.evals[len..].to_vec();
        let mut tail = self.evals[0..len].to_vec();
        result.evals.append(&mut tail);
        result
    }
}

//
// Serialization with serde
//

pub mod serialization {
    //! You can use this module for serialization and deserializing [Evaluations] with [serde].
    //! Simply use the following attribute on your field:
    //! `#[serde(with = "o1_utils::Evaluations::serialization") attribute"]`

    use super::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// You can use this to serialize a [Evaluations] with serde and the "serialize_with" attribute.
    /// See https://serde.rs/field-attrs.html
    pub fn serialize<S, F>(
        evaluations: &Evaluations<F, Radix2EvaluationDomain<F>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        F: FftField,
    {
        let mut bytes = vec![];
        evaluations
            .serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    /// You can use this to deserialize a [Evaluations] with serde and the "deserialize_with" attribute.
    /// See https://serde.rs/field-attrs.html
    pub fn deserialize<'de, D, F>(
        deserializer: D,
    ) -> Result<Evaluations<F, Radix2EvaluationDomain<F>>, D::Error>
    where
        D: serde::Deserializer<'de>,
        F: FftField,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Evaluations::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

//
// Serialization with [serde_with]
//

/// You can use [SerdeAs] with [serde_with] in order to serialize and deserialize containers of Evaluations:
/// Simply add annotations like `#[serde_as(as = "o1_utils::Evaluations::SerdeAs")]`
/// See https://docs.rs/serde_with/1.10.0/serde_with/guide/serde_as/index.html#switching-from-serdes-with-to-serde_as
pub struct SerdeAs;

impl<F> SerializeAs<Evaluations<F, Radix2EvaluationDomain<F>>> for SerdeAs
where
    F: FftField,
{
    fn serialize_as<S>(
        evaluations: &Evaluations<F, Radix2EvaluationDomain<F>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialization::serialize(evaluations, serializer)
    }
}

impl<'de, F> DeserializeAs<'de, Evaluations<F, Radix2EvaluationDomain<F>>> for SerdeAs
where
    F: FftField,
{
    fn deserialize_as<D>(
        deserializer: D,
    ) -> Result<Evaluations<F, Radix2EvaluationDomain<F>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serialization::deserialize(deserializer)
    }
}
