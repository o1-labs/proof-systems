//! This adds a few utility functions for the [DensePolynomial] arkworks type.

use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use serde_with::{DeserializeAs, SerializeAs};

//
// ExtendedDensePolynomial trait
//

/// An extension for the [DensePolynomial] type.
pub trait ExtendedDensePolynomial<F: Field> {
    /// This function "scales" (multiplies all the coefficients of) a polynomial with a scalar.
    fn scale(&self, elm: F) -> Self;

    /// Shifts all the coefficients to the right.
    fn shiftr(&self, size: usize) -> Self;

    /// `eval_polynomial(coeffs, x)` evaluates a polynomial given its coefficients `coeffs` and a point `x`.
    fn eval_polynomial(coeffs: &[F], x: F) -> F;

    /// This function evaluates polynomial in chunks.
    fn eval(&self, elm: F, size: usize) -> Vec<F>;

    /// Multiplies the chunks of a polynomial with powers of zeta^n
    fn chunk_polynomial(&self, zeta_n: F, n: usize) -> Self;
}

impl<F: Field> ExtendedDensePolynomial<F> for DensePolynomial<F> {
    fn scale(&self, elm: F) -> Self {
        let mut result = self.clone();
        for coeff in &mut result.coeffs {
            *coeff *= &elm
        }
        result
    }

    fn shiftr(&self, size: usize) -> Self {
        let mut result = vec![F::zero(); size];
        result.extend(self.coeffs.clone());
        DensePolynomial::<F>::from_coefficients_vec(result)
    }

    fn eval_polynomial(coeffs: &[F], x: F) -> F {
        // this uses https://en.wikipedia.org/wiki/Horner%27s_method
        let mut res = F::zero();
        for c in coeffs.iter().rev() {
            res *= &x;
            res += c;
        }
        res
    }

    fn eval(&self, elm: F, size: usize) -> Vec<F> {
        let mut res = vec![];
        for chunk in self.coeffs.chunks(size) {
            let eval = Self::from_coefficients_slice(chunk).evaluate(&elm);
            res.push(eval);
        }
        res
    }

    fn chunk_polynomial(&self, zeta_n: F, n: usize) -> Self {
        let mut scale = F::one();
        let mut coeffs = vec![F::zero(); n];

        for chunk in self.coeffs.chunks(n) {
            for (j, c) in chunk.iter().enumerate() {
                coeffs[j] += scale * c;
            }
            scale *= zeta_n;
        }

        DensePolynomial { coeffs }
    }
}

//
// Serialization with serde
//

pub mod serialization {
    //! You can use this module for serialization and deserializing [DensePolynomial] with [serde].
    //! Simply use the following attribute on your field:
    //! `#[serde(with = "o1_utils::DensePolynomial::serialization") attribute"]`

    use super::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// You can use this to serialize a [DensePolynomial] with serde and the "serialize_with" attribute.
    /// See https://serde.rs/field-attrs.html
    pub fn serialize<S, F>(domain: &DensePolynomial<F>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        F: Field,
    {
        let mut bytes = vec![];
        domain
            .serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    /// You can use this to deserialize a [DensePolynomial] with serde and the "deserialize_with" attribute.
    /// See https://serde.rs/field-attrs.html
    pub fn deserialize<'de, D, F>(deserializer: D) -> Result<DensePolynomial<F>, D::Error>
    where
        D: serde::Deserializer<'de>,
        F: Field,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        DensePolynomial::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

//
// Serialization with [serde_with]
//

/// You can use [SerdeAs] with [serde_with] in order to serialize and deserialize containers of DensePolynomial:
/// Simply add annotations like `#[serde_as(as = "o1_utils::densepolynomial::SerdeAs")]`
/// See https://docs.rs/serde_with/1.10.0/serde_with/guide/serde_as/index.html#switching-from-serdes-with-to-serde_as
pub struct SerdeAs;

impl<F> SerializeAs<DensePolynomial<F>> for SerdeAs
where
    F: Field,
{
    fn serialize_as<S>(domain: &DensePolynomial<F>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialization::serialize(domain, serializer)
    }
}

impl<'de, F> DeserializeAs<'de, DensePolynomial<F>> for SerdeAs
where
    F: Field,
{
    fn deserialize_as<D>(deserializer: D) -> Result<DensePolynomial<F>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serialization::deserialize(deserializer)
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use mina_curves::pasta::fp::Fp;

    #[test]
    fn test_eval() {
        let zero = Fp::zero();
        let one = Fp::one();
        // 1 + x^2 + x^4 + x^8
        let coeffs = [one, zero, one, zero, one, zero, one, zero];
        let f = DensePolynomial::from_coefficients_slice(&coeffs);
        let evals = f.eval(one, 2);
        for i in 0..4 {
            assert!(evals[i] == one);
        }
    }
}
