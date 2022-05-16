use crate::serialization::SerdeAs;
use ark_ff::Field;
use ark_poly::polynomial::{univariate::DensePolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::{Deref, Index};

#[serde_as]
#[derive(Clone, Serialize)]
pub struct ChunkedEvals<F: CanonicalSerialize> {
    #[serde_as(as = "Vec<SerdeAs>")]
    pub chunk: Vec<F>,
    index: usize,
}

pub struct ChunkedEvalsIterator<'a, F: CanonicalSerialize> {
    chunk: &'a Vec<F>,
    index: usize,
}

impl<F: Field> Index<usize> for ChunkedEvals<F> {
    type Output = F;

    /// Returns the field element at `pos` position
    fn index(&self, pos: usize) -> &Self::Output {
        &self.chunk[pos]
    }
}

// Used to iterate over the chunk
impl<F: Field> Deref for ChunkedEvals<F> {
    type Target = Vec<F>;

    fn deref(&self) -> &Self::Target {
        &self.chunk
    }
}

impl<'a, F: CanonicalSerialize> Iterator for ChunkedEvalsIterator<'a, F> {
    type Item = &'a F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.chunk.len() {
            return None;
        }

        self.index += 1;
        Some(&self.chunk[self.index - 1])
    }
}

impl<F: Field> ChunkedEvals<F> {
    /// Returns the length of the chunk
    pub fn len(&self) -> usize {
        self.chunk.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunk.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &F> + '_ {
        self.chunk.iter()
    }
}

pub trait ToChunk<F: ark_serialize::CanonicalSerialize> {
    fn to_chunk(&self) -> ChunkedEvals<F>;
}

impl<F: Field> ToChunk<F> for Vec<F> {
    fn to_chunk(&self) -> ChunkedEvals<F> {
        ChunkedEvals {
            chunk: self.clone(),
            index: 0,
        }
    }
}

/// This struct contains multiple chunk polynomials with degree `size-1`.
pub struct ChunkedPolynomial<F: Field> {
    /// The chunk polynomials.
    pub polys: Vec<DensePolynomial<F>>,

    /// Each chunk polynomial has degree `size-1`.
    pub size: usize,
}

impl<F: Field> ChunkedPolynomial<F> {
    /// This function evaluates polynomial in chunks.
    pub fn evaluate_chunks(&self, elm: F) -> ChunkedEvals<F> {
        let mut res: Vec<F> = vec![];
        for poly in self.polys.iter() {
            let eval = poly.evaluate(&elm);
            res.push(eval);
        }
        ChunkedEvals {
            chunk: res,
            index: 0,
        }
    }

    /// Multiplies the chunks of a polynomial with powers of zeta^n to make it of degree n-1.
    /// For example, if a polynomial can be written `f = f0 + x^n f1 + x^2n f2`
    /// (where f0, f1, f2 are of degree n-1), then this function returns the new semi-evaluated
    /// `f'(x) = f0(x) + zeta^n f1(x) + zeta^2n f2(x)`.
    pub fn linearize(&self, zeta_n: F) -> DensePolynomial<F> {
        let mut scale = F::one();
        let mut coeffs = vec![F::zero(); self.size];

        for poly in self.polys.iter() {
            for (coeff, poly_coeff) in coeffs.iter_mut().zip(&poly.coeffs) {
                *coeff += scale * poly_coeff;
            }

            scale *= zeta_n;
        }

        while coeffs.last().map_or(false, |c| c.is_zero()) {
            coeffs.pop();
        }

        DensePolynomial { coeffs }
    }
}

#[cfg(test)]
mod tests {
    use crate::ExtendedDensePolynomial;

    use super::*;
    use ark_ff::One;
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use mina_curves::pasta::fp::Fp;

    #[test]

    fn test_chunk_poly() {
        let one = Fp::one();
        let zeta = one + one;
        let zeta_n = zeta.square();
        let res = (one + zeta)
            * (one + zeta_n + zeta_n * zeta.square() + zeta_n * zeta.square() * zeta.square());

        // 1 + x + x^2 + x^3 + x^4 + x^5 + x^6 + x^7 = (1+x) + x^2 (1+x) + x^4 (1+x) + x^6 (1+x)
        let coeffs = [one, one, one, one, one, one, one, one];
        let f = DensePolynomial::from_coefficients_slice(&coeffs);

        let eval = f.to_chunked_polynomial(2).linearize(zeta_n).evaluate(&zeta);

        assert!(eval == res);
    }
}
