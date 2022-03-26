use ark_ff::{Field, Zero};
use ark_poly::polynomial::{univariate::DensePolynomial, Polynomial, UVPolynomial};

use rayon::prelude::*;

#[derive(Clone)]
pub struct ChunkedPolynomials<P> {
    pub polys: Vec<P>,
    pub degree: usize,
}

impl<P> Default for ChunkedPolynomials<P> {
    fn default() -> ChunkedPolynomials<P> {
        ChunkedPolynomials {
            polys: vec![],
            degree: 0,
        }
    }
}

impl<P> ChunkedPolynomials<P> {
    pub fn add_chunk(&mut self, p: P) {
        self.polys.push(p)
    }
}

impl<F: Field> ChunkedPolynomials<DensePolynomial<F>> {
    /// This function evaluates polynomial in chunks.
    pub fn eval(&self, elm: F) -> Vec<F> {
        let mut res: Vec<F> = vec![];
        for poly in self.polys.iter() {
            let eval = poly.evaluate(&elm);
            res.push(eval);
        }
        res
    }

    /// Multiplies the chunks of a polynomial with powers of zeta^n to make it of degree n-1.
    /// For example, if a polynomial can be written `f = f0 + x^n f1 + x^2n f2`
    /// (where f0, f1, f2 are of degree n-1), then this function returns the new semi-evaluated
    /// `f'(x) = f0(x) + zeta^n f1(x) + zeta^2n f2(x)`.
    pub fn compress_polynomial(&self, zeta_n: F) -> DensePolynomial<F> {
        let mut scale = F::one();
        let mut coeffs = vec![F::zero(); self.degree];

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
enum OptShiftedPolynomial<P> {
    Unshifted(P),
    Shifted(P, usize),
}

/// A formal sum of the form
/// `s_0 * p_0 + ... s_n * p_n`
/// where each `s_i` is a scalar and each `p_i` is an optionally shifted polynomial.

///pub struct ChunkedPolynomial<F, P>(Vec<(F, OptShiftedPolynomial<P>)>);

pub struct ScaledChunkedPolynomials<F, P> {
    scale: Vec<F>,
    chunked_polynomials: ChunkedPolynomials<OptShiftedPolynomial<P>>,
}

impl<F, P> Default for ScaledChunkedPolynomials<F, P> {
    fn default() -> ScaledChunkedPolynomials<F, P> {
        ScaledChunkedPolynomials {
            scale: vec![],
            chunked_polynomials: ChunkedPolynomials::<OptShiftedPolynomial<P>>::default(),
        }
    }
}

impl<F, P> ScaledChunkedPolynomials<F, P> {
    pub fn add_unshifted(&mut self, scale: F, p: P) {
        self.scale.push(scale);
        self.chunked_polynomials
            .add_chunk(OptShiftedPolynomial::Unshifted(p))
    }

    pub fn add_shifted(&mut self, scale: F, shift: usize, p: P) {
        self.scale.push(scale);
        self.chunked_polynomials
            .add_chunk(OptShiftedPolynomial::Shifted(p, shift))
    }
}

impl<'a, F: Field> ScaledChunkedPolynomials<F, &'a [F]> {
    /// check length?
    pub fn to_dense_polynomial(&self) -> DensePolynomial<F> {
        let mut res = DensePolynomial::<F>::zero();
        let zipped: Vec<_> = self
            .scale
            .iter()
            .zip(&self.chunked_polynomials.polys)
            .collect();
        let scaled: Vec<_> = zipped
            .par_iter()
            .map(|(_scale, segment)| {
                let _scale = **_scale;
                match segment {
                    OptShiftedPolynomial::Unshifted(segment) => {
                        let v = segment.par_iter().map(|x| _scale * *x).collect();
                        DensePolynomial::from_coefficients_vec(v)
                    }
                    OptShiftedPolynomial::Shifted(segment, shift) => {
                        let mut v: Vec<_> = segment.par_iter().map(|x| _scale * *x).collect();
                        let mut res = vec![F::zero(); *shift];
                        res.append(&mut v);
                        DensePolynomial::from_coefficients_vec(res)
                    }
                }
            })
            .collect();

        for p in scaled {
            res += &p;
        }
        res
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

        let eval = f
            .to_chunked_polynomials(2)
            .compress_polynomial(zeta_n)
            .evaluate(&zeta);

        assert!(eval == res);
    }
}
