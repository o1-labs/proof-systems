use crate::{
    commitment::{b_poly_coefficients, CommitmentCurve},
    ipa::SRS,
    PolynomialsToCombine,
};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{batch_inversion, FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations};
use o1_utils::ExtendedDensePolynomial;
use rayon::prelude::*;

/// Represent a polynomial either with its coefficients or its evaluations
pub enum DensePolynomialOrEvaluations<'a, F: FftField, D: EvaluationDomain<F>> {
    /// Polynomial represented by its coefficients
    DensePolynomial(&'a DensePolynomial<F>),
    /// Polynomial represented by its evaluations over a domain D
    Evaluations(&'a Evaluations<F, D>, D),
}

/// A formal sum of the form
/// `s_0 * p_0 + ... s_n * p_n`
/// where each `s_i` is a scalar and each `p_i` is a polynomial.
/// The parameter `P` is expected to be the coefficients of the polynomial
/// `p_i`, even though we could treat it as the evaluations.
///
/// This hypothesis is important if `to_dense_polynomial` is called.
#[derive(Default)]
struct ScaledChunkedPolynomial<F, P>(Vec<(F, P)>);

impl<F, P> ScaledChunkedPolynomial<F, P> {
    fn add_poly(&mut self, scale: F, p: P) {
        self.0.push((scale, p))
    }
}

impl<'a, F: Field> ScaledChunkedPolynomial<F, &'a [F]> {
    /// Compute the resulting scaled polynomial.
    /// Example:
    /// Given the two polynomials `1 + 2X` and `3 + 4X`, and the scaling
    /// factors `2` and `3`, the result is the polynomial `11 + 16X`.
    /// ```text
    /// 2 * [1, 2] + 3 * [3, 4] = [2, 4] + [9, 12] = [11, 16]
    /// ```
    fn to_dense_polynomial(&self) -> DensePolynomial<F> {
        // Note: using a reference to avoid reallocation of the result.
        let mut res = DensePolynomial::<F>::zero();

        let scaled: Vec<_> = self
            .0
            .par_iter()
            .map(|(scale, segment)| {
                let scale = *scale;
                // We simply scale each coefficients.
                // It is simply because DensePolynomial doesn't have a method
                // `scale`.
                let v = segment.par_iter().map(|x| scale * *x).collect();
                DensePolynomial::from_coefficients_vec(v)
            })
            .collect();

        for p in scaled {
            res += &p;
        }

        res
    }
}

/// Combine the polynomials using a scalar (`polyscale`), creating a single
/// unified polynomial to open. This function also accepts polynomials in
/// evaluations form. In this case it applies an IFFT, and, if necessary,
/// applies chunking to it (ie. split it in multiple polynomials of
/// degree less than the SRS size).
///
/// Parameters:
/// - `plnms`: vector of polynomials, either in evaluations or coefficients form, together with
///    a set of scalars representing their blinders.
/// - `polyscale`: scalar to combine the polynomials, which will be scaled based on the number of
///    polynomials to combine.
///
/// Output:
/// - `combined_poly`: combined polynomial. The order of the output follows the order of `plnms`.
/// - `combined_comm`: combined scalars representing the blinder commitment.
///
/// Example:
/// Given the three polynomials `p1(X)`, and `p3(X)` in coefficients
/// forms, p2(X) in evaluation form,
/// and the scaling factor `polyscale`, the result will be the polynomial:
///
/// ```text
/// p1(X) + polyscale * i_fft(chunks(p2))(X) + polyscale^2 p3(X)
/// ```
///
/// Additional complexity is added to handle chunks.
pub fn combine_polys<G: CommitmentCurve, D: EvaluationDomain<G::ScalarField>>(
    plnms: PolynomialsToCombine<G, D>,
    polyscale: G::ScalarField,
    srs_length: usize,
) -> (DensePolynomial<G::ScalarField>, G::ScalarField) {
    // Initialising the output for the combined coefficients forms
    let mut plnm_coefficients =
        ScaledChunkedPolynomial::<G::ScalarField, &[G::ScalarField]>::default();
    // Initialising the output for the combined evaluations forms
    let mut plnm_evals_part = {
        // For now just check that all the evaluation polynomials are the same
        // degree so that we can do just a single FFT.
        // If/when we change this, we can add more complicated code to handle
        // different degrees.
        let degree = plnms
            .iter()
            .fold(None, |acc, (p, _)| match p {
                DensePolynomialOrEvaluations::DensePolynomial(_) => acc,
                DensePolynomialOrEvaluations::Evaluations(_, d) => {
                    if let Some(n) = acc {
                        assert_eq!(n, d.size());
                    }
                    Some(d.size())
                }
            })
            .unwrap_or(0);
        vec![G::ScalarField::zero(); degree]
    };

    // Will contain ∑ comm_chunk * polyscale^i
    let mut combined_comm = G::ScalarField::zero();

    // Will contain polyscale^i
    let mut polyscale_to_i = G::ScalarField::one();

    // Iterating over polynomials in the batch.
    // Note that the chunks in the commitment `p_i_comm` are given as `PolyComm<G::ScalarField>`. They are
    // evaluations.
    // We do modify two different structures depending on the form of the
    // polynomial we are currently processing: `plnm` and `plnm_evals_part`.
    // We do need to treat both forms separately.
    for (p_i, p_i_comm) in plnms {
        match p_i {
            // Here we scale the polynomial in evaluations forms
            // Note that based on the check above, sub_domain.size() always give
            // the same value
            DensePolynomialOrEvaluations::Evaluations(evals_i, sub_domain) => {
                let stride = evals_i.evals.len() / sub_domain.size();
                let evals = &evals_i.evals;
                plnm_evals_part
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, x)| {
                        *x += polyscale_to_i * evals[i * stride];
                    });
                for comm_chunk in p_i_comm.into_iter() {
                    combined_comm += &(*comm_chunk * polyscale_to_i);
                    polyscale_to_i *= &polyscale;
                }
            }

            // Here we scale the polynomial in coefficient forms
            DensePolynomialOrEvaluations::DensePolynomial(p_i) => {
                let mut offset = 0;
                // iterating over chunks of the polynomial
                for comm_chunk in p_i_comm.into_iter() {
                    let segment = &p_i.coeffs[std::cmp::min(offset, p_i.coeffs.len())
                        ..std::cmp::min(offset + srs_length, p_i.coeffs.len())];
                    plnm_coefficients.add_poly(polyscale_to_i, segment);

                    combined_comm += &(*comm_chunk * polyscale_to_i);
                    polyscale_to_i *= &polyscale;
                    offset += srs_length;
                }
            }
        }
    }

    // Now, we will combine both evaluations and coefficients forms

    // plnm will be our final combined polynomial. We first treat the
    // polynomials in coefficients forms, which is simply scaling the
    // coefficients and add them.
    let mut combined_plnm = plnm_coefficients.to_dense_polynomial();

    if !plnm_evals_part.is_empty() {
        // n is the number of evaluations, which is a multiple of the
        // domain size.
        // We treat now each chunk.
        let n = plnm_evals_part.len();
        let max_poly_size = srs_length;
        // equiv to divceil, but unstable in rust < 1.73.
        let num_chunks = n / max_poly_size + if n % max_poly_size == 0 { 0 } else { 1 };
        // Interpolation on the whole domain, i.e. it can be d2, d4, etc.
        combined_plnm += &Evaluations::from_vec_and_domain(plnm_evals_part, D::new(n).unwrap())
            .interpolate()
            .to_chunked_polynomial(num_chunks, max_poly_size)
            .linearize(polyscale);
    }

    (combined_plnm, combined_comm)
}

// TODO: Not compatible with variable rounds
pub fn batch_dlog_accumulator_check<G: CommitmentCurve>(
    urs: &SRS<G>,
    comms: &[G],
    chals: &[G::ScalarField],
) -> bool {
    let k = comms.len();

    if k == 0 {
        assert_eq!(chals.len(), 0);
        return true;
    }

    let rounds = chals.len() / k;
    assert_eq!(chals.len() % rounds, 0);

    let rs = {
        let r = G::ScalarField::rand(&mut rand::rngs::OsRng);
        let mut rs = vec![G::ScalarField::one(); k];
        for i in 1..k {
            rs[i] = r * rs[i - 1];
        }
        rs
    };

    let mut points = urs.g.clone();
    let n = points.len();
    points.extend(comms);

    let mut scalars = vec![G::ScalarField::zero(); n];
    scalars.extend(&rs[..]);

    let chal_invs = {
        let mut cs = chals.to_vec();
        batch_inversion(&mut cs);
        cs
    };

    let termss: Vec<_> = chals
        .par_iter()
        .zip(chal_invs)
        .chunks(rounds)
        .zip(rs)
        .map(|(chunk, r)| {
            let chals: Vec<_> = chunk.iter().map(|(c, _)| **c).collect();
            let mut s = b_poly_coefficients(&chals);
            s.iter_mut().for_each(|c| *c *= &r);
            s
        })
        .collect();

    for terms in termss {
        assert_eq!(terms.len(), n);
        for i in 0..n {
            scalars[i] -= &terms[i];
        }
    }

    let scalars: Vec<_> = scalars.iter().map(|x| x.into_bigint()).collect();
    G::Group::msm_bigint(&points, &scalars) == G::Group::zero()
}

pub fn batch_dlog_accumulator_generate<G: CommitmentCurve>(
    urs: &SRS<G>,
    num_comms: usize,
    chals: &Vec<G::ScalarField>,
) -> Vec<G> {
    let k = num_comms;

    if k == 0 {
        assert_eq!(chals.len(), 0);
        return vec![];
    }

    let rounds = chals.len() / k;
    assert_eq!(chals.len() % rounds, 0);

    let comms: Vec<_> = chals
        .into_par_iter()
        .chunks(rounds)
        .map(|chals| {
            let chals: Vec<G::ScalarField> = chals.into_iter().copied().collect();
            let scalars: Vec<_> = b_poly_coefficients(&chals)
                .into_iter()
                .map(|x| x.into_bigint())
                .collect();
            let points: Vec<_> = urs.g.clone();
            G::Group::msm_bigint(&points, &scalars).into_affine()
        })
        .collect();

    comms
}
