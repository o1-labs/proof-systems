/*****************************************************************************************************************

This source file implements the compiled constraints primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use commitment_pairing::urs::URS;
use oracle::rndoracle::ProofError;
use algebra::{Field, PairingEngine, Zero};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D, EvaluationDomain, GeneralEvaluationDomain};
pub use super::index::Index;

pub struct Compiled<E: PairingEngine>
{
    // constraint system coefficients in dense form
    pub constraints: CsMat<E::Fr>,

    // compiled polynomial commitments
    pub col_comm: E::G1Affine,
    pub row_comm: E::G1Affine,
    pub val_comm: E::G1Affine,
    pub rc_comm: E::G1Affine,

    // compiled polynomials and evaluations
    pub rc      : DensePolynomial<E::Fr>,
    pub row     : DensePolynomial<E::Fr>,
    pub col     : DensePolynomial<E::Fr>,
    pub val     : DensePolynomial<E::Fr>,
    pub row_eval_k: Evaluations<E::Fr>,
    pub col_eval_k: Evaluations<E::Fr>,
    pub val_eval_k: Evaluations<E::Fr>,
    pub row_eval_b: Evaluations<E::Fr>,
    pub col_eval_b: Evaluations<E::Fr>,
    pub val_eval_b: Evaluations<E::Fr>,
    pub rc_eval_b : Evaluations<E::Fr>,
}

impl<E: PairingEngine> Compiled<E>
{
    // this function compiles the constraints
    //  urs: universal reference string
    //  h_group: evaluation domain for degere h (constrtraint matrix linear size)
    //  k_group: evaluation domain for degere k (constrtraint matrix number of non-zero elements)
    //  b_group: evaluation domain for degere b (h_group*6-6)
    //  constraints: constraint matrix in dense form
    pub fn compile
    (
        urs: &URS<E>,
        h_group: D<E::Fr>,
        k_group: D<E::Fr>,
        b_group: D<E::Fr>,
        constraints: CsMat<E::Fr>,
    ) -> Result<Self, ProofError>
    {
        let mut col_eval_k = vec![E::Fr::zero(); k_group.size as usize];
        let mut row_eval_k = vec![E::Fr::zero(); k_group.size as usize];
        let mut val_eval_k = vec![E::Fr::zero(); k_group.size as usize];

        let h_elems: Vec<E::Fr> = h_group.elements().map(|elm| {elm}).collect();

        for (c, (val, (row, col))) in
        constraints.iter().zip(
            val_eval_k.iter_mut().zip(
                row_eval_k.iter_mut().zip(
                    col_eval_k.iter_mut())))
        {
            *row = h_elems[(c.1).0];
            *col = h_elems[(c.1).1];
            *val = h_group.size_as_field_element.square() *
                // Lagrange polynomial evaluation trick
                &h_elems[if (c.1).0 == 0 {0} else {h_group.size() - (c.1).0}] *
                &h_elems[if (c.1).1 == 0 {0} else {h_group.size() - (c.1).1}];
        }
        algebra::fields::batch_inversion::<E::Fr>(&mut val_eval_k);
        for (c, val) in constraints.iter().zip(val_eval_k.iter_mut())
        {
            *val = *c.0 * val;
        }

        let k_group = GeneralEvaluationDomain::Radix2(k_group);
        let b_group = GeneralEvaluationDomain::Radix2(b_group);

        let row_eval_k = Evaluations::<E::Fr>::from_vec_and_domain(row_eval_k, k_group);
        let col_eval_k = Evaluations::<E::Fr>::from_vec_and_domain(col_eval_k, k_group);
        let val_eval_k = Evaluations::<E::Fr>::from_vec_and_domain(val_eval_k, k_group);
        
        // interpolate the evaluations
        let row = row_eval_k.clone().interpolate();
        let col = col_eval_k.clone().interpolate();
        let val = val_eval_k.clone().interpolate();
        let rc = (&row_eval_k * &col_eval_k).interpolate();

        // commit to the index polynomials
        Ok(Compiled::<E>
        {
            constraints,
            rc_comm: urs.commit(&rc)?,
            row_comm: urs.commit(&row)?,
            col_comm: urs.commit(&col)?,
            val_comm: urs.commit(&val)?,
            row_eval_b: Evaluations::<E::Fr>::from_vec_and_domain(b_group.fft(&row), b_group),
            col_eval_b: Evaluations::<E::Fr>::from_vec_and_domain(b_group.fft(&col), b_group),
            val_eval_b: Evaluations::<E::Fr>::from_vec_and_domain(b_group.fft(&val), b_group),
            rc_eval_b: Evaluations::<E::Fr>::from_vec_and_domain(b_group.fft(&rc), b_group),
            row_eval_k,
            col_eval_k,
            val_eval_k,
            row,
            col,
            val,
            rc
        })
    }

    // this function computes (row(X)-oracle1)*(col(X)-oracle2)
    // evaluations over b_group for this compilation of constraints
    pub fn compute_row_2_col_1
    (
        &self,
        oracle1: E::Fr,
        oracle2: E::Fr,
    ) -> Vec<E::Fr>
    {
        self.row_eval_b.evals.iter().
            zip(self.col_eval_b.evals.iter()).
            zip(self.rc_eval_b.evals.iter()).
            map
        (
            |((row, col), rc)|
            {
                oracle2 * &oracle1 - &(oracle1 * &row) - &(oracle2 * &col) + &rc
            }
        ).collect()
    }
}