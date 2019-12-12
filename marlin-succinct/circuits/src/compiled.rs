/*****************************************************************************************************************

This source file implements the compiled constraints primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use commitment::urs::URS;
use oracle::rndoracle::ProofError;
use algebra::{Field, PrimeField, PairingEngine};
use ff_fft::{DensePolynomial, Evaluations, EvaluationDomain};
pub use super::index::Index;

pub struct Compiled<E: PairingEngine>
{
    // constraint system coefficients in dense form
    pub constraints: CsMat<E::Fr>,

    // compiled polynomial commitments
    pub col_comm: E::G1Affine,
    pub row_comm: E::G1Affine,
    pub val_comm: E::G1Affine,

    // compiled polynomials and evaluations
    pub col     : DensePolynomial<E::Fr>,
    pub row     : DensePolynomial<E::Fr>,
    pub val     : DensePolynomial<E::Fr>,
    pub val_eval: Evaluations<E::Fr>,
    pub col_eval: Evaluations<E::Fr>,
    pub row_eval: Evaluations<E::Fr>,
}

impl<E: PairingEngine> Compiled<E>
{
    // this function compiles the constraints
    //  urs: univarsal reference string
    //  h_group: evaluation domain for degere h
    //  k_group: evaluation domain for degere k
    //  constraints: constraint matrix in dense form
    pub fn compile
    (
        urs: &URS<E>,
        h_group: EvaluationDomain<E::Fr>,
        k_group: EvaluationDomain<E::Fr>,
        constraints: CsMat<E::Fr>,
    ) -> Result<Self, ProofError>
    {
        let shape = constraints.shape();

        let mut col_eval = vec![E::Fr::zero(); k_group.size as usize];
        let mut row_eval = vec![E::Fr::zero(); k_group.size as usize];
        let mut val_eval = vec![E::Fr::zero(); k_group.size as usize];

        for (c, (val, (row, col))) in
        constraints.iter().zip(
            val_eval.iter_mut().zip(
                row_eval.iter_mut().zip(
                    col_eval.iter_mut())))
        {
            *col = h_group.group_gen.pow([(c.1).1 as u64]);
            *row = h_group.group_gen.pow([(c.1).0 as u64]);
            *val = *c.0 / &((*row * col).pow(&[(shape.0 - 1) as u64]) *
                &E::Fr::from_repr(<<E as PairingEngine>::Fr as PrimeField>::BigInt::from(shape.0.pow(2) as u64)));
        }

        let row_eval = Evaluations::<E::Fr>::from_vec_and_domain(row_eval, k_group);
        let col_eval = Evaluations::<E::Fr>::from_vec_and_domain(col_eval, k_group);
        let val_eval = Evaluations::<E::Fr>::from_vec_and_domain(val_eval, k_group);
        
        // interpolate the evaluations
        let row = row_eval.clone().interpolate();
        let col = col_eval.clone().interpolate();
        let val = val_eval.clone().interpolate();

        // commit to the index polynomials
        Ok(Compiled::<E>
        {
            constraints: constraints,
            row_comm: urs.commit(&row, row.coeffs.len())?,
            col_comm: urs.commit(&col, col.coeffs.len())?,
            val_comm: urs.commit(&val, val.coeffs.len())?,
            col_eval: col_eval,
            row_eval: row_eval,
            val_eval: val_eval,
            row : row,
            col : col,
            val : val,
        })
    }

    // this function computes (row(X)-oracle1)*(col(X)-oracle2)
    // polynomial for this compilation of constraints
    pub fn compute_fraction
    (
        &self,
        oracle1: E::Fr,
        oracle2: E::Fr,
    ) -> DensePolynomial<E::Fr>
    {
        let mut x = self.row.clone();
        x.coeffs[0] -= &oracle2;
        let mut y = self.col.clone();
        y.coeffs[0] -= &oracle1;
        &x * &y
    }
}
