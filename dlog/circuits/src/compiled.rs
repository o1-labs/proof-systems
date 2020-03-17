/*****************************************************************************************************************

This source file implements the compiled constraints primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use commitment_dlog::commitment::CommitmentCurve;
use commitment_dlog::srs::SRS;
use oracle::rndoracle::ProofError;
use algebra::{Field, AffineCurve};
use ff_fft::{DensePolynomial, Evaluations, EvaluationDomain};
pub use super::index::Index;

type Fr<G> = <G as AffineCurve>::ScalarField;

pub struct Compiled<G: CommitmentCurve>
{
    // constraint system coefficients in dense form
    pub constraints: CsMat<Fr<G>>,

    // compiled polynomial commitments
    pub col_comm: G,
    pub row_comm: G,
    pub val_comm: G,
    pub rc_comm: G,

    // compiled polynomials and evaluations
    pub rc      : DensePolynomial<Fr<G>>,
    pub row     : DensePolynomial<Fr<G>>,
    pub col     : DensePolynomial<Fr<G>>,
    pub val     : DensePolynomial<Fr<G>>,
    pub row_eval_k: Evaluations<Fr<G>>,
    pub col_eval_k: Evaluations<Fr<G>>,
    pub val_eval_k: Evaluations<Fr<G>>,
    pub row_eval_b: Evaluations<Fr<G>>,
    pub col_eval_b: Evaluations<Fr<G>>,
    pub val_eval_b: Evaluations<Fr<G>>,
    pub rc_eval_b : Evaluations<Fr<G>>,
}

impl<G: CommitmentCurve> Compiled<G>
{
    // this function compiles the constraints
    //  srs: universal reference string
    //  h_group: evaluation domain for degere h (constrtraint matrix linear size)
    //  k_group: evaluation domain for degere k (constrtraint matrix number of non-zero elements)
    //  b_group: evaluation domain for degere b (h_group*6-6)
    //  constraints: constraint matrix in dense form
    pub fn compile
    (
        srs: &SRS<G>,
        h_group: EvaluationDomain<Fr<G>>,
        k_group: EvaluationDomain<Fr<G>>,
        b_group: EvaluationDomain<Fr<G>>,
        constraints: CsMat<Fr<G>>,
    ) -> Result<Self, ProofError>
    {
        let mut col_eval_k = vec![Fr::<G>::zero(); k_group.size as usize];
        let mut row_eval_k = vec![Fr::<G>::zero(); k_group.size as usize];
        let mut val_eval_k = vec![Fr::<G>::zero(); k_group.size as usize];

        let h_elems: Vec<Fr<G>> = h_group.elements().map(|elm| {elm}).collect();

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
        algebra::fields::batch_inversion::<Fr<G>>(&mut val_eval_k);
        for (c, val) in constraints.iter().zip(val_eval_k.iter_mut())
        {
            *val = *c.0 * val;
        }

        let row_eval_k = Evaluations::<Fr<G>>::from_vec_and_domain(row_eval_k, k_group);
        let col_eval_k = Evaluations::<Fr<G>>::from_vec_and_domain(col_eval_k, k_group);
        let val_eval_k = Evaluations::<Fr<G>>::from_vec_and_domain(val_eval_k, k_group);
        
        // interpolate the evaluations
        let row = row_eval_k.clone().interpolate();
        let col = col_eval_k.clone().interpolate();
        let val = val_eval_k.clone().interpolate();
        let rc = (&row_eval_k * &col_eval_k).interpolate();

        // commit to the index polynomials
        Ok(Compiled::<G>
        {
            constraints,
            rc_comm: srs.commit_no_degree_bound(&rc)?,
            row_comm: srs.commit_no_degree_bound(&row)?,
            col_comm: srs.commit_no_degree_bound(&col)?,
            val_comm: srs.commit_no_degree_bound(&val)?,
            row_eval_b: Evaluations::<Fr<G>>::from_vec_and_domain(b_group.fft(&row), b_group),
            col_eval_b: Evaluations::<Fr<G>>::from_vec_and_domain(b_group.fft(&col), b_group),
            val_eval_b: Evaluations::<Fr<G>>::from_vec_and_domain(b_group.fft(&val), b_group),
            rc_eval_b: Evaluations::<Fr<G>>::from_vec_and_domain(b_group.fft(&rc), b_group),
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
        oracle1: Fr<G>,
        oracle2: Fr<G>,
    ) -> Vec<Fr<G>>
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
