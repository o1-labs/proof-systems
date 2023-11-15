use crate::circuits::{
    domains::EvaluationDomains,
    expr::{l0_1, ConstantExpr, Expr},
    polynomials::permutation::vanishes_on_last_row,
};
use crate::curve::KimchiCurve;
use crate::mips::{
    columns::{Column, FixedColumns},
    constraints,
    witness::{CODE_PAGE, DATA_PAGE},
};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain as D};
use poly_commitment::{commitment::PolyComm, srs::SRS};
use std::sync::Arc;

pub struct ProverIndex<G: KimchiCurve> {
    pub srs: Arc<SRS<G>>,
    pub domain: EvaluationDomains<G::ScalarField>,
    pub constraints: Expr<ConstantExpr<G::ScalarField>, Column>,
    pub fixed_columns: FixedColumns<Evaluations<G::ScalarField, D<G::ScalarField>>>,
    pub fixed_columns_commitments: FixedColumns<PolyComm<G>>,
    pub vanishes_on_last_row: Evaluations<G::ScalarField, D<G::ScalarField>>,
    pub l0_1: G::ScalarField,
}

// TODO: Don't hard code
pub const MASK_SIZE: u64 = 16;

pub fn make_sparse(x: u64) -> u64 {
    let mut res = 0;
    for i in 0..MASK_SIZE {
        let mask = 1 << i;
        let bit = x & mask;
        res += bit << i;
    }
    res
}

impl<G: KimchiCurve> ProverIndex<G> {
    pub fn create(srs: Arc<SRS<G>>, domain: EvaluationDomains<G::ScalarField>) -> Self {
        let fixed_columns = {
            let counter = {
                let evals = (0..domain.d1.size())
                    .into_iter()
                    .map(|x| G::ScalarField::from(x as u64))
                    .collect::<Vec<_>>();
                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals, domain.d1,
                )
                .interpolate()
                .evaluate_over_domain(domain.d8)
            };
            let sparse_counter = {
                assert_eq!(1 << MASK_SIZE, domain.d1.size());
                let evals = (0..domain.d1.size())
                    .into_iter()
                    .map(|x| G::ScalarField::from(make_sparse(x as u64)))
                    .collect::<Vec<_>>();
                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    evals, domain.d1,
                )
                .interpolate()
                .evaluate_over_domain(domain.d8)
            };
            FixedColumns {
                counter,
                sparse_counter,
            }
        };

        let fixed_columns_commitments = fixed_columns
            .as_ref()
            .map(|evals| srs.commit_evaluations_non_hiding(domain.d1, evals));
        let vanishes_on_last_row = vanishes_on_last_row(domain.d1).evaluate_over_domain(domain.d8);
        let l0_1 = l0_1(domain.d1);
        ProverIndex {
            srs,
            domain,
            constraints: constraints::constraints(vec![CODE_PAGE, DATA_PAGE]),
            fixed_columns,
            fixed_columns_commitments,
            vanishes_on_last_row,
            l0_1,
        }
    }
}
