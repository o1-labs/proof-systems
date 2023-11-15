use crate::circuits::{domains::EvaluationDomains, expr::PolishToken};
use crate::curve::KimchiCurve;
use crate::mips::{
    columns::{Column, FixedColumns},
    prover_index::ProverIndex,
};
use poly_commitment::commitment::PolyComm;
use poly_commitment::srs::SRS;
use std::sync::Arc;

pub struct VerifierIndex<G: KimchiCurve> {
    pub srs: Arc<SRS<G>>,
    pub domain: EvaluationDomains<G::ScalarField>,
    pub constraints: Vec<PolishToken<G::ScalarField, Column>>,
    pub fixed_columns: FixedColumns<PolyComm<G>>,
}

impl<G: KimchiCurve> ProverIndex<G> {
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        VerifierIndex {
            srs: self.srs.clone(),
            domain: self.domain,
            constraints: self.constraints.to_polish(),
            fixed_columns: self.fixed_columns_commitments.clone(),
        }
    }
}
