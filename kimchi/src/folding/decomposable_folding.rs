//! This variant of folding is designed to efficiently handle cases where
//! certain assumptions about the witness can be made.
//! Specifically, an alternative is provided such that the scheme is created
//! from a set of list of constraints, each set associated with a particular selector, as opposed to a single list of constraints.

use super::FoldingScheme;
use super::{
    expressions::FoldingCompatibleExpr,
    instance_witness::{RelaxedInstance, RelaxedWitness},
};
use crate::folding::{instance_witness::RelaxablePair, FoldingConfig, ScalarField};
use ark_poly::Radix2EvaluationDomain;
use poly_commitment::PolyComm;
use std::collections::BTreeMap;
use std::marker::PhantomData;

pub struct DecomposableFoldingScheme<CF: FoldingConfig, S> {
    inner: FoldingScheme<CF>,
    todo: PhantomData<S>,
}

impl<CF: FoldingConfig, S> DecomposableFoldingScheme<CF, S> {
    pub fn new(
        //constraints with a dynamic selector
        constraints: BTreeMap<S, Vec<FoldingCompatibleExpr<CF>>>,
        //constraints to be applied to every single instance regardless of selectors
        common_constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: CF::Srs,
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        structure: CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        todo!()
    }

    #[allow(clippy::type_complexity)]
    /// folding with a selector will assume that only the selector in question is enabled (1)
    /// in all rows, and any other selector is 0 over all rows.
    /// If that is not the case, providing None will fold without assumptions
    pub fn fold_instance_witness_pair<I, W, A, B>(
        &self,
        a: A,
        b: B,
        selector: Option<S>,
    ) -> (
        RelaxedInstance<CF::Curve, CF::Instance>,
        RelaxedWitness<CF::Curve, CF::Witness>,
        [PolyComm<CF::Curve>; 2],
    )
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
    {
        todo!()
    }
}
