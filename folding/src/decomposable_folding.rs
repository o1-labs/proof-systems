//! This variant of folding is designed to efficiently handle cases where
//! certain assumptions about the witness can be made.
//! Specifically, an alternative is provided such that the scheme is created
//! from a set of list of constraints, each set associated with a particular selector, as opposed to a single list of constraints.

use crate::{
    error_term::{compute_error, ExtendedEnv},
    expressions::{
        ExtendedFoldingColumn, FoldingCompatibleExpr, FoldingCompatibleExprInner, FoldingExp,
    },
    instance_witness::{RelaxablePair, RelaxedInstance, RelaxedWitness},
    FoldingConfig, FoldingScheme, ScalarField, Sponge,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi::circuits::expr::Op2;
use poly_commitment::{PolyComm, SRS};
use std::collections::BTreeMap;

pub struct DecomposableFoldingScheme<CF: FoldingConfig> {
    inner: FoldingScheme<CF>,
}

impl<CF: FoldingConfig> DecomposableFoldingScheme<CF> {
    pub fn new(
        //constraints with a dynamic selector
        constraints: BTreeMap<CF::S, Vec<FoldingCompatibleExpr<CF>>>,
        //constraints to be applied to every single instance regardless of selectors
        common_constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: CF::Srs,
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        structure: CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        let constraints = constraints
            .into_iter()
            .flat_map(|(s, exps)| {
                exps.into_iter().map(move |exp| {
                    let s = FoldingCompatibleExprInner::Extensions(super::ExpExtension::Selector(
                        s.clone(),
                    ));
                    let s = Box::new(FoldingCompatibleExpr::Atom(s));
                    FoldingCompatibleExpr::BinOp(Op2::Mul, s, Box::new(exp))
                })
            })
            .chain(common_constraints)
            .collect();
        let (inner, exp) = FoldingScheme::new(constraints, srs, domain, structure);
        (DecomposableFoldingScheme { inner }, exp)
    }

    #[allow(clippy::type_complexity)]
    /// folding with a selector will assume that only the selector in question is enabled (1)
    /// in all rows, and any other selector is 0 over all rows.
    /// If that is not the case, providing None will fold without assumptions
    pub fn fold_instance_witness_pair<I, W, A, B>(
        &self,
        a: A,
        b: B,
        selector: Option<CF::S>,
    ) -> (
        RelaxedInstance<CF::Curve, CF::Instance>,
        RelaxedWitness<CF::Curve, CF::Witness>,
        [PolyComm<CF::Curve>; 2],
    )
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
    {
        let scheme = &self.inner;
        let a = a.relax(&scheme.zero_vec, scheme.zero_commitment.clone());
        let b = b.relax(&scheme.zero_vec, scheme.zero_commitment.clone());

        let u = (a.0.u, b.0.u);

        let (ins1, wit1) = a;
        let (ins2, wit2) = b;
        let env = ExtendedEnv::new(
            &scheme.structure,
            [ins1, ins2],
            [wit1, wit2],
            scheme.domain,
            selector,
        );
        let env = env.compute_extension(&scheme.extended_witness_generator, &scheme.srs);
        let error = compute_error(&scheme.expression, &env, u);
        let error_evals = error.map(|e| Evaluations::from_vec_and_domain(e, scheme.domain));

        //can use array::each_ref() when stable
        let error_commitments = [&error_evals[0], &error_evals[1]]
            .map(|e| scheme.srs.commit_evaluations_non_hiding(scheme.domain, e));

        let error = error_evals.map(|e| e.evals);
        let challenge = <CF::Sponge>::challenge(&error_commitments);
        let ([ins1, ins2], [wit1, wit2]) = env.unwrap();
        let instance =
            RelaxedInstance::combine_and_sub_error(ins1, ins2, challenge, &error_commitments);
        let witness = RelaxedWitness::combine_and_sub_error(wit1, wit2, challenge, error);
        (instance, witness, error_commitments)
    }
}

pub(crate) fn check_selector<C: FoldingConfig>(exp: &FoldingExp<C>) -> Option<&C::S> {
    match exp {
        FoldingExp::Atom(ExtendedFoldingColumn::Selector(s)) => Some(s),
        _ => None,
    }
}
