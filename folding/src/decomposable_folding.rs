//! This variant of folding is designed to efficiently handle cases where
//! certain assumptions about the witness can be made.
//! Specifically, an alternative is provided such that the scheme is created
//! from a set of list of constraints, each set associated with a particular selector, as opposed to a single list of constraints.

use crate::{
    columns::ExtendedFoldingColumn,
    error_term::{compute_error, ExtendedEnv},
    expressions::{ExpExtension, FoldingCompatibleExpr, FoldingCompatibleExprInner, FoldingExp},
    instance_witness::{RelaxablePair, RelaxedInstance, RelaxedWitness},
    BaseField, FoldingConfig, FoldingScheme, ScalarField,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use mina_poseidon::FqSponge;
use poly_commitment::{PolyComm, SRS};
use std::collections::BTreeMap;

pub struct DecomposableFoldingScheme<'a, CF: FoldingConfig> {
    inner: FoldingScheme<'a, CF>,
}

impl<'a, CF: FoldingConfig> DecomposableFoldingScheme<'a, CF> {
    pub fn new(
        // constraints with a dynamic selector
        constraints: BTreeMap<CF::Selector, Vec<FoldingCompatibleExpr<CF>>>,
        // constraints to be applied to every single instance regardless of selectors
        common_constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: &'a CF::Srs,
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        structure: &CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        let constraints = constraints
            .into_iter()
            .flat_map(|(s, exps)| {
                exps.into_iter().map(move |exp| {
                    let s = FoldingCompatibleExprInner::Extensions(ExpExtension::Selector(s));
                    let s = Box::new(FoldingCompatibleExpr::Atom(s));
                    FoldingCompatibleExpr::Mul(s, Box::new(exp))
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
    pub fn fold_instance_witness_pair<A, B, Sponge>(
        &self,
        a: A,
        b: B,
        selector: Option<CF::Selector>,
        fq_sponge: &mut Sponge,
    ) -> (
        RelaxedInstance<CF::Curve, CF::Instance>,
        RelaxedWitness<CF::Curve, CF::Witness>,
        [PolyComm<CF::Curve>; 2],
    )
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        Sponge: FqSponge<BaseField<CF>, CF::Curve, ScalarField<CF>>,
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
        let env = env.compute_extension(&scheme.extended_witness_generator, scheme.srs);
        let error = compute_error(&scheme.expression, &env, u);
        let error_evals = error.map(|e| Evaluations::from_vec_and_domain(e, scheme.domain));

        let error_commitments = error_evals
            .iter()
            .map(|e| scheme.srs.commit_evaluations_non_hiding(scheme.domain, e))
            .collect::<Vec<_>>();
        let error_commitments: [PolyComm<CF::Curve>; 2] = error_commitments.try_into().unwrap();

        let error = error_evals.into_iter().map(|e| e.evals).collect::<Vec<_>>();
        let error: [Vec<_>; 2] = error.try_into().unwrap();

        // sanity check to verify that we only have one commitment in polycomm
        // (i.e. domain = poly size)
        assert_eq!(error_commitments[0].elems.len(), 1);
        assert_eq!(error_commitments[1].elems.len(), 1);

        fq_sponge.absorb_g(&error_commitments[0].elems);
        fq_sponge.absorb_g(&error_commitments[1].elems);

        let to_absorb = env.to_absorb();
        fq_sponge.absorb_fr(&to_absorb.0);
        fq_sponge.absorb_fq(&to_absorb.1);

        let challenge = fq_sponge.challenge();

        let ([ins1, ins2], [wit1, wit2]) = env.unwrap();
        let instance =
            RelaxedInstance::combine_and_sub_error(ins1, ins2, challenge, &error_commitments);
        let witness = RelaxedWitness::combine_and_sub_error(wit1, wit2, challenge, error);
        (instance, witness, error_commitments)
    }
}

pub(crate) fn check_selector<C: FoldingConfig>(exp: &FoldingExp<C>) -> Option<&C::Selector> {
    match exp {
        FoldingExp::Atom(ExtendedFoldingColumn::Selector(s)) => Some(s),
        _ => None,
    }
}
