//! This variant of folding is designed to efficiently handle cases where
//! certain assumptions about the witness can be made.
//! Specifically, an alternative is provided such that the scheme is created
//! from a set of list of constraints, each set associated with a particular
//! selector, as opposed to a single list of constraints.

use crate::{
    columns::ExtendedFoldingColumn,
    error_term::{compute_error, ExtendedEnv},
    expressions::{ExpExtension, FoldingCompatibleExpr, FoldingCompatibleExprInner, FoldingExp},
    instance_witness::{RelaxableInstance, RelaxablePair, RelaxedInstance, RelaxedWitness},
    BaseField, FoldingConfig, FoldingOutput, FoldingScheme, ScalarField,
};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use mina_poseidon::FqSponge;
use poly_commitment::{PolyComm, SRS};
use std::collections::BTreeMap;

pub struct DecomposableFoldingScheme<'a, CF: FoldingConfig> {
    inner: FoldingScheme<'a, CF>,
}

impl<'a, CF: FoldingConfig> DecomposableFoldingScheme<'a, CF> {
    /// Creates a new folding scheme for decomposable circuits.
    /// It takes as input:
    /// - a set of constraints, each associated with a particular selector;
    /// - a list of common constraints, that are applied to every instance
    ///   regardless of the selector (can be empty);
    /// - a structured reference string;
    /// - a domain;
    /// - a structure of the associated folding configuration.
    ///
    /// The function uses the normal `FoldingScheme::new()` function to create
    /// the decomposable scheme, using for that the concatenation of the
    /// constraints associated with each selector multiplied by the selector,
    /// and the common constraints.
    /// This product is performed with
    /// `FoldingCompatibleExprInner::Extensions(ExpExtension::Selector(s))`.
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

    /// Return the number of additional columns added by quadraticization
    pub fn get_number_of_additional_columns(&self) -> usize {
        self.inner.get_number_of_additional_columns()
    }

    #[allow(clippy::type_complexity)]
    /// folding with a selector will assume that only the selector in question
    /// is enabled (i.e. set to 1) in all rows, and any other selector is 0 over
    /// all rows.
    /// If that is not the case, providing `None` will fold without assumptions
    pub fn fold_instance_witness_pair<A, B, Sponge>(
        &self,
        a: A,
        b: B,
        selector: Option<CF::Selector>,
        fq_sponge: &mut Sponge,
    ) -> FoldingOutput<CF>
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        Sponge: FqSponge<BaseField<CF>, CF::Curve, ScalarField<CF>>,
    {
        let scheme = &self.inner;
        let a = a.relax(&scheme.zero_vec);
        let b = b.relax(&scheme.zero_vec);

        let u = (a.0.u, b.0.u);

        let (left_instance, left_witness) = a;
        let (right_instance, right_witness) = b;
        let env = ExtendedEnv::new(
            &scheme.structure,
            [left_instance, right_instance],
            [left_witness, right_witness],
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
        assert_eq!(error_commitments[0].len(), 1);
        assert_eq!(error_commitments[1].len(), 1);

        let t0 = &error_commitments[0].get_first_chunk();
        let t1 = &error_commitments[1].get_first_chunk();

        let to_absorb = env.to_absorb(t0, t1);
        fq_sponge.absorb_fr(&to_absorb.0);
        fq_sponge.absorb_g(&to_absorb.1);

        let challenge = fq_sponge.challenge();

        let (
            [relaxed_extended_left_instance, relaxed_extended_right_instance],
            [relaxed_extended_left_witness, relaxed_extended_right_witness],
        ) = env.unwrap();

        let folded_instance = RelaxedInstance::combine_and_sub_cross_terms(
            // FIXME: remove clone
            relaxed_extended_left_instance.clone(),
            relaxed_extended_right_instance.clone(),
            challenge,
            &error_commitments,
        );

        let folded_witness = RelaxedWitness::combine_and_sub_cross_terms(
            relaxed_extended_left_witness,
            relaxed_extended_right_witness,
            challenge,
            error,
        );
        FoldingOutput {
            folded_instance,
            folded_witness,
            t_0: error_commitments[0].clone(),
            t_1: error_commitments[1].clone(),
            relaxed_extended_left_instance,
            relaxed_extended_right_instance,
            to_absorb,
        }
    }

    /// Fold two relaxable instances into a relaxed instance.
    /// It is parametrized by two different types `A` and `B` that represent
    /// "relaxable" instances to be able to fold a normal and "already relaxed"
    /// instance.
    pub fn fold_instance_pair<A, B, Sponge>(
        &self,
        a: A,
        b: B,
        error_commitments: [PolyComm<CF::Curve>; 2],
        fq_sponge: &mut Sponge,
    ) -> RelaxedInstance<CF::Curve, CF::Instance>
    where
        A: RelaxableInstance<CF::Curve, CF::Instance>,
        B: RelaxableInstance<CF::Curve, CF::Instance>,
        Sponge: FqSponge<BaseField<CF>, CF::Curve, ScalarField<CF>>,
    {
        let a: RelaxedInstance<CF::Curve, CF::Instance> = a.relax();
        let b: RelaxedInstance<CF::Curve, CF::Instance> = b.relax();

        // sanity check to verify that we only have one commitment in polycomm
        // (i.e. domain = poly size)
        assert_eq!(error_commitments[0].len(), 1);
        assert_eq!(error_commitments[1].len(), 1);

        let to_absorb = {
            let mut left = a.to_absorb();
            let right = b.to_absorb();
            left.0.extend(right.0);
            left.1.extend(right.1);
            left.1.extend([
                error_commitments[0].get_first_chunk(),
                error_commitments[1].get_first_chunk(),
            ]);
            left
        };

        fq_sponge.absorb_fr(&to_absorb.0);
        fq_sponge.absorb_g(&to_absorb.1);

        let challenge = fq_sponge.challenge();

        RelaxedInstance::combine_and_sub_cross_terms(a, b, challenge, &error_commitments)
    }
}

pub(crate) fn check_selector<C: FoldingConfig>(exp: &FoldingExp<C>) -> Option<&C::Selector> {
    match exp {
        FoldingExp::Atom(ExtendedFoldingColumn::Selector(s)) => Some(s),
        _ => None,
    }
}
