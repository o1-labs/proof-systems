//! This library implements basic components to fold computations expressed as
//! multivariate polynomials of any degree. It is based on the "folding scheme"
//! described in the [Nova](https://eprint.iacr.org/2021/370.pdf) paper.
//! It implements different components to achieve it:
//! - [quadraticization]: a submodule to reduce multivariate polynomials
//!   to degree `2`.
//! - [decomposable_folding]: a submodule to "parallelize" folded
//!   computations.
//!
//! Examples can be found in the directory `examples`.
//!
//! The folding library is meant to be used in harmony with the library `ivc`.
//! To use the library, the user has to define first a "folding configuration"
//! described in the trait [FoldingConfig].
//! After that, the user can provide folding compatible expressions and build a
//! folding scheme [FoldingScheme]. The process is described in the module
//! [expressions].
// TODO: the documentation above might need more descriptions.

use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use core::{fmt::Debug, hash::Hash, iter::successors};
use error_term::{compute_error, ExtendedEnv};
use expressions::{folding_expression, FoldingColumnTrait, IntegratedFoldingExpr};
use instance_witness::{Foldable, RelaxableInstance, RelaxablePair};
use kimchi::circuits::gate::CurrOrNext;
use mina_poseidon::FqSponge;
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS};
use quadraticization::ExtendedWitnessGenerator;
use std::{
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

// Make available outside the crate to avoid code duplication
pub use error_term::Side;
pub use expressions::{ExpExtension, FoldingCompatibleExpr};
pub use instance_witness::{Instance, RelaxedInstance, RelaxedWitness, Witness};

pub mod columns;
pub mod decomposable_folding;

mod error_term;

pub mod eval_leaf;
pub mod expressions;
pub mod instance_witness;
pub mod quadraticization;
pub mod standard_config;

/// Define the different structures required for the examples (both internal and
/// external)
pub mod checker;

// Simple type alias as ScalarField/BaseField is often used. Reduce type
// complexity for clippy.
// Should be moved into FoldingConfig, but associated type defaults are unstable
// at the moment.
type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineRepr>::ScalarField;
type BaseField<C> = <<C as FoldingConfig>::Curve as AffineRepr>::BaseField;

// 'static seems to be used for expressions. Can we get rid of it?
pub trait FoldingConfig: Debug + 'static {
    type Column: FoldingColumnTrait + Debug + Eq + Hash;

    // in case of using docomposable folding, if not it can be just ()
    type Selector: Clone + Debug + Eq + Hash + Copy + Ord + PartialOrd;

    /// The type of an abstract challenge that can be found in the expressions
    /// provided as constraints.
    type Challenge: Clone + Copy + Debug + Eq + Hash;

    /// The target curve used by the polynomial commitment
    type Curve: CommitmentCurve;

    /// The SRS used by the polynomial commitment. The SRS is used to commit to
    /// the additional columns that are added by the quadraticization.
    type Srs: SRS<Self::Curve>;

    /// For Plonk, it will be the commitments to the polynomials and the challenges
    type Instance: Instance<Self::Curve> + Clone;

    /// For PlonK, it will be the polynomials in evaluation form that we commit
    /// to, i.e. the columns.
    /// In the generic prover/verifier, it would be `kimchi_msm::witness::Witness`.
    type Witness: Witness<Self::Curve> + Clone;

    type Structure: Clone;

    type Env: FoldingEnv<
        <Self::Curve as AffineRepr>::ScalarField,
        Self::Instance,
        Self::Witness,
        Self::Column,
        Self::Challenge,
        Self::Selector,
        Structure = Self::Structure,
    >;
}

/// Describe a folding environment.
/// The type parameters are:
/// - `F`: The field of the circuit/computation
/// - `I`: The instance type, i.e the public inputs
/// - `W`: The type of the witness, i.e. the private inputs
/// - `Col`: The type of the column
/// - `Chal`: The type of the challenge
/// - `Selector`: The type of the selector
pub trait FoldingEnv<F: Zero + Clone, I, W, Col, Chal, Selector> {
    /// Structure which could be storing useful information like selectors, etc.
    type Structure;

    /// Creates a new environment storing the structure, instances and
    /// witnesses.
    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self;

    /// Obtains a given challenge from the expanded instance for one side.
    /// The challenges are stored inside the instances structs.
    fn challenge(&self, challenge: Chal, side: Side) -> F;

    /// Returns the evaluations of a given column witness at omega or zeta*omega.
    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &[F];

    /// similar to [Self::col], but folding may ask for a dynamic selector directly
    /// instead of just column that happens to be a selector
    fn selector(&self, s: &Selector, side: Side) -> &[F];
}

type Evals<F> = Evaluations<F, Radix2EvaluationDomain<F>>;

pub struct FoldingScheme<'a, CF: FoldingConfig> {
    pub expression: IntegratedFoldingExpr<CF>,
    pub srs: &'a CF::Srs,
    pub domain: Radix2EvaluationDomain<ScalarField<CF>>,
    pub zero_vec: Evals<ScalarField<CF>>,
    pub structure: CF::Structure,
    pub extended_witness_generator: ExtendedWitnessGenerator<CF>,
    quadraticization_columns: usize,
}

impl<'a, CF: FoldingConfig> FoldingScheme<'a, CF> {
    pub fn new(
        constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: &'a CF::Srs,
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        structure: &CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        let (expression, extended_witness_generator, quadraticization_columns) =
            folding_expression(constraints);
        let zero = <ScalarField<CF>>::zero();
        let evals = core::iter::repeat(zero).take(domain.size()).collect();
        let zero_vec = Evaluations::from_vec_and_domain(evals, domain);
        let final_expression = expression.clone().final_expression();
        let scheme = Self {
            expression,
            srs,
            domain,
            zero_vec,
            structure: structure.clone(),
            extended_witness_generator,
            quadraticization_columns,
        };
        (scheme, final_expression)
    }

    /// Return the number of additional columns added by quadraticization
    pub fn get_number_of_additional_columns(&self) -> usize {
        self.quadraticization_columns
    }

    /// This is the main entry point to fold two instances and their witnesses.
    /// The process is as follows:
    /// - Both pairs are relaxed.
    /// - Both witnesses and instances are extended, i.e. all polynomials are
    ///   reduced to degree 2 and additional constraints are added to the
    ///   expression.
    /// - While computing the commitments to the additional columns, the
    ///   commitments are added into a list to absorb them into the sponge later.
    /// - The error terms are computed and committed.
    /// - The sponge absorbs the commitments and challenges.
    #[allow(clippy::type_complexity)]
    pub fn fold_instance_witness_pair<A, B, Sponge>(
        &self,
        a: A,
        b: B,
        fq_sponge: &mut Sponge,
    ) -> FoldingOutput<CF>
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        Sponge: FqSponge<BaseField<CF>, CF::Curve, ScalarField<CF>>,
    {
        let a = a.relax(&self.zero_vec);
        let b = b.relax(&self.zero_vec);

        let u = (a.0.u, b.0.u);

        let (left_instance, left_witness) = a;
        let (right_instance, right_witness) = b;
        let env = ExtendedEnv::new(
            &self.structure,
            [left_instance, right_instance],
            [left_witness, right_witness],
            self.domain,
            None,
        );
        // Computing the additional columns, resulting of the quadritization
        // process.
        // Side-effect: commitments are added in both relaxed (extended) instance.
        let env: ExtendedEnv<CF> =
            env.compute_extension(&self.extended_witness_generator, self.srs);

        // Computing the error terms
        let error: [Vec<ScalarField<CF>>; 2] = compute_error(&self.expression, &env, u);
        let error_evals = error.map(|e| Evaluations::from_vec_and_domain(e, self.domain));

        // Committing to the cross terms
        // Default blinder for committing to the cross terms
        let blinders = PolyComm::new(vec![ScalarField::<CF>::one()]);
        let error_commitments = error_evals
            .iter()
            .map(|e| {
                self.srs
                    .commit_evaluations_custom(self.domain, e, &blinders)
                    .unwrap()
                    .commitment
            })
            .collect::<Vec<_>>();
        let error_commitments: [PolyComm<CF::Curve>; 2] = error_commitments.try_into().unwrap();

        let error: [Vec<_>; 2] = error_evals.map(|e| e.evals);

        // sanity check to verify that we only have one commitment in polycomm
        // (i.e. domain = poly size)
        assert_eq!(error_commitments[0].len(), 1);
        assert_eq!(error_commitments[1].len(), 1);

        let t_0 = &error_commitments[0].get_first_chunk();
        let t_1 = &error_commitments[1].get_first_chunk();

        // Absorbing the commitments into the sponge
        let to_absorb = env.to_absorb(t_0, t_1);

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

    #[allow(clippy::type_complexity)]
    /// Verifier of the folding scheme; returns a new folded instance,
    /// which can be then compared with the one claimed to be the real
    /// one.
    pub fn verify_fold<Sponge>(
        &self,
        left_instance: RelaxedInstance<CF::Curve, CF::Instance>,
        right_instance: RelaxedInstance<CF::Curve, CF::Instance>,
        t_0: PolyComm<CF::Curve>,
        t_1: PolyComm<CF::Curve>,
        fq_sponge: &mut Sponge,
    ) -> RelaxedInstance<CF::Curve, CF::Instance>
    where
        Sponge: FqSponge<BaseField<CF>, CF::Curve, ScalarField<CF>>,
    {
        let to_absorb = {
            let mut left = left_instance.to_absorb();
            let right = right_instance.to_absorb();
            left.0.extend(right.0);
            left.1.extend(right.1);
            left.1
                .extend([t_0.get_first_chunk(), t_1.get_first_chunk()]);
            left
        };

        fq_sponge.absorb_fr(&to_absorb.0);
        fq_sponge.absorb_g(&to_absorb.1);

        let challenge = fq_sponge.challenge();

        RelaxedInstance::combine_and_sub_cross_terms(
            // FIXME: remove clone
            left_instance.clone(),
            right_instance.clone(),
            challenge,
            &[t_0, t_1],
        )
    }
}

/// Output of the folding prover
pub struct FoldingOutput<C: FoldingConfig> {
    /// The folded instance, containing, in particular, the result `C_l + r C_r`
    pub folded_instance: RelaxedInstance<C::Curve, C::Instance>,
    /// Folded witness, containing, in particular, the result of the evaluations
    /// `W_l + r W_r`
    pub folded_witness: RelaxedWitness<C::Curve, C::Witness>,
    /// The error terms of degree 1, see the top-level documentation of
    /// [crate::expressions]
    pub t_0: PolyComm<C::Curve>,
    /// The error terms of degree 2, see the top-level documentation of
    /// [crate::expressions]
    pub t_1: PolyComm<C::Curve>,
    /// The left relaxed instance, including the potential additional columns
    /// added by quadritization
    pub relaxed_extended_left_instance: RelaxedInstance<C::Curve, C::Instance>,
    /// The right relaxed instance, including the potential additional columns
    /// added by quadritization
    pub relaxed_extended_right_instance: RelaxedInstance<C::Curve, C::Instance>,
    /// Elements to absorbed in IVC, in the same order as done in folding
    pub to_absorb: (Vec<ScalarField<C>>, Vec<C::Curve>),
}

impl<C: FoldingConfig> FoldingOutput<C> {
    #[allow(clippy::type_complexity)]
    pub fn pair(
        self,
    ) -> (
        RelaxedInstance<C::Curve, C::Instance>,
        RelaxedWitness<C::Curve, C::Witness>,
    ) {
        (self.folded_instance, self.folded_witness)
    }
}

/// Combinators that will be used to fold the constraints,
/// called the "alphas".
/// The alphas are exceptional, their number cannot be known ahead of time as it
/// will be defined by folding.
/// The values will be computed as powers in new instances, but after folding
/// each alpha will be a linear combination of other alphas, instand of a power
/// of other element. This type represents that, allowing to also recognize
/// which case is present.
#[derive(Debug, Clone)]
pub enum Alphas<F: Field> {
    Powers(F, Rc<AtomicUsize>),
    Combinations(Vec<F>),
}

impl<F: Field> PartialEq for Alphas<F> {
    fn eq(&self, other: &Self) -> bool {
        // Maybe there's a more efficient way
        self.clone().powers() == other.clone().powers()
    }
}

impl<F: Field> Eq for Alphas<F> {}

impl<F: Field> Foldable<F> for Alphas<F> {
    fn combine(a: Self, b: Self, challenge: F) -> Self {
        let a = a.powers();
        let b = b.powers();
        assert_eq!(a.len(), b.len());
        let comb = a
            .into_iter()
            .zip(b)
            .map(|(a, b)| a + b * challenge)
            .collect();
        Self::Combinations(comb)
    }
}

impl<F: Field> Alphas<F> {
    pub fn new(alpha: F) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(0)))
    }

    pub fn new_sized(alpha: F, count: usize) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(count)))
    }

    pub fn get(&self, i: usize) -> Option<F> {
        match self {
            Alphas::Powers(alpha, count) => {
                let _ = count.fetch_max(i + 1, Ordering::Relaxed);
                let i = [i as u64];
                Some(alpha.pow(i))
            }
            Alphas::Combinations(alphas) => alphas.get(i).cloned(),
        }
    }

    pub fn powers(self) -> Vec<F> {
        match self {
            Alphas::Powers(alpha, count) => {
                let n = count.load(Ordering::Relaxed);
                let alphas = successors(Some(F::one()), |last| Some(*last * alpha));
                alphas.take(n).collect()
            }
            Alphas::Combinations(c) => c,
        }
    }
}
