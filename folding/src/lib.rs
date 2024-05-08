//! This library implements basic components to fold computations expressed as
//! multivariate polynomials of any degree. It is based on the "folding scheme"
//! described in the [Nova](https://eprint.iacr.org/2021/370.pdf) paper.
//! It implements different components to achieve it:
//! - [quadraticization]: a submodule to reduce multivariate polynomials
//! to degree `2`.
//! - [decomposable_folding]: a submodule to "parallelize" folded
//! computations.
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

use ark_ec::AffineCurve;
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use error_term::{compute_error, ExtendedEnv};
use expressions::{
    folding_expression, FoldingColumnTrait, FoldingCompatibleExpr, IntegratedFoldingExpr,
};
use instance_witness::{RelaxableInstance, RelaxablePair};
use kimchi::circuits::gate::CurrOrNext;
use mina_poseidon::FqSponge;
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS};
use quadraticization::ExtendedWitnessGenerator;
use std::{
    fmt::Debug,
    hash::Hash,
    iter::successors,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
};

// Make available outside the crate to avoid code duplication
pub use error_term::Side;
pub use expressions::ExpExtension;
pub use instance_witness::{Instance, RelaxedInstance, RelaxedWitness, Witness};

pub mod columns;
pub mod decomposable_folding;

mod error_term;

mod eval_leaf;
pub mod expressions;
mod instance_witness;
pub mod quadraticization;

// Modules strictly related to tests
// TODO: should we move them into an explicit subdirectory `test`?
#[cfg(test)]
#[cfg(feature = "bn254")]
mod examples;

/// Define the different structures required for the examples (both internal and
/// external)
pub mod checker;

// Simple type alias as ScalarField/BaseField is often used. Reduce type
// complexity for clippy.
// Should be moved into FoldingConfig, but associated type defaults are unstable
// at the moment.
type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;
type BaseField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::BaseField;

// 'static seems to be used for expressions. Can we get rid of it?
pub trait FoldingConfig: Clone + Debug + Eq + Hash + 'static {
    type Column: FoldingColumnTrait + Debug + Eq + Hash;

    // in case of using docomposable folding, if not it can be just ()
    type Selector: Clone + Debug + Eq + Hash + Copy;

    /// The type of an abstract challenge that can be found in the expressions
    /// provided as constraints.
    type Challenge: Clone + Copy + Debug + Eq + Hash;

    /// The target curve used by the polynomial commitment
    type Curve: CommitmentCurve;

    type Srs: SRS<Self::Curve>;

    /// For Plonk, it will be the commitments to the polynomials and the challenges
    type Instance: Instance<Self::Curve> + Clone;

    /// For PlonK, it will be the polynomials in evaluation form that we commit
    /// to, i.e. the columns.
    /// In the generic prover/verifier, it would be `kimchi_msm::witness::Witness`.
    type Witness: Witness<Self::Curve> + Clone;

    type Structure;

    type Env: FoldingEnv<
        <Self::Curve as AffineCurve>::ScalarField,
        Self::Instance,
        Self::Witness,
        Self::Column,
        Self::Challenge,
        Self::Selector,
        Structure = Self::Structure,
    >;

    /// Return the size of the circuit, i.e. the number of rows
    fn rows() -> usize;
}

/// Describe a folding environment.
/// The type parameters are:
/// - `F`: The field of the circuit/computation
/// - `I`: The instance type, i.e the public inputs
/// - `W`: The type of the witness, i.e. the private inputs
/// - `Col`: The type of the column
/// - `Chal`: The type of the challenge
/// - `Selector`: The type of the selector
pub trait FoldingEnv<F, I, W, Col, Chal, Selector> {
    /// Structure which could be storing useful information like selectors, etc.
    type Structure;

    /// Creates a new environment storing the structure, instances and witnesses.
    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self;

    // TODO: move into `FoldingConfig`
    // FIXME: when we move this to `FoldingConfig` it will be general for all impls as:
    // vec![F::zero(); Self::rows()]
    /// Returns a vector of zeros with the same length as the number of rows in
    /// the circuit.
    fn zero_vec(&self) -> Vec<F>;

    /// Returns the evaluations of a given column witness at omega or zeta*omega.
    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<F>;

    /// Obtains a given challenge from the expanded instance for one side.
    /// The challenges are stored inside the instances structs.
    fn challenge(&self, challenge: Chal, side: Side) -> F;

    /// Computes the i-th power of alpha for a given side.
    /// Folding itself will provide us with the alpha value.
    fn alpha(&self, i: usize, side: Side) -> F;

    /// similar to [Self::col], but folding may ask for a dynamic selector directly
    /// instead of just column that happens to be a selector
    fn selector(&self, s: &Selector, side: Side) -> &Vec<F>;
}

type Evals<F> = Evaluations<F, Radix2EvaluationDomain<F>>;

pub struct FoldingScheme<'a, CF: FoldingConfig> {
    pub expression: IntegratedFoldingExpr<CF>,
    pub srs: &'a CF::Srs,
    pub domain: Radix2EvaluationDomain<ScalarField<CF>>,
    pub zero_commitment: PolyComm<CF::Curve>,
    pub zero_vec: Evals<ScalarField<CF>>,
    pub structure: CF::Structure,
    pub extended_witness_generator: ExtendedWitnessGenerator<CF>,
}

impl<'a, CF: FoldingConfig> FoldingScheme<'a, CF> {
    pub fn new(
        constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: &'a CF::Srs,
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        structure: CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        let (expression, extended_witness_generator) = folding_expression(constraints);
        let zero = <ScalarField<CF>>::zero();
        let evals = std::iter::repeat(zero).take(domain.size()).collect();
        let zero_vec_evals = Evaluations::from_vec_and_domain(evals, domain);
        let zero_commitment = srs.commit_evaluations_non_hiding(domain, &zero_vec_evals);
        let zero_vec = zero_vec_evals;
        let final_expression = expression.clone().final_expression();
        let scheme = Self {
            expression,
            srs,
            domain,
            zero_commitment,
            zero_vec,
            structure,
            extended_witness_generator,
        };
        (scheme, final_expression)
    }

    #[allow(clippy::type_complexity)]
    pub fn fold_instance_witness_pair<A, B, Sponge>(
        &self,
        a: A,
        b: B,
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
        let a = a.relax(&self.zero_vec, self.zero_commitment.clone());
        let b = b.relax(&self.zero_vec, self.zero_commitment.clone());

        let u = (a.0.u, b.0.u);

        let (ins1, wit1) = a;
        let (ins2, wit2) = b;
        let env = ExtendedEnv::new(
            &self.structure,
            [ins1, ins2],
            [wit1, wit2],
            self.domain,
            None,
        );
        let env: ExtendedEnv<CF> =
            env.compute_extension(&self.extended_witness_generator, self.srs);
        let error: [Vec<ScalarField<CF>>; 2] = compute_error(&self.expression, &env, u);

        let error_evals = error.map(|e| Evaluations::from_vec_and_domain(e, self.domain));

        let error_commitments = error_evals
            .iter()
            .map(|e| self.srs.commit_evaluations_non_hiding(self.domain, e))
            .collect::<Vec<_>>();
        let error_commitments: [PolyComm<CF::Curve>; 2] = error_commitments.try_into().unwrap();

        // sanity check to verify that we only have one commitment in polycomm
        // (i.e. domain = poly size)
        assert_eq!(error_commitments[0].elems.len(), 1);
        assert_eq!(error_commitments[1].elems.len(), 1);

        fq_sponge.absorb_g(&error_commitments[0].elems);
        fq_sponge.absorb_g(&error_commitments[1].elems);

        let challenge = fq_sponge.challenge();

        let error = error_evals.map(|e| e.evals);
        let ([ins1, ins2], [wit1, wit2]) = env.unwrap();
        let instance =
            RelaxedInstance::combine_and_sub_error(ins1, ins2, challenge, &error_commitments);
        let witness = RelaxedWitness::combine_and_sub_error(wit1, wit2, challenge, error);
        (instance, witness, error_commitments)
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
        let a: RelaxedInstance<CF::Curve, CF::Instance> = a.relax(self.zero_commitment.clone());
        let b: RelaxedInstance<CF::Curve, CF::Instance> = b.relax(self.zero_commitment.clone());

        // sanity check to verify that we only have one commitment in polycomm
        // (i.e. domain = poly size)
        assert_eq!(error_commitments[0].elems.len(), 1);
        assert_eq!(error_commitments[1].elems.len(), 1);

        fq_sponge.absorb_g(&error_commitments[0].elems);
        fq_sponge.absorb_g(&error_commitments[1].elems);

        let challenge = fq_sponge.challenge();

        RelaxedInstance::combine_and_sub_error(a, b, challenge, &error_commitments)
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

impl<F: Field> Alphas<F> {
    pub fn new(alpha: F) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(0)))
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
    pub fn combine(a: Self, b: Self, challenge: F) -> Self {
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
