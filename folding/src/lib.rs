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
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use error_term::{compute_error, ExtendedEnv};
use expressions::{
    folding_expression, FoldingColumnTrait, FoldingCompatibleExpr, IntegratedFoldingExpr,
};
use instance_witness::{RelaxableInstance, RelaxablePair};
use kimchi::circuits::gate::CurrOrNext;
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS};
use quadraticization::ExtendedWitnessGenerator;
use std::{fmt::Debug, hash::Hash};

// Make available outside the crate to avoid code duplication
pub use error_term::Side;
pub use expressions::ExpExtension;
pub use instance_witness::{Instance, RelaxedInstance, RelaxedWitness, Witness};

pub mod columns;
pub mod decomposable_folding;

mod error_term;

pub mod expressions;
mod instance_witness;
pub mod quadraticization;

// Modules strictly related to tests
// TODO: should we move them into an explicit subdirectory `test`?
#[cfg(test)]
#[cfg(feature = "bn254")]
mod examples;
#[cfg(test)]
mod mock;

// Simple type alias as ScalarField is often used. Reduce type complexity for
// clippy.
// Should be moved into FoldingConfig, but associated type defaults are unstable
// at the moment.
type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

pub trait FoldingConfig: Clone + Debug + Eq + Hash + 'static {
    type Column: FoldingColumnTrait + Debug + Eq + Hash;
    // in case of using docomposable folding, if not it can be just ()
    type Selector: Clone + Debug + Eq + Hash;

    /// The type of an abstract challenge that can be found in the expressions
    /// provided as constraints.
    type Challenge: Clone + Copy + Debug + Eq + Hash;

    /// The target curve used by the polynomial commitment
    type Curve: CommitmentCurve;

    type Srs: SRS<Self::Curve>;

    /// The sponge used to create challenges
    // FIXME: use Sponge from kimchi
    type Sponge: Sponge<Self::Curve>;

    /// For Plonk, it will be the commitments to the polynomials and the challenges
    type Instance: Instance<Self::Curve>;

    /// For PlonK, it will be the polynomials in evaluation form that we commit
    /// to, i.e. the columns.
    /// In the generic prover/verifier, it would be `kimchi_msm::witness::Witness`.
    type Witness: Witness<Self::Curve>;

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

#[derive(Clone, Debug)]
pub(crate) enum EvalLeaf<'a, F> {
    Const(F),
    Col(&'a Vec<F>),
    Result(Vec<F>),
}

impl<'a, F: std::fmt::Display> std::fmt::Display for EvalLeaf<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vec = match self {
            EvalLeaf::Const(c) => {
                write!(f, "Const: {}", c)?;
                return Ok(());
            }
            EvalLeaf::Col(a) => a,
            EvalLeaf::Result(a) => a,
        };
        writeln!(f, "[")?;
        for e in vec.iter() {
            writeln!(f, "{e}")?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl<'a, F: std::ops::Add<Output = F> + Clone> std::ops::Add for EvalLeaf<'a, F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a + b, self, rhs)
    }
}

impl<'a, F: std::ops::Sub<Output = F> + Clone> std::ops::Sub for EvalLeaf<'a, F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a - b, self, rhs)
    }
}

impl<'a, F: std::ops::Mul<Output = F> + Clone> std::ops::Mul for EvalLeaf<'a, F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a * b, self, rhs)
    }
}

impl<'a, F: std::ops::Mul<Output = F> + Clone> std::ops::Mul<F> for EvalLeaf<'a, F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        self * Self::Const(rhs)
    }
}

impl<'a, F: Clone> EvalLeaf<'a, F> {
    fn map<M: Fn(&F) -> F, I: Fn(&mut F)>(self, map: M, in_place: I) -> Self {
        use EvalLeaf::*;
        match self {
            Const(c) => Const(map(&c)),
            Col(col) => {
                let res = col.iter().map(map).collect();
                Result(res)
            }
            Result(mut col) => {
                for cell in col.iter_mut() {
                    in_place(cell);
                }
                Result(col)
            }
        }
    }

    fn bin_op<M: Fn(F, F) -> F>(f: M, a: Self, b: Self) -> Self {
        use EvalLeaf::*;
        match (a, b) {
            (Const(a), Const(b)) => Const(f(a, b)),
            (Const(a), Col(b)) => {
                let res = b.iter().map(|b| f(a.clone(), b.clone())).collect();
                Result(res)
            }
            (Col(a), Const(b)) => {
                let res = a.iter().map(|a| f(a.clone(), b.clone())).collect();
                Result(res)
            }
            (Col(a), Col(b)) => {
                let res = (a.iter())
                    .zip(b.iter())
                    .map(|(a, b)| f(a.clone(), b.clone()))
                    .collect();
                Result(res)
            }
            (Result(mut a), Const(b)) => {
                for a in a.iter_mut() {
                    *a = f(a.clone(), b.clone())
                }
                Result(a)
            }
            (Const(a), Result(mut b)) => {
                for b in b.iter_mut() {
                    *b = f(a.clone(), b.clone())
                }
                Result(b)
            }
            (Result(mut a), Col(b)) => {
                for (a, b) in a.iter_mut().zip(b.iter()) {
                    *a = f(a.clone(), b.clone())
                }
                Result(a)
            }
            (Col(a), Result(mut b)) => {
                for (a, b) in a.iter().zip(b.iter_mut()) {
                    *b = f(b.clone(), a.clone())
                }
                Result(b)
            }
            (Result(mut a), Result(b)) => {
                for (a, b) in a.iter_mut().zip(b.into_iter()) {
                    *a = f(a.clone(), b)
                }
                Result(a)
            }
        }
    }

    fn unwrap(self) -> Vec<F>
    where
        F: Clone,
    {
        match self {
            EvalLeaf::Col(res) => res.to_vec(),
            EvalLeaf::Result(res) => res,
            EvalLeaf::Const(_) => panic!("Attempted to unwrap a constant"),
        }
    }
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

    // TODO: could be shared across circuits of the same type
    /// Returns the evaluations of the i-th Lagrangian term.
    fn lagrange_basis(&self, i: usize) -> &Vec<F>;

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

/// TODO: Use Sponge trait from kimchi
pub trait Sponge<G: CommitmentCurve> {
    /// Compute a challenge from two commitments
    fn challenge(absorbe: &[PolyComm<G>; 2]) -> G::ScalarField;
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
    pub fn fold_instance_witness_pair<A, B>(
        &self,
        a: A,
        b: B,
    ) -> (
        RelaxedInstance<CF::Curve, CF::Instance>,
        RelaxedWitness<CF::Curve, CF::Witness>,
        [PolyComm<CF::Curve>; 2],
    )
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
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
        let env = env.compute_extension(&self.extended_witness_generator, self.srs);
        let error = compute_error(&self.expression, &env, u);
        let error_evals = error.map(|e| Evaluations::from_vec_and_domain(e, self.domain));

        //can use array::each_ref() when stable
        let error_commitments = [&error_evals[0], &error_evals[1]]
            .map(|e| self.srs.commit_evaluations_non_hiding(self.domain, e));

        let error = error_evals.map(|e| e.evals);
        let challenge = <CF::Sponge>::challenge(&error_commitments);
        let ([ins1, ins2], [wit1, wit2]) = env.unwrap();
        let instance =
            RelaxedInstance::combine_and_sub_error(ins1, ins2, challenge, &error_commitments);
        let witness = RelaxedWitness::combine_and_sub_error(wit1, wit2, challenge, error);
        (instance, witness, error_commitments)
    }

    pub fn fold_instance_pair<A, B>(
        &self,
        a: A,
        b: B,
        error_commitments: [PolyComm<CF::Curve>; 2],
    ) -> RelaxedInstance<CF::Curve, CF::Instance>
    where
        A: RelaxableInstance<CF::Curve, CF::Instance>,
        B: RelaxableInstance<CF::Curve, CF::Instance>,
    {
        let a: RelaxedInstance<CF::Curve, CF::Instance> = a.relax(self.zero_commitment.clone());
        let b: RelaxedInstance<CF::Curve, CF::Instance> = b.relax(self.zero_commitment.clone());
        let challenge = <CF::Sponge>::challenge(&error_commitments);
        RelaxedInstance::combine_and_sub_error(a, b, challenge, &error_commitments)
    }
}
