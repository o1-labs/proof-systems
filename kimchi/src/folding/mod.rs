use crate::circuits::gate::CurrOrNext;
use ark_ec::AffineCurve;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use error_term::{compute_error, ExtendedEnv, Side};
use expressions::{folding_expression, FoldingColumnTrait, IntegratedFoldingExpr};
pub use expressions::{ExpExtension, FoldingCompatibleExpr};
pub use instance_witness::{Instance, RelaxedInstance, RelaxedWitness, Witness};
use instance_witness::{RelaxableInstance, RelaxablePair};
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS};
use quadraticization::ExtendedWitnessGenerator;
use std::{fmt::Debug, hash::Hash};

mod error_term;
pub mod expressions;
mod instance_witness;
mod quadraticization;
#[cfg(test)]
mod test;

type ScalarField<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

pub trait FoldingConfig: Clone + Debug + Eq + Hash + 'static {
    type Column: FoldingColumnTrait + Debug + Eq + Hash;

    /// The type of challenge that the Sponge returns
    type Challenge: Clone + Copy + Debug + Eq + Hash;

    /// The target curve used by the polynomial commitment
    type Curve: CommitmentCurve;

    type Srs: SRS<Self::Curve>;

    /// FIXME: use Sponge from kimchi
    /// The sponge used to create challenges
    type Sponge: Sponge<Self::Curve>;

    /// FIXME: ??
    type Instance: Instance<Self::Curve>;

    /// For PlonK, it will be the polynomials we commit to, i.e. the columns.
    /// In the generic prover/verifier, it would be WitnessColumns.
    type Witness: Witness<Self::Curve>;

    type Structure;

    type Env: FoldingEnv<
        <Self::Curve as AffineCurve>::ScalarField,
        Self::Instance,
        Self::Witness,
        Self::Column,
        Self::Challenge,
        Structure = Self::Structure,
    >;

    /// Return the size of the circuit, i.e. the number of rows
    fn rows() -> usize;
}

#[derive(Clone)]
pub(crate) enum EvalLeaf<'a, F> {
    Const(F),
    Col(&'a Vec<F>),
    Result(Vec<F>),
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
pub trait FoldingEnv<F, I, W, Col, Chal> {
    /// Equivalent to a polynomial that
    type Structure;

    /// A vec of zeros of the same length as other columns
    fn zero_vec(&self) -> Vec<F>;

    /// ??
    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<F>;

    fn lagrange_basis(&self, i: usize) -> &Vec<F>;

    fn challenge(&self, challenge: Chal, side: Side) -> F;

    fn alpha(&self, i: usize, side: Side) -> F;

    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self;
}

/// TODO: Use Sponge trait from kimchi
pub trait Sponge<G: CommitmentCurve> {
    /// Compute a challenge from two commitments
    fn challenge(absorbe: &[PolyComm<G>; 2]) -> G::ScalarField;
}

type Evals<F> = Evaluations<F, Radix2EvaluationDomain<F>>;

pub struct FoldingScheme<CF: FoldingConfig> {
    expression: IntegratedFoldingExpr<CF>,
    srs: CF::Srs,
    domain: Radix2EvaluationDomain<ScalarField<CF>>,
    zero_commitment: PolyComm<CF::Curve>,
    zero_vec: Evals<ScalarField<CF>>,
    structure: CF::Structure,
    extended_witness_generator: ExtendedWitnessGenerator<CF>,
}

impl<CF: FoldingConfig> FoldingScheme<CF> {
    pub fn new(
        constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: CF::Srs,
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
    pub fn fold_instance_witness_pair<I, W, A, B>(
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
        let env = ExtendedEnv::new(&self.structure, [ins1, ins2], [wit1, wit2], self.domain);
        let env = env.compute_extension(&self.extended_witness_generator, &self.srs);
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

#[cfg(test)]
mod tests {
    use ark_poly::Evaluations;
    use mina_poseidon::FqSponge;

    use crate::folding::{FoldingConfig, FoldingEnv, Instance, Sponge, Witness};

    use super::expressions::FoldingColumnTrait;

    struct TestConfig;

    /// Field = BN254 prime field
    /// Statement: I know w such that C(x, y, w) = 0
    ///   public
    ///     |
    ///   ----  |--- private
    /// C(x, y, w) = x + y - w
    /// I want to fold two instances

    /// (A Z) . (B Z) = (C Z)
    /// Z = (x, y, z)
    /// A = (1 1 -1)
    /// B = (0, 0, 0)
    /// C = (1 1 -1)

    fn test_folding_instance() {
        /// X(1) = x
        /// X(2) = y
        /// X(3) = w
        use kimchi::circuits::expr::{ConstantExprInner, ExprInner, Operations, Variable};
        use kimchi::circuits::gate::CurrOrNext;
        use mina_poseidon::{
            constants::PlonkSpongeConstantsKimchi,
            sponge::{DefaultFqSponge, DefaultFrSponge},
        };
        use poly_commitment::PolyComm;

        #[derive(Debug, Eq, Hash, Clone)]
        pub enum Column {
            X(usize),
        }

        type Fp = ark_bn254::Fr;
        type Curve = ark_bn254::G1Affine;
        type SpongeParams = PlonkSpongeConstantsKimchi;
        type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

        // TODO: get rid of trait Sponge in folding, and use the one from kimchi
        impl Sponge<Curve> for BaseSponge {
            fn challenge(absorbe: &[PolyComm<Curve>; 2]) -> Fp {
                // FIXME: we should have a self maybe?
                let mut s = BaseSponge::new(SpongeParams::new());
                s.absorb_fq(absorbe[0].unshifted.clone());
                s.absorb_fq(absorbe[1].unshifted.clone());
            }
        }

        type E<F> = Expr<ConstantExpr<F>, Column>;
        let x1 = E::<Fp>::Atom(
            ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
                col: Column::X(1),
                row: CurrOrNext::Curr,
            }),
        );
        let x2 = E::<Fp>::Atom(
            ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
                col: Column::X(2),
                row: CurrOrNext::Curr,
            }),
        );
        let x3 = E::<Fp>::Atom(
            ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
                col: Column::X(3),
                row: CurrOrNext::Curr,
            }),
        );
        let constraint = x3 - x1 - x2;

        /// The instance is the commitments to the polynomials.
        type SInstance = [Curve; 3];
        impl Instance<Curve> for SInstance {
            fn combine(a: Self, b: Self, challenge: Fp) -> Self {
                [
                    a[0] + challenge * b[0],
                    a[1] + challenge * b[1],
                    a[2] + challenge * b[2],
                ]
            }
        }

        /// Our witness is going to be the polynomials that we will commit too.
        /// Vec<Fp> will be the evaluations of each x_1, x_2 and x_3 over the domain.
        /// FIXME: use evaluations
        type SWitness = [Vec<Fp>; 3];

        impl Witness<Curve> for SWitness {
            fn combine(a: Self, b: Self, challenge: Fp) -> Self {
                a.into_iter()
                    .zip(b)
                    .map(|(p1, p2)| {
                        p1.iter()
                            .zip(p2)
                            .map(|x1, x2| x1 + challenge * x2)
                            .collect::<Vec<Fp>>()
                    })
                    .collect::<Vec<_>>().try_into().unwrap()
            }
        }

        struct SFoldingEnv;
        impl FoldingEnv for SFoldingEnv {
            type Structure = ();
            type Column = Column;
            type Challenge = ();
            type Curve = Curve;
            type Instance = ();
            type Witness = ();
            type Env = ();
        }

        struct SFoldingConfig;

        impl FoldingConfig for SFoldingConfig {
            type Column = Column;
            // FIXME
            type Challenge = ();

            type Curve = Curve;
            type Srs = poly_commitment::srs::SRS<Curve>;
            type Sponge = BaseSponge;

            // FIXME
            type Instance = Witness<Curve>;

            type Witness = Witness<Curve>;

            // FIXME
            type Structure = ();

            // FIXME
            type Env = ();

            fn rows() -> usize {
                // FIXME: this is the domain size. Atm, let's have only one
                // column
                1
            }
        }
    }
}
