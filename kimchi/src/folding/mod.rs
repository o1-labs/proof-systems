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
    /// Structure which could be storing useful information like selectors, etc.
    type Structure;

    /// Creates a new environment storing the structure, instances and witnesses.
    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self;

    // TODO: move into `FoldingConfig`
    // FIXME: when we move this to `FoldingConfig` it will be general for all impls as:
    // vec![F::zero(); Self::rows()]
    /// Returns a vector of zeros with the same length as the number of rows in the circuit.
    fn zero_vec(&self) -> Vec<F>;

    /// Returns the evaluations of a given column witness at omega or zeta*omega.
    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<F>;

    // TODO: could be shared across circuits of the same type
    /// Returns the evaluations of the i-th lagrangian term.
    fn lagrange_basis(&self, i: usize) -> &Vec<F>;

    /// Obtains a given challenge from the expanded instance for one side.
    /// The challenges are stored inside the instances structs.
    fn challenge(&self, challenge: Chal, side: Side) -> F;

    /// Computes the i-th power of alpha for a given side.
    /// Folding itself will provide us with the alpha value.
    fn alpha(&self, i: usize, side: Side) -> F;
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
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_poly::Evaluations;
    use mina_poseidon::{constants::SpongeConstants, sponge::ScalarChallenge, FqSponge};
    use poly_commitment::commitment::CommitmentCurve;

    use crate::{
        curve::KimchiCurve,
        folding::{error_term::Side, FoldingConfig, FoldingEnv, Instance, Sponge, Witness},
    };
    use ark_bn254;

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

    #[test]
    fn test_folding_instance() {
        /// X(1) = x
        /// X(2) = y
        /// X(3) = w
        use crate::circuits::expr::{
            ConstantExpr, ConstantExprInner, Expr, ExprInner, Operations, Variable,
        };
        use crate::circuits::gate::CurrOrNext;
        use ark_ff::Zero;
        use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
        use poly_commitment::PolyComm;

        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub enum TestColumn {
            X(usize),
        }

        impl FoldingColumnTrait for TestColumn {
            fn is_witness(&self) -> bool {
                true
            }
        }

        type Fp = ark_bn254::Fr;
        type Curve = ark_bn254::G1Affine;
        type SpongeParams = PlonkSpongeConstantsKimchi;
        type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

        // TODO: get rid of trait Sponge in folding, and use the one from kimchi
        impl Sponge<Curve> for BaseSponge {
            fn challenge(absorbe: &[PolyComm<Curve>; 2]) -> Fp {
                // This function does not have a &self because it is meant to absorb and squeeze only once
                let mut s = BaseSponge::new(Curve::other_curve_sponge_params());
                s.absorb_g(&absorbe[0].elems);
                s.absorb_g(&absorbe[1].elems);
                // Squeeze sponge
                let chal = ScalarChallenge(s.challenge());
                let (_, endo_r) = Curve::endos();
                chal.to_field(endo_r)
            }
        }

        type E<F> = Expr<ConstantExpr<F>, TestColumn>;
        let x1 = E::<Fp>::Atom(
            ExprInner::<Operations<ConstantExprInner<Fp>>, TestColumn>::Cell(Variable {
                col: TestColumn::X(1),
                row: CurrOrNext::Curr,
            }),
        );
        let x2 = E::<Fp>::Atom(
            ExprInner::<Operations<ConstantExprInner<Fp>>, TestColumn>::Cell(Variable {
                col: TestColumn::X(2),
                row: CurrOrNext::Curr,
            }),
        );
        let x3 = E::<Fp>::Atom(
            ExprInner::<Operations<ConstantExprInner<Fp>>, TestColumn>::Cell(Variable {
                col: TestColumn::X(3),
                row: CurrOrNext::Curr,
            }),
        );
        let constraint = x3 - x1 - x2;

        /// The instance is the commitments to the polynomials and the challenges
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct TestInstance {
            commitments: [Curve; 3],
            challenges: [Fp; 3],
        }

        impl Instance<Curve> for TestInstance {
            fn combine(a: Self, b: Self, challenge: Fp) -> Self {
                TestInstance {
                    commitments: [
                        a.commitments[0] + b.commitments[0].mul(challenge).into_affine(),
                        a.commitments[1] + b.commitments[1].mul(challenge).into_affine(),
                        a.commitments[2] + b.commitments[2].mul(challenge).into_affine(),
                    ],
                    challenges: [
                        a.challenges[0] + challenge * b.challenges[0],
                        a.challenges[1] + challenge * b.challenges[1],
                        a.challenges[2] + challenge * b.challenges[2],
                    ],
                }
            }
        }

        /// Our witness is going to be the polynomials that we will commit too.
        /// Vec<Fp> will be the evaluations of each x_1, x_2 and x_3 over the domain.
        // FIXME: use evaluations
        type TestWitness = [Vec<Fp>; 3];

        impl Witness<Curve> for TestWitness {
            fn combine(a: Self, b: Self, challenge: Fp) -> Self {
                a.into_iter()
                    .zip(b)
                    .map(|(p1, p2)| {
                        p1.iter()
                            .zip(p2)
                            .map(|(x1, x2)| *x1 + challenge * x2)
                            .collect::<Vec<Fp>>()
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            }
        }

        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        struct TestStructure {
            column_type: TestColumn,
            challenge_type: TestChallenge,
        }

        struct TestFoldingEnv {
            structure: TestStructure,
            instances: [TestInstance; 2],
            witnesses: [TestWitness; 2],
        }

        impl FoldingEnv<Fp, TestInstance, TestWitness, TestColumn, TestChallenge> for TestFoldingEnv {
            type Structure = TestStructure;

            fn new(
                structure: &Self::Structure,
                instances: [&TestInstance; 2],
                witnesses: [&TestWitness; 2],
            ) -> Self {
                TestFoldingEnv {
                    structure: *structure,
                    instances: [instances[0].clone(), instances[1].clone()],
                    witnesses: [witnesses[0].clone(), witnesses[1].clone()],
                }
            }

            fn zero_vec(&self) -> Vec<Fp> {
                vec![Fp::zero(); 1]
            }

            fn col(&self, col: TestColumn, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
                let wit = match col {
                    TestColumn::X(1) => &self.witnesses[side as usize][0],
                    TestColumn::X(2) => &self.witnesses[side as usize][1],
                    TestColumn::X(3) => &self.witnesses[side as usize][2],
                    TestColumn::X(_) => panic!("Invalid column"),
                };
                let mut wit = wit.clone();
                let evals = match curr_or_next {
                    CurrOrNext::Curr => wit,
                    CurrOrNext::Next => {
                        wit.rotate_left(1);
                        wit
                    }
                };
                &evals
            }

            fn challenge(&self, challenge: TestChallenge, side: Side) -> Fp {
                match challenge {
                    TestChallenge::Beta => self.instances[side as usize].challenges[0],
                    TestChallenge::Gamma => self.instances[side as usize].challenges[1],
                    TestChallenge::JointCombiner => self.instances[side as usize].challenges[2],
                }
            }

            fn lagrange_basis(&self, _i: usize) -> &Vec<Fp> {
                todo!()
            }

            fn alpha(&self, _i: usize, _side: Side) -> Fp {
                todo!()
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        struct TestFoldingConfig;

        // Does not contain alpha because this one should be provided by folding itself
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        enum TestChallenge {
            Beta,
            Gamma,
            JointCombiner,
        }

        impl FoldingConfig for TestFoldingConfig {
            type Structure = TestStructure;
            type Column = TestColumn;
            type Challenge = TestChallenge;
            type Curve = Curve;
            type Srs = poly_commitment::srs::SRS<Curve>;
            type Sponge = BaseSponge;
            type Instance = TestInstance;
            type Witness = TestWitness;
            type Env = TestFoldingEnv;

            fn rows() -> usize {
                // FIXME: this is the domain size. Atm, let's have only one row
                1
            }
        }
    }
}
