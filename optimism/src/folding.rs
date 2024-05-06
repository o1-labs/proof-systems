use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use core::sync::atomic::Ordering;
use folding::{FoldingEnv, Instance, Side, Sponge, Witness};
use kimchi::{
    circuits::{expr::ChallengeTerm, gate::CurrOrNext},
    curve::KimchiCurve,
};
use kimchi_msm::witness::Witness as GenericWitness;
use mina_poseidon::{
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::PolyComm;
use std::{array, iter::successors, ops::Index, rc::Rc, sync::atomic::AtomicUsize};

use crate::{BaseSponge as BaseSpongeT, Curve, Fp, DOMAIN_SIZE};

// FIXME: Using a struct as Rust asks for it, but we should change how folding
// uses the sponge.
pub struct BaseSponge(BaseSpongeT);

// TODO: get rid of trait Sponge in folding, and use the one from kimchi
impl Sponge<Curve> for BaseSponge {
    fn challenge(absorb: &[PolyComm<Curve>; 2]) -> Fp {
        // This function does not have a &self because it is meant to absorb and
        // squeeze only once
        let x = DefaultFqSponge::new(Curve::other_curve_sponge_params());
        let mut s = BaseSponge(x);
        s.0.absorb_g(&absorb[0].elems);
        s.0.absorb_g(&absorb[1].elems);
        // Squeeze sponge
        let chal = ScalarChallenge(s.0.challenge());
        let (_, endo_r) = Curve::endos();
        chal.to_field(endo_r)
    }
}

// Does not contain alpha because this one should be provided by folding itself
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Challenge {
    Beta,
    Gamma,
    JointCombiner,
}

/// The alphas are exceptional, their number cannot be known ahead of time as it
/// will be defined by folding. The values will be computed as powers in new
/// instances, but after folding each alfa will be a linear combination of other
/// alphas, instand of a power of other element. This type represents that,
/// allowing to also recognize which case is present
#[derive(Debug, Clone)]
pub enum Alphas {
    Powers(Fp, Rc<AtomicUsize>),
    Combinations(Vec<Fp>),
}

impl Alphas {
    pub fn new(alpha: Fp) -> Self {
        Self::Powers(alpha, Rc::new(AtomicUsize::from(0)))
    }
    pub fn get(&self, i: usize) -> Option<Fp> {
        match self {
            Alphas::Powers(alpha, count) => {
                let _ = count.fetch_max(i + 1, Ordering::Relaxed);
                let i = [i as u64];
                Some(alpha.pow(i))
            }
            Alphas::Combinations(alphas) => alphas.get(i).cloned(),
        }
    }
    pub fn powers(self) -> Vec<Fp> {
        match self {
            Alphas::Powers(alpha, count) => {
                let n = count.load(Ordering::Relaxed);
                let alphas = successors(Some(Fp::one()), |last| Some(*last * alpha));
                alphas.take(n).collect()
            }
            Alphas::Combinations(c) => c,
        }
    }
    pub fn combine(a: Self, b: Self, challenge: Fp) -> Self {
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

// Needed to transform from expressions to folding expressions
impl From<ChallengeTerm> for Challenge {
    fn from(chal: ChallengeTerm) -> Self {
        match chal {
            ChallengeTerm::Beta => Challenge::Beta,
            ChallengeTerm::Gamma => Challenge::Gamma,
            ChallengeTerm::JointCombiner => Challenge::JointCombiner,
            ChallengeTerm::Alpha => panic!("Alpha not allowed in folding expressions"),
        }
    }
}

/// Folding instance containing the commitment to a witness of N columns, challenges for the proof, and the alphas
#[derive(Debug, Clone)]
pub(crate) struct FoldingInstance<const N: usize> {
    /// Commitments to the witness columns, including the dynamic selectors
    pub(crate) commitments: [Curve; N],
    /// Challenges for the proof
    pub(crate) challenges: [Fp; 3],
    /// Reuses the Alphas defined in the example of folding
    pub(crate) alphas: Alphas,
}

impl<const N: usize> Instance<Curve> for FoldingInstance<N> {
    fn combine(a: Self, b: Self, challenge: Fp) -> Self {
        FoldingInstance {
            commitments: array::from_fn(|i| {
                a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
            }),
            challenges: [
                a.challenges[0] + challenge * b.challenges[0],
                a.challenges[1] + challenge * b.challenges[1],
                a.challenges[2] + challenge * b.challenges[2],
            ],
            alphas: Alphas::combine(a.alphas, b.alphas, challenge),
        }
    }
}

/// Includes the data witness columns and also the dynamic selector columns
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FoldingWitness<const N: usize> {
    pub(crate) witness: GenericWitness<N, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
}

impl<const N: usize> Witness<Curve> for FoldingWitness<N> {
    fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
        for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

/// Environment for the folding protocol, for a given number of witness columns and structure
pub(crate) struct FoldingEnvironment<const N: usize, Structure> {
    /// Structure of the folded circuit (not used right now)
    #[allow(dead_code)]
    pub(crate) structure: Structure,
    /// Commitments to the witness columns, for both sides
    pub(crate) instances: [FoldingInstance<N>; 2],
    /// Corresponds to the omega evaluations, for both sides
    pub(crate) curr_witnesses: [FoldingWitness<N>; 2],
    /// Corresponds to the zeta*omega evaluations, for both sides
    /// This is curr_witness but left shifted by 1
    pub(crate) next_witnesses: [FoldingWitness<N>; 2],
}

impl<const N: usize, Col, Selector: Copy + Clone, Structure: Clone>
    FoldingEnv<Fp, FoldingInstance<N>, FoldingWitness<N>, Col, Challenge, Selector>
    for FoldingEnvironment<N, Structure>
where
    FoldingWitness<N>: Index<Col, Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
    FoldingWitness<N>: Index<Selector, Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
{
    type Structure = Structure;

    fn new(
        structure: &Self::Structure,
        instances: [&FoldingInstance<N>; 2],
        witnesses: [&FoldingWitness<N>; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.witness.cols.iter_mut() {
                col.evals.rotate_left(1);
            }
        }
        FoldingEnvironment {
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn zero_vec(&self) -> Vec<Fp> {
        vec![Fp::zero(); DOMAIN_SIZE]
    }

    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
        let wit = match curr_or_next {
            CurrOrNext::Curr => &self.curr_witnesses[side as usize],
            CurrOrNext::Next => &self.next_witnesses[side as usize],
        };
        // The following is possible because Index is implemented for our circuit witnesses
        &wit[col].evals
    }

    fn challenge(&self, challenge: Challenge, side: Side) -> Fp {
        match challenge {
            Challenge::Beta => self.instances[side as usize].challenges[0],
            Challenge::Gamma => self.instances[side as usize].challenges[1],
            Challenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn lagrange_basis(&self, _i: usize) -> &Vec<Fp> {
        todo!()
    }

    fn alpha(&self, i: usize, side: Side) -> Fp {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }

    fn selector(&self, s: &Selector, side: Side) -> &Vec<Fp> {
        let witness = &self.curr_witnesses[side as usize];
        &witness[*s].evals
    }
}

#[cfg(feature = "bn254")]
#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use kimchi::{
        circuits::expr::{
            ConstantExprInner, ConstantTerm, Constants, Expr, ExprInner, Literal, Op2, Variable,
        },
        curve::KimchiCurve,
        folding::{
            expressions::{FoldingColumnTrait, FoldingCompatibleExprInner},
            BaseSponge, FoldingCompatibleExpr, FoldingConfig,
        },
    };
    use std::ops::Index;

    use super::{FoldingEnvironment, FoldingInstance, FoldingWitness};

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum TestColumn {
        X,
        Y,
        Z,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestStructure;

    // TODO
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct TestConfig;

    type TestWitness<T> = kimchi_msm::witness::Witness<3, T>;
    type TestFoldingWitness = FoldingWitness<3>;
    type TestFoldingInstance = FoldingInstance<3>;
    type TestFoldingEnvironment = FoldingEnvironment<3, TestStructure>;

    impl Index<TestColumn> for TestFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: TestColumn) -> &Self::Output {
            &self.witness[index]
        }
    }

    // Implemented for decomposable folding compatibility (Selector is usize in this case)
    impl Index<usize> for TestFoldingWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        fn index(&self, index: usize) -> &Self::Output {
            &self.witness.cols[index]
        }
    }

    impl FoldingColumnTrait for TestColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    impl<T: Clone> Index<TestColumn> for TestWitness<T> {
        type Output = T;
        fn index(&self, index: TestColumn) -> &Self::Output {
            match index {
                TestColumn::X => &self.cols[0],
                TestColumn::Y => &self.cols[1],
                TestColumn::Z => &self.cols[2],
            }
        }
    }

    impl FoldingConfig for TestConfig {
        type Column = TestColumn;
        type Selector = usize;
        type Challenge = Challenge;
        type Curve = Curve;
        type Srs = poly_commitment::srs::SRS<Curve>;
        type Sponge = BaseSponge;
        type Instance = TestFoldingInstance;
        type Witness = TestFoldingWitness;
        type Structure = TestStructure;
        type Env = TestFoldingEnvironment;

        fn rows() -> usize {
            4
        }
    }

    #[test]
    fn test_expr_translation() {
        use super::*;
        use kimchi::circuits::expr::ChallengeTerm;

        // Check that the conversion from ChallengeTerm to Challenge works as expected
        assert_eq!(Challenge::Beta, ChallengeTerm::Beta.into());
        assert_eq!(Challenge::Gamma, ChallengeTerm::Gamma.into());
        assert_eq!(
            Challenge::JointCombiner,
            ChallengeTerm::JointCombiner.into()
        );

        // Create my special constants
        let constants = Constants {
            endo_coefficient: Fp::from(3),
            mds: &Curve::sponge_params().mds,
            zk_rows: 0,
        };

        // Define variables to be used in larger expressions
        let x = Expr::Atom(ExprInner::Cell::<ConstantExprInner<Fp>, TestColumn>(
            Variable {
                col: TestColumn::X,
                row: CurrOrNext::Curr,
            },
        ));
        let y = Expr::Atom(ExprInner::Cell::<ConstantExprInner<Fp>, TestColumn>(
            Variable {
                col: TestColumn::Y,
                row: CurrOrNext::Curr,
            },
        ));
        let z = Expr::Atom(ExprInner::Cell::<ConstantExprInner<Fp>, TestColumn>(
            Variable {
                col: TestColumn::Z,
                row: CurrOrNext::Curr,
            },
        ));
        let endo = Expr::Atom(ExprInner::<ConstantExprInner<Fp>, TestColumn>::Constant(
            ConstantExprInner::Constant(ConstantTerm::EndoCoefficient),
        ));

        // Define variables with folding expressions
        let x_f =
            FoldingCompatibleExpr::<TestConfig>::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col: TestColumn::X,
                row: CurrOrNext::Curr,
            }));
        let y_f =
            FoldingCompatibleExpr::<TestConfig>::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col: TestColumn::Y,
                row: CurrOrNext::Curr,
            }));
        let z_f =
            FoldingCompatibleExpr::<TestConfig>::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col: TestColumn::Z,
                row: CurrOrNext::Curr,
            }));

        // Check conversion of general expressions
        let xyz = x.clone() * y * z;
        let xyz_f = FoldingCompatibleExpr::<TestConfig>::BinOp(
            Op2::Mul,
            Box::new(FoldingCompatibleExpr::<TestConfig>::BinOp(
                Op2::Mul,
                Box::new(x_f.clone()),
                Box::new(y_f),
            )),
            Box::new(z_f),
        );
        assert_eq!(FoldingCompatibleExpr::<TestConfig>::from(xyz), xyz_f);

        let x_endo = x + endo;
        let x_endo_f = FoldingCompatibleExpr::<TestConfig>::BinOp(
            Op2::Add,
            Box::new(x_f),
            Box::new(FoldingCompatibleExpr::<TestConfig>::Atom(
                FoldingCompatibleExprInner::Constant(constants.endo_coefficient),
            )),
        );
        let x_endo_lit = x_endo.as_literal(&constants);
        assert_eq!(
            FoldingCompatibleExpr::<TestConfig>::from(x_endo_lit),
            x_endo_f
        );
    }
}
