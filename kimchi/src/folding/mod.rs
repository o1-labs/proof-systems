use self::error::{compute_error, Side};
use crate::circuits::{
    expr::{CacheId, Expr, FeatureFlag},
    gate::GateType,
};
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use expressions::{folding_expression, IntegratedFoldingExpr};
pub use instance_witness::{InstanceTrait, RelaxedInstance, RelaxedWitness, WitnessTrait};
use instance_witness::{RelaxableInstance, RelaxablePair};
use poly_commitment::PolyComm;
use poly_commitment::{commitment::CommitmentCurve, SRS};
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

mod error;
mod expressions;
mod instance_witness;
#[cfg(test)]
mod test;

pub(crate) trait FoldingEnv<F> {
    fn witness(&self, i: usize, side: Side) -> &Vec<F>;
    fn witness_ext(&self, i: usize, side: Side) -> &Vec<F>;
    fn index(&self, i: &GateType) -> &Vec<F>;
    fn coefficient(&self, i: usize) -> &Vec<F>;
    fn shift(&self) -> &Vec<F>;
    fn lagrange_basis(&self, i: &i32) -> Vec<F>;
    ///a vec of just zeros of the same length as other columns
    fn zero_vec(&self) -> Vec<F>;
}

pub(crate) enum EvalLeaf<'a, F: Field> {
    Const(F),
    Col(&'a Vec<F>),
    Result(Vec<F>),
}

impl<'a, F: Field> EvalLeaf<'a, F> {
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
    fn bin_op<M: Fn(&F, &F) -> F, I: Fn(&mut F, &F)>(
        a: Self,
        b: Self,
        map: M,
        in_place: I,
    ) -> Self {
        use EvalLeaf::*;
        match (a, b) {
            (Const(a), Const(b)) => Const(map(&a, &b)),
            (Const(a), Col(b)) | (Col(b), Const(a)) => {
                let res = b.iter().map(|f| map(f, &a)).collect();
                Result(res)
            }
            (Col(a), Col(b)) => {
                let res = a.iter().zip(b.iter()).map(|(a, b)| map(a, b)).collect();
                Result(res)
            }
            (Result(mut a), Const(b)) | (Const(b), Result(mut a)) => {
                for a in a.iter_mut() {
                    in_place(a, &b);
                }
                Result(a)
            }
            (Result(mut a), Col(b)) | (Col(b), Result(mut a)) => {
                for (a, b) in a.iter_mut().zip(b.iter()) {
                    in_place(a, b);
                }
                Result(a)
            }
            (Result(mut a), Result(b)) => {
                for (a, b) in a.iter_mut().zip(b.iter()) {
                    in_place(a, b);
                }
                Result(a)
            }
        }
    }
}
struct Env<'a, G, I, W>
where
    G: CommitmentCurve,
    I: InstanceTrait<G>,
    W: WitnessTrait<G>,
{
    a: (RelaxedInstance<G, I>, RelaxedWitness<G, W>),
    b: (RelaxedInstance<G, I>, RelaxedWitness<G, W>),
    index: &'a HashMap<GateType, Vec<G::ScalarField>>,
    coefficients: &'a [Vec<G::ScalarField>],
    shift: &'a Vec<G::ScalarField>,
    len: usize,
}
impl<'a, G, I, W> FoldingEnv<G::ScalarField> for Env<'a, G, I, W>
where
    G: CommitmentCurve,
    I: InstanceTrait<G>,
    W: WitnessTrait<G>,
{
    fn witness(&self, i: usize, side: Side) -> &Vec<G::ScalarField> {
        match side {
            Side::Left => self.a.1.witness.witness_ext(i),
            Side::Right => self.b.1.witness.witness_ext(i),
        }
    }

    fn witness_ext(&self, i: usize, side: Side) -> &Vec<G::ScalarField> {
        match side {
            Side::Left => self.a.1.witness.witness_ext(i),
            Side::Right => self.b.1.witness.witness_ext(i),
        }
    }

    fn index(&self, i: &GateType) -> &Vec<G::ScalarField> {
        self.index.get(i).unwrap()
    }

    fn coefficient(&self, i: usize) -> &Vec<G::ScalarField> {
        &self.coefficients[i]
    }

    fn shift(&self) -> &Vec<G::ScalarField> {
        self.shift
    }

    fn lagrange_basis(&self, i: &i32) -> Vec<G::ScalarField> {
        assert!(i >= &0);
        let zero = G::ScalarField::zero();
        let mut basis = vec![zero; self.len];
        basis[*i as usize] = G::ScalarField::one();
        basis
    }

    fn zero_vec(&self) -> Vec<G::ScalarField> {
        let zero = G::ScalarField::zero();
        vec![zero; self.len]
    }
}
pub trait Sponge<G: CommitmentCurve> {
    fn challenge(absorbe: &PolyComm<G>) -> G::ScalarField;
}

pub struct FoldingScheme<G: CommitmentCurve, S: Sponge<G>, C: SRS<G>> {
    _sponge: PhantomData<S>,
    expression: IntegratedFoldingExpr<G::ScalarField>,
    index: HashMap<GateType, Vec<G::ScalarField>>,
    coefficients: Vec<Vec<G::ScalarField>>,
    shift: Vec<G::ScalarField>,
    srs: Arc<C>,
    domain: Radix2EvaluationDomain<G::ScalarField>,
    zero_commitment: PolyComm<G>,
    zero_vec: Vec<G::ScalarField>,
}
impl<G: CommitmentCurve, S: Sponge<G>, C: SRS<G>> FoldingScheme<G, S, C> {
    pub fn new<F: Fn(&FeatureFlag) -> bool>(
        expression: &Expr<G::ScalarField>,
        index: HashMap<GateType, Vec<G::ScalarField>>,
        coefficients: Vec<Vec<G::ScalarField>>,
        srs: Arc<C>,
        domain: Radix2EvaluationDomain<G::ScalarField>,
        flag_resolver: &F,
    ) -> Self {
        let expression = folding_expression(expression, flag_resolver);
        let shift = domain.elements().collect();
        let zero: G::ScalarField = G::ScalarField::zero();
        let evals = std::iter::repeat(zero).take(domain.size()).collect();
        let zero_vec_evals = Evaluations::from_vec_and_domain(evals, domain);
        let zero_commitment = srs.commit_evaluations_non_hiding(domain, &zero_vec_evals);
        let zero_vec = zero_vec_evals.evals;
        Self {
            _sponge: PhantomData,
            expression,
            index,
            coefficients,
            shift,
            srs,
            domain,
            zero_vec,
            zero_commitment,
        }
    }

    pub fn fold_instance_witness_pair<I, W, A, B>(
        &self,
        a: A,
        b: B,
    ) -> (RelaxedInstance<G, I>, RelaxedWitness<G, W>, PolyComm<G>)
    where
        I: InstanceTrait<G>,
        W: WitnessTrait<G>,
        A: RelaxablePair<G, I, W>,
        B: RelaxablePair<G, I, W>,
    {
        let a = a.relax(&self.zero_vec, self.zero_commitment.clone());
        let b = b.relax(&self.zero_vec, self.zero_commitment.clone());

        let len = a.1.witness.rows();
        let u = (a.0.u, b.0.u);

        let env = Env {
            a,
            b,
            index: &self.index,
            coefficients: &self.coefficients,
            shift: &self.shift,
            len,
        };
        let error = compute_error(&self.expression, &env, u);
        let error_evals = Evaluations::from_vec_and_domain(error, self.domain);
        let error_commitment = self
            .srs
            .commit_evaluations_non_hiding(self.domain, &error_evals);
        let error = error_evals.evals;
        let challenge = S::challenge(&error_commitment);
        let Env {
            a: (ins1, wit1),
            b: (ins2, wit2),
            ..
        } = env;
        let instance =
            RelaxedInstance::combine(ins1, ins2, challenge).add_error(&error_commitment, challenge);
        //subtrac instead
        let witness = RelaxedWitness::combine(wit1, wit2, challenge).add_error(error, challenge);
        (instance, witness, error_commitment)
    }
    pub fn fold_instance_pair<I, W, A, B>(
        &self,
        a: A,
        b: B,
        error_commitment: PolyComm<G>,
    ) -> RelaxedInstance<G, I>
    where
        I: InstanceTrait<G>,
        W: WitnessTrait<G>,
        A: RelaxableInstance<G, I>,
        B: RelaxableInstance<G, I>,
    {
        let a: RelaxedInstance<G, I> = a.relax(self.zero_commitment.clone());
        let b: RelaxedInstance<G, I> = b.relax(self.zero_commitment.clone());
        let challenge = S::challenge(&error_commitment);
        RelaxedInstance::combine(a, b, challenge).add_error(&error_commitment, challenge)
    }

    //this can be reused for quadricization
    /*fn degree_of_expression<C>(exp: &Expr<C>) -> Degree {
        use Degree::*;
        match exp {
            Expr::Constant(_) => Zero,
            Expr::Cell(var) => match var.col {
                Column::Witness(_) => One,
                Column::Index(_) | Column::Coefficient(_) => Zero,
                Column::Z
                | Column::LookupSorted(_)
                | Column::LookupAggreg
                | Column::LookupTable
                | Column::LookupKindIndex(_)
                | Column::LookupRuntimeSelector
                | Column::LookupRuntimeTable
                | Column::Permutation(_) => unreachable!(),
            },
            Expr::Double(exp) => Self::degree_of_expression(exp),
            Expr::Square(exp) => match Self::degree_of_expression(exp) {
                Zero => Zero,
                One => Two,
                Two => panic!("degree over 2"),
            },
            Expr::BinOp(Op2::Add | Op2::Sub, e1, e2) => {
                let d1 = Self::degree_of_expression(e1);
                let d2 = Self::degree_of_expression(e2);
                match (d1, d2) {
                    (Zero, Zero) => Zero,
                    (Zero, One) | (One, Zero) | (One, One) => One,
                    (_, Two) | (Two, _) => Two,
                }
            }
            Expr::BinOp(Op2::Mul, e1, e2) => {
                let d1 = Self::degree_of_expression(e1);
                let d2 = Self::degree_of_expression(e2);
                match (d1, d2) {
                    (Zero, Zero) => Zero,
                    (Zero, One) | (One, Zero) => One,
                    (Zero, Two) | (One, One) | (Two, Zero) => Two,
                    (One, Two) | (Two, One) | (Two, Two) => panic!("degree over 2"),
                }
            }
            Expr::VanishesOnLast4Rows => unreachable!(),
            Expr::UnnormalizedLagrangeBasis(_) => panic!("revisit if needed"),
            Expr::Pow(exp, p) => {
                //quadricization should result in only this case
                assert_eq!(p, &2);
                assert_eq!(Self::degree_of_expression(exp), One);
                Two
            }
            Expr::Cache(_, exp) => Self::degree_of_expression(exp),
            Expr::IfFeature(flag, e1, e2) => {
                //TODO: use the flag
                let d1 = Self::degree_of_expression(e1);
                let d2 = Self::degree_of_expression(e2);
                match (d1, d2) {
                    (Zero, Zero) => Zero,
                    (Zero, One) | (One, Zero) | (One, One) => One,
                    (_, Two) | (Two, _) => Two,
                }
            }
        }
    }*/
}
