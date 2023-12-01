use self::{
    error::{compute_error, ExtendedEnv, Side},
    expressions::{FoldingColumnTrait, FoldingCompatibleExpr, IntegratedFoldingExpr},
};
use ark_ec::AffineCurve;
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use expressions::folding_expression;
pub use instance_witness::{InstanceTrait, RelaxedInstance, RelaxedWitness, WitnessTrait};
use instance_witness::{RelaxableInstance, RelaxablePair};
use poly_commitment::PolyComm;
use poly_commitment::{commitment::CommitmentCurve, SRS};
use std::fmt::Debug;

mod error;
mod expressions;
mod instance_witness;
mod quadricization;
#[cfg(test)]
mod test;

type Fi<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

pub trait FoldingConfig: Clone + Debug + 'static {
    type Column: FoldingColumnTrait + Debug;
    type Challenge: Clone + Copy + Debug;
    type Curve: CommitmentCurve;
    type Srs: SRS<Self::Curve>;
    type Sponge: Sponge<Self::Curve>;
    type Instance: InstanceTrait<Self::Curve>;
    type Witness: WitnessTrait<Self::Curve>;
    type Structure;
    type Env: FoldingEnv<
        <Self::Curve as AffineCurve>::ScalarField,
        Self::Instance,
        Self::Witness,
        Self::Column,
        Self::Challenge,
        Structure = Self::Structure,
    >;
    fn rows() -> usize;
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

pub trait FoldingEnv<F, I, W, Col, Chal> {
    type Structure;
    // fn lagrange_basis(&self, i: &i32) -> Vec<G::ScalarField>;
    ///a vec of just zeros of the same length as other columns
    fn zero_vec(&self) -> Vec<F>;
    fn col(&self, col: Col, side: Side) -> &Vec<F>;
    fn lagrange_basis(&self, i: usize) -> &Vec<F>;
    fn challenge(&self, challenge: Chal) -> F;
    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self;
}
pub trait Sponge<G: CommitmentCurve> {
    fn challenge(absorbe: &PolyComm<G>) -> G::ScalarField;
}

pub struct FoldingScheme2<CF: FoldingConfig> {
    expression: IntegratedFoldingExpr<CF>,
    shift: Vec<Fi<CF>>,
    srs: CF::Srs,
    domain: Radix2EvaluationDomain<Fi<CF>>,
    zero_commitment: PolyComm<CF::Curve>,
    zero_vec: Vec<Fi<CF>>,
    structure: CF::Structure,
}
impl<CF: FoldingConfig> FoldingScheme2<CF> {
    pub fn new(
        constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: CF::Srs,
        domain: Radix2EvaluationDomain<Fi<CF>>,
        structure: CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        let expression = folding_expression(constraints);
        let shift = domain.elements().collect();
        let zero = <Fi<CF>>::zero();
        let evals = std::iter::repeat(zero).take(domain.size()).collect();
        let zero_vec_evals = Evaluations::from_vec_and_domain(evals, domain);
        let zero_commitment = srs.commit_evaluations_non_hiding(domain, &zero_vec_evals);
        let zero_vec = zero_vec_evals.evals;
        let final_expression = expression.clone().final_expression();
        let scheme = Self {
            expression,
            shift,
            srs,
            domain,
            zero_commitment,
            zero_vec,
            structure,
        };
        (scheme, final_expression)
    }
    pub fn fold_instance_witness_pair<I, W, A, B>(
        &self,
        a: A,
        b: B,
    ) -> (
        RelaxedInstance<CF::Curve, CF::Instance>,
        RelaxedWitness<CF::Curve, CF::Witness>,
        PolyComm<CF::Curve>,
    )
    where
        A: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
        B: RelaxablePair<CF::Curve, CF::Instance, CF::Witness>,
    {
        let a = a.relax(&self.zero_vec, self.zero_commitment.clone());
        let b = b.relax(&self.zero_vec, self.zero_commitment.clone());

        // let len = CF::rows();
        let u = (a.0.u, b.0.u);

        let (ins1, wit1) = a;
        let (ins2, wit2) = b;
        let env = ExtendedEnv::new(&self.structure, &self.shift, [ins1, ins2], [wit1, wit2]);
        let error = compute_error(&self.expression, &env, u);
        let error_evals = Evaluations::from_vec_and_domain(error, self.domain);
        let error_commitment = self
            .srs
            .commit_evaluations_non_hiding(self.domain, &error_evals);
        let error = error_evals.evals;
        let challenge = <CF::Sponge>::challenge(&error_commitment);
        let ([ins1, ins2], [wit1, wit2]) = env.unwrap();
        let instance =
            RelaxedInstance::combine_and_sub_error(ins1, ins2, challenge, &error_commitment);
        let witness = RelaxedWitness::combine_and_sub_error(wit1, wit2, challenge, error);
        (instance, witness, error_commitment)
    }

    pub fn fold_instance_pair<A, B>(
        &self,
        a: A,
        b: B,
        error_commitment: PolyComm<CF::Curve>,
    ) -> RelaxedInstance<CF::Curve, CF::Instance>
    where
        A: RelaxableInstance<CF::Curve, CF::Instance>,
        B: RelaxableInstance<CF::Curve, CF::Instance>,
    {
        let a: RelaxedInstance<CF::Curve, CF::Instance> = a.relax(self.zero_commitment.clone());
        let b: RelaxedInstance<CF::Curve, CF::Instance> = b.relax(self.zero_commitment.clone());
        let challenge = <CF::Sponge>::challenge(&error_commitment);
        RelaxedInstance::combine_and_sub_error(a, b, challenge, &error_commitment)
    }
}
