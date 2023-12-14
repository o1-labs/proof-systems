use ark_ec::AffineCurve;
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use error::{compute_error, ExtendedEnv, Side};
use expressions::{folding_expression, FoldingColumnTrait, IntegratedFoldingExpr};
pub use expressions::{ExpExtension, FoldingCompatibleExpr, Var};
pub use instance_witness::{Instance, RelaxedInstance, RelaxedWitness, Witness};
use instance_witness::{RelaxableInstance, RelaxablePair};
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS};
use quadricization::ExtendedWitnessGenerator;
use std::{fmt::Debug, hash::Hash};

mod error;
mod expressions;
mod instance_witness;
mod quadricization;
#[cfg(test)]
mod test;

type Fi<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

pub trait FoldingConfig: Clone + Debug + Eq + Hash + 'static {
    type Column: FoldingColumnTrait + Debug + Eq + Hash;
    type Challenge: Clone + Copy + Debug + Eq + Hash;
    type Curve: CommitmentCurve;
    type Srs: SRS<Self::Curve>;
    type Sponge: Sponge<Self::Curve>;
    type Instance: Instance<Self::Curve>;
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
    fn rows() -> usize;
}

#[derive(Clone)]
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

    fn unwrap_result(self) -> Vec<F> {
        match self {
            EvalLeaf::Result(res) => res,
            _ => panic!("is not result"),
        }
    }
}

pub trait FoldingEnv<F, I, W, Col, Chal> {
    type Structure;
    ///a vec of just zeros of the same length as other columns
    fn zero_vec(&self) -> Vec<F>;
    fn col(&self, col: Col, side: Side) -> &Vec<F>;
    fn lagrange_basis(&self, i: usize) -> &Vec<F>;
    fn challenge(&self, challenge: Chal, side: Side) -> F;
    fn alpha(&self, i: usize, side: Side) -> F;
    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self;
}

pub trait Sponge<G: CommitmentCurve> {
    fn challenge(absorbe: &[PolyComm<G>; 2]) -> G::ScalarField;
}

type Evals<F> = Evaluations<F, Radix2EvaluationDomain<F>>;

pub struct FoldingScheme<CF: FoldingConfig> {
    expression: IntegratedFoldingExpr<CF>,
    shift: Vec<Fi<CF>>,
    srs: CF::Srs,
    domain: Radix2EvaluationDomain<Fi<CF>>,
    zero_commitment: PolyComm<CF::Curve>,
    zero_vec: Evals<Fi<CF>>,
    structure: CF::Structure,
    extended_witness_generator: ExtendedWitnessGenerator<CF>,
}

impl<CF: FoldingConfig> FoldingScheme<CF> {
    pub fn new(
        constraints: Vec<FoldingCompatibleExpr<CF>>,
        srs: CF::Srs,
        domain: Radix2EvaluationDomain<Fi<CF>>,
        structure: CF::Structure,
    ) -> (Self, FoldingCompatibleExpr<CF>) {
        let (expression, extended_witness_generator) = folding_expression(constraints);
        let shift = domain.elements().collect();
        let zero = <Fi<CF>>::zero();
        let evals = std::iter::repeat(zero).take(domain.size()).collect();
        let zero_vec_evals = Evaluations::from_vec_and_domain(evals, domain);
        let zero_commitment = srs.commit_evaluations_non_hiding(domain, &zero_vec_evals);
        let zero_vec = zero_vec_evals;
        let final_expression = expression.clone().final_expression();
        let scheme = Self {
            expression,
            shift,
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
        let env = ExtendedEnv::new(
            &self.structure,
            &self.shift,
            [ins1, ins2],
            [wit1, wit2],
            self.domain,
        );
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
