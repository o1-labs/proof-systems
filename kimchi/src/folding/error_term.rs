use crate::folding::{
    expressions::{Degree, ExtendedFoldingColumn, FoldingExp, IntegratedFoldingExpr},
    quadricization::ExtendedWitnessGenerator,
    EvalLeaf, FoldingConfig, FoldingEnv, RelaxedInstance, RelaxedWitness,
};
use ark_ec::AffineCurve;
use ark_ff::Field;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use poly_commitment::SRS;

#[derive(Clone, Copy)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        }
    }
}

type Fi<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

///evaluates the expression in the provided side
pub(crate) fn eval_sided<'a, C: FoldingConfig>(
    exp: &FoldingExp<C>,
    env: &'a ExtendedEnv<C>,
    side: Side,
) -> EvalLeaf<'a, Fi<C>> {
    use FoldingExp::*;

    let eval_bin = |e1, e2| (eval_exp_error(e1, env, side), eval_exp_error(e2, env, side));
    match exp {
        Cell(col) => env.col(col, side),
        Double(e) => {
            let col = eval_exp_error(e, env, side);
            col.map(Field::double, |f| {
                Field::double_in_place(f);
            })
        }
        Square(e) => {
            let col = eval_exp_error(e, env, side);
            col.map(Field::square, |f| {
                Field::square_in_place(f);
            })
        }
        Add(e1, e2) => {
            let (a, b) = eval_bin(e1, e2);
            EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b)
        }
        Sub(e1, e2) => {
            let (a, b) = eval_bin(e1, e2);
            EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b)
        }
        Mul(e1, e2) => {
            let (a, b) = eval_bin(e1, e2);
            EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b)
        }
    }
}

pub(crate) fn eval_exp_error<'a, C: FoldingConfig>(
    exp: &FoldingExp<C>,
    env: &'a ExtendedEnv<C>,
    side: Side,
) -> EvalLeaf<'a, Fi<C>> {
    let degree = exp.folding_degree();
    use FoldingExp::*;

    let eval_bin = |e1, e2| (eval_exp_error(e1, env, side), eval_exp_error(e2, env, side));
    match exp {
        Cell(col) => env.col(col, side),
        Double(e) => {
            let col = eval_exp_error(e, env, side);
            col.map(Field::double, |f| {
                Field::double_in_place(f);
            })
        }
        Square(e) => match degree {
            Degree::Two => {
                let a = eval_exp_error(e, env, side);
                let b = eval_exp_error(e, env, side.other());
                let cross = EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b);
                cross.map(Field::square, |f| {
                    Field::double_in_place(f);
                })
            }
            _ => {
                let e = eval_exp_error(e, env, side);
                e.map(Field::square, |f| {
                    Field::square_in_place(f);
                })
            }
        },
        Add(e1, e2) => {
            let (a, b) = eval_bin(e1, e2);
            EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b)
        }
        Sub(e1, e2) => {
            let (a, b) = eval_bin(e1, e2);
            EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b)
        }
        Mul(e1, e2) => match (degree, e1.folding_degree()) {
            (Degree::Two, Degree::One) => {
                let a = eval_exp_error(e1, env, side);
                let b = eval_exp_error(e2, env, side.other());
                let first = EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b);
                let a = eval_exp_error(e1, env, side.other());
                let b = eval_exp_error(e2, env, side);
                let second = EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b);
                EvalLeaf::bin_op(first, second, |a, b| *a + b, |a, b| *a += b)
            }
            _ => {
                let (a, b) = eval_bin(e1, e2);
                EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b)
            }
        },
    }
}

pub(crate) fn compute_error<C: FoldingConfig>(
    exp: &IntegratedFoldingExpr<C>,
    env: &ExtendedEnv<C>,
    u: (Fi<C>, Fi<C>),
) -> [Vec<Fi<C>>; 2] {
    let add = |a, b| EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b);
    let sub = |a, b| EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b);
    let scale = |t, s| EvalLeaf::bin_op(t, EvalLeaf::Const(s), |a, b| *a * b, |a, b| *a *= b);

    let (ul, ur) = (u.0, u.1);
    let u_cross = ul * ur;
    let zero = || EvalLeaf::Result(env.inner().zero_vec());

    let add_signed = |sign| match sign {
        true => add,
        false => sub,
    };
    let t_0 = {
        let t_0 = (zero(), zero());
        let (l, r) = exp.degree_0.iter().fold(t_0, |(l, r), (exp, sign, alpha)| {
            //could be left or right, doesn't matter for constant terms
            let exp = eval_exp_error(exp, env, Side::Left);
            let alpha_l = env.inner().alpha(*alpha, Side::Left);
            let alpha_r = env.inner().alpha(*alpha, Side::Right);
            let add_signed = add_signed(*sign);
            (
                add_signed(l, scale(exp.clone(), alpha_l)),
                add_signed(r, scale(exp, alpha_r)),
            )
        });
        let cross2 = u_cross.double();
        let e0 = add(scale(l.clone(), cross2), scale(r.clone(), ul.square()));
        let e1 = add(scale(r, cross2), scale(l, ur.square()));
        (e0, e1)
    };

    let t_1 = {
        let t_1 = (zero(), zero(), zero());
        let (l, cross, r) = exp
            .degree_1
            .iter()
            .fold(t_1, |(l, cross, r), (exp, sign, alpha)| {
                let expl = eval_exp_error(exp, env, Side::Left);
                let expr = eval_exp_error(exp, env, Side::Right);
                let alpha_l = env.inner().alpha(*alpha, Side::Left);
                let alpha_r = env.inner().alpha(*alpha, Side::Right);
                let expr_cross = add(scale(expl.clone(), alpha_r), scale(expr.clone(), alpha_l));
                let add_signed = add_signed(*sign);
                let l = add_signed(l, scale(expl, alpha_l));
                let r = add_signed(r, scale(expr, alpha_r));
                let cross = add_signed(cross, expr_cross);
                (l, cross, r)
            });
        let e0 = add(scale(cross.clone(), ul), scale(l, ur));
        let e1 = add(scale(cross.clone(), ur), scale(r, ul));
        (e0, e1)
    };
    let t_2 = (zero(), zero());
    let t_2 = exp.degree_2.iter().fold(t_2, |(l, r), (exp, sign, alpha)| {
        let expl = eval_sided(exp, env, Side::Left);
        let expr = eval_sided(exp, env, Side::Right);
        //left or right matter in some way, but not at the top level call
        let cross = eval_exp_error(exp, env, Side::Left);
        let alpha_l = env.inner().alpha(*alpha, Side::Left);
        let alpha_r = env.inner().alpha(*alpha, Side::Right);
        let left = add(scale(expl, alpha_r), scale(cross.clone(), alpha_l));
        let right = add(scale(expr, alpha_l), scale(cross, alpha_r));
        let add_signed = add_signed(*sign);
        let l = add_signed(l, left);
        let r = add_signed(r, right);
        (l, r)
    });
    let t = [t_1, t_2]
        .into_iter()
        .fold(t_0, |(tl, tr), (txl, txr)| (add(tl, txl), add(tr, txr)));

    match t {
        (EvalLeaf::Result(l), EvalLeaf::Result(r)) => [l, r],
        _ => unreachable!(),
    }
}

type Evals<C> = Vec<<<C as FoldingConfig>::Curve as AffineCurve>::ScalarField>;
pub(crate) struct ExtendedEnv<'a, CF: FoldingConfig> {
    inner: CF::Env,
    instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
    witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
    shift: &'a Evals<CF>,
    domain: Radix2EvaluationDomain<Fi<CF>>,
}

impl<'a, CF: FoldingConfig> ExtendedEnv<'a, CF> {
    pub fn new(
        structure: &CF::Structure,
        //maybe better to have some structure exteded or something like that
        shift: &'a Evals<CF>,
        instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
        witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
        domain: Radix2EvaluationDomain<Fi<CF>>,
    ) -> Self {
        let inner_instances = [
            instances[0].inner_instance().inner(),
            instances[1].inner_instance().inner(),
        ];
        let inner_witnesses = [witnesses[0].inner().inner(), witnesses[1].inner().inner()];
        let inner = <CF::Env>::new(structure, inner_instances, inner_witnesses);
        Self {
            inner,
            instances,
            witnesses,
            shift,
            domain,
        }
    }

    pub fn inner(&self) -> &CF::Env {
        &self.inner
    }

    #[allow(clippy::type_complexity)]
    pub fn unwrap(
        self,
    ) -> (
        [RelaxedInstance<CF::Curve, CF::Instance>; 2],
        [RelaxedWitness<CF::Curve, CF::Witness>; 2],
    ) {
        let Self {
            instances,
            witnesses,
            ..
        } = self;
        (instances, witnesses)
    }

    pub fn col(&self, col: &ExtendedFoldingColumn<CF>, side: Side) -> EvalLeaf<Fi<CF>> {
        use EvalLeaf::Col;
        use ExtendedFoldingColumn::*;
        let (_instance, witness) = match side {
            Side::Left => (&self.instances[0], &self.witnesses[0]),
            Side::Right => (&self.instances[1], &self.witnesses[1]),
        };
        match col {
            Inner(col) => Col(self.inner().col(*col, side)),
            WitnessExtended(i) => Col(&witness
                .inner()
                .extended
                .get(i)
                .expect("extended column not present")
                .evals),
            Error => panic!("shouldn't happen"),
            Shift => Col(self.shift),
            UnnormalizedLagrangeBasis(i) => Col(self.inner().lagrange_basis(*i)),
            Constant(c) => EvalLeaf::Const(*c),
            Challenge(chall) => EvalLeaf::Const(self.inner().challenge(*chall, side)),
            Alpha(i) => EvalLeaf::Const(self.inner().alpha(*i, side)),
        }
    }

    pub fn col_try(&self, col: &ExtendedFoldingColumn<CF>, side: Side) -> bool {
        use ExtendedFoldingColumn::*;
        let (_instance, witness) = match side {
            Side::Left => (&self.instances[0], &self.witnesses[0]),
            Side::Right => (&self.instances[1], &self.witnesses[1]),
        };
        match col {
            WitnessExtended(i) => witness.inner().extended.get(i).is_some(),
            Error => panic!("shouldn't happen"),
            Inner(_)
            | Shift
            | UnnormalizedLagrangeBasis(_)
            | Constant(_)
            | Challenge(_)
            | Alpha(_) => true,
        }
    }

    pub fn add_witness_evals(&mut self, i: usize, evals: Vec<Fi<CF>>, side: Side) {
        let (_instance, witness) = match side {
            Side::Left => (&self.instances[0], &mut self.witnesses[0]),
            Side::Right => (&self.instances[1], &mut self.witnesses[1]),
        };
        let evals = Evaluations::from_vec_and_domain(evals, self.domain);
        witness.inner_mut().add_witness_evals(i, evals);
    }

    /// computes the extended witness column and the corresponding commitments,
    /// updating the innner instance/witness pairs
    pub fn compute_extension(
        self,
        witness_generator: &ExtendedWitnessGenerator<CF>,
        srs: &CF::Srs,
    ) -> Self {
        let env = self;
        let env = witness_generator.compute_extended_witness(env, Side::Left);
        let env = witness_generator.compute_extended_witness(env, Side::Right);
        let env = env.compute_extended_commitments(srs, Side::Left);
        let env = env.compute_extended_commitments(srs, Side::Right);
        env
    }

    fn compute_extended_commitments(mut self, srs: &CF::Srs, side: Side) -> Self {
        let (instance, witness) = match side {
            Side::Left => (&mut self.instances[0], &self.witnesses[0]),
            Side::Right => (&mut self.instances[1], &self.witnesses[1]),
        };

        for (expected_i, (i, wit)) in witness.inner().extended.iter().enumerate() {
            //in case any where to be missing for some reason
            assert_eq!(*i, expected_i);
            let commit = srs.commit_evaluations_non_hiding(self.domain, wit);
            instance.inner_mut().extended.push(commit)
        }
        self
    }
}
