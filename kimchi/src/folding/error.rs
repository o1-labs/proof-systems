use super::expressions::{FoldingExp, IntegratedFoldingExpr};
use super::{FoldingConfig, FoldingEnv, RelaxedInstance, RelaxedWitness};
use crate::folding::expressions::{Degree, ExtendedFoldingColumn};
use crate::folding::EvalLeaf;
use ark_ec::AffineCurve;
use ark_ff::Field;

#[derive(Clone, Copy)]
pub enum Side {
    Left,
    Right,
}
impl std::ops::Not for Side {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        }
    }
}
type Fi<C> = <<C as FoldingConfig>::Curve as AffineCurve>::ScalarField;

pub(crate) fn eval_exp_error<'a, C: FoldingConfig>(
    exp: &FoldingExp<C>,
    env: &'a ExtendedEnv<C>,
    side: Side,
) -> EvalLeaf<'a, Fi<C>> {
    let degree = exp.folding_degree();
    use FoldingExp::*;

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
            let a = eval_exp_error(e1, env, side);
            let b = eval_exp_error(e2, env, side);
            EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b)
        }
        Sub(e1, e2) => {
            let a = eval_exp_error(e1, env, side);
            let b = eval_exp_error(e2, env, side);
            EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b)
        }
        Mul(e1, e2) => match (degree, e1.folding_degree()) {
            (Degree::Two, Degree::One) => {
                let a = eval_exp_error(e1, env, side);
                let b = eval_exp_error(e2, env, !side);
                let first = EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b);
                let a = eval_exp_error(e1, env, !side);
                let b = eval_exp_error(e2, env, side);
                let second = EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b);
                EvalLeaf::bin_op(first, second, |a, b| *a + b, |a, b| *a += b)
            }
            _ => {
                let a = eval_exp_error(e1, env, side);
                let b = eval_exp_error(e2, env, side);
                EvalLeaf::bin_op(a, b, |a, b| *a * b, |a, b| *a *= b)
            }
        },
    }
}

pub(crate) fn compute_error<C: FoldingConfig>(
    exp: &IntegratedFoldingExpr<C>,
    env: &ExtendedEnv<C>,
    u: (Fi<C>, Fi<C>),
) -> Vec<Fi<C>> {
    let add = |a, b| EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b);
    let sub = |a, b| EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b);
    let scale = |t, s| EvalLeaf::bin_op(t, EvalLeaf::Const(s), |a, b| *a * b, |a, b| *a *= b);

    let t_0 = EvalLeaf::Result(env.inner().zero_vec());
    let t_0 = exp.degree_0.iter().fold(t_0, |t_0, (exp, sign)| {
        //could be left or right, doesn't matter for constant terms
        let e = eval_exp_error(exp, env, Side::Left);
        if *sign {
            add(t_0, e)
        } else {
            sub(t_0, e)
        }
    });
    let t_0 = scale(t_0, (u.0 * u.1).double());

    let t_1l = EvalLeaf::Result(env.inner().zero_vec());
    let t_1r = EvalLeaf::Result(env.inner().zero_vec());
    let (t_1l, t_1r) = exp
        .degree_1
        .iter()
        .fold((t_1l, t_1r), |(t_1l, t_1r), (exp, sign)| {
            let el = eval_exp_error(exp, env, Side::Left);
            let er = eval_exp_error(exp, env, Side::Right);
            if *sign {
                (add(t_1l, el), add(t_1r, er))
            } else {
                (sub(t_1l, el), sub(t_1r, er))
            }
        });
    let t_1l = scale(t_1l, u.1);
    let t_1r = scale(t_1r, u.0);
    let t_1 = EvalLeaf::bin_op(t_1l, t_1r, |a, b| *a + b, |a, b| *a += b);

    let t_2 = EvalLeaf::Result(env.inner().zero_vec());
    let t_2 = exp.degree_2.iter().fold(t_2, |t_2, (exp, sign)| {
        //left or right matter in some way, but not at the top level call
        let e = eval_exp_error(exp, env, Side::Left);
        if *sign {
            add(t_2, e)
        } else {
            sub(t_2, e)
        }
    });
    let t = add(add(t_0, t_1), t_2);

    match t {
        EvalLeaf::Result(res) => res,
        _ => unreachable!(),
    }
}

type Evals<C> = Vec<<<C as FoldingConfig>::Curve as AffineCurve>::ScalarField>;
pub(crate) struct ExtendedEnv<'a, CF: FoldingConfig> {
    inner: CF::Env,
    instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
    witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
    shift: &'a Evals<CF>,
}

impl<'a, CF: FoldingConfig> ExtendedEnv<'a, CF> {
    pub fn new(
        structure: &CF::Structure,
        //maybe better to have some structure exteded or something like that
        shift: &'a Evals<CF>,
        instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
        witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
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
        }
    }
    pub fn inner(&self) -> &CF::Env {
        &self.inner
    }
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
        let (instance, witness) = match side {
            Side::Left => (&self.instances[0], &self.witnesses[0]),
            Side::Right => (&self.instances[1], &self.witnesses[1]),
        };
        match col {
            Inner(col) => Col(self.inner().col(*col, side)),
            WitnessExtended(i) => Col(witness
                .inner()
                .extended
                .get(*i)
                .expect("extended column not present")),
            Error => panic!("shouldn't happen"),
            Shift => Col(self.shift),
            ///handle todos
            UnnormalizedLagrangeBasis(i) => Col(self.inner().lagrange_basis(*i)),
            Constant(c) => EvalLeaf::Const(*c),
            Challenge(chall) => EvalLeaf::Const(self.inner().challenge(*chall)),
            Alpha(_) => todo!(),
        }
    }
}
