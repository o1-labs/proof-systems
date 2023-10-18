use super::expressions::{FoldingExp, IntegratedFoldingExpr};
use super::FoldingEnv;
use crate::folding::expressions::{Degree, FoldingColumn};
use crate::folding::EvalLeaf;
use ark_ff::Field;

pub(crate) fn eval_exp_error<'a, F: Field, E: FoldingEnv<F>>(
    exp: &FoldingExp<F>,
    env: &'a E,
    side: bool,
) -> EvalLeaf<'a, F> {
    let degree = exp.degree();
    use EvalLeaf::*;
    use FoldingColumn::*;
    use FoldingExp::*;

    match exp {
        Constant(c) => EvalLeaf::Const(*c),
        Cell(col) => match col {
            Witness(i) => Col(env.witness(*i, side)),
            WitnessExtended(i) => Col(env.witness_ext(*i, side)),
            Index(i) => Col(env.index(i)),
            Coefficient(i) => Col(env.coefficient(*i)),
            //TODO: maybe specialize
            Shift => Col(env.shift()),
        },
        Double(e) => {
            let col = eval_exp_error(e, env, side);
            col.map(Field::double, |f| {
                Field::double_in_place(f);
            })
        }
        FoldingExp::Square(e) => {
            let col = eval_exp_error(e, env, side);
            col.map(Field::square, |f| {
                Field::square_in_place(f);
            })
        }
        FoldingExp::Add(e1, e2) => {
            let a = eval_exp_error(e1, env, side);
            let b = eval_exp_error(e2, env, side);
            EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b)
        }
        FoldingExp::Sub(e1, e2) => {
            let a = eval_exp_error(e1, env, side);
            let b = eval_exp_error(e2, env, side);
            EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b)
        }
        FoldingExp::Mul(e1, e2) => match (degree, e1.degree()) {
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
        FoldingExp::UnnormalizedLagrangeBasis(i) => EvalLeaf::Result(env.lagrange_basis(i)),
        //TODO: use cache
        FoldingExp::Cache(_id, exp) => eval_exp_error(exp, env, side),
    }
}

pub(crate) fn compute_error<'a, F: Field, E: FoldingEnv<F>>(
    exp: &IntegratedFoldingExpr<F>,
    env: &'a E,
    u: (F, F),
) -> Vec<F> {
    let add = |a, b| EvalLeaf::bin_op(a, b, |a, b| *a + b, |a, b| *a += b);
    let sub = |a, b| EvalLeaf::bin_op(a, b, |a, b| *a - b, |a, b| *a -= b);
    let scale = |t, s| EvalLeaf::bin_op(t, EvalLeaf::Const(s), |a, b| *a * b, |a, b| *a *= b);

    let t_0 = EvalLeaf::Result(env.zero_vec());
    let t_0 = exp.degree_0.iter().fold(t_0, |t_0, (exp, sign)| {
        //could be true or false, doesn't matter for constant terms
        let e = eval_exp_error(exp, env, true);
        if *sign {
            add(t_0, e)
        } else {
            sub(t_0, e)
        }
    });
    let t_0 = scale(t_0, (u.0 * u.1).double());

    let t_1l = EvalLeaf::Result(env.zero_vec());
    let t_1r = EvalLeaf::Result(env.zero_vec());
    let (t_1l, t_1r) = exp
        .degree_0
        .iter()
        .fold((t_1l, t_1r), |(t_1l, t_1r), (exp, sign)| {
            let el = eval_exp_error(exp, env, true);
            let er = eval_exp_error(exp, env, false);
            if *sign {
                (add(t_1l, el), add(t_1r, er))
            } else {
                (sub(t_1l, el), sub(t_1r, er))
            }
        });
    let t_1l = scale(t_1l, u.1);
    let t_1r = scale(t_1r, u.0);
    let t_1 = EvalLeaf::bin_op(t_1l, t_1r, |a, b| *a + b, |a, b| *a += b);

    let t_2 = EvalLeaf::Result(env.zero_vec());
    let t_2 = exp.degree_0.iter().fold(t_2, |t_2, (exp, sign)| {
        //true or false matter in some way, but not at the top level call
        let e = eval_exp_error(exp, env, true);
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
