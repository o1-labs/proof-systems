use kimchi::circuits::expr::{ConstantExpr, Expr, Op2};
// use kimchi::circuits::polynomials::permutations::ZK_ROWS;
use circuit_construction::{Cs, Var};

use ark_ff::{FftField, PrimeField};
use ark_poly::Radix2EvaluationDomain as D;

const ZK_ROWS: u64 = 3;

/// Evaluates the polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
fn eval_vanishes_on_last_4_rows<F: FftField>(d: D<F>, x: Var<F>) -> Var<F> {
    let w4 = d.group_gen.pow(&[d.size - (ZK_ROWS + 1)]);
    let w3 = d.group_gen * w4;
    let w2 = d.group_gen * w3;
    let w1 = d.group_gen * w2;
    // (x - w1) * (x - w2) * (x - w3) * (x - w4)

    unimplemented!()
}

/*
struct ExprVar {
    alpha: Var<F>,
    beta: Var<F>,
}

fn symbolic_eval_const(
    const_expr: ConstantExpr<F>,
    var: &ExprVar,
) -> Var<F> {
    unimplemented!()
}

/// Derive constraints for an expression
fn symbolic_eval<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    d: D<F>,
    pt: Var<F>,
    expr: &Expr<ConstantExpr<F>>,
    var: &ExprVar,
) -> Var<F> {
    match expr {
        Expr::Constant(x) => symbolic_eval_const(x, var),
        Expr::Pow(x, p) => symbolic_eval(cs, d, pt, &x, openings), // .pow(p),
        Expr::Double(x) => {
            let x = symbolic_eval(cs, d, pt, &x, openings);
            cs.add(x, x)
        }
        Expr::Square(x) => {
            let x = symbolic_eval(cs, d, pt, &x, openings);
            cs.mul(x, x)
        }
        Expr::BinOp(Op2::Mul, x, y) => {
            let x = symbolic_eval(cs, d, pt, &x, openings);
            let y = symbolic_eval(cs, d, pt, &y, openings);
            cs.mul(x, y)
        }
        Expr::BinOp(Op2::Add, x, y) => {
            let x = symbolic_eval(cs, d, pt, &x, openings);
            let y = symbolic_eval(cs, d, pt, &y, openings);
            cs.add(x, y)
        }
        VanishesOnLast4Rows => {
            eval_vanishes_on_last_4_rows(d, pt)
        }
        _ => unimplemented!(),
        /*
        Pow(x, p) => Ok(x.evaluate(d, pt, evals)?.pow(&[*p as u64])),
        Double(x) => x.evaluate(d, pt, evals).map(|x| x.double()),
        Square(x) => x.evaluate(d, pt, evals).map(|x| x.square()),
        BinOp(Op2::Mul, x, y) => {
            let x = (*x).evaluate(d, pt, evals)?;
            let y = (*y).evaluate(d, pt, evals)?;
            Ok(x * y)
        }
        BinOp(Op2::Add, x, y) => {
            let x = (*x).evaluate(d, pt, evals)?;
            let y = (*y).evaluate(d, pt, evals)?;
            Ok(x + y)
        }
        BinOp(Op2::Sub, x, y) => {
            let x = (*x).evaluate(d, pt, evals)?;
            let y = (*y).evaluate(d, pt, evals)?;
            Ok(x - y)
        }
        VanishesOnLast4Rows => Ok(eval_vanishes_on_last_4_rows(d, pt)),
        UnnormalizedLagrangeBasis(i) => {
            Ok(d.evaluate_vanishing_polynomial(pt) / (pt - d.group_gen.pow(&[*i as u64])))
        }
        Cell(v) => v.evaluate(evals),
        Cache(_, e) => e.evaluate(d, pt, evals),
        */
    }
}
*/
