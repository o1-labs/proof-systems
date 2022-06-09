use kimchi::circuits::expr::{ConstantExpr, Expr, Op2};
// use kimchi::circuits::polynomials::permutations::ZK_ROWS;
use circuit_construction::{Cs, Var};

use ark_ff::{FftField, PrimeField};
use ark_poly::Radix2EvaluationDomain as D;

const ZK_ROWS: u64 = 3;

/// Evaluates the polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
fn eval_vanishes_on_last_4_rows<F: FftField + PrimeField, C: Cs<F>>(cs: &mut C, d: D<F>, x: Var<F>) -> Var<F> {
    let w4: F = d.group_gen.pow(&[d.size - (ZK_ROWS + 1)]);
    let w3: F = d.group_gen * w4;
    let w2: F = d.group_gen * w3;
    let w1: F = d.group_gen * w2;

    // Done using 2 generic gates and mul
    //
    // (x - w1) * (x - w2) * (x - w3) * (x - w4)
    //
    // Split:
    //
    // a = (x - w1) * (x - w2) = x^2 + w1*w2 - x*(w1 + w2)
    // b = (x - w3) * (x - w4) = x^2 + w3*w4 - x*(w3 + w4)
    // return a*b
    let a = cs.generic_gate(x, x, -w1, -w2, F::one(), w1*w2);
    let b = cs.generic_gate(x, x, -w3, -w4, F::one(), w3*w4);
    cs.mul(a, b)
}

struct Assignments<F: FftField + PrimeField> {
    alpha: Var<F>,
    beta: Var<F>,
    gamma: Var<F>,
    endo_coefficient: F,
    mds: Vec<Vec<F>>,
}

///
/// TODO: This can be optimized by propergating
/// constants and evaluating these at circuit compile time.
fn symbolic_eval_const<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    const_expr: &ConstantExpr<F>,
    assignment: &Assignments<F>,
) -> Var<F> {
    match const_expr {
        // Variables
        ConstantExpr::Alpha => assignment.alpha,
        ConstantExpr::Beta => assignment.beta,
        ConstantExpr::Gamma => assignment.gamma,
        ConstantExpr::JointCombiner => unimplemented!(), // for Plookup

        // Constants
        ConstantExpr::EndoCoefficient => cs.constant(assignment.endo_coefficient),
        ConstantExpr::Mds { row, col } => cs.constant(assignment.mds[*row][*col]),
        ConstantExpr::Literal(value) => cs.constant(*value),

        // Arithmetic operations
        ConstantExpr::Pow(expr, n) => {
            let expr = symbolic_eval_const(cs, expr, assignment);
            cs.pow(expr, *n)
        }
        ConstantExpr::Add(expr1, expr2) => {
            let expr1 = symbolic_eval_const(cs, expr1, assignment);
            let expr2 = symbolic_eval_const(cs, expr2, assignment);
            cs.add(expr1, expr2)
        }
        ConstantExpr::Mul(expr1, expr2) => {
            let expr1 = symbolic_eval_const(cs, expr1, assignment);
            let expr2 = symbolic_eval_const(cs, expr2, assignment);
            cs.mul(expr1, expr2)
        }
        ConstantExpr::Sub(expr1, expr2) => {
            let expr1 = symbolic_eval_const(cs, expr1, assignment);
            let expr2 = symbolic_eval_const(cs, expr2, assignment);
            cs.sub(expr1, expr2)
        }
    }
}

/// Derive constraints for an expression
fn symbolic_eval<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    d: D<F>,
    pt: Var<F>,
    expr: &Expr<ConstantExpr<F>>,
    assignment: &Assignments<F>,
) -> Var<F> {
    match expr {
        Expr::Constant(const_expr) => symbolic_eval_const(cs, const_expr, assignment),
        Expr::Pow(expr, n) => {
            let base = symbolic_eval(cs, d, pt, &expr, assignment);
            cs.pow(base, *n)
        }
        Expr::Double(expr) => {
            let eval = symbolic_eval(cs, d, pt, expr, assignment);
            cs.add(eval, eval)
        }
        Expr::Square(expr) => {
            let eval = symbolic_eval(cs, d, pt, expr, assignment);
            cs.mul(eval, eval)
        }
        Expr::BinOp(Op2::Mul, expr1, expr2) => {
            let x = symbolic_eval(cs, d, pt, &expr1, assignment);
            let y = symbolic_eval(cs, d, pt, &expr2, assignment);
            cs.mul(x, y)
        }
        Expr::BinOp(Op2::Add, expr1, expr2) => {
            let x = symbolic_eval(cs, d, pt, &expr1, assignment);
            let y = symbolic_eval(cs, d, pt, &expr2, assignment);
            cs.add(x, y)
        }
        VanishesOnLast4Rows => eval_vanishes_on_last_4_rows(cs, d, pt),
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
