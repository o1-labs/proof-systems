use std::collections::HashMap;
use std::collections::hash_map::Entry;

use kimchi::circuits::expr::{Column, ConstantExpr, CacheId, Expr, Op2, Variable};
use kimchi::circuits::gate::{CurrOrNext, GateType};

// use kimchi::circuits::polynomials::permutations::ZK_ROWS;
use circuit_construction::{Cs, Var};

use ark_ff::{FftField, PrimeField};
use ark_poly::Radix2EvaluationDomain as D;

use super::proof::{VarEvaluation, VarEvaluations};

const ZK_ROWS: u64 = 3;


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

        // Arithmetic
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

fn symbolic_eval_variable<'a, F: FftField + PrimeField>(
    variable: &Variable,
    evaluations: &'a VarEvaluations<F>,
) -> &'a Var<F> {
    // select the right row (evaluation point)
    let evals = match variable.row {
        CurrOrNext::Curr => &evaluations.z,  // evaluation at \zeta
        CurrOrNext::Next => &evaluations.zw, // evaluations at \zeta\omega
    };

    // select the right column (which evaluation)
    match variable.col {
        // Witness evaluations
        Column::Witness(i) => evals.w[i].as_ref(),
        Column::Z => evals.z.as_ref(),

        // Lookup / Plookup Related Evaluations
        Column::LookupSorted(i) => unimplemented!("plookup not impl."),
        Column::LookupAggreg => unimplemented!("plookup not impl."),
        Column::LookupTable => unimplemented!("plookup not impl."),

        // Evaluations from the index
        Column::Index(GateType::Poseidon) => evals.poseidon_selector.as_ref(),
        Column::Index(GateType::Generic) => evals.generic_selector.as_ref(),

        // Cairo support (TODO)
        Column::Index(GateType::CairoClaim)
        | Column::Index(GateType::CairoInstruction)
        | Column::Index(GateType::CairoFlags)
        | Column::Index(GateType::CairoTransition) => todo!(),

        _ => unimplemented!(),
    }
}

struct ExprEvaluator<'a, F: FftField + PrimeField> {
    d: D<F>,
    pt: Var<F>,
    cache: HashMap<CacheId, Var<F>>,
    evaluations: &'a VarEvaluations<F>,
    assignment: &'a Assignments<F>,
}

impl <'a, F: FftField + PrimeField> ExprEvaluator<'a, F> {
        
    /// Evaluates the polynomial
    /// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
    fn eval_vanishes_on_last_4_rows<C: Cs<F>>(
        &self,
        cs: &mut C,
    ) -> Var<F> {
        let w4: F = self.d.group_gen.pow(&[self.d.size - (ZK_ROWS + 1)]);
        let w3: F = self.d.group_gen * w4;
        let w2: F = self.d.group_gen * w3;
        let w1: F = self.d.group_gen * w2;

        // Done using 2 generic gates and mul
        //
        // (x - w1) * (x - w2) * (x - w3) * (x - w4)
        //
        // Split:
        //
        // a = (x - w1) * (x - w2) = x^2 + w1*w2 - x*(w1 + w2)
        // b = (x - w3) * (x - w4) = x^2 + w3*w4 - x*(w3 + w4)
        // return a*b
        let a = cs.generic_gate(self.pt, self.pt, -w1, -w2, F::one(), w1 * w2);
        let b = cs.generic_gate(self.pt, self.pt, -w3, -w4, F::one(), w3 * w4);
        cs.mul(a, b)
    }

    /// Evaluates the vanishing polynomial of the domain at self.pt
    /// i.e. f(X) = X^{|<\omega>|} - 1
    fn eval_vanishing_polynomial<C: Cs<F>>(
        &self,
        cs: &mut C,
    ) -> Var<F> {
        assert!(self.d.size.is_power_of_two());
        let pow = cs.pow(self.pt, self.d.size);
        let one = cs.constant(F::one());
        cs.sub(pow, one)
    }
    fn eval<C: Cs<F>>(&mut self, cs: &mut C, expr: &Expr<ConstantExpr<F>>) -> Var<F> {
        match expr {
            Expr::Constant(const_expr) => symbolic_eval_const(cs, const_expr, &self.assignment),
            Expr::Pow(expr, n) => {
                let base = self.eval(cs, &expr);
                cs.pow(base, *n)
            }
            Expr::Double(expr) => {
                let eval = self.eval(cs, expr);
                cs.add(eval, eval)
            }
            Expr::Square(expr) => {
                let eval = self.eval(cs, expr);
                cs.mul(eval, eval)
            }
            Expr::BinOp(Op2::Mul, expr1, expr2) => {
                let x = self.eval(cs, &expr1);
                let y = self.eval(cs, &expr2);
                cs.mul(x, y)
            }
            Expr::BinOp(Op2::Add, expr1, expr2) => {
                let x = self.eval(cs, &expr1);
                let y = self.eval(cs, &expr2);
                cs.add(x, y)
            }
            Expr::VanishesOnLast4Rows => 
                self.eval_vanishes_on_last_4_rows(cs),
            Expr::UnnormalizedLagrangeBasis(i) => {
                // \omega^i
                let w_pow_i = cs.constant(self.d.group_gen.pow(&[*i as u64]));
                
                // evaluate vanishing polynomial:
                // i.e. f(X) = X^{|<\omega>|} - 1
                let num = self.eval_vanishing_polynomial(cs);
                let denom = cs.sub(self.pt, w_pow_i);

                // witness 
                // num / denom
                unimplemented!()
            }
            Expr::Cell(variable) => symbolic_eval_variable(variable, &self.evaluations).clone(),
            Expr::Cache(id, expr) => {
                // check cache
                if let Some(entry) = self.cache.get(id) {
                    return entry.clone()
                }

                // otherwise, evaluate and cache result
                let expr = self.eval(cs, expr);
                self.cache.insert(*id, expr);
                expr
            }
            _ => unimplemented!(),
        }
    }
}

/*
/// Derive constraints for an expression
fn symbolic_eval<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    d: D<F>,
    pt: Var<F>,
    expr: &Expr<ConstantExpr<F>>,
    evaluations: &VarEvaluations<F>,
    assignment: &Assignments<F>,
) -> Var<F> {
    match expr {
        Expr::Constant(const_expr) => symbolic_eval_const(cs, const_expr, assignment),
        Expr::Pow(expr, n) => {
            let base = symbolic_eval(cs, d, pt, &expr, evaluations, assignment);
            cs.pow(base, *n)
        }
        Expr::Double(expr) => {
            let eval = symbolic_eval(cs, d, pt, expr, evaluations, assignment);
            cs.add(eval, eval)
        }
        Expr::Square(expr) => {
            let eval = symbolic_eval(cs, d, pt, expr, evaluations, assignment);
            cs.mul(eval, eval)
        }
        Expr::BinOp(Op2::Mul, expr1, expr2) => {
            let x = symbolic_eval(cs, d, pt, &expr1, evaluations, assignment);
            let y = symbolic_eval(cs, d, pt, &expr2, evaluations, assignment);
            cs.mul(x, y)
        }
        Expr::BinOp(Op2::Add, expr1, expr2) => {
            let x = symbolic_eval(cs, d, pt, &expr1, evaluations, assignment);
            let y = symbolic_eval(cs, d, pt, &expr2, evaluations, assignment);
            cs.add(x, y)
        }
        Expr::VanishesOnLast4Rows => eval_vanishes_on_last_4_rows(cs, d, pt),
        Expr::Cell(variable) => symbolic_eval_variable(variable, evaluations).clone(),
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