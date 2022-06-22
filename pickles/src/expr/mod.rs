use std::collections::HashMap;

use kimchi::circuits::expr::{CacheId, Column, ConstantExpr, Expr, Op2, Variable};
use kimchi::circuits::gate::{CurrOrNext, GateType};
use kimchi::circuits::lookup::constraints::ZK_ROWS;

use circuit_construction::{Constants, Cs, Var};

use ark_ff::{FftField, PrimeField};
use ark_poly::Radix2EvaluationDomain as Domain;

use crate::plonk::proof::VarEvaluations;

pub struct Assignments<F: FftField + PrimeField> {
    // verifier challenges
    alpha: Var<F>,
    beta: Var<F>,
    gamma: Var<F>,
    // circuit constants, e.g. Poseidon round constants
    constant: Constants<F>,
}

/// Enables the evaluation of an Expr types into constraints.
/// This is used to enforce row/gate constraints using the Expr's provided by Kimchi
/// (which contains the gate descriptions).
pub struct Evaluator<'a, F: FftField + PrimeField> {
    domain: Domain<F>,                  // FFT domain
    zeta: Var<F>,                       // evaluation point, called "pt" in Kimchi; it is \zeta
    cache: HashMap<CacheId, Var<F>>,    // cached evaluations of sub-expressions
    evaluations: &'a VarEvaluations<F>, // openings of polynomial commitments at (\zeta, \zeta\omega)
    assignment: Assignments<F>,         //
}

impl<'a, F: FftField + PrimeField> Evaluator<'a, F> {
    pub fn new(
        zeta: Var<F>,
        domain: Domain<F>,
        assignment: Assignments<F>,
        evaluations: &'a VarEvaluations<F>,
    ) -> Self {
        Evaluator {
            zeta,
            domain,
            cache: HashMap::new(),
            assignment,
            evaluations,
        }
    }

    // TODO: This can be further optimized by propergating
    // constants and evaluating these at circuit compile time.
    fn eval_const<C: Cs<F>>(&self, cs: &mut C, const_expr: &ConstantExpr<F>) -> Var<F> {
        match const_expr {
            // Variables
            ConstantExpr::Alpha => self.assignment.alpha,
            ConstantExpr::Beta => self.assignment.beta,
            ConstantExpr::Gamma => self.assignment.gamma,
            ConstantExpr::JointCombiner => unimplemented!(), // for Plookup

            // Constants
            ConstantExpr::EndoCoefficient => cs.constant(self.assignment.constant.endo),
            ConstantExpr::Mds { row, col } => {
                cs.constant(self.assignment.constant.poseidon.mds[*row][*col])
            }
            ConstantExpr::Literal(value) => cs.constant(*value),

            // Arithmetic
            ConstantExpr::Pow(expr, n) => {
                let res = self.eval_const(cs, expr);
                cs.pow(res, *n)
            }
            ConstantExpr::Add(expr1, expr2) => {
                let res1 = self.eval_const(cs, expr1);
                let res2 = self.eval_const(cs, expr2);
                cs.add(res1, res2)
            }
            ConstantExpr::Mul(expr1, expr2) => {
                let res1 = self.eval_const(cs, expr1);
                let res2 = self.eval_const(cs, expr2);
                cs.mul(res1, res2)
            }
            ConstantExpr::Sub(expr1, expr2) => {
                let res1 = self.eval_const(cs, expr1);
                let res2 = self.eval_const(cs, expr2);
                cs.sub(res1, res2)
            }
        }
    }

    fn eval_variable(&self, variable: &Variable) -> &'a Var<F> {
        // select the right row (evaluation point)
        let evals = match variable.row {
            CurrOrNext::Curr => &self.evaluations.zeta, // evaluation at \zeta
            CurrOrNext::Next => &self.evaluations.zetaw, // evaluations at \zeta\omega
        };

        // select the right column (which evaluation)
        // note: we deref polynomial evaluations with 1 chunk to Var
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

    /// Evaluates the polynomial
    /// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
    fn eval_vanishes_on_last_4_rows<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        let w4: F = self
            .domain
            .group_gen
            .pow(&[self.domain.size - (ZK_ROWS as u64 + 1)]);
        let w3: F = self.domain.group_gen * w4;
        let w2: F = self.domain.group_gen * w3;
        let w1: F = self.domain.group_gen * w2;

        // Done using 2 generic gates and mul
        //
        // (x - w1) * (x - w2) * (x - w3) * (x - w4)
        //
        // Split:
        //
        // a = (x - w1) * (x - w2) = x^2 + w1*w2 - x*(w1 + w2)
        // b = (x - w3) * (x - w4) = x^2 + w3*w4 - x*(w3 + w4)
        // return a*b
        let a = cs.generic_gate(self.zeta, self.zeta, -w1, -w2, F::one(), w1 * w2);
        let b = cs.generic_gate(self.zeta, self.zeta, -w3, -w4, F::one(), w3 * w4);
        cs.mul(a, b)
    }

    /// Evaluates the vanishing polynomial of the domain at self.zeta
    /// i.e. f(X) = X^{|<\omega>|} - 1
    fn eval_vanishing_polynomial<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        assert!(self.domain.size.is_power_of_two());
        let pow = cs.pow(self.zeta, self.domain.size);
        let one = cs.constant(F::one());
        cs.sub(pow, one)
    }

    /// Generate the constraints for a expression and
    /// return the variable corresponding to its execution
    pub fn eval_expr<C: Cs<F>>(&mut self, cs: &mut C, expr: &Expr<ConstantExpr<F>>) -> Var<F> {
        match expr {
            Expr::Constant(const_expr) => self.eval_const(cs, const_expr),
            Expr::Pow(expr, n) => {
                let base = self.eval_expr(cs, &expr);
                cs.pow(base, *n)
            }
            Expr::Double(expr) => {
                let res = self.eval_expr(cs, expr);
                cs.add(res, res)
            }
            Expr::Square(expr) => {
                let res = self.eval_expr(cs, expr);
                cs.mul(res, res)
            }
            Expr::BinOp(Op2::Mul, expr1, expr2) => {
                let res1 = self.eval_expr(cs, &expr1);
                let res2 = self.eval_expr(cs, &expr2);
                cs.mul(res1, res2)
            }
            Expr::BinOp(Op2::Add, expr1, expr2) => {
                let res1 = self.eval_expr(cs, &expr1);
                let res2 = self.eval_expr(cs, &expr2);
                cs.add(res1, res2)
            }
            Expr::BinOp(Op2::Sub, expr1, expr2) => {
                let res1 = self.eval_expr(cs, &expr1);
                let res2 = self.eval_expr(cs, &expr2);
                cs.sub(res1, res2)
            }
            Expr::VanishesOnLast4Rows => self.eval_vanishes_on_last_4_rows(cs),
            Expr::UnnormalizedLagrangeBasis(i) => {
                // \omega^i
                let w_pow_i = cs.constant(self.domain.group_gen.pow(&[*i as u64]));

                // evaluate vanishing polynomial
                let num = self.eval_vanishing_polynomial(cs);

                // compute normalization term
                let denom = cs.sub(self.zeta, w_pow_i);

                // return num/denom (assumes denom != 0, if not completness fails)
                cs.div(num, denom)
            }
            Expr::Cell(variable) => self.eval_variable(variable).clone(),
            Expr::Cache(id, expr) => {
                // check cache
                if let Some(entry) = self.cache.get(id) {
                    return entry.clone();
                }

                // otherwise, evaluate and cache result
                let res = self.eval_expr(cs, expr);
                self.cache.insert(*id, res);
                res
            }
        }
    }
}
