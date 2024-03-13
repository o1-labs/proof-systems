use ark_ff::{Field, PrimeField, Zero};
use kimchi::circuits::{
    expr::{ChallengeTerm, ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

use crate::{
    columns::Column,
    expr::{curr_cell, E},
    serialization::N_INTERMEDIATE_LIMBS,
    MVLookupTableID as _, N_LIMBS,
};

use super::Lookup;
use super::{interpreter::InterpreterEnv, LookupTable};

/// Compute the following constraint:
/// ```text
///                     lhs
///    |------------------------------------------|
///    |                           denominators   |
///    |                         /--------------\ |
/// column * (\prod_{i = 1}^{N} (\beta + f_{i}(X))) =
/// \sum_{i = 1}^{N} m_{i} * \prod_{j = 1, j \neq i}^{N} (\beta + f_{j}(X))
///    |             |--------------------------------------------------|
///    |                             Inner part of rhs                  |
///    |                                                                |
///    |                                                               /
///     \                                                             /
///      \                                                           /
///       \---------------------------------------------------------/
///                           rhs
/// ```
pub fn combine_lookups<F: Field>(column: Column, lookups: Vec<Lookup<E<F>>>) -> E<F> {
    let joint_combiner = {
        let joint_combiner = ConstantExpr::from(ChallengeTerm::JointCombiner);
        E::Atom(ExprInner::Constant(joint_combiner))
    };
    let beta = {
        let beta = ConstantExpr::from(ChallengeTerm::Beta);
        E::Atom(ExprInner::Constant(beta))
    };

    // Compute (\beta + f_{i}(X)) for each i.
    // Note that f_i(X) = x_{0} + r x_{1} + ... r^{N} x_{N} + r^{N + 1} table_id
    let denominators = lookups
        .iter()
        .map(|x| {
            let combined_value = (x
                .value
                .iter()
                .rev()
                .fold(E::zero(), |acc, y| acc * joint_combiner.clone() + y.clone())
                * joint_combiner.clone())
                + x.table_id.to_constraint();
            beta.clone() + combined_value
        })
        .collect::<Vec<_>>();
    // Compute `column * (\prod_{i = 1}^{N} (\beta + f_{i}(X)))`
    let lhs = denominators
        .iter()
        .fold(curr_cell(column), |acc, x| acc * x.clone());
    let rhs = lookups
        .into_iter()
        .enumerate()
        .map(|(i, x)| {
            denominators.iter().enumerate().fold(
                // Compute individual \sum_{j = 1, j \neq i}^{N} f_{j}(X)
                // This is the inner part of rhs. It multiplies with m_{i}
                x.numerator,
                |acc, (j, y)| {
                    if i == j {
                        acc
                    } else {
                        acc * y.clone()
                    }
                },
            )
        })
        // Individual sums
        .reduce(|x, y| x + y)
        .unwrap_or(E::zero());
    lhs - rhs
}

pub struct Env<Fp: PrimeField> {
    /// An indexed set of constraints.
    /// The index can be used to differentiate the constraints used by different
    /// calls to the interpreter function, and let the callers ordered them for
    /// folding for instance.
    pub constraints: Vec<(usize, E<Fp>)>,

    pub constrain_index: usize,

    pub rangecheck4_lookups: Vec<Lookup<E<Fp>>>,
    pub rangecheck15_lookups: Vec<Lookup<E<Fp>>>,
}

impl<Fp: PrimeField> Env<Fp> {
    pub fn create() -> Self {
        Self {
            constraints: vec![],
            constrain_index: 0,
            rangecheck4_lookups: vec![],
            rangecheck15_lookups: vec![],
        }
    }
}

impl<F: PrimeField> InterpreterEnv<F> for Env<F> {
    /// Schemas for the columns:
    /// - kimchi_limbs: 0 to 2
    /// - msm_limbs: 3 to 20
    /// - intermediate_limbs: 21 to 40
    /// - lookup_aggreg: 41
    /// - lookup multiplicities: 42 and 43 (2 tables)
    /// - 3 lookup partial sums RC15: 44 to 46
    /// - 4 lookup partial sums RC4: 48 to 51
    type Position = Column;

    type Variable = E<F>;

    fn add_constraint(&mut self, cst: Self::Variable) {
        // FIXME: We should enforce that we add the same expression
        // Maybe we could have a digest of the expression
        let index = self.constrain_index;
        self.constraints.push((index, cst));
        self.constrain_index += 1;
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let y = Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }));
        self.add_constraint(y.clone() - x.clone());
        y
    }

    fn get_column_for_kimchi_limb(j: usize) -> Self::Position {
        assert!(j < 3);
        Column::X(j)
    }

    fn get_column_for_intermediate_limb(j: usize) -> Self::Position {
        assert!(j < N_INTERMEDIATE_LIMBS);
        Column::X(3 + N_LIMBS + j)
    }

    fn get_column_for_msm_limb(j: usize) -> Self::Position {
        assert!(j < N_LIMBS);
        Column::X(3 + j)
    }

    fn range_check15(&mut self, value: &Self::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        self.rangecheck15_lookups.push(Lookup {
            table_id: LookupTable::RangeCheck15,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        })
    }

    fn range_check4(&mut self, value: &Self::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        self.rangecheck4_lookups.push(Lookup {
            table_id: LookupTable::RangeCheck4,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        })
    }

    fn constant(value: F) -> Self::Variable {
        let cst_expr_inner = ConstantExpr::from(ConstantTerm::Literal(value));
        Expr::Atom(ExprInner::Constant(cst_expr_inner))
    }

    /// Extract the bits from the variable `x` between `highest_bit` (excluded)
    /// and `lowest_bit` (included), and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        // No constraint added. It is supposed that the caller will constraint
        // later the returned variable and/or do a range check.
        curr_cell(position)
    }
}

impl<Fp: PrimeField> Env<Fp> {
    #[allow(dead_code)]
    fn constrain_lookups(&self) -> Vec<E<Fp>> {
        // FIXME
        let cst_expr_inner = ConstantExpr::from(ConstantTerm::Literal(Fp::zero()));
        let x = Expr::Atom(ExprInner::Constant(cst_expr_inner));
        vec![x]

        // TODO: individual lookup partial term
        // TODO: lookup aggregation
        // TODO: lookup multiplicities
        // 0 to 6, RC4
    }
}
