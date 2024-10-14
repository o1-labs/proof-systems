//! This module defines the particular form of the expressions used in the Mina
//! Berkeley hardfork. You can find more information in [this blog
//! article](https://www.o1labs.org/blog/reintroducing-kimchi).
//! This module is also a good starting point if you want to implement your own
//! variant of Kimchi using the expression framework.
//!
//! The module uses the generic expression framework defined in the
//! [crate::circuits::expr] module.
//! The expressions define the polynomials that can be used to describe the
//! constraints.
//! It starts by defining the different challenges used by the PLONK IOP in
//! [BerkeleyChallengeTerm] and [BerkeleyChallenges].
//! It then defines the [Column] type which represents the different variables
//! the polynomials are defined over.
//!
//! Two "environments" are after that defined: one for the lookup argument
//! [LookupEnvironment], and one for the main argument [Environment], which
//! contains the former.
//! The trait [ColumnEnvironment] is then defined to provide the necessary
//! primitives used to evaluate the quotient polynomial.

use crate::{
    circuits::{
        domains::EvaluationDomains,
        expr::{
            CacheId, ColumnEnvironment, ColumnEvaluations, ConstantExpr, ConstantTerm, Constants,
            Domain, Expr, ExprError, FormattedOutput,
        },
        gate::{CurrOrNext, GateType},
        lookup::{index::LookupSelectors, lookups::LookupPattern},
        polynomials::foreign_field_common::KimchiForeignElement,
        wires::COLUMNS,
    },
    proof::{PointEvaluations, ProofEvaluations},
};
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub},
};

/// The challenge terms used in Berkeley.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BerkeleyChallengeTerm {
    /// Used to combine constraints
    Alpha,
    /// The first challenge used in the permutation argument
    Beta,
    /// The second challenge used in the permutation argument
    Gamma,
    /// A challenge used to columns of a lookup table
    JointCombiner,
}

impl std::fmt::Display for BerkeleyChallengeTerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BerkeleyChallengeTerm::*;
        let str = match self {
            Alpha => "alpha".to_string(),
            Beta => "beta".to_string(),
            Gamma => "gamma".to_string(),
            JointCombiner => "joint_combiner".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl<'a> super::expr::AlphaChallengeTerm<'a> for BerkeleyChallengeTerm {
    const ALPHA: Self = Self::Alpha;
}

pub struct BerkeleyChallenges<F> {
    /// The challenge α from the PLONK IOP.
    pub alpha: F,
    /// The challenge β from the PLONK IOP.
    pub beta: F,
    /// The challenge γ from the PLONK IOP.
    pub gamma: F,
    /// The challenge joint_combiner which is used to combine joint lookup
    /// tables.
    pub joint_combiner: F,
}

impl<F: ark_ff::Field> std::ops::Index<BerkeleyChallengeTerm> for BerkeleyChallenges<F> {
    type Output = F;

    fn index(&self, challenge_term: BerkeleyChallengeTerm) -> &Self::Output {
        match challenge_term {
            BerkeleyChallengeTerm::Alpha => &self.alpha,
            BerkeleyChallengeTerm::Beta => &self.beta,
            BerkeleyChallengeTerm::Gamma => &self.gamma,
            BerkeleyChallengeTerm::JointCombiner => &self.joint_combiner,
        }
    }
}

/// A type representing the variables involved in the constraints of the
/// Berkeley hardfork.
///
/// In Berkeley, the constraints are defined over the following variables:
/// - The [COLUMNS] witness columns.
/// - The permutation polynomial, Z.
/// - The public coefficients, `Coefficients`, which can be used for public
/// values. For instance, it is used for the Poseidon round constants.
/// - ...
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Column {
    Witness(usize),
    Z,
    LookupSorted(usize),
    LookupAggreg,
    LookupTable,
    LookupKindIndex(LookupPattern),
    LookupRuntimeSelector,
    LookupRuntimeTable,
    Index(GateType),
    Coefficient(usize),
    Permutation(usize),
}

impl FormattedOutput for Column {
    fn is_alpha(&self) -> bool {
        // FIXME. Unused at the moment
        unimplemented!()
    }

    fn ocaml(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        // FIXME. Unused at the moment
        unimplemented!()
    }

    fn latex(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Witness(i) => format!("w_{{{i}}}"),
            Column::Z => "Z".to_string(),
            Column::LookupSorted(i) => format!("s_{{{i}}}"),
            Column::LookupAggreg => "a".to_string(),
            Column::LookupTable => "t".to_string(),
            Column::LookupKindIndex(i) => format!("k_{{{i:?}}}"),
            Column::LookupRuntimeSelector => "rts".to_string(),
            Column::LookupRuntimeTable => "rt".to_string(),
            Column::Index(gate) => {
                format!("{gate:?}")
            }
            Column::Coefficient(i) => format!("c_{{{i}}}"),
            Column::Permutation(i) => format!("sigma_{{{i}}}"),
        }
    }

    fn text(&self, _cache: &mut HashMap<CacheId, Self>) -> String {
        match self {
            Column::Witness(i) => format!("w[{i}]"),
            Column::Z => "Z".to_string(),
            Column::LookupSorted(i) => format!("s[{i}]"),
            Column::LookupAggreg => "a".to_string(),
            Column::LookupTable => "t".to_string(),
            Column::LookupKindIndex(i) => format!("k[{i:?}]"),
            Column::LookupRuntimeSelector => "rts".to_string(),
            Column::LookupRuntimeTable => "rt".to_string(),
            Column::Index(gate) => {
                format!("{gate:?}")
            }
            Column::Coefficient(i) => format!("c[{i}]"),
            Column::Permutation(i) => format!("sigma_[{i}]"),
        }
    }
}

impl<F: Copy> ColumnEvaluations<F> for ProofEvaluations<PointEvaluations<F>> {
    type Column = Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        use Column::*;
        match col {
            Witness(i) => Ok(self.w[i]),
            Z => Ok(self.z),
            LookupSorted(i) => self.lookup_sorted[i].ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupAggreg => self
                .lookup_aggregation
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupTable => self
                .lookup_table
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupRuntimeTable => self
                .runtime_lookup_table
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::Poseidon) => Ok(self.poseidon_selector),
            Index(GateType::Generic) => Ok(self.generic_selector),
            Index(GateType::CompleteAdd) => Ok(self.complete_add_selector),
            Index(GateType::VarBaseMul) => Ok(self.mul_selector),
            Index(GateType::EndoMul) => Ok(self.emul_selector),
            Index(GateType::EndoMulScalar) => Ok(self.endomul_scalar_selector),
            Index(GateType::RangeCheck0) => self
                .range_check0_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::RangeCheck1) => self
                .range_check1_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::ForeignFieldAdd) => self
                .foreign_field_add_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::ForeignFieldMul) => self
                .foreign_field_mul_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::Xor16) => self
                .xor_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(GateType::Rot64) => self
                .rot_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Permutation(i) => Ok(self.s[i]),
            Coefficient(i) => Ok(self.coefficients[i]),
            LookupKindIndex(LookupPattern::Xor) => self
                .xor_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupKindIndex(LookupPattern::Lookup) => self
                .lookup_gate_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupKindIndex(LookupPattern::RangeCheck) => self
                .range_check_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupKindIndex(LookupPattern::ForeignFieldMul) => self
                .foreign_field_mul_lookup_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            LookupRuntimeSelector => self
                .runtime_lookup_table_selector
                .ok_or(ExprError::MissingIndexEvaluation(col)),
            Index(_) => Err(ExprError::MissingIndexEvaluation(col)),
        }
    }
}

impl<'a, F: FftField> ColumnEnvironment<'a, F, BerkeleyChallengeTerm, BerkeleyChallenges<F>>
    for Environment<'a, F>
{
    type Column = Column;

    fn get_column(&self, col: &Self::Column) -> Option<&'a Evaluations<F, D<F>>> {
        use Column::*;
        let lookup = self.lookup.as_ref();
        match col {
            Witness(i) => Some(&self.witness[*i]),
            Coefficient(i) => Some(&self.coefficient[*i]),
            Z => Some(self.z),
            LookupKindIndex(i) => lookup.and_then(|l| l.selectors[*i].as_ref()),
            LookupSorted(i) => lookup.map(|l| &l.sorted[*i]),
            LookupAggreg => lookup.map(|l| l.aggreg),
            LookupTable => lookup.map(|l| l.table),
            LookupRuntimeSelector => lookup.and_then(|l| l.runtime_selector),
            LookupRuntimeTable => lookup.and_then(|l| l.runtime_table),
            Index(t) => match self.index.get(t) {
                None => None,
                Some(e) => Some(e),
            },
            Permutation(_) => None,
        }
    }

    fn get_domain(&self, d: Domain) -> D<F> {
        match d {
            Domain::D1 => self.domain.d1,
            Domain::D2 => self.domain.d2,
            Domain::D4 => self.domain.d4,
            Domain::D8 => self.domain.d8,
        }
    }

    fn column_domain(&self, col: &Self::Column) -> Domain {
        match *col {
            Self::Column::Index(GateType::Generic) => Domain::D4,
            Self::Column::Index(GateType::CompleteAdd) => Domain::D4,
            _ => Domain::D8,
        }
    }

    fn get_constants(&self) -> &Constants<F> {
        &self.constants
    }

    fn get_challenges(&self) -> &BerkeleyChallenges<F> {
        &self.challenges
    }

    fn vanishes_on_zero_knowledge_and_previous_rows(&self) -> &'a Evaluations<F, D<F>> {
        self.vanishes_on_zero_knowledge_and_previous_rows
    }

    fn l0_1(&self) -> F {
        self.l0_1
    }
}

/// The polynomials specific to the lookup argument.
///
/// All are evaluations over the D8 domain
pub struct LookupEnvironment<'a, F: FftField> {
    /// The sorted lookup table polynomials.
    pub sorted: &'a Vec<Evaluations<F, D<F>>>,
    /// The lookup aggregation polynomials.
    pub aggreg: &'a Evaluations<F, D<F>>,
    /// The lookup-type selector polynomials.
    pub selectors: &'a LookupSelectors<Evaluations<F, D<F>>>,
    /// The evaluations of the combined lookup table polynomial.
    pub table: &'a Evaluations<F, D<F>>,
    /// The evaluations of the optional runtime selector polynomial.
    pub runtime_selector: Option<&'a Evaluations<F, D<F>>>,
    /// The evaluations of the optional runtime table.
    pub runtime_table: Option<&'a Evaluations<F, D<F>>>,
}

/// The collection of polynomials (all in evaluation form) and constants
/// required to evaluate an expression as a polynomial.
///
/// All are evaluations.
pub struct Environment<'a, F: FftField> {
    /// The witness column polynomials
    pub witness: &'a [Evaluations<F, D<F>>; COLUMNS],
    /// The coefficient column polynomials
    pub coefficient: &'a [Evaluations<F, D<F>>; COLUMNS],
    /// The polynomial that vanishes on the zero-knowledge rows and the row before.
    pub vanishes_on_zero_knowledge_and_previous_rows: &'a Evaluations<F, D<F>>,
    /// The permutation aggregation polynomial.
    pub z: &'a Evaluations<F, D<F>>,
    /// The index selector polynomials.
    pub index: HashMap<GateType, &'a Evaluations<F, D<F>>>,
    /// The value `prod_{j != 1} (1 - omega^j)`, used for efficiently
    /// computing the evaluations of the unnormalized Lagrange basis polynomials.
    pub l0_1: F,
    /// Constant values required
    pub constants: Constants<F>,
    /// Challenges from the IOP.
    pub challenges: BerkeleyChallenges<F>,
    /// The domains used in the PLONK argument.
    pub domain: EvaluationDomains<F>,
    /// Lookup specific polynomials
    pub lookup: Option<LookupEnvironment<'a, F>>,
}

//
// Helpers
//

/// An alias for the intended usage of the expression type in constructing constraints.
pub type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;

/// Convenience function to create a constant as [Expr].
pub fn constant<F>(x: F) -> E<F> {
    ConstantTerm::Literal(x).into()
}

/// Helper function to quickly create an expression for a witness.
pub fn witness<F>(i: usize, row: CurrOrNext) -> E<F> {
    E::<F>::cell(Column::Witness(i), row)
}

/// Same as [witness] but for the current row.
pub fn witness_curr<F>(i: usize) -> E<F> {
    witness(i, CurrOrNext::Curr)
}

/// Same as [witness] but for the next row.
pub fn witness_next<F>(i: usize) -> E<F> {
    witness(i, CurrOrNext::Next)
}

/// Handy function to quickly create an expression for a gate.
pub fn index<F>(g: GateType) -> E<F> {
    E::<F>::cell(Column::Index(g), CurrOrNext::Curr)
}

pub fn coeff<F>(i: usize) -> E<F> {
    E::<F>::cell(Column::Coefficient(i), CurrOrNext::Curr)
}

/// A number of useful constraints
pub mod constraints {
    use o1_utils::{foreign_field::ForeignFieldHelpers, Two};

    use crate::circuits::argument::ArgumentData;
    use std::fmt;

    use super::*;
    use crate::circuits::berkeley_columns::{coeff, witness};

    /// This trait defines a common arithmetic operations interface
    /// that can be used by constraints.  It allows us to reuse
    /// constraint code for witness computation.
    pub trait ExprOps<F, ChallengeTerm>:
        Add<Output = Self>
        + Sub<Output = Self>
        + Neg<Output = Self>
        + Mul<Output = Self>
        + AddAssign<Self>
        + MulAssign<Self>
        + Clone
        + Zero
        + One
        + From<u64>
        + fmt::Debug
        + fmt::Display
    // Add more as necessary
    where
        Self: std::marker::Sized,
    {
        /// 2^pow
        fn two_pow(pow: u64) -> Self;

        /// 2^{LIMB_BITS}
        fn two_to_limb() -> Self;

        /// 2^{2 * LIMB_BITS}
        fn two_to_2limb() -> Self;

        /// 2^{3 * LIMB_BITS}
        fn two_to_3limb() -> Self;

        /// Double the value
        fn double(&self) -> Self;

        /// Compute the square of this value
        fn square(&self) -> Self;

        /// Raise the value to the given power
        fn pow(&self, p: u64) -> Self;

        /// Constrain to boolean
        fn boolean(&self) -> Self;

        /// Constrain to crumb (i.e. two bits)
        fn crumb(&self) -> Self;

        /// Create a literal
        fn literal(x: F) -> Self;

        // Witness variable
        fn witness(row: CurrOrNext, col: usize, env: Option<&ArgumentData<F>>) -> Self;

        /// Coefficient
        fn coeff(col: usize, env: Option<&ArgumentData<F>>) -> Self;

        /// Create a constant
        fn constant(expr: ConstantExpr<F, ChallengeTerm>, env: Option<&ArgumentData<F>>) -> Self;

        /// Cache item
        fn cache(&self, cache: &mut Cache) -> Self;
    }

    // TODO generalize with generic Column/challengeterm
    // We need to create a trait for berkeley_columns::Environment
    impl<F> ExprOps<F, BerkeleyChallengeTerm>
        for Expr<ConstantExpr<F, BerkeleyChallengeTerm>, super::Column>
    where
        F: PrimeField,
        // TODO remove
        Expr<ConstantExpr<F, BerkeleyChallengeTerm>, super::Column>: std::fmt::Display,
    {
        fn two_pow(pow: u64) -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, super::Column>::literal(
                <F as Two<F>>::two_pow(pow),
            )
        }

        fn two_to_limb() -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, super::Column>::literal(
                KimchiForeignElement::<F>::two_to_limb(),
            )
        }

        fn two_to_2limb() -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, super::Column>::literal(
                KimchiForeignElement::<F>::two_to_2limb(),
            )
        }

        fn two_to_3limb() -> Self {
            Expr::<ConstantExpr<F, BerkeleyChallengeTerm>, super::Column>::literal(
                KimchiForeignElement::<F>::two_to_3limb(),
            )
        }

        fn double(&self) -> Self {
            Expr::double(self.clone())
        }

        fn square(&self) -> Self {
            Expr::square(self.clone())
        }

        fn pow(&self, p: u64) -> Self {
            Expr::pow(self.clone(), p)
        }

        fn boolean(&self) -> Self {
            crate::circuits::constraints::boolean(self)
        }

        fn crumb(&self) -> Self {
            crate::circuits::constraints::crumb(self)
        }

        fn literal(x: F) -> Self {
            ConstantTerm::Literal(x).into()
        }

        fn witness(row: CurrOrNext, col: usize, _: Option<&ArgumentData<F>>) -> Self {
            witness(col, row)
        }

        fn coeff(col: usize, _: Option<&ArgumentData<F>>) -> Self {
            coeff(col)
        }

        fn constant(
            expr: ConstantExpr<F, BerkeleyChallengeTerm>,
            _: Option<&ArgumentData<F>>,
        ) -> Self {
            Expr::from(expr)
        }

        fn cache(&self, cache: &mut Cache) -> Self {
            Expr::Cache(cache.next_id(), Box::new(self.clone()))
        }
    }

    // TODO generalize with generic Column/challengeterm
    // We need to generalize argument.rs
    impl<F: Field> ExprOps<F, BerkeleyChallengeTerm> for F {
        fn two_pow(pow: u64) -> Self {
            <F as Two<F>>::two_pow(pow)
        }

        fn two_to_limb() -> Self {
            KimchiForeignElement::<F>::two_to_limb()
        }

        fn two_to_2limb() -> Self {
            KimchiForeignElement::<F>::two_to_2limb()
        }

        fn two_to_3limb() -> Self {
            KimchiForeignElement::<F>::two_to_3limb()
        }

        fn double(&self) -> Self {
            *self * F::from(2u64)
        }

        fn square(&self) -> Self {
            *self * *self
        }

        fn pow(&self, p: u64) -> Self {
            self.pow([p])
        }

        fn boolean(&self) -> Self {
            self.clone().square() - self.clone()
        }

        fn crumb(&self) -> Self {
            self.clone()
                * (self.clone() - 1u64.into())
                * (self.clone() - 2u64.into())
                * (self.clone() - 3u64.into())
        }

        fn literal(x: F) -> Self {
            x
        }

        fn witness(row: CurrOrNext, col: usize, env: Option<&ArgumentData<F>>) -> Self {
            match env {
                Some(data) => data.witness[(row, col)],
                None => panic!("Missing witness"),
            }
        }

        fn coeff(col: usize, env: Option<&ArgumentData<F>>) -> Self {
            match env {
                Some(data) => data.coeffs[col],
                None => panic!("Missing coefficients"),
            }
        }

        fn constant(
            expr: ConstantExpr<F, BerkeleyChallengeTerm>,
            env: Option<&ArgumentData<F>>,
        ) -> Self {
            match env {
                Some(data) => expr.value(&data.constants, &data.challenges),
                None => panic!("Missing constants"),
            }
        }

        fn cache(&self, _: &mut Cache) -> Self {
            *self
        }
    }

    /// Creates a constraint to enforce that b is either 0 or 1.
    pub fn boolean<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(b: &T) -> T {
        b.square() - b.clone()
    }

    /// Crumb constraint for 2-bit value x
    pub fn crumb<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(x: &T) -> T {
        // Assert x \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
        x.clone()
            * (x.clone() - 1u64.into())
            * (x.clone() - 2u64.into())
            * (x.clone() - 3u64.into())
    }

    /// lo + mi * 2^{LIMB_BITS}
    pub fn compact_limb<F: Field, ChallengeTerm, T: ExprOps<F, ChallengeTerm>>(
        lo: &T,
        mi: &T,
    ) -> T {
        lo.clone() + mi.clone() * T::two_to_limb()
    }
}
